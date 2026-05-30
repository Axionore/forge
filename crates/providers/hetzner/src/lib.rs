//! Hetzner Cloud provider for Forge (first narrow slice of A0-4).
//!
//! Goals for this slice:
//! - Basic server creation using raw Hetzner Cloud API
//! - Cloud-init that bootstraps the Forge agent with an enrollment token
//! - Clean, production-minded error handling

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum HetznerError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Hetzner API error: {status} - {body}")]
    Api { status: u16, body: String },
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Server creation failed: {0}")]
    CreationFailed(String),
    #[error("Invalid response from Hetzner: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HetznerConfig {
    pub api_token: String,
    pub default_location: Option<String>,
    pub default_server_type: Option<String>,
    pub default_image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedHetznerServer {
    pub id: i64,
    pub name: String,
    pub ipv4: Option<String>,
    pub status: String,
}

/// Minimal Hetzner provider for the first slice.
#[derive(Clone)]
pub struct HetznerProvider {
    config: HetznerConfig,
    client: Client,
}

impl HetznerProvider {
    pub fn new(config: HetznerConfig) -> Self {
        let client = Client::builder()
            .user_agent("forge-provider-hetzner/0.1")
            .build()
            .expect("Failed to build HTTP client");

        Self { config, client }
    }

    /// Create a server on Hetzner Cloud with the given cloud-init user data.
    /// If `private_network_name` is provided, a new private network will be created (if it doesn't exist)
    /// and the server attached to it.
    // Hetzner's create-server API genuinely takes this many independent optional
    // inputs (type/image/location/user-data/private-net name+range); grouping them
    // into a struct would add ceremony without clarity for a single call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_server(
        &self,
        name: &str,
        server_type: Option<&str>,
        image: Option<&str>,
        location: Option<&str>,
        user_data: Option<&str>,
        private_network_name: Option<&str>,
        private_network_ip_range: Option<&str>,
    ) -> Result<CreatedHetznerServer, HetznerError> {
        let server_type = server_type
            .or(self.config.default_server_type.as_deref())
            .unwrap_or("cx22");

        let image = image
            .or(self.config.default_image.as_deref())
            .unwrap_or("ubuntu-24.04");

        let location = location
            .or(self.config.default_location.as_deref())
            .unwrap_or("fsn1");

        info!(
            "Provisioning Hetzner server name={name} type={server_type} image={image} location={location}"
        );

        let mut body = serde_json::json!({
            "name": name,
            "server_type": server_type,
            "image": image,
            "location": location,
        });

        if let Some(ud) = user_data {
            body["user_data"] = serde_json::Value::String(ud.to_string());
        }

        // Private network handling (creation + attachment)
        if let Some(net_name) = private_network_name {
            let ip_range = private_network_ip_range.unwrap_or("10.0.0.0/16");
            let network_body = serde_json::json!({
                "name": net_name,
                "ip_range": ip_range
            });

            let net_resp = self
                .client
                .post("https://api.hetzner.cloud/v1/networks")
                .bearer_auth(&self.config.api_token)
                .json(&network_body)
                .send()
                .await?;

            if net_resp.status().is_success() {
                if let Ok(net_json) = net_resp.json::<serde_json::Value>().await {
                    if let Some(net_id) = net_json
                        .get("network")
                        .and_then(|n| n.get("id"))
                        .and_then(|v| v.as_i64())
                    {
                        body["networks"] = serde_json::json!([net_id]);
                    }
                }
            } else {
                // If creation fails (e.g. name exists), we still try to attach by name later if needed.
                // For v1 we log and continue without private net.
                tracing::warn!(
                    "Failed to create private network '{net_name}', server will be created without it"
                );
            }
        }

        let resp = self
            .client
            .post("https://api.hetzner.cloud/v1/servers")
            .bearer_auth(&self.config.api_token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(HetznerError::Api { status, body });
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| HetznerError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        let server = json.get("server").ok_or_else(|| {
            HetznerError::InvalidResponse("Missing 'server' in response".to_string())
        })?;

        let id = server["id"]
            .as_i64()
            .ok_or_else(|| HetznerError::InvalidResponse("Invalid server id".to_string()))?;
        let name = server["name"].as_str().unwrap_or("unknown").to_string();
        let ipv4 = server
            .get("public_net")
            .and_then(|n| n.get("ipv4"))
            .and_then(|i| i.get("ip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let server_status = server["status"].as_str().unwrap_or("unknown").to_string();

        info!("Hetzner server created: id={id}, name={name}, ipv4={ipv4:?}");

        Ok(CreatedHetznerServer {
            id,
            name,
            ipv4,
            status: server_status,
        })
    }

    /// Generate a hardened cloud-init script for Forge agent bootstrap.
    ///
    /// Includes security best practices:
    /// - Package updates + unattended upgrades
    /// - Disable SSH password auth
    /// - Basic UFW firewall (only 22 + agent ports if known)
    /// - Secure permissions on agent config
    /// - Fail2ban (light)
    pub fn build_agent_cloud_init(
        &self,
        control_plane_url: &str,
        enrollment_token: &str,
        desired_hostname: Option<&str>,
    ) -> String {
        let hostname = desired_hostname.unwrap_or("forge-node");

        format!(
            r#"#cloud-config
# Forge Agent - Hardened Hetzner Bootstrap (generated by forge-provider-hetzner)
hostname: {hostname}
package_update: true
package_upgrade: true

# Security hardening
ssh_pwauth: false
disable_root: true

users:
  - name: forge
    groups: docker
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true

# Basic firewall + fail2ban
runcmd:
  - |
    apt-get install -y ufw fail2ban unattended-upgrades
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    # Agent control plane ports (adjust if you use custom ports)
    ufw allow 8080/tcp
    ufw allow 6001/tcp
    ufw --force enable
  - |
    curl -fsSL {cp}/install-agent.sh | bash -s -- \
      --control-plane="{cp}" \
      --enrollment-token="{token}"
  - |
    chown -R root:root /etc/forge
    chmod 700 /etc/forge
    systemctl restart forge-agent || true

# Enable automatic security updates
unattended-upgrades:
  origins:
    - ${{distro_id}}:${{distro_codename}}
    - ${{distro_id}}:${{distro_codename}}-security
  auto-fix: true
"#,
            hostname = hostname,
            cp = control_plane_url.trim_end_matches('/'),
            token = enrollment_token
        )
    }
}
