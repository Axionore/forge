//! [`CloudProvider`] implementation for Hetzner Cloud + Hetzner DNS.
//!
//! Resource IDs are exchanged with the abstraction as strings; Hetzner uses numeric IDs
//! internally, so we parse/format at the boundary.

// The `CloudProvider` trait documents error semantics centrally.
#![allow(clippy::missing_errors_doc)]
// Const-ness of small accessors is an internal detail.
#![allow(clippy::missing_const_for_fn)]

use crate::client::{Api, HetznerClient};
use async_trait::async_trait;
use forge_providers::{
    Capabilities, CloudProvider, Direction, DnsRecord, DnsRecordType, FirewallRule, ImageInfo,
    LbService, LbTarget, LoadBalancerInfo, NetworkInfo, Protocol, ProviderError, RegionInfo,
    Result, ServerId, ServerInfo, ServerSpec, ServerStatus, SizeInfo, VolumeInfo,
};
use reqwest::Method;
use serde_json::{Value, json};

/// Hetzner provider. Holds the HTTP client (which holds both credentials).
#[derive(Debug, Clone)]
pub struct HetznerProvider {
    client: HetznerClient,
}

impl HetznerProvider {
    #[must_use]
    pub fn new(client: HetznerClient) -> Self {
        Self { client }
    }

    #[must_use]
    pub fn client(&self) -> &HetznerClient {
        &self.client
    }
}

fn num_id(id: &str, what: &str) -> Result<i64> {
    id.parse::<i64>()
        .map_err(|_| ProviderError::InvalidRequest(format!("invalid {what} id: {id}")))
}

fn parse_server(v: &Value) -> Result<ServerInfo> {
    let id = v
        .get("id")
        .and_then(Value::as_i64)
        .ok_or_else(|| ProviderError::Http("server missing id".to_string()))?;
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let status = match v.get("status").and_then(Value::as_str).unwrap_or("") {
        "initializing" => ServerStatus::Initializing,
        "starting" => ServerStatus::Starting,
        "running" => ServerStatus::Running,
        "stopping" => ServerStatus::Stopping,
        "off" => ServerStatus::Off,
        "deleting" => ServerStatus::Deleting,
        "rebuilding" => ServerStatus::Rebuilding,
        "migrating" => ServerStatus::Migrating,
        _ => ServerStatus::Unknown,
    };
    let public_ipv4 = v
        .pointer("/public_net/ipv4/ip")
        .and_then(Value::as_str)
        .map(str::to_string);
    let public_ipv6 = v
        .pointer("/public_net/ipv6/ip")
        .and_then(Value::as_str)
        .map(str::to_string);
    let private_ips = v
        .get("private_net")
        .and_then(Value::as_array)
        .map(|nets| {
            nets.iter()
                .filter_map(|n| n.get("ip").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let region = v
        .pointer("/datacenter/location/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let size = v
        .pointer("/server_type/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let image = v
        .pointer("/image/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let labels = v
        .get("labels")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(ServerInfo {
        id: ServerId::new(id.to_string()),
        name,
        status,
        public_ipv4,
        public_ipv6,
        private_ips,
        region,
        size,
        image,
        labels,
    })
}

fn fw_rule_json(rule: &FirewallRule) -> Value {
    let dir = match rule.direction {
        Direction::In => "in",
        Direction::Out => "out",
    };
    let proto = match rule.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
    };
    let mut obj = json!({
        "direction": dir,
        "protocol": proto,
    });
    if let Some(port) = &rule.port_range {
        obj["port"] = Value::String(port.clone());
    }
    // Hetzner names the CIDR field by direction.
    let cidrs: Vec<Value> = rule
        .cidrs
        .iter()
        .map(|c| Value::String(c.clone()))
        .collect();
    match rule.direction {
        Direction::In => obj["source_ips"] = Value::Array(cidrs),
        Direction::Out => obj["destination_ips"] = Value::Array(cidrs),
    }
    obj
}

fn dns_type_str(t: DnsRecordType) -> &'static str {
    match t {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
        DnsRecordType::Cname => "CNAME",
        DnsRecordType::Txt => "TXT",
        DnsRecordType::Mx => "MX",
        DnsRecordType::Caa => "CAA",
        DnsRecordType::Ns => "NS",
    }
}

fn parse_dns_type(s: &str) -> Option<DnsRecordType> {
    Some(match s {
        "A" => DnsRecordType::A,
        "AAAA" => DnsRecordType::Aaaa,
        "CNAME" => DnsRecordType::Cname,
        "TXT" => DnsRecordType::Txt,
        "MX" => DnsRecordType::Mx,
        "CAA" => DnsRecordType::Caa,
        "NS" => DnsRecordType::Ns,
        _ => return None,
    })
}

#[async_trait]
impl CloudProvider for HetznerProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            servers: true,
            ssh_keys: true,
            networks: true,
            firewalls: true,
            floating_ips: true,
            volumes: true,
            load_balancers: true,
            // DNS only if a DNS token was configured.
            dns: self.client.dns_enabled(),
            resize: true,
            rebuild: true,
        }
    }

    async fn list_regions(&self) -> Result<Vec<RegionInfo>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/locations", "locations")
            .await?;
        Ok(items
            .iter()
            .filter_map(|v| {
                Some(RegionInfo {
                    id: v.get("name")?.as_str()?.to_string(),
                    name: v
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    country: v.get("country").and_then(Value::as_str).map(str::to_string),
                    city: v.get("city").and_then(Value::as_str).map(str::to_string),
                })
            })
            .collect())
    }

    async fn list_sizes(&self) -> Result<Vec<SizeInfo>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/server_types", "server_types")
            .await?;
        Ok(items
            .iter()
            .filter(|v| {
                !v.get("deprecated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .filter_map(|v| {
                let available_regions = v
                    .get("prices")
                    .and_then(Value::as_array)
                    .map(|prices| {
                        prices
                            .iter()
                            .filter_map(|p| {
                                p.get("location")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(SizeInfo {
                    id: v.get("name")?.as_str()?.to_string(),
                    description: v
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    vcpus: u32::try_from(v.get("cores").and_then(Value::as_u64).unwrap_or(0))
                        .unwrap_or(0),
                    memory_gb: v.get("memory").and_then(Value::as_f64).unwrap_or(0.0),
                    disk_gb: v.get("disk").and_then(Value::as_f64).unwrap_or(0.0),
                    available_regions,
                })
            })
            .collect())
    }

    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/images", "images")
            .await?;
        Ok(items
            .iter()
            .filter_map(|v| {
                let id = match v.get("name").and_then(Value::as_str) {
                    Some(name) => name.to_string(),
                    None => v.get("id").and_then(Value::as_i64)?.to_string(),
                };
                Some(ImageInfo {
                    id,
                    name: v
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    description: v
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    os_flavor: v
                        .get("os_flavor")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    os_version: v
                        .get("os_version")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
            })
            .collect())
    }

    async fn provision_server(&self, spec: &ServerSpec) -> Result<ServerInfo> {
        // Resources we attach during this call and must clean up on failure.
        // (Networks/firewalls/keys referenced by ID are caller-owned; we only tear down the
        // server we created here, plus anything we implicitly created — none, in this design.)
        let mut created: Vec<String> = Vec::new();

        let mut body = json!({
            "name": spec.name,
            "server_type": spec.size,
            "image": spec.image,
            "location": spec.region,
            "start_after_create": true,
        });
        if let Some(ud) = &spec.user_data {
            body["user_data"] = Value::String(ud.clone());
        }
        if !spec.ssh_key_ids.is_empty() {
            body["ssh_keys"] = Value::Array(
                spec.ssh_key_ids
                    .iter()
                    .map(|k| {
                        k.parse::<i64>()
                            .map_or_else(|_| Value::String(k.clone()), |n| json!(n))
                    })
                    .collect(),
            );
        }
        if !spec.network_ids.is_empty() {
            let nets: Result<Vec<Value>> = spec
                .network_ids
                .iter()
                .map(|n| num_id(n, "network").map(|i| json!(i)))
                .collect();
            body["networks"] = Value::Array(nets?);
        }
        if !spec.firewall_ids.is_empty() {
            let fws: Result<Vec<Value>> = spec
                .firewall_ids
                .iter()
                .map(|f| num_id(f, "firewall").map(|i| json!({ "firewall": i })))
                .collect();
            body["firewalls"] = Value::Array(fws?);
        }
        if !spec.labels.is_empty() {
            body["labels"] = json!(spec.labels);
        }

        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/servers", Some(&body))
            .await?;

        let server = resp
            .get("server")
            .ok_or_else(|| ProviderError::Http("create server: missing 'server'".to_string()))?;
        let server_id = server
            .get("id")
            .and_then(Value::as_i64)
            .ok_or_else(|| ProviderError::Http("create server: missing id".to_string()))?;
        created.push(server_id.to_string());

        // The create call returns a root action plus next_actions; wait for them so the server
        // is actually usable. On failure, tear down the server we just created.
        if let Err(e) = self.client.poll_response_action(&resp).await {
            let leftover = self.cleanup(&created).await;
            return Err(ProviderError::PartialFailure {
                message: format!("server provisioning action failed: {e}"),
                created_resource_ids: created,
                leftover_resource_ids: leftover,
            });
        }
        if let Some(next) = resp.get("next_actions") {
            if let Err(e) = self
                .client
                .poll_response_action(&json!({ "actions": next }))
                .await
            {
                let leftover = self.cleanup(&created).await;
                return Err(ProviderError::PartialFailure {
                    message: format!("server follow-up action failed: {e}"),
                    created_resource_ids: created,
                    leftover_resource_ids: leftover,
                });
            }
        }

        // Re-fetch for a fully-populated view (IPs assigned after actions complete).
        match self.get_server(&ServerId::new(server_id.to_string())).await {
            Ok(info) => Ok(info),
            Err(e) => {
                let leftover = self.cleanup(&created).await;
                Err(ProviderError::PartialFailure {
                    message: format!("server created but could not be read back: {e}"),
                    created_resource_ids: created,
                    leftover_resource_ids: leftover,
                })
            }
        }
    }

    async fn get_server(&self, id: &ServerId) -> Result<ServerInfo> {
        let sid = num_id(id.as_str(), "server")?;
        let resp = self
            .client
            .request(Api::Cloud, Method::GET, &format!("/servers/{sid}"), None)
            .await?;
        let server = resp
            .get("server")
            .ok_or_else(|| ProviderError::NotFound(format!("server {sid}")))?;
        parse_server(server)
    }

    async fn list_servers(&self) -> Result<Vec<ServerInfo>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/servers", "servers")
            .await?;
        items.iter().map(parse_server).collect()
    }

    async fn delete_server(&self, id: &ServerId) -> Result<()> {
        let sid = num_id(id.as_str(), "server")?;
        let resp = self
            .client
            .request(Api::Cloud, Method::DELETE, &format!("/servers/{sid}"), None)
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn resize_server(&self, id: &ServerId, new_size: &str, upgrade_disk: bool) -> Result<()> {
        let sid = num_id(id.as_str(), "server")?;
        let body = json!({ "server_type": new_size, "upgrade_disk": upgrade_disk });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/servers/{sid}/actions/change_type"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn rebuild_server(&self, id: &ServerId, image: &str) -> Result<()> {
        let sid = num_id(id.as_str(), "server")?;
        let body = json!({ "image": image });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/servers/{sid}/actions/rebuild"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn ensure_ssh_key(&self, name: &str, public_key: &str) -> Result<String> {
        // Match on the normalized key material (ignoring the trailing comment) or the name.
        let existing = self
            .client
            .list_all(Api::Cloud, "/ssh_keys", "ssh_keys")
            .await?;
        let wanted_material = public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        for k in &existing {
            let same_name = k.get("name").and_then(Value::as_str) == Some(name);
            let same_key = k
                .get("public_key")
                .and_then(Value::as_str)
                .map(|pk| pk.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
                == Some(wanted_material.clone());
            if same_name || same_key {
                if let Some(id) = k.get("id").and_then(Value::as_i64) {
                    return Ok(id.to_string());
                }
            }
        }
        let body = json!({ "name": name, "public_key": public_key });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/ssh_keys", Some(&body))
            .await?;
        resp.pointer("/ssh_key/id")
            .and_then(Value::as_i64)
            .map(|i| i.to_string())
            .ok_or_else(|| ProviderError::Http("create ssh_key: missing id".to_string()))
    }

    async fn list_ssh_keys(&self) -> Result<Vec<(String, String)>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/ssh_keys", "ssh_keys")
            .await?;
        Ok(items
            .iter()
            .filter_map(|k| {
                let id = k.get("id").and_then(Value::as_i64)?.to_string();
                let name = k
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Some((id, name))
            })
            .collect())
    }

    async fn delete_ssh_key(&self, id: &str) -> Result<()> {
        let kid = num_id(id, "ssh_key")?;
        self.client
            .request(
                Api::Cloud,
                Method::DELETE,
                &format!("/ssh_keys/{kid}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn create_network(&self, name: &str, ip_range: &str) -> Result<NetworkInfo> {
        let body = json!({ "name": name, "ip_range": ip_range });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/networks", Some(&body))
            .await?;
        let net = resp
            .get("network")
            .ok_or_else(|| ProviderError::Http("create network: missing 'network'".to_string()))?;
        Ok(NetworkInfo {
            id: net
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| ProviderError::Http("network missing id".to_string()))?
                .to_string(),
            name: net
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string(),
            ip_range: net
                .get("ip_range")
                .and_then(Value::as_str)
                .unwrap_or(ip_range)
                .to_string(),
        })
    }

    async fn delete_network(&self, id: &str) -> Result<()> {
        let nid = num_id(id, "network")?;
        self.client
            .request(
                Api::Cloud,
                Method::DELETE,
                &format!("/networks/{nid}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn list_networks(&self) -> Result<Vec<NetworkInfo>> {
        let items = self
            .client
            .list_all(Api::Cloud, "/networks", "networks")
            .await?;
        Ok(items
            .iter()
            .filter_map(|n| {
                Some(NetworkInfo {
                    id: n.get("id").and_then(Value::as_i64)?.to_string(),
                    name: n
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    ip_range: n
                        .get("ip_range")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
            })
            .collect())
    }

    async fn attach_server_to_network(&self, server: &ServerId, network_id: &str) -> Result<()> {
        let sid = num_id(server.as_str(), "server")?;
        let nid = num_id(network_id, "network")?;
        let body = json!({ "network": nid });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/servers/{sid}/actions/attach_to_network"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn create_firewall(&self, name: &str, rules: &[FirewallRule]) -> Result<String> {
        let rules_json: Vec<Value> = rules.iter().map(fw_rule_json).collect();
        let body = json!({ "name": name, "rules": rules_json });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/firewalls", Some(&body))
            .await?;
        // Firewall creation may include actions; poll if present.
        self.client.poll_response_action(&resp).await?;
        resp.pointer("/firewall/id")
            .and_then(Value::as_i64)
            .map(|i| i.to_string())
            .ok_or_else(|| ProviderError::Http("create firewall: missing id".to_string()))
    }

    async fn delete_firewall(&self, id: &str) -> Result<()> {
        let fid = num_id(id, "firewall")?;
        self.client
            .request(
                Api::Cloud,
                Method::DELETE,
                &format!("/firewalls/{fid}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn attach_firewall(&self, firewall_id: &str, server: &ServerId) -> Result<()> {
        let fid = num_id(firewall_id, "firewall")?;
        let sid = num_id(server.as_str(), "server")?;
        let body = json!({ "apply_to": [{ "type": "server", "server": { "id": sid } }] });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/firewalls/{fid}/actions/apply_to_resources"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn detach_firewall(&self, firewall_id: &str, server: &ServerId) -> Result<()> {
        let fid = num_id(firewall_id, "firewall")?;
        let sid = num_id(server.as_str(), "server")?;
        let body = json!({ "remove_from": [{ "type": "server", "server": { "id": sid } }] });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/firewalls/{fid}/actions/remove_from_resources"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn allocate_ip(&self, region: &str, ipv6: bool) -> Result<(String, String)> {
        let body = json!({
            "type": if ipv6 { "ipv6" } else { "ipv4" },
            "datacenter": region,
            "assignee_type": "server",
        });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/primary_ips", Some(&body))
            .await?;
        self.client.poll_response_action(&resp).await?;
        let ip = resp
            .get("primary_ip")
            .ok_or_else(|| ProviderError::Http("allocate ip: missing 'primary_ip'".to_string()))?;
        let id = ip
            .get("id")
            .and_then(Value::as_i64)
            .ok_or_else(|| ProviderError::Http("primary_ip missing id".to_string()))?
            .to_string();
        let addr = ip
            .get("ip")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok((id, addr))
    }

    async fn assign_ip(&self, ip_id: &str, server: &ServerId) -> Result<()> {
        let pid = num_id(ip_id, "primary_ip")?;
        let sid = num_id(server.as_str(), "server")?;
        let body = json!({ "assignee_id": sid, "assignee_type": "server" });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/primary_ips/{pid}/actions/assign"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn release_ip(&self, ip_id: &str) -> Result<()> {
        let pid = num_id(ip_id, "primary_ip")?;
        self.client
            .request(
                Api::Cloud,
                Method::DELETE,
                &format!("/primary_ips/{pid}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn create_volume(&self, name: &str, size_gb: u64, region: &str) -> Result<VolumeInfo> {
        let body = json!({
            "name": name,
            "size": size_gb,
            "location": region,
            "format": "ext4",
        });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/volumes", Some(&body))
            .await?;
        self.client.poll_response_action(&resp).await?;
        let vol = resp
            .get("volume")
            .ok_or_else(|| ProviderError::Http("create volume: missing 'volume'".to_string()))?;
        Ok(VolumeInfo {
            id: vol
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| ProviderError::Http("volume missing id".to_string()))?
                .to_string(),
            name: vol
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string(),
            size_gb: vol.get("size").and_then(Value::as_u64).unwrap_or(size_gb),
            region: region.to_string(),
            attached_to: vol
                .get("server")
                .and_then(Value::as_i64)
                .map(|s| ServerId::new(s.to_string())),
            linux_device: vol
                .get("linux_device")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    async fn attach_volume(&self, volume_id: &str, server: &ServerId) -> Result<()> {
        let vid = num_id(volume_id, "volume")?;
        let sid = num_id(server.as_str(), "server")?;
        let body = json!({ "server": sid, "automount": false });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/volumes/{vid}/actions/attach"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn detach_volume(&self, volume_id: &str) -> Result<()> {
        let vid = num_id(volume_id, "volume")?;
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/volumes/{vid}/actions/detach"),
                Some(&json!({})),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn resize_volume(&self, volume_id: &str, new_size_gb: u64) -> Result<()> {
        let vid = num_id(volume_id, "volume")?;
        let body = json!({ "size": new_size_gb });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/volumes/{vid}/actions/resize"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<()> {
        let vid = num_id(volume_id, "volume")?;
        self.client
            .request(Api::Cloud, Method::DELETE, &format!("/volumes/{vid}"), None)
            .await
            .map(|_| ())
    }

    async fn create_load_balancer(
        &self,
        name: &str,
        region: &str,
        services: &[LbService],
    ) -> Result<LoadBalancerInfo> {
        let svcs: Vec<Value> = services.iter().map(lb_service_json).collect();
        let body = json!({
            "name": name,
            "load_balancer_type": "lb11",
            "location": region,
            "services": svcs,
        });
        let resp = self
            .client
            .request(Api::Cloud, Method::POST, "/load_balancers", Some(&body))
            .await?;
        self.client.poll_response_action(&resp).await?;
        let lb = resp.get("load_balancer").ok_or_else(|| {
            ProviderError::Http("create load_balancer: missing 'load_balancer'".to_string())
        })?;
        Ok(LoadBalancerInfo {
            id: lb
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| ProviderError::Http("load_balancer missing id".to_string()))?
                .to_string(),
            name: lb
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string(),
            public_ipv4: lb
                .pointer("/public_net/ipv4/ip")
                .and_then(Value::as_str)
                .map(str::to_string),
            region: region.to_string(),
            services: services.to_vec(),
            targets: Vec::new(),
        })
    }

    async fn delete_load_balancer(&self, id: &str) -> Result<()> {
        let lid = num_id(id, "load_balancer")?;
        self.client
            .request(
                Api::Cloud,
                Method::DELETE,
                &format!("/load_balancers/{lid}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn add_lb_target(&self, lb_id: &str, target: &LbTarget) -> Result<()> {
        let lid = num_id(lb_id, "load_balancer")?;
        let sid = num_id(target.server_id.as_str(), "server")?;
        let body = json!({
            "type": "server",
            "server": { "id": sid },
            "use_private_ip": target.use_private_ip,
        });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/load_balancers/{lid}/actions/add_target"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn remove_lb_target(&self, lb_id: &str, server: &ServerId) -> Result<()> {
        let lid = num_id(lb_id, "load_balancer")?;
        let sid = num_id(server.as_str(), "server")?;
        let body = json!({ "type": "server", "server": { "id": sid } });
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/load_balancers/{lid}/actions/remove_target"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn update_lb_service(&self, lb_id: &str, service: &LbService) -> Result<()> {
        let lid = num_id(lb_id, "load_balancer")?;
        let body = lb_service_json(service);
        let resp = self
            .client
            .request(
                Api::Cloud,
                Method::POST,
                &format!("/load_balancers/{lid}/actions/update_service"),
                Some(&body),
            )
            .await?;
        self.client.poll_response_action(&resp).await
    }

    async fn dns_ensure_zone(&self, domain: &str) -> Result<String> {
        let zones = self.client.list_all(Api::Dns, "/zones", "zones").await?;
        if let Some(z) = zones
            .iter()
            .find(|z| z.get("name").and_then(Value::as_str) == Some(domain))
        {
            if let Some(id) = z.get("id").and_then(Value::as_str) {
                return Ok(id.to_string());
            }
        }
        let body = json!({ "name": domain });
        let resp = self
            .client
            .request(Api::Dns, Method::POST, "/zones", Some(&body))
            .await?;
        resp.pointer("/zone/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ProviderError::Http("create zone: missing id".to_string()))
    }

    async fn dns_upsert_record(&self, record: &DnsRecord) -> Result<String> {
        let rtype = dns_type_str(record.record_type);
        // Find an existing record with the same name + type.
        let existing = self.dns_list_records(&record.zone_id).await?;
        let found = existing
            .iter()
            .find(|r| r.name == record.name && r.record_type == record.record_type);

        let mut body = json!({
            "zone_id": record.zone_id,
            "type": rtype,
            "name": record.name,
            "value": record.value,
        });
        if let Some(ttl) = record.ttl {
            body["ttl"] = json!(ttl);
        }

        if let Some(existing_rec) = found {
            let rid = existing_rec
                .id
                .as_ref()
                .ok_or_else(|| ProviderError::Http("existing record missing id".to_string()))?;
            let resp = self
                .client
                .request(
                    Api::Dns,
                    Method::PUT,
                    &format!("/records/{rid}"),
                    Some(&body),
                )
                .await?;
            return resp
                .pointer("/record/id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| ProviderError::Http("update record: missing id".to_string()));
        }

        let resp = self
            .client
            .request(Api::Dns, Method::POST, "/records", Some(&body))
            .await?;
        resp.pointer("/record/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ProviderError::Http("create record: missing id".to_string()))
    }

    async fn dns_delete_record(&self, _zone_id: &str, record_id: &str) -> Result<()> {
        self.client
            .request(
                Api::Dns,
                Method::DELETE,
                &format!("/records/{record_id}"),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn dns_list_records(&self, zone_id: &str) -> Result<Vec<DnsRecord>> {
        let path = format!("/records?zone_id={zone_id}");
        let items = self.client.list_all(Api::Dns, &path, "records").await?;
        Ok(items
            .iter()
            .filter_map(|r| {
                let rtype = parse_dns_type(r.get("type").and_then(Value::as_str)?)?;
                Some(DnsRecord {
                    id: r.get("id").and_then(Value::as_str).map(str::to_string),
                    zone_id: r
                        .get("zone_id")
                        .and_then(Value::as_str)
                        .unwrap_or(zone_id)
                        .to_string(),
                    record_type: rtype,
                    name: r
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    value: r
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    ttl: r
                        .get("ttl")
                        .and_then(Value::as_u64)
                        .and_then(|t| u32::try_from(t).ok()),
                })
            })
            .collect())
    }
}

impl HetznerProvider {
    /// Best-effort teardown of created servers. Returns the IDs that could NOT be removed.
    async fn cleanup(&self, created_resource_ids: &[String]) -> Vec<String> {
        let mut leftover = Vec::new();
        for id in created_resource_ids {
            let sid = ServerId::new(id.clone());
            if self.delete_server(&sid).await.is_err() {
                tracing::warn!(server_id = %id, "cleanup: failed to delete server during rollback");
                leftover.push(id.clone());
            }
        }
        leftover
    }
}

fn lb_service_json(s: &LbService) -> Value {
    // Hetzner LBs speak tcp/http/https; everything maps onto a tcp L4 listener.
    let proto = "tcp";
    let mut obj = json!({
        "protocol": proto,
        "listen_port": s.listen_port,
        "destination_port": s.target_port,
        "proxyprotocol": false,
    });
    if let Some(path) = &s.health_check_path {
        obj["health_check"] = json!({
            "protocol": "http",
            "port": s.target_port,
            "interval": 15,
            "timeout": 10,
            "retries": 3,
            "http": { "path": path },
        });
    }
    obj
}
