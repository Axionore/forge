//! Agent identity and enrollment handling.
//!
//! The agent generates an Ed25519 keypair on first run (its long-term identity).
//! It uses a one-time enrollment token to register with the control plane and
//! receives the control plane's public signing key plus any long-lived credentials.

use crate::config::AgentConfig;
use age::secrecy::ExposeSecret;
use age::x25519::{Identity as AgeIdentity, Recipient as AgeRecipient};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tracing::info;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Stable identifier assigned by the control plane after enrollment.
    pub agent_id: Option<String>,

    /// This agent's long-term Ed25519 private key (used for future attestation / mTLS, etc.).
    /// Stored as raw bytes (32 bytes).
    pub private_key: Vec<u8>,

    /// The control plane's Ed25519 public key (used to verify signed jobs).
    /// Received during enrollment.
    pub control_plane_public_key: Option<Vec<u8>>,

    /// Optional long-lived token for authenticating to the control plane WebSocket.
    pub agent_token: Option<String>,

    /// When this identity was created / last enrolled.
    pub enrolled_at: Option<String>,

    // Auto-issued mTLS client cert + key + CA for connecting Envoy sidecars (and future agent gRPC) to the control plane xDS ADS port.
    // Persisted with 0600. Enables true zero-config mTLS for live canary weight updates.
    pub xds_client_cert_pem: Option<String>,
    pub xds_client_key_pem: Option<String>,
    pub xds_ca_cert_pem: Option<String>,

    /// Tier 3-2: Dedicated age X25519 private key (32 bytes) for decrypting secret envelopes.
    /// Generated on first run alongside the Ed25519 identity. Never leaves the agent.
    /// Stored in the same 0600-protected TOML. Recipient (public) is sent to CP at enrollment
    /// so the control plane can encrypt secrets that only this agent (or cluster mates) can open.
    pub age_private_key: Option<Vec<u8>>,
}

impl AgentIdentity {
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        self.control_plane_public_key
            .as_ref()
            .and_then(|bytes| VerifyingKey::from_bytes(bytes.as_slice().try_into().ok()?).ok())
    }

    pub fn signing_key(&self) -> Option<SigningKey> {
        if self.private_key.len() == 32 {
            let bytes: [u8; 32] = self.private_key.as_slice().try_into().ok()?;
            Some(SigningKey::from_bytes(&bytes))
        } else {
            None
        }
    }

    /// Returns the age identity for decrypting secret envelopes (Tier 3-2).
    /// The private key never leaves this agent.
    pub fn age_identity(&self) -> Option<AgeIdentity> {
        let bytes = self.age_private_key.as_ref()?;
        let s = std::str::from_utf8(bytes).ok()?;
        // The canonical "AGE-SECRET-KEY-..." string parses directly.
        s.parse::<AgeIdentity>().ok()
    }

    /// Returns the public age recipient string ("age1...") that the control plane
    /// uses to encrypt secrets intended for this agent.
    pub fn age_recipient(&self) -> Option<String> {
        self.age_identity().map(|id| {
            let recipient: AgeRecipient = id.to_public();
            recipient.to_string()
        })
    }
}

/// Load existing identity or create a fresh one (generating a new keypair).
pub fn load_or_create_identity(config: &AgentConfig) -> anyhow::Result<AgentIdentity> {
    let path = Path::new(&config.identity_path);

    if path.exists() {
        let content = fs::read_to_string(path)?;
        let mut identity: AgentIdentity = toml::from_str(&content)?;

        // Backfill age identity for agents that existed before Tier 3-2 secret envelopes.
        // This is a one-time upgrade step; the new key is generated locally and never leaves the node.
        if identity.age_private_key.is_none() {
            let age_id = age::x25519::Identity::generate();
            // age returns Secret<String> (secrecy crate) for the private identity string to prevent accidental logging.
            identity.age_private_key = Some(age_id.to_string().expose_secret().as_bytes().to_vec());
            // Re-persist with secure perms so the upgrade is durable.
            let toml = toml::to_string_pretty(&identity)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?;
                file.write_all(toml.as_bytes())?;
                file.sync_all()?;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(path, perms)?;
            }
            #[cfg(not(unix))]
            {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?;
                file.write_all(toml.as_bytes())?;
                file.sync_all()?;
            }
            info!(
                "Backfilled age secret identity for existing agent (one-time upgrade for Tier 3-2)"
            );
        }

        info!(
            "Loaded existing agent identity from {}",
            config.identity_path
        );
        return Ok(identity);
    }

    // Fresh identity — generate keypair + dedicated age secret identity (Tier 3-2)
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let private_key = signing_key.to_bytes().to_vec();

    // Generate a fresh age X25519 identity for secret envelopes (Tier 3-2 baseline).
    // CP will encrypt secrets to the public recipient string ("age1...").
    // Only this agent can decrypt. Stored as the canonical AGE-SECRET-KEY-... string
    // (the recommended format from the age crate for persistence and tooling).
    let age_identity = age::x25519::Identity::generate();
    let age_identity_string = age_identity.to_string(); // "AGE-SECRET-KEY-1..." (Secret<String>)

    let identity = AgentIdentity {
        agent_id: None,
        private_key,
        control_plane_public_key: None,
        agent_token: None,
        enrolled_at: None,
        xds_client_cert_pem: None,
        xds_client_key_pem: None,
        xds_ca_cert_pem: None,
        age_private_key: Some(age_identity_string.expose_secret().as_bytes().to_vec()),
    };

    // Persist with secure permissions (0600 on Unix)
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let toml = toml::to_string_pretty(&identity)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(toml.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(toml.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    info!(
        "Generated new agent identity and wrote it to {} (0600)",
        config.identity_path
    );
    Ok(identity)
}

/// Perform enrollment against the control plane using a one-time token.
/// On success, updates the identity with data returned by the control plane and persists it.
pub async fn enroll_if_needed(
    config: &AgentConfig,
    identity: &mut AgentIdentity,
) -> anyhow::Result<()> {
    if identity.control_plane_public_key.is_some() && identity.agent_id.is_some() {
        // Already enrolled
        return Ok(());
    }

    let token = if !config.enrollment_token.is_empty() {
        config.enrollment_token.clone()
    } else if let Ok(env_token) = std::env::var("FORGE_AGENT_ENROLLMENT_TOKEN") {
        env_token
    } else {
        anyhow::bail!(
            "No enrollment token provided.\n\
             \n\
             To add this server to your Forge control plane:\n\
             1. Go to the Forge admin UI → Enrollment Tokens\n\
             2. Create a new token (one-time use recommended)\n\
             3. Run this agent again with the token:\n\
                FORGE_AGENT_ENROLLMENT_TOKEN=forge_... ./forge-agent\n\
             \n\
             Or set it in your config file under [agent] enrollment_token.\n\
             Full one-liner install script coming in docs."
        );
    };

    let enroll_url = format!(
        "{}/agent/enroll",
        config.control_plane_url.trim_end_matches('/')
    );

    info!("Starting agent enrollment at {}", enroll_url);

    let body = serde_json::json!({
        "enrollment_token": token,
        "agent_public_key": identity.signing_key()
            .map(|sk| sk.verifying_key().as_bytes().to_vec())
            .unwrap_or_default(),
        "age_recipient": identity.age_recipient(),
        "hostname": hostname::get().ok().map(|h| h.to_string_lossy().into_owned()),
    });

    let client = reqwest::Client::new();
    let resp = client.post(&enroll_url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Enrollment failed ({status}): {text}");
    }

    #[derive(serde::Deserialize)]
    struct EnrollResponse {
        agent_id: String,
        control_plane_public_key: Vec<u8>,
        agent_token: Option<String>,
        // Auto client certs for xDS mTLS (issued by control plane at enrollment time).
        xds_client_cert_pem: Option<String>,
        xds_client_key_pem: Option<String>,
        xds_ca_cert_pem: Option<String>,
    }

    let enroll_resp: EnrollResponse = resp.json().await?;

    identity.agent_id = Some(enroll_resp.agent_id);
    identity.control_plane_public_key = Some(enroll_resp.control_plane_public_key);
    identity.agent_token = enroll_resp.agent_token;
    identity.enrolled_at = Some(chrono::Utc::now().to_rfc3339());

    identity.xds_client_cert_pem = enroll_resp.xds_client_cert_pem;
    identity.xds_client_key_pem = enroll_resp.xds_client_key_pem;
    identity.xds_ca_cert_pem = enroll_resp.xds_ca_cert_pem;

    // Persist the updated identity securely
    let path = Path::new(&config.identity_path);
    let toml = toml::to_string_pretty(identity)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(toml.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(toml.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    info!(
        "Agent enrollment successful. Agent ID: {:?}",
        identity.agent_id
    );
    Ok(())
}
