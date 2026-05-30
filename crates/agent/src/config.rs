//! Agent configuration.

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Control plane API base URL (e.g. https://forge.example.com)
    pub control_plane_url: String,

    /// Agent authentication token (short-lived, obtained during enrollment)
    pub agent_token: String,

    /// How often to send heartbeats (in seconds)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Enable Docker execution
    #[serde(default = "default_true")]
    pub enable_docker: bool,

    /// Docker socket path (usually /var/run/docker.sock)
    #[serde(default = "default_docker_socket")]
    pub docker_socket: String,

    /// Enable WireGuard mesh management
    #[serde(default)]
    pub enable_wireguard: bool,

    /// WireGuard interface name (e.g. "wg0")
    #[serde(default = "default_wg_interface")]
    pub wireguard_interface: String,

    /// This agent's WireGuard private key (base64). In production this should come from enrollment.
    #[serde(default)]
    pub wireguard_private_key: String,

    /// This agent's WireGuard listen port
    #[serde(default = "default_wg_port")]
    pub wireguard_listen_port: u16,

    /// Initial peers as "public_key@endpoint" strings (for bootstrap before full mesh sync).
    #[serde(default)]
    pub wireguard_peers: Vec<String>,

    /// Path to the agent's persistent identity file (contains private key + enrolled material).
    /// Created with 0600 permissions.
    #[serde(default = "default_identity_path")]
    pub identity_path: String,

    /// One-time enrollment token (can also be passed via FORGE_AGENT_ENROLLMENT_TOKEN env).
    /// Used only on first run / when no identity exists.
    #[serde(default)]
    pub enrollment_token: String,

    /// SSH port for providers that use SSH (Hetzner, DigitalOcean, bare metal, etc.).
    /// Default 22; override for hardened servers that use a non-standard port (e.g. 2222).
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_wg_interface() -> String {
    "wg0".to_string()
}

fn default_wg_port() -> u16 {
    51820
}

fn default_identity_path() -> String {
    "/var/lib/forge-agent/identity.toml".to_string()
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}

impl AgentConfig {
    pub fn from_env_and_file(path: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        let mut figment = Figment::new().merge(Env::prefixed("FORGE_AGENT_").split("_"));

        if let Some(p) = path {
            figment = figment.merge(Toml::file(p));
        }

        figment.extract().map_err(Box::new)
    }
}
