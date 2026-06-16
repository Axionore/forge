//! Cloud-agnostic provider abstraction for Forge.
//!
//! This crate defines the [`CloudProvider`] trait and the shared, provider-neutral
//! data types it operates on. A provider implementation (e.g. `forge-provider-hetzner`)
//! maps these abstract resources onto a concrete cloud API. The trait is intentionally
//! shaped to map cleanly onto Hetzner, AWS, GCP, Azure, and `DigitalOcean`.
//!
//! Design notes:
//! - The trait is `async` via [`async_trait`] so it is object-safe (`Box<dyn CloudProvider>`),
//!   which the control plane needs to select a provider at runtime.
//! - Capabilities are advertised via [`Capabilities`] so callers can grey out unsupported
//!   features instead of discovering them through a failed call.
//! - Errors are a single typed [`ProviderError`]; providers must never leak raw API tokens
//!   into any error message.
//! - Multi-step operations that partially succeed surface
//!   [`ProviderError::PartialFailure`] carrying the IDs of resources that were created and
//!   should be cleaned up (or were left behind after a best-effort cleanup attempt).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Opaque, provider-scoped identifier for a resource.
///
/// Hetzner uses numeric IDs; AWS/GCP/Azure use strings. We normalize to a string so the
/// abstraction does not leak a provider's ID representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServerId(pub String);

impl ServerId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle status of a server, normalized across providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    Initializing,
    Starting,
    Running,
    Stopping,
    Off,
    Deleting,
    Rebuilding,
    Migrating,
    Unknown,
}

/// A request to provision a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSpec {
    /// Human-readable, provider-unique name.
    pub name: String,
    /// Provider size/type identifier (e.g. Hetzner `cx22`). Resolve via [`CloudProvider::list_sizes`].
    pub size: String,
    /// Image identifier (e.g. Hetzner `ubuntu-24.04`).
    pub image: String,
    /// Region/location identifier (e.g. Hetzner `fsn1`).
    pub region: String,
    /// Cloud-init user data injected at first boot.
    pub user_data: Option<String>,
    /// SSH key IDs (provider-scoped) to inject.
    pub ssh_key_ids: Vec<String>,
    /// Network IDs to attach at creation, if the provider supports it.
    pub network_ids: Vec<String>,
    /// Firewall IDs to apply at creation, if the provider supports it.
    pub firewall_ids: Vec<String>,
    /// Free-form labels/tags applied to the resource.
    pub labels: BTreeMap<String, String>,
}

/// Snapshot of a server's current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: ServerId,
    pub name: String,
    pub status: ServerStatus,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub private_ips: Vec<String>,
    pub region: String,
    pub size: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
}

/// Traffic direction for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// L4 protocol for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

/// A single firewall rule. `port_range` is `None` for ICMP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: Direction,
    pub protocol: Protocol,
    /// e.g. `"443"` or `"8000-8080"`. `None` for protocols without ports (ICMP).
    pub port_range: Option<String>,
    /// Source CIDRs (for `In`) or destination CIDRs (for `Out`).
    pub cidrs: Vec<String>,
}

/// A region/location offered by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub id: String,
    pub name: String,
    pub country: Option<String>,
    pub city: Option<String>,
}

/// A server size/type offered by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeInfo {
    pub id: String,
    pub description: String,
    pub vcpus: u32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    /// Region IDs where this size is currently orderable (empty = unknown/all).
    pub available_regions: Vec<String>,
}

/// An OS/application image offered by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub os_flavor: Option<String>,
    pub os_version: Option<String>,
}

/// A private network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub ip_range: String,
}

/// A block storage volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub id: String,
    pub name: String,
    pub size_gb: u64,
    pub region: String,
    /// Server this volume is attached to, if any.
    pub attached_to: Option<ServerId>,
    /// Device path on the attached server (e.g. `/dev/disk/by-id/...`), if known.
    pub linux_device: Option<String>,
}

/// A load-balancer service mapping (listener -> targets' port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbService {
    pub protocol: Protocol,
    pub listen_port: u16,
    pub target_port: u16,
    /// Path used for HTTP health checks, if applicable.
    pub health_check_path: Option<String>,
}

/// A target attached to a load balancer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbTarget {
    pub server_id: ServerId,
    /// Route over the private network rather than the public IP.
    pub use_private_ip: bool,
}

/// A load balancer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerInfo {
    pub id: String,
    pub name: String,
    pub public_ipv4: Option<String>,
    pub region: String,
    pub services: Vec<LbService>,
    pub targets: Vec<LbTarget>,
}

/// DNS record types supported by the abstraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
    Mx,
    Caa,
    Ns,
}

/// A DNS record within a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Provider record ID, populated on reads / after upsert.
    pub id: Option<String>,
    pub zone_id: String,
    pub record_type: DnsRecordType,
    /// Record name relative to the zone (e.g. `@`, `www`).
    pub name: String,
    pub value: String,
    pub ttl: Option<u32>,
}

/// What a provider can do. A `false`/empty field means the corresponding trait methods
/// will return [`ProviderError::NotImplemented`] for that provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[allow(clippy::struct_excessive_bools)] // intentional capability bitset, not a state machine
pub struct Capabilities {
    pub servers: bool,
    pub ssh_keys: bool,
    pub networks: bool,
    pub firewalls: bool,
    pub floating_ips: bool,
    pub volumes: bool,
    pub load_balancers: bool,
    pub dns: bool,
    pub resize: bool,
    pub rebuild: bool,
}

impl Capabilities {
    /// All capabilities disabled — the correct value for a not-yet-implemented provider.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            servers: false,
            ssh_keys: false,
            networks: false,
            firewalls: false,
            floating_ips: false,
            volumes: false,
            load_balancers: false,
            dns: false,
            resize: false,
            rebuild: false,
        }
    }
}

/// Errors a provider may return. Providers MUST NOT include API tokens in any variant.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The provider does not (yet) support this operation.
    #[error("operation not implemented for this provider")]
    NotImplemented,

    /// A structured API error returned by the provider.
    #[error("provider API error ({status}): {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },

    /// Transport-level failure (DNS, TLS, connection reset, body decode).
    #[error("HTTP transport error: {0}")]
    Http(String),

    /// The operation exceeded its deadline.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// The provider rate-limited the request. `retry_after_secs` is honored when present.
    #[error("rate limited by provider (retry after {retry_after_secs:?}s)")]
    RateLimited { retry_after_secs: Option<u64> },

    /// A requested resource was not found.
    #[error("resource not found: {0}")]
    NotFound(String),

    /// An asynchronous provider action ended in an error state.
    #[error("provider action failed: {0}")]
    ActionFailed(String),

    /// Caller supplied invalid input that the provider rejected before any side effect.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// A multi-step operation failed partway. The listed resource IDs were created during the
    /// attempt; the provider has made a best-effort attempt to tear them down. IDs that could
    /// not be cleaned up are reported so a caller (or operator) can finish the job.
    #[error("partial failure: {message}; leftover resources: {leftover_resource_ids:?}")]
    PartialFailure {
        message: String,
        /// Resources created during the failed attempt (and not successfully cleaned up).
        created_resource_ids: Vec<String>,
        /// Subset of `created_resource_ids` that cleanup could not remove.
        leftover_resource_ids: Vec<String>,
    },
}

/// Convenience result alias for provider operations.
pub type Result<T> = std::result::Result<T, ProviderError>;

/// A cloud-agnostic provider. Implementations map these operations onto a concrete cloud API.
///
/// Methods for capabilities the provider lacks must return [`ProviderError::NotImplemented`].
/// Mutating operations should be effectively idempotent where the underlying API allows it
/// (e.g. [`CloudProvider::ensure_ssh_key`]).
#[async_trait::async_trait]
pub trait CloudProvider: Send + Sync {
    // --- catalog ---

    /// What this provider supports. Callers should consult this before invoking a method.
    fn capabilities(&self) -> Capabilities;

    async fn list_regions(&self) -> Result<Vec<RegionInfo>>;
    async fn list_sizes(&self) -> Result<Vec<SizeInfo>>;
    async fn list_images(&self) -> Result<Vec<ImageInfo>>;

    // --- servers ---

    /// Provision a server. On a multi-step failure, returns [`ProviderError::PartialFailure`]
    /// after a best-effort cleanup of resources created during the attempt.
    async fn provision_server(&self, spec: &ServerSpec) -> Result<ServerInfo>;
    async fn get_server(&self, id: &ServerId) -> Result<ServerInfo>;
    async fn list_servers(&self) -> Result<Vec<ServerInfo>>;
    async fn delete_server(&self, id: &ServerId) -> Result<()>;
    /// Resize a server to a new size. `upgrade_disk` permanently grows the disk when `true`.
    async fn resize_server(&self, id: &ServerId, new_size: &str, upgrade_disk: bool) -> Result<()>;
    async fn rebuild_server(&self, id: &ServerId, image: &str) -> Result<()>;

    // --- ssh keys ---

    /// Create the key if absent (matched by name or fingerprint), otherwise return the existing
    /// key's ID. Idempotent.
    async fn ensure_ssh_key(&self, name: &str, public_key: &str) -> Result<String>;
    async fn list_ssh_keys(&self) -> Result<Vec<(String, String)>>;
    async fn delete_ssh_key(&self, id: &str) -> Result<()>;

    // --- networks ---

    async fn create_network(&self, name: &str, ip_range: &str) -> Result<NetworkInfo>;
    async fn delete_network(&self, id: &str) -> Result<()>;
    async fn list_networks(&self) -> Result<Vec<NetworkInfo>>;
    async fn attach_server_to_network(&self, server: &ServerId, network_id: &str) -> Result<()>;

    // --- firewalls ---

    async fn create_firewall(&self, name: &str, rules: &[FirewallRule]) -> Result<String>;
    async fn delete_firewall(&self, id: &str) -> Result<()>;
    async fn attach_firewall(&self, firewall_id: &str, server: &ServerId) -> Result<()>;
    async fn detach_firewall(&self, firewall_id: &str, server: &ServerId) -> Result<()>;

    // --- IPs ---

    /// Allocate a floating/primary IP. Returns `(ip_id, address)`.
    async fn allocate_ip(&self, region: &str, ipv6: bool) -> Result<(String, String)>;
    async fn assign_ip(&self, ip_id: &str, server: &ServerId) -> Result<()>;
    async fn release_ip(&self, ip_id: &str) -> Result<()>;

    // --- volumes ---

    async fn create_volume(&self, name: &str, size_gb: u64, region: &str) -> Result<VolumeInfo>;
    async fn attach_volume(&self, volume_id: &str, server: &ServerId) -> Result<()>;
    async fn detach_volume(&self, volume_id: &str) -> Result<()>;
    async fn resize_volume(&self, volume_id: &str, new_size_gb: u64) -> Result<()>;
    async fn delete_volume(&self, volume_id: &str) -> Result<()>;

    // --- load balancers ---

    async fn create_load_balancer(
        &self,
        name: &str,
        region: &str,
        services: &[LbService],
    ) -> Result<LoadBalancerInfo>;
    async fn delete_load_balancer(&self, id: &str) -> Result<()>;
    async fn add_lb_target(&self, lb_id: &str, target: &LbTarget) -> Result<()>;
    async fn remove_lb_target(&self, lb_id: &str, server: &ServerId) -> Result<()>;
    async fn update_lb_service(&self, lb_id: &str, service: &LbService) -> Result<()>;

    // --- dns (often a separate API/credential) ---

    /// Ensure a zone exists for `domain`, returning its zone ID.
    async fn dns_ensure_zone(&self, domain: &str) -> Result<String>;
    /// Create or update a record (matched by name + type within the zone). Returns the record ID.
    async fn dns_upsert_record(&self, record: &DnsRecord) -> Result<String>;
    async fn dns_delete_record(&self, zone_id: &str, record_id: &str) -> Result<()>;
    async fn dns_list_records(&self, zone_id: &str) -> Result<Vec<DnsRecord>>;
}
