//! Job types and execution logic for the Forge agent.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A job that has been signed by the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedJob {
    pub job: Job,
    /// Ed25519 signature over the serialized `job`
    pub signature: Vec<u8>,
}

/// The actual work the agent is being asked to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Job {
    /// Deploy or update containers (normal user workloads)
    Deploy {
        deployment_id: Uuid,
        spec: DeploymentSpec,
    },

    /// Execute a system update on this agent (part of "Update Forge")
    SystemUpdate {
        update_id: Uuid,
        version: String,
        /// URL or content-addressable reference to the new agent binary
        binary_ref: String,
        /// SHA256 of the new binary
        binary_sha256: String,
    },

    /// Stop / remove resources
    Stop {
        target: ResourceTarget,
    },

    /// Run a one-off command inside a container (debug, migration helper, etc.)
    Exec {
        /// Target container name or ID to exec into.
        target_container: Option<String>,
        command: Vec<String>,
        working_dir: Option<String>,
        /// Optional user to run the exec as (e.g. "root" or "1000:1000").
        user: Option<String>,
        /// Extra environment variables for the exec process ("KEY=val").
        env: Vec<String>,
        /// Allocate a pseudo-TTY for the exec session.
        tty: Option<bool>,
        /// Run the exec with extended privileges (dangerous, use with care).
        privileged: Option<bool>,
        /// Attach stdin to the exec (for interactive sessions).
        attach_stdin: Option<bool>,
        /// For interactive web terminal use: a correlation ID that allows the control plane
        /// to associate this exec with a live WS session for bidirectional I/O streaming.
        /// When present, the agent will keep the exec attached and support live stdin/stdout.
        #[serde(default)]
        interactive_session_id: Option<String>,
    },

    /// Write raw bytes to the stdin of an active interactive PTY/exec session (used by web terminal).
    InteractiveStdin {
        session_id: String,
        data: Vec<u8>,
    },

    /// Health check / metrics collection
    HealthCheck,

    /// Live update of a running container (resources, restart policy, etc.) without stop/start.
    /// Critical for zero-downtime tuning and HA updates.
    UpdateContainer {
        /// Container name or ID to update in place.
        target: String,
        /// Resource limits to apply (reuses the rich ContainerResources model).
        resources: Option<ContainerResources>,
        /// New restart policy (e.g. "always", "on-failure:5", "unless-stopped").
        restart_policy: Option<String>,
    },

    /// Deeper dynamic L7 traffic update for Envoy sidecar (xDS-style live weight change).
    /// Dispatched on statistical canary promotion to shift traffic on the *running* sidecar
    /// without a full container recreate or full Deploy re-execution. Enables true progressive
    /// rollout with minimal disruption.
    UpdateL7Config {
        deployment_id: Uuid,
        /// Desired canary weight (0-100); main receives 100 - this value.
        canary_weight: u32,
        /// Optional explicit envoy container name (otherwise agent discovers via labels).
        envoy_container: Option<String>,
        /// Optional pre-built full envoy.yaml (if absent, agent regenerates minimal weighted config).
        envoy_config_yaml: Option<String>,
    },

    /// Stream or fetch container logs (advanced observability / debugging).
    ContainerLogs {
        target: String,
        /// Follow the log stream (like -f).
        follow: Option<bool>,
        /// Only return this number of lines from the end.
        tail: Option<String>, // "all" or a number as string
        /// Show timestamps.
        timestamps: Option<bool>,
        /// Only logs since this time (RFC3339 or Unix timestamp as string).
        since: Option<String>,
        /// Only logs before this time.
        until: Option<String>,
        /// Include stdout.
        stdout: Option<bool>,
        /// Include stderr.
        stderr: Option<bool>,
    },

    /// Resize a TTY exec session.
    ResizeExec {
        exec_id: String,
        width: u16,
        height: u16,
    },

    /// Resize the TTY of a running container.
    ResizeContainer {
        target: String,
        width: u16,
        height: u16,
    },

    /// List processes inside a container (like `docker top`).
    ContainerTop {
        target: String,
    },

    /// Inspect a volume.
    InspectVolume {
        name: String,
    },

    /// Prune unused volumes.
    PruneVolumes {
        filters: Vec<(String, Vec<String>)>,
    },

    /// Inspect a network.
    InspectNetwork {
        name: String,
        verbose: Option<bool>,
    },

    /// Prune unused networks.
    PruneNetworks {
        filters: Vec<(String, Vec<String>)>,
    },

    /// Full hijack attach to a container (stdin/stdout/stderr streaming with full control).
    ContainerAttach {
        target: String,
        stdin: Option<bool>,
        stdout: Option<bool>,
        stderr: Option<bool>,
        stream: Option<bool>,
        logs: Option<bool>,
        detach_keys: Option<String>,
    },

    /// Database / volume backup (logical dump + optional S3 upload).
    /// This is the core of first-class backup/restore for catalog services (Postgres, etc.).
    Backup {
        deployment_id: Uuid,
        target_container: String,
        /// "postgres", "mysql", "mongodb" etc. (v1 focuses on postgres via pg_dump)
        db_type: String,
        database: Option<String>,           // specific DB name, or all if None
        /// Optional S3-compatible destination. If present, agent uploads the dump.
        /// Credentials are passed securely in the signed job (in production they would be short-lived).
        s3: Option<S3BackupConfig>,
    },
}

/// Configuration for uploading a backup to S3-compatible storage (MinIO, Hetzner, AWS, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BackupConfig {
    pub endpoint: String,      // e.g. "https://s3.example.com" or MinIO URL
    pub bucket: String,
    pub key: String,           // object key (can include timestamp)
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    /// Region for AWS-style signing (optional for pure S3-compatible)
    pub region: Option<String>,
}

/// Rich network definition for advanced creation (driver, IPAM, internal, attachable, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSpec {
    pub name: String,
    pub driver: Option<String>,
    pub internal: Option<bool>,
    pub attachable: Option<bool>,
    pub ingress: Option<bool>,
    pub enable_ipv6: Option<bool>,
    pub options: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
    pub ipam: Option<IpamConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpamConfig {
    pub driver: Option<String>,
    pub config: Vec<IpamPool>,
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpamPool {
    pub subnet: Option<String>,
    pub ip_range: Option<String>,
    pub gateway: Option<String>,
    pub aux_addresses: Vec<(String, String)>,
}

/// What to deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSpec {
    pub containers: Vec<ContainerSpec>,
    /// Simple network names (backward compatible, created with defaults).
    pub networks: Vec<String>,
    /// Rich network specifications for advanced creation (driver, IPAM, internal, attachable, labels, ipv6, etc.).
    /// When present, these take precedence for creation and the simple `networks` names are still attached.
    pub network_specs: Vec<NetworkSpec>,
    pub volumes: Vec<VolumeSpec>,

    /// Multi-registry credentials (keyed by registry hostname or "https://index...").
    /// When present, sent as X-Registry-Config header for pulls involving multiple private registries.
    pub registry_credentials: Vec<(String, RegistryAuth)>,

    /// Tier 2: Optional build step (buildpack or dockerfile) performed by the agent before running containers.
    /// Enables source-to-image deployments without pre-built images.
    pub build: Option<BuildSpec>,

    /// Tier 3-2: Secrets to inject into containers (env vars or files).
    /// Each SecretRef contains an age-encrypted ciphertext (encrypted for this agent's recipient or the deployment's targets).
    /// The agent decrypts at deploy time using its local age identity and injects via env or secure tmpfs bind mount (never persisted on host disk beyond container lifetime).
    #[serde(default)]
    pub secrets: Vec<SecretRef>,

    /// Optional Git checkout for source builds from private repos using SSH (wired in Tier 3 SSH feature).
    #[serde(default)]
    pub git_checkout: Option<GitCheckout>,
}

/// Build specification for Tier 2 buildpack parity (and future Dockerfile builds).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildSpec {
    /// "buildpack" | "dockerfile" (dockerfile support is thin v1 - mainly for compatibility).
    pub r#type: String,
    /// For buildpack: the builder image, e.g. "paketobuildpacks/builder-jammy-full".
    pub builder: Option<String>,
    /// Build-time environment variables (BP_* for Paketo, etc.).
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

/// Git checkout configuration for private repo builds using SSH keys (Tier 3 SSH feature).
/// When present with a matching SSH secret in `secrets`, the agent will perform
/// a secure shallow clone using the injected key before running containers or builds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitCheckout {
    pub url: String,
    pub r#ref: String, // branch, tag, or commit
    /// Name of the SecretRef in this spec whose File target contains the SSH private key.
    pub ssh_key_secret_name: Option<String>,
}

/// Simplified container spec (will grow significantly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub env: Vec<(String, String)>,

    // Ports
    pub ports: Vec<String>,           // Published ports
    pub expose: Vec<String>,          // Exposed (not published)

    // Storage
    pub volumes: Vec<String>,
    pub tmpfs: Vec<String>,

    // Basic runtime
    pub restart_policy: Option<String>,
    pub user: Option<String>,
    pub working_dir: Option<String>,

    // Resources
    pub resources: Option<ContainerResources>,

    // Configs & Secrets
    pub configs: Vec<ConfigMount>,

    // Networking & DNS
    pub extra_hosts: Vec<String>,
    pub dns: Vec<String>,
    pub dns_options: Vec<String>,
    pub dns_search: Vec<String>,
    pub links: Vec<String>,

    // Security
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub privileged: Option<bool>,
    pub read_only: Option<bool>,
    pub masked_paths: Vec<String>,
    pub readonly_paths: Vec<String>,

    // Advanced
    pub devices: Vec<DeviceMapping>,
    pub ulimits: Vec<Ulimit>,
    pub sysctls: Vec<(String, String)>,
    pub group_add: Vec<String>,
    pub shm_size: Option<i64>,
    pub ipc_mode: Option<String>,
    pub pid_mode: Option<String>,
    pub init: Option<bool>,
    pub stop_signal: Option<String>,
    pub stop_timeout: Option<i64>,
    pub auto_remove: Option<bool>,
    pub cgroup_parent: Option<String>,
    pub blkio_weight: Option<u16>,
    pub blkio_weight_device: Vec<WeightDevice>,
    pub blkio_device_read_bps: Vec<ThrottleDevice>,
    pub blkio_device_write_bps: Vec<ThrottleDevice>,
    pub blkio_device_read_iops: Vec<ThrottleDevice>,
    pub blkio_device_write_iops: Vec<ThrottleDevice>,
    pub pids_limit: Option<i64>,
    pub runtime: Option<String>,
    pub isolation: Option<String>,
    pub cgroupns_mode: Option<String>,
    pub cpu_rt_period: Option<i64>,
    pub cpu_rt_runtime: Option<i64>,
    pub memory_swappiness: Option<i64>,
    pub oom_kill_disable: Option<bool>,
    pub oom_score_adj: Option<i64>,
    pub device_cgroup_rules: Vec<String>,
    pub storage_opt: Vec<(String, String)>,

    // Logging
    pub log_driver: Option<String>,
    pub log_opts: Vec<(String, String)>,

    /// Custom healthcheck configuration (overrides any default).
    pub healthcheck: Option<HealthcheckConfig>,

    // Even more advanced / power-user Docker options
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub hostname: Option<String>,
    pub domainname: Option<String>,
    pub mac_address: Option<String>,
    pub network_disabled: Option<bool>,
    pub uts_mode: Option<String>,
    pub userns_mode: Option<String>,
    pub volumes_from: Vec<String>,
    pub volume_driver: Option<String>,
    pub stdin_open: Option<bool>,
    pub tty: Option<bool>,
    pub attach_stdin: Option<bool>,
    pub attach_stdout: Option<bool>,
    pub attach_stderr: Option<bool>,

    /// Shell to use for the container (for shell-form CMD/ENTRYPOINT).
    pub shell: Option<Vec<String>>,

    /// Initial console size as [height, width] for TTY containers.
    pub console_size: Option<Vec<i32>>,

    /// Network aliases to apply when connecting this container to networks (service discovery).
    pub network_aliases: Vec<String>,

    /// Per-endpoint IPv4 address for this container on attached networks (advanced IPAM).
    pub network_ipv4_address: Option<String>,

    /// Per-endpoint IPv6 address for this container on attached networks.
    pub network_ipv6_address: Option<String>,

    /// Links to other containers on the network (e.g. "othercontainer:alias").
    pub network_links: Vec<String>,

    /// MAC address to assign on the network endpoint.
    pub network_mac_address: Option<String>,

    /// Annotations (key-value, newer Docker feature).
    pub annotations: Vec<(String, String)>,

    // === Newly added advanced power-user fields (this pass) ===
    /// Network mode: "bridge", "host", "none", "container:<name|id>", or custom network name.
    pub network_mode: Option<String>,
    /// Close stdin after the first client disconnects.
    pub stdin_once: Option<bool>,

    /// Modern Mounts API (preferred over raw volume strings for bind propagation, SELinux, tmpfs sizing, subpath, etc.).
    pub mounts: Vec<MountSpec>,

    /// Device requests (GPU, InfiniBand, etc.). Enables `--gpus all` and advanced device plugin requests.
    pub device_requests: Vec<DeviceRequest>,

    /// Platform for image pull + container creation (e.g. "linux/amd64", "linux/arm64/v8").
    /// Critical for correct multi-arch deployments and self-update of the agent itself.
    pub platform: Option<String>,

    /// Optional registry credentials for private image pulls.
    /// When present, used as the credentials parameter to bollard create_image (X-Registry-Auth).
    pub registry_auth: Option<RegistryAuth>,
}

/// Custom healthcheck definition (maps closely to Docker's healthcheck).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthcheckConfig {
    /// Command to run for the healthcheck.
    /// First element is usually "CMD" or "CMD-SHELL".
    pub test: Vec<String>,

    /// Time between running the check (in nanoseconds).
    pub interval: Option<i64>,

    /// Maximum time to allow one check to run (in nanoseconds).
    pub timeout: Option<i64>,

    /// Start period for the container to initialize before starting health-retries countdown (in nanoseconds).
    pub start_period: Option<i64>,

    /// Start interval between health checks during the start period (Docker API 1.44+).
    pub start_interval: Option<i64>,

    /// Number of consecutive failures needed to consider the container as unhealthy.
    pub retries: Option<i64>,
}

/// Weight device for blkio.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WeightDevice {
    pub path: String,
    pub weight: Option<u16>,
    pub leaf_weight: Option<u16>,
}

/// Throttle device for blkio (bps or iops).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThrottleDevice {
    pub path: String,
    pub rate: Option<i64>,
}

/// Resource constraints for a container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerResources {
    /// Memory limit in bytes (soft limit).
    pub memory: Option<i64>,
    /// Memory + swap limit in bytes.
    pub memory_swap: Option<i64>,
    /// Memory soft reservation (Docker will try to keep at least this much available).
    pub memory_reservation: Option<i64>,
    /// CPU shares (relative weight, 0-1024 typical).
    pub cpu_shares: Option<i64>,
    /// CPU quota in microseconds per period (for hard limits).
    pub cpu_quota: Option<i64>,
    /// CPU period in microseconds.
    pub cpu_period: Option<i64>,
    /// CPUs in which to allow execution (e.g. "0-3", "0,1") — cpuset-cpus.
    pub cpuset_cpus: Option<String>,
    /// Memory nodes (MEMs) in which to allow execution (0-3, 0,1) — cpuset-mems.
    pub cpuset_mems: Option<String>,
    /// CPU quota in units of 10^-9 CPUs (nano_cpus). Mutually exclusive with some other CPU settings.
    pub nano_cpus: Option<i64>,
    /// Hard limit for kernel TCP buffer memory (in bytes). Often ignored by default runtimes.
    pub kernel_memory_tcp: Option<i64>,
}

/// Mount for a config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMount {
    /// Name or source of the config.
    pub source: String,
    /// Target path inside the container.
    pub target: String,
    /// Optional file mode (e.g. 0o600).
    pub mode: Option<u32>,
}

/// Ulimit definition (e.g. nofile, nproc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ulimit {
    pub name: String,
    pub soft: i64,
    pub hard: i64,
}

/// Device mapping for `--device`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMapping {
    pub path_on_host: String,
    pub path_in_container: String,
    pub cgroup_permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub name: String,
    /// Optional driver (defaults to "local")
    pub driver: Option<String>,
    pub driver_opts: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceTarget {
    Container { id: String },
    ComposeProject { name: String },
}

/// Modern mount definition (maps to Docker's Mounts API).
/// Supports bind, volume, tmpfs, and advanced options that raw "volumes" strings cannot express cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountSpec {
    /// "bind" | "volume" | "tmpfs" | "npipe" | "cluster"
    pub mount_type: String,
    pub source: Option<String>,
    pub target: String,
    pub read_only: Option<bool>,
    /// Mount consistency (for Mac/Windows): "default", "consistent", "cached", "delegated"
    pub consistency: Option<String>,
    /// Bind propagation: "private" | "rprivate" | "shared" | "rshared" | "slave" | "rslave"
    pub propagation: Option<String>,
    /// SELinux relabeling: "z" (shared) or "Z" (private)
    pub selinux: Option<String>,
    /// For tmpfs mounts only
    pub tmpfs_options: Option<TmpfsMountOptions>,
    /// For volume mounts only
    pub volume_options: Option<VolumeMountOptions>,
    /// Subpath inside the volume (Docker 1.45+)
    pub subpath: Option<String>,
}

/// Tmpfs-specific mount tuning.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TmpfsMountOptions {
    pub size: Option<i64>,   // bytes
    pub mode: Option<i64>,   // file mode as i64 (octal)
}

/// Volume mount driver options + labels.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VolumeMountOptions {
    pub no_copy: Option<bool>,
    pub subpath: Option<String>,
    pub driver_config: Option<DriverConfig>,
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriverConfig {
    pub name: Option<String>,
    pub options: Vec<(String, String)>,
}

/// Device request (for GPUs and other plugins).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRequest {
    pub driver: Option<String>,
    /// Number of devices to request (use -1 or omit + device_ids for "all")
    pub count: Option<i64>,
    pub device_ids: Vec<String>,
    /// Capabilities, e.g. `[["gpu"]]` or `[["compute", "utility"]]`
    pub capabilities: Vec<Vec<String>>,
    pub options: Vec<(String, String)>,
}

// Rich network/volume creation specs + the enhanced HealthcheckConfig (with start_interval) are already defined above.
// Per-container network_mode, Mounts API, and DeviceRequest (GPU etc.) are the major new advanced surface added in this pass.

/// Serializable registry credentials for private image pulls.
/// Maps directly to bollard::auth::DockerCredentials at execution time.
/// Supports the common cases: username+password, or pre-encoded auth token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryAuth {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Base64 encoded "username:password" or identity token.
    pub auth: Option<String>,
    pub email: Option<String>,
    /// Registry hostname, e.g. "registry.example.com:5000" or "https://index.docker.io/v1/"
    pub serveraddress: Option<String>,
    pub identitytoken: Option<String>,
    pub registrytoken: Option<String>,
}

/// ========================================================================
/// Tier 3-2: Secret envelope & reference types (production baseline)
/// ========================================================================
///
/// Design goals (OWASP A04 / A09 / ASVS L2 + minimal-trust model):
/// - Control plane NEVER stores or sees plaintext secret values.
/// - All secrets at rest (DB + in-flight signed Jobs) are age-encrypted ciphertexts.
/// - Baseline is fully self-hosted: no external KMS required. Agent's long-term
///   Ed25519 identity (already enrolled + 0600-protected) is converted to an
///   X25519 recipient for age. CP encrypts to that recipient; only that agent
///   (or agents sharing the same identity material in a cluster) can decrypt.
/// - Later tiers can add KMS-backed recipients (AWS KMS, Vault transit, etc.)
///   via age plugins without changing the wire/DB format.
/// - Versioned envelope so we can rotate algorithms or add per-secret ACLs later.
/// - Secrets are referenced by name + target (env var or file mount). The actual
///   ciphertext travels with the DeploymentSpec in the signed Job (or can be
///   referenced by ID for stored secrets in future).
/// - Never log values. All secret material is redacted in logs, UI, and error
///   paths (see A09 baseline).
///
/// Threat model notes (STRIDE, performed during 2a inventory):
/// - Information disclosure: mitigated by age AEAD + agent-only private key.
/// - Tampering: age provides integrity; any modification fails decryption.
/// - Elevation: agent only ever decrypts secrets that were explicitly attached
///   to a DeploymentSpec it was authorized (via signed job) to run.
/// - Repudiation: all secret operations (create/rotate/use) go through audited
///   CP paths + JobResult correlation.
/// - No plaintext ever crosses the trust boundary from CP to agent except
///   inside the encrypted envelope the agent alone can open.
///
/// Format choice: age crate (X25519 + ChaCha20-Poly1305 or future AEAD).
/// The age "recipient" is derived from the agent's Ed25519 public key at
/// enrollment time (standard conversion exists). The CP stores only the
/// resulting age recipient string + the ciphertext blob.
///
/// This file defines the stable types. Actual encrypt/decrypt lives in
/// agent (decrypt + inject) and api (encrypt when building jobs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    /// Logical name the user/application uses (e.g. "DATABASE_URL", "API_KEY").
    pub name: String,
    /// Where to deliver the decrypted secret inside the container.
    pub target: SecretTarget,
    /// The encrypted payload (age armor or raw bytes).
    /// For small secrets we embed the ciphertext directly in the Job.
    /// For very large or highly-sensitive values we can later add an ID
    /// reference to a CP-managed secret store (still age-encrypted at rest).
    pub ciphertext: SecretCiphertext,
}

/// Delivery target for a decrypted secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretTarget {
    /// Inject as environment variable (most common).
    Env { var: String },
    /// Mount as a file (recommended for large values or tools that read files).
    /// Path is relative to the container (e.g. "/run/secrets/db-password").
    /// Agent will create a tmpfs mount (0600, owned by container user) and
    /// write the plaintext only into that file for the lifetime of the container.
    File { path: String, mode: Option<u32> }, // default 0400
}

/// Versioned ciphertext wrapper so we can evolve the envelope format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretCiphertext {
    /// Envelope format version. "age-v1" for the initial baseline using the
    /// age crate with X25519 recipient derived from the agent's Ed25519 pubkey.
    pub version: String,
    /// The age recipient (public key) this blob was encrypted for.
    /// Stored so the receiving agent can quickly decide "this is for me".
    pub recipient: String,
    /// The actual age-encrypted payload (armored or binary).
    /// For the MVP we use armored ASCII for easy debugging/auditing in the DB.
    pub payload: String,
}

impl SecretCiphertext {
    pub const VERSION_AGE_V1: &'static str = "age-v1";
}

/// Extend DeploymentSpec with first-class secrets (additive, backward compatible).
/// Existing env fields continue to work for non-secret values.
/// New secrets: Vec<SecretRef> will be processed by the agent at deploy time:
///   1. Decrypt each using its local age identity.
///   2. Inject into the bollard Config (env) or create tmpfs + mount (file).
///   3. Never write plaintext to disk or logs.
impl DeploymentSpec {
    /// Returns true if this spec contains any secret references that must be
    /// decrypted by the target agent(s) before container creation.
    pub fn has_secrets(&self) -> bool {
        // When we wire the field into the struct this will be real.
        // For now the method exists so call sites can start using it.
        false
    }
}

// NOTE: The actual `secrets: Vec<SecretRef>` field will be added to
// DeploymentSpec and ContainerSpec in the next micro-slice (2d/2e) once
// the encrypt/decrypt + injection paths are ready. Adding it now would
// require coordinated changes across job creation, UI, and catalog.
// We declare the types here so the format is frozen and reviewed early.

/// Encrypts a secret value for one or more age recipients (public "age1..." strings).
/// Returns a versioned SecretCiphertext ready to embed in a DeploymentSpec / Job.
///
/// This is the control-plane side of the Tier 3-2 envelope.
/// Never logs plaintext. Fails closed on any crypto error.
pub fn encrypt_secret_for_recipients(
    plaintext: &[u8],
    recipients: &[String],
) -> anyhow::Result<SecretCiphertext> {
    if recipients.is_empty() {
        anyhow::bail!("encrypt_secret_for_recipients called with no recipients");
    }

    let age_recipients: Vec<age::x25519::Recipient> = recipients
        .iter()
        .filter_map(|r| r.parse::<age::x25519::Recipient>().ok())
        .collect();

    if age_recipients.is_empty() {
        anyhow::bail!("no valid age recipients provided");
    }

    let boxed_recipients: Vec<Box<dyn age::Recipient + Send + 'static>> = age_recipients
        .into_iter()
        .map(|r| Box::new(r) as Box<dyn age::Recipient + Send + 'static>)
        .collect();

    let encryptor = age::Encryptor::with_recipients(boxed_recipients)
        .ok_or_else(|| anyhow::anyhow!("failed to create age encryptor"))?;

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    use std::io::Write;
    writer.write_all(plaintext)?;
    writer.finish()?;

    // For v1 we store the first recipient as the hint (in practice deployments target specific agents).
    // Future versions can carry a list.
    let primary_recipient = recipients[0].clone();

    Ok(SecretCiphertext {
        version: SecretCiphertext::VERSION_AGE_V1.to_string(),
        recipient: primary_recipient,
        payload: String::from_utf8(encrypted)?, // age armor output is UTF-8 safe
    })
}

/// Decrypts a SecretCiphertext using the agent's local age identity.
/// Returns the original plaintext or an error (never partial data).
///
/// This runs on the agent at deploy time, right before container creation.
/// The resulting bytes are injected via env or tmpfs and then forgotten.
pub fn decrypt_secret(
    cipher: &SecretCiphertext,
    identity: &age::x25519::Identity,
) -> anyhow::Result<Vec<u8>> {
    if cipher.version != SecretCiphertext::VERSION_AGE_V1 {
        anyhow::bail!("unsupported secret envelope version: {}", cipher.version);
    }

    let decryptor = age::Decryptor::new(cipher.payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid age ciphertext: {}", e))?;

    // age 0.10 API (from the crate docs): match on Recipients variant, then call decrypt on the inner.
    let recipients_decryptor = match decryptor {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => anyhow::bail!("secret envelope is passphrase-encrypted (not supported)"),
    };

    let mut reader = recipients_decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("age decryption failed (wrong key or tampered data?): {}", e))?;

    let mut plaintext = vec![];
    std::io::Read::read_to_end(&mut reader, &mut plaintext)?;

    Ok(plaintext)
}

/// Structured result of a job execution, sent back to the control plane for
/// observability, auditing, and UI updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Best-effort correlation id (deployment_id, update_id, exec target, etc.)
    pub correlation_id: String,
    pub job_type: String, // "deploy", "exec", "health_check", "update_container", "container_logs", etc.
    pub success: bool,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: i64,
    pub details: JobResultDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobResultDetails {
    Deploy {
        created_containers: Vec<String>,
        warnings: Vec<String>,
    },
    Exec {
        exit_code: Option<i64>,
        stdout: String,
        stderr: String,
    },
    HealthCheck {
        containers_checked: usize,
        // Rich stats can be added here later
    },
    UpdateContainer {
        applied: bool,
        warnings: Vec<String>,
    },
    ContainerLogs {
        lines_captured: usize,
    },
    ContainerTop {
        processes: usize,
    },
    VolumePrune {
        volumes_deleted: Option<Vec<String>>,
    },
    NetworkPrune {
        networks_deleted: Option<Vec<String>>,
    },
    Attach {
        // Attach is mostly streaming; we can report summary on close
        bytes_written: u64,
    },
    /// Result of a Backup job (logical dump + optional S3 upload).
    Backup {
        success: bool,
        size_bytes: Option<u64>,
        /// S3 key or local volume path where the backup was stored.
        location: Option<String>,
        /// Short log excerpt or error details for UI.
        message: Option<String>,
        db_type: String,
    },
    Generic {
        message: String,
    },
}