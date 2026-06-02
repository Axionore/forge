//! Rich, serializable deployment specification types.
//!
//! These types define exactly what the agent will execute for a `Job::Deploy`.
//! They are the source of truth for container configuration, secrets (age-encrypted),
//! networking, resources, healthchecks, and advanced Docker options.
//!
//! Moved here from `crates/agent/src/job.rs` in Phase 1 (Slice A) so both the
//! control plane and the agent depend on the same definitions. This eliminates
//! duplication and makes the control plane able to construct and reason about
//! rich specs without going through the agent crate.
//!
//! All types are pure data + serde. No runtime dependencies (bollard, tokio, etc.).
//! The agent is still responsible for turning these into actual Docker calls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for uploading a backup to S3-compatible storage (MinIO, Hetzner, AWS, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BackupConfig {
    pub endpoint: String,
    pub bucket: String,
    pub key: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
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

/// Source-to-deploy build specification (Phase B).
///
/// A `BuildSpec` fully describes one build: where the source comes from (git, pinned
/// to a commit SHA), how it is built ([`Builder`]), what the output image is named, and
/// any build-time arguments / secrets. It is pure data + serde — the agent's build
/// executor turns it into Docker/BuildKit calls.
///
/// Security (threat-model `specs/threat-model-source-to-deploy.md`):
/// - `build_secrets` are [`SecretRef`]s (age envelopes). They are decrypted on the agent
///   to a tmpfs file and exposed to the build ONLY via BuildKit `--secret` (never as a
///   build ARG/ENV that would persist in an image layer).
/// - `build_args` are NOT secret — they are visible in `docker history`. The control
///   plane must never route secret material through `build_args`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSpec {
    /// Where the source comes from. Reuses [`GitCheckout`], which now carries the
    /// resolved commit SHA the build is pinned to.
    pub source: GitCheckout,

    /// Which builder to run.
    pub builder: Builder,

    /// Output image repository/name (e.g. `registry.example.com/app`). The tag is in
    /// [`Self::image_tag`]; the agent combines them as `image_name:image_tag`.
    pub image_name: String,

    /// Output image tag (e.g. a short commit SHA). Defaults to `latest` if empty.
    #[serde(default)]
    pub image_tag: String,

    /// Optional registry host the image will be pushed to. When `None` the image stays
    /// local to the build agent (still usable by a same-host Deploy).
    #[serde(default)]
    pub registry: Option<String>,

    /// Non-secret build-time arguments. Visible in `docker history` — never secrets.
    #[serde(default)]
    pub build_args: HashMap<String, String>,

    /// Build-time secrets (age-encrypted). Injected via BuildKit `--secret`, never baked
    /// into a layer. Each secret's [`SecretRef::name`] is the BuildKit secret `id`.
    #[serde(default)]
    pub build_secrets: Vec<SecretRef>,
}

impl BuildSpec {
    /// The fully-qualified target image reference the agent tags and (optionally) pushes.
    pub fn target_image(&self) -> String {
        let tag = if self.image_tag.is_empty() {
            "latest"
        } else {
            &self.image_tag
        };
        match &self.registry {
            Some(reg) if !reg.is_empty() => format!("{reg}/{}:{tag}", self.image_name),
            _ => format!("{}:{tag}", self.image_name),
        }
    }
}

/// The build strategy. Tagged so the wire format is explicit and forward-compatible.
///
/// Builder matrix (Phase B):
/// - [`Builder::Dockerfile`] — fully implemented (BuildKit, supports build secrets).
/// - [`Builder::Nixpacks`] — implemented via the `nixpacks` CLI; fails closed with a
///   clear, actionable error if the binary is absent.
/// - [`Builder::Compose`] — implemented via `docker compose build`; rejects unsafe
///   Compose directives (privileged / host bind-mounts / docker-socket mounts).
/// - [`Builder::Buildpack`] — SCAFFOLD ONLY. Returns a clear "not yet implemented" error
///   at execution time (no silent fake). Wired so the type and API exist; the Paketo
///   lifecycle integration is deliberately deferred (see spec parity matrix: ⏭ scaffold).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Builder {
    /// Build from a Dockerfile via BuildKit. Fully working, supports build secrets.
    Dockerfile {
        /// Path to the Dockerfile, relative to the build context. Defaults to `Dockerfile`.
        #[serde(default)]
        dockerfile_path: Option<String>,
        /// Build context directory, relative to the checked-out repo root. Defaults to `.`.
        #[serde(default)]
        context: Option<String>,
        /// Optional target stage for multi-stage builds (`--target`).
        #[serde(default)]
        target: Option<String>,
    },

    /// Build via the Nixpacks CLI (auto-detects language/framework).
    Nixpacks {
        /// Subdirectory of the repo to build, relative to the repo root. Defaults to `.`.
        #[serde(default)]
        context: Option<String>,
        /// Optional explicit start command override (`--start-cmd`).
        #[serde(default)]
        start_cmd: Option<String>,
    },

    /// Build via `docker compose build`.
    Compose {
        /// Path to the compose file, relative to the repo root (e.g. `docker-compose.yml`).
        file: String,
    },

    /// SCAFFOLD: Cloud Native Buildpacks (Paketo). Not yet implemented — see [`Builder`] docs.
    Buildpack {
        /// The builder image that would be used (e.g. `paketobuildpacks/builder-jammy-base`).
        #[serde(default)]
        builder_image: Option<String>,
    },
}

/// Git checkout configuration. Reused by both the Deploy SSH-clone path (Tier 3) and the
/// Phase B build executor.
///
/// For builds, `commit_sha` MUST be set: the build executor checks out the repo and then
/// resets HARD to this exact commit, so the build is pinned and reproducible (threat-model
/// Tampering mitigation — no floating refs at build time). `r#ref` is the human-facing
/// branch/tag the SHA was resolved from.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitCheckout {
    pub url: String,
    pub r#ref: String,
    pub ssh_key_secret_name: Option<String>,
    /// Resolved, pinned commit SHA the build is fetched at. Required for builds.
    #[serde(default)]
    pub commit_sha: Option<String>,
    /// Optional subdirectory within the repo to treat as the build root.
    #[serde(default)]
    pub subdir: Option<String>,
}

/// Serializable registry credentials for private image pulls.
/// Maps directly to bollard::auth::DockerCredentials at execution time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryAuth {
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth: Option<String>,
    pub email: Option<String>,
    pub serveraddress: Option<String>,
    pub identitytoken: Option<String>,
    pub registrytoken: Option<String>,
}

// ========================================================================
// Tier 3-2: Secret envelope & reference types (production baseline)
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    pub name: String,
    pub target: SecretTarget,
    pub ciphertext: SecretCiphertext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretTarget {
    Env { var: String },
    File { path: String, mode: Option<u32> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretCiphertext {
    pub version: String,
    pub recipient: String,
    pub payload: String,
}

impl SecretCiphertext {
    pub const VERSION_AGE_V1: &'static str = "age-v1";
}

/// What to deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSpec {
    pub containers: Vec<ContainerSpec>,
    pub networks: Vec<String>,
    pub network_specs: Vec<NetworkSpec>,
    pub volumes: Vec<VolumeSpec>,

    pub registry_credentials: Vec<(String, RegistryAuth)>,

    pub build: Option<BuildSpec>,

    #[serde(default)]
    pub secrets: Vec<SecretRef>,

    #[serde(default)]
    pub git_checkout: Option<GitCheckout>,

    /// Supply-chain enforcement policy for this deployment (Phase C). Threaded from the control
    /// plane so the agent knows whether to verify images before running them. Defaults to the
    /// strict policy when absent (a tampered/old spec without this field still fails closed if
    /// it carries [`Self::verify_images`]).
    #[serde(default)]
    pub supply_chain_policy: crate::supplychain::SupplyChainPolicy,

    /// Image digest references (`name@sha256:...`) that the agent MUST cosign-verify before
    /// running, when the policy requires verification. These are exactly the images Forge built
    /// and signed; an externally-supplied `image:` not built by Forge is governed by the policy,
    /// not forced into this list. Empty → nothing to verify.
    #[serde(default)]
    pub verify_images: Vec<String>,
}

/// Simplified container spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub env: Vec<(String, String)>,

    // Ports
    pub ports: Vec<String>,
    pub expose: Vec<String>,

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
    pub pre_stop: Option<Vec<String>>,
    pub drain_grace_seconds: Option<u64>,
    pub is_stateful: Option<bool>,
    pub stateful_health_plugins: Vec<String>,
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

    // Labels for canary / L7 routing
    pub labels: HashMap<String, String>,
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

    pub shell: Option<Vec<String>>,
    pub console_size: Option<Vec<i32>>,
    pub network_aliases: Vec<String>,
    pub network_ipv4_address: Option<String>,
    pub network_ipv6_address: Option<String>,
    pub network_links: Vec<String>,
    pub network_mac_address: Option<String>,
    pub annotations: Vec<(String, String)>,

    pub network_mode: Option<String>,
    pub stdin_once: Option<bool>,

    pub mounts: Vec<MountSpec>,
    pub device_requests: Vec<DeviceRequest>,

    pub platform: Option<String>,

    pub registry_auth: Option<RegistryAuth>,
}

/// Custom healthcheck definition (maps closely to Docker's healthcheck).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthcheckConfig {
    pub test: Vec<String>,
    pub interval: Option<i64>,
    pub timeout: Option<i64>,
    pub start_period: Option<i64>,
    pub start_interval: Option<i64>,
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
    pub memory: Option<i64>,
    pub memory_swap: Option<i64>,
    pub memory_reservation: Option<i64>,
    pub cpu_shares: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<i64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub nano_cpus: Option<i64>,
    pub kernel_memory_tcp: Option<i64>,
}

/// Mount for a config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMount {
    pub source: String,
    pub target: String,
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
    pub driver: Option<String>,
    pub driver_opts: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
}

/// Modern mount definition (maps to Docker's Mounts API).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountSpec {
    pub mount_type: String,
    pub source: Option<String>,
    pub target: String,
    pub read_only: Option<bool>,
    pub consistency: Option<String>,
    pub propagation: Option<String>,
    pub selinux: Option<String>,
    pub tmpfs_options: Option<TmpfsMountOptions>,
    pub volume_options: Option<VolumeMountOptions>,
    pub subpath: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TmpfsMountOptions {
    pub size: Option<i64>,
    pub mode: Option<i64>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceTarget {
    Container { id: String },
    ComposeProject { name: String },
}

/// Device request (for GPUs and other plugins).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRequest {
    pub driver: Option<String>,
    pub count: Option<i64>,
    pub device_ids: Vec<String>,
    pub capabilities: Vec<Vec<String>>,
    pub options: Vec<(String, String)>,
}

#[cfg(test)]
mod build_spec_tests {
    use super::*;

    fn dockerfile_spec() -> BuildSpec {
        BuildSpec {
            source: GitCheckout {
                url: "https://github.com/acme/app.git".into(),
                r#ref: "main".into(),
                ssh_key_secret_name: None,
                commit_sha: Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".into()),
                subdir: None,
            },
            builder: Builder::Dockerfile {
                dockerfile_path: Some("Dockerfile".into()),
                context: Some(".".into()),
                target: None,
            },
            image_name: "registry.example.com/acme/app".into(),
            image_tag: "a1b2c3d".into(),
            registry: Some("registry.example.com".into()),
            build_args: HashMap::from([("RUST_VERSION".into(), "1.95".into())]),
            build_secrets: vec![],
        }
    }

    #[test]
    fn dockerfile_builder_round_trips() {
        let spec = dockerfile_spec();
        let json = serde_json::to_string(&spec).unwrap();
        // The builder is tagged, so the discriminant is explicit on the wire.
        assert!(json.contains(r#""type":"dockerfile""#));
        let back: BuildSpec = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.builder, Builder::Dockerfile { .. }));
        assert_eq!(back.image_name, spec.image_name);
    }

    #[test]
    fn each_builder_variant_tag_is_stable() {
        for (builder, tag) in [
            (
                Builder::Dockerfile {
                    dockerfile_path: None,
                    context: None,
                    target: None,
                },
                "dockerfile",
            ),
            (
                Builder::Nixpacks {
                    context: None,
                    start_cmd: None,
                },
                "nixpacks",
            ),
            (
                Builder::Compose {
                    file: "docker-compose.yml".into(),
                },
                "compose",
            ),
            (
                Builder::Buildpack {
                    builder_image: None,
                },
                "buildpack",
            ),
        ] {
            let json = serde_json::to_value(&builder).unwrap();
            assert_eq!(json["type"], tag, "tag for {builder:?} must be {tag}");
        }
    }

    #[test]
    fn target_image_composes_registry_name_and_tag() {
        let mut spec = dockerfile_spec();
        assert_eq!(
            spec.target_image(),
            "registry.example.com/registry.example.com/acme/app:a1b2c3d"
        );

        // No registry → name:tag only.
        spec.registry = None;
        spec.image_name = "app".into();
        spec.image_tag = "v1".into();
        assert_eq!(spec.target_image(), "app:v1");

        // Empty tag → latest.
        spec.image_tag = String::new();
        assert_eq!(spec.target_image(), "app:latest");
    }

    #[test]
    fn build_secrets_default_to_empty_when_absent() {
        // A minimal spec without the optional fields must still deserialize.
        let json = r#"{
            "source": { "url": "https://x/y.git", "ref": "main", "commit_sha": "abc123" },
            "builder": { "type": "nixpacks" },
            "image_name": "y"
        }"#;
        let spec: BuildSpec = serde_json::from_str(json).unwrap();
        assert!(spec.build_secrets.is_empty());
        assert!(spec.build_args.is_empty());
        assert_eq!(spec.image_tag, "");
        assert!(matches!(spec.builder, Builder::Nixpacks { .. }));
    }
}
