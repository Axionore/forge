//! Job types and execution logic for the Forge agent.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export the rich spec types from forge-core (Phase 1 Slice A).
// This must be early so the Job enum below can use DeploymentSpec, BuildSpec,
// RegistryAuth, etc. by name.
pub use forge_core::spec::*;
pub use forge_core::supplychain::SupplyChainPolicy;

use std::io::{Read, Write};

use age::x25519::{Identity as AgeIdentity, Recipient as AgeRecipient};

/// Error type for the secret-envelope cryptography (age X25519 + ChaCha20-Poly1305).
///
/// Kept deliberately coarse: we never surface key material, recipient strings, or
/// plaintext through `Display` (OWASP A09). The variants carry only a category so
/// callers can log a category and fail closed.
#[derive(Debug, thiserror::Error)]
pub enum SecretCryptoError {
    #[error("no valid recipients supplied")]
    NoRecipients,
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    #[error("malformed recipient")]
    BadRecipient,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

/// Encrypt `plaintext` to one armored age envelope readable by ANY of `recipients`
/// (multi-recipient X25519). Returns a [`SecretCiphertext`] whose `payload` is the
/// ASCII-armored age ciphertext as a UTF-8 string — the exact shape the control
/// plane persists in JSONB and the agent reads back in [`decrypt_secret`].
///
/// Security:
/// - Armored (ASCII) output so it round-trips losslessly through JSON/Postgres text.
/// - Multi-recipient: every enrolled agent recipient can open the SAME ciphertext,
///   so we never store one blob per agent (and never re-encrypt on the hot path).
/// - Fails closed if no recipient parses (we refuse to emit an unencrypted blob).
/// - No key material or plaintext is ever logged or placed in the error.
pub fn encrypt_secret_for_recipients(
    plaintext: &[u8],
    recipients: &[String],
) -> Result<SecretCiphertext, SecretCryptoError> {
    if recipients.is_empty() {
        return Err(SecretCryptoError::NoRecipients);
    }

    // Parse every "age1..." recipient string. Skip malformed ones individually but
    // require at least one valid recipient (fail-closed if all are bad).
    let mut parsed: Vec<Box<dyn age::Recipient + Send>> = Vec::with_capacity(recipients.len());
    for r in recipients {
        match r.parse::<AgeRecipient>() {
            Ok(rec) => parsed.push(Box::new(rec)),
            Err(_) => continue,
        }
    }
    if parsed.is_empty() {
        return Err(SecretCryptoError::BadRecipient);
    }

    let encryptor =
        age::Encryptor::with_recipients(parsed).ok_or(SecretCryptoError::NoRecipients)?;

    // Armor so the ciphertext is valid UTF-8 and survives JSON/Postgres text columns.
    let mut armored = Vec::new();
    {
        let armor_writer =
            age::armor::ArmoredWriter::wrap_output(&mut armored, age::armor::Format::AsciiArmor)
                .map_err(|_| SecretCryptoError::Encrypt)?;
        let mut writer = encryptor
            .wrap_output(armor_writer)
            .map_err(|_| SecretCryptoError::Encrypt)?;
        writer
            .write_all(plaintext)
            .map_err(|_| SecretCryptoError::Encrypt)?;
        // First finish() flushes the age stream; it returns the ArmoredWriter which
        // we must also finish() to emit the closing armor footer.
        let armor_writer = writer.finish().map_err(|_| SecretCryptoError::Encrypt)?;
        armor_writer
            .finish()
            .map_err(|_| SecretCryptoError::Encrypt)?;
    }

    let payload = String::from_utf8(armored).map_err(|_| SecretCryptoError::Encrypt)?;

    Ok(SecretCiphertext {
        version: SecretCiphertext::VERSION_AGE_V1.to_string(),
        // The `recipient` field is informational (which recipient set this was sealed
        // for); the actual file stanzas inside the armor carry the real recipients.
        // We record the first valid recipient for audit/debug, never a private key.
        recipient: recipients
            .iter()
            .find(|r| r.parse::<AgeRecipient>().is_ok())
            .cloned()
            .unwrap_or_default(),
        payload,
    })
}

/// Decrypt a [`SecretCiphertext`] using this agent's age `identity`. Reads the
/// ASCII-armored payload produced by [`encrypt_secret_for_recipients`] and returns
/// the recovered plaintext bytes. Fails closed on version mismatch, malformed
/// armor, or a key that is not among the envelope's recipients.
pub fn decrypt_secret(
    ciphertext: &SecretCiphertext,
    identity: &AgeIdentity,
) -> Result<Vec<u8>, SecretCryptoError> {
    if ciphertext.version != SecretCiphertext::VERSION_AGE_V1 {
        return Err(SecretCryptoError::UnsupportedVersion);
    }

    let armored = ciphertext.payload.as_bytes();
    let armor_reader = age::armor::ArmoredReader::new(armored);
    let decryptor =
        match age::Decryptor::new(armor_reader).map_err(|_| SecretCryptoError::Decrypt)? {
            age::Decryptor::Recipients(d) => d,
            // Passphrase-based envelopes are never produced by this system.
            age::Decryptor::Passphrase(_) => return Err(SecretCryptoError::Decrypt),
        };

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| SecretCryptoError::Decrypt)?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| SecretCryptoError::Decrypt)?;

    Ok(plaintext)
}

#[cfg(test)]
mod secret_crypto_tests {
    use super::*;

    #[test]
    fn round_trips_multi_recipient() {
        let id_a = AgeIdentity::generate();
        let id_b = AgeIdentity::generate();
        let recips = vec![id_a.to_public().to_string(), id_b.to_public().to_string()];

        let ct = encrypt_secret_for_recipients(b"hunter2", &recips).unwrap();
        assert_eq!(ct.version, SecretCiphertext::VERSION_AGE_V1);

        // BOTH recipients can open the SAME ciphertext.
        assert_eq!(decrypt_secret(&ct, &id_a).unwrap(), b"hunter2");
        assert_eq!(decrypt_secret(&ct, &id_b).unwrap(), b"hunter2");
    }

    #[test]
    fn wrong_identity_fails_closed() {
        let id = AgeIdentity::generate();
        let stranger = AgeIdentity::generate();
        let ct = encrypt_secret_for_recipients(b"secret", &[id.to_public().to_string()]).unwrap();
        assert!(decrypt_secret(&ct, &stranger).is_err());
    }

    #[test]
    fn empty_recipients_is_rejected() {
        assert!(matches!(
            encrypt_secret_for_recipients(b"x", &[]),
            Err(SecretCryptoError::NoRecipients)
        ));
    }

    #[test]
    fn bad_version_is_rejected() {
        let id = AgeIdentity::generate();
        let mut ct = encrypt_secret_for_recipients(b"x", &[id.to_public().to_string()]).unwrap();
        ct.version = "bogus".into();
        assert!(matches!(
            decrypt_secret(&ct, &id),
            Err(SecretCryptoError::UnsupportedVersion)
        ));
    }
}

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
    Stop { target: ResourceTarget },

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
    InteractiveStdin { session_id: String, data: Vec<u8> },

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
    ContainerTop { target: String },

    /// Inspect a volume.
    InspectVolume { name: String },

    /// Prune unused volumes.
    PruneVolumes { filters: Vec<(String, Vec<String>)> },

    /// Inspect a network.
    InspectNetwork { name: String, verbose: Option<bool> },

    /// Prune unused networks.
    PruneNetworks { filters: Vec<(String, Vec<String>)> },

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
        database: Option<String>, // specific DB name, or all if None
        /// Optional S3-compatible destination. If present, agent uploads the dump.
        /// Credentials are passed securely in the signed job (in production they would be short-lived).
        s3: Option<S3BackupConfig>,
    },

    /// Execute a build from source (Git + Dockerfile or buildpack) and produce a container image.
    /// This is the core of Phase 4 Source-to-Deploy. The agent reports back the final image
    /// reference via JobResultDetails::Build so the control plane can then dispatch a normal
    /// Deploy job using that image.
    Build {
        build_id: Uuid,
        /// What to build. The source (git url + pinned commit SHA), builder, output image,
        /// build args, and build secrets all live on the `BuildSpec` (Phase B).
        spec: BuildSpec,
        /// Target image reference to tag the result with (control plane decides the name/tag).
        /// This is the same as `spec.target_image()`; carried explicitly for the result
        /// correlation and so the control plane can dispatch a Deploy without re-deriving it.
        target_image: String,
        /// Optional registry auth for push (if the target_image requires it).
        #[serde(default)]
        registry_auth: Option<RegistryAuth>,
        /// Supply-chain enforcement policy (Phase C). Resolved by the control plane from the
        /// app/global setting and whether a cosign key is configured. Governs whether the agent
        /// signs + attests the produced image. Defaults to the strict policy when absent so an
        /// old/tampered job without this field does not silently skip signing.
        #[serde(default)]
        supply_chain_policy: SupplyChainPolicy,
    },
}

// (The re-export of spec types from forge-core is at the top of this file for
// visibility to the Job enum and other items.)

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
    /// Result of a Build job (Phase B source-to-deploy). The control plane records the
    /// image + digest and, on success, dispatches a Deploy using this image. On failure
    /// `success` is false and `error_message` carries a sanitized reason (no secrets).
    Build {
        success: bool,
        /// Fully-qualified image reference the build produced/tagged.
        image: Option<String>,
        /// Image digest (`sha256:...`) recorded after the build, if resolvable.
        image_digest: Option<String>,
        /// Whether the image was pushed to the configured registry.
        pushed: bool,
        /// Whether the image was cosign-signed + provenance-attested (Phase C). When false under
        /// a signing policy the control plane treats the build as supply-chain-incomplete.
        #[serde(default)]
        signed: bool,
        /// Compact, non-secret SLSA provenance summary (subject digest + commit + builder) for
        /// the `builds.provenance` column and the audit chain. `None` when signing was off/failed.
        #[serde(default)]
        provenance: Option<serde_json::Value>,
        /// Sanitized failure reason (never contains secrets or host paths).
        error_message: Option<String>,
    },
    Generic {
        message: String,
    },
}
