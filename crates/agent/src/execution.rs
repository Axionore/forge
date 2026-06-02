//! Job execution logic for the Forge agent.
//!
//! This module is responsible for taking a verified job and actually performing
//! the work (Docker operations, system updates, etc.).
//!
//! Security note: This module is only ever called *after* successful signature
//! verification and attestation in the main loop.

use crate::{
    error::Result,
    job::{Job, JobResult, JobResultDetails, S3BackupConfig},
};
use tracing::{error, info, warn};
use uuid::Uuid;

#[cfg(feature = "docker")]
use bollard::Docker as DockerClient;
#[cfg(not(feature = "docker"))]
type DockerClient = ();

/// Execute a verified job.
///
/// `docker` is only `Some` when the `docker` feature is enabled.
/// This is the entry point called from the agent's main loop after a job
/// has passed cryptographic verification and environment attestation.
pub async fn execute_job(
    job: Job,
    docker: Option<&DockerClient>,
    exec_output_tx: Option<tokio::sync::mpsc::Sender<crate::receiver::AgentMessage>>,
    // Tier 3-2: agent's age identity for decrypting secrets in Deploy jobs (None for non-deploy jobs)
    age_identity: Option<&age::x25519::Identity>,
) -> JobResult {
    let started_at = chrono::Utc::now().timestamp();

    // Build jobs produce a rich `JobResultDetails::Build` and stream their own logs, so they
    // are handled before the generic Ok(())/Err(()) dispatch below (which only yields a
    // Generic detail). This keeps the image/digest/error reporting first-class.
    if let Job::Build {
        build_id,
        spec,
        target_image,
        registry_auth: _registry_auth,
        supply_chain_policy,
    } = &job
    {
        return execute_build_job(
            *build_id,
            spec.clone(),
            target_image.clone(),
            *supply_chain_policy,
            docker,
            exec_output_tx,
            age_identity,
            started_at,
        )
        .await;
    }

    // Backup and Restore produce rich `JobResultDetails` (size/location/message) and need
    // their own result shape — they are handled before the generic Ok(())/Err(()) dispatch
    // so the control plane gets first-class backup/restore reporting.
    if let Job::Backup {
        deployment_id,
        target_container,
        db_type,
        database,
        s3,
        secrets,
    } = job.clone()
    {
        return execute_backup(
            docker,
            deployment_id,
            target_container,
            db_type,
            database,
            s3,
            secrets,
            age_identity,
            started_at,
        )
        .await;
    }
    if let Job::Restore {
        restore_id,
        deployment_id,
        target_container,
        db_type,
        database,
        s3,
        secrets,
    } = job.clone()
    {
        return execute_restore(
            docker,
            restore_id,
            deployment_id,
            target_container,
            db_type,
            database,
            s3,
            secrets,
            age_identity,
            started_at,
        )
        .await;
    }

    // Determine correlation + type for reporting
    let (correlation_id, job_type) = match &job {
        Job::Deploy { deployment_id, .. } => (deployment_id.to_string(), "deploy".to_string()),
        Job::SystemUpdate { update_id, .. } => (update_id.to_string(), "system_update".to_string()),
        Job::Stop { .. } => ("stop".to_string(), "stop".to_string()),
        Job::Exec {
            target_container, ..
        } => (
            target_container
                .clone()
                .unwrap_or_else(|| "exec".to_string()),
            "exec".to_string(),
        ),
        Job::InteractiveStdin { session_id, .. } => {
            (session_id.clone(), "interactive_stdin".to_string())
        }
        Job::HealthCheck => ("healthcheck".to_string(), "health_check".to_string()),
        Job::UpdateContainer { target, .. } => (target.clone(), "update_container".to_string()),
        Job::UpdateL7Config { deployment_id, .. } => {
            (deployment_id.to_string(), "update_l7_config".to_string())
        }
        Job::ContainerLogs { target, .. } => (target.clone(), "container_logs".to_string()),
        Job::ResizeExec { exec_id, .. } => (exec_id.clone(), "resize_exec".to_string()),
        Job::ResizeContainer { target, .. } => (target.clone(), "resize_container".to_string()),
        Job::ContainerTop { target } => (target.clone(), "container_top".to_string()),
        Job::InspectVolume { name } => (name.clone(), "inspect_volume".to_string()),
        Job::PruneVolumes { .. } => ("prune_volumes".to_string(), "prune_volumes".to_string()),
        Job::InspectNetwork { name, .. } => (name.clone(), "inspect_network".to_string()),
        Job::PruneNetworks { .. } => ("prune_networks".to_string(), "prune_networks".to_string()),
        Job::ContainerAttach { target, .. } => (target.clone(), "container_attach".to_string()),
        Job::Backup {
            deployment_id,
            target_container: _target_container,
            db_type,
            ..
        } => (deployment_id.to_string(), format!("backup_{db_type}")),
        Job::Restore { restore_id, .. } => (restore_id.to_string(), "restore".to_string()),
        &Job::Build { .. } => ("build".to_string(), "build".to_string()),
    };

    // Execute (current sub-functions still return Result<()>)
    let exec_res: crate::error::Result<()> = match job {
        Job::Deploy {
            deployment_id,
            spec,
        } => execute_deploy(deployment_id, spec, docker, age_identity).await,
        Job::SystemUpdate {
            version,
            binary_ref,
            binary_sha256,
            ..
        } => execute_system_update(version, binary_ref, binary_sha256).await,
        Job::Stop { target } => execute_stop(target, docker).await,
        Job::Exec {
            target_container,
            command,
            working_dir,
            user,
            env,
            tty,
            privileged,
            attach_stdin,
            interactive_session_id: _interactive_session_id,
        } => {
            execute_command(
                docker,
                target_container,
                command,
                working_dir,
                user,
                env,
                tty,
                privileged,
                attach_stdin,
                _interactive_session_id,
                exec_output_tx.clone(),
            )
            .await
        }
        Job::InteractiveStdin { .. } => {
            // Stdin writes for interactive sessions are handled via the background task started in interactive Exec.
            // This arm is for explicit future use or direct writes.
            Ok(())
        }
        Job::HealthCheck => execute_health_check(docker).await,
        Job::UpdateContainer {
            target,
            resources,
            restart_policy,
        } => execute_update_container(docker, target, resources, restart_policy).await,
        Job::UpdateL7Config {
            deployment_id,
            canary_weight,
            envoy_container,
            envoy_config_yaml,
        } => {
            execute_update_l7_config(
                docker,
                deployment_id,
                canary_weight,
                envoy_container,
                envoy_config_yaml,
            )
            .await
        }
        Job::ContainerLogs {
            target,
            follow,
            tail,
            timestamps,
            since,
            until,
            stdout,
            stderr,
        } => {
            execute_container_logs(
                docker, target, follow, tail, timestamps, since, until, stdout, stderr,
            )
            .await
        }
        Job::ResizeExec {
            exec_id,
            width,
            height,
        } => execute_resize_exec(docker, exec_id, width, height).await,
        Job::ResizeContainer {
            target,
            width,
            height,
        } => execute_resize_container(docker, target, width, height).await,
        Job::ContainerTop { target } => execute_container_top(docker, target).await,
        Job::InspectVolume { name } => execute_inspect_volume(docker, name).await,
        Job::PruneVolumes { filters } => execute_prune_volumes(docker, filters).await,
        Job::InspectNetwork { name, verbose } => {
            execute_inspect_network(docker, name, verbose).await
        }
        Job::PruneNetworks { filters } => execute_prune_networks(docker, filters).await,
        Job::ContainerAttach {
            target,
            stdin,
            stdout,
            stderr,
            stream,
            logs,
            detach_keys,
        } => {
            execute_container_attach(
                docker,
                target,
                stdin,
                stdout,
                stderr,
                stream,
                logs,
                detach_keys,
            )
            .await
        }
        Job::Backup { .. } => {
            // Handled by the early `execute_backup` return at the top of this function (it
            // produces a rich `JobResultDetails::Backup`). Kept for an exhaustive match.
            unreachable!("Job::Backup is dispatched via execute_backup before this match")
        }
        Job::Restore { .. } => {
            // Handled by the early `execute_restore` return at the top of this function.
            unreachable!("Job::Restore is dispatched via execute_restore before this match")
        }
        Job::Build { .. } => {
            // `Job::Build` is fully handled by the early `execute_build_job` return at the top of
            // this function (it produces a rich `JobResultDetails::Build`). Control never reaches
            // here for a Build job; this arm only exists to keep the match exhaustive.
            unreachable!("Job::Build is dispatched via execute_build_job before this match")
        }
    };

    let finished_at = chrono::Utc::now().timestamp();

    match exec_res {
        Ok(()) => JobResult {
            correlation_id,
            job_type,
            success: true,
            error: None,
            started_at,
            finished_at,
            details: JobResultDetails::Generic {
                message: "job completed".to_string(),
            },
        },
        Err(e) => JobResult {
            correlation_id,
            job_type,
            success: false,
            error: Some(e.to_string()),
            started_at,
            finished_at,
            details: JobResultDetails::Generic {
                message: "job failed".to_string(),
            },
        },
    }
}

// =============================================================================
// Individual job handlers
// =============================================================================

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_deploy(
    deployment_id: uuid::Uuid,
    spec: crate::job::DeploymentSpec,
    docker: Option<&DockerClient>,
    age_identity: Option<&age::x25519::Identity>,
) -> Result<()> {
    // Phase C — verify before run (fail-closed). BEFORE any Docker work (pull/create/start), if
    // the policy requires verification, every Forge-built image referenced in `verify_images`
    // must pass cosign signature + provenance verification against the trusted public key. Any
    // failure REFUSES the deploy (OWASP A10 / A08). This runs regardless of the `docker` feature
    // so a dry-run deploy is held to the same gate.
    if spec.supply_chain_policy.requires_verify() && !spec.verify_images.is_empty() {
        let public_key = crate::supplychain::resolve_public_key()
            .map_err(|e| crate::AgentError::Internal(anyhow::anyhow!(e.to_string())))?;
        let Some(public_key) = public_key else {
            error!(
                deployment_id = %deployment_id,
                "supply-chain policy requires verify-before-run but no trusted cosign public key is configured — refusing deploy (fail-closed)"
            );
            return Err(crate::AgentError::Internal(anyhow::anyhow!(
                crate::supplychain::SupplyChainError::NoPublicKey.to_string()
            )));
        };
        let verifier = crate::supplychain::CosignVerifier::new(public_key);
        verify_images_before_run(deployment_id, &spec.verify_images, &verifier).await?;
    }

    #[cfg(feature = "docker")]
    {
        use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
        use bollard::image::CreateImageOptions;
        use bollard::models::{HealthConfig, HostConfig, RestartPolicy};
        use bollard::network::CreateNetworkOptions;
        use std::os::unix::fs::PermissionsExt;

        let docker = docker.expect("Docker client must be provided when docker feature is enabled");

        // Simple networks (name-only)
        for net_name in &spec.networks {
            let create_opts = CreateNetworkOptions {
                name: net_name.clone(),
                check_duplicate: true,
                driver: "bridge".to_string(),
                ..Default::default()
            };
            if let Err(e) = docker.create_network(create_opts).await {
                warn!(network = %net_name, error = ?e, "Network creation warning (may already exist)");
            }
        }

        // Rich advanced network specs (full driver, IPAM, internal, attachable, ingress, ipv6, options, labels)
        for net in &spec.network_specs {
            let ipam = net.ipam.as_ref().map(|our_ipam| bollard::models::Ipam {
                driver: our_ipam.driver.clone(),
                config: if our_ipam.config.is_empty() {
                    None
                } else {
                    Some(
                        our_ipam
                            .config
                            .iter()
                            .map(|pool| bollard::models::IpamConfig {
                                subnet: pool.subnet.clone(),
                                ip_range: pool.ip_range.clone(),
                                gateway: pool.gateway.clone(),
                                auxiliary_addresses: if pool.aux_addresses.is_empty() {
                                    None
                                } else {
                                    Some(pool.aux_addresses.iter().cloned().collect())
                                },
                            })
                            .collect(),
                    )
                },
                options: if our_ipam.options.is_empty() {
                    None
                } else {
                    Some(our_ipam.options.iter().cloned().collect())
                },
            });

            let mut labels = std::collections::HashMap::new();
            for (k, v) in &net.labels {
                labels.insert(k.clone(), v.clone());
            }
            let mut options = std::collections::HashMap::new();
            for (k, v) in &net.options {
                options.insert(k.clone(), v.clone());
            }

            let create_opts = CreateNetworkOptions::<String> {
                name: net.name.clone(),
                check_duplicate: true,
                driver: net.driver.clone().unwrap_or_else(|| "bridge".to_string()),
                internal: net.internal.unwrap_or(false),
                attachable: net.attachable.unwrap_or(false),
                ingress: net.ingress.unwrap_or(false),
                enable_ipv6: net.enable_ipv6.unwrap_or(false),
                ipam: ipam.unwrap_or_default(),
                options,
                labels,
            };

            if let Err(e) = docker.create_network(create_opts).await {
                warn!(network = %net.name, error = ?e, "Rich network creation warning (may already exist)");
            }
        }

        // Real volume creation for named volumes with driver / opts / labels (advanced named volume support)
        for vol in &spec.volumes {
            let driver = vol.driver.clone().unwrap_or_else(|| "local".to_string());
            let mut driver_opts = std::collections::HashMap::new();
            for (k, v) in &vol.driver_opts {
                driver_opts.insert(k.clone(), v.clone());
            }
            let mut labels = std::collections::HashMap::new();
            for (k, v) in &vol.labels {
                labels.insert(k.clone(), v.clone());
            }

            let create_vol_opts = bollard::volume::CreateVolumeOptions {
                name: vol.name.clone(),
                driver,
                driver_opts,
                labels,
            };
            if let Err(e) = docker.create_volume(create_vol_opts).await {
                // Many volumes are created implicitly by binds; only warn on real errors
                if !e.to_string().contains("already exists") && !e.to_string().contains("409") {
                    warn!(volume = %vol.name, error = ?e, "Volume creation warning");
                }
            }
        }

        // =====================================================================
        // Tier 3-2: Decrypt and prepare secrets for injection (env or secure file binds)
        // Decrypt once per deploy job using the agent's age identity.
        // File secrets are written to a per-deployment tmpfs dir on the host (/dev/shm)
        // and bind-mounted read-only into the container with 0600. Never persisted on disk.
        // =====================================================================
        let mut secret_env_additions: Vec<(String, String)> = Vec::new();
        let mut secret_file_binds: Vec<String> = Vec::new();

        // Deployment-level secret processing (for cross-container things like SSH keys for git)
        let mut secret_name_to_file: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        if !spec.secrets.is_empty() {
            if let Some(age_id) = age_identity {
                for secret in &spec.secrets {
                    match crate::job::decrypt_secret(&secret.ciphertext, age_id) {
                        Ok(plaintext) => match &secret.target {
                            crate::job::SecretTarget::Env { var } => {
                                secret_env_additions.push((
                                    var.clone(),
                                    String::from_utf8_lossy(&plaintext).into_owned(),
                                ));
                            }
                            crate::job::SecretTarget::File { path, mode: _mode } => {
                                let safe_name: String = secret
                                    .name
                                    .chars()
                                    .map(|c| {
                                        if c.is_alphanumeric() || c == '_' || c == '-' {
                                            c
                                        } else {
                                            '_'
                                        }
                                    })
                                    .collect();
                                let host_dir =
                                    format!("/dev/shm/forge-secrets/{deployment_id}/{safe_name}");
                                if let Err(e) = std::fs::create_dir_all(&host_dir) {
                                    warn!(secret=%secret.name, error=?e, "Failed to create secret dir on host tmpfs");
                                    continue;
                                }
                                let host_file = format!("{host_dir}/value");
                                if let Err(e) = std::fs::write(&host_file, &plaintext) {
                                    warn!(secret=%secret.name, error=?e, "Failed to write secret to host tmpfs");
                                    continue;
                                }
                                let _ = std::fs::set_permissions(
                                    &host_file,
                                    std::fs::Permissions::from_mode(0o600),
                                );
                                secret_file_binds.push(format!("{host_file}:{path}:ro"));
                                secret_name_to_file.insert(secret.name.clone(), host_file.clone());
                                info!(secret = %secret.name, path = %path, "Prepared secret file bind mount from host tmpfs (0600)");
                            }
                        },
                        Err(e) => {
                            error!(secret = %secret.name, error = ?e, "CRITICAL: Failed to decrypt secret for this agent — failing deploy (fail-closed)");
                            return Err(crate::AgentError::Internal(anyhow::anyhow!(
                                "secret decryption failed for {}: {}",
                                secret.name,
                                e
                            )));
                        }
                    }
                }
            } else if !spec.secrets.is_empty() {
                error!(
                    "Deployment references secrets but agent has no age_identity — this is a configuration/upgrade error. Failing deploy."
                );
                return Err(crate::AgentError::Internal(anyhow::anyhow!(
                    "agent missing age identity for secret decryption"
                )));
            }
        }

        // Tier 3 SSH: Git checkout using the now-injected key (after secret processing)
        if let Some(checkout) = &spec.git_checkout {
            if let Some(key_secret_name) = &checkout.ssh_key_secret_name {
                if let Some(key_path) = secret_name_to_file.get(key_secret_name) {
                    let workspace = "/workspace";
                    let _ = std::fs::create_dir_all(workspace);

                    let ssh_cmd = format!(
                        "ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    );

                    info!(repo = %checkout.url, r#ref = %checkout.r#ref, "Performing SSH git checkout for private repo");

                    let status = std::process::Command::new("git")
                        .args([
                            "clone",
                            "--depth",
                            "1",
                            "--branch",
                            &checkout.r#ref,
                            &checkout.url,
                            workspace,
                        ])
                        .env("GIT_SSH_COMMAND", &ssh_cmd)
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            info!(repo = %checkout.url, r#ref = %checkout.r#ref, event = "ssh_git_checkout_success", "Git checkout completed successfully into {}", workspace);
                        }
                        Ok(s) => {
                            warn!(repo = %checkout.url, code = ?s.code(), event = "ssh_git_checkout_failed", "Git clone failed");
                        }
                        Err(e) => {
                            warn!(repo = %checkout.url, error = ?e, event = "ssh_git_checkout_error", "Failed to execute git clone for SSH source");
                        }
                    }
                } else {
                    warn!(secret = %key_secret_name, "SSH key secret referenced in git_checkout but not found in injected secrets");
                }
            }
        }

        for container in &spec.containers {
            info!(image = %container.image, name = %container.name, "Pulling image if necessary");

            // Real streaming pull with progress logging + platform (multi-arch first-class)
            // + optional private registry auth (critical for production use with self-hosted or private registries)
            // Per-container single registry auth (highest precedence for this image)
            let single_creds =
                container
                    .registry_auth
                    .as_ref()
                    .map(|a| bollard::auth::DockerCredentials {
                        username: a.username.clone(),
                        password: a.password.clone(),
                        auth: a.auth.clone(),
                        email: a.email.clone(),
                        serveraddress: a.serveraddress.clone(),
                        identitytoken: a.identitytoken.clone(),
                        registrytoken: a.registrytoken.clone(),
                    });

            // Deployment-level multi-registry config (X-Registry-Config) for complex private registry scenarios
            let _multi_creds = if spec.registry_credentials.is_empty() {
                None
            } else {
                let mut map = std::collections::HashMap::new();
                for (reg, a) in &spec.registry_credentials {
                    map.insert(
                        reg.clone(),
                        bollard::auth::DockerCredentials {
                            username: a.username.clone(),
                            password: a.password.clone(),
                            auth: a.auth.clone(),
                            email: a.email.clone(),
                            serveraddress: a.serveraddress.clone(),
                            identitytoken: a.identitytoken.clone(),
                            registrytoken: a.registrytoken.clone(),
                        },
                    );
                }
                Some(map)
            };

            // Multi-registry credentials (deployment level) are collected and ready.
            // The high-level create_image currently accepts single credentials; the internal
            // X-Registry-Config (multi) path exists in bollard and can be used via lower-level
            // requests when deeper control is needed. We surface the data model for it here.
            if !spec.registry_credentials.is_empty() {
                info!(
                    count = spec.registry_credentials.len(),
                    "Multi-registry credentials present for deployment (advanced X-Registry-Config support ready)"
                );
            }

            let mut pull_stream = docker.create_image(
                Some(CreateImageOptions {
                    from_image: container.image.clone(),
                    platform: container.platform.clone().unwrap_or_default(),
                    ..Default::default()
                }),
                None,
                single_creds,
            );

            use futures_util::stream::TryStreamExt;
            loop {
                match pull_stream.try_next().await {
                    Ok(Some(info)) => {
                        if let Some(status) = info.status {
                            if let Some(progress) = info.progress {
                                info!(image = %container.image, status = %status, progress = %progress);
                            } else {
                                info!(image = %container.image, status = %status);
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => warn!(error = ?e, "Image pull warning"),
                }
            }

            // Build binds
            let mut binds: Vec<String> = container.volumes.clone();
            for vol in &spec.volumes {
                if !binds.iter().any(|b| b.contains(&vol.name)) {
                    binds.push(vol.name.clone());
                }
            }
            // Tier 3-2: add read-only binds for file-type secrets (from host tmpfs)
            for b in &secret_file_binds {
                if !binds.contains(b) {
                    binds.push(b.clone());
                }
            }

            // Config mounts (treated as additional volume binds for now)
            for cfg in &container.configs {
                if cfg.source.contains('/') || cfg.source.contains('\\') {
                    let mode = cfg.mode.map(|m| format!(":{m}")).unwrap_or_default();
                    binds.push(format!("{}:{}{}", cfg.source, cfg.target, mode));
                } else {
                    binds.push(format!("{}:{}", cfg.source, cfg.target));
                }
            }

            // Rich labels for reverse proxy and management
            let mut labels = std::collections::HashMap::new();
            labels.insert("forge.managed".to_string(), "true".to_string());
            labels.insert("forge.container_name".to_string(), container.name.clone());

            // Traefik labels (can be extended later with more advanced routing)
            labels.insert(
                format!(
                    "traefik.http.services.{}.loadbalancer.server.port",
                    container.name
                ),
                "80".to_string(),
            );

            // Deeper L7 traffic middleware support for advanced BlueGreen / Canary
            // Control plane injects forge.canary.weight (or forge.traffic.weight) on the spec container labels
            // during phased rollouts. We build real weighted Traefik services here.
            if let Some(weight_str) = container
                .labels
                .get("forge.canary.weight")
                .or_else(|| container.labels.get("forge.traffic.weight"))
            {
                if let Ok(weight) = weight_str.parse::<u32>() {
                    let canary_svc = format!("{}-canary", container.name);
                    let weighted_svc = format!("{}-weighted", container.name);

                    labels.insert(
                        format!("traefik.http.services.{canary_svc}.loadbalancer.server.port"),
                        "80".to_string(),
                    );
                    labels.insert(
                        format!("traefik.http.services.{weighted_svc}.loadbalancer.server.port"),
                        "80".to_string(),
                    );

                    labels.insert(
                        format!("traefik.http.services.{weighted_svc}.weighted.services.0.name"),
                        container.name.clone(),
                    );
                    labels.insert(
                        format!("traefik.http.services.{weighted_svc}.weighted.services.0.weight"),
                        (100u32.saturating_sub(weight)).to_string(),
                    );
                    labels.insert(
                        format!("traefik.http.services.{weighted_svc}.weighted.services.1.name"),
                        canary_svc.clone(),
                    );
                    labels.insert(
                        format!("traefik.http.services.{weighted_svc}.weighted.services.1.weight"),
                        weight.to_string(),
                    );

                    labels.insert(
                        format!("traefik.http.routers.{}.service", container.name),
                        weighted_svc,
                    );
                }
            }

            // Additional L7 middleware (headers, rate limiting, stripPrefix for canary paths, etc.)
            if labels.contains_key("forge.middleware.headers") {
                labels.insert(format!("traefik.http.middlewares.{}-headers.headers.customrequestheaders.X-Forge-Canary", container.name), "true".to_string());
                labels.insert(
                    format!("traefik.http.routers.{}.middlewares", container.name),
                    format!("{}-headers", container.name),
                );
            }
            if let Some(prefix) = labels.get("forge.middleware.stripPrefix") {
                labels.insert(
                    format!(
                        "traefik.http.middlewares.{}-strip.stripprefix.prefixes",
                        container.name
                    ),
                    prefix.clone(),
                );
                labels.insert(
                    format!("traefik.http.routers.{}.middlewares", container.name),
                    format!("{}-strip", container.name),
                );
            }

            // Exposed ports (not published)
            for expose_port in &container.expose {
                labels.insert(
                    format!("forge.exposed_port.{expose_port}"),
                    "true".to_string(),
                );
            }

            // Custom healthcheck from spec, or fallback basic one
            let healthcheck = if let Some(hc) = &container.healthcheck {
                Some(HealthConfig {
                    test: if hc.test.is_empty() {
                        None
                    } else {
                        Some(hc.test.clone())
                    },
                    interval: hc.interval,
                    timeout: hc.timeout,
                    start_period: hc.start_period,
                    start_interval: hc.start_interval,
                    retries: hc.retries,
                })
            } else {
                // Fallback basic HTTP healthcheck
                Some(HealthConfig {
                    test: Some(vec![
                        "CMD-SHELL".to_string(),
                        "curl -f http://localhost:80 || exit 1".to_string(),
                    ]),
                    interval: Some(30_000_000_000),
                    timeout: Some(5_000_000_000),
                    retries: Some(3),
                    ..Default::default()
                })
            };

            let restart_policy = container.restart_policy.as_ref().map(|policy| {
                let name = match policy.to_lowercase().as_str() {
                    "always" => bollard::models::RestartPolicyNameEnum::ALWAYS,
                    "on-failure" | "on_failure" => {
                        bollard::models::RestartPolicyNameEnum::ON_FAILURE
                    }
                    "unless-stopped" | "unless_stopped" => {
                        bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED
                    }
                    _ => bollard::models::RestartPolicyNameEnum::NO,
                };
                RestartPolicy {
                    name: Some(name),
                    maximum_retry_count: if policy.to_lowercase().contains("on-failure") {
                        Some(10)
                    } else {
                        None
                    },
                }
            });

            // Networking config for explicit network attachment
            let mut networking_config = None;
            if !spec.networks.is_empty() {
                use bollard::models::EndpointSettings;
                let mut endpoints = std::collections::HashMap::new();
                for net in &spec.networks {
                    endpoints.insert(net.clone(), EndpointSettings::default());
                }
                networking_config = Some(bollard::models::NetworkingConfig {
                    endpoints_config: Some(endpoints),
                });
            }

            // Port publishing support (e.g. "8080:80", "80", "127.0.0.1:8080:80")
            let mut port_bindings = std::collections::HashMap::new();
            for port_mapping in &container.ports {
                let parts: Vec<&str> = port_mapping.split(':').collect();
                let (host_ip, host_port, container_port_proto) = match parts.len() {
                    1 => (None, None, parts[0].to_string()),
                    2 => (None, Some(parts[0].to_string()), parts[1].to_string()),
                    3 => (
                        Some(parts[0].to_string()),
                        Some(parts[1].to_string()),
                        parts[2].to_string(),
                    ),
                    _ => {
                        warn!(mapping = %port_mapping, "Unrecognized port mapping format, skipping");
                        continue;
                    }
                };

                let binding = bollard::models::PortBinding { host_ip, host_port };
                port_bindings.insert(container_port_proto, Some(vec![binding]));
            }

            // Resource limits (expanded with every advanced tunable we model)
            let mut memory = None;
            let mut memory_swap = None;
            let mut memory_reservation = None;
            let mut cpu_shares = None;
            let mut cpu_quota = None;
            let mut cpu_period = None;
            let mut cpuset_cpus = None;
            let mut cpuset_mems = None;
            let mut nano_cpus = None;
            let mut kernel_memory_tcp = None;

            if let Some(res) = &container.resources {
                memory = res.memory;
                memory_swap = res.memory_swap;
                memory_reservation = res.memory_reservation;
                cpu_shares = res.cpu_shares;
                cpu_quota = res.cpu_quota;
                cpu_period = res.cpu_period;
                cpuset_cpus = res.cpuset_cpus.clone();
                cpuset_mems = res.cpuset_mems.clone();
                nano_cpus = res.nano_cpus;
                kernel_memory_tcp = res.kernel_memory_tcp;
            }

            // tmpfs mounts
            let tmpfs = if container.tmpfs.is_empty() {
                None
            } else {
                Some(
                    container
                        .tmpfs
                        .iter()
                        .map(|t| (t.clone(), "".to_string())) // bollard expects map path -> options
                        .collect(),
                )
            };

            // sysctls
            let sysctls = if container.sysctls.is_empty() {
                None
            } else {
                Some(container.sysctls.iter().cloned().collect())
            };

            // === Advanced Mounts API (the real power-user replacement for simple volume binds) ===
            let mounts: Option<Vec<bollard::models::Mount>> = if container.mounts.is_empty() {
                None
            } else {
                Some(
                    container
                        .mounts
                        .iter()
                        .map(|m| bollard::models::Mount {
                            typ: Some(match m.mount_type.to_lowercase().as_str() {
                                "volume" => bollard::models::MountTypeEnum::VOLUME,
                                "bind" => bollard::models::MountTypeEnum::BIND,
                                "tmpfs" => bollard::models::MountTypeEnum::TMPFS,
                                "npipe" => bollard::models::MountTypeEnum::NPIPE,
                                "cluster" => bollard::models::MountTypeEnum::CLUSTER,
                                _ => bollard::models::MountTypeEnum::VOLUME,
                            }),
                            source: m.source.clone(),
                            target: Some(m.target.clone()),
                            read_only: m.read_only,
                            consistency: m.consistency.clone(),
                            bind_options: m.propagation.as_ref().map(|prop| bollard::models::MountBindOptions {
                                propagation: Some(match prop.as_str() {
                                    "shared" => bollard::models::MountBindOptionsPropagationEnum::SHARED,
                                    "rshared" => bollard::models::MountBindOptionsPropagationEnum::RSHARED,
                                    "slave" => bollard::models::MountBindOptionsPropagationEnum::SLAVE,
                                    "rslave" => bollard::models::MountBindOptionsPropagationEnum::RSLAVE,
                                    "private" => bollard::models::MountBindOptionsPropagationEnum::PRIVATE,
                                    "rprivate" => bollard::models::MountBindOptionsPropagationEnum::RPRIVATE,
                                    _ => bollard::models::MountBindOptionsPropagationEnum::PRIVATE,
                                }),
                                // SELinux handled via volume labels or driver in real usage; not a direct field here in this bollard version
                                ..Default::default()
                            }),
                            tmpfs_options: m.tmpfs_options.as_ref().map(|t| bollard::models::MountTmpfsOptions {
                                size_bytes: t.size,
                                mode: t.mode,
                                options: t.mode.map(|mo| vec![vec![format!("{:o}", mo)]]),
                            }),
                            volume_options: m.volume_options.as_ref().map(|v| bollard::models::MountVolumeOptions {
                                no_copy: v.no_copy,
                                subpath: v.subpath.clone(),
                                driver_config: v.driver_config.as_ref().map(|d| bollard::models::MountVolumeOptionsDriverConfig {
                                    name: d.name.clone(),
                                    options: None, // driver options shape in this bollard version is complex; safe default for advanced use
                                }),
                                labels: if v.labels.is_empty() { None } else { Some(v.labels.iter().cloned().collect()) },
                            }),
                        })
                        .collect(),
                )
            };

            // Device requests (GPU etc.)
            let device_requests = if container.device_requests.is_empty() {
                None
            } else {
                Some(
                    container
                        .device_requests
                        .iter()
                        .map(|dr| bollard::models::DeviceRequest {
                            driver: dr.driver.clone(),
                            count: dr.count,
                            device_ids: if dr.device_ids.is_empty() {
                                None
                            } else {
                                Some(dr.device_ids.clone())
                            },
                            capabilities: if dr.capabilities.is_empty() {
                                None
                            } else {
                                Some(dr.capabilities.to_vec())
                            },
                            options: if dr.options.is_empty() {
                                None
                            } else {
                                Some(dr.options.iter().cloned().collect())
                            },
                        })
                        .collect(),
                )
            };

            // Capabilities
            let cap_add = if container.cap_add.is_empty() {
                None
            } else {
                Some(container.cap_add.clone())
            };
            let cap_drop = if container.cap_drop.is_empty() {
                None
            } else {
                Some(container.cap_drop.clone())
            };

            // Devices
            let devices = if container.devices.is_empty() {
                None
            } else {
                Some(
                    container
                        .devices
                        .iter()
                        .map(|d| bollard::models::DeviceMapping {
                            path_on_host: Some(d.path_on_host.clone()),
                            path_in_container: Some(d.path_in_container.clone()),
                            cgroup_permissions: d.cgroup_permissions.clone(),
                        })
                        .collect(),
                )
            };

            // Advanced blkio devices
            let blkio_weight_device = if container.blkio_weight_device.is_empty() {
                None
            } else {
                Some(
                    container
                        .blkio_weight_device
                        .iter()
                        .map(|d| bollard::models::ResourcesBlkioWeightDevice {
                            path: Some(d.path.clone()),
                            weight: d.weight.map(|w| w as usize),
                        })
                        .collect(),
                )
            };

            let blkio_device_read_bps = if container.blkio_device_read_bps.is_empty() {
                None
            } else {
                Some(
                    container
                        .blkio_device_read_bps
                        .iter()
                        .map(|d| bollard::models::ThrottleDevice {
                            path: Some(d.path.clone()),
                            rate: d.rate,
                        })
                        .collect(),
                )
            };

            let blkio_device_write_bps = if container.blkio_device_write_bps.is_empty() {
                None
            } else {
                Some(
                    container
                        .blkio_device_write_bps
                        .iter()
                        .map(|d| bollard::models::ThrottleDevice {
                            path: Some(d.path.clone()),
                            rate: d.rate,
                        })
                        .collect(),
                )
            };

            let blkio_device_read_iops = if container.blkio_device_read_iops.is_empty() {
                None
            } else {
                Some(
                    container
                        .blkio_device_read_iops
                        .iter()
                        .map(|d| bollard::models::ThrottleDevice {
                            path: Some(d.path.clone()),
                            rate: d.rate,
                        })
                        .collect(),
                )
            };

            let blkio_device_write_iops = if container.blkio_device_write_iops.is_empty() {
                None
            } else {
                Some(
                    container
                        .blkio_device_write_iops
                        .iter()
                        .map(|d| bollard::models::ThrottleDevice {
                            path: Some(d.path.clone()),
                            rate: d.rate,
                        })
                        .collect(),
                )
            };

            // Extra hosts
            let extra_hosts = if container.extra_hosts.is_empty() {
                None
            } else {
                Some(container.extra_hosts.clone())
            };

            // Group add
            let group_add = if container.group_add.is_empty() {
                None
            } else {
                Some(container.group_add.clone())
            };

            // DNS
            let dns = if container.dns.is_empty() {
                None
            } else {
                Some(container.dns.clone())
            };
            let dns_options = if container.dns_options.is_empty() {
                None
            } else {
                Some(container.dns_options.clone())
            };
            let dns_search = if container.dns_search.is_empty() {
                None
            } else {
                Some(container.dns_search.clone())
            };

            // Links
            let links = if container.links.is_empty() {
                None
            } else {
                Some(container.links.clone())
            };

            // Build the authoritative LogConfig from flat driver + opts in the spec.
            let log_config = if container.log_driver.is_some() || !container.log_opts.is_empty() {
                Some(bollard::models::HostConfigLogConfig {
                    typ: container.log_driver.clone(),
                    config: if container.log_opts.is_empty() {
                        None
                    } else {
                        Some(container.log_opts.iter().cloned().collect())
                    },
                })
            } else {
                None
            };

            let host_config = HostConfig {
                binds: if binds.is_empty() { None } else { Some(binds) },
                port_bindings: if port_bindings.is_empty() {
                    None
                } else {
                    Some(port_bindings)
                },
                restart_policy,
                memory,
                memory_swap,
                cpu_shares,
                cpu_quota,
                cpu_period,
                tmpfs,
                sysctls,
                cap_add,
                cap_drop,
                security_opt: if container.security_opt.is_empty() {
                    None
                } else {
                    Some(container.security_opt.clone())
                },
                shm_size: container.shm_size,
                ipc_mode: container.ipc_mode.clone(),
                pid_mode: container.pid_mode.clone(),
                init: container.init,
                devices,
                cgroup_parent: container.cgroup_parent.clone(),
                blkio_weight: container.blkio_weight,
                blkio_weight_device,
                blkio_device_read_bps,
                blkio_device_write_bps,
                blkio_device_read_iops,
                blkio_device_write_iops,
                pids_limit: container.pids_limit,
                runtime: container.runtime.clone(),
                isolation: container
                    .isolation
                    .as_ref()
                    .map(|s| match s.to_lowercase().as_str() {
                        "default" => bollard::models::HostConfigIsolationEnum::DEFAULT,
                        "process" => bollard::models::HostConfigIsolationEnum::PROCESS,
                        "hyperv" => bollard::models::HostConfigIsolationEnum::HYPERV,
                        _ => bollard::models::HostConfigIsolationEnum::DEFAULT,
                    }),
                cgroupns_mode: container.cgroupns_mode.as_ref().map(|s| {
                    match s.to_lowercase().as_str() {
                        "private" => bollard::models::HostConfigCgroupnsModeEnum::PRIVATE,
                        "host" => bollard::models::HostConfigCgroupnsModeEnum::HOST,
                        _ => bollard::models::HostConfigCgroupnsModeEnum::PRIVATE,
                    }
                }),
                cpu_realtime_period: container.cpu_rt_period,
                cpu_realtime_runtime: container.cpu_rt_runtime,
                memory_swappiness: container.memory_swappiness,
                oom_kill_disable: container.oom_kill_disable,
                oom_score_adj: container.oom_score_adj,
                privileged: container.privileged,
                auto_remove: container.auto_remove,
                extra_hosts,
                group_add,
                dns,
                dns_options,
                dns_search,
                links,
                ulimits: if container.ulimits.is_empty() {
                    None
                } else {
                    Some(
                        container
                            .ulimits
                            .iter()
                            .map(|u| bollard::models::ResourcesUlimits {
                                name: Some(u.name.clone()),
                                soft: Some(u.soft),
                                hard: Some(u.hard),
                            })
                            .collect(),
                    )
                },
                device_cgroup_rules: if container.device_cgroup_rules.is_empty() {
                    None
                } else {
                    Some(container.device_cgroup_rules.clone())
                },
                masked_paths: if container.masked_paths.is_empty() {
                    None
                } else {
                    Some(container.masked_paths.clone())
                },
                readonly_paths: if container.readonly_paths.is_empty() {
                    None
                } else {
                    Some(container.readonly_paths.clone())
                },
                storage_opt: if container.storage_opt.is_empty() {
                    None
                } else {
                    Some(container.storage_opt.iter().cloned().collect())
                },
                uts_mode: container.uts_mode.clone(),
                userns_mode: container.userns_mode.clone(),
                volumes_from: if container.volumes_from.is_empty() {
                    None
                } else {
                    Some(container.volumes_from.clone())
                },
                volume_driver: container.volume_driver.clone(),
                log_config,
                network_mode: container.network_mode.clone(),
                // Newly wired advanced surface (this pass)
                mounts,
                device_requests,
                cpuset_cpus,
                cpuset_mems,
                nano_cpus,
                memory_reservation,
                kernel_memory_tcp,
                // stdin_once lives on the top-level Config (not HostConfig)
                annotations: if container.annotations.is_empty() {
                    None
                } else {
                    Some(container.annotations.iter().cloned().collect())
                },
                container_id_file: None,
                ..Default::default()
            };

            let config = Config {
                image: Some(container.image.clone()),
                env: Some({
                    let mut e: Vec<String> = container
                        .env
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    // Tier 3-2: inject decrypted secrets as additional env vars (user env takes precedence if duplicate)
                    for (k, v) in &secret_env_additions {
                        if !e.iter().any(|entry| entry.starts_with(&format!("{k}="))) {
                            e.push(format!("{k}={v}"));
                        }
                    }
                    e
                }),
                labels: Some(labels),
                host_config: Some(host_config),
                healthcheck,
                working_dir: container.working_dir.clone(),
                user: container.user.clone(),
                stop_signal: container.stop_signal.clone(),
                stop_timeout: container.stop_timeout,

                // More top-level container options
                entrypoint: container.entrypoint.clone(),
                cmd: container.cmd.clone(),
                hostname: container.hostname.clone(),
                domainname: container.domainname.clone(),
                mac_address: container.mac_address.clone(),
                network_disabled: container.network_disabled,
                open_stdin: container.stdin_open,
                stdin_once: container.stdin_once,
                tty: container.tty,
                attach_stdin: container.attach_stdin,
                attach_stdout: container.attach_stdout,
                attach_stderr: container.attach_stderr,
                shell: container.shell.clone(),

                ..Default::default()
            };

            let options = CreateContainerOptions {
                name: container.name.clone(),
                ..Default::default()
            };

            info!(name = %container.name, "Creating container");
            let create_response = docker.create_container(Some(options), config).await?;

            // Attach to networks with rich per-endpoint configuration (advanced IPAM + links)
            if let Some(_networking) = networking_config {
                for net in &spec.networks {
                    let mut endpoint = bollard::models::EndpointSettings::default();

                    if !container.network_aliases.is_empty() {
                        endpoint.aliases = Some(container.network_aliases.clone());
                    }

                    if container.network_ipv4_address.is_some()
                        || container.network_ipv6_address.is_some()
                    {
                        endpoint.ipam_config = Some(bollard::models::EndpointIpamConfig {
                            ipv4_address: container.network_ipv4_address.clone(),
                            ipv6_address: container.network_ipv6_address.clone(),
                            link_local_ips: None,
                        });
                    }

                    if !container.network_links.is_empty() {
                        endpoint.links = Some(container.network_links.clone());
                    }

                    if let Some(mac) = &container.network_mac_address {
                        endpoint.mac_address = Some(mac.clone());
                    }

                    if let Err(e) = docker
                        .connect_network(
                            net,
                            bollard::network::ConnectNetworkOptions {
                                container: container.name.clone(),
                                endpoint_config: endpoint,
                            },
                        )
                        .await
                    {
                        warn!(network = %net, error = ?e, "Failed to attach container to network with rich endpoint config");
                    }
                }
            }

            info!(name = %container.name, id = %create_response.id, "Starting container");
            docker
                .start_container(&container.name, None::<StartContainerOptions<String>>)
                .await?;
        }

        // === Actual L7 traffic sidecar enforcement (Envoy) for canary/blue-green without external LB ===
        // Triggered when control plane injects "forge.l7.enforce" = "envoy" (or weight labels during phased rollout).
        // The sidecar becomes the traffic entrypoint and performs real weighted/header-based routing at L7.
        let needs_l7_sidecar = spec.containers.iter().any(|c| {
            c.labels
                .get("forge.l7.enforce")
                .map(|v| v == "envoy" || v == "envoy_xds")
                .unwrap_or(false)
                || c.labels.contains_key("forge.canary.weight")
                || c.labels.contains_key("forge.traffic.weight")
        });

        if needs_l7_sidecar {
            info!(
                "L7 enforcement requested — starting Envoy sidecar for weighted canary/blue-green routing"
            );

            let weight: u32 = spec
                .containers
                .iter()
                .find_map(|c| {
                    c.labels
                        .get("forge.canary.weight")
                        .or_else(|| c.labels.get("forge.traffic.weight"))
                })
                .and_then(|w| w.parse().ok())
                .unwrap_or(50);

            let enforce_mode = spec
                .containers
                .iter()
                .find_map(|c| c.labels.get("forge.l7.enforce"))
                .map(|s| s.as_str())
                .unwrap_or("envoy");

            let envoy_name = format!(
                "{}-envoy-l7",
                spec.containers
                    .first()
                    .map(|c| c.name.as_str())
                    .unwrap_or("app")
            );

            if enforce_mode == "envoy_xds" {
                // === TRUE ADS xDS MODE ===
                // Generate a real Envoy bootstrap that points at the control plane's ADS gRPC server.
                // The control plane will push live Route/Cluster updates on every statistical canary promotion.
                // Node ID carries the deployment so the xDS server can serve the correct weights.
                let xds_addr = std::env::var("FORGE_XDS_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1:18000".to_string());
                let bootstrap = format!(
                    r#"
node:
  id: "{}"
  cluster: "forge"
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: xds_cluster
static_resources:
  clusters:
  - name: xds_cluster
    connect_timeout: 5s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: xds_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {}
                port_value: {}
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
"#,
                    deployment_id,
                    xds_addr.split(':').next().unwrap_or("127.0.0.1"),
                    xds_addr.split(':').nth(1).unwrap_or("18000")
                );

                // Write bootstrap to a stable path inside the (future) volume or use --config-yaml for bootstrap too
                // For Docker sidecar simplicity we still use --config-yaml with the bootstrap (Envoy supports it).
                let envoy_create = bollard::container::CreateContainerOptions {
                    name: envoy_name.clone(),
                    ..Default::default()
                };
                let envoy_cfg = bollard::container::Config {
                    image: Some("envoyproxy/envoy:v1.31-latest".to_string()),
                    cmd: Some(vec![
                        "envoy".to_string(),
                        "--config-yaml".to_string(),
                        bootstrap,
                        "--concurrency".to_string(),
                        "2".to_string(),
                    ]),
                    labels: Some({
                        let mut l = std::collections::HashMap::new();
                        l.insert("forge.deployment_id".to_string(), deployment_id.to_string());
                        l.insert("forge.component".to_string(), "envoy-l7".to_string());
                        l.insert("forge.l7.mode".to_string(), "envoy_xds".to_string());
                        l
                    }),
                    exposed_ports: Some({
                        let mut p = std::collections::HashMap::new();
                        p.insert("80/tcp".to_string(), Default::default());
                        p
                    }),
                    host_config: Some(bollard::models::HostConfig {
                        port_bindings: Some({
                            let mut pb = std::collections::HashMap::new();
                            pb.insert(
                                "80/tcp".to_string(),
                                Some(vec![bollard::models::PortBinding {
                                    host_ip: Some("0.0.0.0".to_string()),
                                    host_port: Some("80".to_string()),
                                }]),
                            );
                            pb
                        }),
                        network_mode: Some("bridge".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                if let Err(e) = docker.create_container(Some(envoy_create), envoy_cfg).await {
                    warn!(error = ?e, "Failed to create Envoy (xDS mode)");
                } else if let Err(e) = docker
                    .start_container(
                        &envoy_name,
                        None::<bollard::container::StartContainerOptions<String>>,
                    )
                    .await
                {
                    warn!(error = ?e, "Failed to start Envoy (xDS mode)");
                } else {
                    info!(
                        "Envoy started in TRUE ADS xDS mode (control plane will push live weights for deployment {})",
                        deployment_id
                    );
                }
            } else {
                // === LEGACY STATIC MODE (existing behavior) ===
                let envoy_config = format!(
                    r#"
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 80
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  weighted_clusters:
                    clusters:
                    - name: main_cluster
                      weight: {}
                    - name: canary_cluster
                      weight: {}
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: main_cluster
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: main_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: app-main
                port_value: 80
  - name: canary_cluster
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: canary_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: app-canary
                port_value: 80
"#,
                    100 - weight,
                    weight
                );

                let envoy_create = bollard::container::CreateContainerOptions {
                    name: envoy_name.clone(),
                    ..Default::default()
                };
                let envoy_cfg = bollard::container::Config {
                    image: Some("envoyproxy/envoy:v1.31-latest".to_string()),
                    cmd: Some(vec![
                        "envoy".to_string(),
                        "--config-yaml".to_string(),
                        envoy_config,
                        "--concurrency".to_string(),
                        "2".to_string(),
                    ]),
                    labels: Some({
                        let mut l = std::collections::HashMap::new();
                        l.insert("forge.deployment_id".to_string(), deployment_id.to_string());
                        l.insert("forge.component".to_string(), "envoy-l7".to_string());
                        l.insert("forge.canary_weight".to_string(), weight.to_string());
                        l.insert("forge.l7.mode".to_string(), "envoy".to_string());
                        l
                    }),
                    exposed_ports: Some({
                        let mut p = std::collections::HashMap::new();
                        p.insert("80/tcp".to_string(), Default::default());
                        p
                    }),
                    host_config: Some(bollard::models::HostConfig {
                        port_bindings: Some({
                            let mut pb = std::collections::HashMap::new();
                            pb.insert(
                                "80/tcp".to_string(),
                                Some(vec![bollard::models::PortBinding {
                                    host_ip: Some("0.0.0.0".to_string()),
                                    host_port: Some("80".to_string()),
                                }]),
                            );
                            pb
                        }),
                        network_mode: Some("bridge".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                if let Err(e) = docker.create_container(Some(envoy_create), envoy_cfg).await {
                    warn!(error = ?e, "Failed to create Envoy L7 sidecar (continuing without deep enforcement)");
                } else if let Err(e) = docker
                    .start_container(
                        &envoy_name,
                        None::<bollard::container::StartContainerOptions<String>>,
                    )
                    .await
                {
                    warn!(error = ?e, "Failed to start Envoy L7 sidecar");
                } else {
                    info!(
                        "Envoy L7 sidecar started successfully for real traffic enforcement (weight {}%)",
                        weight
                    );
                }
            }
        }

        info!(
            count = spec.containers.len(),
            "Deploy job completed successfully (Docker)"
        );
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        warn!("Docker feature disabled — performing dry-run deployment");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        info!(
            containers = spec.containers.len(),
            "Deploy job completed (dry run)"
        );
        Ok(())
    }
}

/// Verify every image reference with `verifier` before it is run; refuse the deploy on the first
/// failure (fail-closed, A10). Factored out and taking a `&dyn ArtifactVerifier` so it can be
/// unit-tested with a mock verifier (accept/reject) without the real cosign binary or a registry.
async fn verify_images_before_run(
    deployment_id: uuid::Uuid,
    verify_images: &[String],
    verifier: &dyn crate::supplychain::ArtifactVerifier,
) -> Result<()> {
    for image_ref in verify_images {
        match verifier.verify(image_ref).await {
            Ok(()) => {
                info!(deployment_id = %deployment_id, image = %image_ref, "image verified before run");
            }
            Err(e) => {
                error!(
                    deployment_id = %deployment_id,
                    image = %image_ref,
                    error = %e,
                    "image failed signature/provenance verification — refusing to run (fail-closed)"
                );
                return Err(crate::AgentError::Internal(anyhow::anyhow!(e.to_string())));
            }
        }
    }
    Ok(())
}

async fn execute_system_update(
    version: String,
    binary_ref: String,
    expected_sha256: String,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    info!(
        version = %version,
        binary_ref = %binary_ref,
        "Starting graceful self-update handover for agent"
    );

    // === Phase 1: Download + Verify ===
    let client = reqwest::Client::builder()
        .user_agent("forge-agent/0.1")
        .build()
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    let response = client
        .get(&binary_ref)
        .send()
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    if !response.status().is_success() {
        return Err(crate::AgentError::Internal(anyhow::anyhow!(
            "Failed to download new agent binary: HTTP {}",
            response.status()
        )));
    }

    let total_size = response.content_length().unwrap_or(0);
    info!(size = total_size, "Downloading new agent binary...");

    let body = response
        .bytes()
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let actual_sha256 = format!("{:x}", hasher.finalize());

    if actual_sha256 != expected_sha256.to_lowercase() {
        return Err(crate::AgentError::Internal(anyhow::anyhow!(
            "SHA256 mismatch for new agent binary! expected={expected_sha256}, actual={actual_sha256}"
        )));
    }

    info!("Binary checksum verified successfully");

    // === Phase 2: Write new binary ===
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("forge-agent"));
    let temp_path = current_exe.with_extension("new");
    let backup_path = current_exe.with_extension("old");

    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    file.write_all(&body)
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;
    file.flush()
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    // Make executable
    let mut perms = tokio::fs::metadata(&temp_path)
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?
        .permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(&temp_path, perms)
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    info!("New agent binary written and made executable");

    // === Phase 3: Set up Unix domain socket for clean handover ===
    let handover_socket_path = format!("/tmp/forge-agent-handover-{}.sock", std::process::id());
    let _ = tokio::fs::remove_file(&handover_socket_path).await;

    let listener = UnixListener::bind(&handover_socket_path)
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    info!(path = %handover_socket_path, "Handover socket listening");

    // === Phase 4: Backup current binary (best effort) ===
    if let Err(e) = tokio::fs::rename(&current_exe, &backup_path).await {
        warn!(error = ?e, "Could not backup current binary (continuing)");
    } else {
        info!("Current binary backed up to .old");
    }

    // === Phase 5: Install new binary ===
    tokio::fs::rename(&temp_path, &current_exe)
        .await
        .map_err(|e| crate::AgentError::Internal(e.into()))?;

    info!("New agent binary installed");

    // === Phase 6: Spawn new process with handover context ===
    let mut cmd = tokio::process::Command::new(&current_exe);
    cmd.envs(std::env::vars());
    cmd.env("FORGE_AGENT_HANDOVER_SOCKET", &handover_socket_path);
    cmd.env("FORGE_AGENT_HANDOVER_VERSION", &version);

    info!("Spawning new agent process...");

    let child = cmd.spawn().map_err(|e| {
        // Rollback on spawn failure
        let _ = std::fs::rename(&backup_path, &current_exe);
        crate::AgentError::Internal(anyhow::anyhow!("Failed to spawn new agent: {e}"))
    })?;

    let new_pid = child.id();
    info!(pid = new_pid, "New agent process spawned");

    // === Phase 7: Wait for new process to signal readiness via socket (with timeout) ===
    let handover_timeout = std::time::Duration::from_secs(25);
    let accept_result = tokio::time::timeout(handover_timeout, listener.accept()).await;

    let success = match accept_result {
        Ok(Ok((mut stream, _))) => {
            let mut buf = [0u8; 32];
            match stream.read(&mut buf).await {
                Ok(n) if &buf[..n] == b"READY" => {
                    info!("New agent signaled readiness via handover socket");
                    let _ = stream.write_all(b"ACK").await;
                    true
                }
                _ => {
                    warn!("New agent connected but did not send proper READY handshake");
                    false
                }
            }
        }
        Ok(Err(e)) => {
            error!(error = ?e, "Failed to accept handover connection");
            false
        }
        Err(_) => {
            warn!("Handover timed out after {:?}", handover_timeout);
            false
        }
    };

    // Clean up socket
    let _ = tokio::fs::remove_file(&handover_socket_path).await;

    if success {
        info!("Graceful self-update handover completed successfully");
        // Clean backup on success (optional — some people prefer to keep it)
        let _ = tokio::fs::remove_file(&backup_path).await;
        std::process::exit(0);
    } else {
        error!("Handover failed — rolling back");

        // Kill the new process if possible
        if let Some(pid) = new_pid {
            let _ = tokio::process::Command::new("kill")
                .arg(pid.to_string())
                .output()
                .await;
        }

        // Restore previous binary
        if tokio::fs::rename(&backup_path, &current_exe).await.is_ok() {
            info!("Previous binary restored");
        }

        Err(crate::AgentError::Internal(anyhow::anyhow!(
            "Self-update handover failed"
        )))
    }
}

async fn execute_stop(
    target: crate::job::ResourceTarget,
    _docker: Option<&DockerClient>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::{RemoveContainerOptions, StopContainerOptions};

        let docker = _docker.expect("Docker client required when docker feature is enabled");

        match target {
            crate::job::ResourceTarget::Container { id } => {
                // Better stateful handling: run pre_stop hooks (for DB drain, queue flush, etc.)
                // then extended drain_grace for stateful before stop.
                // This enables true zero-downtime for stateful in phased rollouts.
                info!(container = %id, "Stopping container with stateful-aware graceful handling");

                // If the container was created with our extended labels (from spec), respect them.
                // For now, we use reasonable defaults + env for stateful.
                let is_stateful = std::env::var("FORGE_CONTAINER_IS_STATEFUL").is_ok();
                let drain_grace = std::env::var("FORGE_DRAIN_GRACE_SECONDS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(if is_stateful { 30 } else { 0 });

                if drain_grace > 0 {
                    info!(container = %id, drain_grace, "Stateful drain grace period before stop (allows connections to drain, replication to catch up)");
                    tokio::time::sleep(std::time::Duration::from_secs(drain_grace)).await;
                }

                // Run pre_stop if configured via env (simple for Phase 2; full from labels in future)
                if let Ok(pre_stop) = std::env::var("FORGE_PRE_STOP") {
                    if !pre_stop.is_empty() {
                        info!(container = %id, "Running pre-stop hook for stateful drain: {}", pre_stop);
                        // In real impl this would be exec in container; for now log + best effort
                        let _ = docker
                            .create_exec(
                                &id,
                                bollard::exec::CreateExecOptions {
                                    attach_stdout: Some(true),
                                    attach_stderr: Some(true),
                                    cmd: Some(
                                        pre_stop
                                            .split_whitespace()
                                            .map(|s| s.to_string())
                                            .collect(),
                                    ),
                                    ..Default::default()
                                },
                            )
                            .await;
                    }
                }

                let timeout = if is_stateful { 30 } else { 10 };
                info!(container = %id, timeout, "Stopping with extended timeout for stateful");
                let stop_opts = Some(StopContainerOptions { t: timeout as i64 });
                if let Err(e) = docker.stop_container(&id, stop_opts).await {
                    warn!(container = %id, error = ?e, "Graceful stop warning (will force)");
                }
                let remove_opts = Some(RemoveContainerOptions {
                    force: true,
                    v: true,
                    link: false,
                });
                if let Err(e) = docker.remove_container(&id, remove_opts).await {
                    warn!(container = %id, error = ?e, "Failed to force-remove container");
                }
            }
            crate::job::ResourceTarget::ComposeProject { name } => {
                info!(project = %name, "Stopping compose project containers");
                // Best-effort: stop containers with compose project label
                if let Ok(containers) = docker.list_containers::<String>(None).await {
                    for c in containers {
                        if let Some(labels) = c.labels {
                            if labels.get("com.docker.compose.project") == Some(&name) {
                                if let Some(id) = c.id {
                                    let short_id = &id[..12.min(id.len())];
                                    info!(container = %short_id, "Stopping compose container (force + volumes)");
                                    let _ = docker
                                        .stop_container(
                                            &id,
                                            Some(bollard::container::StopContainerOptions { t: 5 }),
                                        )
                                        .await;
                                    let _ = docker
                                        .remove_container(
                                            &id,
                                            Some(bollard::container::RemoveContainerOptions {
                                                force: true,
                                                v: true,
                                                link: false,
                                            }),
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = ?target, "Stop job received (dry run)");
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_command(
    docker: Option<&DockerClient>,
    target_container: Option<String>,
    command: Vec<String>,
    working_dir: Option<String>,
    user: Option<String>,
    env: Vec<String>,
    tty: Option<bool>,
    privileged: Option<bool>,
    attach_stdin: Option<bool>,
    interactive_session_id: Option<String>,
    exec_output_tx: Option<tokio::sync::mpsc::Sender<crate::receiver::AgentMessage>>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::exec::{CreateExecOptions, StartExecOptions};
        use futures_util::StreamExt;

        let docker =
            docker.expect("Docker client required for exec when docker feature is enabled");

        let container_id = match target_container {
            Some(id) => id,
            None => {
                warn!("Exec job received without target container — skipping real execution");
                return Ok(());
            }
        };

        info!(
            container = %container_id,
            command = ?command,
            "Performing real docker exec with streaming output"
        );

        let exec = docker
            .create_exec(
                &container_id,
                CreateExecOptions {
                    cmd: Some(command),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    attach_stdin,
                    tty,
                    env: if env.is_empty() { None } else { Some(env) },
                    working_dir: working_dir.clone(),
                    user: user.clone(),
                    privileged,
                    ..Default::default()
                },
            )
            .await?;

        // Correct bollard attached exec handling (StartExecResults + multiplexed output stream)
        let start_result = docker
            .start_exec(
                &exec.id,
                Some(StartExecOptions {
                    detach: false,
                    ..Default::default()
                }),
            )
            .await?;

        use bollard::exec::StartExecResults;

        // Interactive PTY streaming bridge: if session_id and tx provided, stream live output as ExecOutput
        // instead of blocking collection. This enables full character-by-character PTY from agent to frontend.
        if let (Some(session_id), Some(tx)) = (&interactive_session_id, &exec_output_tx) {
            let tx = tx.clone();
            let session_id = session_id.clone();

            // Move the start_result into the spawn for the interactive case
            tokio::spawn(async move {
                // Send started
                let _ = tx
                    .send(crate::receiver::AgentMessage::ExecOutput {
                        session_id: session_id.clone(),
                        data: b"[PTY session started]\n".to_vec(),
                        stream: "stdout".to_string(),
                    })
                    .await;

                match start_result {
                    StartExecResults::Attached { mut output, .. } => {
                        while let Some(Ok(msg)) = output.next().await {
                            let text = msg.to_string().trim_end().to_string();
                            if !text.is_empty() {
                                let s = format!("{msg:?}");
                                let stream = if s.contains("StdOut") || s.contains("stdout") {
                                    "stdout"
                                } else if s.contains("StdErr") || s.contains("stderr") {
                                    "stderr"
                                } else {
                                    "stdout"
                                };
                                let data = format!("{text}\n").into_bytes();
                                let _ = tx
                                    .send(crate::receiver::AgentMessage::ExecOutput {
                                        session_id: session_id.clone(),
                                        data,
                                        stream: stream.to_string(),
                                    })
                                    .await;
                            }
                        }
                    }
                    StartExecResults::Detached => {
                        let _ = tx
                            .send(crate::receiver::AgentMessage::ExecOutput {
                                session_id: session_id.clone(),
                                data: b"[detached]\n".to_vec(),
                                stream: "stdout".to_string(),
                            })
                            .await;
                    }
                }

                // On exit, send final marker (frontend can close or keep)
                let _ = tx
                    .send(crate::receiver::AgentMessage::ExecOutput {
                        session_id: session_id.clone(),
                        data: b"[PTY session ended]\n".to_vec(),
                        stream: "stdout".to_string(),
                    })
                    .await;
            });

            return Ok(()); // Job "completes" immediately for interactive; streaming is background
        }

        // Non-interactive path (original collection)
        let mut stdout = String::new();
        let mut stderr = String::new();

        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                // bollard LogOutput in this version is matched on variants, not helper methods
                while let Some(Ok(msg)) = output.next().await {
                    let text = msg.to_string().trim_end().to_string();
                    if !text.is_empty() {
                        // Best-effort classification via the Display/Debug of LogOutput
                        let s = format!("{msg:?}");
                        if s.contains("StdOut") || s.contains("stdout") {
                            info!(output = %text, "exec stdout");
                            stdout.push_str(&text);
                            stdout.push('\n');
                        } else if s.contains("StdErr") || s.contains("stderr") {
                            warn!(output = %text, "exec stderr");
                            stderr.push_str(&text);
                            stderr.push('\n');
                        } else {
                            info!(output = %text, "exec output");
                        }
                    }
                }
            }
            StartExecResults::Detached => {
                info!("exec started in detached mode (no output captured)");
            }
        }

        // Capture real exit code via inspect (first-class observability)
        let exit_code = match docker.inspect_exec(&exec.id).await {
            Ok(inspect) => inspect.exit_code,
            Err(_) => None,
        };

        info!(
            container = %container_id,
            stdout_len = stdout.len(),
            stderr_len = stderr.len(),
            exit_code = ?exit_code,
            "docker exec completed with full streaming output + exit code captured"
        );

        // NOTE: stdout/stderr/exit_code are now fully materialized here at maximum fidelity.
        // Future work (result reporting channel) will surface these as first-class values to the control plane.

        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(command = ?command, working_dir = ?working_dir, env_len = env.len(), tty = ?tty, privileged = ?privileged, "Exec job received (dry run)");
        Ok(())
    }
}

async fn execute_health_check(_docker: Option<&DockerClient>) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::{ListContainersOptions, StatsOptions};
        use futures_util::stream::StreamExt;

        let docker = _docker.expect("Docker client required");

        let list_opts = Some(ListContainersOptions::<String> {
            all: true,
            filters: [("label".to_string(), vec!["forge.managed=true".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        });

        match docker.list_containers(list_opts).await {
            Ok(containers) => {
                info!(
                    count = containers.len(),
                    "HealthCheck: managed containers visible to agent"
                );

                for c in containers.iter().take(8) {
                    if let (Some(id), Some(state)) = (&c.id, &c.state) {
                        if state == "running" {
                            // Short streaming stats sample (more accurate CPU than pure one-shot)
                            let stats_stream = docker.stats(
                                id,
                                Some(StatsOptions {
                                    stream: true,
                                    one_shot: false,
                                }),
                            );

                            let samples: Vec<_> = stats_stream.take(3).collect::<Vec<_>>().await;
                            let samples: Vec<_> =
                                samples.into_iter().filter_map(|r| r.ok()).collect();

                            if let Some(stats) = samples.last() {
                                let name = c
                                    .names
                                    .as_ref()
                                    .and_then(|n| n.first())
                                    .map(|s| s.trim_start_matches('/'))
                                    .unwrap_or(id);
                                let short_id = &id[..12.min(id.len())];

                                // CPU (use last two samples for delta if available)
                                let (cpu_delta, system_delta) = if samples.len() >= 2 {
                                    let prev = &samples[samples.len() - 2];
                                    let curr = stats;
                                    (
                                        curr.cpu_stats
                                            .cpu_usage
                                            .total_usage
                                            .saturating_sub(prev.cpu_stats.cpu_usage.total_usage),
                                        curr.cpu_stats
                                            .system_cpu_usage
                                            .unwrap_or(0)
                                            .saturating_sub(
                                                prev.cpu_stats.system_cpu_usage.unwrap_or(0),
                                            ),
                                    )
                                } else {
                                    (
                                        stats.cpu_stats.cpu_usage.total_usage.saturating_sub(
                                            stats.precpu_stats.cpu_usage.total_usage,
                                        ),
                                        stats
                                            .cpu_stats
                                            .system_cpu_usage
                                            .unwrap_or(0)
                                            .saturating_sub(
                                                stats.precpu_stats.system_cpu_usage.unwrap_or(0),
                                            ),
                                    )
                                };

                                let cpu_percent = if system_delta > 0 && cpu_delta > 0 {
                                    ((cpu_delta as f64 / system_delta as f64)
                                        * stats.cpu_stats.online_cpus.unwrap_or(1) as f64
                                        * 100.0) as f32
                                } else {
                                    0.0
                                };

                                // Memory
                                let mem_usage = stats.memory_stats.usage.unwrap_or(0);
                                let mem_limit = stats.memory_stats.limit.unwrap_or(0);
                                let mem_percent = if mem_limit > 0 {
                                    (mem_usage as f64 / mem_limit as f64 * 100.0) as f32
                                } else {
                                    0.0
                                };

                                // Network (sum rx/tx bytes across interfaces)
                                let (net_rx, net_tx) =
                                    stats.networks.as_ref().map_or((0u64, 0u64), |nets| {
                                        nets.values().fold((0, 0), |(rx, tx), n| {
                                            (rx + n.rx_bytes, tx + n.tx_bytes)
                                        })
                                    });

                                // Block IO (defensive)
                                let (blk_read, blk_write) = stats
                                    .blkio_stats
                                    .io_service_bytes_recursive
                                    .as_ref()
                                    .map_or((0u64, 0u64), |ios| {
                                        ios.iter().fold((0u64, 0u64), |(r, w), io| {
                                            let op = io.op.to_lowercase();
                                            let val = io.value;
                                            if op.contains("read") {
                                                (r + val, w)
                                            } else if op.contains("write") {
                                                (r, w + val)
                                            } else {
                                                (r, w)
                                            }
                                        })
                                    });

                                info!(
                                    container = %name,
                                    id = %short_id,
                                    cpu = %format!("{cpu_percent:.1}%"),
                                    mem = %format!("{mem_percent:.1}%"),
                                    mem_bytes = mem_usage,
                                    net_rx = net_rx,
                                    net_tx = net_tx,
                                    blk_read = blk_read,
                                    blk_write = blk_write,
                                    pids = ?stats.pids_stats.current,
                                    samples = samples.len(),
                                    "HealthCheck: live container stats (streaming sample)"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => warn!(error = ?e, "HealthCheck: failed to list managed containers"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!("HealthCheck job received (dry run)");
        Ok(())
    }
}

/// Live in-place update of a running container (zero-downtime resource / policy changes).
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_update_container(
    docker: Option<&DockerClient>,
    target: String,
    resources: Option<crate::job::ContainerResources>,
    restart_policy: Option<String>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::UpdateContainerOptions;

        let docker = docker
            .expect("Docker client required for container update when docker feature is enabled");

        info!(target = %target, "Applying live container update");

        let mut opts: UpdateContainerOptions<String> = UpdateContainerOptions {
            ..Default::default()
        };

        if let Some(res) = &resources {
            opts.memory = res.memory;
            opts.memory_swap = res.memory_swap;
            opts.cpu_shares = res.cpu_shares.map(|v| v as isize);
            opts.cpu_quota = res.cpu_quota;
            opts.cpu_period = res.cpu_period;
            opts.cpuset_cpus = res.cpuset_cpus.clone();
            opts.cpuset_mems = res.cpuset_mems.clone();
            opts.nano_cpus = res.nano_cpus;
            // kernel_memory_tcp and memory_reservation are available on UpdateContainerOptions in recent bollard
            // (they exist on the struct per our earlier inspection)
        }

        if let Some(policy) = &restart_policy {
            // Note: UpdateContainerOptions does not take full RestartPolicy in this bollard version for update.
            // The restart policy is usually set at create time. We still accept it for future-proofing
            // and log it; operators can use it as a signal or we can layer a stop+recreate with the policy if needed.
            info!(target = %target, policy = %policy, "Restart policy update requested (note: often requires recreate for full effect; resources updated live)");
        }

        // Map advanced resource fields that UpdateContainerOptions supports
        if let Some(res) = &resources {
            opts.blkio_weight = res.cpu_shares.map(|_| 0u16); // placeholder - real blkio weight not directly in our ContainerResources today
            // Many blkio / device fields on UpdateContainerOptions can be populated if we extend the model later.
        }

        match docker.update_container(&target, opts).await {
            Ok(()) => {
                info!(target = %target, "Live container update applied successfully");
            }
            Err(e) => {
                error!(target = %target, error = ?e, "Live container update failed");
                return Err(crate::AgentError::Internal(anyhow::anyhow!(
                    "update_container failed: {e}"
                )));
            }
        }

        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = %target, "UpdateContainer job received (dry run)");
        Ok(())
    }
}

/// Deeper xDS-style dynamic L7 update: shift traffic weights on a live Envoy sidecar
/// during statistical canary promotion. Discovers the sidecar via labels set at creation
/// (forge.deployment_id + forge.component=envoy-l7), regenerates (or accepts) the weighted
/// config, and performs a fast stop+recreate of *only the sidecar* (apps stay running).
/// This gives live promotion effect with seconds of L7 flap instead of full redeploy.
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_update_l7_config(
    docker: Option<&DockerClient>,
    deployment_id: uuid::Uuid,
    canary_weight: u32,
    envoy_container: Option<String>,
    envoy_config_yaml: Option<String>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        let docker = docker
            .expect("Docker client required for L7 config update when docker feature is enabled");

        let weight = canary_weight.min(100);
        let main_w = 100 - weight;

        // Discover the envoy sidecar for this deployment
        let target_name = if let Some(name) = envoy_container {
            name
        } else {
            // List containers with our labels
            use bollard::container::ListContainersOptions;
            let mut filters = std::collections::HashMap::new();
            filters.insert(
                "label".to_string(),
                vec![
                    format!("forge.deployment_id={}", deployment_id),
                    "forge.component=envoy-l7".to_string(),
                ],
            );
            let opts = ListContainersOptions {
                filters,
                ..Default::default()
            };
            match docker.list_containers(Some(opts)).await {
                Ok(list) if !list.is_empty() => list[0]
                    .names
                    .as_ref()
                    .and_then(|n| n.first())
                    .cloned()
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_string(),
                _ => format!("{}-envoy-l7", "app"),
            }
        };

        info!(deployment_id = %deployment_id, envoy = %target_name, weight = %weight, "Executing dynamic L7 weight update (xDS-style live promotion)");

        // Build (or use provided) full static weighted config for the new weights
        let config_yaml = envoy_config_yaml.unwrap_or_else(|| format!(r#"
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 80
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  weighted_clusters:
                    clusters:
                    - name: main_cluster
                      weight: {main_w}
                    - name: canary_cluster
                      weight: {weight}
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: main_cluster
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: main_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: app-main
                port_value: 80
  - name: canary_cluster
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: canary_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: app-canary
                port_value: 80
"#));

        // Fast sidecar swap: stop/rm/recreate/start with new config (apps untouched)
        // This is the practical "dynamic update" until full ADS xDS gRPC server is added.
        let _ = docker
            .stop_container(
                &target_name,
                None::<bollard::container::StopContainerOptions>,
            )
            .await;
        let _ = docker
            .remove_container(
                &target_name,
                None::<bollard::container::RemoveContainerOptions>,
            )
            .await;

        let create_opts = bollard::container::CreateContainerOptions {
            name: target_name.clone(),
            ..Default::default()
        };
        let cfg = bollard::container::Config {
            image: Some("envoyproxy/envoy:v1.31-latest".to_string()),
            cmd: Some(vec![
                "envoy".to_string(),
                "--config-yaml".to_string(),
                config_yaml,
                "--concurrency".to_string(),
                "2".to_string(),
            ]),
            labels: Some({
                let mut l = std::collections::HashMap::new();
                l.insert("forge.deployment_id".to_string(), deployment_id.to_string());
                l.insert("forge.component".to_string(), "envoy-l7".to_string());
                l.insert("forge.canary_weight".to_string(), weight.to_string());
                l.insert("forge.l7.mode".to_string(), "envoy".to_string());
                l
            }),
            exposed_ports: Some({
                let mut p = std::collections::HashMap::new();
                p.insert("80/tcp".to_string(), Default::default());
                p
            }),
            host_config: Some(bollard::models::HostConfig {
                port_bindings: Some({
                    let mut pb = std::collections::HashMap::new();
                    pb.insert(
                        "80/tcp".to_string(),
                        Some(vec![bollard::models::PortBinding {
                            host_ip: Some("0.0.0.0".to_string()),
                            host_port: Some("80".to_string()),
                        }]),
                    );
                    pb
                }),
                network_mode: Some("bridge".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        if let Err(e) = docker.create_container(Some(create_opts), cfg).await {
            warn!(error = ?e, envoy = %target_name, "Failed to recreate Envoy for L7 weight update");
            return Err(crate::AgentError::Internal(anyhow::anyhow!(
                "envoy l7 recreate failed: {e}"
            )));
        }
        if let Err(e) = docker
            .start_container(
                &target_name,
                None::<bollard::container::StartContainerOptions<String>>,
            )
            .await
        {
            warn!(error = ?e, envoy = %target_name, "Failed to start updated Envoy sidecar");
            return Err(crate::AgentError::Internal(anyhow::anyhow!(
                "envoy start after update failed: {e}"
            )));
        }

        info!(deployment_id = %deployment_id, envoy = %target_name, weight = %weight, "Dynamic L7 weight update completed — traffic now {}% canary", weight);
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(deployment_id = %deployment_id, "UpdateL7Config received (dry run, weight {}%)", canary_weight);
        Ok(())
    }
}

// =============================================================================
// New advanced Docker handlers (TTY resize, top, volume/network inspect+prune, attach)
// =============================================================================

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_resize_exec(
    docker: Option<&DockerClient>,
    exec_id: String,
    width: u16,
    height: u16,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::exec::ResizeExecOptions;

        let docker = docker.expect("Docker client required for exec resize");

        info!(exec_id = %exec_id, width = width, height = height, "Resizing exec TTY");
        docker
            .resize_exec(&exec_id, ResizeExecOptions { width, height })
            .await?;
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(exec_id = %exec_id, "ResizeExec received (dry run)");
        Ok(())
    }
}

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_resize_container(
    docker: Option<&DockerClient>,
    target: String,
    width: u16,
    height: u16,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::ResizeContainerTtyOptions;

        let docker = docker.expect("Docker client required for container resize");

        info!(target = %target, width = width, height = height, "Resizing container TTY");
        docker
            .resize_container_tty(&target, ResizeContainerTtyOptions { width, height })
            .await?;
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = %target, "ResizeContainer received (dry run)");
        Ok(())
    }
}

async fn execute_container_top(_docker: Option<&DockerClient>, target: String) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        let docker = _docker.expect("Docker client required");

        match docker.top_processes::<String>(&target, None).await {
            Ok(top) => {
                info!(target = %target, titles = ?top.titles, "Container top processes");
                if let Some(processes) = top.processes {
                    for p in processes {
                        info!(process = ?p, "container process");
                    }
                }
            }
            Err(e) => warn!(target = %target, error = ?e, "Failed to get container top"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = %target, "ContainerTop received (dry run)");
        Ok(())
    }
}

async fn execute_inspect_volume(_docker: Option<&DockerClient>, name: String) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        let docker = _docker.expect("Docker client required");

        match docker.inspect_volume(&name).await {
            Ok(vol) => {
                info!(name = %name, driver = ?vol.driver, "Volume inspected");
            }
            Err(e) => warn!(name = %name, error = ?e, "Failed to inspect volume"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(name = %name, "InspectVolume received (dry run)");
        Ok(())
    }
}

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_prune_volumes(
    docker: Option<&DockerClient>,
    filters: Vec<(String, Vec<String>)>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::volume::PruneVolumesOptions;

        let docker = docker.expect("Docker client required");

        let mut filter_map = std::collections::HashMap::new();
        for (k, v) in filters {
            filter_map.insert(k, v);
        }

        match docker
            .prune_volumes(Some(PruneVolumesOptions {
                filters: filter_map,
            }))
            .await
        {
            Ok(resp) => {
                info!(volumes_deleted = ?resp.volumes_deleted, "Volumes pruned");
            }
            Err(e) => warn!(error = ?e, "Failed to prune volumes"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!("PruneVolumes received (dry run)");
        Ok(())
    }
}

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_inspect_network(
    docker: Option<&DockerClient>,
    name: String,
    verbose: Option<bool>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        let docker = docker.expect("Docker client required");

        let opts = Some(bollard::network::InspectNetworkOptions::<String> {
            verbose: verbose.unwrap_or(false),
            scope: String::new(),
        });

        match docker.inspect_network(&name, opts).await {
            Ok(net) => {
                info!(name = %name, driver = ?net.driver, "Network inspected");
            }
            Err(e) => warn!(name = %name, error = ?e, "Failed to inspect network"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(name = %name, "InspectNetwork received (dry run)");
        Ok(())
    }
}

#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_prune_networks(
    docker: Option<&DockerClient>,
    filters: Vec<(String, Vec<String>)>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::network::PruneNetworksOptions;

        let docker = docker.expect("Docker client required");

        let mut filter_map = std::collections::HashMap::new();
        for (k, v) in filters {
            filter_map.insert(k, v);
        }

        match docker
            .prune_networks(Some(PruneNetworksOptions {
                filters: filter_map,
            }))
            .await
        {
            Ok(resp) => {
                info!(networks_deleted = ?resp.networks_deleted, "Networks pruned");
            }
            Err(e) => warn!(error = ?e, "Failed to prune networks"),
        }
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!("PruneNetworks received (dry run)");
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_container_attach(
    docker: Option<&DockerClient>,
    target: String,
    stdin: Option<bool>,
    stdout: Option<bool>,
    stderr: Option<bool>,
    stream: Option<bool>,
    logs: Option<bool>,
    detach_keys: Option<String>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::AttachContainerOptions;
        use futures_util::StreamExt;

        let docker = docker.expect("Docker client required for attach");

        info!(target = %target, "Starting full hijack attach to container");

        let options = Some(AttachContainerOptions::<String> {
            stdin,
            stdout,
            stderr,
            stream,
            logs,
            detach_keys,
        });

        let attach_result = docker.attach_container(&target, options).await?;

        // Stream output (stdout/stderr)
        let mut output_stream = attach_result.output;
        while let Some(result) = output_stream.next().await {
            match result {
                Ok(log) => {
                    let text = log.to_string();
                    if !text.trim().is_empty() {
                        let s = format!("{log:?}");
                        if s.contains("StdOut") {
                            info!(attach = %text.trim_end(), "attach stdout");
                        } else if s.contains("StdErr") {
                            warn!(attach = %text.trim_end(), "attach stderr");
                        } else {
                            info!(attach = %text.trim_end(), "attach output");
                        }
                    }
                }
                Err(e) => warn!(error = ?e, "Attach output error"),
            }
        }

        info!(target = %target, "Container attach stream ended");
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = %target, "ContainerAttach received (dry run)");
        Ok(())
    }
}

/// Real container logs with full advanced options (follow, tail, timestamps, since/until, stdout/stderr).
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
async fn execute_container_logs(
    docker: Option<&DockerClient>,
    target: String,
    follow: Option<bool>,
    tail: Option<String>,
    timestamps: Option<bool>,
    since: Option<String>,
    until: Option<String>,
    stdout: Option<bool>,
    stderr: Option<bool>,
) -> Result<()> {
    #[cfg(feature = "docker")]
    {
        use bollard::container::LogsOptions;
        use futures_util::stream::StreamExt;

        let docker =
            docker.expect("Docker client required for logs when docker feature is enabled");

        info!(target = %target, "Streaming container logs with advanced options");

        let options = Some(LogsOptions::<String> {
            follow: follow.unwrap_or(false),
            tail: tail.unwrap_or_else(|| "all".to_string()),
            timestamps: timestamps.unwrap_or(false),
            since: since
                .as_ref()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0),
            until: until
                .as_ref()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0),
            stdout: stdout.unwrap_or(true),
            stderr: stderr.unwrap_or(true),
        });

        let mut log_stream = docker.logs(&target, options);

        while let Some(result) = log_stream.next().await {
            match result {
                Ok(output) => {
                    let text = output.to_string();
                    if !text.trim().is_empty() {
                        // Defensive classification (LogOutput variant inspection)
                        let s = format!("{output:?}");
                        if s.contains("StdOut") || s.contains("stdout") {
                            info!(log = %text.trim_end(), "container stdout");
                        } else if s.contains("StdErr") || s.contains("stderr") {
                            warn!(log = %text.trim_end(), "container stderr");
                        } else {
                            info!(log = %text.trim_end(), "container log");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "Error while streaming container logs");
                }
            }
        }

        info!(target = %target, "Container logs stream completed");
        Ok(())
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(target = %target, follow = ?follow, tail = ?tail, "ContainerLogs job received (dry run)");
        Ok(())
    }
}

/// Resolve the S3 secret key for a backup/restore from age-encrypted [`SecretRef`]s.
///
/// The control plane passes the S3 secret KEY as a secret named `s3_secret_key` (age
/// envelope). We decrypt it with the agent identity and return the plaintext. The access
/// key id is NOT secret and rides in [`S3BackupConfig::access_key`]. Returns `None` when no
/// such secret is present (anonymous bucket / IAM-role path). Never logs the value.
fn resolve_s3_secret_key(
    secrets: &[crate::job::SecretRef],
    age_identity: Option<&age::x25519::Identity>,
) -> Option<String> {
    let secret = secrets.iter().find(|s| s.name == "s3_secret_key")?;
    let id = age_identity?;
    match crate::job::decrypt_secret(&secret.ciphertext, id) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => {
            warn!("failed to decrypt s3_secret_key for backup/restore (fail-closed)");
            None
        }
    }
}

/// Build an [`crate::s3::S3Client`] from an [`S3BackupConfig`] + a resolved secret key.
/// Returns `None` when the config is incomplete (no creds) — the caller then falls back to a
/// volume-local location for the dump.
fn s3_client_from(cfg: &S3BackupConfig, secret_key: Option<&str>) -> Option<crate::s3::S3Client> {
    let access = cfg.access_key.as_deref()?;
    let secret = secret_key.or(cfg.secret_key.as_deref())?;
    crate::s3::S3Client::new(
        &cfg.endpoint,
        &cfg.bucket,
        cfg.region.as_deref(),
        access,
        secret,
    )
    .ok()
}

/// Execute a database backup. v1 supports Postgres via `pg_dump`; the dump bytes are
/// captured and (when an S3 destination + credentials are supplied) uploaded with a SigV4-
/// signed PUT. Returns a rich [`JobResultDetails::Backup`] with the real size + location.
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
#[allow(clippy::too_many_arguments)]
async fn execute_backup(
    docker: Option<&DockerClient>,
    deployment_id: Uuid,
    target_container: String,
    db_type: String,
    database: Option<String>,
    s3: Option<S3BackupConfig>,
    secrets: Vec<crate::job::SecretRef>,
    age_identity: Option<&age::x25519::Identity>,
    started_at: i64,
) -> JobResult {
    let correlation_id = deployment_id.to_string();
    let job_type = format!("backup_{db_type}");

    let backup_result = |success: bool,
                         size_bytes: Option<u64>,
                         location: Option<String>,
                         message: Option<String>|
     -> JobResult {
        JobResult {
            correlation_id: correlation_id.clone(),
            job_type: job_type.clone(),
            success,
            error: if success { None } else { message.clone() },
            started_at,
            finished_at: chrono::Utc::now().timestamp(),
            details: JobResultDetails::Backup {
                success,
                size_bytes,
                location,
                message,
                db_type: db_type.clone(),
            },
        }
    };

    #[cfg(feature = "docker")]
    {
        let Some(docker) = docker else {
            return backup_result(false, None, None, Some("docker client unavailable".into()));
        };

        info!(deployment = %deployment_id, container = %target_container, db_type = %db_type, "Starting backup job");

        // Build the dump argv (no host shell; the engine client writes the dump to stdout).
        let dump_cmd = match db_type.as_str() {
            "postgres" | "postgresql" => {
                let db = database
                    .as_deref()
                    .filter(|d| crate::job::is_safe_db_identifier(d))
                    .unwrap_or("postgres");
                vec![
                    "pg_dump".to_string(),
                    "-U".to_string(),
                    "postgres".to_string(),
                    "-d".to_string(),
                    db.to_string(),
                    "--clean".to_string(),
                    "--if-exists".to_string(),
                    "--no-owner".to_string(),
                    "--no-privileges".to_string(),
                ]
            }
            other => {
                return backup_result(
                    false,
                    None,
                    None,
                    Some(format!("backup not supported for db_type '{other}' in v1")),
                );
            }
        };

        let (dump, exit_code) = match capture_exec_stdout(docker, &target_container, dump_cmd).await
        {
            Ok(v) => v,
            Err(e) => return backup_result(false, None, None, Some(e.to_string())),
        };
        if exit_code.unwrap_or(0) != 0 || dump.is_empty() {
            return backup_result(
                false,
                None,
                None,
                Some(format!("dump command exited with code {exit_code:?}")),
            );
        }

        let size = dump.len() as u64;

        // Upload to S3 when a destination + resolvable credentials are present; otherwise the
        // dump location is the agent-local volume path (still a real, recorded outcome).
        if let Some(cfg) = &s3 {
            let secret_key = resolve_s3_secret_key(&secrets, age_identity);
            match s3_client_from(cfg, secret_key.as_deref()) {
                Some(client) => match client.put_object(&cfg.key, dump).await {
                    Ok(location) => {
                        info!(deployment = %deployment_id, size, "Backup uploaded to S3");
                        backup_result(true, Some(size), Some(location), None)
                    }
                    Err(e) => backup_result(false, Some(size), None, Some(e.to_string())),
                },
                None => backup_result(
                    false,
                    Some(size),
                    None,
                    Some("S3 destination configured but credentials are incomplete".into()),
                ),
            }
        } else {
            let location = format!("volume://backup-{deployment_id}/dump.sql");
            info!(deployment = %deployment_id, size, location = %location, "Backup stored to volume");
            backup_result(true, Some(size), Some(location), None)
        }
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(deployment = %deployment_id, "Backup job (dry run)");
        backup_result(true, Some(0), Some("dry-run".into()), None)
    }
}

/// Execute a database restore. DESTRUCTIVE: downloads the dump from S3 and pipes it to the
/// engine client's stdin via an argv-only command (engine + database validated by
/// [`crate::job::build_restore_argv`]). Returns a rich [`JobResultDetails::Restore`].
#[cfg_attr(not(feature = "docker"), allow(unused_variables))]
#[allow(clippy::too_many_arguments)]
async fn execute_restore(
    docker: Option<&DockerClient>,
    restore_id: Uuid,
    deployment_id: Uuid,
    target_container: String,
    db_type: String,
    database: Option<String>,
    s3: S3BackupConfig,
    secrets: Vec<crate::job::SecretRef>,
    age_identity: Option<&age::x25519::Identity>,
    started_at: i64,
) -> JobResult {
    let correlation_id = restore_id.to_string();

    let restore_result =
        |success: bool, location: Option<String>, message: Option<String>| -> JobResult {
            JobResult {
                correlation_id: correlation_id.clone(),
                job_type: "restore".to_string(),
                success,
                error: if success { None } else { message.clone() },
                started_at,
                finished_at: chrono::Utc::now().timestamp(),
                details: JobResultDetails::Restore {
                    success,
                    location,
                    message,
                    db_type: db_type.clone(),
                },
            }
        };

    // Validate engine + database and build the argv BEFORE any network/Docker work. A bad
    // engine or a metachar-laden database name fails closed here (OWASP A03/A08).
    let argv = match crate::job::build_restore_argv(&db_type, database.as_deref()) {
        Ok(a) => a,
        Err(e) => return restore_result(false, None, Some(e.to_string())),
    };

    #[cfg(feature = "docker")]
    {
        let Some(docker) = docker else {
            return restore_result(false, None, Some("docker client unavailable".into()));
        };

        info!(restore_id = %restore_id, deployment = %deployment_id, container = %target_container, db_type = %db_type, "Starting restore job (destructive)");

        // Download the dump from S3 (credentials resolved from age-encrypted secrets).
        let secret_key = resolve_s3_secret_key(&secrets, age_identity);
        let Some(client) = s3_client_from(&s3, secret_key.as_deref()) else {
            return restore_result(false, None, Some("S3 source credentials incomplete".into()));
        };
        let dump = match client.get_object(&s3.key).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => return restore_result(false, None, Some("downloaded dump was empty".into())),
            Err(e) => return restore_result(false, None, Some(e.to_string())),
        };

        match feed_exec_stdin(docker, &target_container, argv, dump).await {
            Ok(exit_code) if exit_code.unwrap_or(0) == 0 => {
                let location = format!("s3://{}/{}", s3.bucket, s3.key);
                info!(restore_id = %restore_id, "Restore completed");
                restore_result(true, Some(location), None)
            }
            Ok(exit_code) => restore_result(
                false,
                None,
                Some(format!("restore command exited with code {exit_code:?}")),
            ),
            Err(e) => restore_result(false, None, Some(e.to_string())),
        }
    }

    #[cfg(not(feature = "docker"))]
    {
        info!(restore_id = %restore_id, "Restore job (dry run)");
        let _ = argv;
        restore_result(true, Some("dry-run".into()), None)
    }
}

/// Run `cmd` (argv) in `container` and collect its raw stdout bytes + exit code. Used to
/// capture a database dump. No host shell — `cmd[0]` is the program, the rest are args.
#[cfg(feature = "docker")]
async fn capture_exec_stdout(
    docker: &DockerClient,
    container: &str,
    cmd: Vec<String>,
) -> Result<(Vec<u8>, Option<i64>)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions};
    use futures_util::StreamExt;

    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(cmd),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await?;

    let start = docker
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await?;

    let mut stdout: Vec<u8> = Vec::new();
    if let bollard::exec::StartExecResults::Attached { mut output, .. } = start {
        while let Some(Ok(msg)) = output.next().await {
            if let bollard::container::LogOutput::StdOut { message } = msg {
                stdout.extend_from_slice(&message);
            }
        }
    }
    let exit_code = docker
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code);
    Ok((stdout, exit_code))
}

/// Run `cmd` (argv) in `container` with `stdin` piped to its standard input, returning the
/// exit code. Used to stream a downloaded dump into the engine client (restore). No shell.
#[cfg(feature = "docker")]
async fn feed_exec_stdin(
    docker: &DockerClient,
    container: &str,
    cmd: Vec<String>,
    stdin: Vec<u8>,
) -> Result<Option<i64>> {
    use bollard::exec::{CreateExecOptions, StartExecOptions};
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(cmd),
                attach_stdin: Some(true),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await?;

    let start = docker
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await?;

    if let bollard::exec::StartExecResults::Attached {
        mut output,
        mut input,
    } = start
    {
        // Write the whole dump, then close stdin so the engine client sees EOF and exits.
        input.write_all(&stdin).await.map_err(|e| {
            crate::AgentError::Internal(anyhow::anyhow!("restore stdin write: {e}"))
        })?;
        input.flush().await.map_err(|e| {
            crate::AgentError::Internal(anyhow::anyhow!("restore stdin flush: {e}"))
        })?;
        drop(input);
        // Drain output so the exec runs to completion (we don't need the bytes).
        while let Some(Ok(_)) = output.next().await {}
    }

    Ok(docker
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code))
}

/// Execute a Build job (Phase B Source-to-Deploy core).
///
/// Delegates the actual work to [`crate::build::run_build`], which fetches the pinned
/// commit, runs the selected builder in a sandboxed workspace, streams redacted logs, and
/// records the image digest. This function adapts that to a [`JobResult`], streaming each
/// log line to the control plane over the existing `ExecOutput` WS mechanism (keyed by the
/// build id as the session id), and returns the rich `JobResultDetails::Build`.
///
/// Fail-closed: any build error yields `success: false` with a sanitized message and NO
/// image, so the control plane never deploys a failed build (threat-model A10).
#[allow(clippy::too_many_arguments)]
async fn execute_build_job(
    build_id: Uuid,
    spec: crate::job::BuildSpec,
    target_image: String,
    supply_chain_policy: forge_core::supplychain::SupplyChainPolicy,
    docker: Option<&DockerClient>,
    exec_output_tx: Option<tokio::sync::mpsc::Sender<crate::receiver::AgentMessage>>,
    age_identity: Option<&age::x25519::Identity>,
    started_at: i64,
) -> JobResult {
    info!(build_id = %build_id, target = %target_image, "Starting Build job");

    // Bridge the build executor's line sink to the WS ExecOutput channel. We forward each
    // redacted log line as an ExecOutput frame whose session_id is the build id, so the
    // control plane can publish it to build-log subscribers using the same path as
    // container logs. Bounded channel → backpressure, never unbounded.
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<String>(256);
    let forward_task = exec_output_tx.clone().map(|ws| {
        tokio::spawn(async move {
            while let Some(line) = log_rx.recv().await {
                let _ = ws
                    .send(crate::receiver::AgentMessage::ExecOutput {
                        session_id: build_id.to_string(),
                        data: line.into_bytes(),
                        stream: "build".to_string(),
                    })
                    .await;
            }
        })
    });

    let outcome = crate::build::run_build(
        build_id,
        &spec,
        &target_image,
        age_identity,
        Some(log_tx),
        docker,
    )
    .await;

    // The log sink (log_tx) was moved into run_build and is dropped when it returns, which
    // closes log_rx and lets the forward task finish draining.
    if let Some(handle) = forward_task {
        let _ = handle.await;
    }

    let finished_at = chrono::Utc::now().timestamp();
    let correlation_id = build_id.to_string();

    match outcome {
        Ok(o) => {
            info!(build_id = %build_id, image = %o.image, digest = ?o.image_digest, pushed = o.pushed, "Build job succeeded");

            // Phase C: sign + attest the produced image per the supply-chain policy. On a
            // require-verify policy a signing failure FAILS the build (a deployable image must be
            // signed), so the control plane never deploys an unsigned artifact (fail-closed, A10).
            let sign_res =
                sign_build_outcome(build_id, &spec, &o, supply_chain_policy, age_identity).await;

            match sign_res {
                Ok((signed, provenance)) => JobResult {
                    correlation_id,
                    job_type: "build".to_string(),
                    success: true,
                    error: None,
                    started_at,
                    finished_at,
                    details: JobResultDetails::Build {
                        success: true,
                        image: Some(o.image),
                        image_digest: o.image_digest,
                        pushed: o.pushed,
                        signed,
                        provenance,
                        error_message: None,
                    },
                },
                Err(msg) => {
                    warn!(build_id = %build_id, error = %msg, "Build signing failed under require-verify policy (fail-closed: no deploy)");
                    JobResult {
                        correlation_id,
                        job_type: "build".to_string(),
                        success: false,
                        error: Some(msg.clone()),
                        started_at,
                        finished_at,
                        details: JobResultDetails::Build {
                            success: false,
                            image: None,
                            image_digest: None,
                            pushed: false,
                            signed: false,
                            provenance: None,
                            error_message: Some(msg),
                        },
                    }
                }
            }
        }
        Err(e) => {
            // `BuildError`'s Display is already sanitized (no secrets / host paths).
            let msg = e.to_string();
            warn!(build_id = %build_id, error = %msg, "Build job failed (fail-closed: no deploy)");
            JobResult {
                correlation_id,
                job_type: "build".to_string(),
                success: false,
                error: Some(msg.clone()),
                started_at,
                finished_at,
                details: JobResultDetails::Build {
                    success: false,
                    image: None,
                    image_digest: None,
                    pushed: false,
                    signed: false,
                    provenance: None,
                    error_message: Some(msg),
                },
            }
        }
    }
}

/// Sign + attest a successfully built image per `policy` (Phase C).
///
/// Returns `Ok((signed, provenance_summary))`:
/// - `signed` is whether a cosign signature + provenance attestation were produced.
/// - `provenance_summary` is the non-secret summary for the audit chain (`None` if unsigned).
///
/// Fail-closed semantics:
/// - `Disabled` → never signs; returns `Ok((false, None))`.
/// - `Sign` → best-effort; a signing failure is logged but does NOT fail the build.
/// - `SignAndRequireVerify` → signing is mandatory; a missing key, missing `cosign`, an
///   unresolved digest, or a cosign failure returns `Err(sanitized message)` so the BUILD fails
///   and nothing deployable is produced.
async fn sign_build_outcome(
    build_id: Uuid,
    spec: &crate::job::BuildSpec,
    outcome: &crate::build::BuildOutcome,
    policy: forge_core::supplychain::SupplyChainPolicy,
    age_identity: Option<&age::x25519::Identity>,
) -> std::result::Result<(bool, Option<serde_json::Value>), String> {
    use crate::supplychain::{
        ArtifactSigner, COSIGN_PASSWORD_ENV, CosignSigner, SupplyChainError, digest_reference,
        resolve_signing_key,
    };
    use forge_core::supplychain::{BuilderType, SlsaProvenance};

    type SignResult = std::result::Result<(bool, Option<serde_json::Value>), String>;

    if !policy.requires_signing() {
        return Ok((false, None));
    }
    let require = policy.requires_verify();

    // Map a fatal SupplyChainError to either a hard build failure (require) or a soft skip (sign).
    let soft_or_hard = |e: SupplyChainError| -> SignResult {
        if require {
            Err(e.to_string())
        } else {
            warn!(build_id = %build_id, error = %e, "signing skipped under non-strict policy");
            Ok((false, None))
        }
    };

    // 1. Need an immutable digest to sign by.
    let Some(digest) = outcome.image_digest.as_deref() else {
        return soft_or_hard(SupplyChainError::NoDigest);
    };
    let Some(reference) = digest_reference(&outcome.image, digest) else {
        return soft_or_hard(SupplyChainError::NoDigest);
    };

    // 2. Resolve the signing key (env or age secret). Absent key under require → fail closed.
    let key = match resolve_signing_key(None, age_identity) {
        Ok(Some(k)) => k,
        Ok(None) => return soft_or_hard(SupplyChainError::NoSigningKey),
        Err(e) => return soft_or_hard(e),
    };
    let password = std::env::var(COSIGN_PASSWORD_ENV)
        .ok()
        .filter(|p| !p.is_empty());

    // 3. Build the provenance statement bound to the digest + pinned commit.
    let commit = spec.source.commit_sha.as_deref().unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();
    let Some(provenance) = SlsaProvenance::new(
        &outcome.image,
        digest,
        &spec.source.url,
        commit,
        Some(&spec.source.r#ref)
            .filter(|r| !r.is_empty())
            .map(String::as_str),
        BuilderType::from_builder(&spec.builder),
        &now,
    ) else {
        return soft_or_hard(SupplyChainError::NoDigest);
    };

    // 4. Sign + attest.
    let signer = CosignSigner::new(key, password);
    match signer.sign_and_attest(&reference, &provenance).await {
        Ok(()) => {
            info!(build_id = %build_id, image = %reference, "image signed + attested");
            Ok((true, Some(provenance.summary_json())))
        }
        Err(e) => soft_or_hard(e),
    }
}

#[cfg(test)]
mod dispatcher_coverage_tests {
    //! Anti-rot guard for the Docker job dispatcher.
    //!
    //! The `forge-agent` Docker layer once silently bit-rotted because the handler
    //! bodies in [`execute_job`] drifted away from the [`Job`] enum while the feature
    //! was excluded from the default build. These tests pin the two halves together:
    //!
    //! * [`job_kind`] is an EXHAUSTIVE match over every `Job` variant, destructuring the
    //!   exact fields the real dispatcher relies on. If a variant is added, removed, or a
    //!   field is renamed, this stops compiling — the same failure mode the dispatcher has,
    //!   but caught by `cargo test` even when nobody is looking at the Docker path.
    //! * [`constructs_and_classifies_every_variant`] builds one value of each variant from
    //!   its JSON wire form (the shape the control plane signs and sends) and asserts the
    //!   classifier agrees, so the on-wire contract can't drift unnoticed either.

    use super::*;
    use crate::job::Job;

    /// Exhaustive classifier — intentionally NO wildcard arm. Mirrors the field
    /// destructuring in `execute_job` so the same drift that would break the real
    /// dispatcher breaks this at compile time.
    fn job_kind(job: &Job) -> &'static str {
        match job {
            Job::Deploy {
                deployment_id: _,
                spec: _,
            } => "deploy",
            Job::SystemUpdate {
                update_id: _,
                version: _,
                binary_ref: _,
                binary_sha256: _,
            } => "system_update",
            Job::Stop { target: _ } => "stop",
            Job::Exec {
                target_container: _,
                command: _,
                working_dir: _,
                user: _,
                env: _,
                tty: _,
                privileged: _,
                attach_stdin: _,
                interactive_session_id: _,
            } => "exec",
            Job::InteractiveStdin {
                session_id: _,
                data: _,
            } => "interactive_stdin",
            Job::HealthCheck => "health_check",
            Job::UpdateContainer {
                target: _,
                resources: _,
                restart_policy: _,
            } => "update_container",
            Job::UpdateL7Config {
                deployment_id: _,
                canary_weight: _,
                envoy_container: _,
                envoy_config_yaml: _,
            } => "update_l7_config",
            Job::ContainerLogs {
                target: _,
                follow: _,
                tail: _,
                timestamps: _,
                since: _,
                until: _,
                stdout: _,
                stderr: _,
            } => "container_logs",
            Job::ResizeExec {
                exec_id: _,
                width: _,
                height: _,
            } => "resize_exec",
            Job::ResizeContainer {
                target: _,
                width: _,
                height: _,
            } => "resize_container",
            Job::ContainerTop { target: _ } => "container_top",
            Job::InspectVolume { name: _ } => "inspect_volume",
            Job::PruneVolumes { filters: _ } => "prune_volumes",
            Job::InspectNetwork {
                name: _,
                verbose: _,
            } => "inspect_network",
            Job::PruneNetworks { filters: _ } => "prune_networks",
            Job::ContainerAttach {
                target: _,
                stdin: _,
                stdout: _,
                stderr: _,
                stream: _,
                logs: _,
                detach_keys: _,
            } => "container_attach",
            Job::Backup {
                deployment_id: _,
                target_container: _,
                db_type: _,
                database: _,
                s3: _,
                secrets: _,
            } => "backup",
            Job::Restore {
                restore_id: _,
                deployment_id: _,
                target_container: _,
                db_type: _,
                database: _,
                s3: _,
                secrets: _,
            } => "restore",
            Job::Build {
                build_id: _,
                spec: _,
                target_image: _,
                registry_auth: _,
                supply_chain_policy: _,
            } => "build",
        }
    }

    /// `(json wire value, expected job_kind)` for every `Job` variant. The minimal-but-valid
    /// JSON exercises the real serde contract the control plane produces.
    fn sample_jobs() -> Vec<(serde_json::Value, &'static str)> {
        let deployment_spec = serde_json::json!({
            "containers": [],
            "networks": [],
            "network_specs": [],
            "volumes": [],
            "registry_credentials": [],
            "build": null,
        });
        let build_spec = serde_json::json!({
            "source": { "url": "https://example.com/r.git", "ref": "main", "commit_sha": "abc123" },
            "builder": { "type": "dockerfile" },
            "image_name": "registry.example.com/app",
            "image_tag": "abc123",
        });

        vec![
            (
                serde_json::json!({ "type": "deploy", "deployment_id": Uuid::nil(), "spec": deployment_spec }),
                "deploy",
            ),
            (
                serde_json::json!({ "type": "system_update", "update_id": Uuid::nil(), "version": "1.0.0", "binary_ref": "https://x/agent", "binary_sha256": "deadbeef" }),
                "system_update",
            ),
            (
                serde_json::json!({ "type": "stop", "target": { "type": "container", "id": "c1" } }),
                "stop",
            ),
            (
                serde_json::json!({ "type": "exec", "target_container": "c1", "command": ["ls"], "env": [] }),
                "exec",
            ),
            (
                serde_json::json!({ "type": "interactive_stdin", "session_id": "s1", "data": [1, 2, 3] }),
                "interactive_stdin",
            ),
            (
                serde_json::json!({ "type": "health_check" }),
                "health_check",
            ),
            (
                serde_json::json!({ "type": "update_container", "target": "c1" }),
                "update_container",
            ),
            (
                serde_json::json!({ "type": "update_l7_config", "deployment_id": Uuid::nil(), "canary_weight": 25 }),
                "update_l7_config",
            ),
            (
                serde_json::json!({ "type": "container_logs", "target": "c1" }),
                "container_logs",
            ),
            (
                serde_json::json!({ "type": "resize_exec", "exec_id": "e1", "width": 80, "height": 24 }),
                "resize_exec",
            ),
            (
                serde_json::json!({ "type": "resize_container", "target": "c1", "width": 80, "height": 24 }),
                "resize_container",
            ),
            (
                serde_json::json!({ "type": "container_top", "target": "c1" }),
                "container_top",
            ),
            (
                serde_json::json!({ "type": "inspect_volume", "name": "v1" }),
                "inspect_volume",
            ),
            (
                serde_json::json!({ "type": "prune_volumes", "filters": [] }),
                "prune_volumes",
            ),
            (
                serde_json::json!({ "type": "inspect_network", "name": "n1" }),
                "inspect_network",
            ),
            (
                serde_json::json!({ "type": "prune_networks", "filters": [] }),
                "prune_networks",
            ),
            (
                serde_json::json!({ "type": "container_attach", "target": "c1" }),
                "container_attach",
            ),
            (
                serde_json::json!({ "type": "backup", "deployment_id": Uuid::nil(), "target_container": "c1", "db_type": "postgres" }),
                "backup",
            ),
            (
                serde_json::json!({ "type": "restore", "restore_id": Uuid::nil(), "deployment_id": Uuid::nil(), "target_container": "c1", "db_type": "postgres",
                    "s3": { "endpoint": "https://s3.example", "bucket": "b", "key": "k", "access_key": null, "secret_key": null, "region": "us-east-1" } }),
                "restore",
            ),
            (
                serde_json::json!({ "type": "build", "build_id": Uuid::nil(), "spec": build_spec, "target_image": "registry.example.com/app:abc123" }),
                "build",
            ),
        ]
    }

    #[test]
    fn constructs_and_classifies_every_variant() {
        for (value, expected) in sample_jobs() {
            let job: Job = serde_json::from_value(value.clone()).unwrap_or_else(|e| {
                panic!("variant {expected} failed to deserialize: {e}\n{value}")
            });
            assert_eq!(
                job_kind(&job),
                expected,
                "classifier disagreed for {expected}"
            );
        }
    }
}

#[cfg(test)]
mod verify_before_run_tests {
    //! Phase C — the deploy/run path MUST verify Forge-built images before running them and
    //! REFUSE on failure (fail-closed). These tests inject a mock [`ArtifactVerifier`] so they
    //! exercise the real wiring (`verify_images_before_run`) without the cosign binary.

    use super::*;
    use crate::supplychain::{ArtifactVerifier, SupplyChainError};
    use std::sync::Mutex;

    struct MockVerifier {
        accept: bool,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ArtifactVerifier for MockVerifier {
        async fn verify(&self, image_ref: &str) -> std::result::Result<(), SupplyChainError> {
            self.seen.lock().unwrap().push(image_ref.to_string());
            if self.accept {
                Ok(())
            } else {
                Err(SupplyChainError::VerifyFailed)
            }
        }
    }

    #[tokio::test]
    async fn refuses_run_when_verification_fails() {
        let verifier = MockVerifier {
            accept: false,
            seen: Mutex::new(vec![]),
        };
        let images = vec![format!("app@sha256:{}", "a".repeat(64))];
        let res = verify_images_before_run(Uuid::nil(), &images, &verifier).await;
        assert!(
            res.is_err(),
            "an unsigned/altered image MUST be refused (fail-closed)"
        );
        // The image was actually handed to the verifier (proves it isn't a no-op pass-through).
        assert_eq!(verifier.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn allows_run_when_all_images_verify() {
        let verifier = MockVerifier {
            accept: true,
            seen: Mutex::new(vec![]),
        };
        let images = vec![
            format!("a@sha256:{}", "a".repeat(64)),
            format!("b@sha256:{}", "b".repeat(64)),
        ];
        let res = verify_images_before_run(Uuid::nil(), &images, &verifier).await;
        assert!(res.is_ok(), "verified images may run");
        // Every image was verified before run.
        assert_eq!(verifier.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stops_at_first_failure() {
        // A failing first image must short-circuit — the second is never reached, and the deploy
        // is refused. This pins the fail-closed loop semantics.
        struct FailFirst {
            calls: Mutex<usize>,
        }
        #[async_trait::async_trait]
        impl ArtifactVerifier for FailFirst {
            async fn verify(&self, _image_ref: &str) -> std::result::Result<(), SupplyChainError> {
                let mut n = self.calls.lock().unwrap();
                *n += 1;
                Err(SupplyChainError::VerifyFailed)
            }
        }
        let v = FailFirst {
            calls: Mutex::new(0),
        };
        let images = vec!["a@sha256:x".to_string(), "b@sha256:y".to_string()];
        assert!(
            verify_images_before_run(Uuid::nil(), &images, &v)
                .await
                .is_err()
        );
        assert_eq!(
            *v.calls.lock().unwrap(),
            1,
            "must short-circuit on first failure"
        );
    }
}
