//! Forge Agent
//!
//! The secure execution agent that runs on every node managed by Forge.
//! This is the primary security boundary of the platform.

use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use forge_agent::{
    config::AgentConfig,
    execution::execute_job,
    receiver::{AgentTelemetry, ControlPlaneJobReceiver, MockJobReceiver},
    verification::verify_and_attest_job,
    AgentError,
};
use std::time::Duration;

use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

#[cfg(feature = "docker")]
type DockerClient = bollard::Docker;
#[cfg(not(feature = "docker"))]
type DockerClient = ();

// Re-export the canonical definition so the rest of the crate (including handover logic) continues to work.
pub use forge_agent::receiver::AgentReadinessState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "forge_agent=info".into()),
        )
        .json()
        .init();

    info!("Forge Agent starting");

    let config_path = std::env::var("FORGE_AGENT_CONFIG")
        .ok()
        .map(PathBuf::from);

    let config = AgentConfig::from_env_and_file(config_path.as_deref())
        .map_err(|e| AgentError::Config(e.to_string()))?;

    info!(
        control_plane = %config.control_plane_url,
        "Agent configuration loaded"
    );

    // Initialize WireGuard mesh if enabled (basic bootstrap; full sync comes later via control plane).
    if let Err(e) = forge_agent::wireguard::initialize_wireguard(&config) {
        warn!(error = %e, "Failed to initialize WireGuard (non-fatal for now)");
    }

    // Check if we were started as part of a graceful self-update handover
    let handover_socket = std::env::var("FORGE_AGENT_HANDOVER_SOCKET").ok();
    let handover_version = std::env::var("FORGE_AGENT_HANDOVER_VERSION").ok();

    if let Some(ref sock) = handover_socket {
        info!(
            socket = %sock,
            version = ?handover_version,
            "Agent started in handover mode (self-update)"
        );
    }

    // === ENROLLMENT / IDENTITY BOOTSTRAP ===
    // This is the secure bootstrap path. A fresh agent generates an identity and
    // uses a one-time enrollment token to obtain the control plane public key + credentials.
    let mut identity = forge_agent::identity::load_or_create_identity(&config)?;

    if identity.control_plane_public_key.is_none() || identity.agent_id.is_none() {
        if let Err(e) = tokio::runtime::Handle::current()
            .block_on(forge_agent::identity::enroll_if_needed(&config, &mut identity))
        {
            error!(error = %e, "Agent enrollment failed — this is fatal on first run");
            // Production: do not continue without successful enrollment.
            // The excellent error message above guides the operator.
            std::process::exit(1);
        }
    }

    let control_plane_public_key = if let Some(bytes) = &identity.control_plane_public_key {
        if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(bytes.as_slice().try_into().unwrap_or(&[0u8; 32])) {
            key
        } else {
            get_control_plane_public_key(&config)?
        }
    } else {
        get_control_plane_public_key(&config)?
    };

    // Tier 3-2: extract the age identity once (for secret decryption). We take ownership here for the main loop.
    let age_identity = identity.age_identity();

    // Readiness channel used for graceful self-update handover.
    // The new agent will only signal "READY" to the old agent once these milestones are reached.
    let (readiness_tx, readiness_rx) = watch::channel(AgentReadinessState::default());

    // Shared telemetry state for richer heartbeats and observability.
    let telemetry = AgentTelemetry::default();

    // Prefer real control plane connection. Fall back to mock only if explicitly
    // requested via FORGE_AGENT_USE_MOCK_RECEIVER=true (useful for local testing).
    let use_mock = std::env::var("FORGE_AGENT_USE_MOCK_RECEIVER")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut receiver: Box<dyn forge_agent::receiver::JobReceiver> = if use_mock {
        info!("Using mock receiver (FORGE_AGENT_USE_MOCK_RECEIVER=true)");
        // For mock we simulate readiness so handover testing still works.
        readiness_tx.send_modify(|state| {
            state.control_plane_connected = true;
            state.first_heartbeat_sent = true;
        });
        let (rx, _tx) = MockJobReceiver::channel(32);
        Box::new(rx)
    } else {
        info!("Connecting to real control plane at {}", config.control_plane_url);
        let effective_token = identity.agent_token.clone().unwrap_or_else(|| config.agent_token.clone());

        match ControlPlaneJobReceiver::connect(&config.control_plane_url, &effective_token, Some(readiness_tx.clone()), Some(telemetry.clone())).await {
            Ok(real_rx) => {
                info!("Successfully connected to control plane WebSocket");
                Box::new(real_rx)
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to control plane — falling back to mock receiver");
                // For mock fallback we still simulate readiness.
                readiness_tx.send_modify(|state| {
                    state.control_plane_connected = true;
                    state.first_heartbeat_sent = true;
                });
                let (rx, _tx) = MockJobReceiver::channel(32);
                Box::new(rx)
            }
        }
    };

    info!("Agent ready to receive jobs");

    // If we are in handover mode, wait for the agent to become meaningfully ready
    // before performing the client-side handshake.
    if let Some(socket_path) = handover_socket.clone() {
        let readiness = readiness_rx.clone();
        tokio::spawn(async move {
            // Wait until the agent has connected to the control plane and sent its first heartbeat.
            // This makes the handover signal much more meaningful and realistic.
            if readiness
                .clone()
                .wait_for(|state| state.control_plane_connected && state.first_heartbeat_sent)
                .await
                .is_err()
            {
                warn!("Readiness channel closed before agent became ready for handover");
                return;
            }

            info!("Agent is ready (control plane connected + first heartbeat sent) — initiating handover handshake");

            match perform_handover_handshake(&socket_path).await {
                Ok(()) => info!("Handover handshake with old agent completed successfully"),
                Err(e) => error!(error = ?e, "Handover handshake failed"),
            }
        });
    }

    let shutdown = signal::ctrl_c();

    // Pass readiness channel so the agent can update handover state
    let readiness_tx = Some(readiness_tx);

    // Create Docker client if the feature is enabled (respecting config)
    #[cfg(feature = "docker")]
    let docker_client: Option<DockerClient> = {
        let socket = &config.docker_socket;
        match bollard::Docker::connect_with_socket(socket, 120, bollard::API_DEFAULT_VERSION) {
            Ok(client) => {
                info!(socket = %socket, "Connected to Docker daemon");
                Some(client)
            }
            Err(e) => {
                error!(error = ?e, "Failed to connect to Docker daemon — Docker jobs will fail");
                None
            }
        }
    };
    #[cfg(not(feature = "docker"))]
    let docker_client: Option<DockerClient> = None;

    tokio::select! {
        _ = shutdown => {
            info!("Received shutdown signal");
        }
        _ = run_agent(&config, &mut *receiver, &control_plane_public_key, readiness_tx, docker_client.as_ref(), &telemetry, age_identity) => {
            warn!("Agent main loop exited");
        }
    }

    info!("Forge Agent shutting down gracefully");
    Ok(())
}

/// Client side of the graceful handover handshake.
/// Called by the *new* agent process when `FORGE_AGENT_HANDOVER_SOCKET` is set.
async fn perform_handover_handshake(socket_path: &str) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    info!(socket = %socket_path, "Connecting to old agent for handover handshake");

    let mut stream = UnixStream::connect(socket_path).await?;

    // Tell the old process we are ready and have taken over
    stream.write_all(b"READY").await?;
    stream.flush().await?;

    // Wait for acknowledgment (best effort)
    let mut buf = [0u8; 8];
    match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if &buf[..n] == b"ACK" => {
            info!("Received ACK from old agent — graceful handover complete");
        }
        _ => {
            warn!("Did not receive ACK from old agent (it may have already exited)");
        }
    }

    Ok(())
}

/// Main agent loop: receive jobs, verify them, then execute.
///
/// This is the security-critical path.
async fn run_agent(
    _config: &AgentConfig,
    receiver: &mut dyn forge_agent::receiver::JobReceiver,
    public_key: &VerifyingKey,
    _readiness_tx: Option<watch::Sender<AgentReadinessState>>,
    docker: Option<&DockerClient>,
    telemetry: &forge_agent::receiver::AgentTelemetry,
    // Tier 3-2: agent's age identity (for secret decryption in Deploy jobs). Owned so it can be moved into the loop if needed.
    age_identity: Option<age::x25519::Identity>,
) {
    info!("Entering job processing loop");

    let mut health_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // Normal job path
            maybe_job = receiver.recv() => {
                let Some(signed_job) = maybe_job else { break; };

                let job_id = match &signed_job.job {
                    forge_agent::job::Job::Deploy { deployment_id, .. } => deployment_id.to_string(),
                    forge_agent::job::Job::SystemUpdate { update_id, .. } => update_id.to_string(),
                    _ => "unknown".to_string(),
                };

                info!(job_id = %job_id, "Received signed job");

                if let Err(e) = verify_and_attest_job(&signed_job, public_key) {
                    error!(job_id = %job_id, error = ?e, "Job verification failed — rejecting job");
                    continue;
                }

                info!(job_id = %job_id, "Job signature and attestation verified successfully");

                // Pass the agent's age identity so deploy jobs can decrypt secrets (Tier 3-2)
                let result = execute_job(signed_job.job, docker, None, age_identity.as_ref()).await;

                if result.success {
                    info!(job_id = %job_id, correlation = %result.correlation_id, "Job executed successfully");

                    // Update shared telemetry for richer heartbeats.
                    if result.job_type == "deploy" {
                        telemetry
                            .managed_container_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    } else if result.job_type == "stop" {
                        telemetry
                            .managed_container_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    error!(job_id = %job_id, correlation = %result.correlation_id, error = ?result.error, "Job execution failed");
                }

                receiver.report_result(result).await;
            }

            // Periodic rich health reporting (now that result reporting works)
            _ = health_interval.tick() => {
                if docker.is_some() {
                    let health_result = execute_job(forge_agent::job::Job::HealthCheck, docker, None, None).await;
                    receiver.report_result(health_result).await;
                }
            }
        }
    }
}

/// Loads or derives the control plane's public key used for job verification.
///
/// In production this will come from secure enrollment.
fn get_control_plane_public_key(_config: &AgentConfig) -> Result<VerifyingKey, AgentError> {
    // Placeholder: In a real system this key would be obtained during agent enrollment
    // and stored securely (e.g. in a TPM or encrypted file).
    //
    // For development we generate a dummy key so the verification code path can be exercised.
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    Ok(signing_key.verifying_key())
}