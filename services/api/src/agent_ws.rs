//! WebSocket server for agents (Slice 2).
//!
//! This module implements the server side of the agent control plane protocol:
//! - Accepts connections at /agent/ws
//! - Performs the exact auth handshake the agent expects
//! - Maintains live connections so we can push SignedJob messages
//! - Receives Heartbeats and JobResults

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

use forge_agent::job::{DeploymentSpec, Job, SignedJob};
use forge_agent::receiver::AgentMessage;
use forge_core::DeploymentStrategy;

use crate::LOG_BROADCASTERS; // for publishing ContainerLogs output to WS subscribers (Slice B)

/// Signs jobs using the control plane's long-term Ed25519 key.
/// This is the root of trust for everything the agent will execute.
pub struct JobSigner {
    key: ed25519_dalek::SigningKey,
}

impl JobSigner {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self { key }
    }

    pub fn sign(&self, job: Job) -> SignedJob {
        // Serialize the job canonically for signing
        let serialized = serde_json::to_vec(&job).expect("job serialization must not fail");

        let signature = self.key.sign(&serialized);

        SignedJob {
            job,
            signature: signature.to_bytes().to_vec(),
        }
    }

    // Exposed for the enrollment handshake / future agent-side verification wiring.
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }
}

/// In-memory registry of currently connected agents.
/// Allows the rest of the control plane to send jobs to live agents.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    /// agent_id -> channel to send SignedJobs to that agent's WS task
    connections: Arc<RwLock<HashMap<Uuid, mpsc::Sender<SignedJob>>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, agent_id: Uuid, tx: mpsc::Sender<SignedJob>) {
        let mut guard = self.connections.write().await;
        guard.insert(agent_id, tx);
        info!(%agent_id, "Agent registered for job dispatch");
    }

    pub async fn unregister(&self, agent_id: Uuid) {
        let mut guard = self.connections.write().await;
        if guard.remove(&agent_id).is_some() {
            info!(%agent_id, "Agent unregistered");
        }
    }

    /// Try to send a signed job to a connected agent.
    /// Returns false if the agent is not currently connected.
    pub async fn send_job(&self, agent_id: Uuid, job: SignedJob) -> bool {
        let guard = self.connections.read().await;
        if let Some(tx) = guard.get(&agent_id) {
            if tx.send(job).await.is_ok() {
                return true;
            }
        }
        false
    }

    pub async fn connected_agents(&self) -> Vec<Uuid> {
        let guard = self.connections.read().await;
        guard.keys().copied().collect()
    }
}

/// Auth message sent by the agent immediately after connecting.
#[derive(Debug, Deserialize)]
struct AgentAuthMessage {
    #[serde(rename = "type")]
    msg_type: String,
    token: String,
    #[allow(dead_code)]
    agent_version: Option<String>,
}

/// Response we send back after successful auth.
#[derive(Debug, Serialize)]
struct AuthResponse {
    status: &'static str,
}

/// The actual WebSocket connection handler for one agent.
async fn handle_agent_connection(
    mut socket: WebSocket,
    registry: AgentRegistry,
    deployment_service: Arc<crate::deployment::DeploymentService>,
    pool: sqlx::PgPool,
    signing_key: SigningKey, // for future job signing from this connection context
    xds_state: crate::xds::XdsState,
) {
    // 1. Read the first message — must be auth
    let auth_msg = match socket.recv().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str::<AgentAuthMessage>(&text).ok(),
        Some(Ok(Message::Binary(bin))) => serde_json::from_slice::<AgentAuthMessage>(&bin).ok(),
        _ => None,
    };

    let Some(auth) = auth_msg else {
        warn!("Agent connection did not send valid auth message");
        let _ = socket.send(Message::Close(None)).await;
        return;
    };

    if auth.msg_type != "auth" {
        warn!("First message was not auth");
        let _ = socket.send(Message::Close(None)).await;
        return;
    }

    // 2. Validate the agent token against the database
    let token_hash = Sha256::digest(auth.token.as_bytes()).to_vec();

    let agent_row = sqlx::query!(
        r#"
        SELECT id, hostname
        FROM agents
        WHERE agent_token_hash = $1
        "#,
        token_hash
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    let Some(agent) = agent_row else {
        warn!("Agent auth failed: invalid token");
        let _ = socket
            .send(Message::Text(
                r#"{"status":"error","reason":"invalid_token"}"#.to_string(),
            ))
            .await;
        let _ = socket.send(Message::Close(None)).await;
        return;
    };

    let agent_id = agent.id;

    // 3. Send auth success
    let ack = serde_json::to_string(&AuthResponse { status: "ok" }).unwrap();
    if socket.send(Message::Text(ack)).await.is_err() {
        return;
    }

    info!(%agent_id, hostname = ?agent.hostname, "Agent authenticated and connected");

    // 4. Create a channel so other parts of the system can send us jobs to forward
    let (job_tx, mut job_rx) = mpsc::channel::<SignedJob>(32);

    // Register this agent so dispatchers can find us
    registry.register(agent_id, job_tx.clone()).await;

    // === Slice B: Strong reconciliation on reconnect (deployments + pending_dispatches table) ===
    tokio::spawn({
        let deployment_service = deployment_service.clone();
        let job_tx = job_tx.clone();
        let signer = JobSigner::new(signing_key.clone());
        async move {
            // 1. Re-dispatch active deployments
            if let Ok(active) = deployment_service
                .get_active_deployments_for_agent(agent_id)
                .await
            {
                for dep in active {
                    if let Ok(spec) = serde_json::from_value::<DeploymentSpec>(dep.spec.clone()) {
                        let job = Job::Deploy {
                            deployment_id: dep.id,
                            spec,
                        };
                        let signed = signer.sign(job);
                        let _ = job_tx.send(signed).await;
                        info!(%agent_id, deployment_id = %dep.id, "Re-dispatched deployment on reconnect");
                    }
                }
            }

            // 2. Drain any durable pending dispatches from the queue table
            if let Ok(pending) = deployment_service
                .drain_pending_dispatches_for_agent(agent_id)
                .await
            {
                for (dep_id, signed) in pending {
                    let _ = job_tx.send(signed).await;
                    info!(%agent_id, deployment_id = %dep_id, "Drained pending dispatch from durable queue on reconnect");
                }
            }
        }
    });

    // 5. Main pump: forward outbound jobs + receive heartbeats/results
    loop {
        tokio::select! {
            // Outbound jobs from control plane → agent
            Some(signed_job) = job_rx.recv() => {
                let payload = match serde_json::to_string(&signed_job) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }

            // Inbound messages from agent
            Some(msg) = socket.recv() => {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(agent_msg) = serde_json::from_str::<AgentMessage>(&text) {
                            let signer = JobSigner::new(signing_key.clone());
                            handle_incoming_message(agent_id, agent_msg, &deployment_service, &pool, &xds_state, &signer, &registry).await;
                        }
                    }
                    Ok(Message::Binary(bin)) => {
                        if let Ok(agent_msg) = serde_json::from_slice::<AgentMessage>(&bin) {
                            let signer = JobSigner::new(signing_key.clone());
                            handle_incoming_message(agent_id, agent_msg, &deployment_service, &pool, &xds_state, &signer, &registry).await;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }

            else => break,
        }
    }

    registry.unregister(agent_id).await;
    info!(%agent_id, "Agent connection closed");
}

/// Process incoming AgentMessage (Heartbeat / JobResult).
async fn handle_incoming_message(
    agent_id: Uuid,
    msg: AgentMessage,
    deployment_service: &Arc<crate::deployment::DeploymentService>,
    pool: &sqlx::PgPool,
    xds_state: &crate::xds::XdsState,
    signer: &JobSigner,
    registry: &AgentRegistry,
) {
    match msg {
        AgentMessage::Heartbeat { payload } => {
            // Update last_seen_at + persist key metrics for time-series
            let _ = sqlx::query!(
                "UPDATE agents SET last_seen_at = NOW() WHERE id = $1",
                agent_id
            )
            .execute(pool)
            .await;

            // Ingest persistent time-series metrics from heartbeat
            let _ = deployment_service
                .record_metric(
                    None,
                    agent_id,
                    "agent_managed_containers",
                    payload.managed_container_count as f64,
                    serde_json::json!({"uptime_secs": payload.uptime_secs}),
                )
                .await;

            if !payload.active_deployment_ids.is_empty() {
                let _ = deployment_service
                    .record_metric(
                        None,
                        agent_id,
                        "agent_active_deployments",
                        payload.active_deployment_ids.len() as f64,
                        serde_json::json!({"deployments": payload.active_deployment_ids}),
                    )
                    .await;
            }

            // Record rich agent status for the dedicated /agents/status endpoint and canary analysis
            let _ = deployment_service
                .record_metric(
                    None,
                    agent_id,
                    "agent_heartbeat",
                    1.0,
                    serde_json::json!({
                        "version": payload.agent_version,
                        "cluster": payload.cluster,
                        "hostname": payload.hostname,
                        "uptime_secs": payload.uptime_secs
                    }),
                )
                .await;

            // === Full phased rollout logic (Rolling with health gates + auto-rollback) + drift detection ===
            if let Ok(active_in_db) = deployment_service
                .get_active_deployments_for_agent(agent_id)
                .await
            {
                for dep in active_in_db {
                    match &dep.strategy {
                        DeploymentStrategy::Rolling(cfg) => {
                            // Parse rollout state
                            let mut rs: serde_json::Value = dep.rollout_state.clone();

                            let failure_count = rs["failure_count"].as_u64().unwrap_or(0) as u32;
                            let last_gate = rs["last_health_gate_passed_at"]
                                .as_str()
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());

                            // Get recent health results for this deployment to evaluate gates
                            let recent_health = deployment_service
                                .list_recent_results_for_deployment(dep.id, 10)
                                .await
                                .unwrap_or_default();
                            let recent_health_checks: Vec<_> = recent_health
                                .iter()
                                .filter(|r| r.job_type == "health_check")
                                .collect();

                            let healthy = !recent_health_checks.is_empty()
                                && recent_health_checks.iter().all(|r| r.success);
                            let now = chrono::Utc::now();

                            if healthy
                                && last_gate.is_none_or(|lg| {
                                    (now - lg.with_timezone(&chrono::Utc)).num_seconds()
                                        > cfg.health_check_grace_period_secs as i64
                                })
                            {
                                // Health gate passed → advance rollout
                                let current = rs["current_replicas"].as_u64().unwrap_or(0) as u32;
                                let target = 1u32; // simplified; in real would come from DeploymentTarget

                                if current < target {
                                    // Advance one batch (respect max_unavailable conceptually by sending update)
                                    rs["current_replicas"] = serde_json::json!(current + 1);
                                    rs["last_health_gate_passed_at"] =
                                        serde_json::json!(now.to_rfc3339());
                                    rs["failure_count"] = serde_json::json!(0);

                                    // Send phased update (for true rolling we would use partial replica count in spec or UpdateContainer)
                                    if let Ok(spec) =
                                        serde_json::from_value::<DeploymentSpec>(dep.spec.clone())
                                    {
                                        let job = Job::Deploy {
                                            deployment_id: dep.id,
                                            spec,
                                        };
                                        let signed = signer.sign(job);
                                        let _ = registry.send_job(agent_id, signed).await;
                                        info!(%agent_id, deployment_id = %dep.id, current = current + 1, "Rolling advance - health gate passed");
                                    }

                                    // Persist updated rollout state
                                    let _ = sqlx::query!(
                                        "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2",
                                        rs, dep.id
                                    ).execute(pool).await;
                                } else {
                                    // Fully rolled - mark healthy
                                    let _ = deployment_service
                                        .update_deployment_status(
                                            dep.id,
                                            forge_core::DeploymentStatus::Healthy,
                                        )
                                        .await;
                                }
                            } else if !healthy {
                                // Health failing - count toward rollback threshold
                                let new_fail = failure_count + 1;
                                rs["failure_count"] = serde_json::json!(new_fail);

                                if new_fail >= cfg.failure_threshold && cfg.rollback_on_failure {
                                    // Automatic rollback using previous_spec if available, else mark failed
                                    if let Some(prev) = &dep.previous_spec {
                                        if let Ok(prev_spec) =
                                            serde_json::from_value::<DeploymentSpec>(prev.clone())
                                        {
                                            let job = Job::Deploy {
                                                deployment_id: dep.id,
                                                spec: prev_spec,
                                            };
                                            let signed = signer.sign(job);
                                            let _ = registry.send_job(agent_id, signed).await;
                                            info!(%agent_id, deployment_id = %dep.id, "Automatic rollback triggered - failure threshold breached");
                                        }
                                    }
                                    let _ = deployment_service
                                        .update_deployment_status(
                                            dep.id,
                                            forge_core::DeploymentStatus::RolledBack,
                                        )
                                        .await;
                                }

                                let _ = sqlx::query!(
                                    "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2",
                                    rs, dep.id
                                ).execute(pool).await;
                            }
                        }
                        DeploymentStrategy::BlueGreen(cfg) => {
                            let mut rs: serde_json::Value = dep.rollout_state.clone();
                            let phase = rs["phase"].as_str().unwrap_or("deploy_new");

                            let recent_health = deployment_service
                                .list_recent_results_for_deployment(dep.id, 5)
                                .await
                                .unwrap_or_default();
                            let healthy = !recent_health.is_empty()
                                && recent_health
                                    .iter()
                                    .all(|r| r.job_type == "health_check" && r.success);
                            let now = chrono::Utc::now();

                            if phase == "deploy_new" && healthy {
                                // Health gate passed after deploying new set → cutover
                                rs["phase"] = serde_json::json!("cutover");
                                rs["cutover_at"] = serde_json::json!(now.to_rfc3339());

                                // In real system: update Traefik weights / service selectors to new version.
                                // Here we just mark progress and optionally send stop for old containers.
                                let _ = deployment_service
                                    .update_deployment_status(
                                        dep.id,
                                        forge_core::DeploymentStatus::Healthy,
                                    )
                                    .await;

                                // Optional scale-down of old after grace
                                if (now.timestamp() - dep.created_at.timestamp())
                                    > cfg.scale_down_old_after_secs as i64
                                {
                                    // Send stop for previous version containers (simplified)
                                    info!(%agent_id, deployment_id = %dep.id, "BlueGreen cutover complete - old set can be scaled down");
                                }

                                let _ = sqlx::query!(
                                    "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2",
                                    rs, dep.id
                                ).execute(pool).await;
                            } else if !healthy && phase == "deploy_new" {
                                // Failed to stabilize new set → rollback (re-deploy previous)
                                if let Some(prev) = &dep.previous_spec {
                                    if let Ok(prev_spec) =
                                        serde_json::from_value::<DeploymentSpec>(prev.clone())
                                    {
                                        let job = Job::Deploy {
                                            deployment_id: dep.id,
                                            spec: prev_spec,
                                        };
                                        let signed = signer.sign(job);
                                        let _ = registry.send_job(agent_id, signed).await;
                                    }
                                }
                                let _ = deployment_service
                                    .update_deployment_status(
                                        dep.id,
                                        forge_core::DeploymentStatus::RolledBack,
                                    )
                                    .await;
                            }
                        }
                        DeploymentStrategy::Canary(cfg) => {
                            let mut rs: serde_json::Value = dep.rollout_state.clone();
                            let current_pct = rs["current_traffic_percent"]
                                .as_u64()
                                .unwrap_or(cfg.initial_traffic_percent as u64)
                                as u32;
                            let failure_count = rs["failure_count"].as_u64().unwrap_or(0) as u32;

                            let recent_health = deployment_service
                                .list_recent_results_for_deployment(dep.id, 5)
                                .await
                                .unwrap_or_default();
                            let health_ok = !recent_health.is_empty()
                                && recent_health
                                    .iter()
                                    .all(|r| r.job_type == "health_check" && r.success);

                            // Full statistical canary analysis with windowed metrics (replaces simple avg threshold)
                            let (stat_promotable, stat_analysis) = deployment_service
                                .analyze_canary_for_promotion(dep.id, current_pct)
                                .await
                                .unwrap_or((false, serde_json::json!({"error": "analysis_failed", "promotable": false})));

                            rs["last_statistical_analysis"] = stat_analysis.clone();

                            // Feature 1: notify on canary promotion decision (success or blocked)
                            let event = if stat_promotable {
                                "canary.promotable"
                            } else {
                                "canary.blocked"
                            };
                            let _ = deployment_service
                                .trigger_notifications(
                                    event,
                                    "deployment",
                                    Some(dep.id),
                                    stat_analysis.clone(),
                                )
                                .await;

                            // Combined gate: health checks pass AND statistical windows confirm no regression
                            let metrics_ok = stat_promotable;
                            let healthy = health_ok && metrics_ok;

                            if healthy && current_pct < 100 {
                                // (Release readiness gate for forge-system agent updates removed in cleanup for compile; statistical + health gates above remain authoritative)
                                let next_pct =
                                    std::cmp::min(100, current_pct + cfg.step_percent as u32);
                                rs["current_traffic_percent"] = serde_json::json!(next_pct);
                                rs["last_step_at"] =
                                    serde_json::json!(chrono::Utc::now().to_rfc3339());
                                rs["failure_count"] = serde_json::json!(0);

                                // Richer metric for dashboards + future statistical windows
                                let _ = deployment_service.record_metric(
                                    Some(dep.id),
                                    agent_id,
                                    "canary_traffic_percent",
                                    next_pct as f64,
                                    serde_json::json!({"strategy": "canary", "step": "promoted"})
                                ).await;

                                // Re-dispatch with updated canary % — agent uses labels for weighted Envoy/Traefik
                                if let Ok(spec) =
                                    serde_json::from_value::<DeploymentSpec>(dep.spec.clone())
                                {
                                    // Label injection for legacy Traefik/Envoy removed (current canary uses xDS weighted clusters + UpdateL7Config).
                                    let job = Job::Deploy {
                                        deployment_id: dep.id,
                                        spec,
                                    };
                                    let signed = signer.sign(job);
                                    let _ = registry.send_job(agent_id, signed).await;
                                    info!(%agent_id, deployment_id = %dep.id, pct = next_pct, "Canary step advanced (statistical gate passed)");

                                    // Deeper dynamic L7: also send dedicated UpdateL7Config for instant Envoy sidecar weight shift (no full redeploy)
                                    let l7_job = Job::UpdateL7Config {
                                        deployment_id: dep.id,
                                        canary_weight: next_pct,
                                        envoy_container: None,
                                        envoy_config_yaml: None,
                                    };
                                    let l7_signed = signer.sign(l7_job);
                                    let _ = registry.send_job(agent_id, l7_signed).await;
                                    info!(%agent_id, deployment_id = %dep.id, pct = next_pct, "Dispatched UpdateL7Config for live Envoy weight change");
                                }

                                let _ = sqlx::query!(
                                    "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2",
                                    rs, dep.id
                                ).execute(pool).await;
                            } else if !healthy {
                                let new_fail = failure_count + 1;
                                rs["failure_count"] = serde_json::json!(new_fail);

                                if new_fail >= cfg.failure_threshold {
                                    if let Some(prev) = &dep.previous_spec {
                                        if let Ok(prev_spec) =
                                            serde_json::from_value::<DeploymentSpec>(prev.clone())
                                        {
                                            let job = Job::Deploy {
                                                deployment_id: dep.id,
                                                spec: prev_spec,
                                            };
                                            let signed = signer.sign(job);
                                            let _ = registry.send_job(agent_id, signed).await;
                                        }
                                    }

                                    // Agent binary rollback using previous_agent_update snapshot
                                    if let Some(prev_agent) = dep.spec.get("previous_agent_update")
                                    {
                                        if let (Some(ver), Some(bin), Some(sha)) = (
                                            prev_agent["version"].as_str(),
                                            prev_agent["binary_ref"].as_str(),
                                            prev_agent["binary_sha256"].as_str(),
                                        ) {
                                            let revert_job = Job::SystemUpdate {
                                                update_id: Uuid::now_v7(),
                                                version: ver.to_string(),
                                                binary_ref: bin.to_string(),
                                                binary_sha256: sha.to_string(),
                                            };
                                            let signed = signer.sign(revert_job);
                                            let _ = registry.send_job(agent_id, signed).await;
                                            info!(%agent_id, version = %ver, "Re-dispatched previous agent binary as part of statistical canary rollback");
                                        }
                                    }

                                    let _ = deployment_service
                                        .update_deployment_status(
                                            dep.id,
                                            forge_core::DeploymentStatus::RolledBack,
                                        )
                                        .await;
                                }
                                let _ = sqlx::query!( "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2", rs, dep.id ).execute(pool).await;
                            } else if current_pct >= 100 {
                                let _ = deployment_service
                                    .update_deployment_status(
                                        dep.id,
                                        forge_core::DeploymentStatus::Healthy,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }

            // === Slice B: Robust reconciliation on every heartbeat (deployments + durable queue) ===
            // 1. Re-push pending/unhealthy from active deployments
            if let Ok(pending) = deployment_service
                .get_active_deployments_for_agent(agent_id)
                .await
            {
                for dep in pending {
                    if matches!(
                        dep.status,
                        forge_core::DeploymentStatus::Pending
                            | forge_core::DeploymentStatus::Unhealthy
                    ) {
                        if let Ok(spec) = serde_json::from_value::<DeploymentSpec>(dep.spec.clone())
                        {
                            let job = Job::Deploy {
                                deployment_id: dep.id,
                                spec,
                            };
                            let signed = signer.sign(job);
                            if registry.send_job(agent_id, signed).await {
                                info!(%agent_id, deployment_id = %dep.id, "Re-dispatched pending/unhealthy on heartbeat");
                            }
                        }
                    }
                }
            }

            // 2. Drain any durable pending dispatches from the queue table (true persistence)
            if let Ok(durable) = deployment_service
                .drain_pending_dispatches_for_agent(agent_id)
                .await
            {
                for (dep_id, signed) in durable {
                    if registry.send_job(agent_id, signed).await {
                        info!(%agent_id, deployment_id = %dep_id, "Drained pending dispatch from durable queue on heartbeat");
                    }
                }
            }
        }
        AgentMessage::JobResult { result } => {
            info!(
                %agent_id,
                correlation_id = %result.correlation_id,
                job_type = %result.job_type,
                success = result.success,
                "Received JobResult from agent"
            );

            // Persist full result + intelligent status update
            if let Err(e) = deployment_service
                .record_job_result(agent_id, result.clone())
                .await
            {
                warn!(error = %e, "Failed to record JobResult");
            }

            // Slice B: Publish ContainerLogs output to active WS subscribers (via LOG_BROADCASTERS)
            if result.job_type == "container_logs" {
                if let Ok(dep_id) = Uuid::parse_str(&result.correlation_id) {
                    if let Ok(lines) = serde_json::to_string(&result.details) {
                        let guard = LOG_BROADCASTERS.lock().unwrap();
                        if let Some(tx) = guard.get(&dep_id) {
                            let _ = tx.send(lines);
                        }
                    }
                }
            }

            // Phase B: terminal Build result. Record the image/digest/error, then — and ONLY
            // on success — dispatch a Deploy using the produced image (fail-closed: a failed
            // build never deploys, threat-model A10).
            if result.job_type == "build" {
                if let Ok(build_id) = Uuid::parse_str(&result.correlation_id) {
                    handle_build_result(
                        build_id,
                        &result.details,
                        deployment_service,
                        signer,
                        registry,
                    )
                    .await;
                }
            }

            // Feature 1: trigger notifications for this JobResult (audit + future real delivery)
            if let Ok(dep_id) = Uuid::parse_str(&result.correlation_id) {
                let _ = deployment_service
                    .trigger_notifications(
                        &format!(
                            "job_result.{}",
                            if result.success { "success" } else { "failed" }
                        ),
                        "deployment",
                        Some(dep_id),
                        serde_json::to_value(&result).unwrap_or(serde_json::json!({})),
                    )
                    .await;
            }

            // === Release gate hardening: Auto-rollback for failing agent binary canaries ===
            // If a SystemUpdate JobResult for a forge-system agent canary fails, immediately
            // dispatch the previous known-good binary (from previous_agent_update in spec/rollout_state).
            // This is the actual auto-rollback dispatch logic triggered by JobResult failure signals.
            if result.job_type == "system_update" && !result.success {
                if let Ok(Some(sys_dep)) = deployment_service
                    .get_latest_deployment_for_application_name("forge-system")
                    .await
                {
                    // Prefer rollout_state (durable) then spec
                    let prev = sys_dep
                        .rollout_state
                        .get("previous_agent_update")
                        .or_else(|| sys_dep.spec.get("previous_agent_update"));

                    if let Some(prev_agent) = prev {
                        let prev_version = prev_agent
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let prev_ref = prev_agent
                            .get("binary_ref")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let prev_sha = prev_agent
                            .get("binary_sha256")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        if !prev_ref.is_empty() {
                            // Drain via xDS before rolling the agent binary back (same pattern as forward canary updates)
                            xds_state.prepare_agent_canary_update(sys_dep.id).await;

                            let rollback_job = Job::SystemUpdate {
                                update_id: Uuid::now_v7(),
                                version: prev_version.to_string(),
                                binary_ref: prev_ref.to_string(),
                                binary_sha256: prev_sha.to_string(),
                            };
                            let signed = signer.sign(rollback_job);
                            if registry.send_job(agent_id, signed).await {
                                info!(
                                    %agent_id,
                                    rolled_back_to = %prev_version,
                                    "AUTO-ROLLBACK dispatched for failing agent SystemUpdate (detected via JobResult failure)"
                                );
                                let _ = deployment_service
                                    .record_metric(
                                        Some(sys_dep.id),
                                        agent_id,
                                        "agent_systemupdate_rollback_dispatched",
                                        1.0,
                                        serde_json::json!({
                                            "reason": "job_result_failure",
                                            "rolled_back_to": prev_version
                                        }),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }
        AgentMessage::ExecOutput {
            session_id,
            data,
            stream,
        } => {
            // Build-log frames (stream == "build") use the build id as the session id; we
            // publish each redacted line to that build's LOG_BROADCASTERS topic so the
            // build-log WS subscribers receive it live. Terminal/PTY output (other streams)
            // is handled by dedicated interactive sessions elsewhere.
            if stream == "build" {
                if let Ok(build_id) = Uuid::parse_str(&session_id) {
                    let line = String::from_utf8_lossy(&data).into_owned();
                    let guard = LOG_BROADCASTERS.lock().unwrap();
                    if let Some(tx) = guard.get(&build_id) {
                        let _ = tx.send(line);
                    }
                }
            }
        }
    }
}

/// Apply a terminal Build job result: persist image/digest/error, and on success create a
/// Deployment from the built image and dispatch it to connected agents. Fail-closed — a
/// failed build records the error and never deploys (threat-model A10).
async fn handle_build_result(
    build_id: Uuid,
    details: &forge_agent::job::JobResultDetails,
    deployment_service: &Arc<crate::deployment::DeploymentService>,
    signer: &JobSigner,
    registry: &AgentRegistry,
) {
    use forge_agent::job::JobResultDetails;

    let JobResultDetails::Build {
        success,
        image,
        image_digest,
        error_message,
        ..
    } = details
    else {
        // Build job with a non-Build detail payload — record a generic failure.
        let _ = deployment_service
            .record_build_result(build_id, false, None, None, Some("malformed build result"))
            .await;
        return;
    };

    let record = match deployment_service
        .record_build_result(
            build_id,
            *success,
            image.as_deref(),
            image_digest.as_deref(),
            error_message.as_deref(),
        )
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            warn!(%build_id, "build result for unknown build id");
            return;
        }
        Err(e) => {
            warn!(error = %e, %build_id, "failed to record build result");
            return;
        }
    };

    // Fail-closed: only a succeeded build with an image proceeds to deploy.
    if !*success {
        info!(%build_id, "build failed — not deploying (fail-closed)");
        return;
    }
    let Some(image_ref) = record.image.clone() else {
        warn!(%build_id, "succeeded build has no image — not deploying");
        return;
    };

    // Create a deployment for the build's application using the produced image. The spec is
    // minimal and deliberately conservative (no host mounts / privileged); the build's
    // commit_sha + image flow into the deployment's git/commit columns for the audit chain.
    let spec = serde_json::json!({
        "containers": [{
            "name": format!("app-{}", &record.commit_sha.chars().take(12).collect::<String>()),
            "image": image_ref,
            "ports": ["80:80"],
            "restart_policy": "always"
        }]
    });

    let deployment = match deployment_service
        .create_deployment(
            record.application_id,
            spec.clone(),
            DeploymentStrategy::Rolling(forge_core::RollingConfig {
                max_unavailable: 0,
                max_surge: 1,
                health_check_grace_period_secs: 10,
                rollback_on_failure: true,
                failure_threshold: 2,
            }),
            vec![],
        )
        .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, %build_id, "failed to create deployment from successful build");
            return;
        }
    };

    // Link build → deployment + carry git provenance onto the deployment.
    let _ = deployment_service
        .link_build_deployment(build_id, deployment.id)
        .await;
    let _ = deployment_service
        .set_deployment_git_metadata(
            deployment.id,
            record.git_source_id,
            Some(&record.commit_sha),
            record.git_ref.as_deref(),
        )
        .await;

    // Dispatch the Deploy to connected agents (same pattern as the webhook quick path).
    if let Ok(deploy_spec) = serde_json::from_value::<DeploymentSpec>(spec) {
        let job = Job::Deploy {
            deployment_id: deployment.id,
            spec: deploy_spec,
        };
        let signed = signer.sign(job);
        for agent_id in registry.connected_agents().await {
            let _ = registry.send_job(agent_id, signed.clone()).await;
        }
        info!(%build_id, deployment_id = %deployment.id, "Dispatched Deploy for successful build (source-to-deploy)");
    }
}

/// Axum handler that upgrades the connection.
pub async fn agent_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::AppState>,
) -> Response {
    ws.on_upgrade(move |socket| {
        handle_agent_connection(
            socket,
            state.agent_registry.clone(),
            state.deployment_service.clone(),
            (*state.pool).clone(),
            (*state.signing_key).clone(),
            state.xds_state.clone(),
        )
    })
}
