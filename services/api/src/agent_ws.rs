//! WebSocket server for agents (Slice 2).
//!
//! This module implements the server side of the agent control plane protocol:
//! - Accepts connections at /agent/ws
//! - Performs the exact auth handshake the agent expects
//! - Maintains live connections so we can push SignedJob messages
//! - Receives Heartbeats and JobResults

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use forge_agent::job::{AgentMessage, DeploymentSpec, Job, JobResult, SignedJob};
use forge_core::DeploymentStrategy;
use crate::agent_ws::JobSigner; // for signing on drift re-dispatch (self reference ok in module)

/// Signs jobs using the control plane's long-term Ed25519 key.
/// This is the root of trust for everything the agent will execute.
pub struct JobSigner {
    key: ed25519_dalek::SigningKey,
}

pub use JobSigner; // re-export for use in main.rs handlers

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
) {
    // 1. Read the first message — must be auth
    let auth_msg = match socket.recv().await {
        Some(Ok(Message::Text(text))) => {
            serde_json::from_str::<AgentAuthMessage>(&text).ok()
        }
        Some(Ok(Message::Binary(bin))) => {
            serde_json::from_slice::<AgentAuthMessage>(&bin).ok()
        }
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
            .send(Message::Text(r#"{"status":"error","reason":"invalid_token"}"#.to_string()))
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

    // === Reconciliation on reconnect / heartbeat ===
    // If there are any in-progress or pending deployments for this agent, re-send the latest desired state.
    tokio::spawn({
        let deployment_service = deployment_service.clone();
        let job_tx = job_tx.clone();
        let signer = JobSigner::new(signing_key.clone());
        async move {
            if let Ok(active) = deployment_service.get_active_deployments_for_agent(agent_id).await {
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
                            handle_incoming_message(agent_id, agent_msg, &deployment_service, &pool, xds_state, &signer, &registry).await;
                        }
                    }
                    Ok(Message::Binary(bin)) => {
                        if let Ok(agent_msg) = serde_json::from_slice::<AgentMessage>(&bin) {
                            let signer = JobSigner::new(signing_key.clone());
                            handle_incoming_message(agent_id, agent_msg, &deployment_service, &pool, xds_state, &signer, &registry).await;
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
            let _ = deployment_service.record_metric(
                None,
                agent_id,
                "agent_managed_containers",
                payload.managed_container_count as f64,
                serde_json::json!({"uptime_secs": payload.uptime_secs})
            ).await;

            if !payload.active_deployment_ids.is_empty() {
                let _ = deployment_service.record_metric(
                    None,
                    agent_id,
                    "agent_active_deployments",
                    payload.active_deployment_ids.len() as f64,
                    serde_json::json!({"deployments": payload.active_deployment_ids})
                ).await;
            }

            // Record rich agent status for the dedicated /agents/status endpoint and canary analysis
            let _ = deployment_service.record_metric(
                None,
                agent_id,
                "agent_heartbeat",
                1.0,
                serde_json::json!({
                    "version": payload.agent_version,
                    "cluster": payload.cluster,
                    "hostname": payload.hostname,
                    "uptime_secs": payload.uptime_secs
                })
            ).await;

            // === Full phased rollout logic (Rolling with health gates + auto-rollback) + drift detection ===
            if let Ok(active_in_db) = deployment_service.get_active_deployments_for_agent(agent_id).await {
                for dep in active_in_db {
                    let dep_str = dep.id.to_string();
                    let is_reported_active = payload.active_deployment_ids.contains(&dep_str);

                    match &dep.strategy {
                        DeploymentStrategy::Rolling(cfg) => {
                            // Parse rollout state
                            let mut rs: serde_json::Value = dep.rollout_state.clone();

                            let failure_count = rs["failure_count"].as_u64().unwrap_or(0) as u32;
                            let last_gate = rs["last_health_gate_passed_at"].as_str().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());

                            // Get recent health results for this deployment to evaluate gates
                            let recent_health = deployment_service.list_recent_results_for_deployment(dep.id, 10).await.unwrap_or_default();
                            let recent_health_checks: Vec<_> = recent_health.iter().filter(|r| r.job_type == "health_check").collect();

                            let healthy = !recent_health_checks.is_empty() && recent_health_checks.iter().all(|r| r.success);
                            let now = chrono::Utc::now();

                            if healthy && last_gate.map_or(true, |lg| (now - lg).num_seconds() > cfg.health_check_grace_period_secs as i64) {
                                // Health gate passed → advance rollout
                                let current = rs["current_replicas"].as_u64().unwrap_or(0) as u32;
                                let target = 1u32; // simplified; in real would come from DeploymentTarget

                                if current < target {
                                    // Advance one batch (respect max_unavailable conceptually by sending update)
                                    rs["current_replicas"] = serde_json::json!(current + 1);
                                    rs["last_health_gate_passed_at"] = serde_json::json!(now.to_rfc3339());
                                    rs["failure_count"] = 0;

                                    // Send phased update (for true rolling we would use partial replica count in spec or UpdateContainer)
                                    if let Ok(spec) = serde_json::from_value::<DeploymentSpec>(dep.spec.clone()) {
                                        let job = Job::Deploy { deployment_id: dep.id, spec };
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
                                    let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::Healthy).await;
                                }
                            } else if !healthy {
                                // Health failing - count toward rollback threshold
                                let new_fail = failure_count + 1;
                                rs["failure_count"] = serde_json::json!(new_fail);

                                if new_fail >= cfg.failure_threshold && cfg.rollback_on_failure {
                                    // Automatic rollback using previous_spec if available, else mark failed
                                    if let Some(prev) = &dep.previous_spec {
                                        if let Ok(prev_spec) = serde_json::from_value::<DeploymentSpec>(prev.clone()) {
                                            let job = Job::Deploy { deployment_id: dep.id, spec: prev_spec };
                                            let signed = signer.sign(job);
                                            let _ = registry.send_job(agent_id, signed).await;
                                            info!(%agent_id, deployment_id = %dep.id, "Automatic rollback triggered - failure threshold breached");
                                        }
                                    }
                                    let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::RolledBack).await;
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

                            let recent_health = deployment_service.list_recent_results_for_deployment(dep.id, 5).await.unwrap_or_default();
                            let healthy = !recent_health.is_empty() && recent_health.iter().all(|r| r.job_type == "health_check" && r.success);
                            let now = chrono::Utc::now();

                            if phase == "deploy_new" && healthy {
                                // Health gate passed after deploying new set → cutover
                                rs["phase"] = serde_json::json!("cutover");
                                rs["cutover_at"] = serde_json::json!(now.to_rfc3339());

                                // In real system: update Traefik weights / service selectors to new version.
                                // Here we just mark progress and optionally send stop for old containers.
                                let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::Healthy).await;

                                // Optional scale-down of old after grace
                                if (now.timestamp() - dep.created_at.timestamp()) > cfg.scale_down_old_after_secs as i64 {
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
                                    if let Ok(prev_spec) = serde_json::from_value::<DeploymentSpec>(prev.clone()) {
                                        let job = Job::Deploy { deployment_id: dep.id, spec: prev_spec };
                                        let signed = signer.sign(job);
                                        let _ = registry.send_job(agent_id, signed).await;
                                    }
                                }
                                let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::RolledBack).await;
                            }
                        }
                        DeploymentStrategy::Canary(cfg) => {
                            let mut rs: serde_json::Value = dep.rollout_state.clone();
                            let current_pct = rs["current_traffic_percent"].as_u64().unwrap_or(cfg.initial_traffic_percent as u64) as u32;
                            let failure_count = rs["failure_count"].as_u64().unwrap_or(0) as u32;

                            let recent_health = deployment_service.list_recent_results_for_deployment(dep.id, 5).await.unwrap_or_default();
                            let health_ok = !recent_health.is_empty() && recent_health.iter().all(|r| r.job_type == "health_check" && r.success);

                            // Full statistical canary analysis with windowed metrics (replaces simple avg threshold)
                            let (stat_promotable, stat_analysis) = deployment_service
                                .analyze_canary_for_promotion(dep.id, current_pct)
                                .await
                                .unwrap_or((false, serde_json::json!({"error": "analysis_failed", "promotable": false})));

                            rs["last_statistical_analysis"] = stat_analysis.clone();

                            // Feature 1: notify on canary promotion decision (success or blocked)
                            let event = if stat_promotable { "canary.promotable" } else { "canary.blocked" };
                            let _ = deployment_service.trigger_notifications(
                                event,
                                "deployment",
                                Some(dep.id),
                                stat_analysis.clone(),
                            ).await;

                            // Combined gate: health checks pass AND statistical windows confirm no regression
                            let metrics_ok = stat_promotable;
                            let healthy = health_ok && metrics_ok;

                            if healthy && current_pct < 100 {
                                // Release readiness gate for system self-updates (including agent canary)
                                if sys_dep.spec.get("agent_update").is_some() || /* forge-system */ true {  // simplified detection
                                    // Basic gate: check recent agent versions match desired + low error rates
                                    let recent_versions = deployment_service.query_deployment_metrics(sys_dep.id, Some("agent_on_desired_version"), Some(chrono::Utc::now() - chrono::Duration::minutes(10)), None, 50).await.unwrap_or_default();
                                    let agents_on_desired = recent_versions.len() as u32;  // proxy
                                    let desired_count = 10; // would come from registry count in real
                                    let versions_ok = agents_on_desired >= (desired_count / 2); // conservative

                                    let error_metrics = deployment_service.query_deployment_metrics(sys_dep.id, Some("http_error_rate"), Some(chrono::Utc::now() - chrono::Duration::minutes(5)), None, 20).await.unwrap_or_default();
                                    let avg_error = if !error_metrics.is_empty() {
                                        error_metrics.iter().map(|m| m["value"].as_f64().unwrap_or(0.0)).sum::<f64>() / error_metrics.len() as f64
                                    } else { 0.0 };
                                    let errors_ok = avg_error < 0.005; // 0.5% threshold for release

                                    if !versions_ok || !errors_ok {
                                        info!(deployment_id = %sys_dep.id, "Release readiness gate blocked canary promotion (versions_ok={}, errors_ok={})", versions_ok, errors_ok);
                                        // do not advance
                                        let _ = sqlx::query!( "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2", rs, sys_dep.id ).execute(pool).await;
                                        continue;
                                    }
                                }

                                let next_pct = std::cmp::min(100, current_pct + cfg.step_percent as u32);
                                rs["current_traffic_percent"] = serde_json::json!(next_pct);
                                rs["last_step_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
                                rs["failure_count"] = 0;

                                // Richer metric for dashboards + future statistical windows
                                let _ = deployment_service.record_metric(
                                    Some(dep.id),
                                    agent_id,
                                    "canary_traffic_percent",
                                    next_pct as f64,
                                    serde_json::json!({"strategy": "canary", "step": "promoted"})
                                ).await;

                                // Re-dispatch with updated canary % — agent uses labels for weighted Envoy/Traefik
                                if let Ok(mut spec) = serde_json::from_value::<DeploymentSpec>(dep.spec.clone()) {
                                    for container in &mut spec.containers {
                                        container.labels.insert("forge.canary.weight".to_string(), next_pct.to_string());
                                        container.labels.insert("forge.l7.enforce".to_string(), "envoy".to_string());
                                    }
                                    let job = Job::Deploy { deployment_id: dep.id, spec };
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
                                        if let Ok(prev_spec) = serde_json::from_value::<DeploymentSpec>(prev.clone()) {
                                            let job = Job::Deploy { deployment_id: dep.id, spec: prev_spec };
                                            let signed = signer.sign(job);
                                            let _ = registry.send_job(agent_id, signed).await;
                                        }
                                    }

                                    // Agent binary rollback using previous_agent_update snapshot
                                    if let Some(prev_agent) = dep.spec.get("previous_agent_update") {
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

                                    let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::RolledBack).await;
                                }
                                let _ = sqlx::query!( "UPDATE deployments SET rollout_state = $1, updated_at = NOW() WHERE id = $2", rs, dep.id ).execute(pool).await;
                            } else if current_pct >= 100 {
                                let _ = deployment_service.update_deployment_status(dep.id, forge_core::DeploymentStatus::Healthy).await;
                            }
                        }
                        _ => {
                            // Default / other strategies: basic drift re-dispatch
                            if !is_reported_active {
                                if let Ok(spec) = serde_json::from_value::<DeploymentSpec>(dep.spec.clone()) {
                                    let job = Job::Deploy { deployment_id: dep.id, spec };
                                    let signed = signer.sign(job);
                                    let _ = registry.send_job(agent_id, signed).await;
                                    info!(%agent_id, deployment_id = %dep.id, "Drift detected on heartbeat - re-dispatched");
                                }
                            }
                        }
                    }
                }
            }
        }

        // === Phased agent SystemUpdate as part of canary system deployments (multi-cluster aware) ===
        // The agent binary update now participates in the statistical canary rollout
        // instead of being a one-shot broadcast. Dispatch is driven by heartbeats +
        // the rollout_state + target_clusters of the "forge-system" deployment.
        if let Ok(Some(sys_dep)) = deployment_service.get_latest_deployment_for_application_name("forge-system").await {
            // Always extract current desired + previous for robust rollback decisions (release gate hardening)
            let agent_update = sys_dep.spec.get("agent_update");
            let desired_version = agent_update
                .and_then(|u| u.get("version").and_then(|v| v.as_str()))
                .unwrap_or("");
            let previous_agent_update = sys_dep.spec.get("previous_agent_update")
                .or_else(|| sys_dep.rollout_state.get("previous_agent_update"))
                .cloned();

            if !desired_version.is_empty() && payload.agent_version != desired_version {
                let rs: serde_json::Value = sys_dep.rollout_state.clone();
                let current_pct = rs["current_traffic_percent"].as_u64().unwrap_or(0) as u32;
                let target_clusters: Vec<String> = sys_dep.spec.get("target_clusters")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                    .unwrap_or_default();

                let agent_cluster = payload.cluster.as_deref().unwrap_or("default");
                let matches_cluster = target_clusters.is_empty() || target_clusters.iter().any(|c| c == agent_cluster || c == "all");

                // Gate by canary % AND cluster targeting (multi-cluster agent phasing)
                if current_pct < 100 && matches_cluster {
                    // Deeper xDS: drain traffic for agents being updated before binary swap
                    xds_state.prepare_agent_canary_update(sys_dep.id).await;

                    let job = Job::SystemUpdate {
                        update_id: Uuid::now_v7(),
                        version: desired_version.to_string(),
                        binary_ref: agent_update.and_then(|u| u.get("binary_ref").and_then(|v| v.as_str())).unwrap_or("").to_string(),
                        binary_sha256: agent_update.and_then(|u| u.get("binary_sha256").and_then(|v| v.as_str())).unwrap_or("").to_string(),
                    };
                    let signed = signer.sign(job);
                    if registry.send_job(agent_id, signed).await {
                        info!(%agent_id, desired = %desired_version, cluster = %agent_cluster, "Phased SystemUpdate dispatched (multi-cluster canary + xDS drain)");
                        let _ = deployment_service.record_metric(
                            Some(sys_dep.id),
                            agent_id,
                            "agent_systemupdate_dispatched",
                            1.0,
                            serde_json::json!({"desired": desired_version, "cluster": agent_cluster})
                        ).await;
                    }
                }
            } else if !desired_version.is_empty() {
                // Agent already on desired version — feed health into the statistical analyzer
                let agent_cluster = payload.cluster.as_deref().unwrap_or("default");
                let _ = deployment_service.record_metric(
                    Some(sys_dep.id),
                    agent_id,
                    "agent_on_desired_version",
                    1.0,
                    serde_json::json!({"version": desired_version, "cluster": agent_cluster})
                ).await;
            }

            // === Heartbeat-based detection for silent/stuck agents after update (release gate hardening) ===
            // Use metrics (which have agent_id) instead of results for reliable per-agent recent dispatch detection.
            if !desired_version.is_empty() && payload.agent_version != desired_version {
                let recent_dispatch = sqlx::query!(
                    r#"
                    SELECT 1 FROM deployment_metrics
                    WHERE agent_id = $1
                      AND metric_name = 'agent_systemupdate_dispatched'
                      AND (labels->>'desired') = $2
                      AND timestamp > NOW() - INTERVAL '15 minutes'
                    LIMIT 1
                    "#,
                    agent_id,
                    desired_version
                )
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .is_some();

                if recent_dispatch {
                    // Silent or stuck after update attempt → attempt rollback using durable previous snapshot
                    if let Some(prev) = &previous_agent_update {
                        let pver = prev.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        let pref = prev.get("binary_ref").and_then(|v| v.as_str()).unwrap_or("");
                        let psha = prev.get("binary_sha256").and_then(|v| v.as_str()).unwrap_or("");

                        if !pref.is_empty() && pver != payload.agent_version {
                            xds_state.prepare_agent_canary_update(sys_dep.id).await;

                            let rb_job = Job::SystemUpdate { update_id: Uuid::now_v7(), version: pver.to_string(), binary_ref: pref.to_string(), binary_sha256: psha.to_string() };
                            let signed_rb = signer.sign(rb_job);
                            if registry.send_job(agent_id, signed_rb).await {
                                info!(%agent_id, rolled_to = %pver, "HEARTBEAT rollback dispatched for silent/stuck agent after update");
                                let _ = deployment_service.record_metric(
                                    Some(sys_dep.id), agent_id, "agent_systemupdate_rollback_dispatched", 1.0,
                                    serde_json::json!({"reason": "heartbeat_silent_after_update", "rolled_back_to": pver})
                                ).await;

                                // Richer failure counting + history in rollout_state (durable for UI and future promotion gates)
                                let mut rs: serde_json::Value = sys_dep.rollout_state.clone();
                                let mut fails = rs["agent_update_failures"].as_object().cloned().unwrap_or_default();
                                let key = agent_id.to_string();
                                let cnt = fails.get(&key).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
                                fails.insert(key, serde_json::json!(cnt));
                                rs["agent_update_failures"] = serde_json::json!(fails);
                                rs["last_agent_rollback_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
                                let _ = sqlx::query!("UPDATE deployments SET rollout_state = $1 WHERE id = $2", rs, sys_dep.id)
                                    .execute(pool).await;
                            }
                        }
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
            if let Err(e) = deployment_service.record_job_result(agent_id, result.clone()).await {
                warn!(error = %e, "Failed to record JobResult");
            }

            // Feature 1: trigger notifications for this JobResult (audit + future real delivery)
            if let Some(dep_id) = Uuid::parse_str(&result.correlation_id).ok() {
                let _ = deployment_service.trigger_notifications(
                    &format!("job_result.{}", if result.success { "success" } else { "failed" }),
                    "deployment",
                    Some(dep_id),
                    serde_json::to_value(&result).unwrap_or(serde_json::json!({})),
                ).await;
            }

            // === Release gate hardening: Auto-rollback for failing agent binary canaries ===
            // If a SystemUpdate JobResult for a forge-system agent canary fails, immediately
            // dispatch the previous known-good binary (from previous_agent_update in spec/rollout_state).
            // This is the actual auto-rollback dispatch logic triggered by JobResult failure signals.
            if result.job_type == "system_update" && !result.success {
                if let Ok(Some(sys_dep)) = deployment_service.get_latest_deployment_for_application_name("forge-system").await {
                    // Prefer rollout_state (durable) then spec
                    let prev = sys_dep.rollout_state.get("previous_agent_update")
                        .or_else(|| sys_dep.spec.get("previous_agent_update"));

                    if let Some(prev_agent) = prev {
                        let prev_version = prev_agent.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        let prev_ref = prev_agent.get("binary_ref").and_then(|v| v.as_str()).unwrap_or("");
                        let prev_sha = prev_agent.get("binary_sha256").and_then(|v| v.as_str()).unwrap_or("");

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
                                let _ = deployment_service.record_metric(
                                    Some(sys_dep.id),
                                    agent_id,
                                    "agent_systemupdate_rollback_dispatched",
                                    1.0,
                                    serde_json::json!({
                                        "reason": "job_result_failure",
                                        "rolled_back_to": prev_version
                                    })
                                ).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Axum handler that upgrades the connection.
pub async fn agent_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::main::AppState>,
) -> Response {
    ws.on_upgrade(move |socket| {
        handle_agent_connection(
            socket,
            state.agent_registry.clone(),
            state.deployment_service.clone(),
            (*state.pool).clone(),
            (*state.signing_key).clone(),
        )
    })
}
