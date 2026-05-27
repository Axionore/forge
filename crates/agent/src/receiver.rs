//! Job receiving abstraction for the Forge agent.
//!
//! This module defines how the agent receives work from the control plane.
//! The real implementation uses a secure WebSocket connection.

use crate::{error::Result, job::SignedJob};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{info, warn};

/// Readiness milestones used for graceful self-update handover.
/// Moved here so the real receiver can drive it.
#[derive(Clone, Debug, Default)]
pub struct AgentReadinessState {
    pub control_plane_connected: bool,
    pub first_heartbeat_sent: bool,
}

/// Trait representing a source of signed jobs.
#[async_trait::async_trait]
pub trait JobReceiver: Send + Sync {
    /// Receive the next signed job.
    ///
    /// Returns `None` when the receiver is shutting down.
    async fn recv(&mut self) -> Option<SignedJob>;

    /// Report the result of a completed job back to the control plane.
    ///
    /// Default implementation is a no-op (used by mocks and testing receivers).
    async fn report_result(&self, _result: crate::job::JobResult) {}
}

/// A simple in-memory receiver used for development and testing.
///
/// This allows us to drive the agent with signed jobs without a real control plane.
pub struct MockJobReceiver {
    rx: mpsc::Receiver<SignedJob>,
}

impl MockJobReceiver {
    pub fn new(rx: mpsc::Receiver<SignedJob>) -> Self {
        Self { rx }
    }

    /// Create a new mock receiver along with a sender that can be used to inject jobs.
    pub fn channel(buffer: usize) -> (Self, mpsc::Sender<SignedJob>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self { rx }, tx)
    }
}

#[async_trait::async_trait]
impl JobReceiver for MockJobReceiver {
    async fn recv(&mut self) -> Option<SignedJob> {
        self.rx.recv().await
    }
}

/// Outbound message from agent to control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    Heartbeat {
        payload: HeartbeatPayload,
    },
    /// Rich result of a previously received job.
    JobResult {
        result: crate::job::JobResult,
    },
    /// Live output from an interactive exec session (used for web terminals).
    /// Sent as binary-friendly chunks for low latency PTY streaming.
    ExecOutput {
        session_id: String,
        data: Vec<u8>,
        /// "stdout" or "stderr"
        stream: String,
    },
}

/// Lightweight heartbeat payload with useful node metadata.
/// Sent regularly so the control plane has good visibility into agent health and capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub agent_version: String,
    pub hostname: Option<String>,
    pub docker_available: bool,
    /// Seconds since the agent process started.
    pub uptime_secs: u64,
    /// Number of containers currently managed by this agent (best effort).
    pub managed_container_count: u32,
    /// Deployment IDs this agent currently has running (used for reconciliation and drift detection on reconnect/heartbeat).
    #[serde(default)]
    pub active_deployment_ids: Vec<String>,
    pub timestamp: i64,

    /// Richer observability metrics collected locally (Envoy admin stats, container health, etc.).
    /// These are recorded into deployment_metrics on the control plane and power the statistical canary analyzer
    /// (keys: "http_error_rate", "p99_latency_ms", with optional deployment-scoped variants).
    #[serde(default)]
    pub metrics: std::collections::HashMap<String, f64>,

    /// Cluster / availability zone / group this agent belongs to. Used for multi-cluster phased rollouts
    /// (e.g. agent binary canary updates respect target_clusters).
    #[serde(default)]
    pub cluster: Option<String>,
}

/// Real control plane client using WebSocket.
///
/// Connects to the control plane, authenticates using the agent token,
/// receives `SignedJob` messages, and sends periodic heartbeats.
pub struct ControlPlaneJobReceiver {
    job_rx: mpsc::Receiver<SignedJob>,
    /// Channel used to send outbound messages (heartbeats + results) to the background WS task.
    out_tx: mpsc::Sender<AgentMessage>,
    /// Telemetry state used to enrich heartbeats (updated by execution paths).
    /// Stored for potential future direct access; currently the cloned state is
    /// captured by the heartbeat task (see new() below).
    _telemetry: AgentTelemetry,
    _handle: tokio::task::JoinHandle<()>,
}

/// Shared telemetry state that the agent can update from execution paths (deploy, stop, etc.).
/// This feeds into richer heartbeats.
#[derive(Clone)]
pub struct AgentTelemetry {
    pub start_time: std::time::Instant,
    pub managed_container_count: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Set of deployment IDs the agent currently has successfully running.
    /// Updated by execution layer on successful Deploy / Stop.
    pub active_deployments: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Recent metrics observed by the agent (populated from execution paths, Envoy admin scrapes, etc.).
    /// Fed into heartbeats → deployment_metrics → statistical canary analyzer.
    pub observed_metrics: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, f64>>>,
}

impl Default for AgentTelemetry {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            managed_container_count: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            active_deployments: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            observed_metrics: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl ControlPlaneJobReceiver {
    /// Connect to the control plane and start the background receiver task.
    ///
    /// The returned receiver is resilient: it will automatically reconnect with
    /// exponential backoff on any failure and will correctly drive the readiness
    /// flags across reconnects (important for graceful self-update handover).
    pub async fn connect(
        control_plane_url: &str,
        agent_token: &str,
        readiness_tx: Option<watch::Sender<AgentReadinessState>>,
        telemetry: Option<AgentTelemetry>,
    ) -> Result<Self> {
        // Derive WebSocket URL
        let ws_url = if control_plane_url.starts_with("https://") {
            control_plane_url.replacen("https://", "wss://", 1) + "/agent/ws"
        } else if control_plane_url.starts_with("http://") {
            control_plane_url.replacen("http://", "ws://", 1) + "/agent/ws"
        } else {
            format!("{}/agent/ws", control_plane_url.trim_end_matches('/'))
        };

        let (job_tx, job_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel::<AgentMessage>(64);

        let ws_url = ws_url.clone();
        let agent_token = agent_token.to_string();
        let readiness_tx = readiness_tx.clone();
        let telemetry_state = telemetry.unwrap_or_default();
        let telemetry_for_self = telemetry_state.clone();

        let handle = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(60);

            loop {
                info!(url = %ws_url, "Attempting to connect to control plane...");

                match connect_async(&ws_url).await {
                    Ok((ws_stream, _)) => {
                        let (mut write, mut read) = ws_stream.split();

                        // Authenticate
                        let auth_msg = serde_json::json!({
                            "type": "auth",
                            "token": agent_token,
                            "agent_version": env!("CARGO_PKG_VERSION"),
                        });

                        if write.send(Message::Text(auth_msg.to_string())).await.is_err() {
                            // backoff below
                        } else {
                            // Wait for auth ack
                            let mut authed = false;
                            if let Some(Ok(msg)) = read.next().await {
                                if let Message::Text(text) = msg {
                                    if text.contains("\"status\":\"ok\"") || text.contains("authenticated") {
                                        info!("Successfully authenticated with control plane");
                                        authed = true;

                                        if let Some(tx) = &readiness_tx {
                                            let _ = tx.send_modify(|s| s.control_plane_connected = true);
                                        }
                                    }
                                }
                            }

                            if authed {
                                backoff = Duration::from_secs(1); // reset

                                // Run pump until this connection dies
                                let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
                                let mut first_hb_sent = false;

                                'pump: loop {
                                    tokio::select! {
                                        msg = read.next() => {
                                            match msg {
                                                Some(Ok(Message::Text(text))) => {
                                                    if let Ok(job) = serde_json::from_str::<SignedJob>(&text) {
                                                        if job_tx.send(job).await.is_err() { break 'pump; }
                                                    }
                                                }
                                                Some(Ok(Message::Binary(d))) => {
                                                    if let Ok(job) = serde_json::from_slice::<SignedJob>(&d) {
                                                        if job_tx.send(job).await.is_err() { break 'pump; }
                                                    }
                                                }
                                                Some(Ok(Message::Close(_))) | None => break 'pump,
                                                Some(Err(_)) => break 'pump,
                                                _ => {}
                                            }
                                        }
                                        _ = heartbeat_interval.tick() => {
                                            let uptime = telemetry_state.start_time.elapsed().as_secs();
                                            let container_count = telemetry_state
                                                .managed_container_count
                                                .load(std::sync::atomic::Ordering::Relaxed);

                                            let active_deployments = telemetry_state
                                                .active_deployments
                                                .lock()
                                                .map(|set| set.iter().map(|id| id.to_string()).collect())
                                                .unwrap_or_default();

                                            let payload = HeartbeatPayload {
                                                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                                                hostname: hostname::get().ok().map(|h| h.to_string_lossy().into_owned()),
                                                docker_available: cfg!(feature = "docker"),
                                                uptime_secs: uptime,
                                                managed_container_count: container_count,
                                                active_deployment_ids: active_deployments,
                                                timestamp: chrono::Utc::now().timestamp(),
                                                metrics: telemetry_state.observed_metrics.lock().map(|m| m.clone()).unwrap_or_default(),
                                                cluster: std::env::var("FORGE_CLUSTER").ok().or_else(|| std::env::var("FORGE_AVAILABILITY_ZONE").ok()),
                                            };

                                            let hb = AgentMessage::Heartbeat { payload };
                                            if let Ok(t) = serde_json::to_string(&hb) {
                                                if write.send(Message::Text(t)).await.is_err() { break 'pump; }
                                            }

                                            if !first_hb_sent {
                                                first_hb_sent = true;
                                                if let Some(tx) = &readiness_tx {
                                                    let _ = tx.send_modify(|s| s.first_heartbeat_sent = true);
                                                }
                                            }
                                        }
                                        out = out_rx.recv() => {
                                            if let Some(m) = out {
                                                if let Ok(t) = serde_json::to_string(&m) {
                                                    if write.send(Message::Text(t)).await.is_err() { break 'pump; }
                                                }
                                            } else {
                                                break 'pump;
                                            }
                                        }
                                    }
                                }

                                // Lost this connection
                                if let Some(tx) = &readiness_tx {
                                    let _ = tx.send_modify(|s| s.control_plane_connected = false);
                                }
                                warn!("Lost control plane connection — will reconnect");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "WebSocket connect failed");
                    }
                }

                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        });

        Ok(Self {
            job_rx,
            out_tx,
            _telemetry: telemetry_for_self,
            _handle: handle,
        })
    }
}

#[async_trait::async_trait]
impl JobReceiver for ControlPlaneJobReceiver {
    async fn recv(&mut self) -> Option<SignedJob> {
        self.job_rx.recv().await
    }

    // We override the default so results actually get sent over the wire.
    async fn report_result(&self, result: crate::job::JobResult) {
        let msg = AgentMessage::JobResult { result };
        let _ = self.out_tx.send(msg).await;
    }
}