//! Phase 1 deployment domain models.
//!
//! Design goals:
//! - Reuse the extremely rich `DeploymentSpec` / `ContainerSpec` already
//!   implemented and battle-tested in the agent as much as possible.
//! - Keep the control plane's "desired state" view at a slightly higher level
//!   than the raw agent job.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// NOTE (Phase 1):
// The extremely rich DeploymentSpec / ContainerSpec / Job types currently live
// in crates/agent. For the first delivery slices we will serialize the agent's
// versions as JSONB in the control plane and reconstruct them when dispatching.
// 
// Once the models stabilize, we will move the shared execution types into this
// crate so both the agent and api depend on forge-core. This is a deliberate
// small refactor to avoid duplication of the 200+ line advanced Docker model.

/// Top-level logical application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A concrete, versioned desired state for an Application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: Uuid,
    pub application_id: Uuid,
    pub version: i32,
    /// The exact spec the agent will execute.
    /// Stored as the rich JSON shape the agent already understands.
    pub spec: serde_json::Value,
    pub status: DeploymentStatus,
    /// Update strategy with configuration (health gates, rollback thresholds, etc.).
    /// This drives phased execution in the control plane.
    pub strategy: DeploymentStrategy,
    /// Snapshot of previous spec for automatic rollback in phased strategies.
    #[serde(default)]
    pub previous_spec: Option<serde_json::Value>,
    /// Live state for the current rollout (phase, batch_size, failure_count, last_health_gate, etc.).
    #[serde(default)]
    pub rollout_state: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Supported deployment strategies with their configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeploymentStrategy {
    Rolling(RollingConfig),
    BlueGreen(BlueGreenConfig),
    Canary(CanaryConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RollingConfig {
    pub max_unavailable: u32,                 // e.g. 1 or percentage in future
    pub max_surge: u32,
    pub health_check_grace_period_secs: u64,
    pub rollback_on_failure: bool,
    pub failure_threshold: u32,               // consecutive failures before rollback
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlueGreenConfig {
    pub scale_down_old_after_secs: u64,
    pub health_check_grace_period_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CanaryConfig {
    pub initial_traffic_percent: u8,
    pub step_percent: u8,
    pub step_duration_secs: u64,
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    InProgress,
    Healthy,
    Unhealthy,
    Failed,
    RolledBack,
}

/// Where this deployment should run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentTarget {
    pub agent_id: Uuid,
    pub replicas: u32,
}

/// Simple registry auth for Phase 1 (will be improved).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCredential {
    pub id: Uuid,
    pub name: String,
    pub registry_host: String,
    pub username: Option<String>,
    // In real deployments this would be KMS-wrapped. For Phase 1 we store
    // it encrypted at rest using a key from the environment.
    pub password_encrypted: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}
