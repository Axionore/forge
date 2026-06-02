//! Prometheus metrics for the Forge Control Plane.
//! Exposes standard exposition format at /metrics.

use prometheus::{Counter, CounterVec, Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder};
use std::sync::Arc;

// Metric handles are registered into `registry` (which IS read by the /metrics
// exporter); several are observed only on code paths not yet wired, so allow the
// individual fields to be unread without losing the registered series.
#[allow(dead_code)]
#[derive(Clone)]
pub struct ControlPlaneMetrics {
    pub registry: Registry,

    // Deployments
    pub deployments_total: Counter,
    pub deployments_active: Gauge,
    pub deployments_by_status: GaugeVec,

    // Agents
    pub agents_connected: Gauge,
    pub agents_total: Counter,

    // Job execution
    pub jobs_dispatched_total: CounterVec,
    pub job_results_total: CounterVec,
    pub job_duration_seconds: GaugeVec,

    // Health & Observability
    pub healthchecks_total: Counter,
    pub container_health_gauge: GaugeVec, // per container or deployment

    // Reconciliation / Drift
    pub reconciliation_runs_total: Counter,
    pub drift_detected_total: Counter,

    // Rollout progress (per deployment we can use labels in practice; global for demo)
    pub rollout_progress_percent: Gauge,
    pub rollout_failure_count: Gauge,
}

impl Default for ControlPlaneMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPlaneMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // Deployments
        let deployments_total = Counter::new(
            "forge_deployments_total",
            "Total number of deployments ever created",
        )
        .unwrap();
        let deployments_active = Gauge::new(
            "forge_deployments_active",
            "Currently active (non-terminal) deployments",
        )
        .unwrap();
        let deployments_by_status = GaugeVec::new(
            Opts::new(
                "forge_deployments_by_status",
                "Deployments grouped by current status",
            ),
            &["status"],
        )
        .unwrap();

        // Agents
        let agents_connected = Gauge::new(
            "forge_agents_connected",
            "Number of agents currently connected via WebSocket",
        )
        .unwrap();
        let agents_total =
            Counter::new("forge_agents_total", "Total agents ever enrolled").unwrap();

        // Jobs
        let jobs_dispatched_total = CounterVec::new(
            Opts::new("forge_jobs_dispatched_total", "Jobs sent to agents"),
            &["job_type"],
        )
        .unwrap();
        let job_results_total = CounterVec::new(
            Opts::new(
                "forge_job_results_total",
                "Job results received from agents",
            ),
            &["job_type", "success"],
        )
        .unwrap();
        let job_duration_seconds = GaugeVec::new(
            Opts::new("forge_job_duration_seconds", "Last observed job duration"),
            &["job_type"],
        )
        .unwrap();

        // Health
        let healthchecks_total = Counter::new(
            "forge_healthchecks_total",
            "Total health check jobs executed",
        )
        .unwrap();
        let container_health_gauge = GaugeVec::new(
            Opts::new(
                "forge_container_health",
                "Per-container health indicators from HealthCheck jobs (1=healthy)",
            ),
            &["deployment_id", "container_name"],
        )
        .unwrap();

        // Reconciliation
        let reconciliation_runs_total = Counter::new(
            "forge_reconciliation_runs_total",
            "Times reconciliation was triggered (on connect or heartbeat)",
        )
        .unwrap();
        let drift_detected_total = Counter::new(
            "forge_drift_detected_total",
            "Drift events detected via heartbeats or reconnects",
        )
        .unwrap();

        // Register everything
        registry
            .register(Box::new(deployments_total.clone()))
            .unwrap();
        registry
            .register(Box::new(deployments_active.clone()))
            .unwrap();
        registry
            .register(Box::new(deployments_by_status.clone()))
            .unwrap();
        registry
            .register(Box::new(agents_connected.clone()))
            .unwrap();
        registry.register(Box::new(agents_total.clone())).unwrap();
        registry
            .register(Box::new(jobs_dispatched_total.clone()))
            .unwrap();
        registry
            .register(Box::new(job_results_total.clone()))
            .unwrap();
        registry
            .register(Box::new(job_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(healthchecks_total.clone()))
            .unwrap();
        registry
            .register(Box::new(container_health_gauge.clone()))
            .unwrap();
        registry
            .register(Box::new(reconciliation_runs_total.clone()))
            .unwrap();
        registry
            .register(Box::new(drift_detected_total.clone()))
            .unwrap();

        let rollout_progress_percent = Gauge::new(
            "forge_rollout_progress_percent",
            "Current rollout progress for active phased deployments (0-100)",
        )
        .unwrap();
        let rollout_failure_count = Gauge::new(
            "forge_rollout_failure_count",
            "Cumulative rollout failure count across strategies",
        )
        .unwrap();
        registry
            .register(Box::new(rollout_progress_percent.clone()))
            .unwrap();
        registry
            .register(Box::new(rollout_failure_count.clone()))
            .unwrap();

        Self {
            registry,
            deployments_total,
            deployments_active,
            deployments_by_status,
            agents_connected,
            agents_total,
            jobs_dispatched_total,
            job_results_total,
            job_duration_seconds,
            healthchecks_total,
            container_health_gauge,
            reconciliation_runs_total,
            drift_detected_total,
            rollout_progress_percent,
            rollout_failure_count,
        }
    }

    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

pub type SharedMetrics = Arc<ControlPlaneMetrics>;
