//! Monitoring threshold alerts.
//!
//! Operators define [`AlertRule`]s that watch the `deployment_metrics` time-series.
//! A bounded background task ([`spawn_alert_evaluator`]) wakes on a fixed interval and,
//! per enabled rule, decides whether the comparator+threshold has been breached
//! *continuously* for `duration_secs`. State transitions:
//!
//! * not-firing → firing: insert an `alert_events` row (`state = 'firing'`) and fire an
//!   `alert.firing` notification via the existing SSRF-safe delivery path.
//! * firing → still-firing: respect `cooldown_secs` — re-notify at most once per cooldown
//!   so a stuck breach never produces an alert storm (OWASP A09 alert-fatigue).
//! * firing → resolved: mark the open event `resolved` and fire an `alert.resolved`
//!   notification.
//!
//! **Fail-safe (A10):** evaluation of one rule never panics the loop. A DB error for a
//! single rule is logged and that rule is skipped; the task keeps running and is wired to
//! a `watch` shutdown signal for graceful stop. No secret material is ever logged.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use uuid::Uuid;

use crate::deployment::DeploymentService;

/// How often the evaluator scans enabled rules.
const EVAL_INTERVAL: Duration = Duration::from_secs(30);

/// Hard cap on rules scanned per tick — bounds work even if an operator creates a huge
/// number of enabled rules (A10: bounded resource use).
const MAX_RULES_PER_TICK: i64 = 1000;

/// Validation / lookup errors for the alert-rule API. Carries no secret material; the
/// `Display` text is safe to surface to an authenticated admin.
#[derive(Debug, Error)]
pub enum AlertError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("alert rule not found")]
    NotFound,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

const SCOPES: [&str; 3] = ["global", "agent", "deployment"];
const COMPARATORS: [&str; 4] = ["gt", "lt", "gte", "lte"];
const SEVERITIES: [&str; 3] = ["info", "warning", "critical"];

/// A persisted alert rule (mirrors the `alert_rules` table).
#[derive(Debug, Clone, Serialize)]
pub struct AlertRule {
    pub id: Uuid,
    pub name: String,
    pub scope: String,
    pub target_id: Option<Uuid>,
    pub metric_name: String,
    pub comparator: String,
    pub threshold: f64,
    pub duration_secs: i32,
    pub severity: String,
    pub enabled: bool,
    pub cooldown_secs: i32,
    pub created_by_principal_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fields accepted when creating or replacing a rule. Validated before any DB write.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertRuleInput {
    pub name: String,
    pub scope: String,
    #[serde(default)]
    pub target_id: Option<Uuid>,
    pub metric_name: String,
    pub comparator: String,
    pub threshold: f64,
    #[serde(default)]
    pub duration_secs: i32,
    pub severity: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: i32,
}

const fn default_enabled() -> bool {
    true
}
const fn default_cooldown() -> i32 {
    300
}

/// Evaluate a comparator against the threshold. The single source of truth for breach
/// polarity — the evaluator and the unit tests both route through it.
#[must_use]
pub fn breaches(comparator: &str, value: f64, threshold: f64) -> bool {
    match comparator {
        "gt" => value > threshold,
        "lt" => value < threshold,
        "gte" => value >= threshold,
        "lte" => value <= threshold,
        // Unknown comparator (should be impossible past validation) → never breach
        // (fail-safe: an unparseable rule does not spuriously fire).
        _ => false,
    }
}

/// Validate operator input, returning a clean message on failure (length-bound + enums).
fn validate_input(input: &AlertRuleInput) -> Result<(), AlertError> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(AlertError::InvalidInput(
            "name must be 1-128 characters".into(),
        ));
    }
    let metric = input.metric_name.trim();
    if metric.is_empty() || metric.len() > 128 {
        return Err(AlertError::InvalidInput(
            "metric_name must be 1-128 characters".into(),
        ));
    }
    if !SCOPES.contains(&input.scope.as_str()) {
        return Err(AlertError::InvalidInput(format!(
            "scope must be one of: {}",
            SCOPES.join(", ")
        )));
    }
    if !COMPARATORS.contains(&input.comparator.as_str()) {
        return Err(AlertError::InvalidInput(format!(
            "comparator must be one of: {}",
            COMPARATORS.join(", ")
        )));
    }
    if !SEVERITIES.contains(&input.severity.as_str()) {
        return Err(AlertError::InvalidInput(format!(
            "severity must be one of: {}",
            SEVERITIES.join(", ")
        )));
    }
    if !input.threshold.is_finite() {
        return Err(AlertError::InvalidInput(
            "threshold must be a finite number".into(),
        ));
    }
    // Bound the windows so a rule cannot ask the evaluator to scan an unbounded history
    // (A10) — 24h breach window / 24h cooldown is far past any practical alerting need.
    if !(0..=86_400).contains(&input.duration_secs) {
        return Err(AlertError::InvalidInput(
            "duration_secs must be between 0 and 86400".into(),
        ));
    }
    if !(0..=86_400).contains(&input.cooldown_secs) {
        return Err(AlertError::InvalidInput(
            "cooldown_secs must be between 0 and 86400".into(),
        ));
    }
    if input.scope == "global" {
        if input.target_id.is_some() {
            return Err(AlertError::InvalidInput(
                "global scope must not carry a target_id".into(),
            ));
        }
    } else if input.target_id.is_none() {
        return Err(AlertError::InvalidInput(format!(
            "{} scope requires a target_id",
            input.scope
        )));
    }
    Ok(())
}

/// Service for alert-rule CRUD + event reads. Holds its own pool clone; the evaluator
/// borrows a [`DeploymentService`] for notification delivery.
#[derive(Clone)]
pub struct AlertService {
    pool: PgPool,
}

impl AlertService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_rule(r: AlertRuleRow) -> AlertRule {
        AlertRule {
            id: r.id,
            name: r.name,
            scope: r.scope,
            target_id: r.target_id,
            metric_name: r.metric_name,
            comparator: r.comparator,
            threshold: r.threshold,
            duration_secs: r.duration_secs,
            severity: r.severity,
            enabled: r.enabled,
            cooldown_secs: r.cooldown_secs,
            created_by_principal_id: r.created_by_principal_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    pub async fn create_rule(
        &self,
        input: &AlertRuleInput,
        created_by_principal_id: Option<Uuid>,
    ) -> Result<AlertRule, AlertError> {
        validate_input(input)?;
        let id = Uuid::now_v7();
        let row = sqlx::query_as!(
            AlertRuleRow,
            r#"
            INSERT INTO alert_rules
                (id, name, scope, target_id, metric_name, comparator, threshold,
                 duration_secs, severity, enabled, cooldown_secs, created_by_principal_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id, name, scope, target_id, metric_name, comparator, threshold,
                      duration_secs, severity, enabled, cooldown_secs,
                      created_by_principal_id, created_at, updated_at
            "#,
            id,
            input.name.trim(),
            input.scope,
            input.target_id,
            input.metric_name.trim(),
            input.comparator,
            input.threshold,
            input.duration_secs,
            input.severity,
            input.enabled,
            input.cooldown_secs,
            created_by_principal_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AlertError::Internal(e.into()))?;
        Ok(Self::row_to_rule(row))
    }

    pub async fn list_rules(&self) -> Result<Vec<AlertRule>, AlertError> {
        let rows = sqlx::query_as!(
            AlertRuleRow,
            r#"
            SELECT id, name, scope, target_id, metric_name, comparator, threshold,
                   duration_secs, severity, enabled, cooldown_secs,
                   created_by_principal_id, created_at, updated_at
            FROM alert_rules
            ORDER BY created_at DESC
            LIMIT 500
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AlertError::Internal(e.into()))?;
        Ok(rows.into_iter().map(Self::row_to_rule).collect())
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<AlertRule, AlertError> {
        let row = sqlx::query_as!(
            AlertRuleRow,
            r#"
            SELECT id, name, scope, target_id, metric_name, comparator, threshold,
                   duration_secs, severity, enabled, cooldown_secs,
                   created_by_principal_id, created_at, updated_at
            FROM alert_rules
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AlertError::Internal(e.into()))?;
        row.map(Self::row_to_rule).ok_or(AlertError::NotFound)
    }

    /// Replace a rule's mutable fields. Validates the same way as create.
    pub async fn update_rule(
        &self,
        id: Uuid,
        input: &AlertRuleInput,
    ) -> Result<AlertRule, AlertError> {
        validate_input(input)?;
        let row = sqlx::query_as!(
            AlertRuleRow,
            r#"
            UPDATE alert_rules
            SET name = $2, scope = $3, target_id = $4, metric_name = $5, comparator = $6,
                threshold = $7, duration_secs = $8, severity = $9, enabled = $10,
                cooldown_secs = $11
            WHERE id = $1
            RETURNING id, name, scope, target_id, metric_name, comparator, threshold,
                      duration_secs, severity, enabled, cooldown_secs,
                      created_by_principal_id, created_at, updated_at
            "#,
            id,
            input.name.trim(),
            input.scope,
            input.target_id,
            input.metric_name.trim(),
            input.comparator,
            input.threshold,
            input.duration_secs,
            input.severity,
            input.enabled,
            input.cooldown_secs,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AlertError::Internal(e.into()))?;
        row.map(Self::row_to_rule).ok_or(AlertError::NotFound)
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<(), AlertError> {
        let res = sqlx::query!("DELETE FROM alert_rules WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AlertError::Internal(e.into()))?;
        if res.rows_affected() == 0 {
            return Err(AlertError::NotFound);
        }
        Ok(())
    }

    /// Recent alert events for the admin feed, optionally filtered by state/severity.
    pub async fn list_events(
        &self,
        state: Option<&str>,
        severity: Option<&str>,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AlertError> {
        // Validate the filter enums so a bad query string can't reach the DB as garbage.
        if let Some(s) = state {
            if s != "firing" && s != "resolved" {
                return Err(AlertError::InvalidInput(
                    "state must be 'firing' or 'resolved'".into(),
                ));
            }
        }
        if let Some(sev) = severity {
            if !SEVERITIES.contains(&sev) {
                return Err(AlertError::InvalidInput(
                    "severity must be info, warning, or critical".into(),
                ));
            }
        }
        let limit = limit.clamp(1, 500);
        let rows = sqlx::query!(
            r#"
            SELECT id, rule_id, scope, target_id, metric_name, observed_value,
                   severity, state, fired_at, resolved_at, notified
            FROM alert_events
            WHERE ($1::text IS NULL OR state = $1)
              AND ($2::text IS NULL OR severity = $2)
            ORDER BY fired_at DESC
            LIMIT $3
            "#,
            state,
            severity,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AlertError::Internal(e.into()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "rule_id": r.rule_id,
                    "scope": r.scope,
                    "target_id": r.target_id,
                    "metric_name": r.metric_name,
                    "observed_value": r.observed_value,
                    "severity": r.severity,
                    "state": r.state,
                    "fired_at": r.fired_at,
                    "resolved_at": r.resolved_at,
                    "notified": r.notified,
                })
            })
            .collect())
    }
}

/// Internal row shape for `alert_rules` reads.
struct AlertRuleRow {
    id: Uuid,
    name: String,
    scope: String,
    target_id: Option<Uuid>,
    metric_name: String,
    comparator: String,
    threshold: f64,
    duration_secs: i32,
    severity: String,
    enabled: bool,
    cooldown_secs: i32,
    created_by_principal_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// The open firing event (if any) for a rule, used to drive the state machine.
struct OpenEvent {
    id: Uuid,
    last_notified_at: Option<DateTime<Utc>>,
}

/// Spawn the bounded background evaluator. Returns immediately; the task runs until the
/// `shutdown` watch flips to `true` (graceful shutdown). Errors per-rule are logged and
/// skipped — the loop never dies. `watch::changed` is cancel-safe, so the `select!` is too.
pub fn spawn_alert_evaluator(
    pool: PgPool,
    deployment_service: Arc<DeploymentService>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(EVAL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                res = shutdown.changed() => {
                    // Sender dropped or value flipped to shutdown → stop the loop.
                    if res.is_err() || *shutdown.borrow() {
                        tracing::info!("alert evaluator shutting down");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = evaluate_all_rules(&pool, &deployment_service).await {
                        // A whole-scan failure (e.g. listing rules) is logged, never fatal.
                        tracing::warn!(error = %e, "alert evaluation scan failed; will retry next tick");
                    }
                }
            }
        }
    })
}

/// One evaluation pass over every enabled rule. Per-rule failures are isolated.
async fn evaluate_all_rules(
    pool: &PgPool,
    deployment_service: &DeploymentService,
) -> Result<(), AlertError> {
    let rules = sqlx::query_as!(
        AlertRuleRow,
        r#"
        SELECT id, name, scope, target_id, metric_name, comparator, threshold,
               duration_secs, severity, enabled, cooldown_secs,
               created_by_principal_id, created_at, updated_at
        FROM alert_rules
        WHERE enabled = true
        ORDER BY created_at
        LIMIT $1
        "#,
        MAX_RULES_PER_TICK
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    for row in rules {
        let rule = AlertService::row_to_rule(row);
        // Fail-safe: one bad rule never aborts the scan or panics the task.
        if let Err(e) = evaluate_rule(pool, deployment_service, &rule).await {
            tracing::warn!(rule_id = %rule.id, error = %e, "alert rule evaluation skipped");
        }
    }
    Ok(())
}

/// Evaluate a single rule and apply the not-firing/firing/resolved transition.
///
/// `now` is threaded in so tests can pin a deterministic clock; production passes
/// `Utc::now()` via [`evaluate_rule`].
pub async fn evaluate_rule_at(
    pool: &PgPool,
    deployment_service: &DeploymentService,
    rule: &AlertRule,
    now: DateTime<Utc>,
) -> Result<(), AlertError> {
    // 1. Determine whether the breach has persisted continuously for duration_secs.
    //    We look at every sample in the window [now - duration, now]. The breach is
    //    "sustained" iff there is at least one sample AND every sample breaches. With
    //    duration_secs = 0 the window collapses to the most-recent sample only.
    let window_start = now - chrono::Duration::seconds(i64::from(rule.duration_secs));
    let samples = fetch_window_samples(pool, rule, window_start, now).await?;

    let (sustained, observed) = if samples.is_empty() {
        (false, None)
    } else {
        let all_breach = samples
            .iter()
            .all(|v| breaches(&rule.comparator, *v, rule.threshold));
        // Observed value = the most recent sample (samples come newest-first).
        let latest = samples.first().copied();
        (all_breach, latest)
    };

    // 2. Look up the currently-open firing event for this rule (if any).
    let open = sqlx::query_as!(
        OpenEvent,
        r#"
        SELECT id, last_notified_at
        FROM alert_events
        WHERE rule_id = $1 AND state = 'firing'
        ORDER BY fired_at DESC
        LIMIT 1
        "#,
        rule.id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    match (sustained, open) {
        // not-firing → firing
        (true, None) => {
            let observed = observed.unwrap_or(rule.threshold);
            fire_new_event(pool, deployment_service, rule, observed, now).await?;
        }
        // firing → still-firing: re-notify only after cooldown.
        (true, Some(ev)) => {
            let due = match ev.last_notified_at {
                Some(last) => {
                    now - last >= chrono::Duration::seconds(i64::from(rule.cooldown_secs))
                }
                None => true,
            };
            if due {
                let observed = observed.unwrap_or(rule.threshold);
                renotify_event(pool, deployment_service, rule, ev.id, observed, now).await?;
            }
        }
        // firing → resolved
        (false, Some(ev)) => {
            resolve_event(pool, deployment_service, rule, ev.id, now).await?;
        }
        // not-firing, no open event → nothing to do.
        (false, None) => {}
    }
    Ok(())
}

/// Production entry: evaluate against the real clock.
async fn evaluate_rule(
    pool: &PgPool,
    deployment_service: &DeploymentService,
    rule: &AlertRule,
) -> Result<(), AlertError> {
    evaluate_rule_at(pool, deployment_service, rule, Utc::now()).await
}

/// Fetch metric values in `[window_start, now]` for the rule's scope/metric, newest-first.
/// Bounded by a row LIMIT so a noisy metric can't return an unbounded set (A10).
async fn fetch_window_samples(
    pool: &PgPool,
    rule: &AlertRule,
    window_start: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<f64>, AlertError> {
    // Scope selects which dimension of deployment_metrics we filter on. For 'global'
    // both target filters are NULL so the predicate matches every row for the metric.
    let (deployment_filter, agent_filter): (Option<Uuid>, Option<Uuid>) = match rule.scope.as_str()
    {
        "deployment" => (rule.target_id, None),
        "agent" => (None, rule.target_id),
        _ => (None, None),
    };

    let rows = sqlx::query_scalar!(
        r#"
        SELECT value
        FROM deployment_metrics
        WHERE metric_name = $1
          AND timestamp >= $2
          AND timestamp <= $3
          AND ($4::uuid IS NULL OR deployment_id = $4)
          AND ($5::uuid IS NULL OR agent_id = $5)
        ORDER BY timestamp DESC
        LIMIT 1000
        "#,
        rule.metric_name,
        window_start,
        now,
        deployment_filter,
        agent_filter,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    Ok(rows)
}

/// Insert a fresh firing event and fire the `alert.firing` notification.
async fn fire_new_event(
    pool: &PgPool,
    deployment_service: &DeploymentService,
    rule: &AlertRule,
    observed: f64,
    now: DateTime<Utc>,
) -> Result<(), AlertError> {
    let event_id = Uuid::now_v7();
    sqlx::query!(
        r#"
        INSERT INTO alert_events
            (id, rule_id, scope, target_id, metric_name, observed_value, severity,
             state, fired_at, notified, last_notified_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'firing', $8, true, $8)
        "#,
        event_id,
        rule.id,
        rule.scope,
        rule.target_id,
        rule.metric_name,
        observed,
        rule.severity,
        now,
    )
    .execute(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    tracing::warn!(
        rule_id = %rule.id,
        severity = %rule.severity,
        metric = %rule.metric_name,
        "alert firing"
    );
    notify(
        deployment_service,
        rule,
        "alert.firing",
        observed,
        event_id,
        now,
    )
    .await;
    Ok(())
}

/// Re-notify a still-firing event after its cooldown elapsed, stamping `last_notified_at`.
async fn renotify_event(
    pool: &PgPool,
    deployment_service: &DeploymentService,
    rule: &AlertRule,
    event_id: Uuid,
    observed: f64,
    now: DateTime<Utc>,
) -> Result<(), AlertError> {
    sqlx::query!(
        "UPDATE alert_events SET last_notified_at = $2, observed_value = $3 WHERE id = $1",
        event_id,
        now,
        observed,
    )
    .execute(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    notify(
        deployment_service,
        rule,
        "alert.firing",
        observed,
        event_id,
        now,
    )
    .await;
    Ok(())
}

/// Mark the open event resolved and fire the `alert.resolved` notification.
async fn resolve_event(
    pool: &PgPool,
    deployment_service: &DeploymentService,
    rule: &AlertRule,
    event_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AlertError> {
    sqlx::query!(
        "UPDATE alert_events SET state = 'resolved', resolved_at = $2 WHERE id = $1",
        event_id,
        now,
    )
    .execute(pool)
    .await
    .map_err(|e| AlertError::Internal(e.into()))?;

    tracing::info!(rule_id = %rule.id, metric = %rule.metric_name, "alert resolved");
    notify(
        deployment_service,
        rule,
        "alert.resolved",
        rule.threshold,
        event_id,
        now,
    )
    .await;
    Ok(())
}

/// Deliver an alert notification through the existing channel/subscription fan-out.
/// Maps the rule scope to the notification `resource_type` so operators can subscribe at
/// the deployment / agent level (or 'system' for global). Delivery failures never abort
/// evaluation — `trigger_notifications` already isolates and logs its own egress.
async fn notify(
    deployment_service: &DeploymentService,
    rule: &AlertRule,
    event_type: &str,
    observed: f64,
    event_id: Uuid,
    now: DateTime<Utc>,
) {
    let resource_type = match rule.scope.as_str() {
        "deployment" => "deployment",
        "agent" => "agent",
        // global rules surface as 'system' subscriptions.
        _ => "system",
    };
    let context = serde_json::json!({
        "alert_event_id": event_id,
        "rule_id": rule.id,
        "rule_name": rule.name,
        "scope": rule.scope,
        "target_id": rule.target_id,
        "metric_name": rule.metric_name,
        "comparator": rule.comparator,
        "threshold": rule.threshold,
        "observed_value": observed,
        "severity": rule.severity,
        "at": now.to_rfc3339(),
    });
    if let Err(e) = deployment_service
        .trigger_notifications(event_type, resource_type, rule.target_id, context)
        .await
    {
        tracing::warn!(rule_id = %rule.id, error = %e, "alert notification trigger failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    // --- Pure comparator logic (no DB) ----------------------------------------

    #[test]
    fn comparator_polarity_is_correct() {
        assert!(breaches("gt", 10.0, 5.0));
        assert!(!breaches("gt", 5.0, 5.0));
        assert!(breaches("gte", 5.0, 5.0));
        assert!(breaches("lt", 1.0, 5.0));
        assert!(!breaches("lt", 5.0, 5.0));
        assert!(breaches("lte", 5.0, 5.0));
        // Unknown comparator must never breach (fail-safe).
        assert!(!breaches("eq", 5.0, 5.0));
    }

    // --- DB-backed evaluation harness -----------------------------------------

    fn dep_svc(pool: PgPool) -> Arc<DeploymentService> {
        let rbac = Arc::new(crate::rbac::RbacService::new(pool.clone()));
        Arc::new(DeploymentService::new(pool, rbac))
    }

    /// Insert a `deployment_metrics` row at an explicit timestamp (global-scope: NULL ids).
    async fn seed_metric(pool: &PgPool, name: &str, value: f64, at: DateTime<Utc>) {
        sqlx::query!(
            r#"
            INSERT INTO deployment_metrics (deployment_id, agent_id, metric_name, value, labels, timestamp)
            VALUES (NULL, NULL, $1, $2, '{}'::jsonb, $3)
            "#,
            name,
            value,
            at,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn make_rule(
        svc: &AlertService,
        comparator: &str,
        threshold: f64,
        duration: i32,
        cooldown: i32,
    ) -> AlertRule {
        svc.create_rule(
            &AlertRuleInput {
                name: "test-rule".into(),
                scope: "global".into(),
                target_id: None,
                metric_name: "cpu".into(),
                comparator: comparator.into(),
                threshold,
                duration_secs: duration,
                severity: "critical".into(),
                enabled: true,
                cooldown_secs: cooldown,
            },
            None,
        )
        .await
        .unwrap()
    }

    async fn open_firing_count(pool: &PgPool, rule_id: Uuid) -> i64 {
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM alert_events WHERE rule_id = $1 AND state = 'firing'",
            rule_id
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or(0)
    }

    async fn resolved_count(pool: &PgPool, rule_id: Uuid) -> i64 {
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM alert_events WHERE rule_id = $1 AND state = 'resolved'",
            rule_id
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or(0)
    }

    /// Subscribe a real (disabled-egress) channel to system alert events so that
    /// `trigger_notifications` writes an auditable `notification_deliveries` row. We use a
    /// disabled channel so delivery is recorded as `skipped` synchronously (no network) —
    /// the row's existence proves the alert path invoked notification fan-out.
    async fn subscribe_system_alerts(pool: &PgPool) {
        let channel_id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO notification_channels (id, name, channel_type, config, enabled)
            VALUES ($1, 'test', 'webhook', '{"url":"https://example.com/h"}'::jsonb, false)
            "#,
            channel_id,
        )
        .execute(pool)
        .await
        .unwrap();
        let sub_id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO notification_subscriptions (id, resource_type, resource_id, channel_id, events, enabled)
            VALUES ($1, 'system', NULL, $2, '["*"]'::jsonb, true)
            "#,
            sub_id,
            channel_id,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn delivery_count(pool: &PgPool, event_type: &str) -> i64 {
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM notification_deliveries WHERE event_type = $1",
            event_type
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or(0)
    }

    #[sqlx::test]
    async fn sustained_breach_fires_and_notifies(pool: PgPool) {
        let svc = AlertService::new(pool.clone());
        let dep = dep_svc(pool.clone());
        subscribe_system_alerts(&pool).await;

        let now = Utc::now();
        let rule = make_rule(&svc, "gt", 80.0, 60, 300).await;

        // Two breaching samples spanning the whole 60s window → continuously breached.
        seed_metric(&pool, "cpu", 95.0, now - chrono::Duration::seconds(55)).await;
        seed_metric(&pool, "cpu", 99.0, now - chrono::Duration::seconds(5)).await;

        evaluate_rule_at(&pool, &dep, &rule, now).await.unwrap();

        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            1,
            "should fire one event"
        );
        // The firing path triggered a notification (recorded as a delivery row).
        assert_eq!(
            delivery_count(&pool, "alert.firing").await,
            1,
            "should enqueue a firing notification"
        );

        // Observed value should be the latest (newest) sample.
        let observed: f64 = sqlx::query_scalar!(
            "SELECT observed_value FROM alert_events WHERE rule_id = $1",
            rule.id
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!((observed - 99.0).abs() < f64::EPSILON);
    }

    #[sqlx::test]
    async fn sub_duration_blip_does_not_fire(pool: PgPool) {
        let svc = AlertService::new(pool.clone());
        let dep = dep_svc(pool.clone());

        let now = Utc::now();
        // Requires 60s of continuous breach.
        let rule = make_rule(&svc, "gt", 80.0, 60, 300).await;

        // A breaching spike, but an earlier (in-window) sample is healthy → NOT continuous.
        seed_metric(&pool, "cpu", 10.0, now - chrono::Duration::seconds(50)).await;
        seed_metric(&pool, "cpu", 99.0, now - chrono::Duration::seconds(2)).await;

        evaluate_rule_at(&pool, &dep, &rule, now).await.unwrap();

        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            0,
            "a sub-duration blip must not fire"
        );
    }

    #[sqlx::test]
    async fn cooldown_suppresses_repeat_fires(pool: PgPool) {
        let svc = AlertService::new(pool.clone());
        let dep = dep_svc(pool.clone());
        subscribe_system_alerts(&pool).await;

        // Duration 0 = fire on the latest breaching sample; cooldown 300s.
        let rule = make_rule(&svc, "gt", 80.0, 0, 300).await;

        let t0 = Utc::now();
        seed_metric(&pool, "cpu", 99.0, t0).await;
        evaluate_rule_at(&pool, &dep, &rule, t0).await.unwrap();
        assert_eq!(open_firing_count(&pool, rule.id).await, 1);
        assert_eq!(delivery_count(&pool, "alert.firing").await, 1);

        // 30s later, still breaching but inside cooldown → no new notification, no new event.
        let t1 = t0 + chrono::Duration::seconds(30);
        seed_metric(&pool, "cpu", 97.0, t1).await;
        evaluate_rule_at(&pool, &dep, &rule, t1).await.unwrap();
        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            1,
            "cooldown must not open a second event"
        );
        assert_eq!(
            delivery_count(&pool, "alert.firing").await,
            1,
            "cooldown must suppress the repeat firing notification"
        );

        // 301s after the first notify → cooldown elapsed → exactly one more notification.
        let t2 = t0 + chrono::Duration::seconds(301);
        seed_metric(&pool, "cpu", 96.0, t2).await;
        evaluate_rule_at(&pool, &dep, &rule, t2).await.unwrap();
        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            1,
            "still one open event"
        );
        assert_eq!(
            delivery_count(&pool, "alert.firing").await,
            2,
            "after cooldown a single re-notification fires"
        );
    }

    #[sqlx::test]
    async fn recovery_marks_resolved_and_notifies(pool: PgPool) {
        let svc = AlertService::new(pool.clone());
        let dep = dep_svc(pool.clone());
        subscribe_system_alerts(&pool).await;

        let rule = make_rule(&svc, "gt", 80.0, 0, 300).await;

        let t0 = Utc::now();
        seed_metric(&pool, "cpu", 99.0, t0).await;
        evaluate_rule_at(&pool, &dep, &rule, t0).await.unwrap();
        assert_eq!(open_firing_count(&pool, rule.id).await, 1);

        // Metric recovers below threshold → next eval resolves the open event.
        let t1 = t0 + chrono::Duration::seconds(40);
        seed_metric(&pool, "cpu", 12.0, t1).await;
        evaluate_rule_at(&pool, &dep, &rule, t1).await.unwrap();

        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            0,
            "event should no longer be firing"
        );
        assert_eq!(
            resolved_count(&pool, rule.id).await,
            1,
            "event should be marked resolved"
        );
        assert_eq!(
            delivery_count(&pool, "alert.resolved").await,
            1,
            "resolve should notify"
        );
    }

    #[sqlx::test]
    async fn lt_comparator_fires_below_threshold(pool: PgPool) {
        let svc = AlertService::new(pool.clone());
        let dep = dep_svc(pool.clone());

        // "available_replicas < 1" — a classic down alert.
        let rule = svc
            .create_rule(
                &AlertRuleInput {
                    name: "down".into(),
                    scope: "global".into(),
                    target_id: None,
                    metric_name: "available_replicas".into(),
                    comparator: "lt".into(),
                    threshold: 1.0,
                    duration_secs: 0,
                    severity: "critical".into(),
                    enabled: true,
                    cooldown_secs: 300,
                },
                None,
            )
            .await
            .unwrap();

        let now = Utc::now();
        seed_metric(&pool, "available_replicas", 0.0, now).await;
        evaluate_rule_at(&pool, &dep, &rule, now).await.unwrap();
        assert_eq!(
            open_firing_count(&pool, rule.id).await,
            1,
            "0 < 1 must fire"
        );

        // A different rule that should NOT fire: gt 1 against value 0.
        let rule2 = make_rule(&svc, "gt", 1.0, 0, 300).await;
        seed_metric(&pool, "cpu", 0.0, now).await;
        evaluate_rule_at(&pool, &dep, &rule2, now).await.unwrap();
        assert_eq!(
            open_firing_count(&pool, rule2.id).await,
            0,
            "0 > 1 must not fire"
        );
    }

    #[sqlx::test]
    async fn create_rule_validates_enums_and_scope(pool: PgPool) {
        let svc = AlertService::new(pool.clone());

        // Bad comparator.
        let err = svc
            .create_rule(
                &AlertRuleInput {
                    name: "x".into(),
                    scope: "global".into(),
                    target_id: None,
                    metric_name: "cpu".into(),
                    comparator: "between".into(),
                    threshold: 1.0,
                    duration_secs: 0,
                    severity: "info".into(),
                    enabled: true,
                    cooldown_secs: 10,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AlertError::InvalidInput(_)));

        // Global scope must not carry a target.
        let err = svc
            .create_rule(
                &AlertRuleInput {
                    name: "x".into(),
                    scope: "global".into(),
                    target_id: Some(Uuid::now_v7()),
                    metric_name: "cpu".into(),
                    comparator: "gt".into(),
                    threshold: 1.0,
                    duration_secs: 0,
                    severity: "info".into(),
                    enabled: true,
                    cooldown_secs: 10,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AlertError::InvalidInput(_)));

        // Deployment scope requires a target.
        let err = svc
            .create_rule(
                &AlertRuleInput {
                    name: "x".into(),
                    scope: "deployment".into(),
                    target_id: None,
                    metric_name: "cpu".into(),
                    comparator: "gt".into(),
                    threshold: 1.0,
                    duration_secs: 0,
                    severity: "info".into(),
                    enabled: true,
                    cooldown_secs: 10,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AlertError::InvalidInput(_)));
    }
}
