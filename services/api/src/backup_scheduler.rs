//! Scheduled backup dispatcher.
//!
//! A bounded background task ([`spawn_backup_scheduler`]) wakes on a fixed interval, reads
//! enabled [`backup_schedules`], and for each schedule that is *due* (per its interval/cron),
//! creates a `pending` `backup_executions` row and dispatches a signed `Job::Backup` to an
//! agent running the deployment. When no agent is connected the job is durably queued via the
//! existing pending-dispatch path. Retention is applied after each successful dispatch.
//!
//! Mirrors `alerts::spawn_alert_evaluator`:
//! * Bounded work per tick (`MAX_SCHEDULES_PER_TICK`).
//! * **Fail-safe (A10):** a per-schedule error is logged and skipped; the loop never panics
//!   and is wired to a `watch` shutdown signal for graceful stop.
//! * No secret material is ever logged.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::watch;
use uuid::Uuid;

use forge_agent::job::Job;
use forge_core::spec::S3BackupConfig;

use crate::agent_ws::{AgentRegistry, JobSigner};
use crate::deployment::{BackupScheduleRow, DeploymentService};
use crate::schedule::is_due;

/// How often the scheduler scans enabled schedules.
const SCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on schedules evaluated per tick (bounded resource use, A10).
const MAX_SCHEDULES_PER_TICK: i64 = 1000;

/// Spawn the bounded backup scheduler. Returns immediately; runs until `shutdown` flips.
pub fn spawn_backup_scheduler(
    pool: PgPool,
    deployment_service: Arc<DeploymentService>,
    registry: AgentRegistry,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SCAN_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        tracing::info!("backup scheduler shutting down");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = scan_once(&pool, &deployment_service, &registry, &signing_key).await {
                        tracing::warn!(error = %e, "backup schedule scan failed; will retry next tick");
                    }
                }
            }
        }
    })
}

/// One scan pass. Per-schedule failures are isolated (fail-safe).
async fn scan_once(
    _pool: &PgPool,
    deployment_service: &DeploymentService,
    registry: &AgentRegistry,
    signing_key: &Arc<ed25519_dalek::SigningKey>,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let schedules = deployment_service
        .list_enabled_backup_schedules(MAX_SCHEDULES_PER_TICK)
        .await?;

    for sched in schedules {
        if !is_due(
            &sched.schedule_type,
            &sched.schedule_value,
            sched.last_run_at,
            now,
        ) {
            continue;
        }
        if let Err(e) = run_schedule(deployment_service, registry, signing_key, &sched, now).await {
            // A whole-schedule failure (bad target, DB error) never aborts the scan.
            tracing::warn!(schedule_id = %sched.id, error = %e, "backup schedule run skipped");
        }
    }
    Ok(())
}

/// Create the pending execution, build + sign the `Job::Backup`, dispatch (or queue), stamp
/// `last_run_at`, and prune old executions.
async fn run_schedule(
    deployment_service: &DeploymentService,
    registry: &AgentRegistry,
    signing_key: &Arc<ed25519_dalek::SigningKey>,
    sched: &BackupScheduleRow,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let Some(deployment_id) = sched.deployment_id else {
        anyhow::bail!("schedule has no deployment_id");
    };

    // Resolve the target container: prefer the stored value, else the deployment spec's first.
    let target_container = match &sched.target_container {
        Some(c) if !c.is_empty() => c.clone(),
        _ => first_container_name(deployment_service, deployment_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("could not resolve a target container"))?,
    };

    // Find an agent currently targeting this deployment.
    let targets = deployment_service
        .get_targets_for_deployment(deployment_id)
        .await?;
    let Some(target) = targets.first() else {
        anyhow::bail!("deployment has no agent targets");
    };
    let agent_id = target.agent_id;

    // Record the pending execution (mark_schedule_ran first so a dispatch failure mid-loop
    // does not cause a tight re-fire next tick).
    deployment_service
        .mark_backup_schedule_ran(sched.id, now)
        .await?;
    let exec_id = deployment_service
        .trigger_backup(
            deployment_id,
            Some(sched.id),
            &sched.db_type,
            sched.database_name.as_deref(),
            sched.s3_endpoint.as_deref(),
            sched.s3_bucket.as_deref(),
            sched.s3_key_prefix.as_deref(),
        )
        .await?;

    // Build the S3 destination (if configured) + resolve the secret KEY as an age SecretRef.
    let (s3, secrets) = build_s3_destination(deployment_service, sched, exec_id).await?;

    let job = Job::Backup {
        deployment_id,
        target_container,
        db_type: sched.db_type.clone(),
        database: sched.database_name.clone(),
        s3,
        secrets,
    };
    let signer = JobSigner::new((**signing_key).clone());
    let signed = signer.sign(job);

    // Dispatch to the connected agent, or durably queue when offline.
    if !registry.send_job(agent_id, signed.clone()).await {
        deployment_service
            .queue_pending_dispatch(deployment_id, agent_id, &signed)
            .await?;
        tracing::info!(schedule_id = %sched.id, %agent_id, "agent offline — backup job queued");
    } else {
        tracing::info!(schedule_id = %sched.id, %agent_id, "dispatched scheduled Job::Backup");
    }

    // Retention: trim old execution rows (and record operator intent for S3 lifecycle).
    let _ = deployment_service
        .prune_backup_executions(sched.id, sched.retention_days, sched.retention_count)
        .await;

    Ok(())
}

/// Build the [`S3BackupConfig`] for a schedule's execution + resolve its secret key ref.
/// The access-key id is non-secret and rides in the config; the secret KEY is fetched from
/// the age secret store as a [`forge_agent::job::SecretRef`] (never plaintext here).
async fn build_s3_destination(
    deployment_service: &DeploymentService,
    sched: &BackupScheduleRow,
    exec_id: Uuid,
) -> anyhow::Result<(Option<S3BackupConfig>, Vec<forge_agent::job::SecretRef>)> {
    let (Some(endpoint), Some(bucket)) = (sched.s3_endpoint.clone(), sched.s3_bucket.clone())
    else {
        return Ok((None, vec![]));
    };

    let prefix = sched.s3_key_prefix.clone().unwrap_or_default();
    let prefix = prefix.trim_end_matches('/');
    let key = if prefix.is_empty() {
        format!("backup-{exec_id}.sql")
    } else {
        format!("{prefix}/backup-{exec_id}.sql")
    };

    let mut secrets = Vec::new();
    if let Some(secret_id) = sched.s3_secret_id {
        if let Some(secret_ref) = deployment_service
            .secret_ref_for(secret_id, "s3_secret_key", "S3_SECRET_KEY")
            .await?
        {
            secrets.push(secret_ref);
        }
    }

    let cfg = S3BackupConfig {
        endpoint,
        bucket,
        key,
        access_key: sched.s3_access_key_id.clone(),
        // The secret key is NEVER inlined here; it travels age-encrypted in `secrets`.
        secret_key: None,
        region: sched.s3_region.clone(),
    };
    Ok((Some(cfg), secrets))
}

/// Resolve the first container name from a deployment's stored spec.
async fn first_container_name(
    deployment_service: &DeploymentService,
    deployment_id: Uuid,
) -> Option<String> {
    let dep = deployment_service
        .get_deployment(deployment_id)
        .await
        .ok()??;
    dep.spec
        .get("containers")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod dispatch_tests {
    //! DB-backed scheduler dispatch tests (`#[sqlx::test]` → isolated DB + ./migrations).
    //! The dispatch seam is the real `AgentRegistry`: we register a fake agent's mpsc channel
    //! and assert a signed `Job::Backup` arrives (or is queued when offline), plus retention.
    use super::*;
    use forge_agent::job::{Job, SignedJob};
    use forge_core::{DeploymentStrategy, DeploymentTarget, RollingConfig};

    fn svc(pool: PgPool) -> Arc<DeploymentService> {
        let rbac = Arc::new(crate::rbac::RbacService::new(pool.clone()));
        Arc::new(DeploymentService::new(pool, rbac))
    }

    fn rolling() -> DeploymentStrategy {
        DeploymentStrategy::Rolling(RollingConfig {
            max_unavailable: 1,
            max_surge: 0,
            health_check_grace_period_secs: 30,
            rollback_on_failure: true,
            failure_threshold: 3,
        })
    }

    /// Insert a minimal agent row so deployment_targets' FK is satisfiable.
    async fn seed_agent(pool: &PgPool) -> Uuid {
        let id = Uuid::now_v7();
        // public_key is UNIQUE NOT NULL; use the agent id bytes as a stand-in key.
        sqlx::query!(
            "INSERT INTO agents (id, hostname, public_key) VALUES ($1, 'test', $2)",
            id,
            id.as_bytes().to_vec()
        )
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// App + deployment (with one target agent) + an interval schedule. Returns ids.
    async fn seed_scheduled_deployment(
        dep_svc: &DeploymentService,
        pool: &PgPool,
        agent_id: Uuid,
    ) -> (Uuid, Uuid) {
        let app = dep_svc
            .create_application("sched-app", None, None)
            .await
            .unwrap();
        let dep = dep_svc
            .create_deployment(
                app.id,
                serde_json::json!({ "containers": [{ "name": "postgres", "image": "postgres:16" }] }),
                rolling(),
                vec![DeploymentTarget { agent_id, replicas: 1 }],
            )
            .await
            .unwrap();
        // Interval=60s, never run yet → due immediately.
        let sched = dep_svc
            .create_backup_schedule(
                dep.id,
                "nightly",
                "postgres",
                None,
                "interval",
                "60",
                30,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("postgres"),
            )
            .await
            .unwrap();
        let schedule_id = sched["id"].as_str().unwrap().parse().unwrap();
        let _ = pool; // pool reused by callers for assertions
        (dep.id, schedule_id)
    }

    #[sqlx::test]
    async fn due_schedule_creates_execution_and_dispatches_backup(pool: PgPool) {
        let dep_svc = svc(pool.clone());
        let agent_id = seed_agent(&pool).await;
        let (dep_id, schedule_id) = seed_scheduled_deployment(&dep_svc, &pool, agent_id).await;

        // Register a fake connected agent so dispatch goes to a channel we can read.
        let registry = AgentRegistry::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SignedJob>(4);
        registry.register(agent_id, tx).await;

        let signing_key = Arc::new(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));

        scan_once(&pool, &dep_svc, &registry, &signing_key)
            .await
            .unwrap();

        // A pending execution row was created.
        let exec_count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM backup_executions WHERE deployment_id = $1",
            dep_id
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
        assert_eq!(exec_count, 1, "scheduler should create one execution");

        // A signed Job::Backup was dispatched to the connected agent.
        let signed = rx
            .try_recv()
            .expect("a backup job should have been dispatched");
        match signed.job {
            Job::Backup {
                deployment_id,
                db_type,
                target_container,
                ..
            } => {
                assert_eq!(deployment_id, dep_id);
                assert_eq!(db_type, "postgres");
                assert_eq!(target_container, "postgres");
            }
            other => panic!("expected Job::Backup, got {other:?}"),
        }

        // last_run_at stamped → not due again on the next immediate scan.
        scan_once(&pool, &dep_svc, &registry, &signing_key)
            .await
            .unwrap();
        let exec_count2 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM backup_executions WHERE deployment_id = $1",
            dep_id
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
        assert_eq!(exec_count2, 1, "interval not elapsed → no second execution");
        let _ = schedule_id;
    }

    #[sqlx::test]
    async fn offline_agent_queues_pending_dispatch(pool: PgPool) {
        let dep_svc = svc(pool.clone());
        let agent_id = seed_agent(&pool).await;
        let (dep_id, _sched) = seed_scheduled_deployment(&dep_svc, &pool, agent_id).await;

        // Empty registry → agent is "offline".
        let registry = AgentRegistry::new();
        let signing_key = Arc::new(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));

        scan_once(&pool, &dep_svc, &registry, &signing_key)
            .await
            .unwrap();

        let queued = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM pending_dispatches WHERE deployment_id = $1",
            dep_id
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
        assert_eq!(queued, 1, "offline agent → job durably queued");
    }

    #[sqlx::test]
    async fn retention_prunes_old_executions(pool: PgPool) {
        let dep_svc = svc(pool.clone());
        let agent_id = seed_agent(&pool).await;
        let (dep_id, schedule_id) = seed_scheduled_deployment(&dep_svc, &pool, agent_id).await;

        // Seed two old SUCCESS executions (40 days old) + retention_days defaulted to 30.
        for _ in 0..2 {
            let id = Uuid::now_v7();
            sqlx::query!(
                r#"INSERT INTO backup_executions (id, schedule_id, deployment_id, status, db_type, created_at)
                   VALUES ($1, $2, $3, 'success', 'postgres', NOW() - INTERVAL '40 days')"#,
                id,
                schedule_id,
                dep_id
            )
            .execute(&pool)
            .await
            .unwrap();
        }

        let pruned = dep_svc
            .prune_backup_executions(schedule_id, 30, None)
            .await
            .unwrap();
        assert_eq!(
            pruned, 2,
            "both 40-day-old executions are beyond 30-day retention"
        );
    }
}
