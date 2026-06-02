-- 0023_alert_rules.up.sql
-- Monitoring threshold alerts: operator-defined rules evaluated against the
-- deployment_metrics time-series, plus a fired/resolved event log.
--
-- A rule fires when its comparator/threshold has been breached *continuously* for
-- `duration_secs` (debounce against transient blips), and re-fires no more often
-- than `cooldown_secs` while still firing (anti alert-storm, OWASP A09).

CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    -- Which slice of metrics this rule watches.
    scope TEXT NOT NULL CHECK (scope IN ('global', 'agent', 'deployment')),
    -- For 'agent' / 'deployment' scopes this is the concrete target; NULL for 'global'.
    target_id UUID,
    metric_name TEXT NOT NULL,
    comparator TEXT NOT NULL CHECK (comparator IN ('gt', 'lt', 'gte', 'lte')),
    threshold DOUBLE PRECISION NOT NULL,
    -- Breach must persist continuously this long before the rule fires.
    duration_secs INTEGER NOT NULL DEFAULT 0 CHECK (duration_secs >= 0),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    -- Minimum seconds between repeat 'firing' notifications while still breached.
    cooldown_secs INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_secs >= 0),
    created_by_principal_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A scoped rule must carry a target; a global rule must not.
    CONSTRAINT alert_rules_scope_target_ck CHECK (
        (scope = 'global' AND target_id IS NULL)
        OR (scope IN ('agent', 'deployment') AND target_id IS NOT NULL)
    )
);

-- The evaluator scans enabled rules each tick.
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules (enabled);

CREATE TABLE IF NOT EXISTS alert_events (
    id UUID PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    target_id UUID,
    metric_name TEXT NOT NULL,
    observed_value DOUBLE PRECISION NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('firing', 'resolved')),
    fired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    -- Whether the firing notification was successfully enqueued (audit / debounce).
    notified BOOLEAN NOT NULL DEFAULT false,
    -- Last time we (re-)sent a firing notification, for cooldown bookkeeping.
    last_notified_at TIMESTAMPTZ
);

-- The evaluator looks up "is there an open firing event for this rule?" every tick.
CREATE INDEX IF NOT EXISTS idx_alert_events_rule_state ON alert_events (rule_id, state);
-- Recent-events feed for the admin UI, filterable by state/severity.
CREATE INDEX IF NOT EXISTS idx_alert_events_fired_at ON alert_events (fired_at DESC);

CREATE TRIGGER trg_alert_rules_updated_at
    BEFORE UPDATE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
