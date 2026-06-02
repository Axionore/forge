//! Pure backup-schedule cadence logic (no DB, no agent deps).
//!
//! Lives in its own module so both the control-plane service (`deployment`) and the
//! background dispatcher (`backup_scheduler`) — and both the lib and bin crate roots —
//! can share the exact same validation + due-evaluation. A schedule is either an `interval`
//! (bounded seconds) or a 5-field `cron` expression.

use chrono::{DateTime, Utc};

/// Smallest interval a schedule may request (seconds). Guards against a runaway 1s schedule.
pub const MIN_INTERVAL_SECS: i64 = 60;
/// Largest interval a schedule may request (seconds) — one year.
pub const MAX_INTERVAL_SECS: i64 = 31_536_000;

/// Validate `(schedule_type, schedule_value)` at creation time. Returns a clean message on
/// failure. For `interval` the value is bounded seconds; for `cron` it must be a 5-field
/// expression we can evaluate.
pub fn validate_schedule(schedule_type: &str, schedule_value: &str) -> Result<(), String> {
    match schedule_type {
        "interval" => {
            let secs: i64 = schedule_value
                .trim()
                .parse()
                .map_err(|_| "interval schedule_value must be an integer number of seconds")?;
            if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs) {
                return Err(format!(
                    "interval must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS} seconds"
                ));
            }
            Ok(())
        }
        "cron" => parse_cron(schedule_value).map(|_| ()),
        _ => Err("schedule_type must be 'interval' or 'cron'".into()),
    }
}

/// A minimal 5-field cron (`min hour dom month dow`). Each field is `*` or a comma list of
/// integers / ranges (`a-b`) / steps (`*/n`). Sufficient for backup cadences without pulling
/// in a cron crate; rejects anything it cannot parse so a bad expression never silently
/// never-fires.
struct Cron {
    minute: CronField,
    hour: CronField,
    dom: CronField,
    month: CronField,
    dow: CronField,
}

enum CronField {
    Any,
    Set(Vec<u32>),
}

impl CronField {
    fn matches(&self, v: u32) -> bool {
        match self {
            CronField::Any => true,
            CronField::Set(s) => s.contains(&v),
        }
    }
}

fn parse_field(spec: &str, min: u32, max: u32) -> Result<CronField, String> {
    let spec = spec.trim();
    if spec == "*" {
        return Ok(CronField::Any);
    }
    let mut out: Vec<u32> = Vec::new();
    for part in spec.split(',') {
        if let Some(step) = part.strip_prefix("*/") {
            let n: u32 = step.parse().map_err(|_| "invalid cron step")?;
            if n == 0 {
                return Err("cron step cannot be zero".into());
            }
            let mut v = min;
            while v <= max {
                out.push(v);
                v += n;
            }
        } else if let Some((a, b)) = part.split_once('-') {
            let a: u32 = a.parse().map_err(|_| "invalid cron range")?;
            let b: u32 = b.parse().map_err(|_| "invalid cron range")?;
            if a > b || a < min || b > max {
                return Err("cron range out of bounds".into());
            }
            out.extend(a..=b);
        } else {
            let v: u32 = part.parse().map_err(|_| "invalid cron value")?;
            if v < min || v > max {
                return Err("cron value out of bounds".into());
            }
            out.push(v);
        }
    }
    if out.is_empty() {
        return Err("empty cron field".into());
    }
    Ok(CronField::Set(out))
}

fn parse_cron(expr: &str) -> Result<Cron, String> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err("cron must have 5 fields: min hour dom month dow".into());
    }
    Ok(Cron {
        minute: parse_field(fields[0], 0, 59)?,
        hour: parse_field(fields[1], 0, 23)?,
        dom: parse_field(fields[2], 1, 31)?,
        month: parse_field(fields[3], 1, 12)?,
        dow: parse_field(fields[4], 0, 6)?,
    })
}

/// Decide whether a schedule is due at `now`, given its `last_run_at`.
///
/// * interval: due when `now - last_run >= interval` (or never run).
/// * cron: due when the current minute matches the expression AND we did not already run in
///   this same minute. Pragmatic "fire at most once per matching minute" suited to a 60s scan.
#[must_use]
pub fn is_due(
    schedule_type: &str,
    schedule_value: &str,
    last_run_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    match schedule_type {
        "interval" => {
            let Ok(secs) = schedule_value.trim().parse::<i64>() else {
                return false; // unparseable → never fire (fail-safe)
            };
            match last_run_at {
                None => true,
                Some(last) => now - last >= chrono::Duration::seconds(secs),
            }
        }
        "cron" => {
            let Ok(cron) = parse_cron(schedule_value) else {
                return false;
            };
            use chrono::{Datelike, Timelike};
            let matches = cron.minute.matches(now.minute())
                && cron.hour.matches(now.hour())
                && cron.dom.matches(now.day())
                && cron.month.matches(now.month())
                && cron.dow.matches(now.weekday().num_days_from_sunday());
            if !matches {
                return false;
            }
            match last_run_at {
                None => true,
                Some(last) => {
                    let same_minute = last.date_naive() == now.date_naive()
                        && last.hour() == now.hour()
                        && last.minute() == now.minute();
                    !same_minute
                }
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_validation_bounds() {
        assert!(validate_schedule("interval", "86400").is_ok());
        assert!(validate_schedule("interval", "30").is_err()); // below MIN
        assert!(validate_schedule("interval", "abc").is_err());
        assert!(validate_schedule("interval", "999999999999").is_err());
    }

    #[test]
    fn cron_validation() {
        assert!(validate_schedule("cron", "0 2 * * *").is_ok());
        assert!(validate_schedule("cron", "*/15 * * * *").is_ok());
        assert!(validate_schedule("cron", "0 2 * *").is_err()); // 4 fields
        assert!(validate_schedule("cron", "99 2 * * *").is_err()); // minute OOB
    }

    #[test]
    fn interval_is_due_logic() {
        let now = Utc::now();
        assert!(is_due("interval", "3600", None, now));
        assert!(!is_due(
            "interval",
            "3600",
            Some(now - chrono::Duration::minutes(30)),
            now
        ));
        assert!(is_due(
            "interval",
            "3600",
            Some(now - chrono::Duration::hours(2)),
            now
        ));
        assert!(!is_due("interval", "nope", None, now));
    }

    #[test]
    fn cron_is_due_matches_minute_once() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap();
        assert!(is_due("cron", "0 2 * * *", None, now));
        assert!(!is_due("cron", "0 2 * * *", Some(now), now));
        let off = Utc.with_ymd_and_hms(2026, 1, 1, 3, 0, 0).unwrap();
        assert!(!is_due("cron", "0 2 * * *", None, off));
    }
}
