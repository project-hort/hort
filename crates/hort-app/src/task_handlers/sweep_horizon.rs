//! Shared `params` → horizon resolution for the three `jobs`-row
//! retention sweeps (`prefetch-row-retention-sweep`,
//! `scan-row-retention-sweep`, `jobs-row-retention-sweep`).
//!
//! All three take the same single-field `params` shape, default to their
//! own 7-day constant when the field is absent, and reject a value above
//! their own 365-day cap as a non-retryable configuration error. The
//! three copies were near-verbatim; the resolution rule lives here once
//! so a change to it cannot land on two sweeps and miss the third.
//!
//! # No supported path supplies `horizon_seconds`
//!
//! Every path that enqueues one of these sweeps writes an **empty**
//! `params` object: the Helm CronJobs and the systemd timers both run
//! `hort-server enqueue-<kind>`, and those subcommands take no arguments
//! and write `{}` unconditionally. The `hort-http-admin-tasks` router
//! enumerates its invoke routes one by one and none of the three
//! retention kinds is among them, so `POST
//! /api/v1/admin/tasks/<kind>` answers 404. The field is therefore
//! readable by the handler and supplied by nothing short of a
//! hand-written `INSERT` into `public.jobs`, which means the default is
//! the horizon in force on every deployment. The parse and the cap are
//! kept because they are what makes that statement safe: a
//! hand-written row with a nonsense value fails the task instead of
//! running a year-wide `DELETE`.

use std::time::Duration;

use serde::Deserialize;

use hort_domain::ports::task_handler::TaskOutcome;

/// Seconds in a day — used only to render the cap in the rejection
/// message in the unit an operator would have reasoned in.
const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// Parsed shape of the `params` JSONB column for any of the three
/// retention sweeps.
#[derive(Debug, Deserialize, Default)]
struct SweepHorizonParams {
    /// Retention horizon in seconds. Rows whose `updated_at` is older
    /// than `now() - horizon_seconds` are eligible for deletion.
    /// Absent on every supported enqueue path (see the module docs), in
    /// which case the caller's default applies.
    #[serde(default)]
    horizon_seconds: Option<u64>,
}

/// Resolve the retention horizon for `kind` from its `params` JSONB.
///
/// Returns `Err(TaskOutcome::Failed { retry: false, .. })` for both
/// failure modes — malformed `params` and a value above `max`. Neither
/// is transient: re-running the same row produces the same verdict, so
/// retrying only burns attempts. `kind` is carried solely to name the
/// sweep in those two messages; all three sweeps otherwise resolve
/// identically.
pub(crate) fn resolve_sweep_horizon(
    kind: &str,
    params: &serde_json::Value,
    default: Duration,
    max: Duration,
) -> Result<Duration, TaskOutcome> {
    let parsed: SweepHorizonParams = serde_json::from_value(params.clone())
        .map_err(|err| TaskOutcome::fail(format!("{kind} params JSON invalid: {err}"), false))?;

    let Some(secs) = parsed.horizon_seconds else {
        return Ok(default);
    };

    let horizon = Duration::from_secs(secs);
    if horizon > max {
        return Err(TaskOutcome::fail(
            format!(
                "{kind}: horizon_seconds {secs} exceeds the {max_secs}-second cap ({days} days)",
                max_secs = max.as_secs(),
                days = max.as_secs() / SECS_PER_DAY,
            ),
            false,
        ));
    }
    Ok(horizon)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    const DEFAULT: Duration = Duration::from_secs(7 * SECS_PER_DAY);
    const MAX: Duration = Duration::from_secs(365 * SECS_PER_DAY);

    #[test]
    fn absent_field_yields_the_caller_default() {
        let horizon = resolve_sweep_horizon("scan-row-retention-sweep", &json!({}), DEFAULT, MAX)
            .expect("bare params resolve");
        assert_eq!(horizon, DEFAULT);
    }

    /// A bare `null` fails to parse rather than resolving to the
    /// default — and that is reachable only through a fabricated
    /// `TaskContext`, never from a real row.
    ///
    /// `TaskDispatcher::dispatch_one` passes
    /// `job.params.clone().unwrap_or(serde_json::Value::Null)`, so the
    /// `Option` suggests a `null` can arrive; the schema says otherwise.
    /// `public.jobs.params` is `jsonb NOT NULL DEFAULT '{}'::jsonb`
    /// (migration 009), so an `INSERT` that names no `params` at all
    /// stores `{}` and the handler sees an empty object. The `None` arm
    /// of that `unwrap_or` is unreachable for any row the database
    /// produced.
    ///
    /// Pinned rather than smoothed over: making `null` resolve to the
    /// default would be a behaviour change dressed as a refactor, and it
    /// would diverge from every sibling handler that parses `params`
    /// this way (`provenance_verify`, `policy_reevaluation`,
    /// `oci_index_child_ingest`, `prefetch_ingest`). If the column ever
    /// becomes nullable, this test is the one that must be revisited.
    #[test]
    fn a_bare_null_is_a_parse_failure_and_is_unreachable_from_a_real_row() {
        let outcome = resolve_sweep_horizon(
            "prefetch-row-retention-sweep",
            &serde_json::Value::Null,
            DEFAULT,
            MAX,
        )
        .expect_err("a bare null does not deserialize into the params struct");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(!retry, "a malformed params value never becomes well-formed");
        assert!(
            reason.contains("prefetch-row-retention-sweep params JSON invalid"),
            "{reason}"
        );
    }

    /// An explicit `null` for the field itself is the same as absent.
    #[test]
    fn explicit_null_field_yields_the_caller_default() {
        let horizon = resolve_sweep_horizon(
            "jobs-row-retention-sweep",
            &json!({"horizon_seconds": null}),
            DEFAULT,
            MAX,
        )
        .expect("explicit null resolves");
        assert_eq!(horizon, DEFAULT);
    }

    #[test]
    fn supplied_value_overrides_the_default() {
        let horizon = resolve_sweep_horizon(
            "scan-row-retention-sweep",
            &json!({"horizon_seconds": 3600}),
            DEFAULT,
            MAX,
        )
        .expect("supplied value resolves");
        assert_eq!(horizon, Duration::from_secs(3600));
    }

    /// The cap check is `>`, so the cap value itself resolves rather
    /// than being rejected.
    #[test]
    fn the_cap_value_itself_is_accepted() {
        let horizon = resolve_sweep_horizon(
            "scan-row-retention-sweep",
            &json!({"horizon_seconds": MAX.as_secs()}),
            DEFAULT,
            MAX,
        )
        .expect("the cap resolves");
        assert_eq!(horizon, MAX);
    }

    /// The cap rejection names the sweep, the offending value, the cap
    /// in seconds, and the cap in days — the last because the cap is
    /// stated in days everywhere an operator would have read it.
    #[test]
    fn above_the_cap_is_a_non_retryable_failure_naming_the_sweep() {
        let outcome = resolve_sweep_horizon(
            "scan-row-retention-sweep",
            &json!({"horizon_seconds": MAX.as_secs() + 1}),
            DEFAULT,
            MAX,
        )
        .expect_err("above the cap fails");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(
            !retry,
            "cap-exceeded is a configuration error, not transient"
        );
        assert!(reason.contains("scan-row-retention-sweep"), "{reason}");
        assert!(reason.contains("365 days"), "{reason}");
        assert!(
            reason.contains(&(MAX.as_secs() + 1).to_string()),
            "{reason}"
        );
    }

    /// The caller's own cap is what is enforced, not a constant baked in
    /// here — a sweep that lowered its cap must reject at the lower one.
    #[test]
    fn the_cap_enforced_is_the_callers_not_a_baked_in_constant() {
        let low = Duration::from_secs(30 * SECS_PER_DAY);
        let outcome = resolve_sweep_horizon(
            "jobs-row-retention-sweep",
            &json!({"horizon_seconds": 31 * SECS_PER_DAY}),
            DEFAULT,
            low,
        )
        .expect_err("above the lowered cap fails");
        let TaskOutcome::Failed { reason, .. } = outcome else {
            panic!("expected Failed");
        };
        assert!(reason.contains("30 days"), "{reason}");
    }

    #[test]
    fn malformed_params_is_a_non_retryable_failure_naming_the_sweep() {
        let outcome = resolve_sweep_horizon(
            "prefetch-row-retention-sweep",
            &json!({"horizon_seconds": "not-a-number"}),
            DEFAULT,
            MAX,
        )
        .expect_err("malformed params fail");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(
            !retry,
            "a malformed params object never becomes well-formed"
        );
        assert!(
            reason.contains("prefetch-row-retention-sweep params JSON invalid"),
            "{reason}"
        );
    }

    /// An unknown key is ignored rather than rejected: `params` is a
    /// JSONB column several writers touch, and a sweep that refused to
    /// run because of a key it does not read would be a worse failure
    /// than ignoring it.
    #[test]
    fn unknown_keys_are_ignored() {
        let horizon = resolve_sweep_horizon(
            "scan-row-retention-sweep",
            &json!({"horizon_seconds": 60, "unrelated": true}),
            DEFAULT,
            MAX,
        )
        .expect("unknown keys ignored");
        assert_eq!(horizon, Duration::from_secs(60));
    }
}
