//! TaskHandler for the periodic quarantine release sweep.
//!
//! Triggered by the k8s CronJob (`deploy/helm/hort-server/templates/
//! cronjob-quarantine-release-sweep.yaml`) which runs the
//! `hort-server enqueue-quarantine-release-sweep` subcommand using the
//! **runtime DSN** — the subcommand inserts the
//! `quarantine-release-sweep` job row directly; the always-on worker
//! then picks it up and dispatches to this handler. This deliberately
//! bypasses the `hort-cli` HTTP admin-task path (no svc-token,
//! no `cronJobs.enabled` umbrella): a
//! default-enabled sweep CronJob must not drag the whole svc-token
//! bootstrap chain to default-on. Default schedule **every 5 minutes**.
//!
//! The handler is a thin orchestration step, modelled 1:1 on
//! [`CronRescanTickHandler`](super::cron_rescan_tick):
//!
//! 1. Capture `now`.
//! 2. Call [`QuarantineReleaseCandidatesRepository::select_expired`]
//!    to fetch up to [`BATCH_SIZE`] artifact ids whose computed
//!    deadline (`quarantine_window_start + effective_duration`) is at
//!    or before `now` — the adapter resolves `repo → effective
//!    duration` from `policy_projections` (repo-scoped → global →
//!    default) and issues one indexed range scan per
//!    distinct duration `D`, using the partial index
//!    `idx_artifacts_quarantine_window_start ON (quarantine_window_start)
//!    WHERE quarantine_status='quarantined'`.
//! 3. Pass the ids to [`QuarantineReleasePort::release_expired`] (the
//!    application-layer `QuarantineUseCase::release_expired`). That
//!    call re-evaluates the
//!    fail-closed release-authority predicate (`ScanSucceeded` /
//!    `ScanWaived`; ADR 0007) per artifact; a window-expired candidate
//!    without a clean scan stays quarantined and falls out of the
//!    returned `Vec`.
//! 4. Return [`TaskOutcome::Completed`] with a result summary
//!    `{ candidates, released, skipped_no_authority }` — the
//!    `skipped_no_authority` count is the deny-by-default
//!    observability signal (per-tick summary:
//!    candidates / released / skipped-no-authority).
//!
//! **No new metric.** Reuse
//! `hort_quarantine_released_total{reason=timer}` — that counter fires
//! inside `release_expired` itself on each successful release. The
//! handler's `info!` line is the per-tick observability.
//!
//! **Authority discipline (ADR 0007).** The candidacy
//! filter and the release-authority gate live in different layers, by
//! construction:
//!
//! - candidacy = "window deadline elapsed" → adapter SQL (this file's
//!   `select_expired` call);
//! - authority = "successful scan exists OR scanning waived" →
//!   `release_expired` (unchanged), which constructs no authority
//!   when neither holds and the candidate is skipped.
//!
//! A defect in the candidacy SQL therefore cannot cause an early
//! release — the worst it can do is enqueue extra ids that are
//! re-checked and immediately discarded. This is the
//! fail-safe-by-construction property the regression test
//! (`run_fail_closed_does_not_release_unscanned_candidate`) pins.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::quarantine_release::QuarantineReleasePort;
use hort_domain::ports::quarantine_release_candidates::QuarantineReleaseCandidatesRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hard cap on candidates fetched per tick. Mirrors
/// [`CronRescanTickHandler`](super::cron_rescan_tick)'s `BATCH_SIZE` —
/// a single tick cannot drive more than this many `release_expired`
/// calls. Subsequent CronJob runs drain any backlog (5-minute cadence).
///
/// Pinning the cap as a `u32` constant (rather than wiring through
/// env) matches `CronRescanTickHandler` — ENV-tuning is deliberately
/// not offered.
const BATCH_SIZE: u32 = 1000;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic quarantine-release sweep.
/// Constructed at composition
/// time with the two ports it touches.
pub struct QuarantineReleaseSweepHandler {
    candidates: Arc<dyn QuarantineReleaseCandidatesRepository>,
    release: Arc<dyn QuarantineReleasePort>,
}

impl QuarantineReleaseSweepHandler {
    /// Construct the handler from its two port dependencies.
    pub fn new(
        candidates: Arc<dyn QuarantineReleaseCandidatesRepository>,
        release: Arc<dyn QuarantineReleasePort>,
    ) -> Self {
        Self {
            candidates,
            release,
        }
    }
}

impl TaskHandler for QuarantineReleaseSweepHandler {
    fn kind(&self) -> &'static str {
        "quarantine-release-sweep"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            let candidates = match self.candidates.select_expired(BATCH_SIZE, now).await {
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "quarantine-release-sweep: select_expired failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("select_expired failed: {err}"),
                        true,
                    ));
                }
            };

            let candidate_count = candidates.len();
            if candidate_count == 0 {
                // Most ticks under steady-state will be empty — short-
                // circuit before invoking `release_expired` (which would
                // otherwise round-trip an empty Vec through the use
                // case). Mirrors `CronRescanTickHandler`'s empty arm.
                tracing::info!(
                    candidates = 0_u64,
                    released = 0_u64,
                    skipped_no_authority = 0_u64,
                    "quarantine-release-sweep tick complete (no candidates)"
                );
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "candidates": 0,
                        "released": 0,
                        "skipped_no_authority": 0,
                    }),
                });
            }

            let ids: Vec<uuid::Uuid> = candidates.iter().map(|c| c.artifact_id).collect();

            let released = match self.release.release_expired(ids).await {
                Ok(r) => r,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        candidates = candidate_count,
                        "quarantine-release-sweep: release_expired failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("release_expired failed: {err}"),
                        true,
                    ));
                }
            };

            let released_count = released.len();
            // `release_expired` returns a strict subset (F-6 fail-
            // closed): a candidate without `ScanSucceeded`/`ScanWaived`
            // authority is skipped, not released. The delta IS the
            // F-6 deny-by-default observability signal.
            let skipped_no_authority = candidate_count.saturating_sub(released_count);

            tracing::info!(
                candidates = candidate_count,
                released = released_count,
                skipped_no_authority,
                "quarantine-release-sweep tick complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "candidates": candidate_count,
                    "released": released_count,
                    "skipped_no_authority": skipped_no_authority,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::DateTime;
    use uuid::Uuid;

    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::quarantine_release_candidates::QuarantineReleaseCandidate;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};

    // ---------- helpers ---------------------------------------------------

    fn make_candidate() -> QuarantineReleaseCandidate {
        QuarantineReleaseCandidate {
            artifact_id: Uuid::new_v4(),
        }
    }

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "quarantine-release-sweep".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "test".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    // ---------- mock QuarantineReleaseCandidatesRepository ---------------

    struct MockCandidates {
        rows: Mutex<Vec<QuarantineReleaseCandidate>>,
        err: Mutex<Option<DomainError>>,
        last_batch_size: Mutex<Option<u32>>,
    }

    impl MockCandidates {
        fn new(rows: Vec<QuarantineReleaseCandidate>) -> Self {
            Self {
                rows: Mutex::new(rows),
                err: Mutex::new(None),
                last_batch_size: Mutex::new(None),
            }
        }

        fn new_failing(err: DomainError) -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                err: Mutex::new(Some(err)),
                last_batch_size: Mutex::new(None),
            }
        }

        fn last_batch_size(&self) -> Option<u32> {
            *self.last_batch_size.lock().unwrap()
        }
    }

    impl QuarantineReleaseCandidatesRepository for MockCandidates {
        fn select_expired<'a>(
            &'a self,
            batch_size: u32,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<QuarantineReleaseCandidate>>> {
            *self.last_batch_size.lock().unwrap() = Some(batch_size);
            let maybe_err = self.err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let rows = self.rows.lock().unwrap().clone();
            Box::pin(async move { Ok(rows) })
        }
    }

    // ---------- mock QuarantineReleasePort -------------------------------

    /// Releaser mock. `released_subset` controls which ids the port
    /// claims it released (F-6: returns a strict subset of input). An
    /// `Internal` failure simulates a non-domain crash (the handler
    /// must surface this as `TaskOutcome::Failed { retry: true }`).
    struct MockReleaser {
        /// Ids the mock pretends to release. Anything in the input not
        /// in this set is "skipped — no authority" (the F-6 path).
        released_subset: Mutex<Vec<Uuid>>,
        err: Mutex<Option<DomainError>>,
        last_input: Mutex<Vec<Uuid>>,
    }

    impl MockReleaser {
        fn releases_none() -> Self {
            Self {
                released_subset: Mutex::new(Vec::new()),
                err: Mutex::new(None),
                last_input: Mutex::new(Vec::new()),
            }
        }

        fn releases_all_input() -> Self {
            // Sentinel: the mock returns `input.clone()` — every id is
            // "released". Used by the happy-path test.
            Self {
                released_subset: Mutex::new(Vec::new()), // unused; flag below
                err: Mutex::new(None),
                last_input: Mutex::new(Vec::new()),
            }
        }

        fn new_failing(err: DomainError) -> Self {
            Self {
                released_subset: Mutex::new(Vec::new()),
                err: Mutex::new(Some(err)),
                last_input: Mutex::new(Vec::new()),
            }
        }

        fn last_input(&self) -> Vec<Uuid> {
            self.last_input.lock().unwrap().clone()
        }
    }

    impl QuarantineReleasePort for MockReleaser {
        fn release_expired<'a>(
            &'a self,
            artifact_ids: Vec<Uuid>,
        ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
            *self.last_input.lock().unwrap() = artifact_ids.clone();
            let maybe_err = self.err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let subset = self.released_subset.lock().unwrap().clone();
            // Convention: empty subset means "release nothing" (F-6
            // fail-closed path); otherwise the mock returns the ids
            // that ALSO appear in the input (intersection).
            let result: Vec<Uuid> = if subset.is_empty() {
                Vec::new()
            } else {
                artifact_ids
                    .into_iter()
                    .filter(|id| subset.contains(id))
                    .collect()
            };
            Box::pin(async move { Ok(result) })
        }
    }

    fn make_handler(
        candidates: Arc<MockCandidates>,
        releaser: Arc<MockReleaser>,
    ) -> QuarantineReleaseSweepHandler {
        QuarantineReleaseSweepHandler::new(
            candidates as Arc<dyn QuarantineReleaseCandidatesRepository>,
            releaser as Arc<dyn QuarantineReleasePort>,
        )
    }

    // =====================================================================
    // kind() returns "quarantine-release-sweep"
    // =====================================================================

    #[test]
    fn kind_returns_quarantine_release_sweep() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let releaser = Arc::new(MockReleaser::releases_none());
        let handler = make_handler(candidates, releaser);
        assert_eq!(handler.kind(), "quarantine-release-sweep");
    }

    // =====================================================================
    // empty: no candidates → result_summary all zeros, release NOT called
    // =====================================================================

    #[tokio::test]
    async fn run_with_empty_candidates_returns_zero_counts_and_skips_release() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let releaser = Arc::new(MockReleaser::releases_none());

        let releaser_for_assert = releaser.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 0);
                assert_eq!(result_summary["released"], 0);
                assert_eq!(result_summary["skipped_no_authority"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(
            releaser_for_assert.last_input().is_empty(),
            "no candidates → release_expired must NOT be called",
        );
    }

    // =====================================================================
    // happy path: 3 candidates, all released → counts line up
    // =====================================================================

    #[tokio::test]
    async fn run_with_three_candidates_all_released_records_correct_counts() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![
            c1.clone(),
            c2.clone(),
            c3.clone(),
        ]));
        let releaser = Arc::new(MockReleaser::releases_all_input());
        // Programme the releaser to "release" every id in the input.
        *releaser.released_subset.lock().unwrap() =
            vec![c1.artifact_id, c2.artifact_id, c3.artifact_id];

        let releaser_for_assert = releaser.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 3);
                assert_eq!(result_summary["released"], 3);
                assert_eq!(result_summary["skipped_no_authority"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // `release_expired` got exactly the candidate ids the SQL
        // returned, in order — the handler does NOT filter, dedupe,
        // or re-order between SQL and use case.
        let input = releaser_for_assert.last_input();
        assert_eq!(input, vec![c1.artifact_id, c2.artifact_id, c3.artifact_id]);
    }

    // =====================================================================
    // F-6 fail-closed regression (Item 1b acceptance — MANDATORY)
    //
    // Backlog item text: "An F-6 regression test: the sweep does NOT
    // release a `Quarantined` artifact with no `ScanCompleted` (no
    // `ScanSucceeded`/`ScanWaived` authority)."
    //
    // The mock releaser models `QuarantineUseCase::release_expired`'s
    // fail-closed behaviour: when no authority is constructible per
    // artifact, the id is dropped from the returned `Vec` (NEVER
    // released). The handler's job is to honour that subset — it must
    // NOT auto-release based on candidacy alone, and the skipped count
    // MUST appear in the result_summary as the F-6 deny-by-default
    // signal.
    // =====================================================================

    #[tokio::test]
    async fn run_fail_closed_does_not_release_unscanned_candidate() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1.clone(), c2.clone()]));
        // Releaser returns the empty set: every candidate fails the
        // F-6 authority check (no ScanCompleted, no scan_backends:[]).
        let releaser = Arc::new(MockReleaser::releases_none());

        let releaser_for_assert = releaser.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 2);
                assert_eq!(
                    result_summary["released"], 0,
                    "F-6 fail-closed: NOTHING released when no authority is constructible",
                );
                assert_eq!(
                    result_summary["skipped_no_authority"], 2,
                    "F-6 fail-closed: skipped-no-authority MUST equal candidates when none release",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // The handler still HANDED the candidates to release_expired
        // — the authority check belongs there, not in the handler.
        // (The handler is a thin orchestration step; defending against
        // a never-passes-to-use-case skip would silently break the F-6
        // contract — the use case is the single source of truth.)
        assert_eq!(
            releaser_for_assert.last_input(),
            vec![c1.artifact_id, c2.artifact_id],
            "handler must hand all candidates to release_expired; F-6 gate \
             is inside release_expired, not in the handler",
        );
    }

    // =====================================================================
    // partial release: 3 candidates, 1 released, 2 skipped → counts split
    // =====================================================================

    #[tokio::test]
    async fn run_mixed_batch_reports_partial_release_split() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![
            c1.clone(),
            c2.clone(),
            c3.clone(),
        ]));
        let releaser = Arc::new(MockReleaser::releases_all_input());
        // Only c2 has authority (e.g. has a ScanCompleted on stream).
        *releaser.released_subset.lock().unwrap() = vec![c2.artifact_id];

        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 3);
                assert_eq!(result_summary["released"], 1);
                assert_eq!(
                    result_summary["skipped_no_authority"], 2,
                    "skipped_no_authority = candidates - released",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // fatal error: select_expired fails → TaskOutcome::Failed { retry:true }
    // =====================================================================

    #[tokio::test]
    async fn run_returns_failed_retry_when_select_expired_errors() {
        let candidates = Arc::new(MockCandidates::new_failing(DomainError::Invariant(
            "simulated select_expired failure".into(),
        )));
        let releaser = Arc::new(MockReleaser::releases_none());

        let releaser_for_assert = releaser.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — select_expired errors are surfaced via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "select_expired failure must retry");
                assert!(
                    reason.contains("select_expired"),
                    "reason should mention select_expired: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(
            releaser_for_assert.last_input().is_empty(),
            "select_expired failure must short-circuit before any release_expired call"
        );
    }

    // =====================================================================
    // fatal error: release_expired fails → TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn run_returns_failed_retry_when_release_expired_errors() {
        let c1 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1]));
        let releaser = Arc::new(MockReleaser::new_failing(DomainError::Invariant(
            "simulated release_expired failure".into(),
        )));

        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — release_expired errors are surfaced via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "release_expired failure must retry");
                assert!(
                    reason.contains("release_expired"),
                    "reason should mention release_expired: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // =====================================================================
    // BATCH_SIZE — handler asks select_expired for exactly 1000
    // =====================================================================

    #[tokio::test]
    async fn run_asks_select_expired_for_exactly_batch_size_1000() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let releaser = Arc::new(MockReleaser::releases_none());

        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, releaser);

        let _ = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        assert_eq!(
            candidates_for_assert.last_batch_size(),
            Some(1000),
            "BATCH_SIZE constant must drive the candidacy LIMIT — handler asks for 1000",
        );
        assert_eq!(BATCH_SIZE, 1000, "design pin: BATCH_SIZE = 1000");
    }
}
