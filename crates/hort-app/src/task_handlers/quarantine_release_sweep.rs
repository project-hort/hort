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
//!    default) and issues one indexed scan per
//!    distinct duration `D`, using the partial index
//!    `idx_artifacts_quarantine_release_cursor ON (release_attempt_at
//!    NULLS FIRST, quarantine_window_start)
//!    WHERE quarantine_status='quarantined'`.
//! 3. Pass the ids to [`QuarantineReleasePort::release_expired`] (the
//!    application-layer `QuarantineUseCase::release_expired`). That
//!    call re-evaluates the
//!    fail-closed release-authority predicate (`ScanSucceeded` /
//!    `ScanWaived`; ADR 0007) per artifact; a window-expired candidate
//!    without a clean scan stays quarantined and falls out of the
//!    summary's `released` list.
//! 4. Stamp the whole candidate batch through
//!    [`QuarantineReleaseCandidatesRepository::mark_attempted`] so the
//!    next tick's candidacy rotates past it (below).
//! 5. Return [`TaskOutcome::Completed`] with a result summary
//!    `{ candidates, released, skipped_no_scan_authority,
//!    skipped_provenance_pending, held_parent_gated }` — the three hold
//!    counts are the deny-by-default observability signal, reported per
//!    cause because each calls for a different operator response: a
//!    scan-authority backlog drains once scanners catch up, a
//!    provenance-pending one resolves per artifact as signatures land
//!    or final verifies decide, and a parent-gated one moves only when
//!    roots get signed (or, in future, via retention) — an unsigned
//!    root's blob constituents hold indefinitely by design (ADR 0039).
//!
//! **Fair candidacy — the attempt cursor.** A candidate the authority or
//! provenance gate permanently holds is never released, so under
//! oldest-first candidacy it never left the head of the selection: once
//! such rows filled a whole [`BATCH_SIZE`] batch, the sweep stopped
//! reaching any other artifact in the deployment and nothing was ever
//! released again, silently. The handler therefore stamps
//! `release_attempt_at` on every candidate it hands to `release_expired`
//! (released ones included — they leave the pool anyway, and excluding
//! them would cost a second statement), and the adapter orders candidacy
//! by that cursor `NULLS FIRST`. Never-attempted artifacts are served
//! first, so a freshly-expired artifact is picked up on the very next
//! tick regardless of backlog size, and a backlog of N is fully
//! re-attempted every `ceil(N / BATCH_SIZE)` ticks.
//!
//! A `mark_attempted` failure is warn-and-continue: the tick's release
//! work already stands, and an unstamped batch merely re-serves next tick
//! — the pre-cursor behaviour, never a wrong release.
//!
//! **Stall signal.** A tick that fills the batch and releases nothing is
//! the saturation signature — the sweep is doing full-batch work with
//! zero progress — and is reported at `warn!` so it is alertable, rather
//! than hiding inside an `info!` line that reads like a normal policy
//! outcome.
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
                    skipped_no_scan_authority = 0_u64,
                    skipped_provenance_pending = 0_u64,
                    held_parent_gated = 0_u64,
                    "quarantine-release-sweep tick complete (no candidates)"
                );
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "candidates": 0,
                        "released": 0,
                        "skipped_no_scan_authority": 0,
                        "skipped_provenance_pending": 0,
                        "held_parent_gated": 0,
                    }),
                });
            }

            let ids: Vec<uuid::Uuid> = candidates.iter().map(|c| c.artifact_id).collect();

            // `ids` is cloned rather than moved so the same batch can be
            // stamped after the release run: the cursor must cover every
            // candidate the tick considered, not just the ones that made
            // it through the gates — that is the whole point of the
            // rotation.
            let summary = match self.release.release_expired(ids.clone()).await {
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

            // Advance the fairness cursor for the batch. Non-gating: the
            // releases above are already committed, and an unstamped
            // batch only means the same rows serve again next tick — the
            // pre-cursor behaviour, never an incorrect release.
            if let Err(err) = self.candidates.mark_attempted(&ids, now).await {
                tracing::warn!(
                    error = %err,
                    candidates = candidate_count,
                    "quarantine-release-sweep: mark_attempted failed; \
                     candidacy cursor not advanced this tick",
                );
            }

            let released_count = summary.released.len();
            // Per-cause counts come from `release_expired` itself. They
            // are NOT a `candidates - released` delta: that delta also
            // swallows candidates the domain source-state guard refused,
            // and it cannot tell the three holds apart — a scan-authority
            // hold drains when scanners catch up, a provenance-pending
            // one resolves per artifact once its signature lands or its
            // final verify decides, and a parent-gated one moves only
            // when roots get signed. Three different operator responses.
            let skipped_no_scan_authority = summary.skipped_no_scan_authority;
            let skipped_provenance_pending = summary.skipped_provenance_pending;
            let held_parent_gated = summary.held_parent_gated;

            // A full batch that released nothing is the saturation
            // signature: the sweep is doing maximum work with zero
            // progress, which under a bounded batch means everything it
            // can currently reach is unreleasable. Alertable at `warn!`
            // — one line per tick at exactly one level, so the stall arm
            // replaces the routine `info!` rather than doubling it.
            if released_count == 0 && candidate_count == BATCH_SIZE as usize {
                tracing::warn!(
                    candidates = candidate_count,
                    released = released_count,
                    skipped_no_scan_authority,
                    skipped_provenance_pending,
                    held_parent_gated,
                    "quarantine-release-sweep: full batch, zero releases — sweep saturated, \
                     nothing releasable this tick",
                );
            } else {
                tracing::info!(
                    candidates = candidate_count,
                    released = released_count,
                    skipped_no_scan_authority,
                    skipped_provenance_pending,
                    held_parent_gated,
                    "quarantine-release-sweep tick complete",
                );
            }

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "candidates": candidate_count,
                    "released": released_count,
                    "skipped_no_scan_authority": skipped_no_scan_authority,
                    "skipped_provenance_pending": skipped_provenance_pending,
                    "held_parent_gated": held_parent_gated,
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
    use hort_domain::ports::quarantine_release::ReleaseExpiredSummary;
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
        /// Ids handed to `mark_attempted`, in call order. `None` until
        /// the first call, so tests can distinguish "not called" from
        /// "called with an empty batch".
        marked: Mutex<Option<Vec<Uuid>>>,
        /// When set, the next `mark_attempted` fails with it — the
        /// warn-and-continue path.
        mark_err: Mutex<Option<DomainError>>,
    }

    impl MockCandidates {
        fn new(rows: Vec<QuarantineReleaseCandidate>) -> Self {
            Self {
                rows: Mutex::new(rows),
                err: Mutex::new(None),
                last_batch_size: Mutex::new(None),
                marked: Mutex::new(None),
                mark_err: Mutex::new(None),
            }
        }

        fn new_failing(err: DomainError) -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                err: Mutex::new(Some(err)),
                last_batch_size: Mutex::new(None),
                marked: Mutex::new(None),
                mark_err: Mutex::new(None),
            }
        }

        fn failing_mark_attempted(rows: Vec<QuarantineReleaseCandidate>, err: DomainError) -> Self {
            let this = Self::new(rows);
            *this.mark_err.lock().unwrap() = Some(err);
            this
        }

        fn last_batch_size(&self) -> Option<u32> {
            *self.last_batch_size.lock().unwrap()
        }

        fn marked(&self) -> Option<Vec<Uuid>> {
            self.marked.lock().unwrap().clone()
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

        fn mark_attempted<'a>(
            &'a self,
            ids: &'a [Uuid],
            _at: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            *self.marked.lock().unwrap() = Some(ids.to_vec());
            let maybe_err = self.mark_err.lock().unwrap().take();
            Box::pin(async move {
                match maybe_err {
                    Some(err) => Err(err),
                    None => Ok(()),
                }
            })
        }
    }

    // ---------- mock QuarantineReleasePort -------------------------------

    /// Releaser mock. `released_subset` controls which ids the port
    /// claims it released (returns a strict subset of input). An
    /// `Internal` failure simulates a non-domain crash (the handler
    /// must surface this as `TaskOutcome::Failed { retry: true }`).
    struct MockReleaser {
        /// Ids the mock pretends to release. Anything in the input not
        /// in this set is "skipped — no authority".
        released_subset: Mutex<Vec<Uuid>>,
        /// Per-cause hold counts the mock reports back:
        /// `(skipped_no_scan_authority, skipped_provenance_pending,
        /// held_parent_gated)`. Programmed independently of
        /// `released_subset` on purpose: the handler must report the
        /// counts the use case gives it, never re-derive them from
        /// `candidates - released`.
        skips: Mutex<(u32, u32, u32)>,
        err: Mutex<Option<DomainError>>,
        last_input: Mutex<Vec<Uuid>>,
    }

    impl MockReleaser {
        fn releases_none() -> Self {
            Self {
                released_subset: Mutex::new(Vec::new()),
                skips: Mutex::new((0, 0, 0)),
                err: Mutex::new(None),
                last_input: Mutex::new(Vec::new()),
            }
        }

        fn releases_all_input() -> Self {
            // Sentinel: the mock returns `input.clone()` — every id is
            // "released". Used by the happy-path test.
            Self {
                released_subset: Mutex::new(Vec::new()), // unused; flag below
                skips: Mutex::new((0, 0, 0)),
                err: Mutex::new(None),
                last_input: Mutex::new(Vec::new()),
            }
        }

        fn new_failing(err: DomainError) -> Self {
            Self {
                released_subset: Mutex::new(Vec::new()),
                skips: Mutex::new((0, 0, 0)),
                err: Mutex::new(Some(err)),
                last_input: Mutex::new(Vec::new()),
            }
        }

        /// Programme the per-cause skip counts the mock reports:
        /// `(skipped_no_scan_authority, skipped_provenance_pending)`.
        /// `held_parent_gated` stays 0 — use [`Self::with_held_parent_gated`]
        /// for tests that need the third bucket populated.
        fn with_skips(self, no_scan_authority: u32, provenance_pending: u32) -> Self {
            let held_parent_gated = self.skips.lock().unwrap().2;
            *self.skips.lock().unwrap() =
                (no_scan_authority, provenance_pending, held_parent_gated);
            self
        }

        /// Programme the `held_parent_gated` count independently of the
        /// other two — the structural-hold bucket the sweep report
        /// carries alongside the two skip counts.
        fn with_held_parent_gated(self, count: u32) -> Self {
            self.skips.lock().unwrap().2 = count;
            self
        }

        fn last_input(&self) -> Vec<Uuid> {
            self.last_input.lock().unwrap().clone()
        }
    }

    impl QuarantineReleasePort for MockReleaser {
        fn release_expired<'a>(
            &'a self,
            artifact_ids: Vec<Uuid>,
        ) -> BoxFuture<'a, DomainResult<ReleaseExpiredSummary>> {
            *self.last_input.lock().unwrap() = artifact_ids.clone();
            let maybe_err = self.err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let subset = self.released_subset.lock().unwrap().clone();
            let (skipped_no_scan_authority, skipped_provenance_pending, held_parent_gated) =
                *self.skips.lock().unwrap();
            // Convention: empty subset means "release nothing" (fail-closed
            // path); otherwise the mock returns the ids that ALSO appear in
            // the input (intersection).
            let released: Vec<Uuid> = if subset.is_empty() {
                Vec::new()
            } else {
                artifact_ids
                    .into_iter()
                    .filter(|id| subset.contains(id))
                    .collect()
            };
            Box::pin(async move {
                Ok(ReleaseExpiredSummary {
                    released,
                    skipped_no_scan_authority,
                    skipped_provenance_pending,
                    held_parent_gated,
                })
            })
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

    // ---------- tracing capture ------------------------------------------
    //
    // The per-tick log line IS the observability contract here (there is
    // no per-tick metric — see the module docs), so the stall signal and
    // the per-cause counts are asserted on the emitted records. Mirrors
    // the capture block in `use_cases/quarantine_use_case.rs`: a global
    // passthrough subscriber is installed once so callsite interest is
    // not cached as "never", then each test layers a thread-local
    // subscriber over it and rebuilds the interest cache.

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        combined: String,
    }

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    fn install_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let subscriber = Registry::default().with(CapturingLayer::default());
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }

    /// Run one tick under a thread-local capturing subscriber and return
    /// the `(level, rendered fields)` records it emitted. Synchronous
    /// (own current-thread runtime) because `set_default` is
    /// thread-scoped — a multi-thread runtime could run the future on a
    /// worker thread the guard does not cover.
    fn capture_tick_logs(handler: &QuarantineReleaseSweepHandler) -> Vec<(tracing::Level, String)> {
        install_passthrough_subscriber();

        let layer = CapturingLayer::default();
        let records = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            handler
                .run(&serde_json::Value::Null, make_context())
                .await
                .expect("Ok");
        });

        let captured = records.lock().unwrap().clone();
        captured
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
        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 0);
                assert_eq!(result_summary["released"], 0);
                assert_eq!(result_summary["skipped_no_scan_authority"], 0);
                assert_eq!(result_summary["skipped_provenance_pending"], 0);
                assert_eq!(result_summary["held_parent_gated"], 0);
                assert!(
                    result_summary.get("skipped_no_authority").is_none(),
                    "the conflated `candidates - released` key is retired; the empty arm \
                     must not resurrect it",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(
            releaser_for_assert.last_input().is_empty(),
            "no candidates → release_expired must NOT be called",
        );
        assert!(
            candidates_for_assert.marked().is_none(),
            "an empty tick has no batch to stamp — mark_attempted must not be called",
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
        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 3);
                assert_eq!(result_summary["released"], 3);
                assert_eq!(result_summary["skipped_no_scan_authority"], 0);
                assert_eq!(result_summary["skipped_provenance_pending"], 0);
                assert_eq!(result_summary["held_parent_gated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // `release_expired` got exactly the candidate ids the SQL
        // returned, in order — the handler does NOT filter, dedupe,
        // or re-order between SQL and use case.
        let input = releaser_for_assert.last_input();
        assert_eq!(input, vec![c1.artifact_id, c2.artifact_id, c3.artifact_id]);
        // Released rows are stamped too: they leave the candidacy pool
        // anyway, and excluding them would buy nothing but a second
        // statement.
        assert_eq!(
            candidates_for_assert.marked(),
            Some(vec![c1.artifact_id, c2.artifact_id, c3.artifact_id]),
            "the cursor is advanced for the WHOLE batch, released rows included",
        );
    }

    // =====================================================================
    // Fail-closed regression (MANDATORY)
    //
    // The sweep does NOT release a `Quarantined` artifact with no
    // `ScanCompleted` (no `ScanSucceeded`/`ScanWaived` authority).
    //
    // The mock releaser models `QuarantineUseCase::release_expired`'s
    // fail-closed behaviour: when no authority is constructible per
    // artifact, the id is dropped from the returned `Vec` (NEVER
    // released). The handler's job is to honour that subset — it must
    // NOT auto-release based on candidacy alone, and the skipped count
    // MUST appear in the result_summary as the deny-by-default signal.
    // =====================================================================

    #[tokio::test]
    async fn run_fail_closed_does_not_release_unscanned_candidate() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1.clone(), c2.clone()]));
        // Releaser returns the empty set: every candidate fails the
        // authority check (no ScanCompleted, no scan_backends:[]).
        let releaser = Arc::new(MockReleaser::releases_none().with_skips(2, 0));

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
                    "fail-closed: NOTHING released when no authority is constructible",
                );
                assert_eq!(
                    result_summary["skipped_no_scan_authority"], 2,
                    "fail-closed: the authority skip MUST account for every candidate when \
                     none release",
                );
                assert_eq!(result_summary["skipped_provenance_pending"], 0);
                assert_eq!(result_summary["held_parent_gated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // The handler still HANDED the candidates to release_expired
        // — the authority check belongs there, not in the handler.
        // (The handler is a thin orchestration step; defending against
        // a never-passes-to-use-case skip would silently break the
        // fail-closed contract — the use case is the single source of truth.)
        assert_eq!(
            releaser_for_assert.last_input(),
            vec![c1.artifact_id, c2.artifact_id],
            "handler must hand all candidates to release_expired; the gate \
             is inside release_expired, not in the handler",
        );
    }

    // =====================================================================
    // partial release: 3 candidates, 1 released, 2 skipped → counts split
    // per cause, straight from the use case (never re-derived)
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
        // Only c2 has authority (e.g. has a ScanCompleted on stream);
        // of the other two, one lacks scan authority and one is held by
        // an unresolved provenance clearance.
        let releaser = Arc::new(MockReleaser::releases_all_input().with_skips(1, 1));
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
                assert_eq!(result_summary["skipped_no_scan_authority"], 1);
                assert_eq!(result_summary["skipped_provenance_pending"], 1);
                assert_eq!(result_summary["held_parent_gated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // three-way mixed batch: one of each hold plus a release → all three
    // counters surface independently, straight from the use case.
    // =====================================================================

    #[tokio::test]
    async fn run_mixed_batch_reports_all_three_hold_counts_independently() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let c4 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![
            c1.clone(),
            c2.clone(),
            c3.clone(),
            c4.clone(),
        ]));
        // c1 releases; c2 lacks scan authority; c3 is an actionable
        // pending provenance hold; c4 is a structural parent-gated hold.
        let releaser = Arc::new(
            MockReleaser::releases_all_input()
                .with_skips(1, 1)
                .with_held_parent_gated(1),
        );
        *releaser.released_subset.lock().unwrap() = vec![c1.artifact_id];

        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 4);
                assert_eq!(result_summary["released"], 1);
                assert_eq!(result_summary["skipped_no_scan_authority"], 1);
                assert_eq!(result_summary["skipped_provenance_pending"], 1);
                assert_eq!(
                    result_summary["held_parent_gated"], 1,
                    "the structural parent-gated hold must surface as its own bucket, \
                     distinct from the actionable pending count",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // The counts are REPORTED, not re-derived. A summary whose skip
    // counts do not sum to `candidates - released` (the domain
    // source-state guard refuses a candidate without counting it as
    // held) must surface verbatim — reconstructing the old
    // `candidates - released` delta would silently re-fabricate the
    // conflated number this split replaces.
    // =====================================================================

    #[tokio::test]
    async fn run_reports_use_case_skip_counts_verbatim_without_rederiving() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let c4 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![
            c1.clone(),
            c2.clone(),
            c3.clone(),
            c4.clone(),
        ]));
        // 4 candidates, 0 released, but only TWO were actually held —
        // the other two hit the not-in-releasable-state arm, which is
        // not a hold at all.
        let releaser = Arc::new(
            MockReleaser::releases_none()
                .with_skips(0, 1)
                .with_held_parent_gated(1),
        );

        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 4);
                assert_eq!(result_summary["released"], 0);
                assert_eq!(
                    result_summary["skipped_no_scan_authority"], 0,
                    "the handler must NOT back-fill a skip count from candidates - released",
                );
                assert_eq!(result_summary["skipped_provenance_pending"], 1);
                assert_eq!(
                    result_summary["held_parent_gated"], 1,
                    "the handler must NOT back-fill the structural-hold count either",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Fairness cursor: the batch is stamped even when nothing releases —
    // that is precisely the case the rotation exists for.
    // =====================================================================

    #[tokio::test]
    async fn run_marks_attempted_for_all_candidates_when_none_release() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1.clone(), c2.clone()]));
        let releaser = Arc::new(MockReleaser::releases_none().with_skips(2, 0));

        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));

        assert_eq!(
            candidates_for_assert.marked(),
            Some(vec![c1.artifact_id, c2.artifact_id]),
            "an all-skipped batch MUST still advance the cursor — otherwise the same \
             unreleasable rows occupy the batch head forever and starve the backlog",
        );
    }

    // =====================================================================
    // `mark_attempted` failure is warn-and-continue: the tick's release
    // work already stands, and an unstamped batch only re-serves next
    // tick (the pre-cursor behaviour).
    // =====================================================================

    #[tokio::test]
    async fn run_completes_when_mark_attempted_fails() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::failing_mark_attempted(
            vec![c1.clone(), c2.clone()],
            DomainError::Invariant("simulated mark_attempted failure".into()),
        ));
        let releaser = Arc::new(MockReleaser::releases_all_input());
        *releaser.released_subset.lock().unwrap() = vec![c1.artifact_id];

        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, releaser);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["released"], 1,
                    "a cursor-stamp failure must not retract the tick's release work",
                );
                assert_eq!(result_summary["candidates"], 2);
            }
            other => panic!("expected Completed despite mark_attempted failure, got {other:?}"),
        }
        assert!(
            candidates_for_assert.marked().is_some(),
            "the handler must have attempted the stamp before swallowing its failure",
        );
    }

    // =====================================================================
    // Stall signal: full batch + zero releases ⇒ `warn!` carrying both
    // per-cause counts. Anything less than a full batch, or any release
    // at all, stays at `info!`.
    // =====================================================================

    /// Build a full `BATCH_SIZE`-sized candidate list.
    fn full_batch() -> Vec<QuarantineReleaseCandidate> {
        (0..BATCH_SIZE).map(|_| make_candidate()).collect()
    }

    #[test]
    fn run_full_batch_with_zero_releases_emits_stall_warn() {
        // The production shape this split exists for: of a full 1000
        // candidate batch, most (964) are structurally held — nothing
        // short of signing their roots moves them — and the remainder
        // splits across the two actionable buckets.
        let rows = full_batch();
        let candidates = Arc::new(MockCandidates::new(rows));
        let releaser = Arc::new(
            MockReleaser::releases_none()
                .with_skips(30, 6)
                .with_held_parent_gated(964),
        );

        let handler = make_handler(candidates, releaser);
        let records = capture_tick_logs(&handler);

        let warn = records
            .iter()
            .find(|(lvl, _)| *lvl == tracing::Level::WARN)
            .map(|(_, msg)| msg.clone())
            .unwrap_or_else(|| panic!("expected a stall warn!; saw {records:?}"));
        assert!(
            warn.contains(
                "quarantine-release-sweep: full batch, zero releases — sweep saturated, \
                 nothing releasable this tick"
            ),
            "stall warn must carry the alertable message; saw {warn}",
        );
        assert!(
            warn.contains("skipped_no_scan_authority=30")
                && warn.contains("skipped_provenance_pending=6")
                && warn.contains("held_parent_gated=964"),
            "stall warn must carry ALL THREE per-cause counts — they are what tells the \
             operator which backlog is holding the sweep, and the structural one is what \
             makes the stall readable rather than alarming; saw {warn}",
        );
        assert!(
            !records.iter().any(|(lvl, _)| *lvl == tracing::Level::INFO),
            "the stall arm replaces the routine info! line, it does not double it; \
             saw {records:?}",
        );
    }

    #[test]
    fn run_full_batch_with_one_release_does_not_warn() {
        let rows = full_batch();
        let first = rows[0].artifact_id;
        let candidates = Arc::new(MockCandidates::new(rows));
        let releaser = Arc::new(MockReleaser::releases_all_input().with_skips(999, 0));
        *releaser.released_subset.lock().unwrap() = vec![first];

        let handler = make_handler(candidates, releaser);
        let records = capture_tick_logs(&handler);

        assert!(
            !records.iter().any(|(lvl, _)| *lvl == tracing::Level::WARN),
            "a full batch that released something is progress, not saturation; saw {records:?}",
        );
        assert!(
            records.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                && msg.contains("quarantine-release-sweep tick complete")),
            "the routine info! line must still be emitted; saw {records:?}",
        );
    }

    #[test]
    fn run_partial_batch_with_zero_releases_does_not_warn() {
        let candidates = Arc::new(MockCandidates::new(vec![make_candidate()]));
        let releaser = Arc::new(MockReleaser::releases_none().with_skips(1, 0));

        let handler = make_handler(candidates, releaser);
        let records = capture_tick_logs(&handler);

        assert!(
            !records.iter().any(|(lvl, _)| *lvl == tracing::Level::WARN),
            "under-full batch: the sweep reached everything it could, so a zero-release \
             tick is an ordinary policy outcome, not saturation; saw {records:?}",
        );
        assert!(
            records.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                && msg.contains("quarantine-release-sweep tick complete")),
            "the routine info! line must still be emitted; saw {records:?}",
        );
    }

    #[test]
    fn run_tick_complete_log_drops_the_retired_conflated_key() {
        let candidates = Arc::new(MockCandidates::new(vec![make_candidate()]));
        let releaser = Arc::new(
            MockReleaser::releases_none()
                .with_skips(1, 0)
                .with_held_parent_gated(0),
        );

        let handler = make_handler(candidates, releaser);
        let records = capture_tick_logs(&handler);

        assert!(
            !records
                .iter()
                .any(|(_, msg)| msg.contains("skipped_no_authority=")),
            "the fabricated candidates-minus-released field is retired from the log \
             line too; saw {records:?}",
        );
        assert!(
            records
                .iter()
                .any(|(_, msg)| msg.contains("skipped_no_scan_authority=1")
                    && msg.contains("skipped_provenance_pending=0")
                    && msg.contains("held_parent_gated=0")),
            "the tick line must carry all three true per-cause counts; saw {records:?}",
        );
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
