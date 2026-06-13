//! `RepoSecurityScoreProjector` — the materialised per-repository
//! security-score projection (see
//! `docs/architecture/explanation/scanning-pipeline.md`).
//!
//! Computes [`ScoreDelta`] values for the `repo_security_scores`
//! projection from artifact lifecycle transitions and bundles them
//! through the lifecycle port so the projection upsert lands in the
//! same Postgres transaction as the originating event append.
//!
//! All transition computations are pure functions of `(prior_status,
//! new_status, severity_summary?, scan_completed_at?)`. The tests in
//! this module cover every transition and the underflow edge.
//!
//! The struct itself wraps an `Arc<dyn RepoSecurityScoreRepository>`
//! and exposes [`apply`](RepoSecurityScoreProjector::apply) — a
//! direct (non-tx) read-modify-write path used by code that doesn't
//! flow through the lifecycle port. The lifecycle dual-write path
//! does NOT call `apply`; it threads the delta into
//! `commit_transition_with_score` / `commit_scan_result_with_score`
//! and the Postgres adapter applies the delta inside the existing
//! transaction.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::events::SeveritySummary;
use hort_domain::ports::repo_security_score_repository::{
    RepoSecurityScore, RepoSecurityScoreRepository, ScoreDelta,
};

use crate::error::{AppError, AppResult};

/// Projector that owns the `repo_security_scores` projection.
///
/// In the v1 lifecycle dual-write path the projector is a pure
/// delta-calculation helper — the wrapped repository handle exists for
/// the [`apply`] direct path used by reconciliation and tests. The
/// lifecycle adapter applies deltas inside its own tx; see the module
/// docstring.
pub struct RepoSecurityScoreProjector {
    repo: Arc<dyn RepoSecurityScoreRepository>,
}

impl RepoSecurityScoreProjector {
    pub fn new(repo: Arc<dyn RepoSecurityScoreRepository>) -> Self {
        Self { repo }
    }

    /// Pure delta for the outcome of `record_scan_result`.
    ///
    /// Severity counts are bumped from the scan's `severity_summary`
    /// (negligible is dropped — the projection table has no
    /// `negligible_count` column). `last_scan_at` is set to
    /// `scan_completed_at`. The status delta depends on how the scan
    /// transitioned the artifact:
    ///
    /// - `Quarantined → Quarantined` (clean scan or pre-existing
    ///   findings that didn't escalate) — no status delta.
    /// - `Quarantined → Rejected` (the policy reject path) —
    ///   quarantined_count -1, rejected_count +1.
    /// - other transitions — status delta is `(prior, new)` mapped via
    ///   [`Self::status_delta`].
    ///
    /// # Single-shot caller contract — required for soundness
    ///
    /// **This function is single-shot per `(repository_id, artifact_id)`.**
    /// The severity-count terms below are *full per-tier counts*,
    /// added to the projection unconditionally. The arithmetic is
    /// sound only when no prior scan's severity contribution is
    /// already included in the projection row for the same artifact.
    ///
    /// The contract is enforced by the **caller** (see
    /// [`crate::use_cases::QuarantineUseCase::record_scan_result`]),
    /// not by this function. The function takes only
    /// `(prior_status, new_status, severity_summary, scan_completed_at)`
    /// — there is no `scan_id` or `artifact_id` parameter, and the
    /// type is `Copy`-able with no internal state, so the projector
    /// itself cannot detect a duplicate invocation. Calling this
    /// function twice for the same artifact (re-ingest, manual
    /// rescan, retry of a partially-applied scan) silently accumulates
    /// severity counts: an artifact with 3 criticals will land
    /// `critical_count` at 3 → 6 → 9 across three calls, not the
    /// invariant 3 → 3 → 3.
    ///
    /// The original producer pipeline protected this contract
    /// because it scanned every artifact **exactly once**, on
    /// `ArtifactIngested`, and the lifecycle dual-write commits the
    /// projection delta in the same Postgres transaction as the
    /// `ScanCompleted` event append.
    ///
    /// # OPEN — replacement-delta semantics own this function's evolution
    ///
    /// The rescan pipeline (cron rescan + advisory watch + manual
    /// rescan) scans
    /// the same artifact a second time (and a third, …). That
    /// breaks the single-shot contract above, and this
    /// function (or its replacement) MUST compute a **replacement
    /// delta**:
    ///
    /// - read the prior scan's per-tier severity counts (e.g. from a
    ///   denormalised column on `artifacts` written in the same tx as
    ///   the prior `ScanCompleted` append, or from the latest
    ///   `scan_findings` projection row),
    /// - subtract them from the projection,
    /// - then add the new scan's counts.
    ///
    /// The witness test
    /// `compute_scan_completed_delta_is_purely_additive_rescan_tripwire`
    /// asserts the current additive behaviour and is intended to fail
    /// (and be rewritten) when the replacement-delta
    /// path lands. Do **not** extend this function with an ad-hoc
    /// second-scan code path — the change should
    /// almost certainly take a new function signature that accepts
    /// the prior `severity_summary` (or a richer `ScanContext`).
    pub fn compute_scan_completed_delta(
        prior_status: QuarantineStatus,
        new_status: QuarantineStatus,
        severity_summary: &SeveritySummary,
        scan_completed_at: DateTime<Utc>,
    ) -> ScoreDelta {
        let mut d = Self::status_delta(prior_status, new_status);
        // Single-shot per (repository_id, artifact_id) — see the
        // "Single-shot caller contract" section in the rustdoc above.
        // The terms below are full per-tier counts added to the
        // projection. The open replacement-delta evolution (see the
        // rustdoc above): when rescanning lands
        // the same artifact twice, the function must subtract the
        // prior scan's counts before adding the new scan's counts, or
        // the projection accumulates double / triple counts.
        d.critical_delta = i32::try_from(severity_summary.critical).unwrap_or(i32::MAX);
        d.high_delta = i32::try_from(severity_summary.high).unwrap_or(i32::MAX);
        d.medium_delta = i32::try_from(severity_summary.medium).unwrap_or(i32::MAX);
        d.low_delta = i32::try_from(severity_summary.low).unwrap_or(i32::MAX);
        d.last_scan_at = Some(scan_completed_at);
        d
    }

    /// Pure delta for a release transition (admin or sweep).
    ///
    /// Maps the prior status to the released-bucket bump:
    /// - `Quarantined → Released` — quarantined_count -1, released_count +1.
    /// - `Rejected → Released` — rejected_count -1, released_count +1.
    /// - any other prior — no change (defensive — the use case checks
    ///   the state machine, but the projector clamps for safety).
    pub fn compute_released_delta(prior_status: QuarantineStatus) -> ScoreDelta {
        Self::status_delta(prior_status, QuarantineStatus::Released)
    }

    /// Pure delta for a quarantine transition.
    ///
    /// `None → Quarantined` — quarantined_count +1.
    /// Other priors are no-ops; the entity state machine forbids them.
    pub fn compute_quarantined_delta() -> ScoreDelta {
        Self::status_delta(QuarantineStatus::None, QuarantineStatus::Quarantined)
    }

    /// Pure delta for a re-evaluation transition (the
    /// `add_exclusion` post-projection sweep). The artifact moves
    /// between `Rejected` and `Quarantined` / `Released` after an
    /// exclusion lands; the projector translates the pair into the
    /// matching count bumps.
    pub fn compute_re_evaluated_delta(
        prior_status: QuarantineStatus,
        new_status: QuarantineStatus,
    ) -> ScoreDelta {
        Self::status_delta(prior_status, new_status)
    }

    /// Pure delta for the terminal scan-failure
    /// transition (`Quarantined`/`None` → `ScanIndeterminate`).
    ///
    /// `ScanIndeterminate` is a *distinct* terminal state that the
    /// three-bucket `repo_security_scores` projection does not model
    /// (adding a fourth bucket is out of scope for Item 5 — it would
    /// need a migration + a score-doc change). It is therefore treated
    /// as un-tracked, exactly like [`QuarantineStatus::None`]: a
    /// `Quarantined → ScanIndeterminate` transition decrements
    /// `quarantined_count` and increments nothing (the artifact is no
    /// longer quarantined and is neither rejected nor released); a
    /// `None → ScanIndeterminate` transition is a projection no-op.
    pub fn compute_scan_indeterminate_delta(prior_status: QuarantineStatus) -> ScoreDelta {
        Self::status_delta(prior_status, QuarantineStatus::ScanIndeterminate)
    }

    /// Translate a `(prior, new)` status pair into the corresponding
    /// per-bucket delta. Status values that are not tracked in the
    /// projection (`QuarantineStatus::None`) cause no decrement —
    /// only Quarantined / Rejected / Released contribute. The same
    /// rule applies to the `new` side so a no-op transition produces
    /// `ScoreDelta::default()`.
    fn status_delta(prior: QuarantineStatus, new: QuarantineStatus) -> ScoreDelta {
        let mut d = ScoreDelta::default();
        if prior == new {
            return d;
        }
        match prior {
            QuarantineStatus::Quarantined => d.quarantined_delta -= 1,
            QuarantineStatus::Rejected => d.rejected_delta -= 1,
            QuarantineStatus::Released => d.released_delta -= 1,
            // ScanIndeterminate is a distinct terminal
            // state not modelled by the three-bucket projection;
            // treated as un-tracked exactly like None (no decrement).
            QuarantineStatus::None | QuarantineStatus::ScanIndeterminate => {}
        }
        match new {
            QuarantineStatus::Quarantined => d.quarantined_delta += 1,
            QuarantineStatus::Rejected => d.rejected_delta += 1,
            QuarantineStatus::Released => d.released_delta += 1,
            QuarantineStatus::None | QuarantineStatus::ScanIndeterminate => {}
        }
        d
    }

    /// Apply a delta to the projection by reading the row, computing
    /// the new values, and upserting. Counts are clamped at zero
    /// (subtracting from a zero column stays at zero).
    ///
    /// **Direct-path only.** The lifecycle dual-write path does NOT
    /// call this method — it threads the delta into the lifecycle
    /// port so the upsert lands inside the existing tx. `apply` is
    /// retained for reconciliation tasks and the test suite.
    pub async fn apply(&self, repo_id: Uuid, delta: &ScoreDelta) -> AppResult<()> {
        if delta.is_noop() {
            return Ok(());
        }
        let now = Utc::now();
        let existing = self.repo.find(repo_id).await.map_err(AppError::Domain)?;
        let next = match existing {
            Some(row) => apply_delta_to_row(&row, delta, now),
            None => apply_delta_to_zero(repo_id, delta, now),
        };
        self.repo.upsert(&next).await.map_err(AppError::Domain)?;
        Ok(())
    }
}

/// Saturating-add an `i32` delta to a `u32` count. Negative deltas
/// that exceed the count clamp at zero. Positive overflow is also
/// clamped (defence-in-depth — counts are bounded by artifact volume,
/// which never approaches `u32::MAX` in practice).
fn saturating_apply(count: u32, delta: i32) -> u32 {
    if delta >= 0 {
        count.saturating_add(delta.unsigned_abs())
    } else {
        count.saturating_sub(delta.unsigned_abs())
    }
}

/// Apply a delta to an existing row.
fn apply_delta_to_row(
    row: &RepoSecurityScore,
    delta: &ScoreDelta,
    now: DateTime<Utc>,
) -> RepoSecurityScore {
    RepoSecurityScore {
        repository_id: row.repository_id,
        quarantined_count: saturating_apply(row.quarantined_count, delta.quarantined_delta),
        rejected_count: saturating_apply(row.rejected_count, delta.rejected_delta),
        released_count: saturating_apply(row.released_count, delta.released_delta),
        critical_count: saturating_apply(row.critical_count, delta.critical_delta),
        high_count: saturating_apply(row.high_count, delta.high_delta),
        medium_count: saturating_apply(row.medium_count, delta.medium_delta),
        low_count: saturating_apply(row.low_count, delta.low_delta),
        last_scan_at: delta.last_scan_at.or(row.last_scan_at),
        updated_at: now,
    }
}

/// Apply a delta against a non-existent row (treat as zero counts).
fn apply_delta_to_zero(repo_id: Uuid, delta: &ScoreDelta, now: DateTime<Utc>) -> RepoSecurityScore {
    RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: saturating_apply(0, delta.quarantined_delta),
        rejected_count: saturating_apply(0, delta.rejected_delta),
        released_count: saturating_apply(0, delta.released_delta),
        critical_count: saturating_apply(0, delta.critical_delta),
        high_count: saturating_apply(0, delta.high_delta),
        medium_count: saturating_apply(0, delta.medium_delta),
        low_count: saturating_apply(0, delta.low_delta),
        last_scan_at: delta.last_scan_at,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::error::DomainResult;
    use hort_domain::ports::BoxFuture;
    use std::sync::Mutex;

    fn ts(unix: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(unix, 0).unwrap()
    }

    fn summary(critical: u32, high: u32, medium: u32, low: u32) -> SeveritySummary {
        SeveritySummary {
            critical,
            high,
            medium,
            low,
            negligible: 0,
        }
    }

    // -- pure delta computations ---------------------------------------------

    #[test]
    fn scan_completed_clean_quarantined_to_quarantined_only_severity_and_last_scan() {
        let d = RepoSecurityScoreProjector::compute_scan_completed_delta(
            QuarantineStatus::Quarantined,
            QuarantineStatus::Quarantined,
            &summary(0, 0, 0, 0),
            ts(100),
        );
        assert_eq!(d.quarantined_delta, 0);
        assert_eq!(d.rejected_delta, 0);
        assert_eq!(d.released_delta, 0);
        assert_eq!(d.critical_delta, 0);
        assert_eq!(d.high_delta, 0);
        assert_eq!(d.medium_delta, 0);
        assert_eq!(d.low_delta, 0);
        assert_eq!(d.last_scan_at, Some(ts(100)));
    }

    #[test]
    fn scan_completed_clean_with_findings_bumps_severity_counts() {
        let d = RepoSecurityScoreProjector::compute_scan_completed_delta(
            QuarantineStatus::Quarantined,
            QuarantineStatus::Quarantined,
            &summary(2, 3, 4, 5),
            ts(200),
        );
        assert_eq!(d.critical_delta, 2);
        assert_eq!(d.high_delta, 3);
        assert_eq!(d.medium_delta, 4);
        assert_eq!(d.low_delta, 5);
        assert_eq!(d.last_scan_at, Some(ts(200)));
        // No status transition.
        assert_eq!(d.quarantined_delta, 0);
        assert_eq!(d.rejected_delta, 0);
        assert_eq!(d.released_delta, 0);
    }

    /// Rescan tripwire — single-shot caller contract.
    ///
    /// `compute_scan_completed_delta` takes only `(prior_status,
    /// new_status, severity_summary, scan_completed_at)` and is
    /// purely additive: severity counts from the supplied summary are
    /// added to the projection unconditionally, with no scan_id or
    /// artifact_id state to detect a duplicate invocation. The
    /// single-shot contract — "called exactly once per
    /// (repository_id, artifact_id)" — is therefore the **caller's**
    /// responsibility, originally enforced by the producer pipeline
    /// scanning every artifact exactly once on `ArtifactIngested`.
    ///
    /// This test witnesses the additive behaviour: invoking the
    /// function twice with identical inputs and applying both deltas
    /// against a zero baseline accumulates the severity counts
    /// (3 → 6, not 3 → 3). When the
    /// replacement-delta path lands, this test MUST fail —
    /// either because the function's signature changes to accept the
    /// prior scan's counts (replacement-delta), or because a new
    /// rescan-aware variant supersedes it. The test exists to force
    /// the rewrite at that moment rather than letting the additive
    /// behaviour silently double-count in production.
    #[test]
    fn compute_scan_completed_delta_is_purely_additive_rescan_tripwire() {
        let sev = summary(3, 0, 0, 0);

        // Two consecutive calls with the same severity input return
        // bit-identical deltas — the function is a pure function of
        // its inputs. That is fine in isolation; the bug surfaces
        // when both deltas are applied to the same projection row.
        let first = RepoSecurityScoreProjector::compute_scan_completed_delta(
            QuarantineStatus::Quarantined,
            QuarantineStatus::Quarantined,
            &sev,
            ts(100),
        );
        let second = RepoSecurityScoreProjector::compute_scan_completed_delta(
            QuarantineStatus::Quarantined,
            QuarantineStatus::Quarantined,
            &sev,
            ts(200),
        );
        assert_eq!(first.critical_delta, 3);
        assert_eq!(second.critical_delta, 3);

        // Apply both deltas in sequence, as the lifecycle adapter
        // would if record_scan_result were (incorrectly) invoked
        // twice for the same artifact. The second call accumulates
        // on top of the first because there is no replacement-delta
        // step; this is the behaviour the replacement-delta evolution
        // must replace.
        let id = Uuid::new_v4();
        let after_first = apply_delta_to_zero(id, &first, ts(0));
        let after_second = apply_delta_to_row(&after_first, &second, ts(0));

        assert_eq!(
            after_first.critical_count, 3,
            "first invocation seeds critical_count from the severity summary"
        );
        assert_eq!(
            after_second.critical_count, 6,
            "second invocation accumulates additively (3 + 3 = 6) — \
             this witnesses the single-shot caller contract documented \
             on compute_scan_completed_delta. The rescan pipeline \
             MUST replace this function with a replacement-delta path — \
             see the rustdoc on compute_scan_completed_delta"
        );
        // last_scan_at advances to the most recent applied delta —
        // that part already behaves correctly across rescans.
        assert_eq!(after_second.last_scan_at, Some(ts(200)));
    }

    #[test]
    fn scan_completed_quarantined_to_rejected_decrements_quarantined_increments_rejected() {
        let d = RepoSecurityScoreProjector::compute_scan_completed_delta(
            QuarantineStatus::Quarantined,
            QuarantineStatus::Rejected,
            &summary(1, 0, 0, 0),
            ts(300),
        );
        assert_eq!(d.quarantined_delta, -1);
        assert_eq!(d.rejected_delta, 1);
        assert_eq!(d.released_delta, 0);
        assert_eq!(d.critical_delta, 1);
        assert_eq!(d.last_scan_at, Some(ts(300)));
    }

    #[test]
    fn release_quarantined_to_released_swaps_buckets() {
        let d = RepoSecurityScoreProjector::compute_released_delta(QuarantineStatus::Quarantined);
        assert_eq!(d.quarantined_delta, -1);
        assert_eq!(d.released_delta, 1);
        assert_eq!(d.rejected_delta, 0);
        assert_eq!(d.last_scan_at, None);
    }

    #[test]
    fn release_rejected_to_released_swaps_buckets() {
        let d = RepoSecurityScoreProjector::compute_released_delta(QuarantineStatus::Rejected);
        assert_eq!(d.rejected_delta, -1);
        assert_eq!(d.released_delta, 1);
        assert_eq!(d.quarantined_delta, 0);
    }

    #[test]
    fn release_from_already_released_is_noop() {
        let d = RepoSecurityScoreProjector::compute_released_delta(QuarantineStatus::Released);
        assert!(d.is_noop());
    }

    #[test]
    fn release_from_none_increments_only_released_bucket() {
        // The entity state machine forbids None→Released, so this
        // branch is unreachable in production. The projector treats
        // `None` as "no prior bucket to decrement" and only bumps the
        // new bucket. The use case is responsible for never invoking
        // the projector on a forbidden transition.
        let d = RepoSecurityScoreProjector::compute_released_delta(QuarantineStatus::None);
        assert_eq!(d.released_delta, 1);
        assert_eq!(d.quarantined_delta, 0);
        assert_eq!(d.rejected_delta, 0);
    }

    #[test]
    fn quarantine_increments_quarantined() {
        let d = RepoSecurityScoreProjector::compute_quarantined_delta();
        assert_eq!(d.quarantined_delta, 1);
        assert_eq!(d.rejected_delta, 0);
        assert_eq!(d.released_delta, 0);
        assert_eq!(d.last_scan_at, None);
    }

    #[test]
    fn re_eval_rejected_to_quarantined_swaps_buckets() {
        let d = RepoSecurityScoreProjector::compute_re_evaluated_delta(
            QuarantineStatus::Rejected,
            QuarantineStatus::Quarantined,
        );
        assert_eq!(d.rejected_delta, -1);
        assert_eq!(d.quarantined_delta, 1);
    }

    #[test]
    fn re_eval_rejected_to_released_swaps_buckets() {
        let d = RepoSecurityScoreProjector::compute_re_evaluated_delta(
            QuarantineStatus::Rejected,
            QuarantineStatus::Released,
        );
        assert_eq!(d.rejected_delta, -1);
        assert_eq!(d.released_delta, 1);
    }

    #[test]
    fn re_eval_same_status_is_noop() {
        let d = RepoSecurityScoreProjector::compute_re_evaluated_delta(
            QuarantineStatus::Rejected,
            QuarantineStatus::Rejected,
        );
        assert!(d.is_noop());
    }

    // -- saturating_apply / underflow ----------------------------------------

    #[test]
    fn saturating_apply_positive_delta_adds() {
        assert_eq!(saturating_apply(3, 4), 7);
    }

    #[test]
    fn saturating_apply_negative_delta_subtracts() {
        assert_eq!(saturating_apply(5, -2), 3);
    }

    #[test]
    fn saturating_apply_negative_delta_underflow_clamps_at_zero() {
        // Subtracting more than the current count stays at zero rather
        // than wrapping around — saturation invariant.
        assert_eq!(saturating_apply(0, -1), 0);
        assert_eq!(saturating_apply(2, -10), 0);
    }

    #[test]
    fn saturating_apply_positive_overflow_clamps_at_max() {
        // u32::MAX + 1 stays at u32::MAX (defence-in-depth).
        assert_eq!(saturating_apply(u32::MAX, 1), u32::MAX);
    }

    #[test]
    fn apply_delta_to_zero_negative_status_delta_clamps() {
        let d = ScoreDelta {
            released_delta: -1,
            ..ScoreDelta::default()
        };
        let row = apply_delta_to_zero(Uuid::nil(), &d, ts(0));
        assert_eq!(row.released_count, 0);
        assert_eq!(row.quarantined_count, 0);
        assert_eq!(row.rejected_count, 0);
    }

    // -- apply (direct path) -------------------------------------------------

    /// Mock repository that records `upsert` calls and serves a seeded
    /// row from `find`.
    struct MockScoreRepo {
        seeded: Mutex<Option<RepoSecurityScore>>,
        upserts: Mutex<Vec<RepoSecurityScore>>,
    }
    impl MockScoreRepo {
        fn new() -> Self {
            Self {
                seeded: Mutex::new(None),
                upserts: Mutex::new(Vec::new()),
            }
        }
        fn seed(&self, row: RepoSecurityScore) {
            *self.seeded.lock().unwrap() = Some(row);
        }
    }
    impl RepoSecurityScoreRepository for MockScoreRepo {
        fn upsert<'a>(&'a self, score: &'a RepoSecurityScore) -> BoxFuture<'a, DomainResult<()>> {
            let cloned = score.clone();
            Box::pin(async move {
                self.upserts.lock().unwrap().push(cloned);
                Ok(())
            })
        }
        fn find(&self, _repo_id: Uuid) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
            let v = self.seeded.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn apply_noop_delta_does_not_upsert() {
        let repo = Arc::new(MockScoreRepo::new());
        let projector = RepoSecurityScoreProjector::new(repo.clone());
        projector
            .apply(Uuid::new_v4(), &ScoreDelta::default())
            .await
            .unwrap();
        assert!(repo.upserts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_to_missing_row_seeds_with_clamped_zero_baseline() {
        let repo = Arc::new(MockScoreRepo::new());
        let projector = RepoSecurityScoreProjector::new(repo.clone());
        let id = Uuid::new_v4();
        let d = ScoreDelta {
            quarantined_delta: 1,
            critical_delta: 2,
            ..ScoreDelta::default()
        };
        projector.apply(id, &d).await.unwrap();
        let upserts = repo.upserts.lock().unwrap().clone();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].quarantined_count, 1);
        assert_eq!(upserts[0].critical_count, 2);
        assert_eq!(upserts[0].released_count, 0);
        assert_eq!(upserts[0].repository_id, id);
    }

    #[tokio::test]
    async fn apply_to_existing_row_adds_delta_and_clamps_underflow() {
        let id = Uuid::new_v4();
        let repo = Arc::new(MockScoreRepo::new());
        repo.seed(RepoSecurityScore {
            repository_id: id,
            quarantined_count: 0, // about to underflow
            rejected_count: 5,
            released_count: 1,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            last_scan_at: None,
            updated_at: ts(0),
        });
        let projector = RepoSecurityScoreProjector::new(repo.clone());
        let d = ScoreDelta {
            quarantined_delta: -1, // would underflow → 0
            rejected_delta: -1,    // 5 → 4
            released_delta: 1,     // 1 → 2
            ..ScoreDelta::default()
        };
        projector.apply(id, &d).await.unwrap();
        let upserts = repo.upserts.lock().unwrap().clone();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].quarantined_count, 0);
        assert_eq!(upserts[0].rejected_count, 4);
        assert_eq!(upserts[0].released_count, 2);
    }

    #[tokio::test]
    async fn apply_propagates_last_scan_at_when_set() {
        let id = Uuid::new_v4();
        let repo = Arc::new(MockScoreRepo::new());
        let projector = RepoSecurityScoreProjector::new(repo.clone());
        let d = ScoreDelta {
            critical_delta: 1,
            last_scan_at: Some(ts(500)),
            ..ScoreDelta::default()
        };
        projector.apply(id, &d).await.unwrap();
        let upserts = repo.upserts.lock().unwrap().clone();
        assert_eq!(upserts[0].last_scan_at, Some(ts(500)));
    }

    #[tokio::test]
    async fn apply_preserves_existing_last_scan_at_when_delta_carries_none() {
        let id = Uuid::new_v4();
        let repo = Arc::new(MockScoreRepo::new());
        repo.seed(RepoSecurityScore {
            repository_id: id,
            quarantined_count: 1,
            rejected_count: 0,
            released_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            last_scan_at: Some(ts(900)),
            updated_at: ts(0),
        });
        let projector = RepoSecurityScoreProjector::new(repo.clone());
        let d = ScoreDelta {
            quarantined_delta: -1,
            released_delta: 1,
            last_scan_at: None,
            ..ScoreDelta::default()
        };
        projector.apply(id, &d).await.unwrap();
        let upserts = repo.upserts.lock().unwrap().clone();
        assert_eq!(upserts[0].last_scan_at, Some(ts(900)));
        assert_eq!(upserts[0].quarantined_count, 0);
        assert_eq!(upserts[0].released_count, 1);
    }

    #[tokio::test]
    async fn apply_propagates_repo_find_error() {
        struct FailingRepo;
        impl RepoSecurityScoreRepository for FailingRepo {
            fn upsert<'a>(
                &'a self,
                _score: &'a RepoSecurityScore,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn find(
                &self,
                _repo_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
                Box::pin(async { Err(hort_domain::error::DomainError::Invariant("boom".into())) })
            }
        }
        let projector = RepoSecurityScoreProjector::new(Arc::new(FailingRepo));
        let d = ScoreDelta {
            quarantined_delta: 1,
            ..ScoreDelta::default()
        };
        let err = projector.apply(Uuid::new_v4(), &d).await.unwrap_err();
        assert!(matches!(err, AppError::Domain(_)));
    }

    #[tokio::test]
    async fn apply_propagates_repo_upsert_error() {
        struct UpsertFails;
        impl RepoSecurityScoreRepository for UpsertFails {
            fn upsert<'a>(
                &'a self,
                _score: &'a RepoSecurityScore,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(hort_domain::error::DomainError::Invariant("boom".into())) })
            }
            fn find(
                &self,
                _repo_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
                Box::pin(async { Ok(None) })
            }
        }
        let projector = RepoSecurityScoreProjector::new(Arc::new(UpsertFails));
        let d = ScoreDelta {
            quarantined_delta: 1,
            ..ScoreDelta::default()
        };
        let err = projector.apply(Uuid::new_v4(), &d).await.unwrap_err();
        assert!(matches!(err, AppError::Domain(_)));
    }
}
