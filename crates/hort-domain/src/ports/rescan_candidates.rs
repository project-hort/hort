//! Outbound port for the cron-rescan eligibility query.
//!
//! `CronRescanTickHandler` (in `hort-app::task_handlers::cron_rescan_tick`)
//! delegates the SQL-side eligibility predicate — joining `artifacts`
//! to `policy_projections` via the repo→policy chain, filtering on the
//! live statuses [`RescanCandidatesRepository::select_eligible`] names
//! and on `rescan_interval_hours > 0`,
//! comparing both `last_scan_at` and the artifact's most recent
//! `kind='scan'` request against the policy interval, and excluding
//! artifacts that already have an in-flight `kind='scan'` job — to this
//! port. Keeping the SQL inside the Postgres adapter and exposing the
//! result as a flat `Vec<RescanCandidate>` lets the handler stay a pure
//! orchestration step (port boundary + dispatch loop only).
//!
//! Eligibility reads the
//! per-artifact `artifacts.last_scan_at` denorm column,
//! NOT `repo_security_scores.last_scan_at` (which is per-repo). See
//! `docs/architecture/explanation/scanning-pipeline.md`.
//!
//! [`RescanCandidatesRepository::select_stranded`] is a companion
//! eligibility query (ADR 0007's retry-exhaustion split, its later
//! widening to artifacts with no scan job at all, and its "A reached
//! verdict supersedes an absent one" amendment) for a *different*
//! predicate: `quarantine_status IN
//! ('quarantined', 'scan_indeterminate')`
//! artifacts whose scan either could not even **run** (every configured
//! scanner backend failed and exhausted `HORT_SCANNER_MAX_ATTEMPTS`
//! retries — the artifact's most recent `kind='scan'` job landed
//! `status='failed'`) **or was never even requested** (no `kind='scan'`
//! job row exists at all for the artifact — the #115 seed-import
//! stranding gap: `IngestUseCase::register_by_hash_inner`'s
//! `quarantine_anchor_override` branch used to quarantine an artifact
//! without enqueueing a scan; that inflow is stopped at the source
//! (#115 item1), but artifacts already stranded that way in deployed
//! environments before that fix need this sweep — there is no manual
//! per-artifact rescan surface, so widening this query IS the
//! remediation for them, not an alternative to one). Both failure modes
//! are transient/infrastructure or missed-enqueue, not a
//! genuinely-ambiguous scan result, so neither transitions the artifact
//! to the `scan_indeterminate` status (ADR 0007 unchanged) — the
//! artifact simply stays `quarantined`.
//!
//! **`scan_indeterminate` is in the predicate too.** An artifact held
//! there is held for want of a verdict, and a verdict that is reached
//! supersedes an absent one: a non-blocking one returns the artifact to
//! the hold and a blocking one condemns it (ADR 0007, "A reached verdict
//! supersedes an absent one"), so a rescan has somewhere to land. This
//! query is the mechanism that delivers that healing rather than a
//! consequence of it — there is no per-artifact operator rescan surface
//! that bypasses it, so a state this query skips is terminal in practice
//! whatever the transition table says. `rejected` stays excluded: a
//! recorded rejection is a positive statement about the artifact, and
//! its exit is `re_evaluate`, not a re-scan.
//!
//! A candidate under either failure mode is stranded ONLY when its
//! resolved policy (repo-scoped-else-global-else-`DefaultPolicy`, the
//! same resolution [`Self::select_eligible`] uses) actually scans:
//! `scan_backends: []` (ScanWaived) is an explicit operator opt-out, and
//! such an artifact is not stranded — it releases via the existing
//! `ScanWaived` release authority — so `select_stranded` must never
//! enqueue a scan that contradicts that policy. `select_stranded` finds
//! exactly the (job-status-failed OR job-absent OR an absent-verdict hold
//! whose last scan request is older than the resolved rescan interval) ∧
//! (resolved-policy-scans) artifacts (with no in-flight scan job) so the
//! sweep can give the scan a chance once the scanner recovers, or a first
//! chance at all. See
//! `docs/architecture/how-to/recover-stranded-artifacts.md`.
//!
//! # The absent-verdict hold cannot be gated on the job row's status
//!
//! The two predicates above read the most recent `kind='scan'` job's
//! **status** as the signal. For a `quarantined` artifact that is exactly
//! right: a `completed` job means the artifact has its verdict and is
//! simply mid-window, and re-enqueueing a scan for it every tick would be
//! a hot loop over healthy rows.
//!
//! For a `scan_indeterminate` artifact it is not right, and the
//! difference is the whole reason that status is in the predicate. A job
//! in which every backend **ran and reported that it had nothing to
//! analyse** is a completed job: nothing failed, so recording it as a
//! failure misdescribes it one field down and makes an operator's
//! `?kind=scan&status=failed` triage listing claim a scanner error that
//! never happened. But the artifact it left behind is held with no
//! verdict and no deadline, and the status word is then the only thing
//! keeping the one query that reaches it from reaching it. So the
//! absent-verdict arm asks the artifact's **status**, which already says
//! "no verdict was reached", and uses time — not the job's status — to
//! bound how often it re-asks.
//!
//! The bound is the resolved `rescan_interval_hours`, measured against
//! the most recent `kind='scan'` job's `created_at`, which advances the
//! moment this sweep enqueues one. That makes the re-ask self-limiting
//! whatever the answer was: an artifact whose verdict is reached leaves
//! the status and the predicate, and one whose abstention is fixed —
//! the artifact's shape and the backend's analyzers are both fixed —
//! is asked again no more often than the policy already re-scans a
//! released artifact. `rescan_interval_hours = 0` reads as the
//! `DefaultPolicy` interval here rather than as "never": `0` turns off
//! the interval rescan of a *live, already-assessed* artifact, and
//! reading it as a standing instruction to keep an unassessed artifact
//! held forever would make this query unreachable for exactly the
//! operators who disabled cadence rescanning.
//!
//! # The third population: a document released with no composite verdict
//!
//! [`RescanCandidatesRepository::select_composite_unassessed`] covers the
//! population neither query above can see, because it is neither held nor
//! interval-stale: an OCI **image manifest** that is `released` (or
//! permissive-default `NULL`) and for which no composite assessment has
//! ever been recorded.
//!
//! A composed image's scan verdict is the manifest's (ADR 0064 D2), and
//! that is now unconditional — but a manifest already released under the
//! earlier rule keeps its release until a scan is driven, and
//! [`Self::select_eligible`] only drives one once the policy interval has
//! elapsed, or never at all when the operator set
//! `rescan_interval_hours = 0`. So "the composite is the verdict" would
//! be true of everything hort ingests next and false of everything it
//! already holds.
//!
//! The predicate is the **absence of a composite observation row**:
//! every composite scan records one, whatever it concluded, so a
//! reassessed manifest leaves the set. A manifest whose composite
//! assessment is already recorded — including one that recorded a
//! refusal — is not in it, and is reached by the ordinary interval sweep
//! like any other released artifact.
//!
//! # A reported scan leaves a trace, and the trace is the job row
//!
//! What all three queries need, and what two of them lacked, is the same
//! thing: a scan that **ran and reported** must leave something that
//! takes the artifact out of the selection, whatever it reported. Absent
//! that, a sweep whose candidate predicate the run does not change
//! re-presents the same rows on every tick for as long as the deployment
//! runs — one enqueued scan per row per tick, for an answer re-running
//! reproduces.
//!
//! Neither of the two obvious candidates for that trace carries it:
//!
//! - **The artifact's status** is deliberately untouched by a verdictless
//!   run on an artifact that already carries a verdict. Both
//!   `QuarantineUseCase::record_scan_indeterminate` and
//!   `hold_for_unproduced_composition` take an already-terminal skip
//!   there, because a run that reached no verdict has no standing to
//!   overwrite one that did.
//! - **`artifacts.last_scan_at`** is the *verdict's* timestamp, written
//!   only by the scan-result commit, and it is also that verdict's
//!   finding rows' identity: three reads join `sf.detected_at =
//!   a.last_scan_at`. Advancing it for a scan that produced no findings
//!   would make an artifact nobody could re-assess read as an artifact
//!   with none — the curator's worklist, the patch-candidate listing and
//!   the retention evaluator all at once.
//! - **A projection row** is best-effort where it is a measurement
//!   surface, which the composite observation deliberately is.
//!
//! The terminal `kind='scan'` `jobs` row is the trace that does carry
//! it. It exists for every reported scan, whatever the disposition, and
//! `TaskDispatcher` is its single writer. So each query bounds candidacy
//! by the most recent scan **request** against the same resolved
//! `rescan_interval_hours` it already resolves — stated once in
//! [`Self::select_stranded`]'s absent-verdict arm and now the rule in all
//! three. Read off the request's age rather than the row's status,
//! because the verdictless outcomes land on different statuses (an
//! abstention completes its row, an unproduced composition fails it)
//! while being one fact here.
//!
//! Its one limit, stated rather than discovered: the
//! `scan-row-retention-sweep` reclaims terminal `kind='scan'` rows past
//! its horizon, so a resolved interval longer than that horizon falls
//! back to whatever the query's other arm says. That bounds the re-ask at
//! the horizon instead of at the interval; it does not restore the
//! per-tick loop.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// One eligible artifact returned by [`RescanCandidatesRepository::select_eligible`].
///
/// All fields are the inputs `JobsRepository::enqueue_scan` needs to
/// insert a fresh `kind='scan'` row plus the policy interval the
/// candidate was matched against (carried for observability — the
/// handler does not branch on `rescan_interval_hours`, but emitting it
/// in tracing fields makes per-policy debugging tractable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RescanCandidate {
    /// The artifact that is eligible for re-scan.
    pub artifact_id: Uuid,
    /// The artifact's parent repository — bound directly into the
    /// `jobs.repository_id` column so the worker dispatch loop need
    /// not re-resolve it.
    pub repository_id: Uuid,
    /// Content-addressable storage hash. Required by `enqueue_scan` so
    /// the resulting `jobs` row carries the same content reference the
    /// scan worker streams from `StoragePort::get`.
    pub content_hash: ContentHash,
    /// Lowercase format token (`"npm"`, `"pypi"`, `"oci"`, …) — sourced
    /// from `repositories.format` via the SQL join. Matches the
    /// `Repository.format` `Display` impl the worker dispatches on.
    pub format: String,
    /// The resolved policy's `rescan_interval_hours`. Carried for
    /// per-candidate tracing only; the eligibility query already filtered
    /// `> 0` and the past-interval predicate.
    ///
    /// **Sentinel `0` for both companion queries**
    /// ([`RescanCandidatesRepository::select_stranded`] and
    /// [`RescanCandidatesRepository::select_composite_unassessed`]):
    /// neither selects on a policy-derived wait the caller could act on —
    /// the stranded predicate re-picks as soon as the last scan attempt
    /// errored or was never made, and the composite-unassessed predicate
    /// has no interval concept at all — so this field is not meaningful
    /// for those rows. The stranded predicate's own absent-verdict arm
    /// *does* compare against the resolved interval, inside the SQL; what
    /// it does not do is hand the number back, because a caller that
    /// branched on it would be branching on an input only one of three
    /// arms used. Kept on the shared struct rather than forking a second
    /// candidate type — `enqueue_scan` (the only consumer) never reads
    /// this field either way.
    pub rescan_interval_hours: i32,
}

/// Outbound port for the rescan eligibility query.
///
/// The Postgres adapter implements this against the canonical SQL
/// (joining `artifacts` to `policy_projections` via the repo→policy
/// chain — repo-scoped policies shadow the global default; archived
/// rows are excluded). The handler crate (`hort-app`) calls this method
/// once per tick and iterates the returned `Vec` to enqueue scan jobs.
pub trait RescanCandidatesRepository: Send + Sync {
    /// Return up to `batch_size` artifacts whose policy-derived rescan
    /// interval has elapsed and that have no in-flight scan job.
    ///
    /// Live means `quarantine_status = 'released'` **or** the
    /// permissive-default `NULL`, the same pair
    /// [`Self::select_composite_unassessed`] selects on. The `NULL` arm
    /// is not an oversight to be tightened: an artifact under no
    /// operator policy, or under one with `quarantine_duration_secs = 0`,
    /// is downloadable and terminal in exactly that state, so excluding
    /// it would leave an out-of-the-box deployment's artifacts
    /// un-rescanned — and it is also the state a decision that never ran
    /// leaves behind, which is the row this sweep most needs to reach.
    ///
    /// `now` is the wall-clock timestamp the handler captured at the
    /// start of the tick — passed in (rather than read inside the
    /// adapter via `now()`) so per-tick semantics stay coherent across
    /// retries and so tests can pin the comparison time.
    fn select_eligible<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>>;

    /// Return up to `batch_size` **stranded** artifacts: `quarantine_status
    /// IN ('quarantined', 'scan_indeterminate')` with a most-recent
    /// `kind='scan'` job in `status='failed'` (a scanner-execution
    /// failure that exhausted retries — see the module doc) or no
    /// `kind='scan'` job at all, **or** a `scan_indeterminate` artifact
    /// whose most recent `kind='scan'` job was requested longer ago than
    /// its resolved `rescan_interval_hours` — whatever that job's status
    /// says. No in-flight `kind='scan'` job, either way.
    ///
    /// That third arm is the one an absent verdict needs and the module
    /// doc says why: a job in which every backend ran and reported
    /// nothing to analyse is a *completed* job, so the status signal the
    /// first two arms read cannot see the artifact it left held, and the
    /// re-ask is bounded by time instead.
    ///
    /// Distinct query from [`Self::select_eligible`] — different source
    /// statuses (the two holds, not `released`/`NULL`), a different "was
    /// it scanned" signal (the most recent `jobs` row, not
    /// `artifacts.last_scan_at`), and no interval gating at all on the
    /// two arms that read the job's status, where an errored or absent
    /// scan is eligible immediately rather than after a policy-derived
    /// wait. Kept as a companion method rather than folded into
    /// `select_eligible`'s SQL so that well-tested query's shape stays
    /// untouched.
    ///
    /// `now` is the wall-clock timestamp the handler captured at the
    /// start of the tick, for the same reason [`Self::select_eligible`]
    /// takes it: per-tick semantics stay coherent across retries and a
    /// test can pin the comparison time.
    fn select_stranded<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>>;

    /// Return up to `batch_size` OCI **image manifests** that are live
    /// (`quarantine_status = 'released'` or the permissive-default
    /// `NULL`) and carry no recorded composite assessment at all, under a
    /// resolved policy that scans and with no in-flight `kind='scan'`
    /// job.
    ///
    /// The population the other two queries structurally cannot see: it
    /// is not held, so [`Self::select_stranded`] excludes it, and its
    /// evidence may be minutes old, so [`Self::select_eligible`]'s
    /// interval excludes it too — yet the evidence it is serving on was
    /// reached under a rule in which the composed image's verdict carried
    /// no release authority. See the module doc for why the predicate is
    /// the *absence* of an observation rather than the absence of a
    /// successful one.
    ///
    /// **And why that predicate alone does not make the sweep
    /// self-limiting.** "Every composite scan records a row" is a
    /// best-effort write by construction: the observation projection is a
    /// measurement surface and may not be able to withhold an artifact,
    /// so `ShadowObservationSink::record` logs a storage failure and
    /// returns, and the run that could not resolve its exclusion set
    /// records nothing at all and says so. Either way the manifest's scan
    /// ran and reported while the row the next tick reads for is absent,
    /// and this query would re-present it on that tick and on every tick
    /// after it. So candidacy is **also** bounded by the most recent
    /// `kind='scan'` request against the resolved `rescan_interval_hours`
    /// — the same bound [`Self::select_stranded`]'s absent-verdict arm
    /// carries, and a backstop rather than a cadence: a manifest whose
    /// scan did record its row has already left the set by the
    /// row-absence predicate before this one is reached.
    ///
    /// An image **index** is excluded: it composes nothing of its own —
    /// its children are the manifests that do — so a composite
    /// assessment is not a thing it can lack.
    ///
    /// `now` is the tick's captured wall-clock, for the same reason the
    /// two queries above take it.
    fn select_composite_unassessed<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion. Mirrors the pattern in
    /// [`crate::ports::policy_projection_repository`].
    fn _assert_dyn_compatible(_: Box<dyn RescanCandidatesRepository>) {}

    /// Runtime size_of probe — only resolves if the trait is dyn-compatible.
    #[test]
    fn rescan_candidates_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn RescanCandidatesRepository>();
    }

    /// `RescanCandidate` is `Clone + PartialEq` so handler tests can
    /// compare expected vs. observed candidate lists without bespoke
    /// per-field assertions.
    #[test]
    fn rescan_candidate_is_clone_and_partial_eq() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("valid sha256 hex");
        let c = RescanCandidate {
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            content_hash: hash,
            format: "npm".into(),
            rescan_interval_hours: 24,
        };
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    /// A handler-style smoke test that drives all three trait methods
    /// through a single `Box<dyn>` to prove dispatch + every `BoxFuture`
    /// signature compiles. One `Stub` exercising every method (rather
    /// than a separate `Stub` per method, each only calling the one it's
    /// testing) so no implementation body is dead weight from another
    /// test's perspective.
    #[tokio::test]
    async fn every_selection_dispatches_through_trait_object() {
        fn sentinel_candidate() -> RescanCandidate {
            RescanCandidate {
                artifact_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .parse()
                    .expect("valid sha256 hex"),
                format: "npm".into(),
                rescan_interval_hours: 0,
            }
        }

        struct Stub;
        impl RescanCandidatesRepository for Stub {
            fn select_eligible<'a>(
                &'a self,
                _batch_size: u32,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn select_stranded<'a>(
                &'a self,
                _batch_size: u32,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
                Box::pin(async { Ok(vec![sentinel_candidate()]) })
            }
            fn select_composite_unassessed<'a>(
                &'a self,
                _batch_size: u32,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
                Box::pin(async { Ok(vec![sentinel_candidate()]) })
            }
        }

        let port: Box<dyn RescanCandidatesRepository> = Box::new(Stub);
        let now = Utc::now();

        let eligible = port.select_eligible(1000, now).await.expect("Ok");
        assert!(eligible.is_empty());

        let stranded = port.select_stranded(1000, now).await.expect("Ok");
        assert_eq!(stranded.len(), 1);
        assert_eq!(stranded[0].rescan_interval_hours, 0);

        let unassessed = port
            .select_composite_unassessed(1000, now)
            .await
            .expect("Ok");
        assert_eq!(unassessed.len(), 1);
        // Both companion queries carry the interval sentinel: neither
        // selects on a policy-derived wait the caller could act on.
        assert_eq!(unassessed[0].rescan_interval_hours, 0);
    }
}
