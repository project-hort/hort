//! `RetentionEvaluateHandler`.
//!
//! The `kind = "retention-evaluate"` TaskHandler. Triggered by the
//! k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/retention-evaluate` (the route +
//! typed params live in
//! `hort-http-admin-tasks`; this module only registers the handler
//! with the worker). Default schedule `0 3 * * *`. Thin orchestration, modelled
//! 1:1 on [`CronRescanTickHandler`](super::cron_rescan_tick):
//!
//! 1. Capture `now`.
//! 2. Read the keyset position the previous completed run stopped at
//!    (see *Cross-tick rotation* below).
//! 3. `RetentionPolicyProjectionRepository::list_active()` → the
//!    active retention policies (O(1) projection read, NOT a stream
//!    replay).
//! 4. Loop `RetentionCandidateReader::list_candidates(BATCH_SIZE,
//!    cursor, now)` from that position, advancing the keyset cursor
//!    until a short page (the walk reached the highest candidate id) or
//!    the per-tick page cap [`MAX_BATCHES_PER_TICK`].
//! 5. Per batch, map `RetentionCandidateRow → RetentionUseCase::
//!    RetentionCandidate` (a trivial field copy — the type stays in
//!    `hort-app`) and call
//!    `RetentionUseCase::evaluate_policies_in_mode(now, &policies,
//!    &candidates, mode)`, accumulating the per-batch [`EvaluateSummary`]
//!    and matched rows.
//! 6. For a dry run, simulate the purge refcount decision, build a
//!    bounded operator sample, and digest the proposal's identity (see
//!    *What the preview proposes* below); for execution, append expiry
//!    events at the same use-case boundary used before modes existed.
//! 7. Return [`TaskOutcome::Completed`] with the projected JSON, carrying
//!    the position the next run resumes from.
//!
//! The handler appends nothing directly — `evaluate_policies_in_mode` owns
//! the `ArtifactExpired` append in execute mode and suppresses that append
//! in dry-run mode. No new metrics are introduced; the handler returns
//! `result_summary` JSON only.
//!
//! # Cross-tick rotation
//!
//! One run evaluates at most `MAX_BATCHES_PER_TICK * BATCH_SIZE`
//! artifacts, so on a registry holding more eligible artifacts than that
//! the cap is reached with candidates still unexamined. Where it stopped
//! is **persisted**: the run writes the last artifact id it evaluated
//! into its own `result_summary.cursor` ([`SweepCursor`]), and the next
//! run's fresh `jobs` row reads that back through
//! [`JobsRepository::last_result_summary_by_kind`] and resumes strictly
//! after it. No new table, no column on `artifacts`, no operator knob:
//! `result_summary` is durable per-row state the run already writes, and
//! the jobs-row retention sweep retains the newest `completed` row of
//! every kind precisely because readers of this shape exist (see
//! [`JobsRepository::delete_terminal_other_kind_rows_older_than`]). It is
//! the [`PrefetchTickHandler`](super::prefetch_tick) rotation's
//! mechanism applied to a single-dimension keyset walk.
//!
//! **A finished pass wraps.** A short — or empty — page means the walk
//! reached the highest candidate id, so the pass is over and the
//! persisted cursor goes back to `null`: the next run starts from the
//! beginning again. A full pass therefore costs
//! `⌈candidates / (MAX_BATCHES_PER_TICK * BATCH_SIZE)⌉` *executions* —
//! only an execution advances the position, see below — and a candidate
//! set that fits inside one run behaves exactly as it did
//! before the cursor existed — one page, short, pass complete, cursor
//! `null` — which is every deployment below 64 000 eligible artifacts.
//!
//! **Coverage comes from the wrap, not from the ordering.**
//! `artifacts.id` is a v4 UUID, so the keyset walks UUID space, not
//! time: a newly ingested artifact lands uniformly at random relative to
//! the saved cursor, and about half of them land *behind* it. A pass
//! therefore cannot promise it saw every artifact that was eligible at
//! some point during it. What is promised is that the next pass, which
//! starts from the beginning, does.
//!
//! **The candidate set is mutable, and that is a property of the design
//! rather than an oversight.** The sort key is the immutable primary
//! key, so no row can shift position between two pages — the classic
//! keyset-over-a-moving-set skip cannot occur here. What moves is
//! *membership*:
//!
//! - An artifact that stops being a candidate (quarantined, rejected,
//!   soft-deleted) before the cursor reaches it is not evaluated, which
//!   is the correct answer rather than a miss.
//! - An artifact that *becomes* a candidate at an id the cursor has
//!   already passed waits for the wrap. The wait is bounded by two
//!   passes — the remainder of the current one plus the next — and the
//!   evaluator is idempotent, so the eventual evaluation reaches the
//!   same decision it would have reached earlier. The same bound covers
//!   a policy activated mid-pass: it reaches the artifacts behind the
//!   cursor on the following pass.
//!
//! **A dry run is an observation and leaves the rotation where it found
//! it.** `dry_run` takes no per-UTC-day single-flight claim (ADR 0028),
//! so an operator may preview as often as they like; each preview reads
//! the cursor — which is what makes it a preview of the window the next
//! execution will act on — and writes back exactly the value it read.
//! Advancing on a preview would let previews walk the rotation past the
//! one execution a day allows; writing `null` would reset it. Echoing is
//! the only value that changes nothing.
//!
//! # What the preview proposes
//!
//! Every figure in the preview — `rows`, `distinct_contents`, the byte
//! total — says *how much* would be expired. None of them says *what*.
//! Two previews can agree on all of them and still name different rows,
//! because an artifact that stopped matching and an equally sized one
//! that started are the same number; among artifacts of the same kind
//! that is not a rare coincidence. The bounded sample cannot close the
//! gap either, since it is capped and may be empty.
//!
//! So a dry run also states the proposal's **identity**:
//! `preview.proposal_digest`, over the `(policy_id, artifact_id)` pairs
//! this run matched, plus one per `(policy, repository)` group so a
//! reader can say which group moved. See [`proposal_digest`] for the
//! encoding and why its ordering is canonical. It is fixed-width on the
//! wire whatever the proposal's size, and it is not content identity —
//! it digests identifiers, never artifact bytes.
//!
//! **Coverage qualifies a comparison of two identities, never a match.**
//! Equal digests mean the same proposed rows however much of the
//! candidate set each run examined. Differing digests over a `partial`
//! run are another matter: the rotation below persists its position, so
//! an execution between two previews moves the window under them, and a
//! reader must say it compared two windows rather than report the window
//! as the world.
//!
//! **`coverage` answers for this run, not for the rotation.** It is
//! `complete` only when the run both started from the beginning and
//! reached the end. A run that resumed mid-pass and drained to the tail
//! reports `partial`, because the artifacts behind its start point are
//! not in its figures.
//!
//! **The cursor is progress state, not a lock.** A run that fails writes
//! no `result_summary` at all — the dispatcher's `mark_completed` is the
//! only writer of one — so a crashed run leaves the previous position
//! standing and the next run re-walks from there. Two *executions* cannot
//! race for it: the admin-tasks route derives a per-UTC-day idempotency
//! key for every destructive invocation (ADR 0028), so at most one
//! `execute` row exists per day cluster-wide and the claim is
//! `FOR UPDATE SKIP LOCKED`. What can overlap is an execution and a
//! preview, since previews are unkeyed: a preview that read the position
//! before an execution moved it, and completed after, writes the older
//! value back. All three outcomes cost one re-walked page and nothing
//! else — re-evaluation is idempotent, an artifact already carrying
//! `ArtifactExpired` lands in `already_expired` with no append — so a
//! repeat is wasted reads, never a wrong decision.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
use hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository;
use hort_domain::ports::retention_preview::{
    RetentionContentSimulation, RetentionPreview, SimulationBoundExceeded,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use hort_domain::retention::RetentionEvaluationMode;
use hort_domain::types::ContentHash;

use crate::use_cases::retention_use_case::{
    EvaluateSummary, EvaluationMatch, EvaluationReport, RetentionCandidate, RetentionUseCase,
};

/// Per-batch keyset page size. Mirrors `CronRescanTickHandler`'s
/// `BATCH_SIZE` (a single tick fetches in 1000-row pages). One tick
/// cannot walk the entire artifact table unbounded — see
/// [`MAX_BATCHES_PER_TICK`].
const BATCH_SIZE: u32 = 1000;

/// Per-tick batch cap: at most this many keyset pages per invocation
/// (`MAX_BATCHES_PER_TICK * BATCH_SIZE` artifacts). It bounds one tick's
/// work even on a huge table, and it is a per-tick **stride** rather than
/// a visibility ceiling: the run persists the id it stopped at and the
/// next run resumes strictly after it, so a candidate set larger than the
/// product is covered across `⌈candidates / product⌉` runs instead of
/// having everything past the first `product` artifacts go permanently
/// unevaluated. See *Cross-tick rotation* in the module docs.
const MAX_BATCHES_PER_TICK: usize = 64;

/// The curation queue's listing cap is the operator-facing precedent for a
/// bounded sanity-check sample.
const MAX_SAMPLE_SIZE: usize = 500;

/// The compatibility tag that travels with every proposal digest.
///
/// A single `apply --from-preview` can compare a baseline written before
/// a rolling upgrade against a fresh preview written after it, so the two
/// digests it holds may have been computed by two different servers. With
/// no tag, a change to the input encoding below would surface to the
/// operator as "the proposal changed" when nothing had — and a warning
/// that fires when nothing moved is trained away, which is precisely how
/// it comes to be ignored on the run where something did. The tag lets
/// the reader say "computed differently, not comparable" instead. Any
/// change to [`proposal_digest`]'s input — what is hashed, its order, or
/// its framing — bumps this string.
const PROPOSAL_DIGEST_SCHEME: &str = "policy-artifact-pairs-v1";

/// Domain-separation prefix hashed ahead of every proposal digest input.
///
/// A proposal digest answers "which rows would this sweep expire". It is
/// **not** content identity: a `ContentHash` is SHA-256 over an
/// artifact's stored bytes, this is SHA-256 over a list of identifiers,
/// and no storage path accepts one in place of the other. The prefix
/// makes that separation structural rather than merely conventional —
/// with it in the input no proposal digest can coincide with the hash of
/// any stored blob except by the collision resistance of SHA-256 itself.
const PROPOSAL_DIGEST_DOMAIN: &str = "hort retention proposal";

/// Input ceiling on the byte simulation, checked before the walk touches the
/// database.
///
/// Measured on Postgres 16 against corpora of 180 000 and 660 000
/// `content_references` edges, the walk costs roughly **2 us per candidate
/// artifact**: holding the reclaimable-target count at zero and raising the
/// candidate set from 1 000 to 10 000 moves the statement from 35 ms to 51 ms.
/// The same corpus costs ~7 us per *target*, so a run's cost is dominated by
/// what its candidates point at, not by how many of them there are. There is
/// no knee anywhere near the input sizes this sweep can produce, so the tight
/// bound does not belong here; it belongs on the target side (see
/// [`MAX_SIMULATION_TARGETS`]).
///
/// The value is therefore a backstop rather than an operational limit: it sits
/// a margin above the sweep's own structural maximum
/// (`MAX_BATCHES_PER_TICK * BATCH_SIZE` = 64 000 candidates examined per tick,
/// and matches cannot exceed candidates), so a normal sweep never reaches it,
/// while an oversized caller still cannot hand the database an unbounded
/// `unnest` array. It is deliberately not written as arithmetic on those two
/// constants: a ceiling that moves whenever the batch cap moves is not a
/// ceiling.
const MAX_SIMULATION_ARTIFACTS: usize = 100_000;

/// Output ceiling on the byte simulation, checked against the walk's result.
///
/// This is the bound that does the work, because the target count is what both
/// costs scale with:
///
/// - the walk itself costs roughly **7 us per target** — holding the candidate
///   set at 10 000 and raising the reclaimable-target count from 0 to 80 000
///   moves the statement from 51 ms to 635 ms on a 180 000-edge table, and
///   from 342 ms to 956 ms on a 660 000-edge one. That is about 3.5x the cost
///   of an artifact, and a flat-format artifact carries 2 targets while an
///   OCI-shaped one carries up to 9;
/// - every returned target then costs **one `StoragePort::size_of` round trip**
///   in [`RetentionEvaluateHandler::build_preview`]. On a filesystem backend
///   that is a `stat`, measured at 8.4 us; on an object-store backend it is an
///   HTTP `HEAD`, so this fan-out — not the SQL — is what puts an upper limit
///   on how large a preview may usefully be, and it is why this ceiling is
///   10^5 rather than 10^6. The round trips are issued
///   [`SIZE_PROBE_CONCURRENCY`] at a time, which divides that cost without
///   removing it: the fan-out is still the dominant term at every target
///   count this bound admits.
///
/// The value covers the sweep's per-tick structural maximum at the ordinary
/// flat-format fanout (64 000 candidates x 2 edges), which is what makes a
/// preview over a repository the size of the largest real one — ~37 000
/// artifacts, ~74 000 targets — report a measured figure instead of `omitted`.
/// An OCI-dominated sweep can still exceed it; the omission then says so, with
/// the bound and the observed count, so the operator can narrow the scope.
const MAX_SIMULATION_TARGETS: u32 = 128_000;

/// Width of the byte simulation's [`StoragePort::size_of`] fan-out.
///
/// The probe loop, not the SQL walk, is what bounds how large a preview may
/// usefully be: on an object-store backend every target costs one HTTP `HEAD`.
/// Issued one at a time, a preview at the [`MAX_SIMULATION_TARGETS`] ceiling
/// costs `128_000 x latency` — over half an hour against a store answering in
/// 15 ms. That cost is what holds that ceiling down, and with it the size of
/// repository whose preview can carry a figure at all rather than `omitted`.
///
/// **Why a width has to exist here at all.** The object-store adapter builds
/// its HTTP client from `object_store::ClientOptions::new()` with only
/// `allow_http` and the extra-CA anchors applied, so every connection knob is
/// at its default: `http1_only = true` (no multiplexing — one in-flight
/// request is one TCP connection), `pool_max_idle_per_host` unset and
/// therefore `reqwest`'s `usize::MAX`, `pool_idle_timeout` unset and
/// therefore 90 s. The client never pushes back. A wider fan-out does not
/// queue against a smaller pool; it opens more sockets, and then holds them
/// idle against the store for 90 s after the sweep has finished. This
/// constant is the only ceiling in the path, and its unit is sockets.
///
/// **Measured**, release build, best of five over 20 000 targets, against a
/// filesystem CAS and an S3-compatible object store on the same host:
///
/// | backend                    | sequential | at this width | plateau |
/// |----------------------------|-----------:|--------------:|--------:|
/// | filesystem (`stat`)        |     5.5 us |        1.3 us |  c >= 8 |
/// | object store (HTTP `HEAD`) |    93.3 us |       51.3 us |  c >= 8 |
///
/// Neither plateau there is a property of the fan-out: that host's object
/// store answers in 93 us, so nothing waits and there is no latency to hide —
/// both numbers are its own CPU wall. Re-measured against the same store with
/// 10 ms of added per-probe latency, which is the regime a real S3 sits in,
/// scaling is linear well past this width (48.9x at 64, 98.2x at 128) and
/// flattens around 192 — exactly that host's ~17 000 probe/s ceiling
/// multiplied by the 10 ms latency.
///
/// **Derived** by applying that same `rate ceiling x latency` relation to the
/// worker's own budget rather than the measuring host's. One object-store
/// probe costs 46-49 us of client CPU across the plateau (measured), and the
/// shipped worker is guaranteed 200 millicores
/// (`deploy/helm/hort-server/values.yaml`, `worker.resources.requests.cpu`),
/// so it sustains roughly 4 000-4 400 probes/s. A width above
/// `rate x latency` cannot be fed from that guaranteed share and turns into
/// sockets rather than throughput, which places the useful width somewhere
/// between about 40 (a 10 ms store) and about 130 (a 30 ms one). This value
/// sits inside that range and deliberately low in it: the width's costs are
/// paid on every run — sockets held 90 s past the sweep, and on the
/// filesystem backend one `spawn_blocking` slot per in-flight probe out of a
/// process-wide pool of 512 shared with every other `tokio::fs` caller in the
/// worker — whereas the upper half of the range buys throughput only against
/// the slowest stores.
const SIZE_PROBE_CONCURRENCY: usize = 64;

/// Where the sweep stopped, carried across runs as the run's own
/// `result_summary.cursor` — see *Cross-tick rotation* in the module
/// docs for why the state lives there rather than in a new table or a
/// column on `artifacts`.
///
/// A struct rather than a bare UUID string because this value is
/// operator-visible in `result_summary`, and a reader looking at a
/// summary needs to know what the UUID is without consulting this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SweepCursor {
    /// The next run enumerates candidates whose `artifacts.id` is
    /// strictly greater than this one.
    after_artifact_id: uuid::Uuid,
}

/// [`TaskHandler`] for the periodic retention-evaluate sweep.
pub struct RetentionEvaluateHandler {
    policies: Arc<dyn RetentionPolicyProjectionRepository>,
    candidates: Arc<dyn RetentionCandidateReader>,
    retention: Arc<RetentionUseCase>,
    preview: Arc<dyn RetentionPreview>,
    storage: Arc<dyn StoragePort>,
    /// The jobs port the run reads its predecessor's
    /// `result_summary.cursor` back through. Port-only, mirroring every
    /// other `hort-app` task handler's shape.
    jobs: Arc<dyn JobsRepository>,
    /// Keyset page size. Defaults to [`BATCH_SIZE`]; a field rather than
    /// a bare const read so the page boundary — and therefore the
    /// cross-run resume — is unit-testable without a 1000-row fixture.
    /// Mirrors [`PrefetchTickHandler`](super::prefetch_tick)'s
    /// `max_repos_per_tick`.
    batch_size: u32,
    /// Per-run page cap. Defaults to [`MAX_BATCHES_PER_TICK`]; a field
    /// for the same reason as [`Self::batch_size`] — reaching the cap is
    /// what makes a run resume rather than finish, and a 64 000-row
    /// fixture is not how that should be proven.
    max_batches_per_tick: usize,
}

impl RetentionEvaluateHandler {
    pub fn new(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
        retention: Arc<RetentionUseCase>,
        preview: Arc<dyn RetentionPreview>,
        storage: Arc<dyn StoragePort>,
        jobs: Arc<dyn JobsRepository>,
    ) -> Self {
        Self {
            policies,
            candidates,
            retention,
            preview,
            storage,
            jobs,
            batch_size: BATCH_SIZE,
            max_batches_per_tick: MAX_BATCHES_PER_TICK,
        }
    }

    /// Read the keyset position the most recently *completed*
    /// `retention-evaluate` run left in its `result_summary.cursor`.
    ///
    /// Every failure mode — the kind has never completed, the port read
    /// failed, the prior summary carries no `cursor`, the value is
    /// `null`, or it fails to deserialise — collapses to `None`, which
    /// means "walk from the beginning". Losing the resume point costs a
    /// pass restart, which the wrap would have done anyway; it is never
    /// a reason to fail the sweep or to skip artifacts.
    async fn read_cursor(&self) -> Option<SweepCursor> {
        let summary = match self.jobs.last_result_summary_by_kind(self.kind()).await {
            Ok(s) => s?,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "retention-evaluate: last_result_summary_by_kind failed; \
                     evaluating from the beginning",
                );
                return None;
            }
        };
        let cursor = summary.get("cursor")?.clone();
        if cursor.is_null() {
            return None;
        }
        match serde_json::from_value::<SweepCursor>(cursor.clone()) {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %cursor,
                    "retention-evaluate: malformed cursor in prior result_summary; \
                     evaluating from the beginning",
                );
                None
            }
        }
    }
}

impl TaskHandler for RetentionEvaluateHandler {
    fn kind(&self) -> &'static str {
        "retention-evaluate"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            let mode_raw = params
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("execute");
            let mode = match RetentionEvaluationMode::from_str(mode_raw) {
                Ok(mode) => mode,
                Err(message) => return Ok(TaskOutcome::fail(message, false)),
            };

            // Read before the policy check, so that an execution's own
            // walk is the only thing that ever moves the sweep's
            // position: every other completing path below writes back
            // the value read here unchanged.
            let resume_after = self.read_cursor().await;

            let policies = match self.policies.list_active().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "retention-evaluate: list_active failed");
                    return Ok(TaskOutcome::fail(format!("list_active failed: {e}"), true));
                }
            };
            if policies.is_empty() {
                // Steady state: no policies configured → no-op. Coverage
                // is `complete` because there is nothing to evaluate,
                // and the cursor is echoed rather than cleared: a
                // policy archived mid-pass must not cost the rotation
                // its position, since re-activating one would then
                // restart the pass from the beginning.
                tracing::info!("retention-evaluate: no active policies — no-op");
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "policies": 0,
                        "mode": mode.as_str(),
                        "coverage": "complete",
                        "cursor": resume_after,
                        "evaluated": 0,
                        "expired": 0,
                        "already_expired": 0,
                        "skipped_protected": 0,
                        "skipped_stale_scan": 0,
                        "errors": 0,
                        "preview": if mode == RetentionEvaluationMode::DryRun {
                            Some(json!({
                                "rows": 0,
                                "distinct_contents": 0,
                                "freed_bytes": { "status": "exact", "bytes": 0 },
                                // The digest over the empty proposal, not
                                // an absent one: "this run proposes
                                // nothing" is a fact a reader may compare
                                // against, whereas an absent digest means
                                // "identity unknown" and costs the
                                // comparison its teeth on the one path
                                // where the answer is trivially certain.
                                "proposal_digest": proposal_digest(
                                    RUN_DIGEST_SCOPE,
                                    &ProposalPairs::new(),
                                ),
                                "groups": [],
                                "sample": [],
                            }))
                        } else {
                            None
                        },
                    }),
                });
            }

            let mut total = EvaluateSummary::default();
            let mut matches = Vec::new();
            let mut cursor: Option<uuid::Uuid> = resume_after.map(|c| c.after_artifact_id);
            // Set when a page comes back short or empty: the walk has
            // reached the highest candidate id, so this pass is finished
            // and the next run starts over from the beginning.
            let mut pass_complete = false;
            for _ in 0..self.max_batches_per_tick {
                let rows = match self
                    .candidates
                    .list_candidates(self.batch_size, cursor, now)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "retention-evaluate: list_candidates failed"
                        );
                        return Ok(TaskOutcome::fail(
                            format!("list_candidates failed: {e}"),
                            true,
                        ));
                    }
                };
                if rows.is_empty() {
                    pass_complete = true;
                    break;
                }
                cursor = rows.last().map(|r| r.artifact.id);
                let short_page = (rows.len() as u32) < self.batch_size;

                // RetentionCandidateRow → RetentionCandidate
                // (trivial field copy).
                let candidates: Vec<RetentionCandidate> = rows
                    .into_iter()
                    .map(|r| RetentionCandidate {
                        artifact: r.artifact,
                        format: r.format,
                        repository_key: r.repository_key,
                        resolved_rescan_interval_hours: r.resolved_rescan_interval_hours,
                        keep_rank: r.keep_rank,
                        tag_targeted: r.tag_targeted,
                    })
                    .collect();

                match self
                    .retention
                    .evaluate_policies_in_mode(now, &policies, &candidates, mode)
                    .await
                {
                    Ok(report) => accumulate(&mut total, &mut matches, report),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "retention-evaluate: evaluate_policies failed"
                        );
                        return Ok(TaskOutcome::fail(
                            format!("evaluate_policies failed: {e}"),
                            true,
                        ));
                    }
                }

                if short_page {
                    pass_complete = true;
                    break;
                }
            }

            // `coverage` answers for this run: it examined everything
            // only if it both started at the beginning and reached the
            // end. A run that resumed mid-pass and drained to the tail
            // still has the artifacts behind its start point missing
            // from its figures.
            let coverage_complete = resume_after.is_none() && pass_complete;

            // A finished pass wraps: the next run starts from the
            // beginning. A dry run reports what the next execution would
            // do and writes back the position it read, so previewing —
            // which takes no per-UTC-day claim and may happen any number
            // of times — cannot walk the rotation forward.
            let next_cursor = if mode == RetentionEvaluationMode::DryRun {
                resume_after
            } else if pass_complete {
                None
            } else {
                cursor.map(|after_artifact_id| SweepCursor { after_artifact_id })
            };

            // `resumed` + `pass_complete` are what tell an operator
            // reading logs alone whether the rotation is advancing: the
            // counters look identical on a run that made progress and on
            // one that re-walked the same page.
            tracing::info!(
                policies = policies.len(),
                evaluated = total.evaluated,
                expired = total.expired,
                already_expired = total.already_expired,
                skipped_protected = total.skipped_protected,
                skipped_stale_scan = total.skipped_stale_scan,
                errors = total.errors,
                resumed = resume_after.is_some(),
                pass_complete,
                "retention-evaluate sweep complete"
            );

            let preview = if mode == RetentionEvaluationMode::DryRun {
                Some(self.build_preview(now, &matches).await)
            } else {
                None
            };

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "mode": mode.as_str(),
                    "coverage": if coverage_complete { "complete" } else { "partial" },
                    "cursor": next_cursor,
                    "policies": policies.len(),
                    "evaluated": total.evaluated,
                    "expired": total.expired,
                    "already_expired": total.already_expired,
                    "skipped_protected": total.skipped_protected,
                    "skipped_stale_scan": total.skipped_stale_scan,
                    "errors": total.errors,
                    "preview": preview,
                }),
            })
        })
    }
}

impl RetentionEvaluateHandler {
    async fn build_preview(
        &self,
        now: chrono::DateTime<Utc>,
        matches: &[EvaluationMatch],
    ) -> serde_json::Value {
        #[derive(Default)]
        struct Group {
            policy_name: String,
            repository_key: String,
            rows: u64,
            checksums: BTreeSet<String>,
            /// This group's share of the proposal, in the canonical
            /// order [`proposal_digest`] requires.
            pairs: ProposalPairs,
        }

        let mut groups: BTreeMap<(uuid::Uuid, uuid::Uuid), Group> = BTreeMap::new();
        let mut distinct_contents = BTreeSet::new();
        let mut artifact_ids = BTreeSet::new();
        // The whole proposal, accumulated beside the group breakdown
        // rather than derived from it: the run digest is specified over
        // pairs ordered by `(policy_id, artifact_id)`, and concatenating
        // the groups would order them by `(policy_id, repository_id,
        // artifact_id)` instead. Both are deterministic, but only the
        // first can be restated — and reproduced — without reference to
        // how this handler happens to bucket its groups.
        let mut proposal: ProposalPairs = ProposalPairs::new();
        let mut sample = Vec::new();

        for hit in matches {
            let group = groups
                .entry((hit.policy_id, hit.repository_id))
                .or_default();
            group.policy_name.clone_from(&hit.policy_name);
            group.repository_key.clone_from(&hit.repository_key);
            group.rows += 1;
            group.checksums.insert(hit.checksum_sha256.clone());
            group.pairs.insert((hit.policy_id, hit.artifact_id));
            distinct_contents.insert(hit.checksum_sha256.clone());
            artifact_ids.insert(hit.artifact_id);
            proposal.insert((hit.policy_id, hit.artifact_id));
            if sample.len() < MAX_SAMPLE_SIZE {
                sample.push(json!({
                    "artifact_id": hit.artifact_id,
                    "policy_id": hit.policy_id,
                    "repository_id": hit.repository_id,
                    "repository_key": hit.repository_key,
                    "name": hit.name,
                    "version": hit.version,
                    "age_seconds": now.signed_duration_since(hit.created_at).num_seconds().max(0),
                }));
            }
        }

        let group_rows: Vec<_> = groups
            .into_iter()
            .map(|((policy_id, repository_id), group)| {
                json!({
                    "policy_id": policy_id,
                    "policy_name": group.policy_name,
                    "repository_id": repository_id,
                    "repository_key": group.repository_key,
                    "rows": group.rows,
                    "distinct_contents": group.checksums.len(),
                    "proposal_digest": proposal_digest(
                        &group_digest_scope(policy_id, repository_id),
                        &group.pairs,
                    ),
                })
            })
            .collect();

        let artifact_ids: Vec<_> = artifact_ids.into_iter().collect();
        let freed_bytes = match self
            .preview
            .reclaimable_content(
                &artifact_ids,
                MAX_SIMULATION_ARTIFACTS,
                MAX_SIMULATION_TARGETS,
            )
            .await
        {
            Ok(RetentionContentSimulation::Exact(hashes)) => {
                match sum_target_sizes(self.storage.as_ref(), hashes).await {
                    Ok(bytes) => json!({ "status": "exact", "bytes": bytes }),
                    Err(reason) => json!({ "status": "omitted", "reason": reason }),
                }
            }
            Ok(RetentionContentSimulation::Omitted(exceeded)) => json!({
                "status": "omitted",
                "reason": bound_omission_reason(&exceeded),
            }),
            Err(error) => {
                tracing::warn!(error = %error, "retention dry-run refcount simulation failed");
                json!({
                    "status": "omitted",
                    "reason": "refcount simulation was unavailable",
                })
            }
        };

        json!({
            "rows": matches.len(),
            "distinct_contents": distinct_contents.len(),
            "freed_bytes": freed_bytes,
            "proposal_digest": proposal_digest(RUN_DIGEST_SCOPE, &proposal),
            "groups": group_rows,
            "sample": sample,
            "sample_limit": MAX_SAMPLE_SIZE,
        })
    }
}

/// The proposal, as the set of `(policy_id, artifact_id)` pairs a sweep
/// matched.
///
/// The pair — not the artifact — is the unit, because one artifact can be
/// matched by several policies and each of those matches is a separate
/// expiry. `BTreeSet` is the type rather than an implementation detail:
/// it *is* the canonical ordering [`proposal_digest`] relies on, so a
/// caller cannot hand the digest an order that varies with how the sweep
/// happened to walk.
type ProposalPairs = BTreeSet<(uuid::Uuid, uuid::Uuid)>;

/// Scope line for the digest that covers a whole run's proposal.
const RUN_DIGEST_SCOPE: &str = "run";

/// Scope line for the digest that covers one `(policy, repository)`
/// group's share of the proposal.
///
/// Separating the two scopes keeps a single-group run — where the group
/// holds exactly the pairs the run does — from producing one value for
/// both, which would let a group digest and a run digest be compared
/// against each other by accident and agree for the wrong reason.
fn group_digest_scope(policy_id: uuid::Uuid, repository_id: uuid::Uuid) -> String {
    format!("group {policy_id} {repository_id}")
}

/// The identity of the set a preview proposes to expire, as
/// `{"scheme": …, "value": …}`.
///
/// # Why an identity has to be on the wire at all
///
/// `rows`, `distinct_contents` and the byte total say *how much* a sweep
/// proposes to expire and nothing about *what*. A reader comparing two
/// previews on those figures alone cannot see an artifact that stopped
/// matching being replaced by an equally sized one that started — and
/// among artifacts of the same kind, equal totals are not a rare
/// coincidence. The sample cannot close that gap either: it is capped and
/// may be empty. A digest closes it exactly, and costs one fixed-width
/// field however large the proposal is.
///
/// # Why this ordering is canonical
///
/// Pairs arrive in walk order — keyset order over `artifacts.id`, crossed
/// with the order the policies were listed in. Neither is a property of
/// the proposal, and both move when a run resumes at a different keyset
/// position, so digesting arrival order would make two previews of the
/// same proposal disagree. [`ProposalPairs`] re-imposes ascending
/// `(policy_id, artifact_id)` order, which is a function of the set
/// alone: two runs proposing the same pairs hash the same bytes however
/// they reached them.
///
/// # Why the encoding cannot be ambiguous
///
/// Each pair is framed as `<policy_id> <artifact_id>\n`. A UUID's
/// canonical text form is 36 characters of lowercase hex and hyphens, so
/// it contains neither the separator nor the terminator; no two different
/// pair sets can encode to the same bytes. The scope line and the
/// domain-separation prefix are framed the same way and for the same
/// reason.
fn proposal_digest(scope: &str, pairs: &ProposalPairs) -> serde_json::Value {
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_DIGEST_DOMAIN.as_bytes());
    hasher.update(b"\n");
    hasher.update(scope.as_bytes());
    hasher.update(b"\n");
    let mut policy_buf = uuid::Uuid::encode_buffer();
    let mut artifact_buf = uuid::Uuid::encode_buffer();
    for (policy_id, artifact_id) in pairs {
        hasher.update(
            policy_id
                .as_hyphenated()
                .encode_lower(&mut policy_buf)
                .as_bytes(),
        );
        hasher.update(b" ");
        hasher.update(
            artifact_id
                .as_hyphenated()
                .encode_lower(&mut artifact_buf)
                .as_bytes(),
        );
        hasher.update(b"\n");
    }
    json!({
        "scheme": PROPOSAL_DIGEST_SCHEME,
        "value": hex::encode(hasher.finalize()),
    })
}

/// Sum the stored size of every reclaimable target, or say why no sum may be
/// reported. Fans the probes out [`SIZE_PROBE_CONCURRENCY`] at a time.
///
/// # Why the two failure reasons are ranked rather than raced
///
/// Concurrently, "the first error" is a property of the scheduler, not of the
/// input: which of several failing probes lands first varies run to run, and
/// so would the sentence the operator reads. Both failures are ranked instead,
/// so the verdict is a function of the target set and the storage's answers
/// alone and reproduces across runs:
///
/// 1. **A failed probe outranks everything.** It is not a preference: a failed
///    probe means the set of measured targets is incomplete, and no claim
///    about the total — including the claim that it overflowed — can be
///    founded on addends that were never observed. The fan-out is abandoned
///    the moment one probe fails, which also keeps a doomed preview from
///    paying for the remaining round trips.
/// 2. **Overflow is decided only over a complete set.** The accumulator is
///    widened to `u128`, which cannot overflow for any input this path admits
///    (at most [`MAX_SIMULATION_TARGETS`] addends below `2^64`, so below
///    `2^81`), and the narrowing to `u64` happens once, at the end. Order
///    therefore cannot change the answer: addition commutes, and the
///    intermediate sums no longer have a ceiling to trip over. `saturating_add`
///    keeps the impossible case impossible rather than a debug-build panic; a
///    saturated total still fails the narrowing and is reported as an
///    overflow.
///
/// A partial sum is never returned: the only `Ok` is a total over every
/// target, narrowed without loss.
async fn sum_target_sizes(
    storage: &dyn StoragePort,
    hashes: Vec<ContentHash>,
) -> Result<u64, &'static str> {
    let mut probes = futures::stream::iter(hashes)
        .map(|hash| async move { storage.size_of(&hash).await })
        .buffer_unordered(SIZE_PROBE_CONCURRENCY);

    let mut total: u128 = 0;
    while let Some(outcome) = probes.next().await {
        match outcome {
            Ok(size) => total = total.saturating_add(u128::from(size)),
            Err(error) => {
                tracing::warn!(error = %error, "retention dry-run storage size lookup failed");
                return Err("a reclaimable target size was unavailable");
            }
        }
    }

    u64::try_from(total).map_err(|_| "byte total overflowed u64")
}

/// Phrase a bound rejection so the operator can act on it: which ceiling, what
/// it is set to, what this run presented to it, and the one lever that changes
/// the answer. An omission that only says "a bound was exceeded" tells someone
/// holding tens of thousands of artifacts nothing they can use.
fn bound_omission_reason(exceeded: &SimulationBoundExceeded) -> String {
    format!(
        "exact byte accounting is bounded at {limit} {bound}; this run reached {observed}. \
         Narrow the sweep's scope — fewer repositories, or a predicate that matches fewer \
         artifacts — to bring it under the bound.",
        limit = exceeded.limit,
        bound = exceeded.bound.as_str(),
        observed = exceeded.observed,
    )
}

fn accumulate(
    total: &mut EvaluateSummary,
    matches: &mut Vec<EvaluationMatch>,
    batch: EvaluationReport,
) {
    total.evaluated += batch.summary.evaluated;
    total.expired += batch.summary.expired;
    total.already_expired += batch.summary.already_expired;
    total.skipped_protected += batch.summary.skipped_protected;
    total.skipped_stale_scan += batch.summary.skipped_stale_scan;
    total.errors += batch.summary.errors;
    matches.extend(batch.matches);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use chrono::{DateTime, Utc};
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::error::DomainError;
    use hort_domain::events::{system_actor, StreamId};
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use hort_domain::ports::jobs_repository::ResultWriteOutcome;
    use hort_domain::ports::retention_candidate_reader::RetentionCandidateRow;
    use hort_domain::ports::retention_preview::{
        ObservedCardinality, RetentionContentSimulation, SimulationBound,
    };
    use hort_domain::ports::retention_scan_reader::FirstObservations;
    use hort_domain::ports::retention_scan_reader::RetentionScanReader;
    use hort_domain::ports::storage::PutResult;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::retention::RetentionPolicy;
    use hort_domain::types::{ByteRange, ContentHash};

    use crate::use_cases::test_support::MockJobsRepository;
    use tokio::io::AsyncRead;
    use uuid::Uuid;

    fn art(id: Uuid) -> Artifact {
        Artifact {
            id,
            repository_id: Uuid::new_v4(),
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0.0".into()),
            path: "pkg/1.0.0".into(),
            size_bytes: 10,
            sha256_checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Released,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            provenance_hold_indefinite: false,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }

    // -- mock projection reader --
    struct MockPolicies {
        rows: Mutex<Vec<RetentionPolicy>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockPolicies {
        fn new(rows: Vec<RetentionPolicy>) -> Self {
            Self {
                rows: Mutex::new(rows),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl RetentionPolicyProjectionRepository for MockPolicies {
        fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let v = self.rows.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
        fn find_by_name(
            &self,
            _n: &str,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<
                    hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
                >,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
        fn find_by_name_including_archived(
            &self,
            _n: &str,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<
                    hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
                >,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_active_rows(
            &self,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Vec<hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow>,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn upsert(
            &self,
            _r: &hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- mock candidate reader --
    struct MockCandidates {
        pages: Mutex<Vec<Vec<RetentionCandidateRow>>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockCandidates {
        fn new(pages: Vec<Vec<RetentionCandidateRow>>) -> Self {
            Self {
                pages: Mutex::new(pages),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                pages: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl RetentionCandidateReader for MockCandidates {
        fn list_candidates<'a>(
            &'a self,
            _b: u32,
            _after: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let next = {
                let mut p = self.pages.lock().unwrap();
                if p.is_empty() {
                    Vec::new()
                } else {
                    p.remove(0)
                }
            };
            Box::pin(async move { Ok(next) })
        }
    }

    // -- mock event store + scan reader for the RetentionUseCase --
    struct InertEvents;
    impl EventStore for InertEvents {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            let n = batch.events.len() as u64;
            Box::pin(async move {
                Ok(AppendResult {
                    stream_position: n.saturating_sub(1),
                    global_positions: (0..n).collect(),
                })
            })
        }
        fn read_stream(
            &self,
            _s: &StreamId,
            _f: ReadFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn read_category(
            &self,
            _c: hort_domain::events::StreamCategory,
            _f: SubscribeFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn delete_stream(
            &self,
            _s: StreamId,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { unimplemented!() })
        }
        fn archive_stream(
            &self,
            _s: StreamId,
            _t: &str,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { unimplemented!() })
        }
    }
    struct InertScan;
    impl RetentionScanReader for InertScan {
        fn list_findings_for_artifact(
            &self,
            _a: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::types::Finding>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn repo_security_score(
            &self,
            _r: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<hort_domain::ports::repo_security_score_repository::RepoSecurityScore>,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
        fn first_observed_at<'a>(
            &'a self,
            _a: Uuid,
            _ids: &'a [String],
        ) -> BoxFuture<'a, DomainResult<FirstObservations>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn retention_uc() -> Arc<RetentionUseCase> {
        Arc::new(RetentionUseCase::new(
            crate::event_store_publisher::wrap_for_test(Arc::new(InertEvents)),
            Arc::new(InertScan),
        ))
    }

    struct InertPreview;
    impl RetentionPreview for InertPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            Box::pin(async { Ok(RetentionContentSimulation::Exact(Vec::new())) })
        }
    }

    #[derive(Default)]
    struct InertStorage {
        sizes: std::collections::HashMap<ContentHash, u64>,
        fail_size: bool,
        /// When set, only this target's probe fails and every other one
        /// answers from `sizes`. Lets one run carry both a failing probe and
        /// a sum that would overflow, which is what pins which verdict wins.
        fail_only: Option<ContentHash>,
        /// How many `yield_now` points each probe passes before answering.
        /// Zero — the default — resolves on the first poll, which is what
        /// every test that is not about the fan-out wants. A non-zero value
        /// holds every probe open long enough for the buffer to fill, so
        /// `peak_in_flight` observes the real width rather than 1.
        yields: usize,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
    }
    impl InertStorage {
        fn failing() -> Self {
            Self {
                fail_size: true,
                ..Default::default()
            }
        }
        fn with_sizes(sizes: std::collections::HashMap<ContentHash, u64>) -> Self {
            Self {
                sizes,
                ..Default::default()
            }
        }
        fn failing_only(
            hash: ContentHash,
            sizes: std::collections::HashMap<ContentHash, u64>,
        ) -> Self {
            Self {
                sizes,
                fail_only: Some(hash),
                ..Default::default()
            }
        }
        fn observing_concurrency() -> Self {
            Self {
                yields: 2,
                ..Default::default()
            }
        }
        fn peak_in_flight(&self) -> usize {
            self.peak_in_flight.load(Ordering::SeqCst)
        }
    }
    impl StoragePort for InertStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { Err(DomainError::Invariant("unused put".into())) })
        }

        fn get(
            &self,
            _hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { Err(DomainError::Invariant("unused get".into())) })
        }

        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { Err(DomainError::Invariant("unused get_range".into())) })
        }

        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Ok(false) })
        }

        fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            let hash = hash.clone();
            Box::pin(async move {
                let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                for _ in 0..self.yields {
                    tokio::task::yield_now().await;
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                if self.fail_size || self.fail_only.as_ref() == Some(&hash) {
                    return Err(DomainError::Invariant("size unavailable".into()));
                }
                Ok(self.sizes.get(&hash).copied().unwrap_or(0))
            })
        }
    }

    fn handler(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
    ) -> RetentionEvaluateHandler {
        handler_with_jobs(
            policies,
            candidates,
            Arc::new(MockJobsRepository::default()),
        )
    }

    /// Variant that threads a caller-supplied jobs port, so a cross-run
    /// test can feed one run's `result_summary` into the next run's
    /// cursor read — which is what the dispatcher's `mark_completed`
    /// plus a fresh `jobs` row do in production.
    fn handler_with_jobs(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
        jobs: Arc<dyn JobsRepository>,
    ) -> RetentionEvaluateHandler {
        RetentionEvaluateHandler::new(
            policies,
            candidates,
            retention_uc(),
            Arc::new(InertPreview),
            Arc::new(InertStorage::default()),
            jobs,
        )
    }

    fn ctx() -> TaskContext {
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "retention-evaluate".into(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "test".into(),
                attempts: 1,
                created_at: DateTime::<Utc>::UNIX_EPOCH,
                updated_at: DateTime::<Utc>::UNIX_EPOCH,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    fn age_policy() -> RetentionPolicy {
        // A pure-age policy that matches nothing here (artifacts are
        // UNIX_EPOCH..now; the evaluator's pure match is exercised by
        // the use-case's own tests — this handler test only asserts
        // orchestration counts + the projection/JSON shape).
        RetentionPolicy::project(&[hort_domain::retention::RetentionPolicyEvent::Created {
            id: Uuid::new_v4(),
            name: "p".into(),
            predicate: hort_domain::retention::PolicyPredicate::AgeExceeds(100 * 365 * 24 * 3600),
            scope: hort_domain::retention::RetentionScope::AllRepos,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
        }])
        .unwrap()
    }

    fn archived_age_policy() -> RetentionPolicy {
        let id = Uuid::new_v4();
        RetentionPolicy::project(&[
            hort_domain::retention::RetentionPolicyEvent::Created {
                id,
                name: "archived".into(),
                predicate: hort_domain::retention::PolicyPredicate::AgeExceeds(1),
                scope: hort_domain::retention::RetentionScope::AllRepos,
                created_at: DateTime::<Utc>::UNIX_EPOCH,
            },
            hort_domain::retention::RetentionPolicyEvent::Archived {
                id,
                by: Uuid::nil(),
                archived_at: DateTime::<Utc>::UNIX_EPOCH,
            },
        ])
        .unwrap()
    }

    #[test]
    fn kind_is_retention_evaluate() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
        );
        assert_eq!(h.kind(), "retention-evaluate");
    }

    #[tokio::test]
    async fn empty_policies_is_completed_noop() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policies"], 0);
                assert_eq!(result_summary["evaluated"], 0);
                assert_eq!(result_summary["mode"], "execute");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_policies_dry_run_returns_an_exact_empty_preview() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
        );
        match h.run(&json!({ "mode": "dry_run" }), ctx()).await.unwrap() {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["mode"], "dry_run");
                assert_eq!(result_summary["preview"]["rows"], 0);
                assert_eq!(result_summary["preview"]["distinct_contents"], 0);
                assert_eq!(result_summary["preview"]["freed_bytes"]["bytes"], 0);
                assert_eq!(result_summary["preview"]["groups"], json!([]));
                assert_eq!(result_summary["preview"]["sample"], json!([]));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn happy_path_evaluates_candidates_and_projects_summary() {
        let rows = vec![
            RetentionCandidateRow {
                artifact: art(Uuid::new_v4()),
                format: hort_domain::entities::repository::RepositoryFormat::Generic,
                repository_key: "npm-proxy".into(),
                resolved_rescan_interval_hours: Some(24),
                keep_rank: Some((4, 10)),
                tag_targeted: false,
            },
            RetentionCandidateRow {
                artifact: art(Uuid::new_v4()),
                format: hort_domain::entities::repository::RepositoryFormat::Generic,
                repository_key: "npm-proxy".into(),
                resolved_rescan_interval_hours: None,
                keep_rank: None,
                tag_targeted: true,
            },
        ];
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::new(vec![rows])),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policies"], 1);
                // 1 policy × 2 candidates evaluated.
                assert_eq!(result_summary["evaluated"], 2);
                assert_eq!(result_summary["expired"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_active_error_fails_with_retry() {
        let h = handler(
            Arc::new(MockPolicies::failing()),
            Arc::new(MockCandidates::new(vec![])),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("list_active"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_candidates_error_fails_with_retry() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::failing()),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("list_candidates"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_mode_fails_without_retry() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::new(vec![])),
        );
        match h
            .run(&json!({ "mode": "preview" }), ctx())
            .await
            .expect("outcome")
        {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry);
                assert!(reason.contains("execute, dry_run"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    fn evaluation_match(
        artifact_id: Uuid,
        policy_id: Uuid,
        repository_id: Uuid,
        checksum: &str,
    ) -> EvaluationMatch {
        evaluation_match_in(artifact_id, policy_id, repository_id, "npm-proxy", checksum)
    }

    fn evaluation_match_in(
        artifact_id: Uuid,
        policy_id: Uuid,
        repository_id: Uuid,
        repository_key: &str,
        checksum: &str,
    ) -> EvaluationMatch {
        EvaluationMatch {
            policy_id,
            policy_name: "cleanup".into(),
            artifact_id,
            repository_id,
            repository_key: repository_key.into(),
            name: "pkg".into(),
            version: Some("1.0.0".into()),
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            checksum_sha256: checksum.into(),
        }
    }

    /// Records the bounds it was called with, so the constants the handler
    /// documents can be asserted at the port boundary.
    #[derive(Default)]
    struct RecordingPreview {
        seen: Mutex<Vec<(usize, u32)>>,
    }
    impl RetentionPreview for RecordingPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            max_artifacts: usize,
            max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            self.seen.lock().unwrap().push((max_artifacts, max_targets));
            Box::pin(async { Ok(RetentionContentSimulation::Exact(Vec::new())) })
        }
    }

    struct FixedPreview(RetentionContentSimulation);
    impl RetentionPreview for FixedPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            let value = self.0.clone();
            Box::pin(async move { Ok(value) })
        }
    }

    struct FailingPreview;
    impl RetentionPreview for FailingPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            Box::pin(async { Err(DomainError::Invariant("simulation unavailable".into())) })
        }
    }

    fn preview_handler(
        preview: Arc<dyn RetentionPreview>,
        storage: Arc<dyn StoragePort>,
    ) -> RetentionEvaluateHandler {
        RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
            retention_uc(),
            preview,
            storage,
            Arc::new(MockJobsRepository::default()),
        )
    }

    #[tokio::test]
    async fn preview_reports_literal_bytes_and_caps_sample() {
        const HASH_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const HASH_B: &str = "4444444444444444444444444444444444444444444444444444444444444444";
        let hash_a: ContentHash = HASH_A.parse().unwrap();
        let hash_b: ContentHash = HASH_B.parse().unwrap();
        let mut sizes = std::collections::HashMap::new();
        sizes.insert(hash_a.clone(), 11);
        sizes.insert(hash_b.clone(), 29);
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![
                hash_a, hash_b,
            ]))),
            Arc::new(InertStorage::with_sizes(sizes)),
        );
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let matches: Vec<_> = (0..501)
            .map(|_| evaluation_match(Uuid::new_v4(), policy_id, repository_id, HASH_A))
            .collect();

        let preview = h.build_preview(Utc::now(), &matches).await;
        assert_eq!(preview["rows"], 501);
        assert_eq!(preview["distinct_contents"], 1);
        assert_eq!(preview["groups"][0]["rows"], 501);
        assert_eq!(preview["groups"][0]["distinct_contents"], 1);
        assert_eq!(preview["sample"].as_array().unwrap().len(), 500);
        assert_eq!(preview["sample_limit"], 500);
        assert_eq!(preview["freed_bytes"]["status"], "exact");
        assert_eq!(preview["freed_bytes"]["bytes"], 40);
    }

    /// The preview names repositories by the key an operator writes into
    /// a policy, beside the id a machine consumer joins on — in both the
    /// grouped rollup and the sample. Two repositories with distinct keys
    /// must stay distinguishable without resolving a UUID.
    #[tokio::test]
    async fn preview_carries_the_repository_key_in_groups_and_sample() {
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![]))),
            Arc::new(InertStorage::default()),
        );
        let policy_id = Uuid::new_v4();
        let npm_repo = Uuid::new_v4();
        let pypi_repo = Uuid::new_v4();
        let matches = vec![
            evaluation_match_in(
                Uuid::new_v4(),
                policy_id,
                npm_repo,
                "npm-proxy",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            evaluation_match_in(
                Uuid::new_v4(),
                policy_id,
                pypi_repo,
                "pypi-proxy",
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        ];

        let preview = h.build_preview(Utc::now(), &matches).await;

        let groups = preview["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 2, "one group per (policy, repository)");
        let keyed: BTreeMap<&str, &str> = groups
            .iter()
            .map(|g| {
                (
                    g["repository_id"].as_str().expect("repository_id"),
                    g["repository_key"].as_str().expect("repository_key"),
                )
            })
            .collect();
        assert_eq!(keyed.get(npm_repo.to_string().as_str()), Some(&"npm-proxy"));
        assert_eq!(
            keyed.get(pypi_repo.to_string().as_str()),
            Some(&"pypi-proxy")
        );

        let sample = preview["sample"].as_array().expect("sample array");
        let sample_keys: BTreeSet<&str> = sample
            .iter()
            .map(|row| row["repository_key"].as_str().expect("repository_key"))
            .collect();
        assert_eq!(
            sample_keys,
            ["npm-proxy", "pypi-proxy"].into_iter().collect(),
            "the sample names repositories by key too"
        );
        for row in sample {
            assert!(
                row["repository_id"].is_string(),
                "the id stays beside the key for machine consumers"
            );
        }
    }

    // -- proposal identity -------------------------------------------------

    /// Pull the digest value out of a preview (or one of its groups),
    /// asserting the scheme tag rides with it.
    fn digest_value(node: &serde_json::Value) -> String {
        let digest = &node["proposal_digest"];
        assert_eq!(
            digest["scheme"], PROPOSAL_DIGEST_SCHEME,
            "every digest carries the scheme that produced it: {digest}"
        );
        let value = digest["value"]
            .as_str()
            .expect("a digest value")
            .to_string();
        assert_eq!(value.len(), 64, "lowercase hex over a 256-bit digest");
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only: {value}"
        );
        value
    }

    fn identity_preview_handler() -> RetentionEvaluateHandler {
        preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![]))),
            Arc::new(InertStorage::default()),
        )
    }

    const IDENTITY_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// The whole point of the digest: two runs proposing the same rows
    /// agree even though the sweep reached them in a different order,
    /// which is what a resumed keyset walk routinely does.
    #[tokio::test]
    async fn the_proposal_digest_does_not_depend_on_the_order_the_sweep_walked() {
        let h = identity_preview_handler();
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();

        let forward: Vec<_> = ids
            .iter()
            .map(|id| evaluation_match(*id, policy_id, repository_id, IDENTITY_HASH))
            .collect();
        let mut reversed = forward.clone();
        reversed.reverse();

        let a = h.build_preview(Utc::now(), &forward).await;
        let b = h.build_preview(Utc::now(), &reversed).await;
        assert_eq!(
            digest_value(&a),
            digest_value(&b),
            "walk order is not a property of the proposal"
        );
        assert_eq!(
            digest_value(&a["groups"][0]),
            digest_value(&b["groups"][0]),
            "and neither is it a property of a group's share of it"
        );
    }

    /// The failure this whole field exists for: one artifact stops
    /// matching, an equally sized one starts, and every total stays put.
    #[tokio::test]
    async fn an_equal_sized_substitution_moves_the_digest_while_every_total_holds() {
        let h = identity_preview_handler();
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let kept = Uuid::new_v4();

        let before = vec![
            evaluation_match(kept, policy_id, repository_id, IDENTITY_HASH),
            evaluation_match(Uuid::new_v4(), policy_id, repository_id, IDENTITY_HASH),
        ];
        let after = vec![
            evaluation_match(kept, policy_id, repository_id, IDENTITY_HASH),
            evaluation_match(Uuid::new_v4(), policy_id, repository_id, IDENTITY_HASH),
        ];

        let a = h.build_preview(Utc::now(), &before).await;
        let b = h.build_preview(Utc::now(), &after).await;

        assert_eq!(
            a["rows"], b["rows"],
            "the totals are the trap, not the tell"
        );
        assert_eq!(a["distinct_contents"], b["distinct_contents"]);
        assert_eq!(a["groups"][0]["rows"], b["groups"][0]["rows"]);
        assert_eq!(
            a["groups"][0]["distinct_contents"],
            b["groups"][0]["distinct_contents"]
        );
        assert_ne!(
            digest_value(&a),
            digest_value(&b),
            "a substituted artifact must move the run's identity"
        );
        assert_ne!(
            digest_value(&a["groups"][0]),
            digest_value(&b["groups"][0]),
            "and the identity of the group it happened in, so a reader can \
             say which one moved"
        );
    }

    /// One artifact matched by two policies is two expiries, so the pair
    /// — not the artifact — is the proposal's unit.
    #[tokio::test]
    async fn the_digest_is_over_policy_artifact_pairs_not_over_artifacts() {
        let h = identity_preview_handler();
        let artifact_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let one_policy = vec![evaluation_match(
            artifact_id,
            Uuid::new_v4(),
            repository_id,
            IDENTITY_HASH,
        )];
        let other_policy = vec![evaluation_match(
            artifact_id,
            Uuid::new_v4(),
            repository_id,
            IDENTITY_HASH,
        )];

        let a = h.build_preview(Utc::now(), &one_policy).await;
        let b = h.build_preview(Utc::now(), &other_policy).await;
        assert_ne!(
            digest_value(&a),
            digest_value(&b),
            "the same artifact expired by a different policy is a different proposal"
        );
    }

    /// A group digest and a run digest over the same pairs must not
    /// collide, or a reader comparing the wrong pair of fields would
    /// agree for a reason that is not about the data.
    #[tokio::test]
    async fn a_single_group_run_does_not_reuse_its_group_digest_as_the_run_digest() {
        let h = identity_preview_handler();
        let matches = vec![evaluation_match(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            IDENTITY_HASH,
        )];
        let preview = h.build_preview(Utc::now(), &matches).await;
        assert_eq!(preview["groups"].as_array().expect("groups").len(), 1);
        assert_ne!(
            digest_value(&preview),
            digest_value(&preview["groups"][0]),
            "the two scopes are separated in the digest input"
        );
    }

    /// A proposal of nothing is a fact, and two of them compare equal.
    /// An absent digest would instead mean "identity unknown" and would
    /// cost a reader the confirmation it is owed.
    #[tokio::test]
    async fn a_proposal_of_nothing_still_has_an_identity() {
        let h = identity_preview_handler();
        let empty = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(empty["rows"], 0);
        let value = digest_value(&empty);

        let noop = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
        );
        match noop
            .run(&json!({ "mode": "dry_run" }), ctx())
            .await
            .unwrap()
        {
            TaskOutcome::Completed { result_summary } => assert_eq!(
                digest_value(&result_summary["preview"]),
                value,
                "the no-active-policies short-circuit proposes the same nothing, \
                 and says so in the same words"
            ),
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// The digest is an identity over identifiers, not content identity.
    /// Two proposals that differ only in the checksums their artifacts
    /// happen to carry are the same proposal.
    #[tokio::test]
    async fn the_digest_ignores_the_content_the_proposed_rows_point_at() {
        let h = identity_preview_handler();
        let artifact_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let a = h
            .build_preview(
                Utc::now(),
                &[evaluation_match(
                    artifact_id,
                    policy_id,
                    repository_id,
                    IDENTITY_HASH,
                )],
            )
            .await;
        let b = h
            .build_preview(
                Utc::now(),
                &[evaluation_match(
                    artifact_id,
                    policy_id,
                    repository_id,
                    "4444444444444444444444444444444444444444444444444444444444444444",
                )],
            )
            .await;
        assert_eq!(
            digest_value(&a),
            digest_value(&b),
            "the same rows are the same proposal whatever bytes they reference"
        );
    }

    /// The domain-separation prefix is what keeps a proposal digest from
    /// ever being read as CAS identity by coincidence.
    #[test]
    fn the_digest_input_is_domain_separated_from_a_bare_hash_of_the_same_pairs() {
        let policy_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let pairs: ProposalPairs = [(policy_id, artifact_id)].into_iter().collect();

        let bare = hex::encode(Sha256::digest(
            format!("{policy_id} {artifact_id}\n").as_bytes(),
        ));
        assert_ne!(
            proposal_digest(RUN_DIGEST_SCOPE, &pairs)["value"]
                .as_str()
                .expect("a value"),
            bare.as_str(),
        );
    }

    #[test]
    fn the_group_scope_names_both_halves_of_the_group_key() {
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let scope = group_digest_scope(policy_id, repository_id);
        assert_eq!(scope, format!("group {policy_id} {repository_id}"));
        assert_ne!(scope, RUN_DIGEST_SCOPE);
    }

    #[tokio::test]
    async fn preview_explicitly_omits_bytes_when_the_simulation_is_unavailable() {
        let failed = preview_handler(Arc::new(FailingPreview), Arc::new(InertStorage::default()));
        let omitted = failed.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("unavailable"));
    }

    /// An omission that does not say which ceiling stopped it, what that
    /// ceiling is, and how far over the run stood leaves the operator with no
    /// way to tell whether a narrower scope brings the figure back.
    #[tokio::test]
    async fn an_input_bound_omission_names_the_bound_its_value_and_the_exact_count() {
        let bounded = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Omitted(
                SimulationBoundExceeded {
                    bound: SimulationBound::Artifacts,
                    limit: 100_000,
                    observed: ObservedCardinality::Exact(120_000),
                },
            ))),
            Arc::new(InertStorage::default()),
        );
        let omitted = bounded.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        let reason = omitted["freed_bytes"]["reason"].as_str().unwrap();
        assert!(reason.contains("bounded at 100000 artifacts"), "{reason}");
        assert!(reason.contains("reached 120000"), "{reason}");
        assert!(reason.contains("Narrow the sweep's scope"), "{reason}");
        assert!(
            omitted["freed_bytes"]["bytes"].is_null(),
            "an omission never carries a figure: {omitted}"
        );
    }

    #[tokio::test]
    async fn an_output_bound_omission_reports_a_lower_bound_not_an_invented_total() {
        let bounded = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Omitted(
                SimulationBoundExceeded {
                    bound: SimulationBound::Targets,
                    limit: 128_000,
                    observed: ObservedCardinality::AtLeast(128_001),
                },
            ))),
            Arc::new(InertStorage::default()),
        );
        let omitted = bounded.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        let reason = omitted["freed_bytes"]["reason"].as_str().unwrap();
        assert!(
            reason.contains("bounded at 128000 reclaimable content targets"),
            "{reason}"
        );
        assert!(reason.contains("reached at least 128001"), "{reason}");
    }

    /// The handler must hand the port the constants it documents; a preview
    /// bounded by something other than the established figures would make
    /// their justification fiction.
    #[tokio::test]
    async fn the_documented_bounds_are_the_ones_the_port_is_given() {
        let recorder = Arc::new(RecordingPreview::default());
        let handler = preview_handler(recorder.clone(), Arc::new(InertStorage::default()));
        handler
            .build_preview(
                Utc::now(),
                &[evaluation_match(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    "cc",
                )],
            )
            .await;
        assert_eq!(
            *recorder.seen.lock().unwrap(),
            vec![(MAX_SIMULATION_ARTIFACTS, MAX_SIMULATION_TARGETS)]
        );
    }

    /// Both ceilings are measured values, and each one's justification is a
    /// relation to the sweep's own structural maximum. Pin the relations so a
    /// later edit cannot quietly drop a bound below the case it was chosen to
    /// cover.
    #[test]
    fn the_bounds_keep_the_relations_their_measurement_established() {
        let per_tick_max = MAX_BATCHES_PER_TICK * BATCH_SIZE as usize;
        assert!(
            MAX_SIMULATION_ARTIFACTS > per_tick_max,
            "the input ceiling is a backstop above the sweep's own maximum, not a limit \
             a normal sweep trips: {MAX_SIMULATION_ARTIFACTS} vs {per_tick_max}"
        );
        assert!(
            MAX_SIMULATION_TARGETS as usize >= 2 * per_tick_max,
            "the output ceiling covers the per-tick maximum at the flat-format fanout of \
             two edges per artifact: {MAX_SIMULATION_TARGETS} vs {}",
            2 * per_tick_max
        );
    }

    #[tokio::test]
    async fn preview_omits_bytes_when_storage_size_is_unavailable() {
        let hash: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![hash]))),
            Arc::new(InertStorage::failing()),
        );
        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("size"));
    }

    #[tokio::test]
    async fn preview_omits_bytes_when_exact_total_overflows() {
        let first: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let second: ContentHash =
            "4444444444444444444444444444444444444444444444444444444444444444"
                .parse()
                .unwrap();
        let mut sizes = std::collections::HashMap::new();
        sizes.insert(first.clone(), u64::MAX);
        sizes.insert(second.clone(), 1);
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![
                first, second,
            ]))),
            Arc::new(InertStorage::with_sizes(sizes)),
        );

        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("overflowed"));
    }

    /// Distinct, well-formed content hashes for fan-out tests. The value is
    /// irrelevant; only that each target is its own key into the mock's size
    /// table.
    fn hash_n(n: usize) -> ContentHash {
        format!("{n:064x}")
            .parse()
            .expect("64 lowercase hex characters is a content hash")
    }

    /// The fan-out is the change: a probe loop that issues one `size_of` at a
    /// time is what made the largest repositories unreportable. Both halves
    /// matter and neither is implied by the other — that probes overlap at
    /// all, and that the overlap never exceeds the documented width, because
    /// on an object-store backend that width is the number of sockets opened
    /// against the store.
    #[tokio::test]
    async fn size_probes_overlap_and_never_exceed_the_documented_width() {
        let targets: Vec<ContentHash> = (0..SIZE_PROBE_CONCURRENCY * 3).map(hash_n).collect();
        let storage = Arc::new(InertStorage::observing_concurrency());
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(targets))),
            storage.clone(),
        );

        let preview = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(preview["freed_bytes"]["status"], "exact");
        assert_eq!(
            storage.peak_in_flight(),
            SIZE_PROBE_CONCURRENCY,
            "the probes must overlap, and exactly as widely as the constant says: a peak of 1 \
             means the fan-out was lost, a peak above the width means the cap is not applied"
        );
    }

    /// The property with no acceptable failure mode: whatever a failing probe
    /// does to the verdict, it must never leave a figure behind. The failing
    /// target is the last of 128 here and every other one answers, so a
    /// short-circuit that kept its accumulator would be holding a large,
    /// plausible, wrong number at the moment it gave up.
    #[tokio::test]
    async fn a_failed_probe_omits_the_figure_instead_of_reporting_what_it_did_measure() {
        let targets: Vec<ContentHash> = (0..SIZE_PROBE_CONCURRENCY * 2).map(hash_n).collect();
        let sizes = targets
            .iter()
            .map(|t| (t.clone(), 1_000_u64))
            .collect::<std::collections::HashMap<_, _>>();
        let doomed = targets.last().expect("non-empty target set").clone();
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(targets))),
            Arc::new(InertStorage::failing_only(doomed, sizes)),
        );

        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(
            omitted["freed_bytes"]["bytes"].is_null(),
            "a partial sum must never be emitted, as `exact` or otherwise: {omitted}"
        );
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .expect("reason")
            .contains("size"));
    }

    /// Overflow is decided once, over the complete target set, and by a
    /// narrowing that cannot be skipped. Each target here is under a 64th of
    /// `u64::MAX`, so neither a single probe nor a buffer-sized batch of them
    /// overflows — only the whole set does. Widening the accumulator makes
    /// every intermediate sum representable, which removes the per-addition
    /// `checked_add` that used to be the guard; this pins that the one check
    /// left still refuses the figure.
    #[tokio::test]
    async fn overflow_is_decided_over_the_whole_target_set_not_a_prefix() {
        let targets: Vec<ContentHash> = (0..SIZE_PROBE_CONCURRENCY * 2).map(hash_n).collect();
        let per_target = u64::MAX / SIZE_PROBE_CONCURRENCY as u64;
        let sizes = targets
            .iter()
            .map(|t| (t.clone(), per_target))
            .collect::<std::collections::HashMap<_, _>>();
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(targets))),
            Arc::new(InertStorage::with_sizes(sizes)),
        );

        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .expect("reason")
            .contains("overflowed"));
    }

    /// Concurrently there is no "first" error, so the two failure reasons are
    /// ranked rather than raced. A failed probe wins: with one target
    /// unmeasured, "the total overflowed" would be a claim about addends that
    /// were never observed. The run here makes both conditions true at once —
    /// the two measured targets alone overflow `u64`, and a third probe fails
    /// — so only the ranking decides the sentence the operator reads.
    #[tokio::test]
    async fn a_failed_probe_outranks_an_overflowing_total() {
        let measured = [hash_n(1), hash_n(2)];
        let doomed = hash_n(3);
        let sizes = measured
            .iter()
            .map(|t| (t.clone(), u64::MAX))
            .collect::<std::collections::HashMap<_, _>>();
        let targets = vec![measured[0].clone(), measured[1].clone(), doomed.clone()];
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(targets))),
            Arc::new(InertStorage::failing_only(doomed, sizes)),
        );

        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        let reason = omitted["freed_bytes"]["reason"].as_str().expect("reason");
        assert!(
            reason.contains("unavailable"),
            "an unmeasured target outranks an overflow verdict it would have to invent: {reason}"
        );
        assert!(!reason.contains("overflowed"), "{reason}");
    }

    /// The width's justification is a range rather than a point: a fan-out
    /// wider than `sustainable probe rate x store latency` converts into open
    /// sockets instead of throughput, and for the shipped worker that rate is
    /// roughly 4 000-4 400 probes/s, which places the range between a 10 ms
    /// store and a 30 ms one. Pin the ends so a later "make it faster" edit
    /// has to re-derive the number instead of rounding it up to a power of two
    /// that the client's unbounded connection pool will happily honour.
    #[test]
    fn the_probe_width_stays_inside_the_range_its_measurement_established() {
        const WIDTH_FED_AT_10MS: usize = 40;
        const WIDTH_FED_AT_30MS: usize = 130;
        assert!(
            (WIDTH_FED_AT_10MS..=WIDTH_FED_AT_30MS).contains(&SIZE_PROBE_CONCURRENCY),
            "{SIZE_PROBE_CONCURRENCY} is outside the measured range \
             {WIDTH_FED_AT_10MS}..={WIDTH_FED_AT_30MS}"
        );
    }

    #[tokio::test]
    async fn inert_storage_non_size_methods_are_explicit_test_failures() {
        let storage = InertStorage::default();
        let hash: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(storage.put(Box::new(tokio::io::empty())).await.is_err());
        assert!(storage.get(&hash).await.is_err());
        assert!(storage
            .get_range(&hash, ByteRange::Inclusive { start: 0, end: 0 })
            .await
            .is_err());
        assert!(!storage.exists(&hash).await.unwrap());
    }

    struct FullPageCandidates {
        row: RetentionCandidateRow,
    }

    impl RetentionCandidateReader for FullPageCandidates {
        fn list_candidates<'a>(
            &'a self,
            batch_size: u32,
            _after: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
            let rows = vec![self.row.clone(); batch_size as usize];
            Box::pin(async move { Ok(rows) })
        }
    }

    #[tokio::test]
    async fn batch_ceiling_is_reported_as_partial_coverage() {
        let row = RetentionCandidateRow {
            artifact: art(Uuid::new_v4()),
            format: hort_domain::entities::repository::RepositoryFormat::Generic,
            repository_key: "npm-proxy".into(),
            resolved_rescan_interval_hours: None,
            keep_rank: None,
            tag_targeted: false,
        };
        let h = handler(
            Arc::new(MockPolicies::new(vec![archived_age_policy()])),
            Arc::new(FullPageCandidates { row }),
        );
        match h.run(&json!({ "mode": "dry_run" }), ctx()).await.unwrap() {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["coverage"], "partial");
                assert_eq!(result_summary["preview"]["rows"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }
    // =====================================================================
    // Cross-run rotation. These fixtures drive the handler across several
    // simulated runs, feeding each run's `result_summary` into the next
    // run's `last_result_summary_by_kind` read — which is what the
    // dispatcher's `mark_completed` plus a fresh `jobs` row do in
    // production.
    // =====================================================================

    /// A candidate reader over a fixed corpus that honours the keyset
    /// `after` bound and the `ORDER BY a.id` the Postgres adapter
    /// provides (`($3::uuid IS NULL OR a.id > $3)`). [`MockCandidates`]
    /// hands out pre-baked pages and ignores `after` entirely, so it
    /// cannot observe where a run started — which is exactly the blind
    /// spot that let a sweep restarting at the beginning every run look
    /// correct.
    struct KeysetCandidates {
        /// The corpus, ascending by artifact id.
        rows: Vec<RetentionCandidateRow>,
        /// The ids served, one entry per `list_candidates` call.
        served: Mutex<Vec<Vec<Uuid>>>,
    }

    impl KeysetCandidates {
        /// A corpus of `count` candidates whose ids ascend in
        /// construction order, so a test can name "the first four"
        /// without sorting UUIDs by hand. Production ids are v4 and land
        /// in the id space at random; the walk only depends on the order
        /// being total and stable, which sequential ids satisfy.
        fn with_rows(count: usize) -> Self {
            Self {
                rows: (1..=count)
                    .map(|i| RetentionCandidateRow {
                        artifact: art(Uuid::from_u128(i as u128)),
                        format: hort_domain::entities::repository::RepositoryFormat::Generic,
                        repository_key: "npm-proxy".into(),
                        resolved_rescan_interval_hours: None,
                        keep_rank: None,
                        tag_targeted: false,
                    })
                    .collect(),
                served: Mutex::new(Vec::new()),
            }
        }

        /// The corpus ids, ascending — the order the reader serves them.
        fn ids(&self) -> Vec<Uuid> {
            self.rows.iter().map(|r| r.artifact.id).collect()
        }

        /// Every id served since the last [`Self::take_served`], in
        /// order, flattened across pages.
        fn take_served(&self) -> Vec<Uuid> {
            std::mem::take(&mut *self.served.lock().unwrap())
                .into_iter()
                .flatten()
                .collect()
        }
    }

    impl RetentionCandidateReader for KeysetCandidates {
        fn list_candidates<'a>(
            &'a self,
            batch_size: u32,
            after: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
            let page: Vec<RetentionCandidateRow> = self
                .rows
                .iter()
                .filter(|r| after.is_none_or(|a| r.artifact.id > a))
                .take(batch_size as usize)
                .cloned()
                .collect();
            self.served
                .lock()
                .unwrap()
                .push(page.iter().map(|r| r.artifact.id).collect());
            Box::pin(async move { Ok(page) })
        }
    }

    /// A handler whose page size and per-run page cap are shrunk to
    /// `batch_size` x `max_batches`, so the resume across runs is proven
    /// at the page boundary rather than with a 64 000-row fixture. The
    /// policy is active and matches nothing, which keeps every run a pure
    /// walk: the rotation, not the predicate, is under test.
    fn rotation_handler(
        candidates: Arc<dyn RetentionCandidateReader>,
        jobs: Arc<dyn JobsRepository>,
        batch_size: u32,
        max_batches: usize,
    ) -> RetentionEvaluateHandler {
        let mut h = handler_with_jobs(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            candidates,
            jobs,
        );
        h.batch_size = batch_size;
        h.max_batches_per_tick = max_batches;
        h
    }

    /// Run one simulated tick and publish its `result_summary` the way
    /// the dispatcher's `mark_completed` does, so the next run's cursor
    /// read sees it.
    async fn tick(
        h: &RetentionEvaluateHandler,
        jobs: &MockJobsRepository,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let TaskOutcome::Completed { result_summary } = h.run(&params, ctx()).await.expect("Ok")
        else {
            panic!("expected Completed");
        };
        jobs.set_last_result_summary_by_kind("retention-evaluate", result_summary.clone());
        result_summary
    }

    fn cursor_value(id: Uuid) -> serde_json::Value {
        json!({ "after_artifact_id": id })
    }

    /// The defect this whole mechanism exists for: a second run must see
    /// artifacts the first did not. Before the cursor was persisted both
    /// runs walked the same leading page and everything past the per-run
    /// cap was never evaluated at all.
    #[tokio::test]
    async fn a_second_run_sees_candidates_the_first_did_not() {
        let candidates = Arc::new(KeysetCandidates::with_rows(10));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        let first_summary = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        let first = candidates.take_served();
        let second_summary = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        let second = candidates.take_served();

        assert_eq!(first, ids[0..4], "the first run walks the leading page");
        assert_eq!(
            second,
            ids[4..8],
            "the second run must resume after the first run's last id, not restart at the \
             beginning"
        );
        assert!(
            second.iter().all(|id| !first.contains(id)),
            "the two runs must not overlap: {first:?} vs {second:?}"
        );
        assert_eq!(first_summary["coverage"], "partial");
        assert_eq!(
            first_summary["cursor"],
            cursor_value(ids[3]),
            "the run publishes where it stopped, in the shape the next run parses"
        );
        assert_eq!(second_summary["cursor"], cursor_value(ids[7]));
    }

    /// The tail reached as a short page: the pass is over, the cursor
    /// goes back to `null`, and the next run starts from the beginning
    /// rather than sitting at the end forever.
    #[tokio::test]
    async fn a_pass_that_ends_on_a_short_page_wraps_to_the_beginning() {
        let candidates = Arc::new(KeysetCandidates::with_rows(5));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[0..4]);

        let tail = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[4..5], "the last, short page");
        assert_eq!(
            tail["cursor"],
            serde_json::Value::Null,
            "a finished pass wraps: the persisted position goes back to the beginning"
        );

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(
            candidates.take_served(),
            ids[0..4],
            "the run after a completed pass starts over"
        );
    }

    /// The same wrap when the tail falls exactly on a page boundary, so
    /// the walk discovers it through an empty page rather than a short
    /// one.
    #[tokio::test]
    async fn a_pass_that_ends_on_an_empty_page_wraps_to_the_beginning() {
        let candidates = Arc::new(KeysetCandidates::with_rows(6));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[0..4]);

        let tail = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(
            candidates.take_served(),
            ids[4..6],
            "a full final page followed by an empty one"
        );
        assert_eq!(tail["cursor"], serde_json::Value::Null);

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[0..4]);
    }

    /// Eventual coverage: successive runs together reach every candidate,
    /// which is the property the per-run cap alone cannot give.
    #[tokio::test]
    async fn successive_runs_cover_every_candidate() {
        let candidates = Arc::new(KeysetCandidates::with_rows(10));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        // Stride 4 over 10 candidates: ceil(10 / 4) = 3 runs.
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        let mut seen: Vec<Uuid> = Vec::new();
        for _ in 0..3 {
            tick(&h, &jobs, json!({ "mode": "execute" })).await;
            seen.extend(candidates.take_served());
        }

        seen.sort();
        assert_eq!(
            seen.len(),
            ids.len(),
            "no candidate is evaluated twice within a pass: the cursor only moves forward",
        );
        seen.dedup();
        assert_eq!(seen, ids, "every candidate is evaluated within one pass");
    }

    /// A preview is an observation: it reports the window the next
    /// execution will act on and leaves the rotation exactly where it
    /// found it. A dry run that advanced the cursor would let previews —
    /// which take no per-UTC-day single-flight claim — walk the rotation
    /// past the one execution a day allows.
    #[tokio::test]
    async fn a_dry_run_leaves_the_cursor_where_it_found_it() {
        let candidates = Arc::new(KeysetCandidates::with_rows(10));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[0..4]);

        let preview = tick(&h, &jobs, json!({ "mode": "dry_run" })).await;
        assert_eq!(
            candidates.take_served(),
            ids[4..8],
            "the preview describes the window the next execution will act on"
        );
        assert_eq!(
            preview["cursor"],
            cursor_value(ids[3]),
            "the preview writes back the position it read, unchanged"
        );

        tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(
            candidates.take_served(),
            ids[4..8],
            "the execution after a preview acts on the window the preview showed"
        );
    }

    /// A candidate set that fits inside one run behaves exactly as it did
    /// before the cursor existed — one pass per run, coverage complete —
    /// and a run that resumed mid-pass reports `partial` even when it
    /// drains to the tail, because the candidates behind its start point
    /// are missing from its figures.
    #[tokio::test]
    async fn coverage_is_complete_only_when_one_run_examined_everything() {
        let candidates = Arc::new(KeysetCandidates::with_rows(3));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

        let whole = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids);
        assert_eq!(whole["coverage"], "complete");
        assert_eq!(whole["cursor"], serde_json::Value::Null);

        jobs.set_last_result_summary_by_kind(
            "retention-evaluate",
            json!({ "cursor": cursor_value(ids[0]) }),
        );
        let resumed = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(candidates.take_served(), ids[1..3]);
        assert_eq!(
            resumed["coverage"], "partial",
            "a run that started mid-pass did not examine the whole candidate set"
        );
    }

    /// No active policies is a no-op that must not cost the rotation its
    /// position: a policy archived mid-pass and re-activated later would
    /// otherwise restart the pass from the beginning.
    #[tokio::test]
    async fn no_active_policies_carries_the_cursor_through() {
        let candidates = Arc::new(KeysetCandidates::with_rows(10));
        let ids = candidates.ids();
        let jobs = Arc::new(MockJobsRepository::default());
        jobs.set_last_result_summary_by_kind(
            "retention-evaluate",
            json!({ "cursor": cursor_value(ids[3]) }),
        );
        let h = handler_with_jobs(
            Arc::new(MockPolicies::new(vec![])),
            candidates.clone(),
            jobs.clone(),
        );

        let summary = tick(&h, &jobs, json!({ "mode": "execute" })).await;
        assert_eq!(summary["policies"], 0);
        assert_eq!(summary["cursor"], cursor_value(ids[3]));
        assert!(
            candidates.take_served().is_empty(),
            "the no-policy short-circuit enumerates nothing"
        );
    }

    /// Every unusable cursor — absent, `null`, or not a cursor at all —
    /// degrades to walking from the beginning. A lost resume point costs
    /// a pass restart, which the wrap does anyway; it must never fail the
    /// sweep or skip a candidate.
    #[tokio::test]
    async fn an_unusable_cursor_evaluates_from_the_beginning() {
        for prior in [
            None,
            Some(json!({ "coverage": "partial" })),
            Some(json!({ "cursor": serde_json::Value::Null })),
            Some(json!({ "cursor": 7 })),
            Some(json!({ "cursor": { "after_artifact_id": "not-a-uuid" } })),
        ] {
            let candidates = Arc::new(KeysetCandidates::with_rows(10));
            let ids = candidates.ids();
            let jobs = Arc::new(MockJobsRepository::default());
            if let Some(prior) = prior.clone() {
                jobs.set_last_result_summary_by_kind("retention-evaluate", prior);
            }
            let h = rotation_handler(candidates.clone(), jobs.clone(), 2, 2);

            let summary = h
                .run(&json!({ "mode": "execute" }), ctx())
                .await
                .expect("Ok");
            assert!(matches!(summary, TaskOutcome::Completed { .. }));
            assert_eq!(
                candidates.take_served(),
                ids[0..4],
                "prior summary {prior:?} must not stop the sweep from walking"
            );
        }
    }

    /// A jobs port whose only divergence from the shared mock is that the
    /// cursor read fails. The shared mock cannot fail this read, and the
    /// failure branch is the one that decides whether a database blip on
    /// a read-only progress lookup can take the sweep down.
    struct CursorReadFails;

    impl JobsRepository for CursorReadFails {
        fn claim_scan_jobs<'a>(
            &'a self,
            _worker_id: &'a str,
            _batch_size: u32,
            _lock_duration: std::time::Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<hort_domain::ports::jobs_repository::ScanJob>>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn mark_completed<'a>(
            &'a self,
            _job_id: Uuid,
            _attempt: u32,
            _result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            Box::pin(async { Ok(ResultWriteOutcome::Applied) })
        }
        fn reschedule<'a>(
            &'a self,
            _job_id: Uuid,
            _attempt: u32,
            _backoff: std::time::Duration,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            Box::pin(async { Ok(ResultWriteOutcome::Applied) })
        }
        fn mark_failed<'a>(
            &'a self,
            _job_id: Uuid,
            _attempt: u32,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            Box::pin(async { Ok(ResultWriteOutcome::Applied) })
        }
        fn enqueue_scan<'a>(
            &'a self,
            _artifact_id: Uuid,
            _repository_id: Uuid,
            _content_hash: &'a ContentHash,
            _format: &'a str,
            _priority: i16,
            _trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            Box::pin(async { Ok(Uuid::nil()) })
        }
        fn last_result_summary_by_kind<'a>(
            &'a self,
            _kind: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<serde_json::Value>>> {
            Box::pin(async { Err(DomainError::Invariant("jobs read unavailable".into())) })
        }
    }

    #[tokio::test]
    async fn a_failing_cursor_read_evaluates_from_the_beginning() {
        let candidates = Arc::new(KeysetCandidates::with_rows(10));
        let ids = candidates.ids();
        let h = rotation_handler(candidates.clone(), Arc::new(CursorReadFails), 2, 2);

        let outcome = h
            .run(&json!({ "mode": "execute" }), ctx())
            .await
            .expect("Ok");
        assert!(
            matches!(outcome, TaskOutcome::Completed { .. }),
            "a failed progress lookup must not fail the sweep"
        );
        assert_eq!(candidates.take_served(), ids[0..4]);
    }

    /// The persisted field name is a contract across server versions: a
    /// summary written before an upgrade has to stay parseable, or the
    /// upgrade silently restarts the pass.
    #[test]
    fn the_cursor_round_trips_through_its_persisted_json_shape() {
        let cursor = SweepCursor {
            after_artifact_id: Uuid::from_u128(9),
        };
        let encoded = serde_json::to_value(cursor).expect("serialize");
        assert_eq!(encoded, cursor_value(cursor.after_artifact_id));
        assert_eq!(
            serde_json::from_value::<SweepCursor>(encoded).expect("deserialize"),
            cursor,
        );
    }

    /// The per-run bound is what the shipped handler carries; the shrunk
    /// values above exist only so the page boundary is testable.
    #[test]
    fn the_shipped_page_size_and_run_cap_are_the_handler_defaults() {
        assert_eq!(BATCH_SIZE, 1000, "design pin: BATCH_SIZE = 1000");
        assert_eq!(
            MAX_BATCHES_PER_TICK, 64,
            "design pin: MAX_BATCHES_PER_TICK = 64"
        );
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
        );
        assert_eq!(h.batch_size, BATCH_SIZE);
        assert_eq!(h.max_batches_per_tick, MAX_BATCHES_PER_TICK);
    }
}
