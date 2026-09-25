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
//! 2. `RetentionPolicyProjectionRepository::list_active()` → the
//!    active retention policies (O(1) projection read, NOT a stream
//!    replay).
//! 3. Loop `RetentionCandidateReader::list_candidates(BATCH_SIZE,
//!    cursor, now)` advancing the keyset cursor until a short page (a
//!    per-tick total cap bounds one tick; the daily cron drains any
//!    backlog — identical posture to cron-rescan's single-shot cap).
//! 4. Per batch, map `RetentionCandidateRow → RetentionUseCase::
//!    RetentionCandidate` (a trivial field copy — the type stays in
//!    `hort-app`) and call
//!    `RetentionUseCase::evaluate_policies_in_mode(now, &policies,
//!    &candidates, mode)`, accumulating the per-batch [`EvaluateSummary`]
//!    and matched rows.
//! 5. For a dry run, simulate the purge refcount decision and build a
//!    bounded operator sample; for execution, append expiry events at the
//!    same use-case boundary used before modes existed.
//! 6. Return [`TaskOutcome::Completed`] with the projected JSON.
//!
//! The handler appends nothing directly — `evaluate_policies_in_mode` owns
//! the `ArtifactExpired` append in execute mode and suppresses that append
//! in dry-run mode. No new metrics are introduced; the handler returns
//! `result_summary` JSON only.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use serde_json::json;

use hort_domain::error::DomainResult;
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
/// `BATCH_SIZE` (a single tick fetches in 1000-row pages). The daily
/// cron drains backlog across runs; one tick cannot walk the entire
/// artifact table unbounded — see [`MAX_BATCHES_PER_TICK`].
const BATCH_SIZE: u32 = 1000;

/// Per-tick batch cap: at most this many keyset pages per invocation
/// (`MAX_BATCHES_PER_TICK * BATCH_SIZE` artifacts). Bounds one tick's
/// work even on a huge table; subsequent daily ticks drain the rest
/// (the cron-rescan single-shot-cap posture, applied to a keyset loop
/// because retention has no in-flight-job dedup to bound re-visits).
const MAX_BATCHES_PER_TICK: usize = 64;

/// The curation queue's listing cap is the operator-facing precedent for a
/// bounded sanity-check sample.
const MAX_SAMPLE_SIZE: usize = 500;

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

/// [`TaskHandler`] for the periodic retention-evaluate sweep.
pub struct RetentionEvaluateHandler {
    policies: Arc<dyn RetentionPolicyProjectionRepository>,
    candidates: Arc<dyn RetentionCandidateReader>,
    retention: Arc<RetentionUseCase>,
    preview: Arc<dyn RetentionPreview>,
    storage: Arc<dyn StoragePort>,
}

impl RetentionEvaluateHandler {
    pub fn new(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
        retention: Arc<RetentionUseCase>,
        preview: Arc<dyn RetentionPreview>,
        storage: Arc<dyn StoragePort>,
    ) -> Self {
        Self {
            policies,
            candidates,
            retention,
            preview,
            storage,
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

            let policies = match self.policies.list_active().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "retention-evaluate: list_active failed");
                    return Ok(TaskOutcome::fail(format!("list_active failed: {e}"), true));
                }
            };
            if policies.is_empty() {
                // Steady state: no policies configured → no-op.
                tracing::info!("retention-evaluate: no active policies — no-op");
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "policies": 0,
                        "mode": mode.as_str(),
                        "coverage": "complete",
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
            let mut cursor: Option<uuid::Uuid> = None;
            let mut coverage_complete = true;
            for batch_index in 0..MAX_BATCHES_PER_TICK {
                let rows = match self
                    .candidates
                    .list_candidates(BATCH_SIZE, cursor, now)
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
                    break;
                }
                cursor = rows.last().map(|r| r.artifact.id);
                let short_page = (rows.len() as u32) < BATCH_SIZE;

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
                    break;
                }
                if batch_index + 1 == MAX_BATCHES_PER_TICK {
                    coverage_complete = false;
                }
            }

            tracing::info!(
                policies = policies.len(),
                evaluated = total.evaluated,
                expired = total.expired,
                already_expired = total.already_expired,
                skipped_protected = total.skipped_protected,
                skipped_stale_scan = total.skipped_stale_scan,
                errors = total.errors,
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
        }

        let mut groups: BTreeMap<(uuid::Uuid, uuid::Uuid), Group> = BTreeMap::new();
        let mut distinct_contents = BTreeSet::new();
        let mut artifact_ids = BTreeSet::new();
        let mut sample = Vec::new();

        for hit in matches {
            let group = groups
                .entry((hit.policy_id, hit.repository_id))
                .or_default();
            group.policy_name.clone_from(&hit.policy_name);
            group.repository_key.clone_from(&hit.repository_key);
            group.rows += 1;
            group.checksums.insert(hit.checksum_sha256.clone());
            distinct_contents.insert(hit.checksum_sha256.clone());
            artifact_ids.insert(hit.artifact_id);
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
            "groups": group_rows,
            "sample": sample,
            "sample_limit": MAX_SAMPLE_SIZE,
        })
    }
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
    use hort_domain::ports::retention_candidate_reader::RetentionCandidateRow;
    use hort_domain::ports::retention_preview::{
        ObservedCardinality, RetentionContentSimulation, SimulationBound,
    };
    use hort_domain::ports::retention_scan_reader::RetentionScanReader;
    use hort_domain::ports::storage::PutResult;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::retention::RetentionPolicy;
    use hort_domain::types::{ByteRange, ContentHash};
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
        fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!() })
        }
        fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
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
        RetentionEvaluateHandler::new(
            policies,
            candidates,
            retention_uc(),
            Arc::new(InertPreview),
            Arc::new(InertStorage::default()),
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
}
