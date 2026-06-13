//! `eventstore-checkpoint` TaskHandler — the external-anchor
//! *emission* half of the event-chain tamper-evidence design.
//!
//! Composes the pure §6.2 checkpoint assembly (`hort-domain`
//! `build_checkpoint`) with the three outbound ports the I/O lives
//! behind.
//!
//! [`EventChainHeadReaderPort`] — a consistent-cut snapshot of every
//! live stream's `(stream_id, final_stream_position, head_event_hash)`
//! plus `max_global_position` plus the `StreamSealed` records on
//! `admin-eventstore-retention` since the previous checkpoint (the
//! set may be empty when nothing has been
//! sealed since the previous checkpoint). Runtime-DML DSN, `SELECT`-only
//! (the adapter's posture).
//!
//! [`CheckpointAnchorPort`] — the **shipped Item-3 read** port, reused
//! byte-unchanged to derive the next monotonic `checkpoint_seq` (max
//! existing + 1, §6.4) and the first-post-migration test (no prior
//! checkpoint ⇒ attach the §5 `backfill_baseline` honesty caveat).
//!
//! [`CheckpointEmitterPort`] — the **additive** sign + S3-Object-Lock
//! WORM write (the verifier↔emitter `SignedBody` contract pin lives in
//! the same crate as the reader, so it cannot drift).
//!
//! ## Cadence / trigger (spec §6.3)
//!
//! Default **hourly**, driven by an external k8s CronJob via the
//! admin-task framework (`POST /api/v1/admin/tasks/eventstore-checkpoint`
//! → `jobs` row → this handler) — **no in-process scheduler**. One
//! checkpoint per tick.
//!
//! ## Pre-purge emission hook (DEFINED here, CALLED by the
//! eventstore-retention purge handler)
//!
//! Spec §6.3 also requires an *unconditional* checkpoint **before** any
//! `delete_stream`/`archive_stream` retention purge, so a `StreamSealed`
//! is always anchored by a checkpoint that post-dates it. This item
//! **defines the contract** as the public, dependency-injected
//! [`CheckpointEmissionHook`] trait below; the
//! retention-purge handler **calls** `hook.emit_checkpoint_now()`
//! immediately before it deletes any row (mirroring how the
//! `StreamSealed` obligation is defined in one place and implemented
//! by the retention path). This module does **not** implement that call
//! site; it provides the seam + the always-available implementation
//! ([`CheckpointEmitterHookAdapter`]) the retention handler wires.
//!
//! ## Observability (architect one-metric-one-layer + spec §11)
//!
//! The **distinct** counter `hort_event_chain_checkpoint_total{result}`
//! with `result ∈ {emitted, sign_failed, anchor_write_failed}` is
//! emitted **only here** (the emission-task layer) — never reusing
//! `hort_event_chain_verify_total` (the verifier's metric, a different
//! layer). `info!` on a successful emission (security-relevant state
//! change — seq, max_global_position, stream count, backfill flag; NO
//! key material); `error!` on sign / anchor-write failure
//! (unrecoverable for that cycle). `#[tracing::instrument(skip(...))]`
//! WITHOUT `err` — a failed cycle is a `TaskOutcome::Failed`, not a
//! `Result::Err`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::json;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{build_checkpoint, BackfillBaseline, CheckpointToEmit};
use hort_domain::ports::checkpoint_anchor::CheckpointAnchorPort;
use hort_domain::ports::checkpoint_emitter::CheckpointEmitterPort;
use hort_domain::ports::event_chain_head_reader::EventChainHeadReaderPort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

// ---------------------------------------------------------------------------
// Constants — metric (the distinct emission metric, NOT the verify one)
// ---------------------------------------------------------------------------

/// The chain-format version this emitter writes (selects the
/// canonicalizer, spec §3.3 — v1 is the only format).
const CHAIN_FORMAT_VERSION: &str = "hort-evchain/v1";

/// The distinct emission metric (architect one-metric-one-layer; spec
/// §11 reserved-name discipline — **never** `hort_event_chain_verify_total`).
const METRIC_NAME: &str = "hort_event_chain_checkpoint_total";
const RESULT_EMITTED: &str = "emitted";
/// Reserved closed-taxonomy label (spec §11). **No v1 runtime path
/// emits it**: the signing key is validated at adapter construction and
/// ed25519 signing of an in-memory `Vec` is infallible, so a cycle
/// cannot reach a sign fault at run time. It is part of the catalog row
/// and exercised by the `DebuggingRecorder` catalog test so the metric
/// schema is complete and a future signing-fault surface has a
/// pre-reserved label (documented, not faked). `dead_code` is allowed
/// for exactly this reason — the constant is referenced only from
/// `CHECKPOINT_RESULTS` (the catalog-test vector) in v1.
#[allow(dead_code)]
const RESULT_SIGN_FAILED: &str = "sign_failed";
const RESULT_ANCHOR_WRITE_FAILED: &str = "anchor_write_failed";

/// The three closed `result` values, in catalog order. The single
/// source of truth the `DebuggingRecorder` catalog test asserts each
/// label of (design §4 last-paragraph obligation). `dead_code` is
/// allowed: in v1 it is referenced only from the test (the
/// `sign_failed` arm has no runtime path — see [`RESULT_SIGN_FAILED`]).
#[allow(dead_code)]
pub(crate) const CHECKPOINT_RESULTS: [&str; 3] = [
    RESULT_EMITTED,
    RESULT_SIGN_FAILED,
    RESULT_ANCHOR_WRITE_FAILED,
];

/// Emit `hort_event_chain_checkpoint_total{result}` exactly once per
/// emission cycle. **The single emitter** for this metric (this
/// `hort-app` emission-task layer). Pure mapping; no I/O.
fn emit_metric(result: &'static str) {
    metrics::counter!(METRIC_NAME, "result" => result).increment(1);
}

// ---------------------------------------------------------------------------
// The §5 backfill-baseline source (operator-provisioned honesty caveat)
// ---------------------------------------------------------------------------

/// The §5 honesty-caveat inputs the **first** post-migration checkpoint
/// records: the max `global_position` the in-migration backfill chained
/// at trust-on-migrate and the migration timestamp. Operator-provisioned
/// (the migration recorded these); passed to the handler at composition
/// time. `None` ⇒ the deployment has no recorded baseline (e.g. a
/// green-field deploy where the chain was present from the first event)
/// — the first checkpoint then carries no `backfill_baseline`, which is
/// correct (there is no pre-chain history to caveat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillBaselineConfig {
    /// Max `events.global_position` the in-migration backfill covered.
    pub baseline_max_global_position: u64,
    /// The migration timestamp — the "tamper-evident from `<this>`"
    /// boundary the compliance wording refers to (spec §5).
    pub migration_timestamp: DateTime<Utc>,
}

impl BackfillBaselineConfig {
    fn to_domain(&self) -> BackfillBaseline {
        BackfillBaseline {
            baseline_max_global_position: self.baseline_max_global_position,
            migration_timestamp: self.migration_timestamp,
        }
    }
}

// ---------------------------------------------------------------------------
// Pre-purge emission hook (DEFINED here; the retention purge CALLS it)
// ---------------------------------------------------------------------------

/// Contract for "anchor a checkpoint **now**, unconditionally".
/// The `delete_stream`/`archive_stream`
/// retention path MUST call [`CheckpointEmissionHook::emit_checkpoint_now`]
/// **before** it deletes any row, so the just-appended `StreamSealed`
/// tombstone is anchored by a checkpoint that post-dates it (otherwise
/// the offline verifier reports `Broken`, not `SealedGap`).
///
/// This module only **defines** the seam.
/// The retention path injects an `Arc<dyn CheckpointEmissionHook>` into its
/// purge handler and calls it; this module does **not** implement that
/// call site. [`CheckpointEmitterHookAdapter`] is the always-available
/// implementation the retention handler wires.
pub trait CheckpointEmissionHook: Send + Sync {
    /// Assemble + sign + WORM-anchor one checkpoint immediately. `Ok`
    /// ⇒ a checkpoint that post-dates every seal so far is durably
    /// anchored; the caller (the retention purge) may then proceed to delete.
    /// `Err` ⇒ the caller MUST abort the purge (deleting without an
    /// anchoring checkpoint would make the chain `Broken`).
    fn emit_checkpoint_now(&self) -> BoxFuture<'_, DomainResult<()>>;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic + pre-purge checkpoint emission
/// (spec §6). Constructed at composition time with the three ports it
/// composes + the operator-provisioned §5 baseline.
pub struct EventstoreCheckpointHandler {
    heads: Arc<dyn EventChainHeadReaderPort>,
    anchor_read: Arc<dyn CheckpointAnchorPort>,
    emitter: Arc<dyn CheckpointEmitterPort>,
    backfill_baseline: Option<BackfillBaselineConfig>,
}

impl EventstoreCheckpointHandler {
    /// Construct the handler.
    ///
    /// * `heads` — live-chain snapshot port (runtime DML DSN, SELECT-only).
    /// * `anchor_read` — the **shipped Item-3** `CheckpointAnchorPort`
    ///   (reused byte-unchanged) to derive next seq + first-checkpoint.
    /// * `emitter` — the additive sign + WORM-write port.
    /// * `backfill_baseline` — the §5 operator-provisioned honesty
    ///   caveat, attached to the **first** post-migration checkpoint
    ///   only. `None` for a green-field deploy with no pre-chain history.
    pub fn new(
        heads: Arc<dyn EventChainHeadReaderPort>,
        anchor_read: Arc<dyn CheckpointAnchorPort>,
        emitter: Arc<dyn CheckpointEmitterPort>,
        backfill_baseline: Option<BackfillBaselineConfig>,
    ) -> Self {
        Self {
            heads,
            anchor_read,
            emitter,
            backfill_baseline,
        }
    }

    /// The shared emission cycle, callable from both the
    /// [`TaskHandler::run`] tick and the pre-purge
    /// [`CheckpointEmissionHook`]. Returns the assembled checkpoint on
    /// success (for logging/result-summary), or a typed error that the
    /// callers map to their own outcome shape (`TaskOutcome::Failed` /
    /// `Err`). Emits the distinct metric + the `info!`/`error!` exactly
    /// once per cycle (the single emitter layer).
    async fn emit_once(&self) -> Result<CheckpointToEmit, CheckpointCycleError> {
        // 1. Read every signature-verified existing checkpoint (the
        //    shipped Item-3 read port). An empty set ⇒ first checkpoint
        //    (seq 1 + the §5 backfill_baseline). An operational read
        //    failure aborts the cycle (retryable) — do NOT emit a
        //    seq-1 duplicate against a transiently-unreadable store.
        let existing = self
            .anchor_read
            .read_all()
            .await
            .map_err(CheckpointCycleError::AnchorReadFailed)?;

        // 2. Snapshot the live chain (runtime DSN, SELECT-only).
        let snapshot = self
            .heads
            .snapshot_live_chain()
            .await
            .map_err(CheckpointCycleError::HeadSnapshotFailed)?;

        // 3. Pure §6.2 assembly: sorted witness + Merkle root +
        //    monotonic seq + first-only backfill_baseline. The builder
        //    defensively drops the baseline on any non-first checkpoint.
        let backfill = self
            .backfill_baseline
            .as_ref()
            .map(BackfillBaselineConfig::to_domain);
        let checkpoint = build_checkpoint(
            CHAIN_FORMAT_VERSION,
            &existing,
            &snapshot.heads,
            &snapshot.sealed_since_previous,
            snapshot.max_global_position,
            Utc::now(),
            backfill,
        );

        // 4. Sign + WORM-anchor (the additive emitter port — shares the
        //    SignedBody contract pin with the Item-3 reader). A failure
        //    here is `anchor_write_failed` (the sign step is infallible
        //    once the key parsed at construction; ed25519 signing of a
        //    Vec cannot fail — so a failure from `emit` is the
        //    anchor-store write, the only fallible step).
        self.emitter
            .emit(&checkpoint)
            .await
            .map_err(CheckpointCycleError::AnchorWriteFailed)?;

        Ok(checkpoint)
    }
}

/// Why an emission cycle failed (maps to the distinct metric `result`,
/// the structured log, and the caller's outcome shape). The `*Failed`
/// suffix on every variant is intentional and semantically load-bearing
/// (these *are* the closed set of failure modes); renaming to satisfy
/// `enum_variant_names` would lose that meaning.
#[allow(clippy::enum_variant_names)]
enum CheckpointCycleError {
    /// Reading the existing checkpoints failed (store unreachable).
    /// Retryable; metric `anchor_write_failed` (an anchor-store I/O
    /// failure — same class as a write failure for alerting; it is the
    /// anchor store being unreachable, not a signing problem).
    AnchorReadFailed(DomainError),
    /// Snapshotting the live chain failed (DB unreachable). Retryable.
    /// Metric `anchor_write_failed` (an infrastructure read failure
    /// that prevented anchoring — not a signing fault; the closed
    /// 3-value enum has no separate `db_read_failed`, and the spec's
    /// taxonomy is `{emitted, sign_failed, anchor_write_failed}` —
    /// "could not anchor this cycle" is `anchor_write_failed`).
    HeadSnapshotFailed(DomainError),
    /// The emitter could not durably write the signed object.
    /// Retryable; metric `anchor_write_failed`.
    AnchorWriteFailed(DomainError),
}

impl CheckpointCycleError {
    /// The distinct-metric `result` label for this failure.
    ///
    /// `sign_failed` is reserved for a future signing-fault surface: in
    /// v1 the signing key is validated at adapter construction and
    /// ed25519 signing of an in-memory `Vec` is infallible, so no cycle
    /// can reach a sign fault at run time — the label is in the closed
    /// taxonomy (spec §11) and is exercised by the catalog test, but no
    /// runtime path emits it (documented, not faked).
    fn metric_result(&self) -> &'static str {
        match self {
            Self::AnchorReadFailed(_)
            | Self::HeadSnapshotFailed(_)
            | Self::AnchorWriteFailed(_) => RESULT_ANCHOR_WRITE_FAILED,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::AnchorReadFailed(e) => format!("reading existing checkpoints failed: {e}"),
            Self::HeadSnapshotFailed(e) => format!("live-chain snapshot failed: {e}"),
            Self::AnchorWriteFailed(e) => format!("anchor checkpoint write failed: {e}"),
        }
    }
}

impl TaskHandler for EventstoreCheckpointHandler {
    fn kind(&self) -> &'static str {
        "eventstore-checkpoint"
    }

    #[tracing::instrument(skip(self, _params, _ctx))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            match self.emit_once().await {
                Ok(cp) => {
                    emit_metric(RESULT_EMITTED);
                    // Security-relevant state change → info!. NO key
                    // material; only the public checkpoint metadata.
                    tracing::info!(
                        checkpoint_seq = cp.checkpoint_seq,
                        max_global_position = cp.max_global_position,
                        stream_count = cp.stream_heads.len(),
                        sealed_count = cp.sealed_streams.len(),
                        backfill_baseline = cp.backfill_baseline.is_some(),
                        "event-chain checkpoint emitted and WORM-anchored"
                    );
                    Ok(TaskOutcome::Completed {
                        result_summary: json!({
                            "checkpoint_seq": cp.checkpoint_seq,
                            "max_global_position": cp.max_global_position,
                            "stream_count": cp.stream_heads.len(),
                            "sealed_count": cp.sealed_streams.len(),
                            "backfill_baseline": cp.backfill_baseline.is_some(),
                        }),
                    })
                }
                Err(e) => {
                    emit_metric(e.metric_result());
                    let msg = e.message();
                    // Unrecoverable for this cycle → error!. The external
                    // CronJob retries on the next tick (Failed{retry:true}).
                    tracing::error!(
                        error = %msg,
                        "event-chain checkpoint emission failed for this cycle"
                    );
                    Ok(TaskOutcome::fail(msg, true))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Pre-purge hook adapter (the always-available impl the retention purge wires)
// ---------------------------------------------------------------------------

/// The always-available [`CheckpointEmissionHook`] implementation.
/// The eventstore-retention path injects this into its purge handler and
/// calls [`CheckpointEmissionHook::emit_checkpoint_now`] before deleting
/// any row. It runs the **same** emission cycle as the periodic tick
/// (same metric / log / signature contract), so a pre-purge checkpoint
/// is indistinguishable from a scheduled one to the verifier — exactly
/// what spec §2.3 needs (a seal is always anchored by a checkpoint that
/// post-dates it).
pub struct CheckpointEmitterHookAdapter {
    handler: Arc<EventstoreCheckpointHandler>,
}

impl CheckpointEmitterHookAdapter {
    /// Wrap a shared [`EventstoreCheckpointHandler`]. The same handler
    /// instance backs both the periodic tick and the pre-purge hook so
    /// there is exactly one emission code path.
    pub fn new(handler: Arc<EventstoreCheckpointHandler>) -> Self {
        Self { handler }
    }
}

impl CheckpointEmissionHook for CheckpointEmitterHookAdapter {
    fn emit_checkpoint_now(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            match self.handler.emit_once().await {
                Ok(cp) => {
                    emit_metric(RESULT_EMITTED);
                    tracing::info!(
                        checkpoint_seq = cp.checkpoint_seq,
                        max_global_position = cp.max_global_position,
                        stream_count = cp.stream_heads.len(),
                        sealed_count = cp.sealed_streams.len(),
                        backfill_baseline = cp.backfill_baseline.is_some(),
                        "pre-purge event-chain checkpoint emitted and WORM-anchored \
                         (spec §2.3 — a seal must be anchored by a post-dating checkpoint)"
                    );
                    Ok(())
                }
                Err(e) => {
                    emit_metric(e.metric_result());
                    let msg = e.message();
                    tracing::error!(
                        error = %msg,
                        "pre-purge event-chain checkpoint emission failed — the \
                         caller MUST abort the retention purge (deleting without \
                         an anchoring checkpoint would make the chain Broken)"
                    );
                    Err(DomainError::Invariant(msg))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use chrono::TimeZone;
    use hort_domain::events::{Checkpoint, EventHash, SealedStreamRecord, StreamHead};
    use hort_domain::ports::event_chain_head_reader::LiveChainSnapshot;
    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use uuid::Uuid;

    // ---- mocks ---------------------------------------------------------

    struct MockHeads {
        snapshot: Mutex<Option<LiveChainSnapshot>>,
        fail: bool,
    }
    impl MockHeads {
        fn ok(s: LiveChainSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(Some(s)),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                snapshot: Mutex::new(None),
                fail: true,
            }
        }
    }
    impl EventChainHeadReaderPort for MockHeads {
        fn snapshot_live_chain(&self) -> BoxFuture<'_, DomainResult<LiveChainSnapshot>> {
            let fail = self.fail;
            let s = self.snapshot.lock().unwrap().clone();
            Box::pin(async move {
                if fail {
                    Err(DomainError::Invariant("db unreachable".into()))
                } else {
                    Ok(s.expect("snapshot set"))
                }
            })
        }
    }

    struct MockAnchorRead {
        existing: Vec<Checkpoint>,
        fail: bool,
    }
    impl MockAnchorRead {
        fn with(existing: Vec<Checkpoint>) -> Self {
            Self {
                existing,
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                existing: vec![],
                fail: true,
            }
        }
    }
    impl CheckpointAnchorPort for MockAnchorRead {
        fn read_all(&self) -> BoxFuture<'_, DomainResult<Vec<Checkpoint>>> {
            let fail = self.fail;
            let cps = self.existing.clone();
            Box::pin(async move {
                if fail {
                    Err(DomainError::Invariant("anchor store unreachable".into()))
                } else {
                    Ok(cps)
                }
            })
        }
    }

    struct MockEmitter {
        captured: Mutex<Vec<CheckpointToEmit>>,
        fail: bool,
    }
    impl MockEmitter {
        fn ok() -> Self {
            Self {
                captured: Mutex::new(vec![]),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                captured: Mutex::new(vec![]),
                fail: true,
            }
        }
        fn last(&self) -> Option<CheckpointToEmit> {
            self.captured.lock().unwrap().last().cloned()
        }
    }
    impl CheckpointEmitterPort for MockEmitter {
        fn emit<'a>(&'a self, checkpoint: &'a CheckpointToEmit) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                if self.fail {
                    Err(DomainError::Invariant("worm write rejected".into()))
                } else {
                    self.captured.lock().unwrap().push(checkpoint.clone());
                    Ok(())
                }
            })
        }
    }

    fn head(id: &str, pos: u64, b: u8) -> StreamHead {
        StreamHead {
            stream_id: id.to_string(),
            final_stream_position: pos,
            head_event_hash: EventHash([b; 32]),
        }
    }

    fn cp(seq: u64) -> Checkpoint {
        Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: seq,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            stream_heads: vec![],
            sealed_streams: vec![],
        }
    }

    fn baseline_cfg() -> BackfillBaselineConfig {
        BackfillBaselineConfig {
            baseline_max_global_position: 4242,
            migration_timestamp: Utc.timestamp_opt(1_699_000_000, 0).unwrap(),
        }
    }

    fn ctx() -> TaskContext {
        use hort_domain::events::system_actor;
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "eventstore-checkpoint".into(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "cron".into(),
                attempts: 1,
                created_at: now,
                updated_at: now,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn counter_for<'a>(entries: &'a [MetricEntry], result: &str) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != METRIC_NAME {
                return None;
            }
            ck.key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == result)
                .then_some(dv)
        })
    }

    fn capture<F: FnOnce()>(f: F) -> Snapshot {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snap.snapshot()
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    // ---- kind ----------------------------------------------------------

    #[test]
    fn kind_is_eventstore_checkpoint_hyphenated() {
        let h = EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::ok(LiveChainSnapshot::new(vec![], 0, vec![]))),
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::ok()),
            None,
        );
        assert_eq!(h.kind(), "eventstore-checkpoint");
    }

    // ---- first checkpoint: seq 1 + backfill_baseline -------------------

    #[test]
    fn first_checkpoint_is_seq_1_with_backfill_baseline() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("admin-b", 3, 2), head("admin-a", 1, 1)],
            12_345,
            vec![],
        )));
        let emitter = Arc::new(MockEmitter::ok());
        let h = EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![])), // none → first
            emitter.clone(),
            Some(baseline_cfg()),
        );
        let snap = capture(|| {
            let outcome = rt()
                .block_on(h.run(&serde_json::Value::Null, ctx()))
                .unwrap();
            assert!(
                matches!(outcome, TaskOutcome::Completed { .. }),
                "first checkpoint emission must Complete"
            );
        });
        let cp = emitter.last().expect("emitter received a checkpoint");
        assert_eq!(cp.checkpoint_seq, 1);
        assert_eq!(cp.max_global_position, 12_345);
        // Witness must be stream_id-sorted.
        let ids: Vec<&str> = cp
            .stream_heads
            .iter()
            .map(|h| h.stream_id.as_str())
            .collect();
        assert_eq!(ids, vec!["admin-a", "admin-b"]);
        // §5: first checkpoint carries the baseline.
        let b = cp.backfill_baseline.expect("first checkpoint has baseline");
        assert_eq!(b.baseline_max_global_position, 4242);
        // Metric: exactly `emitted`.
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_EMITTED),
            Some(DebugValue::Counter(1))
        ));
        assert!(counter_for(&e, RESULT_SIGN_FAILED).is_none());
        assert!(counter_for(&e, RESULT_ANCHOR_WRITE_FAILED).is_none());
    }

    // ---- second checkpoint: seq increments, NO baseline ----------------

    #[test]
    fn second_checkpoint_increments_seq_and_drops_baseline() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("admin-a", 9, 7)],
            99,
            vec![],
        )));
        let emitter = Arc::new(MockEmitter::ok());
        let h = EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![cp(1), cp(2)])), // → seq 3
            emitter.clone(),
            Some(baseline_cfg()), // passed, but NOT first → dropped
        );
        let outcome = rt()
            .block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));
        let cp = emitter.last().unwrap();
        assert_eq!(cp.checkpoint_seq, 3);
        assert_eq!(
            cp.backfill_baseline, None,
            "§5: backfill_baseline is first-checkpoint-only"
        );
    }

    // ---- sealed_streams empty-ok (nothing sealed since last tick) ------

    #[test]
    fn empty_sealed_set_is_valid() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("s", 0, 1)],
            1,
            vec![], // nothing sealed since the previous checkpoint
        )));
        let emitter = Arc::new(MockEmitter::ok());
        let h = EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![])),
            emitter.clone(),
            None,
        );
        let outcome = rt()
            .block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));
        assert!(emitter.last().unwrap().sealed_streams.is_empty());
    }

    #[test]
    fn sealed_records_are_carried_into_the_checkpoint() {
        let sealed = vec![SealedStreamRecord {
            sealed_stream_id: "authorization-gone".into(),
            final_event_hash: EventHash([0xcd; 32]),
        }];
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("s", 0, 1)],
            5,
            sealed.clone(),
        )));
        let emitter = Arc::new(MockEmitter::ok());
        let h = EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![cp(1)])),
            emitter.clone(),
            None,
        );
        rt().block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        assert_eq!(emitter.last().unwrap().sealed_streams, sealed);
    }

    // ---- failure paths: metric + Failed{retry:true} --------------------

    #[test]
    fn anchor_write_failure_emits_metric_and_failed_retry() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("s", 0, 1)],
            1,
            vec![],
        )));
        let h = EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::failing()),
            None,
        );
        let snap = capture(|| {
            let outcome = rt()
                .block_on(h.run(&serde_json::Value::Null, ctx()))
                .unwrap();
            match outcome {
                TaskOutcome::Failed { retry, reason } => {
                    assert!(retry, "anchor write failure is retryable");
                    assert!(reason.contains("anchor checkpoint write failed"));
                }
                _ => panic!("expected Failed"),
            }
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
        assert!(counter_for(&e, RESULT_EMITTED).is_none());
    }

    #[test]
    fn head_snapshot_failure_is_failed_retry_with_metric() {
        let h = EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::failing()),
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::ok()),
            None,
        );
        let snap = capture(|| {
            let outcome = rt()
                .block_on(h.run(&serde_json::Value::Null, ctx()))
                .unwrap();
            assert!(matches!(outcome, TaskOutcome::Failed { retry: true, .. }));
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
    }

    #[test]
    fn anchor_read_failure_aborts_cycle_retryable() {
        // A transiently-unreadable anchor store must NOT emit a fresh
        // seq-1 duplicate — the cycle aborts (retryable).
        let h = EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::ok(LiveChainSnapshot::new(vec![], 0, vec![]))),
            Arc::new(MockAnchorRead::failing()),
            Arc::new(MockEmitter::ok()),
            None,
        );
        let snap = capture(|| {
            let outcome = rt()
                .block_on(h.run(&serde_json::Value::Null, ctx()))
                .unwrap();
            assert!(matches!(outcome, TaskOutcome::Failed { retry: true, .. }));
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
    }

    // ---- pre-purge hook (DEFINED here; the retention purge CALLS it) ----

    #[test]
    fn pre_purge_hook_emits_a_checkpoint_on_success() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("s", 0, 1)],
            7,
            vec![],
        )));
        let emitter = Arc::new(MockEmitter::ok());
        let handler = Arc::new(EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![cp(1)])),
            emitter.clone(),
            None,
        ));
        let hook = CheckpointEmitterHookAdapter::new(handler);
        let snap = capture(|| {
            rt().block_on(hook.emit_checkpoint_now()).unwrap();
        });
        assert_eq!(emitter.last().unwrap().checkpoint_seq, 2);
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_EMITTED),
            Some(DebugValue::Counter(1))
        ));
    }

    #[test]
    fn pre_purge_hook_returns_err_so_caller_aborts_purge() {
        let heads = Arc::new(MockHeads::ok(LiveChainSnapshot::new(
            vec![head("s", 0, 1)],
            1,
            vec![],
        )));
        let handler = Arc::new(EventstoreCheckpointHandler::new(
            heads,
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::failing()),
            None,
        ));
        let hook = CheckpointEmitterHookAdapter::new(handler);
        let snap = capture(|| {
            let r = rt().block_on(hook.emit_checkpoint_now());
            assert!(
                r.is_err(),
                "a failed pre-purge emission MUST surface Err so the retention \
                 purge aborts (deleting unanchored ⇒ Broken chain)"
            );
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
    }

    // ---- catalog test: every closed result value fires -----------------

    #[test]
    fn debugging_recorder_every_result_label_fires() {
        // Architect / design §4 last-paragraph obligation: a
        // DebuggingRecorder test asserting each catalog label fires.
        for r in CHECKPOINT_RESULTS {
            let snap = capture(|| emit_metric(r));
            let e = snap.into_vec();
            assert!(
                matches!(counter_for(&e, r), Some(DebugValue::Counter(1))),
                "result={r} must fire exactly one counter increment"
            );
        }
        assert_eq!(
            CHECKPOINT_RESULTS,
            ["emitted", "sign_failed", "anchor_write_failed"],
            "the closed result taxonomy must match the metrics-catalog row"
        );
    }
}
