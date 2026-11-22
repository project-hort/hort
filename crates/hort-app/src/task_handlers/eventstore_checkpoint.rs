//! `eventstore-checkpoint` TaskHandler — the external-anchor
//! *emission* half of the event-chain tamper-evidence design.
//!
//! Composes the pure checkpoint assembly (`hort-domain`
//! `build_checkpoint`) with the three outbound ports the I/O lives
//! behind.
//!
//! [`EventChainHeadReaderPort`] — a consistent-cut snapshot of every
//! live stream's `(stream_id, final_stream_position, head_event_hash)`
//! plus `max_global_position` plus the `StreamSealed` records on
//! `admin-eventstore-retention` since the previous **anchored**
//! checkpoint (the set may be empty, and empty is the steady state:
//! nothing has been sealed since the last anchor). Runtime-DML DSN,
//! `SELECT`-only (the adapter's posture).
//!
//! ## The seal set is a delta, and this cycle supplies the boundary
//!
//! Each checkpoint carries the seals **no anchored checkpoint has
//! carried yet**, not the whole seal history: re-anchoring the history
//! on every tick would grow each anchor object with the seal count and
//! the anchor store with seals x ticks, permanently — the checkpoint
//! leaves through [`CheckpointEmitterPort::emit`] rather than
//! `EventStore::append`, so no event cap bounds it.
//!
//! The boundary is [`anchored_retention_position`] over the checkpoints
//! step 1 of [`EventstoreCheckpointHandler::emit_once`] already read, so
//! it costs no extra I/O and **only an anchored checkpoint moves it**.
//! That is what makes catch-up structural: a cycle that fails to emit
//! writes no anchor, the boundary stands, and the next successful cycle
//! carries the failed one's seals too.
//!
//! The verifier needs no counterpart change: it unions the sealed sets
//! of *every* signature-verified checkpoint and asks only that each live
//! seal be anchored by *some* checkpoint, and the checkpoint that first
//! carried a seal carries it forever.
//!
//! [`CheckpointAnchorPort`] — the read port, reused byte-unchanged to
//! derive the next monotonic `checkpoint_seq` (max existing + 1) and
//! the first-post-migration test (no prior checkpoint ⇒ attach the
//! `backfill_baseline` honesty caveat).
//!
//! [`CheckpointEmitterPort`] — the **additive** sign + S3-Object-Lock
//! WORM write (the verifier↔emitter `SignedBody` contract pin lives in
//! the same crate as the reader, so it cannot drift).
//!
//! ## Cadence / trigger
//!
//! Default **hourly**, driven by an external k8s CronJob via the
//! admin-task framework (`POST /api/v1/admin/tasks/eventstore-checkpoint`
//! → `jobs` row → this handler) — **no in-process scheduler**. One
//! checkpoint per tick.
//!
//! ## Post-sweep emission hook (DEFINED here, CALLED by
//! `EventStoreArchiveHandler`)
//!
//! A `StreamSealed` tombstone is tamper-evident only once a checkpoint
//! that post-dates it anchors its head; until then the offline verifier
//! records `AnchorBreak::SealUnanchored`
//! (`hort_domain::events::chain`). This module **defines the
//! contract** as the public, dependency-injected
//! [`CheckpointEmissionHook`] trait below and supplies the
//! always-available implementation ([`CheckpointEmitterHookAdapter`]);
//! the audit-retention sweep handler
//! (`crates/hort-app/src/task_handlers/eventstore_archive.rs`)
//! **calls** `hook.emit_checkpoint_now()` once per sweep, **after** the
//! sweep's seals have committed. This module does **not** implement
//! that call site.
//!
//! The emission follows the sweep rather than preceding each delete
//! because **no instant between a seal and its delete is observable**:
//! `PgEventStore::seal_and_remove` appends the `StreamSealed` tombstone
//! and runs `DELETE FROM events` inside one transaction, whose
//! atomicity is the point (ADR 0020), while the emitter reads a
//! `REPEATABLE READ` snapshot on its own connection
//! (`PgEventChainHeadReader`) and so can never see the tombstone before
//! the delete commits. The residual window is therefore the sweep's own
//! duration, after which every seal that sweep made is anchored. The
//! sweep emits **once** for the whole pass — each emission is a sign
//! plus an S3 Object-Lock write — and only when it actually sealed
//! something.
//!
//! ## Observability
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
//!
//! ### Unreadable stored evidence is terminal, and visibly so
//!
//! A cycle can fail because the store is unreachable, and because the
//! **stored chain evidence cannot be read back** — the finding this
//! mechanism exists to produce. The `result` label set is a closed
//! three-value enum and stays closed, so the distinction is carried
//! where it already has an operator-visible home:
//!
//! * [`TaskOutcome::Failed`]'s `retry` field — `false` for unreadable
//!   evidence, which the dispatcher counts as `failed_terminal` rather
//!   than `failed_retry` and does not reschedule. Retrying it would
//!   re-read the same bytes for the same verdict and reach terminality
//!   only by exhausting the attempt budget.
//! * a distinct `error!` event carrying `chain_evidence_locus` as a
//!   field, so the alert is a field match rather than a substring match
//!   on a message.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::json;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    anchored_retention_position, build_checkpoint, BackfillBaseline, CheckpointToEmit,
};
use hort_domain::ports::checkpoint_anchor::CheckpointAnchorPort;
use hort_domain::ports::checkpoint_emitter::CheckpointEmitterPort;
use hort_domain::ports::event_chain_head_reader::{
    ChainSnapshotError, CorruptChainEvidence, EventChainHeadReaderPort,
};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

// ---------------------------------------------------------------------------
// Constants — metric (the distinct emission metric, NOT the verify one)
// ---------------------------------------------------------------------------

/// The chain-format version this emitter writes (selects the
/// canonicalizer — v1 is the only format).
const CHAIN_FORMAT_VERSION: &str = "hort-evchain/v1";

/// The distinct emission metric (one-metric-one-layer discipline —
/// **never** `hort_event_chain_verify_total`).
const METRIC_NAME: &str = "hort_event_chain_checkpoint_total";
const RESULT_EMITTED: &str = "emitted";
/// Reserved closed-taxonomy label. **No v1 runtime path emits it**:
/// the signing key is validated at adapter construction and
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
/// label of. `dead_code` is
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
// The backfill-baseline source (operator-provisioned honesty caveat)
// ---------------------------------------------------------------------------

/// The honesty-caveat inputs for the **first** post-migration checkpoint:
/// the max `global_position` the in-migration backfill chained at
/// trust-on-migrate and the migration timestamp. Operator-provisioned
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
    /// boundary the compliance wording refers to.
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
// Post-sweep emission hook (DEFINED here; EventStoreArchiveHandler CALLS it)
// ---------------------------------------------------------------------------

/// Contract for "anchor a checkpoint **now**, unconditionally".
///
/// The audit-retention stream sweep MUST call
/// [`CheckpointEmissionHook::emit_checkpoint_now`] **once, after** the
/// seals of that sweep have committed, so every `StreamSealed`
/// tombstone it wrote is anchored by a checkpoint that post-dates it
/// (otherwise the offline verifier records
/// `AnchorBreak::SealUnanchored` for those seals).
///
/// **After the sweep, not before each delete.** The seal and the delete
/// share one transaction (`PgEventStore::seal_and_remove`, whose
/// atomicity ADR 0020 protects) and this emitter reads its own
/// `REPEATABLE READ` snapshot, so there is no instant between them an
/// independent reader could observe. The window in which the sweep's
/// seals are unanchored is the sweep's own duration.
///
/// This module only **defines** the seam. The sweep handler
/// (`crates/hort-app/src/task_handlers/eventstore_archive.rs`) takes an
/// `Option<Arc<dyn CheckpointEmissionHook>>` and calls it;
/// [`CheckpointEmitterHookAdapter`] is the always-available
/// implementation the composition root wires there, and `None` is the
/// correct wiring wherever checkpoint emission is off (ADR 0057 — where
/// no anchor is expected, a missing checkpoint is not a failure).
pub trait CheckpointEmissionHook: Send + Sync {
    /// Assemble + sign + WORM-anchor one checkpoint immediately.
    ///
    /// `Ok` ⇒ a checkpoint that post-dates every seal so far is
    /// durably anchored.
    ///
    /// `Err` ⇒ the anchoring did not happen. The caller cannot undo
    /// anything in response — its seals are committed and the rows are
    /// gone — so it must neither swallow this nor report a clean sweep:
    /// it surfaces a non-success outcome naming the
    /// sealed-but-unanchored streams. The next scheduled emission
    /// anchors those seals regardless, which makes a failure here a
    /// visibility and latency problem, not a durability one.
    ///
    /// The `Err` does **not** distinguish an unreachable store from
    /// unreadable stored evidence, and needs no such distinction: the
    /// sweep cannot re-seal what it already sealed, so it reports
    /// `retry: false` for either cause. The distinction is logged at the
    /// locus field by the cycle itself, which is where an operator alert
    /// keys on it.
    fn emit_checkpoint_now(&self) -> BoxFuture<'_, DomainResult<()>>;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic + post-sweep checkpoint emission.
/// Constructed at composition time with the three ports it composes +
/// the operator-provisioned backfill baseline.
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
    /// * `anchor_read` — the `CheckpointAnchorPort` (reused
    ///   byte-unchanged) to derive next seq + first-checkpoint.
    /// * `emitter` — the additive sign + WORM-write port.
    /// * `backfill_baseline` — the operator-provisioned honesty caveat,
    ///   attached to the **first** post-migration checkpoint only.
    ///   `None` for a green-field deploy with no pre-chain history.
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
    /// [`TaskHandler::run`] tick and the post-sweep
    /// [`CheckpointEmissionHook`]. Returns the assembled checkpoint on
    /// success (for logging/result-summary), or a typed error that the
    /// callers map to their own outcome shape (`TaskOutcome::Failed` /
    /// `Err`). Emits the distinct metric + the `info!`/`error!` exactly
    /// once per cycle (the single emitter layer).
    async fn emit_once(&self) -> Result<CheckpointToEmit, CheckpointCycleError> {
        // 1. Read every signature-verified existing checkpoint. An empty
        //    set ⇒ first checkpoint (seq 1 + the backfill_baseline). An
        //    operational read
        //    failure aborts the cycle (retryable) — do NOT emit a
        //    seq-1 duplicate against a transiently-unreadable store.
        let existing = self
            .anchor_read
            .read_all()
            .await
            .map_err(CheckpointCycleError::AnchorReadFailed)?;

        // 2. Snapshot the live chain (runtime DSN, SELECT-only), with
        //    the seal read windowed past what an anchored checkpoint
        //    already carried. The boundary comes out of the signed
        //    witness read in step 1 — no extra I/O, and it advances only
        //    when a checkpoint is actually anchored, which is why a
        //    failed cycle's seals land in the next successful one.
        //    A snapshot failure splits in two, and the split is the
        //    reader's own type: the store being unreachable is this
        //    cycle's bad luck, while stored chain evidence that cannot be
        //    read back is the finding this whole anchor mechanism exists
        //    to surface — and reading the same bytes again returns the
        //    same verdict.
        let snapshot = self
            .heads
            .snapshot_live_chain(anchored_retention_position(&existing))
            .await
            .map_err(|e| match e {
                ChainSnapshotError::Unavailable(e) => CheckpointCycleError::HeadSnapshotFailed(e),
                ChainSnapshotError::CorruptEvidence(c) => {
                    CheckpointCycleError::ChainEvidenceCorrupt(c)
                }
            })?;

        // 3. Pure assembly: sorted witness + Merkle root + monotonic seq
        //    + first-only backfill_baseline. The builder
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
/// suffix on the infrastructure variants is intentional and semantically
/// load-bearing (these *are* the closed set of failure modes); renaming
/// to satisfy `enum_variant_names` would lose that meaning.
#[allow(clippy::enum_variant_names)]
enum CheckpointCycleError {
    /// Reading the existing checkpoints failed (store unreachable).
    /// Retryable; metric `anchor_write_failed` (an anchor-store I/O
    /// failure — same class as a write failure for alerting; it is the
    /// anchor store being unreachable, not a signing problem).
    AnchorReadFailed(DomainError),
    /// An infrastructure step of the live-chain snapshot failed — the DB
    /// was unreachable, the read transaction could not be opened or
    /// committed, a query failed. Retryable.
    /// Metric `anchor_write_failed` (an infrastructure read failure
    /// that prevented anchoring — not a signing fault; the closed
    /// 3-value enum has no separate `db_read_failed`, and the spec's
    /// taxonomy is `{emitted, sign_failed, anchor_write_failed}` —
    /// "could not anchor this cycle" is `anchor_write_failed`).
    ///
    /// Carries the infrastructure half **only**: stored evidence that
    /// cannot be read back is [`Self::ChainEvidenceCorrupt`].
    HeadSnapshotFailed(DomainError),
    /// The stored event-chain evidence cannot be read back as the chain
    /// format requires (a chain-hash column of the wrong width, a
    /// `StreamSealed` payload that does not decode).
    ///
    /// **Terminal, not retryable.** The bytes are what they are: a
    /// retry re-reads them, reaches the same verdict, and only spends
    /// the `jobs` row's attempt budget before the dispatcher fails it
    /// anyway — so terminality by exhaustion instead of by decision,
    /// with the transient series firing on the way there. Metric
    /// `anchor_write_failed` (the closed 3-value taxonomy takes no
    /// fourth value); what separates it for an operator is the
    /// dispatcher's `failed_terminal` series and the distinct log event
    /// carrying the corrupt locus.
    ChainEvidenceCorrupt(CorruptChainEvidence),
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
    /// taxonomy and is exercised by the catalog test, but no
    /// runtime path emits it (documented, not faked).
    fn metric_result(&self) -> &'static str {
        match self {
            Self::AnchorReadFailed(_)
            | Self::HeadSnapshotFailed(_)
            | Self::ChainEvidenceCorrupt(_)
            | Self::AnchorWriteFailed(_) => RESULT_ANCHOR_WRITE_FAILED,
        }
    }

    /// Whether the dispatcher should run this cycle again
    /// ([`TaskOutcome::Failed`]'s `retry` field).
    ///
    /// Every infrastructure failure is a property of the moment and
    /// retries; unreadable stored evidence is a property of the bytes
    /// and does not.
    fn retry(&self) -> bool {
        match self {
            Self::AnchorReadFailed(_)
            | Self::HeadSnapshotFailed(_)
            | Self::AnchorWriteFailed(_) => true,
            Self::ChainEvidenceCorrupt(_) => false,
        }
    }

    /// The corrupt-evidence payload, if this cycle found one — the
    /// structured log's locus comes from here rather than from a
    /// substring of [`Self::message`].
    fn corrupt_evidence(&self) -> Option<&CorruptChainEvidence> {
        match self {
            Self::ChainEvidenceCorrupt(c) => Some(c),
            _ => None,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::AnchorReadFailed(e) => format!("reading existing checkpoints failed: {e}"),
            Self::HeadSnapshotFailed(e) => format!("live-chain snapshot failed: {e}"),
            Self::ChainEvidenceCorrupt(c) => format!("live-chain snapshot refused: {c}"),
            Self::AnchorWriteFailed(e) => format!("anchor checkpoint write failed: {e}"),
        }
    }
}

/// `error!` a corrupt-evidence verdict.
///
/// A distinct event from the transient-failure one, with the locus as a
/// **field**: an operator alerts on `chain_evidence_locus` existing
/// rather than on a substring of a message, which is the only thing that
/// distinguished this class before. No key material, no raw bytes — the
/// payload locates the datum and says nothing about its content.
fn log_corrupt_evidence(c: &CorruptChainEvidence, message: &str) {
    tracing::error!(
        chain_evidence_locus = c.locus.as_str(),
        chain_evidence_subject = %c.subject,
        error = %message,
        "stored event-chain evidence is unreadable — NOT a transient \
         outage: this cycle fails terminally, the chain is unattested \
         until the evidence is repaired, and a retry would only re-read \
         the same bytes"
    );
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
                    match e.corrupt_evidence() {
                        // Unreadable stored evidence: terminal, and its
                        // own log event.
                        Some(c) => log_corrupt_evidence(c, &msg),
                        // Unrecoverable for this cycle → error!. The
                        // external CronJob retries on the next tick.
                        None => tracing::error!(
                            error = %msg,
                            "event-chain checkpoint emission failed for this cycle"
                        ),
                    }
                    Ok(TaskOutcome::fail(msg, e.retry()))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Post-sweep hook adapter (the always-available impl the sweep wires)
// ---------------------------------------------------------------------------

/// The always-available [`CheckpointEmissionHook`] implementation.
/// The composition root injects this into the audit-retention sweep
/// handler, which calls
/// [`CheckpointEmissionHook::emit_checkpoint_now`] once after its seals
/// have committed. It runs the **same** emission cycle as the periodic
/// tick (same metric / log / signature contract), so a post-sweep
/// checkpoint is indistinguishable from a scheduled one to the
/// verifier — exactly what is needed (a seal is anchored by whichever
/// checkpoint post-dates it, and nothing about the anchor records which
/// trigger produced it).
pub struct CheckpointEmitterHookAdapter {
    handler: Arc<EventstoreCheckpointHandler>,
}

impl CheckpointEmitterHookAdapter {
    /// Wrap a shared [`EventstoreCheckpointHandler`]. The same handler
    /// instance backs both the periodic tick and the post-sweep hook so
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
                        "post-sweep event-chain checkpoint emitted and WORM-anchored \
                         (a seal must be anchored by a post-dating checkpoint)"
                    );
                    Ok(())
                }
                Err(e) => {
                    emit_metric(e.metric_result());
                    let msg = e.message();
                    match e.corrupt_evidence() {
                        Some(c) => log_corrupt_evidence(c, &msg),
                        None => tracing::error!(
                            error = %msg,
                            "post-sweep event-chain checkpoint emission failed — the \
                             caller's seals are committed and cannot be undone, so it \
                             must report a non-success outcome naming the \
                             sealed-but-unanchored streams; the next scheduled emission \
                             anchors them regardless"
                        ),
                    }
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
    use hort_domain::events::{Checkpoint, EventHash, SealedStreamRecord, StreamHead, StreamId};
    use hort_domain::ports::event_chain_head_reader::{ChainEvidenceLocus, LiveChainSnapshot};
    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use uuid::Uuid;

    // ---- mocks ---------------------------------------------------------

    /// Which class of snapshot failure the mock reader answers with.
    /// The reader's two classes are the premise of the retry assertions
    /// below, so a test names the one it means.
    #[derive(Clone, Copy)]
    enum HeadsFailure {
        /// The store could not be reached — this cycle's bad luck.
        Unavailable,
        /// The stored evidence cannot be read back.
        CorruptEvidence,
    }

    struct MockHeads {
        snapshot: Mutex<Option<LiveChainSnapshot>>,
        fail: Option<HeadsFailure>,
        /// The simulated audit-meta stream: `(stream_position, record)`.
        /// When set, the mock answers the way the adapter does — the head
        /// query sees the whole stream, the seal query is windowed on the
        /// bound it was handed — so a test asserts the cycle's boundary
        /// handling rather than a canned set.
        audit_meta_stream: Option<Vec<(u64, SealedStreamRecord)>>,
        /// Every bound the cycle handed this reader, in call order.
        bounds: Mutex<Vec<Option<u64>>>,
    }
    impl MockHeads {
        fn ok(s: LiveChainSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(Some(s)),
                fail: None,
                audit_meta_stream: None,
                bounds: Mutex::new(vec![]),
            }
        }
        /// The transient half: the DB is unreachable.
        fn failing() -> Self {
            Self::refusing(HeadsFailure::Unavailable)
        }
        /// The corrupt half: the store answered, and what it holds is
        /// not readable as chain evidence.
        fn corrupt() -> Self {
            Self::refusing(HeadsFailure::CorruptEvidence)
        }
        fn refusing(fail: HeadsFailure) -> Self {
            Self {
                snapshot: Mutex::new(None),
                fail: Some(fail),
                audit_meta_stream: None,
                bounds: Mutex::new(vec![]),
            }
        }
        /// A reader backed by a simulated audit-meta stream, windowing
        /// its seal answer exactly as `PgEventChainHeadReader` does.
        fn over_audit_meta_stream(records: Vec<(u64, SealedStreamRecord)>) -> Self {
            Self {
                snapshot: Mutex::new(None),
                fail: None,
                audit_meta_stream: Some(records),
                bounds: Mutex::new(vec![]),
            }
        }
        fn bounds_seen(&self) -> Vec<Option<u64>> {
            self.bounds.lock().unwrap().clone()
        }
    }

    /// The locus the corrupt-evidence fixture reports — a stored chain
    /// hash of the wrong width, the condition the schema `CHECK` is
    /// supposed to make unreachable.
    const CORRUPT_LOCUS: ChainEvidenceLocus = ChainEvidenceLocus::ChainHashColumn;

    fn corrupt_evidence() -> CorruptChainEvidence {
        CorruptChainEvidence::new(CORRUPT_LOCUS, "event_hash", "is 16 bytes, expected 32")
    }

    impl EventChainHeadReaderPort for MockHeads {
        fn snapshot_live_chain(
            &self,
            anchored_retention_position: Option<u64>,
        ) -> BoxFuture<'_, Result<LiveChainSnapshot, ChainSnapshotError>> {
            self.bounds
                .lock()
                .unwrap()
                .push(anchored_retention_position);
            let fail = self.fail;
            let s = match &self.audit_meta_stream {
                // The adapter's two reads over one consistent cut: the
                // head query reports the stream's real head whatever the
                // bound, and only the seal query is windowed. Recording
                // the un-windowed head is what makes the next cycle's
                // boundary advance.
                Some(stream) => {
                    let head = stream.iter().map(|(pos, _)| *pos).max();
                    let heads = head
                        .map(|pos| vec![head_of(&retention_stream_id(), pos, 0xaa)])
                        .unwrap_or_default();
                    let sealed = stream
                        .iter()
                        .filter(|(pos, _)| {
                            anchored_retention_position.is_none_or(|bound| *pos > bound)
                        })
                        .map(|(_, rec)| rec.clone())
                        .collect();
                    Some(LiveChainSnapshot::new(heads, head.unwrap_or(0), sealed))
                }
                None => self.snapshot.lock().unwrap().clone(),
            };
            Box::pin(async move {
                match fail {
                    Some(HeadsFailure::Unavailable) => {
                        Err(ChainSnapshotError::unavailable("db unreachable"))
                    }
                    Some(HeadsFailure::CorruptEvidence) => Err(corrupt_evidence().into()),
                    None => Ok(s.expect("snapshot set")),
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
        head_of(id, pos, b)
    }

    /// `head` under a name the `MockHeads` impl above can call without
    /// shadowing its own `head` local.
    fn head_of(id: &str, pos: u64, b: u8) -> StreamHead {
        StreamHead {
            stream_id: id.to_string(),
            final_stream_position: pos,
            head_event_hash: EventHash([b; 32]),
        }
    }

    fn retention_stream_id() -> String {
        StreamId::eventstore_retention().to_string()
    }

    fn seal(id: &str, b: u8) -> SealedStreamRecord {
        SealedStreamRecord {
            sealed_stream_id: id.to_string(),
            final_event_hash: EventHash([b; 32]),
        }
    }

    /// The emitted checkpoint as the anchor store hands it back on the
    /// next cycle — the same projection `read_all` performs on a
    /// signature-verified object. Using it (rather than a hand-built
    /// `Checkpoint`) is what makes the boundary in these tests come from
    /// the previous tick's own witness.
    fn anchored(cp: &CheckpointToEmit) -> Checkpoint {
        Checkpoint {
            chain_format_version: cp.chain_format_version.clone(),
            checkpoint_seq: cp.checkpoint_seq,
            created_at: cp.created_at,
            stream_heads: cp
                .stream_heads
                .iter()
                .map(|h| {
                    (
                        h.stream_id.clone(),
                        h.final_stream_position,
                        h.head_event_hash,
                    )
                })
                .collect(),
            sealed_streams: cp.sealed_streams.clone(),
        }
    }

    fn sealed_ids(cp: &CheckpointToEmit) -> Vec<&str> {
        cp.sealed_streams
            .iter()
            .map(|s| s.sealed_stream_id.as_str())
            .collect()
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

    // ---- the seal set is a delta on the last ANCHORED checkpoint -------

    /// Run one cycle and return the checkpoint it emitted, plus the
    /// bound the cycle handed the reader.
    fn tick(
        stream: Vec<(u64, SealedStreamRecord)>,
        existing: Vec<Checkpoint>,
        emitter: &Arc<MockEmitter>,
    ) -> (Option<CheckpointToEmit>, Vec<Option<u64>>) {
        let heads = Arc::new(MockHeads::over_audit_meta_stream(stream));
        let h = EventstoreCheckpointHandler::new(
            heads.clone(),
            Arc::new(MockAnchorRead::with(existing)),
            emitter.clone(),
            None,
        );
        rt().block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        (emitter.last(), heads.bounds_seen())
    }

    /// Two successful ticks over a growing audit-meta stream, with the
    /// first tick's emitted checkpoint fed back as the anchor store's
    /// content for the second. Returns `(first, second, bound the second
    /// tick derived)`.
    ///
    /// The second tick's boundary therefore comes from the first tick's
    /// own signed witness rather than from a literal, which is the whole
    /// property under test.
    fn two_ticks(
        first_stream: Vec<(u64, SealedStreamRecord)>,
        second_stream: Vec<(u64, SealedStreamRecord)>,
    ) -> (CheckpointToEmit, CheckpointToEmit, Vec<Option<u64>>) {
        let first_emitter = Arc::new(MockEmitter::ok());
        let (first, first_bounds) = tick(first_stream, vec![], &first_emitter);
        let first = first.expect("tick 1 emitted");
        assert_eq!(
            first_bounds,
            vec![None],
            "with nothing anchored there is no boundary — the first \
             checkpoint carries the whole history"
        );

        let second_emitter = Arc::new(MockEmitter::ok());
        let (second, second_bounds) = tick(second_stream, vec![anchored(&first)], &second_emitter);
        let second = second.expect("tick 2 emitted");
        (first, second, second_bounds)
    }

    /// Two consecutive successful ticks: the second checkpoint carries
    /// ONLY the seals created between the two cuts. Re-anchoring the
    /// whole seal history on every tick is what grows each anchor object
    /// with the seal count and the anchor store with seals x ticks —
    /// and nothing caps a checkpoint, which leaves the emitter rather
    /// than `EventStore::append`.
    #[test]
    fn the_second_checkpoint_carries_only_the_seals_since_the_first() {
        // Tick 1 sees two seals, at audit-meta positions 0 and 1; tick 2
        // sees a third appended at position 2.
        let (cp1, cp2, bounds) = two_ticks(
            vec![(0, seal("admin-gone-a", 1)), (1, seal("admin-gone-b", 2))],
            vec![
                (0, seal("admin-gone-a", 1)),
                (1, seal("admin-gone-b", 2)),
                (2, seal("admin-gone-c", 3)),
            ],
        );
        assert_eq!(sealed_ids(&cp1), vec!["admin-gone-a", "admin-gone-b"]);
        assert_eq!(
            bounds,
            vec![Some(1)],
            "the boundary is the audit-meta head the first checkpoint's \
             own witness anchored"
        );
        assert_eq!(
            sealed_ids(&cp2),
            vec!["admin-gone-c"],
            "the second checkpoint re-anchors nothing the first one \
             already anchored"
        );
    }

    /// Catch-up pin: a cycle that fails to emit writes no anchor, so the
    /// boundary does not advance and the next successful checkpoint
    /// carries the failed cycle's seals too. Without this the property
    /// is convention — and convention is exactly what let the field name
    /// drift from the query it was named after.
    #[test]
    fn a_failed_emission_is_caught_up_by_the_next_successful_one() {
        let failing = Arc::new(MockEmitter::failing());
        let (cp1, bounds1) = tick(
            vec![(0, seal("admin-gone-a", 1)), (1, seal("admin-gone-b", 2))],
            vec![],
            &failing,
        );
        assert!(cp1.is_none(), "the emitter refused — nothing was anchored");
        assert_eq!(bounds1, vec![None]);

        // The anchor store is still empty: a refused emission writes no
        // object, so `read_all` has nothing new to report.
        let ok_emitter = Arc::new(MockEmitter::ok());
        let (cp2, bounds2) = tick(
            vec![
                (0, seal("admin-gone-a", 1)),
                (1, seal("admin-gone-b", 2)),
                (2, seal("admin-gone-c", 3)),
            ],
            vec![],
            &ok_emitter,
        );
        let cp2 = cp2.expect("tick 2 emitted");
        assert_eq!(
            bounds2,
            vec![None],
            "only an ANCHORED checkpoint moves the boundary — a failed \
             tick must not"
        );
        assert_eq!(
            sealed_ids(&cp2),
            vec!["admin-gone-a", "admin-gone-b", "admin-gone-c"],
            "the failed tick's seals have to land in this checkpoint, or \
             they are anchored by none and the verifier reports \
             SealUnanchored forever"
        );
    }

    /// A first seal sits at audit-meta position 0, so the boundary the
    /// next tick derives is `Some(0)` — which has to window it out. A
    /// derivation that collapsed `Some(0)` into "no boundary" would
    /// re-anchor that seal on every tick for the life of the store, and
    /// every assertion above would still pass.
    #[test]
    fn position_zero_boundary_windows_out_the_first_seal() {
        let (cp1, cp2, bounds) = two_ticks(
            vec![(0, seal("admin-gone-a", 1))],
            vec![(0, seal("admin-gone-a", 1)), (1, seal("admin-gone-b", 2))],
        );
        assert_eq!(sealed_ids(&cp1), vec!["admin-gone-a"]);
        assert_eq!(bounds, vec![Some(0)], "0-based: one anchored event is 0");
        assert_eq!(
            sealed_ids(&cp2),
            vec!["admin-gone-b"],
            "a boundary of Some(0) must window out the seal at position 0 \
             — collapsing it into None would re-anchor that seal on every \
             tick for the life of the store"
        );
    }

    /// A tick with nothing sealed since the last anchor emits a
    /// checkpoint with an empty seal delta — the steady state, and the
    /// whole point of the window.
    #[test]
    fn nothing_sealed_since_the_last_anchor_is_an_empty_delta() {
        let (_, cp2, bounds) = two_ticks(
            vec![(0, seal("admin-gone-a", 1))],
            vec![(0, seal("admin-gone-a", 1))],
        );
        assert_eq!(bounds, vec![Some(0)]);
        assert!(
            cp2.sealed_streams.is_empty(),
            "an unchanged audit-meta stream must produce no seal records"
        );
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
        // First checkpoint carries the baseline.
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
            "backfill_baseline is first-checkpoint-only"
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

    // ---- unreadable stored evidence is terminal, an outage is not -----
    //
    // Both halves are asserted, and both are load-bearing: a change that
    // made every failure terminal would satisfy the first alone, and the
    // defect this pair pins was exactly the mirror of that — every
    // failure retryable, with tamper evidence spending an attempt budget
    // to reach the same verdict.

    /// A snapshot refused over unreadable stored evidence fails the
    /// cycle **terminally**, so the dispatcher counts it as
    /// `failed_terminal` and never reschedules it.
    #[test]
    fn corrupt_chain_evidence_is_terminal() {
        let h = EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::corrupt()),
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::ok()),
            None,
        );
        let outcome = rt()
            .block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    !retry,
                    "unreadable stored evidence cannot be fixed by reading it again"
                );
                // The reason is the text an operator reads off the
                // `jobs` row, so it has to locate the datum.
                assert!(reason.contains(CORRUPT_LOCUS.as_str()), "reason={reason}");
                assert!(reason.contains("event_hash"), "reason={reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// The sibling: an unreachable store still retries. Without this the
    /// terminal assertion above is satisfied by a handler that gave up
    /// on every failure, which would turn an S3 or Postgres blip into a
    /// permanently-failed checkpoint row.
    #[test]
    fn a_transient_snapshot_failure_still_retries() {
        let h = EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::failing()),
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::ok()),
            None,
        );
        let outcome = rt()
            .block_on(h.run(&serde_json::Value::Null, ctx()))
            .unwrap();
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "an unreachable store is this cycle's bad luck");
                assert!(
                    !reason.contains(CORRUPT_LOCUS.as_str()),
                    "an outage must not report a corrupt locus: reason={reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// The `result` label set is a closed three-value enum, and the
    /// corrupt-evidence class deliberately takes no fourth value — the
    /// operator-visible split is the dispatcher's result series, not a
    /// new label here. Pin that for **both** classes, so a later change
    /// cannot widen the enum unnoticed.
    #[test]
    fn both_failure_classes_emit_exactly_one_of_the_three_result_values() {
        for (label, heads) in [
            ("corrupt evidence", Arc::new(MockHeads::corrupt())),
            ("unreachable store", Arc::new(MockHeads::failing())),
        ] {
            let h = EventstoreCheckpointHandler::new(
                heads,
                Arc::new(MockAnchorRead::with(vec![])),
                Arc::new(MockEmitter::ok()),
                None,
            );
            let snap = capture(|| {
                rt().block_on(h.run(&serde_json::Value::Null, ctx()))
                    .unwrap();
            });
            let e = snap.into_vec();
            let fired: Vec<&str> = CHECKPOINT_RESULTS
                .into_iter()
                .filter(|r| counter_for(&e, r).is_some())
                .collect();
            assert_eq!(
                fired,
                vec![RESULT_ANCHOR_WRITE_FAILED],
                "{label} must fire exactly one of the closed three values"
            );
            assert!(matches!(
                counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
                Some(DebugValue::Counter(1))
            ));
            // Nothing outside the closed set may appear on this metric.
            let values: Vec<String> = e
                .iter()
                .filter(|(ck, _, _, _)| ck.key().name() == METRIC_NAME)
                .flat_map(|(ck, _, _, _)| {
                    ck.key()
                        .labels()
                        .filter(|l| l.key() == "result")
                        .map(|l| l.value().to_string())
                        .collect::<Vec<_>>()
                })
                .collect();
            assert!(
                values
                    .iter()
                    .all(|v| CHECKPOINT_RESULTS.contains(&v.as_str())),
                "{label} emitted a result value outside the closed set: {values:?}"
            );
        }
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

    // ---- post-sweep hook (DEFINED here; the sweep handler CALLS it) ----

    #[test]
    fn post_sweep_hook_emits_a_checkpoint_on_success() {
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
    fn post_sweep_hook_returns_err_so_the_caller_can_report_it() {
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
                "a failed emission MUST surface Err so the sweep handler can \
                 report a non-success outcome naming the sealed-but-unanchored \
                 streams — it cannot un-delete anything, and a swallowed error \
                 here would read as a clean sweep"
            );
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
    }

    /// The post-sweep hook runs the same cycle, so it reports the same
    /// classes: a corrupt-evidence refusal reaches the sweep as `Err`
    /// (which it reports with `retry: false` of its own accord, since it
    /// cannot re-seal what it already sealed) and fires the same single
    /// metric value.
    #[test]
    fn the_post_sweep_hook_reports_corrupt_evidence_too() {
        let handler = Arc::new(EventstoreCheckpointHandler::new(
            Arc::new(MockHeads::corrupt()),
            Arc::new(MockAnchorRead::with(vec![])),
            Arc::new(MockEmitter::ok()),
            None,
        ));
        let hook = CheckpointEmitterHookAdapter::new(handler);
        let snap = capture(|| {
            let err = rt()
                .block_on(hook.emit_checkpoint_now())
                .expect_err("a refused snapshot must surface Err to the sweep");
            assert!(
                err.to_string().contains(CORRUPT_LOCUS.as_str()),
                "err={err}"
            );
        });
        let e = snap.into_vec();
        assert!(matches!(
            counter_for(&e, RESULT_ANCHOR_WRITE_FAILED),
            Some(DebugValue::Counter(1))
        ));
        assert!(counter_for(&e, RESULT_EMITTED).is_none());
    }

    // ---- catalog test: every closed result value fires -----------------

    #[test]
    fn debugging_recorder_every_result_label_fires() {
        // DebuggingRecorder catalog test asserting each label fires.
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
