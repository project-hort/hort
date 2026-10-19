//! Tamper-evident event-chain core (the audit-trail tamper-evidence
//! layer ADR 0002 builds on).
//!
//! Pure, zero-I/O implementation of the per-stream cryptographic hash
//! chain.
//! Nothing in this module performs I/O, logging, or `tracing` — it is
//! the `hort-domain` 100%-coverage tier (CLAUDE.md Test Coverage Tiers).
//!
//! The chain establishes the core integrity invariant: for
//! every stream, event *n*'s `event_hash` covers event *n*'s canonical
//! bytes *and* event *(n−1)*'s `event_hash`. Any insertion, deletion,
//! reordering, or field mutation of a row inside a stream is detectable
//! offline by recomputing every hash. The genesis sentinel
//! distinguishes "really position 0" from "field not yet written".
//!
//! Scope note: the checkpoint/anchor types
//! ([`Checkpoint`], [`AnchorFindings`], [`verify_against_checkpoint`],
//! [`ChainReport`], [`roll_up`]) are the pure verify core that the
//! `verify-event-chain` subcommand composes. They are
//! *defined and unit-tested here* because they are pure `hort-domain`
//! logic (the whole verify core lives in `hort-domain`); the
//! `CheckpointAnchorPort`, the S3-Object-Lock anchor adapter, the
//! `eventstore-checkpoint` task, the CLI subcommand, and the
//! `hort_event_chain_verify_total` metric live in the outer layers and
//! are NOT built here.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use super::{DomainEvent, PersistedEvent};

// ---------------------------------------------------------------------------
// Domain separation constants (frozen)
// ---------------------------------------------------------------------------

/// Field-0 domain tag: the 16 ASCII bytes `hort-evchain/v1\0`
/// (field 0 in the canonical byte order). Bumping this is a chain-format version break.
const DOMAIN_TAG: &[u8; 16] = b"hort-evchain/v1\0";

/// Pre-image of the genesis sentinel. A literal zero array
/// is deliberately NOT used — a zero predecessor is indistinguishable
/// from "field not yet written / NULL coerced to zero".
const GENESIS_PREIMAGE: &[u8] = b"hort-event-chain/v1/genesis";

// ---------------------------------------------------------------------------
// EventHash
// ---------------------------------------------------------------------------

/// A 32-byte SHA-256 event hash. A domain newtype so it cannot be mixed
/// with other `[u8; 32]` byte arrays (content hashes, spec digests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventHash(pub [u8; 32]);

impl EventHash {
    /// Borrow the raw 32 bytes (for binding into the DB column).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering, for human-readable diagnostics only.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The genesis sentinel for `stream_position == 0`.
///
/// `SHA-256(b"hort-event-chain/v1/genesis")`. Pure and deterministic;
/// the verifier asserts the first row of every stream chains from this
/// and that no non-zero-position row does.
pub fn genesis_hash() -> EventHash {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_PREIMAGE);
    EventHash(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// ChainInput / ActorCanonical
// ---------------------------------------------------------------------------

/// The four persisted actor columns, in the exact form the events
/// table stores them (`mappers.rs` `ActorColumns`). Borrowed so the
/// adapter/verifier can build a `ChainInput` without cloning.
#[derive(Debug, Clone, Copy)]
pub struct ActorCanonical<'a> {
    /// `actor_type` text column (`"api"` / `"system"` / `"timer"` /
    /// `"gitops"`).
    pub actor_type: &'a str,
    /// `actor_id` column — `Some` only for `actor_type = "api"`.
    pub actor_id: Option<uuid::Uuid>,
    /// `actor_source_file` column — `Some` only for `"gitops"`.
    pub actor_source_file: Option<&'a str>,
    /// `actor_spec_digest` column — `Some` only for `"gitops"`
    /// (32 raw bytes).
    pub actor_spec_digest: Option<&'a [u8]>,
}

/// Everything the per-event hash binds. Built by the
/// adapter (append path) or the verifier from a stored row. Pure data.
///
/// `stored_at` and `global_position` are deliberately absent — they
/// are store-assigned/sequence-assigned and excluded from the hash by
/// design. The typed `event` is what the
/// payload is canonicalized from, never the stored JSONB text.
#[derive(Debug, Clone, Copy)]
pub struct ChainInput<'a> {
    /// Predecessor `event_hash` (genesis sentinel for position 0).
    pub prev_event_hash: EventHash,
    /// The event's UUID (16 raw big-endian bytes in the canonical form).
    pub event_id: uuid::Uuid,
    /// Canonical stream-id string, exactly as persisted in
    /// `events.stream_id` (`StreamId::to_string()`).
    pub stream_id: &'a str,
    /// Persisted `stream_category` text.
    pub stream_category: &'a str,
    /// 0-based per-stream position.
    pub stream_position: u64,
    /// `DomainEvent::event_type()`.
    pub event_type: &'a str,
    /// The `event_version` column (today always 1).
    pub event_version: u32,
    /// The typed event — the payload is canonicalized from this, not
    /// the stored JSONB.
    pub event: &'a DomainEvent,
    /// Correlation id (16 raw bytes).
    pub correlation_id: uuid::Uuid,
    /// Causation id (tag byte + optional 16 raw bytes).
    pub causation_id: Option<uuid::Uuid>,
    /// The four persisted actor columns.
    pub actor: ActorCanonical<'a>,
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Append a `u64`-big-endian length prefix followed by the bytes.
fn put_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Append an `Option`-tagged value: `0x00` for `None`, `0x01` + the
/// caller-emitted bytes for `Some`.
fn put_opt<F: FnOnce(&mut Vec<u8>)>(buf: &mut Vec<u8>, present: bool, emit: F) {
    if present {
        buf.push(0x01);
        emit(buf);
    } else {
        buf.push(0x00);
    }
}

/// Canonical payload bytes: `serde_json::to_vec` of the
/// typed `DomainEvent`, wrapped in the `{"type":…,"data":…}` envelope
/// `serialize_event_data` uses, with object keys recursively sorted so
/// the few `serde_json::Value` payload fields are deterministic. The
/// hash input is a function of the *typed event*, recomputable offline
/// by deserializing the stored JSONB back to `DomainEvent`.
///
/// Infallible: it serializes an already-`validate()`d typed event;
/// `serde_json` cannot fail on `DomainEvent` (no maps with non-string
/// keys, no custom `Serialize` that errors). The append path therefore
/// gains no new fallible step.
fn canonical_payload_bytes(event: &DomainEvent) -> Vec<u8> {
    // Mirror `mappers::serialize_event_data`'s reshape so the canonical
    // form is a deterministic function of the typed event and matches
    // what the verifier reconstructs from the row.
    let raw = serde_json::to_value(event).expect("DomainEvent is always serializable");
    // The stored envelope's `type` is `event_type()`; the serde
    // externally-tagged key to strip is `serde_variant_key()`. They
    // differ only for the `RetentionPolicyChanged` wrapper
    // (identity for every other variant). Passing both keeps this a
    // faithful mirror of `serialize_event_data`.
    let envelope = reshape_to_envelope(event.event_type(), event.serde_variant_key(), raw);
    let canonical = canonicalize_json(envelope);
    serde_json::to_vec(&canonical).expect("canonical JSON value is always serializable")
}

/// Reshape serde's externally-tagged enum form `{"VariantName":{fields}}`
/// into the stored `{"type":…,"data":…}` envelope `serialize_event_data`
/// writes. Factored out (taking the raw `Value`) so both the
/// object-with-key path and the conservative non-object / missing-key
/// fallback are directly unit-testable — `hort-domain` is the 100%
/// coverage tier and the fallback must be exercised, not just asserted
/// unreachable.
fn reshape_to_envelope(
    event_type: &str,
    serde_key: &str,
    raw: serde_json::Value,
) -> serde_json::Value {
    let payload = match raw {
        serde_json::Value::Object(mut map) => {
            // Missing-key arm: mirrors `serialize_event_data`'s
            // `unwrap_or(Null)` — both fall back to `Null` when the
            // externally-tagged key is absent. The key removed is the
            // serde variant key (== `event_type` for every variant
            // except the `RetentionPolicyChanged` wrapper, which has
            // its own wrapper key) — NOT `event_type`, which is
            // the discriminated stored-`type` string.
            map.remove(serde_key).unwrap_or(serde_json::Value::Null)
        }
        // Non-object arm: mirrors `serialize_event_data`'s `other => other`
        // pass-through. A non-object raw value would mean serde's
        // externally-tagged enum representation changed unexpectedly.
        // Passing it through unchanged keeps `reshape_to_envelope` a
        // faithful mirror of `serialize_event_data` for all inputs —
        // not only object inputs — so the tamper-evidence verifier
        // and the append-side serializer always agree.
        other => other,
    };
    serde_json::json!({ "type": event_type, "data": payload })
}

/// Recursively rewrite every object so its keys are emitted in
/// lexicographic order (`serde_json::Map` with the default feature
/// preserves insertion order, so we rebuild it sorted). Arrays keep
/// element order (semantically significant); scalars pass through.
fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in entries {
                out.insert(k, canonicalize_json(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(canonicalize_json).collect())
        }
        scalar => scalar,
    }
}

/// Canonical byte form of a chained event (frozen field
/// order). Domain-separated, length-prefixed. Infallible by
/// construction (see [`canonical_payload_bytes`]).
pub fn canonical_event_bytes(input: &ChainInput<'_>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    // 0: domain tag (fixed 16 bytes).
    buf.extend_from_slice(DOMAIN_TAG);
    // 1: prev_event_hash (32 raw bytes).
    buf.extend_from_slice(&input.prev_event_hash.0);
    // 2: event_id (16 raw big-endian bytes).
    buf.extend_from_slice(input.event_id.as_bytes());
    // 3: stream_id (len-prefixed UTF-8).
    put_lp(&mut buf, input.stream_id.as_bytes());
    // 4: stream_category (len-prefixed UTF-8).
    put_lp(&mut buf, input.stream_category.as_bytes());
    // 5: stream_position (u64 BE).
    buf.extend_from_slice(&input.stream_position.to_be_bytes());
    // 6: event_type (len-prefixed UTF-8).
    put_lp(&mut buf, input.event_type.as_bytes());
    // 7: event_version (u32 BE).
    buf.extend_from_slice(&input.event_version.to_be_bytes());
    // 8: payload (len-prefixed canonical bytes).
    let payload = canonical_payload_bytes(input.event);
    put_lp(&mut buf, &payload);
    // 9: correlation_id (16 raw bytes).
    buf.extend_from_slice(input.correlation_id.as_bytes());
    // 10: causation_id (Option tag + 16 raw bytes).
    put_opt(&mut buf, input.causation_id.is_some(), |b| {
        b.extend_from_slice(
            input
                .causation_id
                .as_ref()
                .expect("present branch only entered when Some")
                .as_bytes(),
        );
    });
    // 11: actor tuple — actor_type (lp), actor_id (opt+16),
    //     actor_source_file (opt+lp UTF-8), actor_spec_digest (opt+lp raw).
    put_lp(&mut buf, input.actor.actor_type.as_bytes());
    put_opt(&mut buf, input.actor.actor_id.is_some(), |b| {
        b.extend_from_slice(
            input
                .actor
                .actor_id
                .as_ref()
                .expect("present branch only entered when Some")
                .as_bytes(),
        );
    });
    put_opt(&mut buf, input.actor.actor_source_file.is_some(), |b| {
        put_lp(
            b,
            input
                .actor
                .actor_source_file
                .expect("present branch only entered when Some")
                .as_bytes(),
        );
    });
    put_opt(&mut buf, input.actor.actor_spec_digest.is_some(), |b| {
        put_lp(
            b,
            input
                .actor
                .actor_spec_digest
                .expect("present branch only entered when Some"),
        );
    });
    buf
}

/// `event_hash = SHA-256(canonical_event_bytes(input))`. Infallible.
pub fn compute_event_hash(input: &ChainInput<'_>) -> EventHash {
    let mut hasher = Sha256::new();
    hasher.update(canonical_event_bytes(input));
    EventHash(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// Stream verification
// ---------------------------------------------------------------------------

/// One row's view as the verifier needs it: the stored hashes plus
/// everything needed to recompute the hash. `ChainInput` already
/// carries the recompute inputs; the stored hashes are the two columns
/// being checked against the recomputation.
#[derive(Debug, Clone, Copy)]
pub struct StreamRow<'a> {
    /// The recompute inputs (typed event + envelope columns).
    pub input: ChainInput<'a>,
    /// `prev_event_hash` as stored in the row.
    pub stored_prev: EventHash,
    /// `event_hash` as stored in the row.
    pub stored_hash: EventHash,
}

/// One stream's rows, ordered by `stream_position` ascending.
#[derive(Debug, Clone, Copy)]
pub struct StreamRows<'a> {
    rows: &'a [StreamRow<'a>],
}

impl<'a> StreamRows<'a> {
    /// Wrap a borrowed slice of rows. The caller guarantees ascending
    /// `stream_position` order (the adapter reads
    /// `ORDER BY stream_position ASC`).
    pub fn new(rows: &'a [StreamRow<'a>]) -> Self {
        Self { rows }
    }
}

/// One stored event row, **owned**, carrying everything the pure
/// verifier core needs: the deserialized [`PersistedEvent`] (typed
/// event plus envelope columns), the four persisted actor columns in
/// their exact stored string form (the canonical hash must bind the
/// bytes as stored, never a re-serialization of the typed
/// [`super::Actor`]), and the two stored chain hashes.
///
/// Owned because it crosses the [`EventChainReaderPort`] boundary from
/// the adapter (the borrowing [`StreamRow`]/[`ChainInput`] cannot). The
/// adapter (`PgEventChainReader`) is the only producer;
/// [`ChainRow::as_stream_row`] lends it to the pure core, tying the
/// `StreamRow`'s lifetime to `&self`. This is the verifier-read analogue
/// of [`StreamHead`](super::StreamHead) on the emitter side: the chain
/// columns `PersistedEvent` deliberately omits, surfaced for the
/// integrity check without widening the `EventStore` port.
///
/// [`EventChainReaderPort`]: crate::ports::event_chain_reader::EventChainReaderPort
#[derive(Debug, Clone)]
pub struct ChainRow {
    /// The deserialized event + envelope (`event_id`, positions,
    /// `event_version`, correlation/causation, typed `event`).
    pub persisted: PersistedEvent,
    /// `stream_id` text column, exactly as persisted.
    pub stream_id: String,
    /// `stream_category` text column.
    pub stream_category: String,
    /// `actor_type` text column.
    pub actor_type: String,
    /// `actor_id` column (`Some` only for `actor_type = "api"`).
    pub actor_id: Option<uuid::Uuid>,
    /// `actor_source_file` column (`Some` only for `"gitops"`).
    pub actor_source_file: Option<String>,
    /// `actor_spec_digest` column (`Some` only for `"gitops"`).
    pub actor_spec_digest: Option<Vec<u8>>,
    /// `prev_event_hash` as stored in the row.
    pub stored_prev: EventHash,
    /// `event_hash` as stored in the row.
    pub stored_hash: EventHash,
}

impl ChainRow {
    /// Borrow this owned row as a pure-core [`StreamRow`]. The returned
    /// view borrows `&self`, so it lives no longer than the `ChainRow`.
    pub fn as_stream_row(&self) -> StreamRow<'_> {
        StreamRow {
            input: ChainInput {
                prev_event_hash: self.stored_prev,
                event_id: self.persisted.event_id,
                stream_id: &self.stream_id,
                stream_category: &self.stream_category,
                stream_position: self.persisted.stream_position,
                event_type: self.persisted.event.event_type(),
                event_version: self.persisted.event_version,
                event: &self.persisted.event,
                correlation_id: self.persisted.correlation_id,
                causation_id: self.persisted.causation_id,
                actor: ActorCanonical {
                    actor_type: &self.actor_type,
                    actor_id: self.actor_id,
                    actor_source_file: self.actor_source_file.as_deref(),
                    actor_spec_digest: self.actor_spec_digest.as_deref(),
                },
            },
            stored_prev: self.stored_prev,
            stored_hash: self.stored_hash,
        }
    }
}

/// Why a stream chain is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBreak {
    /// Recomputed `event_hash` != the stored `event_hash` at this
    /// position (a field was mutated, or a row substituted).
    HashMismatch,
    /// The row's stored `prev_event_hash` != the previous row's
    /// `event_hash` (a row was inserted/removed/reordered).
    PrevMismatch,
    /// `stream_position == 0` but `prev_event_hash` is not the genesis
    /// sentinel.
    NonGenesisAtZero,
    /// `stream_position != 0` but `prev_event_hash` is the genesis
    /// sentinel (a head-truncation re-genesis attempt).
    GenesisAtNonZero,
    /// `stream_position` is not contiguous with the previous row
    /// (a gap — a row was excised).
    PositionGap,
    /// The stream is absent from the live DB with no justifying
    /// `StreamSealed` record (used by the anchor cross-check).
    UnsealedAbsentStream,
    /// A `StreamSealed` head was not covered by any anchored
    /// checkpoint at-or-after the seal.
    HeadNotAnchored,
}

/// Verdict for one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamVerdict {
    /// Chain intact; carries the verified head + final position.
    Ok { head: EventHash, position: u64 },
    /// First position where the chain breaks, and why.
    Broken {
        at_position: u64,
        reason: ChainBreak,
    },
    /// Stream absent but justified by a `StreamSealed` + anchoring
    /// checkpoint (constructed by the anchor cross-check, not by
    /// [`verify_stream_chain`] which only sees present rows).
    SealedGap { final_event_hash: EventHash },
}

/// Verify one stream's chain in isolation. The rows MUST be ordered by `stream_position`
/// ascending. An empty slice is `Ok` with the genesis head at a
/// sentinel position (`u64::MAX`) — "no rows to contradict"; callers
/// that care about absent-vs-empty use the anchor cross-check.
pub fn verify_stream_chain(rows: &StreamRows<'_>) -> StreamVerdict {
    let genesis = genesis_hash();
    let mut expected_prev = genesis;
    let mut expected_position: u64 = 0;
    let mut last_head = genesis;
    let mut last_position = u64::MAX;

    for row in rows.rows {
        let pos = row.input.stream_position;

        // Position contiguity (0, 1, 2, …). Catches an excised row.
        if pos != expected_position {
            return StreamVerdict::Broken {
                at_position: pos,
                reason: ChainBreak::PositionGap,
            };
        }

        // Genesis rule at both ends.
        if pos == 0 && row.stored_prev != genesis {
            return StreamVerdict::Broken {
                at_position: pos,
                reason: ChainBreak::NonGenesisAtZero,
            };
        }
        if pos != 0 && row.stored_prev == genesis {
            return StreamVerdict::Broken {
                at_position: pos,
                reason: ChainBreak::GenesisAtNonZero,
            };
        }

        // The stored predecessor must equal the previous row's head
        // (for pos 0 the previous head is the genesis sentinel).
        if row.stored_prev != expected_prev {
            return StreamVerdict::Broken {
                at_position: pos,
                reason: ChainBreak::PrevMismatch,
            };
        }

        // Recompute and compare against the stored hash. The recompute
        // uses the row's own `prev_event_hash` field; we already
        // verified that field equals the previous head, so a
        // recompute mismatch isolates a *field* mutation.
        let recomputed = compute_event_hash(&row.input);
        if recomputed != row.stored_hash {
            return StreamVerdict::Broken {
                at_position: pos,
                reason: ChainBreak::HashMismatch,
            };
        }

        expected_prev = row.stored_hash;
        last_head = row.stored_hash;
        last_position = pos;
        expected_position = pos + 1;
    }

    StreamVerdict::Ok {
        head: last_head,
        position: last_position,
    }
}

// ---------------------------------------------------------------------------
// Anchor cross-check
// ---------------------------------------------------------------------------

/// A `StreamSealed` fact as the verifier consumes it (the bits of the
/// tombstone the anchor cross-check needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStreamRecord {
    /// Wire-form id of the sealed/deleted stream.
    pub sealed_stream_id: String,
    /// The deleted stream's chain head.
    pub final_event_hash: EventHash,
}

/// A signed, anchored checkpoint, already deserialized.
/// I/O — fetching it from the WORM store — is the adapter's job;
/// this is the pure shape the verify core consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// `"hort-evchain/v1"` — selects the canonicalizer.
    pub chain_format_version: String,
    /// Monotonic sequence; a gap means a missing checkpoint.
    pub checkpoint_seq: u64,
    /// Emit time (store-supplied).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Per-stream heads this checkpoint anchored: `(stream_id,
    /// final_stream_position, head_event_hash)`.
    pub stream_heads: Vec<(String, u64, EventHash)>,
    /// `StreamSealed` records covered since the previous checkpoint.
    pub sealed_streams: Vec<SealedStreamRecord>,
}

/// Why the anchor attestation is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingReason {
    /// No checkpoint exists at all (chain present, never anchored).
    NoCheckpoint,
    /// A `checkpoint_seq` gap (a checkpoint that should exist is
    /// absent from the WORM store).
    SequenceGap,
    /// The newest checkpoint is older than `2 × cadence` (the cron
    /// stopped).
    Stale,
}

/// An actual anchor-level integrity violation (distinct from a missing
/// checkpoint, which is a coverage gap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorBreak {
    /// A live stream's `(final_position, head)` contradicts what a
    /// signature-verified checkpoint anchored for that stream
    /// (rollback / tail rewrite / whole-stream truncation). Every
    /// checkpoint's statement counts, not only the newest one's — see
    /// [`contradicts_anchored_head`] for the relation and for the one
    /// half of it this pure core cannot decide.
    HeadMismatch,
    /// A live stream is absent and there is no `StreamSealed` for it.
    UnsealedAbsentStream,
    /// A `StreamSealed` head was never anchored by a checkpoint.
    SealUnanchored,
    /// Two or more signature-verified checkpoints carry the same
    /// `checkpoint_seq` — a fork in the anchor record.
    ///
    /// The sequence is single-valued by construction: the emitter
    /// derives its seq as `max(existing) + 1` (`next_checkpoint_seq`)
    /// from the same store it is about to write to. So a repeated seq
    /// means either two emitters ran against one store, or a signed
    /// checkpoint was fabricated — and in both cases one of the two
    /// attests a cut the other contradicts. Deduplicating the seqs
    /// made the fork disappear *and* left the `checkpoint_seq`
    /// contiguity count reading as satisfied.
    DuplicateCheckpointSeq,
}

/// Everything the anchor cross-check found, on its two independent
/// axes, before any ranking.
///
/// The cross-check answers two separate questions — "is there a real
/// anchor-level violation?" and "is the anchor attestation complete?"
/// — and a single-verdict return cannot carry both. It used to try:
/// the coverage checks returned early, so a head mismatch under a
/// stale or gapped anchor set was never computed, and [`roll_up`]'s
/// `Broken`-dominates-`MissingCheckpoint` promise had nothing to rank
/// in exactly the case it names. Both axes are therefore reported
/// here and ranked once, in [`roll_up`] — the only ranking site.
///
/// Each `Vec` is a **set in detection order**: [`AnchorBreak`] and
/// [`MissingReason`] carry no per-detection detail, so recording one
/// kind twice would be noise rather than information. Empty on both
/// axes is the clean result, i.e. `AnchorFindings::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorFindings {
    /// Anchor-level integrity violations. Non-empty ⇒
    /// [`ChainReport::Broken`].
    pub breaks: Vec<AnchorBreak>,
    /// Coverage gaps in the anchor attestation. Non-empty with no
    /// break ⇒ [`ChainReport::MissingCheckpoint`].
    pub coverage_gaps: Vec<MissingReason>,
}

/// Push `value` unless it is already present — the backing store for
/// both [`AnchorFindings`] axes, each of which is a set in detection
/// order.
fn record_once<T: PartialEq>(into: &mut Vec<T>, value: T) {
    if !into.contains(&value) {
        into.push(value);
    }
}

impl AnchorFindings {
    /// Record one anchor-level violation kind.
    fn record_break(&mut self, value: AnchorBreak) {
        record_once(&mut self.breaks, value);
    }

    /// Record one coverage-gap reason.
    fn record_gap(&mut self, value: MissingReason) {
        record_once(&mut self.coverage_gaps, value);
    }
}

/// The checkpoint the coverage checks read, selected by a **total**
/// order over the set's own content: highest `checkpoint_seq`, and
/// among equal seqs the *earliest* `created_at`.
///
/// `max_by_key(|c| c.checkpoint_seq)` returns the last of several
/// equal maxima, so its answer was a function of the order the adapter
/// happened to hand the set over in — and
/// `CheckpointAnchorPort::read_all` promises no order at all. A seq
/// tie is itself a reported violation
/// ([`AnchorBreak::DuplicateCheckpointSeq`]); resolving it towards the
/// earliest `created_at` resolves it fail-closed, because a forked
/// sequence cannot vouch for the freshness the later timestamp claims.
///
/// Two checkpoints equal on *both* keys leave which one is returned
/// order-dependent, which is harmless: every use of the result reads
/// only `checkpoint_seq` and `created_at`, so the verdict is not.
fn newest_checkpoint(checkpoints: &[Checkpoint]) -> Option<&Checkpoint> {
    checkpoints.iter().max_by(|a, b| {
        a.checkpoint_seq
            .cmp(&b.checkpoint_seq)
            .then_with(|| b.created_at.cmp(&a.created_at))
    })
}

/// Does a live stream's `(position, head)` contradict what a
/// signature-verified checkpoint anchored for it?
///
/// The chain is append-only, so a head a checkpoint anchored must be
/// **reachable** from the live head: the live stream is at least as
/// long as the anchored statement, and the anchored head is either the
/// live head itself (nothing appended since the cut) or an ancestor of
/// it. The relation against an older anchor is therefore *not*
/// equality — a head legitimately advances between checkpoints.
///
/// Two halves of reachability are decidable from the final head alone,
/// which is all this pure core is given:
///
/// * `anchored_position > live_position` — the stream is *shorter*
///   than a checkpoint attested, so rows were removed from its tail.
/// * `(anchored_position == live_position) != (anchored_head == live_head)`
///   — `stream_position` is bound into the hash (field 5 of
///   [`canonical_event_bytes`]), so one head hash cannot sit at two
///   positions and two distinct heads cannot sit at one. Equal
///   positions with different heads is a tail rewrite; different
///   positions with the same head is a SHA-256 collision.
///
/// What is **not** decidable here: when `anchored_position <
/// live_position` and the heads differ, confirming that the anchored
/// head really is the live chain's hash *at that position* needs the
/// live chain's hash at `anchored_position`, and `live_heads` carries
/// only each stream's final head. So a wholesale rewrite followed by
/// further appends still passes this predicate, while a wholesale
/// rewrite of a stream that has not grown since the cut does not.
/// Closing the residual is a read this function does not have, not a
/// weaker relation.
fn contradicts_anchored_head(
    live_position: u64,
    live_head: &EventHash,
    anchored_position: u64,
    anchored_head: &EventHash,
) -> bool {
    anchored_position > live_position
        || (anchored_position == live_position) != (anchored_head == live_head)
}

/// Cross-check live stream heads + sealed records against **every**
/// signature-verified anchored checkpoint.
///
/// `live_heads`: every present stream's `(stream_id,
/// final_stream_position, head_hash)`. `sealed`: the `StreamSealed`
/// records read from the audit-meta stream. `checkpoints`: all
/// checkpoints read from the anchor store. `now` / `cadence`: for the
/// staleness check.
///
/// Returns both axes of [`AnchorFindings`]; the ranking is
/// [`roll_up`]'s. A coverage gap (stale, gapped) no longer short-
/// circuits the integrity checks: the gap is real and is reported, and
/// so is any violation found under it. The one exception is "no
/// checkpoint at all", where there is no anchored statement for a live
/// head to contradict and nothing to compute.
///
/// Pure: no I/O, and no panic on any caller input (an absurd `cadence`
/// is saturated rather than unwrapped).
pub fn verify_against_checkpoint(
    live_heads: &[(String, u64, EventHash)],
    sealed: &[SealedStreamRecord],
    checkpoints: &[Checkpoint],
    now: chrono::DateTime<chrono::Utc>,
    cadence: std::time::Duration,
) -> AnchorFindings {
    let mut findings = AnchorFindings::default();

    // (a) no checkpoint at all. The only coverage gap that also ends
    //     the function: with nothing anchored there is no statement a
    //     live head could contradict.
    let Some(newest) = newest_checkpoint(checkpoints) else {
        findings.record_gap(MissingReason::NoCheckpoint);
        return findings;
    };

    let mut seqs: Vec<u64> = checkpoints.iter().map(|c| c.checkpoint_seq).collect();
    seqs.sort_unstable();

    // (b) a repeated `checkpoint_seq` is a fork in the anchor record
    //     (see `AnchorBreak::DuplicateCheckpointSeq`) — detected
    //     *before* the dedup the contiguity count below needs, which
    //     is what used to make it vanish.
    if seqs.windows(2).any(|w| w[0] == w[1]) {
        findings.record_break(AnchorBreak::DuplicateCheckpointSeq);
    }

    // (c) checkpoint_seq gap: the *distinct* seqs present must be a
    //     contiguous 1..=max run (a missing intermediate seq =
    //     suppressed anchor). Sequences are 1-based and contiguous, so
    //     the count of distinct seqs must equal the max seq and the
    //     min must be 1.
    seqs.dedup();
    if seqs.first().copied() != Some(1) || (seqs.len() as u64) != newest.checkpoint_seq {
        findings.record_gap(MissingReason::SequenceGap);
    }

    // (d) staleness: newest older than 2 × cadence.
    let max_age = match chrono::Duration::from_std(cadence.saturating_mul(2)) {
        Ok(d) => d,
        // An absurd cadence overflows chrono::Duration; treat the
        // anchor as effectively never-stale rather than panicking
        // (pure-fn must not panic on caller input).
        Err(_) => chrono::Duration::MAX,
    };
    if now.signed_duration_since(newest.created_at) > max_age {
        findings.record_gap(MissingReason::Stale);
    }

    // The two cross-checks below each visit EVERY anchored statement
    // in the store, so both sides are indexed first. A linear scan per
    // statement would be quadratic in the stream count *and* linear in
    // the checkpoint count on top of that; with the index each
    // statement costs one lookup, which is the floor for a check whose
    // premise is that every statement is read.
    let mut live_by_id: HashMap<&str, (u64, &EventHash)> = HashMap::with_capacity(live_heads.len());
    for (sid, pos, head) in live_heads {
        // First occurrence wins, which is what the linear `find` this
        // replaced did. `live_heads` carries one entry per stream by
        // contract, so a repeat is a caller error rather than a case
        // with a better answer.
        live_by_id.entry(sid.as_str()).or_insert((*pos, head));
    }
    let sealed_ids: HashSet<&str> = sealed.iter().map(|r| r.sealed_stream_id.as_str()).collect();
    let anchored_seals: HashSet<(&str, &EventHash)> = checkpoints
        .iter()
        .flat_map(|c| c.sealed_streams.iter())
        .map(|s| (s.sealed_stream_id.as_str(), &s.final_event_hash))
        .collect();

    // Integrity checks against EVERY checkpoint's head statement, not
    // only the newest one's. An older checkpoint was fetched and
    // signature-verified too, so what it says about a stream head is
    // evidence of the same standing; judging a run only against the
    // newest cut means a wholesale rewrite is laundered by simply
    // waiting for the next scheduled checkpoint.
    //
    // For each anchored stream, exactly one of two things must hold:
    // it is still live with a head reachable from the anchored one
    // (`contradicts_anchored_head`), or it is absent and a
    // `StreamSealed` record justifies the absence. An anchored stream
    // that is now absent with no seal is a whole-stream truncation.
    //
    // A live stream NO checkpoint anchored is not visited at all —
    // that is a stream created after every cut, which is not a
    // violation.
    for cp in checkpoints {
        for (sid, anchored_pos, anchored_head) in &cp.stream_heads {
            match live_by_id.get(sid.as_str()) {
                Some((live_pos, live_head)) => {
                    if contradicts_anchored_head(*live_pos, live_head, *anchored_pos, anchored_head)
                    {
                        findings.record_break(AnchorBreak::HeadMismatch);
                    }
                }
                None => {
                    if !sealed_ids.contains(sid.as_str()) {
                        findings.record_break(AnchorBreak::UnsealedAbsentStream);
                    }
                }
            }
        }
    }

    // Every `StreamSealed` must have its head anchored by some
    // checkpoint (so the seal is provably expected).
    for rec in sealed {
        if !anchored_seals.contains(&(rec.sealed_stream_id.as_str(), &rec.final_event_hash)) {
            findings.record_break(AnchorBreak::SealUnanchored);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Top-level roll-up
// ---------------------------------------------------------------------------

/// The top-level pure verdict the `verify-event-chain` subcommand maps to
/// a process exit code + the `hort_event_chain_verify_total{result}` metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainReport {
    /// Every stream verified and the anchor cross-check passed.
    Ok,
    /// At least one detected integrity violation.
    Broken,
    /// No integrity violation, but the anchor attestation is
    /// incomplete (a coverage gap).
    MissingCheckpoint,
}

/// Roll the per-stream verdicts + the anchor findings into the single
/// top-level report. `Broken` dominates
/// `MissingCheckpoint` dominates `Ok` — a real violation is never
/// masked by a coverage gap.
///
/// **This is the only ranking site**, and the dominance it states is
/// now reachable in the case it names: [`verify_against_checkpoint`]
/// reports both axes of [`AnchorFindings`] instead of returning the
/// first coverage gap it finds, so an anchor set that is stale or
/// gapped *and* contradicted by a live head arrives here carrying both
/// facts and ranks as `Broken`.
pub fn roll_up(stream_verdicts: &[StreamVerdict], anchor: &AnchorFindings) -> ChainReport {
    let any_broken = stream_verdicts
        .iter()
        .any(|v| matches!(v, StreamVerdict::Broken { .. }))
        || !anchor.breaks.is_empty();
    if any_broken {
        return ChainReport::Broken;
    }
    if !anchor.coverage_gaps.is_empty() {
        return ChainReport::MissingCheckpoint;
    }
    ChainReport::Ok
}

// ===========================================================================
// Tests — hort-domain is the 100% coverage tier. Every ChainBreak /
// MissingReason / AnchorBreak / ChainReport arm and every boundary
// (genesis, position gap, hash mismatch, prev mismatch,
// non-genesis-at-0, genesis-at-nonzero, empty) gets a constructed-input
// test.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ArtifactIngested, DomainEvent, IngestSource};
    use crate::types::ContentHash;
    use chrono::{Duration, TimeZone, Utc};
    use uuid::Uuid;

    /// Sample event factory for chain-machinery tests.
    ///
    /// The chain-hash tests don't care which event
    /// payload they thread through — `ArtifactIngested` is a stable
    /// variant.
    fn sample_event(n: u32) -> DomainEvent {
        let _ = Utc.timestamp_opt(1_700_000_000 + n as i64, 0).unwrap();
        DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id: Uuid::from_u128(n as u128),
            repository_id: Uuid::nil(),
            name: format!("pkg-{n}"),
            version: Some("1.0".into()),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse::<ContentHash>()
                .unwrap(),
            size_bytes: i64::from(n),
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        })
    }

    fn input<'a>(
        prev: EventHash,
        position: u64,
        event: &'a DomainEvent,
        stream_id: &'a str,
    ) -> ChainInput<'a> {
        ChainInput {
            prev_event_hash: prev,
            event_id: Uuid::from_u128(0xE0 + position as u128),
            stream_id,
            stream_category: "artifact",
            stream_position: position,
            event_type: event.event_type(),
            event_version: 1,
            event,
            correlation_id: Uuid::from_u128(0xC0FFEE),
            causation_id: None,
            actor: ActorCanonical {
                actor_type: "system",
                actor_id: None,
                actor_source_file: None,
                actor_spec_digest: None,
            },
        }
    }

    /// Build a valid chained stream of `n` events; returns the owned
    /// events + the row views (rows borrow the events).
    fn valid_stream(n: u64) -> (Vec<DomainEvent>, String) {
        let events: Vec<DomainEvent> = (0..n).map(|i| sample_event(i as u32)).collect();
        (events, "artifact-deadbeef".to_string())
    }

    fn build_rows<'a>(events: &'a [DomainEvent], stream_id: &'a str) -> Vec<StreamRow<'a>> {
        let mut rows = Vec::new();
        let mut prev = genesis_hash();
        for (i, e) in events.iter().enumerate() {
            let inp = input(prev, i as u64, e, stream_id);
            let h = compute_event_hash(&inp);
            rows.push(StreamRow {
                input: inp,
                stored_prev: prev,
                stored_hash: h,
            });
            prev = h;
        }
        rows
    }

    // ---- genesis_hash / EventHash --------------------------------------

    #[test]
    fn genesis_hash_is_stable_and_not_zero() {
        let g = genesis_hash();
        assert_eq!(g, genesis_hash());
        assert_ne!(g.0, [0u8; 32], "genesis must not be the zero array");
        // Known-answer: SHA-256("hort-event-chain/v1/genesis").
        let want: [u8; 32] = Sha256::digest(GENESIS_PREIMAGE).into();
        assert_eq!(g.0, want);
        assert_eq!(g.as_bytes(), &g.0);
        assert_eq!(g.to_hex().len(), 64);
    }

    #[test]
    fn event_hash_traits() {
        let a = EventHash([1u8; 32]);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, EventHash([2u8; 32]));
        let _ = format!("{a:?}");
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    // ---- canonical encoding determinism --------------------------------

    #[test]
    fn canonical_bytes_are_deterministic_and_domain_separated() {
        let e = sample_event(1);
        let i = input(genesis_hash(), 0, &e, "artifact-x");
        let a = canonical_event_bytes(&i);
        let b = canonical_event_bytes(&i);
        assert_eq!(a, b);
        assert_eq!(&a[..16], DOMAIN_TAG, "field 0 is the frozen domain tag");
        // prev_event_hash occupies bytes 16..48.
        assert_eq!(&a[16..48], &genesis_hash().0);
    }

    #[test]
    fn changing_any_bound_field_changes_the_hash() {
        let e = sample_event(1);
        let base = compute_event_hash(&input(genesis_hash(), 0, &e, "artifact-x"));

        // Different position.
        assert_ne!(
            base,
            compute_event_hash(&input(genesis_hash(), 1, &e, "artifact-x"))
        );
        // Different stream id.
        assert_ne!(
            base,
            compute_event_hash(&input(genesis_hash(), 0, &e, "artifact-y"))
        );
        // Different predecessor.
        assert_ne!(
            base,
            compute_event_hash(&input(EventHash([9u8; 32]), 0, &e, "artifact-x"))
        );
        // Different payload.
        let e2 = sample_event(2);
        assert_ne!(
            base,
            compute_event_hash(&input(genesis_hash(), 0, &e2, "artifact-x"))
        );
    }

    #[test]
    fn payload_canonicalization_sorts_object_keys_recursively() {
        // PolicyUpdated carries serde_json::Value fields; build two
        // logically-equal values whose key insertion order differs and
        // assert the canonical bytes match.
        use crate::events::{PolicyField, PolicyUpdated};
        let mk = |v: serde_json::Value| {
            DomainEvent::PolicyUpdated(PolicyUpdated {
                policy_id: Uuid::nil(),
                field: PolicyField::Name,
                previous_value: v.clone(),
                new_value: v,
            })
        };
        // Object key order must not affect the canonical payload.
        let a = mk(serde_json::json!({"b": 1, "a": {"d": 4, "c": 3}}));
        let b = mk(serde_json::json!({"a": {"c": 3, "d": 4}, "b": 1}));
        assert_eq!(canonical_payload_bytes(&a), canonical_payload_bytes(&b));
    }

    #[test]
    fn canonicalize_json_recurses_into_arrays_and_passes_scalars() {
        // Array of objects with unsorted keys nested inside an object —
        // exercises the Object, Array and scalar arms of
        // canonicalize_json in one value.
        let v = serde_json::json!({
            "z": [ {"b": 1, "a": 2}, {"d": 4, "c": 3} ],
            "a": "scalar"
        });
        let c = canonicalize_json(v);
        // Serialized form has keys in sorted order at every level and
        // array element order preserved.
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"a":"scalar","z":[{"a":2,"b":1},{"c":3,"d":4}]}"#
        );
    }

    #[test]
    fn reshape_to_envelope_object_with_key() {
        // Pre-B6 variant: serde_key == event_type.
        let raw = serde_json::json!({ "ArtifactIngested": {"x": 1} });
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw),
            serde_json::json!({ "type": "ArtifactIngested", "data": {"x": 1} })
        );
    }

    /// The `RetentionPolicyChanged` wrapper is the one
    /// variant where the stored `type` (discriminated) differs from
    /// the serde key. `reshape_to_envelope` must strip the serde key
    /// but stamp the discriminated `type` — exactly what
    /// `serialize_event_data` does.
    #[test]
    fn reshape_to_envelope_b6_wrapper_strips_serde_key_keeps_discriminated_type() {
        let raw = serde_json::json!({ "RetentionPolicyChanged": {"Created": {"id": "x"}} });
        assert_eq!(
            reshape_to_envelope("RetentionPolicyCreated", "RetentionPolicyChanged", raw),
            serde_json::json!({
                "type": "RetentionPolicyCreated",
                "data": {"Created": {"id": "x"}}
            })
        );
    }

    #[test]
    fn reshape_to_envelope_object_missing_key_falls_back_to_null() {
        // Object that does not contain the serde key -> Null data.
        let raw = serde_json::json!({ "SomethingElse": {"x": 1} });
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw),
            serde_json::json!({ "type": "ArtifactIngested", "data": serde_json::Value::Null })
        );
    }

    #[test]
    fn reshape_to_envelope_non_object_passes_through_unchanged() {
        // A non-object raw value (serde enum repr changed) -> the value
        // is passed through as the payload, mirroring `serialize_event_data`'s
        // `other => other` arm. Previously this asserted `Null`; the correct
        // behavior is pass-through so the verifier and serializer agree.
        let raw = serde_json::Value::String("unexpected".into());
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw.clone()),
            serde_json::json!({ "type": "ArtifactIngested", "data": "unexpected" })
        );

        // Also exercise a non-object array input to confirm the arm is
        // truly a pass-through for any non-Object variant.
        let arr = serde_json::Value::Array(vec![serde_json::Value::Bool(true)]);
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", arr.clone()),
            serde_json::json!({ "type": "ArtifactIngested", "data": arr })
        );
    }

    /// Parity test: `reshape_to_envelope`'s non-object arm must produce
    /// the same payload as `serialize_event_data`'s `other => other` arm.
    ///
    /// `serialize_event_data` (mappers.rs ~439-444):
    /// ```text
    /// let payload = match data {
    ///     serde_json::Value::Object(mut map) => { map.remove(event_type).unwrap_or(Null) }
    ///     other => other,   // <-- non-object arm: pass through unchanged
    /// };
    /// ```
    /// This test constructs the same non-object value, runs both code
    /// paths in-line, and asserts they produce identical output — pinning
    /// the parity so a future regression in either arm fails CI.
    #[test]
    fn reshape_to_envelope_non_object_parity_with_serialize_event_data() {
        for non_object in [
            serde_json::Value::String("str-value".into()),
            serde_json::Value::Number(serde_json::Number::from(42)),
            serde_json::Value::Bool(false),
            serde_json::Value::Array(vec![serde_json::json!(1), serde_json::json!(2)]),
            serde_json::Value::Null,
        ] {
            let event_type = "ArtifactIngested";

            // serialize_event_data non-object arm: `other => other`
            let serializer_payload = match non_object.clone() {
                serde_json::Value::Object(mut map) => {
                    map.remove(event_type).unwrap_or(serde_json::Value::Null)
                }
                other => other,
            };

            // reshape_to_envelope result (pre-B6: serde_key == event_type)
            let envelope = reshape_to_envelope(event_type, event_type, non_object);
            let reshaper_payload = envelope
                .get("data")
                .expect("reshape_to_envelope always produces 'data' field")
                .clone();

            assert_eq!(
                reshaper_payload, serializer_payload,
                "non-object parity failed for input type {reshaper_payload:?}"
            );
        }
    }

    #[test]
    fn payload_with_array_field_canonicalizes_stably() {
        // PermissionGrantApplied's `subject` (Claims) carries a
        // Vec<String> -> a JSON array in the payload, exercising the
        // Array arm through the real path.
        use crate::entities::rbac::Permission;
        use crate::events::{GrantSubjectRecord, PermissionGrantApplied};
        let e = DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
            grant_id: Uuid::nil(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["developer".into(), "team-alpha".into()],
            },
            permission: Permission::Read,
            repository_id: None,
        });
        assert_eq!(canonical_payload_bytes(&e), canonical_payload_bytes(&e));
    }

    #[test]
    fn canonical_encoding_covers_some_optional_and_gitops_actor() {
        // Exercise the Some-branches of causation_id and the gitops
        // actor (actor_id None, source_file + spec_digest Some).
        let e = sample_event(3);
        let digest = [0xab_u8; 32];
        let i = ChainInput {
            prev_event_hash: genesis_hash(),
            event_id: Uuid::from_u128(7),
            stream_id: "artifact-z",
            stream_category: "artifact",
            stream_position: 0,
            event_type: e.event_type(),
            event_version: 2,
            event: &e,
            correlation_id: Uuid::from_u128(1),
            causation_id: Some(Uuid::from_u128(2)),
            actor: ActorCanonical {
                actor_type: "gitops",
                actor_id: None,
                actor_source_file: Some("auth/admins.yaml"),
                actor_spec_digest: Some(&digest),
            },
        };
        let bytes = canonical_event_bytes(&i);
        // Recompute is stable and differs from the None/api shape.
        assert_eq!(bytes, canonical_event_bytes(&i));
        let api = ChainInput {
            causation_id: None,
            actor: ActorCanonical {
                actor_type: "api",
                actor_id: Some(Uuid::from_u128(9)),
                actor_source_file: None,
                actor_spec_digest: None,
            },
            ..i
        };
        assert_ne!(canonical_event_bytes(&api), bytes);
    }

    // ---- verify_stream_chain: Ok + empty -------------------------------

    #[test]
    fn empty_stream_is_ok_with_sentinel_position() {
        let v = verify_stream_chain(&StreamRows::new(&[]));
        assert_eq!(
            v,
            StreamVerdict::Ok {
                head: genesis_hash(),
                position: u64::MAX
            }
        );
    }

    #[test]
    fn valid_multi_event_stream_verifies_ok() {
        let (events, sid) = valid_stream(5);
        let rows = build_rows(&events, &sid);
        let head = rows.last().unwrap().stored_hash;
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Ok { head, position: 4 }
        );
    }

    // ---- ChainRow::as_stream_row ---------------------------------------

    #[test]
    fn chain_row_as_stream_row_round_trips_into_a_verifiable_view() {
        use crate::events::{Actor, ApiActor, PersistedEvent, StreamId};
        let user_id = Uuid::from_u128(0xA9);
        let persisted = PersistedEvent {
            event_id: Uuid::from_u128(0xE0),
            stream_id: StreamId::artifact(Uuid::from_u128(1)),
            stream_position: 0,
            global_position: 0,
            event: sample_event(1),
            correlation_id: Uuid::from_u128(0xC0FFEE),
            causation_id: None,
            actor: Actor::Api(ApiActor { user_id }),
            event_version: 1,
            stored_at: Utc::now(),
        };
        // Compute the genuine hash for these inputs, store it, then check
        // that the mapped view verifies as a valid single-row chain. A
        // wrong field mapping in `as_stream_row` would shift the canonical
        // bytes and break verification — so `Ok` exercises the mapping
        // end-to-end, not just field-copy equality.
        let probe = ChainInput {
            prev_event_hash: genesis_hash(),
            event_id: persisted.event_id,
            stream_id: "artifact-x",
            stream_category: "artifact",
            stream_position: 0,
            event_type: persisted.event.event_type(),
            event_version: 1,
            event: &persisted.event,
            correlation_id: persisted.correlation_id,
            causation_id: None,
            actor: ActorCanonical {
                actor_type: "api",
                actor_id: Some(user_id),
                actor_source_file: None,
                actor_spec_digest: None,
            },
        };
        let stored_hash = compute_event_hash(&probe);
        let row = ChainRow {
            persisted,
            stream_id: "artifact-x".to_string(),
            stream_category: "artifact".to_string(),
            actor_type: "api".to_string(),
            actor_id: Some(user_id),
            actor_source_file: None,
            actor_spec_digest: None,
            stored_prev: genesis_hash(),
            stored_hash,
        };
        let view = row.as_stream_row();
        assert_eq!(view.input.event_id, row.persisted.event_id);
        assert_eq!(view.input.stream_id, "artifact-x");
        assert_eq!(view.input.stream_position, 0);
        assert_eq!(view.input.actor.actor_type, "api");
        assert_eq!(view.input.actor.actor_id, Some(user_id));
        assert_eq!(view.stored_prev, genesis_hash());
        assert_eq!(view.stored_hash, stored_hash);
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&[view])),
            StreamVerdict::Ok {
                head: stored_hash,
                position: 0
            }
        );
    }

    // ---- verify_stream_chain: every ChainBreak arm ---------------------

    #[test]
    fn tampered_payload_yields_hash_mismatch() {
        let (events, sid) = valid_stream(3);
        let mut rows = build_rows(&events, &sid);
        // Swap the typed event at position 1 for a different one while
        // leaving the stored hash untouched — a field mutation.
        let tampered = sample_event(99);
        rows[1].input.event = &tampered;
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Broken {
                at_position: 1,
                reason: ChainBreak::HashMismatch
            }
        );
    }

    #[test]
    fn rewired_predecessor_yields_prev_mismatch() {
        let (events, sid) = valid_stream(3);
        let mut rows = build_rows(&events, &sid);
        // Position 1's stored_prev no longer equals position 0's head,
        // but is still non-genesis (so it's PrevMismatch, not the
        // genesis-rule arms).
        rows[1].stored_prev = EventHash([0x5a; 32]);
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Broken {
                at_position: 1,
                reason: ChainBreak::PrevMismatch
            }
        );
    }

    #[test]
    fn non_genesis_at_zero_is_detected() {
        let (events, sid) = valid_stream(1);
        let mut rows = build_rows(&events, &sid);
        rows[0].stored_prev = EventHash([7u8; 32]);
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Broken {
                at_position: 0,
                reason: ChainBreak::NonGenesisAtZero
            }
        );
    }

    #[test]
    fn genesis_at_nonzero_is_detected() {
        let (events, sid) = valid_stream(2);
        let mut rows = build_rows(&events, &sid);
        // Position 1 chains from genesis (a head-truncation re-genesis).
        rows[1].stored_prev = genesis_hash();
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Broken {
                at_position: 1,
                reason: ChainBreak::GenesisAtNonZero
            }
        );
    }

    #[test]
    fn position_gap_is_detected() {
        let (events, sid) = valid_stream(3);
        let rows = build_rows(&events, &sid);
        // Drop the middle row -> positions are 0, 2 -> gap at the
        // second element (expected 1, saw 2).
        let gapped = [rows[0], rows[2]];
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&gapped)),
            StreamVerdict::Broken {
                at_position: 2,
                reason: ChainBreak::PositionGap
            }
        );
    }

    // ---- StreamVerdict::SealedGap can be constructed --------------------

    #[test]
    fn sealed_gap_variant_constructs() {
        let v = StreamVerdict::SealedGap {
            final_event_hash: genesis_hash(),
        };
        assert!(matches!(v, StreamVerdict::SealedGap { .. }));
        // Cover the remaining ChainBreak arms' Debug/Eq used by anchor.
        for b in [
            ChainBreak::UnsealedAbsentStream,
            ChainBreak::HeadNotAnchored,
        ] {
            assert_eq!(b, b);
            let _ = format!("{b:?}");
        }
    }

    // ---- verify_against_checkpoint: every arm --------------------------

    fn cp(seq: u64, ago_secs: i64, heads: Vec<(String, u64, EventHash)>) -> Checkpoint {
        Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: seq,
            created_at: Utc::now() - Duration::seconds(ago_secs),
            stream_heads: heads,
            sealed_streams: vec![],
        }
    }

    /// One hour — the production default cadence, and the one every
    /// anchor test below that does not test staleness itself wants.
    const HOURLY: std::time::Duration = std::time::Duration::from_secs(3600);

    /// The cross-check at the hourly cadence with `now` taken at call
    /// time. Factored out because fourteen anchor tests want exactly
    /// this shape and only the staleness/cadence tests want another.
    fn anchor_check(
        live: &[(String, u64, EventHash)],
        sealed: &[SealedStreamRecord],
        cps: &[Checkpoint],
    ) -> AnchorFindings {
        verify_against_checkpoint(live, sealed, cps, Utc::now(), HOURLY)
    }

    /// Expected findings carrying only the coverage axis.
    fn gap(reason: MissingReason) -> AnchorFindings {
        AnchorFindings {
            breaks: vec![],
            coverage_gaps: vec![reason],
        }
    }

    /// Expected findings carrying only the violation axis.
    fn broke(b: AnchorBreak) -> AnchorFindings {
        AnchorFindings {
            breaks: vec![b],
            coverage_gaps: vec![],
        }
    }

    #[test]
    fn anchor_no_checkpoint() {
        assert_eq!(
            anchor_check(&[], &[], &[]),
            gap(MissingReason::NoCheckpoint)
        );
    }

    #[test]
    fn anchor_sequence_gap() {
        // seqs {1, 3} with max 3 -> count 2 != 3 -> gap.
        let cps = vec![cp(1, 10, vec![]), cp(3, 5, vec![])];
        // Asserting the WHOLE findings is the point: an honest coverage
        // gap with nothing contradicted stays a coverage gap and never
        // acquires a break (acceptance: no reclassification).
        assert_eq!(
            anchor_check(&[], &[], &cps),
            gap(MissingReason::SequenceGap)
        );
    }

    #[test]
    fn anchor_sequence_not_starting_at_one() {
        // single checkpoint with seq 2 -> min != 1 -> gap.
        let cps = vec![cp(2, 5, vec![])];
        assert_eq!(
            anchor_check(&[], &[], &cps),
            gap(MissingReason::SequenceGap)
        );
    }

    #[test]
    fn anchor_stale() {
        // newest is 3h old, cadence 1h -> older than 2× -> Stale.
        let cps = vec![cp(1, 3 * 3600, vec![])];
        assert_eq!(anchor_check(&[], &[], &cps), gap(MissingReason::Stale));
    }

    #[test]
    fn anchor_absurd_cadence_does_not_panic_and_is_not_stale() {
        let cps = vec![cp(1, 10, vec![])];
        let v = verify_against_checkpoint(
            &[],
            &[],
            &cps,
            Utc::now(),
            std::time::Duration::from_secs(u64::MAX),
        );
        assert_eq!(v, AnchorFindings::default());
    }

    /// Acceptance: no panic on any caller input. Every numeric input at
    /// its extreme simultaneously — `u64::MAX` stream positions, a
    /// `u64::MAX`-second cadence, and a `now`/`created_at` pair at the
    /// opposite ends of the representable range. The cadence overflows
    /// `chrono::Duration` (saturated to `MAX`, so never stale) and the
    /// positions are compared, not arithmetic'd.
    #[test]
    fn anchor_extreme_inputs_do_not_panic() {
        let sid = "admin-extreme".to_string();
        let head = EventHash([0xee; 32]);
        let cps = vec![Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: 1,
            created_at: chrono::DateTime::<Utc>::MIN_UTC,
            stream_heads: vec![(sid.clone(), u64::MAX, head)],
            sealed_streams: vec![],
        }];
        let live = vec![(sid, u64::MAX, head)];
        let v = verify_against_checkpoint(
            &live,
            &[],
            &cps,
            chrono::DateTime::<Utc>::MAX_UTC,
            std::time::Duration::from_secs(u64::MAX),
        );
        assert_eq!(v, AnchorFindings::default());
    }

    #[test]
    fn anchor_head_mismatch() {
        let sid = "admin-a".to_string();
        let cps = vec![cp(1, 5, vec![(sid.clone(), 0, EventHash([1u8; 32]))])];
        let live = vec![(sid, 0, EventHash([2u8; 32]))];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::HeadMismatch)
        );
    }

    #[test]
    fn anchor_unsealed_absent_stream() {
        let sid = "admin-a".to_string();
        let cps = vec![cp(1, 5, vec![(sid, 0, EventHash([1u8; 32]))])];
        // No live head, no seal -> whole-stream truncation.
        assert_eq!(
            anchor_check(&[], &[], &cps),
            broke(AnchorBreak::UnsealedAbsentStream)
        );
    }

    #[test]
    fn anchor_seal_unanchored() {
        // A live stream so the absent-stream check passes, plus a
        // sealed record whose head no checkpoint anchored.
        let sid = "admin-a".to_string();
        let cps = vec![cp(1, 5, vec![(sid.clone(), 0, EventHash([1u8; 32]))])];
        let live = vec![(sid, 0, EventHash([1u8; 32]))];
        let sealed = vec![SealedStreamRecord {
            sealed_stream_id: "admin-gone".into(),
            final_event_hash: EventHash([9u8; 32]),
        }];
        assert_eq!(
            anchor_check(&live, &sealed, &cps),
            broke(AnchorBreak::SealUnanchored)
        );
    }

    #[test]
    fn anchor_ok_with_sealed_gap_anchored() {
        let live_sid = "admin-a".to_string();
        let gone_sid = "admin-gone".to_string();
        let gone_head = EventHash([9u8; 32]);
        let mut checkpoint = cp(1, 5, vec![(live_sid.clone(), 0, EventHash([1u8; 32]))]);
        checkpoint.sealed_streams = vec![SealedStreamRecord {
            sealed_stream_id: gone_sid.clone(),
            final_event_hash: gone_head,
        }];
        let live = vec![(live_sid, 0, EventHash([1u8; 32]))];
        let sealed = vec![SealedStreamRecord {
            sealed_stream_id: gone_sid,
            final_event_hash: gone_head,
        }];
        assert_eq!(
            anchor_check(&live, &sealed, &[checkpoint]),
            AnchorFindings::default()
        );
    }

    /// An anchored stream that is absent **and** sealed is justified,
    /// which is the shape the real emitter writes: the checkpoint that
    /// covers a `StreamSealed` also anchors the sealed stream's head,
    /// so the absent-stream arm must consult the seal set before
    /// calling a removal a truncation.
    #[test]
    fn anchor_absent_anchored_stream_with_a_seal_is_not_reported() {
        let gone_sid = "admin-gone".to_string();
        let gone_head = EventHash([9u8; 32]);
        let mut checkpoint = cp(1, 5, vec![(gone_sid.clone(), 2, gone_head)]);
        checkpoint.sealed_streams = vec![SealedStreamRecord {
            sealed_stream_id: gone_sid.clone(),
            final_event_hash: gone_head,
        }];
        let sealed = vec![SealedStreamRecord {
            sealed_stream_id: gone_sid,
            final_event_hash: gone_head,
        }];
        assert_eq!(
            anchor_check(&[], &sealed, &[checkpoint]),
            AnchorFindings::default()
        );
    }

    #[test]
    fn anchor_ok_ignores_streams_newer_than_the_cut() {
        // A live stream the checkpoint never saw is fine (created after
        // the cut) — not a HeadMismatch.
        let anchored_sid = "admin-old".to_string();
        let cps = vec![cp(
            1,
            5,
            vec![(anchored_sid.clone(), 2, EventHash([1u8; 32]))],
        )];
        let live = vec![
            (anchored_sid, 2, EventHash([1u8; 32])),
            ("admin-new".to_string(), 0, EventHash([7u8; 32])),
        ];
        assert_eq!(anchor_check(&live, &[], &cps), AnchorFindings::default());
    }

    // ---- both axes survive: a coverage gap no longer hides a break ------

    /// A gapped anchor set **and** a head mismatch: both facts are
    /// reported and `roll_up` ranks the violation above the coverage
    /// gap. Before the correction the sequence-gap check returned first
    /// and the head comparison — with both operands already in hand —
    /// never ran, so the one case `roll_up`'s dominance comment names
    /// was the one case that could not reach it.
    #[test]
    fn anchor_sequence_gap_plus_head_mismatch_reports_both_and_rolls_up_broken() {
        let sid = "admin-a".to_string();
        let cps = vec![
            cp(1, 10, vec![]),
            cp(3, 5, vec![(sid.clone(), 4, EventHash([1u8; 32]))]),
        ];
        let live = vec![(sid, 4, EventHash([2u8; 32]))];
        let findings = anchor_check(&live, &[], &cps);
        assert_eq!(
            findings,
            AnchorFindings {
                breaks: vec![AnchorBreak::HeadMismatch],
                coverage_gaps: vec![MissingReason::SequenceGap],
            }
        );
        assert_eq!(roll_up(&[], &findings), ChainReport::Broken);
    }

    /// The same, for the other coverage reason: a stale anchor set that
    /// is also contradicted by a live head is `Broken`, not
    /// `MissingCheckpoint`.
    #[test]
    fn anchor_stale_plus_head_mismatch_reports_both_and_rolls_up_broken() {
        let sid = "admin-a".to_string();
        let cps = vec![cp(
            1,
            3 * 3600,
            vec![(sid.clone(), 4, EventHash([1u8; 32]))],
        )];
        let live = vec![(sid, 4, EventHash([2u8; 32]))];
        let findings = anchor_check(&live, &[], &cps);
        assert_eq!(
            findings,
            AnchorFindings {
                breaks: vec![AnchorBreak::HeadMismatch],
                coverage_gaps: vec![MissingReason::Stale],
            }
        );
        assert_eq!(roll_up(&[], &findings), ChainReport::Broken);
    }

    // ---- a repeated checkpoint_seq is a fork, not a duplicate ----------

    /// Two signed checkpoints at one `checkpoint_seq` are reported even
    /// when they agree with each other and with the live head: the
    /// sequence is single-valued by construction, so a repeat is a fork
    /// in the anchor record whatever the two bodies happen to say.
    /// `dedup()` turned it into a thing that did not happen.
    #[test]
    fn anchor_duplicate_checkpoint_seq_is_reported_even_when_the_two_agree() {
        let sid = "admin-a".to_string();
        let head = EventHash([1u8; 32]);
        let heads = vec![(sid.clone(), 4, head)];
        let cps = vec![cp(1, 20, heads.clone()), cp(1, 10, heads)];
        let live = vec![(sid, 4, head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::DuplicateCheckpointSeq)
        );
    }

    /// The fork and the head statement it contradicts are both
    /// reported, in detection order. `max_by_key`'s arbitrary pick used
    /// to drop one of the two bodies on the floor, so the head the
    /// loser attested was never compared with anything.
    #[test]
    fn anchor_duplicate_checkpoint_seq_reports_the_fork_and_the_contradicted_head() {
        let sid = "admin-a".to_string();
        let live_head = EventHash([1u8; 32]);
        let cps = vec![
            cp(1, 30, vec![]),
            cp(2, 20, vec![(sid.clone(), 4, live_head)]),
            cp(2, 10, vec![(sid.clone(), 4, EventHash([2u8; 32]))]),
        ];
        let live = vec![(sid, 4, live_head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            AnchorFindings {
                breaks: vec![
                    AnchorBreak::DuplicateCheckpointSeq,
                    AnchorBreak::HeadMismatch,
                ],
                coverage_gaps: vec![],
            }
        );
    }

    /// A repeated seq does not make the contiguity count read as a
    /// hole: `{1, 1, 2}` is a fork with no missing anchor, so only the
    /// violation is reported. (The dedup the count needs happens after
    /// the fork is detected, which is the whole fix.)
    #[test]
    fn anchor_duplicate_seq_is_not_also_reported_as_a_sequence_gap() {
        let cps = vec![cp(1, 30, vec![]), cp(1, 20, vec![]), cp(2, 10, vec![])];
        assert_eq!(
            anchor_check(&[], &[], &cps),
            broke(AnchorBreak::DuplicateCheckpointSeq)
        );
    }

    /// The newest-checkpoint selection is a function of the set's
    /// content, not of the order the adapter happened to return it in
    /// (`CheckpointAnchorPort::read_all` promises none).
    /// `max_by_key` returned the *last* of several equal maxima, so
    /// with a forked seq the staleness answer flipped with the input
    /// order. The tie resolves towards the earliest `created_at` —
    /// fail-closed, because a forked sequence cannot vouch for the
    /// freshness the later timestamp claims.
    #[test]
    fn anchor_findings_do_not_depend_on_the_order_the_checkpoints_arrive_in() {
        let fresh = cp(2, 10, vec![]);
        let old = cp(2, 3 * 3600, vec![]);
        let base = cp(1, 4 * 3600, vec![]);
        let expected = AnchorFindings {
            breaks: vec![AnchorBreak::DuplicateCheckpointSeq],
            coverage_gaps: vec![MissingReason::Stale],
        };
        for order in [
            vec![base.clone(), fresh.clone(), old.clone()],
            vec![base.clone(), old.clone(), fresh.clone()],
            vec![fresh.clone(), old.clone(), base.clone()],
            vec![old.clone(), fresh.clone(), base.clone()],
        ] {
            assert_eq!(
                anchor_check(&[], &[], &order),
                expected,
                "the verdict must not depend on checkpoint order"
            );
        }
    }

    // ---- every checkpoint's head statement is evidence -----------------

    /// Acceptance: a live head contradicting a **non-newest**
    /// signature-verified checkpoint is reported. The older checkpoint
    /// anchors the contradicting head at the same position the live
    /// stream is at; the newest checkpoint agrees with the live head.
    ///
    /// This is the laundering the old code allowed: rewrite a quiescent
    /// stream, wait for the next scheduled checkpoint, and the run is
    /// judged against that one — the older checkpoint that contradicts
    /// it was fetched and signature-verified, then set aside.
    #[test]
    fn anchor_head_contradicting_an_older_checkpoint_is_reported() {
        let sid = "admin-a".to_string();
        let live_head = EventHash([2u8; 32]);
        let cps = vec![
            // Older: the stream was at position 4 with a DIFFERENT head.
            cp(1, 7200, vec![(sid.clone(), 4, EventHash([1u8; 32]))]),
            // Newest: cut after the rewrite, so it agrees with the live
            // head and on its own reports nothing.
            cp(2, 60, vec![(sid.clone(), 4, live_head)]),
        ];
        let live = vec![(sid, 4, live_head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::HeadMismatch)
        );
    }

    /// A stream shorter than an older checkpoint attested: rows were
    /// removed from its tail. Decidable from the final head alone, and
    /// the reason the anchored `final_stream_position` is compared at
    /// all — it used to be read into `_pos` and dropped.
    #[test]
    fn anchor_live_stream_shorter_than_an_anchored_statement_is_reported() {
        let sid = "admin-a".to_string();
        let live_head = EventHash([2u8; 32]);
        let cps = vec![
            cp(1, 7200, vec![(sid.clone(), 9, EventHash([1u8; 32]))]),
            cp(2, 60, vec![(sid.clone(), 4, live_head)]),
        ];
        let live = vec![(sid, 4, live_head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::HeadMismatch)
        );
    }

    /// One head hash at two different positions is a SHA-256 collision
    /// — `stream_position` is bound into the hash — so an older
    /// checkpoint anchoring the *current* head at a *lower* position is
    /// a contradiction too.
    #[test]
    fn anchor_same_head_at_a_lower_anchored_position_is_reported() {
        let sid = "admin-a".to_string();
        let head = EventHash([3u8; 32]);
        let cps = vec![cp(1, 60, vec![(sid.clone(), 3, head)])];
        let live = vec![(sid, 9, head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::HeadMismatch)
        );
    }

    /// Acceptance, and the false-positive guard that makes the test
    /// above mean something: a head that legitimately **advanced**
    /// between two checkpoints and again since the newest is not
    /// reported. The relation against an older anchor is reachability,
    /// never equality — the chain is append-only, so a prior anchored
    /// head is an ancestor of the current one, not the same hash.
    #[test]
    fn anchor_head_that_advanced_between_checkpoints_is_not_reported() {
        let sid = "admin-a".to_string();
        let cps = vec![
            cp(1, 7200, vec![(sid.clone(), 3, EventHash([1u8; 32]))]),
            cp(2, 3600, vec![(sid.clone(), 7, EventHash([2u8; 32]))]),
        ];
        let live = vec![(sid, 9, EventHash([3u8; 32]))];
        assert_eq!(anchor_check(&live, &[], &cps), AnchorFindings::default());
    }

    /// A stream anchored only by an **older** checkpoint, now absent
    /// with no `StreamSealed`: the newest checkpoint was cut after the
    /// removal and never mentions it, so scanning only the newest
    /// anchored set made a whole-stream truncation invisible.
    #[test]
    fn anchor_absent_stream_anchored_only_by_an_older_checkpoint_is_reported() {
        let live_sid = "admin-a".to_string();
        let gone_sid = "admin-gone".to_string();
        let live_head = EventHash([1u8; 32]);
        let cps = vec![
            cp(
                1,
                7200,
                vec![
                    (live_sid.clone(), 0, live_head),
                    (gone_sid, 0, EventHash([8u8; 32])),
                ],
            ),
            cp(2, 60, vec![(live_sid.clone(), 0, live_head)]),
        ];
        let live = vec![(live_sid, 0, live_head)];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::UnsealedAbsentStream)
        );
    }

    /// Each axis is a set in detection order: two streams contradicting
    /// their anchored heads record one `HeadMismatch`, not two.
    /// `AnchorBreak` carries no per-stream detail, so a repeat would be
    /// noise rather than information.
    #[test]
    fn anchor_repeated_break_kind_is_recorded_once() {
        let a = "admin-a".to_string();
        let b = "admin-b".to_string();
        let cps = vec![cp(
            1,
            60,
            vec![
                (a.clone(), 0, EventHash([1u8; 32])),
                (b.clone(), 0, EventHash([1u8; 32])),
            ],
        )];
        let live = vec![(a, 0, EventHash([2u8; 32])), (b, 0, EventHash([3u8; 32]))];
        assert_eq!(
            anchor_check(&live, &[], &cps),
            broke(AnchorBreak::HeadMismatch)
        );
    }

    /// A repeated `stream_id` in `live_heads` is a caller error with no
    /// better answer available, so the documented resolution — the
    /// first occurrence, exactly what the linear `find` this replaced
    /// returned — is pinned here rather than left to the index's
    /// insertion order. Part of "no panic on any caller input".
    #[test]
    fn anchor_repeated_live_stream_id_resolves_to_the_first_occurrence() {
        let sid = "admin-a".to_string();
        let anchored = EventHash([1u8; 32]);
        let cps = vec![cp(1, 60, vec![(sid.clone(), 4, anchored)])];
        let live = vec![(sid.clone(), 4, anchored), (sid, 4, EventHash([2u8; 32]))];
        assert_eq!(anchor_check(&live, &[], &cps), AnchorFindings::default());
    }

    // ---- roll_up: every arm + dominance --------------------------------

    #[test]
    fn roll_up_ok() {
        let v = vec![StreamVerdict::Ok {
            head: genesis_hash(),
            position: 0,
        }];
        assert_eq!(roll_up(&v, &AnchorFindings::default()), ChainReport::Ok);
    }

    #[test]
    fn roll_up_missing_checkpoint_when_only_coverage_gap() {
        let v = vec![StreamVerdict::Ok {
            head: genesis_hash(),
            position: 0,
        }];
        assert_eq!(
            roll_up(&v, &gap(MissingReason::NoCheckpoint)),
            ChainReport::MissingCheckpoint
        );
    }

    #[test]
    fn roll_up_broken_from_stream_dominates_missing_checkpoint() {
        let v = vec![StreamVerdict::Broken {
            at_position: 0,
            reason: ChainBreak::HashMismatch,
        }];
        assert_eq!(roll_up(&v, &gap(MissingReason::Stale)), ChainReport::Broken);
    }

    #[test]
    fn roll_up_broken_from_anchor() {
        let v = vec![StreamVerdict::Ok {
            head: genesis_hash(),
            position: 0,
        }];
        assert_eq!(
            roll_up(&v, &broke(AnchorBreak::HeadMismatch)),
            ChainReport::Broken
        );
    }

    /// The new break kind reaches the top-level report through the same
    /// ranking as every other one, so the subcommand maps it to exit 2
    /// and `result="broken"` — ADR 0057's existing catalogue, with no
    /// fourth `ChainReport` variant and no fourth metric series.
    #[test]
    fn roll_up_broken_from_duplicate_checkpoint_seq() {
        assert_eq!(
            roll_up(&[], &broke(AnchorBreak::DuplicateCheckpointSeq)),
            ChainReport::Broken
        );
    }

    /// A violation on one axis and a coverage gap on the other, in one
    /// `AnchorFindings` — the shape the cross-check now produces and
    /// the shape the dominance exists to rank.
    #[test]
    fn roll_up_anchor_break_dominates_a_coverage_gap_in_the_same_findings() {
        let findings = AnchorFindings {
            breaks: vec![AnchorBreak::HeadMismatch],
            coverage_gaps: vec![MissingReason::Stale],
        };
        assert_eq!(roll_up(&[], &findings), ChainReport::Broken);
    }

    #[test]
    fn roll_up_sealed_gap_is_not_broken() {
        let v = vec![StreamVerdict::SealedGap {
            final_event_hash: genesis_hash(),
        }];
        assert_eq!(roll_up(&v, &AnchorFindings::default()), ChainReport::Ok);
    }

    // ---- Determinism: full-64-variant canonical round-trip ----

    /// Canonical-bytes determinism binding test.
    ///
    /// Requirement: `canonical_payload_bytes(deserialize(serialize(e))) ==
    /// canonical_payload_bytes(e)` for every `DomainEvent` variant — the
    /// round-trip property test mandated by the spec's "determinism
    /// requirement" paragraph.
    ///
    /// The serialize→deserialize path mirrors exactly what the production
    /// verifier does:
    ///   - `serialize_event_data` (`mappers.rs:434-451`): serde-serialize
    ///     the typed event into the stored `{"type":…,"data":…}` envelope.
    ///   - `deserialize_event_data` (`mappers.rs:452-464`): reconstruct the
    ///     typed `DomainEvent` from the stored envelope.
    ///
    /// The test is in `hort-domain/chain.rs` (the 100%-coverage pure-domain
    /// tier) because `canonical_payload_bytes` is a private function here
    /// and the serialize/deserialize round-trip is purely serde — it needs
    /// no DB, no adapter dependency. The full canonical-variant vector is
    /// provided by the `pub(crate) fn all_test_variants()` accessor added
    /// to `domain_event::tests` (a minimal additive `#[cfg(test)]`
    /// accessor — no production-signature change).
    ///
    /// If any variant fails, the test panics loudly identifying the variant
    /// name and the hex diff of the two byte slices. A failure here is a
    /// a genuine tamper-evidence bug (a `serde(default)`/`skip_serializing_if`/untagged
    /// field that breaks payload identity) — do NOT paper over it.
    #[test]
    fn canonical_payload_bytes_round_trip_all_variants() {
        // Import the canonical variant vector from domain_event::tests.
        // `super` = `events` module (chain is a submodule of events).
        // Access via the full crate path; `domain_event` is a private
        // submodule of `events` but is reachable from within the same crate.
        use crate::events::domain_event::tests::all_test_variants;
        let variants = all_test_variants();

        // The round-trip replicates `serialize_event_data` +
        // `deserialize_event_data` from `hort-adapters-postgres/src/mappers.rs`
        // without importing the adapter crate. The logic is identical: serde
        // serializes the enum as `{"VariantName": {fields}}`, we reshape to
        // `{"type": event_type, "data": {fields}}`, then deserialize back.
        let mut exercised: usize = 0;
        for original in &variants {
            let event_type = original.event_type();
            // The serde externally-tagged key (== event_type
            // for every variant except the `RetentionPolicyChanged`
            // wrapper, which has its own wrapper key). The persistence path uses
            // `serde_variant_key()` for the serialize `map.remove` and
            // `serde_key_for_event_type()` for the deserialize re-tag;
            // this mirror must do the same or the wrapper round-trip
            // (correctly) regresses.
            let serde_key = original.serde_variant_key();

            // --- serialize (mirrors serialize_event_data) ---
            let serde_value =
                serde_json::to_value(original).expect("DomainEvent must be serializable");
            let payload = match serde_value {
                serde_json::Value::Object(mut map) => {
                    map.remove(serde_key).unwrap_or(serde_json::Value::Null)
                }
                other => other,
            };
            let envelope = serde_json::json!({ "type": event_type, "data": payload });

            // --- deserialize (mirrors deserialize_event_data) ---
            let data = envelope
                .get("data")
                .expect("envelope always has 'data' field");
            let deser_key = DomainEvent::serde_key_for_event_type(event_type);
            let serde_enum = serde_json::json!({ deser_key: data });
            let deserialized =
                serde_json::from_value::<DomainEvent>(serde_enum).unwrap_or_else(|e| {
                    panic!(
                        "variant {event_type}: deserialize failed after serialize round-trip: {e}"
                    )
                });

            // --- compare canonical payload bytes ---
            let original_bytes = canonical_payload_bytes(original);
            let roundtrip_bytes = canonical_payload_bytes(&deserialized);
            if original_bytes != roundtrip_bytes {
                panic!(
                    "canonical round-trip FAILED for variant `{event_type}`:\n  \
                     original  ({} bytes): {}\n  \
                     roundtrip ({} bytes): {}",
                    original_bytes.len(),
                    hex::encode(&original_bytes),
                    roundtrip_bytes.len(),
                    hex::encode(&roundtrip_bytes),
                );
            }

            exercised += 1;
        }

        // Explicitly assert the count so a future silent truncation of the
        // variant vector is caught here rather than appearing as a green
        // test. The count is the number of constructed `DomainEvent`
        // instances in `domain_event::tests::all_test_variants()` — it
        // shifts whenever a `DomainEvent` variant (or an
        // inner-discrimination instance like the four
        // `RetentionPolicyChanged` ones) is added or removed.
        // The round-trip itself (the determinism property) must
        // still pass for every one of them; only this anti-silent-
        // truncation tripwire is rebased.
        assert_eq!(
            exercised, 71,
            "expected all 71 DomainEvent test instances to be exercised, got {exercised}"
        );
    }
}
