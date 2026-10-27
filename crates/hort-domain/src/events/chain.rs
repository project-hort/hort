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
//! **The attested object is the row.** Every field the hash binds is a
//! column, taken in the form the row holds it — including the payload,
//! which is the `event_data` value itself rather than a re-serialization
//! of a typed [`DomainEvent`](super::DomainEvent) decoded from it. The
//! two are not the same statement, and the difference is the whole
//! integrity claim above: a re-derivation covers only what today's types
//! can express, so a payload key matching no struct field would be
//! dropped before the recomputation and the mutation would verify `Ok`,
//! while a field added later with a bare `#[serde(default)]` would be
//! *added* to the recomputation and report a mismatch on rows nobody
//! touched. Hashing the stored bytes closes both. Key order is the one
//! difference normalised away, because `jsonb` does not preserve it.
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

/// Golden canonical-byte vectors — frozen stored envelopes plus the
/// `event_hash` computed over them, read from checked-in text. A
/// submodule of `chain` so the measurement can read the real
/// [`canonical_payload_bytes`] instead of a second opinion about it.
#[cfg(test)]
mod chain_vectors;

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
/// design. Every other field is a column, carried in the exact form the
/// row holds it: the hash is a function of the row and of nothing else.
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
    /// The `event_data` payload envelope — on the append path the very
    /// value being written to the column, on the verify path the value
    /// read back out of it. Canonicalized (object keys sorted) and
    /// length-prefixed into field 8; never re-derived from a typed
    /// event. [`stored_payload_envelope`](super::stored_payload_envelope)
    /// is its single producer.
    pub payload: &'a serde_json::Value,
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

/// Canonical payload bytes: the stored `{"type":…,"data":…}` envelope
/// with object keys recursively sorted, serialized.
///
/// The hash input is a function of the **stored payload** — on the
/// append path the exact value bound to the `event_data` column, on the
/// verify path the exact value read back from it. Nothing is
/// re-serialized through `DomainEvent`, so the attested object is the
/// row: a payload key that matches no struct field is covered, and a row
/// written before a field existed re-derives the bytes it was stored
/// with rather than today's wider shape.
///
/// Key order is the one difference normalised away, because `jsonb` does
/// not preserve it; everything else the column holds reaches the hash
/// verbatim.
///
/// Infallible: a `serde_json::Value` is always serializable, so the
/// append path gains no new fallible step.
fn canonical_payload_bytes(payload: &serde_json::Value) -> Vec<u8> {
    let canonical = canonicalize_json(payload);
    serde_json::to_vec(&canonical).expect("canonical JSON value is always serializable")
}

/// Recursively rewrite every object so its keys are emitted in
/// lexicographic order. Arrays keep element order (semantically
/// significant); scalars pass through.
///
/// With the features this workspace resolves, `serde_json::Map` is a
/// `BTreeMap` and already serialises sorted, so this is currently the
/// identity on key order — and it stays here precisely because that is a
/// *feature's* behaviour rather than a guarantee. Enabling
/// `preserve_order` swaps the backing map for an `IndexMap`, at which
/// point key order becomes insertion order and the canonical form of
/// every payload would move; it is the same hazard class as
/// `float_roundtrip` (see
/// `hort-domain/tests/float_roundtrip_is_pinned.rs`), and this function
/// is what makes the derivation immune to it rather than dependent on
/// it. `jsonb` does not preserve key order anyway, so sorting is also
/// the only honest reading of "the bytes the row holds".
fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in entries {
                out.insert(k.clone(), canonicalize_json(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_json).collect())
        }
        scalar => scalar.clone(),
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
    let payload = canonical_payload_bytes(input.payload);
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
    /// The recompute inputs (the stored payload + the envelope columns).
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
/// verifier core needs — and nothing else: the `event_data` payload
/// verbatim, the envelope columns the hash binds, the four persisted
/// actor columns in their exact stored string form, and the two stored
/// chain hashes.
///
/// **No typed event.** Verification recomputes the hash from the stored
/// payload, so it never needs to know whether today's `DomainEvent` can
/// still decode that payload. That matters for the control's
/// availability, not just its tidiness: while this row carried a
/// deserialized `PersistedEvent`, a payload the current types could no
/// longer read — a field later made required, a renamed variant — failed
/// the read with an operational error *before* the verifier reached the
/// hash, so the one tool that could prove the row was intact refused to
/// run on it. The columns it used to supply through the typed event
/// (`event_type`, the positions, `event_version`, correlation/causation)
/// are columns the reader already selects.
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
    /// The `event_data` JSONB column, verbatim — the object the hash
    /// attests.
    pub event_data: serde_json::Value,
    /// `event_id` column.
    pub event_id: uuid::Uuid,
    /// `stream_id` text column, exactly as persisted.
    pub stream_id: String,
    /// `stream_category` text column.
    pub stream_category: String,
    /// `stream_position` column (0-based, per stream).
    pub stream_position: u64,
    /// `event_type` text column — the stored discriminator, not a
    /// re-derivation of it from a decoded event.
    pub event_type: String,
    /// `event_version` column.
    pub event_version: u32,
    /// `correlation_id` column.
    pub correlation_id: uuid::Uuid,
    /// `causation_id` column.
    pub causation_id: Option<uuid::Uuid>,
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
                event_id: self.event_id,
                stream_id: &self.stream_id,
                stream_category: &self.stream_category,
                stream_position: self.stream_position,
                event_type: &self.event_type,
                event_version: self.event_version,
                payload: &self.event_data,
                correlation_id: self.correlation_id,
                causation_id: self.causation_id,
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

    /// The stored payload envelope for [`sample_event`] — the value the
    /// `event_data` column holds, produced by the single producer the
    /// append path uses.
    fn sample_payload(n: u32) -> serde_json::Value {
        crate::events::stored_payload_envelope(&sample_event(n))
    }

    fn input<'a>(
        prev: EventHash,
        position: u64,
        payload: &'a serde_json::Value,
        stream_id: &'a str,
    ) -> ChainInput<'a> {
        ChainInput {
            prev_event_hash: prev,
            event_id: Uuid::from_u128(0xE0 + position as u128),
            stream_id,
            stream_category: "artifact",
            stream_position: position,
            // The stored `event_type` column and the envelope's `type`
            // key are written from the same `event_type()` on the append
            // path, so reading it back off the envelope here keeps the
            // helper to one input.
            event_type: payload["type"]
                .as_str()
                .expect("a stored envelope carries a `type` string"),
            event_version: 1,
            payload,
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
    /// stored payloads + the stream id (the row views borrow both).
    fn valid_stream(n: u64) -> (Vec<serde_json::Value>, String) {
        let payloads: Vec<serde_json::Value> = (0..n).map(|i| sample_payload(i as u32)).collect();
        (payloads, "artifact-deadbeef".to_string())
    }

    fn build_rows<'a>(payloads: &'a [serde_json::Value], stream_id: &'a str) -> Vec<StreamRow<'a>> {
        let mut rows = Vec::new();
        let mut prev = genesis_hash();
        for (i, e) in payloads.iter().enumerate() {
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
        let e = sample_payload(1);
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
        let e = sample_payload(1);
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
        let e2 = sample_payload(2);
        assert_ne!(
            base,
            compute_event_hash(&input(genesis_hash(), 0, &e2, "artifact-x"))
        );
    }

    /// Key order is the one difference the canonicalisation removes —
    /// which it must, because `jsonb` does not preserve insertion order,
    /// so the order the writer happened to emit is not a property of the
    /// row.
    #[test]
    fn payload_canonicalization_sorts_object_keys_recursively() {
        // Two logically-equal stored envelopes whose key insertion order
        // differs at every level, including inside the payload's own
        // `serde_json::Value` fields.
        let a = serde_json::json!({
            "type": "PolicyUpdated",
            "data": {"new_value": {"b": 1, "a": {"d": 4, "c": 3}}, "field": "Name"}
        });
        let b = serde_json::json!({
            "data": {"field": "Name", "new_value": {"a": {"c": 3, "d": 4}, "b": 1}},
            "type": "PolicyUpdated"
        });
        assert_eq!(canonical_payload_bytes(&a), canonical_payload_bytes(&b));
        // And it is only key order: a different *value* still moves the
        // bytes, so the sort is not flattening the payload.
        let c = serde_json::json!({
            "type": "PolicyUpdated",
            "data": {"new_value": {"b": 2, "a": {"d": 4, "c": 3}}, "field": "Name"}
        });
        assert_ne!(canonical_payload_bytes(&a), canonical_payload_bytes(&c));
    }

    /// A stored payload key that matches no `DomainEvent` field reaches
    /// the hash. This is the property the re-derivation could not have:
    /// decoding the payload into a typed event dropped such a key, so
    /// the recomputation reproduced the untampered bytes and an added
    /// key verified `Ok`.
    #[test]
    fn a_payload_key_matching_no_struct_field_changes_the_hash() {
        let clean = sample_payload(1);
        let mut injected = clean.clone();
        injected["data"]["injected_key_matching_no_struct_field"] = serde_json::json!("tampered");
        assert_ne!(
            canonical_payload_bytes(&clean),
            canonical_payload_bytes(&injected),
            "an added payload key must be covered by the hash"
        );
        // The same statement at the hash level, through the production
        // entry point rather than the payload helper.
        let sid = "artifact-x";
        assert_ne!(
            compute_event_hash(&input(genesis_hash(), 0, &clean, sid)),
            compute_event_hash(&input(genesis_hash(), 0, &injected, sid))
        );
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
        let c = canonicalize_json(&v);
        // Serialized form has keys in sorted order at every level and
        // array element order preserved.
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"a":"scalar","z":[{"a":2,"b":1},{"c":3,"d":4}]}"#
        );
    }

    /// Array element order is semantically significant and must survive
    /// the canonicalisation untouched — unlike object key order.
    /// `PermissionGrantApplied`'s `subject` (Claims) carries a
    /// `Vec<String>`, so this exercises the Array arm through a real
    /// event's stored envelope.
    #[test]
    fn payload_with_array_field_keeps_element_order() {
        use crate::entities::rbac::Permission;
        use crate::events::{GrantSubjectRecord, PermissionGrantApplied};
        let mk = |required: Vec<String>| {
            crate::events::stored_payload_envelope(&DomainEvent::PermissionGrantApplied(
                PermissionGrantApplied {
                    grant_id: Uuid::nil(),
                    subject: GrantSubjectRecord::Claims { required },
                    permission: Permission::Read,
                    repository_id: None,
                },
            ))
        };
        let a = mk(vec!["developer".into(), "team-alpha".into()]);
        let reversed = mk(vec!["team-alpha".into(), "developer".into()]);
        assert_eq!(canonical_payload_bytes(&a), canonical_payload_bytes(&a));
        assert_ne!(
            canonical_payload_bytes(&a),
            canonical_payload_bytes(&reversed),
            "array order is part of the payload and must reach the hash"
        );
    }

    #[test]
    fn canonical_encoding_covers_some_optional_and_gitops_actor() {
        // Exercise the Some-branches of causation_id and the gitops
        // actor (actor_id None, source_file + spec_digest Some).
        let e = sample_payload(3);
        let digest = [0xab_u8; 32];
        let i = ChainInput {
            prev_event_hash: genesis_hash(),
            event_id: Uuid::from_u128(7),
            stream_id: "artifact-z",
            stream_category: "artifact",
            stream_position: 0,
            event_type: "ArtifactIngested",
            event_version: 2,
            payload: &e,
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

    /// A `ChainRow` built from stored columns maps into a view that
    /// verifies. A wrong field mapping in `as_stream_row` would shift the
    /// canonical bytes and break verification, so `Ok` exercises the
    /// mapping end-to-end rather than field-copy equality.
    #[test]
    fn chain_row_as_stream_row_round_trips_into_a_verifiable_view() {
        let user_id = Uuid::from_u128(0xA9);
        let event_data = sample_payload(1);
        let probe = ChainInput {
            prev_event_hash: genesis_hash(),
            event_id: Uuid::from_u128(0xE0),
            stream_id: "artifact-x",
            stream_category: "artifact",
            stream_position: 0,
            event_type: "ArtifactIngested",
            event_version: 1,
            payload: &event_data,
            correlation_id: Uuid::from_u128(0xC0FFEE),
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
            event_data: event_data.clone(),
            event_id: Uuid::from_u128(0xE0),
            stream_id: "artifact-x".to_string(),
            stream_category: "artifact".to_string(),
            stream_position: 0,
            event_type: "ArtifactIngested".to_string(),
            event_version: 1,
            correlation_id: Uuid::from_u128(0xC0FFEE),
            causation_id: None,
            actor_type: "api".to_string(),
            actor_id: Some(user_id),
            actor_source_file: None,
            actor_spec_digest: None,
            stored_prev: genesis_hash(),
            stored_hash,
        };
        let view = row.as_stream_row();
        assert_eq!(view.input.event_id, Uuid::from_u128(0xE0));
        assert_eq!(view.input.stream_id, "artifact-x");
        assert_eq!(view.input.stream_position, 0);
        assert_eq!(view.input.event_type, "ArtifactIngested");
        assert_eq!(view.input.payload, &event_data);
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

        // The mapping is not vacuous: a mutated payload in the same row
        // breaks the recomputation. `event_data` is the only field the
        // row carries that the typed-event version did not expose
        // directly, so this is the assertion the decoupling added.
        let mut tampered = row.clone();
        tampered.event_data["data"]["name"] = serde_json::json!("rewritten");
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&[tampered.as_stream_row()])),
            StreamVerdict::Broken {
                at_position: 0,
                reason: ChainBreak::HashMismatch
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
        let tampered = sample_payload(99);
        rows[1].input.payload = &tampered;
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

    // ---- Determinism: the stored envelope round-trips ----

    /// Every `DomainEvent` variant's stored envelope is a fixed point of
    /// store-then-rehydrate: decoding the envelope back to a typed event
    /// and re-producing it yields the same canonical bytes.
    ///
    /// **What this is, after the chain started hashing the stored
    /// payload.** It is no longer the chain's premise — verification
    /// recomputes from the column and never re-serialises a typed event,
    /// so a round-trip failure can no longer make an untouched row read
    /// as tampered. What it still pins is the *write* path's
    /// determinism: the same fact, stored and rehydrated, stores
    /// identically. That is what makes two appends of one fact
    /// comparable, and what a replay or a re-emit depends on. A failure
    /// here is a genuine payload-identity bug (a `serde(default)` /
    /// `skip_serializing_if` / untagged field that does not survive its
    /// own decode) — do NOT paper over it.
    ///
    /// The producer under test is the real one,
    /// [`stored_payload_envelope`](super::stored_payload_envelope), which
    /// `hort-adapters-postgres::mappers::serialize_event_data` delegates
    /// to — not an inline copy of it. The decode mirrors
    /// `mappers::deserialize_event_data`: re-tag `data` with the serde
    /// variant key the stored `type` maps to, then deserialize. (The
    /// decode cannot be shared, since it lives in the adapter and this is
    /// `hort-domain`; it is three lines and the two keys it uses —
    /// `serde_variant_key()` and `serde_key_for_event_type()` — are
    /// `hort-domain`'s own.)
    #[test]
    fn stored_envelope_is_a_fixed_point_of_store_then_rehydrate() {
        use crate::events::domain_event::tests::all_test_variants;
        use crate::events::stored_payload_envelope;
        let variants = all_test_variants();

        let mut exercised: usize = 0;
        for original in &variants {
            let event_type = original.event_type();
            let envelope = stored_payload_envelope(original);

            // --- decode (mirrors deserialize_event_data) ---
            let data = envelope
                .get("data")
                .expect("the stored envelope always has a 'data' field");
            let deser_key = DomainEvent::serde_key_for_event_type(event_type);
            let rehydrated =
                serde_json::from_value::<DomainEvent>(serde_json::json!({ deser_key: data }))
                    .unwrap_or_else(|e| {
                        panic!("variant {event_type}: the stored envelope does not decode: {e}")
                    });

            let stored_bytes = canonical_payload_bytes(&envelope);
            let rehydrated_bytes = canonical_payload_bytes(&stored_payload_envelope(&rehydrated));
            if stored_bytes != rehydrated_bytes {
                panic!(
                    "stored-envelope round trip FAILED for variant `{event_type}`:\n  \
                     stored     ({} bytes): {}\n  \
                     rehydrated ({} bytes): {}",
                    stored_bytes.len(),
                    hex::encode(&stored_bytes),
                    rehydrated_bytes.len(),
                    hex::encode(&rehydrated_bytes),
                );
            }

            exercised += 1;
        }

        // Explicitly assert the count so a future silent truncation of
        // the variant vector is caught here rather than appearing as a
        // green test. The count is the number of constructed
        // `DomainEvent` instances in
        // `domain_event::tests::all_test_variants()` — it shifts whenever
        // a `DomainEvent` variant (or an inner-discrimination instance
        // like the four `RetentionPolicyChanged` ones) is added or
        // removed. The round trip itself must still pass for every one of
        // them; only this anti-silent-truncation tripwire is rebased.
        assert_eq!(
            exercised, 71,
            "expected all 71 DomainEvent test instances to be exercised, got {exercised}"
        );
    }
}
