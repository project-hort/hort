//! Golden canonical-byte vectors for the tamper-evident event chain.
//!
//! Each vector is **frozen text** in
//! `crates/hort-domain/tests/fixtures/chain_vectors.json`: a stored
//! `{"type":…,"data":…}` envelope exactly as the event store holds it, the
//! `event_hash` that was computed over it, and the envelope columns
//! [`compute_event_hash`] binds alongside the payload. Nothing here
//! constructs an event and hashes it — a fixture built at test time would
//! move with the code it is supposed to police, and so would pin nothing.
//!
//! The chain's integrity claim is that `event_hash` covers the event's
//! canonical bytes, and [`ChainInput::payload`] is the stored envelope,
//! so these vectors are the measurement of that claim against frozen
//! text: for every one of them the recomputation has to land back on the
//! `event_hash` the fixture records.
//!
//! The vectors exist because this was not always true. The payload used
//! to be re-derived by deserialising the stored envelope into today's
//! typed event and re-serialising it, which made the hashed bytes a
//! function of the current struct definitions rather than of the row:
//! 10 of the 13 older stored shapes here did not reproduce — a payload
//! field added with a bare `#[serde(default)]` always emits its key, so
//! every row written before the field existed re-derived with a key its
//! stored bytes do not have. [`DIVERGENT_VECTORS`] is the inventory of
//! that gap, and it is now empty.
//!
//! The verdict always comes from the production entry points
//! ([`verify_stream_chain`] over a one-row stream, which is
//! [`compute_event_hash`] plus the genesis/contiguity rules); the
//! per-key diagnostic comes from [`super::canonical_payload_bytes`]
//! itself, so what the report names is what the hash saw.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::{
    canonical_payload_bytes, verify_stream_chain, ActorCanonical, ChainBreak, ChainInput,
    EventHash, StreamRow, StreamRows, StreamVerdict,
};
use crate::events::domain_event::tests::all_test_variants;
use crate::events::DomainEvent;

/// The frozen vectors. Read as text; no code in this crate regenerates
/// them, and none may.
const VECTORS_JSON: &str = include_str!("../../../tests/fixtures/chain_vectors.json");

// ---------------------------------------------------------------------------
// The recorded divergences
// ---------------------------------------------------------------------------

/// Every vector whose stored bytes today's code does **not** reproduce,
/// with the measured key delta and the mechanism behind it.
///
/// **Empty, and the empty state is the assertion.** This is an inventory
/// of a known gap, not an exemption list: the test below asserts the
/// measured divergent set **equals** this constant in both directions,
/// so a new divergence fails and nothing can be waived by adding an
/// entry without also recording the exact key delta it produces.
///
/// It held ten entries while the hash was recomputed from a typed event
/// deserialised out of the stored envelope. Nine were one mechanism — a
/// payload field added with a bare `#[serde(default)]` and no
/// `skip_serializing_if` always emits its key, so a row written before
/// the field existed re-derived with a key its stored bytes do not have
/// and [`ChainBreak::HashMismatch`] was reported on a row nobody
/// touched (`ArtifactIngested`'s `metadata` / `metadata_blob` /
/// `upstream_published_at`, `ScanCompleted.findings_blob`,
/// `Finding`'s four late fields, `TaskInvoked.duplicate_of`). The tenth
/// rewrote the payload rather than adding to it:
/// `ArtifactReEvaluated`'s hand-written `Deserialize` widens the legacy
/// `trigger_exclusion_id` key onto the `trigger` discriminator, and
/// `Serialize` emits only the new shape.
///
/// All ten are closed by the same change and none of them needed a
/// `skip_serializing_if` retrofit — which would have repaired the small
/// old cohort by breaking the large current one. The hash covers the
/// payload as the row holds it, so a stored shape older than today's
/// struct reproduces its own bytes, and the deserialiser's widening
/// stays correct for replay without touching the chain.
///
/// `keys` is the exact difference between the stored payload and the
/// payload the hash saw — `+path` for a key the hash saw that the row
/// does not have, `-path` for one the row has that the hash did not see
/// — measured through [`super::canonical_payload_bytes`] and asserted
/// per vector.
const DIVERGENT_VECTORS: &[Divergence] = &[];

/// One recorded divergence. See [`DIVERGENT_VECTORS`].
struct Divergence {
    /// The vector `name` in the frozen fixture.
    vector: &'static str,
    /// Measured key delta, `+added` / `-dropped`, space-separated and
    /// sorted.
    keys: &'static str,
    /// Why the bytes move. Prose — documented, not asserted.
    mechanism: &'static str,
}

/// Wildcard-free census over `DomainEvent`: `false` for the event types
/// that have at least one frozen stored shape today's code cannot
/// reproduce.
///
/// **Every arm is `true`, and the shape is still load-bearing.** This is
/// the second, independent statement of [`DIVERGENT_VECTORS`]: the test
/// below asserts the two agree, so an event type cannot be classified
/// `false` here without an inventory entry recording its exact key
/// delta, and an inventory entry cannot be added without reclassifying
/// the event type. Five arms read `false` while the payload was
/// re-derived from a typed event.
///
/// A new variant does not compile until it is named, and that is the
/// point at which its golden vector has to be written —
/// `golden_vectors_cover_every_domain_event_variant` then fails until it
/// exists. The classification a new variant should get is `true`: a
/// stored shape that does not reproduce is a defect in the chain now,
/// not a property of the event type. `DomainEvent` is
/// `#[non_exhaustive]`, so this exhaustiveness is only available from
/// inside `hort-domain`, which is why these vectors live here rather
/// than under `tests/`.
fn reproduces_frozen_bytes(event: &DomainEvent) -> bool {
    match event {
        DomainEvent::ArtifactIngested(_)
        | DomainEvent::ScanCompleted(_)
        | DomainEvent::ArtifactBecameVulnerable(_)
        | DomainEvent::ArtifactReEvaluated(_)
        | DomainEvent::TaskInvoked(_)
        | DomainEvent::ChecksumVerified(_)
        | DomainEvent::ChecksumMismatch(_)
        | DomainEvent::ArtifactQuarantined(_)
        | DomainEvent::ScanRequested(_)
        | DomainEvent::ArtifactReleased(_)
        | DomainEvent::ArtifactRejected(_)
        | DomainEvent::ScanIndeterminate(_)
        | DomainEvent::ProvenanceVerified(_)
        | DomainEvent::ProvenanceRejected(_)
        | DomainEvent::PromotionRequested(_)
        | DomainEvent::PolicyEvaluated(_)
        | DomainEvent::ApprovalRequested(_)
        | DomainEvent::ApprovalDecided(_)
        | DomainEvent::ArtifactPromoted(_)
        | DomainEvent::PromotionRejected(_)
        | DomainEvent::ArtifactExpired(_)
        | DomainEvent::ArtifactPurged(_)
        | DomainEvent::ArtifactDeleted(_)
        | DomainEvent::ArtifactDownloaded(_)
        | DomainEvent::PolicyCreated(_)
        | DomainEvent::PolicyUpdated(_)
        | DomainEvent::ExclusionAdded(_)
        | DomainEvent::ExclusionRemoved(_)
        | DomainEvent::PolicyArchived(_)
        | DomainEvent::PolicyReactivated(_)
        | DomainEvent::CasIntegrityMismatch(_)
        | DomainEvent::ArtifactCorrupted(_)
        | DomainEvent::RefMoved(_)
        | DomainEvent::RefRetired(_)
        | DomainEvent::ArtifactGroupInitiated(_)
        | DomainEvent::ArtifactGroupMemberAdded(_)
        | DomainEvent::ArtifactGroupMemberRemoved(_)
        | DomainEvent::ArtifactGroupPrimaryRoleAssigned(_)
        | DomainEvent::CurationApplied(_)
        | DomainEvent::AuthenticationAttempted(_)
        | DomainEvent::OidcKeyRotated(_)
        | DomainEvent::AdminStatusChanged(_)
        | DomainEvent::ClaimMappingApplied(_)
        | DomainEvent::ClaimMappingRevoked(_)
        | DomainEvent::PermissionGrantApplied(_)
        | DomainEvent::PermissionGrantRevoked(_)
        | DomainEvent::RepositoryUpstreamMappingChanged(_)
        | DomainEvent::ApiTokenIssued(_)
        | DomainEvent::ApiTokenRevoked(_)
        | DomainEvent::ApiTokenIssuanceDenied(_)
        | DomainEvent::ApiTokenUsed(_)
        | DomainEvent::TaskFailed(_)
        | DomainEvent::OidcIssuerCreated(_)
        | DomainEvent::OidcIssuerUpdated(_)
        | DomainEvent::OidcIssuerDeleted(_)
        | DomainEvent::ServiceAccountCreated(_)
        | DomainEvent::ServiceAccountUpdated(_)
        | DomainEvent::ServiceAccountDeleted(_)
        | DomainEvent::ServiceAccountTokenRotated(_)
        | DomainEvent::SubscriptionCreated(_)
        | DomainEvent::SubscriptionCreationDenied(_)
        | DomainEvent::SubscriptionUpdated(_)
        | DomainEvent::SubscriptionPaused(_)
        | DomainEvent::SubscriptionResumed(_)
        | DomainEvent::SubscriptionDeleted(_)
        | DomainEvent::SubscriptionDisabled(_)
        | DomainEvent::StreamSealed(_)
        | DomainEvent::RetentionPolicyChanged(_) => true,
    }
}

// ---------------------------------------------------------------------------
// Fixture shape
// ---------------------------------------------------------------------------

/// One golden vector as the fixture stores it. `deny_unknown_fields` so a
/// mistyped fixture key is a failure rather than a silently ignored
/// column.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    /// Unique vector name: the event type, optionally `@<stored-shape>`
    /// for a frozen shape older than the current one.
    name: String,
    /// The stored `event_type` column.
    event_type: String,
    /// The stored `{"type":…,"data":…}` envelope, verbatim.
    stored_envelope: serde_json::Value,
    /// The `event_hash` column, lowercase hex.
    event_hash: String,
    /// The remaining envelope columns the hash binds.
    columns: Columns,
}

/// The envelope columns [`ChainInput`] carries beside the payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Columns {
    prev_event_hash: String,
    event_id: uuid::Uuid,
    stream_id: String,
    stream_category: String,
    stream_position: u64,
    event_version: u32,
    correlation_id: uuid::Uuid,
    causation_id: Option<uuid::Uuid>,
    actor_type: String,
    actor_id: Option<uuid::Uuid>,
    actor_source_file: Option<String>,
    actor_spec_digest: Option<String>,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(VECTORS_JSON).expect("chain_vectors.json must parse")
}

fn hash_from_hex(hex_str: &str) -> EventHash {
    let raw = hex::decode(hex_str).expect("vector hash must be hex");
    EventHash(raw.try_into().expect("vector hash must be 32 bytes"))
}

/// Reconstruct the typed event from a stored envelope, the way the read
/// path does: re-tag the `data` object with the serde variant key the
/// stored `type` maps to, then deserialize.
fn decode(event_type: &str, stored_envelope: &serde_json::Value) -> DomainEvent {
    let data = stored_envelope
        .get("data")
        .expect("stored envelope carries a 'data' key");
    let serde_key = DomainEvent::serde_key_for_event_type(event_type);
    serde_json::from_value(serde_json::json!({ serde_key: data }))
        .unwrap_or_else(|e| panic!("{event_type}: stored envelope does not decode: {e}"))
}

/// Run the frozen vector through the production verifier as a one-row
/// stream at position 0 (so the genesis sentinel is the recorded
/// predecessor and the only reachable break is the hash itself).
///
/// Takes no typed event: the payload the hash covers is the stored
/// envelope, and `event_type` is the stored column. That is the whole
/// subject of these vectors — nothing in the recomputation goes through
/// `DomainEvent`, so a vector whose payload today's types could no
/// longer decode would still be verifiable.
fn verdict(vector: &Vector) -> StreamVerdict {
    let spec_digest = vector
        .columns
        .actor_spec_digest
        .as_ref()
        .map(|h| hex::decode(h).expect("actor_spec_digest must be hex"));
    let stored_prev = hash_from_hex(&vector.columns.prev_event_hash);
    let row = StreamRow {
        input: ChainInput {
            prev_event_hash: stored_prev,
            event_id: vector.columns.event_id,
            stream_id: &vector.columns.stream_id,
            stream_category: &vector.columns.stream_category,
            stream_position: vector.columns.stream_position,
            event_type: &vector.event_type,
            event_version: vector.columns.event_version,
            payload: &vector.stored_envelope,
            correlation_id: vector.columns.correlation_id,
            causation_id: vector.columns.causation_id,
            actor: ActorCanonical {
                actor_type: &vector.columns.actor_type,
                actor_id: vector.columns.actor_id,
                actor_source_file: vector.columns.actor_source_file.as_deref(),
                actor_spec_digest: spec_digest.as_deref(),
            },
        },
        stored_prev,
        stored_hash: hash_from_hex(&vector.event_hash),
    };
    verify_stream_chain(&StreamRows::new(&[row]))
}

/// Collect every object key path in a JSON value, `a.b[0].c` style.
fn key_paths(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                out.push(path.clone());
                key_paths(child, &path, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                key_paths(child, &format!("{prefix}[{idx}]"), out);
            }
        }
        _ => {}
    }
}

/// The exact key delta between a reference envelope and the payload the
/// hash actually saw for `hashed` — the latter read back out of
/// [`super::canonical_payload_bytes`], so this reports what the hash saw
/// rather than a second opinion about it.
///
/// `+path` is a key the hash saw that `reference` does not have, `-path`
/// one `reference` has that the hash did not see. Passing a vector's own
/// stored envelope as both arguments asserts the canonicalisation is
/// key-preserving; passing the clean envelope as `reference` and a
/// tampered one as `hashed` measures what a tamper put into the hash.
fn measured_key_delta(reference: &serde_json::Value, hashed: &serde_json::Value) -> String {
    let seen_by_hash: serde_json::Value =
        serde_json::from_slice(&canonical_payload_bytes(hashed)).expect("canonical bytes are JSON");
    let mut reference_paths = Vec::new();
    let mut hashed_paths = Vec::new();
    key_paths(reference, "", &mut reference_paths);
    key_paths(&seen_by_hash, "", &mut hashed_paths);
    let mut delta: Vec<String> = hashed_paths
        .iter()
        .filter(|p| !reference_paths.contains(p))
        .map(|p| format!("+{p}"))
        .chain(
            reference_paths
                .iter()
                .filter(|p| !hashed_paths.contains(p))
                .map(|p| format!("-{p}")),
        )
        .collect();
    delta.sort();
    delta.join(" ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Every `DomainEvent` variant has at least one frozen vector, and every
/// vector decodes to a fact the production append path would have
/// accepted.
///
/// The variant census is `all_test_variants()` (the crate's canonical
/// one-instance-per-variant corpus) crossed with the wildcard-free
/// [`reproduces_frozen_bytes`] match: a variant added to the enum fails
/// to compile until it is classified there, and fails this test until its
/// vector exists.
///
/// `validate()` is asserted on every decoded vector because the
/// production `EventStore::append` validates every event in a batch — a
/// vector that decodes to an event `validate()` rejects would be a stored
/// row no producer in the system could have written, and a measurement
/// standing on it would prove nothing about the chain.
#[test]
fn golden_vectors_cover_every_domain_event_variant() {
    let vectors = vectors();
    let covered: BTreeSet<&str> = vectors.iter().map(|v| v.event_type.as_str()).collect();
    let expected: BTreeSet<&str> = all_test_variants()
        .iter()
        .map(DomainEvent::event_type)
        .collect();
    assert_eq!(
        expected, covered,
        "every DomainEvent variant needs a golden vector (left: from the enum, \
         right: from chain_vectors.json)"
    );

    let names: BTreeSet<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(
        names.len(),
        vectors.len(),
        "vector names must be unique — they key the divergence inventory"
    );

    for vector in &vectors {
        let event = decode(&vector.event_type, &vector.stored_envelope);
        assert_eq!(
            event.event_type(),
            vector.event_type,
            "{}: decoded event_type disagrees with the stored type column",
            vector.name
        );
        event.validate().unwrap_or_else(|e| {
            panic!(
                "{}: decoded fact is one the append path would reject: {e}",
                vector.name
            )
        });
    }

    // The two statements of the divergent set must agree: the per-variant
    // census and the inventory constant.
    let classified: BTreeSet<&str> = all_test_variants()
        .iter()
        .filter(|e| !reproduces_frozen_bytes(e))
        .map(DomainEvent::event_type)
        .collect();
    let inventoried: BTreeSet<&str> = DIVERGENT_VECTORS
        .iter()
        .map(|d| {
            vectors
                .iter()
                .find(|v| v.name == d.vector)
                .unwrap_or_else(|| panic!("{} names no vector in the fixture", d.vector))
                .event_type
                .as_str()
        })
        .collect();
    assert_eq!(
        classified, inventoried,
        "reproduces_frozen_bytes and DIVERGENT_VECTORS disagree about which event \
         types diverge"
    );
}

/// The frozen canonical bytes still verify — except for the divergences
/// recorded in [`DIVERGENT_VECTORS`], which is empty, and which is
/// asserted by **exact equality** so a new divergence fails rather than
/// being absorbed.
///
/// Each vector is verified as a one-row stream through
/// [`verify_stream_chain`], the same function the `verify-event-chain`
/// path runs, so a divergence here is literally the
/// [`ChainBreak::HashMismatch`] an operator would see on an untouched
/// row.
///
/// This is also the no-format-break check: the 84 frozen `event_hash`
/// values were recorded before the payload derivation changed, so every
/// one of them reproducing is the statement that the change moved no
/// existing hash.
#[test]
fn frozen_canonical_bytes_reproduce_except_the_recorded_divergences() {
    let vectors = vectors();
    let mut measured: BTreeSet<String> = BTreeSet::new();

    for vector in &vectors {
        match verdict(vector) {
            StreamVerdict::Ok { .. } => {
                assert_eq!(
                    measured_key_delta(&vector.stored_envelope, &vector.stored_envelope),
                    "",
                    "{}: hash reproduces but the canonicalisation moved a key",
                    vector.name
                );
            }
            StreamVerdict::Broken {
                at_position,
                reason: ChainBreak::HashMismatch,
            } => {
                assert_eq!(at_position, 0, "{}: unexpected break position", vector.name);
                measured.insert(vector.name.clone());
            }
            other => panic!(
                "{}: the vector is a one-row stream at position 0, so the only \
                 reachable break is the hash, got {other:?}",
                vector.name
            ),
        }
    }

    let recorded: BTreeSet<String> = DIVERGENT_VECTORS
        .iter()
        .map(|d| d.vector.to_string())
        .collect();
    assert_eq!(
        recorded, measured,
        "the divergent set moved (left: DIVERGENT_VECTORS, right: measured). A new \
         entry means additive evolution broke another event type's historical bytes; \
         a missing one means a divergence was resolved and the inventory has to shrink"
    );

    // Per entry, the recorded key delta is the measured one — the
    // inventory's causes are checked, not asserted in prose. Vacuous
    // while the inventory is empty, and kept because the inventory is
    // what shrank: an entry re-added without its real delta fails here.
    for divergence in DIVERGENT_VECTORS {
        let vector = vectors
            .iter()
            .find(|v| v.name == divergence.vector)
            .expect("checked above");
        assert_eq!(
            divergence.keys,
            measured_key_delta(&vector.stored_envelope, &vector.stored_envelope),
            "{}: recorded key delta is stale ({})",
            divergence.vector,
            divergence.mechanism
        );
    }

    // The scan is not vacuously green: the fixture still holds every
    // variant's current shape plus the 13 older stored shapes the
    // divergences were measured on, and all of them were verified above.
    assert_eq!(
        vectors.len(),
        84,
        "the frozen corpus is 84 vectors — 71 current shapes (one per \
         `all_test_variants()` instance) plus 13 older stored shapes. A \
         shrinking corpus makes this test pass by measuring less"
    );
    let older_shapes = vectors.iter().filter(|v| v.name.contains('@')).count();
    assert_eq!(
        older_shapes, 13,
        "the 13 `@<stored-shape>` vectors are the ones a re-derivation from \
         today's types could not reproduce; they are the point of the corpus"
    );
}

/// A key added to a stored payload that matches no struct field is
/// **detected**: it reaches the hash, the recomputation moves, and
/// [`verify_stream_chain`] reports [`ChainBreak::HashMismatch`].
///
/// This test used to assert the opposite, and that is why it exists. No
/// type in `hort-domain` carries `#[serde(deny_unknown_fields)]`, so
/// while the payload was re-derived by deserialising the stored envelope
/// into a typed event, an injected key was dropped by the decode: the
/// recomputed bytes were the ones the *untampered* row had, the hash
/// matched, and the verifier returned `Ok` on a row that had been added
/// to. The chain module's claim is that "any insertion, deletion,
/// reordering, or field mutation of a row inside a stream is detectable
/// offline"; this was the field mutation that was not. `ArtifactIngested`
/// is the exemplar — the gap held for every event type, because the
/// cause was the decode and not any one struct.
#[test]
fn unknown_stored_payload_key_is_detected_by_the_chain_verifier() {
    let vectors = vectors();
    let mut vector = vectors
        .into_iter()
        .find(|v| v.name == "ArtifactIngested")
        .expect("the current-shape ArtifactIngested vector");

    // Baseline: the untampered vector verifies. Without this the
    // assertion below could be satisfied by a vector that never
    // verified.
    assert!(
        matches!(verdict(&vector), StreamVerdict::Ok { .. }),
        "the untampered vector must verify, or the test below proves nothing"
    );

    let clean = vector.stored_envelope.clone();
    vector.stored_envelope["data"]["injected_key_matching_no_struct_field"] =
        serde_json::json!("tampered");

    // The injected key is in the bytes the hash saw — the measurement,
    // read back out of `canonical_payload_bytes` rather than assumed.
    assert_eq!(
        measured_key_delta(&clean, &vector.stored_envelope),
        "+data.injected_key_matching_no_struct_field",
        "the injected key must reach the hash — that is what closes the gap"
    );
    assert_eq!(
        verdict(&vector),
        StreamVerdict::Broken {
            at_position: 0,
            reason: ChainBreak::HashMismatch
        },
        "an added payload key must be detected: the row must stop verifying \
         against the hash it was stored with"
    );

    // A key *removed* from the payload is the same hazard mirrored, and
    // the decode could not see it either (a missing field with a
    // `serde(default)` deserialises to its default and re-serialises the
    // key back in). `metadata` is such a field on this event type.
    let mut deleted = vector.clone();
    deleted.stored_envelope = clean.clone();
    deleted
        .stored_envelope
        .get_mut("data")
        .and_then(serde_json::Value::as_object_mut)
        .expect("the stored payload is an object")
        .remove("metadata")
        .expect("the current-shape ArtifactIngested vector carries `metadata`");
    assert_eq!(
        measured_key_delta(&clean, &deleted.stored_envelope),
        "-data.metadata",
        "the removed key must be missing from the bytes the hash saw"
    );
    assert_eq!(
        verdict(&deleted),
        StreamVerdict::Broken {
            at_position: 0,
            reason: ChainBreak::HashMismatch
        },
        "a removed payload key must be detected too"
    );
}
