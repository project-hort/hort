//! `CheckpointAnchorPort` **read** adapter (ADR 0002, spec §6.1/§6.2).
//!
//! Reads externally-anchored, Ed25519-signed event-chain checkpoints
//! from a WORM-locked object-store prefix and feeds the
//! signature-verified [`Checkpoint`] values to the pure
//! `verify-event-chain` core. This is the I/O the `hort-domain` verify
//! core forbids, isolated behind the
//! [`CheckpointAnchorPort`](hort_domain::ports::checkpoint_anchor::CheckpointAnchorPort)
//! boundary.
//!
//! **Scope (read only).** This crate is the *read* half of F-2's
//! external anchor. Checkpoint **emission** — the S3 Object-Lock
//! *write* adapter and the `eventstore-checkpoint` `TaskHandler` (spec
//! §6/§12) — is a separate, not-yet-scheduled item and is deliberately
//! NOT built here. Until an emitter ships the anchor store is
//! legitimately empty and the verifier resolves the anchor verdict to
//! `missing_checkpoint` (spec §6.4(a)) — a correct, spec-defined
//! verdict, not a failure.
//!
//! **Store-agnostic / no own client.** This crate does *not* build an
//! object store and depends only on `hort-domain` + crypto +
//! `object_store`. It takes an injected `Arc<dyn ObjectStore>`. The
//! composition root (`hort-server`'s `build_anchor`) is what constructs
//! the concrete store via
//! `hort_adapters_storage::builders::build_s3_object_store` (which carries
//! the ADR 0010 extra-CA / TLS posture) and injects it here. This crate
//! therefore constructs no `reqwest::Client` and has no dependency on
//! `hort-adapters-storage` or `hort-config` (no `reqwest::Client::new()`
//! in this crate — there is no client to build here at all).
//!
//! **Signature.** Each checkpoint object is a JSON document with a
//! detached, hex-encoded Ed25519 signature over the canonical
//! serialization of the signed body (spec §6.2). The verifying key is
//! an **operator-provisioned** SPKI PEM public key (§14 R2 — distinct
//! from any runtime credential; KMS/HSM is a documented future). A
//! checkpoint whose signature does not verify is dropped (a forged
//! checkpoint must be indistinguishable from no checkpoint, or an
//! attacker who can write the bucket but not forge the key could
//! fabricate a passing anchor verdict).
//!
//! **Verifier ↔ emitter signature contract (load-bearing).** The
//! signature is Ed25519 over `serde_json::to_vec(&SignedBody)` — i.e.
//! every checkpoint field *except* `signature`, serialized with serde's
//! struct-field declaration order and no insignificant whitespace (see
//! [`CheckpointWire::signed_body_bytes`]). The checkpoint-emission
//! **write** path ([`ObjectStoreCheckpointEmitter`], ADR 0002)
//! lives **in this same crate** and signs **exactly these bytes** by
//! constructing **the same [`SignedBody`] struct** — `SignedBody` is a
//! single shared source of truth, so the contract cannot drift: the
//! emitter and verifier are *structurally* the same serialization. The
//! round-trip is proven end-to-end by
//! `emitted_checkpoint_round_trips_through_the_reader` (an emitted
//! object is fed back through [`ObjectStoreCheckpointAnchor::read_all`]
//! and the pure verify core, asserting `AnchorVerdict::Ok`).
//!
//! **Signed-body field set vs. spec §6.2 (precise — a real nuance).**
//! `SignedBody` is the **shipped Item-3 contract pin**: it covers
//! `chain_format_version`, `checkpoint_seq`, `created_at`,
//! `stream_heads`, `sealed_streams`. The spec §6.2 prose lists
//! `max_global_position` and `backfill_baseline` among the checkpoint
//! fields the signature covers, but the **shipped reader does not
//! verify them** (they are accepted-and-ignored extras —
//! [`CheckpointWire`] doc). Governance forbids reshaping the shipped
//! `SignedBody`. The emitter therefore signs **exactly the shipped
//! `SignedBody`** (so every emitted checkpoint round-trips to
//! `AnchorVerdict::Ok` against the real verifier) and writes
//! `max_global_position` / `backfill_baseline` into the JSON object as
//! **unsigned advisory fields** alongside the signed body — precisely
//! the forward-compatible extension the reader's [`CheckpointWire`]
//! doc anticipates. This is recorded here so the residual is explicit:
//! the §5 `backfill_baseline` honesty caveat is *carried* (auditors can
//! read it) but is **not** itself cryptographically signed by the v1
//! shipped contract; tightening the signature to cover it would be a
//! coordinated reader+emitter `SignedBody` change (a future
//! `hort-evchain/v2`-style bump), not an in-place reshape.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::StreamExt;
use object_store::{ObjectStore, ObjectStoreExt};
use serde::{Deserialize, Serialize};
use tracing::warn;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    BackfillBaseline, Checkpoint, CheckpointToEmit, EventHash, SealedStreamRecord, StreamHead,
};
use hort_domain::ports::checkpoint_anchor::CheckpointAnchorPort;
use hort_domain::ports::checkpoint_emitter::CheckpointEmitterPort;
use hort_domain::ports::BoxFuture;

/// The object-store prefix the checkpoint emitter writes under
/// (spec §6.2: `<bucket>/hort-event-chain-checkpoints/<RFC3339>-<seq>.json`).
/// The read adapter lists exactly this prefix.
pub const CHECKPOINT_PREFIX: &str = "hort-event-chain-checkpoints";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Construction-time failures (operator-facing, surfaced before any I/O
/// the verifier depends on).
#[derive(Debug, thiserror::Error)]
pub enum AnchorAdapterError {
    /// The operator-provisioned anchor public-key PEM did not parse as
    /// an Ed25519 SPKI public key (spec §14 R2).
    #[error("anchor public key PEM is not a valid Ed25519 SPKI key: {0}")]
    BadPublicKey(String),
}

// ---------------------------------------------------------------------------
// Wire DTO (spec §6.2)
// ---------------------------------------------------------------------------

/// On-the-wire checkpoint JSON (spec §6.2). Deserialized from the
/// anchor object, then mapped to the pure [`Checkpoint`] the verify
/// core consumes. Fields the verify core does not need
/// (`max_global_position`, `backfill_baseline`) are accepted and
/// ignored so a future emitter that writes them does not break the
/// reader — forward-compatible by `#[serde(default)]` on the
/// signed-body extras and `deny_unknown_fields` deliberately NOT set.
///
/// `stream_heads` / `sealed_streams` carry 32-byte hashes as lowercase
/// hex strings (JSON has no byte type); `signature` is the detached
/// hex-encoded Ed25519 signature over [`Self::signed_body_bytes`].
#[derive(Debug, Deserialize)]
struct CheckpointWire {
    chain_format_version: String,
    checkpoint_seq: u64,
    created_at: DateTime<Utc>,
    stream_heads: Vec<StreamHeadWire>,
    #[serde(default)]
    sealed_streams: Vec<SealedWire>,
    /// Detached hex-encoded Ed25519 signature over the canonical
    /// serialization of every field above (everything except this one).
    signature: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct StreamHeadWire {
    stream_id: String,
    final_stream_position: u64,
    /// 32-byte head `event_hash`, lowercase hex.
    head_event_hash: String,
}

impl From<&StreamHead> for StreamHeadWire {
    fn from(h: &StreamHead) -> Self {
        Self {
            stream_id: h.stream_id.clone(),
            final_stream_position: h.final_stream_position,
            head_event_hash: hex::encode(h.head_event_hash.0),
        }
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct SealedWire {
    sealed_stream_id: String,
    /// 32-byte sealed-stream chain head, lowercase hex.
    final_event_hash: String,
}

impl From<&SealedStreamRecord> for SealedWire {
    fn from(s: &SealedStreamRecord) -> Self {
        Self {
            sealed_stream_id: s.sealed_stream_id.clone(),
            final_event_hash: hex::encode(s.final_event_hash.0),
        }
    }
}

/// The §5 backfill-baseline honesty caveat, on the wire. Written into
/// the checkpoint JSON object as an **unsigned advisory field**
/// (alongside, not inside, the [`SignedBody`] the shipped reader
/// verifies — see the crate doc's "Signed-body field set vs. spec
/// §6.2" note). `migration_timestamp` is RFC3339 UTC.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
struct BackfillBaselineWire {
    backfill_baseline: bool,
    baseline_max_global_position: u64,
    migration_timestamp: DateTime<Utc>,
}

impl From<&BackfillBaseline> for BackfillBaselineWire {
    fn from(b: &BackfillBaseline) -> Self {
        Self {
            backfill_baseline: true,
            baseline_max_global_position: b.baseline_max_global_position,
            migration_timestamp: b.migration_timestamp,
        }
    }
}

/// The signed body — every field except `signature`, serialized
/// canonically (serde struct-field declaration order, no insignificant
/// whitespace) so the verifier reconstructs exactly the bytes the
/// emitter signed. Mirrors the spec §3.2 "canonical serialization"
/// discipline applied to the checkpoint object.
#[derive(serde::Serialize)]
struct SignedBody<'a> {
    chain_format_version: &'a str,
    checkpoint_seq: u64,
    created_at: &'a DateTime<Utc>,
    stream_heads: &'a [StreamHeadWire],
    sealed_streams: &'a [SealedWire],
}

/// The **single** function that maps a [`SignedBody`] to the exact
/// bytes the detached Ed25519 signature covers. Both the **read**
/// (verify) path ([`CheckpointWire::signed_body_bytes`]) and the
/// **write** (sign) path ([`ObjectStoreCheckpointEmitter::emit`]) call
/// this with the same `SignedBody` struct, so the verifier↔emitter
/// contract is *structurally* identical and cannot drift —
/// `serde_json::to_vec` of a typed struct is deterministic (declaration
/// order, no insignificant whitespace, shortest-round-trip numbers).
fn signed_body_bytes(body: &SignedBody<'_>) -> Vec<u8> {
    serde_json::to_vec(body).expect("SignedBody is always serializable")
}

fn parse_hash_hex(field: &str, hex_str: &str) -> Result<EventHash, String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("{field} is not valid hex: {e}"))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes, got {}", raw.len()))?;
    Ok(EventHash(arr))
}

impl CheckpointWire {
    /// Canonical bytes the detached signature covers (everything but
    /// `signature`). `serde_json::to_vec` is deterministic for a typed
    /// struct: fields emit in declaration order, no insignificant
    /// whitespace, numbers shortest-round-trip — the same determinism
    /// guarantee §3.2 relies on for the per-event payload.
    fn signed_body_bytes(&self) -> Vec<u8> {
        // Behaviour byte-identical to the shipped Item-3 path; the only
        // change is delegating the `serde_json::to_vec` call to the
        // shared `signed_body_bytes` free fn so the emitter signs the
        // *same* bytes from the *same* `SignedBody` struct (single
        // source of truth — the contract cannot drift).
        signed_body_bytes(&SignedBody {
            chain_format_version: &self.chain_format_version,
            checkpoint_seq: self.checkpoint_seq,
            created_at: &self.created_at,
            stream_heads: &self.stream_heads,
            sealed_streams: &self.sealed_streams,
        })
    }

    /// Verify the detached signature against `key`, then map to the
    /// pure domain [`Checkpoint`]. `None` = signature invalid or the
    /// document is structurally malformed in a way attributable to
    /// tampering (a forged/garbled object must read as "no checkpoint",
    /// never as a passing anchor — see the crate doc). The caller logs
    /// the drop at `warn!`.
    fn verify_and_into_domain(&self, key: &VerifyingKey) -> Option<Checkpoint> {
        let sig_bytes = hex::decode(&self.signature).ok()?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().ok()?;
        let signature = Signature::from_bytes(&sig_arr);
        key.verify(&self.signed_body_bytes(), &signature).ok()?;

        let mut stream_heads = Vec::with_capacity(self.stream_heads.len());
        for h in &self.stream_heads {
            let hash = parse_hash_hex("head_event_hash", &h.head_event_hash).ok()?;
            stream_heads.push((h.stream_id.clone(), h.final_stream_position, hash));
        }
        let mut sealed_streams = Vec::with_capacity(self.sealed_streams.len());
        for s in &self.sealed_streams {
            let hash = parse_hash_hex("final_event_hash", &s.final_event_hash).ok()?;
            sealed_streams.push(SealedStreamRecord {
                sealed_stream_id: s.sealed_stream_id.clone(),
                final_event_hash: hash,
            });
        }
        Some(Checkpoint {
            chain_format_version: self.chain_format_version.clone(),
            checkpoint_seq: self.checkpoint_seq,
            created_at: self.created_at,
            stream_heads,
            sealed_streams,
        })
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// S3-Object-Lock-anchored, Ed25519-signed checkpoint **read** adapter.
///
/// Construct via [`ObjectStoreCheckpointAnchor::new`] with a
/// caller-supplied `Arc<dyn ObjectStore>` and the operator-provisioned
/// anchor public-key PEM. The caller (the `hort-server` composition root)
/// builds the store through
/// `hort_adapters_storage::builders::build_s3_object_store` so the ADR 0010
/// TLS posture applies; this crate is store-agnostic and never builds
/// the store itself.
pub struct ObjectStoreCheckpointAnchor {
    store: Arc<dyn ObjectStore>,
    verifying_key: VerifyingKey,
}

impl ObjectStoreCheckpointAnchor {
    /// Build the adapter. `public_key_pem` is the operator-provisioned
    /// SPKI PEM for the anchor signing key's public half (spec §14 R2).
    /// Rejects a malformed key at construction so a misconfiguration is
    /// an operational error (subcommand exit 1), not a silent
    /// drop-everything that would masquerade as `missing_checkpoint`.
    pub fn new(
        store: Arc<dyn ObjectStore>,
        public_key_pem: &str,
    ) -> Result<Self, AnchorAdapterError> {
        let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
            .map_err(|e| AnchorAdapterError::BadPublicKey(e.to_string()))?;
        Ok(Self {
            store,
            verifying_key,
        })
    }
}

impl CheckpointAnchorPort for ObjectStoreCheckpointAnchor {
    fn read_all(&self) -> BoxFuture<'_, DomainResult<Vec<Checkpoint>>> {
        Box::pin(async move {
            let prefix: object_store::path::Path = CHECKPOINT_PREFIX.into();
            let mut listing = self.store.list(Some(&prefix));
            let mut out = Vec::new();

            while let Some(entry) = listing.next().await {
                let meta = entry.map_err(|e| {
                    // An operational failure (store unreachable, creds
                    // rejected): the verifier could not run → exit 1,
                    // NOT a coverage gap. Distinct from "no objects".
                    DomainError::Invariant(format!("anchor store list failed: {e}"))
                })?;
                let location = meta.location.clone();
                let key = location.as_ref().to_string();

                let bytes = self
                    .store
                    .get(&location)
                    .await
                    .map_err(|e| {
                        DomainError::Invariant(format!("anchor object get failed ({key}): {e}"))
                    })?
                    .bytes()
                    .await
                    .map_err(|e| {
                        DomainError::Invariant(format!("anchor object read failed ({key}): {e}"))
                    })?;

                // A JSON parse failure or a signature mismatch is NOT an
                // operational error — a garbled/forged object must read
                // as "absent" (see crate doc). Drop it with a warn so an
                // operator notices anchor-store corruption, but do not
                // fail the run (that would let an attacker turn a
                // detectable coverage gap into a verifier crash).
                let wire: CheckpointWire = match serde_json::from_slice(&bytes) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!(
                            anchor_object = %key,
                            error = %e,
                            "anchor checkpoint object is not valid JSON; ignoring \
                             (treated as absent — chain-break detection is unaffected)"
                        );
                        continue;
                    }
                };
                match wire.verify_and_into_domain(&self.verifying_key) {
                    Some(cp) => out.push(cp),
                    None => warn!(
                        anchor_object = %key,
                        checkpoint_seq = wire.checkpoint_seq,
                        "anchor checkpoint signature did not verify against the \
                         operator-provisioned anchor key; ignoring (treated as \
                         absent — a forged checkpoint must not pass the anchor check)"
                    ),
                }
            }
            Ok(out)
        })
    }
}

// ===========================================================================
// Write path — checkpoint EMISSION (ADR 0002). Separate adapter implementing
// the sibling `CheckpointEmitterPort`. The read path above
// (`ObjectStoreCheckpointAnchor` / `read_all` / `verify_and_into_domain` /
// `SignedBody`) is byte-unchanged in behaviour.
// ===========================================================================

/// The object-store object key for a checkpoint (spec §6.2:
/// `<bucket>/hort-event-chain-checkpoints/<RFC3339-utc>-<seq>.json`). The
/// timestamp is the checkpoint's `created_at` rendered RFC3339 with `Z`,
/// `:` replaced by `-` so the key is filesystem/S3-key clean; the `seq`
/// disambiguates and the read adapter ignores the key shape entirely
/// (it parses every object under the prefix), so this is purely for
/// human/operator legibility + lexical-ish ordering.
fn checkpoint_object_key(created_at: &DateTime<Utc>, seq: u64) -> String {
    let ts = created_at
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        .replace(':', "-");
    format!("{CHECKPOINT_PREFIX}/{ts}-{seq}.json")
}

/// The full on-wire checkpoint object the emitter writes: the
/// [`SignedBody`] fields, the detached hex `signature`, **plus** the
/// unsigned advisory extras (`max_global_position` and, on the first
/// post-migration checkpoint only, the §5 `backfill_baseline` block).
/// The shipped reader parses exactly the signed subset + `signature`
/// and ignores the extras (`CheckpointWire` is not
/// `deny_unknown_fields`) — see the crate doc's signed-body nuance.
#[derive(Serialize)]
struct CheckpointObject<'a> {
    chain_format_version: &'a str,
    checkpoint_seq: u64,
    created_at: &'a DateTime<Utc>,
    stream_heads: &'a [StreamHeadWire],
    sealed_streams: &'a [SealedWire],
    /// Detached hex Ed25519 signature over `signed_body_bytes(SignedBody)`.
    signature: String,
    /// Unsigned advisory cut-marker (spec §6.2 / §13 divergence 6).
    max_global_position: u64,
    /// Unsigned advisory §5 honesty caveat — present only on the first
    /// post-migration checkpoint. Flattened so the keys
    /// (`backfill_baseline`, `baseline_max_global_position`,
    /// `migration_timestamp`) sit at the object root, matching the
    /// reader's accepted-and-ignored extra shape.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    backfill_baseline: Option<BackfillBaselineWire>,
}

/// Construction-time failures for the **write** adapter (operator-facing,
/// surfaced before the task runs any emission cycle).
#[derive(Debug, thiserror::Error)]
pub enum EmitterAdapterError {
    /// The operator-provisioned anchor **signing** key PEM did not parse
    /// as an Ed25519 PKCS#8 private key (spec §14 R2). A missing /
    /// malformed key fails construction — never a silent unsigned or
    /// weakly-signed checkpoint.
    #[error("anchor signing key PEM is not a valid Ed25519 PKCS#8 private key: {0}")]
    BadSigningKey(String),
}

/// S3-Object-Lock-anchored, Ed25519-signed checkpoint **write** adapter
/// (ADR 0002, spec §6 / §9 / §14 R2). The additive counterpart of
/// [`ObjectStoreCheckpointAnchor`].
///
/// Construct via [`ObjectStoreCheckpointEmitter::new`] with a
/// caller-supplied `Arc<dyn ObjectStore>` (the worker composition root
/// builds it through `hort_adapters_storage::builders::build_s3_object_store`
/// so the ADR 0010 TLS / extra-CA posture applies — this crate stays
/// store-agnostic and builds no `reqwest::Client`) and the
/// operator-provisioned anchor **signing** key PEM (the private
/// counterpart of the SPKI public PEM
/// [`ObjectStoreCheckpointAnchor`] verifies).
///
/// ## S3 Object-Lock WORM — exact guarantee + required provisioning
///
/// `object_store` 0.13 exposes **no API to set per-object S3
/// Object-Lock retention on `put`**: `PutOptions` carries only
/// `mode`, a `TagSet`, a fixed `#[non_exhaustive]` `Attributes` enum
/// (Content-*, Cache-Control, Storage-Class, user metadata) and opaque
/// `extensions` ignored by every bundled backend — there is no
/// `x-amz-object-lock-mode` / `x-amz-object-lock-retain-until-date`
/// header path, and `AmazonS3Builder` has no default-retention knob.
/// This adapter therefore performs a **plain `put`**; it does **not**
/// fake a per-object retention it cannot set.
///
/// The WORM guarantee is consequently **operator-provisioned at the
/// bucket level**: the anchor bucket MUST be created with **S3 Object
/// Lock enabled** and a **bucket default retention** in **COMPLIANCE
/// mode** (e.g. `aws s3api put-object-lock-configuration --bucket <b>
/// --object-lock-configuration
/// 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=<≥
/// audit-retention-floor>}}'`). With that configuration S3 stamps the
/// bucket default retention onto **every newly `put` object
/// automatically** — so each checkpoint this adapter writes is WORM
/// (not even the account root can delete/overwrite it before expiry),
/// satisfying spec §6.1 against the in-DB threat model. The residual
/// (documented honestly, not fudged): WORM depends on correct bucket
/// provisioning the *application cannot enforce or verify through
/// `object_store`*; if the operator forgets to enable Object Lock the
/// `put` still succeeds but the object is mutable. The deployment
/// hardening guide MUST state the bucket-provisioning requirement; an
/// `object_store` upgrade that adds a retention `PutOption` would let a
/// future revision additionally assert per-object retention defensively
/// (tracked, not done here — no faked guarantee).
pub struct ObjectStoreCheckpointEmitter {
    store: Arc<dyn ObjectStore>,
    signing_key: SigningKey,
}

impl ObjectStoreCheckpointEmitter {
    /// Build the write adapter. `signing_key_pem` is the
    /// operator-provisioned Ed25519 **PKCS#8 PEM private key** (spec
    /// §14 R2 — a file under the existing `HORT_*` posture, distinct from
    /// any runtime credential, never embedded/derived/generated at
    /// runtime). A malformed/missing key is rejected **here**, at
    /// construction, so a misconfiguration fails the task loudly rather
    /// than emitting a silently-unsigned checkpoint.
    pub fn new(
        store: Arc<dyn ObjectStore>,
        signing_key_pem: &str,
    ) -> Result<Self, EmitterAdapterError> {
        let signing_key = SigningKey::from_pkcs8_pem(signing_key_pem)
            .map_err(|e| EmitterAdapterError::BadSigningKey(e.to_string()))?;
        Ok(Self { store, signing_key })
    }

    /// Pure sign+serialize step (no I/O) — factored out so the
    /// round-trip / signature tests can exercise the exact bytes the
    /// reader will verify without touching an object store. Returns the
    /// full JSON object bytes + the object key.
    fn sign_and_serialize(&self, cp: &CheckpointToEmit) -> (String, Vec<u8>) {
        let stream_heads: Vec<StreamHeadWire> =
            cp.stream_heads.iter().map(StreamHeadWire::from).collect();
        let sealed_streams: Vec<SealedWire> =
            cp.sealed_streams.iter().map(SealedWire::from).collect();

        // Construct the *shared* SignedBody (single source of truth) and
        // sign exactly `signed_body_bytes(&body)` — the same bytes the
        // shipped reader verifies.
        let body = SignedBody {
            chain_format_version: &cp.chain_format_version,
            checkpoint_seq: cp.checkpoint_seq,
            created_at: &cp.created_at,
            stream_heads: &stream_heads,
            sealed_streams: &sealed_streams,
        };
        let sig = self.signing_key.sign(&signed_body_bytes(&body));

        let object = CheckpointObject {
            chain_format_version: &cp.chain_format_version,
            checkpoint_seq: cp.checkpoint_seq,
            created_at: &cp.created_at,
            stream_heads: &stream_heads,
            sealed_streams: &sealed_streams,
            signature: hex::encode(sig.to_bytes()),
            max_global_position: cp.max_global_position,
            backfill_baseline: cp
                .backfill_baseline
                .as_ref()
                .map(BackfillBaselineWire::from),
        };
        let key = checkpoint_object_key(&cp.created_at, cp.checkpoint_seq);
        let bytes = serde_json::to_vec(&object).expect("CheckpointObject is always serializable");
        (key, bytes)
    }
}

impl CheckpointEmitterPort for ObjectStoreCheckpointEmitter {
    fn emit<'a>(&'a self, checkpoint: &'a CheckpointToEmit) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            // Signing is infallible here (the key parsed at construction;
            // ed25519 signing of a Vec cannot fail). The fallible step is
            // the anchor-store write.
            let (key, bytes) = self.sign_and_serialize(checkpoint);
            let path: object_store::path::Path = key.as_str().into();
            // Plain `put` — see the type doc: object_store 0.13 cannot
            // set per-object Object-Lock retention; WORM is the
            // operator-provisioned bucket default retention.
            self.store
                .put(&path, bytes.into())
                .await
                .map(|_| ())
                .map_err(|e| {
                    // Anchor-store write failure for this cycle — the
                    // task maps this to `anchor_write_failed` + `error!`.
                    DomainError::Invariant(format!("anchor checkpoint write failed ({key}): {e}"))
                })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — adapter tier (>= 85%). Exercises: signature accept/reject,
// JSON-garble drop, hash-hex malformations, empty store, list/get error
// surfacing, construction key rejection, and the round-trip into the
// pure `Checkpoint` the verify core consumes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use object_store::memory::InMemory;
    use object_store::ObjectStoreExt;

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode SPKI PEM");
        (sk, pem)
    }

    /// Build a signed checkpoint JSON object the way the (future)
    /// emitter would: serialize the body canonically, sign it, attach
    /// the hex signature.
    fn signed_checkpoint_json(
        sk: &SigningKey,
        seq: u64,
        heads: &[(&str, u64, [u8; 32])],
        sealed: &[(&str, [u8; 32])],
    ) -> Vec<u8> {
        let stream_heads: Vec<StreamHeadWire> = heads
            .iter()
            .map(|(sid, pos, h)| StreamHeadWire {
                stream_id: (*sid).to_string(),
                final_stream_position: *pos,
                head_event_hash: hex::encode(h),
            })
            .collect();
        let sealed_streams: Vec<SealedWire> = sealed
            .iter()
            .map(|(sid, h)| SealedWire {
                sealed_stream_id: (*sid).to_string(),
                final_event_hash: hex::encode(h),
            })
            .collect();
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let body = SignedBody {
            chain_format_version: "hort-evchain/v1",
            checkpoint_seq: seq,
            created_at: &created_at,
            stream_heads: &stream_heads,
            sealed_streams: &sealed_streams,
        };
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let sig = sk.sign(&body_bytes);
        // The full object = signed body fields + the detached signature.
        let mut full = serde_json::to_value(&body).unwrap();
        full.as_object_mut()
            .unwrap()
            .insert("signature".into(), hex::encode(sig.to_bytes()).into());
        serde_json::to_vec(&full).unwrap()
    }

    async fn put(store: &InMemory, name: &str, bytes: Vec<u8>) {
        let path: object_store::path::Path = format!("{CHECKPOINT_PREFIX}/{name}").into();
        store.put(&path, bytes.into()).await.unwrap();
    }

    #[tokio::test]
    async fn empty_store_yields_empty_vec() {
        // No emitter deployed yet -> empty -> the core maps this to
        // MissingReason::NoCheckpoint (spec §6.4(a)), NOT an error.
        let (_sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        let cps = anchor.read_all().await.unwrap();
        assert!(cps.is_empty());
    }

    #[tokio::test]
    async fn valid_signed_checkpoint_round_trips_into_domain() {
        let (sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        let h = [0xab_u8; 32];
        let gone = [0xcd_u8; 32];
        put(
            &store,
            "2023-11-14T22:13:20Z-1.json",
            signed_checkpoint_json(&sk, 1, &[("admin-a", 3, h)], &[("admin-gone", gone)]),
        )
        .await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        let cps = anchor.read_all().await.unwrap();
        assert_eq!(cps.len(), 1);
        let cp = &cps[0];
        assert_eq!(cp.chain_format_version, "hort-evchain/v1");
        assert_eq!(cp.checkpoint_seq, 1);
        assert_eq!(
            cp.stream_heads,
            vec![("admin-a".to_string(), 3, EventHash(h))]
        );
        assert_eq!(cp.sealed_streams.len(), 1);
        assert_eq!(cp.sealed_streams[0].sealed_stream_id, "admin-gone");
        assert_eq!(cp.sealed_streams[0].final_event_hash, EventHash(gone));
    }

    #[tokio::test]
    async fn tampered_body_fails_signature_and_is_dropped() {
        // Sign one body, then mutate a field after signing: the
        // signature no longer covers the bytes -> dropped (treated as
        // absent), NOT surfaced as a passing checkpoint.
        let (sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        let mut obj: serde_json::Value = serde_json::from_slice(&signed_checkpoint_json(
            &sk,
            1,
            &[("admin-a", 3, [1u8; 32])],
            &[],
        ))
        .unwrap();
        // Forge a different head hash while keeping the old signature.
        obj["stream_heads"][0]["head_event_hash"] = hex::encode([9u8; 32]).into();
        put(
            &store,
            "2023-11-14T22:13:20Z-1.json",
            serde_json::to_vec(&obj).unwrap(),
        )
        .await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        let cps = anchor.read_all().await.unwrap();
        assert!(cps.is_empty(), "a forged checkpoint must read as absent");
    }

    #[tokio::test]
    async fn checkpoint_signed_by_wrong_key_is_dropped() {
        let (sk_attacker, _) = keypair();
        let (_sk_real, pem_real) = keypair();
        let store = Arc::new(InMemory::new());
        put(
            &store,
            "2023-11-14T22:13:20Z-1.json",
            signed_checkpoint_json(&sk_attacker, 1, &[("admin-a", 0, [1u8; 32])], &[]),
        )
        .await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem_real).unwrap();
        let cps = anchor.read_all().await.unwrap();
        assert!(cps.is_empty());
    }

    #[tokio::test]
    async fn garbled_json_object_is_dropped_not_errored() {
        let (_sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        put(&store, "bad.json", b"{ not json".to_vec()).await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        // Drop, not Err — a corrupt object must not crash the verifier
        // (that would convert a detectable coverage gap into a DoS).
        let cps = anchor.read_all().await.unwrap();
        assert!(cps.is_empty());
    }

    #[tokio::test]
    async fn bad_hash_hex_in_signed_checkpoint_is_dropped() {
        // Signature is valid but a head hash is not 32-byte hex: the
        // object is internally inconsistent -> dropped.
        let (sk, pem) = keypair();
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let heads = vec![StreamHeadWire {
            stream_id: "admin-a".into(),
            final_stream_position: 0,
            head_event_hash: "zzzz".into(),
        }];
        let body = SignedBody {
            chain_format_version: "hort-evchain/v1",
            checkpoint_seq: 1,
            created_at: &created_at,
            stream_heads: &heads,
            sealed_streams: &[],
        };
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let sig = sk.sign(&body_bytes);
        let mut full = serde_json::to_value(&body).unwrap();
        full.as_object_mut()
            .unwrap()
            .insert("signature".into(), hex::encode(sig.to_bytes()).into());
        let store = Arc::new(InMemory::new());
        put(&store, "x.json", serde_json::to_vec(&full).unwrap()).await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        assert!(anchor.read_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn non_hex_signature_is_dropped() {
        let (_sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        let obj = serde_json::json!({
            "chain_format_version": "hort-evchain/v1",
            "checkpoint_seq": 1,
            "created_at": "2023-11-14T22:13:20Z",
            "stream_heads": [],
            "sealed_streams": [],
            "signature": "not-hex!!"
        });
        put(&store, "x.json", serde_json::to_vec(&obj).unwrap()).await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        assert!(anchor.read_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn wrong_length_signature_is_dropped() {
        let (_sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        let obj = serde_json::json!({
            "chain_format_version": "hort-evchain/v1",
            "checkpoint_seq": 1,
            "created_at": "2023-11-14T22:13:20Z",
            "stream_heads": [],
            "sealed_streams": [],
            "signature": "abcd"
        });
        put(&store, "x.json", serde_json::to_vec(&obj).unwrap()).await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        assert!(anchor.read_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn multiple_checkpoints_all_returned_unsorted() {
        let (sk, pem) = keypair();
        let store = Arc::new(InMemory::new());
        put(
            &store,
            "2023-11-14T22:13:20Z-1.json",
            signed_checkpoint_json(&sk, 1, &[("admin-a", 0, [1u8; 32])], &[]),
        )
        .await;
        put(
            &store,
            "2023-11-14T23:13:20Z-2.json",
            signed_checkpoint_json(&sk, 2, &[("admin-a", 1, [2u8; 32])], &[]),
        )
        .await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        let mut seqs: Vec<u64> = anchor
            .read_all()
            .await
            .unwrap()
            .iter()
            .map(|c| c.checkpoint_seq)
            .collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn malformed_public_key_pem_rejected_at_construction() {
        let store = Arc::new(InMemory::new());
        match ObjectStoreCheckpointAnchor::new(store, "-----BEGIN nope-----") {
            Ok(_) => panic!("malformed PEM must be rejected at construction"),
            Err(AnchorAdapterError::BadPublicKey(msg)) => {
                let e = AnchorAdapterError::BadPublicKey(msg);
                assert!(e.to_string().contains("Ed25519 SPKI"));
            }
        }
    }

    #[test]
    fn parse_hash_hex_rejects_wrong_length() {
        let e = parse_hash_hex("h", &hex::encode([0u8; 16])).unwrap_err();
        assert!(e.contains("32 bytes"));
    }

    #[test]
    fn parse_hash_hex_accepts_32_bytes() {
        let ok = parse_hash_hex("h", &hex::encode([7u8; 32])).unwrap();
        assert_eq!(ok, EventHash([7u8; 32]));
    }

    #[tokio::test]
    async fn checkpoint_without_sealed_streams_field_defaults_empty() {
        // Forward-compat: an emitter that omits `sealed_streams`
        // entirely (none sealed yet) must still parse.
        let (sk, pem) = keypair();
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let body = SignedBody {
            chain_format_version: "hort-evchain/v1",
            checkpoint_seq: 1,
            created_at: &created_at,
            stream_heads: &[],
            sealed_streams: &[],
        };
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let sig = sk.sign(&body_bytes);
        let obj = serde_json::json!({
            "chain_format_version": "hort-evchain/v1",
            "checkpoint_seq": 1,
            "created_at": "2023-11-14T22:13:20Z",
            "stream_heads": [],
            "signature": hex::encode(sig.to_bytes()),
        });
        let store = Arc::new(InMemory::new());
        put(&store, "x.json", serde_json::to_vec(&obj).unwrap()).await;
        let anchor = ObjectStoreCheckpointAnchor::new(store, &pem).unwrap();
        let cps = anchor.read_all().await.unwrap();
        assert_eq!(cps.len(), 1);
        assert!(cps[0].sealed_streams.is_empty());
    }

    // =======================================================================
    // Write path — checkpoint EMISSION (ADR 0002). The centerpiece is the
    // LOAD-BEARING round-trip: a checkpoint this emitter produces is accepted
    // by the read adapter (`read_all`) + the pure verify core
    // (`verify_against_checkpoint`) → `AnchorVerdict::Ok` against a matching
    // live-head set; a tampered body or a wrong signing key is rejected
    // (dropped → not `Ok`). This proves §6.2 + the signature contract
    // end-to-end against the real verifier (the reader is the pin).
    // =======================================================================

    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use hort_domain::events::{
        build_checkpoint, verify_against_checkpoint, AnchorVerdict, BackfillBaseline, Checkpoint,
        MissingReason, StreamHead,
    };

    /// An Ed25519 keypair as the operator would provision it: a PKCS#8
    /// PEM **private** key (for the emitter) + the matching SPKI PEM
    /// **public** key (for the reader). The two are a real keypair.
    fn signing_keypair_pems() -> (String, String) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let priv_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode PKCS#8 PEM")
            .to_string();
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode SPKI PEM");
        (priv_pem, pub_pem)
    }

    fn dh(id: &str, pos: u64, b: u8) -> StreamHead {
        StreamHead {
            stream_id: id.to_string(),
            final_stream_position: pos,
            head_event_hash: EventHash([b; 32]),
        }
    }

    // ---- construction key handling (§14 R2 fail-on-malformed) ----------

    #[test]
    fn emitter_rejects_malformed_signing_key_at_construction() {
        let store = Arc::new(InMemory::new());
        match ObjectStoreCheckpointEmitter::new(store, "-----BEGIN nope-----") {
            Ok(_) => panic!("malformed signing key PEM must be rejected"),
            Err(EmitterAdapterError::BadSigningKey(msg)) => {
                let e = EmitterAdapterError::BadSigningKey(msg);
                assert!(e.to_string().contains("Ed25519 PKCS#8"));
                let _ = format!("{e:?}");
            }
        }
    }

    #[test]
    fn emitter_accepts_valid_pkcs8_signing_key() {
        let (priv_pem, _pub) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());
        assert!(ObjectStoreCheckpointEmitter::new(store, &priv_pem).is_ok());
    }

    // ---- object key shape (spec §6.2) ----------------------------------

    #[test]
    fn object_key_is_prefix_rfc3339_seq() {
        let ts = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let k = checkpoint_object_key(&ts, 7);
        assert_eq!(
            k,
            "hort-event-chain-checkpoints/2023-11-14T22-13-20Z-7.json"
        );
        assert!(k.starts_with(CHECKPOINT_PREFIX));
    }

    // ---- THE load-bearing round-trip: emit → real reader → Ok ----------

    #[tokio::test]
    async fn emitted_checkpoint_round_trips_through_the_reader() {
        let (priv_pem, pub_pem) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());

        // A live-head set. Build the §6.2 checkpoint via the pure domain
        // builder (sorted witness + first-checkpoint backfill_baseline),
        // emit it through the WRITE adapter.
        let heads = vec![dh("admin-b", 3, 0xbb), dh("admin-a", 1, 0xaa)];
        let cp = build_checkpoint(
            "hort-evchain/v1",
            &[], // no prior checkpoints → seq 1, first checkpoint
            &heads,
            &[],
            12_345,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            Some(BackfillBaseline {
                baseline_max_global_position: 999,
                migration_timestamp: Utc.timestamp_opt(1_699_000_000, 0).unwrap(),
            }),
        );
        let emitter = ObjectStoreCheckpointEmitter::new(store.clone(), &priv_pem).unwrap();
        emitter.emit(&cp).await.expect("emit succeeds");

        // Now read it back through the EXISTING Item-3 reader (the
        // contract pin) — signature must verify against the matching
        // public key, and the domain Checkpoint must reconstruct.
        let reader = ObjectStoreCheckpointAnchor::new(store, &pub_pem).unwrap();
        let cps = reader.read_all().await.expect("read_all");
        assert_eq!(cps.len(), 1, "the emitted object must verify + parse");
        let got = &cps[0];
        assert_eq!(got.chain_format_version, "hort-evchain/v1");
        assert_eq!(got.checkpoint_seq, 1);
        // The reader reconstructs the witness list (sorted by stream_id).
        assert_eq!(
            got.stream_heads,
            vec![
                ("admin-a".to_string(), 1, EventHash([0xaa; 32])),
                ("admin-b".to_string(), 3, EventHash([0xbb; 32])),
            ]
        );

        // Feed it through the pure verify core against a MATCHING live
        // head set → AnchorVerdict::Ok. This is the end-to-end §6.2 +
        // signature-contract proof against the real verifier.
        let live = vec![
            ("admin-a".to_string(), 1u64, EventHash([0xaa; 32])),
            ("admin-b".to_string(), 3u64, EventHash([0xbb; 32])),
        ];
        let verdict = verify_against_checkpoint(
            &live,
            &[],
            &cps,
            Utc.timestamp_opt(1_700_000_001, 0).unwrap(),
            std::time::Duration::from_secs(3600),
        );
        assert_eq!(verdict, AnchorVerdict::Ok);

        // The v1 SignedBody signs the flat sorted witness list directly;
        // the reader verifies that signed list — there is no Merkle root
        // recomputation on either path. (See checkpoint_build module doc
        // for the forward-decision note on a future signed-root bump.)
    }

    #[tokio::test]
    async fn emitted_checkpoint_carries_unsigned_advisory_extras() {
        // max_global_position + backfill_baseline are written to the
        // object (auditors read them) even though the shipped reader
        // does not verify them — the documented signed-body residual.
        let (priv_pem, _pub) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());
        let cp = build_checkpoint(
            "hort-evchain/v1",
            &[],
            &[dh("s", 0, 1)],
            &[],
            55_555,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            Some(BackfillBaseline {
                baseline_max_global_position: 4242,
                migration_timestamp: Utc.timestamp_opt(1_699_000_000, 0).unwrap(),
            }),
        );
        let emitter = ObjectStoreCheckpointEmitter::new(store.clone(), &priv_pem).unwrap();
        emitter.emit(&cp).await.unwrap();

        let path: object_store::path::Path =
            "hort-event-chain-checkpoints/2023-11-14T22-13-20Z-1.json".into();
        let raw = store.get(&path).await.unwrap().bytes().await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["max_global_position"], 55_555);
        assert_eq!(v["backfill_baseline"], true);
        assert_eq!(v["baseline_max_global_position"], 4242);
        assert!(v["migration_timestamp"].is_string());
        assert!(v["signature"].is_string());
    }

    #[tokio::test]
    async fn second_checkpoint_has_no_backfill_baseline_in_object() {
        // §5: the honesty caveat is first-checkpoint-only. Build a
        // non-first checkpoint and assert the object omits the baseline
        // keys entirely (skip_serializing_if).
        let (priv_pem, _pub) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());
        let prior = Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: 1,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            stream_heads: vec![],
            sealed_streams: vec![],
        };
        let cp = build_checkpoint(
            "hort-evchain/v1",
            std::slice::from_ref(&prior),
            &[dh("s", 1, 2)],
            &[],
            60_000,
            Utc.timestamp_opt(1_700_003_600, 0).unwrap(),
            None,
        );
        assert_eq!(cp.checkpoint_seq, 2);
        let emitter = ObjectStoreCheckpointEmitter::new(store.clone(), &priv_pem).unwrap();
        emitter.emit(&cp).await.unwrap();
        let path: object_store::path::Path =
            "hort-event-chain-checkpoints/2023-11-14T23-13-20Z-2.json".into();
        let raw = store.get(&path).await.unwrap().bytes().await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(v.get("backfill_baseline").is_none());
        assert!(v.get("baseline_max_global_position").is_none());
        assert!(v.get("migration_timestamp").is_none());
    }

    #[tokio::test]
    async fn wrong_signing_key_checkpoint_is_rejected_by_reader() {
        // Emitter signs with key A; reader verifies with an unrelated
        // key B's public PEM → the reader drops it (treated as absent),
        // never a passing checkpoint. The anchor verdict is then
        // MissingCheckpoint (NoCheckpoint), NOT Ok.
        let (priv_a, _pub_a) = signing_keypair_pems();
        let (_priv_b, pub_b) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());
        let cp = build_checkpoint(
            "hort-evchain/v1",
            &[],
            &[dh("s", 0, 1)],
            &[],
            1,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            None,
        );
        ObjectStoreCheckpointEmitter::new(store.clone(), &priv_a)
            .unwrap()
            .emit(&cp)
            .await
            .unwrap();
        let reader = ObjectStoreCheckpointAnchor::new(store, &pub_b).unwrap();
        let cps = reader.read_all().await.unwrap();
        assert!(cps.is_empty(), "wrong-key checkpoint must read as absent");
        let verdict = verify_against_checkpoint(
            &[],
            &[],
            &cps,
            Utc::now(),
            std::time::Duration::from_secs(3600),
        );
        assert_eq!(
            verdict,
            AnchorVerdict::MissingCheckpoint(MissingReason::NoCheckpoint)
        );
    }

    #[tokio::test]
    async fn tampered_emitted_body_fails_reader_signature() {
        // Emit, then mutate a signed field in the stored object while
        // keeping the original signature → the reader's Ed25519 check
        // fails → dropped (not a passing checkpoint).
        let (priv_pem, pub_pem) = signing_keypair_pems();
        let store = Arc::new(InMemory::new());
        let cp = build_checkpoint(
            "hort-evchain/v1",
            &[],
            &[dh("admin-a", 0, 1)],
            &[],
            1,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            None,
        );
        let emitter = ObjectStoreCheckpointEmitter::new(store.clone(), &priv_pem).unwrap();
        emitter.emit(&cp).await.unwrap();
        let path: object_store::path::Path =
            "hort-event-chain-checkpoints/2023-11-14T22-13-20Z-1.json".into();
        let raw = store.get(&path).await.unwrap().bytes().await.unwrap();
        let mut obj: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        // Forge the head hash; signature now covers different bytes.
        obj["stream_heads"][0]["head_event_hash"] = hex::encode([9u8; 32]).into();
        store
            .put(&path, serde_json::to_vec(&obj).unwrap().into())
            .await
            .unwrap();
        let reader = ObjectStoreCheckpointAnchor::new(store, &pub_pem).unwrap();
        assert!(
            reader.read_all().await.unwrap().is_empty(),
            "a post-sign mutation must fail the reader's signature check"
        );
    }

    #[tokio::test]
    async fn emit_surfaces_anchor_store_write_failure_as_err() {
        // A read-only / failing store surfaces an operational Err for
        // this cycle (the task maps it to anchor_write_failed + error!),
        // never a silently-skipped checkpoint.
        use object_store::path::Path as OsPath;
        use object_store::{
            CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
            PutMultipartOptions, PutOptions, PutPayload, PutResult,
        };

        fn boom() -> object_store::Error {
            object_store::Error::Generic {
                store: "FailingStore",
                source: "simulated anchor-store write failure".into(),
            }
        }

        #[derive(Debug)]
        struct FailingStore;
        impl std::fmt::Display for FailingStore {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FailingStore")
            }
        }
        #[async_trait::async_trait]
        impl ObjectStore for FailingStore {
            async fn put_opts(
                &self,
                _l: &OsPath,
                _p: PutPayload,
                _o: PutOptions,
            ) -> object_store::Result<PutResult> {
                Err(boom())
            }
            async fn put_multipart_opts(
                &self,
                _l: &OsPath,
                _o: PutMultipartOptions,
            ) -> object_store::Result<Box<dyn MultipartUpload>> {
                Err(boom())
            }
            async fn get_opts(
                &self,
                _l: &OsPath,
                _o: GetOptions,
            ) -> object_store::Result<GetResult> {
                Err(boom())
            }
            fn delete_stream(
                &self,
                locations: futures::stream::BoxStream<'static, object_store::Result<OsPath>>,
            ) -> futures::stream::BoxStream<'static, object_store::Result<OsPath>> {
                let _ = locations;
                Box::pin(futures::stream::empty())
            }
            fn list(
                &self,
                _p: Option<&OsPath>,
            ) -> futures::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
                Box::pin(futures::stream::empty())
            }
            async fn list_with_delimiter(
                &self,
                _p: Option<&OsPath>,
            ) -> object_store::Result<ListResult> {
                Err(boom())
            }
            async fn copy_opts(
                &self,
                _f: &OsPath,
                _t: &OsPath,
                _o: CopyOptions,
            ) -> object_store::Result<()> {
                Err(boom())
            }
        }

        let (priv_pem, _pub) = signing_keypair_pems();
        let cp = build_checkpoint(
            "hort-evchain/v1",
            &[],
            &[dh("s", 0, 1)],
            &[],
            1,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            None,
        );
        let emitter = ObjectStoreCheckpointEmitter::new(Arc::new(FailingStore), &priv_pem).unwrap();
        let err = emitter.emit(&cp).await.unwrap_err();
        assert!(err.to_string().contains("anchor checkpoint write failed"));
    }
}
