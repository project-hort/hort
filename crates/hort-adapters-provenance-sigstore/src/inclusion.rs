//! Offline Rekor **Merkle inclusion proof + checkpoint signature**
//! verification for a v0.3 Sigstore bundle (ADR 0027 — "Rekor inclusion
//! verification", Route A).
//!
//! `sigstore` 0.14's `Verifier::verify_digest` validates the Fulcio chain,
//! the embedded SCT, the artifact signature, and the digest binding, but
//! its Rekor inclusion-proof + SET steps are upstream `TODO`s
//! (sigstore-rs#285). This module closes that gap **offline**: it
//! reconstructs the public `rekor::models::InclusionProof` from the
//! bundle's protobuf transparency-log entry and runs the crate's own
//! cryptographically-complete [`InclusionProof::verify`] — full RFC-6962
//! Merkle inclusion + `checkpoint.verify_signature` +
//! `is_valid_for_proof` — against the Rekor public key selected from the
//! already-loaded, pinned trust root by the entry's `logID`.
//!
//! **Scope: v0.3 bundles only.** Per ADR 0027:168 the verifier accepts the
//! Sigstore v0.3 bundle format, whose inclusion proof always carries a
//! checkpoint (`check_02_bundle` rejects a missing proof/checkpoint at
//! parse). The older v0.1 SET / `inclusion_promise` path is **not**
//! implemented — a bundle with no inclusion proof / no checkpoint can
//! never reach `Verified` here, matching the design's "no SET path"
//! decision. It is not *rejected* either: absent log material is material
//! nothing could be concluded from, so the candidate is skipped and the
//! artifact holds as unsigned (see [`InclusionFailureSide`]).
//!
//! **Fail-closed, offline, no panic.** Every conversion that could fail
//! (the `Vec<u8> → [u8; 32]` width narrowing on the root hash and each
//! audit-path hash, the `i64 → u64` narrowing on the tree size, the
//! checkpoint-envelope parse, the `logID` key lookup, the SPKI key parse)
//! returns an [`InclusionError`] rather than panicking.
//! **No failure here can reach `Verified`**; which of three answers it
//! does reach — a terminal rejection, a hold, or a skip — is
//! [`InclusionError::side`]'s decision, because fail-closed is not the
//! same thing as terminal. There is **no** live Rekor fetch — the proof +
//! checkpoint the bundle already carries are verified against the
//! in-memory trust-root key.

use std::collections::BTreeMap;

use sigstore::crypto::CosignVerificationKey;
use sigstore::rekor::models::checkpoint::SignedCheckpoint;
use sigstore::rekor::models::inclusion_proof::InclusionProof;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;

use sigstore::bundle::Bundle;

/// A Rekor public key id is keyed in the trust root's `rekor_keys()` map by
/// the lowercase hex encoding of the `logID.key_id` bytes
/// (`SigstoreTrustRoot::tlog_keys` does `hex::encode(log_id.key_id)`). We
/// re-derive the same hex string from the bundle entry's `logID` to select
/// the matching key.
fn key_id_hex(key_id: &[u8]) -> String {
    hex::encode(key_id)
}

/// Why offline inclusion verification failed — and, through
/// [`InclusionError::side`], which of three answers the candidate gives.
///
/// The variant used to be a label and nothing else: every one of them
/// folded into [`ProvenanceRejectReason::RekorNotFound`]
/// (`hort_provenance_reject_total{reason="rekor_not_found"}`) and the
/// distinction survived only in an adapter-layer `debug!` line. It is
/// load-bearing now, because only readable material from which something
/// was actually proved may condemn an artifact (ADR 0039 D4) and these
/// failures are not all of that kind: one is a disproof, two are faults in
/// our own trust root, and seven are the bundle's own log material being
/// absent, unparseable or structurally impossible. No variant carries key
/// bytes, then or now.
///
/// [`ProvenanceRejectReason::RekorNotFound`]: hort_domain::ports::provenance::ProvenanceRejectReason::RekorNotFound
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InclusionError {
    /// The bundle carries no transparency-log entry (no
    /// `verification_material.tlog_entries[0]`) — so there was no log
    /// material to check.
    NoTlogEntry,
    /// The tlog entry carries no inclusion proof (v0.1-shaped / SET-only)
    /// — out of scope, fail closed: this verifier checks nothing on it and
    /// concludes nothing from it.
    NoInclusionProof,
    /// The inclusion proof carries no checkpoint envelope (a v0.3 proof
    /// always must — `check_02_bundle` enforces it at parse; absence here
    /// is a malformed proof, and fail closed: there is no signed root to
    /// fold the leaf against, so nothing can be concluded either way).
    NoCheckpoint,
    /// The checkpoint signed-note envelope did not parse.
    CheckpointParse,
    /// A `root_hash` / audit-path hash was not exactly 32 bytes (a
    /// fail-closed width check — never a panic on `try_into`).
    HashWidth,
    /// The inclusion proof's `tree_size` is not a possible tree size: the
    /// protobuf field is `i64` and the model's is `u64`, so a negative
    /// value fails the narrowing (a fail-closed width check — never a
    /// panic on `try_into`).
    ///
    /// A structurally absurd number in the bundle's own log material, in
    /// the same family as [`Self::HashWidth`] and
    /// [`Self::CheckpointParse`]: no Merkle fold was attempted against
    /// it, so nothing was checked and nothing was proved. It wore
    /// [`Self::VerifyFailed`] — the enum's one disproof — which claimed a
    /// proof had been read and rejected by the cryptography.
    ///
    /// Narrow, and worth being clear how narrow: reaching it needs the
    /// signer's own log entry to claim a negative tree size on a bundle
    /// that already passed full Fulcio chain, SCT, signature and digest
    /// verification. A hole in the rule rather than a reachable attack.
    TreeSizeInvalid,
    /// The tlog entry carries no `logID.key_id`.
    NoLogId,
    /// No Rekor key in the trust root matches the entry's `logID` — a
    /// trust-root misprovision.
    NoMatchingRekorKey,
    /// The trust-root Rekor key bytes did not parse as a verification key.
    KeyParse,
    /// The cryptographic inclusion / checkpoint verification failed: the
    /// proof was present, readable, and did not verify.
    VerifyFailed,
}

/// Whose side an [`InclusionError`] is a failure on.
///
/// That question is the whole of this type, and it is the test an eleventh
/// [`InclusionError`] variant has to answer: *is this a failure of the
/// material the publisher pushed, or of our own ability to check it — and
/// if it is the material's, was anything actually proved about it?* Only
/// the one answer where something was proved may condemn the artifact
/// (ADR 0039 D4); the other two hold, and they hold for different reasons
/// with different operator actions behind them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InclusionFailureSide {
    /// **The material's, and something was proved against it.** A present,
    /// readable proof that did not verify: a forged or non-included entry.
    /// The only disproof this enum can state, and the only answer that is
    /// terminal.
    Disproof,
    /// **Ours.** The trust root holds no usable key for this check, so the
    /// check never ran. A publisher's correctly signed, log-included
    /// artifact is not implicated by our inability to load a key, and the
    /// remedy is in the operator's trust root rather than in the artifact
    /// — so it is held, and it verifies on the next run once the key is
    /// provisioned.
    TrustRoot,
    /// **The material's, and nothing was proved.** The bundle's own log
    /// material is absent or unparseable: not garbage to be condemned, not
    /// a forgery, nothing concluded. The candidate contributes nothing and
    /// the artifact holds as unsigned — anyone who can write the referrer
    /// surface can attach a bundle of this shape, so condemning on one
    /// would let them reject somebody else's correctly-signed image.
    NothingProved,
}

impl InclusionError {
    /// Classify this failure by whose side it is on.
    ///
    /// **Wildcard-free on purpose:** an eleventh variant does not compile here
    /// until it has answered [`InclusionFailureSide`]'s question. The
    /// evidence for each row below is the variant's own doc comment.
    pub(crate) fn side(&self) -> InclusionFailureSide {
        match self {
            // A proof we read, and the cryptography said no.
            Self::VerifyFailed => InclusionFailureSide::Disproof,
            // Our provisioning: no key for the entry's log, or key bytes
            // of ours that do not parse. Neither says anything about the
            // publisher's material — the check did not run.
            Self::NoMatchingRekorKey | Self::KeyParse => InclusionFailureSide::TrustRoot,
            // The bundle's own log material, absent, unparseable or
            // structurally impossible: no entry, no proof, no checkpoint,
            // an unparseable checkpoint, a hash of the wrong width, a
            // negative tree size, no log id. Nothing was checked, so
            // nothing was proved.
            Self::NoTlogEntry
            | Self::NoInclusionProof
            | Self::NoCheckpoint
            | Self::CheckpointParse
            | Self::HashWidth
            | Self::TreeSizeInvalid
            | Self::NoLogId => InclusionFailureSide::NothingProved,
        }
    }
}

/// The minimal transparency-log material pulled out of a parsed `Bundle`
/// **before** `verify_digest` consumes it. All fields are owned so they
/// outlive the bundle.
pub(crate) struct TlogInclusionMaterial {
    /// The leaf preimage: the canonicalized Rekor entry body fed verbatim
    /// to [`InclusionProof::verify`] (sigstore-rs's own offline path
    /// consumes this same field — no canonical-JSON reconstruction).
    canonicalized_body: Vec<u8>,
    /// Lowercase-hex `logID.key_id`, used to select the Rekor key.
    key_id_hex: String,
    /// The protobuf inclusion proof's `log_index`.
    log_index: i64,
    /// The protobuf inclusion proof's `tree_size`.
    tree_size: i64,
    /// The protobuf inclusion proof's `root_hash` (raw bytes; width is
    /// checked at conversion).
    root_hash: Vec<u8>,
    /// The protobuf inclusion proof's audit-path `hashes` (raw bytes each;
    /// widths checked at conversion).
    hashes: Vec<Vec<u8>>,
    /// The protobuf checkpoint signed-note envelope string.
    checkpoint_envelope: String,
}

impl TlogInclusionMaterial {
    /// Extract the inclusion material from the **first** transparency-log
    /// entry of a parsed bundle. Returns an [`InclusionError`] (fail-closed)
    /// when any required piece is absent — never a panic.
    ///
    /// The first tlog entry is the one `verify_digest`'s structural checks
    /// key on; a v0.3 cosign bundle carries exactly one.
    pub(crate) fn from_bundle(bundle: &Bundle) -> Result<Self, InclusionError> {
        let material = bundle
            .verification_material
            .as_ref()
            .ok_or(InclusionError::NoTlogEntry)?;
        let entry = material
            .tlog_entries
            .first()
            .ok_or(InclusionError::NoTlogEntry)?;
        let proof = entry
            .inclusion_proof
            .as_ref()
            .ok_or(InclusionError::NoInclusionProof)?;
        // A v0.3 inclusion proof always carries a checkpoint; absence is
        // fail-closed (parse-enforced upstream, defensively rechecked here).
        let envelope = proof
            .checkpoint
            .as_ref()
            .map(|c| c.envelope.clone())
            .filter(|e| !e.is_empty())
            .ok_or(InclusionError::NoCheckpoint)?;
        let key_id = entry
            .log_id
            .as_ref()
            .map(|l| l.key_id.clone())
            .filter(|k| !k.is_empty())
            .ok_or(InclusionError::NoLogId)?;

        Ok(Self {
            canonicalized_body: entry.canonicalized_body.clone(),
            key_id_hex: key_id_hex(&key_id),
            log_index: proof.log_index,
            tree_size: proof.tree_size,
            root_hash: proof.root_hash.clone(),
            hashes: proof.hashes.clone(),
            checkpoint_envelope: envelope,
        })
    }
}

/// Convert a raw byte vector to a fixed 32-byte SHA-256 digest, **failing
/// closed** on any width != 32 (never a panic / `unwrap`).
fn to_sha256(bytes: &[u8]) -> Result<[u8; 32], InclusionError> {
    bytes.try_into().map_err(|_| InclusionError::HashWidth)
}

/// Build the public `rekor::models::InclusionProof` from the extracted
/// protobuf material, with fail-closed `Vec<u8> → [u8; 32]` width checks and
/// a checkpoint-envelope parse.
///
/// `SignedCheckpoint::decode` is `pub(crate)` in `sigstore` 0.14, but
/// `SignedCheckpoint` implements `Deserialize` from a signed-note **string**
/// (the same `decode` under the hood), so we parse the protobuf envelope
/// (itself a `String`) by deserializing it as a JSON string value — no
/// dependency on the private `decode`.
fn build_model_proof(material: &TlogInclusionMaterial) -> Result<InclusionProof, InclusionError> {
    let root_hash = to_sha256(&material.root_hash)?;
    let hashes = material
        .hashes
        .iter()
        .map(|h| to_sha256(h))
        .collect::<Result<Vec<[u8; 32]>, _>>()?;

    // `tree_size` is i64 in the protobuf but u64 in the model; a negative
    // value is not a possible tree size and fails closed. It is the
    // bundle's own material being structurally absurd — no fold was
    // attempted against it — so it skips rather than condemning: the one
    // variant that condemns means a proof we read and the cryptography
    // rejected, which this is not.
    let tree_size: u64 = material
        .tree_size
        .try_into()
        .map_err(|_| InclusionError::TreeSizeInvalid)?;

    // Parse the signed-note envelope into a `SignedCheckpoint` via its
    // `Deserialize` impl (which calls the crate-private `decode`). The
    // envelope is a plain string; wrapping it as a JSON string value lets
    // serde drive the string-based deserializer.
    let checkpoint: SignedCheckpoint = serde_json::from_value(serde_json::Value::String(
        material.checkpoint_envelope.clone(),
    ))
    .map_err(|_| InclusionError::CheckpointParse)?;

    Ok(InclusionProof::new(
        material.log_index,
        root_hash,
        tree_size,
        hashes,
        Some(checkpoint),
    ))
}

/// Select the Rekor verification key for this entry from the trust root's
/// `rekor_keys()` map by the entry's `logID` (hex). No matching key, or
/// key bytes that do not parse → fail closed, and on *our* side of the
/// line ([`InclusionFailureSide::TrustRoot`]): the check never ran.
fn select_rekor_key(
    key_id_hex: &str,
    rekor_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<CosignVerificationKey, InclusionError> {
    let der = rekor_keys
        .get(key_id_hex)
        .ok_or(InclusionError::NoMatchingRekorKey)?;
    // The trust-root Rekor key is DER-encoded SPKI; auto-detect the
    // algorithm from the SPKI OID (the production key is ECDSA P-256
    // SHA-256). `try_from_der` parses the SPKI and selects the scheme.
    CosignVerificationKey::try_from_der(der).map_err(|_| InclusionError::KeyParse)
}

/// Verify, fully offline, that the bundle's v0.3 transparency-log entry is
/// provably included in the Rekor log:
/// 1. select the Rekor key from the pinned trust root by the entry's
///    `logID`;
/// 2. reconstruct the public `InclusionProof` (fail-closed width checks +
///    checkpoint parse);
/// 3. run the crate's cryptographically-complete `InclusionProof::verify`
///    (RFC-6962 Merkle inclusion + checkpoint signature + root/size
///    consistency) over the `canonicalized_body` leaf.
///
/// Any failure returns an [`InclusionError`]; the caller classifies it
/// through [`InclusionError::side`], and only `VerifyFailed` is a finding
/// about the artifact. Never panics, never fetches.
pub(crate) fn verify_inclusion(
    material: &TlogInclusionMaterial,
    rekor_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<(), InclusionError> {
    let rekor_key = select_rekor_key(&material.key_id_hex, rekor_keys)?;
    let proof = build_model_proof(material)?;
    proof
        .verify(&material.canonicalized_body, &rekor_key)
        .map_err(|_| InclusionError::VerifyFailed)
}

/// Snapshot the trust root's Rekor public keys into an **owned**
/// `BTreeMap<hex key-id, DER SPKI bytes>` so the keys outlive the
/// `SigstoreTrustRoot` (which `Verifier::new` consumes by value). Keyed
/// exactly as `rekor_keys()` keys them (lowercase hex of `logID.key_id`),
/// so per-entry `logID` selection matches.
///
/// Returns an empty map when the root carries no (time-valid) Rekor key —
/// the §8 boot assertion treats that as a hard error when a verifier is
/// registered, and it has to: a per-verify lookup against an empty map is
/// `NoMatchingRekorKey`, a hold on our own provisioning, so without the
/// boot refusal every artifact in the scope would hold indefinitely
/// instead of the worker declining to start.
pub(crate) fn collect_rekor_keys(trust_root: &SigstoreTrustRoot) -> BTreeMap<String, Vec<u8>> {
    trust_root
        .rekor_keys()
        .map(|m| {
            m.into_iter()
                .map(|(k, v)| (k, v.to_vec()))
                .collect::<BTreeMap<String, Vec<u8>>>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    /// RFC-6962 leaf hash: `sha256(0x00 || leaf)`.
    fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0u8]);
        h.update(leaf);
        h.finalize().into()
    }

    /// A freshly-generated ECDSA P-256 key pair plus the DER SPKI public key
    /// bytes, in the exact shape the trust root stores them.
    struct TestRekorKey {
        key_pair: EcdsaKeyPair,
        spki_der: Vec<u8>,
        rng: aws_lc_rs::rand::SystemRandom,
    }

    impl TestRekorKey {
        fn generate() -> Self {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("generate pkcs8");
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                    .expect("parse pkcs8");
            // The public key from aws-lc-rs is the raw uncompressed EC point
            // (0x04 || X || Y); wrap it in an SPKI so `try_from_der` (which
            // parses SubjectPublicKeyInfo) can read it.
            let spki_der = spki_p256(key_pair.public_key().as_ref());
            Self {
                key_pair,
                spki_der,
                rng,
            }
        }

        /// Sign `msg` and return the raw ASN.1 DER ECDSA signature bytes.
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.key_pair
                .sign(&self.rng, msg)
                .expect("sign")
                .as_ref()
                .to_vec()
        }
    }

    /// Wrap a raw uncompressed P-256 public point (65 bytes, `0x04 || X ||
    /// Y`) in a DER `SubjectPublicKeyInfo` for `id-ecPublicKey` + `secp256r1`
    /// so `CosignVerificationKey::try_from_der` parses it.
    ///
    /// SPKI = SEQUENCE { AlgorithmIdentifier { ecPublicKey, prime256v1 },
    ///                   BIT STRING (the point) }.
    fn spki_p256(point: &[u8]) -> Vec<u8> {
        // AlgorithmIdentifier for id-ecPublicKey (1.2.840.10045.2.1) with
        // parameters = named curve prime256v1 (1.2.840.10045.3.1.7).
        // This is the standard fixed prefix; appending the BIT STRING of the
        // 65-byte point yields a valid P-256 SPKI.
        const SPKI_PREFIX: &[u8] = &[
            0x30, 0x59, // SEQUENCE, len 0x59 (89)
            0x30, 0x13, // SEQUENCE (AlgorithmIdentifier), len 0x13 (19)
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
            0x03, 0x42, 0x00, // BIT STRING, len 0x42 (66), 0 unused bits
        ];
        assert_eq!(point.len(), 65, "uncompressed P-256 point is 65 bytes");
        let mut der = Vec::with_capacity(SPKI_PREFIX.len() + point.len());
        der.extend_from_slice(SPKI_PREFIX);
        der.extend_from_slice(point);
        der
    }

    /// Marshal a single-leaf checkpoint note exactly as
    /// `Checkpoint::marshal` does: `origin\nsize\n<b64 root>\n`.
    fn marshal_note(origin: &str, size: u64, root_hash: &[u8; 32]) -> String {
        format!("{origin}\n{size}\n{}\n", B64.encode(root_hash))
    }

    /// Build a signed-note checkpoint envelope (the format `SignedCheckpoint`
    /// parses): the marshaled note, a blank line, then one signature line
    /// `\u{2014} <name> <b64(key_fingerprint || raw_sig)>\n`.
    fn signed_checkpoint_envelope(
        origin: &str,
        size: u64,
        root_hash: &[u8; 32],
        key: &TestRekorKey,
        key_fingerprint: [u8; 4],
    ) -> String {
        let note = marshal_note(origin, size, root_hash);
        // `verify_signature` checks the signature over `note.marshal()` —
        // i.e. the marshaled note WITHOUT the trailing newline the envelope
        // adds. `marshal()` returns exactly `marshal_note` above.
        let sig = key.sign(note.as_bytes());
        let mut sig_blob = key_fingerprint.to_vec();
        sig_blob.extend_from_slice(&sig);
        let sig_line = format!("\u{2014} {origin} {}\n", B64.encode(&sig_blob));
        // Envelope = note + empty line + signature lines.
        format!("{note}\n{sig_line}")
    }

    /// Build the full single-leaf inclusion material: tree_size = 1,
    /// log_index = 0, empty audit path, root = leaf hash, checkpoint signed
    /// over that root.
    fn single_leaf_material(
        body: &[u8],
        key: &TestRekorKey,
        key_id: &[u8],
    ) -> TlogInclusionMaterial {
        let root = hash_leaf(body);
        let envelope = signed_checkpoint_envelope("test.log", 1, &root, key, [0u8; 4]);
        TlogInclusionMaterial {
            canonicalized_body: body.to_vec(),
            key_id_hex: key_id_hex(key_id),
            log_index: 0,
            tree_size: 1,
            root_hash: root.to_vec(),
            hashes: vec![],
            checkpoint_envelope: envelope,
        }
    }

    fn keys_map(key_id: &[u8], key: &TestRekorKey) -> BTreeMap<String, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert(key_id_hex(key_id), key.spki_der.clone());
        m
    }

    /// **Positive correctness test.** A hand-built, fully-valid single-leaf
    /// Merkle inclusion proof + signed checkpoint, signed by a freshly
    /// generated ECDSA P-256 key, verifies. This proves the real RFC-6962
    /// Merkle fold + checkpoint-signature path runs end to end (no fixture,
    /// no network).
    #[test]
    fn valid_single_leaf_inclusion_verifies() {
        let key = TestRekorKey::generate();
        let key_id = b"\x01\x02\x03\x04rekor-key-id";
        let body = b"a canonicalized rekor entry body";
        let material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        assert_eq!(verify_inclusion(&material, &keys), Ok(()));
    }

    /// Tampered leaf body → the leaf hash no longer matches the checkpoint
    /// root → `VerifyFailed`.
    #[test]
    fn tampered_body_fails() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-tamper-body";
        let body = b"original body";
        let mut material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        // Mutate the body AFTER the checkpoint was signed over the original
        // root: the leaf now folds to a different root than the checkpoint.
        material.canonicalized_body = b"tampered body".to_vec();
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::VerifyFailed)
        );
    }

    /// Wrong `root_hash` (does not match the checkpoint / leaf) → fail.
    #[test]
    fn wrong_root_hash_fails() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-wrong-root";
        let body = b"some body";
        let mut material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        material.root_hash = vec![0xAB; 32]; // valid width, wrong value
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::VerifyFailed)
        );
    }

    /// A tampered audit-path hash (in a multi-leaf proof) breaks the fold.
    /// We build a 2-leaf tree: leaves L0, L1; root = hash_children(h0, h1);
    /// proof for leaf 0 is `[h1]`. Tampering `h1` breaks inclusion.
    #[test]
    fn tampered_audit_path_hash_fails() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-audit";
        let l0 = b"leaf-zero-body";
        let l1 = b"leaf-one-body";
        let h0 = hash_leaf(l0);
        let h1 = hash_leaf(l1);
        // RFC-6962 internal node: sha256(0x01 || left || right).
        let mut hc = Sha256::new();
        hc.update([1u8]);
        hc.update(h0);
        hc.update(h1);
        let root: [u8; 32] = hc.finalize().into();

        let envelope = signed_checkpoint_envelope("test.log", 2, &root, &key, [0u8; 4]);
        let mut material = TlogInclusionMaterial {
            canonicalized_body: l0.to_vec(),
            key_id_hex: key_id_hex(key_id),
            log_index: 0,
            tree_size: 2,
            root_hash: root.to_vec(),
            hashes: vec![h1.to_vec()],
            checkpoint_envelope: envelope,
        };
        let keys = keys_map(key_id, &key);
        // Sanity: the untampered 2-leaf proof verifies.
        assert_eq!(verify_inclusion(&material, &keys), Ok(()));
        // Now flip a byte of the audit-path hash → broken fold.
        material.hashes[0][0] ^= 0xFF;
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::VerifyFailed)
        );
    }

    /// A `root_hash` that is not 32 bytes → fail-closed width check, never a
    /// panic.
    #[test]
    fn short_root_hash_is_hash_width_error() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-short";
        let body = b"body";
        let mut material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        material.root_hash = vec![0u8; 31]; // one byte short
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::HashWidth)
        );
    }

    /// A non-32-byte audit-path hash → fail-closed width check.
    #[test]
    fn wide_audit_path_hash_is_hash_width_error() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-wide";
        let body = b"body";
        let mut material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        material.hashes = vec![vec![0u8; 33]]; // one byte wide
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::HashWidth)
        );
    }

    /// No Rekor key in the trust root matches the entry's `logID` → fail
    /// closed, no key bytes leaked.
    #[test]
    fn missing_rekor_key_fails_closed() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-present";
        let body = b"body";
        let material = single_leaf_material(body, &key, key_id);
        // Map keyed by a DIFFERENT logID → no match.
        let mut keys = BTreeMap::new();
        keys.insert(key_id_hex(b"some-other-keyid"), key.spki_der.clone());
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::NoMatchingRekorKey)
        );
    }

    /// Empty key map → no match (fail closed). Mirrors the post-fix
    /// "verifier registered but trust root has no Rekor key" failure mode.
    #[test]
    fn empty_key_map_fails_closed() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid";
        let material = single_leaf_material(b"body", &key, key_id);
        let keys: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::NoMatchingRekorKey)
        );
    }

    /// The checkpoint signature was made by a DIFFERENT key than the one in
    /// the trust root → `verify_signature` fails → `VerifyFailed`.
    #[test]
    fn wrong_checkpoint_signing_key_fails() {
        let signing_key = TestRekorKey::generate();
        let trust_key = TestRekorKey::generate(); // different key
        let key_id = b"keyid-mismatch";
        let body = b"body";
        // Build material whose checkpoint is signed by `signing_key`...
        let material = single_leaf_material(body, &signing_key, key_id);
        // ...but the trust root holds `trust_key`'s SPKI under that logID.
        let mut keys = BTreeMap::new();
        keys.insert(key_id_hex(key_id), trust_key.spki_der.clone());
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::VerifyFailed)
        );
    }

    /// An unparseable checkpoint envelope → `CheckpointParse`, never a panic.
    #[test]
    fn bad_checkpoint_envelope_is_parse_error() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-badcp";
        let body = b"body";
        let mut material = single_leaf_material(body, &key, key_id);
        let keys = keys_map(key_id, &key);
        material.checkpoint_envelope = "this is not a signed note".to_string();
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::CheckpointParse)
        );
    }

    /// The trust-root "key" bytes are not a parseable SPKI → `KeyParse`.
    #[test]
    fn unparseable_trust_root_key_is_key_parse_error() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-badkey";
        let body = b"body";
        let material = single_leaf_material(body, &key, key_id);
        let mut keys = BTreeMap::new();
        keys.insert(key_id_hex(key_id), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::KeyParse)
        );
    }

    /// `from_bundle` on a bundle with no verification material → fail-closed
    /// `NoTlogEntry`, no panic.
    #[test]
    fn from_bundle_no_material_is_no_tlog_entry() {
        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".into(),
            verification_material: None,
            content: None,
        };
        assert!(matches!(
            TlogInclusionMaterial::from_bundle(&bundle),
            Err(InclusionError::NoTlogEntry)
        ));
    }

    /// Parse the real v0.3 fixture and null one field per test to exercise the
    /// `from_bundle` fail-closed branches that the success/crypto tests don't.
    fn real_v03_bundle() -> Bundle {
        let json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        serde_json::from_str(json).expect("fixture parses")
    }

    /// A tlog entry present but carrying no inclusion proof (v0.1 SET-only
    /// shape) → `NoInclusionProof`, fail-closed.
    #[test]
    fn from_bundle_missing_inclusion_proof_is_no_inclusion_proof() {
        let mut bundle = real_v03_bundle();
        bundle
            .verification_material
            .as_mut()
            .expect("material")
            .tlog_entries[0]
            .inclusion_proof = None;
        assert!(matches!(
            TlogInclusionMaterial::from_bundle(&bundle),
            Err(InclusionError::NoInclusionProof)
        ));
    }

    /// An inclusion proof with no checkpoint → `NoCheckpoint`, fail-closed
    /// (a v0.3 proof must carry one; absence is rejected, never skipped).
    #[test]
    fn from_bundle_missing_checkpoint_is_no_checkpoint() {
        let mut bundle = real_v03_bundle();
        bundle
            .verification_material
            .as_mut()
            .expect("material")
            .tlog_entries[0]
            .inclusion_proof
            .as_mut()
            .expect("proof")
            .checkpoint = None;
        assert!(matches!(
            TlogInclusionMaterial::from_bundle(&bundle),
            Err(InclusionError::NoCheckpoint)
        ));
    }

    /// A tlog entry with no `logID` → `NoLogId`, fail-closed (we cannot select
    /// a Rekor key without it).
    #[test]
    fn from_bundle_missing_log_id_is_no_log_id() {
        let mut bundle = real_v03_bundle();
        bundle
            .verification_material
            .as_mut()
            .expect("material")
            .tlog_entries[0]
            .log_id = None;
        assert!(matches!(
            TlogInclusionMaterial::from_bundle(&bundle),
            Err(InclusionError::NoLogId)
        ));
    }

    /// A negative `tree_size` (not a possible tree size; the protobuf
    /// field is `i64`, the model wants `u64`) → fail-closed at
    /// conversion, never a panic.
    ///
    /// **Changed variant.** This asserted `VerifyFailed`, which after the
    /// side classification landed is the enum's *only* disproof — "a
    /// proof we read, and the cryptography said no". No fold was ever
    /// attempted against this number; the bundle's own material is
    /// structurally absurd, which is `HashWidth`'s and
    /// `CheckpointParse`'s family, and all three skip.
    #[test]
    fn negative_tree_size_is_structurally_invalid_not_a_disproof() {
        let key = TestRekorKey::generate();
        let key_id = b"keyid-negtree";
        let mut material = single_leaf_material(b"body", &key, key_id);
        let keys = keys_map(key_id, &key);
        material.tree_size = -1;
        assert_eq!(
            verify_inclusion(&material, &keys),
            Err(InclusionError::TreeSizeInvalid)
        );
        // The classification is what the change is about, so state it
        // here too rather than only in the table: this condition must not
        // be able to condemn the artifact.
        assert_eq!(
            InclusionError::TreeSizeInvalid.side(),
            InclusionFailureSide::NothingProved,
        );
    }

    /// `from_bundle` on the real committed v0.3 fixture extracts the
    /// material: a non-empty 32-byte-narrowable root hash, a `logID`, and a
    /// checkpoint envelope. (The cryptographic verification against the
    /// production Rekor key is in the crate's `tests/` integration test, so
    /// this only asserts extraction shape.)
    #[test]
    fn from_bundle_extracts_real_fixture_material() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("fixture parses");
        let material = TlogInclusionMaterial::from_bundle(&bundle).expect("extracts material");
        assert!(!material.canonicalized_body.is_empty());
        assert_eq!(material.root_hash.len(), 32);
        assert!(!material.key_id_hex.is_empty());
        assert!(!material.checkpoint_envelope.is_empty());
        // The real proof carries an audit path (a deep tree).
        assert!(!material.hashes.is_empty());
        // The model proof builds (width checks + checkpoint parse all pass).
        build_model_proof(&material).expect("model proof builds from real fixture");
    }

    /// **Real-world positive verification (decoupled from `verify_digest`).**
    /// The committed v0.3 kubewarden cosign bundle's Rekor inclusion proof +
    /// signed checkpoint verifies against the **production** public-good
    /// Sigstore Rekor key, selected from the committed production
    /// `trusted_root.json` by the entry's `logID`. This proves the real
    /// RFC-6962 Merkle fold (an 18-hash audit path over a ~1.1-billion-leaf
    /// tree) plus the production ECDSA P-256 checkpoint signature run
    /// end-to-end, fully offline, on real Rekor data — closing
    /// sigstore-rs#285's gap for the v0.3 format.
    #[test]
    fn real_fixture_inclusion_verifies_against_production_rekor_key() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("fixture parses");
        let material = TlogInclusionMaterial::from_bundle(&bundle).expect("extracts material");

        // Load the production public-good trusted_root.json and snapshot its
        // Rekor keys (keyed by hex logID, time-validity-filtered exactly as
        // production does).
        let trusted_root_json =
            include_bytes!("../tests/fixtures/sigstore_trusted_root_public_good.json");
        let trust_root = SigstoreTrustRoot::from_trusted_root_json_unchecked(trusted_root_json)
            .expect("production trusted root parses");
        let rekor_keys = collect_rekor_keys(&trust_root);
        assert!(
            !rekor_keys.is_empty(),
            "production trust root must carry a Rekor key"
        );
        // The fixture entry's logID must be present in the production keys.
        assert!(
            rekor_keys.contains_key(&material.key_id_hex),
            "fixture logID {} must select a production Rekor key",
            material.key_id_hex
        );

        // The real Merkle inclusion proof + checkpoint signature verify.
        assert_eq!(
            verify_inclusion(&material, &rekor_keys),
            Ok(()),
            "real fixture inclusion proof must verify against the production Rekor key"
        );
    }

    /// Negative companion to the production-key test: tampering the real
    /// fixture's `canonicalized_body` (leaf preimage) makes the real proof
    /// fail closed against the production key — the leaf no longer folds to
    /// the signed checkpoint root.
    #[test]
    fn real_fixture_tampered_body_fails_against_production_key() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("fixture parses");
        let mut material = TlogInclusionMaterial::from_bundle(&bundle).expect("extracts material");

        let trusted_root_json =
            include_bytes!("../tests/fixtures/sigstore_trusted_root_public_good.json");
        let trust_root = SigstoreTrustRoot::from_trusted_root_json_unchecked(trusted_root_json)
            .expect("production trusted root parses");
        let rekor_keys = collect_rekor_keys(&trust_root);

        // Flip one byte of the canonicalized body → different leaf hash →
        // does not fold to the signed root.
        material.canonicalized_body[0] ^= 0xFF;
        assert_eq!(
            verify_inclusion(&material, &rekor_keys),
            Err(InclusionError::VerifyFailed)
        );
    }

    /// **Every variant, and whose side it is on.** One row per
    /// `InclusionError`, each row the answer [`InclusionError::side`]
    /// gives; the evidence for each is the variant's own doc comment, and
    /// the tests above pin which *condition* produces which variant, so
    /// the two together carry a failure all the way from its cause to its
    /// verdict class.
    ///
    /// What forces an eleventh variant to be classified at all is
    /// `side()`'s wildcard-free match, not this table — an eleventh
    /// variant does not compile until it has an arm there. What the table
    /// adds is that the ten answers are the intended ones, and the
    /// counter-assertions below keep it from passing vacuously: a `side()`
    /// that answered `NothingProved` for everything would satisfy seven
    /// rows, and a table that quietly listed one variant twice would still
    /// satisfy every row it listed.
    #[test]
    fn every_inclusion_error_variant_states_whose_side_it_is_on() {
        use InclusionFailureSide::{Disproof, NothingProved, TrustRoot};
        let table = [
            // "The cryptographic inclusion / checkpoint verification
            // failed" — the proof was there, we read it, and it did not
            // verify. The one disproof in the enum.
            (InclusionError::VerifyFailed, Disproof),
            // "No Rekor key in the trust root matches the entry's logID"
            // and "the trust-root Rekor key bytes did not parse" — both
            // name our own trust root, not the pushed material.
            (InclusionError::NoMatchingRekorKey, TrustRoot),
            (InclusionError::KeyParse, TrustRoot),
            // The bundle's own log material, absent, unparseable or
            // structurally impossible: no tlog entry, no inclusion proof
            // (the v0.1 SET-only shape), no checkpoint, an unparseable
            // checkpoint, a hash of the wrong width, a negative tree size,
            // no log id. Nothing was checked, so nothing was proved.
            (InclusionError::NoTlogEntry, NothingProved),
            (InclusionError::NoInclusionProof, NothingProved),
            (InclusionError::NoCheckpoint, NothingProved),
            (InclusionError::CheckpointParse, NothingProved),
            (InclusionError::HashWidth, NothingProved),
            (InclusionError::TreeSizeInvalid, NothingProved),
            (InclusionError::NoLogId, NothingProved),
        ];
        for (err, expected) in &table {
            assert_eq!(err.side(), *expected, "{err:?}");
        }

        // Counter-assertions. Ten rows, ten *distinct* variants (so no
        // variant is standing in for another), and all three answers
        // actually used (so the classification is a split and not a
        // constant).
        assert_eq!(table.len(), 10, "the enum has ten variants");
        let mut variants: Vec<String> = table.iter().map(|(e, _)| format!("{e:?}")).collect();
        variants.sort();
        variants.dedup();
        assert_eq!(variants.len(), 10, "each variant appears exactly once");
        for answer in [Disproof, TrustRoot, NothingProved] {
            assert!(
                table.iter().any(|(_, s)| *s == answer),
                "no variant answers {answer:?} — the split collapsed"
            );
        }
    }
}
