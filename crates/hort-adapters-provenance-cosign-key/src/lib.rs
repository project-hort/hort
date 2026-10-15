//! Keyed (pinned-public-key) cosign provenance verifier — `ProvenancePort`
//! impl for the `"cosign-key"` backend (ADR 0039).
//!
//! Verifies a keyed cosign signature against an operator-pinned public key with
//! **no** Fulcio chain, Rekor proof, SCT, or trust root — strictly more offline
//! than the Sigstore verifier (no network at all). It consumes **both** keyed
//! carriages the orchestrator's §8 carriage builds:
//!
//! - **legacy `simplesigning`** (`cosign sign --key`, `--registry-referrers-mode=legacy`):
//!   `bytes` = the `simplesigning` payload-layer blob, `signature` = the decoded
//!   `dev.cosignproject.cosign/signature` annotation. The signature is over the
//!   raw payload; the bound digest is `critical.image.docker-manifest-digest`.
//! - **cosign v3 keyed Sigstore v0.3 bundle** (`cosign sign --key
//!   --registry-referrers-mode=oci-1-1`): `bytes` = the v0.3 bundle blob,
//!   `signature = Some(raw DSSE sig)`. The bundle carries a **DSSE envelope**
//!   over an in-toto Statement — the signature is over the DSSE PAE (not the raw
//!   payload) and the bound digest is the in-toto `subject[].digest.sha256`.
//!   The keyed shape is a v0.3 bundle whose `verificationMaterial` is a bare
//!   `publicKey` (no Fulcio cert); a keyless (cert-chain) v0.3 bundle stays the
//!   Sigstore verifier's.
//!
//! A keyless bundle (`signature == None`) is the Sigstore verifier's and is
//! ignored here.
//!
//! **Two load-bearing checks, both required (ADR 0039 §2), for either carriage:**
//! 1. ECDSA-verify the signature **over the signed bytes** (the raw payload for
//!    simplesigning; the DSSE PAE for the v0.3 bundle) against a pinned public
//!    key (P-256, the cosign default; SHA-256 prehash is intrinsic).
//! 2. **Bind** the signed subject digest to the served artifact's actual
//!    manifest digest — the referrer tag is attacker-writable, so a validly-
//!    signed payload for image A re-tagged onto image B must be `Rejected`,
//!    never `Verified`.
//!
//! **Unreadable material is not considered.** A keyed candidate whose
//! payload JSON, DSSE material or DER signature cannot be parsed is skipped
//! and counted — not rejected, not held, not evidence of any kind — exactly
//! as a keyless bundle is skipped for not being ours. Only the two checks
//! above, run against material the verifier could actually read, may condemn
//! an artifact: anyone who can write a referrer must not be able to reject
//! somebody else's correctly-signed image by attaching bytes nobody can
//! parse. A set with nothing readable in it is `NoAttestation` — this
//! verifier has nothing to say — which under `Required` is the indefinite
//! hold already defined. The skip count rides the verdict
//! (`ProvenanceVerdict::unreadable_skipped`) so *not considered* does not
//! become *not noticed*.
//!
//! **No "could not check" answer exists here.** The trust material is the
//! pinned key set, parsed once at construction: a key that does not parse
//! is a boot refusal ([`CosignKeyVerifier::from_pem_keys`] returns `Err`)
//! and an empty set fails `health_check` before any artifact is verified.
//! So no per-artifact state remains in which our own provisioning could
//! leave a check un-run — the keyless verifier has one, in its
//! per-entry trust-root Rekor key lookup, and holds the artifact on it;
//! nothing in this backend corresponds to that.
//!
//! Minimal crypto surface: `p256` (already in the locked graph), **not** the
//! `sigstore` PKI crate (ADR 0039 Consequences). The keyed v0.3 bundle's
//! signature-material extraction (DSSE PAE, in-toto subject, keyed/keyless
//! discriminator) is the pure `hort_domain::provenance_bundle` helper, which
//! also owns the `simplesigning` payload parse this verifier binds on.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::provenance::{
    AttestationBundle, ProvenancePort, ProvenanceRejectReason, ProvenanceRequirements,
    ProvenanceSubject, ProvenanceVerdict, SignerIdentity,
};
use hort_domain::ports::BoxFuture;

/// The stable backend name in `ScanPolicy.provenance_backends`, re-exported
/// from the domain (single source — the same const drives the apply-linter's
/// per-backend identity rules, ADR 0039 §4).
pub use hort_domain::entities::scan_policy::COSIGN_KEY_BACKEND;

/// Keyed cosign verifier holding the operator-pinned public key set (ADR 0039
/// §3) — boot-provisioned, parsed once, no live fetch.
pub struct CosignKeyVerifier {
    keys: Vec<VerifyingKey>,
}

/// Per-bundle keyed verification outcome (internal).
enum KeyedOutcome {
    /// Signature valid for a pinned key AND the payload digest binds.
    Verified,
    /// Digest binds but no pinned key verified the signature. A finding
    /// about readable material — terminal.
    WrongKey,
    /// The signed payload names a different manifest digest — the re-tag
    /// attack (caught regardless of signature validity). A finding about
    /// readable material — terminal, and the strongest one this verifier
    /// can state, which is why it reports under its own reason
    /// ([`ProvenanceRejectReason::DigestMismatch`]) rather than under a
    /// structural one an operator cannot act on.
    DigestMismatch,
    /// The payload JSON or the DER signature is structurally unparseable:
    /// the verifier **could not read** this candidate.
    ///
    /// Not a verdict of any kind. Unreadable material proves nothing about
    /// the artifact, so it is skipped and counted exactly as a keyless
    /// bundle (not ours) is skipped — a caller with write access to the
    /// referrer surface must not be able to reject somebody else's
    /// correctly-signed image by attaching bytes nobody can parse.
    Unreadable,
}

impl CosignKeyVerifier {
    /// Parse pinned public keys from PEM (cosign `cosign.pub`, ECDSA P-256
    /// SPKI). A PEM that does not parse → `Err` (boot-reject — fail fast on a
    /// misconfigured key rather than silently verifying nothing). An empty set
    /// constructs (the apply-linter is the gate that a `Required` `cosign-key`
    /// scope HAS a key, ADR 0039 §4) but [`health_check`](Self::health_check)
    /// fails on it.
    pub fn from_pem_keys(pems: &[String]) -> DomainResult<Self> {
        let mut keys = Vec::with_capacity(pems.len());
        for pem in pems {
            let vk = VerifyingKey::from_public_key_pem(pem.trim()).map_err(|e| {
                DomainError::Validation(format!(
                    "cosign-key: pinned public key is not a valid P-256 ECDSA SPKI PEM: {e}"
                ))
            })?;
            keys.push(vk);
        }
        Ok(Self { keys })
    }

    /// The number of pinned keys loaded (rotation-overlap visibility).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify one keyed bundle, recognising **either** carriage from `bytes`:
    ///
    /// - a **cosign v3 keyed Sigstore v0.3 bundle** (`bytes` parses as one whose
    ///   `verificationMaterial` is a bare `publicKey`) — verify the DSSE
    ///   signature over the PAE and bind the in-toto subject digest; or
    /// - a **legacy `simplesigning` payload** (anything the v0.3 extractor does
    ///   not claim) — verify the detached signature over the raw payload and
    ///   bind `critical.image.docker-manifest-digest`.
    ///
    /// In both cases: digest-bind FIRST (catch the re-tag attack even for a
    /// signature validly made for another image), then ECDSA-verify against any
    /// pinned key. The extractor's `Err` (a keyed v0.3 bundle whose DSSE
    /// material is structurally undecodable) is `Unreadable` — it must not fall
    /// through to the simplesigning path, and it must not become a verdict
    /// either.
    fn verify_one(
        &self,
        subject: &ProvenanceSubject<'_>,
        bytes: &[u8],
        sig: &[u8],
    ) -> KeyedOutcome {
        match hort_domain::provenance_bundle::extract_keyed_dsse_signature(bytes) {
            // A keyed v0.3 DSSE bundle: bind the in-toto subject, verify the
            // DSSE signature over the PAE signing input.
            Ok(Some(material)) => self.verify_signed(
                subject,
                &material.subject_digest,
                &material.signing_input,
                sig,
            ),
            // Not a keyed v0.3 bundle (keyless cert-chain, or not a bundle at
            // all) → the legacy simplesigning payload interpretation. A
            // payload that is not simplesigning JSON either is material we
            // cannot read at all: skipped, not judged.
            Ok(None) => match hort_domain::provenance_bundle::simplesigning_subject_digest(bytes) {
                Some(claimed) => self.verify_signed(subject, &claimed, bytes, sig),
                None => KeyedOutcome::Unreadable,
            },
            // The bundle claims to be a keyed v0.3 DSSE bundle but its material
            // (base64 / in-toto payload) is undecodable → unreadable, never a
            // silent fall-through to the other carriage.
            Err(_) => KeyedOutcome::Unreadable,
        }
    }

    /// Bind `claimed_digest` to the served artifact, then ECDSA-verify `sig`
    /// (DER) over `signing_input` against any pinned key. Shared by both
    /// carriages — the ONE place the re-tag bind and the crypto check live.
    fn verify_signed(
        &self,
        subject: &ProvenanceSubject<'_>,
        claimed_digest: &str,
        signing_input: &[u8],
        sig: &[u8],
    ) -> KeyedOutcome {
        // Bind: the signed digest must name THIS artifact's manifest digest.
        let expected = format!("sha256:{}", subject.content_hash);
        if claimed_digest != expected {
            return KeyedOutcome::DigestMismatch;
        }
        // ECDSA-verify against any pinned key (P-256 `Verifier` prehashes with
        // SHA-256). A signature blob that is not DER is material we cannot
        // read — skipped, not a finding. (The digest bound above, so the
        // candidate did name THIS artifact; it still proves nothing, because
        // an unparseable signature is not a failed signature check. Anyone
        // who can write the referrer surface can produce this shape.)
        let Ok(signature) = Signature::from_der(sig) else {
            return KeyedOutcome::Unreadable;
        };
        if self
            .keys
            .iter()
            .any(|k| k.verify(signing_input, &signature).is_ok())
        {
            KeyedOutcome::Verified
        } else {
            KeyedOutcome::WrongKey
        }
    }
}

impl ProvenancePort for CosignKeyVerifier {
    fn name(&self) -> &str {
        COSIGN_KEY_BACKEND
    }

    fn applies_to(&self, format: &str) -> bool {
        format == "oci"
    }

    fn verify<'a>(
        &'a self,
        artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [AttestationBundle],
        _policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        Box::pin(async move {
            // Only KEYED bundles are ours; a keyless v0.3 bundle
            // (`signature == None`) is the Sigstore verifier's — contributes
            // nothing here. Across keyed bundles: any one Verified wins; else
            // a digest mismatch (the alarming re-tag case) outranks a wrong-key
            // reason in the audit trail.
            //
            // The two findings below are findings about material this
            // verifier READ — a payload whose signed digest named another
            // image, a signature that checked out against no pinned key —
            // and only such a finding may condemn the artifact. A candidate
            // we could not read is counted and dropped: it sets no flag, so
            // it can neither become the verdict nor shadow a sibling's real
            // finding.
            let mut saw_digest_mismatch = false;
            let mut saw_wrong_key = false;
            let mut unreadable: u32 = 0;
            for bundle in bundles {
                // Not counted as unreadable: a keyless bundle was not read
                // because it is not ours, which is a different statement
                // from "we could not read it".
                let Some(sig) = bundle.signature.as_deref() else {
                    continue;
                };
                match self.verify_one(artifact, &bundle.bytes, sig) {
                    KeyedOutcome::Verified => {
                        return Ok(ProvenanceVerdict::verified(keyed_signer(), None)
                            .with_unreadable_skipped(unreadable));
                    }
                    KeyedOutcome::DigestMismatch => saw_digest_mismatch = true,
                    KeyedOutcome::WrongKey => saw_wrong_key = true,
                    KeyedOutcome::Unreadable => unreadable = unreadable.saturating_add(1),
                }
            }

            // A digest-binding failure is the priority reason (ADR 0039 §2
            // requires the re-tag case to reject) and it now says so in its
            // own word rather than borrowing the structural complaint. No
            // verdict changes — it was terminal and stays terminal — but
            // the `ProvenanceRejected` record can finally tell "someone
            // re-tagged a signed image" from "the upload is corrupt", and
            // those two call for opposite operator responses. A
            // wrong-key-only set is `UntrustedIdentity`. With neither flag
            // set there is no finding at all — the set was empty, or all
            // keyless, or everything keyed in it was unreadable — and the
            // answer is NoAttestation: this verifier has nothing to say.
            // There is no `saw_keyed` bookkeeping any more, because "a keyed
            // candidate was present" stopped being a reason to produce a
            // verdict the moment an unreadable candidate stopped being
            // evidence.
            let reason = if saw_digest_mismatch {
                ProvenanceRejectReason::DigestMismatch
            } else if saw_wrong_key {
                ProvenanceRejectReason::UntrustedIdentity
            } else {
                return Ok(ProvenanceVerdict::no_attestation().with_unreadable_skipped(unreadable));
            };
            tracing::debug!(
                backend = COSIGN_KEY_BACKEND,
                ?reason,
                unreadable,
                "keyed provenance: a keyed candidate was read and did not verify",
            );
            Ok(ProvenanceVerdict::rejected(reason).with_unreadable_skipped(unreadable))
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            if self.keys.is_empty() {
                return Err(DomainError::Validation(
                    "cosign-key: no pinned public keys configured \
                     (HORT_PROVENANCE_COSIGN_PUBLIC_KEYS)"
                        .to_string(),
                ));
            }
            Ok(())
        })
    }
}

/// The keyed model has no certificate/identity — the pinned key IS the anchor
/// (ADR 0039 §3). A stable keyed marker rides the `ProvenanceVerified` audit
/// event in place of a Fulcio `{issuer, san}`.
fn keyed_signer() -> SignerIdentity {
    SignerIdentity {
        issuer: COSIGN_KEY_BACKEND.to_string(),
        san: "pinned-public-key".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::types::ContentHash;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::Generate;
    use p256::pkcs8::{EncodePublicKey, LineEnding};

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn hash(hex: &str) -> ContentHash {
        hex.parse().unwrap()
    }

    /// A simplesigning payload naming `digest_hex` as the manifest digest.
    fn payload_for(digest_hex: &str) -> Vec<u8> {
        serde_json::json!({
            "critical": {
                "identity": { "docker-reference": "registry.example.com/app" },
                "image": { "docker-manifest-digest": format!("sha256:{digest_hex}") },
                "type": "cosign container image signature"
            },
            "optional": null
        })
        .to_string()
        .into_bytes()
    }

    /// Sign `payload` with `key`, returning the DER ECDSA signature bytes.
    fn der_sign(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        let sig: Signature = key.sign(payload);
        sig.to_der().as_bytes().to_vec()
    }

    fn pub_pem(key: &SigningKey) -> String {
        key.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn subject<'a>(h: &'a ContentHash) -> ProvenanceSubject<'a> {
        ProvenanceSubject {
            content_hash: h,
            payload: b"",
            name: "app",
            version: Some("1.0.0"),
        }
    }

    fn empty_reqs() -> ProvenanceRequirements<'static> {
        ProvenanceRequirements {
            allowed_identities: &[],
        }
    }

    #[test]
    fn name_and_applies_to() {
        let v = CosignKeyVerifier::from_pem_keys(&[]).unwrap();
        assert_eq!(v.name(), "cosign-key");
        assert!(v.applies_to("oci"));
        assert!(!v.applies_to("npm"));
        assert_eq!(v.key_count(), 0);
    }

    #[test]
    fn valid_keyed_signature_with_matching_digest_verifies() {
        let key = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let sig = der_sign(&key, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [AttestationBundle::new_signed(payload, sig)];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(verdict, ProvenanceVerdict::verified(keyed_signer(), None));
    }

    #[test]
    fn wrong_key_rejects_untrusted_identity() {
        let signer = SigningKey::generate();
        let other = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let sig = der_sign(&signer, &payload);
        // Pin a DIFFERENT key than the one that signed.
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&other)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [AttestationBundle::new_signed(payload, sig)];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity)
        );
    }

    /// **Changed reason, unchanged verdict.** This asserted
    /// `Rejected{BundleMalformed}`: the re-tag attack reported under the
    /// structural complaint, indistinguishable in the audit record from a
    /// corrupt upload. It is terminal either way — what the reason buys
    /// is that an operator reading `ProvenanceRejected` can tell "someone
    /// re-tagged a signed image" (investigate the publisher's registry)
    /// from "the upload is corrupt" (re-push), which are opposite
    /// responses.
    #[test]
    fn a_retagged_valid_signature_rejects_digest_mismatch() {
        // The payload is validly signed for image A, but presented for image B.
        let key = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let sig = der_sign(&key, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_B); // served artifact B != payload's A
        let bundles = [AttestationBundle::new_signed(payload, sig)];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::DigestMismatch),
            "a valid signature re-tagged onto a different image must be Rejected, \
             and under the reason that names the attack"
        );
    }

    /// The re-tag finding is the priority reason over a wrong-key sibling,
    /// in either listing order. Both are terminal, so no verdict turns on
    /// this — the audit record does: a set containing a re-tagged valid
    /// signature must report the re-tag, not the weaker complaint about
    /// the other candidate. The referrer surface decides the order and an
    /// attacker can write to it, so both orders are asserted.
    #[test]
    fn the_retag_finding_outranks_a_wrong_key_finding() {
        let signer = SigningKey::generate();
        let other = SigningKey::generate();
        // Validly signed for A, served as B — a digest mismatch.
        let retagged = AttestationBundle::new_signed(
            payload_for(HASH_A),
            der_sign(&signer, &payload_for(HASH_A)),
        );
        // Binds B correctly, but signed by a key that is not pinned.
        let wrong_key = AttestationBundle::new_signed(
            payload_for(HASH_B),
            der_sign(&other, &payload_for(HASH_B)),
        );
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&signer)]).unwrap();
        let h = hash(HASH_B);
        let expected = ProvenanceVerdict::rejected(ProvenanceRejectReason::DigestMismatch);

        let first = [retagged.clone(), wrong_key.clone()];
        assert_eq!(
            run(v.verify(&subject(&h), &first, &empty_reqs())).unwrap(),
            expected
        );
        let second = [wrong_key, retagged];
        assert_eq!(
            run(v.verify(&subject(&h), &second, &empty_reqs())).unwrap(),
            expected
        );
    }

    /// **Changed meaning.** This asserted
    /// `Rejected{BundleMalformed}` for a payload the verifier cannot
    /// parse. An unparseable payload is not a failed check — nothing was
    /// established about the artifact — so it now contributes nothing and
    /// the lone-candidate set answers `NoAttestation`, with the skip
    /// recorded. The old assertion let anyone who can write a referrer
    /// reject an image by attaching bytes nobody can read.
    #[test]
    fn malformed_payload_is_skipped_not_rejected() {
        let key = SigningKey::generate();
        let payload = b"not a simplesigning json".to_vec();
        let sig = der_sign(&key, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [AttestationBundle::new_signed(payload, sig)];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::no_attestation().with_unreadable_skipped(1),
            "material the verifier cannot read must not condemn the artifact",
        );
    }

    /// **Changed meaning.** Same reversal for a signature blob that is not
    /// DER: the payload digest *binds*, so the candidate did name this
    /// artifact, but an unparseable signature is not a signature that
    /// failed to verify — it is material we could not read. Skipped and
    /// counted.
    #[test]
    fn malformed_signature_is_skipped_not_rejected() {
        let key = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        // A non-DER signature blob (digest binds, but the sig is garbage).
        let bundles = [AttestationBundle::new_signed(payload, vec![0xde, 0xad])];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::no_attestation().with_unreadable_skipped(1),
        );
    }

    /// An unreadable sibling does not shadow a finding about readable
    /// material: the wrong-key rejection stands, and the skip is recorded
    /// alongside it. Both directions of the loop order, so the answer does
    /// not depend on which candidate the referrer surface lists first.
    #[test]
    fn an_unreadable_sibling_does_not_mask_a_wrong_key_finding() {
        let signer = SigningKey::generate();
        let other = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let sig = der_sign(&signer, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&other)]).unwrap();
        let h = hash(HASH_A);

        let unreadable =
            || AttestationBundle::new_signed(b"not a simplesigning json".to_vec(), vec![0x30]);
        let expected = ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity)
            .with_unreadable_skipped(1);

        let first = [
            unreadable(),
            AttestationBundle::new_signed(payload.clone(), sig.clone()),
        ];
        assert_eq!(
            run(v.verify(&subject(&h), &first, &empty_reqs())).unwrap(),
            expected
        );

        let second = [AttestationBundle::new_signed(payload, sig), unreadable()];
        assert_eq!(
            run(v.verify(&subject(&h), &second, &empty_reqs())).unwrap(),
            expected
        );
    }

    /// An unreadable sibling does not shadow the strongest finding either:
    /// a re-tagged valid signature still rejects, with the skip recorded.
    /// This is the direction that must not regress — making a digest
    /// mismatch non-terminal, or folding it back into a reason that reads
    /// as "corrupt upload", would be the opposite of this work.
    #[test]
    fn an_unreadable_sibling_does_not_mask_the_retag_finding() {
        let key = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let sig = der_sign(&key, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_B); // served artifact B != the payload's A
        let bundles = [
            AttestationBundle::new_signed(b"unreadable".to_vec(), vec![0x30]),
            AttestationBundle::new_signed(payload, sig),
        ];
        assert_eq!(
            run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap(),
            ProvenanceVerdict::rejected(ProvenanceRejectReason::DigestMismatch)
                .with_unreadable_skipped(1),
        );
    }

    /// A set in which **every** keyed candidate is unreadable is
    /// `NoAttestation` with the full count — not a rejection built out of
    /// the fact that keyed-shaped bytes were present. "A keyed candidate
    /// was there" stopped being a reason to produce a verdict the moment
    /// an unreadable candidate stopped being evidence, which is why the
    /// `saw_keyed` flag is gone.
    #[test]
    fn an_all_unreadable_keyed_set_is_no_attestation_with_the_full_count() {
        let key = SigningKey::generate();
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [
            AttestationBundle::new_signed(b"garbage one".to_vec(), vec![0x30]),
            AttestationBundle::new_signed(b"garbage two".to_vec(), vec![0x30]),
            // Digest binds, signature is not DER → unreadable too.
            AttestationBundle::new_signed(payload_for(HASH_A), vec![0xde, 0xad]),
        ];
        assert_eq!(
            run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap(),
            ProvenanceVerdict::no_attestation().with_unreadable_skipped(3),
        );
    }

    /// A keyless bundle beside an unreadable keyed one: the keyless one is
    /// skipped for not being ours and is **not** counted, so the count
    /// names only what this verifier could not read. Conflating the two
    /// would make every keyless-signed artifact look like it carried
    /// garbage.
    #[test]
    fn a_keyless_bundle_is_not_counted_as_unreadable() {
        let key = SigningKey::generate();
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [
            AttestationBundle::new(b"a keyless bundle, not ours".to_vec()),
            AttestationBundle::new_signed(b"unreadable keyed".to_vec(), vec![0x30]),
        ];
        assert_eq!(
            run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap(),
            ProvenanceVerdict::no_attestation().with_unreadable_skipped(1),
        );
    }

    #[test]
    fn keyless_bundle_yields_no_attestation() {
        let key = SigningKey::generate();
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        // A keyless v0.3 bundle (signature None) is not ours.
        let bundles = [AttestationBundle::new(b"{}".to_vec())];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(verdict, ProvenanceVerdict::no_attestation());
    }

    #[test]
    fn no_bundles_yields_no_attestation() {
        let key = SigningKey::generate();
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let verdict = run(v.verify(&subject(&h), &[], &empty_reqs())).unwrap();
        assert_eq!(verdict, ProvenanceVerdict::no_attestation());
    }

    #[test]
    fn first_valid_keyed_bundle_wins_over_a_bad_one() {
        let key = SigningKey::generate();
        let good = payload_for(HASH_A);
        let good_sig = der_sign(&key, &good);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [
            AttestationBundle::new_signed(payload_for(HASH_B), vec![1, 2, 3]), // bad
            AttestationBundle::new_signed(good, good_sig),                     // good
        ];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(verdict, ProvenanceVerdict::verified(keyed_signer(), None));
    }

    /// The headline shape, from this verifier's side: a valid keyed
    /// signature beside an unreadable keyed candidate still verifies, and
    /// the skip rides the `Verified` verdict rather than being dropped on
    /// the floor. The unreadable candidate is listed FIRST so the
    /// short-circuit cannot be what hides it.
    #[test]
    fn a_valid_signature_verifies_beside_an_unreadable_sibling() {
        let key = SigningKey::generate();
        let good = payload_for(HASH_A);
        let good_sig = der_sign(&key, &good);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [
            AttestationBundle::new_signed(b"unreadable".to_vec(), vec![0x30]),
            AttestationBundle::new_signed(good, good_sig),
        ];
        assert_eq!(
            run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap(),
            ProvenanceVerdict::verified(keyed_signer(), None).with_unreadable_skipped(1),
        );
    }

    #[test]
    fn malformed_pem_key_fails_construction() {
        let result = CosignKeyVerifier::from_pem_keys(&[
            "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----".to_string(),
        ]);
        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    #[test]
    fn health_check_fails_on_empty_keys_passes_with_keys() {
        let empty = CosignKeyVerifier::from_pem_keys(&[]).unwrap();
        assert!(run(empty.health_check()).is_err());

        let key = SigningKey::generate();
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        assert!(run(v.health_check()).is_ok());
    }
}
