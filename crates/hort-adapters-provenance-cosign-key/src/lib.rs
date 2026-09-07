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
//! Minimal crypto surface: `p256` (already in the locked graph), **not** the
//! `sigstore` PKI crate (ADR 0039 Consequences). The keyed v0.3 bundle's
//! signature-material extraction (DSSE PAE, in-toto subject, keyed/keyless
//! discriminator) is the pure `hort_domain::provenance_bundle` helper.

use serde::Deserialize;

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
    /// Digest binds but no pinned key verified the signature.
    WrongKey,
    /// The signed payload names a different manifest digest — the re-tag
    /// attack (caught regardless of signature validity).
    DigestMismatch,
    /// The payload JSON or the DER signature is structurally unparseable.
    Malformed,
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
    /// material is structurally undecodable) is `Malformed` — it must not fall
    /// through to the simplesigning path.
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
            // all) → the legacy simplesigning payload interpretation.
            Ok(None) => match parse_simplesigning_digest(bytes) {
                Some(claimed) => self.verify_signed(subject, &claimed, bytes, sig),
                None => KeyedOutcome::Malformed,
            },
            // The bundle claims to be a keyed v0.3 DSSE bundle but its material
            // (base64 / in-toto payload) is undecodable → Malformed, never a
            // silent fall-through.
            Err(_) => KeyedOutcome::Malformed,
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
        // SHA-256).
        let Ok(signature) = Signature::from_der(sig) else {
            return KeyedOutcome::Malformed;
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
            let mut saw_keyed = false;
            let mut saw_digest_mismatch = false;
            let mut saw_wrong_key = false;
            for bundle in bundles {
                let Some(sig) = bundle.signature.as_deref() else {
                    continue;
                };
                saw_keyed = true;
                match self.verify_one(artifact, &bundle.bytes, sig) {
                    KeyedOutcome::Verified => {
                        return Ok(ProvenanceVerdict::verified(keyed_signer(), None));
                    }
                    KeyedOutcome::DigestMismatch => saw_digest_mismatch = true,
                    KeyedOutcome::WrongKey => saw_wrong_key = true,
                    KeyedOutcome::Malformed => {}
                }
            }

            if !saw_keyed {
                return Ok(ProvenanceVerdict::no_attestation());
            }

            // The re-tag attack + a structurally-broken payload/sig both map to
            // `BundleMalformed`; a digest-binding failure is the priority reason
            // (ADR 0039 §2 reject-reason mapping — no dedicated DigestMismatch
            // variant). A wrong-key-only set is `UntrustedIdentity`.
            let reason = if saw_digest_mismatch || !saw_wrong_key {
                ProvenanceRejectReason::BundleMalformed
            } else {
                ProvenanceRejectReason::UntrustedIdentity
            };
            tracing::debug!(
                backend = COSIGN_KEY_BACKEND,
                ?reason,
                "keyed provenance: no pinned key verified a keyed signature",
            );
            Ok(ProvenanceVerdict::rejected(reason))
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

#[derive(Deserialize)]
struct Simplesigning {
    critical: Critical,
}
#[derive(Deserialize)]
struct Critical {
    image: SimplesigningImage,
}
#[derive(Deserialize)]
struct SimplesigningImage {
    #[serde(rename = "docker-manifest-digest")]
    docker_manifest_digest: String,
}

/// Parse a cosign `simplesigning` payload → its
/// `critical.image.docker-manifest-digest` (`"sha256:<hex>"`). `None` on
/// malformed JSON or a missing field.
fn parse_simplesigning_digest(payload: &[u8]) -> Option<String> {
    let parsed: Simplesigning = serde_json::from_slice(payload).ok()?;
    Some(parsed.critical.image.docker_manifest_digest)
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

    #[test]
    fn digest_mismatch_rejects_bundle_malformed_retag_attack() {
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
            ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed),
            "a valid signature re-tagged onto a different image must be Rejected"
        );
    }

    #[test]
    fn malformed_payload_rejects_bundle_malformed() {
        let key = SigningKey::generate();
        let payload = b"not a simplesigning json".to_vec();
        let sig = der_sign(&key, &payload);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        let bundles = [AttestationBundle::new_signed(payload, sig)];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed)
        );
    }

    #[test]
    fn malformed_signature_rejects() {
        let key = SigningKey::generate();
        let payload = payload_for(HASH_A);
        let v = CosignKeyVerifier::from_pem_keys(&[pub_pem(&key)]).unwrap();
        let h = hash(HASH_A);
        // A non-DER signature blob (digest binds, but the sig is garbage).
        let bundles = [AttestationBundle::new_signed(payload, vec![0xde, 0xad])];
        let verdict = run(v.verify(&subject(&h), &bundles, &empty_reqs())).unwrap();
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed)
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
