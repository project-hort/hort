//! Sigstore/cosign [`ProvenancePort`] adapter — **offline bundle
//! verification** (ADR 0027).
//!
//! `SigstoreProvenanceAdapter` implements
//! [`ProvenancePort`](hort_domain::ports::provenance::ProvenancePort) by
//! verifying each stored Sigstore bundle **offline** against a cached,
//! injectable trust root — there is **no live Rekor/Fulcio lookup on the
//! verify path**. Each bundle already carries its Fulcio certificate chain
//! (with embedded SCT) and the Rekor inclusion proof / SignedEntryTimestamp
//! (SET); the adapter validates that material against the cached Sigstore
//! trust root (Fulcio CA certs + Rekor/CT-log public keys) refreshed
//! periodically via TUF — *not* per verify (see [`trust_root`]).
//!
//! ## Verdict flow ([`SigstoreProvenanceAdapter::verify`])
//! - empty `bundles` → [`NoAttestation`] (the unsigned case — **not** an
//!   error);
//! - a bundle that does not parse / carries no leaf cert / no offline
//!   material → [`Rejected(BundleMalformed)`];
//! - cert chain that does not validate to the trust root → [`Rejected(CertChainInvalid)`];
//! - a missing / invalid Rekor SET (offline) → [`Rejected(RekorNotFound)`]
//!   — **never** a fall-back to a live Rekor fetch;
//! - a cryptographically-valid signature whose observed `{issuer, san}`
//!   matches no allowed [`SignerIdentityPattern`] → [`Rejected(UntrustedIdentity)`];
//! - valid + trusted + identity-match → [`Verified { signer, predicate_type }`].
//!
//! The identity match is the domain's **exact-or-bounded-glob**
//! [`SignerIdentityPattern::matches`] (not `sigstore`'s exact-literal
//! `Identity` policy) — so an operator's bounded glob is honoured. The
//! adapter therefore drives `sigstore`'s cryptographic verification with a
//! pass-through [`policy::AllowAllPolicy`] and applies the glob match to
//! the **observed** identity it extracts from the verified leaf cert (see
//! [`identity`]).
//!
//! ## Digest binding
//! `sigstore`'s only public offline-verify entry,
//! `Verifier::verify_digest(input: Sha256, …)`, takes a **`Sha256` hasher
//! it finalizes** — it needs the artifact *preimage* bytes, not a
//! precomputed digest. `verify_digest` uses the finalized hash as both the
//! subject digest compared against the bundle and the prehash the
//! signature is verified over, so feeding the hasher anything other than
//! the preimage whose SHA-256 is `content_hash` can never reach
//! `Verified`. The [`ProvenanceSubject`] therefore carries the preimage
//! [`payload`](hort_domain::ports::provenance::ProvenanceSubject::payload)
//! (for OCI cosign, the manifest bytes the orchestrator streams from the
//! `StoragePort`); the adapter feeds **that** to the hasher and defensively
//! asserts the subject invariant `sha256(payload) == content_hash` before
//! verifying. The cert-chain / SCT / SET / signature crypto runs **for
//! real** against the injected trust root (it is *not* a stub). The
//! **offline** and **injectable-trust-root** guarantees are fully met here.
//!
//! [`NoAttestation`]: hort_domain::ports::provenance::ProvenanceOutcome::NoAttestation
//! [`Rejected(BundleMalformed)`]: hort_domain::ports::provenance::ProvenanceRejectReason::BundleMalformed
//! [`Rejected(CertChainInvalid)`]: hort_domain::ports::provenance::ProvenanceRejectReason::CertChainInvalid
//! [`Rejected(RekorNotFound)`]: hort_domain::ports::provenance::ProvenanceRejectReason::RekorNotFound
//! [`Rejected(UntrustedIdentity)`]: hort_domain::ports::provenance::ProvenanceRejectReason::UntrustedIdentity
//! [`Verified { signer, predicate_type }`]: hort_domain::ports::provenance::ProvenanceOutcome::Verified
//! [`SignerIdentityPattern`]: hort_domain::entities::scan_policy::SignerIdentityPattern
//! [`SignerIdentityPattern::matches`]: hort_domain::entities::scan_policy::SignerIdentityPattern::matches
//! [`ProvenanceSubject`]: hort_domain::ports::provenance::ProvenanceSubject

mod extra_ca;
mod identity;
pub mod trust_root;
mod verifier;

pub use trust_root::{refresh_trusted_root_json, CachedTrustRoot, DEFAULT_REFRESH_WINDOW_HOURS};

use sha2::{Digest, Sha256};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::provenance::{
    ProvenancePort, ProvenanceRequirements, ProvenanceSubject, ProvenanceVerdict,
};
use hort_domain::ports::BoxFuture;

/// The format this verifier applies to (`cosign` → OCI).
const COSIGN_FORMAT: &str = "oci";

/// Stable backend id used in `ScanPolicy.provenance_backends`.
const BACKEND_NAME: &str = "cosign";

/// Sigstore/cosign offline-bundle provenance verifier.
///
/// Holds the cached, injectable [`CachedTrustRoot`]; constructed once at
/// composition time. The verify path is fully offline — the only live HTTP
/// in the whole adapter is the periodic trust-root refresh
/// (`trust_root::refresh_trusted_root_json`), wired by the composition
/// root, never by `verify`.
pub struct SigstoreProvenanceAdapter {
    trust_root: CachedTrustRoot,
}

impl SigstoreProvenanceAdapter {
    /// Construct the adapter over an already-loaded, injectable trust
    /// root. Tests inject a fixture root; production injects one built
    /// from a TUF-refreshed `trusted_root.json`
    /// ([`CachedTrustRoot::from_trusted_root_json`]).
    pub fn new(trust_root: CachedTrustRoot) -> Self {
        Self { trust_root }
    }

    /// Borrow the cached trust root (composition root / health probes).
    pub fn trust_root(&self) -> &CachedTrustRoot {
        &self.trust_root
    }
}

impl ProvenancePort for SigstoreProvenanceAdapter {
    fn name(&self) -> &str {
        BACKEND_NAME
    }

    fn applies_to(&self, format: &str) -> bool {
        format == COSIGN_FORMAT
    }

    fn verify<'a>(
        &'a self,
        artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [hort_domain::ports::provenance::AttestationBundle],
        policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        Box::pin(async move {
            // Empty bundles → the unsigned case. NOT an error.
            if bundles.is_empty() {
                return Ok(ProvenanceVerdict::no_attestation());
            }

            // Defensive contract guard. `sigstore`'s offline entry,
            // `Verifier::verify_digest(input: Sha256, …)`, finalizes the
            // hasher and uses the result as BOTH the subject digest and the
            // prehash the signature is verified over — so the verifier must
            // feed the artifact *preimage* (`subject.payload`), whose
            // SHA-256 is `content_hash`. The orchestrator's contract
            // (`ProvenanceSubject` invariant) is `sha256(payload) ==
            // content_hash`; a mismatch is a caller bug (wrong bytes loaded
            // from storage), not an attestation problem, so it surfaces as
            // an Invariant — NOT `BundleMalformed` (which is about the
            // bundle).
            let computed = hex::encode(Sha256::digest(artifact.payload));
            if computed != artifact.content_hash.as_ref() {
                return Err(DomainError::Invariant(format!(
                    "provenance-sigstore: ProvenanceSubject.payload does not hash to \
                     content_hash (sha256(payload)={computed}, content_hash={}); the \
                     orchestrator must supply the preimage whose SHA-256 is content_hash",
                    artifact.content_hash.as_ref()
                )));
            }

            // A factory that builds a fresh offline verifier from the
            // cached trust-root bytes on demand (offline; consumes the
            // owned `TrustRoot` `sigstore::Verifier::new` requires). It is
            // invoked only for a well-formed bundle, so a malformed bundle
            // is `BundleMalformed` before any trust-root step.
            let make_verifier = || {
                let trust_root = self.trust_root.build_sigstore_trust_root()?;
                verifier::build_verifier(trust_root)
            };

            // Fold across the supplied bundles: the first bundle that
            // yields a terminal verdict (Verified or a non-malformed
            // Rejected) wins; otherwise we keep the "most informative"
            // rejection. A single OCI artifact usually has one cosign
            // bundle, but the Referrers surface can carry several.
            let verdict = verifier::verify_bundles(
                make_verifier,
                artifact.payload,
                bundles,
                policy.allowed_identities,
            )
            .await;
            Ok(verdict)
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            // Offline health: the trust root must be loaded AND within its
            // refresh window. It does NOT probe live Rekor/Fulcio —
            // a stale-but-loaded root still fails so a worker does not
            // boot a verifier with an out-of-date trust root.
            if self.trust_root.is_fresh() {
                Ok(())
            } else {
                Err(DomainError::Invariant(
                    "provenance-sigstore: cached trust root is stale (outside its TUF \
                     refresh window); refresh required before the verifier is healthy"
                        .to_owned(),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::scan_policy::SignerIdentityPattern;
    use hort_domain::ports::provenance::{AttestationBundle, ProvenanceOutcome};
    use hort_domain::types::ContentHash;

    /// `VALID_SHA256` is `sha256(b"")` — so the empty-byte preimage
    /// satisfies the `ProvenanceSubject` invariant (`sha256(payload) ==
    /// content_hash`) the adapter asserts. Subjects built from
    /// [`subject`] use `payload: b""` to match.
    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn fixture_trust_root() -> CachedTrustRoot {
        CachedTrustRoot::from_trusted_root_json(&trust_root::minimal_trusted_root_json())
            .expect("fixture trust root parses")
    }

    fn adapter() -> SigstoreProvenanceAdapter {
        SigstoreProvenanceAdapter::new(fixture_trust_root())
    }

    /// Build a subject whose `payload` (`b""`) hashes to `hash`. Callers
    /// pass `VALID_SHA256` (= `sha256(b"")`), so the adapter's
    /// payload/content-hash invariant guard is satisfied and the bundle
    /// verdict (not the guard) drives every assertion below.
    fn subject(hash: &ContentHash) -> ProvenanceSubject<'_> {
        ProvenanceSubject {
            content_hash: hash,
            payload: b"",
            name: "library/nginx",
            version: Some("1.27.0"),
        }
    }

    #[test]
    fn name_and_applies_to() {
        let a = adapter();
        assert_eq!(a.name(), "cosign");
        assert!(a.applies_to("oci"));
        assert!(!a.applies_to("npm"));
        assert!(!a.applies_to("maven"));
    }

    #[tokio::test]
    async fn empty_bundles_is_no_attestation() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        let verdict = a.verify(&subj, &[], &reqs).await.expect("ok");
        assert_eq!(verdict.outcome, ProvenanceOutcome::NoAttestation);
    }

    #[tokio::test]
    async fn malformed_bundle_is_rejected_bundle_malformed() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        // Not a Sigstore bundle at all.
        let bundles = [AttestationBundle::new(b"not a bundle".to_vec())];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(
            verdict.outcome,
            ProvenanceOutcome::Rejected(
                hort_domain::ports::provenance::ProvenanceRejectReason::BundleMalformed
            )
        );
    }

    #[tokio::test]
    async fn payload_not_hashing_to_content_hash_is_an_invariant_error() {
        // The `ProvenanceSubject` invariant is `sha256(payload) ==
        // content_hash`. If a caller loads the wrong preimage from
        // storage, the adapter surfaces an Invariant — a
        // caller bug — rather than feeding `verify_digest` a hasher that
        // could never reach `Verified` and silently mislabelling it a
        // bundle problem. This guard is BundleMalformed-distinct on purpose.
        let a = adapter();
        // VALID_SHA256 == sha256(b""), but the payload here is non-empty so
        // sha256(payload) != content_hash → the guard must trip.
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = ProvenanceSubject {
            content_hash: &hash,
            payload: b"not the empty preimage",
            name: "library/nginx",
            version: Some("1.27.0"),
        };
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        // A real-looking (parseable) bundle would otherwise be inspected,
        // but the guard runs first, before any bundle work.
        let bundles = [AttestationBundle::new(b"{}".to_vec())];
        let err = a
            .verify(&subj, &bundles, &reqs)
            .await
            .expect_err("payload/content_hash mismatch is an Invariant error");
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("does not hash to"), "msg: {msg}");
                assert!(msg.contains("content_hash"), "msg: {msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn valid_payload_invariant_reaches_bundle_verdict() {
        // The happy guard branch: payload hashes to content_hash, so the
        // adapter proceeds to the bundle and the verdict is driven by the
        // bundle (here `{}` parses as JSON but is not a valid bundle →
        // BundleMalformed), not the guard.
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash); // payload: b"" == sha256 preimage of VALID_SHA256
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        let bundles = [AttestationBundle::new(b"{}".to_vec())];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(
            verdict.outcome,
            ProvenanceOutcome::Rejected(
                hort_domain::ports::provenance::ProvenanceRejectReason::BundleMalformed
            )
        );
    }

    #[tokio::test]
    async fn health_check_passes_on_fresh_trust_root() {
        let a = adapter();
        a.health_check().await.expect("fresh trust root is healthy");
    }

    #[tokio::test]
    async fn health_check_fails_on_stale_trust_root() {
        // A trust root with a zero-length window is stale the instant
        // after it is loaded.
        let root = CachedTrustRoot::from_trusted_root_json_with_window(
            &trust_root::minimal_trusted_root_json(),
            chrono::Duration::seconds(0),
        )
        .expect("parse");
        // Force staleness deterministically.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let a = SigstoreProvenanceAdapter::new(root);
        let err = a
            .health_check()
            .await
            .expect_err("stale trust root must fail health");
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("stale"), "msg: {msg}"),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    /// The real committed cosign bundle parses, the leaf identity is
    /// extracted, and — because it does **not** chain to our *fixture*
    /// (empty) trust root — it is rejected with a cert/SET reason, never
    /// `Verified`. This exercises the full parse → identity-extract →
    /// offline-crypto path end to end against a real-world bundle without
    /// a live network. (A `Verified` outcome would require the matching
    /// public-good trust root + the original artifact preimage, neither of
    /// which is reproducible offline — see the crate-level fixture note.)
    #[tokio::test]
    async fn real_cosign_bundle_against_fixture_root_is_rejected_not_verified() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let pat =
            SignerIdentityPattern::new("https://token.actions.githubusercontent.com", "*").unwrap();
        let pats = [pat];
        let reqs = ProvenanceRequirements {
            allowed_identities: &pats,
        };
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundles = [AttestationBundle::new(bundle_json.as_bytes().to_vec())];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        // It must NOT spuriously verify against an empty fixture trust root.
        assert!(
            !matches!(verdict.outcome, ProvenanceOutcome::Verified { .. }),
            "real bundle must not verify against the empty fixture trust root: {:?}",
            verdict.outcome
        );
        // And it must be a typed rejection (cert chain / SET / malformed),
        // never a silent pass.
        assert!(
            matches!(verdict.outcome, ProvenanceOutcome::Rejected(_)),
            "expected a typed Rejected, got {:?}",
            verdict.outcome
        );
    }
}
