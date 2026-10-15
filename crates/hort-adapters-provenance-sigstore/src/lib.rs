//! Sigstore/cosign [`ProvenancePort`] adapter — **offline bundle
//! verification** (ADR 0027).
//!
//! `SigstoreProvenanceAdapter` implements
//! [`ProvenancePort`](hort_domain::ports::provenance::ProvenancePort) by
//! verifying each stored Sigstore bundle **offline** against a cached,
//! injectable trust root — there is **no live Rekor/Fulcio lookup on the
//! verify path**. Each bundle already carries its Fulcio certificate chain
//! (with embedded SCT) and the Rekor inclusion proof + signed checkpoint.
//! The adapter validates the **Fulcio certificate chain, the embedded SCT,
//! the artifact signature, the digest binding, and the Rekor Merkle
//! inclusion proof + checkpoint signature** against the cached Sigstore
//! trust root (Fulcio CA certs + CT-log + Rekor public keys) refreshed
//! periodically via TUF — *not* per verify (see [`trust_root`]). A bundle
//! whose transparency-log entry is not provably in the Rekor log can never
//! reach `Verified` (see "Rekor inclusion verification" below).
//!
//! ## Verdict flow ([`SigstoreProvenanceAdapter::verify`])
//! - empty `bundles` → [`NoAttestation`] (the unsigned case — **not** an
//!   error);
//! - a bundle that does not parse / carries no leaf cert / carries no
//!   readable identity → **skipped, not judged**: the verifier could not
//!   read it, so it establishes nothing about the artifact and contributes
//!   nothing to the verdict — no rejection, no hold, no evidence. The skip
//!   is counted on the returned verdict
//!   ([`ProvenanceVerdict::unreadable_skipped`]) so it is not *silent*,
//!   and a bundle set with nothing readable in it answers
//!   [`NoAttestation`]. Only findings about material the verifier read may
//!   condemn an artifact; otherwise anyone who can write a referrer could
//!   reject somebody else's correctly-signed image by attaching
//!   unparseable bytes;
//! - cert chain that does not validate to the trust root → [`Rejected(CertChainInvalid)`];
//! - a trust root carrying no Fulcio certs / CTFE keys, from which no
//!   offline verifier can be built at all → **held**
//!   ([`Indeterminate(TrustRootUnusable)`]), never rejected: the chain
//!   was never examined, so the rejection above would be a finding about
//!   a certificate nothing looked at. The worker refuses to boot on such
//!   a root, so this is the defence rather than the design;
//! - a bundle whose Rekor Merkle inclusion proof or checkpoint signature
//!   does not cryptographically verify against the trust root's Rekor key
//!   → [`Rejected(RekorNotFound)`] — **never** a fall-back to a live
//!   Rekor fetch. That is the forged-but-well-formed entry: a proof the
//!   verifier read, which did not verify;
//! - a bundle whose transparency-log material is structurally absent,
//!   unparseable or impossible (the v0.1 SET-only shape and a negative
//!   tree size among them) → **skipped**, like any other material nothing
//!   could be concluded from — it is not garbage and not a forgery, so
//!   the artifact holds as unsigned rather than being condemned on it;
//! - a bundle whose entry log id matches no Rekor key in the trust root,
//!   or whose matching key bytes do not parse → **held**
//!   ([`Indeterminate(TrustRootUnusable)`]), never rejected: the check
//!   never ran, and a publisher's correctly signed, log-included artifact
//!   is not implicated by our own provisioning. The held artifact
//!   verifies on the next run once the key is there;
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
//! verifying. The cert-chain / SCT / signature / digest-binding crypto runs
//! **for real** against the injected trust root (it is *not* a stub). The
//! **offline** and **injectable-trust-root** guarantees are fully met here.
//!
//! ## Rekor inclusion verification (closes sigstore-rs#285 for v0.3)
//!
//! The pinned `sigstore` 0.14 `Verifier::verify_digest` implements the Fulcio
//! chain, SCT, signature, digest-binding, and cert-validity-window checks, but
//! its Rekor **Merkle inclusion proof** + checkpoint/SET steps are upstream
//! `TODO`s (`sigstore-rs#285`). This adapter closes that gap **offline** for
//! the Sigstore **v0.3** bundle format (ADR 0027): after `verify_digest`
//! succeeds, [`inclusion::verify_inclusion`] reconstructs the public
//! `rekor::models::InclusionProof` from the bundle's protobuf
//! transparency-log entry (fail-closed `Vec<u8> → [u8; 32]` width checks; the
//! checkpoint signed-note envelope parsed via `SignedCheckpoint`) and runs the
//! crate's cryptographically-complete `InclusionProof::verify` — full RFC-6962
//! Merkle inclusion over the entry's `canonicalized_body` leaf, **plus** the
//! checkpoint signature, **plus** root/tree-size consistency — against the
//! Rekor public key selected from the pinned trust root by the entry's
//! `logID`. No failure there can reach `Verified`, and none is ever a
//! panic or a live Rekor fetch — but fail-closed is not the same thing as
//! terminal, so which answer a failure gives depends on whose side it is
//! on: a proof that did not verify is [`Rejected(RekorNotFound)`], a
//! trust root with no usable key for the entry is a hold, and absent or
//! unparseable log material is a skip. So this adapter now proves that a
//! valid Fulcio cert with SCT for a policy-allowed identity signed these
//! bytes **and** that the entry is provably in the public Rekor
//! transparency log. The older v0.1 SET-only (`inclusion_promise`) path is
//! out of scope (ADR 0027:168): a bundle of that shape can never verify
//! here, and it is skipped rather than condemned.
//!
//! [`Indeterminate(TrustRootUnusable)`]: hort_domain::ports::provenance::IndeterminateReason::TrustRootUnusable
//! [`NoAttestation`]: hort_domain::ports::provenance::ProvenanceOutcome::NoAttestation
//! [`ProvenanceVerdict::unreadable_skipped`]: hort_domain::ports::provenance::ProvenanceVerdict::unreadable_skipped
//! [`Rejected(CertChainInvalid)`]: hort_domain::ports::provenance::ProvenanceRejectReason::CertChainInvalid
//! [`Rejected(RekorNotFound)`]: hort_domain::ports::provenance::ProvenanceRejectReason::RekorNotFound
//! [`Rejected(UntrustedIdentity)`]: hort_domain::ports::provenance::ProvenanceRejectReason::UntrustedIdentity
//! [`Verified { signer, predicate_type }`]: hort_domain::ports::provenance::ProvenanceOutcome::Verified
//! [`SignerIdentityPattern`]: hort_domain::entities::scan_policy::SignerIdentityPattern
//! [`SignerIdentityPattern::matches`]: hort_domain::entities::scan_policy::SignerIdentityPattern::matches
//! [`ProvenanceSubject`]: hort_domain::ports::provenance::ProvenanceSubject

mod extra_ca;
mod identity;
mod inclusion;
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
            // invoked only for a well-formed bundle, so an unreadable
            // bundle is skipped before any trust-root step — a broken
            // trust root can never turn one into a chain finding.
            let make_verifier = || {
                let trust_root = self.trust_root.build_sigstore_trust_root()?;
                verifier::build_verifier(trust_root)
            };

            // Snapshot the trust root's Rekor public keys (owned) for the
            // offline Rekor Merkle inclusion-proof + checkpoint-signature
            // verification each bundle runs *after* `verify_digest`
            // succeeds (ADR 0027; the `verify_digest` consume forces the
            // keys to be extracted before the verifier is built). An empty
            // map can never let a verify pass, and it holds every artifact
            // rather than rejecting one — a missing key is our
            // provisioning, not a finding — which is why the worker boot
            // check surfaces a Rekor-keyless trust root up front instead.
            let rekor_keys = self.trust_root.rekor_keys()?;

            // Fold across the supplied bundles: the first `Verified` wins;
            // otherwise we keep the "most informative" finding about
            // material we could read, and if there was none, the honest
            // `NoAttestation`. A single OCI artifact usually has one
            // cosign bundle, but the Referrers surface can carry several —
            // and anyone with write access to it can add one.
            let verdict = verifier::verify_bundles(
                make_verifier,
                artifact.payload,
                bundles,
                policy.allowed_identities,
                &rekor_keys,
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
    use hort_domain::ports::provenance::{
        AttestationBundle, IndeterminateReason, ProvenanceOutcome,
    };
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
        // An empty set skipped nothing — the same outcome as an
        // all-unreadable set, told apart by the count.
        assert_eq!(verdict.unreadable_skipped, 0);
    }

    /// **Changed meaning.** This test was
    /// `malformed_bundle_is_rejected_bundle_malformed` and asserted
    /// `Rejected{BundleMalformed}`.
    ///
    /// Bytes the verifier cannot read prove nothing about the artifact, so
    /// they are not a rejection, not a hold and not evidence of any kind:
    /// the candidate is skipped and counted, and a set with nothing else
    /// in it answers `NoAttestation` — "I have nothing to say about this
    /// artifact". Under `Required` that is the indefinite unsigned hold;
    /// under `VerifyIfPresent`, the allow. The behaviour the old
    /// assertion pinned is the exposure: the referrer surface is writable
    /// by anyone with push access to the repository, so a rejection
    /// derived from unparseable bytes is a denial-of-service against
    /// somebody else's correctly-signed image.
    #[tokio::test]
    async fn malformed_bundle_is_skipped_not_rejected() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        // Not a Sigstore bundle at all.
        let bundles = [AttestationBundle::new(b"not a bundle".to_vec())];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(verdict.outcome, ProvenanceOutcome::NoAttestation);
        // Skipped, but recorded: *not considered* is not *not noticed*.
        assert_eq!(verdict.unreadable_skipped, 1);
    }

    #[tokio::test]
    async fn keyed_bundle_is_skipped_not_rejected() {
        // ADR 0039 §8: a keyed (cosign-key `simplesigning`) bundle is NOT this
        // verifier's — `signature.is_some()` is skipped, so a keyed-only artifact
        // yields NoAttestation here (the keyed verifier decides), NOT a reject
        // that would dominate the fold and false-block a valid keyed image on a
        // worker running both backends.
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        let bundles = [AttestationBundle::new_signed(
            br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc"}}}"#.to_vec(),
            vec![0x30, 0x44, 0x01],
        )];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(verdict.outcome, ProvenanceOutcome::NoAttestation);
    }

    /// **Changed meaning, and this is the test whose old comment stated
    /// the behaviour being reversed.** It was
    /// `mixed_keyed_and_malformed_keyless_skips_keyed_keeps_keyless_reject`,
    /// and its comment read *"the keyed bundle is skipped, but the
    /// malformed KEYLESS bundle still drives the verdict"*.
    ///
    /// Nothing in this set drives a verdict any more. Both candidates are
    /// skipped — the keyed one because it is not this verifier's, the
    /// unreadable one because nothing can be concluded from it — and the
    /// two skips are *different* skips, which is why only one of them is
    /// counted: a keyed bundle was not read because it belongs to the
    /// other backend, and counting it would make every keyed-signed
    /// artifact look like it carried garbage.
    ///
    /// On a worker running BOTH backends this exact set is the attack this
    /// unit closes: the keyed verifier verifies the real signature, this
    /// verifier answers `NoAttestation`, and the fold is `Verified`. The
    /// end-to-end proof is in the orchestration tests
    /// (`a_valid_keyed_signature_survives_unreadable_keyless_garbage`);
    /// here it is this verifier's half.
    #[tokio::test]
    async fn mixed_keyed_and_unreadable_keyless_both_skip_to_no_attestation() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash);
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        let bundles = [
            AttestationBundle::new_signed(b"keyed payload".to_vec(), vec![1, 2]),
            AttestationBundle::new(b"not a bundle".to_vec()),
        ];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(verdict.outcome, ProvenanceOutcome::NoAttestation);
        assert_eq!(
            verdict.unreadable_skipped, 1,
            "only the unreadable keyless candidate counts — the keyed one was not ours",
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

    /// **Changed meaning.** The happy guard branch: the payload hashes to
    /// `content_hash`, so the adapter proceeds to the bundle and the
    /// *bundle* drives the outcome rather than the guard. That is still
    /// what this asserts — only the bundle's own answer moved: `{}` parses
    /// as JSON but carries no verification material, so it is a candidate
    /// the verifier cannot read, and the recorded skip is the proof the
    /// adapter got past the guard and into `verify_bundles`.
    #[tokio::test]
    async fn valid_payload_invariant_reaches_bundle_verdict() {
        let a = adapter();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let subj = subject(&hash); // payload: b"" == sha256 preimage of VALID_SHA256
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };
        let bundles = [AttestationBundle::new(b"{}".to_vec())];
        let verdict = a.verify(&subj, &bundles, &reqs).await.expect("ok");
        assert_eq!(verdict.outcome, ProvenanceOutcome::NoAttestation);
        assert_eq!(
            verdict.unreadable_skipped, 1,
            "the bundle was examined (and unreadable) — not short-circuited by the guard",
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
    /// extracted, and the offline-crypto step is reached — exercising the
    /// full parse → identity-extract → offline-crypto path end to end
    /// against a real-world bundle without a live network. It is never
    /// `Verified`. (A `Verified` outcome would require the matching
    /// public-good trust root + the original artifact preimage, neither of
    /// which is reproducible offline — see the crate-level fixture note.)
    ///
    /// **Changed verdict.** This was
    /// `real_cosign_bundle_against_fixture_root_is_rejected_not_verified`
    /// and asserted `Rejected(_)` — "*it is rejected with a cert/SET
    /// reason*" — because the fixture trust root's inability to build a
    /// verifier was stated as a finding about the publisher's chain. The
    /// fixture root carries no Fulcio certs, so that chain is never
    /// examined; the honest answer is the hold, and this is the adapter's
    /// whole-`verify` statement of it.
    ///
    /// It asserts the reason rather than `Indeterminate(_)`, because the
    /// hold this path must produce is specifically the trust-root one: an
    /// adapter answering some *other* indeterminate here would be
    /// reporting a different fault than the one that occurred.
    #[tokio::test]
    async fn real_cosign_bundle_against_unusable_fixture_root_holds_not_verified() {
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
        // And it must be the typed hold that names our trust root — never
        // a silent pass, and never a rejection minted from a certificate
        // chain no verifier was ever built to examine.
        assert_eq!(
            verdict.outcome,
            ProvenanceOutcome::Indeterminate(IndeterminateReason::TrustRootUnusable),
            "a trust root that cannot build a verifier is our fault, not the publisher's",
        );
        // The bundle was read in full on the way there, so it is not a
        // skip either: *not checked* and *not readable* are different
        // records, and only one of them is true here.
        assert_eq!(verdict.unreadable_skipped, 0);
    }
}
