//! Offline bundle verification core (ADR 0027).
//!
//! Given the cached trust root, the artifact digest, and the raw bundles,
//! [`verify_bundles`] runs `sigstore`'s offline cryptographic verification
//! and folds the result — together with the domain glob identity match —
//! into one [`ProvenanceVerdict`].
//!
//! The cryptographic verification (Fulcio chain → trust root, embedded
//! SCT, Rekor SET from the bundle, signature) is `sigstore`'s; the
//! **identity decision** is the domain's exact-or-bounded-glob
//! [`SignerIdentityPattern::matches`] applied to the observed `{issuer,
//! san}` read out of the verified leaf cert ([`crate::identity`]). We drive
//! `sigstore` with a pass-through [`AllowAllPolicy`] precisely so the
//! bounded-glob half of the policy is not silently bypassed by
//! `sigstore`'s exact-literal `Identity` policy.

use sha2::{Digest, Sha256};
use sigstore::bundle::verify::{policy::VerificationPolicy, Verifier};
use sigstore::bundle::Bundle;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use hort_domain::entities::scan_policy::SignerIdentityPattern;
use hort_domain::error::DomainResult;
use hort_domain::ports::provenance::{
    AttestationBundle, ProvenanceRejectReason, ProvenanceVerdict, SignerIdentity,
};

use crate::identity::observed_identity;

/// Build an offline [`Verifier`] from an owned trust root. Fails when the
/// trust root carries no Fulcio certs / CTFE keys (an un-trustable chain).
/// `RekorConfiguration::default()` is fine — `offline = true` means the
/// rekor config is never used for a network call.
pub(crate) fn build_verifier(trust_root: SigstoreTrustRoot) -> DomainResult<Verifier> {
    Verifier::new(Default::default(), trust_root).map_err(|e| {
        hort_domain::error::DomainError::Invariant(format!(
            "provenance-sigstore: trust root cannot build a verifier \
             (no Fulcio certs / CTFE keys?): {e}"
        ))
    })
}

/// A pass-through [`VerificationPolicy`] — accepts any conforming
/// certificate. The identity decision is the domain glob matcher's job
/// (applied to the observed identity *after* the crypto verifies), so we
/// must NOT also impose `sigstore`'s exact-literal identity policy here;
/// doing so would make a bounded-glob `provenance_identities` pattern
/// inert (it could only ever match an exact literal). The cert chain,
/// SCT, SET, and signature are still fully verified by `sigstore`
/// regardless of this policy — `policy.verify` is only the *identity*
/// gate.
pub(crate) struct AllowAllPolicy;

impl VerificationPolicy for AllowAllPolicy {
    fn verify(&self, _cert: &Certificate) -> sigstore::bundle::verify::policy::PolicyResult {
        Ok(())
    }
}

/// Fold all supplied bundles into a single verdict.
///
/// Precedence (most → least authoritative):
/// 1. the first `Verified` wins immediately;
/// 2. otherwise the first identity-mismatch (`UntrustedIdentity`) — the
///    signature was cryptographically sound but the signer is not allowed;
/// 3. otherwise the first crypto rejection (`CertChainInvalid` /
///    `RekorNotFound`);
/// 4. otherwise `BundleMalformed`.
///
/// `bundles` is guaranteed non-empty by the caller. `make_verifier` builds
/// a fresh offline [`Verifier`] from the cached trust root on demand —
/// it is called **only** for a bundle that has already parsed and yielded
/// a readable leaf identity, so a malformed bundle is reported as
/// `BundleMalformed` **before** any trust-root-dependent step (a broken or
/// empty trust root never masks a malformed-bundle verdict).
///
/// `sigstore::Verifier::new` consumes its `TrustRoot` by value and the
/// root is not `Clone`, so the factory hands back a fresh owned `Verifier`
/// per crypto call. The factory itself fails (returns `Err`) when the
/// trust root carries no Fulcio certs / CTFE keys — that surfaces as a
/// `CertChainInvalid` for *that* bundle (its chain cannot be trusted),
/// never as a masked malformed verdict.
pub(crate) async fn verify_bundles<F>(
    make_verifier: F,
    payload: &[u8],
    bundles: &[AttestationBundle],
    allowed: &[SignerIdentityPattern],
) -> ProvenanceVerdict
where
    F: Fn() -> DomainResult<Verifier>,
{
    let mut best: Option<ProvenanceRejectReason> = None;

    for bundle in bundles {
        match verify_one(&make_verifier, payload, &bundle.bytes, allowed).await {
            BundleVerify::Verified {
                signer,
                predicate_type,
            } => {
                return ProvenanceVerdict::verified(signer, predicate_type);
            }
            BundleVerify::Rejected(reason) => {
                best = Some(merge_reason(best, reason));
            }
        }
    }

    // Non-empty input always produces at least one reject reason here.
    ProvenanceVerdict::rejected(best.unwrap_or(ProvenanceRejectReason::BundleMalformed))
}

/// Keep the more-authoritative reject reason (lower number wins). See the
/// precedence ladder in [`verify_bundles`].
fn merge_reason(
    current: Option<ProvenanceRejectReason>,
    incoming: ProvenanceRejectReason,
) -> ProvenanceRejectReason {
    fn rank(r: ProvenanceRejectReason) -> u8 {
        match r {
            ProvenanceRejectReason::UntrustedIdentity => 0,
            ProvenanceRejectReason::CertChainInvalid => 1,
            ProvenanceRejectReason::RekorNotFound => 2,
            ProvenanceRejectReason::BundleMalformed => 3,
            // Unsigned is an orchestrator-mapped reason, never produced by
            // this adapter; rank it last so it never shadows a real one.
            ProvenanceRejectReason::Unsigned => 4,
        }
    }
    match current {
        Some(c) if rank(c) <= rank(incoming) => c,
        _ => incoming,
    }
}

/// The internal per-bundle outcome.
enum BundleVerify {
    Verified {
        signer: SignerIdentity,
        predicate_type: Option<String>,
    },
    Rejected(ProvenanceRejectReason),
}

/// Verify a single bundle offline. No network — `offline = true` uses the
/// bundle's embedded SET; the `async` is only `sigstore`'s API shape.
///
/// Parsing + identity extraction happen **first** so a malformed bundle is
/// reported as `BundleMalformed` regardless of trust-root health; only a
/// well-formed bundle reaches the trust-root-dependent crypto step.
async fn verify_one<F>(
    make_verifier: &F,
    payload: &[u8],
    bundle_bytes: &[u8],
    allowed: &[SignerIdentityPattern],
) -> BundleVerify
where
    F: Fn() -> DomainResult<Verifier>,
{
    // 1) Parse the bundle JSON. Unparseable → BundleMalformed.
    let Ok(bundle) = serde_json::from_slice::<Bundle>(bundle_bytes) else {
        return BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed);
    };

    // 2) Extract the observed signer identity from the leaf cert. A bundle
    //    with no leaf cert / no readable identity is malformed for our
    //    purposes (we cannot make an identity decision on it).
    let Some(leaf_der) = leaf_cert_der(&bundle) else {
        return BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed);
    };
    let Ok(cert) = Certificate::from_der(&leaf_der) else {
        return BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed);
    };
    let Ok(observed) = observed_identity(&cert) else {
        return BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed);
    };

    // 3) Build the offline verifier (trust-root-dependent) and run
    //    sigstore's cryptographic verification. `offline = true` uses the
    //    bundle's embedded SET / tlog body — NO network. A trust root with
    //    no Fulcio certs / CTFE keys cannot establish a chain → this
    //    well-formed bundle is a `CertChainInvalid` (not malformed).
    //    `verify_digest` consumes the bundle; identity + predicate type are
    //    already extracted above.
    let Ok(verifier) = make_verifier() else {
        return BundleVerify::Rejected(ProvenanceRejectReason::CertChainInvalid);
    };

    let predicate_type = predicate_type_of(&bundle);

    // `verify_digest` finalizes this hasher and uses the result as BOTH the
    // subject digest (compared against the bundle) and the prehash the
    // signature is verified over (sigstore-0.14 `verifier.rs:127`). It must
    // therefore be fed the artifact *preimage* so it finalizes to
    // `sha256(payload) == content_hash`; feeding the content-hash bytes
    // would finalize to `sha256(content_hash)` and could never reach
    // `Verified`. The caller guarantees `sha256(payload) == content_hash`
    // (the `ProvenanceSubject` invariant, asserted at the adapter entry).
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = verifier
        .verify_digest(hasher, bundle, &AllowAllPolicy, true)
        .await;

    match result {
        Ok(()) => {
            // 4) Crypto passed. Apply the domain glob identity match. An
            //    empty allow-list never matches (the any-signer footgun is
            //    apply-rejected upstream under `Required`; under
            //    `VerifyIfPresent` an empty list rejects forged/untrusted
            //    signers — design §2.4).
            let identity_ok = allowed
                .iter()
                .any(|p| p.matches(&observed.issuer, &observed.san));
            if identity_ok {
                BundleVerify::Verified {
                    signer: observed,
                    predicate_type,
                }
            } else {
                BundleVerify::Rejected(ProvenanceRejectReason::UntrustedIdentity)
            }
        }
        Err(e) => BundleVerify::Rejected(map_verification_error(&e)),
    }
}

/// Pull the leaf certificate DER out of a bundle's verification material.
/// Form (3) — a single `Certificate` — is the v0.3 keyless shape; form (2)
/// — an `X509CertificateChain` — is the older v0.1/v0.2 shape (leaf
/// first). Returns `None` when neither is present (no signing cert).
fn leaf_cert_der(bundle: &Bundle) -> Option<Vec<u8>> {
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::verification_material::Content;
    let material = bundle.verification_material.as_ref()?;
    match material.content.as_ref()? {
        Content::Certificate(cert) => Some(cert.raw_bytes.clone()),
        Content::X509CertificateChain(chain) => {
            chain.certificates.first().map(|c| c.raw_bytes.clone())
        }
        // Form (1) — a bare public-key identifier — carries no cert, so we
        // cannot establish a Fulcio identity. Treat as no-leaf.
        _ => None,
    }
}

/// Best-effort predicate-type extraction for the audit record. For a DSSE
/// in-toto attestation the `payloadType` is the predicate envelope type;
/// for a bare message signature there is no structured predicate (`None`).
fn predicate_type_of(bundle: &Bundle) -> Option<String> {
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content;
    match bundle.content.as_ref()? {
        Content::DsseEnvelope(dsse) => {
            let pt = dsse.payload_type.clone();
            if pt.is_empty() {
                None
            } else {
                Some(pt)
            }
        }
        Content::MessageSignature(_) => None,
    }
}

/// Map a `sigstore` [`VerificationError`] to the domain reject reason
/// (design §4). A missing/invalid SET is `RekorNotFound` and is **never**
/// retried online; a chain/SCT failure is `CertChainInvalid`; anything
/// structurally broken in the bundle is `BundleMalformed`.
///
/// `sigstore` keeps the inner error-*kind* enums in a private module
/// (`bundle::verify::models`) — only the outer [`VerificationError`]
/// variants are nameable. We therefore match the **variant** for the
/// coarse class and disambiguate the `Signature` variant's
/// `Transparency` (offline SET-consistency) case via the error's
/// `Display` (which is `#[error("signature transparency materials are
/// inconsistent")]` upstream). This keeps the mapping precise without
/// depending on the private types.
fn map_verification_error(
    err: &sigstore::bundle::verify::VerificationError,
) -> ProvenanceRejectReason {
    use sigstore::bundle::verify::VerificationError as VE;
    match err {
        // Bundle structurally broken / unsupported material / unreadable
        // input.
        VE::Bundle(_) | VE::Input(_) => ProvenanceRejectReason::BundleMalformed,
        // Fulcio chain / SCT failures. A *malformed* cert is a broken
        // bundle; any other certificate failure is an untrusted chain.
        VE::Certificate(_) => {
            if err.to_string().contains("malformed") {
                ProvenanceRejectReason::BundleMalformed
            } else {
                ProvenanceRejectReason::CertChainInvalid
            }
        }
        // The offline tlog/SET-consistency failure surfaces as
        // `SignatureErrorKind::Transparency` ("signature transparency
        // materials are inconsistent") — the SET is missing or does not
        // match the signing materials. Per design §4 this is
        // `RekorNotFound`, NEVER a live Rekor fetch. A genuine bad
        // signature / unsupported algorithm is a cert/key-level failure.
        VE::Signature(_) => {
            if err.to_string().contains("transparency") {
                ProvenanceRejectReason::RekorNotFound
            } else {
                ProvenanceRejectReason::CertChainInvalid
            }
        }
        // The pass-through policy never errors, but map defensively.
        VE::Policy(_) => ProvenanceRejectReason::UntrustedIdentity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `make_verifier` factory over the **empty** fixture trust root.
    /// `Verifier::new` fails on a root with no Fulcio certs / CTFE keys, so
    /// this factory returns `Err` — exercising the "well-formed bundle, but
    /// un-trustable chain → CertChainInvalid" path. A malformed bundle is
    /// rejected before the factory is ever called.
    fn empty_root_factory() -> impl Fn() -> DomainResult<Verifier> {
        || {
            let tr = SigstoreTrustRoot::from_trusted_root_json_unchecked(
                &crate::trust_root::minimal_trusted_root_json(),
            )
            .expect("minimal trust root parses");
            build_verifier(tr)
        }
    }

    #[test]
    fn allow_all_policy_accepts_any_cert() {
        // Construct via the real fixture leaf so we exercise the policy on
        // an actual certificate.
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("fixture parses");
        let der = leaf_cert_der(&bundle).expect("fixture has a leaf");
        let cert = Certificate::from_der(&der).expect("leaf decodes");
        assert!(AllowAllPolicy.verify(&cert).is_ok());
    }

    #[test]
    fn build_verifier_fails_on_empty_trust_root() {
        let tr = SigstoreTrustRoot::from_trusted_root_json_unchecked(
            &crate::trust_root::minimal_trusted_root_json(),
        )
        .expect("parse");
        // `Verifier` is not `Debug`, so match rather than `expect_err`.
        match build_verifier(tr) {
            Err(hort_domain::error::DomainError::Invariant(msg)) => {
                assert!(msg.contains("verifier"), "msg: {msg}");
            }
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("empty root must not build a verifier"),
        }
    }

    #[tokio::test]
    async fn unparseable_bundle_is_malformed() {
        // Even though the trust root is empty (factory would fail), a
        // malformed bundle is rejected BEFORE the factory is consulted.
        let v = verify_one(&empty_root_factory(), &[0u8; 32], b"}{not json", &[]).await;
        assert!(matches!(
            v,
            BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed)
        ));
    }

    #[tokio::test]
    async fn json_without_verification_material_is_malformed() {
        // Valid JSON, but no verificationMaterial → no leaf cert →
        // malformed (again before the trust-root factory).
        let v = verify_one(
            &empty_root_factory(),
            &[0u8; 32],
            b"{\"mediaType\":\"x\"}",
            &[],
        )
        .await;
        assert!(matches!(
            v,
            BundleVerify::Rejected(ProvenanceRejectReason::BundleMalformed)
        ));
    }

    #[tokio::test]
    async fn real_bundle_against_empty_trust_root_is_typed_rejection_not_verified() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        // A lone-star pattern would match the observed identity IF the
        // crypto passed — so this proves the crypto gate runs first. The
        // empty trust root cannot build a verifier → CertChainInvalid (no
        // spurious Verified).
        let pat = SignerIdentityPattern::new("*", "*").unwrap();
        let v = verify_one(
            &empty_root_factory(),
            &[7u8; 32],
            bundle_json.as_bytes(),
            &[pat],
        )
        .await;
        match v {
            BundleVerify::Verified { .. } => {
                panic!("must NOT verify against an empty fixture trust root")
            }
            BundleVerify::Rejected(reason) => {
                assert_eq!(
                    reason,
                    ProvenanceRejectReason::CertChainInvalid,
                    "empty trust root → un-trustable chain"
                );
            }
        }
    }

    #[test]
    fn merge_reason_keeps_more_authoritative() {
        use ProvenanceRejectReason::*;
        // UntrustedIdentity (rank 0) beats everything.
        assert_eq!(
            merge_reason(Some(BundleMalformed), UntrustedIdentity),
            UntrustedIdentity
        );
        assert_eq!(
            merge_reason(Some(UntrustedIdentity), BundleMalformed),
            UntrustedIdentity
        );
        // CertChainInvalid beats RekorNotFound beats BundleMalformed.
        assert_eq!(
            merge_reason(Some(RekorNotFound), CertChainInvalid),
            CertChainInvalid
        );
        assert_eq!(
            merge_reason(Some(BundleMalformed), RekorNotFound),
            RekorNotFound
        );
        // None → take incoming.
        assert_eq!(merge_reason(None, BundleMalformed), BundleMalformed);
        // Unsigned ranks last.
        assert_eq!(
            merge_reason(Some(BundleMalformed), Unsigned),
            BundleMalformed
        );
        assert_eq!(
            merge_reason(Some(Unsigned), BundleMalformed),
            BundleMalformed
        );
    }

    /// Exhaustively exercise the `rank` ladder so every reason arm is
    /// covered: feeding each reason as `incoming` over a `None` current
    /// returns it unchanged, and the full ordering is total + stable.
    #[test]
    fn merge_reason_rank_total_order() {
        use ProvenanceRejectReason::*;
        let ordered = [
            UntrustedIdentity,
            CertChainInvalid,
            RekorNotFound,
            BundleMalformed,
            Unsigned,
        ];
        // None current → incoming wins for every reason (covers each arm).
        for r in ordered {
            assert_eq!(merge_reason(None, r), r);
        }
        // For every (a, b) the more-authoritative (earlier in `ordered`)
        // wins regardless of which is current vs incoming.
        for (i, &a) in ordered.iter().enumerate() {
            for &b in &ordered[i..] {
                // a is >= as authoritative as b.
                assert_eq!(merge_reason(Some(a), b), a, "{a:?} vs {b:?}");
                assert_eq!(merge_reason(Some(b), a), a, "{b:?} vs {a:?}");
            }
        }
    }

    #[tokio::test]
    async fn verify_bundles_folds_to_malformed_for_garbage_inputs() {
        let bundles = [
            AttestationBundle::new(b"garbage".to_vec()),
            AttestationBundle::new(b"{\"mediaType\":\"x\"}".to_vec()),
        ];
        // Both bundles fail to parse / have no leaf → all BundleMalformed;
        // the trust-root factory is never consulted.
        let verdict = verify_bundles(empty_root_factory(), &[0u8; 32], &bundles, &[]).await;
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed)
        );
    }

    #[tokio::test]
    async fn verify_bundles_real_bundle_empty_root_is_cert_chain_invalid() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundles = [AttestationBundle::new(bundle_json.as_bytes().to_vec())];
        let verdict = verify_bundles(empty_root_factory(), &[7u8; 32], &bundles, &[]).await;
        assert_eq!(
            verdict,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::CertChainInvalid)
        );
    }

    #[test]
    fn predicate_type_of_dsse_fixture_is_intoto() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("parses");
        // The real fixture is a DSSE in-toto attestation → its payloadType
        // is the predicate envelope type (recorded on ProvenanceVerified).
        assert_eq!(
            predicate_type_of(&bundle).as_deref(),
            Some("application/vnd.in-toto+json")
        );
    }

    #[test]
    fn predicate_type_of_dsse_with_empty_payload_type_is_none() {
        // A DSSE bundle whose payloadType is empty → None (covers the
        // empty-string guard).
        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".into(),
            verification_material: None,
            content: Some(
                sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(
                    sigstore_protobuf_specs::io::intoto::Envelope {
                        payload: vec![],
                        payload_type: String::new(),
                        signatures: vec![],
                    },
                ),
            ),
        };
        assert_eq!(predicate_type_of(&bundle), None);
    }

    #[test]
    fn predicate_type_of_bundle_without_content_is_none() {
        let bundle = Bundle {
            media_type: "x".into(),
            verification_material: None,
            content: None,
        };
        assert_eq!(predicate_type_of(&bundle), None);
    }

    #[test]
    fn predicate_type_of_message_signature_bundle_is_none() {
        // A message-signature bundle (no DSSE envelope) carries no
        // structured predicate. Build a minimal one with a MessageSignature
        // content and no DSSE.
        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".into(),
            verification_material: None,
            content: Some(
                sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::MessageSignature(
                    sigstore_protobuf_specs::dev::sigstore::common::v1::MessageSignature {
                        message_digest: None,
                        signature: vec![1, 2, 3],
                    },
                ),
            ),
        };
        assert_eq!(predicate_type_of(&bundle), None);
    }

    #[test]
    fn leaf_cert_der_reads_v03_single_certificate_form() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).expect("parses");
        let der = leaf_cert_der(&bundle).expect("v0.3 single-cert form yields a leaf");
        assert!(!der.is_empty());
        // The DER must decode as a real certificate.
        Certificate::from_der(&der).expect("leaf decodes");
    }
}
