//! Outbound port for supply-chain **provenance** verification — Sigstore
//! signatures / in-toto attestations (ADR 0027).
//!
//! Mirrors the [`ScannerPort`](super::scanner::ScannerPort) shape: a
//! per-backend verifier adapter (`hort-adapters-provenance-sigstore`)
//! implements this trait and depends only on `hort-domain`. The
//! orchestrator (`ProvenanceOrchestrationUseCase`) treats a
//! verifier as an opaque *(subject, bundles, requirements) → verdict*
//! function: it fetches the attestation bundles (OCI Referrers surface
//! for cosign; per-version metadata for Tier-2 formats), passes them in,
//! and folds the returned [`ProvenanceVerdict`] through
//! [`Artifact::complete_provenance`](crate::entities::artifact::Artifact::complete_provenance).
//!
//! **Pure domain — zero I/O.** The verdict / requirement / subject types
//! defined here are plain owned/borrowed data; the *network and crypto*
//! live entirely in the adapter. Bundle bytes are opaque to the domain
//! ([`AttestationBundle`] is a thin blob wrapper); the adapter parses them.

use serde::{Deserialize, Serialize};

use crate::entities::scan_policy::SignerIdentityPattern;
use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// The subject of a provenance verification — the content being verified
/// plus the package coordinates a signer identity may be bound to.
///
/// Borrowed (`&'a ProvenanceSubject<'a>` in [`ProvenancePort::verify`])
/// so the orchestrator hands the verifier a view into the artifact it
/// already holds without cloning. `content_hash` is the CAS identity
/// (the bytes whose signature is being checked); `payload` is the
/// artifact *preimage* those bytes hash to (`sha256(payload) ==
/// content_hash`); `name` / `version` are the resolved coordinates the
/// audit trail records on the emitted `ProvenanceVerified` /
/// `ProvenanceRejected` events.
///
/// **Invariant: `sha256(payload) == content_hash`.** The orchestrator
/// loads `payload` from the [`StoragePort`](super::storage) (for OCI
/// cosign, the manifest bytes) so the verifier can finalize the preimage
/// to the same digest the attestation bundle binds. A verifier may rely
/// on this invariant and treat a violation as a caller bug
/// (internal/invariant error), not an attestation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceSubject<'a> {
    /// The CAS content hash whose attestation is being verified.
    pub content_hash: &'a ContentHash,
    /// The artifact preimage whose SHA-256 is `content_hash` (for OCI
    /// cosign, the manifest bytes). The verifier feeds this to the hasher
    /// so the finalized digest binds to this artifact.
    pub payload: &'a [u8],
    /// Normalised package name (the artifact's `name`).
    pub name: &'a str,
    /// Package version, when the format carries one.
    pub version: Option<&'a str>,
}

/// An opaque raw attestation bundle as fetched by the orchestrator.
///
/// The domain treats the bytes as opaque — the Sigstore adapter parses
/// the Fulcio cert chain + Rekor inclusion proof / SET out of the bundle
/// and verifies it offline against a cached trust root. A simple owned-blob
/// wrapper here keeps the port dyn-compatible and the domain crypto-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBundle {
    /// The raw bundle bytes (e.g. a cosign `*.sigstore`/`*.bundle` JSON).
    pub bytes: Vec<u8>,
}

impl AttestationBundle {
    /// Wrap raw bundle bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// A trusted signer identity — the `{issuer, san}` pair an OIDC-backed
/// Sigstore signature certificate binds.
///
/// The **same shape** as `ServiceAccount.federatedIdentities[].claims`:
/// `issuer` is the OIDC issuer URL the Fulcio cert was minted against
/// (e.g. `https://token.actions.githubusercontent.com`); `san` is the
/// certificate Subject Alternative Name (the workflow identity, e.g. a
/// GitHub Actions workflow ref).
///
/// Carries `Serialize`/`Deserialize` because it rides the
/// `ProvenanceVerified` event payload (the audit record of *who* signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    /// OIDC issuer URL the signing certificate was minted against.
    pub issuer: String,
    /// Certificate Subject Alternative Name (the workload identity).
    pub san: String,
}

/// The policy inputs a verifier checks a candidate signature against —
/// the **allowed** signer-identity *patterns* for this scope.
///
/// Borrowed (`&'a ProvenanceRequirements<'a>`) so the orchestrator passes
/// a view into the resolved `ScanPolicy.provenance_identities` without
/// cloning. Tier-2 predicate-type / SLSA-level fields attach here when
/// those land; Tier-1 carries identities only.
///
/// **Carries [`SignerIdentityPattern`], not [`SignerIdentity`]**.
/// The policy stores allowed signers as *patterns* (exact or bounded
/// glob); the verifier matches an **observed** [`SignerIdentity`] (read
/// from the verified Fulcio leaf cert) against these patterns via
/// [`SignerIdentityPattern::matches`](crate::entities::scan_policy::SignerIdentityPattern::matches).
/// Using patterns (rather than concrete identities) means the
/// bounded-glob matching half of every stored pattern is active, not
/// silently inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceRequirements<'a> {
    /// The signer-identity patterns a valid signature must match one of.
    /// An empty slice under `Required` is an apply-time reject (the
    /// any-signer footgun); the port itself does not enforce that policy
    /// rule (it is a verify-time input only). The verifier accepts a
    /// signature whose observed `{issuer, san}` matches **any** pattern
    /// here ([`SignerIdentityPattern::matches`](crate::entities::scan_policy::SignerIdentityPattern::matches)).
    pub allowed_identities: &'a [SignerIdentityPattern],
}

/// Why a verifier rejected an attestation.
///
/// Each variant is a distinct, audited rejection cause carried on the
/// emitted `ProvenanceRejected` event so an operator can tell a forged
/// signature (`UntrustedIdentity`) from a structurally-broken bundle
/// (`BundleMalformed`) from an unsigned-under-`Required` artifact
/// (`Unsigned`).
///
/// Carries `Serialize`/`Deserialize` because it rides the
/// `ProvenanceRejected` event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceRejectReason {
    /// No attestation was present and policy required one (`Required`
    /// mode maps the orchestrator's `NoAttestation` to this).
    Unsigned,
    /// A valid signature whose `{issuer, san}` is not in the allowed set.
    UntrustedIdentity,
    /// The bundle's Rekor transparency-log entry is not provably in the
    /// log: the Merkle inclusion proof or the checkpoint signature failed to
    /// verify against the trust root's Rekor public key, or the tlog
    /// material is structurally absent / unparseable. The Sigstore adapter
    /// verifies this cryptographically and fully offline (RFC-6962 Merkle
    /// inclusion + checkpoint signature, v0.3 bundle format); it is
    /// **never** a fall-back to a live Rekor fetch. This catches both a
    /// structurally absent proof and a forged-but-well-formed one whose
    /// entry is not in the log.
    RekorNotFound,
    /// The Fulcio certificate chain failed validation against the cached
    /// trust root.
    CertChainInvalid,
    /// The bundle is structurally malformed or carries no
    /// offline-verifiable material (e.g. a bare signature, no SET).
    BundleMalformed,
}

/// The outcome of a single verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceOutcome {
    /// A trusted signature was verified. Carries the matched signer and
    /// the attestation predicate type (e.g. an in-toto / SLSA predicate
    /// URI) for the audit record. Like `ScanCompleted(clean)`, a
    /// `Verified` outcome does **not** release the artifact early — it
    /// only records success and (under `Required`) clears the release
    /// gate.
    Verified {
        /// The signer identity the signature matched.
        signer: SignerIdentity,
        /// The attestation predicate type URI (e.g.
        /// `https://slsa.dev/provenance/v1`). `None` for a bare signature
        /// with no structured predicate.
        predicate_type: Option<String>,
    },
    /// Verification failed for a typed reason.
    Rejected(ProvenanceRejectReason),
    /// No bundle was found / passed — the unsigned case. Under
    /// `VerifyIfPresent` this is allowed (no event); under `Required` the
    /// orchestrator maps it to `Rejected(Unsigned)`.
    NoAttestation,
}

/// A verifier's verdict for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceVerdict {
    /// The verification outcome.
    pub outcome: ProvenanceOutcome,
}

impl ProvenanceVerdict {
    /// Convenience constructor for a verified verdict.
    pub fn verified(signer: SignerIdentity, predicate_type: Option<String>) -> Self {
        Self {
            outcome: ProvenanceOutcome::Verified {
                signer,
                predicate_type,
            },
        }
    }

    /// Convenience constructor for a rejected verdict.
    pub fn rejected(reason: ProvenanceRejectReason) -> Self {
        Self {
            outcome: ProvenanceOutcome::Rejected(reason),
        }
    }

    /// Convenience constructor for the no-attestation (unsigned) verdict.
    pub fn no_attestation() -> Self {
        Self {
            outcome: ProvenanceOutcome::NoAttestation,
        }
    }
}

/// Outbound port for a supply-chain provenance verifier (cosign, and
/// Tier-2 PGP / PEP-740 / cargo verifiers).
///
/// Verifier adapters live in their own per-backend crates
/// (`hort-adapters-provenance-<name>`) and depend only on `hort-domain`.
/// The composition root stores them as `Arc<dyn ProvenancePort>` and the
/// orchestrator dispatches the one whose [`applies_to`](Self::applies_to)
/// matches the ingested artifact's format.
pub trait ProvenancePort: Send + Sync {
    /// Stable identifier used in `ScanPolicy.provenance_backends`
    /// (`"cosign"`). Must match the registry name registered at startup.
    fn name(&self) -> &str;

    /// Whether this verifier can verify the given repository format
    /// (`cosign` → `"oci"`; a Tier-2 PGP verifier → `"maven"`). The
    /// orchestrator enqueues a `provenance-verify` job only when some
    /// registered port `applies_to(format)`, so a non-OCI ingest under
    /// the Tier-1 cosign-only set is zero-overhead.
    fn applies_to(&self, format: &str) -> bool;

    /// Verify the artifact's attestation bundles against the policy's
    /// allowed signer identities and return a typed verdict.
    ///
    /// `bundles` may be empty (the unsigned case) — the adapter returns
    /// [`ProvenanceOutcome::NoAttestation`], **not** an error. A fetch /
    /// infra failure is the orchestrator's concern; this method decides
    /// only on the bundles it is handed.
    fn verify<'a>(
        &'a self,
        artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [AttestationBundle],
        policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>>;

    /// Health check invoked at worker startup. For the Sigstore adapter
    /// this verifies the cached trust root is loaded and within its TUF
    /// refresh window (it does **not** probe live Rekor/Fulcio). Failure
    /// means the backend is not deployable; the worker logs and exits
    /// non-zero.
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_hash() -> ContentHash {
        VALID_SHA256.parse().unwrap()
    }

    fn sample_identity() -> SignerIdentity {
        SignerIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        }
    }

    fn sample_pattern() -> SignerIdentityPattern {
        SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
        )
        .expect("sample pattern is valid")
    }

    /// Compile-time assertion that `ProvenancePort` is dyn-compatible
    /// (mirrors `ScannerPort`'s `scanner_port_is_dyn_compatible`).
    /// Runtime: `size_of` executes in the test body for coverage.
    #[test]
    fn provenance_port_is_dyn_compatible() {
        let _ = size_of::<&dyn ProvenancePort>();
    }

    /// `Box<dyn ProvenancePort>` resolves — proves the trait can be
    /// type-erased into an owned trait object the composition root stores.
    #[test]
    fn provenance_port_can_be_boxed() {
        let _: Option<Box<dyn ProvenancePort>> = None;
    }

    /// Trait-object dispatch + `BoxFuture` shape smoke test, mirroring
    /// `quarantine_release.rs`'s stub-dispatch coverage.
    #[tokio::test]
    async fn verify_dispatches_through_trait_object() {
        struct Stub;
        impl ProvenancePort for Stub {
            fn name(&self) -> &str {
                "cosign"
            }
            fn applies_to(&self, format: &str) -> bool {
                format == "oci"
            }
            fn verify<'a>(
                &'a self,
                _artifact: &'a ProvenanceSubject<'a>,
                bundles: &'a [AttestationBundle],
                _policy: &'a ProvenanceRequirements<'a>,
            ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
                Box::pin(async move {
                    if bundles.is_empty() {
                        Ok(ProvenanceVerdict::no_attestation())
                    } else {
                        Ok(ProvenanceVerdict::verified(sample_identity(), None))
                    }
                })
            }
            fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let port: Box<dyn ProvenancePort> = Box::new(Stub);
        assert_eq!(port.name(), "cosign");
        assert!(port.applies_to("oci"));
        assert!(!port.applies_to("npm"));
        port.health_check().await.expect("health ok");

        let hash = sample_hash();
        let subject = ProvenanceSubject {
            content_hash: &hash,
            payload: b"",
            name: "library/nginx",
            version: Some("1.27.0"),
        };
        let reqs = ProvenanceRequirements {
            allowed_identities: &[],
        };

        // Empty bundles → NoAttestation.
        let verdict = port.verify(&subject, &[], &reqs).await.expect("Ok");
        assert_eq!(verdict, ProvenanceVerdict::no_attestation());

        // Non-empty bundles → Verified.
        let bundles = [AttestationBundle::new(b"{}".to_vec())];
        let verdict = port.verify(&subject, &bundles, &reqs).await.expect("Ok");
        assert_eq!(
            verdict,
            ProvenanceVerdict::verified(sample_identity(), None)
        );
    }

    /// `ProvenanceSubject` is a cheap `Copy` view (no allocation), and
    /// its fields round-trip.
    #[test]
    fn provenance_subject_is_copy_view() {
        let hash = sample_hash();
        let subject = ProvenanceSubject {
            content_hash: &hash,
            payload: b"manifest",
            name: "pkg",
            version: Some("1.0.0"),
        };
        let copied = subject;
        assert_eq!(copied, subject);
        assert_eq!(copied.content_hash, &hash);
        assert_eq!(copied.payload, b"manifest");
        assert_eq!(copied.name, "pkg");
        assert_eq!(copied.version, Some("1.0.0"));
    }

    /// `AttestationBundle::new` wraps bytes and `bytes` reads them back.
    #[test]
    fn attestation_bundle_wraps_bytes() {
        let b = AttestationBundle::new(vec![1, 2, 3]);
        assert_eq!(b.bytes, vec![1, 2, 3]);
        assert_eq!(b.clone(), b);
    }

    /// `ProvenanceRequirements` is a `Copy` borrow over the identity
    /// *patterns* (it carries
    /// `SignerIdentityPattern`, not the concrete `SignerIdentity`).
    #[test]
    fn provenance_requirements_is_copy_borrow() {
        let ids = [sample_pattern()];
        let reqs = ProvenanceRequirements {
            allowed_identities: &ids,
        };
        let copied = reqs;
        assert_eq!(copied, reqs);
        assert_eq!(copied.allowed_identities.len(), 1);
    }

    /// `SignerIdentity` carries the `{issuer, san}` shape and round-trips
    /// on clone/eq.
    #[test]
    fn signer_identity_issuer_san_shape() {
        let id = sample_identity();
        let cloned = id.clone();
        assert_eq!(id, cloned);
        assert_eq!(id.issuer, "https://token.actions.githubusercontent.com");
        assert!(id.san.contains("release.yml"));
    }

    /// Every [`ProvenanceRejectReason`] variant constructs and round-trips
    /// (Copy + Eq + Debug), covering the full reason set.
    #[test]
    fn every_reject_reason_constructs_and_round_trips() {
        let reasons = [
            ProvenanceRejectReason::Unsigned,
            ProvenanceRejectReason::UntrustedIdentity,
            ProvenanceRejectReason::RekorNotFound,
            ProvenanceRejectReason::CertChainInvalid,
            ProvenanceRejectReason::BundleMalformed,
        ];
        for r in reasons {
            let copied = r;
            assert_eq!(copied, r);
            // Debug is non-empty (covers the derive).
            assert!(!format!("{r:?}").is_empty());
            // Each constructs a rejected verdict that preserves the reason.
            let verdict = ProvenanceVerdict::rejected(r);
            assert_eq!(verdict.outcome, ProvenanceOutcome::Rejected(r));
        }
    }

    /// The three verdict constructors build the three outcomes.
    #[test]
    fn verdict_constructors_build_each_outcome() {
        let v = ProvenanceVerdict::verified(sample_identity(), Some("pred".into()));
        assert_eq!(
            v.outcome,
            ProvenanceOutcome::Verified {
                signer: sample_identity(),
                predicate_type: Some("pred".into()),
            }
        );

        let r = ProvenanceVerdict::rejected(ProvenanceRejectReason::CertChainInvalid);
        assert_eq!(
            r.outcome,
            ProvenanceOutcome::Rejected(ProvenanceRejectReason::CertChainInvalid)
        );

        let n = ProvenanceVerdict::no_attestation();
        assert_eq!(n.outcome, ProvenanceOutcome::NoAttestation);
    }
}
