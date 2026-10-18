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
    /// The raw bundle bytes. For a keyless v0.3 bundle (`signature == None`)
    /// this is the cosign `*.sigstore`/`*.bundle` JSON; for a keyed cosign
    /// `simplesigning` `.sig` (`signature == Some`) this is the `simplesigning`
    /// payload-layer blob the signature is computed over (ADR 0039 §8).
    pub bytes: Vec<u8>,
    /// The detached raw signature bytes, present **only** for the keyed cosign
    /// `simplesigning` shape (the base64 `dev.cosignproject.cosign/signature`
    /// annotation, decoded). `None` for a keyless v0.3 bundle (whose signature
    /// material lives inside `bytes`). The keyed verifier requires `Some`; the
    /// Sigstore verifier ignores it.
    pub signature: Option<Vec<u8>>,
}

impl AttestationBundle {
    /// Wrap raw bundle bytes with no detached signature — the keyless v0.3
    /// bundle shape (`signature == None`).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            signature: None,
        }
    }

    /// Wrap a keyed cosign `simplesigning` payload (`bytes`) + its detached raw
    /// signature (ADR 0039 §8). The keyed verifier checks `signature` over
    /// `bytes` against the pinned key and binds the payload's claimed manifest
    /// digest.
    pub fn new_signed(bytes: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            bytes,
            signature: Some(signature),
        }
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

/// Why a verifier rejected an attestation — **a finding about material it
/// could read**.
///
/// Each variant is a distinct, audited rejection cause carried on the
/// emitted `ProvenanceRejected` event so an operator can tell a forged
/// signature (`UntrustedIdentity`) from a structurally-broken bundle
/// (`BundleMalformed`) from an unsigned-under-`Required` artifact
/// (`Unsigned`).
///
/// **Every variant here is a positive disproof, and only a positive
/// disproof is terminal** (ADR 0039 D4). A failure of *our own* ability to
/// check — a trust root with no usable key, attestation material that could
/// never be fetched, a verifier that did not return a verdict — proves
/// nothing about the artifact and belongs to
/// [`IndeterminateReason`], which holds instead. There is deliberately **no**
/// `From<IndeterminateReason>` for this type: that conversion is the one
/// thing that would re-open the line, letting "we could not check" be
/// spelled as "proved bad" at a call site a reviewer reads as a formality.
///
/// The line needs no source-scan guard. It is a compile error:
/// [`ProvenanceOutcome::Rejected`] does not accept an
/// [`IndeterminateReason`], and the matches over [`ProvenanceOutcome`] are
/// wildcard-free, so a future outcome must be classified before it compiles.
/// A grep guard on top would imply that compile-time property is
/// insufficient, and the next reader would reasonably trust the weaker of
/// the two.
///
/// Carries `Serialize`/`Deserialize` because it rides the
/// `ProvenanceRejected` event payload. **Adding a variant is forward-only**:
/// the derive is externally tagged, so a build predating a variant cannot
/// deserialise an event carrying it. That is the same class as adding a new
/// `DomainEvent` type — a rollback past the vocabulary cannot read streams
/// written after it — and not a new hazard; it is why no variant is ever
/// removed or renamed here, only added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceRejectReason {
    /// No attestation was present and policy required one.
    ///
    /// **No producer remains.** The `Required`-mode policy mapping that
    /// emitted it was removed by ADR 0039's 2026-09-12 amendment (D1 —
    /// an unsigned artifact holds), and no verifier produces it. The
    /// variant stays because persisted `ProvenanceRejected` events on
    /// existing streams carry it and must keep deserialising; the
    /// merge-ranking below keeps ordering it last for the same reason.
    Unsigned,
    /// A valid signature whose `{issuer, san}` is not in the allowed set.
    UntrustedIdentity,
    /// The bundle's Rekor transparency-log entry is not provably in the
    /// log: a **present, readable** Merkle inclusion proof or checkpoint
    /// signature failed to verify against the trust root's Rekor public
    /// key. The Sigstore adapter verifies this cryptographically and fully
    /// offline (RFC-6962 Merkle inclusion + checkpoint signature, v0.3
    /// bundle format); it is **never** a fall-back to a live Rekor fetch.
    /// The case it exists for is a forged-but-well-formed entry whose
    /// proof does not check out.
    ///
    /// **Four neighbouring failures no longer reach it**, because none of
    /// them proves anything about the artifact (ADR 0039 D4):
    ///
    /// - transparency-log material that is **structurally absent or
    ///   unparseable** is *skipped* — that candidate contributes no
    ///   verdict at all, so this variant's wording no longer covers it;
    /// - a trust root holding **no usable key** for the entry's log is
    ///   [`IndeterminateReason::TrustRootUnusable`] — our provisioning,
    ///   not the publisher's signature;
    /// - attestation material that could **never be fetched** is
    ///   [`IndeterminateReason::AttestationFetchFailed`]. The
    ///   orchestration's fetch-exhaustion path stated this variant until
    ///   it held instead, and that was precisely the use the "never a
    ///   live Rekor fetch" sentence above forbids: nothing offline or
    ///   cryptographic had happened at all;
    /// - a dispatched verifier that **returned no verdict at all** is
    ///   [`IndeterminateReason::VerifierUnavailable`]. That was the last
    ///   orchestration-side producer of this variant, which leaves the
    ///   keyless verifier's offline inclusion check as its **only**
    ///   producer in the workspace — i.e. the wording above now describes
    ///   every event that carries it.
    RekorNotFound,
    /// The Fulcio certificate chain failed validation against the cached
    /// trust root.
    CertChainInvalid,
    /// The bundle is structurally malformed or carries no
    /// offline-verifiable material (e.g. a bare signature, no SET).
    ///
    /// **Unreadable material no longer produces it.** A candidate a
    /// verifier cannot parse or decode proves nothing about the artifact,
    /// so it is skipped and contributes no verdict at all — the keyless
    /// verifier's parse / leaf-cert / certificate-decode / identity gates
    /// and the unreadable arms of its error classification all `continue`
    /// now, and the keyed verifier's undecodable-payload and
    /// undecodable-signature outcomes do the same.
    ///
    /// **No producer remains.** The keyed verifier's digest-binding
    /// failure was the last one, and it states [`Self::DigestMismatch`]
    /// now — the reason it was in substance all along, and the one an
    /// operator can act on: a re-tagged signature and a corrupt upload
    /// called for opposite responses while sharing this variant.
    ///
    /// The variant stays regardless: persisted `ProvenanceRejected` events
    /// carry it and must keep deserialising, exactly as [`Self::Unsigned`]
    /// does, and the keyless verifier's reject-reason ranking keeps its
    /// rung for the same reason.
    BundleMalformed,
    /// A signature that verifies — against a pinned key or a trusted
    /// chain — but covers a **different digest** than the artifact being
    /// served: the re-tag attack. The `sha256-<hex>.sig` carriage tag is
    /// attacker-writable in the registry, so a valid signature for image A
    /// re-tagged onto image B must reject, and it is the strongest
    /// disproof the pipeline can state: the crypto succeeded and still
    /// says this is not the signed artifact.
    ///
    /// Distinct from [`Self::BundleMalformed`] because the audit record
    /// has to separate an attack from a corrupt upload — they are the
    /// same variant's two halves today, and an operator cannot tell them
    /// apart.
    ///
    /// Appended last because the declaration order is not the wire form
    /// (unit variants serialise as their names) and not the reject-reason
    /// precedence either (that ranking lives in the verifier adapter that
    /// folds several per-bundle reasons into one).
    DigestMismatch,
}

/// Why a verification **could not be carried out**. *Our* side: nothing
/// about the artifact's material was established, so nothing was
/// disproved, and the artifact is HELD — never rejected (ADR 0039 D4,
/// terminality only from positive disproof; D2, fail-closed is not the
/// same as terminal).
///
/// Material that *was* readable and failed is a
/// [`ProvenanceRejectReason`]; the two types are separate because the
/// outcomes are separate, and the separation is what makes the line a
/// compile error rather than a convention. See that type's rustdoc for
/// why no conversion between them exists and why no source-scan guard
/// accompanies this.
///
/// Carries `Serialize`/`Deserialize` for symmetry with
/// [`ProvenanceRejectReason`] and so a future hold record can carry the
/// reason; **no event payload references it today** (a hold emits no
/// event at all — that absence *is* the hold).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndeterminateReason {
    /// Attestation material could not be obtained at all — the fetch
    /// failed, exhausted its retries, or the CAS read behind it did. The
    /// bundle may be present and perfectly valid; we never saw it.
    AttestationFetchFailed,
    /// The trust root holds no usable key for this check — no Rekor key
    /// matches the entry's log id, our own key bytes did not parse, or the
    /// root carries no Fulcio certs / CTFE keys and so cannot build a
    /// verifier at all. An operator provisioning fault, not a finding
    /// about the artifact: the publisher's signature is not implicated by
    /// our inability to load a key.
    TrustRootUnusable,
    /// A verifier we dispatched did not return a verdict — the adapter
    /// itself failed. The material was fetched and handed over; what did
    /// not work is the check.
    ///
    /// **The category, where its two neighbours are causes.** An adapter
    /// error is reachable from several of them (a trust root that cannot
    /// build a verifier, a subject-payload/content-hash mismatch, an
    /// internal fault), and the orchestration cannot see which: it holds
    /// a `DomainError` and nothing more. Naming it
    /// [`Self::TrustRootUnusable`] would assert one cause out of several,
    /// and [`Self::AttestationFetchFailed`] would assert the material was
    /// never obtained when in fact it was read — so the honest value is
    /// its own.
    ///
    /// Reported exactly as the other two are (`held_indeterminate` under
    /// `Required`, `allowed_indeterminate` otherwise), because the
    /// epistemic state is the same: nothing about the artifact was
    /// established. Contributing *nothing* instead would be worse than
    /// either lie — an all-verifiers-errored run would fold to
    /// [`ProvenanceOutcome::NoAttestation`] and send the operator to the
    /// publisher's signer for a fault of ours.
    VerifierUnavailable,
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
    /// artifact is HELD (`Quarantined`, `Pending` at the release gate,
    /// 503 to a pull) until a signature arrives. It is never terminal:
    /// "no signature has reached Hort yet" is a statement about a point
    /// in time, not about the artifact (ADR 0039's 2026-09-12 amendment,
    /// D1).
    NoAttestation,
    /// The check could not be carried out — see [`IndeterminateReason`].
    /// A hold, with exactly the shape [`Self::NoAttestation`] has: no
    /// event, no status change, `Pending` at the release gate under
    /// `Required` (fail-closed, 503), the normal quarantine window under
    /// `VerifyIfPresent` / `Off`.
    ///
    /// Never terminal, and for a stronger reason than `NoAttestation`'s:
    /// an unsigned artifact at least has a fact about it recorded (no
    /// signature had arrived), while here *nothing* about the artifact was
    /// established. A publisher's artifact must not go terminal because
    /// our trust root was misprovisioned, a network call failed, or our
    /// verifier could not run — nobody's material is at fault
    /// (ADR 0039 D4).
    Indeterminate(IndeterminateReason),
}

/// A verifier's verdict for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceVerdict {
    /// The verification outcome.
    pub outcome: ProvenanceOutcome,
    /// How many candidates the verifier **could not read**, and therefore
    /// did not take into account when reaching [`Self::outcome`].
    ///
    /// Material a verifier cannot parse or decode proves nothing about the
    /// artifact, so it contributes nothing to the verdict: not a
    /// rejection, not a hold, not evidence of any kind. It is skipped,
    /// exactly as a candidate belonging to another backend is. This count
    /// is the whole difference between *not considered* and *not noticed*
    /// — without it, a publisher whose own signature material is broken
    /// would see only "unsigned", and an operator would never learn that
    /// someone attached garbage to an artifact.
    ///
    /// Deliberately **orthogonal to the outcome**: a non-zero count can
    /// accompany any of the four, `Verified` included (one candidate
    /// verified while a sibling was unreadable). It is reporting only and
    /// gates nothing — it reaches the job's `result_summary`, a log line
    /// and a counter, and no decision reads it.
    ///
    /// Counted per candidate the verifier **examined**. A verifier that
    /// short-circuits on its first acceptance has not examined what
    /// follows, so a later unreadable candidate is not counted (it was
    /// never skipped — it was never looked at).
    pub unreadable_skipped: u32,
}

impl ProvenanceVerdict {
    /// Convenience constructor for a verified verdict.
    pub fn verified(signer: SignerIdentity, predicate_type: Option<String>) -> Self {
        Self {
            outcome: ProvenanceOutcome::Verified {
                signer,
                predicate_type,
            },
            unreadable_skipped: 0,
        }
    }

    /// Convenience constructor for a rejected verdict.
    pub fn rejected(reason: ProvenanceRejectReason) -> Self {
        Self {
            outcome: ProvenanceOutcome::Rejected(reason),
            unreadable_skipped: 0,
        }
    }

    /// Convenience constructor for the no-attestation (unsigned) verdict.
    pub fn no_attestation() -> Self {
        Self {
            outcome: ProvenanceOutcome::NoAttestation,
            unreadable_skipped: 0,
        }
    }

    /// Convenience constructor for the indeterminate (could-not-check)
    /// verdict — a hold, never a rejection.
    pub fn indeterminate(reason: IndeterminateReason) -> Self {
        Self {
            outcome: ProvenanceOutcome::Indeterminate(reason),
            unreadable_skipped: 0,
        }
    }

    /// Record that `count` candidates were skipped as unreadable while
    /// reaching this verdict (see [`Self::unreadable_skipped`]).
    ///
    /// A builder rather than a constructor argument: every verdict carries
    /// the count, including the three the four constructors above build
    /// with nothing skipped, and an adapter that skips nothing should not
    /// have to say so.
    #[must_use]
    pub fn with_unreadable_skipped(mut self, count: u32) -> Self {
        self.unreadable_skipped = count;
        self
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

    /// Every rejection cause the vocabulary has. Listed once so a new
    /// variant is added in one place and both reason tests below see it.
    const ALL_REJECT_REASONS: [ProvenanceRejectReason; 6] = [
        ProvenanceRejectReason::Unsigned,
        ProvenanceRejectReason::UntrustedIdentity,
        ProvenanceRejectReason::RekorNotFound,
        ProvenanceRejectReason::CertChainInvalid,
        ProvenanceRejectReason::BundleMalformed,
        ProvenanceRejectReason::DigestMismatch,
    ];

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

    /// `AttestationBundle::new` wraps bytes (unsigned), and `new_signed`
    /// carries the detached signature (ADR 0039 §8).
    #[test]
    fn attestation_bundle_wraps_bytes() {
        let b = AttestationBundle::new(vec![1, 2, 3]);
        assert_eq!(b.bytes, vec![1, 2, 3]);
        assert_eq!(b.signature, None);
        assert_eq!(b.clone(), b);

        let signed = AttestationBundle::new_signed(vec![4, 5], vec![9, 9]);
        assert_eq!(signed.bytes, vec![4, 5]);
        assert_eq!(signed.signature, Some(vec![9, 9]));
        assert_ne!(signed, b);
        assert_eq!(signed.clone(), signed);
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
        for r in ALL_REJECT_REASONS {
            let copied = r;
            assert_eq!(copied, r);
            // Debug is non-empty (covers the derive).
            assert!(!format!("{r:?}").is_empty());
            // Each constructs a rejected verdict that preserves the reason.
            let verdict = ProvenanceVerdict::rejected(r);
            assert_eq!(verdict.outcome, ProvenanceOutcome::Rejected(r));
        }
    }

    /// Every reject reason's **wire form** is its variant name, and every
    /// one of them deserialises back. The type rides the persisted
    /// `ProvenanceRejected` payload, so the string is the compatibility
    /// surface: a rename is a stream that stops loading. (The
    /// whole-payload load is pinned beside the event itself, in
    /// `events::artifact_events`.)
    #[test]
    fn every_reject_reason_serialises_as_its_variant_name() {
        let expected = [
            "Unsigned",
            "UntrustedIdentity",
            "RekorNotFound",
            "CertChainInvalid",
            "BundleMalformed",
            "DigestMismatch",
        ];
        assert_eq!(ALL_REJECT_REASONS.len(), expected.len());
        for (r, name) in ALL_REJECT_REASONS.into_iter().zip(expected) {
            let json = serde_json::to_value(r).expect("serialises");
            assert_eq!(json, serde_json::json!(name), "{r:?}");
            let back: ProvenanceRejectReason = serde_json::from_value(json).expect("deserialises");
            assert_eq!(back, r);
        }
    }

    /// Every [`IndeterminateReason`] variant constructs, round-trips on
    /// the wire, and reaches a verdict through
    /// [`ProvenanceVerdict::indeterminate`] — which produces
    /// [`ProvenanceOutcome::Indeterminate`] and nothing else. There is no
    /// path from one of these to a [`ProvenanceRejectReason`]: the absence
    /// of that conversion is what keeps "we could not check" from being
    /// spelled as "proved bad".
    ///
    /// The three are also **pairwise distinct**, which is the property the
    /// vocabulary exists for: each names a different thing that did not
    /// work on our side, and a variant quietly standing in for another
    /// would satisfy every "is it held?" assertion in the suite.
    #[test]
    fn every_indeterminate_reason_constructs_and_round_trips() {
        let expected = [
            (
                IndeterminateReason::AttestationFetchFailed,
                "AttestationFetchFailed",
            ),
            (IndeterminateReason::TrustRootUnusable, "TrustRootUnusable"),
            (
                IndeterminateReason::VerifierUnavailable,
                "VerifierUnavailable",
            ),
        ];
        for (r, name) in expected {
            let copied = r;
            assert_eq!(copied, r);
            assert!(!format!("{r:?}").is_empty());

            let json = serde_json::to_value(r).expect("serialises");
            assert_eq!(json, serde_json::json!(name), "{r:?}");
            let back: IndeterminateReason = serde_json::from_value(json).expect("deserialises");
            assert_eq!(back, r);

            let verdict = ProvenanceVerdict::indeterminate(r);
            assert_eq!(verdict.outcome, ProvenanceOutcome::Indeterminate(r));
            // The outcome's own derives, on the new variant.
            assert_eq!(verdict.clone(), verdict);
            assert!(!format!("{:?}", verdict.outcome).is_empty());
        }
        // Pairwise distinct over the whole vocabulary, not just the first
        // two: three reasons that compared equal would make the holds
        // indistinguishable without changing a single hold's behaviour.
        for (i, (a, _)) in expected.iter().enumerate() {
            for (b, _) in &expected[i + 1..] {
                assert_ne!(a, b, "{a:?} vs {b:?}");
            }
        }
    }

    /// The four verdict constructors build the four outcomes.
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

        let i = ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable);
        assert_eq!(
            i.outcome,
            ProvenanceOutcome::Indeterminate(IndeterminateReason::TrustRootUnusable)
        );

        // A rejection and a hold are never equal, whatever they carry —
        // the two reason vocabularies do not meet.
        assert_ne!(r.outcome, i.outcome);
        assert_ne!(n.outcome, i.outcome);
    }

    /// Every constructor starts at nothing skipped, and
    /// `with_unreadable_skipped` is the only thing that moves the count.
    /// Nothing about a verdict built the ordinary way claims an unreadable
    /// candidate.
    #[test]
    fn every_constructor_starts_with_nothing_skipped() {
        let built = [
            ProvenanceVerdict::verified(sample_identity(), None),
            ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
            ProvenanceVerdict::no_attestation(),
            ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable),
        ];
        for v in built {
            assert_eq!(v.unreadable_skipped, 0, "{:?}", v.outcome);
            let carried = v.clone().with_unreadable_skipped(3);
            assert_eq!(carried.unreadable_skipped, 3);
            // The count is orthogonal: carrying it changes nothing about
            // the outcome it accompanies.
            assert_eq!(carried.outcome, v.outcome);
        }
    }

    /// The count rides **every** outcome, `Verified` included — one
    /// candidate verified while a sibling was unreadable is exactly the
    /// case the attack this field exists for produces, and a type that
    /// could only carry the count on a rejection would lose it there.
    ///
    /// It is also part of the verdict's identity: two verdicts that agree
    /// on the outcome and disagree on how much was skipped are not the
    /// same verdict, which is what keeps a fold from silently discarding
    /// the record.
    #[test]
    fn the_skip_count_rides_every_outcome_and_is_part_of_verdict_identity() {
        let verified = ProvenanceVerdict::verified(sample_identity(), None);
        let with_skip = verified.clone().with_unreadable_skipped(1);
        assert!(matches!(
            with_skip.outcome,
            ProvenanceOutcome::Verified { .. }
        ));
        assert_eq!(with_skip.unreadable_skipped, 1);
        assert_ne!(with_skip, verified);

        // The builder is total over the range, not a flag.
        assert_eq!(
            ProvenanceVerdict::no_attestation()
                .with_unreadable_skipped(u32::MAX)
                .unreadable_skipped,
            u32::MAX
        );
        // Last call wins (the adapters set it once, at the end of a fold).
        assert_eq!(
            ProvenanceVerdict::no_attestation()
                .with_unreadable_skipped(2)
                .with_unreadable_skipped(5)
                .unreadable_skipped,
            5
        );
    }
}
