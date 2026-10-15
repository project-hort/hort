//! Offline bundle verification core (ADR 0027).
//!
//! Given the cached trust root, the artifact digest, and the raw bundles,
//! [`verify_bundles`] runs `sigstore`'s offline cryptographic verification
//! and folds the result — together with the domain glob identity match —
//! into one [`ProvenanceVerdict`].
//!
//! The Fulcio chain → trust root, embedded SCT, signature, and digest
//! binding are `sigstore`'s `verify_digest`; the **Rekor Merkle inclusion
//! proof + checkpoint signature** are verified by [`crate::inclusion`]
//! immediately after `verify_digest` succeeds (sigstore 0.14 does not — see
//! the crate-level "Rekor inclusion verification" note); the **identity
//! decision** is the domain's exact-or-bounded-glob
//! [`SignerIdentityPattern::matches`] applied to the observed `{issuer,
//! san}` read out of the verified leaf cert ([`crate::identity`]). We drive
//! `sigstore` with a pass-through [`AllowAllPolicy`] precisely so the
//! bounded-glob half of the policy is not silently bypassed by
//! `sigstore`'s exact-literal `Identity` policy.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use sigstore::bundle::verify::{policy::VerificationPolicy, Verifier};
use sigstore::bundle::Bundle;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use hort_domain::entities::scan_policy::SignerIdentityPattern;
use hort_domain::error::DomainResult;
use hort_domain::ports::provenance::{
    AttestationBundle, IndeterminateReason, ProvenanceRejectReason, ProvenanceVerdict,
    SignerIdentity,
};

use crate::identity::observed_identity;
use crate::inclusion::{
    verify_inclusion, InclusionError, InclusionFailureSide, TlogInclusionMaterial,
};

/// Build an offline [`Verifier`] from an owned trust root. Fails when the
/// trust root carries no Fulcio certs / CTFE keys — a root we cannot
/// check *anything* against, which is a fault on our side and not a
/// statement about any publisher's chain (the caller holds rather than
/// rejects, and the worker refuses to boot on such a root at all).
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
/// 4. otherwise `Indeterminate` — a check this verifier could not carry
///    out, because our own trust root held no usable Rekor key for the
///    entry's log, or carried no Fulcio certs / CTFE keys and so could
///    not build a verifier at all;
/// 5. otherwise `NoAttestation` — nothing readable was found, so this
///    verifier has nothing to say about the artifact.
///
/// **Only readable material from which something was actually proved can
/// condemn an artifact.** Rungs 2 and 3 are findings about material this
/// verifier read: a chain that did not validate, an inclusion proof that
/// did not verify, an identity that is not allowed. A candidate the
/// verifier could not read is none of those — it is `continue`d in the
/// same loop position as a bundle belonging to the other backend, and it
/// never reaches [`merge_reason`], never becomes `best`, never folds.
/// That is why rung 5 is `NoAttestation` and not a structural rejection:
/// with nothing readable in the set, the honest answer is silence, which
/// under `Required` is the indefinite hold and under `VerifyIfPresent` is
/// the allow — both already defined, no new state.
///
/// **Rungs 4 and 5 are the same state and must stay different answers.**
/// Both hold under `Required`, so the artifact's state does not tell them
/// apart and no transition does either — but rung 4 names *our*
/// provisioning ("fix the trust root", and the held
/// artifact verifies on the next run once it is fixed) while rung 5
/// says the artifact carries no usable signature ("sign it"). Same state,
/// different operator action, which is the only thing the distinction is
/// for: collapsing them into one label would lose it. Rung 4 sits below
/// every rejection because a finding about the material beats "we could
/// not check", and above rung 5 because it is the more informative hold.
///
/// The skip is **recorded**, not silent: the returned verdict carries
/// [`ProvenanceVerdict::unreadable_skipped`], the count of candidates
/// this verifier examined and could not read. Rung 1 short-circuits, so a
/// candidate sitting after the first `Verified` is never examined and
/// never counted.
///
/// `bundles` is guaranteed non-empty by the caller. `make_verifier` builds
/// a fresh offline [`Verifier`] from the cached trust root on demand —
/// it is called **only** for a bundle that has already parsed and yielded
/// a readable leaf identity, so an unreadable bundle is skipped **before**
/// any trust-root-dependent step (a broken or empty trust root never turns
/// an unreadable candidate into a chain finding).
///
/// `sigstore::Verifier::new` consumes its `TrustRoot` by value and the
/// root is not `Clone`, so the factory hands back a fresh owned `Verifier`
/// per crypto call. The factory itself fails (returns `Err`) when the
/// trust root carries no Fulcio certs / CTFE keys — that is rung 4 for
/// *that* bundle, a hold: the chain was never examined, so nothing about
/// it was established.
pub(crate) async fn verify_bundles<F>(
    make_verifier: F,
    payload: &[u8],
    bundles: &[AttestationBundle],
    allowed: &[SignerIdentityPattern],
    rekor_keys: &BTreeMap<String, Vec<u8>>,
) -> ProvenanceVerdict
where
    F: Fn() -> DomainResult<Verifier>,
{
    let mut fold = Fold::default();

    for bundle in bundles {
        // Skip keyed (cosign-key `simplesigning`) bundles — `signature.is_some()`
        // means the keyed verifier owns this one (ADR 0039 §8). This verifier
        // reads ONLY keyless v0.3 bundles; a keyed bundle is not a v0.3 bundle
        // and must NOT be rejected here. A worker running BOTH backends hands the
        // same bundle set to both verifiers; the keyed verifier symmetrically
        // skips `signature.is_none()`, so the two cleanly partition the set and
        // the OR-fold never false-rejects a validly keyed-signed artifact.
        //
        // A keyed bundle is not counted as unreadable: it was not read because
        // it is not ours, which is a different statement from "we could not
        // read it" and would make every keyed-signed artifact look like it
        // carried garbage.
        if bundle.signature.is_some() {
            continue;
        }
        let outcome = verify_one(&make_verifier, payload, &bundle.bytes, allowed, rekor_keys).await;
        if let Some(verdict) = fold.observe(outcome) {
            return verdict;
        }
    }

    fold.finish()
}

/// The running fold across candidates: the most authoritative answer a
/// candidate the verifier **read** has contributed so far, plus the count
/// of candidates it could not read.
///
/// [`verify_bundles`] keeps the loop — rung 1 short-circuits, which is a
/// `return` — but everything the loop *does* with a candidate's outcome
/// happens here. That split is load-bearing rather than tidy: no offline
/// fixture can carry a bundle past `verify_digest` to the Rekor inclusion
/// step (the chain, SCT, signature and digest bind all have to pass
/// first), so the three answers an inclusion failure produces are not
/// reachable through `verify_bundles` in a test at all. With the fold
/// named, a test hands an outcome straight to the same two functions the
/// loop drives instead of restating their decisions.
#[derive(Default)]
struct Fold {
    /// The most authoritative answer so far — see [`merge_reason`].
    /// `None` means no candidate the verifier could read has contributed
    /// anything.
    best: Option<CandidateAnswer>,
    /// How many candidates were examined and could not be read.
    unreadable: u32,
}

impl Fold {
    /// Take one candidate's outcome. `Some(verdict)` ends the fold — that
    /// candidate verified, and the first `Verified` wins; `None` means the
    /// candidate's contribution was recorded and the loop continues.
    fn observe(&mut self, outcome: BundleVerify) -> Option<ProvenanceVerdict> {
        match outcome {
            BundleVerify::Verified {
                signer,
                predicate_type,
            } => Some(
                ProvenanceVerdict::verified(signer, predicate_type)
                    .with_unreadable_skipped(self.unreadable),
            ),
            BundleVerify::Rejected(reason) => {
                self.best = Some(merge_reason(self.best, CandidateAnswer::Rejected(reason)));
                None
            }
            BundleVerify::Indeterminate(reason) => {
                self.best = Some(merge_reason(
                    self.best,
                    CandidateAnswer::Indeterminate(reason),
                ));
                None
            }
            // Unreadable: counted and dropped. It sets no `best`, so it
            // cannot become the verdict, and it cannot shadow a sibling's
            // real finding either.
            BundleVerify::Unreadable => {
                self.unreadable = self.unreadable.saturating_add(1);
                None
            }
        }
    }

    /// The verdict this verifier reached with no candidate having
    /// verified.
    ///
    /// `best` is `Some` only if some candidate was readable AND did not
    /// pass — a finding about its material, or a check we could not carry
    /// out on it. Otherwise this verifier has nothing to attest: the set
    /// was empty, or all keyed (the keyed verifier, if registered,
    /// decides), or everything in it was unreadable. All three are the
    /// same answer — NoAttestation, never a reject.
    ///
    /// The match is wildcard-free, which is what keeps the two holds
    /// apart: a rejection and an indeterminate read off the same `best`
    /// into two different verdicts, and a third kind of answer has to say
    /// which verdict it is before it compiles.
    fn finish(self) -> ProvenanceVerdict {
        match self.best {
            Some(CandidateAnswer::Rejected(reason)) => ProvenanceVerdict::rejected(reason),
            Some(CandidateAnswer::Indeterminate(reason)) => {
                ProvenanceVerdict::indeterminate(reason)
            }
            None => ProvenanceVerdict::no_attestation(),
        }
        .with_unreadable_skipped(self.unreadable)
    }
}

/// What a candidate the verifier **read** contributed to the fold: a
/// finding about its material, or our own inability to check it.
///
/// Two domain reason types, held side by side and deliberately not merged
/// — there is no conversion between `ProvenanceRejectReason` and
/// `IndeterminateReason`, and that absence is what makes "we could not
/// check" unable to be spelled as "proved bad". This local enum ranks them
/// against each other without converting either, and [`Fold::finish`]
/// reads two different verdicts off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateAnswer {
    /// A finding about material this verifier read — terminal.
    Rejected(ProvenanceRejectReason),
    /// A check this verifier could not carry out — a hold.
    Indeterminate(IndeterminateReason),
}

/// Keep the more-authoritative answer (lower number wins). See the
/// precedence ladder in [`verify_bundles`].
fn merge_reason(current: Option<CandidateAnswer>, incoming: CandidateAnswer) -> CandidateAnswer {
    fn rank(a: CandidateAnswer) -> u8 {
        match a {
            CandidateAnswer::Rejected(r) => match r {
                // A signature that verified and still covers the wrong
                // digest is the strongest statement any bundle in the set
                // can make, so it shadows every other reason. This adapter
                // does not produce it today — its digest binding happens
                // inside `verify_digest`, whose failure surfaces as a
                // signature / certificate error — but the ladder has to
                // place it, and placing it below a structural complaint
                // would let a malformed sibling bundle hide a re-tag
                // attack.
                ProvenanceRejectReason::DigestMismatch => 0,
                ProvenanceRejectReason::UntrustedIdentity => 1,
                ProvenanceRejectReason::CertChainInvalid => 2,
                ProvenanceRejectReason::RekorNotFound => 3,
                // No path in this verifier produces `BundleMalformed` any
                // more — unreadable material is skipped before it can
                // become a reason. The rung stays because `rank` is total
                // over the wire enum (whose variants are never removed),
                // and because removing it would say the ladder had changed
                // when only its producers did.
                ProvenanceRejectReason::BundleMalformed => 4,
                // Unsigned is an orchestrator-mapped reason, never produced
                // by this adapter; rank it last so it never shadows a real
                // one.
                ProvenanceRejectReason::Unsigned => 5,
            },
            // Below every rejection: a finding about material this verifier
            // read says something about the artifact, and an indeterminate
            // says something about us, so the finding decides. The rung
            // belongs to the *category* rather than to the reason — any
            // future `IndeterminateReason` is still an answer about our own
            // side and inherits this rung correctly — which is why the
            // inner pattern is a binding and not an enumeration. Among
            // indeterminates the first one observed is kept; nothing
            // downstream distinguishes them (the orchestrator's hold label
            // carries no reason), and this adapter produces only
            // `TrustRootUnusable`.
            CandidateAnswer::Indeterminate(_) => 6,
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
    /// A finding about material the verifier **read**: the only outcome
    /// that may condemn the artifact.
    Rejected(ProvenanceRejectReason),
    /// The check could not be carried out on this candidate: our own
    /// trust root held no usable key for its Rekor inclusion proof, or
    /// could not build a verifier at all.
    ///
    /// Not a finding about the artifact — nothing about its material was
    /// established, so nothing was disproved — and so a hold, never a
    /// rejection. It is not counted as unreadable either: the candidate
    /// was perfectly readable, and we were the part that did not work.
    Indeterminate(IndeterminateReason),
    /// The verifier could not read this candidate — unparseable bundle
    /// JSON, no leaf certificate, an undecodable certificate, an
    /// unreadable identity, or an error from `sigstore` about the input
    /// itself. Nothing was established, so nothing is contributed: the
    /// candidate is skipped and counted, exactly as a bundle belonging to
    /// the other backend is skipped.
    Unreadable,
}

/// Verify a single bundle offline. No network — `offline = true` uses the
/// bundle's embedded tlog material; the `async` is only `sigstore`'s API
/// shape.
///
/// Parsing + identity extraction happen **first** so an unreadable bundle
/// is skipped regardless of trust-root health; only a well-formed bundle
/// reaches the trust-root-dependent crypto step. After
/// `verify_digest` passes, the Rekor Merkle inclusion proof + checkpoint
/// signature are verified ([`verify_inclusion`]) against the trust root's
/// Rekor key — a failure there can never reach `Verified`: it
/// short-circuits before the identity match, as a rejection, a hold or a
/// skip depending on whose side the failure is on
/// ([`inclusion_outcome`]).
async fn verify_one<F>(
    make_verifier: &F,
    payload: &[u8],
    bundle_bytes: &[u8],
    allowed: &[SignerIdentityPattern],
    rekor_keys: &BTreeMap<String, Vec<u8>>,
) -> BundleVerify
where
    F: Fn() -> DomainResult<Verifier>,
{
    // The four read gates. Each one is a statement that the verifier
    // cannot read the input — not a statement about the artifact — so each
    // one skips. A candidate that fails here is indistinguishable, as
    // evidence, from one that was never pushed: nothing was proved, so
    // nothing may be concluded, and condemning an artifact on it would let
    // anyone with write access to the referrer surface attach bytes that
    // reject somebody else's correctly-signed image.
    //
    // 1) Parse the bundle JSON. Unparseable → unreadable.
    let Ok(bundle) = serde_json::from_slice::<Bundle>(bundle_bytes) else {
        return BundleVerify::Unreadable;
    };

    // 2) Extract the observed signer identity from the leaf cert. A bundle
    //    with no leaf cert / no readable identity leaves us no identity
    //    decision to make, so there is nothing to decide on it.
    let Some(leaf_der) = leaf_cert_der(&bundle) else {
        return BundleVerify::Unreadable;
    };
    let Ok(cert) = Certificate::from_der(&leaf_der) else {
        return BundleVerify::Unreadable;
    };
    let Ok(observed) = observed_identity(&cert) else {
        return BundleVerify::Unreadable;
    };

    // 3) Build the offline verifier (trust-root-dependent) and run
    //    sigstore's cryptographic verification. `offline = true` uses the
    //    bundle's embedded SET / tlog body — NO network.
    //    `verify_digest` consumes the bundle; identity + predicate type are
    //    already extracted above.
    //
    //    A trust root with no Fulcio certs / CTFE keys cannot build a
    //    verifier at all, so the publisher's chain is never examined — the
    //    candidate is HELD, not condemned. Same class as a trust root
    //    holding no Rekor key for the entry's log, and the same reason:
    //    what did not work here is literally our own trust root. A
    //    rejection would terminalise every artifact in the scope over a
    //    fault the operator can fix, leaving a fleet of unrecoverable rows
    //    behind the fix. The worker's boot assertion refuses to start on
    //    such a root, so this arm is the defence and not the design.
    let Ok(verifier) = make_verifier() else {
        return BundleVerify::Indeterminate(IndeterminateReason::TrustRootUnusable);
    };

    let predicate_type = predicate_type_of(&bundle);

    // Extract the transparency-log inclusion material from the bundle
    // BEFORE `verify_digest` consumes it. A v0.3 bundle that reached this
    // point structurally carries an inclusion proof with a checkpoint
    // (`check_02_bundle` enforces it at parse); a bundle that does not (a
    // v0.1 SET-only shape, or a malformed entry) yields an extraction
    // error, classified after the crypto step like any other inclusion
    // failure — none of the extraction errors is a disproof, so a bundle
    // carrying no readable log material is skipped rather than condemned.
    // We clone the (small) tlog material so it outlives the consumed
    // bundle.
    let tlog_material = TlogInclusionMaterial::from_bundle(&bundle);

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
            // 4) Fulcio chain / SCT / signature / digest-binding passed.
            //    Now verify — fully offline — the Rekor Merkle inclusion
            //    proof + checkpoint signature against the pinned trust
            //    root's Rekor key (sigstore 0.14's `verify_digest` does
            //    NOT do this; sigstore-rs#285). A bundle whose tlog entry
            //    is not provably in the log can never reach `Verified`.
            //    No extraction / conversion / crypto failure here can
            //    reach `Verified`, and none of them is ever a live fetch
            //    — but they are not one answer either. The
            //    `InclusionError` variant decides which of three the
            //    candidate gives ([`inclusion_outcome`]):
            //    `NoMatchingRekorKey` — a trust-root misprovision — is a
            //    fault on our side and holds, `VerifyFailed` — a
            //    forged/non-included proof — is the one disproof and
            //    stays terminal, and absent or unparseable log material
            //    proved nothing, so that candidate is skipped. The variant
            //    is still recorded at `debug!` (it carries no key bytes);
            //    the verdict itself is logged at the use-case layer.
            let inclusion = match tlog_material.as_ref() {
                Ok(m) => verify_inclusion(m, rekor_keys),
                Err(e) => Err(e.clone()),
            };
            if let Err(reason) = inclusion {
                tracing::debug!(?reason, "rekor inclusion verification did not pass");
                return inclusion_outcome(&reason);
            }

            // 5) Crypto + inclusion passed. Apply the domain glob identity
            //    match. An empty allow-list never matches (the any-signer
            //    footgun is apply-rejected upstream under `Required`; under
            //    `VerifyIfPresent` an empty list rejects forged/untrusted
            //    signers).
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
        Err(e) => classify_verification_error(&e),
    }
}

/// What an offline Rekor inclusion failure makes of the candidate.
///
/// The three-way split itself is [`InclusionError::side`]'s — the
/// variants' own doc comments are the evidence for it, and the match there
/// is wildcard-free so an eleventh variant must be classified. This function
/// is the translation into a per-candidate outcome, and is wildcard-free
/// for the same reason: a fourth side has to be told what it does to the
/// artifact.
fn inclusion_outcome(error: &InclusionError) -> BundleVerify {
    match error.side() {
        // A present, readable proof that did not verify: the entry is not
        // provably in the log, and that is a finding about the bundle.
        InclusionFailureSide::Disproof => {
            BundleVerify::Rejected(ProvenanceRejectReason::RekorNotFound)
        }
        // Our trust root holds no usable key for this entry's log, so the
        // check never ran. A publisher's correctly signed, log-included
        // artifact must not go terminal on that — the remedy is in the
        // operator's trust root, and the held artifact verifies on the
        // next run once the key is provisioned.
        InclusionFailureSide::TrustRoot => {
            BundleVerify::Indeterminate(IndeterminateReason::TrustRootUnusable)
        }
        // The bundle's own log material is absent or unparseable: nothing
        // was proved, so the candidate contributes nothing and the
        // artifact holds as unsigned. Counted with the parse-gate skips —
        // the count is what keeps a skip from being silent, and this is a
        // skip.
        InclusionFailureSide::NothingProved => BundleVerify::Unreadable,
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

/// Classify a `sigstore` [`VerificationError`] into the per-candidate
/// outcome: a **finding** about material the verifier read, or material it
/// could not read at all.
///
/// The split is the whole of this function's job. A missing/invalid SET is
/// a finding (`RekorNotFound`, and **never** retried online); a chain/SCT
/// failure is a finding (`CertChainInvalid`). An error about the *input* —
/// a structurally broken bundle, unsupported material, a malformed
/// certificate — is the verifier saying it could not read what it was
/// handed, which proves nothing about the artifact and therefore
/// contributes nothing: [`BundleVerify::Unreadable`].
///
/// It never returns `Verified`; an error is never an acceptance. The
/// return type is the per-candidate outcome anyway so the unreadable half
/// is expressible at all — a function returning a reject reason has no way
/// to say "no reason, this one does not count".
///
/// `sigstore` keeps the inner error-*kind* enums in a private module
/// (`bundle::verify::models`) — only the outer [`VerificationError`]
/// variants are nameable. We therefore match the **variant** for the
/// coarse class and disambiguate the `Signature` variant's
/// `Transparency` (offline SET-consistency) case via the error's
/// `Display` (which is `#[error("signature transparency materials are
/// inconsistent")]` upstream). This keeps the classification precise
/// without depending on the private types.
fn classify_verification_error(err: &sigstore::bundle::verify::VerificationError) -> BundleVerify {
    use sigstore::bundle::verify::VerificationError as VE;
    match err {
        // Bundle structurally broken / unsupported material / unreadable
        // input — we could not read it, so it is skipped.
        VE::Bundle(_) | VE::Input(_) => BundleVerify::Unreadable,
        // Fulcio chain / SCT failures. A *malformed* cert is material we
        // could not read; any other certificate failure is a finding — a
        // chain that was readable and did not validate.
        VE::Certificate(_) => {
            if err.to_string().contains("malformed") {
                BundleVerify::Unreadable
            } else {
                BundleVerify::Rejected(ProvenanceRejectReason::CertChainInvalid)
            }
        }
        // The offline tlog/SET-consistency failure surfaces as
        // `SignatureErrorKind::Transparency` ("signature transparency
        // materials are inconsistent") — the SET is missing or does not
        // match the signing materials. This maps to `RekorNotFound`,
        // NEVER a live Rekor fetch. A genuine bad signature /
        // unsupported algorithm is a cert/key-level failure. Both are
        // findings about readable material and stay terminal.
        VE::Signature(_) => {
            if err.to_string().contains("transparency") {
                BundleVerify::Rejected(ProvenanceRejectReason::RekorNotFound)
            } else {
                BundleVerify::Rejected(ProvenanceRejectReason::CertChainInvalid)
            }
        }
        // The pass-through policy never errors, but classify defensively.
        VE::Policy(_) => BundleVerify::Rejected(ProvenanceRejectReason::UntrustedIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `make_verifier` factory over the **empty** fixture trust root.
    /// `Verifier::new` fails on a root with no Fulcio certs / CTFE keys, so
    /// this factory returns `Err` — exercising the "well-formed bundle,
    /// but we cannot build a verifier for it → hold on our trust root"
    /// path. An unreadable bundle is skipped before the factory is ever
    /// called, so no verdict here is an artifact of trust-root health.
    fn empty_root_factory() -> impl Fn() -> DomainResult<Verifier> {
        || {
            let tr = SigstoreTrustRoot::from_trusted_root_json_unchecked(
                &crate::trust_root::minimal_trusted_root_json(),
            )
            .expect("minimal trust root parses");
            build_verifier(tr)
        }
    }

    /// An empty Rekor-key map — the minimal fixture trust root carries no
    /// `tlogs`, so its Rekor keys are empty. The crypto rejections in these
    /// tests happen at or before `verify_digest`, never reaching the
    /// inclusion step, so the empty map is inert for them.
    fn no_rekor_keys() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::new()
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

    /// The push-path well-formedness door must never refuse material THIS
    /// verifier can read. The real keyless fixture is the ground truth for
    /// that direction: it is read all the way to the crypto step below
    /// (`real_bundle_against_unusable_trust_root_holds_not_verified`),
    /// so a door that rejected it would refuse a push whose signature the
    /// system can in fact read and judge.
    #[test]
    fn the_real_keyless_fixture_passes_the_push_path_well_formedness_door() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        assert!(
            hort_domain::provenance_bundle::is_well_formed_sigstore_bundle(bundle_json.as_bytes()),
            "the real keyless cosign bundle must pass the push-path door"
        );
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

    /// Gate 1 — unparseable bundle JSON. The verifier could not read it,
    /// so it contributes nothing: `Unreadable`, not a rejection. (It is
    /// reached before the trust-root factory, which would itself fail
    /// here, so the skip is not an artifact of trust-root health.)
    #[tokio::test]
    async fn unparseable_bundle_is_unreadable_not_a_rejection() {
        let v = verify_one(
            &empty_root_factory(),
            &[0u8; 32],
            b"}{not json",
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert!(matches!(v, BundleVerify::Unreadable), "must not be judged");
    }

    /// Gate 2 — valid JSON with no `verificationMaterial`, so no leaf cert
    /// and no identity to decide on. Unreadable, again before the
    /// trust-root factory.
    #[tokio::test]
    async fn json_without_verification_material_is_unreadable() {
        let v = verify_one(
            &empty_root_factory(),
            &[0u8; 32],
            b"{\"mediaType\":\"x\"}",
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert!(matches!(v, BundleVerify::Unreadable));
    }

    /// Gates 2b/2c — a bundle whose `verificationMaterial` carries a
    /// certificate whose DER does **not** decode, and one whose leaf
    /// decodes but carries no readable `{issuer, san}`. Both are the
    /// verifier failing to read its input, both skip.
    #[tokio::test]
    async fn undecodable_and_identity_less_certificates_are_unreadable() {
        // `rawBytes` is valid base64 but not a certificate → `from_der`
        // fails (gate 2b).
        let not_a_cert = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": { "certificate": { "rawBytes": "AAAA" } },
            "dsseEnvelope": {
                "payload": "e30=",
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": "AAAA" } ]
            }
        }"#;
        let v = verify_one(
            &empty_root_factory(),
            &[0u8; 32],
            not_a_cert,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert!(matches!(v, BundleVerify::Unreadable));

        // An `X509CertificateChain` whose first entry is likewise not a
        // certificate — the v0.1/v0.2 leaf-first shape, same gate.
        let chain_not_a_cert = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "x509CertificateChain": { "certificates": [ { "rawBytes": "AAAA" } ] }
            },
            "dsseEnvelope": {
                "payload": "e30=",
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": "AAAA" } ]
            }
        }"#;
        let v = verify_one(
            &empty_root_factory(),
            &[0u8; 32],
            chain_not_a_cert,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert!(matches!(v, BundleVerify::Unreadable));
    }

    /// **Changed verdict.** This test was
    /// `real_bundle_against_empty_trust_root_is_typed_rejection_not_verified`
    /// and asserted `Rejected{CertChainInvalid}` on the strength of the
    /// comment *"empty trust root → un-trustable chain"*.
    ///
    /// The fixture root carries no Fulcio certs, so the factory cannot
    /// build a verifier and **this bundle's chain is never examined**.
    /// Calling that an un-trustable chain stated a finding about the
    /// publisher's certificate where the only thing that failed was our
    /// own provisioning — the one move ADR 0039 D4 forbids. The hold is
    /// the honest answer, and it is what the operator can act on: fix the
    /// trust root and the artifact verifies on the next run.
    ///
    /// What the test still proves is unchanged and is the reason it
    /// exists: a lone-star pattern would match the observed identity IF
    /// the crypto had passed, so a `Verified` here would mean the identity
    /// gate had overtaken the crypto gate.
    #[tokio::test]
    async fn real_bundle_against_unusable_trust_root_holds_not_verified() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let pat = SignerIdentityPattern::new("*", "*").unwrap();
        let v = verify_one(
            &empty_root_factory(),
            &[7u8; 32],
            bundle_json.as_bytes(),
            &[pat],
            &no_rekor_keys(),
        )
        .await;
        match v {
            BundleVerify::Verified { .. } => {
                panic!("must NOT verify against an empty fixture trust root")
            }
            BundleVerify::Indeterminate(reason) => {
                assert_eq!(
                    reason,
                    IndeterminateReason::TrustRootUnusable,
                    "the trust root is what did not work, so it is what the hold names"
                );
            }
            // The fixture bundle IS readable — it parses, carries a leaf
            // cert and yields an identity — so a skip here would mean the
            // read gates had started swallowing readable material, which
            // is the failure mode on the other side of this unit. It
            // would also be the *wrong* hold: a skip says the bundle had
            // nothing in it, and this bundle does.
            BundleVerify::Unreadable => {
                panic!("a readable bundle held on our trust root must not read as empty material")
            }
            // The regression this test now guards: a rejection minted
            // from a chain nobody looked at.
            BundleVerify::Rejected(reason) => panic!(
                "the chain was never examined — a verifier that cannot be built proves \
                 nothing about it: {reason:?}"
            ),
        }
    }

    /// Shorthands so the ladder assertions below read as the ladder.
    fn rej(r: ProvenanceRejectReason) -> CandidateAnswer {
        CandidateAnswer::Rejected(r)
    }

    fn ind(r: IndeterminateReason) -> CandidateAnswer {
        CandidateAnswer::Indeterminate(r)
    }

    #[test]
    fn merge_reason_keeps_more_authoritative() {
        use ProvenanceRejectReason::*;
        // DigestMismatch outranks everything — a signature that verified
        // and covers the wrong digest is the strongest disproof in the set.
        assert_eq!(
            merge_reason(Some(rej(UntrustedIdentity)), rej(DigestMismatch)),
            rej(DigestMismatch)
        );
        assert_eq!(
            merge_reason(Some(rej(DigestMismatch)), rej(UntrustedIdentity)),
            rej(DigestMismatch)
        );
        // UntrustedIdentity beats everything below it.
        assert_eq!(
            merge_reason(Some(rej(BundleMalformed)), rej(UntrustedIdentity)),
            rej(UntrustedIdentity)
        );
        assert_eq!(
            merge_reason(Some(rej(UntrustedIdentity)), rej(BundleMalformed)),
            rej(UntrustedIdentity)
        );
        // CertChainInvalid beats RekorNotFound beats BundleMalformed.
        assert_eq!(
            merge_reason(Some(rej(RekorNotFound)), rej(CertChainInvalid)),
            rej(CertChainInvalid)
        );
        assert_eq!(
            merge_reason(Some(rej(BundleMalformed)), rej(RekorNotFound)),
            rej(RekorNotFound)
        );
        // None → take incoming.
        assert_eq!(
            merge_reason(None, rej(BundleMalformed)),
            rej(BundleMalformed)
        );
        // Unsigned ranks last of the rejections.
        assert_eq!(
            merge_reason(Some(rej(BundleMalformed)), rej(Unsigned)),
            rej(BundleMalformed)
        );
        assert_eq!(
            merge_reason(Some(rej(Unsigned)), rej(BundleMalformed)),
            rej(BundleMalformed)
        );
    }

    /// Exhaustively exercise the `rank` ladder so every arm is covered:
    /// feeding each answer as `incoming` over a `None` current returns it
    /// unchanged, and the full ordering is total + stable.
    ///
    /// The indeterminate rung is the ladder's last: it is listed once,
    /// because every `IndeterminateReason` shares that rung and a
    /// same-rung pair is not strictly ordered (see
    /// `indeterminate_reasons_share_the_last_rung`).
    #[test]
    fn merge_reason_rank_total_order() {
        use ProvenanceRejectReason::*;
        let ordered = [
            rej(DigestMismatch),
            rej(UntrustedIdentity),
            rej(CertChainInvalid),
            rej(RekorNotFound),
            rej(BundleMalformed),
            rej(Unsigned),
            ind(IndeterminateReason::TrustRootUnusable),
        ];
        // None current → incoming wins for every answer (covers each arm).
        for a in ordered {
            assert_eq!(merge_reason(None, a), a);
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

    /// **Every rejection outranks every indeterminate, both ways round.**
    /// A finding about material this verifier read says something about
    /// the artifact; an indeterminate says something about us, so the
    /// finding decides. This is the direction that must not slip: an
    /// unprovisioned trust-root key on one candidate cannot be allowed to
    /// turn a sibling's forged proof into a hold.
    #[test]
    fn a_rejection_outranks_an_indeterminate_either_way_round() {
        use IndeterminateReason::{AttestationFetchFailed, TrustRootUnusable, VerifierUnavailable};
        use ProvenanceRejectReason::*;
        for r in [
            DigestMismatch,
            UntrustedIdentity,
            CertChainInvalid,
            RekorNotFound,
            BundleMalformed,
            Unsigned,
        ] {
            // Every reason, because the rung belongs to the category: a
            // future one must inherit the direction, not be exempt from it.
            for i in [
                TrustRootUnusable,
                AttestationFetchFailed,
                VerifierUnavailable,
            ] {
                assert_eq!(merge_reason(Some(ind(i)), rej(r)), rej(r), "{i:?} vs {r:?}");
                assert_eq!(merge_reason(Some(rej(r)), ind(i)), rej(r), "{r:?} vs {i:?}");
            }
        }
    }

    /// All the indeterminate reasons share the last rung, so a tie keeps
    /// the first observed. Nothing downstream tells them apart (the
    /// orchestrator holds on any of them and its hold label carries no
    /// reason), and this adapter only ever produces `TrustRootUnusable` —
    /// `AttestationFetchFailed` and `VerifierUnavailable` are the
    /// orchestrator's own. What has to hold is the rung, which the test
    /// above pins.
    ///
    /// Driven over every ordered pair rather than one, so a `rank` that
    /// split the category by reason would fail here rather than only
    /// behind whichever pair happened to be listed.
    #[test]
    fn indeterminate_reasons_share_the_last_rung() {
        use IndeterminateReason::{AttestationFetchFailed, TrustRootUnusable, VerifierUnavailable};
        let reasons = [
            TrustRootUnusable,
            AttestationFetchFailed,
            VerifierUnavailable,
        ];
        for first in reasons {
            for second in reasons {
                assert_eq!(
                    merge_reason(Some(ind(first)), ind(second)),
                    ind(first),
                    "{first:?} observed first must survive {second:?}",
                );
            }
        }
    }

    /// Drive the fold with a single candidate, exactly as
    /// [`verify_bundles`] does for a set of one: the per-candidate outcome
    /// through [`Fold::observe`], then [`Fold::finish`] if that did not
    /// already end the fold.
    fn lone_candidate(outcome: BundleVerify) -> ProvenanceVerdict {
        let mut fold = Fold::default();
        match fold.observe(outcome) {
            Some(verdict) => verdict,
            None => fold.finish(),
        }
    }

    /// **Every `InclusionError`, all the way to the verdict it produces.**
    /// `inclusion.rs` pins which condition produces which variant and
    /// which side each variant is on; this pins what each side does to the
    /// artifact.
    ///
    /// It is driven through the fold rather than through
    /// [`verify_bundles`] because no offline fixture can carry a bundle
    /// past `verify_digest` (Fulcio chain + SCT + signature + digest bind)
    /// to the inclusion step, so there is no bundle that reaches these
    /// branches in a test. The chain condition → variant → side → verdict
    /// is covered link by link instead.
    #[test]
    fn every_inclusion_error_reaches_its_verdict() {
        use InclusionError::*;
        // The one disproof — a present, readable proof that did not
        // verify. Terminal, and it must not drift into the hold: this is
        // the forged / non-included entry.
        assert_eq!(
            lone_candidate(inclusion_outcome(&VerifyFailed)),
            ProvenanceVerdict::rejected(ProvenanceRejectReason::RekorNotFound),
            "a proof that did not verify is a finding about the artifact",
        );
        // Ours — the hold that names the trust root. Not counted as
        // unreadable (the candidate was readable; the key was not there).
        for e in [NoMatchingRekorKey, KeyParse] {
            assert_eq!(
                lone_candidate(inclusion_outcome(&e)),
                ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable),
                "{e:?} is our provisioning, not a finding about the artifact",
            );
        }
        // The bundle's own log material, absent, unparseable or
        // structurally impossible — the plain unsigned hold, with the skip
        // recorded so it is not silent.
        for e in [
            NoTlogEntry,
            NoInclusionProof,
            NoCheckpoint,
            CheckpointParse,
            HashWidth,
            TreeSizeInvalid,
            NoLogId,
        ] {
            assert_eq!(
                lone_candidate(inclusion_outcome(&e)),
                ProvenanceVerdict::no_attestation().with_unreadable_skipped(1),
                "{e:?} proved nothing, so it contributes nothing",
            );
        }
    }

    /// **The two non-terminal groups are the same state and must not be
    /// the same answer.** Both hold under `Required`; what differs is the
    /// operator action behind the hold — fix the trust root, versus sign
    /// the artifact — and that is the only thing keeping them apart is
    /// for. A unit that collapsed them into one label would still pass
    /// every "is it held?" assertion in the suite.
    #[test]
    fn the_trust_root_hold_is_not_the_unsigned_hold() {
        use hort_domain::ports::provenance::ProvenanceOutcome;
        let trust_root = lone_candidate(inclusion_outcome(&InclusionError::NoMatchingRekorKey));
        let unsigned = lone_candidate(inclusion_outcome(&InclusionError::NoTlogEntry));
        assert_eq!(
            trust_root.outcome,
            ProvenanceOutcome::Indeterminate(IndeterminateReason::TrustRootUnusable),
            "the trust-root hold names the trust root",
        );
        assert_eq!(
            unsigned.outcome,
            ProvenanceOutcome::NoAttestation,
            "the material rows produce the plain unsigned hold",
        );
        assert_ne!(
            trust_root.outcome, unsigned.outcome,
            "same state, different operator action — they must stay distinguishable",
        );
    }

    /// In the fold, a sibling's finding is not masked by "we could not
    /// check" — in either listing order, because the referrer surface
    /// decides the order and an attacker can write to it.
    #[test]
    fn a_readable_finding_outranks_a_trust_root_hold_in_the_fold() {
        let expected = ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity);
        for order in [false, true] {
            let mut fold = Fold::default();
            let outcomes = if order {
                [
                    BundleVerify::Indeterminate(IndeterminateReason::TrustRootUnusable),
                    BundleVerify::Rejected(ProvenanceRejectReason::UntrustedIdentity),
                ]
            } else {
                [
                    BundleVerify::Rejected(ProvenanceRejectReason::UntrustedIdentity),
                    BundleVerify::Indeterminate(IndeterminateReason::TrustRootUnusable),
                ]
            };
            for o in outcomes {
                assert!(fold.observe(o).is_none(), "neither answer ends the fold");
            }
            assert_eq!(fold.finish(), expected);
        }
    }

    /// A candidate that verified ends the fold even after a trust-root
    /// hold on a sibling: our inability to check one bundle cannot
    /// invalidate another bundle we did verify. The same direction the
    /// cross-verifier fold takes (`Verified` outranks `Indeterminate`
    /// there), reached here by the first-`Verified`-wins short-circuit.
    #[test]
    fn a_verified_candidate_ends_the_fold_after_a_trust_root_hold() {
        let signer = SignerIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        };
        let mut fold = Fold::default();
        assert!(fold
            .observe(BundleVerify::Indeterminate(
                IndeterminateReason::TrustRootUnusable
            ))
            .is_none());
        assert!(fold.observe(BundleVerify::Unreadable).is_none());
        let verdict = fold
            .observe(BundleVerify::Verified {
                signer: signer.clone(),
                predicate_type: None,
            })
            .expect("a verified candidate ends the fold");
        assert_eq!(
            verdict,
            ProvenanceVerdict::verified(signer, None).with_unreadable_skipped(1),
            "the accepted verdict still carries the sibling skip",
        );
    }

    /// An indeterminate candidate beside an unreadable one holds on the
    /// trust root, with the skip recorded alongside: the skip neither
    /// becomes the verdict nor erases the hold's reason.
    #[test]
    fn a_trust_root_hold_survives_an_unreadable_sibling() {
        let mut fold = Fold::default();
        assert!(fold.observe(BundleVerify::Unreadable).is_none());
        assert!(fold
            .observe(BundleVerify::Indeterminate(
                IndeterminateReason::TrustRootUnusable
            ))
            .is_none());
        assert_eq!(
            fold.finish(),
            ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable)
                .with_unreadable_skipped(1),
        );
    }

    /// A set of nothing but garbage is `NoAttestation` — "I have nothing
    /// to say about this artifact" — and the two skips are **counted**.
    /// Under `Required` that is the indefinite unsigned hold; under
    /// `VerifyIfPresent` the allow. What it must never be is a rejection:
    /// no readable material was found, so nothing was proved.
    #[tokio::test]
    async fn verify_bundles_answers_no_attestation_for_garbage_inputs() {
        let bundles = [
            AttestationBundle::new(b"garbage".to_vec()),
            AttestationBundle::new(b"{\"mediaType\":\"x\"}".to_vec()),
        ];
        // Neither parses / has a leaf → both skipped; the trust-root
        // factory is never consulted.
        let verdict = verify_bundles(
            empty_root_factory(),
            &[0u8; 32],
            &bundles,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert_eq!(
            verdict,
            ProvenanceVerdict::no_attestation().with_unreadable_skipped(2),
            "unreadable material contributes nothing — and the skip is recorded",
        );
    }

    /// An unreadable sibling neither becomes the verdict nor erases the
    /// answer a readable candidate reached: the readable bundle's hold
    /// stands, with the skip recorded alongside it.
    ///
    /// **Changed verdict.** This asserted
    /// `Rejected{CertChainInvalid}` + one skip, because the empty fixture
    /// root condemned the readable bundle. It now asserts the hold, and
    /// the property being pinned survives the change intact — the two
    /// answers a candidate can contribute to the fold, a rejection and a
    /// hold, are both answers the skip must not displace. The rejection
    /// direction has its own test
    /// (`a_readable_finding_outranks_a_trust_root_hold_in_the_fold`).
    ///
    /// This is the direction that matters for the ladder — before the
    /// skip, a garbage candidate could only ever *lose* to a real answer
    /// (it ranked last); now it does not enter the ladder at all, so an
    /// answer that ranked **below** `BundleMalformed` — as every
    /// indeterminate does — would not have been hidden either. With the
    /// hold on the readable candidate that is no longer hypothetical:
    /// this set is exactly the case the old ladder would have got wrong.
    #[tokio::test]
    async fn an_unreadable_sibling_does_not_mask_a_readable_candidates_answer() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundles = [
            AttestationBundle::new(b"garbage".to_vec()),
            AttestationBundle::new(bundle_json.as_bytes().to_vec()),
        ];
        let verdict = verify_bundles(
            empty_root_factory(),
            &[7u8; 32],
            &bundles,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert_eq!(
            verdict,
            ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable)
                .with_unreadable_skipped(1),
        );
    }

    /// A keyed bundle is skipped because it is not ours, which is **not**
    /// the same as unreadable: the count stays 0 so a keyed-signed
    /// artifact never looks like it carried garbage.
    #[tokio::test]
    async fn a_keyed_bundle_is_skipped_without_being_counted_unreadable() {
        let bundles = [AttestationBundle::new_signed(
            br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc"}}}"#.to_vec(),
            vec![0x30, 0x44, 0x01],
        )];
        let verdict = verify_bundles(
            empty_root_factory(),
            &[0u8; 32],
            &bundles,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert_eq!(verdict, ProvenanceVerdict::no_attestation());
        assert_eq!(verdict.unreadable_skipped, 0);
    }

    /// **Changed verdict.** This was
    /// `verify_bundles_real_bundle_empty_root_is_cert_chain_invalid` — the
    /// whole-`verify_bundles` statement of the same reversal, with the
    /// old reason in its name.
    ///
    /// The count assertion is the part that must NOT move, and it is why
    /// the hold is not merely "a different hold": a candidate whose check
    /// we could not run is not a candidate we could not read. The bundle
    /// parsed, carried a leaf cert and yielded an identity — the skip
    /// count stays 0, and an operator reading it learns that this artifact
    /// has real signature material waiting on a fixed trust root rather
    /// than garbage attached to it.
    #[tokio::test]
    async fn verify_bundles_real_bundle_unusable_root_holds_on_the_trust_root() {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let bundles = [AttestationBundle::new(bundle_json.as_bytes().to_vec())];
        let verdict = verify_bundles(
            empty_root_factory(),
            &[7u8; 32],
            &bundles,
            &[],
            &no_rekor_keys(),
        )
        .await;
        assert_eq!(
            verdict,
            ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable)
        );
        assert_eq!(
            verdict.unreadable_skipped, 0,
            "the candidate was perfectly readable — we were the part that did not work",
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
