# 0027 — Artifact provenance verification (Sigstore/cosign, offline, policy-gated)

- **Status:** Accepted
- **Enforced by:** the domain release predicate (`Artifact::release`, `crates/hort-domain/src/entities/artifact.rs:499`) denies the timer arm unless `ProvenanceClearance ∈ {NotRequired, Cleared}` — exhaustively tested under the 100 % domain-coverage tier; the apply-time gitops linter rejects under-specified `provenanceMode` configurations (`crates/hort-app/src/use_cases/apply_config_use_case.rs:1066`); the worker refuses to boot a verifier without a parseable, fresh pinned trust root (`crates/hort-worker/src/composition.rs:1452`); and the pure-bundle quarantine exemption is pinned by the mixed-manifest red test `put_mixed_bundle_plus_tar_gzip_referrer_is_still_scanned` (`crates/hort-http-oci/src/manifests_write.rs:1941`).
- **Supersedes:** the inert `ScanPolicy.require_signature: bool` (parsed and operator-toggleable but read by no gate — the canonical "policy field accepted at apply, inert at runtime" anti-pattern instance; removed from the codebase, zero remaining references).

## Context

Checksum verification (ADR 0006) proves an artifact's bytes are the bytes the
upstream *index* declared — it says nothing about **who built and published
them**. Sigstore/cosign attestations close that gap, but provenance in the
real package ecosystem is sparse and heterogeneous: OCI cosign signatures are
opt-in, npm/PyPI Sigstore provenance is opt-in, crates.io has none. A blanket
"require a signature" bool therefore cannot be load-bearing — it would block
the unsigned majority of any proxied catalog — and the predecessor field
(`require_signature`) was in fact accepted at apply and read by nothing.

Three further constraints shaped the design:

1. **The verify path must not depend on live transparency-log infrastructure.**
   A per-verify Rekor/Fulcio round-trip adds an SSRF-shaped outbound surface
   and couples ingest availability to a third-party service.
2. **A Sigstore signature is not an artifact.** Quarantine (ADR 0007) is an
   observation window for content whose safety resolves over time; a bundle's
   validity is deterministic and knowable immediately, so quarantining one is
   a category error — and it 503s an external `cosign verify` against the
   registry for the duration of the window.
3. **Hosted and proxy repositories must get the same verification surface.**
   A signature for a proxied image lives in the *upstream* registry; without
   fetching it, any proxy-scope policy could only ever observe "no
   attestation".

## Decision

**Provenance verification is cosign-bundle-based, fully offline against a
pinned trust root, opt-in at deploy time, and policy-gated per scope by a
tri-state `provenance_mode`. It gates release fail-closed only in the mode
that demands it, exempts pure signature manifests from quarantine, and
fetches upstream referrers on proxy scopes so hosted and proxied artifacts
verify identically.**

1. **Offline bundle verification, pinned trust root — no live TUF or
   transparency-log fetch on the verify path.** The verifier
   (`crates/hort-adapters-provenance-sigstore/src/verifier.rs`) validates a
   stored Sigstore v0.3 bundle's own material — Fulcio certificate chain
   (with SCT), artifact signature, digest binding, **and the Rekor Merkle
   inclusion proof + checkpoint signature** — against a cached trust root
   (`src/trust_root.rs`), and matches the observed signer `{issuer, san}`
   extracted from the leaf certificate (`src/identity.rs`) against the
   policy's allowed-identity patterns. The trust root is loaded **once at
   boot** from an operator-provisioned `trusted_root.json`
   (`HORT_PROVENANCE_TRUSTED_ROOT_FILE`); a missing, malformed, or stale file
   is a hard boot error (`crates/hort-worker/src/composition.rs`), as is a
   trust root carrying no Rekor public key (it would reject every bundle
   `RekorNotFound`). The adapter's live-refresh helper exists but is
   deliberately unwired — the root rotates through the release pipeline,
   never a runtime fetch. A bundle lacking offline-verifiable material is
   `Rejected{BundleMalformed}`; an absent bundle is `NoAttestation`; neither
   ever falls back to a live lookup. Signature binding is to the artifact
   preimage: the verifier recomputes the digest from the bytes, so a valid
   bundle for a *different* digest can never yield `Verified`.

   **Rekor inclusion verification (closes sigstore-rs#285 for v0.3).** The
   pinned `sigstore` 0.14 `verify_digest` leaves the Rekor Merkle inclusion
   proof + checkpoint/SET steps as upstream `TODO`s. The adapter closes that
   gap **offline** for the v0.3 bundle format
   (`src/inclusion.rs`): after `verify_digest` succeeds it reconstructs the
   public `rekor::models::InclusionProof` from the bundle's protobuf
   transparency-log entry (fail-closed `Vec<u8> → [u8; 32]` width checks; the
   checkpoint signed-note envelope parsed via `SignedCheckpoint`) and runs
   the crate's cryptographically-complete `InclusionProof::verify` — full
   RFC-6962 Merkle inclusion over the entry's `canonicalized_body` leaf, the
   checkpoint signature, and root/tree-size consistency — against the Rekor
   public key selected from the pinned trust root by the entry's `logID`. Any
   failure is fail-closed `Rejected{RekorNotFound}` (never a panic, skip, or
   live fetch). Verification now attests *"a valid Fulcio cert + SCT for a
   policy-allowed signer signed these bytes **and** the entry is provably in
   the public Rekor transparency log."* The older v0.1 SET-only
   (`inclusion_promise`) path is out of scope and rejected. Route A (the
   official `sigstore` 0.14 public `InclusionProof::verify` primitive, no
   dependency swap) was chosen over migrating to the third-party
   `sigstore-verify` 0.8 crate: a source review found the latter **never
   computes the Merkle leaf→root proof** (its `inclusion_proof.hashes` audit
   path is unused — it verifies only the checkpoint signature plus a
   same-bundle root-hash equality), so it is *weaker* on the exact guarantee
   this closes, and it would raise supply-chain surface (a conda-ecosystem
   reimplementation, not official sigstore-rs).
2. **Deploy-time opt-in, policy-time mode.** The cosign verifier registers in
   the worker only when `HORT_PROVENANCE_COSIGN_ENABLED=true` (default
   `false` — `crates/hort-worker/src/config.rs:350`). The per-policy field is
   `ScanPolicy.provenance_mode: Off | VerifyIfPresent | Required`
   (`crates/hort-domain/src/entities/scan_policy.rs:105`), default
   `VerifyIfPresent` — fail-safe: it rejects forged or untrusted-signer
   bundles where a verifier is deployed and is a no-op where none is. A
   `provenance-verify` job is enqueued at ingest only when the resolved mode
   is not `Off` **and** a registered verifier `applies_to` the format
   (`crates/hort-app/src/use_cases/ingest_use_case.rs:537`), so
   non-applicable ingests are zero-overhead.
3. **`provenance_mode` supersedes `require_signature`.** The inert bool is
   gone; the replacement is load-bearing end to end (policy → enqueue →
   verdict → events `ProvenanceVerified` / `ProvenanceRejected`
   (`crates/hort-domain/src/events/artifact_events.rs:593`) → release gate).
   Verdicts are mode-applied by `Artifact::complete_provenance`
   (`crates/hort-domain/src/entities/artifact.rs:615`): `Rejected` is
   terminal (`rejected` status, any mode); `NoAttestation` is allowed under
   `VerifyIfPresent` and maps to `ProvenanceRejected{Unsigned}` under
   `Required`.
4. **Release-gate integration is an AND-precondition on the timer arm,
   fail-closed in `Required` mode.** The release sweep computes a
   `ProvenanceClearance` per candidate
   (`crates/hort-app/src/use_cases/quarantine_use_case.rs:1067`):
   `NotRequired` for `Off`/`VerifyIfPresent`, `Cleared` iff a
   `ProvenanceVerified` event exists on the stream, else `Pending`. The
   domain predicate (`artifact.rs:553`) authorizes `(Timer,
   ScanSucceeded|ScanWaived)` only when the clearance is
   `NotRequired | Cleared` — a `Pending` artifact never timer-releases.
   Explicit Admin / Curator / PolicyReEvaluation releases ignore the
   provenance parameter: provenance adds no new release authority to the
   ADR 0007 predicate and can never relax it, only tighten it. Bundle-fetch
   exhaustion under `Required` fail-closes (`Rejected{RekorNotFound}`); under
   `VerifyIfPresent` it degrades to `NoAttestation` so infrastructure
   flakiness never blocks a proxy
   (`crates/hort-app/src/use_cases/provenance_orchestration.rs:246`).
5. **Apply-time linting is fail-closed for the dangerous configurations.**
   The gitops apply path rejects: `Required` on a scope whose format has no
   verifier in the static backend→format capability map; any mode other than
   `Off` with empty `provenance_backends`; `Required` with empty
   `provenance_identities` (the any-signer footgun). `VerifyIfPresent` with
   empty identities is a warning — tamper detection without signer pinning
   (`apply_config_use_case.rs:493–1131`).
6. **The verifier receives the bundle blob, never the referrer manifest.**
   `fetch_bundles_once`
   (`crates/hort-app/src/use_cases/provenance_orchestration.rs:368`) parses
   the stored referrer manifest with the pure helper
   `sigstore_bundle_layers` (`crates/hort-domain/src/oci.rs:54`) and reads
   each declared Sigstore-bundle layer from CAS by its digest (OCI blob
   digest ≡ CAS content hash), feeding the verifier the bundle JSON it
   actually parses.
7. **Pure Sigstore-bundle signature manifests bypass quarantine on push;
   mixed manifests do not.** A pushed manifest that is a referrer (subject
   digest present) whose **every** layer carries the Sigstore bundle media
   type (`is_pure_sigstore_bundle`, `crates/hort-domain/src/oci.rs:118`) is
   landed via the narrow `IngestUseCase::ingest_signature_manifest`
   (`ingest_use_case.rs:1329`): status `None`, immediately servable, no scan,
   no self-referential provenance job
   (`crates/hort-http-oci/src/manifests_write.rs:475`). The all-layers
   predicate is the safety leg: a manifest carrying any non-bundle (runnable)
   layer fails it and stays on the full `ingest_verified` pipeline —
   scanned and quarantined. The exemption cannot smuggle runnable content,
   and a forged "bundle" is verification-inert (it can only produce
   `Rejected`/`BundleMalformed`, never `Verified`).
8. **Proxy scopes fetch upstream referrers lazily, inside the verify job.**
   When local bundles are empty and the repository resolves to an upstream,
   the orchestrator calls `UpstreamProxy::fetch_referrers`
   (`crates/hort-domain/src/ports/upstream_proxy.rs:263`; adapter
   `crates/hort-adapters-upstream-http/src/lib.rs:2421`) — OCI Distribution
   Spec v1.1 Referrers API with the cosign `sha256-<hex>.sig` tag-scheme
   fallback for upstreams that lack it — then narrow-creates the referrer
   manifest (status `None`) and stores the bundle blob in CAS, asserting the
   stored hash equals the manifest-declared digest and skipping the referrer
   on mismatch. The fetch runs only in the worker job, never on the
   latency-critical pull path, and only for scopes where provenance is
   configured. Trust is anchored in the Sigstore PKI plus the pinned trust
   root, not in the upstream registry — which is what makes proxied
   verification meaningful rather than theatre.

## Consequences

- A combined real-verifier end-to-end test remains open: the full chain
  (referrer manifest in CAS → bundle-blob extraction → offline verifier →
  release gate) is proven by composition of per-layer tests rather than by a
  single test driving a genuine signed image through a live stack.
- Trust-root rotation is an operator/release-pipeline responsibility. The
  pinned file removes the live TUF client (and its SSRF surface) at the cost
  of automatic rotation; a deployment that never updates the file eventually
  fails the worker's boot freshness check rather than silently verifying
  against a stale root.
- `Required` is deliberately sharp: it rejects genuinely-unsigned upstream
  images on a proxy (that is what it means), and an operator who enables
  `Required` while leaving the worker verifier disabled gets artifacts that
  stay `Pending` forever — fail-closed, never fail-open, but operationally
  surprising; the enablement how-to warns about it.
- Only the Sigstore v0.3 bundle format verifies. A signature published solely
  in the legacy cosign `simplesigning` shape yields `NoAttestation` (allowed
  under `VerifyIfPresent`, rejected `Unsigned` under `Required`).
- The lifecycle exemption is bounded to pure Sigstore-bundle referrers. SBOM
  referrers, other in-toto predicates, and arbitrary referrer types keep the
  full quarantine/scan lifecycle; widening the exemption is a new decision,
  not an extension of this one.
- The `sigstore` dependency tree is large and advisory-prone; advisories are
  handled by precise-version bumps first, dual-file ignores
  (`.cargo/audit.toml` + `deny.toml`, parity-enforced) only as documented
  risk acceptances.
- Non-OCI verifiers (npm/PyPI Sigstore, Maven PGP) slot in as additional
  `provenance_backends` entries behind the same `ProvenancePort`; the
  enqueue gate auto-activates them per format with no schema change.

## Alternatives considered

- **Keep `require_signature: bool`.** Rejected: a boolean cannot express
  "verify when present, allow unsigned" — the only deployable stance for a
  proxy over ecosystems where most content is unsigned — and the field was
  already inert, the exact accepted-at-apply/ignored-at-runtime footgun the
  apply-linter doctrine (ADR 0015) exists to kill.
- **Live Rekor/Fulcio verification per verify.** Rejected: couples ingest to
  transparency-log availability and latency and adds an outbound SSRF
  surface to the core path; the bundle already carries everything offline
  verification needs.
- **Live TUF trust-root refresh at runtime.** Rejected: the verification
  crate's built-in TUF fetcher constructs its own un-injectable HTTP client
  (the exact pattern ADR 0010 forbids) and could not be made both
  TLS-policy-clean and TUF-chain-verified; a pinned file eliminates the live
  client entirely.
- **A new `ReleaseAuthorization` for provenance.** Rejected: the ADR 0007
  predicate stays an exhaustive five-pair enumeration; provenance is an
  AND-precondition on the existing timer arm, so it can tighten but never
  bypass the scan/time gate.
- **Apply-time rejection of `Required` on proxy scopes.** Rejected: once the
  proxy referrer fetch exists, `Required` on a proxy is correct behaviour
  (reject unsigned upstreams), and the guard would have been a band-aid for
  a missing capability rather than a safety property.
- **Eager referrer fetch on image pull-through.** Rejected: adds an upstream
  round-trip to every cache-miss pull, including scopes with provenance
  `Off`; the lazy in-job fetch pays the cost only where a verifier and a
  non-`Off` mode are actually configured.
- **Routing pushed signature manifests through the normal ingest pipeline.**
  Rejected: quarantining a deterministic, immediately-checkable signature
  protects nothing, burns a scan and a no-op verify job per signature, and
  503s external `cosign verify` against the registry for the window when a
  signature lands after its image released.

## References

- `crates/hort-adapters-provenance-sigstore/src/` — `verifier.rs` (offline
  bundle verification), `trust_root.rs` (`CachedTrustRoot`, pinned-root
  load + freshness), `identity.rs` (observed `{issuer, san}` extraction).
- `crates/hort-domain/src/entities/artifact.rs` — `ProvenanceClearance`,
  `complete_provenance`, the timer-arm AND-precondition in `release`.
- `crates/hort-domain/src/entities/scan_policy.rs` — `ProvenanceMode`,
  `provenance_backends`, `provenance_identities` validation.
- `crates/hort-domain/src/oci.rs` — `sigstore_bundle_layers`,
  `is_pure_sigstore_bundle`, `SIGSTORE_BUNDLE_MEDIA_TYPE`.
- `crates/hort-app/src/use_cases/provenance_orchestration.rs` — bundle
  resolution, proxy referrer-fetch arm, mode-applied verdict fold, the
  `hort_provenance_verify_total` / `hort_provenance_reject_total` metrics.
- `crates/hort-app/src/use_cases/quarantine_use_case.rs` —
  `resolve_provenance_clearance` in the release sweep.
- `crates/hort-app/src/use_cases/ingest_use_case.rs` — the
  `provenance-verify` enqueue gate and `ingest_signature_manifest`.
- `crates/hort-http-oci/src/manifests_write.rs` — pure-bundle routing and
  the mixed-manifest still-scanned guard test.
- `crates/hort-domain/src/ports/upstream_proxy.rs` /
  `crates/hort-adapters-upstream-http/src/lib.rs` —
  `UpstreamProxy::fetch_referrers` with the tag-scheme fallback.
- `crates/hort-worker/src/composition.rs` — verifier registration, pinned
  trust-root boot contract, `health_check` semantics;
  `crates/hort-worker/src/metrics_server.rs` — the worker `/metrics`
  listener that makes the provenance series scrapeable.
- ADR 0006 — mandatory upstream verification (the checksum leg of the same
  Origin principle; this ADR adds the publisher-identity leg).
- ADR 0007 — fail-closed quarantine release predicate (the gate this
  decision tightens without adding an authority).
- ADR 0010 — TLS via builder, no insecure knobs (drives the pinned-root
  choice); ADR 0015 — apply-time linter doctrine (drives the fail-closed
  mode linting).
- Full design history: preserved in the frozen pre-1.0 development history
  (git).
