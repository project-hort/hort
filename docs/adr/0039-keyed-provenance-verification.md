# 0039 — Keyed (pinned-public-key) provenance verification backend

- **Status:** Accepted
- **Extends:** ADR 0027 (artifact provenance verification) — adds a second
  `provenance_backends` entry behind the same `ProvenancePort`
  (`crates/hort-domain/src/ports/provenance.rs`), reusing `provenance_mode`,
  the release-gate AND-precondition, the apply-time linter, the enqueue gate,
  the `ProvenanceVerified`/`ProvenanceRejected` events, and the verdict-fold
  orchestrator. Only the verification primitive and its trust material differ.
  No new release authority (ADR 0007 unchanged); no new outbound surface
  (ADR 0010 — the keyed path is strictly *more* offline than the bundle path).
- **Enforcement has landed** — the keyed backend
  (`crates/hort-adapters-provenance-cosign-key`), the apply-time linter, and the
  worker wiring are on `develop` behind the same `ProvenancePort`. Code anchors
  below cite symbols, not line numbers.

## Context

ADR 0027 made provenance verification **cosign-bundle-based**: the verifier
validates a Sigstore v0.3 bundle's own material (Fulcio certificate chain with
SCT, Rekor inclusion proof) against a pinned `trusted_root.json`, and matches
the leaf certificate's `{issuer, san}` against the policy's
`provenance_identities`. That model assumes a **Fulcio-issued, OIDC-bound
signing identity** — the correct default for public and ecosystem provenance.
ADR 0027 names its own boundary explicitly: *"a signature published solely in
the legacy cosign `simplesigning` shape yields `NoAttestation`"*, and *"non-OCI
verifiers slot in as additional `provenance_backends` entries behind the same
`ProvenancePort`"*. This ADR fills the first gap using the second mechanism.

The excluded class is the **sovereign, internal-audience operator who signs
first-party artifacts with a long-lived key** (`cosign sign --key`, the
`simplesigning` shape — the live signer here additionally uses
`--registry-referrers-mode=legacy`). For that operator the keyless path is not
merely inconvenient, it is unreachable:

1. **No public Fulcio will issue for the signing identity.** Public Fulcio
   trusts a fixed set of OIDC issuers; a self-hosted GitLab is not one. The
   only keyless route is a self-hosted Sigstore (Fulcio + Rekor) — a whole PKI
   and transparency subsystem stood up purely to satisfy the bundle *format*.
2. **The audience is internal and Hort is the verifier.** The consumer is the
   operator's own clusters/builds pulling *through Hort*, so a key-based
   signature enforced on ingest is a real, load-bearing control — even though
   it carries no transparency-log backing and the ecosystem clients
   (`docker`/`containerd`) never check it. A custom key is the *correct* tool
   for an internal trust domain, not a compromise.
3. **Today the feature is simply off-limits to them.** A keyed first-party
   image under `provenance_mode: Required` resolves to `NoAttestation` →
   `ProvenanceRejected{Unsigned}` (it never produced a Sigstore bundle), so
   `Required` would reject validly-signed first-party content. The only
   deployable stance left is `Off` — i.e. no registry-level provenance gate at
   all.

The pinned trust root in ADR 0027 already makes the *verify* path fully
offline; the missing piece is a second trust primitive — verify a bare
signature against a pinned **public key** rather than a Fulcio chain against a
pinned **root**.

## Decision

**Add a keyed cosign backend — `"cosign-key"` — as an additional
`provenance_backends` entry behind the existing `ProvenancePort`. It verifies a
keyed cosign signature over the OCI `simplesigning` payload against an
operator-pinned public key, binds the payload's claimed manifest digest to the
artifact's actual digest, and uses no Fulcio chain, Rekor proof, SCT, or trust
root. It reuses the ADR 0027 lifecycle (mode, release gate, events, verdict
fold) unchanged; the new code is the verifier adapter, its trust material, **and
a simplesigning-aware carriage extension** — the existing referrer carriage
filters to the modern Sigstore bundle and currently *drops* the legacy `.sig`
(§8), so this is not a pure verifier swap.**

1. **New backend, not new machinery.** `provenance_backends` is a
   `Vec<String>` (`crates/hort-domain/src/entities/scan_policy.rs`, default
   `["cosign"]`); `cosign-key` is a new value in that vec. It registers a
   `ProvenancePort` implementation (`crates/hort-domain/src/ports/provenance.rs`)
   exactly as the Sigstore backend does, and the backend→format capability map
   gains `cosign-key → {"oci"}` (Tier-1, mirroring cosign —
   `crates/hort-app/src/use_cases/apply_config_use_case.rs`). The enqueue gate,
   the `ProvenanceClearance` release AND-precondition
   (`crates/hort-domain/src/entities/artifact.rs`), the verdict fold
   (`crates/hort-app/src/use_cases/provenance_orchestration.rs`), and the events
   are untouched; the `backend` *metric label* gains a new value (see §5).

2. **Verification primitive: keyed signature over the `simplesigning` payload,
   with an explicit digest bind.** `cosign sign --key` over an OCI image does
   **not** sign the artifact bytes — it signs the cosign `simplesigning` JSON
   payload, which carries `critical.image.docker-manifest-digest`. The keyed
   verifier therefore does two load-bearing things, **both required**:
   1. verify the detached signature **over that payload** against the
      configured public key; and
   2. **bind** the payload's `critical.image.docker-manifest-digest` to the
      artifact's *actual* manifest digest.

   Step 2 is not optional. `.sig` carriage is the `sha256-<hex>.sig` tag
   scheme, and **the tag name is attacker-writable in the registry** — so a
   valid signature for image A's payload, re-tagged onto image B, must be
   `Rejected`, never `Verified`. This is exactly the binding the Sigstore
   verifier already treats as first-class — the subject-digest comparison in
   `crates/hort-adapters-provenance-sigstore/src/verifier.rs` and the
   `## Digest binding` section / `sha256(payload) == content_hash` subject
   invariant documented in that crate's `lib.rs`; the keyed verifier must
   mirror it (the *shape* of the bound value differs — a JSON field rather
   than a bundle subject — but the invariant "the signed digest equals the
   served artifact's digest" is identical). Verdicts map as ADR 0027:
   valid signature + matching digest → `Verified`; absent signature →
   `NoAttestation` (allowed under `VerifyIfPresent`, `Unsigned` under
   `Required`); present but signature-invalid, wrong-key, **or digest-mismatch**
   → `Rejected`. The path touches no network.

3. **Trust material is a pinned public key, parallel to `trusted_root.json`.**
   A boot-provisioned public key or key *set*
   (`HORT_PROVENANCE_COSIGN_PUBLIC_KEYS` / a `provenance.cosign.publicKeys`
   Helm value, loaded once — no live fetch). The keyless `provenance_identities`
   `{issuer, san}` model does **not** apply to this backend — there is no
   certificate to extract an identity from; the pinned key *is* the identity
   anchor. **Planned rotation** is a key-set overlap window (same operator
   responsibility as trust-root rotation in ADR 0027). **Compromise revocation
   is sharper:** a keyed `simplesigning` signature carries no trusted
   timestamp, so a compromised key cannot be "rotated past" — there is no Rekor
   time anchor to distinguish pre- from post-compromise signatures. Revoking it
   means removing the key from the pinned set entirely **and re-signing every
   legitimate artifact** that relied on it. The enablement how-to must state
   this.

4. **The apply-time linter becomes backend-aware — in both directions.**
   ADR 0027's fail-closed guards (`scan_policy.rs` validation +
   `apply_config_use_case.rs`) today read: `mode != Off` + empty
   `provenance_backends` ⇒ reject; `Required` + empty `provenance_identities` ⇒
   reject (the any-signer footgun). For `cosign-key` the "identity" requirement
   is a **non-empty pinned key**, not non-empty `provenance_identities`. The
   linter must therefore gate per backend:
   - a scope selecting `cosign-key` under `Required` requires a configured
     public key (fail-closed, mirroring the keyless identity rule); **and**
   - a `cosign-key`-only scope that sets a non-empty `provenance_identities` is
     **rejected**, not silently accepted — those patterns are inert for the
     keyed backend (the key is the only anchor), and accepting-but-ignoring
     them is precisely the accepted-at-apply/inert-at-runtime footgun ADR 0015
     exists to kill.

   A `cosign` (keyless) scope keeps the existing identity-pattern rule
   unchanged.

5. **Metrics gain a new `backend` value — catalog update required.** `backend`
   is a real metric label (`provenance_orchestration.rs`, set from the resolved
   verifier's `name()`); `cosign-key` is a new value of it. Per the
   metrics-catalog doctrine the implementing PR must add the value to
   `docs/metrics-catalog.md`. `backend` is an allowed label and the cardinality
   is trivial (two values), so the addition is in-policy — but ADR 0027's
   "events and metrics untouched" does **not** hold for this label; it is the
   one metric surface that changes.

6. **Verdict fold is OR; the verifiers partition by signature shape.** The fold
   is **already multi-verifier**: `dispatch_and_fold` (`provenance_orchestration.rs`)
   iterates every applicable verifier and folds via `fold_two` — `Rejected` ⊳
   `Verified` ⊳ `NoAttestation`. The two backends **cleanly partition** the bundle
   set: the keyed verifier skips keyless v0.3 bundles (`signature.is_none()`) and
   the keyless verifier skips keyed simplesigning bundles (`signature.is_some()`),
   each returning `NoAttestation` for the other's shape. So on a worker running
   both, a keyed-signed artifact folds `NoAttestation` (keyless) `+ Verified`
   (keyed) `→ Verified` — and vice versa — **never a false-reject**. *(An earlier
   draft missed that the keyless verifier `Rejected{BundleMalformed}` a foreign
   bundle; the symmetric `signature.is_some()` skip in `verify_bundles`
   (`hort-adapters-provenance-sigstore`) is the fix that makes the OR genuinely
   hold.)*

   **Dispatch is worker-level, not per-scope.** `dispatch_and_fold` selects
   verifiers by `applies_to(format)` — it does **not** consult the scope's
   `provenanceBackends` (that field is apply-time config validation, §4; it does
   not gate runtime dispatch). A worker therefore runs *every* configured verifier
   on each OCI artifact. In practice an artifact carries one signature shape, so the
   matching backend decides and the other `NoAttestation`s; the OR is **benign** — a
   keyed signature **requires the operator's pinned key** (unforgeable), so accepting
   it alongside keyless is not a downgrade. To run a **single** backend strictly,
   configure only that verifier on the worker (the keyless trust root XOR the keyed
   key file). The remaining single-verifier simplification is the metric label —
   `backend` names the verifier that decided the folded verdict (A2.4).

7. **Non-OCI (npm/PyPI/cargo) is out of scope here.** The keyed primitive is
   format-agnostic, but those formats have **no referrer/`.sig` carriage**, so
   attaching and fetching a detached keyed signature for a tarball / wheel+sdist
   / crate is a distinct mechanism (a Hort-side detached-signature register +
   an ingest-time fetch), not a verifier swap. Per ADR 0027's "auto-activate
   per format with no schema change", that lands as a future backend+carriage
   addition. Recorded operator intent: sign first-party npm/PyPI/cargo too,
   eventually — **not a current blocker** (the immediate first-party surface is
   OCI images).

8. **Carriage: the legacy `.sig` needs a simplesigning-aware path (the original
   "no carriage work" framing was wrong).** `hort_domain::oci` defines only
   `SIGSTORE_BUNDLE_MEDIA_TYPE` (`application/vnd.dev.sigstore.bundle.v0.3+json`)
   and `sigstore_bundle_layers` keeps *only* layers of that media type, so the
   three carriage sites — `fetch_bundles_once`, `land_one_referrer`, and
   `fetch_and_land_upstream_referrers` (`provenance_orchestration.rs`) —
   **discover but then drop** a legacy cosign `simplesigning` `.sig` (layer media
   type `application/vnd.dev.cosign.simplesigning.v1+json`; signature in the layer
   annotation `dev.cosignproject.cosign/signature`). With the carriage unchanged a
   `cosign-key` verifier receives an empty bundle set → always `NoAttestation`
   (dead code). The keyed path therefore adds, in `hort-domain` + `hort-app`:
   - a simplesigning media-type constant + a `simplesigning_signature_layers`
     helper in `hort_domain::oci` returning, per signature layer, the **payload
     layer digest** and the **`dev.cosignproject.cosign/signature` annotation**
     (the base64 signature); and
   - a keyed branch at the three carriage sites that collects/lands the
     simplesigning referrer (payload blob + manifest) alongside the bundle path.

   **`AttestationBundle` gains one optional field (option b):** the verifier lives
   in an adapter with **no `StoragePort`**, so it cannot read the payload layer
   itself — the orchestrator must hand it both halves. `AttestationBundle` becomes
   `{ bytes, signature: Option<Vec<u8>> }`: for a keyless v0.3 bundle `signature =
   None` and `bytes` is the bundle blob (unchanged); for a keyed `.sig` the
   orchestrator reads the simplesigning **payload layer blob** into `bytes` and the
   **annotation** into `signature`. The keyed verifier requires `signature.is_some()`,
   verifies it over `bytes` against the pinned key, and binds
   `bytes.critical.image.docker-manifest-digest == "sha256:" + subject.content_hash`;
   the keyless verifier ignores `signature` and parses `bytes` as a v0.3 bundle (a
   simplesigning `bytes` is not one → `NoAttestation`). One bundle list thus carries
   both shapes and each verifier self-selects (§6).

## Consequences

- A sovereign keyed-cosign operator gets `provenance_mode: Required`
  enforcement on first-party **OCI** images with **zero new infrastructure** —
  no Fulcio, no Rekor, no trust root; the public key already held in the
  operator's secret store is the only new config.
- A keyed signature is a **weaker assertion than a keyless bundle**: no
  transparency-log inclusion, no OIDC-identity binding, no public verifiability,
  and **no trusted timestamp** — so it attests only "signed by the holder of
  key K", trusted solely because the operator pinned K, and a key compromise
  forces full re-signing rather than a rotation window (§3). It is the correct
  trade *only* for an internal-audience deployment where Hort is the verifier;
  it must never be presented as public-grade provenance.
- The `simplesigning`-→-`NoAttestation` limitation ADR 0027 documented is
  lifted **only for scopes that select `cosign-key`**; keyless scopes are
  byte-for-byte unchanged.
- A worker runs every configured verifier; the keyed and keyless verifiers
  **partition by signature shape** (each skips the other's bundles), so the
  OR-fold never false-rejects (§6). `provenanceBackends` is apply-time config
  validation, **not** a runtime dispatch gate — to run a single backend strictly,
  configure only that verifier on the worker (keyless trust root XOR keyed key file).
- The keyed verifier needs only a minimal cosign-signature / public-key
  primitive, not the full `sigstore` bundle/PKI crate — a smaller dependency
  and advisory surface on that path.
- Two cross-cutting edits, not one. (1) The apply-linter: per-backend
  identity-requirement checks in **both** directions (require a key for keyed;
  reject inert identities on keyed) — a tightening, not a relaxation (every
  previously-rejected config still rejects). (2) The simplesigning carriage (§8):
  `AttestationBundle` gains an optional `signature` field and the three referrer
  sites stop filtering the legacy `.sig` out — additive (the keyless v0.3 path is
  byte-for-byte unchanged: `signature = None`, same `bytes`).
- The `backend` metric label gains the `cosign-key` value (catalog update in
  the implementing PR — §5).

## Alternatives considered

- **Stand up a self-hosted Sigstore (Fulcio + Rekor) and stay keyless.**
  Rejected for this use case: an entire PKI + transparency subsystem to obtain
  guarantees the internal audience does not consume (no external verifier, no
  transparency auditor); the pinned key is the minimal sufficient trust anchor.
- **Sign first-party images keyless via *public* Sigstore from the CI.** Not
  possible: public Fulcio will not issue a certificate for a self-hosted-GitLab
  OIDC identity.
- **Leave Hort `Off` and verify only at admission (Kyverno) against the key.**
  A viable interim and complementary defence, but it leaves the *registry*
  ungated — Hort would store unsigned first-party pushes and serve them; the
  registry-level `Required` gate (reject on ingest) is the property this ADR
  buys.
- **A new top-level keyed-provenance config rather than a `provenance_backends`
  entry.** Rejected: it would duplicate the `provenance_mode` / release-gate /
  linter / event machinery ADR 0027 already made load-bearing; the backend slot
  is the designed extension point.
- **Verify keyed signatures by wrapping the key in a synthetic trust root.**
  Rejected: a cosign keyed `simplesigning` signature has no Fulcio certificate
  or Rekor entry to validate against a root; forcing it through the bundle
  verifier is a category mismatch. A distinct, smaller keyed verifier is
  cleaner than contorting the Sigstore path.
- **AND-fold both backends (require keyless *and* keyed).** Rejected as the
  default: it would force every first-party image to carry two signature shapes;
  the deployment that wants both assurances can express it by separate scopes or
  a future explicit AND mode, but OR with deliberate per-scope backend
  selection (§6) is the simpler correct default.

## References

- ADR 0027 — artifact provenance verification (the design this extends: the
  `ProvenancePort`, `provenance_mode`, `ProvenanceClearance` release gate,
  apply-time linter, referrer carriage, and the explicit "`simplesigning` →
  `NoAttestation`" boundary this ADR addresses).
- ADR 0006 / 0007 / 0010 / 0015 — checksum leg / fail-closed release predicate /
  TLS-builder offline discipline / apply-time-linter doctrine (as cited in the
  header and §4).
- `crates/hort-domain/src/entities/scan_policy.rs` — `provenance_backends`
  (default `["cosign"]`), `provenance_identities`, `ProvenanceMode`, and the
  fail-closed validation guards the linter extends.
- `crates/hort-domain/src/ports/provenance.rs` — `ProvenancePort`, the
  abstraction the `cosign-key` adapter implements.
- `crates/hort-adapters-provenance-sigstore/src/{verifier.rs,lib.rs}` — the
  subject-digest binding (`## Digest binding`, the `sha256(payload) ==
  content_hash` invariant) the keyed verifier mirrors for step 2.2.
- `crates/hort-app/src/use_cases/apply_config_use_case.rs` — the backend→format
  capability map (Tier-1 `{"oci"}` for cosign) and the fail-closed config lints
  to make backend-aware.
- `crates/hort-app/src/use_cases/provenance_orchestration.rs` — the
  single-verifier `applicable[0]` selection, the `backend` metric label, and the
  verdict fold this ADR makes the first multi-verifier user of.
- `crates/hort-domain/src/entities/artifact.rs` — `ProvenanceClearance` /
  `complete_provenance` / the release timer-arm AND-precondition, reused
  unchanged.
