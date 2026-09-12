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
- **The 2026-09-12 amendment is a decision, not yet enforcement.** Its D1–D7
  supersede the "unsigned at window expiry ⇒ terminal `Rejected{Unsigned}`"
  outcome throughout this ADR (the body is written to the amended decision);
  the code still produces that rejection until the implementing change lands.
  As-built references that describe the current behaviour — `docs/metrics-catalog.md`,
  the E2E scenario inventory — are correct as they stand and move with that
  change, not with this one.

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
`simplesigning` shape). Hosted keyed signing on Hort **requires OCI referrers
mode** (`cosign sign --registry-referrers-mode=oci-1-1`); see §9 — the canary
signer must use `oci-1-1`, **not** `--registry-referrers-mode=legacy`. For that
operator the keyless path is not merely inconvenient, it is unreachable:

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
   `NoAttestation` (allowed under `VerifyIfPresent`; **held** under `Required`,
   never terminal — see the 2026-09-12 amendment below, which replaces the
   earlier `Unsigned`-at-expiry rejection); present but signature-invalid,
   wrong-key, **or digest-mismatch** → `Rejected`. The path touches no network.

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

8. **The keyed carriage covers TWO shapes: the legacy `simplesigning` `.sig`
   AND the cosign v3 keyed Sigstore v0.3 bundle.** The keyed backend consumes
   both carriages a keyed `cosign sign --key` can emit; the earlier "keyed ⟺
   simplesigning" framing held only for cosign v2 / `--registry-referrers-mode=legacy`:

   - **Legacy `simplesigning`** (layer media type
     `application/vnd.dev.cosign.simplesigning.v1+json`; signature in the layer
     annotation `dev.cosignproject.cosign/signature`). `hort_domain::oci`'s
     `sigstore_bundle_layers` keeps *only* `SIGSTORE_BUNDLE_MEDIA_TYPE` layers,
     so the three carriage sites — `fetch_bundles_once`, `land_one_referrer`,
     `fetch_and_land_upstream_referrers` (`provenance_orchestration.rs`) —
     would otherwise **drop** this `.sig`. The keyed path adds a
     `simplesigning_signature_layers` helper + media-type constant returning,
     per signature layer, the **payload layer digest** + the base64
     **`dev.cosignproject.cosign/signature` annotation**, and a keyed branch at
     the three sites that collects/lands the simplesigning referrer.

   - **cosign v3 keyed Sigstore v0.3 bundle** — the shape
     `cosign sign --key --registry-referrers-mode=oci-1-1` actually emits (cosign
     v3, the ADR §9-required mode). It is a v0.3 bundle referrer
     (`artifactType = application/vnd.dev.sigstore.bundle.v0.3+json`, layer media
     type the same) carrying a **DSSE envelope** over an in-toto Statement — the
     *same wire shape* as a keyless bundle. It is already collected by the
     existing `sigstore_bundle_layers` bundle path; the keyed/keyless split is
     the bundle's `verificationMaterial`: **keyed = a bare `publicKey` (no Fulcio
     cert); keyless = a `certificate` / `x509CertificateChain`.** A pure
     `hort_domain::provenance_bundle::extract_keyed_dsse_signature` helper parses
     the bundle bytes and, iff keyed (no cert), returns the DSSE **PAE** signing
     input (`DSSEv1 SP len(type) SP type SP len(payload) SP payload` — the
     signature is over the PAE, **not** the raw payload), the raw signature, and
     the in-toto `subject[].digest.sha256` to bind. The orchestrator's
     `build_bundle` routes a keyed bundle as `signature = Some(raw DSSE sig)`
     (the keyed verifier's) and a keyless one as `signature = None`
     (the Sigstore verifier's, byte-for-byte unchanged).

   **`AttestationBundle` gains one optional field (option b):** the verifier lives
   in an adapter with **no `StoragePort`**, so it cannot read the payload layer
   itself — the orchestrator must hand it both halves. `AttestationBundle` becomes
   `{ bytes, signature: Option<Vec<u8>> }`. For a **keyed simplesigning** `.sig`
   the orchestrator reads the simplesigning payload-layer blob into `bytes` and the
   decoded annotation into `signature`, and the keyed verifier binds
   `bytes.critical.image.docker-manifest-digest`. For a **keyed v0.3 bundle**
   `bytes` is the bundle blob and `signature` is the raw DSSE signature, and the
   keyed verifier re-derives the DSSE PAE + in-toto subject digest from `bytes`.
   For a **keyless v0.3 bundle** `signature = None` and `bytes` is the bundle blob
   (unchanged). The keyed verifier requires `signature.is_some()` and self-selects
   on the `bytes` shape (a v0.3 bundle → DSSE PAE path; else → simplesigning
   payload path); the keyless verifier ignores `signature` and parses `bytes` as a
   v0.3 bundle. One bundle list thus carries every shape and each verifier
   self-selects (§6).

9. **Keyed hosted signing requires OCI referrers mode.** The keyed carriage
   (§8) collects a keyed signature from a subject-linked **referrer** manifest —
   the `oci_subject` content-reference row that push writes
   (`crates/hort-http-oci/src/manifests_write.rs`) is what binds the signature to
   the image the verifier is judging, and what S3's signature-arrival re-verify
   (ADR 0027 amendment) resolves. Under `--registry-referrers-mode=oci-1-1`,
   cosign v3 emits a keyed **Sigstore v0.3 bundle** referrer (a DSSE envelope
   whose `verificationMaterial` is a bare `publicKey`), **not** a legacy
   `simplesigning` layer — the keyed backend consumes that bundle shape too (§8).
   The legacy cosign
   `sha256-<hex>.sig` **tag scheme** is honored only on the **upstream-proxy
   fetch** path (`UpstreamProxy::fetch_referrers`'s tag-scheme fallback, ADR
   0027 §8 / `provenance_orchestration.rs`), **not** on the hosted push path: a
   signature pushed to a `sha256-<hex>.sig` tag carries no `subject` and so is
   never subject-linked into local carriage, stays invisible to the verifier,
   and — under `provenance_mode: Required` — the subject image is never cleared
   and so stays **held** (`Quarantined`, 503) indefinitely, per the 2026-09-12
   amendment below. Fail-closed either way, and unlike the terminal rejection
   that outcome replaces, recoverable: re-sign with `oci-1-1` and the subject
   verifies.
   Therefore **first-party hosted keyed signing MUST use
   `cosign sign --registry-referrers-mode=oci-1-1`** (subject-based referrers,
   already handled by carriage), and the enablement how-to states this. Legacy
   tag-scheme support on the hosted push path is deliberately **not built**
   (recorded operator intent: if it is ever needed, it is a follow-on that
   mirrors the proxy-side tag-scheme fallback onto push — `manifests_write`
   recognition + `oci_subject` linkage — not part of this decision). The canary
   / test signer must accordingly use `--registry-referrers-mode=oci-1-1`, not
   `legacy`. This is the one operator-facing behaviour change; it is a
   documentation requirement, not new code (the OCI-referrers path was already
   the supported carriage).

10. **The hold-read exemption covers a write-authorized manifest HEAD *and*
    GET, and it keys on the principal's *granted* write authority.** Under
    `provenance_mode: Required` the subject image is held
    `Quarantined` (ADR 0027 hold-until-signed amendment) until a signature
    arrives, so the signer needs a way to resolve the subject *before* the
    manifest is released. Keyed `cosign sign` resolves the subject manifest by a
    `GET manifests/<digest>`, not only a `HEAD`, before it attaches the
    signature — so the manifest hold exemption in `crates/hort-http-oci/src/
    manifests.rs` (`serve`, `write_authorized_hold_read`) covers a
    write-authorized manifest **HEAD and GET**. A manifest is a routing document
    (config + layer digests), not runnable content; the layer blobs are the real
    bytes, and `crates/hort-http-oci/src/blobs.rs` keeps its existence probe
    **HEAD-only**, so a held layer's bytes are never served and the image cannot
    be pulled or run while held. The exemption is `Write`-only: every read
    caller whose identity lacks the Write grant (non-writer / anonymous / proxy
    read scope) and every layer blob stay 503, so no runnable content leaves
    quarantine (only the metadata manifest, only to a write-granted principal)
    and the transparent-proxy contract (quarantine invariant #5) is untouched.

    **"Write-authorized" means granted write authority — the grants leg alone,
    not the presented token's cap.** Standard OCI clients
    (cosign / go-containerregistry, skopeo, docker) scope a subject read as
    `pull` — spec-correct, least-privilege — so under native tokens
    (ADR 0036) the capability JWT presented on the subject read synthesizes a
    read-only cap even when the principal's grants carry Write. A hold
    exemption keyed on the full cap-intersected `Write` resolve therefore
    never engages for a correctly-behaving signer: the held-manifest GET 503s,
    `cosign sign` aborts, and the artifact is never signed at all — so it stays
    held forever (under the 2026-09-12 amendment below; before that amendment
    it expired `Rejected{Unsigned}`). Note that the amendment makes this
    exemption *more* load-bearing rather than less: with no expiry to force the
    issue, an exemption that does not engage means an image that is never
    consumable, with nothing in the artifact's state to say why. The
    two exemption sites — the held-manifest HEAD/GET predicate in
    `manifests.rs` and the held-blob HEAD existence probe in `blobs.rs` —
    evaluate `RepositoryAccessUseCase::resolve_granted_write`, which runs
    `RbacEvaluator::authorize_granted` (the grants leg only, including the B1
    fail-closed admin-claim/no-cap arm) instead of the grants ∧ cap
    `authorize`. The read being exempted stays fully cap-gated: a pull-scoped
    token satisfies the ordinary `resolve(Read)` path normally; only the
    *held-visibility* decision consults identity-level authority.

    **Bounded ADR 0036 exception + blast radius.** This is a deliberate,
    narrow exception to the ADR 0036 cap-intersection invariant, bounded to
    exactly these two exemption sites; every other authorization decision
    keeps the two-leg AND. Blast radius of the exception: a stolen pull-scoped
    token of a write-granted principal can read *held manifests* (and observe
    held-blob existence) in repositories that principal can write —
    metadata-only, principal-bound, layer bytes still gated. The same stolen
    token could not push, and a stolen token of a non-writer gains nothing.

11. **A verified subject's clearance cascades to its signed constituents.**
    cosign signs only the **top-level digest** — the index for a multi-arch
    image, the manifest for a single-arch one. Under `provenance_mode:
    Required` the per-artifact gate alone therefore structurally rejects
    every constituent of a validly signed image: the subject verifies and
    releases, but its child manifests and config/layer blobs can never carry
    a signature of their own, so without the cascade they never clear at all
    and the released index stays unpullable (each child GET → 404). (As
    originally built the constituents *terminally rejected* `Unsigned` at
    window expiry; they now hold instead — the amendments below — but the
    index is equally unpullable either way, which is what makes the cascade
    load-bearing rather than merely convenient.)

    **Cryptographic justification.** The signed top-level digest binds the
    whole tree: an index's `manifests[]` child digests are inside the signed
    index bytes, and each manifest's `config`/`layers[]` digests are inside
    that manifest's bytes — a Merkle-like chain, so the signature over the
    root digest covers the exact bytes of every constituent. Clearing the
    constituents on the subject's `Verified` verdict extends the *same*
    attestation to the *same* bytes; it widens no trust.

    **Mechanism.** When the orchestrator's folded verdict is `Verified`
    under `Required`, it derives the constituent set **from the verified
    subject's CAS bytes** (`is_image_index` → `index_child_digests`, then
    per child manifest read back from CAS — and for a single-image subject,
    the subject bytes themselves — `manifest_blob_digests` for the
    `config` + `layers[]` digests), resolves each digest to an artifact row
    **in the same repository**, and appends a `ProvenanceVerified` to each
    held constituent's stream via the domain's
    `Artifact::cascade_provenance_clearance` + the same
    `commit_transition` the subject's own clearance uses. The event carries
    the subject's verified `signer` and a `cascaded_from: <root digest>`
    field, so the audit trail reads "cleared via signature over `<root>`"
    and a cascaded clearance is always distinguishable from a direct one.

    **Fail-closed edges (all load-bearing):**
    - The set derives from the **signed CAS bytes only** — never from
      `content_references` / `oci_index_member` DB edges or the name-keyed
      group model, which are broader and mutable; deriving from them would
      cascade clearance to content the signature does not cover.
    - **Same repository only** (`find_by_repo_and_checksum`); a same-digest
      artifact in another repo is never touched.
    - **Held (`Quarantined`) constituents only.** A terminally rejected or
      scan-indeterminate constituent stays terminal (the operator
      re-pushes); `Released`/status-`None` rows need no clearance. The
      domain guard refuses every non-`Quarantined` state.
    - **Only the provenance authority cascades.** The constituent stays
      held: its own scan success / waiver and the observation window still
      gate its release per-artifact (ADR 0007's fail-closed predicate,
      ADR 0043's layer-level-safety model are unchanged).
    - **Bounded** by the existing parse caps (`MAX_INDEX_CHILDREN`,
      `MAX_MANIFEST_BLOBS` mirroring the write path's
      `MAX_BLOB_REFERENCES`); a subject whose bytes fail to parse cascades
      to nothing (warn), and no cascade failure can retract or block the
      subject's own already-committed clearance (best-effort, warn +
      continue per constituent).
    - **One level of index nesting.** The cascade walks exactly one level:
      index → child manifests → their `config`/`layers` blobs. A child that
      is itself an index contributes only its own digest — its children are
      never read — so grandchildren of an index-of-indexes remain
      provenance-gated and never clear under `Required` (fail-closed; they
      stay **held** per the 2026-09-12 amendment below, where they previously
      rejected terminally — either way such nesting is not supported for pull
      under `Required` today).
    - **Idempotent**: a constituent already carrying a `ProvenanceVerified`
      takes no duplicate. A per-constituent append that loses a version
      race (a concurrent event on the constituent's stream) retries once
      with a fresh read before falling back to warn + skip.

    **The already-cleared verify no-op.** A cleared artifact — most
    importantly a cascade-cleared constituent whose S4 expiry-backstop
    verify was enqueued while it was still `Pending` — has no referrer
    surface of its own, so a window-closed re-verify would re-judge it to
    `Rejected{Unsigned}` (under the 2026-09-12 amendment below it would
    instead re-judge it to a *hold* — which keeps this skip worth having:
    an already-cleared artifact must not be reported as waiting for
    evidence it does not need). The orchestrator therefore skips the verify
    (`SkippedAlreadyCleared`, `result_summary: skipped:already_cleared`)
    whenever a `Required`-mode artifact's stream already carries a
    `ProvenanceVerified`. When the stored clearance is a **direct**
    verification (`cascaded_from: None` — the artifact is a signed
    subject), the skip first re-drives the idempotent cascade with the
    stored event's signer, so re-signing heals a constituent whose
    cascaded append was lost; a cascaded clearance never re-walks bytes.

    **The verify-BEFORE-cascade race (issue #115, amended 2026-08-05).**
    `SkippedAlreadyCleared` guards one ordering — a re-verify landing
    *after* the cascade. The inverse ordering was open: a constituent
    verified *before* its subject's cascade ran. OCI pull-through writes
    `oci_config`/`oci_layer` edges before the blobs are pulled, so every
    layer ingests as a **zero-window referenced-tree descendant** (ADR 0007
    / issue #46) and immediately enqueues its own `provenance-verify`. That
    verify finds no bundle — cosign signs only the top-level digest — and
    under `Required` with `window_open == false` it terminally rejected the
    layer as `Unsigned` *before* the subject was even verified. The cascade
    then hit the "terminal is terminal" refusal on an artifact it should
    have cleared, and the signed image was permanently unpullable.

    Closed at the **verdict layer** (not by skipping the ingest enqueue —
    that would leave the S4 backstop and duplicate S3 enqueues able to
    reject through the same door, the exact mistake `SkippedAlreadyCleared`
    exists to prevent): `Artifact::complete_provenance`'s
    `NoAttestation × Required` arm now holds on `window_open ||
    is_referenced_descendant`. **The cascade is therefore guaranteed to
    find its constituents in `Quarantined`, never terminally rejected**, in
    either ordering — which is what makes the §11 cascade's
    `Quarantined`-only precondition satisfiable in practice. A descendant's
    provenance authority is its parent's signature; it can never carry an
    attestation of its own, so "unsigned at expiry" is not a meaningful
    verdict for it. Scoped exactly like `window_open`: a forged /
    untrusted / digest-mismatch signature on a descendant still rejects
    terminally.

    The never-signed path is **amended accordingly**: an unsigned root
    still cascades nothing, but its constituents now stay **held
    `Quarantined`** (503, `Pending` at the release gate) instead of
    rejecting `Unsigned` at expiry. Fail-closed either way — and unlike
    the terminal rejection it replaces, recoverable: sign the root, the S3
    hook re-verifies the subject, and the cascade clears the constituents.
    The **root itself** was left unchanged by that amendment — it is not a
    descendant, so it still rejected `Unsigned` at expiry. **The 2026-09-12
    amendment below closes that last shape too:** the root is held on the same
    terms as its constituents, because "the signature has not arrived yet" is
    a statement about a point in time on every shape, the subject included.
    After that amendment the never-signed path holds the whole tree, and the
    recoverability described above applies to the root as well.

    **The late-joiner (constituent-end) trigger (amended 2026-08-08,
    issue #135; direction and this amendment approved on-issue).** The
    cascade above fires at the SUBJECT's verify, over the constituents
    that exist *at that moment*. The inverse arrival order had no
    trigger at all: a constituent ingested AFTER its subject was
    verified never gets one. Its own verify finds no bundle (cosign
    signs only the top-level digest); the `NoAttestation × Required`
    arm HOLDS it (the amendment above); and the S4 expiry backstop skips
    parent-gated blob constituents — so it stays `Pending` forever, and
    the non-skipped shapes (a child *manifest*) churn the backstop every
    tick. Consumer-visible on any multi-arch proxy repo under `Required`:
    a `skopeo copy --all` after the release pulls the foreign-platform
    subtrees through cold pull-through, and every one of them strands.

    Closed by the **symmetric second trigger**: at its own
    quarantine-commit time, a `Required`-mode constituent looks *up* for
    an already-verified subject and clears itself. Mechanism, in the same
    fail-closed shape as the subject end:

    - **Inbound edges only NOMINATE.** The constituent reads
      `content_references.find_by_target(repo, hash)` (unfiltered — kind
      is not authority) and treats each distinct source artifact as a
      *candidate* subject. Its own `primary_content`/`metadata_blob`
      refcount rows are excluded (self-clearing would be circular).
    - **Membership is decided by the signed CAS bytes**, via the SAME
      `constituent_digests` walk the subject end uses — index →
      `manifests[]` children → each child's `config`/`layers`, one level,
      same caps. A digest not inside those bytes does not clear, no
      matter what the edge says. This is the load-bearing half: DB edges
      are mutable projections and must never become clearance authority.
    - **Authority is a DIRECTLY-verified subject.** A candidate holding
      `cascaded_from: None` is its own authority. A candidate that was
      itself cascade-cleared is NOT: its bytes are covered by someone
      else's signature, and re-walking them is exactly how an
      index-of-indexes would leak clearance to grandchildren. The walk
      instead continues **one hop** to the root its `cascaded_from`
      names, requires THAT root's clearance to be direct, and checks
      membership in the root's bytes. So the covered set is byte-for-byte
      the set the verify-time cascade derives from the same root — never
      wider. (This hop is what lets a late-joining `config`/`layer` blob
      clear: its only inbound edge is its parent child-manifest, which
      under a signed multi-arch index is itself only cascade-cleared,
      while the blob's digest IS inside the index's one-level walk.)
    - **Everything else is inherited unchanged** from the subject end:
      same-repository only, `Quarantined`-only (the domain guard),
      idempotent, one version-conflict retry, and the identical
      `cascaded_from: <root digest>` attribution — a late-joiner
      clearance is indistinguishable from a verify-time one in the audit
      trail, because it *is* the same clearance.
    - **Best-effort, post-commit, never gating.** The quarantine
      transition is already durable when the hook runs. Every failure
      arm — edge-read error, unresolvable candidate, missing/indirect
      clearance, unreadable or unparseable subject bytes, membership
      miss, append failure — is `warn!` + continue and leaves EXACTLY
      the hold the artifact already had. Nothing here can fail, delay,
      or roll back an ingest.

    Observability: `hort_provenance_late_joiner_cleared_total{backend}`
    (one increment per self-clear) plus an `info!` naming subject +
    constituent. Emitted on the ingest path, so it is a `hort-server`
    series — see `docs/metrics-catalog.md`.

12. **Both-ends-trigger principle.** A standing cross-artifact lifecycle
    dependency — "artifact A's state change decides artifact B's state" —
    MUST name a trigger at **both** ends: one fired by A's change, one
    fired by B's arrival/change. A single-ended trigger is correct only
    for the arrival order its author had in mind, and silently strands
    the other order; §11's late-joiner gap is the worked example (the
    subject-end cascade shipped alone, and every constituent that
    happened to arrive later stranded until this amendment). Both ends
    must resolve the decision from the SAME authority — here, the signed
    bytes — so the two can never disagree about what is covered; sharing
    one implementation (`ProvenanceCascade`) is how that is enforced
    structurally rather than by convention. This generalises beyond
    provenance: apply it to any future subject⇄constituent, parent⇄child,
    or policy⇄artifact dependency.

    **Cross-opt-in interaction matrix (ADR 0016 discipline).** The
    late-joiner end adds a clearance **producer**, not a new
    release-authority kind — `ProvenanceClearance` still resolves
    `Cleared` iff a `ProvenanceVerified` exists, the release predicate is
    untouched, and the scan gate is still ANDed. Its interaction with
    every existing operator opt-in that can influence the release-gate
    computation:

    | Opt-in | Interaction | Why it cannot collapse a gate |
    |---|---|---|
    | `trust_upstream_publish_time` | **Orthogonal.** | The late-joiner walk reads no timestamps at all — not the subject's, not the constituent's. It changes *which* artifacts hold a provenance clearance, never *when* an observation window opens or closes. A publish-time-anchored constituent gets its clearance on exactly the same terms as an ingest-anchored one, and still waits out whatever window its anchor produced. |
    | `scan_backends: []` | **Unchanged, still ANDed.** | The clearance is the provenance leg only. A constituent that self-clears still needs its own scan authority (`ScanSucceeded`/`ScanWaived`) to release; with no scan backends the existing waiver semantics apply verbatim, exactly as they do for a verify-time cascaded clearance. No new path reaches release without the scan leg. |
    | `requireApproval` | **Unchanged.** | Approval is a separate release-authority leg evaluated after clearance; producing a clearance earlier does not satisfy it. |

    No combination of the three shortens an observation window, removes
    a leg from the release conjunction, or lets untrusted input into the
    clearance decision: the only new input the late-joiner end reads that
    the subject end does not is the `content_references` edge set, and
    that input is *non-authoritative by construction* — it can only
    propose a candidate subject whose signed bytes must then bind the
    digest. A hostile or corrupted edge set can therefore cause a missed
    clearance (a hold — fail-closed) but never an unearned one. Because
    it adds no operator surface, there is nothing here for the
    apply-time linter to reject; the fail-closed close is structural.

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
  previously-rejected config still rejects). (2) The keyed carriage (§8):
  `AttestationBundle` gains an optional `signature` field, the three referrer
  sites collect the legacy `simplesigning` `.sig`, and `build_bundle` routes a
  keyed cosign v3 Sigstore v0.3 bundle (bare `publicKey`, no Fulcio cert) to the
  keyed verifier `signature`-populated — additive (the keyless v0.3 path is
  byte-for-byte unchanged: `signature = None`, same `bytes`).
- The `backend` metric label gains the `cosign-key` value (catalog update in
  the implementing PR — §5).
- Under `provenance_mode: Required` a validly signed multi-arch image is
  actually consumable end to end: the signature over the index digest clears
  the index **and** — via the §11 cascade — its child manifests and
  config/layer blobs, each still gated by its own scan + window. The cascaded
  clearances are individually audited (`ProvenanceVerified` with
  `cascaded_from: <root digest>` per constituent), and a terminally rejected
  constituent is never resurrected by a later signature.
- Hosted keyed signing has one operator requirement: sign with
  `--registry-referrers-mode=oci-1-1` (§9). A legacy `sha256-<hex>.sig`-tagged
  signature pushed to Hort is not subject-linked and stays invisible to the
  verifier — under `Required` the image is therefore never cleared and stays
  **held** indefinitely (`Quarantined`, 503; see the 2026-09-12 amendment
  below, which replaces the earlier "rejects `Unsigned` at window expiry"
  outcome). The legacy tag scheme remains honored only on the upstream-proxy
  fetch path.

## Amendment (2026-09-12) — absence of evidence is not evidence of absence: an unsigned hold is never terminal

**The defect in one sentence.** A provenance verdict reached *before* the
evidence could arrive becomes terminal, and no later successful verification
lifts it. With cosign the signature necessarily follows the subject it signs —
the signer must resolve the subject manifest before it can attach a signature
to it (§10) — so "the verdict ran first" is the **normal** ordering, not an
edge case.

**This amendment extends a decision already made; it introduces no new
concept.** ADR 0007 already governs "the check could not be completed" on the
**scan** axis, and its answer is a hold: a scan that exhausts its retries
mid-observation-window leaves the artifact `quarantined`, writes **no**
status, and is re-scanned once the scanner recovers — *"self-healing without
operator intervention"*. The provenance axis, in the **identical** situation
("the evidence is not here yet"), does the opposite: it writes a terminal
status. That asymmetry — not any single missing predicate — is the defect
class, and closing it is all this amendment does. Everything below is ADR
0007's existing answer, applied to the second axis.

The decisions are numbered **D1–D7** to keep them distinct from the 1–12 of
the *Decision* section above; they amend §11's never-signed path, the
`NoAttestation × Required` arm the ADR 0027 hold-until-signed amendment
introduced, and §10's expiry reasoning. They supersede, specifically, the
"window closed on a subject ⇒ terminal `Rejected{Unsigned}`" arm of that
amendment — and nothing else about it: the hold itself, its window-awareness,
and its fail-closed release reading are unchanged.

### Field evidence (one production instance)

One affected artifact's complete event stream:

```text
ArtifactIngested / ChecksumVerified / ScanRequested / ArtifactQuarantined   (t+0)
ArtifactGroupMemberAdded                                                     (t+0.09)
ProvenanceRejected   reason=Unsigned  backend=(policy)                       (t+1.08)
ProvenanceVerified   backend=cosign-key                                      (t+6.18)
ScanCompleted                                                                (t+11.2)
   — stream ends —
```

The scan was clean (0 findings). The signature *did* arrive and *did* verify,
5.1 s after the rejection. **No `ArtifactRejected` event exists on the
stream**, yet the artifact's `quarantine_status` is `rejected`, and the
release sweep never picked it up again.

The control group across the same instance: **18878** artifacts carrying a
`ProvenanceVerified` with no prior `ProvenanceRejected` → **18878** released,
zero exceptions. Every artifact carrying a *prior* `ProvenanceRejected` is
stuck. Six such artifacts, all with zero scan findings, anchor→rejection
1.01–2.78 s, rejection→verification ~5.1 s. All six affected repositories run
`quarantine_duration_secs = 1` with `provenance_mode: required`; no
`required` repository on that instance runs a larger window.

### D1 — absence of evidence is not evidence of absence

`ProvenanceRejected{Unsigned}` is a statement about **a point in time** — "no
signature had reached Hort when this verify ran" — not a statement about the
artifact. It must therefore **never** produce a terminal state.

Only a **positive disproof** is a statement about the artifact: a signature
that is *present* and invalid, forged, signed by an untrusted key, or bound to
a different digest. That verdict is position-independent — it is equally wrong
at every later moment — and it alone may be terminal.

The distinction is not stylistic. A terminal state asserts "no future
evidence can change this", and for a missing signature that assertion is
simply false: the very next second can falsify it, and on the instance above
it did — the signature landed ~5.1 s after the rejection in all six cases.
The 18878 healthy artifacts are the same ordering winning the race rather
than a different mechanism; the six lost it by one verify tick.

### D2 — fail-closed is not the same as terminal

"Do not release" and "never reconsider" are separate properties, and safety
needs only the first.

A held artifact is exactly as unrunnable as a rejected one. Under `Required`
both answer `503` to a pull, neither is a release candidate (`Pending` at the
release gate), and the layer bytes are withheld either way — `blobs.rs` keeps
its hold-read extension to a **HEAD-only** existence probe (§10), so no
runnable content leaves quarantine in either state. Holding therefore costs
**nothing** in security, and preserves correctability.

That is why D1 is not a trade-off, and why this amendment does not weigh
safety against recoverability: there is no safety difference to weigh. The
terminal status bought nothing that the hold does not already buy.

### D3 — the shape enumeration goes away

`Artifact::complete_provenance` today holds the `NoAttestation × Required`
arm on `window_open || is_referenced_descendant || is_constituent`. Those
three predicates accumulated from three separate incidents, and each one
covers exactly one **shape** of "the evidence had not arrived yet":

- `window_open` — the signature may still be coming (a late anchor);
- `is_referenced_descendant` — an inbound `content_references` edge already
  exists, so this row is somebody's constituent;
- `is_constituent` — the format handler says this row can never carry an
  attestation of its own, whether or not the edge exists yet.

**The subject manifest is the fourth shape**, and it is the one shape the
enumeration structurally cannot reach: a subject is *defined* by being the
thing a signature is attached to, so "its signature has not arrived yet" is
its normal state for the whole interval between push and sign.

Under D1 the reason `Unsigned` holds **regardless of shape**, and the
enumeration becomes unnecessary. Record this explicitly, because it is the
measurable difference between implementing the decision and patching the
symptom: **a correct implementation of this amendment removes code.** It
deletes the three-predicate condition (and the plumbing that threads those
flags from `ProvenanceOrchestrationUseCase::verify_artifact` into
`complete_provenance` and `apply_verdict`) rather than adding a fourth
condition to it. A change that adds a fourth predicate has not implemented
this amendment; it has produced the fifth incident's precondition.

### D4 — terminality on the provenance axis arises *only* from positive disproof

No deadline. No time window for the signature. Under `Required`, unsigned ⇒
held **indefinitely** (`Quarantined`, answering `503`). An artifact leaves
the hold on the provenance axis only by being verified — directly, or by the
§11 cascade — or through an operator authority that already exists: an admin
release, a curator waiver, or an explicit deletion. Note that retention is
**not** one of them, in either state: the GC-protection filter below excludes
`quarantined` and `rejected` alike, so neither state ages out on its own.

A deadline ("held, but rejected after N") was considered and is **rejected**.
Each argument for one dissolves on inspection:

- **Storage reclamation — no.** `retention_candidate_reader` filters
  `quarantine_status NOT IN ('quarantined', 'rejected', 'scan_indeterminate')`
  *before any retention predicate runs*, and `retention_use_case`'s invariant
  1 names this GC-protection: *"a terminal-failure artifact is evidence, not
  GC fodder."* `Rejected` is reclaimed exactly as little as `Quarantined`, so
  a deadline moves an artifact between two equally GC-protected states and
  buys no bytes back. Note the direction this existing decision actually
  points: if both states are retained as evidence anyway, then **"waiting" is
  the truthful label** for an artifact that is waiting.
- **Sweep load is a query concern, not a status concern.** A `Required`
  artifact whose clearance resolves `Pending` can be skipped by the candidate
  query without any status change — the sweep already resolves that clearance
  through `release_clearance::resolve_provenance_clearance`.
- **"Will this ever release?" is an observability question.** A metric
  answers it strictly better than a status column, because it **keeps the
  age** instead of discarding it: a status transition collapses "held for 20
  seconds" and "held for 20 days" into the same value, which is precisely the
  information an operator needs. The hold itself already ticks the existing
  `hort_provenance_verify_total{result="held_pending_signature"}` value — no
  new label value is required for it; an age-carrying signal for "how long
  has this been waiting" is the implementing change's to name, and lands in
  `docs/metrics-catalog.md` with it (ADR 0017).
- **The cost is concrete, and it is the reason this is a hard no.** A
  deadline re-creates the very construct that has now failed three times
  (`window_open` alone, then `|| is_referenced_descendant`, then
  `|| is_constituent`), and it introduces an operator knob whose only failure
  mode is the bug it exists to bound. There is no value an operator could set
  that is better than "wait".

**Stated plainly, the accepted cost.** A never-signed artifact's row and bytes
persist indefinitely. That is not a new cost — the rejected population it
replaces persists exactly as indefinitely, under the same GC-protection — but
it is a real one, and it is accepted here rather than papered over. If it ever
becomes load-bearing, the answer is a retention rule that can reclaim held or
terminal *evidence* on its own explicit terms, not a status transition whose
purpose is to smuggle the artifact past a filter that was written to protect
it.

### D5 — no `Retry-After` on a hold with no self-resolving deadline

A permanent `503` **with** `Retry-After` tells a well-behaved client to keep
coming back, forever. That is not a hypothetical: `check_quarantine` computes
`Retry-After` from the hydrated deadline and clamps a past deadline to `1`,
so a held-past-expiry artifact today answers `503 Retry-After: 1` on every
pull — an unbounded retry loop advertised by us.

The correct shape already exists in the same module. `check_scan_indeterminate`
returns `503` **without** `Retry-After`, reasoned as *"no self-resolving
deadline"*. An unsigned hold past its observation window has none either: the
thing it waits for is an external event, not the passage of time. **Keep the
`503`, drop the header** for that state; a hold whose window has *not* yet
elapsed keeps its honest computed `Retry-After`, because there the deadline
is real.

**This amendment introduces no new configuration value.** The observation
window keeps exactly the meaning ADR 0054 gives it — a proxy for elapsed
**ecosystem exposure** — and gains no second job. That is the whole point of
D4: the window stops being consulted as a signing deadline, so it goes back to
meaning one thing.

### D6 — the invariant that makes it machine-checkable

**`quarantine_status = Rejected` without an `ArtifactRejected` event on the
artifact's stream is an illegal state.** The status is a projection; the
stream is the record (ADR 0002). A status with no event behind it cannot be
audited, cannot be re-derived, and — as the field evidence above shows — is
invisible to anyone reading the stream to find out what happened.

The provenance axis is the producer, and it has **two** arms that produce it:
`complete_provenance` sets `quarantine_status = Rejected` while appending only
`ProvenanceRejected`, both for the unsigned-at-expiry policy decision and for a
positive disproof. Every other axis already appends an `ArtifactRejected`
alongside its own axis event (the scan path in `QuarantineUseCase`, curation in
`CurationUseCase`, the retroactive policy path in `PolicyUseCase`); provenance
is the one that does not.

D1 removes the first arm — the one the field evidence caught, and the only one
that was ever reachable without a real signature. It does **not** by itself
remove the second: a positive disproof stays terminal (D1, D4), so it keeps
producing `Rejected` off a `ProvenanceRejected` alone. Closing D6 therefore has
a second half — the disproof arm must append an `ArtifactRejected` next to its
`ProvenanceRejected` — and it is recorded here rather than folded silently into
D1, because the two halves are independent: D1 is about *which verdicts may be
terminal*, D6 is about *what a terminal verdict must write*. A terminal
provenance rejection is a legitimate rejection and should look like one on the
stream.

### D7 — ADR 0041 invariant #6 is incomplete, not wrong

ADR 0041 invariant #6(a) is correct in what it says: a *scan* re-judgement
must not clear a provenance rejection, so only a scan-clearable rejection
(`reason = Scanner`) is eligible for one. What is missing is the **provenance
re-judgement** that should stand beside it.

As-built, `Rejected` arising from a provenance rejection is a state with **no
exit at all**:

- `Artifact::release`'s source-state guard admits only `Quarantined` and
  `ScanIndeterminate`; a `(Curator, CuratorWaiver)` release admits
  `Quarantined` alone. So neither admin release nor curator waiver reaches a
  `Rejected` artifact.
- `Artifact::re_evaluate` is the only named exit from `Rejected` — and its
  eligibility guard excludes exactly this rejection kind, because
  `complete_provenance` deliberately leaves `rejection_reason = None` (not
  `Scanner`) to satisfy invariant #6(a). Measured against a production
  artifact, the re-evaluation endpoint returned `200
  {"outcome":"still_rejected"}` and wrote nothing.

Under D1 the state stops arising. The **exit vocabulary still has to name the
gap**, because artifacts are in it now: the six above, and any others on
deployed instances. Closing it is not a re-litigation of invariant #6 — a
provenance-rejected artifact must still be ineligible for a *scan*
re-judgement, exactly as #6(a) says. What it needs is a provenance-axis
re-judgement with its own guard, or an explicit operator exit, and that
naming is the implementing change's scope.

### Operator-facing consequence: a mislabelled parameter, not careless operation

Every affected repository was configured identically, and none of them was
configured carelessly. `quarantine_duration_secs = 1` is a sensible
**exposure** choice for a fast-CI first-party repository — the content is the
operator's own, freshly built, and ADR 0054's ecosystem-exposure rationale
does not apply to bytes nobody else has ever seen.

Nothing in the parameter's name, its type, or its documentation signals that
the same value also bounds **how long a signature may still arrive**. The
window silently acquired a second job (ADR 0007's own amendment records it:
*"the window is ALSO the `Required`-mode provenance hold predicate"*), and an
operator tuning the first job could not see the second. That is why all six
repositories look the same: the configuration was right for what the name
says, and the name did not say the other thing. D4 and D5 remove the second
job rather than renaming the parameter — one meaning per knob is the durable
fix, and ADR 0029's hard-rename machinery is not needed for a field whose
documented meaning is the one that survives.

### What this amendment does not change

- **The release gate.** `ProvenanceClearance` still resolves `Cleared` iff a
  `ProvenanceVerified` exists on the stream; `Pending` is still the
  fail-closed reading; the scan, curation and window conjuncts are untouched.
  No release authority is added or widened.
- **Positive disproof.** A forged, wrong-key, digest-mismatched or malformed
  signature still rejects terminally, on every shape — subject, constituent,
  descendant alike (§11's existing wording on that point stands verbatim).
- **The §11 cascade and both its triggers**, including the
  both-ends-trigger principle (§12). The amendment *widens* the population
  the cascade is guaranteed to find in `Quarantined`: under D1 a subject can
  no longer terminally reject itself before its own signature lands, which is
  the subject-end analogue of what the descendant hold did for constituents.
- **ADR 0016 is not triggered.** The amendment adds no operator opt-in and no
  new input to the release-gate computation; it *removes* a transition. Its
  only configuration effect is subtractive — the observation window stops
  influencing the provenance axis (D5), which narrows, not widens, what an
  operator setting can reach.

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
- `crates/hort-domain/src/provenance_bundle.rs` —
  `extract_keyed_dsse_signature`, the pure zero-I/O helper that parses a cosign
  v3 keyed Sigstore v0.3 bundle (bare `publicKey`, DSSE envelope) into the PAE
  signing input + raw signature + in-toto subject digest (§8), and the
  keyed/keyless discriminator (no Fulcio cert ⟺ keyed).
- `crates/hort-app/src/use_cases/apply_config_use_case.rs` — the backend→format
  capability map (Tier-1 `{"oci"}` for cosign) and the fail-closed config lints
  to make backend-aware.
- `crates/hort-app/src/use_cases/provenance_cascade.rs` — the shared
  clearance-cascade machinery both trigger ends of §11 use
  (`cascade_clearance` / `constituent_digests` / `cascade_one` for the
  subject end, `resolve_late_joiner_clearance` / `clearance_root` for the
  constituent end). One implementation so the two ends can never drift on
  what a signature covers (§12).
- `crates/hort-app/src/use_cases/provenance_orchestration.rs` — the
  single-verifier `applicable[0]` selection, the `backend` metric label, and the
  verdict fold this ADR makes the first multi-verifier user of.
- `crates/hort-domain/src/entities/artifact.rs` — `ProvenanceClearance` /
  `complete_provenance` (window-aware per the ADR 0027 hold-until-signed
  amendment; its `NoAttestation × Required` shape enumeration is what the
  2026-09-12 amendment's D3 removes) / the release timer-arm
  AND-precondition, reused unchanged; `release`'s source-state guard and
  `re_evaluate`'s eligibility guard — together the reason a
  provenance-derived `Rejected` has no exit (D7).
- `crates/hort-app/src/use_cases/release_clearance.rs` —
  `resolve_provenance_clearance`, the single-source `Cleared`/`Pending`
  resolution the release sweep and the ADR 0041 re-evaluation callers share;
  the reason a `Pending` artifact can be skipped by a query rather than by a
  status change (D4).
- `crates/hort-http-oci/src/quarantine.rs` — `check_quarantine` (computed
  `Retry-After`, clamped to 1 on a past deadline) and
  `check_scan_indeterminate` (`503`, no `Retry-After`, *"no self-resolving
  deadline"*) — the two shapes D5 chooses between.
- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` and
  `crates/hort-app/src/use_cases/retention_use_case.rs` — the
  `quarantine_status NOT IN ('quarantined', 'rejected', 'scan_indeterminate')`
  GC-protection filter and its invariant 1 (*"a terminal-failure artifact is
  evidence, not GC fodder"*): why a deadline reclaims nothing (D4).
- ADR 0054 — the quarantine window as a proxy for elapsed **ecosystem
  exposure**, the single meaning D5 keeps it to.
- ADR 0041 — invariant #6, which D7 records as incomplete rather than wrong.
- `crates/hort-http-oci/src/manifests_write.rs` — the `oci_subject`
  content-reference row that subject-links a pushed referrer (why §9 requires
  `--registry-referrers-mode=oci-1-1` for hosted keyed signing).
