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
   and — under `provenance_mode: Required` with the hold-until-signed amendment
   — the subject image is never cleared and rejects `Unsigned` at window expiry.
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
    `cosign sign` aborts, and the artifact expires `Rejected{Unsigned}`. The
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
    a signature of their own and terminally reject `Unsigned` at window
    expiry, leaving the released index unpullable (each child GET → 404).

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
      provenance-gated and terminally reject under `Required` (fail-closed;
      such nesting is not supported for pull under `Required` today).
    - **Idempotent**: a constituent already carrying a `ProvenanceVerified`
      takes no duplicate. A per-constituent append that loses a version
      race (a concurrent event on the constituent's stream) retries once
      with a fresh read before falling back to warn + skip.

    **The already-cleared verify no-op.** A cleared artifact — most
    importantly a cascade-cleared constituent whose S4 expiry-backstop
    verify was enqueued while it was still `Pending` — has no referrer
    surface of its own, so a window-closed re-verify would re-judge it to
    `Rejected{Unsigned}`. The orchestrator therefore skips the verify
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
    The **root itself** is unchanged — it is not a descendant, so it still
    rejects `Unsigned` at expiry.

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
  verifier — under `Required` (with the ADR 0027 hold-until-signed amendment)
  the image then rejects `Unsigned` at window expiry. The legacy tag scheme
  remains honored only on the upstream-proxy fetch path.

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
- `crates/hort-app/src/use_cases/provenance_orchestration.rs` — the
  single-verifier `applicable[0]` selection, the `backend` metric label, and the
  verdict fold this ADR makes the first multi-verifier user of.
- `crates/hort-domain/src/entities/artifact.rs` — `ProvenanceClearance` /
  `complete_provenance` (now window-aware — ADR 0027 hold-until-signed
  amendment) / the release timer-arm AND-precondition, reused unchanged.
- `crates/hort-http-oci/src/manifests_write.rs` — the `oci_subject`
  content-reference row that subject-links a pushed referrer (why §9 requires
  `--registry-referrers-mode=oci-1-1` for hosted keyed signing).
