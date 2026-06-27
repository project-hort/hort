# Dogfood supply-chain migration — backlog

Branch-local planning doc (doc-lifecycle: reviewed, then removed at release).
Companion to **ADR 0039** (keyed provenance verification) on this branch and
**ADR 0034** (public dogfood deployment).

**Goal.** Retire the dogfood deployment's legacy `supply-chain-security` GitLab
pipeline incrementally, with **Hort as the registry-level security gate**:
first-party images published to Hort with keyed signing + Hort-enforced
provenance, third-party images served through Hort's proxy-cache + scan-gate.
Sovereign (no public Sigstore — the signing CI is a self-hosted GitLab that no
public Fulcio will issue for), internal audience (consumers are the operator's
own clusters pulling through Hort). This is the dogfood realisation of ADR 0034.

**Current state.** Prod + test Hort on `0.9.4-beta.5`. OIDC federation
(GitLab→Hort token exchange) verified end-to-end. Prod scan-gate
(`default-scan-1h`, Trivy, block-on-critical) + the admin-task reapers live.
First-party images today are built by app CI and pushed to **Zot**; the legacy
pipeline mirrors/scans/signs **third-party** images into Zot (RED overall on its
mirror stage — see P1 — but its decoupled federation probe is green). Kyverno
(operator cluster) does registry-rewrite + **audit-mode** cosign verify.

The pipeline does two unrelated jobs — curate the 3rd-party mirror (Track B) and
prove the federation push path (now a vestigial probe). First-party signing
lives in app CI, not this pipeline. The two tracks are independent; A1 and B2
are the "start now" items.

---

## Track A — first-party images → Hort (the new capability)

- **A1 — Pilot one first-party image onto Hort (storage + scan). [NOW, non-blocking]**
  Pick one low-risk internal image; point its CI publish at a Hort hosted repo;
  keep keyed cosign signing in CI (Vault key, unchanged); Hort scan-gate applies
  on ingest. Verification stays at **admission** — flip the Kyverno
  `verify-image-signatures` policy `Audit`→`Enforce` for that image. Hort
  `provenanceMode: off` for now (it can't verify keyed sigs yet — A2). Proves the
  first-party→Hort path before A2 ships.

- **A2 — [IN THIS REPO / BLOCKS A3] Keyed provenance backend — ADR 0039.**
  `cosign-key` backend: verify a keyed cosign signature over the simplesigning
  payload against a pinned public key + bind the manifest digest. ADR 0039 on
  this branch, Status **Proposed** (review-revised). Decomposed into the PR-sized
  **A2 implementation sub-backlog** below (§A2.1a–A2.5) — A2.1a (carriage) +
  A2.1b (verifier) are the blocking core, A2.3 the fail-closed gate. Tracks
  implementation + release in a Hort build.

- **A3 — [BLOCKED ON A2] Enforce keyed provenance at the registry.**
  Once 0039 ships: first-party hosted repo ScanPolicy `provenanceMode: required`
  + `provenanceBackends: [cosign-key]` + pinned public key (from the operator's
  secret store). Registry then rejects unsigned/invalid first-party pushes on
  ingest. Decide Kyverno keyed-verify disposition — keep as admission-layer
  defence-in-depth, or retire (coupled: don't drop the registry gate and the
  admission gate at once).

- **A4 — [FUTURE, non-blocking] Cross-format keyed signing (npm/pypi/cargo).**
  Operator intends to sign first-party npm/pypi/cargo too. Needs Hort
  signature-*carriage* for non-OCI (no referrer/`.sig` equivalent) — a follow-on
  ADR after 0039 (recorded in 0039 §7 as out-of-scope). Not a current need.

### A2 implementation sub-backlog (ADR 0039)

PR-sized, dependency-ordered; bracketed §-refs point at ADR 0039. Coverage
gates per CLAUDE.md: `hort-domain`/`hort-app` **100%**, adapters **≥85%**.

- **A2.1a — Simplesigning carriage extension (domain + app). [BLOCKS A2.1b; the §5 "no carriage" claim was wrong — §8]** [§8]
  *Read first:* `crates/hort-domain/src/oci.rs` (`SIGSTORE_BUNDLE_MEDIA_TYPE` + `sigstore_bundle_layers`),
  `crates/hort-domain/src/ports/provenance.rs` (`AttestationBundle`),
  `crates/hort-app/src/use_cases/provenance_orchestration.rs` (the three carriage sites:
  `fetch_bundles_once`, `land_one_referrer`, `fetch_and_land_upstream_referrers`).
  Add `COSIGN_SIMPLESIGNING_MEDIA_TYPE` (`application/vnd.dev.cosign.simplesigning.v1+json`) +
  `simplesigning_signature_layers` in `hort_domain::oci` returning, per signature layer, the **payload
  layer digest** and the **`dev.cosignproject.cosign/signature` annotation**. Add
  `AttestationBundle.signature: Option<Vec<u8>>`. Keyed branch at the three sites: stop filtering the
  legacy `.sig` out; populate `bytes` = simplesigning **payload layer blob**, `signature` = annotation.
  The keyless v0.3 path stays byte-for-byte (`signature = None`, same `bytes`).
  *Acceptance:* domain **100%** (helper extracts payload+annotation; non-simplesigning manifest → empty;
  malformed → typed `DomainError`); app **100%** (a keyed `.sig` is collected, not dropped, yielding an
  `AttestationBundle{signature: Some}`; keyless path unchanged).
  *Starter:* "/hort-architect Implement ADR 0039 §8 simplesigning carriage: the `hort_domain::oci` helper
  + the `AttestationBundle.signature` field + the keyed branch at the three `provenance_orchestration.rs`
  carriage sites. Keyless v0.3 path must stay byte-for-byte."

- **A2.1b — Keyed verifier adapter + `cosign-key` `ProvenancePort` impl. [BLOCKED ON A2.1a; BLOCKS A2.3–A2.5]** [§2, §8]
  *Read first:* `crates/hort-adapters-provenance-sigstore/src/{verifier,lib}.rs` (mirror the
  `## Digest binding` / subject-digest compare), `crates/hort-domain/src/ports/provenance.rs`.
  Minimal keyed primitive — for a bundle with `signature.is_some()`: parse the simplesigning JSON from
  `bytes`, verify the signature **over `bytes`** against the pinned public key(s), then **bind**
  `bytes.critical.image.docker-manifest-digest == "sha256:" + subject.content_hash`. A `signature.is_none()`
  bundle (a v0.3 keyless one) contributes `NoAttestation`. `name()="cosign-key"`, capability `{"oci"}`.
  No `sigstore` PKI crate; no `reqwest`. **Resolve the reject-reason mapping** (the enum has no
  `SignatureInvalid`/`DigestMismatch`): map wrong-key → `UntrustedIdentity`, digest-mismatch →
  `BundleMalformed`, OR add new `ProvenanceRejectReason` variants (domain change — pick one and note it).
  *Acceptance:* unit tests for valid-sig+matching-digest→`Verified`, wrong-key→`Rejected`,
  **digest-mismatch→`Rejected`** (the re-tag attack, §2), absent-sig→`NoAttestation`,
  malformed-key→boot-reject; ≥85%; `cargo tree` shows no `reqwest` edge on this path.
  *Starter:* "/hort-architect Implement the `cosign-key` keyed verifier per ADR 0039 §2 over the §8
  carriage. Mirror the sigstore verifier's digest-binding; the digest-mismatch reject is the load-bearing
  test. Resolve the reject-reason mapping."

- **A2.2 — Pinned-key trust material wiring. [BLOCKS A3]** [§3]
  *Read first:* `crates/hort-server/src/composition.rs` (the `trusted_root.json` load), the Helm
  `values.schema.json` + provenance values.
  `HORT_PROVENANCE_COSIGN_PUBLIC_KEYS` env + `provenance.cosign.publicKeys` Helm value, loaded ONCE
  at composition and handed to the A2.1 adapter (a key *set* for rotation overlap). No live fetch.
  *Acceptance:* boot loads a key set; key bytes never logged; Helm value renders + passes the strict
  schema; a `cosign-key` scope with no key wired is caught by A2.3 (not a silent pass).
  *Starter:* "/hort-architect Wire `HORT_PROVENANCE_COSIGN_PUBLIC_KEYS` / `provenance.cosign.publicKeys`
  into composition per ADR 0039 §3, feeding the A2.1 adapter; mirror the trusted-root load shape."

- **A2.3 — Backend-aware apply-linter (both directions) + capability map. [FAIL-CLOSED GATE]** [§4]
  *Read first:* `crates/hort-domain/src/entities/scan_policy.rs` (provenance validation),
  `crates/hort-app/src/use_cases/apply_config_use_case.rs` (the provenance lints + backend→format map).
  Per-backend identity requirement: `cosign-key`+`Required` ⇒ require a pinned key;
  `cosign-key`-only scope with non-empty `provenance_identities` ⇒ **reject** (inert-field, ADR 0015);
  `cosign` keeps the identity-pattern rule; add `cosign-key → {"oci"}`.
  *Acceptance:* domain/app **100%** — every reject path tested (keyed+Required+no-key→reject;
  keyed-only+identities→reject; keyless+Required+no-identities still rejects; mixed scope OK).
  *Starter:* "/hort-architect Make the provenance apply-linter backend-aware in both directions per
  ADR 0039 §4. Every new reject branch needs a test — this is the fail-closed gate."

- **A2.4 — Multi-verifier metric label + fold test. [the fold ALREADY exists]** [§6]
  *Read first:* `crates/hort-app/src/use_cases/provenance_orchestration.rs` (`dispatch_and_fold` +
  `fold_two`).
  The OR fold is **already implemented** — `dispatch_and_fold` iterates every applicable verifier and
  folds via `fold_two` (`Rejected` ⊳ `Verified` ⊳ `NoAttestation`). The only single-verifier
  simplification is the **metric label** (`backend = applicable[0].name()`), which loses per-backend
  visibility on a genuine two-verifier run. Decide per-backend-vs-representative and implement it; add
  the two-verifier fold tests (the fold itself is unchanged).
  *Acceptance:* app **100%** — keyed-only verifies; keyless-only verifies; both-present→either verifies;
  both-absent→`NoAttestation`; the `backend` metric label asserted for a two-verifier run.
  *Starter:* "/hort-architect The provenance OR fold already exists (`dispatch_and_fold`/`fold_two`).
  Fix only the metric label for the two-verifier case per ADR 0039 §6, and add the fold tests."

- **A2.5 — Docs: metrics-catalog + enablement how-to. [SAME-CHANGE rule]** [§3, §5]
  *Read first:* `docs/metrics-catalog.md` (the provenance `backend` label),
  `docs/architecture/how-to/enable-provenance-verification.md`.
  Add `cosign-key` to the `backend` label values (catalog, in the same change as A2.4); the how-to
  documents the keyed backend, the **"never public-grade provenance"** warning, and the
  **compromise-revocation = remove key + re-sign everything** caveat (§3). Distill ADR 0039 into this
  how-to before merge (doc-lifecycle D7).
  *Acceptance:* catalog carries the value; how-to states the weaker-guarantee + revocation caveats;
  `docs/plans/*` removed at release.
  *Starter:* "/hort-architect Land the ADR 0039 docs: the metrics-catalog `cosign-key` `backend`
  value + the enablement how-to weaker-guarantee/revocation warnings."

---

## Track B — third-party images: route pulls through Hort, retire the pipeline's 3rd-party stages

- **B1 — [GATED ON HORT SOAK] Repoint cluster pulls Zot → Hort proxy-cache.**
  containerd `registries.yaml` + Kyverno `prepend-mirror-registry` mutate target
  → Hort; bump Hort ScanPolicy `severityThreshold` `critical`→`high` to match the
  pipeline's CRITICAL+HIGH gate. **Do not** make a `0.9.x-beta` Hort the sole
  non-bypassable cluster pull path until it has real soak time (it just had a
  10-day silent scan-gate outage). Keystone for B3/B4.

- **B2 — [NOW] Drop the pipeline's 3rd-party `sign:*` jobs.**
  Re-signing upstream images with our key attests "we copied this," not vendor
  authenticity — low value (agreed). Independent of B1.

- **B3 — [BLOCKED ON B1] Retire pipeline `mirror:*` + `scan:*`.**
  Once pulls demonstrably flow through Hort's proxy + scan-gate, the 3rd-party
  mirror/scan stages are redundant.

- **B4 — [BLOCKED ON A + B3] Retire the supply-chain-security pipeline.**
  With first-party signing relocated to app CI (A) and 3rd-party served via Hort
  proxy (B3), only the federation probe remains (vestigial). Retire the pipeline.

---

## Parked / operational (off the critical path)

- **P1 — Zot GC/dedup dangling-index.** Zot v2.1.15 (`gc:true`/`gcDelay:1h`/
  `dedupe:true`) GCs untagged per-arch children of tagged indexes → dangling
  index → `manifest unknown` → fails `mirror:k3s-system`. Decoupled from the
  probe (`needs:[]`). Fix: `dedupe:false` / upgrade / stop double-managing
  docker.io. **Becomes moot if B1+B3 retire the mirror stage.**

- **P2 — CronJob-`Forbid`-stuck-active wart — scope the fix per-job (do NOT blanket-`Replace`).**
  A failed Job stuck in `.status.active` under `concurrencyPolicy: Forbid` blocked the
  **`quarantine-release-sweep`** (non-destructive) for 10 days → artifacts never released →
  permanent 503. The chart fix must be **per-job**:
  - **`Replace` only on the idempotent, non-destructive sweeps/ticks** — the culprit
    `quarantine-release-sweep`, plus `cron-rescan-tick` / `prefetch-tick` / `advisory-watch-tick` /
    `eventstore-checkpoint` / `wheel-metadata-backfill` / `staging-sweep` (each safe to
    kill-and-restart; verify idempotency before flipping each).
  - **DESTRUCTIVE jobs keep `Forbid`** — `eventstore-archive`, `retention-purge`,
    `retention-evaluate`, `replay-seen-prune`, `prefetch-row-retention-sweep`,
    `scanner-registry-prune`. `Replace` would **interrupt an in-flight DELETE/seal**.
    `eventstore-archive`'s `Forbid` is specifically the **ADR 0020 seal-pool F-2 hard-block**
    (layer-1 of the single-flight bounding `seal_and_remove`'s unbounded `StreamSealed` append) —
    relaxing it needs a security co-review, and `Replace` is *worse* than `Allow`. For the whole
    destructive set, **detect-don't-relax**: a `lastScheduleTime`-staleness **alert**.

  Net: `concurrencyPolicy: Replace` on the non-destructive set; `Forbid` + a staleness alert on the
  destructive set. The alert is the durable fix; do not reach for it via a blanket policy flip.

- ~~Prod reaper gap~~ — **DONE** (`scheduledTasks.adminTasksEnabled` +
  `scannerRegistryPrune` enabled on the prod deployment).

---

## Sequencing

```
A1 (now) ─────────────────────────────────► first-party on Hort (scan only)
A2 (ADR 0039) ──────► A3 (enforce) ────────► first-party gated at registry
                              └────────────► A4 (cross-format, future)
B2 (now) ; B1 (after soak) ──► B3 ──┐
                                    A + B3 ──► B4 (retire pipeline)
```

Independent "start now": **A1** (pilot first-party) and **B2** (drop 3rd-party
signing). Registry-as-pull-path (B1) waits on Hort soak; registry-enforced
first-party provenance (A3) waits on ADR 0039 shipping.
