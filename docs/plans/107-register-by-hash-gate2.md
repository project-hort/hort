# #107 — `register_by_hash` bypasses Gate-2 (cross-repo mount + pull-dedup follower)

Issue: #107 (source: audit #106 finding H1, HIGH, adversarially verified; spec approved
by the human 2026-08-05). Feature branch: `agent/107-register-by-hash-gate2`.
Branch-lifetime planning doc (D7): no ADR change is scoped — the fix RESTORES ADR 0007
conformance (the `None`-status mint was never an accepted carve-out); durable behavior
is already specified there.

## §1 Scope, deferred-items sweep, rationale re-validation

`register_by_hash_inner` (every non-seed caller) mints `quarantine_status = None` with
no policy resolution, no quarantine, no scan enqueue — `None` → `is_downloadable() ==
true` immediately. Reachable by:

- **Trigger A (deterministic):** OCI cross-repo blob mount
  (`hort-http-oci/src/uploads.rs::handle_cross_mount` → `register_by_hash(req, hash,
  Some(src_repo.id), …)`). Source-repo Read authz only; the source row's
  `quarantine_status` is never consulted (only `size_bytes`). A `Rejected` blob in
  repo-A launders into repo-B as immediately-downloadable.
- **Trigger B (racy):** cross-repo pull-dedup followers. Grooming inventory — the
  follower re-registration exists in **five** call sites, all funnelling into the same
  inner fn: `hort-http-oci/src/blobs.rs` (~940), `hort-http-oci/src/manifests.rs`
  (~1503), and the `upstream_pull.rs` follower paths of `hort-http-pypi`, `hort-http-npm`,
  `hort-http-cargo`, `hort-http-maven`. Trigger B therefore spans EVERY pull-through
  format, not just OCI — one more reason the fix belongs in the shared inner fn, not
  per call site.

Bounded, not permanent (the rescan sweep eventually scans NULL-status rows), but the
unscanned-download window is attacker-openable at will via Trigger A.

**Deferred-items sweep (Step 0, run 2026-08-05).** ADR 0000 register: no open row
covers this (the audit filed it as new). `docs/plans/115-*` (same-area, on its own
branch) explicitly lists #107 as out of scope and reserves the generalization for this
initiative — that breadcrumb is this doc. No other inherited deferred work applies.

**Inherited-rationale re-validation (Step 0.5).** Two rationales re-checked:
(i) The follower-path comment "quarantine is policy-driven through the leader's primary
`ingest_verified`" — **reversed here**: the leader's quarantine covers only the
LEADER's per-repo row; `quarantine_status` is a per-repo-row column, so the follower's
row was never policy-gated at all. (ii) The mount-path "authorize source Read + target
Write" posture — **still valid but insufficient**: authz was never the missing gate;
the lifecycle gate was. Both recorded per the sweep discipline.

**Relationship to #115 (confirmed 2026-08-05, its Item 1 dispatches first).** #115
Item 1 introduces the policy-resolution + `commit_transition_with_enqueues` gate
machinery in `register_by_hash_inner`'s anchor-override (seed) branch. This
initiative's Item 1 **generalizes that gate to every caller** — after it, the
anchor override only changes the anchor value inside one shared gate. Sequencing:
`115-item1 → 107-item1 → 107-item2 → 107-item3`.

**Deviation from the issue's fix sketch — declared.** The issue sketch says "follower
inherits leader status". Groomed design instead: **the follower's row quarantines
fresh under the TARGET repo's policy** (same as every other `register_by_hash_inner`
mint). Concretely better because: (a) it is strictly fail-closed — inheriting
`Released` from a leader in a laxer-policy repo would let repo-B skip its own
observation window (a policy-autonomy hole the inheritance sketch re-opens); (b) it
needs no cross-repo status plumbing (the follower path passes `source_repo = None` and
has no leader row in scope); (c) per-repo-row status independence is the existing
model the quarantine invariants are written against. The human confirms this deviation
at the refined gate.

**Explicitly out of scope.** (i) The seed branch's gate (lands as #115 Item 1 —
dependency, not scope). (ii) Retroactive remediation of pre-fix NULL rows — the
existing `select_eligible` sweep already scans them (the issue's own "bounded"
finding); no new remediation surface. (iii) Same-repo dedup (`RegisterOutcome::
Duplicate` arm) — already safe, unchanged. (iv) Any ADR text change.

## §2 Decisions

### D1 — `register_by_hash_inner` quarantines-by-default for EVERY caller (Item 1)

After #115 Item 1, hoist its gate out of the anchor-override branch so the shared
tail of `register_by_hash_inner` runs for all callers: resolve the target repo's
active policy; `effective_duration_secs` per the same `matched_policy → DefaultPolicy`
fallback as `ingest_inner`; if `> 0`, transition `None → Quarantined` with anchor =
`quarantine_anchor_override.unwrap_or(now)` and land `ArtifactQuarantined` + gated
`ScanRequested` + `Scan`/`ProvenanceVerify` enqueues atomically
(`commit_transition_with_enqueues`, trigger_source distinguishes
`"seed-import"` / `"register-by-hash"`). Operator `quarantineDuration: 0` stays the
one honoured permissive opt-out (mirrors `ingest_inner`; the scan still enqueues per
`scan_will_run`). The mount/follower callers change behaviour: a freshly mounted or
follower-registered blob is HELD for the target repo's window and scanned before it
serves — that is the fix.

### D2 — Source-status refusal on the `Some(src)` path (Item 2)

In the `Some(src) → find_by_repo_and_checksum` arm, refuse a source row whose
`quarantine_status` is `Rejected` or `ScanIndeterminate` by mapping to
`DomainError::NotFound` (anti-enumeration collapse — the caller cannot distinguish
"no such blob" from "terminally blocked blob"). `handle_cross_mount` then falls
through to initiate a regular upload per the OCI spec — the existing NotFound arm,
no handler change. A `Quarantined` source stays mountable: the target-repo copy is
itself quarantined + scanned under D1, so no unscanned bytes serve; refusing it would
only break legitimate mid-window mounts. `Released`/`None` unchanged.

### D3 — Trigger-level regression tests (Item 3)

Handler/integration-level pins for both triggers plus one non-OCI follower:
(a) mount of a clean source → target row `Quarantined`, blob GET on target 503s
until released; (b) mount of a `Rejected` source → 202-initiate fall-through (no
row minted from the rejected source); (c) OCI follower re-registration → row
`Quarantined` + scan job present; (d) one non-OCI (PyPI) follower path asserting the
same, pinning that the fix reaches the format crates through the shared inner fn.
Module docs on the follower paths corrected (the reversed rationale from §1).

## §3 Observability

No new metric names/labels. D1's enqueues reuse the ingest instrumentation;
quarantine transition logs ride the existing `commit_transition` flow. D2's refusal
logs `info!` (security-relevant denial: source repo, hash, source status — no
credential material), mirroring the privilege-denial convention.

## §4 Test plan / coverage

`hort-app` 100% on touched branches: gate matrix (duration>0/=0 × override
Some/None × scan_will_run × provenance_will_run), D2 refusal arms (Rejected,
ScanIndeterminate, Quarantined-allowed, Released-allowed), Duplicate arm untouched.
`hort-http-oci` ≥85%: mount + follower handler tests via `build_mock_ctx`. Format
crate (PyPI) follower test. Full pre-push gate per CLAUDE.md.
