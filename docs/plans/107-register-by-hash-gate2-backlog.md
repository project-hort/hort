# #107 backlog — register_by_hash Gate-2 bypass (cross-repo mount + pull-dedup follower)

Feature branch: `agent/107-register-by-hash-gate2`. Design doc:
`docs/plans/107-register-by-hash-gate2.md` (branch-local, D7 — no ADR change scoped).
**Dependency:** Item 1 builds on #115 Item 1 (the seed-branch gate in
`register_by_hash_inner`) — dispatch order `115-item1 → 107-item1 → 107-item2 →
107-item3`. Items 2–3 depend on Item 1.

## Item 1 — `register_by_hash_inner` quarantines-by-default for every caller

**Design doc section:** §2 D1
**Read first:** `crates/hort-app/src/use_cases/ingest_use_case.rs` (`register_by_hash_inner` — including the #115-item1 gate in the anchor-override branch; `ingest_inner`'s `scan_will_run`/`provenance_will_run`/`effective_duration_secs` derivations), `crates/hort-http-oci/src/uploads.rs::handle_cross_mount`, `crates/hort-http-oci/src/blobs.rs` (~940 follower), design doc §1 (five follower call sites)
**Acceptance:**
- The policy-resolution + quarantine + atomic-enqueue gate runs for EVERY
  `register_by_hash_inner` caller: anchor = `quarantine_anchor_override.unwrap_or(now)`;
  `None → Quarantined` whenever effective duration > 0; `ArtifactQuarantined` +
  gated `ScanRequested` + `Scan`/`ProvenanceVerify` enqueues land in ONE
  `commit_transition_with_enqueues` (trigger_source `"register-by-hash"` for
  non-seed callers; seed keeps `"seed-import"`).
- Operator `quarantineDuration: 0` honoured verbatim (permissive; scan still
  enqueues per `scan_will_run`) — mirrors `ingest_inner` exactly.
- `RegisterOutcome::Duplicate` (same-path-same-hash) arm unchanged.
- Follower-path module docs corrected (the "policy-driven through the leader's
  ingest" claim is false for cross-repo followers — design §1 rationale
  re-validation).
- `hort-app` 100% on the gate matrix (design §4); workspace gate green.

### Starter prompt

/hort-architect

Implement Item 1 of `docs/plans/107-register-by-hash-gate2-backlog.md` (branch
`agent/107-register-by-hash-gate2`, issue #107 — HIGH). Read design doc §2 D1 and §1
first. #115 Item 1 already landed the policy-resolution +
`commit_transition_with_enqueues` gate in `register_by_hash_inner`'s anchor-override
branch — generalize that gate to every caller per the acceptance list (anchor =
override-or-now, quarantine-by-default, atomic enqueues, `quarantineDuration: 0`
permissive opt-out honoured). Do not change `handle_cross_mount` or the follower call
sites themselves — the fix lives in the shared inner fn. Correct the follower-path
module docs. Restate acceptance in your report; run the full pre-push gate.

## Item 2 — refuse `Rejected`/`ScanIndeterminate` mount sources (anti-enum NotFound collapse)

**Design doc section:** §2 D2
**Read first:** `crates/hort-app/src/use_cases/ingest_use_case.rs`
(`register_by_hash_inner`'s `Some(src) → find_by_repo_and_checksum` arm),
`crates/hort-http-oci/src/uploads.rs::handle_cross_mount` (the existing NotFound →
fall-through-to-initiate arm), ADR 0025 (state-precondition semantics)
**Acceptance:**
- The `Some(src)` arm refuses a source row with `quarantine_status ∈ {Rejected,
  ScanIndeterminate}` by returning `DomainError::NotFound` (anti-enumeration: caller
  cannot distinguish "absent" from "terminally blocked"); `handle_cross_mount`'s
  existing NotFound arm then falls through to initiate per the OCI spec — no handler
  change.
- `Quarantined` and `Released`/`None` sources stay mountable (the target copy is
  itself gated by Item 1's fresh quarantine).
- Refusal logs `info!` (source repo, hash, status — privilege-denial convention,
  no `err` instrumentation).
- `hort-app` 100% on the four status arms; an `hort-http-oci` handler test pins
  the 202-initiate fall-through for a rejected source; workspace gate green.

### Starter prompt

/hort-architect

Implement Item 2 of `docs/plans/107-register-by-hash-gate2-backlog.md` (branch
`agent/107-register-by-hash-gate2`, issue #107 — HIGH; depends on Item 1). Read
design doc §2 D2 first. In `register_by_hash_inner`'s `Some(src)` source-lookup arm,
refuse `Rejected`/`ScanIndeterminate` sources via a `DomainError::NotFound` collapse
(anti-enumeration; the OCI mount handler's existing NotFound arm gives the
spec-correct initiate fall-through — do NOT touch the handler). Keep `Quarantined`
mountable. Denial logs info!. Cover all four status arms plus the handler-level
202 fall-through test. Run the full pre-push gate.

## Item 3 — trigger-level regression tests (mount, OCI follower, non-OCI follower)

**Design doc section:** §2 D3
**Read first:** `crates/hort-http-oci/tests/` (existing mount/blob handler tests +
`build_mock_ctx` harness), `crates/hort-http-oci/src/blobs.rs` (~900-975 follower
branch), `crates/hort-http-pypi/src/upstream_pull.rs` (follower branch + its test
module)
**Acceptance:**
- (a) Mount of a clean source → target-repo row `Quarantined`, scan job enqueued,
  target blob GET held (503/`Retry-After` path) until released.
- (b) Mount of a `Rejected` source → initiate fall-through, no row minted.
- (c) OCI follower re-registration → target row `Quarantined` + scan enqueued.
- (d) PyPI follower path → same assertions, pinning the shared-inner-fn reach into
  the non-OCI format crates.
- Tests live at the handler/integration level (`build_mock_ctx`); ≥85% on touched
  test-support code; workspace gate green.

### Starter prompt

/hort-architect

Implement Item 3 of `docs/plans/107-register-by-hash-gate2-backlog.md` (branch
`agent/107-register-by-hash-gate2`, issue #107 — HIGH; depends on Items 1–2). Read
design doc §2 D3 first. Add the four trigger-level regression pins (a)–(d) from the
acceptance list at the handler level via `build_mock_ctx` — mount-clean-source held,
mount-rejected-source initiate-fall-through, OCI follower quarantined, PyPI follower
quarantined. No production-code changes expected; if a pin fails, STOP and report the
failure instead of adjusting the pin. Run the full pre-push gate.
