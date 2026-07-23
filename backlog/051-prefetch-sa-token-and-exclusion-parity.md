# 051 — #80 (blockers): SA-token prefetch + registry exclusion parity

**Issue:** #80 (first-real-run blockers; analysis + authority-hierarchy resolution on the issue)
**Read first:** `docs/ci/hort-quarantine-integration.md` (**the spec for this surface** — §CI
federation designs the prefetch caller as a "read + prefetch-only, non-admin ServiceAccount
bearer", ADR 0044-snapshotted, audited; the implementation drifted from it),
`crates/hort-http-discovery/src/` (the CliSession token-kind gate — `lib.rs`, `routes.rs`,
the prefetch handler), `docs/auth-catalog.md`, ADR 0013 + ADR 0044,
`deploy/ansible/files/gitops/auth/grants/gha-ci-read-cargo-virtual.yaml` (grant template),
`scripts/native-tests/fixtures/gitops-policies/policies/exclusion-cve-2024-3094-old-xz.yaml`
(Exclusion template), `deploy/ansible/files/gitops/policies/crates-scan.yaml`,
`scripts/check-advisory-sync.sh` (the parity-guard pattern to extend), `.cargo/audit.toml` +
`deny.toml` (the build-side acceptances to mirror).

## A — code: the prefetch POST accepts a ServiceAccount token, permission-gated

The design doc specifies SA-bearer prefetch for CI; the blanket CliSession gate on
`POST /api/v1/repositories/:repo_key/prefetch` is implementation drift (spec wins). Change:
- The **prefetch handler only**: accept `TokenKind::CliSession` (unchanged) **or** a
  service-account token **iff the caller's resolved grants include `prefetch` on the target
  repository** (the same RbacEvaluator path other permission checks use — no bespoke logic).
- PATs stay rejected; the discovery/list surfaces keep their CliSession gate **untouched**
  (the design doc speaks only to prefetch).
- Prod evidence of the current failure: `self-service prefetch denied: token kind is not
  CliSession` → 403 (#80, run 30040631720).
- Tests: SA-with-prefetch-grant → 200/queued; SA-without-grant → 403 (authority, not kind);
  PAT → rejected as today; CliSession → byte-identical behavior. Update the
  `hort-http-discovery` module docs + `docs/auth-catalog.md` entry to the corrected posture
  (cite the design doc + this issue). Flag in the report whether an ADR-0013 amendment is
  warranted (the doc-update may suffice — the design doc already carries the decision).

## B — gitops: the grants + exclusions the design intended

1. `auth/grants/gha-ci-prefetch-cargo-virtual.yaml` — `prefetch` on `cargo-virtual` for
   `gha-ci` (template: the sibling read grant). The design doc names the CI prefetch target
   as the cargo surface; do NOT blanket-grant prefetch on every proxy without need.
2. `policies/exclusions/` (new dir alongside `policies/`): two `kind: Exclusion` objects
   scoped to the crates scan policy for **RUSTSEC-2026-0002** and **GHSA-rhfx-m35p-ff5j**
   (the lru 0.12.5 findings), each with a comment mirroring the risk-acceptance rationale
   already documented in `.cargo/audit.toml` (hort's usage doesn't hit the unsound path).
   `ExclusionAdded` re-evaluation un-rejects the artifact — no manual surgery.
3. The gitops-tree guards (`public_deploy_gitops_tree`) must pass with the new objects.

## C — guard: three-way advisory parity

Extend `scripts/check-advisory-sync.sh` (audit.toml ↔ deny.toml today) to also assert:
every advisory ignored on the build side has a **matching registry Exclusion** in
`deploy/ansible/files/gitops/` (and report the reverse direction — a registry exclusion
with no build-side acceptance — as a warning, not a failure; the registry may legitimately
exclude more). Keep the script's existing style/exit conventions; it runs in the existing
`security:advisory-sync` job — no new CI wiring.

## Acceptance
- A's four token-matrix tests green; CliSession behavior provably unchanged; discovery/list
  gates untouched.
- B parses + cross-validates (gitops guards green); exclusions scoped to crates only.
- C fails on a synthetic drift (test it by temporarily removing one exclusion in a scratch
  check), passes on the real tree.
- Full gate green.

### Starter prompt

```
/hort-architect

Implement backlog item 051 (issue #80 blockers) on branch agent/80-prefetch-sa-token.
IMPORTANT: verify `git branch --show-current` before every commit — never develop. Read
docs/ci/hort-quarantine-integration.md FIRST — it is the spec: the CI prefetch caller is a
ServiceAccount bearer, so the prefetch POST's blanket CliSession gate is implementation
drift (spec wins; the discovery/list CliSession gates stay). A: accept SA tokens on the
prefetch handler iff grants include prefetch on the target repo (RbacEvaluator path), PATs
still rejected, four token-matrix tests. B: gha-ci prefetch grant on cargo-virtual + two
crates-scoped Exclusions (RUSTSEC-2026-0002, GHSA-rhfx-m35p-ff5j) mirroring the audit.toml
acceptances. C: extend check-advisory-sync.sh to three-way parity (build ignores must have
registry exclusions; reverse = warning). Update auth-catalog + module docs; flag the ADR
call. Full gate; report per the handover protocol.
```
