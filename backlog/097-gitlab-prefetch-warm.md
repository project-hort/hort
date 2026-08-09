# 097 — GitLab-side cargo warm: prefetch grant, shared preflight script, two pipeline jobs

**Issue:** #138 · **Branch:** `agent/138-gitlab-prefetch-warm` (off develop, AFTER #137 merges) · **Scope:** gitops grant + `scripts/ci/` + `.gitlab-ci.yml`

## Change

### 1. Gitops grant (one new file)

TWO new files, both mirroring `gha-ci-prefetch-cargo-virtual.yaml` (subject
kind `serviceAccount`, `permission: prefetch`, `repository: cargo-virtual`),
each with a header noting the Read ∧ Prefetch gate and the existing sibling
read grant:

- `gitlab-ci-prefetch-cargo-virtual.yaml` — for the new GitLab warm job.
- `gha-release-prefetch-cargo-virtual.yaml` — **found during #137 review**:
  `gha-release` holds only read/write grants, so the preflight's auto-warm
  POST (landed in #137) 403s today. Without this grant the release-time warm
  silently does nothing.

**Both take effect only on the operator's Ansible apply** — every consumer
below must therefore treat 403 as a loud warning, never a pipeline failure.

### 2. Shared script — one implementation, three call sites

Extract what #137 landed inline in `release.yml` into `scripts/ci/`:

- `scripts/ci/locked-registry-deps.sh` — awk over `Cargo.lock`, emits
  `name version` per `registry+` package. No cargo, no index (source
  replacement may be active in the caller).
- `scripts/ci/vetted-index-preflight.sh` — takes the hort base URL, repo key
  and bearer; resolves each distinct name's sparse-index path (cargo prefix
  rule), collects served versions, prints every cold `name version`, exits
  non-zero iff any are cold. No side effects (the caller decides whether to
  prefetch and whether to fail).

Rewire `release.yml`'s preflight to call the scripts (behavior otherwise
unchanged; this is the de-duplication half — CLAUDE.md's 3-occurrence rule
bites once GitLab adds two more call sites). While rewiring, fix the #137
review finding: the warm POST uses `curl -sS` without `-f`, so a 403 renders
as a misleading `queued: ?  already_present: ?` line. Use `curl -fsS` and emit
an explicit `::warning::` naming the likely cause (missing prefetch grant, not
yet applied).

### 3. `.gitlab-ci.yml` — two jobs, different semantics

- **`prefetch:warm`** — stage `test` (earliest useful), rules: `develop`
  branch pipelines plus `$CI_PIPELINE_SOURCE == "schedule"`; gated on
  `HORT_PROXY_ENABLED == "true"`. Uses the existing `.hort-auth` anchor for
  `HORT_TOKEN`, then `locked-registry-deps.sh` → one batched POST to
  `/api/v1/repositories/${HORT_CARGO_SOURCE_REPO:-cargo-virtual}/prefetch`.
  `allow_failure: true` and every error path is a warning: this job must
  never gate a pipeline (fire-and-forget, mirroring the GitHub twin).
- **`prefetch:verify`** — same auth, runs `vetted-index-preflight.sh` and
  reports the complete cold set; scheduled pipelines only, `allow_failure:
  true`. This is the pre-release readiness signal, NOT a gate.

Both jobs carry a comment stating the invariant: a build through the vetted
index cannot warm a cold dep (released_only hides it, so resolution fails
before any fetch) — the POST is the warm, the resolve is the check.

### 4. The warm job doubles as the federation probe

The GitLab↔hort OIDC federation is DECLARED in the gitops tree but its applied
state on registry.hort.rs is unverified (the Ansible apply is a parked
operator step), `HORT_PROXY_ENABLED` may not be `true` in the project, and the
issuer envelope still carries an open CONFIRM about whether GitLab id_tokens
carry `jti`. `prefetch:warm` traverses exactly that path, so its diagnostics
MUST distinguish the three outcomes on its own output — no log spelunking:

- **exchange failed** (no `access_token`): print that the federation is not
  usable yet and name the three candidate causes (gitops not applied /
  audience or `jti` mismatch / `HORT_PROXY_ENABLED` unset).
- **exchange OK, prefetch 403**: federation WORKS, the prefetch grant is not
  applied yet — name the grant file.
- **success**: print `queued` / `already_present` / `rejected` counts.

Every branch stays `allow_failure: true`; this job never gates a pipeline.

## Acceptance

- `bash -n` on both new scripts and on any extracted block; YAML parse of
  `.gitlab-ci.yml` and `release.yml`.
- Script self-tests pasted in the report: `locked-registry-deps.sh` over the
  real `Cargo.lock` (count + `lru 0.18.2` present); prefix mapping for
  `a`/`ab`/`abc`/`serde`.
- `release.yml`'s preflight produces the same output as before the extraction
  (diff review — no behavior change).
- No crates/ change ⇒ no cargo gates.
