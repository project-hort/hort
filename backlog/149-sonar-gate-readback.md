# 149 — quality:sonar: gate verdict + findings read-back, clippy import, image pin

**Issue:** #219 · **Branch:** `agent/219-sonar-findings` · **One reviewable unit (one MR).**

## Problem

The `quality:sonar` job uploads a SonarQube analysis and exits: no
`sonar.qualitygate.wait`, so the server-side quality-gate verdict is read by
nobody, no finding ever reaches a job log, clippy output never reaches Sonar
(the gating `test:lint` run emits no JSON), and the scanner image is the
floating `sonarsource/sonar-scanner-cli:latest` (subject to the mirror's
28h new-digest quarantine whenever `:latest` moves).

## Confirmed decisions

**D1 — advisory-first gate.** `sonar.qualitygate.wait=true` (in
`sonar-project.properties`, static config) **and** `allow_failure: true` on
`quality:sonar`. The job comment states the invariant: the gate verdict is
advisory while the project's gate baseline is unestablished; re-tightening
(removing `allow_failure`) is a deliberate later change once the gate runs
green on the integration trunk. Side effect: a dead/expired token no longer
kills the pipeline — the findings job (D2) names it loudly instead.

**D2 — findings read-back job `quality:sonar-findings`.** New job, quality
stage, `when: always` + `allow_failure: true`, same `rules:` shape as
`quality:sonar` (MR pipelines skipped; token-gated; tag vs branch split), tag
`platform` (in-cluster DNS, same as the scanner). Prints to the job log:

1. quality-gate status and **every failing condition** as
   `metricKey: actualValue comparator errorThreshold`;
2. open issues, worst severity first, as
   `[SEVERITY] component:line rule message`;
3. unreviewed security hotspots (separate endpoint, see trap 3).

Behavioral requirements (each one is a documented upstream trap — implement
all five):

- **Auth probe first, HTTP status checked.** `GET
  /api/qualitygates/project_status` is the probe AND the gate fetch (one
  request, response reused). An unauthenticated `/api/issues/search` returns
  HTTP 200 with an empty list — indistinguishable from a clean project — so
  the job must refuse to print any findings list unless the probe's HTTP
  status proved the token was accepted, and must report an auth failure AS an
  auth failure, never as "no findings".
- **Token transport fallback.** SonarQube accepts the token as a bearer
  header or as the basic-auth username with empty password, depending on
  server version. Probe one, fall back to the other, reuse whichever worked
  for all subsequent requests.
- **Hotspots are not issues.** `/api/issues/search` never returns hotspots; a
  gate failing on `new_security_hotspots_reviewed` would otherwise print
  "0 open issues" with nothing to explain it. Query `/api/hotspots/search`
  separately; a non-200 there (after a successful probe) is a *permissions*
  answer (token-type whitelist), report it as such — not as a credentials
  failure.
- **Project key from `.scannerwork/report-task.txt`**, never from
  `sonar-project.properties` (the two drift; the CI additionally overrides
  the key via `$SONAR_PROJECT_KEY`). This requires `quality:sonar` to export
  `.scannerwork/report-task.txt` as an artifact (`when: always`), and the
  findings job to `needs:` it with `artifacts: true`.
- **Never an explanation-free red gate.** If the gate is red but both lists
  come back empty (or hotspots were unreadable), print the failing metric
  keys as the thing to chase.

Missing `.scannerwork/report-task.txt` (scanner skipped or died before
upload): print a clear one-line explanation and exit 0 — never an
unresolvable-`needs` error and never a spurious red. Mind that
`quality:sonar` is `allow_failure: true` after D1, so the findings job runs
even when the scanner failed; the missing-file path is its normal companion
on that branch.

Put the script body in `scripts/ci/sonar-findings.sh` (bash, `set -euo
pipefail`), not inline YAML — grep-able, `bash -n`-checkable. Job image:
`alpine:3.24` + `apk add --no-cache bash curl jq` (mirrors other alpine jobs).

**D3 — clippy import from the gating lint run.** `test:lint` changes its
clippy invocation to

```
cargo clippy --workspace --all-targets --message-format=json -- -D warnings > clippy-report.json
```

Plain redirect — NOT `tee` — so the shell's exit status stays clippy's and no
`pipefail` subtlety exists. On failure, render a short human summary from the
JSON (jq over `compiler-message` entries) so the job log stays diagnosable,
then exit non-zero. Export `clippy-report.json` as an artifact
(`when: always`). `sonar-project.properties` gains:

```
sonar.rust.clippyReport.reportPaths=clippy-report.json
sonar.rust.clippy.enabled=false
```

The second line is load-bearing: without it the community-rust analyzer runs
`cargo clippy` itself inside the scanner image, where there is no cargo, and
fails. `quality:sonar` adds a `needs:` entry on `test:lint` with
`artifacts: true` and `optional: true` (mirror the existing
`security:cargo-audit` needs-entry shape — rules of the two jobs are not
identical, and a missing report must not become an unresolvable-needs error;
the analyzer tolerates a missing report path with a warning).

**D4 — image pin.** Replace `sonarsource/sonar-scanner-cli:latest` with the
mirror-addressed, digest-pinned ref (digest resolved from the mirror,
2026-08-30; tag 12.1 is ingested and released there):

```
hort.kdp.kloni.cloud/docker-io/sonarsource/sonar-scanner-cli:12.1@sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9
```

Addressing through the mirror explicitly means the cluster's
mirror-prepend admission rewrite does not touch the ref, and a moved
upstream `:latest` can never surprise-quarantine the job. Comment on the
image line states that invariant (pin + mirror addressing), not the history.

**D5 — token is operational, out of scope here.** The replacement
`SONAR_TOKEN` is already set as a masked CI/CD variable by the operator; this
item changes no credential handling.

## Explicitly out of scope

- Re-tightening the gate (removing `allow_failure` from `quality:sonar`) — a
  deliberate later change once the gate is green on the trunk.
- The REST `crates/{name}/{version}` route — unrelated (#217 shipped the
  index-side fix).
- Any change to the MR-pipeline skip rule — it stays; D2 tolerates the
  skipped scanner.

## Files touched (expected)

- `.gitlab-ci.yml` — `quality:sonar` (image pin, allow_failure, artifacts,
  needs), new `quality:sonar-findings`, `test:lint` (clippy JSON + artifact)
- `sonar-project.properties` — `sonar.qualitygate.wait=true`, clippy report
  import block
- `scripts/ci/sonar-findings.sh` — new
- `docs/ci/README.md` — Sonar section: advisory posture + re-tighten
  criterion, findings job, clippy import
- `CHANGELOG.md` — `[Unreleased]` → `### Changed` entry

## Acceptance

- `sonar-project.properties` carries `sonar.qualitygate.wait=true` and both
  clippy lines; `quality:sonar` is `allow_failure: true` with the pinned
  mirror ref above and exports `.scannerwork/report-task.txt`.
- `quality:sonar-findings` implements all five trap behaviors above;
  `bash -n scripts/ci/sonar-findings.sh` passes; missing `report-task.txt`
  is a clean, explained exit 0.
- `test:lint` produces `clippy-report.json` as an artifact while its exit
  status remains clippy's; a lint failure still renders human-readable
  diagnostics in the log.
- Harness-only diff (CI YAML, properties, scripts/, docs/) — no Rust change,
  so the gate is `bash -n` + diff-proof + `cargo audit`/`cargo deny` (per
  the pre-push checklist's harness-only economy); the architect validates
  the final `.gitlab-ci.yml` against the GitLab CI lint API at review.
- Comment discipline: comments state invariants (advisory posture, pin
  rationale, trap behaviors); no issue/backlog references outside the commit
  message.
