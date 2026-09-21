# 189 — Weekly container scan: the SARIF is the inventory, a JSON policy scan drives the issue-opener

**Issue:** #262 · **Branch:** `agent/262-scheduled-scan-policy-split` · single item · harness-only (`.github/workflows/`).

## Problem

`.github/workflows/scheduled-container-scan.yml` runs trivy-action once with
`format: sarif` and `severity: CRITICAL,HIGH`. trivy-action's SARIF mode ignores the
severity filter ("Building SARIF report with all severities"), so the uploaded SARIF —
and therefore the Security-tab alerts — carry every severity, and the issue-opener
step counts `runs[0].results.length` of that SARIF and titles its GitHub issue
"Trivy found **N** CRITICAL/HIGH finding(s) with available fixes" for findings that
are MEDIUM or LOW. The step summary makes the same false claim. Precedent: the
publish-path gate had the identical defect and was split into two invocations —
a SARIF scan (all severities, non-blocking) and a table scan carrying the policy
(`docker-publish.yml`, "Trivy scan - Backend (SARIF…)" / "Trivy gate - Backend").

Governing decisions: none in `docs/adr/`; the publish-path split is the precedent
(its rationale is in the comments of `docker-publish.yml` ~186–235). No new
mechanism — apply the same split.

## Change

1. Keep the SARIF scan + `upload-sarif` step in substance (all severities,
   `exit-code: '0'`, same `category`). Add the same explanatory comment the
   publish workflow carries: SARIF mode ignores the severity filter; this file is
   the inventory for the Security tab.
2. Add a second trivy-action invocation on the same `image-ref` with
   `format: 'json'`, `output: 'server-trivy-policy.json'`,
   `severity: 'CRITICAL,HIGH'`, `ignore-unfixed: true`, `exit-code: '0'`,
   `skip-setup-trivy: true` (trivy is already installed by the earlier step).
3. Point the `github-script` issue-opener and the step summary at the JSON:
   count `Results[].Vulnerabilities[]` (sum over results; `Vulnerabilities` may be
   absent → 0). The wording "CRITICAL/HIGH finding(s) with available fixes" is then
   true by construction; keep the existing open-issue lookup/update logic.
4. Upload both files in the `trivy-weekly-reports` artifact.
5. Comments state the invariant ("SARIF = inventory, JSON = policy"); no issue
   references in the YAML.

## Acceptance

- A SARIF containing only MEDIUM/LOW results opens no issue; summary reports 0.
- ≥1 fixable CRITICAL/HIGH in the JSON opens/updates the issue with the right count.
- Security tab still receives the full SARIF under `trivy-server-scheduled`.
- Harness-only diff: gate = `bash -n` on any embedded shell, YAML parses
  (`python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' <file>`),
  `actionlint` if available in the sandbox, plus `cargo-audit audit -D warnings` and
  `cargo-deny check` (unconditional). No fmt/clippy/test (no Rust touched).
- No `CHANGELOG.md` entry (CI-internal).

## Out of scope

- Changing the policy thresholds themselves.
- Any GitLab-side container scanning (none exists).
- The CVE that surfaced this (glibc CVE-2026-5450) — already fixed on `develop` via the
  distroless digest bump; ships with the next public stable.
