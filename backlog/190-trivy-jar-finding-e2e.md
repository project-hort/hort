# 190 — E2E: a known-vulnerable JAR through a Trivy-policy Maven proxy yields ≥ 1 finding

**Issue:** #264, item 1 of 2 · **Branch:** `agent/264-trivy-materialisation` · E2E-gated (branch-first on the human's harness).

## Purpose

Empirical confirmation and permanent regression test in one: today the Trivy adapter
materialises every artifact as `<sha256>.bin`, which no Trivy analyzer matches, so this
scenario must be **red** on the current tree (0 findings) and **green** after item 191.

## Scenario `scripts/native-tests/scenarios/quarantine/trivy-jar-finding.sh`

- `requires: db worker scanner egress` (self-describing header per
  `scripts/native-tests/README.md`).
- Fixture: a Maven **proxy** repository (`maven-trivy-e2e`, upstream Maven Central) with a
  repo-scoped `ScanPolicy { scan_backends: ["trivy"], enforcement: record,
  quarantine_duration_secs: <short> }` — record mode so the verdict never blocks the
  scenario; mirror the `hort-crates` record-mode fixture used by dogfood (h).
- Pull `org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar` (CVE-2021-44228)
  through the proxy (authenticated, existing SA pattern), then await `ScanCompleted` on
  the JAR artifact via the existing psql helpers (bounded poll, ~2 sweep ticks + scan).
- Assert: `ScanCompleted` carries **≥ 1 finding** whose id is `CVE-2021-44228` (Trivy
  reports it against `org.apache.logging.log4j:log4j-core`), and the scanner label is
  `trivy`.
- Negative control in the same scenario: `.pom` of the same coordinate → no Trivy
  crash, a verdict is recorded (its content is item 191's concern).

## Acceptance

- Scenario listed by `run.sh --list`, runs in the `quarantine` group.
- On the current tree: FAIL with the message naming "0 findings for a known-vulnerable
  JAR" (that failure IS the confirmation asked for on #264 and is recorded there).
- After item 191: PASS.
