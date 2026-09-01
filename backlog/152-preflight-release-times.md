# 152 — preflight: per-dep quarantine release timestamps from the download-path 503

**Issue:** #222 · **Branch:** `agent/222-preflight-release-times` · **One reviewable unit (one MR).**

## Problem

`scripts/ci/vetted-index-preflight.sh` names cold deps but not WHEN each
clears quarantine — the operator is told "re-run after the window" blind.
The cargo download path already answers `503 + Retry-After: <seconds until
quarantine_until>` for a quarantined artifact
(`render_cargo_crate_response`, `crates/hort-http-cargo/src/lib.rs`); the
released_only index cannot carry the information (the version is simply
absent). Tooling-only: no server change.

## Task

All inside `scripts/ci/vetted-index-preflight.sh` (single implementation,
shared by `.github/workflows/release.yml` and the GitLab prefetch jobs):

1. After the cold set is computed and printed, resolve the repo's `dl`
   template once from the served `GET {hort_url}/cargo/{repo_key}/config.json`
   (do not hard-code the download-URL shape; the config is already
   auth-reachable with the same bearer). Fall back to
   `{hort_url}/cargo/{repo_key}/api/v1/crates` with a stderr note if the
   config fetch fails — annotation is best-effort and must never turn a
   working preflight red on its own.
2. Probe each cold dep read-only:
   `HEAD`-equivalent via `curl -sS -o /dev/null -D` on
   `{dl}/{name}/{version}/download`, capturing HTTP status and
   `Retry-After`.
3. Annotate per cold dep on **stderr**:
   - `503` with `Retry-After: N` → `<name> <version> — releases at <RFC 3339 UTC>`
     (`date -u -d "+N seconds"`; N is always delta-seconds here since the
     server emits seconds, but tolerate an absent header: print the raw
     status instead of fabricating a time).
   - `404` → `<name> <version> — not yet ingested (window starts when the
     warm's fetch lands)`.
   - `200` → `<name> <version> — already released (index refresh pending)`.
   - anything else (incl. curl failure `000`) → raw status, no guessing.
4. Closing stderr summary: `earliest clean re-run: <max of the 503-derived
   timestamps>` — only when at least one 503 annotation exists; when 404s
   exist add ` (plus deps not yet ingested — their windows have not
   started)`.
5. **stdout stays byte-identical**: cold "name version" pairs only, same
   ordering. `release.yml` captures stdout into `cold.txt` and feeds the
   prefetch-warm POST from it — any stdout change breaks the warm.
   The script stays side-effect-free (all probes are GET/HEAD).
6. Bounded parallelism consistent with the existing `xargs -P8` fetch
   pattern is fine but optional — cold sets are small; a serial loop is
   acceptable.

## Explicitly NOT in scope

- No release.yml change (the stderr annotations land in the job log via the
  existing call).
- No server-side change; no new headers; no index change.
- No retry/wait loop — the script reports, the operator re-runs.

## Acceptance

- With a quarantined cold dep, the run prints its absolute UTC release
  timestamp and the earliest-clean-re-run summary; a never-ingested dep is
  labeled as such; a config.json failure degrades to the fallback URL with
  a note, never a hard failure of the preflight itself.
- stdout for a given cold set is byte-identical to before the change
  (assert by eye in the report: show a before/after run transcript or a
  captured diff of stdout on a synthetic cold set).
- `bash -n` clean; matches the script's existing house style (fail-closed
  fetch pattern, stderr for humans / stdout for machines).
- Harness-only diff (one script) — gate per the harness-only economy:
  `bash -n`, diff-proof, `cargo audit`/`cargo deny`.
- Comment discipline: invariants only (esp. WHY stdout must stay stable and
  why annotation is best-effort).

## Governing decisions

Quarantine gate render (`Quarantined → 503 + Retry-After` — the base
already speaks correct HTTP; tooling reads it) · single-implementation rule
for the preflight (shared GitHub/GitLab) · release-warm choreography
precedent (warm via prefetch POST; lead the tag by one window).
