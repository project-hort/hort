# 298 — One predicate decides whether a scan verdict blocks, read by both paths

**Issue:** #344 · **Branch:** `agent/344-scan-verdict-release-authority`
**Governing decisions:** ADR 0007 (the authorities a timer release may carry),
ADR 0041 (continuous enforcement). **Depends on item 297.**

## What is true today

The release authority is derived in **two** places, from **two different
facts**, and they disagree:

| Where | Fact consulted | For 13 findings, none blocking |
|---|---|---|
| `record_scan_result`'s fast path (`quarantine_use_case.rs:410`, used at `:507`) | `findings_recorded = !violations.is_empty()` — the **policy verdict** | `ScanSucceeded` ⇒ released |
| `resolve_release_authority` step 1 (`:1448`) | `scan_completed.finding_count == 0` — the **raw count** (`findings.len()` at the emitter, `:910`) | no authority ⇒ stays quarantined |

The fast path's own comment claims *"This mirrors `resolve_release_authority`,
which the sweep uses for the same artifact when the window has not yet elapsed
at scan time"* (`:505`). It does not mirror it.

**Nothing documents the resulting behaviour** — no ADR, no doc, no test: the
same artifact releases or hangs depending on whether its scan finished *after*
or *within* its observation window, because the fast path only fires when the
window had already elapsed at scan time (`:479`–`:489`). With a ten-second
window and scans landing seconds after ingest, the sweep is the normal path.

Measured consequence (#342, production): one artifact with 13 findings and no
CRITICAL, in a repository with `enforcement: reject`, quarantined and
unreachable for more than seven hours, with the release gate attempting and
refusing it on every cycle.

## What to do

1. **One predicate, one definition:** "does the latest scan verdict for this
   artifact block under the active policy?" Both the fast path and
   `resolve_release_authority` read it. Two spellings of this question is the
   defect; do not leave a second one behind, and do not add a third caller
   without saying so in the report.
2. **The sweep reads the recorded verdict** (item 297), not a count: the latest
   `ScanCompleted`, a `PolicyEvaluated{Pass}` after it, and no later
   `ArtifactRejected` ⇒ the scan axis is satisfied. This is what makes the
   specification's "regardless of when the last scan was" true.
3. **Keep `finding_count == 0` as a second satisfier, for the legacy
   population only**, and say so in the code: artifacts scanned before item 297
   carry no verdict event, and a clean scan among them must keep releasing. No
   backfill, no migration.
4. **The ordering of the steps stays**: the `scan_backends: []` waiver and the
   `enforcement: record` arm keep their current precedence and meaning. This
   item changes which fact step 1 reads, not the shape of the ladder.
5. **Fail closed is unchanged**: no `ScanCompleted` ⇒ no authority, whatever
   the policy says. The regression that guards this
   (`release_expired_fail_closed_does_not_release_unscanned`) must pass
   untouched; if it needs editing, something is wrong with the change.

## Explicitly out of scope

- The authority **value** the new case carries (item 299). Until that lands it
  is acceptable for this item to reuse the existing value *in code*, but the
  report must say so explicitly, because the audit trail is then still
  dishonest and item 299 is what fixes it.
- Re-blocking a released artifact (item 300) and the test fixture (item 301).

## Acceptance

- An artifact with findings none of which breach the threshold, in a repository
  with `enforcement: reject`, is released by `release_expired` after its
  window — the production case from #342, as a test.
- The same artifact, scanned **after** its window had elapsed, is released by
  the fast path. Both paths asserted in one test module so the agreement is
  visible at the call site, not inferred.
- An artifact whose latest verdict **blocks** is not released by either path,
  and neither is one with no `ScanCompleted` at all.
- A legacy artifact — `ScanCompleted{finding_count: 0}` and **no**
  `PolicyEvaluated` — still releases.
- `scan_backends: []` and `enforcement: record` behave exactly as today; their
  existing tests pass unchanged.
- Non-vacuity: revert the sweep's leg and show the first test red; restore.
- Gate: full local gate, one-shot capture, foreground, report before exit.
