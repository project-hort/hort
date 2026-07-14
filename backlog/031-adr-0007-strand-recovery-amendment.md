# 031 — Amend ADR 0007 + architect-guide invariant #2 for the #6 stranded-scan behavior

- **Source:** GitLab issue #31 (architecture & security re-audit). Finding **C-1**.
- **Type:** docs (standing-decision reconciliation) — **security control**.
- **Gated on:** an **answered `agent:decision` issue** (platform contract: *ADR
  changes land only after an answered `agent:decision` issue*). Do NOT edit
  `docs/adr/0007-*` until the decision is answered.
- **Model hint:** **capable** — touches a security-control ADR and the architect
  guide; wording must be precise about the fail-closed guarantee.
- **Reviewable unit:** one directive (doc-only), on branch `agent/31-audit-develop-changes`.

## Problem

Commit `55a93e40` (`fix(resilience): auto-recover artifacts stranded by a
scanner outage`, issue #6) **changed the documented behavior of a security
control without amending its ADR.**

Before: a scan job that **exhausts retries** transitions the artifact to the
terminal `scan_indeterminate` status — unconditionally.

After `55a93e40`: on retry-exhaustion the handler
(`ScanOrchestrationUseCase::record_outcome`) **splits by current status**:
- `quarantine_status = 'quarantined'` (mid-observation-window) → **stays
  `quarantined`** (no `ScanIndeterminate` event, no status UPDATE); the failed
  `jobs` row is the "last scan errored" signal that `select_stranded` +
  `CronRescanTickHandler` read to re-enqueue once the scanner recovers.
- any other status (`None` / already-terminal) → `scan_indeterminate` **exactly
  as before**.

This contradicts the standing record in two places, both now stale as-built:
- **`docs/adr/0007-fail-closed-quarantine-release-predicate.md`** lines 25 &
  29: *"A scan job that exhausts retries goes to the terminal
  `scan_indeterminate` status"* / *"A missing or failed scan fails closed … it
  lands in `scan_indeterminate`."*
- **Architect guide** (`.claude/commands/hort-architect.md`) **Quarantine
  invariant #2**: *"A scan job that exhausts retries transitions the artifact to
  the terminal `scan_indeterminate` status (event `ScanIndeterminate`)."*
  (Mirrored in `CLAUDE.md`'s anti-pattern bullet for *scanner clean → immediate
  release*, which cites the same predicate.)

## Why this is a finding, not a defect in the code

The **runtime behavior is fail-closed and correct** — independently verified: a
`quarantined`, never-successfully-scanned artifact **cannot be timer-released**.
`resolve_release_authority`
(`crates/hort-app/src/use_cases/quarantine_use_case.rs`) derives `ScanSucceeded`
from a `ScanCompleted` **event on the artifact stream**; the stranded artifact
has none, so the sweep skips it (`skipped_no_authority`), and the domain
predicate `Artifact::release` (`crates/hort-domain/src/entities/artifact.rs`)
re-denies by construction. CAS, upstream verification, and the event chain are
untouched (staying `quarantined` is a **non-transition**, so no event is owed —
there is no silent-UPDATE violation). The change adds **no new release
authority**.

So the code likely deserves ratification. **The gap is process + record
integrity:** a security-control behavior documented in a standing ADR was
changed by an implementation commit landed directly on `develop` while the
architect guide was not loaded, and ADR 0007 + the guide now lie about the
as-built. The platform contract requires an ADR amendment (behind an answered
`agent:decision`) for exactly this.

## Approach (once the decision is answered)

1. **Amend ADR 0007** (do not rewrite intent): keep the two impossible-failure
   modes (§ line 9) verbatim — the guarantee is unchanged. Add a subsection
   documenting the exhaustion **split**: `quarantined` stays `quarantined`
   (recoverable via the existing `ScanSucceeded` authority, self-healed by the
   rescan sweep); every other status still fails to terminal `scan_indeterminate`.
   State explicitly *why staying `quarantined` is still fail-closed* (release
   still requires a stream-derived authority; window expiry is candidacy only).
   Reference issue #6 and `55a93e40`.
2. **Update architect-guide Quarantine invariant #2** and the mirrored
   `CLAUDE.md` bullet to match — one aligned sentence, no drift between the two.
3. **Cross-check** the `scan_indeterminate` terminal-state prose elsewhere in the
   guide (invariant #3, the anti-patterns checklist) for any now-inaccurate
   "exhaustion ⇒ scan_indeterminate" absolutes; qualify with "unless already
   `quarantined` mid-window".
4. No code change. No new migration. Doc-only.

## Acceptance

- ADR 0007 and architect-guide invariant #2 (and the `CLAUDE.md` mirror)
  describe the as-built exhaustion split and explicitly re-assert the
  fail-closed guarantee for the `quarantined`-stays-`quarantined` path.
- The `agent:decision` issue is answered (human ratifies the ADR amendment)
  **before** the ADR edit merges.
- `grep -n "exhausts retries" docs/adr/0007-*.md .claude/commands/hort-architect.md`
  returns no statement that contradicts the code.

## Out of scope

- Reverting or re-implementing `55a93e40` — the behavior is verified fail-closed.
- Any change to the release predicate, release authorities, or `Artifact::release`.
