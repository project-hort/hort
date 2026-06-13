# 0007 — Fail-closed quarantine release predicate

- **Status:** Accepted
- **Enforced by:** the background sweep releases an artifact only when `quarantine_until <= now()` **AND** the application layer can supply a recognised release authority; the predicate accepts exactly five `(reason, authority)` pairs and denies every other. The predicate is implemented in `Artifact::release` (`crates/hort-domain/src/entities/artifact.rs`) with exhaustive per-authority tests; the architect anti-pattern *scanner clean → immediate release* is a review hard-block.
- **Supersedes:** —

## Context

Quarantine is the observation window that lets a scan run and lets a malicious package's reputation catch up before it can be downloaded or promoted. Two failure modes must be impossible: (1) a clean scan releasing an artifact *early* (before the window elapses), and (2) a never-successfully-scanned artifact releasing on the timer alone when its window expires. Both would let an unvetted artifact through.

`quarantine_until <= now()` answers "is the window over?" — it must never, by itself, answer "may this be released?".

## Decision

Downloads are blocked while `quarantine_status = 'quarantined'`, regardless of the timestamp — the **status** is the gate, the **timestamp** is only the sweep's candidacy filter.

The background sweep transitions an artifact to `released` only when `quarantine_until <= now()` **AND** a release authority is available. The release predicate accepts **exactly five authorities** and denies every other `(reason, authority)` pair:

1. `ScanSucceeded` — a successful `ScanCompleted` on the artifact stream.
2. `ScanWaived` — the resolved `ScanPolicy` declares `scan_backends: []`.
3. `AdminOverride` — explicit admin release.
4. `CuratorWaiver` — curator waive (`Quarantined`-state only).
5. `PolicyReEvaluation` — post-exclusion policy re-evaluation.

`ScanCompleted(clean)` does **not** clear `quarantine_until` or set `released`. `ScanCompleted(findings)` immediately sets `rejected` (time never reverses this). A scan job that exhausts retries goes to the terminal `scan_indeterminate` status — non-downloadable, non-promotable, **not releasable by a timer alone** (only admin override or post-exclusion re-evaluation).

## Consequences

- A missing or failed scan **fails closed**: the artifact does not leak out when its timer expires; it lands in `scan_indeterminate`.
- Adding any new release path means adding an authority to the enumerated predicate, with its own guard — there is no "fall through to released".
- The `scan_backends: []` waiver is an explicit, audited authority, not an accidental gap.
- Re-evaluation after an exclusion does not skip the remaining observation window: it removes the scan block, not the time hold.

## Alternatives considered

- **Release on `quarantine_until` expiry alone.** Rejected: this is precisely the hole the fail-closed predicate exists to plug — an artifact that never passed a scan would auto-release on the timer.
- **Clean scan releases immediately.** Rejected: collapses the observation window the quarantine exists to provide.
- **A boolean "releasable" flag set by various code paths.** Rejected: a single mutable flag with many writers is exactly the ambiguity the enumerated `(reason, authority)` predicate removes.

## References

- `crates/hort-domain/src/entities/artifact.rs` (`Artifact::release`) and `crates/hort-domain/src/ports/quarantine_release.rs` — the release predicate and `ScanIndeterminate` status.
- The architect skill → Quarantine Invariants; anti-pattern *scanner clean → immediate release*.
- `docs/architecture/how-to/curator-workflow.md` — the curator-waiver authority in practice.
