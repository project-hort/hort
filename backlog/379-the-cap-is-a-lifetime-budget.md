# 379 — The 200-event cap is a lifetime budget that every rescan spends

**Issue:** #406 · **Branch:** `agent/406-lifetime-event-budget` · single item.

Found 2026-11-03 reviewing everything since `v0.17.2`, where it was first
filed as a defect in the provenance-hold work. The mechanism is older than
`v0.17.2` and sits underneath it. Verified against `develop` `fdcfaa43`.

## The finding

**`STREAM_EVENT_CAP` is not a read budget. It is an enforced invariant, and
therefore a lifetime budget of 200 events per artifact that every rescan
spends.**

The constant says so itself (`crates/hort-app/src/use_cases/mod.rs:265`):

> The maximum number of events an artifact stream may hold … an enforced,
> fail-closed bound, not an estimate of how long a stream gets. It is what
> makes a single capped `ReadFrom::Start` read of an artifact stream equal to
> reading the whole stream — the property every consumer of the stream's
> history silently depends on.

Both sides enforce it: the write side refuses to derive an append version for a
stream over the cap, and the read side reads `CAP + 1` and refuses rather than
hand its caller the oldest prefix. **So the oldest-first read direction is
correct by construction** — if a stream may never exceed 200 events, a capped
forward read *is* the whole stream.

What the design assumes is that 200 events are more than an artifact needs. The
rescan path breaks that assumption: `record_scan_result` appends a
`ScanCompleted` on **every** scan, whether the verdict moved or not
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:1267-1286`).
`ArtifactBecameVulnerable` and the policy reject events are appended only on a
change. The fuse is therefore the **rescan cadence, not the artifact's age**:
roughly half a year at a daily rescan, roughly four years at a weekly one.

**The breach is detected, not prevented.** The predicate is `len > CAP`
(`mod.rs:381`), so at 200 events `over_cap` is still false, the next append is
admitted and takes the stream to 201 — and from there every read refuses. The
**201st event is admitted and is what freezes the artifact.**

**What that costs.** In `record_scan_result`, `paired.evidence()` refuses and
the error propagates deliberately (`quarantine_use_case.rs:1263-1266`: *"failing
it makes the dispatcher retry instead of silently dropping a scan result"*), so
the scan job retries to its attempt cap and the verdict is never recorded. The
release sweep skips the candidate with an `error!` and leaves it quarantined;
the comment there calls it *"frozen until an operator intervenes, and nothing
else in the system will say so"* (`quarantine_use_case.rs:1931-1938`).

## The maintainer's decision (2026-11-03)

Append `ScanCompleted` only when the verdict changes, and raise the cap to
1000.

## The outcome

1. **`ScanCompleted` is appended only on a changed verdict.** Changed means the
   `severity_summary` **or** the content hash of the `findings_blob` differs
   from the last recorded `ScanCompleted`. The summary alone is too coarse: two
   scans can both be "1 HIGH" about different CVEs. The blob is `serde_json`
   over the findings list — `purl`, `vulnerability_id`, `severity`,
   `cvss_score`, `title`, `fixed_versions`, `source_scanner`, `references`,
   `aliases` (`quarantine_use_case.rs:1512-1520`) — and carries **no timestamp
   and no scanner version**, so an identical finding set hashes identically.
   **The finding order must be deterministic before serialisation**, or the
   hash flaps and the saving never materialises. The comparison material is
   already in hand: the prior `ScanCompleted` baseline is read for delta
   detection.
2. **`STREAM_EVENT_CAP` goes from 200 to 1000**, in the one place it is defined
   (`mod.rs:300`). Test corpora derive their size from the constant
   (`artifact_use_case.rs:4209`) and scale with it.
3. **The scan path refuses before it breaches**, in the shape
   `RetentionUseCase::append_expired` already has
   (`retention_use_case.rs:702`: `stream_len + 1 > STREAM_EVENT_CAP`). That is
   the other repeatable writer on this category and it gets this right; the
   scan path takes the same check so the invariant is prevented rather than
   detected afterwards.

## Not in this item

- **Moving scan history to its own stream** — proposed and withdrawn. The
  release authority would then decide from two streams and lose the no-strand
  guarantee of ADR 0002/0004, and existing artifact streams already hold these
  events, so it is not backward compatible.
- **Reversing the read direction** — proposed and withdrawn. The oldest 200 are
  correct as long as the cap holds; reversing would have cost a port change
  (`ReadFrom` carries only `Start` and `After`) to solve a problem the design
  does not have.
- **Tooling for already-frozen artifacts** — raising the cap to 1000 *is* the
  recovery: every artifact between 201 and 1000 events is readable and
  releasable again after the deploy.

## Acceptance

1. A rescan whose verdict is unchanged appends **no** event — shown by a test
   that feeds the same finding set twice and compares the stream length.
2. A rescan with a **different finding set at the same `severity_summary`**
   does append. That is the case a summary-only check misses, and it needs its
   own test.
3. `artifacts.last_scan_at` and the `scan_findings` projection are still
   updated when no event is appended — *when* and *what* stay observable.
4. The scan path refuses at `len + 1 > CAP`, naming the stream and the cap,
   **before** appending.
5. The cap is defined in exactly one place; no test and no guard carries the
   number a second time.
6. `CHANGELOG.md`: one entry. Subscribers to the artifact events will see
   `ScanCompleted` only on a verdict change, which is observable and belongs
   there.
