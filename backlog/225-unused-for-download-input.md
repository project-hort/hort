# 225 — `UnusedFor` must mean unused, or be refused at apply

**Issue:** #287 (part 2 of 2) · **Branch:** `agent/287-predicate-inputs`
**Depends on:** part 1 only for sequencing (same branch, land it after).
**Governing decisions:** ADR 0015 — a field an operator sets must be effective at
runtime, or apply must reject it · the architectural direction's externalised
timeseries for download counts.

## Why

The evaluator receives `last_downloaded_at: None`
(`crates/hort-app/src/use_cases/retention_use_case.rs:387-396`), and the
predicate then falls back to creation time
(`crates/hort-domain/src/retention/evaluate.rs:117-121`):

```rust
PolicyPredicate::UnusedFor(secs) => match inputs.last_downloaded_at {
    // Never downloaded → "unused since creation": the artifact
    // is unused for at least its full age.
    None => elapsed_at_least(inputs.created_at, inputs.now, *secs),
    Some(dl) => elapsed_at_least(dl, inputs.now, *secs),
},
```

The fallback is defensible for an artifact that is **known** never to have been
downloaded. It is wrong whenever the history is merely *unknown* — then
`UnusedFor` silently means "old", and a policy written to reclaim cold proxy cache
deletes hot content that happens to be old enough.

And the history is unknown more often than the audit flag suggests. Even with
auditing enabled, an absent `ArtifactDownloaded` does not prove absence of use:

- a failed audit append still serves the bytes
  (`crates/hort-app/src/use_cases/artifact_use_case.rs:483-541`),
- the OCI range GET deliberately bypasses the audit
  (`crates/hort-http-oci/src/blobs.rs:626-654,684-689`),
- auditing may have been switched on after the artifact was already in use,
- and `DownloadAudit` streams are age-archived, by default past 90 days
  (`crates/hort-app/src/use_cases/eventstore_retention_use_case.rs:156-158`).

So the input this predicate needs is not "the newest download event we can find"
but **a last-use signal that is complete and durable for the interval being
claimed**. Where that cannot be established, `UnusedFor` must be refused rather
than approximated — the fail-safe in the pure evaluator is the last line, and it
does not make an unknown history safe.

Whether the data exists is a per-repository setting: `download_audit_enabled`
defaults to `false` (`crates/hort-domain/src/entities/repository.rs:726`), and
without it the registry *"produces no `ArtifactDownloaded` events at all"*
(`crates/hort-domain/src/events/download_events.rs:8`).

That is exactly the shape ADR 0015 calls a hard block: a field accepted at apply
whose meaning at runtime is not what the operator wrote.

## Read first

- `crates/hort-domain/src/events/download_events.rs` — the event and when it is
  emitted at all.
- `crates/hort-domain/src/entities/repository.rs` — `download_audit_enabled`.
- The apply-time linter for retention policies in `hort-config` — where the
  rejection belongs, next to the existing cross-spec rules.
- `crates/hort-app/src/use_cases/retention_use_case.rs:380-400`.

## Scope

1. **Establish a last-use signal that covers the claimed interval** — including
   range reads and the audit-write failure path — and hand it to the evaluator
   instead of `None`. Closing those two gaps is part of this item; without them
   the signal is not what the predicate needs.
2. **Reject at apply** a policy whose predicate uses `UnusedFor` when the signal
   cannot cover its interval — a repository without `download_audit_enabled`, or
   an interval reaching further back than the audit-retention floor keeps the
   evidence. The message names the
   repository and the missing switch, so the operator can either turn auditing on
   or choose an age predicate deliberately.
3. **Keep the fail-safe** in the pure evaluator unchanged — it is the last line,
   not the first.

## Acceptance

- With auditing on, a frequently downloaded but old artifact does **not** expire
  under `UnusedFor` — the case today's code decides wrongly.
- With auditing off, the policy is refused at apply, naming the repository.
- An `UnusedFor` interval longer than the audit-retention floor is refused, rather
  than reading archived-away evidence as "never used".
- A range GET counts as use; a download whose audit append failed does not silently
  count as non-use.
- The pure evaluator's behaviour for an absent value is unchanged.
- `hort-domain` and `hort-app` stay at 100 %; DB-backed tests carry
  `#[serial(hort_pg_db)]`; gate green; no issue, MR or backlog numbers in code
  comments.

## Explicitly not in this item

No new download-counting infrastructure — this reads what the audit already
writes. No change to `KeepLastN` (part 1), no new predicates.
