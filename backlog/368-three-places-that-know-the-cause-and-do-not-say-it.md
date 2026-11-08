# 368 — Three places that know the cause and do not say it

**Issue:** #400 · **Branch:** `agent/400-operator-messages` · item 2 of 2.

Second wave of the #331 sweep. Three reports where the application **holds**
the distinguishing fact and drops it on the way out, so two situations that
call for different actions read the same. The rule that governs this wave: a
message exists for the action that follows it.

All three verified against develop `9202dcbc`; the line anchors in the #331
entries are from the day they were found and have drifted, so the ones below
are the current ones.

## a) A missing CAS file and an unreachable store read identically

**What the operator sees** (retention preview):

```
storage freed   NOT MEASURED — a reclaimable target size was unavailable
```

**Where it comes from.** `sum_target_sizes`
(`crates/hort-app/src/task_handlers/retention_evaluate.rs:868`) fans
`storage.size_of()` over every reclaim target and aborts on the first failure
— deliberately, because nothing can be claimed about a summand never
observed. On that path the specific error is logged
(`:878`, `tracing::warn!(error = %error, …)`) and then **replaced** by the
static `"a reclaimable target size was unavailable"` (`:880`). The return type
is `Result<u64, &'static str>`, which is why the cause cannot currently travel.
The CLI renders whatever reason arrives
(`crates/hort-cli/src/admin/retention/render.rs:94`).

**Why the action differs.** *The store did not answer* is an operations
problem. *Some of your targets no longer exist* is a data-integrity finding —
a dangling `content_references` row, an artifact reported as present that
cannot be served. On a registry the second is the more interesting one, and
today an operator only learns it by searching the worker log — with the very
tool that is withholding it.

**The outcome.** The cause travels to the operator output: at minimum "a
target is missing" against "the store did not answer", better with the hash.
The aborting semantics do not change and no partial sums appear.

## b) The release preflight advises waiting where waiting never helps

**What the operator sees** (`.github/workflows/release.yml:536`):

> hort-publish preflight: N locked dependency version(s) are not yet served by
> the vetted index (cargo-virtual, released_only) … re-run this release after
> the crates-proxy quarantine window (24h, or 3d …) so every cold dep above
> has cleared quarantine.

**The finding.** A version is absent from the index for **three** reasons and
the text knows two. `cargo-virtual` is `released_only`, and
`crates/hort-http-cargo/src/serve.rs:41` says it outright: *"terminal verdicts
stay hidden from everyone"*.

| why it is invisible | does waiting help? |
|---|---|
| never ingested (cold) | yes — after the warm plus the window |
| inside the quarantine window | yes — the window expires |
| **terminally rejected** | **no, never** |

For the third row both the advice and the job's action (a prefetch POST) are
inert: prefetch moves a crate from *absent* to *ingested*, not from *rejected*
to *served*.

**Why the action differs.** A release blocked on a rejected dependency is told
to do something that never comes true; the operator waits, re-runs, waits
again, and the error is the same every time. The actual ways out are not named
anywhere: a re-scan clears a scanner rejection
(`is_scan_clearable`, `crates/hort-domain/src/entities/artifact.rs:2393`) and a
curator waive overrides the overridable reasons
(`is_curator_overridable`, `:2491`) — `Admin` and `Corruption` are neither.

**The outcome.** The honest text: list the cold set **and** say that a version
still missing after the warm and the window is not a window problem but a
verdict problem, naming the ways out. Querying each version's status and
reporting the three cases separately is the larger variant and depends on
which status surface the release identity may read — out of scope here, and
the text must not imply it happened.

While rewriting it: the message currently points the operator at an internal
tracker item for the 3-day figure. An operator cannot read our tracker — state
the figure, not the reference.

## c) The metrics catalog describes a duration the code does not measure

**What a reader sees** (`docs/metrics-catalog.md:4208`):

> `hort_admin_tasks_duration_seconds` … wall-clock time **from claim to
> outcome recording**, wrapping `TaskHandler::run`

**What the code does.** In `dispatch_one`
(`crates/hort-app/src/task_dispatcher.rs:877`) the measurement starts at
`:914`, immediately before `handler.run`, and the histogram is observed at
`:925`. The concurrency permit is taken **before** `dispatch_one` is called
(`:544`). Between the claim and the measurement's start therefore sit: the
`tokio::spawn`, the **permit wait**, params parsing, the `TaskContext` build,
the in-flight gauge (`:905`) and the lease-renewal spawn (`:912`). The
sentence's second half ("wrapping `TaskHandler::run`") is right; the first
("from claim") is wrong.

**Why it matters more than a typo.** A reader concludes the metric contains
wait time, so for "how long do the kinds actually run?" they look elsewhere or
build something new — while the metric already **is** the pure active runtime
per kind, which is exactly the runtime half of ADR 0066's class assignment.
The confusion is not harmless in the other direction either: whoever wants
claim-to-outcome latency does **not** find it here and would have to derive it
from `jobs`.

**The outcome.** The description is pulled onto what is measured, and — since
the gap is then named — it says that the wait time is in no metric.

**Half of this already landed on another branch, so re-read before writing.**
#399's lease unit corrected the *same wrong sentence* at its other site —
`task_dispatcher.rs`'s module header, which claimed "elapsed time from claim to
`record_outcome_for_row`" and now reads "elapsed time inside `TaskHandler::run`,
and nothing else … no metric here covers that yet". The catalog line is still
wrong and is still this item's (`docs/metrics-catalog.md:4208` on develop
after #399 — the line number has moved twice, so re-grep rather than trusting
it). Match the code's wording rather
than inventing a second phrasing, and note that the permit wait became *more*
worth naming there: after that unit a claimed row can wait arbitrarily long
without its lease lapsing, so the wait is now the invisible part of a task's
life rather than a short gap.

## Acceptance

1. **Every changed output is shown as rendered text, before and after** — not
   as a format string.
2. One test per entry that asserts the **distinction**, not the wording: (a)
   the two failure causes produce different operator text; (b) the preflight
   text names the third reason and the ways out. For (c) the catalog is prose
   — the proof is the quoted code anchor, not a test.
3. (a) does not change the aborting semantics and reports no partial sums.
4. (b) changes no gate and no job condition — text only.
5. No issue, MR or backlog reference appears in any changed message (the
   release message's existing one goes).
6. `CHANGELOG.md`: one entry covering (a) and (b). (c) is documentation and
   gets none.

## Not in this item

- The curation queue (item 1).
- **E43 — the provenance hold's reason reaching the publisher.** Parked on a
  maintainer decision, not on work: the content route deliberately keeps the
  two holds indistinguishable
  (`crates/hort-http-core/src/artifact_gate.rs:192-196`) and a hold emits no
  event by design (`crates/hort-domain/src/ports/provenance.rs:286-287`), so
  the outcome is a decision about what a publisher may learn and whether a
  hold gets a record. The typed reason already reaches the per-artifact
  job-row `result_summary` as `held_indeterminate`
  (`crates/hort-app/src/task_handlers/provenance_verify.rs:181`).
