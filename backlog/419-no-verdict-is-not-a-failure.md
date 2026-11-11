# 419 — "Nothing to analyse" is an answer, not a failure

**Issue:** #427 · **Branch:** `agent/427-no-verdict-is-not-a-failure` ·
the only item. **No ADR change, no migration.**

**Governing decisions:** ADR 0007 (*"findings are evidence, the verdict is
the decision"* — and its retry-exhaustion split, which is what the stranded
sweep implements), ADR 0064 D6 (why such a blob has nothing to analyse). **No
new decision:** the domain already models this outcome as distinct; this item
stops one table row from collapsing it.

## The property

**A scan that answered must not be recorded as a scan that failed.**

`ScanAnalysis` (`crates/hort-domain/src/ports/scanner.rs:511-518`) carries
two **Ok** variants and states the difference itself:

- `Analysed(Vec<Finding>)` — *"An empty vector here **is** a clean verdict
  and carries release authority."*
- `NothingAnalysable(NotAnalysable)` — *"The backend produced no verdict at
  all. Carries no findings by construction."*

So "no verdict" is explicitly **neither** an error **nor** clean. One row in
the scan handler's disposition table
(`crates/hort-app/src/task_handlers/scan.rs:41`) collapses the first half:

```
| NothingAnalysable | Failed(reason) | Failed { retry: false } |
```

That produces a `jobs` row with `status='failed'`, and `select_stranded`
(`crates/hort-domain/src/ports/rescan_candidates.rs:131-145`) selects exactly
that — most recent `kind='scan'` job `failed`, no in-flight scan, and
explicitly *"no interval/`now` gating — a stranded artifact is eligible
immediately, not after a policy-derived wait."* The `cron-rescan-tick`
re-enqueues every tick. For a structurally unanalysable target the loop never
terminates.

**The table's own neighbourhood is the argument for this item.** The comment
directly above it records that this very collapse was fixed once: *"'answered',
'still owes an answer' and 'gave up' were one word at the one place an
operator looks."* Three words were separated and `NothingAnalysable` landed on
the "gave up" side.

## What to build

**A fourth disposition** — "answered, had nothing to analyse" — so the row is
not `failed`.

**The shape is already determined by the existing outcome vocabulary**, and
the review established it so this item does not have to invent one:

- it maps to **`TaskOutcome::Completed { result_summary }`** — the only
  existing outcome that writes `result_summary`, where `Failed` writes
  `last_error` (`crates/hort-domain/src/ports/task_handler.rs:55-83`;
  `crates/hort-adapters-postgres/src/jobs_repository.rs:530-546`);
- **no fourth persisted `JobStatus` is needed**, and none may be added;
- the dispatcher still applies the same `(id, attempts)` fence and remains
  the single result writer, and a completed outcome **does not spend a retry
  attempt** (`jobs_repository.rs:485-520`;
  `crates/hort-app/src/task_dispatcher.rs:1514-1552`);
- admin task responses already carry both status and structured summary, so
  no API surface changes (`crates/hort-http-admin-tasks/src/dto.rs:20-57`).

**And the scan-job metric needs a distinct no-verdict label — this is a
requirement, not a nicety.** The scan counter's `completed` means *"the scan
recorded a result"* and its taxonomy is closed at four values
(`crates/hort-app/src/metrics.rs:2600-2649`;
`docs/metrics-catalog.md:3320-3374`). **Relabelling today's `failed`
emission as `completed` would make a held, unassessed artifact look clean in
the scan counter** — trading a wrong "failed" for a wrong "clean", which is
the worse direction. Add the label and update the catalog in the same change.
The artifact-terminal `indeterminate` emission stays truthful because the
artifact transition is unchanged.

Three consequences that are the acceptance, not side effects:

1. **The stranded sweep stops seeing it**, so the loop ends. No change to
   `select_stranded`: its query is right, it was being fed a wrong fact.
2. **The reason moves out of `last_error`** into the result summary. An
   operator reads `last_error` for errors; a non-error reason there is the
   same category mistake one field down.
3. **`hort_cron_rescan_stranded_eligible_artifacts` becomes meaningful
   again.** Its contract is scanner-outage detection — *"a recovered scanner
   drains this to zero every tick"* — and it has been counting structural
   cases as outages.

## What must not change

**The artifact stays held.** No verdict carries no release authority, and
that is correct: if nothing looked inside, nothing knows it is clean. This
item changes a *job disposition*, not a release decision. A test must pin
that the artifact's `quarantine_status` is unchanged by this item.

`compositeVerdictMode` is **irrelevant here** — the scan handler never reads
it (zero occurrences in the file) and the mapping is unconditional, so this
defect exists in both modes and this fix applies in both. The mode question
is #428's.

## This item must NOT ship alone — corrected 2026-11-09 by an outside review

**An earlier draft of this item said it could "land first and alone", and
that was backwards.** The review found that on its own it **replaces an
endless retry with a durable withheld artifact**:

- a `NothingAnalysable` scan still records **`scan_indeterminate`** on the
  artifact (`crates/hort-app/src/use_cases/scan_orchestration.rs:1383-1420`),
  and this item deliberately leaves that transition alone;
- but the now-**completed** job is no longer selected by `select_stranded`,
  which requires the latest `kind='scan'` job to be `failed` or absent
  (`crates/hort-adapters-postgres/src/rescan_candidates.rs:273-307`);
- and the interval sweep **excludes `scan_indeterminate`** (`:135-150`).

So the artifact loses its **only automatic selection signal**, and #428
landing later repairs no stored fact. Today's loop is wasteful; this item
alone would make it quiet and permanent. **That is worse.**

**Therefore: the code reviews may stay separate, but the rollout is one.**
This item ships together with #428's targeted reassessment of the
completed/no-verdict population it creates, or it does not ship. The
acceptance below carries that as a condition rather than a note.

## The operator's discovery surface moves with the row

The section above moves the *reason* out of `last_error`. It also moves the
whole population out of every surface keyed on `status='failed'` — and two
documents name that key as a promise to an operator.

`docs/architecture/how-to/recover-stranded-artifacts.md` is the playbook for
exactly this situation:

- it names `GET /api/v1/admin/tasks?kind=scan&status=failed` as the way to
  list these jobs (`:102-103`), and the persisted `jobs.status='failed'` fact
  as what makes an artifact "stranded" (`:44-45`, `:143`). After this change
  that query no longer returns the no-verdict population — the playbook would
  send an operator to a listing that silently omits exactly the artifacts
  they came to find;
- and it already states this item's coupling, as a promise: *"A scan that
  produced no verdict still goes to the `scan_indeterminate` path, and as of
  ADR 0007's 'A reached verdict supersedes an absent one' the same sweep
  recovers that state too — the two differ in which status the artifact waits
  in, not in whether anything re-scans it."* (`:46-49`). **This item alone
  makes that sentence false**, which is the "must not ship alone" argument
  above written down as an operator-facing guarantee. #428's cutover is what
  makes it true again.

`docs/metrics-catalog.md:3395-3404` says of this very case that
`hort_scan_jobs_total{result=failed}` still fires and that
`jobs.status='failed'` is what `select_stranded` reads to re-pick the artifact
once the scanner recovers. Both halves become false for this population.

So the documentation update is not cosmetic: it is the module-doc-table
requirement applied to the two documents an operator actually reads. Update
the passages that name `status='failed'` as **this population's** discovery
signal — and nothing else; the genuine scanner-failure population keeps every
one of them.

## The label's own neighbourhood

The fifth `ScanJobsResult` value makes four one-line statements false:

- `ScanJobsResult`'s doc — *"Closed taxonomy of 4"*
  (`crates/hort-app/src/metrics.rs:2599-2601`);
- `ScanJobsResult::Failed`'s doc — *"the job exhausted `max_attempts`, or had
  nothing analysable"* (`:2620-2622`);
- the catalog's table row (`docs/metrics-catalog.md:2906`) and its cardinality
  line *"`hort_scan_jobs_total`: 4 result values → 4 series ceiling"*
  (`:3308` — **not** `:3407`, which is `hort_scan_terminal_total`'s and stays
  at 4).

And one that is **already** false, directly beside the change:
`ScanTerminalResult::Indeterminate`'s doc says it is *"Emitted on the
retry-exhausted `Failed` arm"* (`metrics.rs:2677-2680`), but it is emitted at
two sites — `scan_orchestration.rs:1419` (this item's `NothingAnalysable` arm)
and `:1506` (the retry-exhausted one). Correct it to name both. A reader
comparing the new no-verdict label against its artifact-terminal sibling would
otherwise conclude this arm emits no terminal tick at all. That is the only
pre-existing line to fix; do not sweep further.

## The one real design decision

Whether `ScanRowDisposition` gains a fourth variant or this arm returns the
existing `Completed`. Both satisfy "the row is not `failed`", and the type is
read in exactly one place — `outcome_for`
(`crates/hort-app/src/task_handlers/scan.rs:85-91`) — so a fourth variant's
only effect is documentary plus exhaustive-match pressure. Argue the call in
the report; do not leave it implicit.

Either way **three comments become false and must be corrected in the same
change**, because as written they read as *forbidding* the new mapping:

- `outcome_for`'s doc: *"the thing a future change is most likely to get wrong
  is returning `Completed` for an arm that did not complete"* (`:79`) and
  *"`result_summary` rides only the `Completed` disposition"* (`:82`). This arm
  **did** complete — it answered — which is this item's whole premise;
- the summary builder's comment: *"These two arms never reach a `Completed`
  disposition, so `outcome_for` drops the summary"* (`:219`).

And note what you do **not** have to build. The `result_summary` for this arm
already exists — `{"scanner": …, "nothing_analysable": reason}` — carrying a
comment that anticipated this exact change: *"Built anyway: a future arm that
starts completing must not inherit a `Null` summary by omission."* Use it. A
second summary shape would be the duplication this codebase rejects.

## Explicitly not in scope

The permanent hold itself, whether such a blob should be assessed at all, and
the mode retirement — all #428.

## Acceptance

- A scan where every backend answers "nothing analysable" leaves a `jobs` row
  that is **not** `status='failed'`, and `select_stranded` does not return
  that artifact. Both halves asserted — the row's disposition **and** the
  sweep's selection over it.
- The artifact's `quarantine_status` is unchanged by the new disposition.
- The reason is in the result summary and **not** in `last_error`.
- A genuine scanner-execution failure still becomes `failed` and **is** still
  selected by the sweep, with its retry behaviour unchanged. This is the
  counter-assertion: the fix must not make real failures invisible.
- The disposition table in the module doc is updated in the same change — it
  is the thing a reader consults, and a stale table here is how the first
  collapse survived.
- **The two operator-facing documents are updated in the same change** —
  `docs/architecture/how-to/recover-stranded-artifacts.md`'s `status=failed`
  discovery passages and its no-verdict-recovery promise, and
  `docs/metrics-catalog.md:3395-3404`. Same reason as the module-doc table,
  one level up: this is where an operator looks.
- **The five one-line statements named above are corrected** — four made false
  by the new label, one already false (`ScanTerminalResult::Indeterminate`'s
  single-site claim) — plus the three comments in `task_handlers/scan.rs` that
  otherwise read as forbidding the new mapping.
- **The rollout condition is stated in the report**: this item's completed
  no-verdict population is reassessed by #428's cutover, and the report says
  so explicitly rather than leaving the coupling implicit.
- Gate green; no uncovered added lines; no ticket numbers in code comments.
