# 384 — Three places the class guarantee is not enforced

**Issue:** #409 · **Branch:** `agent/409-the-class-guarantee-is-not-enforced` ·
single item, three parts.

**Governing decisions:** ADR 0066 D1 (non-displacement), D5 (every class is
guaranteed service), D6 (no producer names a number). **No ADR change** — all
three parts enforce a decision that already exists. Whether the ADR must
*name* the share-zero waiver is deliberately not here: that is #413.

Verified against `develop` `454f8fb7`; the line numbers below are from that
tree.

## a) A smaller claim batch voids the band reservation, and the arithmetic is written nowhere

`CLAIM_PENDING_BY_KINDS_SQL`
(`crates/hort-adapters-postgres/src/jobs_repository.rs:196-240`) spends the
batch in three passes. `reserved` takes up to `$7` (the share) rows **per
band** through a `CROSS JOIN LATERAL`, then `ORDER BY held.ord LIMIT $2` cuts
the pass down to the batch — and `ord` is the band order, so the cut removes
the **lowest** class first. `oldest` then gets
`LEAST($2 - |reserved|, 1)`, `ranked` the remainder.

That produces a threshold nothing states. The reservation covers the
**waited-on** bands only — `waited_on_bands()` is `TaskTier::ALL` filtered by
`is_waited_on()`, and `TaskTier::Bulk` is deliberately absent (D4) — so there
are **two** reserved bands, not three:

| batch (`HORT_SCANNER_BATCH_SIZE`) | share 1 | outcome |
|---|---|---|
| 1 | 1 | the reserved pass is capped at 1 — only `Interactive` is ever claimed |
| 2 | 1 | the reserved pass takes both waited-on bands and `oldest` gets `LEAST(0, 1)` — `Bulk` is never claimed |
| **3** | 1 | reserved 2 + the age slot 1 — every class is served; this is the minimum |
| 4 (default) | 1 | the minimum, plus one row for the ranked remainder |

An operator who lowers the batch — the obvious move against lock contention —
silently removes a band from allocation. Raising the share without raising the
batch does the same.

**Build: refuse at boot** below `bands × slots_per_band + 1`, with the band
count read **off the reservation** rather than written as a literal: a literal
would refuse a batch that does serve every class, and a band count typed into
`hort-worker` would be a second answer to "which classes get a reserved share",
which is what D6 exists to prevent. The message names both values, the
minimum, and why. Not a warning: a class that is never served is a D5 defect, and this
configuration has one. The house style is already this — the worker config
rejects a typo rather than interpreting it.

**State the compatibility consequence rather than discovering it.** A
deployment that today runs `HORT_SCANNER_BATCH_SIZE=2` will **refuse to start**
after this change; `=3` still starts, because it serves every class. That is intended — such a worker never claims `Bulk` work —
and it is the reason the error message has to carry the arithmetic and the fix
in one line, and the reason this gets a `CHANGELOG.md` entry naming the
variable.

Do **not** silently raise the batch to the minimum: overriding an operator's
number without saying so is the failure mode this whole ticket is about. Put
the arithmetic in the doc comments of both knobs as well, so the relationship
is readable where the numbers are configured.

## b) The ordinal guard only sees method-call syntax

`crates/hort-app/tests/no_producer_names_an_ordinal.rs` (classifier at
`:264-285`) matches the literal `.enqueue_task(` / `.enqueue_scan(` and
resolves the ordinal argument's position from the port signature. A valid call
in UFCS form — `JobsRepository::enqueue_task(&*repo, …, 60, …)` — contains no
such literal and is invisible. The counter-assertion is
`count(Ordinal::Table, "enqueue") >= 4` (`:452`), a **lower bound**: rewriting
one existing table call site into UFCS leaves four and keeps the guard green.
UFCS also shifts every argument position by one, because `self` becomes the
first argument, so a naive widening of the matcher would check the wrong
argument.

No current violation — every producer today uses the table. But the guard *is*
D6's enforcement, and its blind spot sits on a syntax a compiler suggestion or
a refactoring tool produces by itself.

**Build:** match both call forms and derive the argument position **per form**
instead of assuming one. Turn the `>= 4` counter-assertion into an exact
number if it can be derived; a lower bound cannot tell a vanished hit from one
that was never there. Add a fixture in UFCS form that the guard must catch.

## c) The dispatcher runs a row after the fence said it is not its row

After the permit is granted, the dispatcher writes the row's capacity wait back
(`end_capacity_wait`, `crates/hort-app/src/task_dispatcher.rs:922-947`). The
adapter answers `Ok(false)` when the row is no longer this worker's:
`CLEAR_CAPACITY_WAIT_SQL` fences on `locked_by = $2 AND status = 'running'`
(`crates/hort-adapters-postgres/src/jobs_repository.rs:329-347`), and that
statement's own doc comment gives the purpose verbatim — *"a worker whose row
was swept and handed on must not write to the row its successor now holds"*,
and *"`rows_affected() == 0` is 'the row moved on', not an error"*.

The dispatcher logs `debug!` *"leaving it to whoever holds it now"* (`:934`)
and calls `dispatch_one` on the **next line** (`:694` → `:695`), which runs the
handler.

**The premise the in-tree justification rests on is false.** The test comment
says the renewal guard is what the dispatcher acts on for that row, but
`stop_renewing_and_check_fence` is evaluated *after* `handler.run` on both
paths — it gates the result write and never the execution.

Consequence: two workers run the same row at once. The result write is fenced
by `AND attempts = $2`, so the state does not go wrong, but the work doubles —
a second scan occupies scanner capacity, and both runs can append
`ScanCompleted` to the same stream. "Dropping work on the floor" is not the
counter-argument: the other worker *has* the row. Worst case (the sweep
requeued it and nobody re-claimed) the row waits one poll interval.

**Build: do not run it.** On `Ok(false)`, skip the dispatch and leave the row
to its holder. The cheap check already runs and its answer is discarded, and
the project's posture is fail-closed. **Correct the false sentence in the test
comment** in the same change — the behaviour and its justification move
together. `Err` (the database did not answer) is untouched: that is no
statement about ownership and must keep running.

## Acceptance

1. (a) A batch/share combination that removes a band from allocation fails
   worker startup — one test per direction (batch too small, share too large),
   and one that the default pair starts **and that the minimum itself starts
   while one below it does not**, with the minimum taken from the reservation
   rather than spelled. The message names both values, the minimum and the fix.
2. (a) The arithmetic is documented where both knobs are documented.
3. (b) The guard catches an ordinal named in a UFCS call — shown by a fixture
   in that form. The counter-assertion is no longer a lower bound, or the
   reason it must stay one is written down.
4. (c) After `Ok(false)` no handler runs — shown by a test that feeds exactly
   that return value. After `Err` it still runs, with its own test.
5. (c) The test comment no longer carries the false premise.
6. No test that is green today has to be rewritten; if one does, that is a
   finding to report, not an adjustment to make.

## Read first

- `crates/hort-adapters-postgres/src/jobs_repository.rs:178-250` — the claim
  SQL and the doc comment that already explains the per-band `LIMIT`.
- `crates/hort-worker/src/config.rs:200-245` — both knobs and the rejection
  style to follow.
- `crates/hort-app/tests/no_producer_names_an_ordinal.rs` — all of it; the
  module header states what the guard claims to enforce.
- `crates/hort-app/src/task_dispatcher.rs:680-700, 900-950, 1280-1330` — the
  dispatch site, the capacity-wait write, and the fence that is evaluated
  after `handler.run`.
- `docs/adr/0066-background-work-never-outranks-a-waiting-client.md` — D1, D5,
  D6 and the consequences.
