# 313 — The dedup reports only what it compared

**Issue:** #346 · **Branch:** `agent/346-pullthrough-weaker-than-its-proof`
**Governing decisions:** **ADR 0006** (every pull-through fetch verifies a
checksum — there is no operator opt-out), ADR 0003 (the CAS key is SHA-256).

**Independent of items 311 and 312.** Lowest severity of the block, and the
one whose correct shape needs a measurement before it is written.

## What is true today

The hosted/pull ingest path takes two early exits
(`crates/hort-app/src/use_cases/ingest_use_case.rs:3711` and `:3719`,
`ControlFlow::Break(early_ok) => return Ok(early_ok)`) **before** three
comparisons run (`:3723`–`:3730`):

```
verify_declared_sha256(...)      // :3723
verify_sha512_upstream(...)      // :3726
verify_sha1_upstream(...)        // :3729
```

The first exit comes from `find_existing_and_check_declared_dedup` (`:2500`),
which — as its name says — *does* check the declared SHA-256 inside itself. The
comparisons that are skipped are the **upstream-published** SHA-512 and SHA-1:
exactly the ones Maven and npm rely on, and exactly the ones a caller declared
in this request.

So a same-path dedup hit returns a success that reports a verification it did
not perform for *this* request. The bytes in CAS were verified when they were
first ingested — against **that** upstream's declared digest. A second caller
declaring a different algorithm, or a different value, has had nothing
compared.

## What to do

**Measure first, then choose — and say which you chose and why.** Both shapes
are defensible and the measurement decides:

1. **Run the comparisons on the dedup path.** Honest and closes the gap
   completely. Cost: `verify_sha512_upstream` / `verify_sha1_upstream` hash the
   bytes, so a dedup hit stops being free — it becomes a full CAS read. Measure
   what that costs on the path that exists to avoid exactly that read.
2. **Take the early exit only when there is nothing left to compare** — i.e.
   when the request declares no upstream digest the existing row has not
   already been verified against. A request that does declare one falls through
   to the normal path and pays the read it needs. Dedup stays free where it is
   sound.

**What is not an option:** returning a result that says verified when nothing
was compared. ADR 0006 has no operator opt-out and no "already verified once,
by someone else" clause — and this is a *serving* decision, so a wrong answer
here is a wrong answer about bytes.

Whichever shape wins, the comparison's absence must be **impossible to reach
silently**: either it ran, or the path did not claim it.

## Explicitly out of scope

- The declared-SHA-256 check inside `find_existing_and_check_declared_dedup` —
  it already happens; do not duplicate it.
- The post-put dedup exit's other purpose (`put_and_check_post_dedup`, `:3719`)
  beyond this one question.
- Any change to what a *successful* verification reports.
- Performance work beyond measuring the option you did not take.

## Acceptance

- A second ingest on the same path declaring an upstream SHA-512 that **does
  not** match the stored bytes is refused. This is the test that fails today.
- A second ingest declaring one that **does** match succeeds, and the report
  states whether it re-read the blob.
- A second ingest declaring **no** upstream digest keeps today's behaviour
  (dedup stays free) — asserted, so the fix cannot quietly tax every dedup.
- The report names the chosen shape, the measured cost of the comparison on a
  dedup hit, and why the other shape was not taken.
- **Non-vacuity: revert the guard, show the first test red, restore it.**
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-app` — judge by the output, not the rc,
  and quote the totals. Do **not** run `cargo test --workspace`, `cargo audit`,
  `cargo deny` or the attribution script; the architect runs the full gate
  before any MR.
