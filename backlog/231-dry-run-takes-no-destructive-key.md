# 231 — A dry run must not take the destructive single-flight key

**Issue:** #291 · **Branch:** `agent/291-dry-run-no-destructive-key`
**Found by:** #289, at the behaviour, not by reading.
**Governing decisions:** ADR 0028 (the per-UTC-day key and what it is for) ·
#283 (introduced the mode) · #289 (the surface whose safety this restores).

## Why

`retention-evaluate` is in `DESTRUCTIVE_TASK_KINDS`, and the invoke handler
derives the durable per-UTC-day key for **every** invocation of a destructive
kind (`crates/hort-http-admin-tasks/src/handlers/invoke.rs:229-244`) — keyed off
the kind, with the mode as an extra segment:

```rust
if hort_domain::events::task_kind_is_destructive(P::KIND) {
    let derived = if P::KIND == "retention-evaluate" {
        format!("cron:{}:{mode}:{utc_today}", P::KIND)
    } else { … };
    Some(IdempotencyKey::try_from(derived)?)
}
```

So a **dry run** gets a key too. A second dry run on the same UTC day is
`EnqueueOutcome::Duplicate`, and the handler answers `200 OK` with the existing
job instead of `202 Accepted` with a new one.

### What that does to the cleanup

1. The operator runs `preview` → job A, a real sweep.
2. They read it, then run `apply --from-preview A`.
3. `apply`'s "fresh preview immediately before executing" is deduplicated back
   to **job A**. The delta is A against A: always empty.
4. The execute step *is* fresh — its own key, first execute of the day — so it
   evaluates the world as it is now and expires what it finds.

The operator sees a stale proposal, reads "nothing changed", and then expires a
set computed from different data. That is exactly the failure #289 exists to
prevent, and it happens on every day the intended workflow is followed, because
previewing first is what guarantees the dedup.

#289's CLI detects it exactly — 202 versus 200 from the server, not a clock
comparison — and says so in the header, the delta section, the JSON and the
confirmation question. That is an honest mitigation, not the fix.

## The fix

**A dry run is not destructive and must not take the destructive single-flight
key.** ADR 0028 introduced that key so a controller restart could not re-fire a
**destructive** sweep. Running an observation twice is harmless; *preventing* it
makes "look again" impossible, which is the one thing a preview has to support.

The decision already exists, one function away:
`TaskUseCase::requires_destructive_claim(kind, params)`
(`crates/hort-app/src/use_cases/task_use_case.rs:184-199`) answers precisely
"is **this invocation** destructive?" — it is what gates the claim. The key
derivation asks a different question (`task_kind_is_destructive(P::KIND)`,
"is this **kind** ever destructive?") and gets a different answer. One of the
two is wrong for the key, and it is the one the key uses.

With the fix, the mode segment in the preview's key becomes moot — a dry run
has no key, so it can collide with nothing. Keep the mode in the **execute**
key: it costs nothing, it documents the dimension, and it means a second kind
gaining a mode does not silently reintroduce a collision.

## Read first

- `crates/hort-http-admin-tasks/src/handlers/invoke.rs:120-250` — the
  authorization pre-check and the key derivation, the two places that now
  disagree.
- `crates/hort-app/src/use_cases/task_use_case.rs:100-200` — `authorize_kind`
  and `requires_destructive_claim`.
- `crates/hort-domain/src/retention/mode.rs` — `is_destructive()`.
- `docs/adr/0028-destructive-task-idempotency.md` — the decision and its
  rationale, which this change keeps and describes more accurately.
- `crates/hort-http-admin-tasks/tests/destructive_kinds_carry_db_idempotency.rs`
  — the closed-set guard that must be updated rather than worked around.

## Scope

1. **One decision, two consumers.** The same function that decides whether an
   invocation needs the destructive claim decides whether it takes the durable
   key. Do not add a second string-literal branch beside the first — that
   duplication is how the two answers diverged. If you prefer to push it into
   the typed params (`TaskParams::is_destructive_invocation()`), that is the
   shape #283's report already suggested; argue whichever you choose.
2. **Keep the mode in the execute key.**
3. **Update the closed-set guard** so it expects the per-kind shapes as they now
   are, including "a dry run derives no key". A guard that is edited into
   agreement without stating the new rule is worse than none.
4. **ADR 0028 follows the code.** It says the key is derived for every
   destructive *kind*; it becomes every destructive *invocation*. Descriptive
   only — the normative decision (server-derived per-day key, DB-enforced,
   ephemeral fast-path as an extra layer) is untouched.
5. **Leave #289's dedup messaging in place.** It becomes rare, not wrong: a
   second execute in one day is still deduplicated, by design, and then the CLI
   saying so is exactly right.

## Acceptance

- Two `preview` runs in the same UTC day are two distinct jobs and both answer
  `202`.
- `apply --from-preview <A>` compares a fresh sweep against A, never A against
  itself. A test walks that exact sequence.
- A preview and an execution in the same UTC day remain distinct jobs — the
  property #283 established must not regress.
- A second execution in the same UTC day is still deduplicated and still returns
  the earlier job.
- The claim gate and the key derivation cannot disagree: a test that changes the
  mode observes both answers move together.
- ADR 0028 describes the behaviour the code has.
- Gate green; no issue, MR or backlog numbers in code comments.

## Explicitly not in this item

No change to authorization behaviour itself, to the ephemeral `idem-task:`
layer, to the CLI, or to what the dry run computes. No change to the other
destructive kinds' keys.
