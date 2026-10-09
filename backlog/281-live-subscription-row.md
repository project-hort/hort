# 281 — A running delivery task reads the live subscription row

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0061 (notification delivery is driven by the
event store from a persisted cursor — this item does not touch that, and the
accepted late-commit/duplicate semantics stay as they are) · ADR 0021 (the
per-resource visibility filter is the only authorization gate on this path) ·
ADR 0016 (no new configuration knob as the close).

## What is true today

`PATCH /api/v1/subscriptions/:id` persists a new target and filter through
`SubscriptionUseCase::update`, and the Postgres adapter writes the row and
emits `subscription_changes` in the same transaction
(`crates/hort-adapters-postgres/src/subscription_repo.rs`). The dispatcher
does reconcile on that notification and every 30 seconds.

What it reconciles is no longer "nothing": the pass now walks **every** active
subscription and publishes a freshly synthesised owner principal into the
`ArcSwap` a running task holds (`dispatcher.rs`, `TaskHandle::owner_principal`
— the mechanism is in the tree and is this item's template). The *row* is
still only read at spawn:

    pub async fn run(subscription: Subscription, deps: SubscriptionTaskDeps, …)

`subscription` is an owned value, and every consumer inside the task reads it:
`subscribes_to(&subscription, event)` decides category and event-type
matching, and the send path resolves `subscription.target`. Nothing replaces
it for the lifetime of the task.

So a PATCH is acknowledged, the new row is visible through the API, and
delivery keeps following the old one:

- A user rotating away from a **compromised webhook URL** keeps delivering
  full events to the old receiver until the process restarts.
- A **narrowed** filter keeps delivering the categories and event types it
  removed.

The existing reconcile test asserts only that the ID is still present and
names leaving a running task untouched as intended — that test encodes the
skip that causes this, and it has to be reworked with the behaviour.

## Why this is the shape of the fix

It is the same defect as the owner principal, one field over, and it gets the
same answer: an input to a per-event decision may not be older than the
cadence the rest of that decision runs on. The reconcile pass already holds a
fresh `Subscription` for every active ID — it listed them — so publishing the
mutable part of that row costs nothing beyond the write.

**Take only the delivery-shaping fields from the live row.** This is the one
trap in the item: the task owns its own progress. `last_delivered_position`
on a republished row is whatever the last debounced write happened to persist,
which is behind the task's in-memory position by up to `PROGRESS_DEBOUNCE`.
A task that re-read its cursor from the published row would **re-deliver** the
window in between on every tick. The published value must therefore be the
delivery-shaping state (`target`, `filter`, and `snapshot_claims` if the
principal path does not already cover it), never the cursor, the state column,
or the failure budget.

## What to do

1. **Publish the live row into the task.** Mirror `owner_principal`: the
   `TaskHandle` keeps the handle, the reconcile pass writes the freshly listed
   row into it on every pass (not only on change — the unconditional write is
   cheaper than a comparison and has the same effect), and the task loads it
   where it already loads the principal and the evaluator, so one event is
   decided against one consistent snapshot.
2. **Scope what travels.** Define the published value so the cursor cannot
   ride along — a narrow struct of the delivery-shaping fields is preferable
   to publishing the whole `Subscription` and remembering not to read two of
   its fields. Say in the report which shape you chose and why.
3. **Resolve the target per event from the published value**, so the first
   delivery after a PATCH uses the new target. The notifier registry walk
   (`supports(target)`) stays as it is; a target that no adapter supports
   keeps its current degraded-state behaviour.
4. **Do not re-validate the target in the task.** The create/update path
   validates a webhook target (including the DNS guard) before it is
   persisted, so a row that reached the database was admitted. Adding a second
   validation inside the delivery walk would put network work on the hot path
   and is not this item's subject.
5. **Rework the reconcile test.** The assertion that an existing task is left
   untouched is now wrong in the half that matters. Keep what is still true
   (the task is not cancelled and not respawned) and assert the new property
   beside it.
6. **State the retroactivity semantic, and write it down once.** A filter
   PATCH applies from the cursor forward; a *widened* filter does not
   retroactively deliver events the task already passed under the narrow one.
   That is inherent to a cursor-driven walk (ADR 0061) and is not changed
   here, but it is operator-visible, so
   `docs/architecture/explanation/event-notifications.md` gets one sentence
   saying it. Flag it in the report as a documented semantic, not a fix.

## Explicitly out of scope

- The cursor, the failure budget, the progress debouncer, catch-up paging.
- The accepted late-commit gap and duplicate semantics of ADR 0061.
- Any new configuration (the reconcile interval is the existing contract).
- `state` transitions (pause/disable). The reconcile already cancels a task
  whose row left the active set; that path is unchanged.

## Behaviour changes to surface in the report

- A PATCHed target takes effect for the next delivered event, within one
  reconcile interval, with no restart.
- A PATCHed filter likewise — including the narrowing direction, which is the
  security-relevant one.

## Acceptance

- A test patches the target of an **active** subscription, runs one reconcile
  tick, and proves the next delivery goes to the new target — with the task
  neither cancelled nor respawned. A test that reaches the outcome by
  restarting the task proves nothing about this item.
- A test narrows the filter of an active subscription and proves a
  now-excluded event is no longer delivered, same conditions.
- A test proves the task's position does **not** regress across a republish:
  deliver, let the debouncer hold the write back, republish, and assert no
  re-delivery of the already-delivered event.
- No comment claims the row is fixed for the task's lifetime.
- The diff adds no uncovered lines: for every line the diff adds in
  `hort-app`, `cargo llvm-cov --lib -p hort-app --show-missing-lines` does not
  list it. (CLAUDE.md's 100 % claim for this crate does not match the measured
  tree, so the checkable criterion is the diff, not the total.)
- Gate green, one-shot capture, exit codes separate from the output:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace`, `cargo-audit audit -D warnings`,
  `cargo-deny check`.
