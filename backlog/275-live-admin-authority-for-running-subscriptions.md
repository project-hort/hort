# 275 — A running subscription's admin authority follows the owner's live state

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0021 (the per-resource visibility filter is the
*only* authorization gate on a read path, and is therefore load-bearing — the
ADR names this very notification path as the case that proved it) · ADR 0012
(the additive-claims evaluator; the `"admin"` claim is synthesised from the
live `User.is_admin` bit, never trusted from a snapshot) · ADR 0061
(notification delivery is driven by the event store).

**The decision is answered.** The human, 2026-10-07: *"Bei 17-3 folge ich
deinem Vorschlag."* The live state wins; the code is corrected and the
documentation stays as it is, because the documentation has promised the right
thing all along.

## What is true today

`DispatcherCore::synthesise_principal`
(`crates/hort-app/src/dispatcher/dispatcher.rs:332`) loads the owner's `User`
row, strips any stale `"admin"` from `subscription.snapshot_claims`, and
re-adds it iff `user.is_admin` is currently true. That part is correct and
stays.

The problem is **when** it runs. The reconcile loop calls it only for a
subscription that has no task yet; for one that already has a task it skips
past (`if tasks.contains_key(&sub.id) { continue; }`). The resulting
`CallerPrincipal` is moved into `SubscriptionTaskDeps::owner_principal`
(`subscription_task.rs:283`) as a plain owned value and the per-event filter
walk reuses it for the lifetime of the task.

So on every delivered event, `process_event_for_subscription`
(`subscription_task.rs:635-651`) hands
`crate::use_cases::subscription_filter::matches` two inputs of different ages:

| Input | Freshness |
|---|---|
| `rbac: Arc<ArcSwap<RbacEvaluator>>` | reloaded per event (`deps.rbac.load()`), swapped by the refresh task every `HORT_RBAC_REFRESH_SECS` (default 30) |
| `owner_principal` | **resolved once, at task spawn** |

`subscription_filter.rs:174` authorizes `Permission::Admin` for a
privileged-category event by calling `authorize(ctx.owner_principal, …)` — so
the frozen input is the one that decides it. Revoking `User.is_admin` does not
stop a running subscription from delivering privileged-category events, and no
reconcile tick repairs it; only a cancel-and-respawn does.

Revoked *grants* do take effect, because they travel in the evaluator. The
single stale input is the `is_admin` bit.

`docs/architecture/explanation/event-notifications.md:166-172` states the
opposite as a property of the system:

> **At delivery**, the filter walk … re-checks `Permission::Admin` for
> privileged-category events against the owner's **live state**, and intersects
> every repository-scoped event with the owner's *current* `Read` grants.

Two source comments call the gap a "bounded accepted residual"
(`dispatcher.rs:33`, `subscription_task.rs:282`).

## Why this is the shape of the fix

The two inputs to one authorization decision must age at the same rate. They
do not today, and the one that is allowed to go stale is the one carrying
admin authority.

Note what "live" already means everywhere else in this system: the
`RbacEvaluator` itself is refreshed by a polling task every
`HORT_RBAC_REFRESH_SECS` (`crates/hort-server/src/cli/rbac_refresh.rs`,
default 30 s, one `list_all` for the whole fleet). Grant revocation is
therefore *already* bounded by one refresh interval rather than instantaneous.
So the target is not a per-event database read for the admin bit — it is the
**same cadence as the grant snapshot**, reached by the same mechanism: publish
the refreshed principal through an `ArcSwap` the task loads per event, exactly
beside the evaluator it is handed to. One freshness contract, not two.

A per-event `find_by_id` would be the other way to satisfy the wording, and it
is worse: it adds database I/O to the delivery hot path to buy precision that
the grant half of the very same decision does not have.

## What to do

1. **Make the principal swappable.** `SubscriptionTaskDeps::owner_principal`
   becomes a handle the task can re-read per event (the `rbac` field beside it
   is the shape to mirror). `process_event_for_subscription` loads it where it
   already loads the evaluator, so the two snapshots are taken together.
2. **Re-synthesise on the reconcile tick.** The reconcile stops skipping a
   subscription that already has a task: it re-runs the principal resolution
   and publishes the result. `synthesise_principal` returning `None` for a
   deactivated owner must now **tear the task down**, which is the same
   disposition the reconcile already applies to a disabled row.
3. **Mind the read cost, and say what you chose.** Re-resolving per tick means
   one owner read per active subscription per interval, where the loop
   previously did one read per *new* subscription. Prefer a batched read if
   `UserRepository` already offers one; a point read per active subscription is
   acceptable at the scale this loop already assumes. Whatever you pick, state
   the cost in the report — do not add a new tuning knob for it (ADR 0016: no
   new configuration as the close).
4. **Correct the two comments.** The "accepted residual" wording in
   `dispatcher.rs:33` and `subscription_task.rs:282` no longer describes the
   code. Replace it with what now holds, including the bound: the principal is
   refreshed on the reconcile cadence, which is the same bound the grant
   snapshot has. State the durable property, not the history of the change,
   and name no issue or backlog item (CLAUDE.md → *Code comments*).
5. **Leave the documentation alone.** `event-notifications.md` already states
   the intended property. Changing it was the alternative the human rejected.

## Explicitly out of scope

- The `snapshot_claims` authority floor and its resolution at create/update
  time. Correct as it stands, and unchanged.
- Making grant revocation instantaneous, or anything else about
  `HORT_RBAC_REFRESH_SECS`. The refresh cadence is the existing contract; this
  item adopts it, it does not revise it.
- The dispatcher's failure budget, progress debouncing, and catch-up cursor.
- `DispatcherPrincipalSource` and its counter, beyond keeping them accurate if
  a re-resolution now emits one.

## Behaviour changes to surface in the report

Both are the intent, not side effects — name them so they reach the human:

- Revoking `User.is_admin` now stops a running subscription from delivering
  privileged-category events within one reconcile interval, where it
  previously required a cancel-and-respawn.
- Deactivating an owner (`is_active = false`) now tears down that owner's
  already-running subscription tasks at the next tick, where it previously
  only prevented new spawns.

## Acceptance

- A test proves a privileged-category event stops being delivered after the
  owner's `is_admin` is revoked **and one reconcile tick has run**, with the
  task never cancelled or respawned. A test that reaches the outcome by
  restarting the task proves nothing about this item.
- A test proves a deactivated owner's running task is torn down by the
  reconcile.
- No comment anywhere still claims the principal is frozen for the task's
  lifetime or that the staleness is accepted.
- `hort-app` coverage stays at 100 % (CLAUDE.md → *Test Coverage Tiers*): every
  new branch, including the `None`-from-re-synthesis teardown path and the
  unchanged-principal path, has a test.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
