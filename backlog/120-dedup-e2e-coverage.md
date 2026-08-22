# 120 — Deterministic pull-dedup E2E coverage, un-quarantined

Issue: #164. Shape confirmed by the maintainer. E2E harness work — the
sandbox cannot run compose, so the operator's full-suite run is the
acceptance evidence; **no MR until that run is green**.

## Why

`scripts/native-tests/scenarios/proxy/pull-dedup.sh` is quarantined —
excluded from pass/fail — and its "tracked separately" note tracked
nothing. Coalescing therefore has no enforced end-to-end coverage, which
is the machinery that produced both halves of #161. The quarantine has no
expiry, so it must not remain the resting state.

## Why the current assertions cannot pass

They expect ten concurrent `npm install`s to yield ≥9
`follower_waited_hit` per key. npm serialises installs, so that
concurrency never materialises and `upstream_fetch{npm}` lands on
different counts than the ported expectation. The assertions are not too
strict — they are betting on a client behaviour that does not exist.

## Deliverable 1 — deterministic coalescing assertions

Reformulate around the **Layer-B** property, which needs no concurrency:
the leader's terminal success record persists for `leader_lock_ttl`
(default 90 s, `PullDedupConfig::defaults`, not overridden in
`deploy/compose/docker-compose.yml`), so any caller arriving inside that
window takes the fast path and counts as `follower_waited_hit`.

- Drive requests **sequentially within the TTL** and assert
  `follower_waited_hit ≥ 1` together with exactly one `upstream_fetch`
  for that key.
- Read the TTL from configuration rather than hard-coding 90 s, or assert
  well inside it with a stated margin — a config change must not silently
  turn this scenario red.
- The header's "do not relax them" instruction is honoured by making the
  assertions **deterministic, not weaker**: the rewrite must still fail
  if coalescing stops happening. State in the report how you verified
  that (e.g. by reasoning about what a no-coalescing build would produce
  for each counter).
- If the Layer-A concurrency path is still worth exercising, keep it as a
  separate, explicitly best-effort probe that cannot fail the suite —
  never as the gating assertion.

## Deliverable 2 — the cross-repository follower case

The scenario does not exercise the leg that produced #161 at all. Add it:
the same content pulled through **two repositories**, the second arriving
as a follower, asserting that the follower's row is **structurally
complete** —

- its `content_references` membership edges exist (the fix in
  `2912a7f9`), and
- its quarantine anchor matches what the leader's row received (the
  carve-out parity fix).

Both are regression pins for defects that reached a release gate; assert
them on the follower's own row, in its own repository.

## Deliverable 3 — un-quarantine

Remove the scenario's quarantine marker so it gates again. If any part
must stay non-gating, say exactly which and why in the report — a
silently still-quarantined scenario is the state this item exists to end.

## Constraints

- Comment provenance rule applies to shell too: state the invariant, not
  the tracker history.
- Do not weaken any assertion that currently holds.

## Acceptance

- Full compose suite green with `proxy/pull-dedup` **counted**, run by
  the operator on the branch.
- The scenario's own output shows the follower path was actually taken
  (the counters, not just an overall pass).
