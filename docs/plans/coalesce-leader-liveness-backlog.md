# Coalesce leader liveness — backlog (issue #55)

Branch-local (D7). Two PR-sized items, strictly ordered: Item 1 is the guard + bounds (the fix); Item 2 is the metric/catalog surface. They could be one MR, but Item 1 is the security-relevant change and deserves its own review.

Design doc: `docs/plans/coalesce-leader-liveness.md`.

---

## Item 1 — Bound the leader, bound the Layer-A follower, make cleanup total

**Design doc section:** §3.1, §3.2, §3.3, §6
**Read first:** `crates/hort-app/src/pull_dedup.rs` (lines 680–1140 are the whole surface: `coalesce_inner` 680, `layer_b_election` 755, `run_as_leader` 886, `run_as_leader_layer_b_down` 994, `layer_b_follower_poll` 1039, `spawn_heartbeat` 1126), `crates/hort-server/src/cli/serve.rs:671` (config wiring)

**Acceptance:**
1. `PullDedupConfig` gains `leader_deadline: Duration`, default 600 s, wired from `HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS` in the composition root. The existing `defaults()` test at pull_dedup.rs:2412 is extended, not replaced.
2. `fetch_fn` is wrapped in `tokio::time::timeout(leader_deadline, …)` at **both** pull_dedup.rs:918 and pull_dedup.rs:1009. On elapse: `Failed{Timeout}` terminal written with the existing `ttl_timeout` TTL, `Err(AppError::External("pull-dedup: leader deadline exceeded"))` returned.
3. The Layer-A follower `rx.recv().await` at pull_dedup.rs:700 is bounded by `config.follower_wait`; on elapse it evicts the Layer-A entry and falls through to Layer B rather than returning immediately.
4. A `LeaderGuard` with a `Drop` impl replaces the manual cleanup: it unconditionally aborts the heartbeat and removes the Layer-A entry unless disarmed on the happy path. The existing `remove` at 974/1028 becomes a disarm; **entry removal must still happen after the broadcast send at 971** so current follower ordering is preserved.
5. Tests 1–5 from design §6 all present and passing. In particular: a `std::future::pending()` leader must not hang a follower, and a subsequent call after leader timeout must run a **fresh closure** (assert the closure ran twice).
6. Tracing per design §5. **Never log the URL** — this module logs only the 8-hex `key_hash` (see pull_dedup.rs:109, 297–307); preserve that.

**Watch for:**
- `JoinHandle` does **not** abort on drop — the guard must hold an `AbortHandle` (or abort explicitly in `Drop`). This is the pre-existing cancelled-leader leak, not just a wedge fix.
- `InMemoryEphemeralStore` (pull_dedup.rs:1297) is **wall-clock**, so `start_paused = true` will not expire its entries (see the comment at 2454–2457). Use short real durations via a `fast_cfg()`-style config (1854–1864). `capture()` (1453) is not paused-clock either — metric assertions and virtual time cannot be combined with the current helpers.
- Do not touch `ttl_timeout`'s meaning. It is a negative-cache TTL consumed at 935/1024, **not** an execution bound. Conflating the two is the misreading this whole issue came from.

### Starter prompt

/hort-architect

Implement Item 1 of `docs/plans/coalesce-leader-liveness-backlog.md` (issue #55) on branch `agent/55-coalesce-leader-liveness`. Read `docs/plans/coalesce-leader-liveness.md` §2, §3.1–§3.3 and §6 first, then `crates/hort-app/src/pull_dedup.rs` lines 680–1140.

A wedged pull-through coalesce leader currently hangs every follower on the replica forever, with no self-heal until the process restarts — it was the root cause of #53. There are four distinct defects (design §2); fix all four or the poisoning survives. Work TDD: the design's §6 test list describes failures that no current test produces, so write those first and watch them hang/fail before implementing.

Acceptance is the numbered list in the backlog item. Gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`, `cargo deny check`.

---

## Item 2 — `leader_timeout` / `leader_cancelled` metrics + catalog parity

**Design doc section:** §3.4, §5
**Read first:** `crates/hort-app/src/metrics.rs` (`DedupOutcomeLabel` 1458, `as_metric_label` conventions 1507, uniqueness test 5454, wire-string assertions 5484–5518), `docs/metrics-catalog.md`, `crates/hort-app/src/pull_dedup.rs` `emit_total` 1246 / `emit_wait` 1258

**Acceptance:**
1. `DedupOutcomeLabel` gains `LeaderTimeout` → `"leader_timeout"` and `LeaderCancelled` → `"leader_cancelled"`. The closed-taxonomy tests at metrics.rs:5454 and 5484–5518 are extended.
2. Both are emitted from the Item 1 code paths: `leader_timeout` on deadline elapse, `leader_cancelled` from the guard when it runs without a terminal outcome.
3. `docs/metrics-catalog.md` carries both, with exact string parity (the convention comment at metrics.rs:1507 requires it).
4. The catalog entry for `leader_timeout` states explicitly that `hort_pull_dedup_wait_seconds` does **not** cover the wedge case — `emit_wait` at pull_dedup.rs:920 fires only after `fetch_fn` returns, so a wedged leader emits no wait sample at all. This counter is the only signal. Without that note someone will later "fix" the histogram on the assumption it already covers this.

### Starter prompt

/hort-architect

Implement Item 2 of `docs/plans/coalesce-leader-liveness-backlog.md` (issue #55) on branch `agent/55-coalesce-leader-liveness`, on top of Item 1. Read design doc §3.4 and §5, then `crates/hort-app/src/metrics.rs` around `DedupOutcomeLabel` (1458).

Add the two new dedup outcome labels, emit them from the Item 1 timeout and guard paths, and update `docs/metrics-catalog.md` with exact string parity. The label taxonomy is closed and has uniqueness + wire-string tests — extend them.

Acceptance is the numbered list in the backlog item. Same gate as Item 1.
