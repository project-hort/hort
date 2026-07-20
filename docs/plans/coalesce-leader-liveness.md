# Coalesce leader liveness — design (issue #55)

Branch-local planning doc (D7). Distil durable decisions into an ADR before merge; delete this file.

## §1 — Deferred-items sweep (architect Step 0, mandatory)

Run 2026-07-20 against `develop` @ `a3dff74c`.

- `docs/plans/*.md` — **no hits**: `docs/plans/` does not exist on `develop` (D7 working as intended; #46's plans were distilled into ADR 0007/0043 amendments and deleted by `a1fe134c`).
- `docs/adr/0000-historical-decisions-index.md` open-items register — 20 OPEN rows reviewed. **No row concerns pull-dedup, coalescing, or leader liveness.** Three OCI-index rows exist (child-status rollup, promotion cascade, Maven Phase-2 prefetch) but none touch this initiative. **Decision: no inherited deferred work to absorb.**
- Issue #53's own deferrals — the `HORT_STORAGE_PUT_TIMEOUT_SECS` mitigation (`7f556535`) and the phase diagnostics (`939e7bfe`) both shipped in v0.9.11. #53 named this issue as the durable fix. **Decision: include now** — this initiative is that follow-on.

### Inherited-rationale re-validation (Step 0.5)

One reused rationale, and it does **not** survive contact with #55:

> **Reused claim (pull_dedup.rs module doc + `PullDedupConfig::follower_wait`, default 300 s):** "follower waits are bounded, so a bad leader degrades to a 503 rather than a hang."

**Verdict: REVERSED HERE — the claim is true of Layer B only.** `layer_b_follower_poll` (pull_dedup.rs:1039) enforces `follower_wait` at line 1044. But the Layer-A in-process follower path at **pull_dedup.rs:700** is a bare `rx.recv().await` with no ceiling, no `select!`, and no deadline. A follower that reaches Layer A never reaches the bounded Layer-B loop. The bound was designed and tested against a *ghost* leader (a pre-seeded `InFlight` record with no in-process entry — see the test at pull_dedup.rs:2031), which is precisely the case that *does* reach Layer B. The live-but-wedged local leader was never modelled. Recorded here so a future sweep finds the decision, not silence.

## §2 — Root cause (verified against source, not the issue text)

The issue frames this as "no leader-liveness bound." That is right but incomplete. There are **four** independent defects, and fixing only the obvious one leaves the poisoning intact.

**D1 — Layer-A follower wait is unbounded.** `pull_dedup.rs:700`, `match rx.recv().await`. This is the actual hang. Every caller on the wedged replica takes the branch at 692 → 693 (`Weak::upgrade` succeeds, because the leader task is alive-but-stuck, so the `Arc<Sender>` is still held) → 700, and blocks forever.

**D2 — no bound on the leader's closure.** The caller-supplied future is driven at exactly two sites: `run_as_leader` **pull_dedup.rs:918** and `run_as_leader_layer_b_down` **pull_dedup.rs:1009**. Neither is wrapped. `grep` confirms **zero** occurrences of `tokio::time::timeout` in the whole 2536-line file. `ttl_timeout` (line 128, default 10 s) is a **negative-cache TTL for an already-returned error**, not an execution bound — it is consumed only at lines 935/1024 on the `Err` arm, feeding `expires_at_unix_secs`. Do not mistake it for a leader deadline.

**D3 — the heartbeat is immortal on a wedge, so Layer B cannot self-heal either.** `spawn_heartbeat` (pull_dedup.rs:1126) is an unconditional `loop { ticker.tick().await; extend_ttl(LEADER_LOCK_TTL) }` with no deadline and no liveness check. It is spawned at line 915 and aborted at line **923 — after** the `fetch_fn().await` at 918. A wedged leader never reaches 923, so the detached task re-extends the 90 s cluster lock every 30 s in perpetuity. The designed cluster-side self-heal (lock TTL expiry → `Ok(None)` → `lock_expired_re_elected`) therefore **never fires**. This is why a pod restart is the only recovery: it is the only thing that kills the heartbeat task.

**D4 — cleanup is not exit-path-total.** `self.layer_a.remove(key)` appears only at lines **974** and **1028**, both on the sequential path after the awaits. There is **no `Drop` impl anywhere in the file**. The `Weak` value type (line 531) covers *drop and panic* — the `Arc<Sender>` dies, `upgrade()` returns `None`, the follower falls through to Layer B. It does **nothing** for a wedged-but-alive future. Separately, a *cancelled* leader (client disconnect, runtime shutdown) skips the `heartbeat_handle.abort()` at 923 — `JoinHandle` does not abort on drop — leaking an immortal heartbeat that pins the cluster lock with no leader at all.

**Why isolated tests passed.** #53's reproduction fetched the 76 MB blob standalone (1.57 s) and wrote it to Garage standalone (both v1.0.1 and v2.2.0) — neither exercises the coalesce window. The wedge lives in the composition.

## §3 — The fix

Four changes, one per defect. All in `crates/hort-app/src/pull_dedup.rs`.

### §3.1 — Bound the leader (D2)

New `PullDedugConfig` field:

```rust
/// Hard ceiling on the leader's `fetch_fn` execution. On elapse the leader is
/// abandoned, the Layer-A entry evicted and a `Failed{Timeout}` terminal written,
/// so the next caller elects fresh. MUST exceed the slowest legitimate
/// fetch+ingest, which is itself bounded by `HORT_STORAGE_PUT_TIMEOUT_SECS`.
pub leader_deadline: Duration,
```

Default **600 s**, env `HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS`.

**Why 600 and not something tighter.** The leader closure's slowest leg is `ingest_verified`, whose storage `put` is bounded at `HORT_STORAGE_PUT_TIMEOUT_SECS` (default **300 s**, shipped in v0.9.11 via `7f556535`). The tag-pull closure (manifests.rs:1051) additionally does a digest parse, a `ref_use_case.set`, a full `tokio::fs::read`, and `register_membership_edges_from_pull` — which issues **one DB round-trip per referenced child/blob, serially** (manifests_write.rs:1414–1450). A deadline at or below 300 s would abandon leaders that are legitimately still working on a large multi-arch pull. 600 s = 2× the storage bound leaves headroom for the surrounding legs while converting "poisoned until restart" into "self-heals within 10 minutes."

Apply at **both** 918 and 1009. Wrapping only 918 leaves the Layer-B-down path unbounded — and that path also inserts into Layer A (line 1006), so it poisons identically.

On elapse: emit `DedupOutcomeLabel::LeaderTimeout` (new), write the `Failed{Timeout}` terminal record with the existing `ttl_timeout` negative-cache TTL, and return `AppError::External("pull-dedup: leader deadline exceeded")`.

### §3.2 — Bound the Layer-A follower (D1)

```rust
match tokio::time::timeout(self.config.follower_wait, rx.recv()).await {
    Ok(Ok(outcome)) => { /* existing line 701 path */ }
    Ok(Err(RecvError::Closed))  => { /* existing fall-through to Layer B */ }
    Ok(Err(RecvError::Lagged(n))) => { /* existing fall-through */ }
    Err(_elapsed) => {
        // Leader alive but wedged past our patience. Evict the poisoned entry so
        // the NEXT caller elects fresh, emit the metric, and fall through to Layer B.
        self.layer_a.remove(&key);
        emit_total(DedupLayer::InProcess, key.format_label(), DedupOutcomeLabel::FollowerFellthrough503);
        // fall through
    }
}
```

Reuse `follower_wait` (already 300 s) rather than adding a knob — it is the same question Layer B already answers, and answering it differently per layer is how this bug hid. Note `follower_wait` (300 s) < `leader_deadline` (600 s) is deliberate: followers give up and retry-or-503 well before the leader is abandoned, so a slow-but-healthy leader still gets to finish and serve later callers from the terminal record.

### §3.3 — Kill the immortal heartbeat (D3) and make cleanup total (D4)

Introduce an RAII guard constructed immediately after the Layer-A insert (lines 912 / 1006):

```rust
struct LeaderGuard {
    layer_a: Arc<LayerAMap>,
    key: DedupKey,
    heartbeat: tokio::task::AbortHandle,
    disarmed: bool,
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        self.heartbeat.abort();              // unconditional — the immortal-task fix
        if !self.disarmed {
            self.layer_a.remove(&self.key);  // only if the happy path did not already
        }
    }
}
```

This closes **every** exit path at once — success, error, timeout, panic, cancellation. The existing manual `remove` at 974/1028 becomes `guard.disarm()` on the happy path (the entry is removed *after* the broadcast send at 971, preserving current ordering); the guard handles the rest. Critically, `heartbeat.abort()` in `Drop` fixes the pre-existing cancelled-leader leak that has nothing to do with a wedge.

### §3.4 — Metrics

Two new `DedupOutcomeLabel` variants in `crates/hort-app/src/metrics.rs` (closed taxonomy, line 1458; uniqueness test at 5454; wire strings asserted at 5484–5518):

- `leader_timeout` — leader abandoned at `leader_deadline`. **This is the alertable signal for a recurrence of #53.**
- `leader_cancelled` — guard ran without a terminal outcome (client disconnect / shutdown). Distinguishes "we gave up" from "the caller went away."

Both must be added to `docs/metrics-catalog.md` in the same change — the naming convention comment at metrics.rs:1507 requires exact parity.

**Also fix a pre-existing observability gap while here:** `emit_wait` at line 920 fires only *after* `fetch_fn` returns, so a wedged leader emits **no** wait sample at all — the histogram cannot surface the very failure it should. The `leader_timeout` counter is what makes the wedge visible; note this explicitly in the catalog entry so nobody later "fixes" the histogram by assuming it covers this.

## §4 — Explicitly out of scope

- **Bounding follower count.** The issue floats it. `LAYER_A_CHANNEL_CAPACITY = 64` (line 93) already degrades gracefully: overflow → `RecvError::Lagged` → fall through to Layer B (lines 729–741). No change needed. Carried forward as: no further action, closed as no-longer-relevant.
- **Calling `EphemeralStore::delete` to unpin the cluster lock immediately on timeout.** The primitive exists (port method, used only by test doubles at 1393/1442) but the terminal `Failed` write at 959 already overwrites the lock, which is the established release mechanism. Adding a second release path is unnecessary surface. Carried forward to a future initiative only if the terminal write itself proves unreliable.
- **`prefetch_ingest.rs` bypasses `PullDedup` entirely** (it calls `fetch_artifact` at 485/932 and `ingest_verified` at 525/973 directly) **while its module doc at lines 40–47 claims it is wrapped.** A real doc/impl mismatch, but orthogonal to leader liveness and out of scope here. **Carried forward explicitly** — file as its own issue.

## §5 — Observability

- `info!` — leader abandoned at deadline (state-changing, operator-actionable): `key_hash`, `format`, `layer`, `elapsed_secs`, `leader_deadline_secs`. Never the URL (the module logs only the 8-hex `key_hash`, line 109 / 297–307 — preserve that).
- `warn!` — Layer-A follower hit its ceiling and evicted a live entry: this means a leader is wedged *right now*.
- `debug!` — guard-driven eviction on the cancellation path (routine; a client disconnecting is not an error).
- No new health check.

## §6 — Testing

The gap is stark: **no existing test has a leader that fails to complete.** Nothing inspects `dd.layer_a`; nothing asserts the heartbeat stops; the `Weak`-tombstone path (743–745) is unexercised.

Required new tests:

1. **Wedged leader → follower is bounded.** Leader closure = `std::future::pending()`. With a short `follower_wait`, a Layer-A follower must return `Err` within the bound, not hang.
2. **Wedged leader → self-heal.** After the leader deadline elapses, a *subsequent* call must run a **fresh** closure (assert the closure ran twice) rather than inheriting the wedge. This is the acceptance criterion from the issue.
3. **Layer-A entry eviction.** Assert `dd.layer_a` no longer contains the key after leader timeout — no test currently touches this map.
4. **Heartbeat is aborted on every exit path** — timeout, error, and cancellation. Assert `is_finished()`, mirroring the existing test at 2430.
5. **Cancelled leader leaks nothing.** Drop the leader future mid-flight; assert both the heartbeat is finished and the Layer-A entry is gone.

**Harness constraint — read before writing tests.** `InMemoryEphemeralStore` (1297–1408) uses **wall-clock `SystemTime`** for TTLs, so `#[tokio::test(start_paused = true)]` virtual time does *not* advance its expiry (already called out at 2454–2457). Tests 1–3 must therefore either use a genuinely short `follower_wait`/`leader_deadline` via a `fast_cfg()`-style config (see 1854–1864) or teach the double a clock injection. Prefer short real durations (tens of ms) — a clock abstraction is a larger change than this initiative warrants. Note that `capture()` (1453) builds its own current-thread runtime and is not paused-clock, so metric assertions and virtual time are mutually exclusive with the current helpers.

## §7 — Layering check

No architectural movement. `PullDedup` is an `hort-app` service consuming the existing `Arc<dyn EphemeralStore>`; it introduces **no outbound port**, **no domain event**, and **no `IngestUseCase` change** (module doc, lines 20–35). This initiative adds a timeout, a guard and two counters — all inside that existing envelope. Coalescing remains a performance optimisation, not a domain state transition; `ArtifactIngested` / `ChecksumVerified` / `ChecksumMismatch` continue to fire exactly once per coalesced burst from the leader's `ingest_verified`.

The new env knob is read in the composition root (`crates/hort-server/src/cli/serve.rs:671` builds `PullDedupConfig`), not in `hort-app` — consistent with every other knob.
