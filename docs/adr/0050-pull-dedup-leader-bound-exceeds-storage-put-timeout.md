# 0050 — The pull-dedup leader bound must exceed the storage put timeout

- **Status:** Accepted
- **Enforced by:** authoring-time discipline (this ADR + the doc comment on
  `PullDedupConfig::leader_deadline`), backed at runtime by the
  `hort_pull_dedup_total{outcome="leader_timeout"}` counter — a sustained
  non-zero rate against a healthy upstream is the symptom of the two knobs
  having drifted into a bad relationship. There is no compile-time or
  apply-time check: the two values live in different crates and are set by
  independent environment variables, which is precisely why the relationship
  needs recording.
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the release
  predicate the coalesce path must never influence); issue #53 (the
  openbao 2.6.0 layer that was unpullable for days); issue #55 (the wedged
  coalesce leader that was #53's root cause, fixed in `!168`).

## Context

Pull-through fetches are coalesced: the first request for a digest becomes the
**leader** and runs `fetch + ingest`; concurrent and retried requests become
**followers** that wait on its outcome rather than starting their own attempt
(`crates/hort-app/src/pull_dedup.rs`).

Before issue #55 nothing bounded the leader. A leader that wedged on a transient
condition never resolved its coalesce entry, so every subsequent request for that
digest joined the wedge, and its heartbeat re-extended the cluster lock in
perpetuity. A *transient* upstream or storage hiccup therefore became a
*permanent, deterministic-looking* hang: the digest stayed poisoned until the
process restarted. That is what made one openbao layer unpullable for days while
both an isolated upstream fetch and an isolated S3 write of the same bytes
succeeded — the fault lived in the composition, not in either half.

#55 introduced `HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS` (`PullDedupConfig::leader_deadline`,
default **600 s**) to bound the leader, alongside an RAII guard making cleanup
total across every exit path.

## Decision

**`HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS` must remain comfortably greater than
`HORT_STORAGE_PUT_TIMEOUT_SECS`.** The shipped defaults are 600 s and 300 s.

The leader's closure is `fetch + ingest_verified`, and `ingest_verified`'s
slowest leg is the storage `put` — itself bounded by
`HORT_STORAGE_PUT_TIMEOUT_SECS` (issue #53). The leader must be able to outlive
its own slowest legitimate operation, plus the surrounding work: digest
parsing, the reference write, the manifest re-read, and the per-referenced-blob
`content_references` inserts, which are issued serially.

Set the leader bound at or below the storage bound and the system abandons
leaders that are still working correctly — converting a slow-but-healthy large
pull into a failed one, and doing so *most* often for exactly the large
multi-arch images the coalescing exists to protect.

Two corollaries follow:

- **`follower_wait` (default 300 s) stays below the leader deadline.** Followers
  give up and retry — or surface a bounded failure — well before the leader is
  abandoned, so a slow-but-healthy leader still finishes and serves later
  callers from its terminal record.
- **Bounds fail fast and retry; they never fail open.** On elapse the entry is
  evicted and a `Failed{Timeout}` terminal is written under the existing
  negative-cache TTL, so the next request elects a fresh leader. A bound must
  never degrade into "proceed without the guarantee" — the coalesce path sits in
  front of ingest, and ingest is where [ADR 0007](0007-fail-closed-quarantine-release-predicate.md)'s
  fail-closed release authority is established.

## Consequences

- Tuning either knob is a **paired** decision. Raising
  `HORT_STORAGE_PUT_TIMEOUT_SECS` for a slow backend without raising the leader
  deadline reintroduces false abandonment; lowering the leader deadline to
  "recover faster" does the same. The relationship, not either value, is what
  matters.
- A wedged leader now self-heals within the leader deadline instead of requiring
  a process restart, at the cost of one bounded stall for the callers in that
  window.
- `leader_timeout` and `leader_cancelled` counters make both the wedge and the
  tuning error observable. Note `hort_pull_dedup_wait_seconds` does **not**
  cover the wedge: it records only after the leader's closure returns, so a
  wedged leader emits no wait sample at all.
- The relationship spans `hort-app` and `hort-adapters-storage` and is expressed
  through two independent environment variables, so no single module's comments
  can carry it. Hence this ADR.

## Alternatives considered

- **A code comment on `leader_deadline` naming `HORT_STORAGE_PUT_TIMEOUT_SECS`.**
  Kept — but not *instead* of this. An operator tuning a slow S3 backend is
  reading storage configuration, not `hort-app` source, and would never see it.
- **Deriving the leader deadline from the storage timeout** (e.g. `2 ×`). Rejected:
  it couples an inbound-side service to an adapter's configuration, inverting the
  dependency direction the hexagonal layering exists to protect, and the leader's
  closure includes non-storage work whose cost the storage timeout cannot express.
- **Bounding the storage put alone** (the shipped #53 mitigation). Necessary but
  insufficient — it bounds one leg while the aggregate coalesce operation stays
  unbounded, which is exactly the gap #55 closed.

## Addendum (issue #65) — the cluster leader-lock TTL is a third, deliberately-unpaired knob

`PullDedupConfig::leader_lock_ttl` (`HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS`,
default 90s) is the Layer-B cluster-wide `EphemeralStore` lock lease — a knob
this ADR's "paired decision" reasoning does not cover, and deliberately does
not need to. `leader_deadline` / `HORT_STORAGE_PUT_TIMEOUT_SECS` bound how
long the leader's *own fetch* may legitimately run; `leader_lock_ttl` bounds
how long **other replicas** wait to detect a leader that is truly gone
(process crash, no heartbeat) before re-electing. As long as the heartbeat
renews the lock every `leader_lock_ttl / 3` and that renewal is itself
resilient to a transient blip, the lock survives for the *entire* duration of
a legitimately-slow leader's fetch regardless of the TTL value — so, unlike
`leader_deadline` vs the storage timeout, raising or lowering
`leader_lock_ttl` alone does not reintroduce false abandonment of a healthy
leader. It only trades off crash-recovery latency (how long a dead leader's
digest stays "poisoned" before a follower re-elects) against heartbeat
traffic.

That said, issue #65 found the pre-existing heartbeat was not actually that
resilient: `spawn_heartbeat`'s `extend_ttl` failure path used to `debug!` and
wait a full next `heartbeat_interval` tick to retry, so two consecutive
transient failures (a ~2×`heartbeat_interval` window) could lapse the lock
out from under a still-progressing leader — the false-abandonment failure
mode this ADR describes for the *other* pairing, reachable here too, but
through a liveness bug rather than a tuning mismatch. Fixed with a bounded
retry-with-backoff (`HEARTBEAT_RETRY_MAX_ATTEMPTS` × `HEARTBEAT_RETRY_BACKOFF`,
well under `heartbeat_interval`) inside each tick, so a transient blip is
absorbed without waiting for the next natural tick. This addendum, not a new
ADR, records the decision: no new fail-open surface was introduced (the retry
still gives up and lets the lock lapse if the backend stays down past the
retry budget — the eventual-fallback contract this ADR's *Decision* section
requires is unchanged), and the reasoning is a direct corollary of this
document's existing scope rather than an independent standing decision.

## References

- `crates/hort-app/src/pull_dedup.rs` — `PullDedupConfig::leader_deadline`,
  `PullDedupConfig::leader_lock_ttl` (issue #65), `LeaderGuard`,
  `spawn_heartbeat`, the two `tokio::time::timeout` sites.
- `crates/hort-adapters-storage/src/object_store_backend.rs` — the `put`
  timeout and its phase diagnostics.
- `docs/metrics-catalog.md` — `leader_timeout` / `leader_cancelled`.
