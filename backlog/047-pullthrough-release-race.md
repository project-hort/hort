# 047 — #65: pull-through cold-blob first-GET 503 race (bounded-await) + leader-lock lease too tight

**Issue:** #65 (root-caused by the maintainer against prod logs+DB+source; direction confirmed)
**Read first:** `crates/hort-http-oci/src/blobs.rs::serve` (L290 `try_upstream_blob_pull`,
L387 `check_quarantine`), `crates/hort-http-oci/src/quarantine.rs`,
`crates/hort-domain/src/entities/artifact.rs::release()` (ADR 0007),
`crates/hort-app/src/use_cases/ingest_use_case.rs:3155-3235` (descendant zero-window fast-path),
`crates/hort-app/src/use_cases/quarantine_use_case.rs` (event-driven release),
`crates/hort-app/src/pull_dedup.rs` (`LEADER_LOCK_TTL` L83, heartbeat L85/L1345),
`docs/adr/0050-*.md`, ADR 0007. **`/hort-architect` — this is ADR-0007-adjacent.**

## Primary — the cold-blob first-GET 503 race (the main fix)

On a cache-miss pull-through blob GET, `serve` blocks on `try_upstream_blob_pull` (fetch+ingest,
L290) then falls through to `check_quarantine` on the **just-ingested** row (L387). Ingest **always**
marks the blob `Quarantined`; its own trivy scan flips it to `Released` ~1–5 s later, async in the
worker — *after* the GET has already 503'd. Every cold layer costs a 503+retry; across a large
multi-arch image these stack past a CI runner's ~180 s deadline. **This is confirmed per-blob and
window-independent** — docker-io children of a released index already get a **zero/expired**
quarantine window (`ingest_use_case.rs:3155-3235`), so they're release-eligible-pending only their
**own** scan; it's the `quarantine_status` column flip lagging the read by ~1–5 s.

**Fix (confirmed direction — option 1 bounded-await; option 3 was rejected because each layer is
scanned individually and release authority is strictly per-artifact `ScanSucceeded`, so releasing
children off the parent-index scan would weaken ADR 0007 fail-closed):**
- In `serve`, after the artifact is resolved (whether just-ingested or already-present), **only when
  it is `Quarantined` AND its quarantine window has already ELAPSED** (deadline in the past — i.e.
  release-pending on its own scan, not a genuine time-hold), **bounded-await** its release before the
  `check_quarantine` 503 decision. Serve 200 (fall through to `download`) if it releases within the
  bound; **fall back to the current `check_quarantine` → 503 + `Retry-After`** if the bound elapses
  (scan slow/failed).
- **Do NOT await when the window has NOT elapsed** (a genuine time-based quarantine hold — e.g. a
  non-released-parent manifest's 5-min window): 503 immediately as today; don't hold the request for
  minutes.
- **Never weakens the predicate** — it only *waits* for the artifact's **own** `ScanSucceeded`/
  release; it never serves an unreleased blob. ADR-0007 fail-closed intact.
- **Await mechanism:** subscribe to the artifact's release event if a clean hook exists, else a
  short poll-with-backoff on the artifact status (e.g. ~200 ms intervals) up to the bound. Cold
  first-pull only (rare); the alternative today is a 503 + client retry loop anyway.
- **Bound:** operator-tunable, default ~10 s (comfortably above the observed 1–5 s, far below the
  180 s runner deadline) — e.g. `HORT_OCI_PULLTHROUGH_RELEASE_WAIT_SECS` (0 = disable = today's
  behavior).

## Secondary — the 90 s leader-lock lease is too tight for large layers

`pull_dedup.rs:83` `LEADER_LOCK_TTL = 90 s` (hardcoded, heartbeat `/3` = 30 s). A coalesce leader
fetching a large layer (e.g. 64 MiB on a throttled upstream) is abandoned at exactly 90 s
(`lock expired without terminal outcome; re-electing` → re-fetch, + a possibly-expired cached
upstream token → re-exchange), a ~90 s stall mapping to 502/500 (distinct from the 503). **Investigate
why the 30 s heartbeat (L1345 `extend_ttl`) lapses during a large fetch — is the heartbeat task
blocked by / not independent of the fetch/PUT?** Fix so a legitimately-in-flight leader (heartbeat
still firing, fetch/PUT progressing) isn't abandoned: the heartbeat must run independently of the
fetch, and/or the lease should scale with expected large-blob fetch time (tunable). Coordinate with
ADR 0050's `leader_deadline` (600 s) / `storage_put_timeout` (300 s) — this 90 s cluster-lock lease
is a *separate* knob the ADR didn't cover.

## Acceptance

- **Primary:** a cold pull-through blob whose window is elapsed and releases within the bound serves
  **200** (test); a genuine-time-quarantine blob (window not elapsed) still 503s **immediately**
  (test); a blob whose scan never completes 503s after the bound (fallback test). ADR-0007 predicate
  unchanged (assert `Artifact::release` untouched).
- **Secondary:** a leader whose fetch legitimately exceeds 90 s while heartbeating is **not**
  abandoned (test the heartbeat/lease interaction).
- Full gate green.

### Starter prompt

```
/hort-architect

Implement backlog item 047 (issue #65) on branch agent/65-pullthrough-release-race. IMPORTANT:
verify `git branch --show-current` before every commit — never develop. This is ADR-0007-adjacent —
the primary fix must NOT weaken the fail-closed release predicate (it only WAITS for the artifact's
OWN scan/release, never serves an unreleased blob). Primary: in blobs.rs::serve, bounded-await the
artifact's release before the check_quarantine 503 ONLY when it's Quarantined AND its window has
already elapsed (release-pending on its own scan); serve 200 on release within the bound (tunable,
~10s default, 0=off), fall back to the current 503+Retry-After past it; never await a genuine
not-yet-elapsed time-quarantine. Secondary: investigate why pull_dedup's 90s LEADER_LOCK_TTL expires
despite the 30s heartbeat on a large-layer fetch, and fix so an in-flight-heartbeating leader isn't
abandoned (heartbeat independent of the fetch and/or scaled/tunable TTL; coordinate ADR 0050). Tests
per the acceptance criteria. Run the full gate; report per the handover protocol.
```
