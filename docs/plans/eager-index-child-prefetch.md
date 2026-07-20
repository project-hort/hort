# Warm an index child's layers on the digest path — design (issue #51)

Branch-local planning doc (D7). **Revised 2026-07-20** after Tom's steer: the original design (index fan-out + a `PrefetchPolicy` platform allowlist) is withdrawn in favour of a materially smaller change. The withdrawn version is summarised in §6 so the reasoning is not lost.

## §1 — Deferred-items sweep (architect Step 0)

Run 2026-07-20 against `develop` @ post-`!168`.

- `docs/plans/` — one sibling, `coalesce-leader-liveness.md` (#55), now **merged** via !168. Its §4 carry-forward (`prefetch_ingest.rs` bypasses `PullDedup` while its doc claims otherwise) is filed as **#57**. **Decision: carry forward** — related but independent; this item does not touch the task-queue cascade.
- ADR open-items register — *OCI image-index child-status rollup* and *OCI image-index promotion cascade* (both [0043]) reviewed. **Decision: carry forward, not absorbed.** Both concern indexes but neither concerns fetch timing.
- #46's Option-B deferred eager-tree fetch — **this item is that deferral surfacing.** Include now.

### Inherited-rationale re-validation

**Reused claim (#46 Option B):** "register-only is sufficient for v1; the fetch half can be deferred because the descendant zero-window carve-out already collapses the latency."

**Verdict: still valid — and it is now the reason this item shrank.** Prod validation showed a cold multi-arch pull dropped from ~15–18 min to ~5–8 min. The remaining cost is the sequential level-by-level walk, not a broken invariant. That framing is what makes the cheap fix below sufficient.

## §2 — Prerequisite: #55 (SATISFIED)

Eager fetching adds concurrent pull-through fetches, all riding `PullDedup`. Before !168 a wedged coalesce leader hung every in-process follower forever. **!168 merged**, so the leader is now bounded and self-healing. This item is unblocked.

## §3 — The actual gap

`fire_prefetch_trigger_oci` (`crates/hort-http-oci/src/prefetch.rs:133`) already warms a manifest's config + layer blobs in the background, each riding `PullDedup`, best-effort. It is wired into the **tag path only** (`manifests.rs:1210`).

So a `docker pull` of a multi-arch image today does:

1. `GET /manifests/:tag` → index ingested → trigger fires → `parse_manifest_blob_digests` returns `Some(empty)` for an index → **nothing prefetched** (early return, prefetch.rs:197).
2. `GET /manifests/sha256:<child>` → the digest path → `content_references` edges written → **no prefetch fired at all**.
3. Every layer pulled lazily, one round trip at a time.

**Step 2 is the gap, and it is one missing call.** The client's own request for a specific child digest is an unambiguous statement of which architecture it wants — no inference, no policy, no guessing. Firing the existing trigger there warms exactly that arch's layers while the client is still parsing the child manifest.

## §4 — What to build

**One change: fire the blob-warming fan-out on the digest path of manifest pull-through.**

`fire_prefetch_trigger_oci` cannot be called verbatim — its signature takes `tag` + `prior_held_digest` and gates on a dist-tag move (`prior_held_digest != upstream_digest`), neither of which exists for a by-digest pull. Split it:

```rust
// prefetch.rs — the existing tag-move gate, unchanged in behaviour.
pub(crate) fn fire_prefetch_trigger_oci(ctx, repo, name, tag, upstream_digest,
                                        prior_held_digest, manifest_bytes) {
    if !repo.prefetch_policy.enabled { return; }
    if prior_held_digest == Some(upstream_digest) { return; }   // no tag move
    if ctx.prefetch_use_case.plan(..).is_empty() { return; }    // planner gate
    warm_manifest_blobs(ctx, repo, name, manifest_bytes);
}

// NEW — the shared fan-out half, callable without a tag.
pub(crate) fn warm_manifest_blobs(ctx, repo, name, manifest_bytes) { … }
```

Call `warm_manifest_blobs` from the digest path (`manifests.rs`, alongside the existing `register_membership_edges_from_pull` at :891), gated on `repo.prefetch_policy.enabled` only.

**No planner call on the digest path.** The planner's trigger taxonomy has no "child manifest fetched" kind, and its role at the tag site is a plain on/off gate. Adding a trigger variant to satisfy a gate that `prefetch_policy.enabled` already answers is machinery for its own sake. If a future initiative needs per-trigger prefetch accounting, it can add the variant then.

That is the whole change: one extracted helper, one new call site, one `enabled` check.

## §5 — Explicitly NOT doing

Recorded so these are not silently reintroduced.

- **Index child fan-out.** Withdrawn. Fetching an index's children eagerly means guessing which arches matter; the client tells us for free one round trip later. The index → child hop stays sequential — it is a single few-KB manifest fetch, and all the bytes are in the layers this design already warms.
- **A `PrefetchPolicy.platforms` allowlist.** Withdrawn with the fan-out. No new operator surface, so **ADR 0015 does not apply at all** — there is no field to make load-bearing.
- **Bounded-concurrency runner for the spawn fan-out.** The existing per-blob `tokio::spawn` at prefetch.rs:227 has no cap. Under this design the digest path warms **one manifest's** config + layers (~10 spawns) — identical in shape and width to what the tag path already does in production today. This change therefore adds **no** new concurrency pressure, so a cap is not required *for this item*. The unbounded spawn remains a pre-existing latent issue; if it is worth fixing it is worth fixing on its own merits, not smuggled in here. **Carried forward** — file separately if it ever bites.
- **Quarantine changes.** None needed. An eagerly-warmed blob rides the identical `try_upstream_blob_pull` path a lazy client GET uses, so it is gated exactly as before. Eager warming changes **when** bytes arrive, never **whether** they are gated. ADR 0007's release predicate is untouched.

## §6 — Withdrawn design (kept for the record)

The first pass proposed teaching `fire_prefetch_trigger_oci` the index case: parse `parse_index_children`, fetch each child manifest, let each child's own registration discover its blobs — plus a `PrefetchPolicy.platforms` allowlist (default `linux/amd64` + `linux/arm64`) to avoid pulling all 5–10 published arches, plus a `Semaphore` because an 8-arch image would have meant ~88 concurrent pull-throughs from one client request.

**Why withdrawn:** it solved a problem the client solves for us. Every part of that cost — the arch guess, the operator-facing policy field and its ADR 0015 enforcement obligation, the concurrency cap made necessary only by the fan-out itself — existed to work around not knowing the architecture at index-ingest time. We learn it definitively one request later. The simpler design captures essentially the same latency win (the layers are the bytes) at none of that cost.

## §7 — Observability

Deliberately minimal — this rides an existing instrumented path.

- The existing `info!` in the fan-out already reports `repo_key` / `name` / `blob_count`. Extend its call site to distinguish the trigger source (`tag_move` vs `child_digest`) so an operator can see which path warmed a blob.
- No new metric. `hort_upstream_fetch_total` already counts the resulting pulls, and the existing prefetch counters cover the tag path. A dedicated counter here would measure a code path, not an operator-meaningful outcome.

## §8 — Testing

- A by-digest manifest pull-through on a `prefetch_policy.enabled` repo spawns warming pulls for that manifest's config + layers.
- The same pull on a **disabled** repo spawns nothing.
- The tag path's existing behaviour — including the tag-move gate and the planner gate — is unchanged. The existing prefetch tests (prefetch.rs:544+) must pass untouched; the refactor is behaviour-preserving on that side.
- An index pulled by digest warms nothing (it has no config/layers) and does not error.

## §9 — Layering

Entirely within `hort-http-oci`. No new port, no domain event, no config field, no `IngestUseCase` change. `hort-http-oci` must not import `hort-adapters-*` (ADR 0008) — the fan-out calls existing `crate::blobs` helpers, so this holds by construction.
