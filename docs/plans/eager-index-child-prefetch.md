# Eager index-child prefetch — design (issue #51)

Branch-local planning doc (D7). **Blocked on #55** — see §2.

## §1 — Deferred-items sweep (architect Step 0)

Run 2026-07-20 against `develop` @ `a3dff74c`.

- `docs/plans/*.md` — one sibling present on this branch line: `coalesce-leader-liveness.md` (#55). Its §4 carries forward *"`prefetch_ingest.rs` bypasses `PullDedup` while its module doc claims otherwise"* → filed as **#57**. **Decision: carry forward** — related (both concern prefetch dedup) but independent; #51 does not touch the task-queue cascade.
- ADR open-items register — two OCI-index rows reviewed:
  - *OCI image-index child-status rollup* ([0043]) — index visibility does not reflect child quarantine state. **Decision: carry forward, not absorbed.** Adjacent but distinct: that is about *serving* an index whose children are held; this is about *fetching* them earlier. Eager prefetch does not change what is served.
  - *OCI image-index promotion cascade* ([0043]) — promotion does not walk `oci_index_member`. **Decision: carry forward.** Same edges, different consumer.
- Issue #46's Option-B design deferred the eager-tree fetch explicitly; #51 **is** that deferral surfacing. **Decision: include now** — this is the scheduled follow-on.

### Inherited-rationale re-validation

**Reused claim (#46 Option B):** "register-only is sufficient for v1; the fetch half can be deferred because the descendant zero-window carve-out already collapses the latency."

**Verdict: still valid, and it is why this item is low-priority.** Tom's prod validation confirmed a cold multi-arch pull dropped from ~15–18 min to ~5–8 min (bounded by the index's own quarantine window). The residual is the sequential per-level walk, not a broken invariant. Nothing about the threat surface changed. Recorded so the next sweep sees the verdict rather than silence.

## §2 — Hard prerequisite: #55 must land first

This is a sequencing constraint, not a preference.

Eager child fetch means issuing **N child manifests × M config/layer blobs** concurrent pull-through fetches per index. Every one of those rides `PullDedup`. Per #55's design §2, a wedged coalesce leader currently hangs **every** in-process follower forever (`pull_dedup.rs:700`, unbounded `rx.recv().await`) and its heartbeat re-extends the cluster lock in perpetuity (`spawn_heartbeat`, aborted at 923 only after the await at 918).

Shipping eager fan-out onto that machinery multiplies the blast radius of a known-open bug from one wedged digest to a whole image tree. **Do not schedule this item until #55's fix is merged.**

## §3 — Reframing: this is not a new code path

The issue proposes eager register+fetch at the pull-through seam. The register half already shipped (`58b8548c`). For the fetch half, there are two candidate seams, and the obvious one is wrong.

**Rejected — inside the coalesce closure.** `register_membership_edges_from_pull` (manifests_write.rs:1362) runs its edge-write loop (1414–1450) *inside* the leader's `coalesce_blob`/`coalesce_to_hash` closure (called from manifests.rs:891 digest-path, manifests.rs:1201 tag-path). Adding N+M network fetches there extends the critical section that every Layer-A follower is blocked on. That loop is already the heaviest thing in the window — one DB round-trip per referenced blob, **serially**. Making it fetch too would turn a ~seconds window into a ~minutes one, which is precisely the condition #55 exists to bound. Reject.

**Chosen — extend the existing post-ingest prefetch trigger.** `fire_prefetch_trigger_oci` (`crates/hort-http-oci/src/prefetch.rs:133`) already does exactly this job for single-image manifests: fired *after* ingest, spawns background blob pull-throughs, each riding `PullDedup` via `try_upstream_blob_pull`, results logged and discarded (best-effort). It is gated on `repo.prefetch_policy.enabled` and on an actual tag move (`prior_held_digest != upstream_digest`, line 158).

It bails on an index. `parse_manifest_blob_digests` returns `Some(empty)` for index media types, hitting the early return at prefetch.rs:197–205: *"manifest references no blobs (config-only or index); nothing to prefetch."*

**So #51 is: teach the shipped trigger the index case.** No new path, no new dedup story, no change to the pull-through hot path. That is a materially smaller and safer change than the issue implies.

## §4 — What to build

### §4.1 — Index-aware fan-out

When the ingested manifest is an index, walk `parse_index_children` (manifests_write.rs:1222 — already `pub(crate)`, already caps width via the domain-level `index_child_digests`), then for each selected child: pull the child manifest through `try_upstream_manifest_pull_by_digest`, and let that call's own `register_membership_edges_from_pull` discover the child's config+layer blobs, which the existing single-image path then prefetches.

The recursion is one level deep and terminates naturally: index → child manifests → their blobs.

### §4.2 — Bounded concurrency (new, and required)

The current fan-out at prefetch.rs:227 is a bare `tokio::spawn` per blob — **no `Semaphore`, no `JoinSet`, no cap, no backpressure**. For a single-image manifest (config + a handful of layers) that is tolerable. For an index it is not: a 8-arch image at ~10 layers each is ~88 concurrent pull-throughs against one upstream from a single client request.

Introduce a bounded runner — a `Semaphore` sized by a new `HORT_OCI_PREFETCH_MAX_CONCURRENCY` (proposed default **8**) — and route **both** the existing single-image fan-out and the new index fan-out through it. Fixing the existing unbounded spawn is in scope: it is the same code path and leaving it unbounded while adding a much wider consumer would be negligent.

### §4.3 — Arch selection — **OPEN, needs Tom's steer**

This is the one genuine product decision and it is not mine to make. Fetching all arches of a multi-arch image is the difference between prefetching ~1 GB and ~8 GB per tag move.

- **(a) All children.** Simplest, guarantees the hit, worst bandwidth/storage. A typical cluster consumes 1–2 of 5–10 published arches.
- **(b) Operator-configured platform allowlist** on `PrefetchPolicy` (e.g. `platforms: ["linux/amd64", "linux/arm64"]`), default to those two. Covers the overwhelming majority of real deployments at ~20–25 % of (a)'s cost.
- **(c) Only the arch the triggering client is about to request.** Cheapest, but not knowable at trigger time — the client has only fetched the index. Would require deferring until the first child request, which is the lazy behaviour this issue exists to remove. **Not viable.**

**Recommendation: (b).** It is the only option that lets an operator express the actual consumption profile, and the cost gap over (a) is large enough to matter on a proxy serving a cluster.

**Note the ADR 0015 constraint:** a new `PrefetchPolicy` field must be **either enforced by the consuming use case or rejected at gitops apply**. A `platforms:` field accepted at apply and ignored at runtime is a hard block — operators would make capacity decisions on an inert knob. If (b) is chosen, the field and its enforcement ship together, in one item.

### §4.4 — Quarantine semantics for eagerly-fetched children

No change required, and this is worth stating so nobody invents one. An eagerly-fetched child is ingested through the identical `try_upstream_manifest_pull_by_digest` path a lazy client pull would use, so it lands with the same zero-length quarantine window that #46 Item 2 gives any referenced-tree descendant, and releases on its own clean scan under its own authority. Eager fetch changes **when** bytes arrive, never **whether** they are gated. The release predicate (ADR 0007) is untouched.

## §5 — Observability

- `info!` on index fan-out start: `repo_key`, `name`, `tag`, `child_count`, `selected_count` (so a platform filter's effect is visible).
- `warn!` on a child pull failure — best-effort, non-fatal, mirroring the existing single-image posture at prefetch.rs:240+.
- New counter `hort_oci_prefetch_children_total{outcome}` — `selected` / `skipped_platform` / `succeeded` / `failed`. Without `skipped_platform` an operator cannot tell a working filter from a broken parse.
- `docs/metrics-catalog.md` parity required (metrics.rs:1507 convention).

## §6 — Explicitly out of scope

- The task-queue prefetch cascade (`prefetch_dependencies.rs` / `prefetch_ingest.rs`) — different mechanism, L3-deduped. See **#57**.
- Index **promotion** cascade and index **child-status rollup** — carried forward from the ADR register per §1.
- Any change to what a client is *served*. This item changes fetch timing only.

## §7 — Layering check

Stays within the inbound OCI adapter (`hort-http-oci`) plus one config field if §4.3(b) is chosen. No new port, no new domain event, no `IngestUseCase` change. `hort-http-oci` must not import `hort-adapters-*` (ADR 0008) — the fan-out calls existing `crate::blobs` / `crate::manifests` helpers, so this holds by construction.
