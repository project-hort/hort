# 221 — A retention policy must show what it would take, before it takes it

**Issue:** #283 · **Branch:** `agent/283-retention-dry-run`
**Depends on:** unit A (naming repositories) — a preview is only useful once a
policy can be written by name.
**Governing decisions:** the concept's D2 (one mechanism, not two — the dry run
*is* the propose half of propose→confirm→execute) · ADR 0054 (CAS-shared bytes:
rows are not bytes).

## Why

A policy's `last_matched_count` / `last_expired_count` are written **after**
evaluation, i.e. after the `ArtifactExpired` events already exist. There is no
way to write a policy and see what it would take first.

Against 142 GB, with a predicate like `KeepLastN(20)` over a repository holding
36 894 artifacts, "apply once and look" is not an option. The preview is the
condition under which that mass may be touched at all.

## The shape: same path, different mode

The dry run is **not a second evaluation path**. Two paths drift, and at the
first disagreement neither is believed — the drift `release_clearance.rs` exists
to prevent elsewhere.

`retention-evaluate` gains a mode in which it

- draws the same candidates through the same reader and the same predicates,
- appends **no** `ArtifactExpired` and advances no projection field,
- writes its finding into its own `jobs` row's `result_summary`.

That makes the preview equal to the action by construction, and it is readable
through the admin-tasks surface without inventing a second one.

## The collision this must not walk into

Preview and execution would both be `retention-evaluate`, and **two independent
idempotency layers would fold them into a single job.** Fixing one and leaving
the other is the likely failure of this unit, so both are in scope.

1. **The durable, server-derived layer.** The invoke handler builds
   `cron:<kind>:<UTC-day>` for every destructive kind and threads it into the
   enqueue's partial-unique check
   (`crates/hort-http-admin-tasks/src/handlers/invoke.rs:192-240`). Kind and day
   only; the params are never inspected. A preview in the morning makes the
   evening's execution return the **preview's** job instead of enqueueing
   anything. The operator sees a completed job and no deletions, and nothing
   looks broken.
2. **The ephemeral header layer, which is blinder still.** When the caller sends
   an `Idempotency-Key`, the handler looks up `idem-task:<that value>` in
   `ephemeral_durable` and returns the cached `task_job_id` **before** the
   enqueue is ever reached (`invoke.rs:163-183`). The cache key is the client's
   header value alone — not the kind, not the mode, not the params — with a 300 s
   TTL. And `hort-cli` makes that collision the normal path rather than an edge
   case: `--idempotency-window` derives `<window-prefix>:<kind>`
   (`crates/hort-cli/src/admin/task_invoke.rs:173-195`), which is kind-scoped and
   mode-blind, so a preview and an execution inside the same window send an
   identical header by construction.

So the mode must enter **both** derived keys, and the ephemeral entry must record
what it was issued for, so a lookup that does not match the invocation is a miss
rather than a wrong hit.

The mode must also be visible to the authorization check (the destructive
permission gates execution, never the preview) — today both the HTTP pre-check
and the internal enqueue authorize by kind alone (`invoke.rs:120-138`,
`task_use_case.rs:127-160,276-288`).

## Read first

- `crates/hort-app/src/task_handlers/retention_evaluate.rs` — the batch loop and
  the existing `expired` / `already_expired` summary shape.
- `crates/hort-app/src/use_cases/retention_use_case.rs` — `evaluate_one`, scope
  matching, and where `ArtifactExpired` is appended.
- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the
  candidate enumeration and its keyset pagination.
- `crates/hort-app/src/use_cases/purge_use_case.rs` + `purge_gc.rs` — how the
  refcount decides whether a blob actually falls (`refs_remaining == 0`); this
  is what the byte figure must simulate rather than estimate.
- `crates/hort-http-admin-tasks/src/handlers/list.rs` — the existing surface the
  result is read through.
- `crates/hort-http-admin-tasks/src/handlers/invoke.rs:120-138,163-183,192-240` —
  the kind-only authorization pre-check, the header-keyed ephemeral cache, and
  the kind+day durable key.
- `crates/hort-cli/src/admin/task_invoke.rs:120-195` — the window key the CLI
  sends by default, and its kind-scoped, mode-blind shape.

## What the preview must report

One number is not enough, and the naive number misleads:

1. **Rows per policy and repository** — how many artifacts the predicate hits.
2. **Distinct `checksum_sha256`** — because rows are not bytes (ADR 0054).
3. **Bytes that would actually be freed** — over the **full** reference set the
   purge removes, not only each artifact's own `checksum_sha256`: `purge_gc`
   deletes every `content_references` source edge, including `metadata_blob` and
   the OCI child edges (`purge_gc.rs:244-275,337-345`). A figure computed over
   primary content alone understates what falls — the real figure and the hard part: a
   blob falls only when its CAS refcount reaches zero across the *whole*
   candidate set. Summing `size_bytes` over the hits systematically overstates
   it. Simulate the refcount over the candidate set; if that is too expensive
   for a given set, **omit the figure and report it as omitted** — never
   estimate it.
4. **A bounded sample** of affected artifacts (name, version, age) so an
   operator can sanity-check the selection. Cap it the way the curation queue
   caps its listing.

## Acceptance

- A dry run appends no event and advances no projection — proven by a test that
  compares the artifact stream before and after.
- Preview and execution provably draw the same candidates: one test runs both
  over the same fixture and compares the sets element-wise.
- The report carries rows, distinct contents, and either simulated freed bytes
  or an explicit omission — never an estimated byte figure.
- The byte figure is pinned by a fixture with **shared** targets, not by an
  arithmetic identity: the candidate set holds two artifacts sharing a primary
  content hash, one metadata blob shared with an artifact outside the set, and an
  OCI child target a surviving manifest still references. The expected figure is
  asserted as a literal, and the bytes shared with a survivor are **not** in it.
  A fixture of unshared artifacts lets a naive `SUM(size_bytes)` pass every other
  criterion here.
- The sample is capped, and a run that hits the sweep's batch ceiling reports the
  coverage as partial rather than presenting a truncated count as complete.
- A preview and an execution on the same UTC day are distinct jobs: the execution
  runs. A test pins that, because the current key would silently collapse them.
- The same holds when both are sent with an identical `Idempotency-Key`,
  including the key `hort-cli --idempotency-window` derives by default. Its own
  test: the durable layer's fix does not reach this one, and the CLI's default
  path walks straight into it.
- The preview is invocable without the destructive permission; the execution is
  not.
- Gate green; `hort-app` stays at 100 %; no issue, MR or backlog numbers in code
  comments.

## Explicitly not in this item

This item delivers an **observation**, not the propose→confirm→execute contract:
nothing here binds a later execution to what the preview showed. Policies, tags,
download evidence and artifact state can all move in between. Calling the output a
proposal would overstate it until a confirmation step revalidates or pins it.

No confirm/execute half, no HTTP surface beyond what admin-tasks already
provides, no predicate changes, no evidence-class state opt-in.
