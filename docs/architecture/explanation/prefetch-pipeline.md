# The Prefetch Pipeline

Quarantine creates build friction by design: the first pull of a cold
artifact through a proxy repository lands in quarantine, and the build
that requested it waits out the observation window. Prefetching exists
to move that wait off the critical path — pull the artifact *before* a
build asks for it, so the quarantine clock starts (and usually expires)
ahead of demand. Prefetched bytes pass through exactly the same
verification and quarantine gates as client-driven pulls; the pipeline
changes **when** the clock starts, never **whether** the gates apply.

Because warming costs storage, bandwidth, and scan load proportional to
its aggressiveness, the entire pipeline is opt-in per repository with
conservative defaults. A repository that never opts in never prefetches
anything — upgrading the binary cannot silently start mirroring
upstream traffic.

## The policy gate

`PrefetchPolicy` (`crates/hort-domain/src/entities/repository.rs`,
`PrefetchPolicy` + `PrefetchTrigger`) is the per-repository contract:

- **`enabled`** — master switch, default `false`.
- **`triggers`** — which trigger paths may schedule prefetches. Empty
  default; even with `enabled = true`, no triggers means no work.
- **`depth`** — newest N versions to warm per package on the
  non-transitive triggers. Serde-defaulted to `3`.
- **`transitive_depth`** — cascade depth cap. Serde-defaulted to `5`.
- **`max_age_days`** — optional age filter, defaulted to `None`.
- **`max_descendants`** — cumulative breadth cap on the transitive
  cascade. Serde-defaulted to `200`; `0` collapses transitive
  enqueueing entirely while leaving the trigger configured.

The serde posture is deliberate and asymmetric. The numeric knobs carry
`#[serde(default = …)]` functions pinned to the design values
(`default_prefetch_depth`, `default_transitive_depth`,
`default_max_descendants`), so a minimal
`prefetchPolicy: { enabled: true, triggers: […] }` gitops block parses
with the documented defaults applied — the YAML wire, the DB row
mapper, and the struct `Default` agree. But `enabled` and `triggers`
stay **required**: there is no struct-level `#[serde(default)]`, so
`prefetchPolicy: {}` is a parse error rather than a silently disabled
policy. A policy block must declare what it enables and which triggers
fire.

## Trigger surfaces

Three trigger kinds live in the policy (`PrefetchTrigger`), and one
surface sits outside it:

- **`on_dist_tag_move`** — the hot-path trigger. When a format crate
  serves upstream index/metadata (the npm packument, the PyPI simple
  index, the cargo index), it checks whether the upstream's newest
  version has moved past the locally held set and fires the planner
  inline (`fire_prefetch_trigger_npm` in
  `crates/hort-http-npm/src/packument.rs`, the PyPI sibling in
  `crates/hort-http-pypi/src/simple_index.rs`, cargo in
  `crates/hort-http-cargo/src/index_source.rs`). The name comes from
  npm's mutable `dist-tags.latest` pointer; formats without a native
  mutable tag synthesise "newest" by per-format version ordering. OCI's
  variant (`crates/hort-http-oci/src/prefetch.rs`) detects real
  upstream tag-digest divergence at the manifest-fetch path.
- **`scheduled`** — a periodic sweep driven by the `prefetch-tick`
  worker task (below). The operator chooses the cadence at deployment
  time; the binary contains no scheduler.
- **`transitive_deps`** — the on-ingest cascade: when an artifact
  ingests into a repository listing this trigger, its declared runtime
  dependencies are resolved and warmed (below).
- **Self-service** — `POST /api/v1/repositories/:repo_key/prefetch`
  (`crates/hort-http-discovery/src/handlers/prefetch.rs` →
  `SelfServicePrefetchUseCase::enqueue_self_service`). This is an
  authenticated request surface, not a policy trigger: a developer who
  knows next sprint's dependency list warms it explicitly. The
  `Read ∧ Prefetch` permission gate and the token-kind gate live inside
  the use case.

Anonymous reads never trigger prefetch. An earlier implicit
trigger-on-index-fetch pathway was removed precisely because it let
unauthenticated traffic drive upstream fetches; the self-service
endpoint is its explicit, authenticated replacement (see the removal
note on `PrefetchTrigger` in
`crates/hort-domain/src/entities/repository.rs`).

## The planner

`PrefetchUseCase::plan`
(`crates/hort-app/src/use_cases/prefetch_use_case.rs`) is a pure
planner — no upstream call, no DB read, no spawn. Callers hand it the
repository (carrying the policy), the requested trigger, the upstream
version set, the locally held set, and a per-format `VersionOrdering`;
it returns the newest-first list of versions to warm, capped at
`policy.depth`. Every early exit is a counted skip: `disabled`,
`trigger_not_enabled`, `already_held`, `not_newer` — emitted on
`hort_prefetch_skipped_total{reason}`, with
`hort_prefetch_enqueued_total{trigger}` emitted once per planned
version. The `not_newer` filter is what bounds the planner to "warm
the newest depth" rather than back-filling a package's full history.

What happens to the plan depends on the caller. The hot-path triggers
are request-scoped and naturally rate-limited by client traffic, so
they spawn the pull-throughs directly (`spawn_prefetch_pulls_npm` and
siblings). The scheduled tick is a bulk walk and instead routes every
planned version through the jobs table, where deduplication, priority,
retry, and backpressure live.

## Two job kinds: leaves and drivers

The jobs table carries two prefetch kinds with strictly separated
roles:

- **`prefetch`** — the *leaf-ingest*. Its params carry the artifact
  identity: `{ repository_id, package, version }`, with `package`
  already normalised and `version` always concrete (never a range).
  The leaf fetches and ingests; it never walks dependencies.
- **`prefetch-dependencies`** — the *cascade driver*. It walks one
  artifact's manifest and enqueues; it never ingests.

`PrefetchIngestHandler`
(`crates/hort-app/src/task_handlers/prefetch_ingest.rs`) consumes the
leaf kind. Per claimed row it loads the repository and format handler,
resolves the catch-all upstream mapping (`path_prefix = ""`), fetches
the upstream metadata body so `FormatHandler::parse_upstream_checksum`
can recover the upstream-published checksum, composes the artifact
URL(s) via `FormatHandler::build_pull_url`, and per URL runs
`UpstreamProxy::fetch_artifact` →
`IngestUseCase::ingest_verified` with the upstream-published checksum
as the integrity target. PyPI is the multi-distribution special case:
one version maps to many files (sdist + wheels) with per-file
checksums, so the leaf fans out over the per-version JSON manifest's
`urls[]` array, one verified ingest per distribution. Individual URL
failures are non-fatal — the leaf completes with
`urls_attempted / urls_succeeded / urls_failed` counts in its
`result_summary`, and the next pull re-derives anything missed.

All prefetch rows carry `priority = 0`, so manual, cron, and advisory
work drains first. Warming is a background concern; starving it under
load is acceptable because the cascade is stateless and re-derivable.

## The transitive cascade

When a repository's triggers include `transitive_deps`, every ingest
fires a seed hook (`crates/hort-app/src/use_cases/ingest_use_case.rs`,
the block guarded by `suppress_cascade_seed` and the
`TransitiveDeps` membership check) that enqueues one root
`prefetch-dependencies` row for the just-ingested artifact at depth 0.
The hook runs strictly after the ingest transition commits and is
best-effort: an enqueue failure logs a warning and leaves the ingest's
success untouched — the next pull re-triggers.

`PrefetchDependenciesHandler`
(`crates/hort-app/src/task_handlers/prefetch_dependencies.rs`) drives
the walk. It reads the stored artifact from CAS (a buffered, capped
read) and hands the archive to
`FormatHandler::extract_dependency_specs` to obtain the declared
runtime dependency specs. Resolution is then a two-pass hybrid. Pass 1
is held-set resolution, free of upstream I/O: each spec's range is
resolved against the versions the repository already holds
(`resolve_range_max`); a satisfiable spec is already warm and drops
out. Pass 2 takes the cold cohort, coalesces it by normalised package
name so two specs for the same package make one metadata fetch, pulls
the upstream version set, and resolves each range to a **concrete**
version. A range upstream cannot satisfy is logged and skipped — the
cascade never fabricates versions.

Each resolved cold dependency produces a *pair* of rows: a `prefetch`
leaf (the warming) and — while `current_depth + 1` is within
`transitive_depth` — a child `prefetch-dependencies` driver. The depth
cap is on cascade *recursion*, not on warming: at the cap the leaf is
still enqueued, only the child walk is omitted. The child row cannot
carry an `artifact_id` (its artifact does not exist until the paired
leaf ingests), so it carries the `(repository_id, package, version)`
coordinate and the handler re-resolves the artifact on claim; if the
leaf has not landed yet, the claim retries.

Breadth is bounded by `max_descendants`, carried cumulatively in the
task params (`current_descendants_so_far`) rather than a progress
store. The cohort is truncated to the remaining headroom *before* the
insert, child rows truncated in lockstep, and the new running total
stamped onto each child — so the cap holds per cascade branch no
matter how wide a single manifest fans out.

### Seed suppression

Every cascade-enqueued row carries `trigger_source = "prefetch"`. When
a cascade leaf ingests, `is_cascade_internal_leaf`
(`prefetch_ingest.rs`) sets `cascade_internal`, which rides the ingest
request as `suppress_cascade_seed` — and the on-ingest seed hook does
not fire. This matters twice over: the artifact is already covered by
its parent's depth-carrying child row, so a seed would double-walk it;
and a seed restarts at depth 0, which would reset the
`transitive_depth` and `max_descendants` accounting and unbound the
cascade. Genuine seeds — client pulls, self-service roots
(`trigger_source = "self_service"`), scheduled rows
(`trigger_source = "scheduled"`) — leave the flag unset and fire the
hook normally.

### Stateless re-derivation

The cascade keeps no progress state beyond the jobs rows themselves. A
failed driver leaves a terminal row; the dedup index (below) excludes
terminal states, so the next pull of any dependent re-derives the
missing subtree from the artifacts projection. Terminal `prefetch%`
rows are garbage-collected by the `prefetch-row-retention-sweep` task
(`crates/hort-app/src/task_handlers/prefetch_row_retention_sweep.rs`).

## Archive-aware dependency extraction

`FormatHandler::extract_dependency_specs`
(`crates/hort-domain/src/ports/format_handler.rs`) takes the stored
artifact stream — the format's own archive, the ground truth the
publisher shipped — not a registry-derived metadata document. Each
handler locates its declared-runtime manifest inside the archive:

| Format | Container | Manifest located | Classes followed |
|---|---|---|---|
| npm | gzip-tar `.tgz` | `package/package.json` | top-level `dependencies` only (`crates/hort-formats/src/npm.rs`, `parse_npm_runtime_dependencies`) |
| cargo | gzip-tar `.crate` | the single top-level `{dir}/Cargo.toml` | `[dependencies]` only; the `package` rename key wins over the table key (`crates/hort-formats/src/cargo.rs`) |
| pypi | magic-byte sniff | wheel (`PK\x03\x04`) → `*.dist-info/METADATA` `Requires-Dist`; sdist (`\x1f\x8b`) → best-effort empty | extras-gated deps (`; extra == '…'`) dropped (`crates/hort-formats/src/pypi.rs`) |
| OCI / others | — | trait default | `Ok(vec![])` — no cascade |

PyPI gets only a `Read`, not a filename, hence the magic-byte sniff;
sdists are skipped because `PKG-INFO` frequently lacks `Requires-Dist`.
A manifest that is present but unparseable, or absent from a container
that must carry one, is a `Validation` error — a non-retryable walk
failure, since the bytes will not change.

All archive decoding routes through
`crates/hort-formats/src/archive_bounds.rs` — the single sanctioned
home for archive extraction (`deny.toml` locks the archive crates to
`hort-formats` for this reason). `read_tar_gz_entry` (gzip-tar) and
`iter_zip_entries` (zip) enforce a compression-ratio bound, an output
cap, an entry-count cap, and nested-archive rejection; a guard trip is
an `Err`, never a silent partial result. Entries are read in memory
only — nothing is extracted to disk, so there is no path-traversal
surface. One asymmetry to know: the tar reader's output bound is
cumulative across the sequential scan, so a manifest ordered after the
cap's worth of decompressed bytes is unreachable — fine in practice,
because real npm and cargo archives place their manifest as an early
entry, while zip's central directory lets the wheel path seek straight
to `METADATA`.

## Three layers of dedup

Prefetch traffic overlaps with itself (consecutive ticks, overlapping
ranges) and with client pulls. Three layers absorb the duplicates:

- **L1 — pull single-flight.** Concurrent fetches of the same blob
  coalesce in the upstream proxy; the second caller sees the leader's
  outcome. The leaf handler composes with this for free.
- **L2 — projection uniqueness.** The artifacts projection is keyed on
  `(repository_id, path)`; a terminal re-ingest of the same logical
  artifact is absorbed.
- **L3 — enqueue-time job dedup.** `jobs.target_key` carries a
  canonical `(repository, format, normalised package, concrete
  version)` coordinate (`prefetch_dependencies::target_key`), and a
  partial unique index over pending/running `prefetch` rows
  (`jobs_prefetch_unique`, `migrations/009_scan_jobs_and_findings.sql`)
  makes `JobsRepository::enqueue_prefetch_batch`'s
  `ON CONFLICT (target_key) DO NOTHING` the dedup itself — no
  read-then-insert race. Keying on the concrete version (never the
  range string) is what lets overlapping ranges (`^1.0`, `~1.2`) that
  resolve to the same release collapse into one row. The partial WHERE
  excludes terminal states, so a failed row never blocks
  re-derivation.

The `trigger_source` column keeps the sources distinguishable in audit
and metrics: a runaway `scheduled` rate is a runaway scheduler, a
runaway `prefetch` rate is a runaway cascade, and `self_service`
attributes to an operator request.

## The scheduled tick

`PrefetchTickHandler`
(`crates/hort-app/src/task_handlers/prefetch_tick.rs`, kind
`prefetch-tick`) is the periodic sweep. It is dispatched like any
other admin task — an external CronJob (or operator cron) invokes the
task endpoint, the worker claims the row — so the server binary stays
scheduler-free. Per tick it walks every repository whose policy lists
`scheduled` (bounded by `MAX_REPOS_PER_TICK` ×
`MAX_PACKAGES_PER_REPO`), and for each *tracked* package — a distinct
name already held in the repository — fetches the upstream version
set, runs the planner with the `Scheduled` trigger, and enqueues one
`prefetch` leaf per planned version through `enqueue_prefetch_batch`
with `trigger_source = "scheduled"` and a real `target_key`.

Routing through the batch path rather than a plain enqueue is
load-bearing. The planner filters only on the held set and has no view
of pending jobs, so a version planned at tick N but not yet ingested
by tick N+1 is re-planned every tick until it lands; the `target_key`
conflict collapses each re-plan into the existing row instead of
accumulating duplicates. A per-tick budget (`MAX_PREFETCHES_PER_TICK`,
checked between packages) bounds genuinely-new enqueues; when it
trips, the tick records `budget_exhausted` and the next tick resumes.
The tick's `result_summary` reports `prefetches_planned`,
`prefetches_enqueued`, and `prefetches_deduped` separately, so the
operator sees actual warming rather than planner intent.

Because `"scheduled"` is not the cascade-internal trigger source, a
scheduled leaf is a seed: when the repository also lists
`transitive_deps`, the root's ingest fires the cascade hook and the
dependency tree follows — the identical path a client pull takes.

## One constructor for the logical path

The artifacts projection is keyed on `(repository_id, coords.path)`,
so every site that writes a row must produce the exact string the
read-side lookup computes — or the row is unreachable and its
quarantine state splits from the package's identity.
`FormatHandler::build_artifact_logical_path`
(`crates/hort-domain/src/ports/format_handler.rs`) is the single
constructor for that string: it embeds `normalize_name(name)` — the
registry's own identity rule (PEP 503 for PyPI, lowercase-only for
cargo, case-preserving for npm) — as the name segment and assembles
the format's path shape. `parse_download_path` (the read side),
publish, on-demand pull, and the prefetch leaf
(`prefetch_ingest.rs`, `leaf_logical_path`) all delegate to it,
so read and write cannot drift apart. The default implementation
fails loudly (`Err(Validation)`) for formats without a logical-path
projection (OCI is digest-addressed), rather than writing a wrong
path.

Two invariants ride on this. Identity collapses to the protocol rule —
`Foo.Bar`, `foo_bar`, and `foo-bar` are one PyPI row with one
quarantine verdict, while npm's case-sensitive names stay distinct —
with `name_as_published` retaining the as-typed spelling for display
and audit. And the path's basename stays the verbatim upstream
filename, because the upstream-checksum match
(`parse_upstream_checksum` matching the metadata's `urls[]` entry by
filename) reads it; normalisation applies to the directory segments,
never the file segment.

## No gate bypass

Every byte the pipeline warms enters through
`IngestUseCase::ingest_verified` with an upstream-published checksum
as the integrity target — the same mandatory upstream verification
every pull-through fetch carries
([ADR 0006](../../adr/0006-mandatory-upstream-verification.md)). From
there the artifact flows the normal lifecycle: quarantine per the
repository's scan policy, scanning, and the fail-closed release
predicate ([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)).
There is no prefetch-specific trust shortcut, no reduced observation
window, and no release-gate input the pipeline can influence. Prefetch
is purely a scheduling optimisation on top of an unchanged security
pipeline — which is exactly why it is safe to leave it opt-in,
best-effort, and starvable.

## Related pages

- [Format handlers](format-handlers.md) — the `FormatHandler` port the
  pipeline leans on (`normalize_name`, `build_pull_url`,
  `parse_upstream_checksum`, `extract_dependency_specs`,
  `resolve_range_max`).
- [Content-addressable storage](cas-storage.md) — where the warmed
  bytes land.
- [Event sourcing](event-sourcing.md) — the lifecycle events a
  prefetched artifact emits like any other ingest.
