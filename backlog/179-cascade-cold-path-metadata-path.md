# 179 — the cascade's cold path composes the wrong upstream URL

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` ·
follows items 172 and 178.

## Problem

`transitive_deps` on a Maven proxy is now accepted at apply and the
dependency extraction works, but the cascade's cold path cannot fetch
anything for Maven, so the trigger still warms almost nothing.

`crates/hort-app/src/task_handlers/prefetch_dependencies.rs` has a
module-scope pair of helpers, `upstream_metadata_path_for` and
`upstream_accept_for`. The first special-cases PyPI and otherwise falls
through to `handler.upstream_checksum_metadata_path(&coords)` with
`version: None` and an empty `path`, then `unwrap_or_else(|| format!("/{package}"))`.

For Maven that inner call returns `None` by design — there is no
per-artifact checksum document for a catalog-level request — so the helper
composes `/com.example:foo`, which cannot 200 against any Maven upstream.
Pass 1 (the held set) works; Pass 2 (the cold set) marks every dependency
`deps_upstream_unsatisfiable`. On a proxy holding a dozen artifacts nearly
the whole tree is cold, so the cascade's observable value is close to zero
even though the reader itself is complete.

**This is drift, not a design choice.** Both helpers' docs say they mirror
`prefetch_tick::upstream_metadata_path_for` / `::upstream_accept_for`, and
the section header says the two handlers are kept "in lock-step". Those
`prefetch_tick` functions **no longer exist** — that handler now calls
`vd.upstream_metadata_path(package)` and `vd.upstream_metadata_accept()`
directly, which is what those `VersionDiscovery` members are for. The
cascade kept the copy after the original was replaced.

## What to change

Have `prefetch_dependencies` obtain the path and the `Accept` set from the
`VersionDiscovery` trait, exactly as `prefetch_tick` does, and delete both
local helpers along with the stale "mirrors …" and "lock-step" comments.

Two consequences to confirm rather than assume:

- The PyPI special case becomes redundant — `PyPiFormatHandler::upstream_metadata_path`
  already returns `/simple/{normalized}/`. Check it, then remove the arm;
  do not leave a special case that shadows the trait.
- npm and cargo are unaffected: their metadata-index and
  checksum-metadata paths coincide, which the trait doc calls out as a
  documented coincidence rather than a rule. Pin that with a test so the
  coincidence cannot silently become load-bearing again.

The handler here is reached the same way `prefetch_tick` reaches it, so
route through `version_discovery()` and skip a non-participating format on
the same terms — a format that reaches the cascade without the capability
should not fall back to a guessed URL.

## Read first

- `crates/hort-app/src/task_handlers/prefetch_dependencies.rs` — the two
  helpers at module scope and their call sites in the cold-cohort pass.
- `crates/hort-app/src/task_handlers/prefetch_tick.rs` — how the same two
  values are obtained from `vd`, including the `None` skip and its log.
- `crates/hort-domain/src/ports/format_handler.rs` — `upstream_metadata_path`
  and `upstream_metadata_accept`, and the note distinguishing them from
  `upstream_checksum_metadata_path`.

## Acceptance

- No local metadata-path or accept helper remains in
  `prefetch_dependencies.rs`; both come from `VersionDiscovery`.
- A test drives the cold cohort for a Maven repository and asserts the
  fetched path is the A-level `maven-metadata.xml` path the handler
  returns — not `/{package}`, and not a checksum path.
- Tests pin the npm, cargo and pypi paths as unchanged by this refactor.
- A cascade over a Maven proxy whose dependencies are all cold enqueues
  those dependencies instead of reporting them
  `deps_upstream_unsatisfiable`.
- Full local gate green per the pre-push checklist, `DATABASE_URL` set.
