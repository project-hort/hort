# 172 — Maven `extract_dependency_specs`: the POM's own dependencies

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` · Item 2 of 3
(depends on item 171 only in ordering, not in code).

## Problem

Maven is the one proxied format with no warm-up path. OCI images are
enumerable in advance; npm, PyPI and cargo self-warm through the transitive
cascade. Maven has neither, so a non-zero quarantine window on a Maven proxy
means a resolver failure that reads like a broken POM, with nothing an operator
can do but build the tree a day early.

Measured on the operator's instance the day this was filed: `npm-public` 1,899
artifacts, `crates-proxy` 1,845, `docker-io` 629, **`maven-central` 12**.

## The contract fixes the scope — this is not a judgement call

`FormatHandler::extract_dependency_specs(&self, content: &mut dyn Read)` is a
pure function over **one artifact's own bytes**, read from local storage by the
cascade before the call. It holds no port, no client, no fetcher.

So a Maven implementation structurally **cannot** reach a parent POM or an
imported BOM. The first cut is not a pragmatic subset somebody chose; it is
exactly what the trait permits. Anything beyond it needs a contract change, and
the shapes such a change could take are recorded on the issue — do not attempt
one here.

## Governing decisions

- **ADR 0053 D5** settles scopes: cargo `[dependencies]`, npm `dependencies`,
  PyPI `requires-dist`, **Maven compile scope** — runtime declaration classes
  only. `test` and `provided` are excluded by an existing decision, not by a new
  one.
- **ADR 0053 D2** — resolution picks the range maximum at ingest time; a range
  upstream cannot satisfy is skipped and logged, never guessed at.
- **ADR 0005** — `VersionDiscovery` is a capability group; a format that
  declares it should implement the whole group rather than a defaulted no-op.

## Read first

- `crates/hort-domain/src/ports/format_handler.rs` — the `VersionDiscovery`
  trait in full, especially `extract_dependency_specs`'s doc on what `Err`
  means (structurally invalid input) versus `Ok(vec![])` (well-formed, nothing
  declared). Getting that distinction wrong turns a POM this cut cannot fully
  resolve into a cascade abort.
- `crates/hort-formats/src/npm.rs`, `cargo.rs`, `pypi.rs` — the three existing
  implementations and how each returns `Some(self)`.
- `crates/hort-app/src/task_handlers/prefetch_dependencies.rs` — the consumer,
  its bounds (`transitive_depth`, `max_descendants`) and its per-leaf failure
  isolation.
- `crates/hort-formats/src/maven.rs` — whatever POM handling already exists.

## What to build

`VersionDiscovery` for the Maven handler, with `extract_dependency_specs`
reading the POM's own `<dependencies>` block:

- **Properties** resolved from that POM's own `<properties>` plus the built-ins
  computable from the POM itself (`${project.version}`, `${project.groupId}`
  and their `pom.`-prefixed spellings).
- **Compile scope only**, per ADR 0053 D5. Treat an absent `<scope>` as
  compile, which is Maven's own default.
- **Everything else skipped, with its reason recorded** — an unresolvable
  property, a version that lives in a parent or an imported BOM, an unsupported
  range. A skip is a normal outcome, never an `Err`.
- **`Err` is reserved for structurally invalid input** — bytes that are not a
  POM, unparseable XML. A POM whose versions all live in a parent is *valid*
  and yields `Ok` with everything skipped.

## The skip count is the contract, not telemetry

This cut structurally cannot see parent POMs or imported BOMs, and that is
exactly where a Spring Boot tree keeps most of its versions. An operator who
sets the policy believes the tree is warmed. The count of what was skipped, and
why, is the only thing standing between them and a policy that quietly warms a
fraction of it.

So: the skip reasons are part of this item's acceptance, not a follow-up.
Item 173 surfaces them in the metrics catalogue and the docs; this item must
produce them, distinguishably, per reason.

## Explicitly not in this item

- Parent-chain resolution, BOM imports, or any fetch from inside the handler.
- Any change to `extract_dependency_specs`'s signature or to the trait.
- A general Maven resolver. Range handling beyond what `resolve_range_max`
  already offers is out of scope; an unsupported range is a counted skip.
- The metrics catalogue and documentation (item 173).

## Acceptance

- The Maven handler returns `Some(self)` from `version_discovery()`.
- A flat POM with literal versions yields every compile-scope dependency.
- A POM using its own `<properties>` resolves them.
- `test` and `provided` dependencies are absent from the result.
- A dependency whose version lives in a parent or a BOM import is skipped and
  counted under a reason distinguishable from an unresolvable property.
- A POM that declares no dependencies returns `Ok(vec![])`, not `Err`.
- Non-POM bytes return `Err`.
- `hort-formats` coverage ≥ 85%.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
