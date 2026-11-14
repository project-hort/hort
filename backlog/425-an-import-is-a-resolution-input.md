# 425 — An import is a resolution input, not a dependency

**Issue:** #439 · **Branch:** `agent/439-an-import-is-a-resolution-input` ·
the only item. **No ADR change** — this brings one edge class into line with a
carve-out already decided for its sibling. No migration.

**Governing decisions:** ADR 0053 D5 (the cascade warms *runtime declaration
classes* only; for Maven, compile and runtime scopes — **not amended here**,
see below), #418 / MR !853 (the `<parent>` edge entered the edge set on the
argument that it is a precondition of resolvability rather than an optional
dependency), ADR 0007 (untouched).

**Why this does not amend D5.** D5 bounds which *dependency declarations* the
cascade resolves and warms. A `<dependencyManagement>` entry with
`<type>pom</type><scope>import</scope>` is not a dependency of the project at
all: Maven requires it to carry `type=pom`, and its effect is to supply
versions. It belongs with `<parent>` — an input the POM cannot be resolved
without — and `<parent>` already stands outside D5's scope filter for exactly
that reason (the rationale sits above the `resolve_parent` call,
`crates/hort-formats/src/maven/pom.rs:782-786`). Filing `import` alongside
`test` / `provided` / `system` is a category error: those three are real
dependencies outside the warmed class.

## Group A — the import edge enters the edge set

`parse_pom_dependencies` iterates `pom.dependencies`, i.e. the `<dependencies>`
block alone (`crates/hort-formats/src/maven/pom.rs:792`). `pom.managed` is only
a lookup table supplying scope and version to *those* entries (declared
`pom.rs:763`, consulted `:814`, `:824`, `:848`); a managed entry is never
emitted as a `DependencySpec`. Maven permits `scope=import` only inside
`<dependencyManagement>`, so an import edge always sits in the position the
loop does not reach.

**What to build:** a managed entry whose effective scope is `import` and whose
type is `pom` becomes an emitted `DependencySpec`, resolved by the same
interpolation rules as every other edge (its own literal version, this POM's
`<properties>`, the model built-ins, this POM's own `<dependencyManagement>`),
and skipped-and-counted under the existing reasons when those cannot reach a
version.

It is **not** exempt from the descendant budget or the depth bound — order it
with the parent edge, which is ordered first for truncation and is likewise
inside the bound, never outside it (`pom.rs:782-786`).

## Group B — the accounting says what it actually does

Two defects, both in the skip bookkeeping, and the second survives Group A.

**B1 — a claim the code cannot hold.** `EMITTED_SCOPES`' doc states that
`import` is counted as `PomSkipReason::ScopeExcluded` (`pom.rs:121`). That
cannot happen: the scope check (`pom.rs:838`) is reached only by
`<dependencies>` entries, and `scope=import` is legal only in
`<dependencyManagement>`. The test backing the claim,
`non_emitted_scopes_are_excluded_and_counted` (`pom.rs:1685`), constructs
`<scope>import</scope>` inside a plain `<dependencies>` block — an input Maven
rejects — so the one position where `import` occurs is uncovered. After
Group A the honest statement changes rather than disappears: `import` is
emitted, not excluded, and both the doc and the test's `import` case must say
so on a legal input shape.

**B2 — `0 extracted` is indistinguishable from a leaf.** A pure BOM declares no
`<dependencies>`, so there is nothing to skip and nothing to count; its walk
logs `deps_extracted=0` and reads exactly like an artifact with no edges. The
existing per-reason diagnosis is `debug!`
(`crates/hort-formats/src/maven/mod.rs:779`) and invisible at production log
level, and for this case it would be empty even at `debug`. A POM that declares
managed coordinates and emits nothing from them must say so at a level an
operator sees — the figure to carry is how many managed coordinates were
present, not a new skip reason for a non-skip.

`PomSkipReason`'s own doc gives the standard this has to meet: a deliberate
class boundary is counted too, so that *how much of my tree did the cascade
warm* stays answerable from the counters alone.

## Measurements this item is derived from

Production, hort 0.17.3, ingest of `org.junit:junit-bom:5.14.4` on a Maven
proxy with `prefetchPolicy.enabled: true`, `triggers: [transitive_deps,
on_dist_tag_move]`: `prefetch-dependencies walk complete` with
`deps_extracted=0`, `prefetch_rows_enqueued=0`, no `last_error`. The POM has no
`<parent>`, no `<dependency>` outside `<dependencyManagement>`, and 18 inside
it, every version literal — so neither the parent edge, nor property
interpolation, nor "leaf reached" explains the zero.

Staging UAT on `0.17.4-beta.6` (so with #418's parent edge and #421's candidate
filter in place), one pull of `spring-boot-starter-parent:3.3.5` producing a
two-level cascade:

| depth | walk | result |
|---|---|---|
| 0 | `spring-boot-starter-parent:3.3.5` | `deps_extracted=1`; the enqueued coordinate confirmed in the log as `spring-boot-dependencies:3.3.5` |
| 1 | `spring-boot-dependencies:3.3.5` (43 entries with `type=pom, scope=import`) | `deps_extracted=0`, `prefetch_rows_enqueued=0` — none of the 43 |

## Acceptance

- A consumer POM whose `<dependencyManagement>` imports a BOM enqueues that
  BOM's coordinate. A test pins the two-level shape from the measurement
  above: the parent edge followed, the import edge followed, and a managed
  entry that is *not* an import still not emitted.
- The import edge is inside the descendant budget and the depth bound — a test
  pins that it is truncated like any other edge rather than exempt.
- A POM that declares managed coordinates and emits nothing from them is
  distinguishable from a leaf at production log level, and the signal carries
  how many managed coordinates it saw.
- `EMITTED_SCOPES`' doc matches the code, and the `import` case of
  `non_emitted_scopes_are_excluded_and_counted` uses an input shape Maven
  accepts — or is removed in favour of a case that exercises the real
  position.
- Every match over `PomSkipReason` stays exhaustive with no wildcard.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).
  `hort-formats` is a `>= 85%` crate, but the per-change criterion is the one
  that binds.
- Gate green. No ticket, MR or backlog numbers in any code comment.

## Out of scope

- **Warming every coordinate a BOM manages** (the 18 of `junit-bom` itself).
  That is a heuristic extension outside D5 and an open maintainer decision on
  #439; it is also only worth judging after this item, since a build may
  converge on the import edge alone.
- **`VersionFromParentOrBom`** — a `<dependencies>` entry whose version lives
  in a parent or an imported BOM. It stays a counted skip: resolving it means
  reading beyond this artifact's own bytes, which is a different unit.
- No change to the scope selection for real dependencies, no digest pinning, no
  `maxDescendants` default change.
