# 181 — two ADR corrections the Maven prefetch work made necessary

**Issue:** #234 · **Branch:** `agent/234-adr-text-corrections` · single item.

**Documentation only.** The behaviour already shipped and is merged; this
writes down what was decided.

## 1. ADR 0053 D5 — `Maven compile scope` is shorthand, and it misled

D5 states the boundary as **"runtime declaration classes only"**, then names
one example per format: cargo `[dependencies]`, npm `dependencies`, PyPI
`requires-dist`, `Maven compile scope`. For the first three the example *is*
the whole class. For Maven it is not — Maven splits that class across
`compile` and `runtime`, and `runtime` (the JDBC-driver case: not needed to
build, required to run) is propagated transitively to consumers.

A literal reading of the example therefore contradicts the principle stated
in the same sentence. It already did: an implementation directive said
"compile scope only" on the strength of it, and the resulting reader dropped
runtime-scoped dependencies from every warmed tree until it was corrected.

**Confirmed reading: compile + runtime.** `provided`, `test`, `system` and
`import` stay outside — `provided` and `test` are build/test closure that D4
rejects inflating the fan-out with, `system` names a local file path with no
upstream artifact, and `import` is a BOM reference the reader does not
resolve.

**The edit:** D5's example reads `Maven compile and runtime scopes`, so the
shorthand cannot be misread the same way again.

## 2. ADR 0032 — discharge the deferral, but **keep** the hard-block

ADR 0032's *Design integrity* section does not merely defer Maven Phase-2
prefetch. It records a **hard-block**: "A new Maven-shaped abstraction, or a
`match format { Maven => … }` arm in shared dispatch, was an explicit
hard-block — none was introduced." Three specific facts are its evidence: no
Maven arm in `prefetch_tick` / `self_service_prefetch_use_case`
`ordering_for_format`, no Maven branch in the `hort-formats-upstream`
dispatch, and no Maven branch in the shared ingest core.

The first two are now false. **The hard-block is not lifted, and the
amendment must not read as though it were** — an amendment that sounds like
the block was retired quietly licenses the next Maven-shaped branch. That
distinction is the entire point of this edit.

- **The two `ordering_for_format` arms no longer exist to have a Maven
  case**: the duplicated matches were collapsed into one canonical mapping,
  where Maven resolves `MavenVersionOrdering` exactly as npm resolves
  `NpmSemverOrdering`. Equal footing, not a special case. A parity guard now
  asserts that declaring the capability group and resolving an ordering
  cannot diverge, so participation is enforced structurally rather than by
  the absence the old text relied on.
- **The `hort-formats-upstream` Maven branch is genuinely differently
  shaped**, and the ADR must say so rather than smooth it over. npm, PyPI and
  cargo route through a per-format `fetch_raw_with_cache` that owns ephemeral
  caching and pull-dedup; Maven calls `UpstreamProxy::fetch_metadata`
  directly, because nothing caches `maven-metadata.xml` and there is no typed
  projection to read a version list from. That is exactly the asymmetry the
  hard-block exists to prevent, it is live today, and it is tracked as an
  open integrity item (issue #235) — which the amendment names.

**The edit:** an amendment block on ADR 0032 recording that the Phase-2
deferral is discharged; that the two `ordering_for_format` facts are
superseded by a single canonical mapping in which Maven participates on
equal footing; that the hard-block on Maven-shaped abstractions **stands**;
and that one branch currently strains it, named with its tracking issue.

## 3. Index rows

`docs/adr/0000-historical-decisions-index.md` must agree with both amended
ADRs. The *Maven Phase-2 prefetch* open-item row is already closed. Check the
0032 and 0053 decision rows for any repetition of the corrected claims.

## Read first

- `docs/adr/0053-dependency-ranges-resolve-and-pin.md` — D4 and D5.
- `docs/adr/0032-maven-gradle-multi-file-handler.md` — the *Design integrity*
  section and its three-fact list.
- `docs/adr/0000-historical-decisions-index.md` — the 0032 and 0053 rows.
- `crates/hort-app/src/use_cases/index_serve_filter.rs` — the canonical
  `ordering_for_format`, so the amendment describes what is actually there.
- `crates/hort-formats-upstream/src/lib.rs` — the Maven `list_versions`
  branch and its three differently-shaped siblings.

## Acceptance

- ADR 0053 D5's example names compile **and** runtime scopes.
- ADR 0032 carries an amendment block that discharges the deferral,
  supersedes the two false facts, and **explicitly preserves** the
  hard-block rather than retiring it.
- That amendment names the `hort-formats-upstream` asymmetry as an open
  integrity item.
- No index row contradicts either amended ADR.
- Docs only: `git diff --stat` shows no `.rs` change.
