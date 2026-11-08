# 400 — The parent is an edge

**Issue:** #418 · **Branch:** `agent/418-the-parent-is-an-edge` · single item.

**Governing decisions:** ADR 0053 D5 (compile + runtime are the emitted
scopes — **untouched here**, and the parent is outside it because it has no
scope at all) · ADR 0053 D2 (a range upstream cannot satisfy is skipped and
counted, never guessed) · ADR 0026 (the streaming metadata contract the reader
signature rests on).

## The property

**A POM's `<parent>` is an edge of the transitive-prefetch walk.** Today it is
not, so the cascade warms a tree whose root is still cold, and a Maven build
advances exactly one link of its parent chain per quarantine window.

## What was measured, and what it means

The reporting instance observed `maven-install-plugin:3.2.0` ingest and produce
exactly **one** prefetch job. Its parent `maven-plugins:49` got its first row
**35 hours later**, written by the build itself rather than the cascade. The
chain is `maven-install-plugin:3.2.0 → maven-plugins:49 → maven-parent:49 →
apache:39`: four links, four windows, serialised — and the one dependency that
*was* warmed bought the build nothing, because without the parent it never
reaches the dependency list at all.

**The ticket's "1 of 16 edges" is not the acceptance criterion and must not be
read as one.** Of those 16: **12** are `provided` or `test`, excluded by
ADR 0053 D5 because Maven does not propagate them transitively; **2** are
`compile` whose version lives in the parent's `dependencyManagement`, a
documented and counted `PomSkipReason::VersionFromParentOrBom`; **1** resolved
locally and was warmed; **1** is the parent. Of the edges this reader is
designed to emit, it emitted 1 of 1. Widening the scope set is an ADR change,
not this unit — if the implementation finds itself touching `EMITTED_SCOPES`,
it has left the item.

## Why this is reachable from here at all

`crates/hort-formats/src/maven/pom.rs` is a pure function over **one
artifact's own bytes** — no port, no HTTP client, no fetcher — which is why a
version held by a parent POM or an imported BOM is structurally out of reach
and is counted rather than resolved. The parent *coordinate* is different: a
`<parent>` block spells out groupId, artifactId and version, all three, in the
POM in front of the reader. So emitting it needs no parent walk and does not
weaken the purity contract.

(That is a property of the Maven POM schema. The comment on
`RawPom::artifact_id` says something narrower — that `<project><artifactId>` is
never inherited from a parent — and is not evidence for this.)

## The shape

1. **Add `parent_artifact_id` to `RawPom` and fill it in the XML reader.** It
   does not exist today: the struct carries `parent_group_id` and
   `parent_version` only, because both exist solely as fallbacks for the
   project's own coordinates and the artifactId never needed one. This step is
   the reason the unit is not a one-line push.
2. **Emit the parent as a `DependencySpec`** — `name` = `groupId:artifactId`,
   `range` = the literal `<parent><version>` — alongside the `<dependencies>`
   specs.
3. **The scope filter must not see it.** A `<parent>` has no `<scope>`, so
   routing it through the `EMITTED_SCOPES` check would drop it as
   `ScopeExcluded` and reproduce the defect in a new place.
4. **Property interpolation applies.** A `<parent><version>` may be written as
   a property in principle; if it does not resolve from this POM's own bytes it
   is an `UnresolvedProperty` skip, exactly like a dependency's.
5. **An incomplete `<parent>` is a counted skip, not an error.** Any of the
   three parts missing → `PomSkipReason::IncompleteCoordinate`, which already
   means "structurally incomplete rather than deferred". Do not add a variant
   for it; the existing one says the right thing.
6. **A version range in `<parent><version>`** follows ADR 0053 D2 —
   `UnsupportedRange`, skipped and counted, never guessed.

## The budget question, decided

The parent **participates in the descendant budget and the depth bound like any
other edge.** It is tempting to exempt it — it is a precondition, not a leaf —
but an exemption would make the one unbounded edge in the walk the one that
recurses deepest, since parent chains nest and each parent has a parent. The
bound exists to stop exactly that. A deep chain therefore still costs several
windows in the worst case; what this unit removes is that the chain was not
being walked **at all**.

What it may do is go **first**: the parent is emitted ahead of the
`<dependencies>` specs so that, under a budget that truncates, the edge the POM
cannot be interpolated without is the one that survives. That is ordering
within the existing bound, not an exemption from it.

## Out of scope

- `EMITTED_SCOPES` and the scope policy (ADR 0053 D5).
- Resolving versions held by a parent or an imported BOM — still structurally
  out of reach, still a counted skip. This unit warms the parent *artifact*; it
  does not make the parent's `dependencyManagement` readable.
- The self-service prefetch endpoint's metadata caching (#235) — adjacent area,
  no overlap.
- Any change to quarantine windows or the cascade's trigger set.

## Acceptance

- A POM with a `<parent>` yields a spec for the parent coordinate. A test
  shows it, using a POM whose `<dependencies>` is empty, so the parent edge is
  the only thing the assertion can be reading.
- The parent spec is emitted **first**.
- A `<parent>` missing any of groupId / artifactId / version yields an
  `IncompleteCoordinate` skip and no spec.
- A `<parent><version>` that is a property resolvable from this POM's own
  `<properties>` resolves; one that is not is an `UnresolvedProperty` skip.
- A POM with **no** `<parent>` is unchanged — no spec, no skip record.
- `provided` / `test` dependencies are still excluded, and the existing scope
  tests pass untouched.
- The module header's "what this reader can see" list gains the parent edge,
  since that list is the contract a reader checks first.
- Gate green, workspace suite run **once**.
