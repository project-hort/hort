# 173 — make the Maven cascade's ceiling visible

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` · Item 3 of 3
(depends on item 172).

## Problem

Item 172 ships a resolver that structurally cannot see parent POMs or imported
BOMs — which is where a Spring Boot tree keeps most of its versions. The risk
is not that it warms too little; it is that an operator sets `prefetchPolicy`,
believes the tree is warm, and still gets stalls with nothing to look at.

This item is what makes the partial resolver honest. It is not a formality and
should not be treated as one.

## Governing decisions

- **ADR 0015** — the reason a half-working operator surface needs its limits
  visible rather than inferred.
- **ADR 0053** — the cascade's own documented posture, which the pull-through
  docs already describe for the other formats.

## Read first

- `docs/metrics-catalog.md` — the existing counter conventions and how other
  skip/failure reasons are labelled.
- `docs/architecture/explanation/prefetch-pipeline.md` — where the cascade's
  behaviour is explained for npm, PyPI and cargo.
- The pull-through how-to that covers proxied-format warm-up.
- Item 172's skip reasons, which this item surfaces rather than invents.

## What to write

**Metrics.** Item 172's skip reasons reach the metrics catalogue as documented,
labelled outcomes — an unresolvable property, a version deferred to a parent or
a BOM import, an unsupported range. An operator watching a Maven proxy must be
able to answer "how much of my tree is the cascade actually reaching" from
metrics alone, without reading logs.

**Documentation.** State plainly, on the page an operator reads before enabling
this, what the Maven cascade reaches and what it does not: the POM's own
dependencies with its own properties, compile scope; not parent POMs, not
imported BOMs. Say that a project which keeps its versions in a parent or a BOM
will see a high skip count and a correspondingly cold tree, and that the metric
is where to look.

Do not soften it. An operator who learns the ceiling from the documentation
loses nothing; one who learns it from a stalled build in a release window loses
a day, which is the exact failure this whole issue exists to prevent.

**Record the ceiling as a known one.** Note that reaching beyond a single POM
requires a change to the `VersionDiscovery` contract rather than more effort, so
a future reader understands the boundary is architectural and deliberate.

## Explicitly not in this item

- Any code change to the resolver.
- Any new metric that item 172 does not already produce.
- A new documentation page. Extend the pages that already cover the cascade.

## The two skip classes must not be presented as one

`PomSkipReason` now carries five reasons, and they fall into **two classes an
operator must be able to tell apart**:

- `scope_excluded` is a **deliberate class boundary**. Nothing is wrong; the
  cascade is declining to warm `provided` / `test` / `system` / `import`
  dependencies on purpose (ADR 0053 D4/D5). A high count here is normal and
  explains why the warmed set is smaller than the dependency list an operator
  reads in their POM.
- The other four are **limits of a reader that cannot see parent POMs or
  imported BOMs**. A high count here means the tree really was only partly
  reached.

Collapsing them into one "skipped" number is what makes the signal useless in
both directions: a healthy cascade looks broken, and a half-blind one looks
fine. The catalogue entry and the operator page must state the split, not
merely list five reasons side by side.


## A third conflation to resolve: "could not ask" vs "asked and got nothing"

The cold cohort now folds a per-package **routing dead-end** — the handler
declined to name an upstream metadata path at all — into
`deps_upstream_unsatisfiable`, the same counter that means "we fetched and
upstream had no satisfying version". Those are different problems wearing one
number: the first is a capability or configuration gap on our side, the second
is a fact about upstream. An operator who cannot tell them apart will go
looking upstream for a cause that is local.

This is the same principle as the scope split above, so resolve it the same
way — either a distinct counter or a reason label on the existing one. The
call site is the `None` arm of the metadata-path lookup in
`prefetch_dependencies.rs`'s cold pass; it is a one-field addition plus a
`to_json` line, deliberately not added speculatively when the routing fix
landed.


## Acceptance

- Every skip reason appears in the metrics catalogue with its meaning, and
  each is identified as either a deliberate class boundary or a reader limit.
- The operator page states the two-class split explicitly, so a `scope_excluded`
  count is never read as a coverage gap.
- The operator-facing page states the ceiling explicitly, including the
  parent-POM and BOM-import cases by name.
- The architectural reason for the ceiling is recorded.
- A routing dead-end is distinguishable from an upstream-unsatisfiable
  outcome, by a separate counter or a reason label.
- Prose and catalogue are the bulk of this item; the only permitted `.rs`
  change is the counter/label needed for the distinction above and its test.
