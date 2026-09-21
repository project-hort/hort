# 177 — `runtime` scope is a runtime declaration class

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` · follows item 172.

## Problem

`crates/hort-formats/src/maven/pom.rs` emits a dependency only when its
effective scope is exactly `compile`, and counts every other scope as a
`ScopeExcluded` skip. That came from item 172's directive, which said
"compile scope only" — **that wording was wrong, and the error is the
directive's, not the implementation's.** The implementation followed it
faithfully and flagged the tension in its report.

ADR 0053 D5 states the boundary as **"runtime declaration classes only"**
and then names `Maven compile scope` as its example. The example is
shorthand for Maven's *default* scope, not an enumeration. Maven's
`runtime` scope — the JDBC-driver case: not needed to compile, required to
run — is squarely a runtime declaration class, and Maven **does** propagate
it transitively to consumers. Excluding it means the cascade silently omits
real closure members from every tree it warms, which is the same class of
under-warming the issue exists to fix.

## What to change

In `pom.rs`, treat the emitted set as `{compile, runtime}` — an absent
`<scope>` still defaults to `compile`.

Everything else stays excluded, and for reasons worth keeping distinct:

- `provided` — the container supplies it at run time and Maven does not
  propagate it transitively. Build-time closure; ADR 0053 D4 rejects
  inflating the fan-out by that closure.
- `test` — the dev/test closure D5 explicitly keeps out.
- `system` — names a local file path, so there is no upstream artifact to
  warm at all.
- `import` — only meaningful inside `<dependencyManagement>` as a BOM
  import, which this reader deliberately does not resolve.

## Explicitly NOT changing: `<optional>true</optional>` stays included

Item 172's report raised this as an open question. **The answer is to keep
it as implemented**, and the module doc's reasoning is the right one: ADR
0053 D5 draws its class boundary at *scope*, not at optionality, and the
cost is asymmetric — warming an extra artifact costs storage, while failing
to warm one a consumer opts into costs a resolver failure against a cold
proxy. Do not turn this into a fifth skip reason.

## Read first

- `crates/hort-formats/src/maven/pom.rs` — `SCOPE_COMPILE`, the scope
  branch around the `declared_scope` / managed-entry resolution, and the
  module doc's scope bullet.
- `docs/adr/0053-dependency-ranges-resolve-and-pin.md` — D4 and D5.

## Acceptance

- A `<scope>runtime</scope>` dependency with a resolvable version is
  emitted as a `DependencySpec`, and is **not** counted as a skip.
- `provided`, `test`, `system` and `import` remain counted scope skips.
- An absent `<scope>` still resolves to `compile` and is emitted.
- A managed `<scope>` from this POM's own `<dependencyManagement>` still
  applies when the dependency declares none, and a declared scope still
  wins over the managed one — both for `runtime` as well as `compile`.
- The module doc's scope bullet and the `SCOPE_COMPILE` naming are updated
  so the constant no longer implies a single permitted scope.
- Coverage on `pom.rs` stays at its current level (99 %+).

## Note for the ADR

ADR 0053 D5's phrase `Maven compile scope` is what made this
misreading available, and it should read `Maven compile and runtime
scopes`. **Do not edit the ADR in this item** — ADR changes need the
human's answer first, and that question is being put to them separately.
