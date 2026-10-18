# 280 — A guard holds the publish chain's gating edges

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0030 (structural guards on the sensitive surface
— the family this joins) · ADR 0048 / ADR 0051 (what a published artifact
asserts) · ADR 0016 (fail-closed, no degraded path).

## Why this unit exists at all

Units 276, 277 and 278 added the three edges the audit asked for. **None of
them is verifiable here**: these workflows run only on GitHub, so neither the
sandbox gate nor the project's compose E2E executes them. Each run therefore
proved its edge with a throwaway script in `/tmp` and threw it away — which is
the correct shape for a one-off proof and no protection at all against the
next edit.

And the next edit is the whole problem this audit has been documenting. Every
finding in it has the same shape: a mechanism that is correct where it runs and
was never carried to new surface, because nothing re-checked the claim. A
`needs:` edge is exactly that kind of claim. Removing one is a one-line diff
that no test, no linter and no pipeline in this repository would notice.

So this unit turns the predicate the previous two runs built into a checked-in
test. It is the only unit of Block 3 that makes the other three durable.

## What to build

`crates/hort-app/tests/publish_chain_is_gated.rs` — a DB-free, sub-second
source scan in the family of `expand_contract_guard`, `no_sensitive_drops`,
`capped_stream_reads` and `status_decode_fails_closed`. Being a `tests/`
target means `cargo test --workspace` runs it with no gate-list entry, which is
what CLAUDE.md asks of a new structural guard.

### The precedent to follow, and the dependency question it settles

`expand_contract_guard` already reads a checked-in non-Rust file outside its
own crate: `workspace_root().join("migrations")`, via `CARGO_MANIFEST_DIR`.
Reuse that idiom for `.github/workflows/`.

Parse the YAML with **`serde_yaml_ng`**, already a workspace dependency (root
`Cargo.toml`, used by `hort-config`), added here as a `hort-app`
`[dev-dependencies]` entry. The rationale is the one that crate's sibling
already carries, verbatim in spirit — `hort-app`'s `toml` dev-dep says:

> Hand-rolling a TOML subset parser would make the guard's own input format the
> least-trusted part of a fail-closed guard

The same holds doubly for YAML, where `needs:` may be a flow sequence or a
block sequence and an `if:` expression may be folded across lines. **Check that
this adds no new `[[package]]` to `Cargo.lock`** — it should not, the crate is
already there — and say so in the report, because a new third-party package
would oblige an attribution regeneration (ADR 0047 / ADR 0049).

### The three assertions

For `.github/workflows/docker-publish.yml` and `.github/workflows/release.yml`,
for every job classified as publishing:

1. Its **effective** `needs:` closure reaches `ci-gate`.
2. In `docker-publish.yml`, it also reaches `scan-containers`.
3. Its **effective** run condition requires a `refs/tags/v` ref.

**Assert (3) per job, not only over the closure.** Unit 278's counter-tests
showed why: a chain whose *root* is gated makes every mid-chain removal look
fine, so three separate mutations passed a closure-only walk. Each publishing
job states the condition itself today; the guard holds that, not a weaker
property.

**And `requires_ref()` must refuse to credit a disjunction or a negation.**
Turning `startsWith(github.ref, 'refs/tags/v') && X` into
`startsWith(github.ref, 'refs/tags/v') || X` is a one-character edit that
re-opens the entire finding and reads as gated to any grep. Unit 278's
counter-test L is exactly that edit — carry it over.

### No allow-list. Derive the exemption or do without it

CLAUDE.md is explicit for this family: `db_tests_are_serialized` and
`status_decode_fails_closed` have **no allow-list, by design** — a site that
genuinely should not be flagged is a review conversation, not an entry in a
table. That rule is the whole reason this unit exists as its own unit, and
there is one case that will tempt you to break it.

Classifying a job by the text it executes has to fold in the text of a `uses:`
callee, or a job that publishes *through* a reusable workflow reads as inert.
Fold it in, and `ci-gate` (`uses: ./ci.yml`) inherits the markers of ci.yml's
own verify `build-binaries` — which calls `build-binaries.yml`, where
`cosign sign-blob` lives. So `ci-gate` classifies as a signing job, which is
false in fact: ci.yml's verify build carries `if: ${{ !inputs.gate_for && … }}`
and both callers pass a non-empty `gate_for`, so that job cannot run on a gate
pass at all.

Unit 278 handled it with a printed note plus a `gate_exempt` list. Unit 279
**replaced that with a derived rule**: skip a callee job whose `if:` contains
`!inputs.<name>` when the caller passes a non-empty literal for `<name>`. Carry
the derived rule, not the list. It is conservative in the safe direction —
only that one syntactic form is evaluated, anything else counts as reachable,
so being wrong demands a ref condition that is not needed and can never excuse
a missing one.

**"Effective", not declared — this is the part that matters most.** Unit 277
established it: a job whose `if:` contains `always()` runs even when a `needs:`
entry failed, so that edge only gates if the `if:` *also* tests that entry's
result. The `release` job's `sbom` edge was exactly this — present in `needs:`,
voided by `always()`, decorative. A guard that walks declared `needs:` would
have called the pre-277 tree correctly gated. Walk declared edges minus the
ones an `always()` voids, and fold in a job's own `if:` plus every `if:` it
inherits.

### The counter-assertions, without which the guard can go vacuously green

The family's own convention (`capped_stream_reads` and
`status_decode_fails_closed` both carry one): prove the corpus is real, so a
rename cannot empty the scan and pass.

- Both workflow files exist and parse, with a non-trivial job count.
- `ci-gate` exists in both files and `scan-containers` in `docker-publish.yml`,
  **by name** — if a rename makes a gate invisible, assertions 1–3 would
  otherwise become vacuous rather than failing.
- The publisher classification finds **at least** the jobs known to publish
  today, named explicitly: `merge`, `publish-chart`, `mirror-to-hort-oci`,
  `mirror-to-hort-base`, `publish-chart-registry-hort-rs` in
  `docker-publish.yml`, and `build-binaries`, `sbom`, `release`, `hort-publish`
  in `release.yml`. A rename that hides a publisher from the markers then fails
  *this* assertion instead of silently shrinking the set the other three check.
- **The ungated set is pinned, and it is nearly empty.** In `release.yml` every
  job now carries the ref condition, including `ci-gate` and `e2e-gate` — so
  the expected ungated set there is **empty**. In `docker-publish.yml` it is
  exactly `summary`, the reporter, which keeps `if: always()` deliberately so
  it can explain a held chain. Pin both. A new ungated job then has to be
  argued for in review rather than appearing quietly.

### State the blind spots in the module doc

Honestly and in full, because the next reader has to know what the green does
not cover:

- **The publisher markers are a list.** A genuinely new publishing mechanism —
  a new action, a new CLI — is invisible until its marker is added. The
  known-set counter-assertion catches a *rename*; it cannot catch a *new
  mechanism*. Say so.
- Classification that reads a job's text folds in the text of a `uses:` callee,
  which is why the gate jobs themselves must be excluded by name rather than by
  pattern.
- The guard reads the files as checked in. It cannot know GitHub's evaluation
  semantics, and it cannot see repository settings — notably whether the
  `release` environment has required reviewers, which is the half of unit 278
  that lives outside this tree.

## Explicitly out of scope

- Any change to the three workflows. If the guard goes red on the tree as
  committed, that is a finding to report, not a workflow to adjust.
- `ci.yml`, `e2e.yml`, `build-binaries.yml` and the other workflows. The
  invariant is about the two publish workflows.
- Any assertion about GitLab CI.
- Extending the guard to the installers or the site publish.

## Verification

This unit **does** touch `crates/` and `Cargo.toml`, so unlike units 276–278
the full gate applies: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit -D
warnings`, `cargo-deny check` — in the foreground, exit codes captured
separately from the output, no masking pipe. Bounce the sidecars first for a
clean database baseline if the tooling allows it; either way, count the
`hort_test_*` databases afterwards and put the number in the report as evidence
the DB suites ran.

Beyond the gate:

- **Mutation-test every assertion.** For each of the three, mutate the tree so
  it should fail, show that it does, and revert. At minimum: drop
  `scan-containers` from `merge`'s `needs:`; drop `ci-gate` from
  `build-binaries`'s `needs:`; add an `always()` that voids a gating edge; drop
  the ref condition from one publishing job; rename `scan-containers`. A guard
  whose failure path has never run is not a guard.
- Confirm the target is DB-free and sub-second, and that it runs under a bare
  `cargo test --workspace` with no `DATABASE_URL`.
- Report whether `Cargo.lock` gained any `[[package]]` entry (expected: none).

## Acceptance

- The guard asserts all three edges over both workflows, walking **effective**
  needs and conditions.
- Every assertion has a demonstrated failing mutation, in the report.
- The counter-assertions are present and the known publisher set is named.
- The module doc states the three blind spots.
- `cargo test --workspace` runs it with no gate-list entry and no database.
- No new `[[package]]` in `Cargo.lock`; no change to the workflows.
