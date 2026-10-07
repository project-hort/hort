# 279 — The release workflow's dispatch path cannot mint a tag or sign assets off a branch

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0034 (first-party posture, the `gha-release`
identity, and the `release` environment's intended rule) · ADR 0048 (release
routing) · ADR 0051 (the signature property of a released artifact) ·
ADR 0016 (the close is fail-closed rejection, never a degraded path).

## Why this item exists, and why it is not scope creep

Unit 278 closed exactly this finding in `docker-publish.yml`: a
`workflow_dispatch` from a freely chosen ref could mint and sign public
artifacts. Its backlog item put `release.yml` out of scope to keep that unit
focused. The run that implemented 278 then traced the neighbouring file and
found the same shape there, with the numbers read off the file.

Closing a finding in one file and leaving the identical shape in the file next
door is **the exact pattern this audit documents** — a mechanism correct where
it runs, never carried to the adjacent surface, because nothing re-checked the
claim. So this is one more unit of the same block, not a new concern.

## What is true today

`release.yml` triggers on `push: tags: ['v*']` **and** `workflow_dispatch`
with a `version` input. On a dispatch from a branch with `version: 2.0.0`:

- **`build-binaries` runs with `publish: true`**, which `cosign sign-blob`s
  every release asset under hort's release identity
  (`build-binaries.yml:152-167`).
- **`sbom` runs and signs too.** It does **not** carry `environment: release`;
  only `hort-publish` does (`release.yml:354`).
- **`hort-publish` is already ref-gated** in its own `if:`
  (`… && startsWith(github.ref, 'refs/tags/v') && vars.HORT_PROXY_ENABLED ==
  'true'`), so nothing reaches registry.hort.rs. That job is fine and is the
  shape the others want.
- **`release` is not ref-gated.** Its `if:` is
  `always() && needs.build-binaries.result == 'success'` (`:523`). It takes the
  tag from the dispatch input and `softprops/action-gh-release` (`:615`, with
  `contents: write`) **creates that tag**, pointing at the dispatched branch
  commit, and attaches the signed assets.
- **The release itself stays a draft**, because `all_passed` requires
  `needs.verify-images-published.result == 'success'`, that job *is* ref-gated,
  and on a branch it is `skipped`.

So: no *publication* — but a real `v2.0.0` git tag on a branch commit, and a
draft release full of cosign-signed assets. A git tag is not a draft; it is
visible to every clone and to any tooling that reads `git describe` or the tag
list. The signed blobs are real signatures over branch content carrying a
release version number.

(No workflow cascade: a tag created by a `GITHUB_TOKEN`-authenticated action
does not trigger workflows, so `docker-publish.yml` does not fire. That bounds
the blast radius; it does not make the tag or the signatures go away.)

## What to do

The same movement as unit 278, applied here.

1. **Pin the ref for everything that signs or publishes.** `build-binaries`,
   `sbom` and `release` require `startsWith(github.ref, 'refs/tags/v')`. Mind
   that `release`'s `if:` already contains `always()` — the condition must be
   added so the job genuinely cannot run off a tag, not merely so a `needs:`
   entry is listed. (Unit 277's lesson: an `always()` job's declared edges
   gate only what its `if:` tests.)
2. **The version comes from the ref, not from an input.** This mirrors what
   unit 278 did to `publish-chart`'s chart version: with the ref pinned to a
   release tag, `GITHUB_REF` already carries the version, and a separate input
   can only disagree with it. Derive it from the ref on both paths. If the
   input stays for ergonomics, it must equal the ref's version and be rejected
   loudly otherwise — the shape unit 278 gave `merge`'s `tag` input.
3. **Leave `hort-publish` alone.** It is already correct and is the in-file
   precedent for the condition.
4. **Say what the draft does and does not protect** where the gate step
   explains itself. "It stays a draft" is the current reason nothing worse
   happens, and that is a consequence of another job's ref gate, not a
   decision anyone recorded. After this change the ref condition is the
   reason, and the comment should say so.

## Explicitly out of scope

- `environment: release`'s own settings. Outside the tree; the architect has
  the question open with the human (see the note on unit 278).
- Adding `environment: release` to `sbom` or `release`. Unit 278 established
  that the declaration's protection depends on settings this repository does
  not contain, so it is not the close here either — the ref condition is.
- The `-alpha.N` question for `release.yml`. Still deliberately untouched: on
  an alpha the release stays a draft for the same `verify-images-published`
  reason, and changing that is a separate decision about what an alpha means.
- `docker-publish.yml`, done in unit 278.
- Any new input, flag or override (ADR 0016).

## Verification

Workflow-only diff, so the gate economy of units 276–278: no `fmt` / `clippy` /
`cargo test`, and `cargo-audit audit -D warnings` plus `cargo-deny check`
unconditionally.

- Parse the changed workflow with a real YAML parser; command and output in the
  report.
- `actionlint`, the same way units 277 and 278 used it — pinned binary into
  `/tmp`, never committed, `-shellcheck= -pyflakes=` — showing no new finding
  beyond the pre-existing `artifact-metadata` scope one.
- **Assert the conditions, do not describe them.** Extend the script from unit
  278 to `release.yml`: every job that signs, publishes or creates a tag must
  have an effective run condition requiring a `refs/tags/v` ref. Assert it
  **per job** as well as over the closure — unit 278's counter-tests showed a
  root-gated chain makes every mid-chain removal look fine — and make the
  condition check refuse to credit a disjunction or a negation, which is the
  one-line edit that reads as gated to any grep.
- Counter-tests: drop the condition from each of the three jobs in turn; weaken
  one to a disjunction; make the version input disagree with the ref.

## Acceptance

- `build-binaries`, `sbom` and `release` cannot run on a dispatch whose ref is
  not a `refs/tags/v*` ref, asserted per job and with counter-tests.
- No `v*` tag can be created from a branch commit by this workflow.
- The release version is derived from the ref; any surviving input must equal
  it or be rejected loudly.
- `hort-publish` is unchanged.
- No new input, flag or override.
- `actionlint` plus the per-job condition assertions and counter-test output in
  the report.
