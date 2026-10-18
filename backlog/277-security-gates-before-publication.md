# 277 — The security and attribution gates are prerequisites of publication

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0047 and ADR 0049 (third-party attribution is
verified before shipping) · ADR 0048 (release routing; `-alpha.N` is the
internal track) · ADR 0016 (the close is fail-closed, never a degraded path).

## What is true today

A `v*` tag independently triggers three workflows: `ci.yml`,
`docker-publish.yml` and `release.yml`.

`ci.yml` runs `cargo audit --deny warnings`, `cargo deny` and
`scripts/check-attribution.sh`, and rolls them into `ci-complete` (`:622`).
**Neither publish workflow consumes that status.**

- `docker-publish.yml` starts `build-images` (`:42`) directly. No gate job
  exists in the file.
- `release.yml` waits on `e2e-gate` and `build-binaries`, and its `release`
  job (`:450`) has `needs: [build-binaries, verify-images-published, sbom]`
  with `if: always() && needs.build-binaries.result == 'success'`. Its
  "Check gate status" step reads **only** `needs.verify-images-published.result`.

So a tagged commit that leaves generated attribution stale, adds a denied
dependency, or trips a fresh advisory can have those jobs red in `ci.yml`
while GHCR publishes and cosign-signs the images and charts.

GitLab's `security:attribution-sync` does run on tags before GitLab's *own*
image and chart stages. That is correct and is not the defect — it simply
cannot stop a workflow running on GitHub.

**A second, smaller gap in the same `release` job.** `sbom` is already in
`needs`, but `if: always()` neutralises the implicit blocking and the gate step
never looks at its result. A red `sbom` job therefore yields a fully published
(non-draft) release with no signed SBOM — the provenance ADR 0047 and ADR 0049
promise.

## The mechanism, decided

GitHub Actions has **no cross-workflow `needs:`**, so this needs a deliberate
choice. Take the one this repository already uses twice: a **reusable
workflow** consumed with `uses:`. `release.yml` does exactly this for the E2E
suite — `e2e-gate: uses: ./.github/workflows/e2e.yml` — and `build-binaries.yml`
is consumed the same way. Both carry `workflow_call:`.

So: give `ci.yml` a `workflow_call: {}` trigger (keeping all its existing
triggers — adding one does not remove the others) and add a `ci-gate` job to
each publish workflow that the chain's root job depends on.

**Rejected: `workflow_run`.** It is the other standard answer and it is worse
here: a `workflow_run`-triggered run executes in the default branch's context
rather than the tag's, which is the wrong commit for a gate whose whole point
is "these checks passed *for this artifact*".

**The cost, named rather than hidden.** On a non-alpha tag `ci.yml` then runs
three times — once standalone, once per calling workflow. That is real waste
and it is accepted here deliberately: the alternative is extracting the three
security gates into their own small reusable workflow so only the cheap part
re-runs, which is a restructuring of `ci.yml` for a cost nobody has measured.
If tag-build cost becomes a problem, that extraction is a clean follow-on
change on its own. Do **not** do it in this unit.

**Mind the alpha skip.** In `docker-publish.yml`, `build-images` carries
`if: ${{ !contains(github.ref, '-alpha.') }}` and the whole public chain skips
on an internal alpha tag (ADR 0048). A gate job added as its dependency would
still *run*, burning a full CI run for a chain that then skips — so the gate
job carries the same condition as the root it gates.

In `release.yml` there is no alpha guard and this unit does not add one. Worth
knowing while working there: that workflow's alpha safety is indirect — on an
alpha tag `verify-images-published` fails (no images are published for alphas),
the gate step therefore reports not-all-passed, and the GitHub Release stays a
**draft**. `build-binaries` only ever uploads workflow artifacts, so nothing
public is produced either way. Leave that arrangement alone; it is not this
unit's subject.

## What to do

1. Add `workflow_call: {}` to `ci.yml`'s triggers. Change nothing else about
   when CI runs.
2. `docker-publish.yml`: add a `ci-gate` job that `uses:
   ./.github/workflows/ci.yml`, carrying `build-images`'s alpha condition, and
   make `build-images` depend on it. Everything else in that workflow reaches
   `build-images` or `merge`, so confirm each job inherits it rather than
   assuming.
3. `release.yml`: add the same `ci-gate` job and make `build-binaries` and
   `sbom` depend on it alongside `e2e-gate`.
4. Make the `release` job consult the `sbom` result. The gate step already
   computes a publish-vs-draft decision from `verify-images-published`; the
   SBOM is part of the promised provenance, so a red `sbom` must reach that
   same decision. Keep the existing draft-on-failure behaviour — a draft is
   the fail-closed outcome here and it already works.
5. Update the comments that describe the gate set, including the
   "publish-vs-draft decision rests on the image-publish gate" comment at
   `:478`, which stops being true.

## Explicitly out of scope

- Extracting the security gates into their own reusable workflow (above).
- Any alpha guard for `release.yml`.
- `ci.yml`'s job set, its `paths-ignore`, and the `ci-complete` roll-up's own
  membership.
- The dispatch-authority work — the next unit's subject.
- GitLab's `security:attribution-sync` scoping, which is correct as it is.

## Verification

Workflow-only diff, so the gate economy applies exactly as for the previous
unit: no `fmt` / `clippy` / `cargo test`, and `cargo-audit audit -D warnings`
plus `cargo-deny check` unconditionally.

- Parse every changed workflow with a real YAML parser; show command and
  output. `python3` with PyYAML 6.0.2 is in the container.
- **Assert the graph, do not describe it.** Extend the script from the previous
  unit: for every job that pushes, signs or publishes, walk `needs:`
  transitively and assert it reaches **both** `scan-containers` and `ci-gate`.
  Script and output in the report; throwaway, not committed — a later unit
  turns the same predicate into a checked-in guard.
- A `uses:` path is only a gate if the file it names exists and is callable.
  Assert that too: `ci.yml` has `workflow_call`, and each `uses:` path
  resolves.

## Acceptance

- Neither `build-images` nor `build-binaries` nor `sbom` can start before
  `ci-gate` succeeds, written out job by job in the report.
- A red `sbom` leaves the GitHub Release a draft, and the comment set says so.
- `ci-gate` does not run on an `-alpha.` tag in `docker-publish.yml`.
- No comment still describes the publish path as gated only on image
  availability.
- The graph assertion covers both edges and is in the report with its script.
