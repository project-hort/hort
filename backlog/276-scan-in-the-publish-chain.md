# 276 — The container scan is in the publish chain, and covers what is published

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0048 (release routing; `-alpha.N` is the internal
track and never this public GHCR publish) · ADR 0051 (the mirror and signature
property of a published image) · ADR 0016 (the close is fail-closed rejection,
never a degraded runtime path).

## What is true today

Everything below is read off `.github/workflows/docker-publish.yml` on
`develop` at `c87814f2`.

**The job declares a blocking policy and enforces it on itself.**
`scan-containers` (`:153`) runs two Trivy invocations, deliberately split: one
produces SARIF at all severities with `exit-code: '0'`, the other is the gate —
`severity: 'CRITICAL'`, `ignore-unfixed: true`, `exit-code: '1'`. Its own
comment says *"The publish-path scan below is BLOCKING on fixable CRITICALs"*.

**Nothing depends on it.** `scan-containers` has `needs: [build-images]`, and
no job anywhere names it. `merge` (`:267`) has `needs: [build-images]`;
`publish-chart` (`:513`) needs `merge`; `verify-published` (`:816`) needs
`merge, publish-chart`; `mirror-to-hort-oci` (`:364`), `mirror-to-hort-base`
(`:446`) and `publish-chart-registry-hort-rs` (`:683`) all reach back to
`merge`. So the gate fails its own job and `merge` pushes the tags and
`cosign sign`s the digest beside it.

**The file says both things, and the one a human reads is the wrong one.** The
job's final step writes to `$GITHUB_STEP_SUMMARY`:

> **Policy**: CRITICAL / HIGH CVEs reported (informational; unfixed base-image
> CVEs do not block)

That is *true of the system* and contradicts the step comment, which is true
of the step. The gap between them is the finding, and it is already written in
the file.

**Three of four published digests have no scan input.** The job downloads only
`server-digests-amd64` and resolves a single `backend` ref. `build-images` is a
matrix of `image: [server, worker]` × `platform: [linux/amd64, linux/arm64]`,
each entry uploading `${{ matrix.image }}-digests-${{ matrix.arch }}` and
pushing to `${{ github.repository }}-${{ matrix.image }}`. The worker image and
both arm64 variants are never scanned on this path.

## What to do

1. **Put the scan in the chain.** `merge` depends on `scan-containers` as well
   as `build-images`. Everything downstream inherits it transitively — but
   walk each one (`publish-chart`, `verify-published`, both mirror jobs,
   `publish-chart-registry-hort-rs`) and confirm it rather than assuming.
   `summary` keeps its `if: always()`; it is a reporter, not a publisher.
2. **Scan the axis that is published.** Matrix the job over the same
   image × arch set, each entry downloading its own `<image>-digests-<arch>`
   and scanning that digest. The runner stays amd64 for all four: Trivy scans a
   digest pulled from the registry, so an arm64 image needs no arm64 runner.
   Give each entry its own SARIF `category`, or the Security tab collapses four
   results into one.
3. **Only the gate step may block.** The `upload-sarif` and `upload-artifact`
   steps are `if: always()` visibility, and the job's own comment already says
   the SARIF upload must not change the verdict (*"the Security tab keeps full
   visibility even when this step fails"*). Once the job is a publish
   prerequisite, a hiccup in the CodeQL upload action would block a release on
   something that is not a security finding. Mark them `continue-on-error: true`
   so the Trivy gate step is the only thing that decides the job's result.
4. **Rewrite the run summary** so it states what now holds, per matrix entry,
   and stop calling the publish-path scan informational.
5. **Correct the comment at `:50-52`.** It lists `scan-containers` in one
   breath with the publish chain (*"`scan-containers` / `merge` / … all
   transitively `needs:` it"*). For the skip-cascade purpose it was written for
   that is true and must stay true; it also reads as though the scan were part
   of the chain, which it was not. After this change it is — say both things
   precisely instead of one sentence that blurs them.

## Behaviour change to surface

**The first publish after this may go red, and that is the gate working.**
Three of the four images have never been scanned here and the fourth's verdict
has never been able to stop anything, so a pre-existing fixable CRITICAL in the
worker image or an arm64 layer will now hold the publish.

Do not weaken the policy to get green. Report what the scan found, with CVE
ids and the affected image, and leave the choice between a base-image bump and
a `.trivyignore` entry to the human. ADR 0016 is explicit that the close is
fail-closed rejection rather than a degraded path, and that applies just as
much to not degrading it the first time it bites.

## Explicitly out of scope

- The accepted posture that HIGH and unfixed CVEs are informational.
  `ignore-unfixed: true` and the HIGH treatment stay exactly as they are; this
  item only makes the **already-declared** CRITICAL policy effective.
- The contents of `.trivyignore`.
- Any scan edge in `release.yml`, and the `ci-complete` prerequisite — the next
  unit's business, deliberately not smuggled in here.
- The Trivy version pin and the extract-from-GHCR-image install workaround.
- `summary`'s `if: always()`.

## Verification — and why the usual gate is the wrong one here

This unit changes **only** `.github/workflows/docker-publish.yml`. Nothing
under `crates/`, `Cargo.*` or `migrations/` moves, so the Rust gate has nothing
to say about it and running it proves nothing (the gate economy: a
harness-only diff gets a YAML/shell proof plus `cargo-audit` / `cargo-deny`,
not `fmt`/`clippy`/`test`).

These workflows run **only on GitHub**. Neither this sandbox nor the project's
compose E2E executes them, so the evidence has to be structural:

- Parse the changed workflow with a real YAML parser and show the command and
  its output. `python3` with PyYAML 6.0.2 is in the container.
- **Assert the dependency graph, do not describe it.** Write the check as a
  short script that loads the YAML, walks `needs:` transitively from every job
  that pushes, signs or publishes, and asserts each one reaches
  `scan-containers`. Put the script and its output in the report. It is throwaway
  for this unit — a later unit of #339 turns the same assertion into a
  checked-in guard — so keep it in the report, not in the tree.
- `cargo-audit audit -D warnings` and `cargo-deny check`: unconditional, because
  the advisory database is live and can turn a gate red with no diff at all.

## Acceptance

- `merge` cannot run when `scan-containers` failed, and every publishing job
  downstream inherits that. The report writes the graph out job by job with its
  `needs:` edges.
- All four published digests (server and worker × amd64 and arm64) are scanned,
  each under its own SARIF category.
- A failing SARIF or artifact upload cannot block a publish; a failing Trivy
  gate can.
- No comment and no run summary still calls the publish-path scan
  informational.
- The dependency-graph assertion is in the report, with the script that
  produced it.
