# 278 — Publication authority is fail-closed: no release tag, no published artifact

**Issue:** #339 · **Branch:** `agent/339-audit-block-3`
**Governing decisions:** ADR 0034 (first-party posture and the `gha-release`
identity) · ADR 0048 (release routing; `-alpha.N` is the internal track and
never this public GHCR publish) · ADR 0051 (the signature property of a
published image) · ADR 0016 (the close is fail-closed rejection, never a
degraded runtime path).

## What is true today

Read off `.github/workflows/docker-publish.yml` on this branch.

**The dispatch input becomes a pushed, signed public tag.** `workflow_dispatch`
takes a free-form `tag` input, `required: true`, `default: 'latest'` (`:6-11`).
The `merge` job's metadata step turns it into a tag directly —
`type=raw,value=${{ github.event.inputs.tag }},enable=${{ github.event_name ==
'workflow_dispatch' }}` — `imagetools create` pushes the resulting tag set, and
the next step runs `cosign sign --yes` on the digest.

**The chart's own guard is switched off on that path.** On a tag push
`publish-chart` derives the version from `GITHUB_REF`; on a dispatch it takes
`INPUT_TAG`, strips a leading `v`, and accepts anything matching a SemVer
regex. There is no comparison against the in-tree `Chart.yaml` and no
requirement that the ref be a tag at all.

**The protected environment is on the wrong half.** `environment: release`
guards the **internal** mirror jobs — `mirror-to-hort-oci` (`:363`),
`mirror-to-hort-base` (`:438`), `publish-chart-registry-hort-rs` (`:682`) — and
is absent from the **public** GHCR jobs `build-images`, `merge` and
`publish-chart`.

GitHub's [manually-run-a-workflow
documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
states both the write-access prerequisite and that the dispatcher chooses the
ref. So an account that can dispatch Actions picks `develop` or any other
writable ref, leaves the input at `latest`, and publishes a cosign-signed
public image under the most-consumed mutable tag — with no release approval
anywhere in the path.

Units 276 and 277 do not touch this. They made the chain wait for the CVE scan
and for CI; both of those pass perfectly well on a dispatch from a branch.

## The close, and the one part that is not ours

**The self-contained half — do this fully.** Nothing publishes unless the ref
is a release tag. `github.ref` on a dispatch is the chosen ref, so the
condition is a `startsWith(github.ref, 'refs/tags/v')` test, applied so that no
job in the public chain can push, sign or attest without it. That closes the
"freely chosen branch" finding completely and depends on no setting outside
this repository.

Two tightenings that belong to the same finding, because the audit names both:

1. **The chart's dispatch path gets the assertion the tag path has.** With the
   ref now required to be a release tag, compare the resolved chart version
   against the in-tree `Chart.yaml` on *both* paths rather than only on a tag
   push. The skip was explicit; it stops being defensible once the ref is
   pinned.
2. **The raw image-tag input stops being arbitrary.** Once the ref must be a
   release tag, `docker/metadata-action`'s `type=semver` entries already derive
   the correct version tags *from the ref*; the raw input's only remaining power
   is to **add** a tag. Accept exactly the two uses the input documents for
   itself (`e.g., v1.0.0, latest`): `latest`, or the ref's own version. That
   removes "push `v2.0.0` onto the `v0.14.1` build" while keeping both
   documented uses, and it is a comparison against the ref, not a new allow-list
   to maintain.

**The half that is not ours.** Also declare `environment: release` on the
public publish path, so it carries the same protection as the internal mirror
jobs. Be precise about what that buys: a GitHub environment only gates if the
repository's environment settings carry required reviewers or a branch/tag
restriction, and **that is a setting outside this tree** — the audit explicitly
did not inspect it. So the declaration is necessary but on its own possibly
inert, which is exactly why the ref condition above is the load-bearing part
and must not be weakened into "the environment will catch it". The architect
has the question open with the human; do not block on it.

## Explicitly out of scope

- GHCR tag immutability, organisation Actions policies, repository write
  membership, and the `release` environment's own settings. External, and the
  audit said so.
- `release.yml`'s dispatch path and its lack of an alpha guard.
- The `-alpha.N` exclusion itself (ADR 0048), which works.
- The installer identity regex in `install/install-cli.sh` — a note in the
  audit with no established attack path, not a finding.
- Any new operator-facing input, flag or override. ADR 0016: the close is
  rejection, not a knob that re-opens it.

## Verification

Workflow-only diff, so the same gate economy as units 276 and 277: no `fmt` /
`clippy` / `cargo test`, and `cargo-audit audit -D warnings` plus
`cargo-deny check` unconditionally.

- Parse every changed workflow with a real YAML parser; command and output in
  the report. `python3` with PyYAML 6.0.2 is in the container.
- `actionlint` settled the one expression-context question in unit 277 the
  only way it could be settled. Use it again the same way — pinned binary
  fetched to `/tmp`, never committed, `-shellcheck= -pyflakes=` since neither
  is installed — and show that this change adds **no** finding beyond the
  pre-existing `artifact-metadata` scope one.
- **Assert the condition, do not describe it.** Extend the script: for every
  job that pushes, signs, attests or publishes, its effective run condition
  must require a `refs/tags/v` ref. "Effective" as unit 277 established —
  declared `needs:` minus the edges an `always()` voids, and a job's own `if:`
  plus every `if:` it inherits. Include counter-tests: a mutation that drops
  the ref condition from one job must fail the assertion.

## Acceptance

- No job in the public chain can push, sign or attest on a dispatch whose ref
  is not a `refs/tags/v*` ref, asserted mechanically and with a counter-test.
- The chart version is compared against the in-tree `Chart.yaml` on the
  dispatch path as well as the tag path.
- The raw image-tag input accepts only `latest` or the ref's own version.
- `environment: release` is declared on the public publish path, and the
  comment beside it states plainly that its protection depends on repository
  settings outside the tree — so the next reader does not mistake the
  declaration for the guarantee.
- No new input, flag or override anywhere.
- `actionlint` and the graph/condition assertions in the report, with their
  scripts and counter-test output.
