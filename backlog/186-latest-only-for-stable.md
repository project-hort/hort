# 186 — `:latest` follows stable releases, not "whatever is not rc or beta"

**Issue:** #248 · **Branch:** `agent/248-latest-prerelease` · single item.

## Problem

Every alpha tag moves the internal registry's `:latest` onto a pre-release.
Observed on three consecutive cuts (`0.14.0-alpha.3`, `.4`, `.5`), on **both**
images:

```
PUSH_LATEST=true
=== Pushed and signed ===
  …/hort-server:0.14.0-alpha.5
  …/hort-server:latest
```

`.gitlab-ci.yml` (`build-images:hort-server`, and its line-for-line twin in
`build-images:hort-worker`):

```bash
if [ -n "${CI_COMMIT_TAG:-}" ]; then
  VERSION_TAG="${CI_COMMIT_TAG#v}"
  case "${VERSION_TAG}" in
    *-rc.*|*-beta.*) PUSH_LATEST="false" ;;
    *)      PUSH_LATEST="true"  ;;
  esac
```

The exclusion list names `-rc` and `-beta`. `-alpha` is absent, so every alpha
falls into the permissive catch-all and `buildah push "${IMAGE}:latest"` runs.

This is not an interpretation gap. The intent is stated eight lines above in the
same file — *"stable releases additionally push `:latest`"* — and again in
`CLAUDE.md`: *"`:latest` is only set for stable releases (no `-rc`, `-beta`,
`-alpha`, etc.)"*. The implementation contradicts its own documented rule.

## Why it happened, and the shape of the real fault

The `case` dates from a commit that added Zot publishing **on `-beta` tags**,
written when `-rc` and `-beta` were the pre-release kinds that existed. The
internal alpha track arrived later (ADR 0048) and the enumeration was never
re-asked.

The structural fault is the **direction** of the test: a deny-list of known
pre-release suffixes with a permissive fallback is open by construction to every
future kind. The safe form is the inverse — `:latest` only for a version with no
pre-release suffix at all.

## Correction

Both `case` blocks:

```bash
case "${VERSION_TAG}" in
  *-*) PUSH_LATEST="false" ;;   # any pre-release: alpha, beta, rc, and whatever comes next
  *)   PUSH_LATEST="true"  ;;
esac
```

Semver pre-releases are exactly the versions carrying a `-` after the patch
level, so this single pattern separates stable from non-stable without a list
that can go stale again. The comment must say **why** it is a single pattern
rather than an enumeration, so the next author does not "helpfully" expand it
back into a list.

The two blocks are identical line for line, which is why the defect exists
twice. If a shared source (a YAML anchor, or a small script under `.gitlab/ci/`)
fits without contortion, that is the better correction. If not, change both and
say so in the commit.

## Must not change

- A tag with no pre-release suffix still pushes `:latest`.
- `main` branch builds still push `:<short-sha>` **and** `:latest`.
- `release/*` branch builds still push `:<short-sha>` only.
- The chart publish is untouched — it never pushed `:latest`.

## Out of scope

Resetting the `:latest` pointer, which currently resolves to `0.14.0-alpha.5`.
The correction stops the drift; it does not rewind it. Whether to re-push the
last stable tag as `:latest` is an operator decision recorded on the issue.

## Acceptance

- An alpha, beta or rc tag pushes **no** `:latest` — demonstrable as
  `PUSH_LATEST=false` in the next alpha cut's job trace.
- A suffix-free tag still pushes `:latest`.
- `main` and `release/*` branch behaviour unchanged.
- Both image jobs corrected, not just `hort-server`.
