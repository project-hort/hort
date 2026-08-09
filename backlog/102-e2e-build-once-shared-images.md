# 102 — E2E: build the images once, share them across both lanes

**Issue:** #144 · **Branch:** `agent/144-e2e-build-once` · **Scope:** `.github/workflows/e2e.yml`, `deploy/compose/docker-compose.yml`, `scripts/native-tests/run.sh`

## Why

Each E2E lane performs the full image build; with two lanes that cost is paid
twice per run, in parallel. Measured: one lane took 17m25s before the second
lane existed, and both then hit the 20-minute cap (raised to 40 as a
stop-gap). The whole suite is a single step — everything else in the job is
under 3 seconds — so the wall-clock is build, not test.

Three images are built from source per lane:

| image | Dockerfile | used by |
|---|---|---|
| server | `deploy/compose/Dockerfile` | `hort-server`, `hort-server-migrate`, `hort-sweep-ticker` |
| worker | `docker/Dockerfile.worker` | `hort-worker` |
| test client | `scripts/native-tests/Dockerfile.client` | the scenario runner |

## The blocker to handle first

`hort-server`, `hort-server-migrate` and `hort-sweep-ticker` declare `build:`
with **no `image:` name**. A service without an image name is always built —
a pre-loaded image can never satisfy it. Give each an env-overridable
`image:` whose default reproduces today's behaviour, so a developer running
the suite locally still builds exactly as now.

`run.sh` also passes `--build` unconditionally on `compose up`, which forces a
rebuild even when a suitable image is present. That flag has to become
conditional.

## Change

1. **Name the images.** Add `image: ${HORT_SERVER_IMAGE:-...}` (and the
   equivalents) so all four app services resolve to nameable images. Keep
   `build:` in place — the fallback path must still work.
2. **Make the build conditional in `run.sh`.** A documented opt-out (env or
   flag) skips `build_image` and drops `--build`, for the case where the
   images were loaded beforehand. Default behaviour unchanged: a local run
   still builds. When the opt-out is active and an expected image is
   **missing**, fail loudly with the missing name — never silently rebuild,
   because that would hide the very cost this item removes.
3. **Pre-build job in `e2e.yml`.** One job builds the three images with
   buildx and the GitHub Actions cache backend (`cache-from`/`cache-to:
   type=gha`), then hands them to both lanes. Prefer `docker save` +
   `actions/upload-artifact` → `docker load`, which needs no registry
   credentials; a ghcr push under a commit-sha tag is acceptable if it
   measures better. Both lanes `needs:` that job and run with the build
   opt-out active.
4. **Log the provenance.** Each lane prints where its images came from, so a
   silent fallback to building is visible in the log rather than only in the
   duration.

## Out of scope

Shortening scenario waits (the sweep tick is already 5s; what remains are two
120-second quarantine windows that *are* the assertion), and re-tightening
`timeout-minutes` — that happens once the new cost is measured, in a
follow-up, so this item is not judged on a number it cannot yet know.

## Acceptance

- Both lanes green on the first GitHub run after merge, and the per-lane
  wall-clock reported before/after.
- A log line in each lane proving the images came from the shared build.
- A local run with no opt-out still builds and passes — the fallback is not
  theoretical.
- **Verification limitation:** the cockpit sandbox has no docker, so this
  cannot be exercised there. Verification is structural (YAML parse, shell
  syntax, and a careful reading of the compose resolution order); the
  measured proof comes from the first GitHub run, which the architect checks.
