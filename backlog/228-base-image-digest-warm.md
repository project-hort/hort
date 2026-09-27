# 228 — A base-image digest bump must warm at merge, not at the release build

**Issue:** #275 · **Branch:** `agent/275-base-image-warm`
**Governing decisions:** ADR 0007 (the quarantine time gate — this item does not
touch it) · ADR 0034 (the dogfood proxy is the build's source) · `RELEASING.md`
"Crates publish: warm the vetted index before tagging" — the same choreography,
which this item extends to base images instead of inventing a second one.

## Why

A base-image digest bump lands on `develop` through a routine Renovate MR. The
MR pipeline builds no images — `build-images:*` runs on tags, `main` and
`release/*` only. So the **first** consumer of the new digest is always a
release-shaped build, and that build is also the first thing that pulls the
digest through the dogfood proxy: ingest and quarantine start at the moment the
build needs the bytes. The build therefore fails by construction, for exactly
one quarantine window.

Observed on the `v0.14.0-beta.4` tag pipeline:

```
FROM debian:trixie-slim@sha256:a99cfc51… AS trivy
Error: creating build container: … received unexpected HTTP status: 503 Service Unavailable
```

and directly against the proxy:

```
503, Retry-After: 100733
{"code":"UNAVAILABLE","message":"artifact is quarantined","detail":{"retry_after_seconds":100733}}
```

Not a defect — the time gate doing its job on content nobody had ingested yet.
The gap is choreographic, and it is the one `RELEASING.md` already documents for
crates: **the warm must lead the tag by at least one window.** For base images
that rule is written down nowhere and enforced by nothing.

This recurs on every bump. At the time of writing `debian:trixie-slim` already
resolves to a different digest than the pinned one, so the next Renovate bump
walks into the same wall.

## Two measurements that constrain the design

Both taken on the real case, and they rule out "just wait for the window":

- **The sweep tick costs five to ten minutes on top of the window.** Release at
  14:55:22 against a computed deadline of 14:45 (base image); five minutes on
  the `v0.14.0` internal publish. Release follows the sweep tick, not the
  individual artifact — of three artifacts past their deadline, one answered
  200 while two still answered 503.
- **`Retry-After` is useless in that state.** Past the deadline it is the clamp
  value `(deadline - now).max(1)` — `Retry-After: 1` — so a well-behaved client
  retries every second and learns nothing. Do not build the warm's
  wait-and-poll (if any) on that header.

## Read first

- `.gitlab-ci.yml` — `prefetch:warm` (the shape to mirror: `needs: []`,
  `allow_failure: true`, `develop` + schedule, `id_tokens` referenced from
  `.hort-auth`, `*hort-auth-steps` in `before_script`), `prefetch:warm:internal`
  (why a second target gets its own job and the `platform` tag), and the
  `.docker` template's `before_script` — that is precisely the pull the warm has
  to anticipate.
- `docker/Dockerfile.worker`, `docker/Dockerfile.hort-server`,
  `deploy/compose/Dockerfile` — the pinned `FROM …@sha256:` set.
- `RELEASING.md` §"Crates publish: warm the vetted index before tagging" — the
  paragraph the new rule sits next to.
- `.github/workflows/prefetch-warm.yml` — the GitHub-side counterpart's
  reasoning about triggers; the base-image warm belongs on the **GitLab** side,
  because that is where images are built.

## Two facts that decide the implementation

1. **The prefetch API cannot be used.** `/api/v1/repositories/<repo>/prefetch`
   rejects OCI outright — `SelfServicePrefetchUseCase` returns a validation
   error when the resolved repository's format is `Oci`
   (`crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs:345-360`).
   The warm must therefore be a **pull through the proxy**, not an API call.
   This is the one place where this item deviates from the crates choreography,
   and it is forced.

2. **A manifest fetch is not enough, and `skopeo inspect` is not enough.** Blob
   reads are quarantine-gated on the same axis as manifests
   (`crates/hort-http-oci/src/blobs.rs` has its own `check_quarantine` →
   503 + `Retry-After`). If the warm ingests only the manifest and config, the
   layers are still cold when the release build asks for them — the window just
   moves one round later, and the build fails again on a layer instead of a
   manifest. **Warm the full image**: every object the build will request —
   manifest, config and all layers — must begin its window at warm time.
   (The issue text suggested `skopeo inspect`; that was wrong, and this item
   supersedes it.)

## Scope

1. **A warm job on the GitLab side**, in the shape of `prefetch:warm`: runs on
   `develop` pushes and on schedule, `needs: []`, `allow_failure: true` (a failed
   warm must never fail a pipeline — its cost is a cold digest later, which is
   visible where it matters), gated on the same `HORT_*` switches, and tagged for
   the runner that can reach the proxy.
2. **Pull the pinned base images by the same reference strings the Dockerfiles
   use.** The mapping from `debian:trixie-slim` to a dogfood-proxy pull lives in
   the runner's container configuration, **not in this repository** — so do not
   re-derive it. Run the warm with the same container tooling on the same runner
   as `.docker`, against the unchanged reference, and the mapping applies by
   itself. A second, repository-local copy of that mapping would be a new source
   of drift.
3. **Warm the whole set every run, not the diff.** `prefetch:warm` warms the
   whole lock rather than what changed, for good reason: an already-released
   digest is a no-op, and a diff-driven trigger silently misses a digest that
   arrived by any other route (a manual edit, a revert, a `develop` sync). Parse
   the `FROM …@sha256:` lines out of the three Dockerfiles and warm all of them.
4. **Report the three outcomes distinguishably**, as `prefetch:warm` does: the
   pull succeeded (already released), the pull was refused with 503 (the warm
   worked — the window is now running), or it failed for any other reason (a
   warning naming the reference and the status). A 503 here is a **success**
   for this job, and the log must say so, or the next reader will treat the job
   as broken.
5. **Write the rule into `RELEASING.md`** beside the crates-warm paragraph: a
   base-image digest bump is a warm-requiring change, the warm must lead the tag
   by one window, and the release-day slack is the sweep tick (five to ten
   minutes), not the deadline.

## Acceptance

- After a run of the warm against a digest the proxy has never seen, **every**
  object a build would request for that reference — manifest, config, each
  layer — is present in the proxy rather than absent. A 503 on all of them
  immediately after the warm is the expected, passing state; an object that is
  still unknown to the proxy is the failure this item exists to prevent.
- A second run of the warm over an already-released set is a clean no-op and
  stays green.
- The job cannot fail a pipeline: `allow_failure: true`, `needs: []`, and no
  other job takes a dependency on it.
- The job's log distinguishes released / newly quarantined / error per reference.
- `RELEASING.md` carries the base-image warm rule next to the crates one, and
  names the sweep-tick slack.
- No change to any quarantine window, to `check_quarantine`, or to the
  `Retry-After` computation. Shortening the window for base images was the
  rejected alternative: it lowers the time gate for convenience and still leaves
  the ingest happening inside the build.

## Explicitly not in this item

No change to the time gate or to any proxy policy. No `Retry-After` change on
the scan axis, even though the clamp value is unhelpful past the deadline — that
observation belongs to its own unit if it recurs as a steady state rather than a
ten-minute transient. No image build on MR pipelines (that would cost a full
release-profile build per MR to solve a problem a warm solves for free).
