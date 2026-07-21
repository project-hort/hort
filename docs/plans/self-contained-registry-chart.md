# Self-contained hort chart + registry.hort.rs cold-start hosting — design (issue #60)

Branch-local planning doc (D7). Distil into an ADR + Diátaxis how-to before merge; delete this file.

## §1 — Deferred-items sweep (architect Step 0)

Run 2026-07-21 against `develop` @ post-`105edffb`.

- `docs/plans/` — empty (cleared by #59). No prior branch-local plans to inherit.
- ADR open-items register — three hits:
  - **GitLab CI error-path token leak** (register line 124, ADR 0034 Task 6 M3): *"the `echo \"${_hort_response}\"` line in the `.hort_auth` error path can print the `access_token` … Sanitize the error output before enabling `HORT_PROXY_ENABLED` in production."* **Directly implicated.** This initiative's whole purpose is to make enabling `HORT_PROXY_ENABLED` in production safe and useful. **Include now, as a hard precondition (Item 0).** See the rationale re-validation below — the GitLab side is fixed but the GitHub side is not.
  - **Dogfood Dex needs a group-capable connector** (register line 152, ADR 0038 follow-on 3): the dogfood Dex ships `staticPasswords` only → resolves non-admin. **Carry forward, not absorbed.** #60 hosts the dex *image*; it does not touch dex *config* or its admin story. Unrelated axis.
  - **Workload-identity federation for CronJobs** (register line 151): unrelated. Carry forward.
- No other register row concerns chart image resolution, registry mirroring, or the cold-start chain.

### Inherited-rationale re-validation (Step 0.5)

**Reused rationale (register line 124):** "the `.hort_auth` error path must not echo the exchange response before `HORT_PROXY_ENABLED` goes to production."

**Verdict: REVERSED-HERE for the surface this initiative actually uses.** The GitLab `.hort_auth` was sanitized (`.gitlab-ci.yml:409` now echoes `"no access_token in response (omitted)"` — the body is gone). But #60's mirror steps run in **GitHub Actions**, through `.github/actions/hort-auth`, whose exchange-error path still does **`echo "Response: ${response}"`** (`action.yml:95`). Same leak class, unsanitized, on the exact surface #60 builds on. The inherited fix covered one of the two hort-auth implementations; the initiative that turns the flag on in anger is the one that must close the other. **Item 0 fixes it; filed independently as its own security issue so it can land ahead of the rest.**

## §2 — What already exists (grounding)

- **`hort-oci`** gitops set is the exact template to twin: `deploy/ansible/files/gitops/repositories/hort-oci.yaml` (hosted, `isPublic: true`, filesystem CAS), `policies/hort-oci-scan.yaml` (trivy, `high` threshold, 1h window), `auth/grants/gha-release-{read,write}-hort-oci.yaml` (serviceAccount-subject grants for `gha-release`).
- **`mirror-to-hort-oci`** (`.github/workflows/docker-publish.yml:340`): `cosign copy --force` of `hort-{server,worker}` ghcr → `registry.hort.rs/hort-oci/*` with signatures + attestations, gated `startsWith(ref,'refs/tags/v') && vars.HORT_PROXY_ENABLED == 'true'`, authenticating via `./.github/actions/hort-auth`. Twin this for base images.
- **`publish-chart`** (`docker-publish.yml`, after `merge`): packages the chart, pushes to `ghcr.io/<owner>/charts/hort-server`, keyless-signs it (#47 / ADR-adjacent). Extend for the second flavor.
- **Chart image seam:** every image ref resolves through two helpers — `hort-server.image` and `hort-server.worker.image` (`_helpers.tpl:64,102`) — plus the dex ref (`values.yaml:227`, `auth.dex.image`). Three consumers, one helper file. This is the clean seam; no per-template edits.
- **Chart `examples/`** already exists (`external-lb`, `gateway-api`, `ingress-nginx-cert-manager`) — the pattern for the postgres (b) example.

## §3 — Design decisions

### D1 — `global.imageRegistry`, consumed only through the two helpers + dex

Add `global.imageRegistry` (default `""`). Semantics:

- `""` (default) → **today's behaviour, byte-identical**: `hort-server.image` → `ghcr.io/project-hort/hort-server:<tag>`, worker likewise, dex → `ghcr.io/dexidp/dex:v2.41.1`. The ghcr/docker defaults stay in `values.yaml`.
- non-empty (`registry.hort.rs`) → the helpers rewrite the **registry+path prefix**, not the whole ref:
  - `hort-server` → `<reg>/hort-oci/hort-server:<tag>`
  - `hort-worker` → `<reg>/hort-oci/hort-worker:<tag>`
  - dex → `<reg>/hort-base/dex:<pinned>`

**The rewrite lives entirely in `_helpers.tpl`.** `hort-server.image` becomes: if `global.imageRegistry` set, emit `<reg>/hort-oci/hort-<component>:<tag>`; else emit `.Values.image.repository:<tag>` as today. Dex needs a parallel `hort-server.dex.image` helper (it is currently an inline `.Values.auth.dex.image` string — introduce the helper so the mapping rule lives in one place, matching server/worker).

**ADR 0015 (inert-field) compliance:** `global.imageRegistry` is consumed the moment it is set — there is no apply-time-accepted-but-runtime-ignored path. A `helm template` with it set and unset is the enforcement test (Item 3 acceptance).

**Why registry+path-prefix rewrite, not a full `image.repository` override per component:** the issue's own framing — "the chart already documents `image.repository` as a mirror-operator override; this generalizes that." A single `global.imageRegistry` is one value an operator sets once; N per-component repository overrides are N chances to get the `hort-oci`/`hort-base` split wrong. The helper owns the split.

### D2 — `hort-base` gitops repo (twin of `hort-oci`)

New `deploy/ansible/files/gitops/repositories/hort-base.yaml` — `format: oci`, `type: hosted`, `isPublic: true`, filesystem CAS at `/var/lib/hort-server/cas/hort-base`. Plus a `gha-release` write grant twinning `gha-release-write-hort-oci.yaml`. Holds **pinned, digest-referenced** third-party base images (`dex`, `postgres`).

**Scan policy — a real decision, recommending scan-record-but-accept-hold-degrades-to-fallback.** `hort-oci` blocks on `high` trivy findings, with the rationale "a held image degrades only this showcase face; ghcr is canonical." That rationale transfers *partially*: for `hort-base` the fallback is also upstream (dockerhub/ghcr via containerd), so a held base image degrades only the mirror, never availability. **But** the "rebuild on a patched base" remediation `hort-oci`'s policy assumes does **not** exist for third-party images — we cannot patch `postgres:17-alpine`; only upstream can. A block there is unactionable by us and would flap the cold-start mirror on every upstream base-CVE disclosure.

Two viable shapes:
- **(D2-a, recommended) scan on, threshold `critical`** (not `high`): record findings for visibility, but only a `critical` holds — narrower than `hort-oci` precisely because we can't remediate, and the held→upstream-fallback keeps availability. Documents the tradeoff inline.
- **(D2-b) `scanBackends: []`** — no scan, pure availability. Cleaner but loses defense-in-depth visibility on images we serve to our own fleet's cold start.

**DECISION: D2-a — CONFIRMED by the maintainer (Tom, #60, 2026-07-21: "threshold critical").** trivy on, `severityThreshold: critical`. It keeps visibility, holds only on the unignorable, and the held→upstream-fallback covers the availability hole. D2-b is not taken.

### D3 — CI: `mirror-to-hort-base` step + second chart flavor

- **`mirror-to-hort-base`** — a twin of `mirror-to-hort-oci` in `docker-publish.yml`: `cosign copy --force` the **digest-pinned** `dex` and `postgres` refs → `registry.hort.rs/hort-base/{dex,postgres}:<tag>`, same `HORT_PROXY_ENABLED` gate, same `hort-auth` action, same `gha-release` SA. Sources are pinned by digest (renovate already tracks `dex`/`postgres` tags — !160 is the dex bump; the pin the mirror copies must match `values.yaml`'s dex tag and the chart's documented postgres tag).
- **Second chart flavor** — extend `publish-chart` to publish a *second* copy of the chart to `registry.hort.rs` (`hort-oci/charts/hort-server` or a dedicated `hort-charts` repo — **decision: `hort-charts`**, a clean separation from image repos, mirroring how the two-flavor split is conceptually distinct) with `global.imageRegistry` **defaulted to `registry.hort.rs`** in that published copy only. Same #47 keyless signing so the mirrored chart verifies. The ghcr flavor keeps `global.imageRegistry: ""`. **One source tree, two published defaults** — the flavor difference is a single `--set`/`values` override at package time, never a forked chart.

### D4 — Postgres: option (b) only (option (a) deferred)

Per the issue, **(b) is recommended-first and confirmed in scope; (a) is deferred.** Ship `deploy/helm/hort-server/examples/registry-hort-rs/values.yaml` + a Diátaxis how-to: an operator standing up their own external postgres, pointing its image at `registry.hort.rs/hort-base/postgres`, with `global.imageRegistry: registry.hort.rs` set. The chart stays external-DB by design (ADR-aligned — no bundled DB).

**Deferred (a) — bundled-postgres subchart** for a single-install demo. Carried forward to a future initiative; recorded in §5.

## §4 — Observability

No new metrics, no new tracing — this is chart/CI/gitops, no `hort-*` Rust. The one runtime-visible change is that pods pull from `registry.hort.rs`; that is observable through the existing image-pull events and needs nothing new.

## §5 — Explicitly out of scope

- **Bundled-postgres subchart (option a)** — deferred per the issue; a future single-install-demo initiative. Revisit trigger: demand for a zero-dependency quickstart.
- **Enabling `HORT_PROXY_ENABLED` itself** — that is the operator's/release-owner's action. This initiative makes the machinery correct and safe (Item 0); it does not flip the flag.
- **Dex admin-group connector** (register line 152) — unrelated axis, carried forward.
- **Mirroring the chart's non-image dependencies beyond dex/postgres** — the cold-start chain is exactly {server, worker, dex, postgres, chart}; nothing else.

## §6 — Security invariants (must hold)

1. **No auth-exchange response body is ever echoed to CI logs** (Item 0). GitHub Actions logs are readable by anyone with repo actions access; a public repo makes them public.
2. **Mirrored images + chart carry the same cosign signatures/attestations as the ghcr copies** and verify identically (`cosign copy` preserves them; the chart re-signs via #47 keyless). A mirror that drops signatures is a supply-chain regression — the acceptance test verifies a mirrored artifact against the same identity.
3. **`hort-base` is `isPublic: true`, anon-pull, no pull-through.** It is a *hosted* repo populated only by the `gha-release` SA — never a proxy that could fetch arbitrary upstream on a cache miss. (Same posture as `hort-oci`.)
4. **Base images are digest-pinned**, not tag-floating, at the mirror source — the mirror copies a specific digest so the sovereign copy is reproducible and cannot drift under a moved upstream tag.

## §7 — Layering / ADR

No hexagonal-layer code. Durable decisions to distill before merge:
- **New ADR** (proposed 0051): "Self-contained chart via `global.imageRegistry` + `hort-base` cold-start hosting" — records the `global.imageRegistry` contract (empty-default, helper-owned rewrite), the `hort-base` repo + its scan-policy decision (D2), the two-flavor published chart, and the digest-pin invariant. Add the index row.
- **Diátaxis how-to**: `docs/architecture/how-to/self-contained-registry-install.md` — the operator recipe (install `oci://registry.hort.rs/hort-charts/hort-server`, everything resolves sovereign, no node `registries.yaml`).
