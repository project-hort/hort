# 0051 — Self-contained chart via `global.imageRegistry` + `hort-base` cold-start hosting

- **Status:** Accepted
- **Enforced by:** the chart's `hort-server.image` / `hort-server.worker.image` /
  `hort-server.dex.image` helpers (`deploy/helm/hort-server/templates/_helpers.tpl`) own the
  empty-vs-set rewrite; `values.schema.json` declares the `global` block (strict
  `additionalProperties: false`). The empty-default byte-identical-render property is guarded by
  `scripts/test-helm-templates.sh` (the `quality:helm-template-test` job). The base-image mirror and
  the two-flavor chart publish live in `.github/workflows/docker-publish.yml`, gated on
  `vars.HORT_PROXY_ENABLED == 'true'` + a release tag.
- **Supersedes:** —
- **Relates:** [0047](0047-dual-license-generated-attribution.md) / #47 (keyless chart signing, the
  Flux-discoverable legacy `.sig` flow this reuses); [0034](0034-public-dogfood-deployment.md)
  (`registry.hort.rs` dogfood, the `gha-release` SA, `HORT_PROXY_ENABLED`); issue #60.

## Context

A downstream operator running hort as the **sole in-cluster registry** hits a bootstrap
circularity: hort's own image and its cold-start dependencies cannot be routed through the
in-cluster hort (it may be down during a cold start). The escape was either pulling the cold-start
chain direct from upstream (ghcr/dockerhub) or hand-crafting per-node `registries.yaml` mirror
rules. The cold-start chain is five artifacts: `hort-server`, `hort-worker`, **`dex`**,
**`postgres`**, and the **chart** itself. `mirror-to-hort-oci` already mirrored the two hort images
to `registry.hort.rs/hort-oci`; dex, postgres, and the chart were not covered.

## Decision

**1. `global.imageRegistry` (chart) — a single operator value, helper-owned rewrite.**
Default `""` renders every image reference exactly as before (`image.repository` /
`worker.image.repository` / `auth.dex.image`, each with its own tag) — byte-for-byte. Set to a
registry host, all three rewrite in one step: server/worker → `<reg>/hort-oci/hort-{server,worker}:<tag>`,
dex → `<reg>/hort-base/dex:<pin>`. The rewrite is a **registry+path-prefix** substitution (the tag is
untouched — the dex pin is parsed as everything after the last `:`, port-safe), living **only** in
the three helpers. Rejected: per-component `image.repository` overrides — one value the helper splits
beats N chances to get the `hort-oci`/`hort-base` split wrong.

**2. `hort-base` — a hosted, `isPublic: true` gitops repo for pinned third-party base images.**
Twin of `hort-oci` (anon-pull, no pull-through, populated only by the `gha-release` SA). Holds
digest-referenced dex + postgres. Its `ScanPolicy` uses **`severityThreshold: critical`, not `high`**
(the deliberate difference from `hort-oci`): we cannot remediate a CVE in a third-party base image —
only upstream can — so a `high` bar would flap the mirror on every upstream base-CVE for a hold we
can take no action on. `critical` keeps full finding *visibility* (findings are recorded regardless
of threshold; only the *hold* bar moves) while holding only on the unignorable, and a held base image
degrades **only the mirror face** — containerd falls back to the real upstream.

**3. Two published chart flavors from one source tree.** The ghcr chart keeps `global.imageRegistry: ""`
(upstream/dev). A second copy is published to `registry.hort.rs/hort-charts/hort-server` with the
packaged default set to `registry.hort.rs` (turnkey/sovereign) — a `yq` mutation of a **temp copy**'s
`values.yaml` at package time (`helm package` has no `--set`), never a chart fork. Both are
keyless-signed with the identical #47 legacy-`.sig` cosign flow so both verify for Flux.

**4. Postgres stays external-DB.** The chart does not bundle postgres; the operator points their own
postgres deployment at `registry.hort.rs/hort-base/postgres` (documented, not a chart value). A
bundled-postgres subchart is deferred (revisit trigger: demand for a zero-dependency quickstart).

## Invariants

- **Empty `global.imageRegistry` renders byte-identically to the pre-feature chart** — existing ghcr
  consumers are untouched. This is the regression guard for every future change to the image helpers.
- **Base-image mirror sources are digest-pinned**, not tag-floating — the sovereign copy is
  reproducible and cannot drift under a moved upstream tag.
- **The dex mirror destination tag is the upstream tag** (e.g. `v2.41.1`), matching what
  `hort-server.dex.image` resolves — mirroring under hort's release version would 404 at pull.
- **Mirrored images + both chart flavors carry cosign signatures/attestations verifying identically
  to the ghcr copies** — a mirror that drops signatures is a supply-chain regression.
- **`hort-base` is `isPublic: true`, anon-pull, hosted (never a proxy)** — same posture as `hort-oci`.

## Consequences

- An operator installs `oci://registry.hort.rs/hort-charts/hort-server` and every pod pulls the whole
  cold-start chain from `registry.hort.rs` with **no node `registries.yaml`** — direct-upstream is
  only the containerd fallback.
- The mirror + flavor jobs are inert until `HORT_PROXY_ENABLED == 'true'` on a release tag; their
  first real exercise is a release cut with the flag on. Their correctness is not provable in CI-on-MR.
- Enabling `HORT_PROXY_ENABLED` in production had one outstanding precondition — the `.hort_auth`
  error path must not echo the token-exchange response body. Both surfaces are now sanitized (GitLab
  historically; the GitHub twin in issue #61), closing that gate.

## Alternatives considered

- **Per-node `registries.yaml` mirror rules** (the status quo escape) — rejected: per-cluster node
  config, exactly what a self-contained chart removes.
- **A forked sovereign chart** — rejected: two source trees drift. One tree, two packaged defaults.
- **Bundled-postgres subchart** — deferred, not rejected (§4).

## References

- `deploy/helm/hort-server/templates/_helpers.tpl`, `values.yaml`, `values.schema.json`
- `deploy/ansible/files/gitops/{repositories,policies,auth/grants}/hort-base*.yaml`
- `.github/workflows/docker-publish.yml` — `mirror-to-hort-base`, `publish-chart-registry-hort-rs`
- `docs/architecture/how-to/deploy/self-contained-registry-install.md`
