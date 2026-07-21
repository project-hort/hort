# Install `hort-server` fully sovereign against `registry.hort.rs`

This is the recipe for running the entire `hort-server` cold-start
chain — server, worker, dex, and the operator's external Postgres —
without a single image pulled directly from `ghcr.io` or Docker Hub.
It assumes you already have a live hort instance publishing to
`registry.hort.rs` (issue #60): the fleet installing hort now pulls
hort's own images, and hort's cold-start dependencies, from itself.

This document does not repeat the base install path — see
[`install.md`](./install.md) for prerequisites, the Postgres runbook,
Secret kinds, and OIDC configuration. It layers one additional
decision (which chart flavor, and where images resolve from) on top
of that guide.

## The two chart flavors

Every tagged release publishes **two** copies of the same chart —
one source tree, two packaged defaults (see
[`helm-chart.md`](../../reference/helm-chart.md) and the chart's
`global.imageRegistry` value):

| Flavor | Location | Packaged `global.imageRegistry` default |
|---|---|---|
| ghcr (default) | `oci://ghcr.io/project-hort/charts/hort-server` | `""` — images resolve from `ghcr.io` |
| sovereign | `oci://registry.hort.rs/hort-charts/hort-server` | `registry.hort.rs` — images resolve from `registry.hort.rs` |

Installing the **sovereign flavor** gets you a fully self-contained
deployment with no extra `--set` or overlay:

```bash
helm install hort oci://registry.hort.rs/hort-charts/hort-server \
  -f my-values.yaml
```

`my-values.yaml` is still your own file — `postgres.{app,admin}.existingSecret`,
`publicBaseUrl`, `auth.oidc.*`, and everything else `install.md`
covers. Nothing here changes: the sovereign flavor differs from the
ghcr flavor *only* in `global.imageRegistry`'s packaged default.

If you'd rather install the ordinary ghcr flavor but still want
everything sovereign, layer the
[`examples/registry-hort-rs/`](../../../../deploy/helm/hort-server/examples/registry-hort-rs/)
overlay instead — same effect, opt-in rather than default. See that
overlay's README for the exact command and the per-component
resolution table.

## What resolves from where

With `global.imageRegistry: registry.hort.rs` in effect (packaged
default on the sovereign flavor, or via the overlay):

- `hort-server` and `hort-worker` pull from
  `registry.hort.rs/hort-oci/hort-{server,worker}:<tag>`.
- `dex` (if `auth.dex.enabled`) pulls from
  `registry.hort.rs/hort-base/dex:<pin>` — the pin is whatever
  `auth.dex.image`'s tag is (`v2.41.1` today); the rewrite changes
  only the registry+path prefix, never the tag.
- **Postgres is not a chart value.** The chart is external-DB by
  design — no bundled Postgres subchart (deferred; see
  `docs/plans/self-contained-registry-chart.md` §5). Point your own
  Postgres deployment's image (a StatefulSet, a CloudNativePG
  `Cluster`, or whatever your Postgres operator manages) at
  `registry.hort.rs/hort-base/postgres:17-alpine` directly — that is
  an edit you make in your own Postgres manifest, not a chart value
  the chart can set for you. See
  [`postgres-roles.md`](./postgres-roles.md) for the Postgres
  provisioning steps this sits alongside.

## The cold-start property

Once installed this way, **nothing in the chain pulls from ghcr.io or
Docker Hub directly** — every image the fleet needs to bring itself
up (server, worker, dex, and the documented Postgres source) is
served by the same hort instance the fleet is joining. Direct-upstream
(`ghcr.io/dexidp/dex`, `docker.io/postgres`) exists only as
containerd's fallback path if a pod is not yet pointed at
`registry.hort.rs` — normal operation never reaches it. This is a
chart/CI/gitops property, not a runtime one: there is no new metric
or trace to check, only the pull source each pod's spec names (see
`kubectl get pod -o jsonpath='{.spec.containers[*].image}'` against a
running deployment).

No node-level `registries.yaml` rewrite, admission webhook, or
containerd mirror configuration is required for this property to
hold for hort's own components — it is entirely a Helm-values-layer
rewrite. (A node-level mirror may still be worth running for
*other* images your cluster pulls; that is out of scope here.)

## See also

- [`install.md`](./install.md) — full install path: prerequisites,
  the two-role Postgres runbook, Secret kinds, OIDC, `helm install`
  scenarios, and post-install verification. Do this first; this
  document only adds the registry-flavor decision on top.
- [`examples-overlays.md`](./examples-overlays.md) — the edge-overlay
  explanation doc (ingress-nginx, Gateway API, external-LB); the
  `examples/registry-hort-rs/` overlay referenced above follows the
  same shape.
- [`values-reference.md`](./values-reference.md) — per-key
  `values.yaml` reference, including `global.imageRegistry`.
- [`helm-chart.md`](../../reference/helm-chart.md) — the chart
  structure reference.
