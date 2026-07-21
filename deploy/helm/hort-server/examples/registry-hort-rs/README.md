# Overlay: sovereign registry (`registry.hort.rs`)

A minimal values overlay for the `hort-server` chart that rewrites
every image reference the chart templates onto `registry.hort.rs`
instead of `ghcr.io` / `docker.io` — server, worker, and dex (if
enabled) all resolve sovereign. The chart's own external-Postgres
image is the one piece this overlay cannot set, because the chart
does not run Postgres; see below.

## When to pick this overlay

Pick this when you want the running fleet to resolve every image it
pulls from your own `registry.hort.rs` instance rather than directly
from ghcr.io / Docker Hub — no proxy admission controller, no node
`registries.yaml` rewrite, no mirror configuration outside the chart
itself. Typical drivers: air-gapped or restricted-egress clusters,
supply-chain policies that require every pulled image to come from an
operator-controlled registry, or simply dogfooding hort as your own
registry of record.

If you install the **registry.hort.rs chart flavor**
(`oci://registry.hort.rs/hort-charts/hort-server` — published
alongside the default ghcr flavor, see
[the how-to](../../../../docs/architecture/how-to/deploy/self-contained-registry-install.md))
this overlay is **redundant**: that flavor's packaged `values.yaml`
already defaults `global.imageRegistry` to `registry.hort.rs`. This
overlay exists for the case where you install the ordinary ghcr
flavor but still want everything sovereign.

## Install

```bash
helm install hort oci://registry.hort.rs/hort-charts/hort-server \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/registry-hort-rs/values.yaml
```

Or, layered on the ghcr flavor:

```bash
helm install hort oci://ghcr.io/project-hort/charts/hort-server \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/registry-hort-rs/values.yaml
```

`my-values.yaml` is the operator's own file — `postgres.{app,admin}.existingSecret`,
`publicBaseUrl`, `auth.oidc.*`, and everything else the base
[install guide](../../../../docs/architecture/how-to/deploy/install.md)
covers. This overlay only touches `global.imageRegistry`.

## What resolves from where

| Component | Without this overlay | With this overlay |
|---|---|---|
| `hort-server` | `ghcr.io/project-hort/hort-server:<tag>` | `registry.hort.rs/hort-oci/hort-server:<tag>` |
| `hort-worker` | `ghcr.io/project-hort/hort-worker:<tag>` | `registry.hort.rs/hort-oci/hort-worker:<tag>` |
| `dex` (if `auth.dex.enabled`) | `ghcr.io/dexidp/dex:<pin>` | `registry.hort.rs/hort-base/dex:<pin>` |
| Postgres (external, operator-managed) | whatever the operator's Postgres deployment already pulls | point it yourself at `registry.hort.rs/hort-base/postgres:17-alpine` |

The rewrite is registry+path-prefix only — the tag/pin on each image
is untouched, so `dex`'s resolved tag is still whatever
`auth.dex.image` in `values.yaml` pins today (`v2.41.1`), just served
from `hort-base` instead of `ghcr.io/dexidp`.

## The key promise: no node `registries.yaml` changes

Every rewrite above happens at the Helm-values layer — the rendered
Pod specs simply name `registry.hort.rs/...` images directly. Nothing
requires editing containerd's `/etc/containerd/certs.d/` mirror
configuration, a cluster-wide `ImagePolicyWebhook`, or any node-level
registry rewrite. An operator who only ever wants the fleet's own
images sovereign gets that from chart values alone; a node-level
mirror (if one already exists for unrelated reasons) is neither
required nor assumed here.

## Pitfall: Postgres is not a chart value

Don't look for a `postgres.image` key — there isn't one. The chart is
external-DB by design (no bundled Postgres subchart); Postgres is
whatever the operator already provisions and points at via
`postgres.{app,admin}.existingSecret` DSNs. Pulling that Postgres
image from `registry.hort.rs/hort-base/postgres:17-alpine` is a
change you make in *your own* Postgres deployment manifest (a
StatefulSet, a CloudNativePG `Cluster`, or whatever your Postgres
operator uses) — this overlay cannot reach into that resource.
