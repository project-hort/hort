# hort-server Helm chart

Production deployment chart for `hort-server`, the hort backend.
The chart ships a `Deployment`, `Service` (ClusterIP), gitops `ConfigMap`,
optional `PersistentVolumeClaim`, optional `PodDisruptionBudget`, optional
`ServiceMonitor`, optional `NetworkPolicy`, a pre-install/pre-upgrade
migrations `Job`, and a `helm test` Job. **The chart does NOT ship an
Ingress, Gateway, or HTTPRoute** — the operator owns the edge. See
`docs/architecture/how-to/deploy/examples-overlays.md` for the three
canonical edge shapes (ingress-nginx + cert-manager, Gateway API,
external LB).

## Quick start

```sh
helm install hort-server oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server \
  --version 1.0.0-rc.14 \
  --set publicBaseUrl=https://hort.example.com \
  --set auth.oidc.issuerUrl=https://idp.example.com/realms/hort \
  --set auth.oidc.audience=hort-server \
  --set postgres.app.existingSecret=hort-postgres-app \
  --set postgres.admin.existingSecret=hort-postgres-admin
```

## Required values

| Key | Why |
|-----|-----|
| `publicBaseUrl` | Canonical https URL the operator's edge terminates as |
| `auth.oidc.issuerUrl` + `auth.oidc.audience` | Required when `auth.provider=oidc` (the default) |
| `postgres.app.existingSecret` | Runtime DSN as `hort_app_role` (DML only) |
| `postgres.admin.existingSecret` | Runtime DSN as `hort_admin` (DDL — Job only) |
| `storage.s3.{endpoint,bucket,existingSecret}` | Required when `storage.backend=s3` |
| `ephemeralStore.redis.{url|existingSecret}` | Required when `ephemeralStore.backend=redis` |

`values.schema.json` enforces these at `helm install` time.

## Topology

| | Single-replica | HA |
|---|---|---|
| `replicaCount` | 1 | >= 2 |
| `storage.backend` | `filesystem` (PVC, RWO) | `s3` (forced) |
| `ephemeralStore.backend` | `memory` | `redis` (forced) |

The schema blocks the inconsistent middle states. RWO PVC cannot
multi-attach; in-process ephemeral state cannot survive across pods.

## Operator documentation

| Doc | Purpose |
|---|---|
| `docs/architecture/reference/helm-chart.md` | Chart-structure reference: rendered-resource matrix, install-time schema rules, hook ordering, workload wiring, chart-vs-binary caveats |
| `docs/architecture/reference/server-and-worker-configuration.md` | Every binary env var + CLI subcommand the chart renders into |
| `docs/architecture/how-to/deploy/install.md` | Full operator install playbook (eight sections, ~400 lines) |
| `docs/architecture/how-to/deploy/values-reference.md` | Every values key documented with type, default, and rationale |
| `docs/architecture/how-to/deploy/examples-overlays.md` | Three edge-shape overlays |
| `docs/architecture/how-to/deploy/security-hardening-checklist.md` | Security control cross-walk |
| `docs/architecture/how-to/wire-secrets.md` | Secret-mount conventions (used by `secrets.mounts`) |
| `docs/architecture/how-to/declare-gitops-config.md` | Gitops config layout (used by `gitopsConfig`) |

## Versioning

Chart version and app version are coupled — they advance together. The
current release ships chart `version: 1.0.0-rc.14` with
`appVersion: 1.0.0-rc.14`.
