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

## NetworkPolicy — what it bounds, and what it does not

`networkPolicy.enabled` is **on by default** and renders two policies: a
deny-all-until-you-populate posture on the app pods (`networkPolicy.ingress`
/ `networkPolicy.egress`, both empty by default), and an additive allowance
on this release's Job/CronJob pods so the pre-install `migrate` hook can
reach a Postgres whose address the chart never sees. Setting
`networkPolicy.enabled: false` disables both.

The Job-scoped policy selects its pods by label — this release's
`app.kubernetes.io/{name,instance}` plus the `hort-server.io/job` key every
Job/CronJob pod template carries — because pod labels and namespaces are the
whole of what a NetworkPolicy can see. It cannot see a ServiceAccount, an
owner reference, or whether Helm created the pod. **Those labels are a scope,
not a credential:** anyone who may create or label a Pod in the namespace can
write all three onto a pod of their own and be selected. No NetworkPolicy can
close that and this chart does not claim to — a principal holding create-Pod
in the release's namespace is not an attacker a NetworkPolicy defends
against. Keep Pod creation in that namespace off untrusted principals;
network position never substitutes for authorization.

What the chart does bound is how much a selected pod gets. By default that is
DNS plus unrestricted egress, because the destinations live in opaque Secret
DSNs. If you know yours, set **`networkPolicy.jobEgress`** to your own
Kubernetes egress rules: they replace the unrestricted rule (the DNS rule
stays), so those Job pods reach what you list and nothing else. Note the
semantics are the opposite of `networkPolicy.egress` — leaving `jobEgress`
empty keeps the shipped allowance rather than denying everything, so an
upgrade changes nothing until you populate it. One allowance covers every
Job/CronJob pod of the release, so cover the union of what they reach:
Postgres, the kube-apiserver, and whatever the scheduled tasks you enable
reach. Getting it wrong fails loudly — `helm install` aborts at the
pre-install hook when the migrate Job cannot reach the database.

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

## Upgrading — Deployment selector change (one-time, per existing install)

The server and worker Deployments' `spec.selector.matchLabels` now each
carry an `app.kubernetes.io/component` discriminator, matching the label
their own pod template already renders. `matchLabels` is immutable
post-create, so `helm upgrade` fails against an existing release with
`spec.selector` is immutable-shaped errors. This is a one-time step per
install; a fresh install needs no action.

Pick one of:

- **Delete-then-upgrade** (brief downtime; pods are recreated):
  ```sh
  kubectl delete deploy <fullname> <fullname>-worker
  helm upgrade hort-server oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server ...
  ```
- **`--cascade=orphan` + re-adoption** (zero-downtime-sensitive installs —
  the orphaned pods keep serving while the new Deployments adopt them):
  ```sh
  kubectl delete deploy <fullname> <fullname>-worker --cascade=orphan
  helm upgrade hort-server oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server ...
  ```
- **Flux-managed installs**: suspend the reconciliation, delete the two
  Deployments, then resume:
  ```sh
  flux suspend helmrelease hort-server
  kubectl delete deploy <fullname> <fullname>-worker
  flux resume helmrelease hort-server
  ```

`<fullname>` is the release's `hort-server.fullname` (defaults to the
release name); the worker Deployment is always `<fullname>-worker`.

## Versioning

Chart version and app version are coupled — they advance together. The
current release ships chart `version: 1.0.0-rc.14` with
`appVersion: 1.0.0-rc.14`.
