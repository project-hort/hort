# Install hort on Kubernetes with Helm

**Goal:** deploy `hort-server` using the repository's Helm chart. This page covers the recommended *single-replica OIDC* baseline; high availability and specialized storage are separate operating modes.

## Prerequisites

| Dependency | Requirement |
| --- | --- |
| Kubernetes | 1.27+ |
| Helm | 3.8+ with OCI chart support |
| PostgreSQL | External PostgreSQL 14+; two DSNs with correctly provisioned roles |
| Authentication | OIDC issuer URL and audience; fallback no-IdP mode is a separate procedure |
| Storage | [Filesystem/PVC or S3-compatible backend](storage.md); S3 plus Redis for multiple replicas |
| Network | Operator-owned TLS edge; chart does **not** ship Ingress/Gateway/HTTPRoute |

Provision `hort_admin` and `hort_app_role` following [Prepare PostgreSQL](postgresql.md). The migrations role requires `CREATEROLE` and default privileges as defined in that recipe. Store connection strings in Kubernetes Secrets instead of inline Helm values.

## Create namespace and database Secrets

```bash
kubectl create namespace hort
kubectl -n hort create secret generic hort-postgres-app \
  --from-literal=DATABASE_URL='postgres://hort_app_role:<PASSWORD>@<DB_HOST>:5432/hort'
kubectl -n hort create secret generic hort-postgres-admin \
  --from-literal=DATABASE_URL='postgres://hort_admin:<PASSWORD>@<DB_HOST>:5432/hort'
```

These commands contain explicit placeholders; replace them before execution. In production, use your organization's secret-management mechanism rather than passing credentials in a shell command that may end up in history. The secret **key** must be `DATABASE_URL` unless you override `postgres.*.secretKey`.

## Configure chart values

Save `values.yaml`:

```yaml
publicBaseUrl: https://hort.example.com
auth:
  provider: oidc
  oidc:
    issuerUrl: https://idp.example.com/realms/hort
    audience: hort-server
postgres:
  app: {existingSecret: hort-postgres-app}
  admin: {existingSecret: hort-postgres-admin}
storage:
  backend: filesystem
  filesystem:
    pvc: {enabled: true, size: 50Gi}
ephemeralStore: {backend: memory}
```

**This fragment is not a complete network configuration.** The chart defaults to `networkPolicy.enabled: true` with **empty application ingress and egress rule lists**, which deny traffic to and from the application pods. Before installation, supply the ingress rules for your edge/probes and explicit egress rules for PostgreSQL, OIDC, DNS, upstream registries and any enabled storage or external services. The exact CIDRs, pod selectors and namespace selectors depend on your cluster, so there is no safe portable rule to paste here. Verify the rendered `NetworkPolicy` objects and the full rendered manifests against your network layout. Do not turn off enforcement simply to make the example pass.

Confirm the supported chart version and values for your deployment against the chart documentation before applying these examples. The commands below illustrate version `0.17.0`.

## Install and verify

```bash
helm install hort oci://ghcr.io/project-hort/charts/hort-server \
  --version 0.17.0 -n hort -f values.yaml
kubectl -n hort get pods
kubectl -n hort get jobs
curl -fsS https://hort.example.com/healthz
curl -fsS https://hort.example.com/readyz
```

An ingress or gateway **must already route** your public URL to the chart's service, with TLS terminated appropriately. If the migrations Job is not complete, review its logs and the database role recipe before attempting ad hoc grants.

## Operational constraints

- Default `networkPolicy.enabled` is on; review and explicitly define ingress and egress. Migration Jobs require access to Postgres.
- `replicaCount > 1` requires S3-compatible artifact storage **and** Redis ephemeral state.
- Worker deployment and scanner resource sizing are separate from the API server; see worker configuration before enabling scan-heavy workloads.
- Metrics require a dedicated configured listener and bearer authorization (`read_metrics`), rather than anonymous scrapes.
- Do not perform a production rollout without confirming image/chart versions, backup/restore practices, external secrets, and your organization's identity and storage configuration.

## Next steps

Define repositories via `HORT_CONFIG_DIR` and validate with `hort-server validate-config --strict`. See [Declarative configuration](../configuration/declarative.md) for the operator workflow. For higher availability, follow [Configure artifact storage](storage.md) to plan S3-compatible storage and Redis together, and validate the resulting Helm configuration for your environment.

