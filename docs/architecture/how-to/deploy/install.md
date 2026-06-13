# Install `hort-server` on Kubernetes

This guide takes operators from "I have kubectl access" to
"`hort-server` is serving traffic". Covers cluster prerequisites, the
two-role Postgres runbook, the Secret kinds the chart consumes, OIDC
configuration with a Keycloak worked example, three `helm install`
scenarios (Minimal-OIDC, HA-S3-Redis, No-IdP-bootstrap), the
edge-overlay sketch, and a six-command post-install verification.

Chart reference:
[`helm-chart.md`](../../reference/helm-chart.md).
Chart source: `deploy/helm/hort-server/`. Published at
`oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server`.

---

## 1. Prerequisites

Before `helm install` you need:

- **Kubernetes ≥ 1.27.** PSS-restricted defaults (`runAsNonRoot`,
  `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem`) are
  applied unconditionally; older clusters need admission overrides.
- **Helm v3.8+** for OCI-chart support; templates are linted against v3.17.
- **`kubectl`** with cluster-admin or namespace-admin in the target
  namespace.
- **An OIDC provider** (recommended). Keycloak, Okta, Auth0, Azure
  AD, Google Workspace, or any compliant generic OIDC issuer.
  `auth.provider: oidc` default fails fast if `issuerUrl` /
  `audience` are unset. **OR** the no-IdP fallback path documented
  in §5.3 — `auth.provider: disabled` + `auth.nativeTokens.enabled:
  true` — for evaluation, air-gapped sites, or appliance deployments
  where bringing in an IdP is disproportionate. The no-IdP path is
  operationally functional but locks all admin work to paste-token
  CLI; introduce OIDC as soon as a provider is available. The
  `auth.provider: basic` enum value is retired — values files
  carrying it now fail `helm install`'s schema validation.
- **An external Postgres ≥ 14.** No bundled subchart — operators
  provision out-of-band (RDS, Cloud SQL, `bitnami/postgresql`, CNPG)
  and supply two role DSNs per §2 + §3. The canonical role-grant
  recipe (including `ALTER DEFAULT PRIVILEGES` — the gotcha operators
  most often miss) lives in
  [postgres-roles.md](postgres-roles.md).
- **A storage backend.** Filesystem (default, RWO PVC, single replica
  only — PVC carries `helm.sh/resource-policy: keep` so disk
  survives `helm uninstall`) or S3-compatible (AWS S3, MinIO, zot,
  Garage; required for `replicaCount > 1`).
- **(HA only) Redis ≥ 6** with a password-authenticated DSN.
  `replicaCount > 1` requires `ephemeralStore.backend: redis` — the
  in-memory store cannot share state across pods.

### Storage caveat — range-read integrity (filesystem backend)

When the chart uses `storage.backend: filesystem` (the default), range-read
responses to large blob downloads are served by streaming offsets out of
the on-disk file without re-verifying the SHA-256 of the slice against the
manifest digest. The whole-object integrity check happens at PUT time (the
CAS guarantee), and an offset read of an unmodified file returns the same
bytes. The narrow risk is host-level corruption — filesystem bitrot, or a
concurrent process tampering with files under the PVC mount — where a
partial slice read could differ from the originally-stored content without
a checksum mismatch surfacing. Operators with a strict
integrity-on-every-read requirement should use `storage.backend: s3` (the
S3 adapter re-verifies on slice) or wait for the planned chunked-CAS
work. This is an accepted, documented limitation of the filesystem
backend.

The chart ships a daily `hort-server scrub` CronJob
(`templates/cronjob-scrub.yaml`, gated by `scheduledTasks.scrub.enabled`,
default true) that backstops at-rest corruption — it walks every blob
and re-verifies the SHA-256. Operators on range-heavy workloads
should treat this as load-bearing and pick a cadence that fits their
detection budget. See the
[CAS storage explanation](../../explanation/cas-storage.md#background-integrity-scrub)
for the schedule and `actionOnMismatch` knob (`alert` flag-only;
`tombstone` auto-blocks corrupted artifacts via the existing
quarantine state machine).

---

## 2. Provision the two Postgres roles

The chart takes **two DSNs**, never one:

- `hort_admin` — DDL role. Used **only** by the migrations Job;
  owns the schema.
- `hort_app_role` — DML role. Used by the runtime Deployment. Has
  `INSERT, SELECT` on `events` (append-only event store); no
  `UPDATE`, `DELETE`, or DDL anywhere. A compromised pod cannot
  mutate the audit log.

Generate the two passwords first — these are the values you put in
the Secrets in §3:

```bash
HORT_ADMIN_PASSWORD="$(pwgen -s 32 1)"
HORT_APP_PASSWORD="$(pwgen -s 32 1)"
```

> **Abbreviated excerpt** — use the complete recipe in
> [`postgres-roles.md`](postgres-roles.md) for a production
> provisioning. It includes `CREATEROLE` on `hort_admin` and the
> `ALTER DEFAULT PRIVILEGES` grants that the migrations need for
> tables created after initial install.

Connect to Postgres as a superuser and provision:

```sql
CREATE DATABASE hort;
\connect hort

-- DDL role: owns the schema, runs migrations.
CREATE ROLE hort_admin LOGIN PASSWORD '<HORT_ADMIN_PASSWORD>';
GRANT ALL PRIVILEGES ON DATABASE hort TO hort_admin;
GRANT ALL ON SCHEMA public TO hort_admin;
ALTER DATABASE hort OWNER TO hort_admin;

-- DML role: runtime. Table-level grants land AFTER migrations.
CREATE ROLE hort_app_role LOGIN PASSWORD '<HORT_APP_PASSWORD>';
GRANT CONNECT ON DATABASE hort TO hort_app_role;
GRANT USAGE ON SCHEMA public TO hort_app_role;
```

After the migrations Job has completed (§7 verifies this), reconnect
as `hort_admin` and grant the runtime role exactly what the binary
needs:

```sql
\connect hort hort_admin

GRANT INSERT, SELECT ON events TO hort_app_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO hort_app_role;
-- Read-only on projection tables (repositories, RBAC, …); gitops
-- mutations go through the admin Job, never the runtime Deployment.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO hort_app_role;
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM hort_app_role;
```

Verify the role separation:

```bash
psql "postgres://hort_app_role:${HORT_APP_PASSWORD}@<host>:5432/hort" \
  -c "UPDATE events SET stream_id='x' WHERE false;"
# Expected: ERROR: permission denied for table events
```

If the `UPDATE` is permission-denied, the role split is correct. If
it succeeds, re-run the `REVOKE` block above.

---

## 3. Provision Secrets

The chart consumes four kinds of Kubernetes `Secret`. Create them in
the target namespace before `helm install`.

### 3.1 `postgres-app-dsn` — runtime DSN (always required)

```bash
kubectl create secret generic hort-postgres-app \
  --namespace hort \
  --from-literal=DATABASE_URL='postgres://hort_app_role:<HORT_APP_PASSWORD>@pg.example.com:5432/hort'
```

Referenced by `postgres.app.existingSecret: hort-postgres-app`. The Secret
**data key** is `DATABASE_URL` (matching the default `postgres.app.secretKey`)
— this is the key *inside* the Secret, independent of the env-var name. The
chart maps it to the container env var **`HORT_DATABASE_URL`** (the canonical
DSN var; the binary falls back to bare `DATABASE_URL` — Backlog 078 Item 5). To
use a different data-key name, set `postgres.app.secretKey` to match.

### 3.2 `postgres-admin-dsn` — migrations DSN (always required)

```bash
kubectl create secret generic hort-postgres-admin \
  --namespace hort \
  --from-literal=DATABASE_URL='postgres://hort_admin:<HORT_ADMIN_PASSWORD>@pg.example.com:5432/hort'
```

Referenced by `postgres.admin.existingSecret: hort-postgres-admin`. The
chart mounts this **only** on the pre-install Job — never on the
runtime Deployment.

### 3.3 `s3-credentials` — S3 access (only when `storage.backend: s3`)

```bash
kubectl create secret generic hort-s3-creds \
  --namespace hort \
  --from-literal=AWS_ACCESS_KEY_ID='AKIA...' \
  --from-literal=AWS_SECRET_ACCESS_KEY='...'
```

Referenced by `storage.s3.existingSecret: hort-s3-creds`. The keys must
be exactly `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` — these
become env vars verbatim.

### 3.4 `redis-url` — Redis DSN (only when `ephemeralStore.backend: redis`)

```bash
kubectl create secret generic hort-redis-creds \
  --namespace hort \
  --from-literal=REDIS_URL='redis://:<password>@redis.example.com:6379/0'
```

Referenced by `ephemeralStore.redis.existingSecret: hort-redis-creds`.

### 3.5 Upstream credentials and the mTLS surface

For pull-through repos needing an upstream PAT, mTLS client cert,
custom CA bundle, or cert pinning, populate `secrets.mounts`. The
chart projects each entry under `secrets.fileRoot`
(default `/etc/hort-server/secrets`) and the binary's `SecretPort`
reads it at resolve time. See
[`wire-secrets.md`](../wire-secrets.md) for the full pattern catalog
and [`declare-gitops-config.md`](../declare-gitops-config.md) for the
gitops `ArtifactRepository` shape that references the mounted files
via `proxy.secretRef`.

---

## 4. Configure the OIDC provider

`auth.provider: oidc` is the default. The binary validates incoming
bearer tokens against the issuer's JWKS endpoint and checks the
audience claim matches `auth.oidc.audience`. The repository ships a
known-good Keycloak realm at `deploy/compose/keycloak/realm.json` as the
worked example — Okta, Auth0, Azure AD, Google Workspace, and
generic OIDC use the same mapping.

### 4.1 Map realm.json knobs to chart values

`cat deploy/compose/keycloak/realm.json` and locate the following:

| Realm.json path | Chart value | Notes |
|---|---|---|
| `realm.realm` | suffix of `auth.oidc.issuerUrl` | The issuer URL the binary discovers from is `https://<keycloak-host>/realms/<realm.realm>`. |
| `realm.clients[?clientId=='hort-server'].clientId` | `auth.oidc.audience` | Must match exactly — the binary rejects tokens whose `aud` claim does not contain this value. |
| `realm.clients[?clientId=='hort-server'].defaultClientScopes` | (informational) | Includes `groups` so RBAC group claims travel in the access token. |
| `realm.clients[?clientId=='hort-server'].protocolMappers[?name=='audience-hort-server']` | (informational) | The audience mapper that injects the `aud` claim. Without this mapper, tokens lack the audience and the binary rejects them. |

### 4.2 Discover the JWKS endpoint

The binary auto-discovers JWKS from the issuer's
`.well-known/openid-configuration` document. Confirm it resolves:

```bash
curl -fsS https://idp.example.com/realms/hort/.well-known/openid-configuration \
  | jq -r .jwks_uri
# Expected: https://idp.example.com/realms/hort/protocol/openid-connect/certs
```

Resulting chart values:

```yaml
auth:
  provider: oidc
  oidc:
    issuerUrl: https://idp.example.com/realms/hort
    audience: hort-server
    groupsClaim: groups
    jwksCacheTtlSeconds: 600
```

### 4.3 Other IdPs

`issuerUrl` is the IdP's `iss` claim value; `audience` is whatever
your client/app configuration injects into the token's `aud` claim.
Auth0 calls this the "API audience"; Okta calls it the "audience" on
the authorization server; Azure AD's audience is the Application ID
URI.

---

## 5. `helm install`

Three install scenarios. Each shows the values snippet plus the
`helm install` invocation. Run from a working directory containing
the values YAML.

### 5.1 Minimal-OIDC (single replica, filesystem, OIDC)

The most common starting deployment. One pod, one PVC, OIDC auth.

```yaml
# values.yaml
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

```bash
helm install hort oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server \
  --version 2.0.0-rc.7 -n hort --create-namespace \
  -f values.yaml
```

### 5.2 HA-S3-Redis (three replicas, S3 storage, Redis ephemeral)

The production HA path. Multi-pod deployments require
S3 (RWO PVC cannot multi-attach) and Redis (in-memory ephemeral
store cannot share state across pods). The chart's
`values.schema.json` blocks the inconsistent middle states.

Adds to the §5.1 values: `replicaCount`, `trustedProxyCidrs`,
S3 storage block, Redis ephemeral block, ServiceMonitor toggle, PDB.

```yaml
# values-ha.yaml — full file (postgres + auth identical to §5.1)
publicBaseUrl: https://hort.example.com
replicaCount: 3
trustedProxyCidrs: ["10.244.0.0/16", "::1/128"]

auth:
  provider: oidc
  oidc:
    issuerUrl: https://idp.example.com/realms/hort
    audience: hort-server

postgres:
  app: {existingSecret: hort-postgres-app}
  admin: {existingSecret: hort-postgres-admin}

storage:
  backend: s3
  s3:
    endpoint: https://s3.example.com
    region: us-east-1
    bucket: hort-artifacts
    pathStyle: true
    existingSecret: hort-s3-creds

ephemeralStore:
  backend: redis
  redis: {existingSecret: hort-redis-creds}

metrics:
  serviceMonitor: {enabled: true}

podDisruptionBudget:
  minAvailable: 2
```

```bash
helm install hort oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server \
  --version 2.0.0-rc.7 -n hort --create-namespace \
  -f values-ha.yaml
```

### 5.3 No-IdP bootstrap (no OIDC provider available)

For evaluation when an OIDC IdP is genuinely unavailable, for
air-gapped sites, or for appliance deployments where bringing in an
IdP is disproportionate. The prior `auth.provider: basic` recipe is
retired — the HTTP-Basic-against-local-admin-row identity path it
gated was deleted end-to-end (see `docs/auth-catalog.md` Entry 8),
and the producer surface was retired with it. The no-IdP path
is `auth.provider: disabled` + `auth.nativeTokens.enabled: true`:
the composition root wires `AuthContext::BearerOnly` and the only
inbound identity surface is the native-token validator
(`Bearer hort_<kind>_*`). Operators bootstrap a workstation token via
the `hort-server admin issue-svc-token` CLI and consume it with
`hort-cli auth login --paste`.

This path is operationally functional but locks all admin work to
paste-token CLI — there is no browser-driven SSO flow. Migrate to
§5.1 once an IdP is available.

**Prerequisite — generate the OCI token signing key.** Whenever
`nativeTokens.enabled: true`, the binary boot-fails with
`ConfigError::OciTokenSigningKeyMissing` unless an Ed25519 PEM is
provisioned. This is mandatory even if you never serve OCI/Docker
artifacts:

```bash
openssl genpkey -algorithm Ed25519 -out /tmp/oci-signing.pem
chmod 0600 /tmp/oci-signing.pem

kubectl -n hort create secret generic hort-oci-signing-key \
    --from-file=hort-oci-token-signing-key.pem=/tmp/oci-signing.pem

shred -u /tmp/oci-signing.pem   # plaintext only in the Secret now
```

Operator instances that rotate keys regularly should also wire the
previous key via `auth.nativeTokens.signingKey.prevExistingSecret`
so JWTs minted under the old key validate during the rotation
window — see §11.3 of [local-bringup.md](local-bringup.md) for the
rotation mechanics (identical between k8s and single-host).

**Values:**

```yaml
# values-noidc.yaml
publicBaseUrl: https://hort.internal.example   # operator's edge URL
requireHttps: true                            # set to false ONLY on trusted-LAN/HTTP

auth:
  provider: disabled
  nativeTokens:
    enabled: true
    signingKey:
      existingSecret: hort-oci-signing-key
      secretKey: hort-oci-token-signing-key.pem

postgres:
  app: {existingSecret: hort-postgres-app}
  admin: {existingSecret: hort-postgres-admin}

storage: {backend: filesystem}
ephemeralStore: {backend: memory}
```

The chart ships a test fixture
([`deploy/helm/hort-server/test-values-local-bringup.yaml`](../../../../deploy/helm/hort-server/test-values-local-bringup.yaml))
that exercises this exact recipe — copy it as a starting point and
adapt `publicBaseUrl` + the two postgres secret names.

**Install:**

```bash
helm install hort oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server \
  --version 2.0.0-rc.23 -n hort --create-namespace \
  -f values-noidc.yaml
```

**Bootstrap the workstation operator token.** The chart's
`NOTES.txt` reminds you of this; here it is for reference:

```bash
kubectl -n hort exec -it deploy/hort-server -- \
    hort-server admin issue-svc-token \
        --name=ops \
        --permission=admin \
        --output=stdout
# → hort_svc_<48-chars>

# On the operator's workstation:
hort-cli auth login --paste --server https://hort.internal.example
# Paste the hort_svc_… at the prompt. The token is stored in the
# workstation's keyring (or ~/.config/hort-cli/config.toml when no
# keyring is available).
```

The `admin issue-svc-token` command is **DSN-authorised** — it needs
operator-level Postgres access (which the in-pod execution has via
the admin DSN), not a caller-principal Bearer token. No HTTP, no
authentication. Idempotent on re-run; pass `--rotate` to force a
fresh value.

**Cron-job and publishing-pipeline tokens** follow the same minting
pattern but with different caps (`admin_task_invoke` for cron jobs,
`write` for CI publishing). The full recipes — including per-format
client integration (npm, PyPI, Cargo, Maven, Docker/OCI, Helm) and
CI-system integration (GitHub Actions, GitLab CI, Jenkins) — live in
[local-bringup.md](local-bringup.md) §5.2, §7, and §10. The
k8s-specific equivalent is the chart's
`worker.cronjobs[].svcTokenName` post-install Job (see
[values-reference.md](values-reference.md) `worker.cronjobs.*`),
which calls `admin issue-svc-token` from a Helm hook Pod and writes
the token into a Secret that the CronJob pod mounts as `HORT_TOKEN`.

**Migrate to §5.1 once an IdP is available.** The schema is the
same; flip `auth.provider: disabled → oidc`, add the
`auth.oidc.{issuerUrl, audience, …}` block per §4, drop
`nativeTokens.enabled` (or keep it on if you want both OIDC and
PAT-via-Bearer working in parallel; the two paths coexist cleanly).
Existing `hort_svc_*` tokens minted on the no-IdP path continue to
validate post-flip — they live in the same `api_tokens` table the
OIDC-path tokens use.

---

## 6. Wire the edge

The chart ships a ClusterIP Service only — no Ingress, no Gateway,
no HTTPRoute. Operators own the edge. Three example
overlays under `deploy/helm/hort-server/examples/`:

- **`ingress-nginx-cert-manager/`** — ingress-nginx + cert-manager
  TLS. Pick this for the most common in-cluster ingress topology.
- **`gateway-api/`** — Gateway API v1 (`Gateway` + `HTTPRoute`). Pick
  this for clusters running Istio, Cilium, Contour, or NGINX Gateway
  Fabric where forward-compatible routing matters.
- **`external-lb/`** — Service `type: LoadBalancer` with TLS
  terminated by a cloud LB (AWS NLB, GCP TCP/SSL LB). Pick this for
  cloud deployments where the LB is the TLS terminator.

All three overlays set `HORT_PUBLIC_BASE_URL` to the externally-visible
URL and populate `trustedProxyCidrs` with the edge's source CIDR. See
[`examples-overlays.md`](examples-overlays.md)
for the per-overlay walk-through.

---

## 7. Verify

After `helm install` returns, run these six commands. They cover the
minimum surface of a successful install. Substitute
`<ns>` with your namespace and `<svc-or-ingress>` with the
cluster-internal service URL (`kubectl -n <ns> get svc`) or the
public ingress hostname.

```bash
# 7.1 Pods Ready — every hort-server-<...> pod READY 1/1, Running.
kubectl get pods -n <ns>

# 7.2 Migrations Job completed — expected output: True.
# Replace hort-server-migrate with <release-name>-hort-server-migrate.
kubectl get job -n <ns> hort-server-migrate \
  -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}'

# 7.3 /healthz — expected: 200 OK with body "ok".
curl -fsS http://<svc-or-ingress>/healthz

# 7.4 /readyz — expected: 200 OK once migrations succeeded AND at
#               least one Deployment pod is Ready.
curl -fsS http://<svc-or-ingress>/readyz

# 7.5 /metrics — expected: 401 Unauthorized (the metrics-auth
#                gate). A 200 means
#                metrics.requireAuth=false — re-check your values.
curl -i http://<svc-or-ingress>/metrics

# 7.6 OIDC-authenticated admin request — expected: 200 with body []
#     on a fresh install or the repositories configured via gitops.
#     A 401 means the audience or issuer doesn't match — re-check §4.
TOKEN="$(curl -fsS -d 'grant_type=password' \
  -d 'client_id=hort-server' -d 'client_secret=<secret>' \
  -d 'username=<admin>' -d 'password=<password>' \
  https://idp.example.com/realms/hort/protocol/openid-connect/token \
  | jq -r .access_token)"
curl -fsS -H "Authorization: Bearer $TOKEN" \
  http://<svc-or-ingress>/admin/repositories
```

### 7.7 Gitops boot apply (conditional)

If you populated `gitopsConfig:` in your values, validate that the
ConfigMap projection reached the binary's directory walker — the
chart's ConfigMap volume is mounted through a Kubernetes-specific
two-level symlink layout, and a regression on the binary's
symlink-following walker would surface as `files_loaded: 0` on
boot. The bundled assertion script reads the runtime pod's tracing
output and asserts both the walk and the apply succeeded:

```bash
./scripts/k8s-tests/test-gitops-k8s-configmap.sh \
    --release <release-name> \
    --namespace <ns>
```

Cluster-targeting flags (operators with kubectl configured against
a different default cluster):

```bash
KUBECONFIG=/path/to/cluster.kubeconfig \
    ./scripts/k8s-tests/test-gitops-k8s-configmap.sh \
        --release <release-name> --namespace <ns>

# or
./scripts/k8s-tests/test-gitops-k8s-configmap.sh \
    --kubeconfig /path/to/cluster.kubeconfig \
    --release <release-name> --namespace <ns>

# or pin to a non-current context within your existing kubeconfig
./scripts/k8s-tests/test-gitops-k8s-configmap.sh \
    --context my-test-cluster \
    --release <release-name> --namespace <ns>
```

The script is read-only — `kubectl get` / `logs` / `version` only,
no mutations — and prints the resolved kubeconfig path + context in
its header so you have one-screen confirmation of which cluster
you are probing before any pod lookup runs. Run `--help` for the
full WHY / WHAT prologue (the script's own doc-comments are the
canonical reference).

Skip this step if `gitopsConfig:` is empty (the chart's default).
With no envelopes declared, the binary's gitops boot is a no-op
and there is nothing to validate.

For operator-tunable HTTP timeouts see
[`http-transport-timeouts.md`](../http-transport-timeouts.md).

---

## 8. Appendix — starter Prometheus rules

When `metrics.serviceMonitor.enabled: true`, the chart renders a
`ServiceMonitor` for the Prometheus Operator stack. The starter
`PrometheusRule` below covers the critical alerts derivable from the
`hort_*` metric surface. Thresholds are illustrative.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: hort-server-rules
  namespace: hort
  labels: {app.kubernetes.io/part-of: hort-server}
spec:
  groups:
    - name: hort-server.critical
      rules:
        - alert: HortEventStoreFailures
          expr: sum(rate(hort_event_store_appends_total{result!="success"}[5m])) > 0.1
          for: 5m
          labels: {severity: critical}
          annotations:
            summary: hort-server event-store append failures
            description: Non-success rate > 0.1/s — check Postgres connectivity.
        - alert: HortStorageErrors
          expr: sum(rate(hort_storage_operations_total{result!="success"}[5m])) > 0.1
          for: 5m
          labels: {severity: critical}
          annotations:
            summary: hort-server storage backend errors
            description: For S3 check IAM/bucket policy; for filesystem check PVC capacity.
    - name: hort-server.warning
      rules:
        - alert: HortLoadShedding
          expr: sum(rate(hort_http_responses_total{result="shed"}[5m])) > 1
          for: 5m
          labels: {severity: warning}
          annotations:
            summary: hort-server is shedding load
            description: At HORT_MAX_INFLIGHT cap — under-provisioned or cap too low.
```


A matching `ServiceMonitor` is rendered automatically when
`metrics.serviceMonitor.enabled: true`; ensure the Prometheus
Operator's namespace selector covers the release namespace.

---

## See also

- [`values-reference.md`](values-reference.md) — every chart key documented (Sprint 3 — Item 7).
- [`examples-overlays.md`](examples-overlays.md) — edge-wiring overlays (Sprint 3 — Item 8).
- [`security-hardening-checklist.md`](security-hardening-checklist.md) — chart hardening posture (Sprint 3 — Item 9).
- [`../wire-secrets.md`](../wire-secrets.md) — operator-side secret-sync pattern catalog.
- [`../declare-gitops-config.md`](../declare-gitops-config.md) — `$HORT_CONFIG_DIR` shape and gitops apply contract.
- [`../http-transport-timeouts.md`](../http-transport-timeouts.md) — operator-tunable HTTP timeout knobs.
