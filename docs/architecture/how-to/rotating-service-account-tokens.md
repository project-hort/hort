# Rotate service-account PATs via the worker reconciler

This guide is for operators whose workloads cannot do OIDC
federation and need an automatically rotated PAT delivered into a
k8s Secret. The worker's `ServiceAccountRotationHandler`
mints a fresh PAT on a fixed cadence and writes it into
an operator-declared Secret in an operator-allowed namespace.

For the design rationale see
[ADR 0018](../../adr/0018-auth-catalog-canonical.md) and the
machine-identity entries in [`docs/auth-catalog.md`](../../auth-catalog.md).

---

## 1. When to use this

Federation is preferred. Every workload that can fetch a
short-lived OIDC JWT and exchange it at `/api/v1/auth/exchange`
should — that path is auditable, scoped per workflow, and
requires no rotation discipline. Rotation is the **fallback** for
workloads that genuinely can't do federation.

Common cases that legitimately need the fallback path:

- **Jenkins controllers without an OIDC plugin** — pipelines bake
  credentials into `withCredentials` blocks.
- **GitLab CE / EE older than 15.7** — the `id_tokens:` block
  arrived in 15.7; older instances have no JWT to exchange.
- **`docker pull` from k8s `imagePullSecrets`** — kubelet has no
  in-line federation flow.
- **Legacy on-prem build agents** reading static credentials from
  a config file on disk.

If none of these apply, prefer
[`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md)
or
[`federate-ci-oidc.md`](./federate-ci-oidc.md).

---

## 2. How it works

The reconciler is stateless. On each tick (every 15 minutes by
default), the worker:

1. Lists every `ServiceAccount` envelope that has a
   `fallbackRotation:` block set.
2. For each SA, reads the named k8s Secret in the declared
   namespace. The "last rotated" timestamp lives on the Secret
   itself as the `project-hort.de/last-rotated` **annotation** (annotation,
   not label, because RFC 3339 timestamps contain `:` which k8s
   forbids in label values) — there is no row in hort-server's
   database tracking this.
3. Decides:
   - Namespace not in `worker.rotation.targetNamespaces` →
     log + metric, skip.
   - Existing Secret without `project-hort.de/managed-by=hort-worker` label
     → log + metric, skip (collision; operator must hand off
     ownership explicitly).
   - Existing Secret with `project-hort.de/last-rotated` annotation newer
     than `rotation_interval` ago → debug + metric, skip (fresh).
   - Otherwise (missing or stale) → mint a fresh PAT via
     `ApiTokenUseCase`, write the new Secret via
     `KubernetesSecretWriter`, emit `ServiceAccountTokenRotated`.

The previous PAT stays valid until its natural `expires_at` — the
reconciler does NOT revoke. The `validity ≥ 2 × rotationInterval`
constraint IS the grace window: an old token outlives at least
one full rotation cycle, so consumers have time to reload before
their cached credential becomes unusable.

---

## 3. Choose a format: `dockerconfigjson` vs `opaque`

Two valid Secret shapes. Pick the one your consumer expects.

| Consumer | Format |
|---|---|
| `docker pull` via k8s `imagePullSecrets`, podman, skopeo, helm OCI | `dockerconfigjson` |
| `twine`, `pip`, `npm`, `cargo`, curl, any HTTP-bearer client | `opaque` |
| Jenkins Pipeline `withCredentials` (token-shaped) | `opaque` |

`dockerconfigjson` produces:

```json
{
  "auths": {
    "registry.example.com:5443": {
      "username": "oauth",
      "password": "hort_sa_…",
      "auth": "b2F1dGg6YWtfc2FfLi4u"
    }
  }
}
```

`opaque` produces a Secret with a single `token` key holding the
raw PAT string. Consumers read it via a volume mount + `cat`, or
via an `envFrom: secretRef:` injection.

Both formats receive the same metadata:
- Labels: `project-hort.de/managed-by=hort-worker`,
  `project-hort.de/service-account=<sa-name>`, `project-hort.de/token-id=<UUID>`.
- Annotation: `project-hort.de/last-rotated=<RFC3339 timestamp>` (an
  annotation rather than a label because RFC 3339 timestamps
  contain `:`, which k8s rejects in label values).

The labels are how the reconciler identifies which Secrets it
owns; the annotation drives the freshness check.

---

## 4. Step 1 — enable the reconciler in the chart

Fallback PAT rotation is enabled by a **single** chart toggle:
`scheduledTasks.serviceAccountRotation.enabled`. That one flag drives
*both* the CronJob trigger *and* the worker-side wiring (the
`KubernetesSecretWriter` env block + the per-namespace RBAC) — there is
no separate `worker.rotation.enabled` switch. Edit your Helm values:

```yaml
scheduledTasks:
  adminTasksEnabled: true            # umbrella for all admin-task CronJobs
  serviceAccountRotation:
    enabled: true                    # the single rotation toggle
    schedule: "*/15 * * * *"

worker:
  enabled: true                      # the worker performs the rotation
  rotation:                          # worker-side PARAMETERS (not a switch)
    targetNamespaces: [ci-system]
    publicRegistryHost: "registry.example.com:5443"
```

The chart's `values.schema.json` rejects a **half-set** config at
`helm install` / `helm template` (fail-fast, no silent half-on). When
`scheduledTasks.serviceAccountRotation.enabled: true`, the schema
requires all of:

- `scheduledTasks.adminTasksEnabled: true` — the admin-task CronJob
  renders only under this umbrella; without it the single toggle would
  render no CronJob.
- `worker.enabled: true` — the worker pod is the k8s API client that
  writes the managed Secrets.
- `worker.rotation.publicRegistryHost` non-empty — the
  `dockerconfigjson.auths` map has nowhere to point otherwise.

What each key does:

- `scheduledTasks.serviceAccountRotation.enabled` — **the single
  source-of-truth toggle.** Renders the CronJob that hits the worker's
  admin-task endpoint, wires `KubernetesSecretWriter` into the worker
  (`HORT_K8S_SECRET_WRITER_ENABLED`), and renders the per-namespace
  RBAC. When false (default), none of those render.
- `scheduledTasks.serviceAccountRotation.schedule` — cron spec. The
  `5-minute floor` rule documented in the `scheduledTasks` section header
  applies (Idempotency-Key uses minute granularity).
- `worker.rotation.targetNamespaces` — every namespace named here
  gets a per-namespace `Role` + `RoleBinding` rendered by
  `templates/svc-rotation-rbac.yaml`. The list MUST contain every
  namespace any `ServiceAccount.fallbackRotation.targetSecret.namespace`
  points at; mismatches produce `namespace_not_authorized`
  metric ticks and warn logs each tick.
- `worker.rotation.publicRegistryHost` — the registry-host string
  embedded in `dockerconfigjson` Secrets' `auths` map. Typically
  the public DNS name + port consumers will hit
  (`registry.example.com:5443`). Required (schema-enforced) when
  rotation is enabled.
- **Rotation cadence and validity are NOT chart-level values.**
  The chart has no `defaultValidity` / `defaultRotationInterval`
  knobs — each `ServiceAccount` envelope declares its own
  `spec.fallbackRotation.rotationInterval` and
  `spec.fallbackRotation.validity` (see §5 below). The per-SA YAML
  is the only source of truth; mixing SAs with different cadences
  in the same cluster is supported by design.

Apply the chart change and confirm the per-namespace RBAC
rendered:

```bash
kubectl get role,rolebinding -n ci-system | grep rotation
```

You should see one `Role` (`<release>-rotation-ci-system`) and
one `RoleBinding` per target namespace.

---

## 5. Step 2 — declare the `ServiceAccount`

The envelope below produces a `dockerconfigjson` Secret for a
docker-pull client:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: legacy-docker-puller
spec:
  role: reader
  repositories: [oci-internal]
  fallbackRotation:
    targetSecret:
      name: hort-pull-secret
      namespace: ci-system
      format: dockerconfigjson
    rotationInterval: 6h
    validity: 24h
```

And here is the `opaque` shape for a twine / npm / curl
consumer:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: legacy-pypi-pusher
spec:
  role: developer
  repositories: [pypi-internal]
  fallbackRotation:
    targetSecret:
      name: hort-pypi-token
      namespace: ci-system
      format: opaque
    rotationInterval: 6h
    validity: 24h
```

Validation rules the apply pipeline enforces (full list in
[`declare-gitops-config.md`](./declare-gitops-config.md)
`kind: ServiceAccount`):

- `role` ∈ `{developer, reader}` — admin SAs forbidden.
- `repositories` non-empty.
- `fallbackRotation.targetSecret.format` ∈
  `{dockerconfigjson, opaque}`.
- `fallbackRotation.rotationInterval` ≥ `1h`.
- `fallbackRotation.validity` ≥ 2 × `rotationInterval`.
- `targetSecret.namespace` is NOT validated against
  `worker.rotation.targetNamespaces` at apply time — the chart's
  allow-list is a runtime concern. A mismatch produces
  reconciler warnings, not an apply-time rejection.

---

## 6. Step 3 — wire the workload

### 6a. `dockerconfigjson` — image pull

Pods consume `dockerconfigjson` Secrets via `imagePullSecrets`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: ci-system
spec:
  imagePullSecrets:
    - name: hort-pull-secret
  containers:
    - name: app
      image: registry.example.com:5443/oci-internal/my-app:1.2.3
```

kubelet reads the Secret on every pull. When the reconciler
overwrites the Secret with a fresh token, the next pull picks up
the new credential automatically — there is no kubelet cache to
invalidate at the cluster level.

### 6b. `opaque` — HTTP-bearer client

For an `opaque` Secret, mount it as a volume and read the
`token` key:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pypi-pusher
  namespace: ci-system
spec:
  containers:
    - name: app
      image: my-org/pypi-publisher:1.0
      env:
        - name: HORT_TOKEN_FILE
          value: /var/run/secrets/hort/token
      volumeMounts:
        - name: hort-token
          mountPath: /var/run/secrets/hort
          readOnly: true
  volumes:
    - name: hort-token
      secret:
        secretName: hort-pypi-token
```

The container reads the token on each call (`$(cat
$HORT_TOKEN_FILE)`) rather than caching it. kubelet refreshes
volume-mounted Secrets within ~60 seconds. An `envFrom:
secretRef:` injection works too but only refreshes on pod
restart, so volume-mount is preferred for long-running workloads.

---

## 7. The grace-window math

Concrete numbers from the example envelopes:

- `validity = 24h` → every minted PAT has `expires_at = now + 24h`.
- `rotationInterval = 6h` → reconciler mints a fresh PAT every
  6 hours per SA.
- CronJob fires every 15 minutes → within 15 min of an SA
  crossing the staleness threshold, the Secret is updated.

Timeline:

```
T=0     mint #1, expires at T+24h
T=6h    mint #2. #1 still valid (12h remaining).
T=12h   mint #3. #2 still valid (12h), #1 still valid (12h).
T=18h   mint #4. #3 valid 12h, #2 valid 6h, #1 expires.
T=24h   mint #5. #4 valid 12h, #3 valid 6h, #2 expires.
```

At any moment, the most recent token plus the previous one are
both valid. The overlap is exactly one `rotationInterval` —
which is the consumer-side reload budget. A volume-mounted
Secret refreshes within kubelet's ~60-second window; an
`envFrom`-injected Secret refreshes only on pod restart, so
volume-mount is the recommended pattern.

If you tighten `rotationInterval` to `1h` (the minimum), set
`validity` to at least `2h`. The apply pipeline rejects any
envelope where `validity < 2 × rotationInterval`.

---

## 8. Verify it works

Check the per-namespace RBAC exists, wait one CronJob tick, then
inspect the Secret's metadata:

```bash
kubectl get role,rolebinding -n ci-system | grep rotation
kubectl get secret hort-pull-secret -n ci-system \
  -o jsonpath='{.metadata.labels}' | jq .
kubectl get secret hort-pull-secret -n ci-system \
  -o jsonpath='{.metadata.annotations}' | jq .
```

Expect labels:

```json
{
  "project-hort.de/managed-by": "hort-worker",
  "project-hort.de/service-account": "legacy-docker-puller",
  "project-hort.de/token-id": "0e2f8c1a-…"
}
```

Expect annotation:

```json
{
  "project-hort.de/last-rotated": "2026-05-13T10:15:00Z"
}
```

After `rotationInterval` elapses, the `project-hort.de/last-rotated`
annotation and the `project-hort.de/token-id` label update on the next
tick. To force an immediate rotation for testing, `kubectl
delete secret hort-pull-secret -n ci-system` and wait one tick.

The metric `hort_rotation_total{result="rotated"}` increments per
write; the gauge `hort_rotation_lag_seconds{service_account=…}`
shows time since last rotation per SA. Alert on
`hort_rotation_total{result!~"rotated|skipped_fresh"}` to catch
collisions and namespace mismatches.

---

## 9. Troubleshooting

### `namespace_not_authorized` in worker logs

The SA's `targetSecret.namespace` is not in
`worker.rotation.targetNamespaces`. Either add the namespace to
the Helm values and roll the chart, or move the SA's target
Secret to a namespace already on the list. The reconciler
deliberately refuses to write outside the operator-allowed set
— the bound is policy, not technical.

### `collision` in worker logs

The Secret already exists but lacks the
`project-hort.de/managed-by=hort-worker` label — typically created
out-of-band (kubectl, Sealed Secrets, another controller).
Resolution: delete the Secret to let the reconciler take
ownership.

```bash
kubectl delete secret <name> -n <ns>
```

The reconciler refuses to overwrite collision Secrets by design;
silent overwrite would mask gitops-vs-imperative drift.

### Workload still using old PAT after rotation

For volume-mounted Secrets: kubelet refreshes within ~60 seconds.
If the workload caches the token in process memory, restart the
pod (`kubectl rollout restart` or `kubectl delete pod`) to pick
up the new value. The previous token is still valid (grace
window), so the restart is graceful.

For `envFrom: secretRef:`: pod restart is mandatory. Consider
switching to volume-mount for long-lived workloads.

### `mint_failed` / `write_failed` in worker logs

`mint_failed`: `ApiTokenUseCase::issue` rejected. Common causes:
DB read-only (post-failover), worker's admin-task token invalid,
event-store append failed. `write_failed`: k8s API rejected the
upsert — typically per-namespace RBAC missing or stale
(`kubectl describe role …`), namespace deleted between SA
declaration and the tick, or k8s API unreachable. Drill into the
worker log message for the exact cause.

---

## 10. What's NOT covered

- **Cross-cluster rotation.** The reconciler writes Secrets only
  in the cluster where the worker pod runs. If you need the same
  PAT delivered to multiple clusters, deploy one hort-worker per
  cluster and share the same `ServiceAccount` envelope across
  them (each cluster's reconciler manages its own Secret
  independently).
- **Revoking the previous PAT before its natural expiry.** The
  reconciler deliberately does not call `DELETE /tokens/:id` after
  writing a replacement. The grace window IS the safety margin;
  revoking proactively would force consumers to deal with abrupt
  invalidations, defeating the smooth-overlap design.
- **Per-service-account active-token limit (BSI ORP.4.A6).** The
  natural `validity > rotationInterval` overlap and the stale-token
  expiry bound the active set; an explicit count is deferred future
  hardening.
- **Importing an existing PAT under CRD management.** Operators
  with PATs minted via `hort-cli admin token issue` outside this
  path can adopt it by writing a `ServiceAccount` envelope with
  `metadata.name = <existing-username minus "sa:" prefix>`. The
  apply pipeline detects the existing backing user and binds to
  it. A dedicated `hort-cli admin service-account import <user>`
  helper is a small follow-on; not shipped yet.

---

## 11. See also

- [`docs/auth-catalog.md`](../../auth-catalog.md) — the canonical
  auth-surface catalog, including the machine-identity entries.
- [`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md)
  — the preferred path for k8s workloads (no PAT at rest).
- [`federate-ci-oidc.md`](./federate-ci-oidc.md) — the preferred
  path for GitHub Actions / GitLab CI runners.
- [`declare-gitops-config.md`](./declare-gitops-config.md)
  `kind: ServiceAccount` — canonical reference for the
  `fallbackRotation:` block.
- [`wire-secrets.md`](./wire-secrets.md) — orthogonal: the
  general pattern for wiring operator-supplied k8s Secrets into
  hort-server.
