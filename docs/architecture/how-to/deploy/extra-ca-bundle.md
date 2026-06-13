# Extra CA bundle — trusting internal or corporate CAs

`hort-server` opens TLS connections on behalf of every outbound path:
upstream proxy requests, S3/MinIO storage, OIDC discovery + JWKS, and
outbound webhook delivery.
By default the binary trusts the OS-level root CA store (populated by
the container image's base layer). If your cluster terminates TLS with
an internal or corporate CA that is **not** in the public root store,
the binary will reject the connection at boot or at request time.

`HORT_EXTRA_CA_BUNDLE` is the operator knob. Set it to the path of a
PEM file containing one or more X.509 certificates; the binary adds
them to the trust store **in addition to** the public CAs, for all
four TLS surfaces simultaneously.

**Fail-closed guarantee:** If `HORT_EXTRA_CA_BUNDLE` is set but the
file is unreadable, malformed, or contains zero parseable certificates,
the binary refuses to start. A misconfigured trust knob never silently
degrades to a state where the CA is not trusted. Both `hort-server` and
`hort-worker` enforce this at boot; the worker's fatal additionally
names the missing mount path so a half-wired manual recipe (below)
fails with an actionable error rather than an opaque crashloop.

The Helm chart surfaces this as `extraCaBundle.path` plus two
mutually-exclusive **auto-mount sources**:

- `extraCaBundle.configMapName` — Recipe A (ConfigMap).
- `extraCaBundle.secretName` — Recipe A-Secret (Secret). Behaves
  identically to `configMapName`.

**Mount/secret symmetry.** Whenever
an auto-mount source is set, the chart mounts the bundle read-only at
`extraCaBundle.path` **and** sets `HORT_EXTRA_CA_BUNDLE` on **every** pod
that needs it — the `hort-server` Deployment, the `hort-worker`
Deployment, and the server-runtime CronJobs — symmetrically. The chart
**never sets `HORT_EXTRA_CA_BUNDLE` on a pod it did not also mount the
bundle onto.** Consequently, with NEITHER source set (the fully-manual
Recipe B below) the chart mounts nothing and sets no env: you wire the
volume *and* the env yourself, on both Deployments. This closes the
previous footgun where a path-only config set `HORT_EXTRA_CA_BUNDLE` on
the worker without mounting the file, crashlooping it.

`configMapName` and `secretName` are mutually exclusive — a pod can
mount only one `ca.crt` at `extraCaBundle.path`; setting both fails the
render at `helm install`.

Three delivery mechanisms are documented below; pick the one that
matches your Kubernetes version and policy.

---

## Recipe A — ConfigMap-projected PEM bundle (all Kubernetes versions)

Use this recipe when:
- Your Kubernetes cluster is < 1.27, or
- Your cluster does not enable the `ClusterTrustBundle` feature gate, or
- You want the simplest possible setup with no alpha/beta dependencies.

### Step 1 — Create the ConfigMap

Store your PEM bundle under the key `ca.crt`. Concatenate multiple
root certificates into a single PEM file if needed.

```bash
kubectl create configmap corporate-ca-bundle \
  --from-file=ca.crt=/path/to/your/ca.pem \
  --namespace <hort-server-namespace>
```

To include multiple CAs, concatenate them first:

```bash
cat root-ca.pem intermediate-ca.pem > bundle.pem
kubectl create configmap corporate-ca-bundle \
  --from-file=ca.crt=bundle.pem \
  --namespace <hort-server-namespace>
```

### Step 2 — Set chart values

```yaml
extraCaBundle:
  # Path inside the container where the PEM file will be mounted.
  # The binary reads this path; choose any location under a
  # read-only filesystem path (e.g. /etc/hort-server/).
  path: /etc/hort-server/ca-bundle/ca.crt
  # Name of the ConfigMap created in Step 1.
  configMapName: corporate-ca-bundle
```

### What the chart renders

With both `path` and `configMapName` set, the chart produces — on
**both** the `hort-server` Deployment **and** the `hort-worker`
Deployment (and the server-runtime CronJobs), symmetrically:

```yaml
# env section of each container:
- name: HORT_EXTRA_CA_BUNDLE
  value: /etc/hort-server/ca-bundle/ca.crt

# volumeMounts section:
- name: extra-ca-bundle
  mountPath: /etc/hort-server/ca-bundle/ca.crt
  subPath: ca.crt
  readOnly: true

# volumes section:
- name: extra-ca-bundle
  configMap:
    name: corporate-ca-bundle
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
```

You do **not** wire `worker.extraVolumes` / `worker.extraVolumeMounts`
for this recipe — the chart mounts the bundle on the worker for you.

### Keeping the bundle up to date

ConfigMaps are not hot-reloaded — the binary reads the PEM file once
at startup. To rotate the CA bundle:

1. Update the ConfigMap with the new PEM content.
2. Trigger a rolling restart:
   ```bash
   kubectl rollout restart deployment/<hort-server-release-name> \
     --namespace <hort-server-namespace>
   ```

For automated rotation, pair with
[secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/)
or External Secrets Operator + a reloader sidecar (e.g.
[Reloader](https://github.com/stakater/Reloader)).

### Rotation contract

The chart wires a Pod-template annotation that hashes the ConfigMap's
data at chart-render time:

```yaml
# in spec.template.metadata.annotations:
checksum/extra-ca-bundle: <sha256 hex>
```

This pins the relationship between "the data the operator put in the
ConfigMap" and "the Pod that boots with that data." Two cases:

- **`helm upgrade` re-renders.** The chart calls `lookup` against the
  live cluster, fetches the current ConfigMap data, and computes a new
  digest. If the digest differs from what the previous render
  recorded, Kubernetes detects the Pod-template-hash change and
  performs a rolling update. **No manual restart needed.**
- **A direct `kubectl edit` / `kubectl apply` updates the ConfigMap
  without a `helm upgrade`.** The chart's `lookup` only fires when
  Helm re-renders. A hot edit therefore does NOT change the rendered
  annotation and the Pods do NOT roll automatically. Operators MUST
  trigger:
  ```bash
  kubectl rollout restart deployment/<hort-server-release-name> \
    --namespace <hort-server-namespace>
  ```
  This is the rotation contract: in-band edits require an out-of-band
  rollout. The annotation auto-rolls only on `helm upgrade`.

The same contract applies to Recipe B (ClusterTrustBundle) — the
projected volume updates the mounted file when the CTB object
changes, but the binary reads the file once at startup, so a pod
restart is still required.

### Observability

The binary emits two metrics at boot:

| Metric | Type | What it reports |
|---|---|---|
| `hort_extra_ca_anchors` | gauge (no labels) | Count of trust anchors loaded. `0` when the env var is unset; `N` when N certs parsed. Not set on a load failure. |
| `hort_extra_ca_load_total{result=…}` | counter | One increment per boot. `result=ok` covers both "anchors loaded" and "env unset"; `result=unreadable` fires when `fs::read` failed; `result=parse_failed` fires when PEM parsing rejected the file or found zero certificates. |

See [`docs/metrics-catalog.md`](../../../metrics-catalog.md) for the
canonical entry.

### Operator escalation — gauge reports zero when one was expected

If `hort_extra_ca_anchors == 0` after a rollout but you expect
trust anchors to be loaded:

1. **Confirm the Pod has the env var.** Run
   `kubectl set env pod/<pod> --list | grep HORT_EXTRA_CA_BUNDLE`. If the
   value is empty, the chart did not render `HORT_EXTRA_CA_BUNDLE` —
   for Recipe A/A-Secret, check that an auto-mount source
   (`extraCaBundle.configMapName` or `extraCaBundle.secretName`) **and**
   `extraCaBundle.path` are both set (Backlog 078 Item 7: the chart only
   sets the env when it also mounts the bundle). For the manual Recipe B,
   check your `extraEnv` / `worker.extraEnv` entry.
2. **Confirm the file is mounted.** Run
   `kubectl exec <pod> -- ls -l /etc/hort-server/ca-bundle/ca.crt` (or
   whichever path your values reference). If `ls` returns
   `No such file or directory`, the volume mount didn't render —
   check that an auto-mount source is set (Recipe A/A-Secret) or that
   your `extraVolumes` block lands the file at the correct path
   (Recipe B), on the worker too if it is enabled.
3. **Check the failure counter.** Scrape `/metrics` and look for
   `hort_extra_ca_load_total{result="unreadable"}` or
   `…{result="parse_failed"}` increments. `unreadable` indicates the
   file is mounted but the binary cannot read it (a `defaultMode`
   issue, a SELinux deny, or a cross-namespace volume that the
   service account cannot access). `parse_failed` indicates the file
   is readable but contains zero `-----BEGIN CERTIFICATE-----` blocks
   or has corrupted base64 — re-encode the bundle and re-apply the
   ConfigMap.
4. **Inspect the boot log.** A successful load logs
   `extra CA bundle loaded path=… count=N`. A failure logs
   `ConfigError::ExtraCaUnreadable` or `ConfigError::ExtraCaParse`
   with the path and underlying error. The binary refuses to start
   on the failure paths, so the Pod will be in `CrashLoopBackOff`
   rather than running with an empty trust set — a healthy Pod with
   `gauge == 0` always means the env var was unset.

---

## Recipe A-Secret — Secret-projected PEM bundle (Backlog 078 Item 7)

Identical to Recipe A, but the bundle lives in a Kubernetes **Secret**
instead of a ConfigMap. Use this when the PEM is produced by
cert-manager, External Secrets Operator, or another tool that writes to
a Secret, or when your policy keeps trust material in Secrets.

### Step 1 — Create (or reference) the Secret

Store the PEM under the key `ca.crt`:

```bash
kubectl create secret generic corporate-ca-bundle-secret \
  --from-file=ca.crt=/path/to/your/ca.pem \
  --namespace <hort-server-namespace>
```

### Step 2 — Set chart values

```yaml
extraCaBundle:
  path: /etc/hort-server/ca-bundle/ca.crt
  # Mutually exclusive with configMapName.
  secretName: corporate-ca-bundle-secret
```

### What the chart renders

Exactly Recipe A's output (server + worker + CronJobs, env⟺mount on each)
but the volume projects the **Secret** read-only at 0444:

```yaml
- name: extra-ca-bundle
  secret:
    secretName: corporate-ca-bundle-secret
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
```

There is **no** `checksum/extra-ca-bundle` Pod-template annotation for
the Secret source (that annotation is ConfigMap-specific). Secret
content changes still require a `kubectl rollout restart` to take effect
because the binary reads the PEM once at startup — same rotation
contract as Recipe A.

---

## Recipe B — fully-manual wiring (ClusterTrustBundle projected volume, Kubernetes ≥ 1.27)

**Minimum Kubernetes version: 1.27** (ClusterTrustBundle is alpha in
1.27, beta in 1.32). The `ClusterTrustBundleProjection` feature gate
must be enabled on the API server and kubelet (off by default in alpha;
on by default in beta).

Use this recipe when:
- Your cluster admin manages platform CAs centrally via
  `ClusterTrustBundle` objects, and
- You want the projected volume to update automatically when the
  cluster's CA bundle changes (without a pod restart).

### Step 1 — Verify ClusterTrustBundle availability

```bash
kubectl api-resources --api-group=certificates.k8s.io | grep ClusterTrustBundle
```

If the command returns a result, the feature is available. If not,
fall back to Recipe A.

### Step 2 — Locate or create the ClusterTrustBundle

Your cluster admin will have created a `ClusterTrustBundle` for the
platform CA. Confirm the name:

```bash
kubectl get clustertrustbundles
```

If none exists, the cluster admin creates one:

```bash
kubectl create clustertrustbundle platform-ca \
  --signer-name="" \
  --certificate /path/to/ca.crt
```

### Step 3 — Wire the projected volume via `extraVolumes` and `extraVolumeMounts`

Because `ClusterTrustBundle` projected volumes require
cluster-specific signer names and optional label selectors, the chart
cannot auto-mount this. This is the **fully-manual** recipe: you own
both the volume **and** the env, on **both** Deployments.

Leave **both** `extraCaBundle.configMapName` and
`extraCaBundle.secretName` unset, set `extraCaBundle.path` to record the
mount path, and wire everything else yourself. Backlog 078 Item 7: with
no auto-mount source the chart sets **no** `HORT_EXTRA_CA_BUNDLE` env and
mounts nothing — you supply the env via `extraEnv` (server) and
`worker.extraEnv` (worker), and the volume via `extraVolumes` /
`extraVolumeMounts` and the `worker.*` equivalents:

```yaml
extraCaBundle:
  # Path inside the container where the projected volume lands.
  path: /etc/hort-server/ca-bundle/ca.crt
  # Leave BOTH auto-mount sources unset — manual recipe.
  configMapName: ""
  secretName: ""

# --- server Deployment ---
extraEnv:
  - name: HORT_EXTRA_CA_BUNDLE
    value: /etc/hort-server/ca-bundle/ca.crt
extraVolumeMounts:
  - name: cluster-trust-bundle
    mountPath: /etc/hort-server/ca-bundle
    readOnly: true
extraVolumes:
  - name: cluster-trust-bundle
    projected:
      sources:
        - clusterTrustBundle:
            # Replace with your ClusterTrustBundle name.
            name: platform-ca
            path: ca.crt
            # Optional: only use if the CTB has an optional label selector.
            # labelSelector:
            #   matchLabels:
            #     environment: production

# --- worker Deployment (REQUIRED if the worker is enabled) ---
# Mirror the env + volume on the worker, or the worker boots with no
# extra trust (and any private-CA outbound call from the worker fails).
# The worker's boot read of HORT_EXTRA_CA_BUNDLE is fail-closed: if you
# set worker.extraEnv but forget worker.extraVolumes/extraVolumeMounts,
# the worker aborts with a clear, named "missing CA-bundle mount" fatal.
worker:
  extraEnv:
    - name: HORT_EXTRA_CA_BUNDLE
      value: /etc/hort-server/ca-bundle/ca.crt
  extraVolumeMounts:
    - name: cluster-trust-bundle
      mountPath: /etc/hort-server/ca-bundle
      readOnly: true
  extraVolumes:
    - name: cluster-trust-bundle
      projected:
        sources:
          - clusterTrustBundle:
              name: platform-ca
              path: ca.crt
```

> **Tip:** prefer Recipe A-Secret over this manual recipe whenever your
> trust material can live in a Secret — the chart then mounts + wires
> the env on both pods for you, and the worker-half footgun disappears.

> **Note:** The `mountPath` in `extraVolumeMounts` is the parent
> directory (`/etc/hort-server/ca-bundle`), and `path` inside the
> `clusterTrustBundle` source is the filename (`ca.crt`). Together
> they produce the full file path `/etc/hort-server/ca-bundle/ca.crt`
> that matches `extraCaBundle.path`.

### What the chart renders (manual recipe)

With both auto-mount sources unset, the chart renders **nothing** for
the CA bundle — no env, no volume, no mount. Everything in the rendered
manifest comes from your `extraEnv` / `extraVolumes` /
`extraVolumeMounts` (and the `worker.*` equivalents) verbatim.

### Automatic bundle updates

ClusterTrustBundle projected volumes update the mounted file
automatically when the `ClusterTrustBundle` object changes. However,
`hort-server` reads the PEM file once at startup. To pick up a CA
rotation, trigger a rolling restart after the bundle object is
updated:

```bash
kubectl rollout restart deployment/<hort-server-release-name> \
  --namespace <hort-server-namespace>
```

### Verify after install

```bash
kubectl logs deploy/<release-name> | grep "extra CA bundle"
```

You should see a line like `extra CA bundle loaded path=… count=N`. If
you see `ConfigError::ExtraCaUnreadable` (server) or a
`HORT_EXTRA_CA_BUNDLE points at … but no file is readable there … The
worker pod is missing the CA-bundle mount at that path` fatal (worker),
re-check that the `extraVolumes` block actually projects `ca.crt` at the
path you set in `extraCaBundle.path` — **on the worker too**. The
worker's fatal names the missing path precisely so you can see which
half (env vs mount) is misaligned.

---

## Choosing between the recipes

| Consideration | Recipe A (ConfigMap) | Recipe A-Secret (Secret) | Recipe B (manual / ClusterTrustBundle) |
|---|---|---|---|
| Minimum k8s version | Any | Any | 1.27+ (CTB alpha); 1.32+ (beta, gate on by default) |
| Managed by | Namespace admin | Namespace admin / cert-manager | Cluster admin |
| Scope | Namespace | Namespace | Cluster-wide |
| Chart automation | Full — env + volume + mount on server **and** worker **and** CronJobs | Full — same as Recipe A (Secret-backed volume) | None — operator wires env + volume on both Deployments |
| Worker auto-mount | Yes | Yes | No (you set `worker.extraEnv` + `worker.extraVolumes`/Mounts) |
| Pod-template checksum annotation | Yes (ConfigMap) | No | No |
| CA rotation | Manual restart after ConfigMap update | Manual restart after Secret update | Restart after CTB object update |
| Multi-namespace reuse | Duplicate ConfigMap per namespace | Duplicate Secret per namespace | Single CTB, all namespaces |

For most single-cluster, single-namespace deployments, **Recipe A (or
A-Secret if your trust material is Secret-backed) is simplest** — and
crucially, the chart mounts the bundle on the worker for you, so the
worker-half footgun never arises. Recipe B (fully manual) is for the
`ClusterTrustBundle` case where the cluster admin manages a single
platform CA across multiple workloads; remember to mirror the env +
volume on the worker.

---

## Cross-references

- [`values-reference.md`](./values-reference.md) — `extraCaBundle`
  values-reference entry
- [`wire-secrets.md`](../wire-secrets.md) — per-upstream `ca_bundle_ref`
  (complements the process-wide bundle for a specific upstream only)
- [ADR 0010](../../../adr/0010-tls-builder-no-insecure-knobs.md) — the
  trust model: one process-wide extra-CA bundle, no insecure-TLS knobs
- [ADR 0029](../../../adr/0029-operator-config-hard-rename.md) —
  operator-config naming conventions (incl. the mount/secret symmetry
  rule: no env without a matching mount)
