# Provision a Prometheus scraper ServiceAccount for `/metrics`

This guide is for operators who need Prometheus (or any other
scrape client) to read `hort-server`'s `/metrics` endpoint.

`/metrics` is **not** anonymously readable and **not** readable by
every authenticated principal. It requires a bearer carrying the
global `read_metrics` grant, and it is served **only** on the
dedicated admin listener. There is no opt-out — see
[ADR 0052](../../../adr/0052-scoped-metrics-read-capability.md) for
why (the exposition's `repository` labels leak the full repository
roster, defeating the anti-enumeration `404` collapse on the read
path).

Two things follow, and this guide covers both:

1. You must declare a **non-admin scraper identity** plus an
   **unscoped `read_metrics` grant**, through the audited gitops
   apply path. A Prometheus scraper must never be an admin —
   `Admin` does not imply `read_metrics`, deliberately.
2. Your git repository **never contains a token.** It declares the
   *identity* and the *grant*; `hort-server` mints and rotates the
   credential.

Two delivery models are supported. **Model B (workload identity)
is the featured recipe** — no secret at rest at all. **Model A
(fallback rotation)** is the alternative for scrapers that cannot
do an OIDC token exchange, and is the one that drops straight into
a Prometheus-Operator `ServiceMonitor`.

---

## 1. Pick your model

| | **Model B — workload identity** (featured) | **Model A — fallback rotation** |
|---|---|---|
| Secret at rest | **None.** The pod exchanges its own projected k8s SA token for a short-lived bearer. | One k8s Secret, rotated by `hort-worker`. |
| What git holds | `OidcIssuer` + `ServiceAccount` + `PermissionGrant` | `ServiceAccount` + `PermissionGrant` |
| Prometheus wiring | `authorization.credentials_file`, refreshed by a sidecar | `authorization.credentials` / `bearerTokenSecret` → the Secret |
| Works with a `ServiceMonitor` CR | Not directly — see [§5](#5-model-b-and-prometheus-operator) | **Yes**, natively |
| Needs | k8s 1.21+, cluster OIDC issuer reachable by hort-server | `worker.rotation` enabled on the chart |

Pick Model A if you drive Prometheus through the Prometheus
Operator and want the shortest path. Pick Model B if you run
Prometheus from raw `scrape_configs` and want nothing persistent.

---

## 2. Prerequisites

- **`HORT_METRICS_BIND` must be set.** `/metrics` lives only on the
  admin listener; if that listener does not bind, `/metrics` exists
  nowhere at all (there is no main-listener fallback). The Helm
  default `metrics.bindAddr: "127.0.0.1:9090"` is pod-loopback —
  fine for a sidecar scrape, not reachable from another pod. See
  [`values-reference.md`](../deploy/values-reference.md) → `metrics`.
- Binding the listener to an internal interface remains recommended
  **as defense-in-depth**, never as the gate: network position is
  never a substitute for access control
  ([`control-plane-tiers.md`](../deploy/control-plane-tiers.md)).
- Gitops write access to `$HORT_CONFIG_DIR` and familiarity with
  [`declare-gitops-config.md`](../declare-gitops-config.md).
- For Model B only: everything in
  [`federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md)
  §2 (cluster `--service-account-issuer`, JWKS reachable from
  hort-server, `HORT_EXTRA_CA_BUNDLE` for a private CA).

---

## 3. Declare the identity and the grant

This part is **identical for both models** except for the
`ServiceAccount`'s delivery block. Two envelopes, both in git.

### 3.1 The grant: unscoped, `serviceAccount`-subject

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: metrics-scraper-read-metrics
spec:
  subject:
    kind: serviceAccount
    name: metrics-scraper
  permission: read_metrics
  # `repository:` is OMITTED — read_metrics is a global permission.
  # The exposition is process-wide; there is nothing to scope.
```

Three things about this shape are load-bearing:

- **`repository:` is omitted.** `read_metrics` is always evaluated
  with `repository = None`. Setting a repository would not narrow
  anything (the exposition is not per-repository) and the grant
  would simply never match.
- **The subject is `serviceAccount`, not `claims`.** This matters
  at apply time, not just stylistically. An unscoped grant with a
  `serviceAccount` subject resolves to an SA-owned `User` grant and
  takes the apply linter's **provenance exemption → `Pass`**. The
  same unscoped grant written with a `claims` subject trips
  **`wildcard-repo-non-admin` → `Reject`** (a global claim-gated
  grant is instance-wide by construction), and a single-claim
  subject additionally trips `single-claim-grant`. Bind the scrape
  capability to one declared identity, not to whoever currently
  carries a claim. Do **not** reach for the linter rule-downgrade
  knobs to work around this — see
  [`claim-based-rbac.md`](./claim-based-rbac.md) §5.
- **`permission: admin` is not an alternative.** A `serviceAccount`
  subject with `permission: admin` is hard-rejected at apply
  ([ADR 0038](../../../adr/0038-admin-identity-model.md)), and
  `Admin` would not satisfy `read_metrics` anyway.

### 3.2 The identity: Model B (`federatedIdentities`)

```yaml
apiVersion: project-hort.de/v1
kind: OidcIssuer
metadata:
  name: cluster-prod
spec:
  issuerUrl: https://kubernetes.default.svc.cluster.local
  audiences: [hort-server]
  jwksRefreshInterval: 1h
  allowedAlgorithms: [RS256]
---
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: metrics-scraper
spec:
  federatedIdentities:
    - issuer: cluster-prod
      claims:
        # Subject-identifying claim — pins the exact k8s SA that may
        # assume this identity. REQUIRED; never rely on `aud` alone.
        sub: system:serviceaccount:monitoring:prometheus
        # Relying-party pin. Bound against the validator-resolved
        # audience, so an array-shaped `aud` matches correctly.
        aud: hort-server
```

**Pin `sub`, and pin it *as well as* `aud` — not instead of.** An
`aud`-only trust policy says "any workload in this cluster that can
mint a token for hort-server may assume this identity", which is a
privilege-escalation footgun — apply-time validation rejects such a
fragment outright. `sub: system:serviceaccount:<namespace>:<name>` is
what actually names the workload.

Pinning `aud` **in addition** closes the confused-deputy /
token-redirection vector: a JWT minted for a *different* relying
party cannot satisfy the fragment. The `aud` key is special-cased to
bind the validator-resolved audience rather than the raw claim, so
the RFC 7519 §4.1.3 array form (`"aud": ["hort-server"]`, which is
what k8s emits) matches correctly.

`sub` is a subject-identifying claim — apply requires at least one
of `sub`, `repository`, or `project_path` on every FI; `aud` and
other run-context claims refine a subject, they never identify one.
A `sub`-only fragment is therefore validation-clean and triggers no
apply-time warning: the apply-time **under-constrained federated
identity** warning only fires on a `repository`/`project_path` claim
left without a discriminating `ref`/`environment`/`workflow` claim
alongside it, a shape this fragment does not have.

An empty `claims:` map is **hard-rejected** at apply and
fail-closed at runtime — it would mean "any JWT from this issuer
can assume me".

### 3.3 The identity: Model A (`fallbackRotation`)

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: metrics-scraper
spec:
  fallbackRotation:
    targetSecret:
      name: hort-metrics-token
      namespace: monitoring
      # `opaque` — Prometheus is an HTTP-bearer client, not a
      # docker-pull client.
      format: opaque
    rotationInterval: 6h
    validity: 24h
```

`hort-worker` mints a PAT carrying this SA's grants and writes it
into the named Secret, rotating on schedule. `validity ≥ 2 ×
rotationInterval` is enforced at apply and **is** the grace window:
the previous token stays valid across at least one full rotation,
so Prometheus has time to pick up the new one. The reconciler does
not revoke.

`monitoring` must appear in `worker.rotation.targetNamespaces` or
the rotation is skipped with a `namespace_not_authorized` metric
tick — see
[`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
§4.

### 3.4 Apply

Place the files in `$HORT_CONFIG_DIR` and let your gitops
controller roll them (or restart `hort-server`); the apply happens
before the listener binds. Confirm the grant landed and the linter
passed:

```bash
kubectl logs -n hort-server deploy/hort-server | grep -E 'gitops apply|linter'
```

A `Reject` aborts the whole apply atomically — no partial grant
lands.

---

## 4. Model B — the refresh loop

The pod mounts a projected SA token, exchanges it for an
`hort-server` bearer, and writes the bearer to a file Prometheus
reads. Nothing persists across a pod restart.

The exchange itself is the standard flow from
[`federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md)
§6 — RFC 8693 token exchange against
`POST /api/v1/auth/exchange`. The only scraper-specific part is
writing the result where Prometheus expects it.

### 4.1 Pod spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: prometheus
  namespace: monitoring
spec:
  serviceAccountName: prometheus     # ⇒ the `sub` pinned in §3.2
  containers:
    - name: prometheus
      image: prom/prometheus:v3.1.0
      args: ["--config.file=/etc/prometheus/prometheus.yml"]
      volumeMounts:
        - name: hort-creds
          mountPath: /var/run/hort
          readOnly: true
        - name: config
          mountPath: /etc/prometheus

    - name: hort-token-refresh
      image: alpine/curl-jq:latest       # anything with curl + jq
      command: ["/bin/sh", "/scripts/refresh.sh"]
      volumeMounts:
        - name: hort-token               # projected k8s SA token (in)
          mountPath: /var/run/secrets/hort-server
          readOnly: true
        - name: hort-creds               # bearer for Prometheus (out)
          mountPath: /var/run/hort
        - name: refresh-script
          mountPath: /scripts

  volumes:
    - name: hort-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: hort-server      # ⇒ the `aud` pinned in §3.2
              expirationSeconds: 3600
    - name: hort-creds
      emptyDir:
        medium: Memory                   # never touches disk
    - name: config
      configMap: { name: prometheus-config }
    - name: refresh-script
      configMap: { name: hort-token-refresh, defaultMode: 0755 }
```

`hort-creds` is `emptyDir` with `medium: Memory` — the bearer lives
in a tmpfs shared between the two containers and never reaches
persistent storage.

### 4.2 The refresh loop

```sh
#!/bin/sh
# ConfigMap: hort-token-refresh, key refresh.sh
set -eu

HORT_URL="${HORT_URL:-https://hort.example.com}"
JWT_PATH=/var/run/secrets/hort-server/token
OUT=/var/run/hort/token

while :; do
  # Re-read the projected token every iteration — kubelet refreshes
  # the file in place (at ~80% of its lifetime), so never cache it.
  jwt=$(cat "$JWT_PATH")

  resp=$(curl -sS --fail-with-body -X POST \
    "${HORT_URL}/api/v1/auth/exchange" \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    -d "subject_token=${jwt}" \
    -d 'subject_token_type=urn:ietf:params:oauth:token-type:jwt') || {
      echo "exchange failed: ${resp:-no body}" >&2
      sleep 30
      continue
    }

  # Write via a temp file + atomic rename so Prometheus never reads
  # a half-written credential mid-scrape.
  printf '%s' "$(echo "$resp" | jq -er .access_token)" > "${OUT}.tmp"
  mv "${OUT}.tmp" "$OUT"

  # Re-exchange at half the bearer's lifetime. `expires_in` is the
  # lesser of 1h and the source JWT's remaining `exp`; no refresh
  # token is issued, so the loop simply repeats the exchange.
  ttl=$(echo "$resp" | jq -er .expires_in)
  sleep $(( ttl / 2 ))
done
```

Two details that matter:

- **Atomic rename.** Prometheus re-reads `credentials_file` from
  disk on *every scrape* — that is exactly what makes this pattern
  work without restarting Prometheus — so a partially-written file
  is a real (if brief) failure window. Write-then-`mv`.
- **Re-read the projected token each iteration.** kubelet rewrites
  it in place; a cached copy goes stale and the exchange starts
  failing with `403`.

### 4.3 Prometheus scrape config

```yaml
scrape_configs:
  - job_name: hort-server
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /var/run/hort/token
    static_configs:
      - targets: ['hort-server.hort-server.svc:9090']
```

The target port is the **admin listener** (`metrics.bindAddr`,
exposed as `service.metricsPort`), not the public API port
(`service.httpPort`). Scraping the public port returns `404` —
`/metrics` is not routed there at all.

---

## 5. Model B and Prometheus Operator

A `ServiceMonitor`'s `authorization.credentials` takes a **Secret
key reference**, not a file path. A bearer written to a tmpfs by a
sidecar therefore cannot be referenced from a `ServiceMonitor` CR.

So, with Prometheus Operator:

- **Use Model A.** The rotated Secret drops straight into
  `authorization.credentials` (or the older `bearerTokenSecret`).
  This is why the chart's own `metrics.serviceMonitor` template
  tells you to supply a Secret — it cannot guess your issuance
  mechanism, and it deliberately does not ship one.
- Or keep Model B's zero-secret-at-rest property by running
  Prometheus from raw `scrape_configs` (§4) instead of letting the
  Operator generate them.

Setting `metrics.serviceMonitor.enabled: true` with an empty
`metrics.bindAddr` fails the chart render by design: there would be
no metrics Service port to scrape.

---

## 6. Verify

### 6.1 The bearer actually carries the grant

Ask hort-server what the token can do, rather than inferring it:

```bash
TOKEN=$(cat /var/run/hort/token)     # or from the Model A Secret
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  https://hort.example.com/api/v1/auth/whoami | jq .
```

For the scraper SA you should see a `read_metrics` cell with a
`null` repository (the unscoped grant), and **no** `global_admin`
marker:

```json
{
  "effective_grants": [
    { "repository": null, "permission": "read_metrics" }
  ]
}
```

The exchanged / rotated bearer's cap is a **snapshot of the SA's
grants taken at issuance**, so this is also the check that your
grant landed before the token was minted. A grant added after the
last mint takes effect on the next exchange or rotation tick;
a grant *removed* bites immediately (revocation rides the live
grants leg).

> **If the scraper is an admin credential, you have the wrong
> setup.** `whoami` rendering `{"global_admin": true,
> "read_metrics": false}` means the principal is an admin that does
> *not* hold `read_metrics` — it will get `403` from `/metrics`.
> That `read_metrics` field exists precisely because `read_metrics`
> is the one permission the `global_admin` marker does not imply
> ([ADR 0052](../../../adr/0052-scoped-metrics-read-capability.md)).
> Provision the dedicated non-admin SA above rather than granting
> `read_metrics` to an admin.

### 6.2 The scrape

```bash
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  http://hort-server.hort-server.svc:9090/metrics | grep '^hort_' | head
```

And confirm Prometheus itself is succeeding:
`up{job="hort-server"} == 1`.

---

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| `401 Unauthorized` | No bearer, or an expired/invalid one. On Model B: the refresh loop is failing (check its logs) or wrote an empty file. |
| `403 Forbidden` | Authenticated, but the principal lacks `read_metrics`. Check `whoami` (§6.1). Most common causes: the grant was applied *after* the token was minted (re-exchange / wait for the next rotation tick), the grant carries a `repository:` (it must be omitted), or you are using an admin credential and expecting `Admin` to imply `read_metrics` (it does not). |
| `404 Not Found` | You are scraping the **public** API port. `/metrics` is admin-listener-only. Use `metrics.bindAddr`'s port. |
| Connection refused on the metrics port | `HORT_METRICS_BIND` / `metrics.bindAddr` is unset → no admin listener binds → `/metrics` exists nowhere. |
| Connection refused from *another pod*, works in-pod | `metrics.bindAddr` is `127.0.0.1:9090` (pod loopback). Bind a routable interface — `0.0.0.0` additionally requires `metrics.allowUnspecifiedBind: true` — and restrict reach with a NetworkPolicy. |
| `403` with `no_sa_match` on exchange | The FI `claims:` fragment did not exact-match the JWT. Usually a typo in `sub: system:serviceaccount:<ns>:<name>`, or the pod's `serviceAccountName` differs from the pinned one. |
| `403` with `aud_mismatch` / `AudienceDenied` | The projected token's `audience:` does not match `OidcIssuer.spec.audiences` (or the `aud` you pinned in the FI). |
| Apply logs an under-constrained-FI `warn` | The FI pins a `repository`/`project_path` claim with no discriminating `ref`/`environment`/`workflow` claim alongside it — any workflow in that repo/project could assume the identity. Add a discriminating claim. Not applicable to the `sub` + `aud` shape in §3.2, which never triggers this warning. |
| Apply rejected with `wildcard-repo-non-admin` | The grant used a `claims` subject with no `repository`. Use the `serviceAccount` subject form (§3.1). |
| Rotation never happens (Model A) | The Secret's namespace is not in `worker.rotation.targetNamespaces`, or an existing Secret lacks the `project-hort.de/managed-by=hort-worker` label (ownership collision — hand off explicitly). |

A `read_metrics` denial logs at `info!` (an audit line, not an
error) and increments
`hort_authz_decisions_total{permission="read_metrics",
result="deny"}`. Alert on it: a sustained non-zero rate is how a
scraper whose grant was removed becomes visible.

---

## 8. What's NOT covered

- **Per-repository metrics authorization.** `read_metrics` is
  global by design — the exposition is process-wide, so there is
  nothing for a repository scope to narrow
  ([ADR 0052](../../../adr/0052-scoped-metrics-read-capability.md)).
  To reduce `repository`-label cardinality (a scale concern, not a
  security one) use `METRICS_INCLUDE_REPOSITORY_LABEL=false`.
- **mTLS on the scrape path.** An operator/ingress concern,
  orthogonal to this grant, and defense-in-depth rather than the
  gate.
- **Anonymous scraping.** There is no flag for it. The retired
  `HORT_METRICS_REQUIRE_AUTH` / `metrics.requireAuth` knob is gone
  end-to-end; a stale env var is silently ignored and a values file
  still setting `metrics.requireAuth` fails chart schema
  validation. A genuinely isolated network is expressed by not
  granting a network path, not by disabling authorization.
- **Federating a scraper outside k8s.** For CI-runner-shaped OIDC
  identities see
  [`federate-ci-oidc.md`](../federate-ci-oidc.md); the grant half
  (§3.1) is unchanged.
- **The `hort-worker` metrics listener.** `hort-worker` serves its
  own opt-in `GET /metrics` (`HORT_WORKER_METRICS_BIND`, disabled by
  default) which has **no per-request auth** — the `read_metrics`
  grant does not apply to it. Its `repository` labels carry repo
  names, so if you enable it you must restrict it with a
  NetworkPolicy. See
  [`../enable-provenance-verification.md`](../enable-provenance-verification.md)
  → *Worker metrics*.

---

## 9. See also

- [ADR 0052](../../../adr/0052-scoped-metrics-read-capability.md) —
  why the capability is scoped and non-admin, and why admin-gating
  and ingress-as-sole-control were both rejected.
- [`federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md)
  — the full workload-identity federation flow this builds on.
- [`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
  — Model A's rotation reconciler in detail.
- [`claim-based-rbac.md`](./claim-based-rbac.md) — grant subjects,
  the apply-config linter and its rules.
- [`declare-gitops-config.md`](../declare-gitops-config.md) —
  canonical reference for `kind: OidcIssuer`, `kind: ServiceAccount`,
  `kind: PermissionGrant`.
- [`security-hardening-checklist.md`](../deploy/security-hardening-checklist.md)
  → `/metrics` — the hardening posture and post-install check.
- [`values-reference.md`](../deploy/values-reference.md) →
  `metrics` — `bindAddr`, `allowUnspecifiedBind`, `serviceMonitor`.
- [`docs/metrics-catalog.md`](../../../metrics-catalog.md) — what
  the exposition actually contains.
