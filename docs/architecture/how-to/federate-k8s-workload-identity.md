# Federate a k8s workload to hort-server via projected SA tokens

This guide is for platform engineers running Flux (or any other
gitops controller) who want their k8s workloads to authenticate to
`hort` without a long-lived PAT pasted into a Secret. The
workload's pod fetches a projected ServiceAccount token from the
cluster's API server, exchanges it at
`POST /api/v1/auth/exchange`, and gets back a short-lived bearer
scoped to the repositories its `kind: ServiceAccount` envelope
permits.

For the design rationale see
[ADR 0018](../../adr/0018-auth-catalog-canonical.md) and the
federation entries in [`docs/auth-catalog.md`](../../auth-catalog.md).

---

## 1. What this gives you

The 2026 industry-standard pattern for non-human identities in k8s
is "no long-lived tokens at rest." Every pod that needs to talk to
hort-server fetches a short-lived JWT from its own cluster's API
server, exchanges it for an hort-server bearer, and either repeats
the exchange when the bearer expires or simply re-fetches the
projected token on each call. Nothing persists across pod
restarts.

hort-server treats the cluster as a generic OIDC issuer: the JWKS
endpoint is the cluster's `/openid/v1/jwks` (served by the API
server itself when `--service-account-issuer` is configured), the
JWT's `iss` claim is the cluster's issuer URL, and the `sub` claim
encodes the pod's ServiceAccount as
`system:serviceaccount:<namespace>:<name>`. The operator declares
trust by writing one `kind: OidcIssuer` envelope per cluster + one
`kind: ServiceAccount` envelope per workload identity.

The two artefacts that change in your gitops repository:

1. **`kind: OidcIssuer`** — names the trusted cluster and binds the
   audience the projected token must carry.
2. **`kind: ServiceAccount`** — declares the non-human identity in
   hort-server, scopes it to repositories, and lists which JWT claim
   shapes are allowed to assume it.

Existing PATs continue to work — federation is additive. Operators
adopt this path workload-by-workload at their own pace.

---

## 2. Prerequisites

- k8s 1.21+ on every cluster that participates. Projected
  ServiceAccount tokens reached GA in 1.21; earlier versions issue
  only legacy long-lived SA tokens, which are out of scope here.
- The cluster's API server is started with
  `--service-account-issuer=<URL>` (a stable, externally reachable
  URL) and `--service-account-jwks-uri=<URL>` (or relies on the
  default `/.well-known/openid-configuration`). Managed offerings
  (GKE, EKS, AKS) expose this out of the box; self-hosted k8s
  installations using kubeadm pass the flags in
  `kube-apiserver` static-pod manifests.
- hort-server can reach the cluster's JWKS endpoint over HTTPS. If
  the cluster uses a private CA, mount the CA bundle on hort-server
  via `HORT_EXTRA_CA_BUNDLE` — there is no `insecure_jwks_url` knob
  ([ADR 0010](../../adr/0010-tls-builder-no-insecure-knobs.md)).
- Operator authority to `kubectl apply -f` in the workload's
  namespace, and gitops write access for the new envelopes.

Useful upstream documentation:
[ServiceAccount token volume projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection)
and
[Manage Service Accounts (issuer flags)](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).

---

## 3. Step 1 — declare the `OidcIssuer`

One envelope per cluster. The `issuerUrl` must match the cluster's
`--service-account-issuer` flag exactly — hort-server matches on the
`iss` claim string with no normalisation.

```yaml
apiVersion: project-hort.de/v1beta1
kind: OidcIssuer
metadata:
  name: cluster-prod
spec:
  issuerUrl: https://kubernetes.default.svc.cluster.local
  audiences: [hort-server]
  jwksRefreshInterval: 1h
  allowedAlgorithms: [RS256]
```

Field-by-field:

- `metadata.name` — envelope identity. Used by `ServiceAccount`
  envelopes' `federatedIdentities[].issuer` reference. Pick a name
  per cluster you trust (`cluster-prod`, `cluster-staging`, …).
- `spec.issuerUrl` — exact `iss` claim. For most managed offerings
  this is an HTTPS URL; for self-hosted k8s the in-cluster default
  is `https://kubernetes.default.svc.cluster.local`. Plaintext
  (`http://`) is rejected at apply time.
- `spec.audiences` — the projected token's `aud` must be one of
  these. `hort-server` is the conventional choice; if multiple
  hort-server deployments share one cluster, scope per-deployment
  (e.g. `hort-server-prod`, `hort-server-staging`).
- `spec.jwksRefreshInterval` — bounded between `1m` and `24h`. The
  default `1h` is appropriate for most clusters; tighten if you
  rotate signing keys aggressively.
- `spec.allowedAlgorithms` — k8s API servers default to `RS256`;
  symmetric algorithms (`HS*`) are forbidden by the domain enum
  because there is no JWKS to verify them against.

`kubectl apply -f oidc-issuer-cluster-prod.yaml` is the wrong tool
— `kind: OidcIssuer` is an hort-server gitops envelope, not a k8s
CRD. Place the file in `$HORT_CONFIG_DIR` and restart hort-server (or
push to your gitops repo and let Flux roll the chart). See
[`declare-gitops-config.md`](./declare-gitops-config.md) §5 for
the boot sequence.

---

## 4. Step 2 — declare the `ServiceAccount`

One envelope per workload identity. The `federatedIdentities[]`
block lists which `(issuer, claims)` shapes may assume this SA.
Multiple shapes are an OR — any single match suffices; multiple
matches across SAs are a `multiple_sa_match` deny.

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: prod-pypi-pusher
spec:
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: cluster-prod
      claims:
        sub: system:serviceaccount:apps:pypi-publisher
```

The `claims:` map is exact-match — every `(key, value)` in the map
must equal the corresponding field in the JWT payload. The
canonical k8s SA claim shape is
`sub: system:serviceaccount:<namespace>:<name>`; that single claim
is usually enough to pin the identity. Newer clusters also expose
`kubernetes.io/serviceaccount/namespace` and `…/name` as separate
claims — match on whichever subset gives you the desired
specificity.

Validation rules the apply pipeline enforces:

- `role` ∈ `{developer, reader}`. `admin` is explicitly forbidden
  — admin authority is reserved for short-lived interactive
  sessions ([ADR 0013](../../adr/0013-idp-authoritative-cli-sessions.md)).
- `repositories` non-empty (no global service-account grants).
- `federatedIdentities[].issuer` must reference a declared
  `OidcIssuer`. Apply-time foreign key.
- `federatedIdentities[].claims` non-empty. Empty claims means
  "any JWT from this issuer can assume me" — a
  privilege-escalation footgun on a misconfigured issuer. Hard
  reject.

See [`declare-gitops-config.md`](./declare-gitops-config.md)
`kind: ServiceAccount` for the canonical reference.

---

## 5. Step 3 — configure the pod

Mount a projected SA token with the right audience. The token's
`aud` must be one of the values in
`OidcIssuer.spec.audiences` — `hort-server` in this example.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pypi-publisher
  namespace: apps
spec:
  serviceAccountName: pypi-publisher
  containers:
    - name: app
      image: my-org/pypi-publisher:1.2.3
      volumeMounts:
        - name: hort-token
          mountPath: /var/run/secrets/hort-server
          readOnly: true
  volumes:
    - name: hort-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: hort-server
              expirationSeconds: 3600
```

`expirationSeconds: 3600` is the lower bound k8s honours; the API
server may issue a longer-lived token but kubelet refreshes the
file inside the pod well before expiry (kubelet starts refreshing
at 80% of token lifetime). Treat the token file as a moving
target — read it on every exchange, do not cache its contents in
process memory.

The pod's `serviceAccountName: pypi-publisher` must exist in the
namespace (`kubectl create serviceaccount pypi-publisher -n
apps`). That k8s ServiceAccount is the `sub` claim source — the
JWT will carry `sub: system:serviceaccount:apps:pypi-publisher`,
which is exactly what the `kind: ServiceAccount` envelope above
matches on.

---

## 6. Step 4 — fetch and exchange

Inside the pod, read the projected token and post it to
`/api/v1/auth/exchange`. The exchange returns a short-lived
bearer.

```bash
JWT=$(cat /var/run/secrets/hort-server/token)
RESPONSE=$(curl -sS -X POST \
  https://hort.example.com/api/v1/auth/exchange \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${JWT}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt")
HORT_TOKEN=$(echo "${RESPONSE}" | jq -r .access_token)
```

The response body is RFC 8693 §2.2.1 standard:

```json
{
  "access_token": "hort_sa_…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

`expires_in` is the lesser of 1 hour and the JWT's remaining
`exp` — the bearer cannot outlive the source token. No refresh
token is issued; when `${HORT_TOKEN}` expires, re-read the projected
token (still fresh, kubelet keeps it that way) and repeat the
exchange.

---

## 7. Step 5 — verify it works

A `twine upload` is a tight end-to-end check: it exercises auth,
authorization, repository scoping, and the ingest path. Substitute
your repository's URL and any tiny package you have at hand.

```bash
twine upload \
  --repository-url https://hort.example.com/pypi/pypi-internal/ \
  --username __token__ \
  --password "${HORT_TOKEN}" \
  dist/*.whl
```

A successful upload returns `200 OK` from twine and prints the
artifact path. To confirm the federation path was actually taken,
check hort-server logs for the `TokenIssued` event matching this
exchange:

```bash
kubectl logs -n hort-server deploy/hort-server | grep TokenIssued | tail -1
```

Look for `source_issuer = "cluster-prod"`, `source_sub =
"system:serviceaccount:apps:pypi-publisher"`, and `source_jti`
populated with the projected token's `jti`. If those three fields
appear, the federation branch handled the exchange — not a
fallback path.

The metric `hort_token_exchange_total{kind="federated_jwt",
result="success"}` increments on every successful exchange. Plot
it alongside `kind="federated_jwt", result!="success"` to alert on
broken trust policies.

---

## 8. Troubleshooting

Every deny returns `403` with a `error_description` body. The
table maps the deny reason to its likely cause; the second column
quotes the deny hint hort-server emits in the response body so
operator-side automation can match exactly.

| Reason | Deny hint | Likely cause |
|---|---|---|
| `unknown_issuer` | `"no OidcIssuer matches \`iss\` — declare one or fix the JWT"` | The `iss` claim of the projected token does not equal `OidcIssuer.spec.issuerUrl`. Compare the JWT payload's `iss` to the envelope. The cluster's `--service-account-issuer` may have changed (e.g. after a managed-control-plane upgrade). |
| `aud_mismatch` | `"aud not in OidcIssuer.audiences"` | The projected token's `aud` does not match any entry in `spec.audiences`. Common cause: the `serviceAccountToken.audience:` on the pod is missing or differs from `hort-server`. |
| `no_sa_match` | (handler-emitted) `"no ServiceAccount.federatedIdentities matched"` | The token validated cryptographically but the `claims:` map in every candidate SA failed exact-match against the JWT payload. The pod's `sub` claim is the usual mismatch site — typo in the namespace or k8s SA name. |
| `multiple_sa_match` | (handler-emitted) `"multiple ServiceAccount matches"` | Two `ServiceAccount` envelopes are overly broad. Tighten one envelope's `claims:` map (add a discriminator). The full SA-name candidates appear in hort-server's INFO log. |
| `signature_invalid` | `"signature verification failed"` | JWKS cache is stale relative to the issuer, or the projected token was minted by a different cluster. Lowering `jwksRefreshInterval` to `5m` temporarily, then back, is a fast way to confirm staleness. |

For the full taxonomy see the `FederationDenyReason`
enum in `crates/hort-domain/src/ports/federated_jwt_validator.rs`.

---

## 9. What's NOT covered

- **Cross-cluster trust.** Each cluster's API server has its own
  signing keys and its own `iss` claim. Declare one
  `kind: OidcIssuer` per cluster; do not try to share an envelope
  across clusters by listing both `iss` values.
- **Rotation of the cluster's signing key.** k8s clusters rotate
  signing keys on their own cadence; the JWKS-refresh interval on
  the `OidcIssuer` covers the propagation delay. If your cluster
  rotates keys faster than `1h`, drop the interval (down to
  `1m` minimum).
- **Long-lived `kubernetes.io/service-account-token` Secrets.**
  Legacy SA Secrets are not OIDC JWTs and do not flow through
  this path. If your workload predates projected tokens, see
  [`rotating-service-account-tokens.md`](./rotating-service-account-tokens.md)
  for the fallback PAT-rotation recipe instead.
- **Multi-tenant scoping.** `ServiceAccount` envelopes are global
  to the hort-server deployment. Per-namespace authorization
  scoping is deferred future work.

---

## 10. See also

- [`docs/auth-catalog.md`](../../auth-catalog.md) — the canonical
  auth-surface catalog, including the federation/exchange entries.
- [`federate-ci-oidc.md`](./federate-ci-oidc.md) — the same
  pattern for GitHub Actions and GitLab CI runners.
- [`rotating-service-account-tokens.md`](./rotating-service-account-tokens.md)
  — fallback PAT rotation for workloads that cannot do OIDC.
- [`declare-gitops-config.md`](./declare-gitops-config.md)
  `kind: OidcIssuer` + `kind: ServiceAccount` — the canonical
  reference for the two envelopes shown here.
- [`using-hort-cli-with-admin-ops.md`](./using-hort-cli-with-admin-ops.md)
  — human-CLI admin flow. Workloads use federation; humans use
  `hort-cli auth login`.
