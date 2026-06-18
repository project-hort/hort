# `hort-server` Helm chart — edge overlays

The chart at `deploy/helm/hort-server/` deliberately ships **no Ingress,
no Gateway, no HTTPRoute**. The operator owns the edge — the chart
ends at the ClusterIP Service. This document explains the three
example edge configurations under
`deploy/helm/hort-server/examples/`: when to pick each one, what to
apply alongside the chart, and the pitfalls each shape commonly trips
over.

This is the *explanation* document. The READMEs inside each overlay
directory are the *install path* — they show the exact commands and
manifests to apply. This document does not duplicate them; it
explains the trade-offs that drive the choice and the binary-side
behaviour each shape interacts with.

For the chart-wide picture see
[`helm-chart.md`](../../reference/helm-chart.md).
For per-key values explanations see
[`values-reference.md`](./values-reference.md). For the full install
path see [`install.md`](./install.md).

---

## 1. ingress-nginx + cert-manager (the common case)

Source: [`deploy/helm/hort-server/examples/ingress-nginx-cert-manager/`](../../../../deploy/helm/hort-server/examples/ingress-nginx-cert-manager/).

### When to pick this overlay

ingress-nginx + cert-manager is by far the most common edge in a
Kubernetes cluster: the controller is widely deployed, cert-manager
is the de-facto Let's Encrypt integration, and the combination
handles TLS termination, ACME challenges, and certificate rotation
without operator intervention. Pick this overlay when:

- You do not already have an external load balancer doing TLS
  termination outside the cluster.
- Your cluster runs the ingress-nginx controller (or you can install
  it).
- You use cert-manager — or are willing to install it — for
  automated TLS certificates from Let's Encrypt or an internal CA.

### Install

```bash
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/ingress-nginx-cert-manager/values.yaml
```

The overlay carries `requireHttps: true`, `api.bindAddr: "0.0.0.0:8080"`, and a
private-RFC1918 `trustedProxyCidrs` list. The Ingress resource itself
is **not** rendered by the chart — apply the YAML in the overlay's
README separately. See the overlay README for the canonical Ingress
manifest (annotations, `ingressClassName: nginx`, `tls:` block, and
`backend.service.name: <fullname>-hort-server`).

### TLS termination details

The chart's pods see plain HTTP. ingress-nginx terminates TLS using
the certificate cert-manager issued. The chart's `requireHttps: true`
works because `trustedProxyCidrs` is non-empty AND the ingress
controller sets `X-Forwarded-Proto: https` — the binary's
HSTS-emission path checks that combination as
positive evidence of upstream TLS, and HSTS becomes safe to emit.

### Pitfalls

#### `proxy-buffer-size` truncates OCI manifest list responses

The default ingress-nginx proxy buffer is 4 KB. OCI manifest list
responses for multi-arch images, especially with many layers and
extensive annotations, routinely exceed that. When the buffer
overflows, ingress-nginx replies `502 Bad Gateway` or — worse —
emits a truncated body. Container clients then see partial JSON,
fail to parse the manifest, and report cryptic pull errors. Set
`nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"` and
`proxy-buffers-number: "8"` on the Ingress (the overlay README's
manifest already does so).

#### `proxy-body-size` blocks large blob uploads

`docker push` of a non-trivial container image streams every blob
through the ingress. ingress-nginx defaults to a 1 MB body limit —
which fails every realistic image push partway through. Set
`nginx.ingress.kubernetes.io/proxy-body-size: "8g"` to cover most
enterprise images (custom OS bases, ML model layers can exceed
this — raise further as required).

#### Proxy timeouts must match `oci.uploadTimeoutSeconds`

The chart's `oci.uploadTimeoutSeconds` defaults to `3600`
(60 minutes) — the chart-side window for an OCI long-tail blob
upload to complete. The Ingress annotations
`nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"` and
`proxy-send-timeout: "3600"` keep the ingress side aligned. If you
raise `oci.uploadTimeoutSeconds`, raise both annotations to
match — otherwise the ingress severs the connection while the
binary is still happily reading. See
[`http-transport-timeouts.md`](../http-transport-timeouts.md) for
the depth on this knob.

---

## 2. Gateway API (Kubernetes 1.30+)

Source: [`deploy/helm/hort-server/examples/gateway-api/`](../../../../deploy/helm/hort-server/examples/gateway-api/).

### When to pick this overlay

The Gateway API graduated to v1 (GA) in Kubernetes 1.30 and is the
strategic replacement for the older Ingress resource. Pick this
overlay when:

- Kubernetes ≥ 1.30 (Gateway API v1 is GA from this version).
- You have a Gateway-API-aware controller installed (Cilium, Istio,
  Envoy Gateway, NGINX Gateway Fabric, Traefik, or any conformant
  implementation).
- You want to consolidate ingress under Gateway API rather than
  maintain Ingress resources alongside.

Operators with no existing Gateway controller will find
ingress-nginx + cert-manager simpler — prefer §1.

### Install

```bash
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/gateway-api/values.yaml
```

The overlay carries `requireHttps: true`, `api.bindAddr: "0.0.0.0:8080"`, and a
private-RFC1918 `trustedProxyCidrs` list. The Gateway, HTTPRoute and
(optional) `BackendTLSPolicy` resources are **not** rendered by the
chart — apply the YAML in the overlay's README. The HTTPRoute's
`backendRefs.name` references the chart's rendered fullname Service
(default `<release>-hort-server`); the Gateway listens on port 443
with `tls.mode: Terminate` against a Secret in the Gateway's
namespace.

### TLS termination and BackendTLSPolicy

The Gateway terminates TLS at port 443; the HTTPRoute forwards plain
HTTP to the chart's pods on port 8080. Same shape as §1 from the
binary's perspective: the listener sees plain HTTP plus
`X-Forwarded-Proto: https` from a trusted CIDR, and the HSTS path
fires.

`BackendTLSPolicy` (also under `gateway.networking.k8s.io/v1`) is the
Gateway-API mechanism for re-encrypting traffic to backend pods. For
v2 it is **not applicable** — the binary does not terminate TLS in
itself; in-binary TLS is deferred.
`BackendTLSPolicy` becomes relevant once a future "in-binary TLS"
change ships and the chart's Service grows an HTTPS port.
Until then, the Gateway terminates and forwards HTTP plaintext.

### Pitfalls

#### Kubernetes 1.27–1.29 needs `v1beta1`

The overlay README's YAML targets `gateway.networking.k8s.io/v1`,
which is GA in K8s 1.30 and later. On 1.27–1.29 you must use the
`v1beta1` API group. The shape is similar but not identical;
consult your controller's documentation for the exact CRD versions
it supports.

#### `gatewayClassName` is operator-specific

The Gateway resource references a `GatewayClass` by name; the value
depends on which controller you installed. Run
`kubectl get gatewayclass` to see what is available, and pick the
one your controller is reconciling. The overlay README uses
`<your-gateway-class>` as a placeholder — every cluster substitutes
its own value.

#### Long-lived blob upload connections vary by controller

Gateway controllers vary in how they handle long-lived HTTP/1.1
connections. Verify your controller's request and response timeout
defaults against the chart's `oci.uploadTimeoutSeconds`
(default `3600`). If your controller imposes a shorter timeout,
raise it via a controller-specific policy resource (consult its
docs) — lowering `oci.uploadTimeoutSeconds` to match would
cause large OCI blob uploads to fail mid-stream.

---

## 3. external-lb (TLS upstream of the cluster)

Source: [`deploy/helm/hort-server/examples/external-lb/`](../../../../deploy/helm/hort-server/examples/external-lb/).

### When to pick this overlay

Pick this when TLS termination is owned by the network layer outside
the cluster:

- The organisation already has a centrally-managed load balancer
  with corporate certificates and audit/compliance hooks.
- A cloud-account-level NLB sits in front of multiple clusters and
  fans traffic out.
- An air-gapped or restricted-egress environment cannot reach
  Let's Encrypt, ruling out cert-manager.

If TLS lives inside the cluster, prefer §1 or §2.

### Install

```bash
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/external-lb/values.yaml
```

The overlay carries `requireHttps: false`, `api.bindAddr: "0.0.0.0:8080"`, and
**placeholder** `trustedProxyCidrs` you must replace with your LB's
actual source IPs. The chart's Service defaults to ClusterIP — for
this overlay override it in your `my-values.yaml` to `NodePort`
(plus a firewall rule LB-→-node-port) or `LoadBalancer` (cloud LB
target). See the overlay README for the Service-type override
snippet.

### TLS termination details

TLS is terminated upstream of the cluster. The chart's pods see
plain HTTP arriving from the LB. `requireHttps: false` is
**deliberate**: the chart's listener has no positive TLS evidence,
and setting `requireHttps: true` here would either (a) reject every
request because the `X-Forwarded-Proto` check fails, or
(b) silently produce HSTS without corroboration. False is the safe
call.

### Why HSTS stays off in this configuration

The chart's HSTS code path emits
`Strict-Transport-Security` only when there is positive TLS
evidence: an `X-Forwarded-Proto: https` header from a source inside
`trustedProxyCidrs` AND a `publicBaseUrl` that begins `https://`.
External-LB-without-explicit-`X-Forwarded-Proto: https` would create
a footgun where a misconfigured LB forwarding plain HTTP would
publish a permanent redirect-to-HTTPS the chart cannot verify is
honest. The chart errs on the side of not emitting. Operators who
want HSTS in this setup configure it on the LB itself — every
enterprise LB supports adding response headers.

### Pitfalls

#### LB MUST set `X-Forwarded-Proto: https` (and `X-Forwarded-For`)

If the LB is misconfigured and forwards traffic without these
headers (or with wrong values), every request looks to the binary
like plain HTTP arriving from the LB's IP. The chart will then
render `http://` URLs back to clients in OCI manifest responses,
Cargo download links, and similar self-referential surfaces — even
though clients hit `https://registry.example.com`. The mismatch
breaks clients that enforce scheme consistency. Verify with
`curl -I https://registry.example.com/healthz` from outside the
cluster and check pod logs to confirm the binary saw
`X-Forwarded-Proto: https`.

#### `trustedProxyCidrs` MUST list every LB source IP

The chart trusts `X-Forwarded-*` headers only from the CIDRs listed
in `trustedProxyCidrs`. If the LB's egress IPs are missing, the
chart silently ignores the headers and reverts to seeing plain
HTTP from the LB's IP — the same symptoms as the previous pitfall.
If the LB rotates IPs (cloud NLB scaling, autoscaled VM pool),
wildcard the LB's subnet (e.g. `10.123.4.0/24`) rather than
enumerating instances. Every IP not in `trustedProxyCidrs` is
treated as untrusted.

#### `publicBaseUrl` MUST be the public HTTPS URL

`publicBaseUrl` in the operator's values file MUST be the public
HTTPS URL clients hit (the LB's external hostname), NOT the
cluster-internal Service URL. The binary uses this value to build
self-referential URLs; getting it wrong publishes broken links to
every client that downloads anything.

---

## 4. Comparison

| Aspect | ingress-nginx + cert-manager | Gateway API | external-LB |
|---|---|---|---|
| TLS termination | Ingress (cert-manager) | Gateway listener (`tls.mode: Terminate`) | External LB (outside cluster) |
| K8s version floor | 1.27 | 1.30 (1.27–1.29 with `v1beta1`) | 1.27 |
| Controller required | ingress-nginx | Gateway-API-conformant controller | none in-cluster |
| Cert lifecycle | cert-manager + ACME / internal CA | external Secret (cert-manager or manual) | LB / network team |
| HSTS emitted | yes | yes | no (deliberate — see §3) |
| `requireHttps` | `true` | `true` | `false` |
| `BackendTLSPolicy` applicable | n/a | future (v2 = no) | n/a |
| Chart Service type | ClusterIP | ClusterIP | NodePort or LoadBalancer |
| Common-case difficulty | low | medium | medium |

---

## See also

- [`install.md`](./install.md) — full install path, Postgres
  runbook, Secret kinds, OIDC, `helm install` scenarios, and
  six-command verification.
- [`values-reference.md`](./values-reference.md) — every chart key
  documented; the canonical home for per-key rationale.
- `security-hardening-checklist.md` — chart hardening posture.
- [`../wire-secrets.md`](../wire-secrets.md) — `SecretPort` +
  mTLS / CA / cert-pin mount surface.
- [`../http-transport-timeouts.md`](../http-transport-timeouts.md)
  — operator-tunable HTTP timeout knobs;
  `oci.uploadTimeoutSeconds` rationale.
- [`helm-chart.md`](../../reference/helm-chart.md) — the chart
  reference, including the "operator owns the edge" posture.
