# Overlay: external load balancer (TLS terminated outside the cluster)

A partial values overlay for the `hort-server` chart that wires the
binary behind an external load balancer — a cloud NLB (AWS NLB, GCP
TCP/SSL LB, Azure LB), an on-prem appliance (F5, Citrix ADC), or a
hardware LB — that terminates TLS outside Kubernetes and forwards
plain HTTP to the chart's Service.

## When to pick this overlay

Pick this when TLS termination is owned by the network layer outside
the cluster:

- The organization already has a centrally-managed LB with corporate
  certificates and audit/compliance hooks.
- A cloud-account-level NLB sits in front of multiple clusters and
  fans out traffic.
- An air-gapped or restricted-egress environment cannot reach
  Let's Encrypt, ruling out cert-manager.

If TLS lives inside the cluster, prefer the
`ingress-nginx-cert-manager/` or `gateway-api/` overlay instead.

## Prerequisites

- An external LB is provisioned with TLS termination configured for
  the public hostname (e.g. `registry.example.com`).
- The LB's source IPs (the addresses Kubernetes nodes see proxied
  traffic come from) are known and stable enough to enumerate. Cloud
  NLBs that scale dynamically may require wildcarding the LB's subnet
  rather than listing instances.
- A way to expose the chart's Service to the LB. Two common options:
  - `service.type: NodePort` plus a cluster-network firewall rule
    permitting LB → node-port traffic.
  - `service.type: LoadBalancer` provisioning an internal cloud LB
    that the external LB then targets.

## Install

```
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/external-lb/values.yaml
```

`my-values.yaml` is the operator's own file: it carries
`image.repository`, `image.tag`, `publicBaseUrl`, the
`postgres.{app,admin}.existingSecret` references, the
`auth.oidc.*` settings, **and the actual `trustedProxyCidrs`** for
your LB (the values in this overlay are placeholders).

## Service-type override

The chart's `templates/service.yaml` defaults to `ClusterIP`, which is
not reachable from outside the cluster. Override the Service type in
your `my-values.yaml`:

```yaml
service:
  type: NodePort
  # Optional — omit to let the cluster pick a free port in the
  # configured node-port range.
  # nodePort: 30080
```

For cloud environments where the external LB targets an internal
cloud-provided LB, set `service.type: LoadBalancer` instead and
attach the relevant cloud annotations (`service.beta.kubernetes.io/...`).

## Why HSTS stays off

The overlay sets `requireHttps: false` deliberately. When TLS is
terminated outside the cluster, nothing inside the cluster has
positive evidence that the original request used HTTPS — the chart's
listener sees plain HTTP, and `X-Forwarded-Proto` is the only
indicator. The chart's HSTS code path declines to emit
`Strict-Transport-Security` in this configuration. That is
intentional: emitting HSTS without positive TLS evidence creates a
footgun where a misconfigured LB forwarding plain HTTP would publish
a permanent redirect-to-HTTPS that the chart cannot verify is honest.
Operators who want HSTS in this setup configure it on the LB itself
(every enterprise LB supports adding response headers).

## Pitfalls

### LB must set `X-Forwarded-Proto` and `X-Forwarded-For` correctly

If the LB is misconfigured and forwards traffic without these headers
(or with wrong values), every request looks like plain HTTP arriving
from the LB's IP. The chart will then render `http://` URLs back to
clients in OCI manifest responses, Cargo download links, and similar
self-referential surfaces — even though clients hit
`https://registry.example.com`. The mismatch breaks clients that
enforce scheme consistency. Verify with
`curl -I https://registry.example.com/healthz` from outside the
cluster and check pod logs to confirm the binary saw `X-Forwarded-Proto: https`.

### `trustedProxyCidrs` MUST list every LB source IP

The chart trusts `X-Forwarded-*` headers only from the CIDRs listed
in `trustedProxyCidrs`. If the LB's egress IPs are missing, the chart
silently ignores the headers and reverts to seeing plain HTTP from
the LB's IP — same symptoms as the previous pitfall. If the LB rotates
IPs (cloud NLB scaling, autoscaled VM pool), wildcard the LB's subnet
(e.g. `10.123.4.0/24`) rather than enumerating individual instances.
Every IP not in `trustedProxyCidrs` is treated as untrusted.

### `publicBaseUrl` must be the public HTTPS URL

`publicBaseUrl` in the operator's values file MUST be the public
HTTPS URL clients hit (the LB's external hostname), NOT the
cluster-internal Service URL. The binary uses this value to build
self-referential URLs; getting it wrong publishes broken links to
every client that downloads anything.
