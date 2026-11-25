# Configure inbound credential transport

Hort's listeners speak HTTP. For a credential to be accepted, hort needs a
trusted proxy's scheme report or a declared scope where the TLS requirement
is waived. The policy and its limits are recorded in
[ADR 0068](../../../adr/0068-inbound-credential-transport-evidence.md).

## TLS-terminating edge

Set `HORT_TRUSTED_PROXY_CIDRS` to the immediate proxy's source ranges. That
proxy must **overwrite, never pass through or append**, both `Forwarded` and
`X-Forwarded-Proto`. Remove client-supplied values of either name and send one
scheme value for the client-to-edge hop. An `https` report from a trusted
peer is TLS evidence; an `http` report, disagreement, malformed value, or
multi-element list is a refusal for a credential unless the unscoped legacy
flag applies to that surface. No header from an untrusted peer establishes TLS. Restrict
direct network access to the listener: if a shared pod subnet is declared
trusted, any pod that reaches the socket can supply its own scheme.

`HORT_REQUIRE_HTTPS=true` checks configuration at boot. In the current
implementation it rejects an explicit `http://` public base URL with an
empty trusted-proxy list; an unset base URL also passes this check, although
another boot gate may still fail. It is **never**
evidence about a request. Set an `https://` public base URL for correct
links, and verify the proxy's actual header behavior independently.

## TLS inside the server pod

Set `tlsSidecar.enabled: true` and `tlsSidecar.secretName` to an existing
Kubernetes Secret with `tls.crt` and `tls.key`. The certificate must cover the
Service DNS name used by in-cluster clients; those clients must trust its CA.
The chart does not issue or rotate the certificate. Restart the server
Deployment after replacing the Secret so nginx reloads the certificate.
The Service keeps `service.httpPort` but targets nginx's TLS listener at
`tlsSidecar.httpsPort`. Hort binds `127.0.0.1:<service.httpPort>` so other
pods cannot reach its plaintext listener directly. The chart adds
`127.0.0.1/32` to `HORT_TRUSTED_PROXY_CIDRS` for nginx's scheme assertion.
If `networkPolicy.ingress` restricts ports, permit the TLS listener port
instead of hort's loopback port.

The edge must redirect or refuse plaintext client requests before it forwards
to the Service, and verify the Service certificate on its TLS connection.
nginx overwrites `X-Forwarded-Proto` with `https` to report
the ingress-to-pod TLS hop; it cannot prove how the client reached the edge.
nginx discards a caller's `Forwarded` header and appends to
`X-Forwarded-For`. Configure the edge to append or overwrite
`X-Forwarded-For` with the real client address, and list the edge's source
range in `trustedProxyCidrs` as well as the chart-added loopback address.
Hort's rightmost-untrusted address is then the client. A range that also
trusts unrelated pods can damage attribution, even though they cannot reach
hort's loopback listener to forge TLS evidence. Keep the edge range narrow.

The sidecar is off by default. With it off, the Service still carries HTTP
between ingress and pod. The operator must keep the edge's scheme headers
trustworthy for credentialed external calls and provide TLS or an applicable
scope for credentialed in-cluster calls. With the sidecar enabled, the
credentialed admin-task CronJobs use the HTTPS Service URL and the chart
mounts the CA named by `extraCaBundle.configMapName` or
`extraCaBundle.secretName` at `extraCaBundle.path`. Set the source and path
before enabling `scheduledTasks.adminTasksEnabled`; the chart rejects that
combination without an auto-mounted CA. The certificate must cover the
Service DNS name the CronJobs use.

## Deliberate plaintext hops

Set `HORT_TLS_NOT_REQUIRED_FROM` to a CSV of raw TCP peer CIDRs only for a
hop intentionally left plaintext. The default is empty. The scope admits
every caller able to reach the listener from those ranges, so use narrow
ranges and network policy. It waives `Unknown` evidence only for an
**unrelayed** caller that is not a trusted proxy. Any `Forwarded` or
`X-Forwarded-*` header makes the request ineligible, even when its proxy is
absent from the trust list. A trusted proxy reporting `proto=http` supplies
`Plaintext` evidence and cannot use the scope; give such an internal client
a direct unrelayed path or TLS. An ingress that source-NATs into the waived
range, sends no forwarding header, and is absent from the trust list remains
indistinguishable from a direct client. Do not put external ingress traffic
in a waived scope.

With the TLS sidecar disabled, the chart's eleven admin-task CronJobs use the
plain HTTP Service URL. Measure
their observed peer before setting `tlsNotRequiredFrom`; an ordinary
source-preserving ClusterIP path shows the CronJob pod IP, while meshes and
NAT can change it. The default metrics listener binds `127.0.0.1:9090` for
a sidecar; that scrape has a loopback peer and needs TLS or a separate
loopback scope. A loopback scope admits any process sharing the pod's network
namespace.

`HORT_BEARER_ALLOW_OVER_HTTP` is the unscoped legacy waiver: it can accept
presented credentials from any peer and can cover OCI minting. It does **not**
reach `POST /api/v1/auth/exchange`. Prefer the scoped declaration. A token
exchange inside a waived scope is accepted, but RFC 6749 §3.2 conformance
is not claimed for that request.

## Measure before tightening

Inspect `hort_credential_transport_total{entry_point,evidence}` for the six
entry points (`require`, `optional`, `metrics`, `oci_consume`, `oci_mint`,
`exchange`). `evidence="unknown"` shows calls without a usable scheme report;
`evidence="plaintext"` shows a trusted peer reported HTTP or ambiguous
headers. Compare `hort_credential_transport_waived_total{entry_point,scope}`
to see which waiver carries traffic. Alert on
`hort_credential_transport_refusals_total{entry_point}`: it covers all six
route classes. The generic auth middleware also writes
`hort_auth_attempts_total{result="transport_refused"}` and attempts a
best-effort auth audit event.
The OCI subtree emits neither auth stream, so they cannot stand in for the
transport refusal counter.

To identify the **peer address**, set
`RUST_LOG=info,hort_http_core::middleware::trust=debug` and inspect the
`request trust evaluated` line. Its `peer` field is the raw socket peer;
`client_ip` may be derived through the proxy. The transport counters carry
no address label. Compare the observed peer with the configured CIDR before
declaring a scope.
