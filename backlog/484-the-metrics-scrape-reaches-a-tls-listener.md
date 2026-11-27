# 484 — a credentialed metrics scrape reaches a TLS listener

**Issue:** #462 · **Branch:** `agent/462-sidecar-half-surface`.
**Depends on** unit 483: its certificate `map` must cover this listener too.

## What is wrong

`/metrics` sits on the admin router, which attaches `require_principal`
whenever auth is wired (`crates/hort-server/src/http.rs:390-415`), and that
middleware renders the credential-transport verdict
(`crates/hort-http-core/src/middleware/auth.rs:293-344`) — no bearer gives
`401`, a bearer gives the transport verdict **before** validation and
authorization. `/metrics` is only a telemetry entry-point label there, not an
exemption. Confirmed from outside against a running installation: with a
credential `426 credential transport refused`, without one `401 missing
Authorization header`, one second apart on the same URL and hop.

The chart's only TLS server proxies the API
(`templates/tls-sidecar-configmap.yaml:20-38`), and the Service's `metrics`
port targets the bare container port (`templates/service.yaml:21-37`). So a
credentialed scrape has no TLS-bearing hop available.

**`/metrics` staying on the admin listener is a decision, not an oversight**
(ADR 0052; `http.rs:37-45` — *"`/metrics` is NEVER mounted on this router"*).
It does not move onto the API router. There is also no anonymous opt-out to
reintroduce.

A second existing discrepancy is repaired by the same change: `metrics.bindAddr`
defaults to loopback (`values.yaml:487-505`) while `service.yaml:29-37` targets
the server's metrics port directly, so a cross-pod scrape is unreachable at
defaults even without the transport gate.

## What to build

A second `listen … ssl` in the existing nginx sidecar on its own unprivileged
`tlsSidecar.metricsHttpsPort`, proxying **only** to
`127.0.0.1:<metrics bind port>`, overwriting `X-Forwarded-Proto` with `https`
and clearing `Forwarded`, exactly as the API server block does. With it:

- a second named pod port, and the Service's `metrics` port targeting it when
  the sidecar is enabled (`deployment.yaml:488-502`, `service.yaml:29-37`);
- the server's admin bind stays on loopback, and a `metrics.bindAddr` or
  `extraEnv` that would leave a network-reachable plaintext bypass is
  **refused at render time** — otherwise the old port stays reachable beside
  the TLS one;
- the ports stay distinct so a NetworkPolicy can admit Prometheus to the
  metrics TLS port without opening the API port;
- `templates/servicemonitor.yaml:19-38` gains `scheme: https`, a CA and server
  name, and a Secret-backed bearer reference. It carries none of those today
  and tells the operator to extend the template themselves. **No switch that
  disables verification** (ADR 0010).

## Acceptance

With the sidecar enabled and auth active:

| request | expected |
|---|---|
| token **with** `read_metrics`, over the TLS hop | `200` |
| no token, same hop | `401` |
| token **without** the grant | `403` |
| credential over a plaintext hop | `426` |
| `/metrics` on the API router | `404` |

Plus: the Service's `metrics` port demonstrably targets the sidecar port, the
admin listener is loopback-only, and a render matrix covers the positive
combination (sidecar + ServiceMonitor + admin tasks) **and** the negative ones
— every API/metrics/control port collision, a `HORT_API_BIND` or
`HORT_METRICS_BIND` override through `extraEnv`, sidecar plus admin tasks with
no CA source, and an enabled ServiceMonitor with a disabled metrics bind. The
existing render-time `fail`s stay effective and extend to the new port.

**The scrape tests belong in `scripts/k8s-tests/` (kind).** A render proves no
traffic works.

## One thing this unit must not claim

The proxy's `X-Forwarded-Proto: https` is an **assertion accepted from a
trusted loopback peer**, not in-process measurement. ADR 0068 leaves that
residual risk explicitly. Nothing in this unit may be described as giving the
server cryptographic evidence of the hop, or as proving an end-to-end TLS path
from a gateway.

## Open, and this unit decides it

The optional control listener (`values.yaml:517-549`,
`crates/hort-server/src/cli/serve.rs:958-985`) has no port in
`templates/service.yaml:21-37`. Sidecar plus a control split plus admin tasks
can therefore produce a `404` of its own, unrelated to metrics. Either wire
that listener or refuse the combination with a render-time error naming it —
the unit states which and why, rather than leaving it to be discovered.
