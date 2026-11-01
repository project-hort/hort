# Monitor hort and troubleshoot failures

Monitor the public API, repository operations, and background processing separately. The monitoring endpoint must not be exposed as a public unauthenticated interface.

## Check service health

From a host that can reach the configured public endpoint:

```bash
curl -fsS https://hort.example.com/healthz
curl -fsS https://hort.example.com/readyz
```

Replace the hostname with your own deployment. A successful readiness check does not prove that registry access, authorization, or scanner jobs are working; verify representative client requests too.

## Enable protected metrics access

**Server metrics:** `hort-server` exposes `/metrics` on a **dedicated admin listener**, not the normal public API listener. Configure `HORT_METRICS_BIND` and restrict network access. Each scrape needs an authorized bearer token with the **global `read_metrics` permission grant**; being an administrator does not automatically grant it. Do not expose this listener publicly.

**Worker metrics:** the optional Helm setting `worker.metrics.enabled: true` exposes a **separate worker listener without per-request bearer-token authentication**. Its protection relies on the chart's restrictive Kubernetes NetworkPolicy and an explicit `worker.metrics.scrapeFrom` allowlist. Do not expose it to an untrusted network or disable NetworkPolicy as a workaround. If you operate native worker metrics, restrict the bind address and network access using the installed version's worker configuration.

Before enabling either scrape, verify access from an authorized monitor **and denial from an unauthorized client**. Protect and rotate the server scrape token. A `401` on the server listener and a network-level rejection on the worker listener have different causes.

## Troubleshoot common symptoms

| Symptom | What to check first |
| --- | --- |
| API unreachable | Process/pod, network route, TLS, reverse proxy, health and readiness |
| Pull receives `503` | Scan/quarantine state and any `Retry-After` response |
| Pull receives `502` | Upstream availability, upstream credentials, DNS/network connectivity |
| Scan jobs stop progressing | Worker logs, scanner process availability, queue backlog, CPU and memory |
| `/metrics` returns `401` | Monitoring token and global `read_metrics` grant |
| `/metrics` returns `404` on the public port | Wrong listener; use the configured server admin endpoint |
| Worker metrics cannot be reached | Check `worker.metrics.enabled`, the worker listener and the NetworkPolicy `scrapeFrom` allowlist; do not substitute the server bearer-token settings |

## Metrics and alert hygiene

Use the metrics catalog for the **installed release** when choosing dashboards and alerts. Measure error rates, API latency, job backlog, duration, and failures where those series are available. Avoid assuming that a metric with a similar name has identical labels across versions.

If you operate large numbers of repositories, review repository-label cardinality and the `METRICS_INCLUDE_REPOSITORY_LABEL` setting before enabling high-cardinality dimensions.

For AI-assisted diagnosis, combine versioned configuration, validator output and narrowly authorized observability data. Review recommendations before changing production. Never paste secrets or unrestricted telemetry into an unapproved external service.

**Related guides:** [Server & workers](workers.md) · [Declarative configuration](../configuration/declarative.md) · [Scanning & governance](scanning-governance.md).
