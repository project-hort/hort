# Hort observability — Grafana dashboard samples

Two ready-to-import Grafana dashboards for a Hort deployment. They are **samples**:
standalone dashboard JSON with no bundled datasource/provisioning. Wire the
datasource template variables at import time (below).

| File | UID | Covers |
|------|-----|--------|
| `grafana/dashboards/hort-performance.json` | `hort-performance` | HTTP serving, ingest/download throughput, OCI stateful uploads, pull-through dedup, repository/artifact proxies, worker tasks, scan jobs. |
| `grafana/dashboards/hort-operational.json` | `hort-operational` | Error budget & failures, storage, event store & DB, health/safety gauges, supply-chain & security ops, artifact-lifecycle/quarantine state, and (Loki) recent-lifecycle log panels. |

The canonical definition of every metric these dashboards query — name, type,
labels, and allowed label values — is [`docs/metrics-catalog.md`](../../docs/metrics-catalog.md).
If a panel and the catalog disagree, the catalog wins.

## Prerequisites

### Prometheus (both dashboards)

A Prometheus instance scraping:

- **hort-server** — the bulk of the metrics (HTTP, ingest/download, storage,
  event store, quarantine, the boot-time liveness/unsafe-config gauges).
- **hort-worker** — the worker-emitted series: scan jobs/duration/queue depth,
  `hort_admin_tasks_*` (the dispatcher runs in the worker), advisory watch,
  cron-rescan backlog, and provenance verification. The worker exposes an
  **opt-in** `GET /metrics` listener bound via `HORT_WORKER_METRICS_BIND`
  (**disabled by default**). It has **no per-request auth** and its
  `repository` labels carry repo names, so it **must** be restricted with a
  NetworkPolicy — see
  [`docs/architecture/how-to/enable-provenance-verification.md`](../../docs/architecture/how-to/enable-provenance-verification.md)
  → *Worker metrics*. Without this scrape target the scan/worker/provenance/rescan
  panels stay empty.

### Loki (operational dashboard, log panels only)

The three "Recent lifecycle events" panels (latest released / rejected /
quarantined) read the structured `tracing` lines Hort emits per transition. They
require:

1. `HORT_LOG_FORMAT=json` on the hort pods,
2. a **Loki** datasource, and
3. a log shipper (promtail / Grafana Alloy) scraping the hort pods.

These panels are a convenience view; the authoritative record is the
append-only event store (`ArtifactReleased` / `ArtifactRejected` /
`ArtifactQuarantined`).

## Importing

Grafana UI → **Dashboards → New → Import → Upload JSON file**, then bind the
datasource variables. Or provision them by mounting the `grafana/dashboards/`
directory into a [dashboard provider](https://grafana.com/docs/grafana/latest/administration/provisioning/#dashboards)
and adding a Prometheus (and, for the operational log panels, a Loki) datasource.

### Template variables

Both dashboards expose `$datasource` (Prometheus). The operational dashboard
additionally exposes `$loki` and `$loki_selector` (edit `$loki_selector` to
match your log pipeline's stream labels — default `{app=~"hort-server|hort-worker"}`).

The **performance** dashboard exposes `$format` and `$repository` multi-selects.
They apply **only** to panels whose metric carries those labels — *Ingest rate
by format*, *Download rate by result*, and *Ingest byte throughput*. Most other
panels query metrics without a `format`/`repository` dimension (e.g.
`hort_event_store_*`, `hort_storage_*`, `hort_http_*`) and are unaffected by the
selectors — this is expected.

> **Repository-label cardinality.** At scale a deployment may set
> `METRICS_INCLUDE_REPOSITORY_LABEL=false`, which emits `repository="_all"`
> instead of per-repo series. When it is disabled, the `$repository` selector,
> the *Active repositories* stat, and the *top-repositories* panels all collapse
> to the single `_all` sentinel. See the catalog's
> [cardinality ceiling note](../../docs/metrics-catalog.md#label-schema-and-cardinality-rules).

## Exact live inventory (optional)

Hort **externalises entity counts** — there is intentionally no Prometheus gauge
for the live number of repositories or artifacts.
The performance dashboard's *Artifacts ingested* and *Active repositories* stats
are honest Prometheus-derived **proxies** (a cumulative all-time success counter
and a count of repositories with ingest traffic), not a current inventory.

For an exact live count, add a **PostgreSQL** datasource pointed at the Hort
database (a read-only role is sufficient) and a table panel running, e.g.:

```sql
SELECT 'repositories' AS entity, count(*) FROM repositories
UNION ALL
SELECT 'artifacts', count(*) FROM artifacts;
```

This is deliberately not shipped in the sample dashboards because it requires a
direct DB datasource that most Prometheus-only setups will not have.
