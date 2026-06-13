# Tune HTTP transport timeouts

This guide is for operators who need to adjust how aggressively
`hort` cuts slow or stuck HTTP connections. The shipped defaults are
conservative and suit most deployments; you only need this guide if
you operate a network where the defaults bite.

---

## 1. What the timeouts protect against

Without explicit timeouts, `axum::serve(...)` runs with hyper defaults:
no header-read timeout, no idle-cap on HTTP/2 sessions, no per-handler
deadline. A single attacker holding a slowloris connection could pin
a hyper accept worker until the kernel socket timer fired (typically
minutes); a slow database query could pin a worker until the request
returned. The per-IP rate-limit (`tower_governor`) only fires after
header parsing, so it does not bound either surface.

Instead, the binary cuts:

| Surface | Cap | Configurable via |
|---|---|---|
| Slow request-line / headers | 15 s | `HORT_HTTP_HEADER_READ_TIMEOUT_SECS` |
| HTTP/2 idle session (PING / pong) | 30 s interval, 30 s timeout | not exposed yet — file an issue |
| Per-handler runtime deadline | 5 min | `HORT_HTTP_REQUEST_TIMEOUT_SECS` |
| OCI blob upload runtime deadline | 60 min | `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` |
| Graceful-shutdown drain | 60 s | `HORT_SHUTDOWN_GRACE_SECS` |

The HTTP/1 between-request idle on a keep-alive connection is governed
by `HORT_HTTP_HEADER_READ_TIMEOUT_SECS` — hyper 1.x does not expose a
separate `keep_alive_timeout` for HTTP/1 because the next request's
request-line + headers must arrive within the header-read window.

---

## 2. The env vars

All accept a positive integer number of seconds. A non-integer value
is rejected at startup with `ConfigError::InvalidInt`; zero is rejected
with `ConfigError::ValueNotPositive`. Either way the log line names the
offending variable. Unset → default below.

### `HORT_HTTP_HEADER_READ_TIMEOUT_SECS`

**Default:** `15`

The wall-clock cap on how long a connected client can take to send a
complete request line + headers. Slowloris-style attacks trickle one
byte every 30 s to keep a connection open forever; this knob bounds
that to 15 s.

**When to raise:** clients on satellite or other very-high-latency
links may legitimately take >15 s to deliver headers. If you see
`IncompleteMessage` errors at debug level for legitimate clients,
raise to 30–60 s. Do not raise above the per-request timeout below —
it would not help and would weaken slowloris protection.

**When to lower:** datacenter-internal deployments behind a TLS
terminator can safely drop to 5 s; the terminator handles the
slow-byte side.

### `HORT_HTTP_REQUEST_TIMEOUT_SECS`

**Default:** `300` (5 minutes)

The wall-clock cap on how long any single handler may run after a
complete request has been parsed. Slow upstream metadata fetches,
slow database queries, and slow scanner submissions are all bounded
here. On expiry the handler future is dropped and the client receives
`408 Request Timeout`.

**When to raise:** if you proxy an unusually slow upstream metadata
endpoint (e.g. a private mirror with cold caches), 600 s may be
necessary. Watch `hort_http_concurrent_inflight` — long-running
handlers consume worker slots.

**When to lower:** if your scanner SLA is 60 s and you'd rather fail
fast than tie up a worker, drop to 90 s. Test with the slow-upstream
suites under `scripts/native-tests/` before committing.

### `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`

**Default:** `3600` (60 minutes)

The per-route override applied to OCI blob upload routes
(`PATCH /v2/.../blobs/uploads/<uuid>` and the corresponding `PUT`).
Multi-GB image layers from slow corporate networks legitimately exceed
the 5-minute global deadline; this ceiling exists so a stuck push
still terminates rather than pinning a worker forever.

**When to raise:** very-large-layer scientific images (e.g. CUDA
base images) on slow uplinks may need 90–120 min. Prefer fixing the
upstream instead — uploads above an hour usually indicate a missing
edge cache.

**When to lower:** for clusters where every push is a built-in-CI
image (so layers are fresh and small), 600 s is plenty and reduces
the worker-pinning surface.

**Helm key:** wire this via `oci.uploadTimeoutSeconds` (Backlog 078
Item 10 grouped it with the other OCI surfaces; the pre-078
`http.ociUploadTimeoutSeconds` key is retired — HARD rename, no alias).
The env var name above is unchanged.

### `HORT_SHUTDOWN_GRACE_SECS`

**Default:** `60` (seconds)

**Units:** seconds. Zero or negative values are rejected at startup
with `ConfigError::ValueNotPositive` and a log line naming the
variable. Unset → 60 s default.

The wall-clock cap on how long the binary waits for in-flight
requests to drain after receiving SIGTERM / SIGINT. The signal
fan-out (a single `CancellationToken`) tells every listener and
background task to stop accepting new work; the hyper-util
`GracefulShutdown` watcher then waits for active connections to
finish their current request. Most well-behaved handlers complete in
milliseconds, but a stuck handler (frozen DB pool, hung upstream)
would otherwise pin shutdown forever — orchestrators (systemd
`TimeoutStopSec`, Kubernetes `terminationGracePeriodSeconds`) eventually
escalate to `SIGKILL`, which leaves in-flight uploads in undefined
state on the storage side.

**When to tune:** the default sits one tier above Kubernetes's
default `terminationGracePeriodSeconds` of 30 s. Set this knob
*below* your orchestrator's grace period so the binary's own
deadline fires first and you get the structured warn line, not a
SIGKILL with no diagnostic. If you bump the orchestrator side to
120 s for slow drains, bump this to 90 s to match.

**On expiry:** the runtime aborts the outstanding handles via drop
and emits a single `tracing::warn!` on `target = "hort::shutdown"`
carrying the in-flight count and the configured grace as structured
fields:

```text
WARN hort::shutdown: graceful shutdown timed out; aborting outstanding handlers
  in_flight=3 grace_secs=60
```

The process then exits cleanly. Routine shutdowns inside the window
emit only the pre-existing `info!("hort-server shutdown complete")`
line — `WARN` on `hort::shutdown` is therefore an actionable signal:
either a handler is genuinely hung, or the grace is set too low for
this workload.

---

## 3. Symptoms of misconfiguration

| Symptom | Likely cause | Fix |
|---|---|---|
| Legitimate clients see `408 Request Timeout` on routine requests | `HORT_HTTP_REQUEST_TIMEOUT_SECS` set too low for upstream proxy fetches | Raise to 600 s and check upstream latency |
| Connections to satellite-link clients close mid-handshake | `HORT_HTTP_HEADER_READ_TIMEOUT_SECS` too low for client RTT | Raise to 30–60 s |
| `docker push` of large layers fails with 408 | `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` too low for layer size / uplink | Raise to 7200 s and inspect why the upload is so slow |
| Server logs show `shutdown deadline exceeded; dropping in-flight connections` on every restart | A handler is hung past the per-listener 60 s graceful drain | Investigate the hung handler — the drain is intentionally bounded |
| Server logs `WARN hort::shutdown: graceful shutdown timed out` on every restart | A handler is still running when `HORT_SHUTDOWN_GRACE_SECS` expires | Investigate the hung handler; bump `HORT_SHUTDOWN_GRACE_SECS` only if the workload genuinely needs longer drain |
| Worker count saturates under load that used to be fine | Handlers running longer than the new deadline cuts | Profile slow handlers; do not silently raise the deadline |

---

## 4. Verification

After changing any of these variables, restart the binary and
exercise:

```bash
# Slow-header probe — connection should close within
# HORT_HTTP_HEADER_READ_TIMEOUT_SECS + ε.
{ printf 'GET / HTTP/1.1\r\nHost: x\r\n'; sleep 60; } | nc -w 30 <hort-host> 8080

# Long-request probe — should receive 408 after
# HORT_HTTP_REQUEST_TIMEOUT_SECS.
curl -m 600 -X POST http://<hort-host>:8080/<a-slow-route>

# OCI-upload exemption — should NOT 408 inside the global deadline.
docker push <hort-host>:8080/myrepo/big-image:latest
```

The integration test
[`crates/hort-server/tests/http_timeouts.rs`](../../../crates/hort-server/tests/http_timeouts.rs)
asserts the same behaviours under CI. If a value you configured
behaves differently from the table above, that test is the
ground-truth specification — open an issue with the regression you
observe.
