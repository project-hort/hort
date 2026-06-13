# Configure PyPI pull-through with verified upstream

This guide is for operators who want a Remote PyPI repository in
`hort` that proxies `pypi.org` (or a private PyPI mirror)
and serves wheels and sdists to `pip`. It covers the YAML to declare,
the `pip install` command shape, and how to read the two `502`
responses you may see when verification rejects an upstream file.

For the architectural rationale see
[ADR 0006 — mandatory upstream verification](../../adr/0006-mandatory-upstream-verification.md).

---

## 1. What pull-through verification means

Every file that `pip` fetches through a Remote PyPI repository is
SHA-256-verified against the digest published by the upstream's
per-version JSON API (`/pypi/{name}/{version}/json` →
`urls[].digests.sha256`). On match the bytes land in local CAS and a
`ChecksumVerified` event is appended to the artifact stream;
subsequent requests for the same file serve from CAS without
re-fetching upstream.

Verification is a **type-system invariant**, not a per-repository
opt-in — there is no `enabled: true` to set, no flag to relax the
requirement. A PyPI proxy that cannot reach a SHA-256 in the
upstream's JSON cannot serve the file at all. Operators who need
content with no upstream-published checksum (vendored sdists,
historical files predating PEP 503) must publish it through a Hosted
PyPI repository with a client-supplied digest.

A tampered file (one whose bytes do not hash to the digest the JSON
advertised) produces a `502 Bad Gateway` response, a
`ChecksumMismatch` event in the audit log, and **never reaches local
CAS**.

---

## 2. Declare a Remote PyPI repository

Two YAML files under `$HORT_CONFIG_DIR`. The first declares the
repository, the second declares its upstream mapping.

### 2a. `repositories/pypi-public.yaml`

```yaml
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: pypi-public
spec:
  name: "PyPI Public Mirror"
  description: "Pull-through cache for the public PyPI registry."
  format: pypi
  type: proxy
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/pypi-public
  proxy:
    upstreamUrl: https://pypi.org/
  isPublic: true
  replicationPriority: local_only
```

`metadata.name` is the repository key — the `<repo>` segment in every
URL `pip` will hit. It must match `^[a-z][a-z0-9-]{0,62}$`.

The `proxy:` block is required by the gitops validator for
`type: proxy` repositories. The actual upstream-mapping row that
`try_upstream_file_pull` resolves at request time is defined by the
separate `UpstreamMapping` resource below; the two `upstreamUrl`
values must agree.

### 2b. `upstreams/pypi-public.yaml`

```yaml
apiVersion: project-hort.de/v1beta1
kind: UpstreamMapping
metadata:
  name: pypi-public
spec:
  repository: pypi-public
  pathPrefix: ""
  upstreamUrl: https://pypi.org/
  auth:
    type: anonymous
```

`spec.repository` references the `metadata.name` of the repository
above. PyPI uses a single catch-all upstream per repository, so
`pathPrefix` is the empty string. `auth.type: anonymous` is correct
for `pypi.org` and most public mirrors; for a private mirror that
requires credentials, use `bearer` or `basic` and reference a secret
via [`wire-secrets.md`](wire-secrets.md). The credentialed
pull-through path itself is gated on the gitops-mapping-writer
follow-on — see [`declare-gitops-config.md`](declare-gitops-config.md)
§6.

Restart `hort-server` to apply. There is no live-reload;
[`declare-gitops-config.md`](declare-gitops-config.md) §5 covers the
boot sequence.

---

## 3. Point `pip` at the proxy

```
pip install \
  --index-url http://hort.example.com/pypi/pypi-public/simple/ \
  requests
```

- `--index-url` points at the simple-index proxy. `pip` requests
  `/simple/requests/`; the proxy fetches the upstream HTML and
  rewrites every `files.pythonhosted.org` link back to this
  `/pypi/pypi-public/...` prefix so `pip` never connects to the
  upstream directly.
- The first download triggers verified pull-through: the orchestrator
  fetches `/pypi/requests/{ver}/json`, parses
  `urls[].digests.sha256` for the requested filename, fetches the
  file via the JSON's absolute `urls[].url`, and streams bytes
  through SHA-256 verification into local CAS.
- Subsequent downloads of the same file are served from CAS without
  re-fetching upstream.
- **Concurrent cache-miss requests are coalesced.**
  Both the simple-index fetch, the per-version JSON metadata fetch,
  and the wheel/sdist fetch run through `PullDedup`'s two-layer
  service: in-process across handler invocations on the same replica
  (DashMap + `tokio::broadcast`) and cluster-wide via the
  `EphemeralStore`-backed `pulldedup:` keyspace. N parallel
  `pip install`s for the same uncached package produce ≤ 1 upstream
  metadata request and ≤ 1 upstream file request. Upstream `404`,
  `5xx`, `429`, and timeout outcomes coalesce into the same short-
  cached response for every follower — a single rate-limit burst
  against `pypi.org` produces one upstream request and N short-
  cached `502 Bad Gateway` responses, not N retries. The follower-
  cache TTLs are tunable via `HORT_PULL_DEDUP_TTL_*` env vars; see
  [`deploy/values-reference.md`](deploy/values-reference.md). Single-
  replica deployments get coalescing for free via the in-memory
  `EphemeralStore`.

For a persistent setting, write it once into `pip.conf` (Linux/macOS)
or `pip.ini` (Windows):

```ini
[global]
index-url = http://hort.example.com/pypi/pypi-public/simple/
```

`--extra-index-url` works for hybrid setups that fall back to another
PyPI registry for content the proxy chooses not to serve.

---

## 4. Diagnose `502 Bad Gateway` from the proxy

Two verification failure modes surface as `502`, distinguished by the
`X-Hort-Reason` response header.

### `X-Hort-Reason: upstream-checksum-mismatch`

The bytes the upstream served did not hash to the SHA-256 the upstream
JSON advertised. Causes: the upstream mirror is compromised or serving
stale content from a poisoned cache; a transparent proxy on the
network path is rewriting bodies; or — rarely — a withdraw-republish
race upstream.

Check `hort-server` logs for `ChecksumMismatch` (`warn!` level, with
published vs actual digest and the upstream URL). Validate the
upstream URL in `upstreams/pypi-public.yaml` and the network path.
Re-running `pip install` will not recover — the proxy refuses to
cache bad bytes by design. The fix is upstream.

### `X-Hort-Reason: upstream-metadata-malformed`

The upstream JSON returned for `/pypi/{name}/{version}/json` was
unparseable, missing the `urls[]` entry for the requested filename,
or had no `digests.sha256` for that entry. The most common cause is
a file withdrawal between simple-index discovery and file download —
`pip` saw the file in the index, requested it, but the JSON no
longer lists it. Less commonly: the upstream is a non-compliant
mirror that publishes only `md5` or `sha1` (both rejected by
design — they are not safe for supply-chain integrity).

Check `hort-server` logs for the parse-error detail at `warn!` level.
For a legitimate withdrawal, retry once; if it persists, the file is
gone. For a mirror that lacks SHA-256, switch `upstreamUrl` to
`https://pypi.org/` or another compliant mirror.

For both modes, the metric
`hort_upstream_checksum_total{format="pypi", result="mismatch"}` ticks
on every detected tampering — alerting on a non-zero rate is
recommended.

---

## 5. See also

- [ADR 0006 — mandatory upstream verification](../../adr/0006-mandatory-upstream-verification.md)
  — architectural rationale and the type-system invariants.
- [Format handlers § "Upstream verification"](../explanation/format-handlers.md#upstream-verification)
  — how per-format trait methods compose into the two verification
  cases.
- [`declare-gitops-config.md`](declare-gitops-config.md) — the
  `$HORT_CONFIG_DIR` model and YAML envelope shape.
- [`wire-secrets.md`](wire-secrets.md) — credentials for private
  upstream mirrors.
