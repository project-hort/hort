# Configure npm pull-through with verified upstream

This guide is for operators who want a Remote npm repository in
`hort` that proxies `registry.npmjs.org` (or a private npm
mirror) and serves packuments and tarballs to `npm`. It covers the
YAML to declare, the `.npmrc` shape, how to read the four `502`
responses you may see when verification rejects an upstream tarball
or its packument, and how to tell a version hort is *holding* (`503`)
apart from one that does not exist (`404`).

For the architectural rationale see
[ADR 0006 — mandatory upstream verification](../../adr/0006-mandatory-upstream-verification.md).

---

## 1. What pull-through verification means

Every tarball that `npm` fetches through a Remote npm repository is
SHA-512-verified against the SRI digest published by the upstream's
packument (`GET /{pkg}` →
`versions[ver].dist.integrity`, `sha512-<base64>`). On match the
bytes land in local CAS and a `ChecksumVerified` event with
`algorithm: Sha512` is appended to the artifact stream; subsequent
requests for the same tarball serve from CAS without re-fetching
upstream.

npm is the **only multi-algorithm format in v2**: every other v2
format (Cargo, PyPI, OCI, Maven, etc.) verifies with SHA-256. npm
publishes `dist.integrity` as an SRI string keyed on SHA-512, so the
ingest pipeline wraps the upstream stream in `Sha512HashingRead`
specifically for this format.

The audit invariant: every npm tarball that hort serves
from a Proxy repo has exactly one `ChecksumVerified` event in its
`artifact:<id>` stream, in the same append batch as
`ArtifactIngested`, with `algorithm = HashAlgorithm::Sha512`. A
tampered tarball (one whose bytes do not hash to the SHA-512 the
packument advertised) produces a `502 Bad Gateway` response, a
`ChecksumMismatch` event with `algorithm: Sha512` on the
repository stream, and **never reaches local CAS**.

---

## 2. Why SHA-1 `dist.shasum` is not a fallback

Modern npm packuments carry both `dist.integrity` (SHA-512 SRI,
published by `registry.npmjs.org` since 2017) and `dist.shasum`
(SHA-1 hex, the legacy field). hort reads only
`dist.integrity` and rejects packages whose packument does not
publish one — there is no soft fallback to `dist.shasum`.

SHA-1 has been collision-broken since 2017 (SHAttered). Admitting
SHA-1 fallback would let an attacker who can produce a SHA-1
collision substitute a different tarball under the legitimate
metadata while preserving the published `dist.shasum`; the proxy
would cache the colliding bytes and serve them to every subsequent
client. That defeats the supply-chain integrity guarantee the
verified-pull-through framework exists to provide.

---

## 3. Legacy packages without `dist.integrity` cannot be proxied

A small tail of pre-2017 packages on `registry.npmjs.org` may not
publish `dist.integrity` at all — only the legacy `dist.shasum`.
These packages cannot be served through a Proxy repo: pull-through
returns `502 Bad Gateway` with `X-Hort-Reason: upstream-metadata-malformed`,
the parse-error log mentions "publishes no dist.integrity (legacy
packument); SHA-1 dist.shasum fallback is not accepted", and no
bytes are cached.

Operator workaround: download the tarball out-of-band, verify it
out-of-band (sigstore signature, vendor-published SHA-256, the
publisher's own attestation), then upload directly via
`npm publish --registry http://hort.example.com/npm/<hosted-repo>/`
to a Hosted (not Proxy) npm repo. The Hosted publish path stores the
tarball under a client-supplied content shape and does not depend on
`dist.integrity`. The Proxy path will continue to 502 for that
package — that is the intentional contract, not a bug.

---

## 4. Scoped package URL handling

npm scoped names (`@scope/name`, e.g. `@types/node`) URL-encode the
`/` separator between scope and name as **lowercase `%2f`** in the
metadata fetch path; the `@` is **not** encoded. Other characters
(lowercase letters, digits, `-`, `_`, `.`) are passed through
verbatim. The encoding is pinned to lowercase `%2f` to match the npm
registry convention; an upstream that requires uppercase `%2F`
breaks the contract.

The fetch path hort sends to the upstream looks like:

```
GET https://registry.npmjs.org/@types%2fnode
```

The route through hort preserves this end-to-end:
`npm install @types/node` against a Proxy repo just works. The
client-facing route `/npm/<repo-key>/@<scope>/<name>` is captured by
the scoped-route extractor, decoded into the canonical
`@scope/name` form, and re-encoded into the upstream `%2f` form by
the orchestrator before the metadata fetch leg.

---

## 5. Declare a Remote npm repository

Two YAML files under `$HORT_CONFIG_DIR`. The first declares the
repository, the second declares its upstream mapping.

### 5a. `repositories/npm-public.yaml`

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-public
spec:
  name: "npm Public Mirror"
  description: "Pull-through cache for the public npmjs.org registry."
  format: npm
  type: proxy
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/npm-public
  proxy:
    upstreamUrl: https://registry.npmjs.org
  isPublic: true
  replicationPriority: local_only
```

`metadata.name` is the repository key — the `<repo-key>` segment in
every URL `npm` will hit. It must match `^[a-z][a-z0-9-]{0,62}$`.

The `proxy:` block is required by the gitops validator for
`type: proxy` repositories. The actual upstream-mapping row that
the tarball orchestrator resolves at request time is defined by the
separate `UpstreamMapping` resource below; the two `upstreamUrl`
values must agree.

### 5b. `upstreams/npm-public.yaml`

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: npm-public
spec:
  repository: npm-public
  pathPrefix: ""
  upstreamUrl: https://registry.npmjs.org
  auth:
    type: anonymous
```

`spec.repository` references the `metadata.name` of the repository
above. npm uses a single catch-all upstream per repository, so
`pathPrefix` is the empty string. `auth.type: anonymous` is correct
for `registry.npmjs.org` and most public mirrors; for a private
mirror that requires credentials, use `basic` and reference a
secret via [`wire-secrets.md`](wire-secrets.md). The credentialed
pull-through path itself is gated on the gitops-mapping-writer
follow-on — see [`declare-gitops-config.md`](declare-gitops-config.md)
§6.

Restart `hort-server` to apply. There is no live-reload;
[`declare-gitops-config.md`](declare-gitops-config.md) §5 covers the
boot sequence.

---

## 6. Point `npm` at the proxy

Per-project `.npmrc`:

```ini
registry=http://hort.example.com/npm/npm-public/
```

Or one-shot via the CLI:

```
npm install --registry http://hort.example.com/npm/npm-public/ express
```

- `registry=` points at the npm route prefix. `npm` requests
  `GET /npm/npm-public/express` for the packument; the proxy
  fetches the upstream packument, rewrites every
  `versions[*].dist.tarball` URL to point back at this
  `/npm/npm-public/...` prefix, and caches the rewritten body in an
  `EphemeralStore`-backed packument cache so subsequent packument
  reads avoid the upstream round-trip.
- The first tarball download triggers verified pull-through: the
  orchestrator resolves the cached (or freshly-fetched) packument,
  parses `versions[ver].dist.integrity` for the requested version,
  decodes the `sha512-<base64>` SRI into a 64-byte digest, validates
  that the upstream `dist.tarball` basename matches the requested
  filename, fetches the tarball via the original upstream URL, and
  streams bytes through SHA-512 verification into local CAS.
- Subsequent downloads of the same tarball are served from CAS
  without re-fetching upstream.
- **Concurrent cache-miss requests are coalesced.**
  Both the packument fetch and the tarball fetch run through
  `PullDedup`'s two-layer service: in-process across handler
  invocations on the same replica (DashMap + `tokio::broadcast`) and
  cluster-wide via the `EphemeralStore`-backed `pulldedup:` keyspace.
  N parallel `npm install`s for the same uncached package produce
  ≤ 1 upstream packument request and ≤ 1 upstream tarball request.
  Upstream `404`, `5xx`, `429`, and timeout outcomes coalesce into
  the same short-cached response for every follower — a single rate-
  limit burst against `registry.npmjs.org` produces one upstream
  request and N short-cached `502 Bad Gateway` responses, not N
  retries. The follower-cache TTLs are tunable via
  `HORT_PULL_DEDUP_TTL_*` env vars; see
  [`deploy/values-reference.md`](deploy/values-reference.md). Single-
  replica deployments get coalescing for free via the in-memory
  `EphemeralStore`.

For scoped names, the encoding described in §4 happens
transparently — `npm install @types/node` against the proxy works
without any client-side configuration beyond the `registry=` line.

---

## 7. Diagnose `502 Bad Gateway` from the proxy

Four verification failure modes surface as `502`, distinguished by
the `X-Hort-Reason` response header.

### `X-Hort-Reason: upstream-checksum-mismatch`

The bytes the upstream served did not hash to the SHA-512 the
packument's `dist.integrity` advertised. Causes: the upstream
mirror is compromised or serving stale content from a poisoned
cache; a transparent proxy on the network path is rewriting bodies;
or — rarely — a withdraw-republish race upstream.

Check `hort-server` logs for the `npm upstream checksum mismatch`
warn at WARN level. The event carries `format=npm`,
`repository_id=<uuid>`, and `algorithm=sha512`; correlate it with
the corresponding `ChecksumMismatch` event on the
`repository:<repo_id>` stream in the audit log. Validate the
upstream URL in `upstreams/npm-public.yaml` and the network path.
Re-running `npm install` will not recover — the proxy refuses to
cache bad bytes by design. The fix is upstream.

### `X-Hort-Reason: upstream-metadata-malformed`

The upstream packument body was unparseable, the requested version
is not present in `versions[]`, the version entry has no
`dist.integrity`, or the `dist.integrity` SRI string contains no
sha512 entry / is malformed base64 / decodes to the wrong length.
The same `X-Hort-Reason` also covers `dist.tarball` extraction
failures (missing field, non-`https://` scheme).

The most common causes are: a legacy package that publishes only
`dist.shasum` (see §3 — switch to direct upload to a Hosted repo);
a withdraw-republish race where `npm` saw the version in the
packument but the upstream removed it before the file fetch; or a
non-compliant mirror that strips `dist.integrity`.

Check `hort-server` logs for `npm upstream packument checksum parse failed`
or `npm upstream tarball URL extraction failed` at WARN level — the
warn carries the parse-error detail (e.g. "publishes no
dist.integrity", "no sha512 entry", "32 bytes, expected 64",
"non-https tarball URL").

### `X-Hort-Reason: upstream-filename-mismatch`

The npm-specific defence-in-depth check fired: the basename of the
upstream `dist.tarball` URL does not equal the filename the client
asked for. The client requested `foo-1.0.0.tgz`; the upstream
packument's `dist.tarball` ended in `bar-2.0.0.tgz`. This is treated
as upstream tampering — an upstream substituting a different
tarball under legitimate metadata — and the orchestrator refuses
the fetch before any byte is downloaded.

Check `hort-server` logs for `npm upstream tarball filename does not match request filename; refusing to fetch`
at WARN level. The warn carries the expected and actual basenames.
This is a strong signal of upstream compromise; investigate the
upstream registry, not the proxy.

### `X-Hort-Reason: upstream-unavailable`

The upstream packument or tarball fetch failed at the transport
level — network timeout, connection refused, upstream 5xx, DNS
failure. Distinct from the verification failures above: these are
recoverable. Check the upstream's status page; retry the
`npm install`.

Check `hort-server` logs for `npm upstream packument fetch failed`
(metadata leg) or `npm upstream tarball fetch failed` (tarball
leg) at WARN level. Both carry the underlying transport error in
the `cause` field.

---

For all four modes, the metric
`hort_upstream_checksum_total{format="npm", result="mismatch"}` ticks
on every detected tampering — alerting on a non-zero rate is
recommended. The success path ticks
`hort_upstream_checksum_total{format="npm", result="verified"}` on
every cache miss that successfully verifies.

---

## 8. Diagnose a `503` — a version hort is holding

A `502` means verification rejected something. A **`503` means the
opposite**: the bytes verified, hort has them, and it is deliberately
not serving them yet.

### What you will see

A pinned install — `npm ci` against a `package-lock.json`, or
`npm install pkg@7.29.7` — fails hard:

```
npm error 503 Service Unavailable - GET http://hort.example.com/npm/npm-public/pkg/-/pkg-7.29.7.tgz
```

The response carries a `Retry-After` header in seconds and the body
`{"error":"artifact is quarantined"}`.

**This is intended.** The version is inside its scan observation window
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)):
hort ingested and checksum-verified it, has not finished deciding
whether it is safe, and fails closed rather than serving unvetted bytes.
A lockfile names an exact version, so there is nothing for the client to
fall back to — the install fails rather than silently resolving
something else. A *non-pinned* install of the same package succeeds
against a different version, because the served index never offers a
held one (see §8.3).

### 8.1. Tell "held" apart from "does not exist"

Two different problems produce a failed install, and they are
distinguished by the response code on the **tarball** route:

| You asked for | hort answers | Means |
|---|---|---|
| a held version's tarball | `503` + `Retry-After` | hort has it; the observation window has not elapsed |
| a rejected version's tarball | `403` | hort has it and a scan verdict went against it — permanent |
| a version nothing published | `404` | hort has never seen it, and neither has the upstream it proxies |

The **packument** answers the same question without guessing a tarball
URL. `GET /npm/<repo-key>/<pkg>` carries an additional top-level `hort`
block listing every version the served index is withholding, and why:

```json
{
  "name": "pkg",
  "versions": { "…only the versions hort will serve…" },
  "dist-tags": { "latest": "7.29.6" },
  "hort": {
    "held": [
      { "version": "7.29.7", "status": "quarantined",
        "available_after": "2026-08-26T08:18:00Z" }
    ]
  }
}
```

- `status: quarantined` — a timed hold. It resolves on its own.
- `status: rejected` — a scan verdict went against the version. It is
  not waiting for anything and carries no `available_after`; only an
  operator decision (see
  [`curator-workflow.md`](curator-workflow.md)) changes it.
- `status: scan_indeterminate` — the scanner could not decide, and hort
  fails closed. Also terminal, also no `available_after`.
- `available_after` is the instant the hold lifts, computed from the
  same window the tarball route's `Retry-After` counts down to. It is
  **omitted** when hort cannot compute it (no recorded window anchor, or
  a `type: virtual` repository, which holds no artifact rows of its own
  and aggregates its members' — query the member repository directly for
  the deadline). An absent field means "not known", never "no deadline".

The `hort` key is **absent entirely** when nothing is held, so a
packument that carries no `hort` block is one where every version hort
knows about is servable.

A version that appears in **neither** `versions{}` nor `hort.held` is
one hort holds nothing for: on a Proxy repo under the default
`indexMode: releasedOnly` that is an upstream version hort has not
pulled through yet (requesting it pulls it normally), and otherwise it
is a version that was never published.

### 8.2. Wait, or release it

The condition is temporary. Options, in order of preference:

1. **Wait** until `available_after` and re-run the install. The window
   is `quarantineDuration` on the active `ScanPolicy`.
2. **Release it early**, if the scan has completed and you accept the
   findings — the curator flow in
   [`curator-workflow.md`](curator-workflow.md).
3. **Shorten the window** for the repository via its `ScanPolicy`. This
   weakens the guarantee for every consumer of that repository, not just
   the blocked one; prefer 1 or 2.

Re-running `npm ci` before the window elapses returns the same `503`.

### 8.3. Why the held version is not in `versions{}`

The served index lists only versions hort holds in a servable status, so
that a range (`^7.29.0`), a bare `npm install pkg`, or `latest` can
never resolve to a version that would `503`. That property protects
every consumer of the repository, and it is why the hold costs only the
pinned installs rather than all of them.

It says nothing about whether the catalog may *explain* a version's
absence — which is exactly what the `hort.held` block does. The block
lives outside the resolution surface: `versions{}` and `dist-tags` are
byte-identical to what they would be without it, and the
`GET /npm/<repo>/<pkg>/<version-or-tag>` route resolves through the same
filtered set, so a held version stays unresolvable there too. Nothing in
the block makes a held version reachable; it only stops the catalog
being silent about one.

---

## 9. What is NOT covered

A few related concerns are deliberately out of scope for the npm
verified-pull-through path. Recorded here so operators do not
expect them as configuration knobs:

- **npm package signature verification.** npm's package signing
  scheme (`npm publish --provenance`, sigstore attestations) is not
  yet widely deployed and is treated as a separate trust layer.
  Upstream verification covers content-hash verification only;
  npm signature verification is deferred.
- **Per-repository TTL tunability for the packument cache.** The
  freshness window (60 s) and stale-while-revalidate window (1 h)
  are hardcoded. There is no `cargo_index_*_ttl_secs`-style override
  on `Repository` today. Promoting them to typed `Repository` fields
  is gated on operator demand.
- **Replicating `ChecksumVerified` events to mesh peers.** When a
  cluster member verifies an upstream tarball, the resulting
  `ChecksumVerified` event lives only on the local artifact stream;
  peer members re-verify on their own first fetch. End-to-end mesh
  replication of verification events depends on `ReplicationPort`
  and is out of scope until that lands.

---

## 10. See also

- [ADR 0006 — mandatory upstream verification](../../adr/0006-mandatory-upstream-verification.md)
  — architectural rationale and the type-system invariants for the
  cross-format framework.
- [`pypi-pull-through.md`](pypi-pull-through.md) — sibling format
  that verifies upstream tarballs with SHA-256 instead of SHA-512.
- [Format handlers § "Upstream verification"](../explanation/format-handlers.md#upstream-verification)
  — how per-format trait methods compose into the verification
  cases.
- [`declare-gitops-config.md`](declare-gitops-config.md) — the
  `$HORT_CONFIG_DIR` model and YAML envelope shape.
- [`wire-secrets.md`](wire-secrets.md) — credentials for private
  upstream mirrors.
