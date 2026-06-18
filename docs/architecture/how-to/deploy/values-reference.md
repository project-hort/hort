# `hort-server` Helm chart — values reference

Per-key reference for `deploy/helm/hort-server/values.yaml`. For the
install path see [`install.md`](./install.md); for edge-shape choices
see `examples-overlays.md`; for the security
posture see `security-hardening-checklist.md`.

The chart's `values.yaml` carries inline doc-comments above every
top-level key. Those comments are short pointers; the canonical
rationale for every `HORT_*` env var lives in
[`crates/hort-server/src/config.rs`](../../../../crates/hort-server/src/config.rs).
Where this document and `config.rs` disagree, **`config.rs` wins** and
this document is the bug.

For the **binary-level** surface this chart renders into — every
`hort-server` / `hort-worker` env var and CLI subcommand with its default,
required-ness, and startup interlocks — see the
[server & worker configuration reference](../../reference/server-and-worker-configuration.md).
This document maps a subset of those env vars to Helm values; the
reference is the complete list.

`scripts/check-values-comments.sh` (wired into CI)
asserts every top-level key in `values.yaml` has a comment
block above it. [`values.schema.json`](../../../../deploy/helm/hort-server/values.schema.json)
enforces required-vs-optional and cross-field invariants at
`helm install` time (eight cross-field rules).

**The schema is strict** (see
[ADR 0029](../../../adr/0029-operator-config-hard-rename.md)):
`additionalProperties: false` is set on the top-level object **and every
nested object block the chart owns the shape of**, so an unknown,
mistyped, or **retired** key fails `helm install`/`helm template` with a
clear `Additional property <key> is not allowed` error instead of being
silently accepted and ignored. A typo like `worker.scanner.osvv`, a
retired key like `apiBindAddr` / `worker.scanner.osvScanner` /
`http.ociUploadTimeoutSeconds`, or a top-level `replicaCountt` is caught
at install time, not discovered at runtime when the intended setting
turns out to have had no effect. Free-form passthrough blocks the
operator owns the shape of (`resources`, `probes.*`, `affinity`,
`nodeSelector`, the `*SecurityContext` blocks, `gitopsConfig`, and the
verbatim Kubernetes array entries such as `extraEnv` / `extraVolumes` /
`networkPolicy.ingress`) stay permissive by design — the strict lint
guards the chart's **own** config keys, not arbitrary pod-spec content.

---

## 1. Security-relevant values mapping

The security hardening controls introduced knobs the chart exposes as
values keys. The table below cross-walks each env var to its values key,
chart default, and binary default; see
[`security-hardening-checklist.md`](./security-hardening-checklist.md)
for the full rationale behind each control.

| control | env var(s) | values key | chart default | binary default |
|---|---|---|---|---|
| Auth provider | `HORT_AUTH_PROVIDER` | `auth.provider` | `oidc` | `disabled` (see caveat) |
| Request timeout | `HORT_HTTP_REQUEST_TIMEOUT_SECS` | `http.requestTimeoutSeconds` | `300` | `300` |
| Header-read timeout | `HORT_HTTP_HEADER_READ_TIMEOUT_SECS` | `http.headerReadTimeoutSeconds` | `15` | `15` |
| OCI upload timeout | `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` | `oci.uploadTimeoutSeconds` | `3600` | `3600` |
| Metrics auth | `HORT_METRICS_REQUIRE_AUTH` | `metrics.requireAuth` | `true` | `true` |
| Metrics bind | `HORT_METRICS_BIND` | `metrics.bindAddr` | `127.0.0.1:9090` | unset |
| Metrics unspecified-bind guard | `HORT_METRICS_PUBLIC_BIND` | `metrics.allowUnspecifiedBind` | `false` | `false` |
| Two-role Postgres | `HORT_DATABASE_URL` (split by role; chart injects this canonical name, binary falls back to bare `DATABASE_URL`) | `postgres.app.existingSecret` + `postgres.admin.existingSecret` | (required) | (no default) |
| Concurrency cap | `HORT_MAX_INFLIGHT` | `http.maxInflight` | `0` (binary default) | `512` |
| Per-IP concurrency cap | `HORT_MAX_INFLIGHT_PER_IP` | `http.maxInflightPerIp` | `0` (binary default) | `32` |
| API bind | `HORT_API_BIND` | `api.bindAddr` | `0.0.0.0:8080` | `127.0.0.1:8080` |
| Require HTTPS | `HORT_REQUIRE_HTTPS` | `requireHttps` | `true` | `false` |
| Public base URL | `HORT_PUBLIC_BASE_URL` | `publicBaseUrl` | (required) | (no default) |
| Secret file root | `HORT_SECRETS_FILE_ROOT` | `secrets.fileRoot` | `/etc/hort-server/secrets` | (none) |
| Graceful shutdown | `HORT_SHUTDOWN_GRACE_SECS` | `shutdown.gracefulSeconds` | `60` | `60` |
| OCI upload-session cap | `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL` | `oci.maxSessionsPerPrincipal` | `0` (binary default) | `32` |

Four caveats:

- `HORT_AUTH_PROVIDER` has a **binary default of `disabled`** (valid
  values: `disabled` | `oidc`). It is not a required env var. What the
  "(required)" intent in earlier revisions of this table tried to
  convey is the *runtime startup interlock*: `hort-server serve` refuses
  to boot with auth disabled **unless** `HORT_NATIVE_TOKENS_ENABLED=true`
  (there must be at least one inbound auth surface). The
  local-admin-row identity path is removed, so the prior
  `UserRepository::has_local_admin` escape no longer exists — the
  native-token validator is now the only alternative inbound surface.
  The chart sets `oidc`, so a chart-driven deployment never hits the
  disabled path. There is no `basic` provider value.
- `HORT_TRUSTED_PROXY_CIDRS` is
  exposed as `trustedProxyCidrs`. It predates the HTTPS hardening, which
  made it a
  precondition for `HORT_REQUIRE_HTTPS=true` to start without an
  `https://` `publicBaseUrl`.
- `HORT_OCI_LEGACY_CATALOG_ENABLED` (`oci.legacyCatalogEnabled`) is not
  an audit-driven knob — it is exposed for operators consuming the
  aggregating catalog endpoint.
- `HORT_EPHEMERAL_STORE_BACKEND` (`ephemeralStore.backend`)
  is a hard precondition for HA —
  `values.schema.json` Rule 8a blocks the multi-replica + memory
  combination.

---

## 2. Per-upstream mTLS surface

`repository_upstream_mappings` carries four columns
for per-upstream TLS posture: `mtls_cert_ref`, `mtls_key_ref`,
`ca_bundle_ref`, `pinned_cert_sha256`. Each is a `SecretPort` ID
resolved via the mounted-file secret adapter at fetch time.

The chart surface is two values keys:

- `secrets.fileRoot` — containment root the
  `MountedFileSecretAdapter` enforces. Anything resolved outside this
  root is rejected (symlink-escape protection,
  symlink-escape protection).
- `secrets.mounts` — operator-supplied projections of
  `Secret.data[<key>]` to a file under `secrets.fileRoot`. mTLS cert,
  mTLS key, CA bundle, and (when pinned) the pinned-SHA file all live
  here.

The full plumbing — gitops `ArtifactRepository` YAML through `Secret`
to mount to `RepositoryUpstreamMapping` row — lives in
[`wire-secrets.md`](../wire-secrets.md). This document only covers
the chart-side surface.

---

## 3. Per-key reference

Subsections follow `values.yaml` order. For each key:

- **Type** — JSON-schema-style type
- **Default** — what the chart ships
- **Required** — `yes` (chart fails install without it),
  `conditional` (depends on other values), or `no`
- **Description** — one-line; expanded only when the *why* is
  non-obvious
- **Example** — copy-pasteable override

### `image`

Container image reference. The chart does not enforce image signatures
itself; admission control (Kyverno / sigstore policy-controller /
Connaisseur) verifies against `image.cosign.publicKey` if set.

> **`image.repository` and `worker.image.repository` are placeholder
> defaults** (`hort/hort-server` / `hort/hort-worker`). They must be
> overridden to the canonical registry paths for a real install:
> `ghcr.io/project-hort/hort-server` and
> `ghcr.io/project-hort/hort-worker`. Leaving the bare placeholders
> will fail with an image-pull error unless a local registry alias is
> configured.

| sub-key | type | default | required | notes |
|---|---|---|---|---|
| `image.repository` | string | `hort/hort-server` | yes | override at install time |
| `image.tag` | string | `""` | no | empty resolves to `.Chart.appVersion` |
| `image.pullPolicy` | enum | `IfNotPresent` | no | `Always` / `IfNotPresent` / `Never` |
| `image.pullSecrets` | list | `[]` | no | required for private registries |
| `image.cosign.publicKey` | PEM string | `""` | no | consumed by deploy-time policy controller |

Example:

```yaml
image:
  repository: registry.example.com/hort/hort-server
  tag: 2.0.0-rc.7
  pullSecrets: [{name: ghcr-pull}]
```

### `replicaCount`

- **Type:** integer (`>= 1`)
- **Default:** `1`
- **Required:** yes
- **Description:** Number of `hort-server` Deployment replicas.
  `replicaCount > 1` forces `storage.backend: s3` (RWO PVC cannot
  multi-attach) and `ephemeralStore.backend: redis` (the in-memory
  ephemeral store cannot share state across pods).
  `values.schema.json` Rules 8a + 8b block the inconsistent middle
  states.
- **Example:** `3`

### `publicBaseUrl`

- **Type:** string (matches `^https?://.+`)
- **Default:** `""` (chart fails install — schema rule 1)
- **Required:** yes
- **Description:** Canonical URL the operator's edge terminates as.
  Drives `Strict-Transport-Security` emission
  (HSTS only fires when this URL's scheme is `https`) and the OCI
  `WWW-Authenticate: Bearer realm=...` value.
- **Example:** `https://hort.example.com`
- **See also:** [`security-hardening-checklist.md`](./security-hardening-checklist.md) — HTTPS-only realm + upstream URL scheme, HSTS.

### `api.bindAddr`

- **Type:** string (non-empty)
- **Default:** `"0.0.0.0:8080"`
- **Required:** no
- **Description:** Maps to `HORT_API_BIND`. Bind address for the main
  API listener. Follows the `<subsystem>.bindAddr` shape shared by
  `metrics.bindAddr` and `control.bindAddr` (the prior
  top-level `apiBindAddr` key is retired; HARD rename, no
  alias — ADR 0029). The chart default (`0.0.0.0:8080`) diverges from
  the binary
  default (`127.0.0.1:8080`) deliberately because Kubernetes kubelet
  liveness / readiness probes require a non-loopback bind on most CNI
  setups. Use `127.0.0.1:8080` only when an in-pod sidecar proxies
  the binary; non-default ports (e.g. `0.0.0.0:9080`) work too,
  remember to raise `service.httpPort` to match.
- **Example:** `"127.0.0.1:8080"`
- **See also:** [`security-hardening-checklist.md`](./security-hardening-checklist.md) — HSTS + bind-default + `HORT_REQUIRE_HTTPS`.

### `requireHttps`

- **Type:** boolean
- **Default:** `true`
- **Required:** no
- **Description:** Maps to `HORT_REQUIRE_HTTPS`. When `true`, the binary
  refuses to start unless **either** `publicBaseUrl` is `https://...`
  **or** `trustedProxyCidrs` is non-empty (positive evidence of a
  TLS-terminating proxy in front). The AND-condition is deliberate:
  only the "neither pinned nor proxied" case fails. The chart default
  diverges from the binary default (`false`) on the principle that
  production charts ship with the security gate enabled.
- **Example:** `false`
- **See also:** [`security-hardening-checklist.md`](./security-hardening-checklist.md) — HSTS + bind-default + `HORT_REQUIRE_HTTPS`.

### `trustedProxyCidrs`

- **Type:** list of CIDR strings
- **Default:** `[]`
- **Required:** conditional — required when `requireHttps: true` and
  `publicBaseUrl` is `http://`
- **Description:** CIDRs whose socket peer the binary trusts to have
  set `X-Forwarded-*`. Scope this to **the address range of the
  ingress-controller / gateway pods themselves** — not the cluster pod
  network. An empty list means no peer is trusted and `X-Forwarded-*`
  is ignored regardless of source. A sentinel covers misconfiguration:
  if the peer is trusted **and** `X-Forwarded-For`
  is absent, `client_ip` becomes `0.0.0.0` and a throttled `WARN`
  fires — proxy misconfiguration is detectable in dashboards without
  conflating attribution onto the proxy.
- **Example:** `["10.244.3.0/24"]` — the ingress-controller's **own
  pod range** (e.g. the subnet the gateway Deployment's pods land in),
  *not* the cluster-wide pod CIDR. Find it with
  `kubectl -n <ingress-ns> get pods -l <ingress-selector> -o wide`
  and trust the narrowest CIDR that covers those pods (commonly a
  single node's pod range, or a dedicated gateway node pool). If your
  gateway is a `LoadBalancer`/external proxy rather than in-cluster,
  use that proxy's source range instead.

  > **Footgun — do not trust the whole pod CIDR.** `trustedProxyCidrs`
  > authorises a peer to *forge* `client_ip` via `X-Forwarded-For`.
  > Listing the cluster-wide pod network (e.g. a whole `/16`) means
  > **any pod in the cluster** — including a compromised or hostile
  > tenant workload — can spoof its source IP past rate-limiting,
  > fail2ban, and audit attribution. Scope the list to the
  > gateway/ingress pods — see the "Rightmost-untrusted `X-Forwarded-For`"
  > section in the [security hardening checklist](security-hardening-checklist.md)
  > for the matching operator action.
  >
  > **The edge proxy MUST actually set `X-Forwarded-For`.** Trusting a
  > peer does not synthesise the header. If a trusted peer reaches the
  > binary *without* `X-Forwarded-For` (proxy not configured to add it,
  > or it is stripped en route), `client_ip` degrades to the
  > `0.0.0.0` **sentinel** and a throttled `WARN` is logged — the
  > (`XFF_MISSING_SENTINEL` in
  > `crates/hort-http-core/src/middleware/trust.rs`). All callers through
  > that proxy then share the one sentinel bucket and per-client
  > attribution is lost until the proxy is fixed. Confirm your ingress
  > sets `X-Forwarded-For` (most controllers do by default; verify
  > after any custom `proxy_set_header` / header-rewrite config) and
  > watch for the `trusted peer with missing X-Forwarded-For` WARN.
- **See also:** [`security-hardening-checklist.md`](./security-hardening-checklist.md) — HSTS, rightmost-untrusted `X-Forwarded-For`.

### `auth`

Authentication configuration. Default is `oidc`; install fails (via
schema Rule 2) if `auth.oidc.issuerUrl` and `auth.oidc.audience` are
unset when `provider: oidc`. `disabled` is allowed but emits a
prominent post-install `NOTES.txt` warning.

| sub-key | type | default | required |
|---|---|---|---|
| `auth.provider` | `oidc` / `disabled` | `oidc` | yes |
| `auth.oidc.issuerUrl` | string | `""` | yes when `provider: oidc` |
| `auth.oidc.audience` | string | `""` | yes when `provider: oidc` |
| `auth.oidc.groupsClaim` | string | `groups` | no |
| `auth.oidc.jwksCacheTtlSeconds` | integer | `600` | no (maps to `HORT_JWKS_CACHE_TTL_SECS`) |
| `auth.tokenExchange.enabled` | boolean | `false` | no |
| `auth.tokenExchange.cliClientId` | string | `""` | yes when `tokenExchange.enabled: true` |
| `auth.nativeTokens.enabled` | boolean | `false` | no |
| `auth.nativeTokens.signingKey.existingSecret` | string | `""` | yes when `nativeTokens.enabled: true` |
| `auth.nativeTokens.signingKey.secretKey` | string | `hort-oci-token-signing-key.pem` | no |
| `auth.nativeTokens.signingKey.prevExistingSecret` | string | `""` | no (rotation window) |
| `auth.nativeTokens.signingKey.prevSecretKey` | string | `hort-oci-token-signing-key-prev.pem` | no |

`disabled` is fail-closed in OCI (no synthetic
admin), so the binary is safe; but a chart that defaults `disabled` is
publishing the configuration the security audit worked hardest to
close. Operators wanting a no-IdP eval path use
`deploy/compose/docker-compose.yml` (which bundles Keycloak), not
`helm install`.

The `auth.oidc.jwksCacheTtlSeconds` value still carries that name in the
chart, but it now maps to the renamed `HORT_JWKS_CACHE_TTL_SECS` env var
(the JWKS client tunables are unified under the
`HORT_JWKS_*` prefix with `_SECS` durations — ADR 0029; the chart key is
unchanged).

`auth.tokenExchange.*` gates `POST /api/v1/auth/exchange` (RFC 8693) and
the anonymous discovery doc at `GET /.well-known/hort-client-config`
(`HORT_TOKEN_EXCHANGE_ENABLED`). It **requires**
`auth.nativeTokens.enabled: true` — the schema install-block rule and the
binary boot gate (`ConfigError::TokenExchangeRequiresNativeTokens`) both
enforce the coupling. `auth.nativeTokens.*`
(`HORT_NATIVE_TOKENS_ENABLED`)
gates the `hort_(pat|svc|cli)_*` PAT validator and the OCI `/v2/auth`
JWT-minting path; when enabled it requires the
`signingKey.existingSecret` ed25519 OCI token-signing key.

The prior `auth.basic` block
and `auth.lockout` block are removed (the `HORT_AUTH_LOCKOUT_*` env
vars powered the
now-deleted `authenticate_local` HTTP-Basic-against-local-admin-row
path — see `docs/auth-catalog.md` Entry 8). The PAT-side bearer-path
brute-force protection
(`HORT_PAT_LOCKOUT_*`, distinct mechanism inside `PatValidationUseCase`)
is unchanged. A values file with `auth.provider: basic`, an `auth.basic`
block, or an `auth.lockout` block is rejected by the strict
`values.schema.json` at install/upgrade time.

Example:

```yaml
auth:
  provider: oidc
  oidc:
    issuerUrl: https://keycloak.example.com/realms/hort
    audience: hort-server
    groupsClaim: realm_access.roles
```

### `http`

HTTP transport tunables — connection-level timeouts and per-router
load-shed limits. See
[`http-transport-timeouts.md`](../http-transport-timeouts.md) for
operator-level depth on the timeout knobs.

| sub-key | type | default | required |
|---|---|---|---|
| `http.requestTimeoutSeconds` | integer | `300` | no |
| `http.headerReadTimeoutSeconds` | integer | `15` | no |
| `http.maxInflight` | integer | `0` (binary default `512`) | no |
| `http.maxInflightPerIp` | integer | `0` (binary default `32`) | no |
| `http.publishBodyMaxSize` | size string | `""` (binary default `300Mi`) | no |

`headerReadTimeoutSeconds` closes Slowloris-style attacks at the
connection layer. The OCI blob-upload per-route deadline lives
under [`oci.uploadTimeoutSeconds`](#oci) (grouped
with the other OCI surfaces; it still maps to
`HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`).

Beyond `maxInflight`, the load-shed layer returns `503` with no body
and emits `hort_http_responses_total{result="shed"}`.

Override `publishBodyMaxSize` only when publishing artifacts above
300 MiB. It is a human-readable size string (e.g. `"512Mi"`, `"1Gi"`);
an empty string leaves it unset (binary default), and an explicit
`"0"` is the refuse-all-publishes kill-switch. The env var is the
size-string `HORT_PUBLISH_BODY_MAX_SIZE` — a size string (not a
bare integer) so a multi-GiB value cannot round-trip through Helm's
float64 coercion into scientific notation (a known boot-crash class;
ADR 0029).

### `upstream`

Streaming-fetch storage backstops on the pull-through path (the
streaming-metadata contract,
[ADR 0026](../../../adr/0026-streaming-metadata-projection.md)).
Each cap bounds the per-fetch on-disk write; a trip
emits a structured `502` with `bytes_read` + `cap` and the
`result=<metadata|manifest|version_object>_too_large` metric label.

| sub-key | type | default | required |
|---|---|---|---|
| `upstream.metadataCacheMaxSize` | size string | `64Mi` | no |
| `upstream.manifestCacheMaxSize` | size string | `16Mi` | no |
| `upstream.projectorVersionObjectMaxSize` | size string | `2Mi` | no |

All three are **human-readable size strings** (`64Mi`, `1Gi`, `512Ki`,
decimal `64M`, or a bare byte integer — quote them), not integers, for
the same float64-coercion reason as `http.publishBodyMaxSize`
(ADR 0029). They map to
`HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`,
`HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`, and
`HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`. `metadataCacheMaxSize`
caps the streamed `fetch_metadata` write (npm packument, PyPI JSON,
Cargo sparse-index — largest known packument `@types/node` ~50 MiB, so
`64Mi` gives ~28% headroom); `manifestCacheMaxSize` caps the OCI
manifest / index / attached-signature streamed write;
`projectorVersionObjectMaxSize` caps a single version object inside the
streaming JSON projector.

### `metrics`

Prometheus scrape configuration.

| sub-key | type | default | required |
|---|---|---|---|
| `metrics.bindAddr` | string (host:port) | `127.0.0.1:9090` | no |
| `metrics.allowUnspecifiedBind` | boolean | `false` | no |
| `metrics.requireAuth` | boolean | `true` | no |
| `metrics.serviceMonitor.enabled` | boolean | `false` | no |
| `metrics.serviceMonitor.interval` | duration | `30s` | no |
| `metrics.serviceMonitor.scrapeTimeout` | duration | `10s` | no |
| `metrics.serviceMonitor.namespace` | string | `""` (release ns) | no |

`/metrics` is always served by the binary. `bindAddr` controls where:

- **`bindAddr: "127.0.0.1:9090"` (default)** — dedicated listener
  bound to the pod's loopback. The main `8080` router carries no
  `/metrics` route. Container + Service ports for `metricsPort` are
  exposed; sidecar-scrape pattern.
- **`bindAddr: "0.0.0.0:9090"`** — dedicated listener on all
  interfaces. Requires `allowUnspecifiedBind: true` (the
  unspecified-bind guard); the binary refuses to start without the explicit
  opt-in. Operators take responsibility for restricting reach via
  NetworkPolicy / firewall.
- **`bindAddr: ""`** — no separate listener. `/metrics` mounts on
  the main `8080` router under `requireAuth`. Metrics container +
  Service ports are skipped. Useful for dev / single-port deploys.

`requireAuth: true` (the default) requires admin authentication on
the `/metrics` endpoint regardless of which listener serves it.
Setting `false` re-permits anonymous scraping for legacy deployments
and emits a startup `WARN` plus a prominent NOTES.txt post-install
warning.

`serviceMonitor.enabled: true` requires the Prometheus Operator CRDs
(`monitoring.coreos.com/v1`) installed in the cluster, AND
`bindAddr` to be non-empty (the ServiceMonitor scrapes the dedicated
metrics Service port). The chart fails `helm template` / `helm
install` with an explicit message if these conditions are not met.

### `control`

Internal-only control-plane listener. Moves
the `/admin` API, `/api/v1/admin/*`, and `/api/v1/subscriptions`
management routes onto a dedicated pod-internal listener so a
NetworkPolicy can restrict them to the operator network. Mirrors
`metrics.bindAddr` exactly. See
[`control-plane-tiers.md`](./control-plane-tiers.md).

| sub-key | type | default | required |
|---|---|---|---|
| `control.bindAddr` | string (host:port) | `""` | no |
| `control.allowUnspecifiedBind` | boolean | `false` | no |

`control.bindAddr` maps to `HORT_CONTROL_BIND`. Empty (default) keeps the
control routes on the main `8080` router — byte-identical to the
no-split behaviour, no migration. Non-empty moves them onto a dedicated
listener
and exposes `service.controlPort` (default `9443`). It follows the
`<subsystem>.bindAddr` shape shared by `api.bindAddr` and
`metrics.bindAddr`. `control.allowUnspecifiedBind`
maps to `HORT_CONTROL_PUBLIC_BIND` — required to bind `0.0.0.0`/`::`
(the same 0.0.0.0 footgun guard the metrics listener carries). The
token-generation and artifact-pull planes are **never** moved here — they
are public by requirement.

### `oci`

| sub-key | type | default | required |
|---|---|---|---|
| `oci.uploadTimeoutSeconds` | integer | `3600` | no |
| `oci.legacyCatalogEnabled` | boolean | `false` | no |
| `oci.maxSessionsPerPrincipal` | integer | `0` (binary default `32`) | no |

`uploadTimeoutSeconds` maps to `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` and
is applied as a per-route override on
`PATCH /v2/.../blobs/uploads/<uuid>` and the corresponding `PUT`. Raise
it (and `shutdown.gracefulSeconds` with it) when uploading
multi-gigabyte images on slow networks. This knob moved here
from the retired `http.ociUploadTimeoutSeconds` key (HARD rename,
no alias — ADR 0029; the env var is unchanged).

`legacyCatalogEnabled` opts in to the aggregating `/v2/_catalog`
endpoint — only enable if an external client explicitly needs it.

`maxSessionsPerPrincipal` caps `(repo_id, principal)` outstanding
upload sessions; beyond the cap, new session requests return
`429 Too Many Requests` and emit
`hort_oci_session_cap_rejections_total{repo, result}`.

### `shutdown`

| sub-key | type | default | required |
|---|---|---|---|
| `shutdown.gracefulSeconds` | integer | `60` | no |

Wraps `with_graceful_shutdown` in `tokio::time::timeout`. On timeout
the runtime aborts outstanding join handles and emits a `WARN`
carrying the in-flight count. Worst-case OCI long-tail uploads should
complete in under `oci.uploadTimeoutSeconds`; if you raised that,
raise this in tandem.

### `secrets`

Surface for the mounted-file `SecretPort` adapter. See
[`wire-secrets.md`](../wire-secrets.md) for the operator-side
walk-through.

| sub-key | type | default | required |
|---|---|---|---|
| `secrets.fileRoot` | absolute path | `/etc/hort-server/secrets` | no |
| `secrets.mounts` | list of `{name, secretName, key, path}` | `[]` | no |

`secrets.fileRoot` is the containment root for `secret_ref`
resolution; anything resolved outside this root is rejected
(symlink-escape protection). The adapter also requires file
mode `& 0o077 == 0`; it logs a `WARN` for the K8s-default
`0644` mode but does not refuse.

`secrets.mounts` projects one key from a Kubernetes Secret to a file
under `fileRoot`. Used for upstream-registry credentials and the
four per-upstream mTLS surface fields (`mtls_cert_ref`,
`mtls_key_ref`, `ca_bundle_ref`, `pinned_cert_sha256`).

Example:

```yaml
secrets:
  mounts:
    - name: dockerhub-password
      secretName: dockerhub-pull
      key: password
      path: upstream/dockerhub/password
    - name: ghcr-mtls-cert
      secretName: ghcr-mtls
      key: cert.pem
      path: upstream/ghcr/cert.pem
    - name: ghcr-mtls-key
      secretName: ghcr-mtls
      key: key.pem
      path: upstream/ghcr/key.pem
```

### `postgres`

External-only Postgres. Two roles:
`admin` (DDL) used by the migrations Job at install/upgrade time only,
`app` (DML) used by the runtime Deployment with `INSERT, SELECT` only
on `events`. Startup-time `has_table_privilege` probes refuse to start
if the runtime role retains `UPDATE` / `DELETE` / `TRUNCATE` /
`REFERENCES` on `events`. The chart does not bundle a Postgres
subchart; eval/dev users use `deploy/compose/docker-compose.yml`.

| sub-key | type | default | required |
|---|---|---|---|
| `postgres.app.existingSecret` | string | `""` | yes (schema rule 5) |
| `postgres.app.secretKey` | string | `DATABASE_URL` | no |
| `postgres.admin.existingSecret` | string | `""` | yes (schema rule 6) |
| `postgres.admin.secretKey` | string | `DATABASE_URL` | no |

Both `existingSecret` references point at Kubernetes Secrets in the
chart's namespace whose `secretKey` value is a full
`postgres://user:...@host:5432/db` DSN. The `admin` Secret is
**never** mounted on the runtime Deployment.

`secretKey` is the key **inside** the Secret (default `DATABASE_URL`),
independent of the container env-var name. The chart maps it to the env var
**`HORT_DATABASE_URL`** on every pod (server, worker, migrate Job, and the
DSN-direct CronJobs) — the canonical operator DSN var.
The binary still honors bare `DATABASE_URL` as a fallback (sqlx-cli / Tier-2
tests / 12-factor), so changing `secretKey` only changes the Secret's data-key,
not the env-var name the chart injects.

### `storage`

Artifact CAS backend.

| sub-key | type | default | required |
|---|---|---|---|
| `storage.backend` | `filesystem` / `s3` | `filesystem` | yes |
| `storage.filesystem.pvc.enabled` | boolean | `true` | no |
| `storage.filesystem.pvc.size` | quantity | `50Gi` | no |
| `storage.filesystem.pvc.storageClassName` | string | `""` (cluster default) | no |
| `storage.filesystem.pvc.accessMode` | string | `ReadWriteOnce` | no |
| `storage.s3.endpoint` | string | `""` | yes when `backend: s3` |
| `storage.s3.region` | string | `""` | yes when `backend: s3` |
| `storage.s3.bucket` | string | `""` | yes when `backend: s3` |
| `storage.s3.pathStyle` | boolean | `true` | no |
| `storage.s3.allowHttp` | boolean | `false` | no |
| `storage.s3.sseMode` | `""` / `bucket-default` / `sse256` / `sse-kms` | `""` | no |
| `storage.s3.sseKmsKeyArn` | string | `""` | yes when `sseMode: sse-kms` |
| `storage.s3.existingSecret` | string | `""` | yes when `backend: s3` |

`filesystem` uses an RWO PVC (single replica only). `s3` is required
when `replicaCount > 1` (RWO PVC cannot multi-attach; schema rule
8b).

`pathStyle: true` is required for MinIO / zot; AWS S3 supports both
virtual-hosted and path style.

`storage.s3.allowHttp` (`HORT_STORAGE_S3_ALLOW_HTTP`) opts in to plain
HTTP S3 endpoints (the `object_store` crate refuses HTTP by default);
the binary's validator rejects it on `https://` endpoints and on real
AWS S3. Acceptable on a trusted cluster network because the application
layer enforces integrity via SHA-256 CAS; never over the public
internet.

`storage.s3.sseMode` (`HORT_S3_SSE_MODE`) selects the server-side
encryption mode requested on puts: `""`/`bucket-default` send no opinion
(the bucket default applies; AWS S3 has applied SSE-S3 unconditionally
since 2023), `sse256` requests SSE-S3 (AES256), `sse-kms` requests
SSE-KMS. When `sse-kms`, `storage.s3.sseKmsKeyArn`
(`HORT_S3_SSE_KMS_KEY_ARN`) is required (the server refuses to start
otherwise) and the KMS key must grant the S3 service
`kms:Encrypt`/`kms:Decrypt`/`kms:GenerateDataKey*`.

`storage.s3.existingSecret` points at a Kubernetes Secret with keys
`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`.

### `ephemeralStore`

Ephemeral state backend (auth lockout counters, OCI session counts,
JWKS cache).

| sub-key | type | default | required |
|---|---|---|---|
| `ephemeralStore.backend` | `memory` / `redis` | `memory` | yes |
| `ephemeralStore.memory` | object | `{}` | no |
| `ephemeralStore.redis.url` | string | `""` | yes when `backend: redis` and `existingSecret` empty |
| `ephemeralStore.redis.existingSecret` | string | `""` | yes when `backend: redis` and `url` empty |
| `ephemeralStore.redis.secretKey` | string | `REDIS_URL` | no |
| `ephemeralStore.redis.evictableUrl` | string | `""` | no |
| `ephemeralStore.redis.evictableExistingSecret` | string | `""` | no |
| `ephemeralStore.redis.evictableSecretKey` | string | `REDIS_URL_EVICTABLE` | no |
| `ephemeralStore.redis.durableUrl` | string | `""` | no |
| `ephemeralStore.redis.durableExistingSecret` | string | `""` | no |
| `ephemeralStore.redis.durableSecretKey` | string | `REDIS_URL_DURABLE` | no |

Multi-pod deployments **must** use Redis — `memory` cannot share state
across pods. `values.schema.json` Rule 8a blocks `replicaCount > 1` +
`memory`. `redis.url` and `redis.existingSecret` are mutually
exclusive (schema rule 4).

The optional `evictable*` / `durable*` keys (per-class keyspace
routing) split Redis traffic onto dedicated instances: the **evictable**
class (`HORT_REDIS_URL_EVICTABLE` — Cargo/PyPI/npm caches, pull-through
dedup) and the **durable** class (`HORT_REDIS_URL_DURABLE` — auth lockout
flags, OCI session records, auth-event throttle). Each falls back to
`redis.url` when unset. Within a class, the plaintext `*Url` and the
`*ExistingSecret` indirection are mutually exclusive (schema rules 4b /
4c).

### Pull-through deduplication

Two-layer request coalescing covers every upstream
pull-through path (Cargo, npm, PyPI, OCI). The chart **does not yet
expose named values** for this feature; the binary reads five
`HORT_PULL_DEDUP_*` env vars. Set them via `extraEnv` until the chart
exposes named keys.

| env var | default | purpose |
|---|---|---|
| `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS` | `30` | Negative-cache TTL for upstream `404` responses. Followers see the same `404` for this window without re-querying upstream. |
| `HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS` | `10` | Short-cache TTL for upstream `5xx` and `429`. A single rate-limit burst against the upstream registry produces one upstream request and N short-cached `502 Bad Gateway` responses — set this conservatively to avoid amplifying transient upstream issues. |
| `HORT_PULL_DEDUP_TTL_TIMEOUT_SECS` | `10` | Short-cache TTL for upstream timeouts and network errors. Same rationale as `UNAVAILABLE`. |
| `HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS` | `60` | Short-cache TTL for upstream-checksum-mismatch outcomes. Longer than `UNAVAILABLE` because checksum mismatch is a content-integrity signal, not a transient transport issue — re-fetching immediately wastes bandwidth on the same poisoned upstream. |
| `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS` | `300` | Maximum wall-time a follower waits for the leader's fetch to complete (Layer B / cluster-wide path). On expiry, the follower returns `502 Bad Gateway` with a `leader-timeout` reason. Set higher than your slowest expected upstream fetch — defaults safe for OCI image-layer pulls under typical latency. |

Coalescing has no chart-level toggle: it is **always on** because
the in-memory `EphemeralStore` adapter is functionally identical to
Redis at this scale (sub-microsecond `put_if_absent`). Single-replica
deployments get coalescing for free.

The keyspace prefix is `pulldedup:`, registered as **Evictable** in
the `KEYSPACE_REGISTRY` — losing a coalescing record under
memory pressure converts at worst into a duplicate upstream fetch,
never into a correctness violation. If a sustained pull-burst
workload starts evicting longer-lived records (auth lockout, OCI
session caps), split the keyspace onto a dedicated Redis instance
via the per-class routing primitive (`HORT_REDIS_URL_EVICTABLE`).

Observable surface: `hort_pull_dedup_total{layer, format, outcome}`
counter and `hort_pull_dedup_wait_seconds{layer, format}` summary.
Both are emitted whether or not the chart values are set; full label
schema is in `docs/metrics-catalog.md`.

```yaml
extraEnv:
  - name: HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS
    value: "30"          # tighter rate-limit absorbing
  - name: HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS
    value: "120"         # smaller upstream — tighter follower bound
```

### `serviceAccount`

| sub-key | type | default | required |
|---|---|---|---|
| `serviceAccount.create` | boolean | `true` | no |
| `serviceAccount.name` | string | `""` (generated from chart fullname) | no |
| `serviceAccount.annotations` | map[string]string | `{}` | no |

`annotations` are used to attach EKS IAM-roles-for-ServiceAccounts or
GKE Workload Identity bindings.

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/hort-server
```

### `podSecurityContext` and `containerSecurityContext`

PSS-restricted defaults. The chart applies these unconditionally;
older clusters lacking PSS-restricted admission need overrides.

| sub-key | type | default |
|---|---|---|
| `podSecurityContext.runAsNonRoot` | boolean | `true` |
| `podSecurityContext.runAsUser` | integer | `65532` (distroless `nonroot`) |
| `podSecurityContext.runAsGroup` | integer | `65532` |
| `podSecurityContext.fsGroup` | integer | `65532` |
| `podSecurityContext.seccompProfile.type` | string | `RuntimeDefault` |
| `containerSecurityContext.allowPrivilegeEscalation` | boolean | `false` |
| `containerSecurityContext.readOnlyRootFilesystem` | boolean | `true` |
| `containerSecurityContext.capabilities.drop` | list | `[ALL]` |

The container image is built to run as UID
`65532`.

### `resources`

| sub-key | type | default |
|---|---|---|
| `resources.requests.cpu` | quantity | `250m` |
| `resources.requests.memory` | quantity | `256Mi` |
| `resources.limits.cpu` | quantity | `1000m` |
| `resources.limits.memory` | quantity | `1Gi` |

Defaults are sized for a single-replica light-traffic deployment; tune
up for production.

### `probes`

Wired to the binary's `/healthz` and `/readyz` endpoints.

| probe | path | initialDelay | period | timeout | failureThreshold |
|---|---|---|---|---|---|
| `liveness` | `/healthz` | `10` | `15` | `3` | `5` |
| `readiness` | `/readyz` | `5` | `5` | `2` | `3` |
| `startup` | `/healthz` | `0` | `5` | `2` | `60` (300 s budget) |

The 300 s startup budget (60 × 5 s) accommodates the worst-case cold
OIDC discovery + JWKS fetch on a slow network. The startup probe runs
first; liveness/readiness only take over once it succeeds.

### `podDisruptionBudget`

| sub-key | type | default | required |
|---|---|---|---|
| `podDisruptionBudget.enabled` | boolean | `false` | no |
| `podDisruptionBudget.minAvailable` | integer or percent | `1` | no |

When `replicaCount > 1`, the chart auto-renders a PDB regardless of
`enabled`. Set `enabled: true` to render at `replicaCount: 1` (rare;
typical single-replica deployments accept eviction).

### `networkPolicy`

| sub-key | type | default | required |
|---|---|---|---|
| `networkPolicy.enabled` | boolean | `true` | no |
| `networkPolicy.ingress` | list (NetworkPolicy ingress rules) | `[]` | no |
| `networkPolicy.egress` | list (NetworkPolicy egress rules) | `[]` | no |

**Default-on** (flipped from the previous default off). Set `networkPolicy.enabled: false` to opt out entirely (documented
escape hatch — e.g. a mesh `AuthorizationPolicy` already governs the
namespace). With it enabled, an **empty** `ingress` / `egress` list
renders a policy that selects the policyType with zero rules ⇒ stock
Kubernetes **denies all** traffic in that direction — the pod is
unreachable / cannot egress until you populate rules (there is no
implicit namespace baseline). Populate: public `8080` from the
artifact/token-gen clients, and — when `control.bindAddr` is set —
`service.controlPort` (9443) restricted to the operator namespace.
Egress: open to Postgres / S3 / Redis / OIDC issuer / upstream registries
plus the known webhook-forwarder set. A separate Job-scoped policy
auto-renders to grant the migrate/bootstrap Jobs DNS + egress.
See [`control-plane-tiers.md`](./control-plane-tiers.md) for a
worked three-tier example.

### `extraEnv` / `extraVolumes` / `extraVolumeMounts`

Escape hatches for any `HORT_*` knob the chart does not yet surface as
a top-level key, plus the Volume / VolumeMount pair for any sidecar
or extra mount. Use sparingly — prefer raising a chart issue when a
new knob is needed.

| key | type | default |
|---|---|---|
| `extraEnv` | list of `EnvVar` objects | `[]` |
| `extraVolumes` | list of `Volume` objects | `[]` |
| `extraVolumeMounts` | list of `VolumeMount` objects | `[]` |

Example:

```yaml
extraEnv:
  - name: HORT_RBAC_REFRESH_SECS
    value: "60"
```

### `nodeSelector` / `tolerations` / `affinity` / `topologySpreadConstraints`

Standard Kubernetes scheduling primitives, passed through to the
Deployment pod-spec verbatim.

| key | type | default |
|---|---|---|
| `nodeSelector` | map[string]string | `{}` |
| `tolerations` | list of `Toleration` objects | `[]` |
| `affinity` | `Affinity` object | `{}` |
| `topologySpreadConstraints` | list of `TopologySpreadConstraint` objects | `[]` |

When `replicaCount > 1`, consider adding a
`topology.kubernetes.io/zone` constraint so replicas spread across
availability zones.

### `service`

| sub-key | type | default |
|---|---|---|
| `service.type` | string | `ClusterIP` |
| `service.httpPort` | integer | `8080` |
| `service.metricsPort` | integer | `9090` |
| `service.controlPort` | integer | `9443` |
| `service.annotations` | map[string]string | `{}` |

`type: ClusterIP` is the only fully-tested type; `LoadBalancer` works
but the operator typically owns the edge via an Ingress / Gateway
resource (see `examples-overlays.md`). `service.controlPort` is the
container/Service port for the dedicated control-plane listener — only
exposed when `control.bindAddr` is non-empty (mirrors how `metricsPort`
is gated on `metrics.bindAddr`).

### `extraCaBundle`

Process-wide extra CA trust bundle
([ADR 0010](../../../adr/0010-tls-builder-no-insecure-knobs.md)).
Controls whether
the binary loads additional X.509 trust anchors at boot time for all
outbound TLS connections: upstream proxy requests, S3/MinIO storage,
and OIDC discovery and JWKS. See
[`extra-ca-bundle.md`](./extra-ca-bundle.md) for operator recipes.

| sub-key | type | default | required |
|---|---|---|---|
| `extraCaBundle.path` | string (absolute path in container) | `""` | conditional |
| `extraCaBundle.configMapName` | string (ConfigMap name) | `""` | conditional |
| `extraCaBundle.secretName` | string (Secret name) | `""` | conditional |

**Failure semantics (fail-closed):** If `path` is set but the file is
unreadable, malformed, or contains zero parseable certificates, the
binary refuses to start with a `ConfigError` (server) or a named fatal
that points at the missing mount (worker). A misconfigured trust knob
never silently degrades to untrusted-CA behaviour.

**Auto-mount sources.** `configMapName` and `secretName` are
mutually-exclusive auto-mount sources (a pod can mount only one `ca.crt`
at `path`); setting both fails the render at `helm install`. Either one,
when set, requires a non-empty `path` and makes the chart mount the
bundle read-only (0444) at `path` AND set `HORT_EXTRA_CA_BUNDLE` —
symmetrically on the `hort-server` Deployment, the `hort-worker`
Deployment, and the server-runtime CronJobs.

**Rendering states (mount/secret symmetry —
the chart never sets the env on a pod it did not mount the
bundle onto):**

- `path` + `configMapName` set — chart renders `HORT_EXTRA_CA_BUNDLE`,
  a `volumeMount` mapping `configMapName`'s `ca.crt` to `path`, and a
  ConfigMap `volumes` entry, **on server + worker + CronJobs**. Also
  renders the `checksum/extra-ca-bundle` Pod-template annotation.
- `path` + `secretName` set — identical, but the volume projects the
  **Secret** instead of a ConfigMap, and there is **no** checksum
  annotation (Secret-specific).
- `path` set, **neither** source set (fully-manual recipe) — chart
  renders **nothing** for the bundle (no env, no volume, no mount). The
  operator wires the env via `extraEnv` / `worker.extraEnv` AND the
  volume via `extraVolumes` / `extraVolumeMounts` (and `worker.*`),
  on both Deployments.
- `path` **unset** and no source — binary trusts only public CAs.

Example (Secret recipe):

```yaml
extraCaBundle:
  path: /etc/hort-server/ca-bundle/ca.crt
  secretName: corporate-ca-bundle-secret   # or configMapName: …
```

### `gitopsConfig`

- **Type:** map[string]string (relative file path → YAML content)
- **Default:** `{}`
- **Required:** no
- **Description:** Each entry becomes a key in the `hort-server-config`
  ConfigMap, mounted at `HORT_CONFIG_DIR` (`/etc/hort-server/config`) on
  both the runtime Deployment and the migrations Job.
  `ApplyConfigUseCase` handles an empty config dir cleanly. The
  complete shape — `ArtifactRepository`, `auth/oidc.yaml` group
  mappings, RBAC group bindings, etc. — is documented in
  [`declare-gitops-config.md`](../declare-gitops-config.md).

```yaml
gitopsConfig:
  "auth/oidc.yaml": |
    mappings:
      - claim: groups
        value: hort-admins
        role: admin
  "repos/ghcr-mirror.yaml": |
    apiVersion: project-hort.de/v1beta1
    kind: ArtifactRepository
    metadata:
      name: ghcr-mirror
    spec:
      format: oci
      type: proxy
      proxy:
        upstreamUrl: https://ghcr.io
```

### `scheduledTasks`

ALL periodic/scheduled tasks live under this one tree
(ADR 0029). Previously the set was split — five tasks at the top
level and the rest nested under `cronJobs.*` — leaking the execution-path
implementation detail into the config-tree *location*. That is
collapsed: every task is here, and each carries an `executionPath`
attribute
(`dsn-direct` | `admin-task`) recording how it is invoked. The prior
`cronJobs.*` block and the five top-level task keys are **retired (HARD
rename, no alias)** — the strict schema rejects them at
install.

Two execution paths:

- **`executionPath: dsn-direct`** — the CronJob runs a `hort-server`
  subcommand directly in its own pod with the runtime DSN only (no
  svc-token, no bootstrap Job). Gated **solely** by the task's own
  `enabled` — independent of the `adminTasksEnabled` umbrella. These keep
  their original defaults.
- **`executionPath: admin-task`** — the CronJob invokes
  `hort-cli admin task invoke <kind>` against the admin-task HTTP
  endpoint, mounting the `<release>-svc-token` PAT. Gated by **both** the
  global `adminTasksEnabled` master toggle (which also gates the
  svc-token-bootstrap Job + RBAC) AND the task's own `enabled`. (The one
  hybrid, `verifyEventChain`, is gated by the umbrella but actually runs
  the `hort-server verify-event-chain` subcommand directly — no PAT.)

Top-level gating keys:

| sub-key | type | default | required |
|---|---|---|---|
| `scheduledTasks.adminTasksEnabled` | boolean | `false` | no |
| `scheduledTasks.svcTokenKubectlImage` | string | `bitnamilegacy/kubectl:1.30` | no |
| `scheduledTasks.rotateSvcToken` | boolean | `false` | no |

`adminTasksEnabled` is the single opt-in surface for every
`executionPath: admin-task` task — it replaces the retired
`cronJobs.enabled`. `svcTokenKubectlImage` / `rotateSvcToken` replace the
retired `cronJobs.kubectlImage` / `cronJobs.rotateSvcToken`.

Each task block carries `executionPath` (string), `enabled` (boolean),
and `schedule` (cron string); some carry extra parameters. The full set
as of HEAD:

| task | executionPath | default `enabled` | default `schedule` | extra params |
|---|---|---|---|---|
| `scrub` | dsn-direct | `true` | `0 3 * * *` | `samplingRate`, `concurrency`, `actionOnMismatch` |
| `quarantineReleaseSweep` | dsn-direct | `true` | `*/5 * * * *` | — |
| `prefetchTick` | dsn-direct | `false` | `*/15 * * * *` | — |
| `prefetchRowRetentionSweep` | dsn-direct | `false` | `0 2 * * *` | — |
| `wheelMetadataBackfill` | dsn-direct | `false` | `0 4 * * 0` | `batchSize` |
| `noop` | admin-task | `false` | `0 0 * * *` | — |
| `stagingSweep` | admin-task | `false` | `*/15 * * * *` | — |
| `cronRescanTick` | admin-task | `false` | `*/5 * * * *` | — |
| `advisoryWatchTick` | admin-task | `false` | `0 */6 * * *` | — |
| `retentionEvaluate` | admin-task | `false` | `0 3 * * *` | — |
| `retentionPurge` | admin-task | `false` | `0 4 * * *` | — |
| `eventstoreArchive` | admin-task | `false` | `0 5 * * 0` | — |
| `serviceAccountRotation` | admin-task | `false` | `*/15 * * * *` | — |
| `eventstoreCheckpoint` | admin-task | `false` | `0 * * * *` | — |
| `replaySeenPrune` | admin-task | `true` | `0 * * * *` | — |
| `verifyEventChain` | admin-task | `false` | `0 2 * * *` | — |

`replaySeenPrune` is the only admin-task task that defaults `enabled:
true` (it runs once `adminTasksEnabled` is flipped). `scrub.actionOnMismatch`
(`HORT_CAS_SCRUB_ACTION_ON_MISMATCH`) is **also read by the main
Deployment**, so it is load-bearing even with `scrub.enabled: false`. The
schedule floor is 5 minutes (the admin-task Idempotency-Key uses
minute-granularity windows).

`serviceAccountRotation.enabled` is the **single source-of-truth toggle**
for fallback PAT rotation (the prior
two-place switch is collapsed). When true it drives both the CronJob and
the
worker-side wiring; the schema requires `adminTasksEnabled: true` and a
non-empty `worker.rotation.publicRegistryHost` (fail-fast on a half-set
config). See
[`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md).

### `worker`

The `hort-worker` Deployment — a
separate pod from the server that claims `jobs` rows and dispatches each
to its registered `TaskHandler` (scan, cron-rescan-tick,
advisory-watch-tick, staging-sweep, etc.).

| sub-key | type | default | required |
|---|---|---|---|
| `worker.enabled` | boolean | `true` | no |
| `worker.replicas` | integer | `1` | no |
| `worker.workerIdOverride` | string | `""` | no |
| `worker.image.repository` | string | `hort/hort-worker` | no |
| `worker.image.tag` | string | `""` | no (empty ⇒ `.Chart.appVersion`) |
| `worker.image.pullPolicy` | enum | `IfNotPresent` | no |
| `worker.resources` | object | `{cpu, memory}` | no |
| `worker.scanner.pollIntervalSecs` | integer | `5` | no |
| `worker.scanner.batchSize` | integer | `4` | no |
| `worker.scanner.maxAttempts` | integer | `5` | no |
| `worker.scanner.lockDurationSecs` | integer | `900` | no |
| `worker.scanner.trivy.enabled` | boolean | `true` | no |
| `worker.scanner.trivy.binary` | string | `/usr/local/bin/trivy` | no |
| `worker.scanner.trivy.dbDir` | string | `/var/cache/trivy` | no |
| `worker.scanner.osv.enabled` | boolean | `true` | no |
| `worker.scanner.osv.binary` | string | `/usr/local/bin/osv-scanner` | no |
| `worker.advisory.osvUrl` | string | `https://api.osv.dev/v1/querybatch` | no |
| `worker.db.lockTimeoutMs` | integer | `120000` | no |
| `worker.serviceAccount.create` | boolean | `true` | no |
| `worker.serviceAccount.name` | string | `""` | no |
| `worker.serviceAccount.annotations` | map | `{}` | no |
| `worker.rotation.targetNamespaces` | list | `[]` | no |
| `worker.rotation.publicRegistryHost` | string | `""` | conditional |

`worker.enabled: false` stops the worker rendering; dispatched
`kind='scan'` jobs then accumulate with no progress. Under
quarantine-by-default that strands ingested artifacts in
`Quarantined` unless the operator declares a `ScanPolicy` with
`scan_backends: []` (the explicit `ScanWaived` authority) — so the chart
defaults `enabled: true`.

The scanner backend block is the parallel-named pair `worker.scanner.{trivy, osv}`
(the prior `osvScanner` key was renamed `osv` to match
`trivy` — ADR 0029). Each `*.enabled` is **load-bearing**: `enabled: false`
makes the worker **not register** that backend even if the binary
`--version` probe would pass — the flag is the enabling gate, the probe a
secondary health check. Disabling **both** backends is a hard boot error
(a scanner worker with nothing to scan); set `worker.enabled: false`
instead.

`worker.rotation.*` carries the **parameters** of the single
`scheduledTasks.serviceAccountRotation.enabled` toggle — `targetNamespaces`
(per-namespace RBAC rendered for each) and `publicRegistryHost` (the
`dockerconfigjson.auths` host, schema-required when rotation is enabled).
There is **no** `worker.rotation.enabled` switch (the prior
two-place toggle is collapsed). Worker-scoped `extraEnv` / `extraVolumes`
/ `extraVolumeMounts` / `nodeSelector` / `tolerations` / `affinity` mirror
the top-level keys but apply to the worker pod only.

---

## 4. Cross-references

- [`install.md`](./install.md) — install path
- `examples-overlays.md` — edge-overlay wiring
- `security-hardening-checklist.md` — chart hardening posture
- [`../wire-secrets.md`](../wire-secrets.md) — `SecretPort` + mTLS
  mount surface
- [`../declare-gitops-config.md`](../declare-gitops-config.md) — gitops
  mounting reference
- [`../http-transport-timeouts.md`](../http-transport-timeouts.md) —
  `http.*` knobs in operator depth
- [`crates/hort-server/src/config.rs`](../../../../crates/hort-server/src/config.rs)
  — canonical doc-comments for every `HORT_*` env var
