# Reference — `hort-server` and `hort-worker` configuration

Canonical, exhaustive reference for the **command-line surface** and
**environment variables** of the two v2 runtime binaries:

- `hort-server` — the HTTP service + operational subcommands
  (`crates/hort-server/`)
- `hort-worker` — the multi-kind job dispatcher (`crates/hort-worker/`)

Scope: the v2 rewrite in `crates/` only. The `backend/` prototype and
the prototype-migration how-tos are out of scope here.

> **Authority.** The ground truth for every value below is the parsing
> code: `crates/hort-server/src/config.rs` (+ `composition.rs`,
> `telemetry.rs`) for `hort-server` and
> `crates/hort-worker/src/config.rs` (+ `composition.rs`, `extra_ca.rs`,
> `telemetry.rs`) for `hort-worker`. Where this page and that code
> disagree, **the code wins and this page is the bug** — fix it in the
> same change. The Helm-values mapping lives in
> [`how-to/deploy/values-reference.md`](../how-to/deploy/values-reference.md);
> this page documents the binary surface the chart renders into.

Conventions used in the tables:

- **Default** is the literal value the binary uses when the variable is
  unset, quoted exactly as coded. "_unset → …_" describes the
  unset-path behaviour when there is no static default.
- **Required?** — "Yes" means the binary refuses to start without it;
  "Cond." means required only under a condition stated in
  [§ Validation & interlocks](#hort-server--validation--interlocks).
- Durations are seconds unless the name says otherwise.
- A `0`/non-integer value is rejected at startup for every
  positive-integer knob (`ConfigError::ValueNotPositive` for `0`,
  `ConfigError::InvalidInt` for a non-integer) **except** the two
  explicitly noted kill-switch knobs.

---

## `hort-server` — command-line surface

`hort-server` is a multi-subcommand binary (`clap`). **The subcommand is
optional: a bare `hort-server` invocation is exactly equivalent to
`hort-server serve`.** Both `ExecStart=/usr/local/bin/hort-server` (systemd)
and `args: ["serve"]` (k8s) are therefore correct and identical.

| Subcommand | Purpose | Config parsed |
|---|---|---|
| _(none)_ / `serve` | Start the HTTP service; run until SIGTERM/SIGINT. | **full `Config`** |
| `migrate` | Apply pending DB migrations + re-assert events-role hardening, then exit. Init-container / pre-install-Job pattern. | `MinimalConfig` |
| `scrub [FLAGS]` | CAS integrity scrubber — re-hash stored blobs, detect drift. | **full `Config`** |
| `admin <SUB>` | Admin-user / service-token management (nested, required). | `MinimalConfig` |
| `reconcile-groups [--since]` | Heal artifacts whose ingest-path group commit dropped between the `ArtifactIngested` and `ArtifactGroupMemberAdded` transactions. | `MinimalConfig` |
| `validate-config [--strict]` | Offline gitops-config validation (CI pre-merge gate); see [§ `validate-config`](#validate-config). | _none_ — DSN-free; reads its own env directly |

`--help` / `--version` work at the top level and on every subcommand.
Unknown subcommand → clap `InvalidSubcommand` (non-zero exit). On error
each subcommand prints `Error: {err:?}` (full `anyhow` context chain)
and exits non-zero; a Tokio-runtime build failure prints
`error: building tokio runtime: {err}`.

> **Why `migrate`/`admin`/`reconcile-groups` use `MinimalConfig`**
> ([ADR 0009](../../adr/0009-least-privilege-runtime-migrate-subcommand.md)):
> the runtime DSN is least-privilege (DML only) and
> these DB-only subcommands must not require the storage /
> public-base-url / OIDC surface. `MinimalConfig` parses exactly the
> five shared variables in
> [§ Core (shared)](#core-shared--minimalconfig). `serve` and `scrub`
> parse the full surface and enforce every interlock. Migrations are
> owned **only** by `hort-server migrate` — the `serve` path calls
> `migrate::assert_current` (a read-only check on `_sqlx_migrations`)
> and refuses to run `migrate::run`.

### `scrub` flags

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--concurrency` | usize | `4` | Max in-flight re-hash tasks. Must be `>= 1`. |
| `--sample-fraction` | f64 | `1.0` | Per-blob sampling probability; must be in `[0.0, 1.0]`. |

Exit code: `0` when there are no hash mismatches (even with missing /
read-error blobs); `1` when any mismatch is found (so a CronJob can
escalate); non-zero failure on config/connection error. The
mismatch-handling behaviour itself is selected by
[`HORT_CAS_SCRUB_ACTION_ON_MISMATCH`](#cas-scrubber).

### `admin` subcommands

**`admin issue-svc-token`** — mint a service-account token.

The prior `admin bootstrap`
subcommand is removed (it seeded the now-deleted HTTP-Basic-against-
local-admin-row identity path — see `docs/auth-catalog.md` Entry 8).
Minimal-setup bring-up uses `issue-svc-token`
plus `hort-cli auth login --paste`; see `crates/hort-server/README.md`.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--name` | String | _(required)_ | Logical token name; derives SA username `hort-svc-<name>`. |
| `--permission` | String (repeatable) | `["admin_task_invoke"]` | Permissions to grant. |
| `--output` | String | `"stdout"` | `stdout` \| `file:<path>` (mode `0600`); `kube-secret` is rejected in v1. |
| `--rotate` | flag | off | Force revoke + re-mint; default is idempotent (exit 0, no rotation if it already exists). |
| `--expires-in-days` | u32 | `365` | Token lifetime. |

### `reconcile-groups` flags

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--since` | RFC 3339 timestamp | _(none → use-case default = last 7 days)_ | Lower bound for the `ArtifactIngested` scan window. |

### `validate-config`

Offline gitops-config validation: runs the **static subset** of the
boot-time apply pass — parse + cross-validate plus the snapshot-free
linter rules, via the same `StaticConfigValidator`
(`crates/hort-app/src/lint/static_validate.rs`) the apply path delegates
to — over the tree in `HORT_CONFIG_DIR`, with no database and no running
server. Implementation:
`crates/hort-server/src/cli/validate_config.rs`. The CI-recipe
walkthrough (deriving the env from Helm values) is in
[declare-gitops-config.md §5a](../how-to/declare-gitops-config.md#5a-validate-your-config-before-applying-hort-server-validate-config).

Synchronous and DSN-free: it builds no Tokio runtime, parses neither
`Config` nor `MinimalConfig`, and never reads `HORT_DATABASE_URL` /
`DATABASE_URL` or connects to anything.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--strict` | flag | off | Promote every warning — rule warnings, the zero-files warning, the `HORT_UPSTREAM_USER_AGENT` warning — from exit `0` to exit `1`. The only flag; config inputs are env-only. |

Environment inputs (read directly, not via `Config`):

| Variable | Required? | Behaviour |
|---|---|---|
| `HORT_CONFIG_DIR` | Yes | The gitops tree to validate — the same variable `serve` reads at boot. Unset or blank → exit `2`. |
| `HORT_STORAGE_BACKEND` | Yes | The deployment storage-backend **kind** (`filesystem` \| `s3`) for the per-repo `storage.backend` cross-check. **No `filesystem` default** (unlike `serve`); unset or any other value → exit `2`. Kind only — the S3 bucket / endpoint / credentials are never read. |
| `HORT_UPSTREAM_USER_AGENT` | No | Outbound User-Agent override. Unset/empty → no finding. A non-empty value that is not a valid HTTP header value → **warning** (at boot the server silently falls back to its built-in default), exit `1` only under `--strict`. Linted with the same predicate the runtime applies (`hort_adapters_upstream_http::validate_user_agent_override`, `crates/hort-adapters-upstream-http/src/lib.rs`). |
| `HORT_LOG_FORMAT` | No | `json` → JSON tracing; anything else — including unset or an invalid value — → `pretty`. Unlike the other subcommands, an invalid value does **not** fail this command (lenient by design: a cosmetic log knob must never fail the gate). |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean — no errors (warnings allowed when `--strict` is off). |
| `1` | Validation error(s): a parse / cross-validate failure or any reject rule — **or** `--strict` with any warning present. |
| `2` | Missing/invalid required env (`HORT_CONFIG_DIR` / `HORT_STORAGE_BACKEND`). Checked before any file is read. |
| `3` | Operational — the config directory is unreadable / the directory walk errored. |

Checks run vs. not run:

| | Checks |
|---|---|
| **Run (offline)** | YAML parse + per-envelope domain validation + cross-validate + singleton-conflict; desired-internal `ServiceAccount` → `OidcIssuer` reference consistency; the under-constrained `federatedIdentities` advisory (warning); the `trustUpstreamPublishTime` × empty-`scanBackends` cross-opt-in reject; the inert `prefetchPolicy.maxAgeDays` reject; provenance-policy validation against the binary's provenance-capable format set; the per-repo `storage.backend` vs `HORT_STORAGE_BACKEND` mismatch reject; the permission-grant linter (secure-default `LintConfig` base, desired-side overrides applied). |
| **Not run (need the live deployment)** | Current-state checks (managed-by ownership, immutable-field changes). The `scanBackends` supported-backend check runs only at apply (validating against the binary's compiled-in scanner set, not the live worker registry — regression H20); the offline validator does not currently run it. A clean run is therefore necessary but not sufficient for a clean apply; the command prints a one-line footer saying so. |

A directory that exists but contains zero YAML files validates clean —
exit `0` — with the warning `validated 0 config files — is
HORT_CONFIG_DIR correct?`; under `--strict` it is exit `1` (catches a
typo'd-but-existing path in CI). The validator and its static facts
(the provenance-capable format set, the linter defaults) are compiled
into the binary, so the invoked image tag is exactly the version being
validated against; there is no `--version` selector.

---

## `hort-server` — environment variables

### Core (shared — `MinimalConfig`)

Parsed by **every** subcommand except `validate-config`, which is
DSN-free and reads its own env directly (see
[§ `validate-config`](#validate-config)).

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_DATABASE_URL` | string | _unset → falls back to `DATABASE_URL`_ | Yes¹ | Postgres connection DSN. Canonical operator var; tried first. Redacted in `Debug`. |
| `DATABASE_URL` | string | _unset → error if `HORT_DATABASE_URL` also unset_ | Yes¹ | Fallback DSN. Read by sqlx-cli, the Tier-2 `maybe_pool()` test helpers, and 12-factor tooling; the chart now wires `HORT_DATABASE_URL`. Redacted in `Debug`. |
| `HORT_LOG_FORMAT` | `pretty` \| `json` | `pretty` | No | Tracing subscriber format (case-insensitive; unknown → error). |
| `METRICS_INCLUDE_REPOSITORY_LABEL` | bool | `true` | No | Emit the `repository` metric label; `false` → `repository="_all"` sentinel (cardinality control at scale). No `HORT_` prefix. |
| `PG_STATEMENT_TIMEOUT_MS` | u64 | _unset → none (Postgres default)_ | No | Per-session `statement_timeout` in ms. `0` rejected. No `HORT_` prefix. |
| `PG_ACQUIRE_TIMEOUT_SECS` | u64 | `30` | No | Pool `acquire_timeout`. `0` rejected. No `HORT_` prefix. |

¹ Exactly one of `HORT_DATABASE_URL` / `DATABASE_URL` is required;
`HORT_DATABASE_URL` is the canonical operator var and is tried first, with bare
`DATABASE_URL` as the documented compat fallback. With neither set the error
surfaces the name `"DATABASE_URL"`. This is identical to the worker.

### Logging & tracing

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `RUST_LOG` | tracing `EnvFilter` directive | `info` | No | Standard `tracing-subscriber` filter; unset/unparsable falls back to `info`. There is no `LOG_LEVEL` knob. |

### HTTP server & binding (`serve`)

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_API_BIND` | SocketAddr | `127.0.0.1:8080` | No | Main API listener. The binary default is loopback; the chart sets `0.0.0.0:8080` so kubelet probes reach it. |
| `HORT_HTTP_HEADER_READ_TIMEOUT_SECS` | u64 | `15` | No | Slowloris cap on request-line + headers. |
| `HORT_HTTP_REQUEST_TIMEOUT_SECS` | u64 | `300` | No | Global per-handler runtime deadline. |
| `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` | u64 | `3600` | No | Per-route override for OCI blob-upload `PATCH`/`PUT`. |
| `HORT_SHUTDOWN_GRACE_SECS` | u64 | `60` | No | Graceful-drain wall-clock cap after SIGTERM/SIGINT. |
| `HORT_PUBLISH_BODY_MAX_SIZE` | size string | _unset → 300 MiB_ | No | PyPI/npm publish body cap. Size string (`"300Mi"`, `"1Gi"`, or a bare byte integer). **`"0"` = refuse all publishes** (kill-switch; not rejected). |
| `HORT_METADATA_BLOB_MAX_SIZE` | size string | `10Mi` (10 MiB) | No | CAS metadata-blob ceiling. Size string (`"10Mi"`, or a bare byte integer). **`"0"` = accept anything** (not rejected). |
| `METADATA_CAP_BYTES_<FORMAT>` | usize | _unset → handler default_ | No | Per-format metadata-cap override; `<FORMAT>` suffix is lowercased to the format key. No `HORT_` prefix. |

See [tune HTTP transport timeouts](../how-to/http-transport-timeouts.md)
for the timeout knobs in depth.

### Trust, TLS & public URL

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_PUBLIC_BASE_URL` | URL | _unset → none_ | Cond. | Public-facing base URL (scheme+authority only; must be `http`/`https` with a host). |
| `HORT_TRUSTED_PROXY_CIDRS` | CSV of CIDRs | _empty_ | Cond. | Reverse-proxy allowlist for trusting `X-Forwarded-*`. |
| `HORT_REQUIRE_HTTPS` | bool | `false` | No | Refuse to boot without positive TLS evidence (see interlocks). |
| `HORT_EXTRA_CA_BUNDLE` | path | _unset → system trust only_ | No | Extra CA PEM bundle, layered onto the system store for **all four** outbound TLS surfaces (upstream proxy, S3/MinIO, OIDC discovery+JWKS, outbound webhook delivery). **Fail-closed**: set-but-unreadable / bad PEM / zero certs aborts boot. See [extra-ca-bundle.md](../how-to/deploy/extra-ca-bundle.md). |

> One of `HORT_PUBLIC_BASE_URL` or a non-empty `HORT_TRUSTED_PROXY_CIDRS`
> is mandatory — with neither set the binary fails at startup
> (`ConfigError::TrustUnconfigured`).

### Authentication provider (OIDC)

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_AUTH_PROVIDER` | `disabled` \| `oidc` | `disabled` | No | Auth provider. There is **no `basic` value** (the HTTP-Basic path was removed end-to-end; see `docs/auth-catalog.md` Entry 8). With `disabled`, `serve` refuses to boot unless `HORT_NATIVE_TOKENS_ENABLED=true` — there must be at least one inbound auth surface, and the only `disabled`-compatible surface is native tokens. |
| `HORT_OIDC_ISSUER_URL` | string | _unset → error when `oidc`_ | Cond. | OIDC issuer (`iss`). |
| `HORT_OIDC_AUDIENCE` | string | _unset → error when `oidc`_ | Cond. | Required token audience (`aud`). |
| `HORT_OIDC_GROUPS_CLAIM` | string | `groups` | No | IdP claim carrying group memberships. |
| `HORT_JWKS_CACHE_TTL_SECS` | u64 | `600` | No | JWKS cache TTL. |
| `HORT_OIDC_CLI_CLIENT_ID` | string | _unset → none_ | Cond. | OAuth client id `hort-cli` presents for the device flow (required iff token exchange is enabled). |
| `HORT_JWKS_EVICTION_BACKOFF_SECS` | u64 | `10` | No | Per-kid JWKS signature-mismatch eviction cooldown. |
| `HORT_JWKS_RESP_BODY_MAX_SIZE` | size string | `1Mi` (1 MiB) | No | Discovery / JWKS response body cap. Size string (`"1Mi"`, `"4Mi"`, or a bare byte integer); a sub-1-byte value (incl. `"0"`) is rejected. |

### Native tokens, OCI token signing & token exchange

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_NATIVE_TOKENS_ENABLED` | bool | `false` | No | Enable the native `Bearer hort_<kind>_*` token surface. Requires a resolved signing key. |
| `HORT_TOKEN_EXCHANGE_ENABLED` | bool | `false` | No | Mount `POST /api/v1/auth/exchange` (RFC 8693). Requires `HORT_NATIVE_TOKENS_ENABLED=true` **always**; under `HORT_AUTH_PROVIDER=oidc` *additionally* requires `HORT_OIDC_ISSUER_URL` + `HORT_OIDC_CLI_CLIENT_ID` + `HORT_PUBLIC_BASE_URL` (these back the interactive discovery doc and are **not** consulted under `disabled` — federation-only mode). |
| `HORT_OCI_TOKEN_SIGNING_KEY` | inline PEM | _unset → none_ | Cond. | Active OCI-token Ed25519 PKCS#8 signing key (inline). Redacted. |
| `HORT_OCI_TOKEN_SIGNING_KEY_FILE` | path | _unset → none_ | Cond. | Active signing key from a file (preferred over inline; mutually exclusive with it). |
| `HORT_OCI_TOKEN_SIGNING_KEY_PREV` | inline PEM | _unset → none_ | No | Previous signing key (verify-only, for rotation). |
| `HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE` | path | _unset → none_ | No | Previous signing key from a file (mutually exclusive with the inline `_PREV`). |
| `HORT_TOKEN_ALLOW_ADMIN` | bool | `false` | No | Permit `Permission::Admin` in token issuance / exchange. |
| `HORT_TOKEN_ALLOW_UNBOUNDED_SVC` | bool | `false` | No | Permit null-expiry service-account tokens via admin-mint. |
| `HORT_BEARER_ALLOW_OVER_HTTP` | bool | `false` | No | Allow bearer auth (every bearer kind: PAT + CliSession JWT) over plaintext HTTP (transport-unsafe; logs one boot WARN + sets the unsafe-config gauge). **Boot-fails** when combined with an `https://` `HORT_PUBLIC_BASE_URL` — a TLS-terminated deploy that also relaxes the bearer transport guard is self-contradictory (INFRA-13). Only WARNs when `HORT_PUBLIC_BASE_URL` is `http://...` or unset. |

### Rate limiting, lockout & load shedding

The `HORT_AUTH_LOCKOUT_*` env vars are removed — they powered the
now-deleted
`authenticate_local` HTTP-Basic-against-local-admin-row path. The
`HORT_PAT_LOCKOUT_*` env vars (a distinct mechanism — bearer-path
per-IP / per-token-prefix brute-force protection inside
`PatValidationUseCase`) are unchanged.

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_RATELIMIT_AUTH_PER_MIN` | u32 | `60` | No | Per-IP auth-attempt rate cap. |
| `HORT_RATELIMIT_WRITE_PER_MIN` | u32 | `300` | No | Per-IP write-path rate cap. |
| `HORT_MAX_INFLIGHT` | usize | `512` | No | Workspace-wide concurrent-request cap. |
| `HORT_MAX_INFLIGHT_PER_IP` | usize | `32` | No | Per-IP concurrent-request cap. |
| `HORT_PAT_CACHE_SIZE` | usize | `10000` | No | PAT-validation cache size. |
| `HORT_PAT_LOCKOUT_THRESHOLD` | u32 | `30` | No | Per-IP PAT failed-attempt threshold. |
| `HORT_PAT_LOCKOUT_WINDOW_SECS` | u64 | `300` | No | PAT failed-attempt window. |
| `HORT_PAT_LOCKOUT_DURATION_SECS` | u64 | `900` | No | PAT lockout cooldown. |

### Storage

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_STORAGE_BACKEND` | `filesystem` \| `s3` | `filesystem` | No | Storage adapter selection. |
| `HORT_STORAGE_FILESYSTEM_PATH` | path | _unset → error when filesystem_ | Cond. | Filesystem CAS root. |
| `HORT_STORAGE_S3_BUCKET` | string | _unset → error when s3_ | Cond. | S3 bucket name. |
| `AWS_REGION` | string | _unset → error when s3_ | Cond. | S3 region (preferred). Falls back to `AWS_DEFAULT_REGION`. |
| `AWS_DEFAULT_REGION` | string | _fallback for `AWS_REGION`_ | Cond. | Legacy region name; used only if `AWS_REGION` is unset. |
| `AWS_ENDPOINT_URL_S3` | URL | _unset → none_ | No | S3 endpoint override (service-specific; wins over `AWS_ENDPOINT_URL`). |
| `AWS_ENDPOINT_URL` | URL | _unset → none_ | No | S3 endpoint override (cross-service fallback). |
| `AWS_ACCESS_KEY_ID` | string | _unset → error when s3_ | Cond. | S3 access key (passed explicitly; the AWS SDK credential chain is **not** consulted). |
| `AWS_SECRET_ACCESS_KEY` | string | _unset → error when s3_ | Cond. | S3 secret key. Redacted. |
| `HORT_STORAGE_S3_FORCE_PATH_STYLE` | bool | `false` | No | Path-style addressing (required `true` for MinIO/zot). |
| `HORT_STORAGE_S3_ALLOW_HTTP` | bool | `false` | No | Opt-in to a plaintext S3 endpoint; cross-checked against the endpoint scheme (see interlocks). |
| `HORT_S3_SSE_MODE` | `bucket-default` \| `sse256` \| `sse-kms` | _unset → no SSE opinion_ | No | S3 server-side-encryption mode. |
| `HORT_S3_SSE_KMS_KEY_ARN` | string | _unset → error when `sse-kms`_ | Cond. | KMS key ARN; required when `HORT_S3_SSE_MODE=sse-kms`. |

### Ephemeral store (Redis)

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_EPHEMERAL_STORE_BACKEND` | `memory` \| `redis` | `memory` | No | EphemeralStore backend. `memory` is single-process only (blocks multi-replica HA via the values schema). |
| `HORT_REDIS_URL` | string | _unset → error when `redis`_ | Cond. | Redis URL. Redacted. |
| `HORT_REDIS_URL_EVICTABLE` | string | _unset → falls back to `HORT_REDIS_URL`_ | No | Per-class evictable Redis override (per-class keyspace routing). |
| `HORT_REDIS_URL_DURABLE` | string | _unset → falls back to `HORT_REDIS_URL`_ | No | Per-class durable Redis override. |

### Pull-through deduplication

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS` | u64 | `30` | No | Negative-cache TTL for upstream `NotFound`. |
| `HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS` | u64 | `10` | No | TTL for RateLimited / upstream-5xx / upstream-4xx / Unauthorized. |
| `HORT_PULL_DEDUP_TTL_TIMEOUT_SECS` | u64 | `10` | No | TTL for Timeout / NetworkError. |
| `HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS` | u64 | `60` | No | TTL for ChecksumMismatch / ParseError / BodyTooLarge / PinMismatch / CaUnknown. |
| `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS` | u64 | `300` | No | Follower-wait ceiling for a concurrent in-flight fetch. |

#### Pull-through coalescing degradation alarm (recommended)

Pull-through stampede suppression is **TTL-best-effort, not durable**: the
`pulldedup:` keyspace is registered in the **Evictable** class, so under the
sustained pull-burst the negative cache exists to absorb, `allkeys-lru`
eviction (or a Redis outage) can degrade cluster-wide coalescing toward
per-replica or fully un-coalesced upstream retries. Correctness is never
affected (the CAS + path-conflict short-circuit absorbs the fan-out
idempotently); only backpressure efficacy degrades. This is an audited,
accepted residual. There is **no new
metric** — alarm on the existing signals only:

| Symptom | Alarm on (existing metrics — see `docs/metrics-catalog.md`) | Reading |
|---|---|---|
| Redis-degraded coalescing (case 8 fail-open) | Sustained non-zero rate of `hort_pull_dedup_total{outcome="layer_b_unavailable"}` | Cluster-wide coalescing is off; every replica is un-coalescing independently. |
| Negative cache evicted under burst (case 9) | `hort_pull_dedup_total{outcome="negative_cache_hit"}` rate collapsing while `hort_pull_dedup_total{outcome="leader_started"}` for the same `format` stays high, **and/or** evictable-class memory pressure visible as elevated `hort_ephemeral_store_operations_total{class="evictable"}` op rate (optionally with `result="error"`) | The `Failed` record is being evicted before its TTL; followers re-elect and re-hit the upstream instead of short-circuiting on the cached failure. |

**Operator action when the alarm fires:** isolate the `pulldedup:` /
evictable keyspace onto its own Redis instance via
`HORT_REDIS_URL_EVICTABLE` (per-class routing — see the *Ephemeral
store* table above) and/or raise that instance's `maxmemory` so the
short-lived `Failed` records survive their TTL; alternatively, accept the
degraded-to-per-replica backpressure posture (correctness holds either
way — the trade-off is only upstream-amplification risk during a burst).
Routing the negative-cache `Failed` records to the Durable class is the
stronger structural fix; it is deferred pending a `KEYSPACE_REGISTRY`
class-assignment review (load-bearing, user-coordination-gated).

#### Scan-queue backlog alarm (recommended)

The scan queue is fed by four trigger sources (`ingest`, `cron`,
`advisory`, `manual`). The `cron` and `manual` paths can amplify
enqueue volume faster
than the worker drains it: a cron-rescan tick batches up to 1000 stale
artifacts per invocation, and an unthrottled manual-rescan caller can
enqueue repeatedly. This is an audited, accepted residual (see the
open-items register in
[`docs/adr/0000-historical-decisions-index.md`](../../adr/0000-historical-decisions-index.md)).
The **security half is already neutralised** — the fail-closed release
predicate ([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md))
makes release contingent on a successful scan, so a
deep scan queue can only delay availability of newly-ingested or
just-rescanned artifacts, never weaken the quarantine gate. The residual
is therefore an **availability** concern only; alarm on the existing
signal — there is **no new metric**:

| Symptom | Alarm on (existing metric — see `docs/metrics-catalog.md`) | Reading |
|---|---|---|
| Scan queue growing faster than the worker drains it | `hort_scan_queue_depth` sustained above the worker's steady-state drain rate (depth not returning toward baseline across several heartbeat intervals; the heartbeat emits every 60 s) | The worker cannot keep pace with the enqueue rate (cron batch cap + manual rescans + ingest first-scans). New/just-rescanned artifacts wait longer in `pending`; correctness is unaffected (the fail-closed release predicate holds the gate). |

**Metric-name note.** Older audit prose referred to
`hort_jobs_pending_count{kind="scan"}`; that metric name **does not
exist**. Its shipped equivalent is `hort_scan_queue_depth`
(see `docs/metrics-catalog.md` — a no-label
gauge emitted by the worker heartbeat tick reading
`count(*) FROM jobs WHERE kind='scan' AND status='pending'`, which is
exactly the "pending scan jobs" quantity the audit named). Treat
`hort_scan_queue_depth` as the canonical name when
wiring the alarm.

**Operator action when the alarm fires:** scale out worker replicas
(the claim loop is `FOR UPDATE SKIP LOCKED`, so additional replicas
drain cooperatively without coordination), and/or raise `priority` on
the latency-sensitive trigger sources via admin so ingest first-scans
stay ahead of routine cron rescans. Lengthening the cron-rescan schedule
(`scheduledTasks.cronRescanTick.schedule`) reduces the batch-injection rate.
The structural fix — a per-(principal, repository) manual-rescan enqueue
rate cap with an HTTP 429 response — is **deferred** (it requires a
`KEYSPACE_REGISTRY` durable prefix and an `hort-http-core`
error-contract 429 change, both cross-cutting); the open item is
recorded in the open-items register
([`docs/adr/0000-historical-decisions-index.md`](../../adr/0000-historical-decisions-index.md)).
Because the
security half is already closed by the release predicate, this deferral
carries no
security risk — it is purely an availability-hardening follow-on.

#### Anomalous advisory-diff-volume alarm (recommended)

The advisory-watch tick (`AdvisoryWatchTickHandler`)
ingests the OSV bulk feed over **TLS only**; OSV publishes no signed
manifest or per-zip hash for the bulk `all.zip` archives, so the feed is
**trusted-but-unauthenticated**. This is an audited, **accepted
residual** (see the open-items register in
[`docs/adr/0000-historical-decisions-index.md`](../../adr/0000-historical-decisions-index.md))
with this alarm as one of two
compensating controls (the other is the *reject-requires-scanner*
invariant — a poisoned advisory only ever enqueues a rescan that a real
scanner adjudicates, so a
poisoned advisory alone cannot reject a clean artifact). This alarm is
the **feed-poisoning / feed-suppression tripwire**; it also serves the
NIS2 21(2)(f) vulnerability-handling-efficacy signal. There is **no new
metric** — alarm on the existing signals only:

| Symptom | Alarm on (existing metrics — see `docs/metrics-catalog.md`) | Reading |
|---|---|---|
| Advisory **injection** (false/over-broad entries → mass cross-tenant rescans) | A single advisory-watch tick's `hort_advisory_diff_processed_total{result="ok"}` for an `ecosystem` spiking far above that ecosystem's rolling baseline (catalog line 2911); corroborate with anomalous `hort_advisory_diff_duration_seconds{ecosystem}` (line 2912) | The feed delivered an abnormal burst of "new/modified" advisories for this ecosystem — consistent with a poisoned/injected feed. Expect a `hort_scan_jobs_enqueued_total{trigger_source="advisory"}` surge and rising `hort_scan_queue_depth` shortly after. |
| Advisory **suppression** (entries silently dropped → vulnerable artifacts never re-flagged; compounds a broken feed) | `hort_advisory_diff_processed_total{result="ok"}` collapsing toward ~0 across **all** ecosystems while the prior baseline was non-zero, **and** `hort_advisory_ingest_count` falling below its expected per-ecosystem floor (the feed-efficacy signal; see `docs/metrics-catalog.md`) | The feed has gone silent or is being suppressed upstream. The advisory DB is no longer being populated; a suppressed feed and a broken/under-ingesting feed are indistinguishable here and share this signal. |

**Metric-name note.** The shipped metrics are
`hort_advisory_diff_processed_total{ecosystem,result}`,
`hort_advisory_diff_duration_seconds{ecosystem}`, and
`hort_advisory_ingest_count{category}` (the
under-floor efficacy metric, **not** a per-tick diff counter — all
documented in `docs/metrics-catalog.md`). No metric
is added; the suppression
tripwire deliberately reuses the **existing**
`hort_advisory_ingest_count` under-floor alert rather than introducing a
parallel signal.

**Operator action when the alarm fires:** treat it as a **possible
feed-poisoning or feed-suppression event**, not a routine queue blip.
Do **not** trust the next rescan wave at face value: cross-check OSV's
published advisory volume out-of-band (the OSV web UI / a second
mirror), inspect the affected ecosystem's recent `hort_advisory_diff_*`
samples, and confirm whether a real upstream advisory drop explains the
volume before letting the enqueued rescans proceed to operator
attention. On a confirmed injection, the *reject-requires-scanner*
invariant already bounds the blast radius to scan-queue amplification
(no false rejections) — the queue-amplification mitigations in the
*Scan-queue backlog alarm* above apply. On a confirmed suppression,
escalate as a vulnerability-handling-efficacy incident (NIS2
21(2)(f)): the advisory DB is stale and the cron-rescan safety net
re-runs the *same* poisoned/suppressed data, so it is not an independent
recovery path. The stronger structural control — a second,
authenticated feed (GitHub Advisory) — is **deferred** (see the
open-items register in
[`docs/adr/0000-historical-decisions-index.md`](../../adr/0000-historical-decisions-index.md));
it is referenced, not scheduled here.

### Notifications & webhooks

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_NOTIFICATIONS_ENABLED` | bool | `true` | No | Event-notification substrate on/off. |
| `HORT_NOTIFY_CHANNEL_CAPACITY` | u32 | `1024` | No | Notification broadcast channel capacity. |
| `HORT_WEBHOOK_ALLOW_PLAINTEXT` | bool | `false` | No | Allow `http://` webhook URLs (transport-unsafe gauge when on). |
| `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` | bool | `false` | No | Skip the webhook SSRF / routable-target check (unsafe gauge when on). |
| `HORT_NATS_URL` | string | _unset/empty → none_ | No | NATS JetStream notifier URL. Redacted. |

### Metrics

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_METRICS_REQUIRE_AUTH` | bool | `true` | No | Require admin auth on `/metrics`; `false` re-permits anonymous scrape (boot WARN). |
| `HORT_METRICS_BIND` | SocketAddr | _unset → metrics on the main router_ | No | Dedicated metrics listener address. |
| `HORT_METRICS_PUBLIC_BIND` | bool | `false` | No | Allow the metrics listener to bind an unspecified address (`0.0.0.0`/`::`). Parsed before `HORT_METRICS_BIND` so the guard can consult it. |

### CAS scrubber

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_CAS_SCRUB_ACTION_ON_MISMATCH` | `alert` \| `tombstone` | `alert` | No | What `hort-server scrub` does on a hash mismatch. See [cas-storage.md](../explanation/cas-storage.md). |

### Operational / gitops / misc

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_CONFIG_DIR` | path | _unset → none_ | No | Gitops desired-state config directory; applied automatically at `serve` startup (no separate apply subcommand). Must be a directory if set. Also the input tree for [`validate-config`](#validate-config), which **requires** it. See [declare-gitops-config.md](../how-to/declare-gitops-config.md). |
| `HORT_SECRETS_FILE_ROOT` | path | _unset → unconstrained_ | No | Containment root for the mounted-file SecretPort; path-escape is rejected when set. See [wire-secrets.md](../how-to/wire-secrets.md). |
| `HORT_K8S_SECRET_WRITER_ENABLED` | exact `"true"` | _disabled_ | No | Enables the k8s Secret writer for the PAT-rotation reconciler. **Only the literal string `true` enables it**; `true` + in-cluster auth failure aborts boot (never a silent no-op). |
| `HORT_RBAC_REFRESH_SECS` | u32 | `30` | No | RBAC snapshot poll cadence. |
| `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` | u32 | `60` | No | Upstream-resolver snapshot refresh cadence. Minimum `5` (lower → error). |
| `HORT_UPSTREAM_ALLOWLIST_HOSTS` | tri-state CSV | _unset → disabled_ | No | Apply-time upstream-host allowlist. `__deny_all__` → strict deny; `h1,h2` → host list; empty/unset → no enforcement. |
| `HORT_STATEFUL_UPLOAD_STAGING_DIR` | path | _derived_ | No | Stateful-upload chunk staging root. Default: `<HORT_STORAGE_FILESYSTEM_PATH>/stateful-upload-staging` (filesystem) or `/var/lib/hort/stateful-upload-staging` (S3, + boot WARN). |
| `HORT_OCI_LEGACY_CATALOG_ENABLED` | bool | `false` | No | Mount the Docker-legacy global `/v2/_catalog`. |
| `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL` | u32 | `32` | No | Per-(repo, principal) OCI upload-session cap. |

---

## `hort-server` — validation & interlocks

These cross-field rules are enforced at startup by `serve` / `scrub`
(full `Config`). Each is fail-fast — the binary refuses to start
rather than run misconfigured.

1. **Trust unconfigured (unconditional).** `HORT_PUBLIC_BASE_URL` unset
   **and** `HORT_TRUSTED_PROXY_CIDRS` empty → boot fails
   (`TrustUnconfigured`). One of the two is mandatory.
2. **`HORT_REQUIRE_HTTPS=true`.** Fails if `HORT_PUBLIC_BASE_URL` is `http`
   **and** `HORT_TRUSTED_PROXY_CIDRS` is empty (no positive TLS
   evidence). An `https://` base URL **or** a non-empty CIDR list
   satisfies it.
3. **Metrics public-bind guard.** `HORT_METRICS_BIND` on an unspecified
   IP while `HORT_METRICS_PUBLIC_BIND=false` → boot fails
   (`MetricsPublicBindRefused`).
4. **Storage required fields.** `filesystem` requires
   `HORT_STORAGE_FILESYSTEM_PATH`; `s3` requires `HORT_STORAGE_S3_BUCKET`,
   a region (`AWS_REGION`/`AWS_DEFAULT_REGION`), `AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY`.
5. **S3 allow-http ↔ endpoint scheme.** `http://` endpoint without
   `HORT_STORAGE_S3_ALLOW_HTTP=true` → error; the flag set with an
   `https://` endpoint, or set with no endpoint (real AWS S3) → error.
6. **S3 SSE-KMS requires the ARN.** `HORT_S3_SSE_MODE=sse-kms` without
   `HORT_S3_SSE_KMS_KEY_ARN` → error (never silently downgrades).
7. **OCI signing key source exclusivity.** Setting both
   `HORT_OCI_TOKEN_SIGNING_KEY_FILE` and `HORT_OCI_TOKEN_SIGNING_KEY`
   (non-empty) → error; `_FILE` wins. Same rule for the `_PREV` pair.
8. **Native tokens need a key.** `HORT_NATIVE_TOKENS_ENABLED=true` with no
   resolved active signing key → error.
9. **Token exchange dependency set.**
   `HORT_TOKEN_EXCHANGE_ENABLED=true` requires `HORT_NATIVE_TOKENS_ENABLED=true`
   **always** (the exchange mints `hort_*` native tokens the server must be able
   to validate). Under `HORT_AUTH_PROVIDER=oidc` it *additionally* requires
   `HORT_OIDC_ISSUER_URL`, `HORT_OIDC_CLI_CLIENT_ID`, and `HORT_PUBLIC_BASE_URL`
   (they back the `/.well-known/hort-client-config` discovery doc + the
   interactive device flow). Under `HORT_AUTH_PROVIDER=disabled` none of those
   three are required — the federated-JWT branch validates against the gitops
   `OidcIssuer` rows, not the interactive IdP config (federation-only /
   no-Keycloak mode). The error names every missing variable.
10. **Redis URL under the Redis backend.**
    `HORT_EPHEMERAL_STORE_BACKEND=redis` requires `HORT_REDIS_URL` (the
    per-class overrides fall back to it at composition time).
11. **`HORT_CONFIG_DIR` must be a directory** if set non-empty.
12. **`HORT_UPSTREAM_RESOLVER_REFRESH_SECS` floor** is `5`.
13. **Auth-enabled startup gate.** `HORT_AUTH_PROVIDER=disabled` is
    rejected unless a local admin row exists **or**
    `HORT_NATIVE_TOKENS_ENABLED=true`. `oidc` always passes without a DB
    query.
14. **`HORT_EXTRA_CA_BUNDLE` fail-closed.** Set-but-unreadable / invalid
    PEM / zero certs aborts boot — never degrades silently to
    public-CA-only trust.

---

## `hort-worker` — command-line surface

`hort-worker` claims jobs from the shared `jobs` table and dispatches
each row to the `TaskHandler` registered for its `kind` (scan,
cron-rescan-tick, advisory-watch-tick, staging-sweep,
service-account-rotation, noop).

| Subcommand | Purpose |
|---|---|
| _(none)_ | Parse env → init tracing + Prometheus → load `HORT_EXTRA_CA_BUNDLE` → build composition → run the `TaskDispatcher` + heartbeat until SIGTERM/SIGINT. This is what every deployment manifest invokes. |
| `healthcheck` | k8s `livenessProbe` exec gate. |

`healthcheck` deliberately stays cheap (it runs every few seconds): it
(1) parses `WorkerConfig::from_env`, then (2) opens a one-connection
pool (acquire timeout `2000 ms`) and runs a single `SELECT 1` under an
outer `2500 ms` budget, then exits. It does **not** start the
dispatcher, probe scanners, or initialise tracing/Prometheus. Exit `0`
on success, `1` on any failure (`hort-worker fatal: …` to stderr).
Unknown subcommand → clap `InvalidSubcommand`.

The worker is otherwise driven by Helm values and an HTTP admin-task
endpoint (CronJob → `POST /api/v1/admin/tasks/{kind}`), not by
additional CLI flags — see
[rotating-service-account-tokens.md](../how-to/rotating-service-account-tokens.md).

---

## `hort-worker` — environment variables

The scanner adapters (`hort-adapters-scanner-trivy` / `-osv`) and the
advisory adapter (`hort-adapters-advisory-osv`) read **no** env vars
themselves — every value reaches them through `WorkerConfig` fields
wired in `composition.rs`. The worker uses the `hort_app_role` runtime
DSN only (it asserts, never runs, migrations) and does **not** read
`HORT_NATS_URL`, `HORT_EPHEMERAL_STORE_BACKEND`, a non-evictable
`HORT_REDIS_URL`, or any AWS SDK credential-chain variable.

### Core, identity & logging

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_DATABASE_URL` | string | _unset → falls back to `DATABASE_URL`_ | Yes¹ | Postgres DSN for the `hort_app_role` runtime role; tried first. |
| `DATABASE_URL` | string | _unset → error if `HORT_DATABASE_URL` also unset_ | Yes¹ | Fallback DSN (the name the Helm chart wires). |
| `HORT_LOG_FORMAT` | `pretty` \| `json` | `pretty` | No | Tracing subscriber format. |
| `RUST_LOG` | `EnvFilter` directive | `info` | No | Standard tracing filter (not read by `healthcheck`). |
| `HORT_WORKER_ID` | string | _derived_ | No | Explicit worker identity. Used verbatim if non-empty; else `${POD_NAME}-${8-hex}`; else `pod-${8-hex}`. |
| `POD_NAME` | string | `pod` | No | k8s downward-API pod name; the worker-id prefix when `HORT_WORKER_ID` is unset. |
| `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` | bool | `true` | No | Per-SA metric-label cardinality switch; `false` collapses the `hort_rotation_lag_seconds` SA label to `_all`. No `HORT_` prefix. |

¹ Exactly one of `HORT_DATABASE_URL` / `DATABASE_URL` is required; with
neither set the error surfaces the name `"DATABASE_URL"`.

### Dispatcher tuning

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_SCANNER_POLL_INTERVAL_SECS` | u64 | `5` | No | Dispatcher poll interval. |
| `HORT_SCANNER_BATCH_SIZE` | u32 | `4` | No | Jobs claimed per poll (clamped to `u16::MAX`). |
| `HORT_SCANNER_MAX_ATTEMPTS` | u32 | `5` | No | Max scan attempts before a job is failed. |
| `HORT_SCANNER_LOCK_DURATION_SECS` | u64 | `900` (15 min) | No | Job lock / lease duration. |

### Scanner & advisory adapters

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_SCANNER_TRIVY_ENABLED` | bool | `true` | No | **Load-bearing.** When `false`, the worker does NOT register the Trivy backend even if its `--version` probe would pass — the flag is the enabling gate; the probe is a secondary health check that only runs on flag-enabled backends. Set from `worker.scanner.trivy.enabled`. |
| `HORT_SCANNER_OSV_ENABLED` | bool | `true` | No | **Load-bearing**, same contract as `HORT_SCANNER_TRIVY_ENABLED`. Set from `worker.scanner.osv.enabled`. Disabling **both** backends is a hard boot error (a scanner worker with no backends has nothing to scan). |
| `HORT_SCANNER_TRIVY_BIN` | path | `trivy` | No | Trivy binary path/name. |
| `HORT_SCANNER_TRIVY_DB_DIR` | path | _unset → Trivy default cache_ | No | Trivy `--cache-dir`; omitted when unset. |
| `HORT_SCANNER_OSV_BIN` | path | `osv-scanner` | No | osv-scanner binary path/name. |
| `HORT_ADVISORY_OSV_API_URL` | URL | `https://api.osv.dev/v1/querybatch` | No | OSV per-component `querybatch` endpoint. |
| `HORT_ADVISORY_OSV_BULK_URL` | URL | `https://osv-vulnerabilities.storage.googleapis.com` | No | Base URL for per-ecosystem OSV bulk archives (advisory-watch tick). |
| `HORT_ADVISORY_WATCH_ECOSYSTEMS` | CSV | _unset → built-in 8: `npm, PyPI, crates.io, Maven, Go, RubyGems, NuGet, Packagist`_ | No | Per-tick ecosystem labels for the advisory watch. |
| `HORT_REDIS_URL_EVICTABLE` | string | _unset → in-memory cache (warn; single-process)_ | No | Evictable Redis URL for the OSV advisory cache. |

### Storage (for `staging-sweep` + scanner content reads)

Same names and semantics as the `hort-server`
[Storage](#storage) table — `HORT_STORAGE_BACKEND` (default
`filesystem`), `HORT_STORAGE_FILESYSTEM_PATH`, `HORT_STORAGE_S3_BUCKET`,
`AWS_REGION` / `AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3` /
`AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`HORT_STORAGE_S3_FORCE_PATH_STYLE`, `HORT_STORAGE_S3_ALLOW_HTTP`. The
filesystem CAS root must match the server's. `HORT_STATEFUL_UPLOAD_STAGING_DIR`
is read by the `staging-sweep` task with the same derivation rule as
the server.

### Service-account rotation

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_ROTATION_TARGET_NAMESPACES` | CSV | _empty_ | No | k8s namespaces the rotation handler may write Secrets in. Empty → every SA is a safe `namespace_not_authorized` no-op. |
| `HORT_PUBLIC_REGISTRY_HOST` | string | _unset → handler not registered_ | No | Registry host for the `dockerconfigjson.auths` key. **If unset, the service-account-rotation handler is not registered at all.** |

### Extra CA / subprocess trust

| Variable | Type | Default | Required? | Semantics |
|---|---|---|---|---|
| `HORT_EXTRA_CA_BUNDLE` | path | _unset → no-op_ | No | Operator CA PEM bundle. See propagation below. |
| `SSL_CERT_FILE` | path | _set by the worker, never read_ | — | The worker **sets** this per-subprocess on each Trivy / osv-scanner `Command`; it never reads it from the environment. |

#### `HORT_EXTRA_CA_BUNDLE` propagation (worker)

`extra_ca::read_and_propagate` runs once at boot, before composition:

- **Unset/empty** → no-op; scanner subprocesses use their default OS
  trust store; `SSL_CERT_FILE` is left untouched.
- **Set & non-empty**: the bundle is read and parsed
  (`ExtraTrustAnchors`), merged with the system store
  (`/etc/ssl/certs/ca-certificates.crt`), and the merged PEM is written
  atomically to `/tmp/hort-worker-ca-bundle.pem`. The parsed anchors flow
  into the OSV advisory adapter's reqwest client; the merged-bundle
  path flows into each scanner subprocess as the per-process
  `SSL_CERT_FILE`. Any read / parse / write failure **aborts boot**
  (`hort-worker fatal: …`) — a configured-but-broken bundle fails fast
  rather than degrading to public-root-only TLS. The unreadable-file
  fatal **names the missing path and points at the absent CA-bundle
  mount**, so a half-wired manual recipe (env set but the worker volume
  forgotten) is an actionable error, not an opaque crashloop. The chart only sets `HORT_EXTRA_CA_BUNDLE` on the worker
  when it also auto-mounts the bundle there (`extraCaBundle.configMapName`
  / `secretName`); see [extra-ca-bundle.md](../how-to/deploy/extra-ca-bundle.md).
  The chart must provide a writable `/tmp` (an `emptyDir`).

---

## Not consumed by the v2 binaries

Operators occasionally carry these forward from the prototype or the
target-architecture docs. The v2 binaries do **not** read them — they
have no effect:

| Token | Status |
|---|---|
| `WASM_PLUGIN_DIR` / `PLUGINS_DIR` | Not read. WASM format modules are a *future* target ([ADR 0005](../../adr/0005-wasm-format-modules-capability-taxonomy.md)); v2 format handlers are compiled-in. |
| `HORT_GROUP_MAPPINGS_PATH` | Removed. `hort-server serve` reads it only to emit a one-shot deprecation WARN; it has no effect on behaviour. Use `HORT_CONFIG_DIR`. |
| `LOG_LEVEL` | Not read. Use `RUST_LOG`. |
| `*_INSECURE_TLS`, `HORT_TLS_INSECURE`, `S3_INSECURE_TLS`, `OIDC_INSECURE_TLS`, `insecure_jwks_url` | Do not exist by policy. The only internal-CA mechanism is `HORT_EXTRA_CA_BUNDLE`. |
| `OTEL_*` | No OpenTelemetry env vars are read. |

---

## See also

- [Helm values reference](../how-to/deploy/values-reference.md) — the
  chart keys that render into these env vars.
- [Security hardening checklist](../how-to/deploy/security-hardening-checklist.md)
  — chart-vs-binary defaults for the security-relevant knobs.
- [Tune HTTP transport timeouts](../how-to/http-transport-timeouts.md)
- [Trust internal or corporate CAs](../how-to/deploy/extra-ca-bundle.md)
- [Wire secrets](../how-to/wire-secrets.md)
- [Provision the two Postgres roles](../how-to/deploy/postgres-roles.md)
- [Declare configuration via `$HORT_CONFIG_DIR`](../how-to/declare-gitops-config.md)
