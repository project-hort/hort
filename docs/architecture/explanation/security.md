# Security

hort's security posture rests on three
pillars: external auth (OIDC, RBAC, native tokens),
request-path hardening (authorization extractors,
request trust middleware, rate limiting, JWKS resilience, CAS
integrity, audit refinements), and RBAC enforcement at
the use-case boundary (read-side authz + visibility live in the
application layer, anti-enumeration on Read denial, structural
`pub(crate)` flip on `AppContext` data ports). This document describes
the shipped state — what a request passes through, what the server
trusts, and what operators still own.

For format-specific content integrity see
[cas-storage.md](cas-storage.md); for the audit-log semantics see
[event-sourcing.md](event-sourcing.md); for the legal artefact covering
event-log retention, the GDPR Art 17(3)(b) erasure exemption, and the
ROPA outline see
[`docs/compliance/GDPR.md`](../../compliance/GDPR.md). The standing
decisions live in the ADRs — notably
[ADR 0012 (claim-based RBAC)](../../adr/0012-claim-based-rbac-claimless-static-tokens.md),
[ADR 0021 (anonymous-by-default read handlers)](../../adr/0021-read-handler-anonymous-by-default.md),
and
[ADR 0008 (use-case-only data access from format crates)](../../adr/0008-per-format-adapter-free-http-crates.md)
— and in [`docs/auth-catalog.md`](../../auth-catalog.md), the canonical
inbound-auth surface
([ADR 0018](../../adr/0018-auth-catalog-canonical.md)).

## Trust boundaries

What the server is willing to trust, and why:

| Boundary | Trust basis |
|---|---|
| OIDC issuer | `HORT_OIDC_ISSUER_URL` pinned at startup. Tokens whose `iss` claim mismatches are rejected without a JWKS fetch. |
| JWKS signing keys | Fetched from the issuer's discovery document; cached per-kid with per-kid eviction backoff to defeat forged-`kid` DoS. See `crates/hort-adapters-oidc/src/lib.rs`. |
| Reverse proxy peer | `HORT_TRUSTED_PROXY_CIDRS` — only peers in the allowlist have their `X-Forwarded-*` headers honoured. Everyone else falls back to the socket peer IP and `Host` header. |
| Public base URL | `HORT_PUBLIC_BASE_URL`, if set, is used verbatim for emitted URLs. Forwarded headers are ignored entirely in that mode. |
| `DATABASE_URL` | Operator-level privilege, equivalent to root. Anyone with the runtime DSN can read every row in `users`, `api_tokens`, etc. via `psql`; the runtime is least-privileged DML-only, but the bare DSN itself is sensitive. |

Everything else is untrusted and subject to validation before it
reaches the domain layer.

## Authentication

Two entry points share the same middleware at
`crates/hort-http-core/src/middleware/auth.rs`. The middleware extracts either a
`Bearer` token or a `Basic` credential pair from the `Authorization`
header; on success, it inserts a `CallerPrincipal` into request
extensions. Handlers never see the raw token.

| Header | Path |
|---|---|
| `Bearer <jwt>` | `AuthenticateUseCase::authenticate_bearer` — validates against the pinned OIDC issuer + audience via the cached JWKS, or as a native token (`hort_<kind>_*`) via `PatValidationUseCase`. JIT-provisions the OIDC user on first sight; refreshes group / claim mappings + `is_admin` on every call. |
| `Basic <b64>` | Token **carrier** only — the password half is fed into `authenticate_bearer` (the PyPI `__token__` / Docker Hub convention of embedding a JWT or native token in the password field). The username half is ignored as an identity input; a non-`__token__` username present alongside a non-token password is logged as a deprecated-shape attempt and rejected by the bearer validator. |

The prior HTTP-Basic-against-local-admin-row identity path
(`authenticate_local` + the `users.password_hash` column +
`AdminBootstrapped`/`AdminPasswordRotated` events + the
`hort-server admin bootstrap` CLI) was removed pre-v1.0 as a hard
cutover, end-to-end including the producer side. Minimal-setup
bring-up without an OIDC IdP uses
`hort-server admin issue-svc-token` (mints an `hort_svc_*` native token)
consumed by `hort-cli auth login --paste`. See
`docs/auth-catalog.md` Entry 8.

On failure the middleware emits `hort_auth_attempts_total{result}` with
one of: `success`, `invalid_token`, `expired`, `unknown_issuer`,
`missing_header`, `malformed_basic`. The classification is driven by
`OidcValidationError` — a structured enum on the `IdentityProvider`
port, not by substring-matching an error string.

## Authorization

`RbacEvaluator::authorize(principal, permission, repo_id) -> bool` is a
**pure predicate**. It takes the principal's role set + a permission
intent + an optional repository scope, and returns a boolean. No I/O,
no side effects, no inline emissions.

### Where the policy lives

Read-side authz + repo visibility live in the application layer, not
in the inbound HTTP handlers. The single
source of truth is
`RepositoryAccessUseCase` (`crates/hort-app/src/use_cases/repository_access.rs`):

```rust
pub enum AccessLevel { Read, Write }

impl RepositoryAccessUseCase {
    pub async fn resolve(&self, repo_key: &str,
        actor: Option<&CallerPrincipal>, level: AccessLevel)
        -> AppResult<Repository>;
    pub async fn resolve_by_id(&self, repo_id: Uuid,
        actor: Option<&CallerPrincipal>, level: AccessLevel)
        -> AppResult<Repository>;
    pub async fn list_visible(&self, actor: Option<&CallerPrincipal>,
        page: PageRequest) -> AppResult<Page<Repository>>;
    pub async fn metric_label(&self, repo_id: Uuid) -> String;
}
```

Two further use cases compose `RepositoryAccessUseCase::resolve` so
visibility is enforced uniformly across every read path:

- `ArtifactUseCase::find_visible_by_path` /
  `find_visible_by_id` / `find_in_repo_by_hash` / `download_range` /
  `list_by_raw_name_visible` / `list_distinct_names_visible` /
  `batch_metadata` (`crates/hort-app/src/use_cases/artifact_use_case.rs`).
- `ContentReferenceUseCase::find_by_visible_target` /
  `insert_for_repo` / `delete_by_source_for_repo`
  (`crates/hort-app/src/use_cases/content_reference.rs`).

### Inbound extractors

Three `FromRequestParts` extractors in
`crates/hort-http-core/src/authz/extractors.rs` keep their
handler-signature-ergonomic shape:

```rust
pub struct AdminPrincipal(pub CallerPrincipal);
pub struct WriteRepoAccess { pub principal: CallerPrincipal, pub repository: Arc<Repository> }
pub struct DeleteRepoAccess { pub principal: CallerPrincipal, pub repository: Arc<Repository> }
```

`WriteRepoAccess` and `DeleteRepoAccess` both collapse to thin
wrappers over `RepositoryAccessUseCase::resolve(repo_key, actor,
AccessLevel::{Write,Delete})` — the policy itself lives in the use
case; the extractors exist so handlers keep the "one fetch per
request, stashed in extensions" property. `AdminPrincipal` is
unchanged.

`Delete` is split out of `Write` deliberately. Destroying an
artifact is structurally distinct from publishing one — a CI service
account that legitimately needs to push images should not, by the
same grant, be able to wipe the repository. The OCI manifest-delete
endpoint (`DELETE /v2/<name>/manifests/<reference>`) is the first
caller of `DeleteRepoAccess`; non-OCI lifecycle endpoints stay on
`WriteRepoAccess` until per-format demand surfaces.

Each extractor emits `hort_authz_decisions_total{permission, result}`
and returns `403 Forbidden` on deny *before* the handler body runs.
Handlers that forget the extractor are typed into harmless territory —
no admin-typed operation accepts a bare `CallerPrincipal`.

For read paths, the handler calls the use case directly:
`ctx.repository_access_use_case.resolve(repo_key, actor,
AccessLevel::Read)` for the bare repo lookup, or
`ctx.artifact_use_case.find_visible_by_path(...)` for the combined
repo-visibility + artifact-row hop. Both encapsulate the "exactly one
fetch per request" property internally; the extractor was once
the only mechanism, but is no longer the only path.

### Visibility model and anti-enumeration

The use-case methods return errors as follows:

| Caller asserts | Repo state | Result |
|---|---|---|
| `Read` | repo missing | `NotFound` |
| `Read` | repo present but invisible to actor | `NotFound` (byte-identical to missing) |
| `Read` | repo visible | `Ok(repository)` |
| `Write` | repo missing | `NotFound` |
| `Write` | repo present, actor lacks Read | `NotFound` |
| `Write` | repo present, actor has Read but not Write | `Forbidden` |
| `Write` | repo visible and writable | `Ok(repository)` |

**Anti-enumeration is load-bearing.** Returning `Forbidden` on a Read
denial would leak the existence of private repositories to
unauthenticated probers (the classic 404-vs-403 oracle). A `Read`
denial therefore collapses "missing" and "invisible" into the same
envelope. `Write` is permitted to return `Forbidden` only in the one
case where the actor is already known to have Read on the repository —
the actor is authenticated and a Read-visible-but-not-writable
response carries no extra information beyond what the principal
already knows. A `Write` probe by an actor without Read still 404s, so
Write requests cannot be used to enumerate.

Under `RbacAccess::Disabled` (single-node dev / bootstrap) every
existing repo resolves `Ok` regardless of `actor` / `level`.

### Structural enforcement

Seven `AppContext` data-port fields are
`pub(crate)`, not `pub`, in `crates/hort-http-core/src/context.rs`
([ADR 0008](../../adr/0008-per-format-adapter-free-http-crates.md)):
`repositories`, `artifacts`, `refs`, `artifact_groups`,
`content_references`, `artifact_metadata`, `storage`. Inbound HTTP
crates (`hort-http-cargo`, `hort-http-npm`, `hort-http-pypi`,
`hort-http-oci`) that try to type `ctx.repositories.find_by_key(...)`
or `ctx.storage.get(...)` get an `error[E0616]: field is private`
compile error. The intended path is the corresponding use case
(`RepositoryAccessUseCase`, `ArtifactUseCase`,
`ContentReferenceUseCase`) — direct access is structurally
unreachable from a handler context. The composition root in
`hort-server` constructs `AppContext` via `AppContext::new(parts:
AppContextParts)`; `AppContextParts` has the same field set with
`pub` visibility so wiring in `hort-server::composition` stays
mechanical.

Format-shaped infrastructure ports (`ephemeral`,
`stateful_upload_staging`, `upstream_resolver`, `upstream_proxy`)
remain handler-reachable: they represent format-specific coordination
(upload state machines, pull-through resolvers, Redis-backed scratch
state) rather than authz-bearing data access, so they legitimately
live in `hort-http-<format>`.

Unknown `repo_key` still returns **404 Not Found** and still fires the
dedicated `hort_http_404_repo_lookups_total{format}` counter — the
enumeration-defence separation keeps brute-force dashboards
(`result=deny` spike) distinct from enumeration dashboards (404 spike).

## Request trust

`crates/hort-http-core/src/middleware/trust.rs` populates
`RequestTrust { client_ip, public_url }` once per request, before auth
runs. Every downstream consumer (auth attempt logs, `UrlResolver`, the
rate-limiter's key extractor) reads from extensions — none
re-implement peer-IP or proxy-trust logic.

Three legal configurations:

| `HORT_PUBLIC_BASE_URL` | `HORT_TRUSTED_PROXY_CIDRS` | Behaviour |
|---|---|---|
| set | (ignored) | Use verbatim; `X-Forwarded-*` and `Host` ignored. |
| unset | set | Trust `X-Forwarded-Proto/Host/For` only when the peer IP is in the allowlist. Otherwise synthesise `public_url` from `Host` + `https`, `client_ip` from the socket peer. |
| unset | unset | **Unconditional startup failure.** `X-Forwarded-Host` injection poisons PyPI/npm/cargo download URLs regardless of auth state, so the check is not auth-gated. |

`main.rs` wraps the axum listener with
`into_make_service_with_connect_info::<SocketAddr>()` so `ConnectInfo`
actually lands in extensions; without it the trust layer silently sees
no peer. A probe-layer test pins the layer order: `request_trust_layer`
is the outermost, attached last in the builder chain so it runs first
at dispatch.

**`X-Forwarded-For` parsing — rightmost-untrusted.**
When the peer is in `HORT_TRUSTED_PROXY_CIDRS`, the trust middleware
walks the comma-separated `X-Forwarded-For` header **right-to-left**
and returns the rightmost hop that is **not** in the trusted-CIDRs
allowlist (`rightmost_untrusted_forwarded_for` in
`crates/hort-http-core/src/middleware/trust.rs`). The naive "leftmost"
reading is forgeable — any client can prepend an arbitrary IP. The rightmost-untrusted reading walks
the proxy chain backwards and stops at the first hop your trust
configuration says could be a client, which is the only honest
answer when the chain length isn't fixed. CIDR membership uses
`Ipv6Addr::to_canonical()` before `IpNet::contains` so an
IPv4-mapped IPv6 peer (`::ffff:10.0.0.5`) matches the same
allowlist entry as the bare IPv4 form.

## Defence in depth

Additional layers, each small and focused:

- **Rate limiting.** `tower-governor` at `middleware/rate_limit.rs`.
  Auth-attempt layer (default 60/min) wraps `require_principal`;
  write-path layer (default 300/min) wraps POST/PUT/DELETE routes.
  Keyed on `RequestTrust::client_ip`. Emits
  `hort_rate_limit_rejects_total{path, scope}` with
  `path=MatchedPath` (never a raw URI).
- **Body + field caps.** `crates/hort-http-core/src/limits.rs` exports
  `DEFAULT_PUBLISH_BODY_LIMIT` (300 MiB), `MAX_MULTIPART_FIELDS` (100),
  `MAX_ROUTE_PARAM_BYTES` (512). Path-param caps are enforced by the
  `BoundedPath<T>` extractor used by every format handler.
- **Response headers.** `middleware/security_headers.rs` always emits
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`; CSP `default-src 'none';
  style-src 'unsafe-inline'` only on `Content-Type: text/html`.
- **Error sanitisation.** `AppError::External` and `AppError::Scanner`
  serialise to `{"error":"upstream unavailable"}` at the wire. The raw
  message goes to `error = %err` in tracing. An integration-test helper
  `assert_no_internal_leakage` rejects 5xx bodies containing `/`,
  `sqlx::`, `postgres://`, `Pool`, or `hort_` substrings.
- **Postgres timeouts.** `PG_ACQUIRE_TIMEOUT_SECS` (default 30) and
  optional `PG_STATEMENT_TIMEOUT_MS`. Zero is rejected as a foot-gun.
- **JWKS resilience.** Per-kid eviction backoff
  (`HORT_JWKS_EVICTION_BACKOFF_SECS`, default 10s) limits forged-`kid`
  refetch amplification; a 1 MiB response body cap
  (`HORT_JWKS_RESP_BODY_MAX_SIZE`) prevents memory blow-up from a
  malicious discovery endpoint. First-seen kids bypass backoff so
  legitimate key rotation still works.
- **CAS integrity.** `hort-server scrub` (a CLI over `CasScrubUseCase`)
  re-streams every blob, recomputes SHA-256, and emits
  `CasIntegrityMismatch` events on drift. Exit code 1 on any mismatch
  so cron can escalate.
- **Temp-file hygiene.** Filesystem CAS writes temps under
  `<root>/.staging/` with mode `0o700`. Startup escalates to `error!`
  if post-chmod the directory still has world bits set.
- **RBAC live refresh.** `AuthContext::Enabled.rbac` is an
  `arc-swap::ArcSwap<RbacEvaluator>`; a background poll on
  `cli::serve::run()` rebuilds the evaluator every
  `HORT_RBAC_REFRESH_SECS` (default 30) and atomically swaps. DB down →
  old snapshot retained. Startup jitter (0–5s) desyncs replicas.

## Supply-chain security gate

Where authn / RBAC controls *who* may publish and download, the
supply-chain gate controls *what* may transit a quarantined artifact
into a released one. Three event-sourced or CRUD kinds compose into
that gate:

- **`ScanPolicy`** defines the gate itself. Per policy: severity
  threshold, license policy (allow/deny lists), quarantine duration,
  signature requirement, approval requirement, and max-artifact-age.
  Scoped globally or per-repository.
- **`Exclusion`** is an auditable override on a `ScanPolicy`. A
  whitelisted CVE for a specific package pattern, recorded with a
  free-text `reason` and an optional `expires_at`. Each exclusion is
  identified by `(policy_name, cve_id, package_pattern_or_null)`;
  changing an exclusion's scope or expiry is modelled as
  `ExclusionRemoved` + `ExclusionAdded` so the lifecycle is fully
  recoverable from the event log.
- **`CurationRule`** is a per-package allow/deny/warn ruling that
  runs alongside scan-result evaluation — for example, a blanket
  block on a known-malicious package family irrespective of any CVE
  data.

Each rule mutation is event-sourced on the `policy-{uuid}` stream
(`PolicyCreated`, `PolicyUpdated`, `ExclusionAdded`,
`ExclusionRemoved`, `PolicyArchived`). Authorship and timing are
immutable in the log, and the apply path attributes every event to
`Actor::GitOps` — so an auditor can reconstruct exactly which YAML
revision introduced an exclusion and when. See
[event-sourcing.md](event-sourcing.md) for the projection write
pattern and the optimistic-concurrency guarantee.

> **Wired into the ingest path (fail-closed).** `ScanPolicy`
> resolution is wired into ingest and quarantine —
> `ingest_use_case` and `quarantine_use_case` resolve the active
> (repo-scoped or global) policy via `PolicyProjectionRepository`.
> Release is fail-closed in `hort-domain`
> ([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)):
> `Artifact::release()` is deny-by-default and the terminal
> `ScanIndeterminate` state holds artifacts whose scan never
> succeeded. The timer sweep derives its release authority from the
> artifact's own stream and resolved policy (a successful
> `ScanCompleted` → `ScanSucceeded`, or a `scan_backends: []` policy
> → `ScanWaived`); a candidate with neither gets no authority and the
> predicate refuses it, so timer-driven release skips it —
> fail-closed by construction.

The operator-facing how-to is at
[../how-to/declare-gitops-config.md](../how-to/declare-gitops-config.md).

## Audit trail

Two complementary signals:

- **Event log** (authoritative record of *what happened*). Every
  artifact and policy lifecycle change is an event. Events are
  immutable — a Postgres trigger owned by a separate role rejects
  `UPDATE`/`DELETE`. See [event-sourcing.md](event-sourcing.md).
- **Tracing** (record of *what was attempted*, including failures that
  never reach the event store). Security-relevant events log at `info!`
  with structured fields: `user_id`, `action`, `client_ip`. Privilege
  denials are explicitly not errors — they log `info!`, not via
  `#[instrument(err)]`.

## Secrets hygiene

Non-negotiable, enforced by convention and review:

- **Never logged:** credentials, tokens, passwords, password hashes, SQL
  bind values, full event payloads.
- **Password hashing uses Argon2id** (OWASP 2024 parameters) via
  `crates/hort-app/src/argon2_hash.rs`. A workspace-wide structural guard
  (`crates/hort-app/tests/no_bcrypt.rs`) rejects any reintroduction of
  bcrypt into the dependency graph.
- **`Debug` on secret-bearing config types** (S3 secret access key,
  OIDC client secret, `DATABASE_URL`) redacts to `"***"`.
- **`#[instrument(err)]` is banned** across the workspace. It logs all
  `Err` variants at ERROR level indiscriminately — a denied privilege
  check and a Postgres connection failure are not the same thing.
  Application code uses `#[instrument(skip(self))]` and logs explicitly.

Tests in `hort-http-core/src/error.rs` (plus per-format 5xx tests in each
`hort-http-<format>` crate that pulls the helper in via
`features = ["test-support"]`) assert `assert_no_internal_leakage` on
every 5xx path.

## Operator responsibilities

What the server does **not** attempt:

- **TLS termination.** hort speaks plain HTTP. TLS is the
  reverse proxy's job.
- **HSTS.** Emitted by the reverse proxy — hort does not
  know its public hostname.
- **Secrets management.** `DATABASE_URL`, OIDC client secret, S3
  credentials are read from env. Rotation, vault integration, and
  per-environment isolation are the operator's.
- **DDoS at the network layer.** Rate limiting is per-IP token bucket
  at the application — it absorbs small-scale abuse, not a volumetric
  attack. Put a reverse proxy in front.
- **Multi-tenant isolation.** Repositories are scoped and authorized,
  but workload isolation between tenants on a shared deployment is
  out of scope today.
