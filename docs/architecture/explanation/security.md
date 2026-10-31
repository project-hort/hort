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

`WriteRepoAccess` and `DeleteRepoAccess` do **not** go through
`RepositoryAccessUseCase` — that use case's `AccessLevel` only has
`Read`/`Write` variants, with no `Delete`. Instead both extractors call
local helpers inside `hort-http-core::authz::extractors`:
`resolve_repository()` (looks the repository up directly) and
`authorize()` (evaluates `RbacEvaluator` directly against
`Permission::Write` / `Permission::Delete` — a different enum, on
`hort-domain::entities::rbac`). The extractors exist so handlers keep the
"one fetch per request, stashed in extensions" property. `AdminPrincipal`
is unchanged.

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

**The two fields read different inputs.** `HORT_PUBLIC_BASE_URL`
governs `public_url`; `HORT_TRUSTED_PROXY_CIDRS` governs `client_ip`.
A pinned public base URL does **not** switch off `X-Forwarded-For`
attribution — `evaluate_trust` never reads `public_base_url` when
computing `client_ip`. (This document and the middleware's own policy
table both used to say it did; no code path implemented that, and the
claim is why a deployment attributing every caller to its ingress
looked correctly configured.)

`public_url`:

| `HORT_PUBLIC_BASE_URL` | `HORT_TRUSTED_PROXY_CIDRS` | Behaviour |
|---|---|---|
| set | (not read for this) | Use verbatim; `X-Forwarded-*` and `Host` ignored. |
| unset | set, peer trusted | `X-Forwarded-Proto`/`-Host`, falling back to `Host`. |
| unset | peer not trusted | Synthesise from `Host` + `https`; bind-address default when `Host` is absent. |
| unset | unset | **Unconditional startup failure.** `X-Forwarded-Host` injection poisons PyPI/npm/cargo download URLs regardless of auth state, so the check is not auth-gated. |

`client_ip`:

| `HORT_TRUSTED_PROXY_CIDRS` | Peer | Behaviour |
|---|---|---|
| set | in the allowlist | Rightmost-untrusted `X-Forwarded-For` entry (below); `0.0.0.0` sentinel + throttled `warn!` when XFF is absent or entirely internal. |
| set | not in the allowlist | The socket peer. |
| empty | (any) | The socket peer — **and the operator must declare that shape** with `HORT_CLIENT_IP_FROM_SOCKET_PEER=true`, or the binary refuses to start (`ClientIpAttributionUnconfigured`). |

**Why the empty-allowlist case is an admission check, not a default.**
With no allowlist, attribution is the TCP peer. For a directly-exposed
server that is right. Behind a proxy, ingress or LB it is the edge's
address for every caller in the world, so everything keyed on
`client_ip` — the PAT brute-force lockout, the auth-failure rate-limit
bucket, the per-IP concurrency cap, fail2ban — collapses onto a single
bucket, and thirty failed credential presentations from anywhere deny
credentialed access deployment-wide. Nothing observable at boot
distinguishes the two deployments. A runtime heuristic cannot either:
"an untrusted peer sent `X-Forwarded-For`" would let a
directly-connected attacker opt out of its own bucket by adding a
header. So the operator declares the deployment shape and the
undeclared case fails closed at admission, never degrades to a
best-guess authority at runtime (ADR 0016). `0.0.0.0/0` is not a way
to satisfy it: that trusts `X-Forwarded-For` from everyone, which is
the forgeable-attribution hole in a different shape.

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
reading is forgeable — any client can prepend an arbitrary IP, and an
appending proxy (nginx's `$proxy_add_x_forwarded_for`) tacks the real
client on the right without stripping it. The rightmost-untrusted
reading walks the proxy chain backwards and stops at the first hop your
trust configuration says could be a client, which is the only honest
answer when the chain length isn't fixed.

The predicate is **per entry and local**: an entry is a proxy hop iff
its own address is in the allowlist. Nothing about an entry's
neighbours can make it attributable — in particular a prepended entry
naming an address inside the allowlist is stepped over as the hop it
claims to be, never returned, because naming an internal address costs
a caller nothing. A walk that instead stopped at the first entry whose
right-hand neighbour was untrusted stops one entry too early and
returns the caller's own chosen string; that is the shape this walk had
until the attribution audit, and the two unit tests it passed were the
two chains with no prepended entry, where leftmost-untrusted and
rightmost-untrusted coincide.

CIDR membership uses `Ipv6Addr::to_canonical()` before
`IpNet::contains` so an IPv4-mapped IPv6 peer (`::ffff:10.0.0.5`)
matches the same allowlist entry as the bare IPv4 form.

**Every credential path reads `client_ip` from the extension.** The
three inbound credential presentations — the write-path auth middleware
(`require_principal`), the OCI consume-side bearer middleware, and
`POST /api/v1/auth/exchange` — thread `RequestTrust.client_ip` into
`AuthenticateUseCase::authenticate_bearer_with_client_ip`, which is
what arms the PAT per-IP brute-force lockout; the Distribution-Spec
mint endpoint `GET /v2/auth` reads the same extension rather than
`ConnectInfo`. `crates/hort-app/tests/bearer_auth_threads_client_ip.rs`
is a source guard that fails the build if a production call site drops
it, because dropping it changes no response, metric or log — it only
disarms the lockout.

The one deliberate exception is the **read path**
(`extract_optional_principal`), which calls the named
`authenticate_bearer_read_path_without_ip_lockout`. A lockout there
would let an unauthenticated reader with a bad token deny its whole
/24's *writes* for fifteen minutes — reads need no credential at all
(ADR 0021), so a bad token on a read is not a step towards access. Its
exposure is **cost**: a PAT-cache miss buys an Argon2id verify at
`m=19456, t=2, p=1`. That is bounded by the auth-scope rate-limit
bucket instead, whose method filter admits a read **only when the
request presents a credential** — an anonymous read stays out of the
bucket entirely, a failed credentialed read counts, and a successful
one does not.

## Egress and SSRF posture

`hort-net-egress::is_routable` is the single canonical routability
predicate (rejects loopback/link-local/RFC1918/CGNAT/IPv4-mapped-IPv6
IMDS addresses); every outbound-URL adapter below builds on it, but
each applies it at a different point in its request lifecycle
depending on whether the target is operator-vetted or user-submitted.

| Adapter / surface | Target trust | Checks applied |
|---|---|---|
| Upstream artifact/metadata fetch (`hort-adapters-upstream-http`) | Operator-configured upstream (Cargo/npm/PyPI registry mapping) | `check_ssrf_safe` at URL-validation time, a per-hop `is_routable` re-check on every redirect (`build_redirect_policy`), **and** a connect-time `GuardedDnsResolver` (security audit finding INJ-1) that re-runs `is_routable` on every dial-time resolution — closing the TOCTOU window between validation and dial. |
| Webhook delivery (`hort-notifier-webhook`) | User-submitted (any caller with subscription-create privilege) | `WebhookTargetGuard::check` at subscription create-time (IP literal or single-shot DNS resolution), `Policy::limited(0)` (zero redirects — any 3xx is rejected outright), and a connect-time `GuardedDnsResolver` closing the create→deliver DNS-rebind TOCTOU. Operator opt-outs: `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` (blanket, last resort) and `HORT_WEBHOOK_ALLOWLIST_HOSTS` (targeted, per-host/CIDR). |
| OIDC discovery / JWKS fetch (`hort-adapters-oidc`) | Operator-configured issuer (deployment-pinned) | Same-host binding (the JWKS fetch is pinned to the issuer's own host, so a compromised discovery document cannot redirect it elsewhere) — no `is_routable` leg. Deliberately dropped: it broke the canonical in-cluster-IdP deployment for negligible benefit given same-host binding is already load-bearing. |
| S3-compatible storage backend (`hort-adapters-storage`) | Operator-configured endpoint (deployment config) | No connect-time guard; the endpoint is deployment config, not attacker-influenced input. Defence in depth is TLS cert validation (`HORT_EXTRA_CA_BUNDLE`) and artifact-layer content-checksum verification. |

**Why upstream-http and webhook diverge from OIDC/S3.** Upstream
artifact URLs are metadata-supplied (an attacker who influences
upstream registry metadata influences the fetch target) and webhook
URLs are literally user-submitted — both are within an attacker's
reach, so both get the full three-layer treatment including a
connect-time guard. OIDC issuer and S3 endpoint URLs are
operator-configured deployment config; a connect-time guard there
would only produce false positives against legitimate internal
targets (in-cluster IdP, private S3-compatible endpoint) for a
threat that requires the operator's own configuration to already be
compromised.

## Defence in depth

Additional layers, each small and focused:

- **Rate limiting.** `middleware/rate_limit.rs`. Auth-failure layer
  (default 60 **failures**/min) counts every write and every read that
  *presents a credential*, consuming only on failure; write-path layer
  (`tower-governor`, default 300/min) consumes on every POST/PUT/DELETE
  regardless of outcome. Both keyed on `RequestTrust::client_ip`. Emits
  `hort_rate_limit_rejects_total{path, scope}` with
  `path=MatchedPath` (never a raw URI).
- **Body + field caps.** `crates/hort-http-core/src/limits.rs` exports
  `DEFAULT_PUBLISH_BODY_LIMIT` (300 MiB), `CARGO_PUBLISH_BODY_LIMIT`
  (200 MiB), `MAX_MULTIPART_FIELDS` (100), `MAX_ROUTE_PARAM_BYTES`
  (512). Path-param caps are enforced by the `BoundedPath<T>` extractor
  used by every format handler. `HORT_PUBLISH_BODY_MAX_SIZE` overrides
  the publish cap for npm / PyPI / Maven; cargo keeps its own ceiling
  against any non-zero value and OCI push takes no ceiling from it
  (`limits::cargo_publish_body_limit`).
- **Publish kill switch.** `HORT_PUBLISH_BODY_MAX_SIZE=0` is not a
  smaller ceiling but an administrative hold, and
  `limits::refuse_publishes_when_disabled` is its single definition:
  each publish subtree applies it, and it answers `503` (no
  `Retry-After` — the hold has no deadline) on the publish methods
  before a request reaches a handler. Reach is every publish surface,
  the four hosted formats and the OCI push path alike. Reads (`GET` /
  `HEAD`) and deletions pass, so turning publishing off never takes
  serving down with it. The refusal is deliberately not left to the
  body limit: `DefaultBodyLimit::max(0)` admits a zero-byte body, and a
  Maven PUT has no envelope that could fail on one — an empty artifact
  was ingested, with an `ArtifactIngested`, a quarantine timer and a
  scan job behind it, out of a gate the operator believed shut.
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
  threshold, quarantine duration, provenance mode, and approval
  requirement. Scoped globally or per-repository. (Neither
  `licensePolicy` nor `maxArtifactAge` is part of the gate: no port
  surfaces an artifact's licences, and the age evaluator has no caller
  on any scan, release or retention path, so declaring either is an
  apply-time rejection rather than a control — see
  [the linter-row matrix](../reference/apply-time-linter-rows.md).)
- **`Exclusion`** is an auditable override on a `ScanPolicy`. A
  whitelisted CVE for a specific package pattern, recorded with a
  free-text `reason` and an optional `expires_at`. Each exclusion is
  identified by `(policy_name, cve_id, package_pattern_or_null)`;
  changing an exclusion's reason or expiry is modelled as
  `ExclusionRemoved` + `ExclusionAdded` so the lifecycle is fully
  recoverable from the event log. Its reach is the **parent policy's**
  scope: an exclusion's own `scope` must be `global`, because the
  finding filter never reads it — a repository-scoped one would clear
  its CVE everywhere the policy governs, so every writer refuses it.
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
> `ScanCompleted` → `ScanSucceeded`, a `scan_backends: []` policy
> → `ScanWaived`, or a scanned artifact under an
> `enforcement: record` policy → `ScanRecorded`); a candidate with
> none of them gets no authority and the predicate refuses it, so
> timer-driven release skips it — fail-closed by construction.

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
