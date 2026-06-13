# Metrics Catalog

This file is canonical. No new metric name or label value may be emitted without
updating it. Reviewed as part of every architect-skill review.

Canonical-status decision: ADR 0017
(`docs/adr/0017-metrics-catalog-canonical.md`).

Every metric is `snake_case`, starts with the `hort_` prefix, and documents
its labels and units.

---

## Label schema and cardinality rules

### Allowed labels

| Label | Values | Cardinality |
|-------|--------|-------------|
| `format` | `pypi`, `cargo`, `npm`, `maven`, `oci`, ... | ~40 |
| `repository` | Repo key | ~100s typical, ~10k max |
| `result` | Per-metric enum (see catalog) | ~5-10 per metric |
| `backend` | `filesystem`, `s3`, `gcs`, `azure`, `memory` (tests) | 5 |
| `upstream` | Hostname | ~20 typical |
| `operation` | `put`, `get`, `exists`, `append`, `read_stream`, `read_category` | ~10 |
| `category` | Per-metric — event-stream metrics use `artifact`, `policy`, `admin`, `ref`, `artifact_group`, `curation`, `repository` (7 values); `hort_advisory_ingest_count` uses its own advisory-ecosystem-class taxonomy (see §"Advisory ingest efficacy"). Each metric's catalog entry is the authoritative source for its `category` value set. | per-metric |
| `strategy` | `inline`, `hash_reference` | 2 |
| `kind` | 10 values — see `hort_gitops_objects_total` for the full kind enum (`repository`, `claim_mapping`, `permission_grant`, `curation_rule`, `scan_policy`, `retention_policy`, `exclusion`, `upstream_mapping`, `oidc_issuer`, `service_account`) | 10 |
| `decision_point` | `scan_result`, `promotion`, `re_evaluation`, `curation`, `curation_retroactive` (policy enforcement); `startup_probe`, `trigger_caught` (events mutation-block decision points) | 7 |
| `attempted_op` | `update`, `delete`, `truncate` (events mutation-block taxonomy) | 3 |
| `rule` | `cve-severity-threshold`, `license-compliance`, `license-policy-shape`, `require-signature`, `max-artifact-age`, `curation-block`, `curation-warn` (policy violation rules) | 7 |
| `scanner` | `trivy`, `osv`, `advisory`, ...registered backend names | ~10 |
| `severity` | `critical`, `high`, `medium`, `low` (`'negligible'` is folded to `low` by the Trivy adapter and never reaches the metric) | 4 |
| `ingest_source` | `direct`, `proxied` (`ArtifactIngested.source` mirror) | 2 |
| `source` | Per-metric origin classification. `hort_service_account_authenticated_total`: `federated`, `pat`. `hort_dispatcher_principal_resolved_total`: `snapshot_present`, `snapshot_empty_admin`, `snapshot_empty_no_admin`. Each metric's catalog entry is authoritative for its value set; the sets are disjoint and closed. | ≤3 per metric |
| `mode` | `off`, `verify_if_present`, `required` (resolved `provenance_mode` on `hort_provenance_verify_total`; lowercase wire-form of `ProvenanceMode`) | 3 |
| `method`, `path`, `status` | HTTP — `path` MUST be the matched route template | ~50 routes |

**Cardinality ceiling note:** with `repository` (~10k) × `format` (~40) ×
`result` (~6), the theoretical ceiling per metric is ~2.4M series. In
practice a PyPI repo only emits `format="pypi"` so effective cardinality
is much lower (~60k at the worst deployment). That's still heavy for a
small Prometheus instance. **Operator guidance**: for deployments with
>1k repositories, disable the `repository` label via config
(`METRICS_INCLUDE_REPOSITORY_LABEL=true|false`) and rely on logs/traces
for per-repo drill-down.

### Sentinel label values

Readability over surprise:

- When `METRICS_INCLUDE_REPOSITORY_LABEL=false` → emit `repository="_all"`
  (so operators can distinguish "label disabled" from "label missing")
- When the use case cannot resolve a repository (e.g. `ingest` with an
  unknown `repository_id`) → emit `repository="unknown"`. **Do NOT use
  the UUID string** — a malicious or misconfigured client spamming random
  UUIDs would inflate series indefinitely.
- When the HTTP middleware cannot resolve a matched route (404s, unmatched
  paths) → emit `path="<unmatched>"`. Do NOT emit the concrete client URL.
- When the use case cannot resolve the artifact's `format` (e.g.
  `download` called with an `artifact_id` whose artifact/repository lookup
  fails) → emit `format="unknown"`. Mirrors the `repository="unknown"`
  pattern so operators can spot classification misses in dashboards.

### Forbidden labels

Hard rules, enforced by this catalog:

- `artifact_id`, `stream_id`, `content_hash` — use tracing for per-artifact info
- `user_id`, `actor_id` — audit goes to events
- Concrete file paths, version strings, package names

---

## Metric catalog

### HTTP layer (middleware)

| Metric | Type | Labels | Unit |
|--------|------|--------|------|
| `hort_http_requests_received_total` | counter | `method`, `path` | — |
| `hort_http_responses_total` | counter | `method`, `path`, `status` | — |
| `hort_http_request_duration_seconds` | histogram | `method`, `path` | seconds |
| `hort_http_requests_in_flight` | gauge | `method`, `path` | concurrent requests |
| `hort_http_load_shed_total` | counter | `result`, `path` | — |

The "requests_received vs responses_total" split is intentional — the
difference between the two over any window is the count of stuck/panicked
requests, a useful ops signal.

**`hort_http_load_shed_total` `result` semantics:**

- `result="shed"` — workspace-wide concurrency cap hit. The
  `HORT_MAX_INFLIGHT` semaphore had no permits when the request arrived;
  the request was rejected with `503 Service Unavailable` and a
  `Connection: close` header before reaching the handler. Indicates the
  service is at saturation across all clients (legitimate load spike OR
  distributed flood).
- `result="per_ip_shed"` — per-IP concurrency cap hit. The
  `HORT_MAX_INFLIGHT_PER_IP` semaphore for this client IP had no permits;
  same 503 + `Connection: close` response. Indicates a single IP
  source pinning slots — the long-running-upload DoS vector that
  bypasses tower-governor's per-minute buckets.

`path` is the matched route template (`axum::extract::MatchedPath`),
falling back to the `<unmatched>` sentinel for unmatched routes —
mirrors the rate-limit catalog convention. `client_ip` is **never** a
metric label (cardinality); operators trace per-IP detail via the
`tracing::warn!` span fields the middleware emits on every shed event.

The 503 response also ticks `hort_http_responses_total{status="503"}` via
the metrics middleware, so a "5xx ratio" alert sees both the standard
HTTP error counter and the dedicated shed counter.

### Rate limiting

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_rate_limit_rejects_total` | counter | `path`, `scope` | — | `scope` ∈ `auth`, `write` |

Emitted by `hort-http-core::middleware::rate_limit` on every `429 Too Many
Requests` response produced by either layer builder
(`auth_rate_limit_layer` / `write_rate_limit_layer`).

**`scope` semantics:**

- `auth` — the per-IP token bucket protecting `require_principal`
  (credential stuffing defense). Bucket cap via
  `HORT_RATELIMIT_AUTH_PER_MIN` (default 60). Only engages on the same
  HTTP methods that reach `require_principal` (POST, PUT, DELETE,
  PATCH) — GET/HEAD/OPTIONS traffic bypasses the bucket entirely
  because the read-path auth layer (`extract_optional_principal`)
  doesn't 401 on invalid tokens and isn't a credential-stuffing
  surface.
- `write` — the per-IP token bucket bounding mutation throughput on
  POST/PUT/DELETE/PATCH. Bucket cap via `HORT_RATELIMIT_WRITE_PER_MIN`
  (default 300). Applied unconditionally (engages even under
  `HORT_AUTH_PROVIDER=disabled` — mutation pressure is a DoS vector
  regardless of authentication state).

**Scope overlap:** both layers engage on the same write-method set,
so a single write request consumes from BOTH buckets simultaneously.
With the defaults (auth=60/min, write=300/min) the auth bucket is the
binding constraint on every single-IP burst, and `scope=write`
rejections stay near-zero by design. Operators who want the write
cap to actually surface in metrics should raise
`HORT_RATELIMIT_AUTH_PER_MIN` above `HORT_RATELIMIT_WRITE_PER_MIN`.
Rationale: the two caps defend different threat models
(credential-stuffing vs. mutation-throughput abuse); when both
defaults are in force, auth-floor applies first and write-floor is
the backstop. See `crates/hort-http-core/src/middleware/rate_limit.rs` module
docstring for the full rationale.

**`path` semantics:**

- `path` is the `axum::extract::MatchedPath` route template
  (e.g. `/pypi/:repo_key/`, `/npm/:repo_key/:scope/:name`) — **NOT**
  the concrete request URI. Matches the same cardinality rule as
  `hort_http_responses_total` / `hort_http_request_duration_seconds`.
- `path="<unmatched>"` — sentinel for the rare case where a rejection
  fires on a route the matcher hasn't resolved yet (e.g. a pre-route
  layer rejecting before dispatch). Mirrors the
  [sentinel label values](#sentinel-label-values) convention.

Cardinality: ~50 routes × 2 scopes = ~100 series on a busy deployment;
well under any ceiling. The 429 response additionally carries a
`Retry-After` header (from `tower_governor`) so well-behaved clients
back off without sampling the metric.

Companion `tracing::info!` audit log on every reject carries
`client_ip`, `scope`, and `path` — single-line-per-event shape for
fail2ban / SIEM consumers.

### Auth middleware

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_auth_attempts_total` | counter | `result` | — | `success`, `missing_header`, `invalid_token`, `expired`, `unknown_issuer`, `idp_unavailable` |

Emitted by both `hort-http-core::middleware::auth::require_principal` (write
paths) and `hort-http-core::middleware::auth::extract_optional_principal` (read
paths) exactly once per invocation, BEFORE handler dispatch. Covers every
request that hits the auth layer regardless of side. Emission covers the
read path so SIEM / fail2ban consumers can detect read-side
credential-stuffing (the read layer otherwise swallows every IdP failure
with `.ok()` and the metric would be silent for those calls). The
read path still surfaces `Option<CallerPrincipal> = None` on any failure
(no `401`); the wire-level contract is unchanged.

**`result` semantics:**

- `success` — token validated, principal inserted into request extensions.
- `missing_header` — no `Authorization: Bearer` header (or empty token).
  On the write path response is `401` with a bare
  `WWW-Authenticate: Bearer realm="..."`; on the read path the request
  flows through with `None`.
- `invalid_token` — token present but failed validation for a reason not
  more specifically classified below (bad signature, malformed claims,
  unknown audience, etc.). On the write path response is `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`.
- `expired` — token's `exp` is in the past.
- `unknown_issuer` — token's `iss` claim doesn't match the configured
  IdP.
- `idp_unavailable` — the IdP's JWKS / discovery fetch failed (transport
  error, non-2xx upstream status, oversize response body, or malformed
  JSON). The token may well be genuine; we simply could not verify it on
  this server. Surfaced as `OidcValidationError::IdpUnavailable` by the
  OIDC adapter; kept distinct from
  `invalid_token` so SOC tooling can pivot on the right label.
  Operationally: a sustained climb here is an IdP outage
  (operator-actionable); a sustained climb on `invalid_token` is a
  credential-stuffing campaign (security-actionable). On the wire this
  still surfaces as `401` (write path) or `Option<CallerPrincipal> = None`
  (read path) — the distinction lives in metrics + tracing.

Classification goes through the structured
`OidcValidationError` variant: the middleware pattern-matches the
port-contract enum and never substring-matches an error message. New
variants are an additive change to the port and require a catalog entry
here in the same PR.

No emission at all when `HORT_AUTH_PROVIDER=disabled` — neither middleware is
attached to the router in that mode.

### Authorization decisions

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|-----------------|
| `hort_authz_decisions_total` | counter | `result`, `permission` | — | `result` ∈ `allow`, `deny` / `permission` ∈ `read`, `write`, `delete`, `admin`, `curate` |
| `hort_http_404_repo_lookups_total` | counter | `format` | — | `format` ∈ known [`RepositoryFormat`](../crates/hort-domain/src/entities/repository.rs) values + sentinel `unknown` |

Emission of `hort_authz_decisions_total` moved from per-handler helpers
(previously mirrored inline in each `hort-http-<format>` crate) into the
three `FromRequestParts` extractors in
`crates/hort-http-core/src/authz/extractors.rs` (`AdminPrincipal`,
`WriteRepoAccess`, `ReadRepoAccess`). The label pair still captures the
call's inputs + decision:

- `result=allow` — `authorize()` returned `true`. Handler proceeds.
- `result=deny` — `authorize()` returned `false`. Extractor returns
  `403` with body `{"error":"insufficient permissions"}` before the
  handler body runs, and emits a `tracing::info!` audit line carrying
  `user_id` / `permission` / `repository_id`. The tracing line is NOT
  suppressed on deny — it is the audit trail and complements this
  metric.
- `permission` mirrors the [`Permission`](../crates/hort-domain/src/entities/rbac.rs)
  enum's lowercase spelling. Values are `{read, write, delete, admin, curate}`.
  `delete` is emitted via the `DeleteRepoAccess` extractor; the OCI
  `DELETE /v2/<name>/manifests/<reference>` endpoint is currently the
  only production path that emits `permission="delete"`. Cancel/finalize
  of an in-flight upload deliberately stays on `permission="write"`.
  `curate` covers the `CurateOrAdminPrincipal`
  extractor that gates the HTTP decision endpoints under
  `/api/v1/admin/curation/...`. A decision lights up
  `permission="curate"` regardless of whether the underlying
  authority was `Permission::Curate` or `Permission::Admin` (the
  extractor accepts either) — the label tracks "decisions on the
  curator surface", not "which authority the evaluator consulted".
  An admin-only caller hitting `/api/v1/admin/curation/...` ticks
  `curate=allow`, NOT `admin=allow`.

Some legacy call sites (`pypi.rs::upload` / `cargo.rs::publish` /
`npm.rs::publish_*`) still emit via per-handler `emit_authz_metric`
helpers pending migration to `WriteRepoAccess` and `ReadRepoAccess`;
they emit the same metric under the same label pair — no cardinality
change, just a single source at migration-complete.

`hort_http_404_repo_lookups_total` is distinct from the authz decision
metric by design. Authorization denials ("deny") fire against a real
resource and belong on brute-force / policy-tightening dashboards;
repo-not-found 404s fire BEFORE the RBAC check and belong on
enumeration-detection dashboards (attackers probing for which repo keys
exist before targeting a known one). Keeping the two metrics separate
lets operators watch each signal without diluting the other.

- `format="<known>"` — the resolved repository's format, e.g. `pypi`,
  `cargo`, `npm`, `maven`, `helm`, `oci`, `docker`, `rpm`, `debian`, …
  (full set: [`RepositoryFormat`](../crates/hort-domain/src/entities/repository.rs)).
  Not emitted by the extractors — they only know the repo is missing,
  so they cannot resolve the real format. Reserved for call-site
  migrations where the handler knows its format before invoking the
  extractor; the extractor will then surface the known format on the
  404 path too.
- `format="unknown"` — emitted by the extractors when a `repo_key`
  does not resolve. The extractor has no aggregate to ask; `"unknown"`
  mirrors the existing `repository="unknown"` sentinel convention for
  pre-resolution metric emission points (see "Sentinel label values"
  above).

No emission of either metric when `HORT_AUTH_PROVIDER=disabled` — the
extractors refuse to engage under [`AuthContext::Disabled`] and the
handler-side helpers skip both `req_principal()` and the `authorize()`
call, preserving the `Uuid::nil()` placeholder actor. The
metrics answer "what did the authz decision look like" and "was the
repo key resolvable"; under Disabled, neither question has an answer.

### Auth-event store appends

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_auth_events_appended_total` | counter | `result` | — | `success`, `appended`, `throttled`, `error` |

Emitted by `hort-app::use_cases::authenticate_use_case::maybe_append_auth_event`
on every authentication-failure classification site
(`hort-app::use_cases::authenticate_use_case::AuthenticateUseCase::record_auth_failure`
and `hort-http-core::middleware::auth::{require_principal,
extract_optional_principal}`). Every authentication
failure produces a durable `AuthenticationAttempted` event
on the `auth-{date}` stream category, throttled to ≤ 1 append per 60s
per `(client_ip_bucket, result)` tuple via the `EphemeralStore`.

**`result` semantics:**

- `success` — reserved. Successes do NOT currently produce events
  (audit-value-per-byte: every authenticated request would dominate
  stream volume; successes are reconstructible via `correlation_id`
  from request logs). The label value is reserved in the catalog so a
  future policy flip does not require a new variant.
- `appended` — the event was successfully written to the event store.
  This is the durable audit signal NIS2 Art. 21(2)(h) asks for.
- `throttled` — the throttle key (`auth:event:throttle:{result}:{ip_bucket}`,
  60s TTL via `put_if_absent`) was already engaged; no event was
  appended. Operators alert on sustained climb as "credential-stuffing
  campaign in progress" — same source/result tuple is hammering the
  endpoint.
- `error` — the event store rejected the append (concurrency conflict,
  adapter I/O error, ...). The auth path is unaffected — the caller
  still receives the originating 401; the audit log is best-effort.

**IP bucketing (throttle key, NOT metric label).**

The throttle key uses a coarsened IP — `/24` for IPv4
(`IPV4_BUCKET_PREFIX_BITS = 24`), `/48` for IPv6
(`IPV6_BUCKET_PREFIX_BITS = 48`) — to bound `EphemeralStore` key
cardinality from the attacker side. Without coarsening, an IPv6
attacker can mint 2^128 unique keys and exhaust ephemeral memory
long before any TTL kicks in. The constants live in
`hort-app::metrics` next to `client_ip_bucket()`. The RAW IP — not
the bucket — lands in the durable `AuthenticationAttempted` event
payload, because the audit value belongs in the durable record
where per-instance dimensionality is fine. The metric carries
ONLY the `result` label; `client_ip` does NOT appear here (high-
cardinality attacker-controlled dimensions on metrics are the
architect's hard-block anti-pattern).

**Cardinality:** rank-1 in `result` (four values, fixed taxonomy).
No high-cardinality risk.

**Event payload `result` values** (closed taxonomy enforced at
review). The OIDC-classification values are byte-for-byte identical
to the `result` label values on `hort_auth_attempts_total` so
SIEM consumers can join metric series with audit records on the
`result` field directly:

- `local_invalid_credentials` — local-auth wrong-password / unknown
  username. *(Local-only; no metric counterpart.)*
- `local_locked_out` — local-auth lockout flag was active.
  *(Local-only; no metric counterpart.)*
- `invalid_token` — OIDC `Malformed` / `SignatureInvalid` /
  `ClaimMissing(_)`, or fallback for non-OIDC errors that surface
  from `authenticate_bearer`. *(Joins 1:1 with the metric.)*
- `expired` — OIDC `Expired`. *(Joins 1:1 with the metric.)*
- `unknown_issuer` — OIDC `UnknownIssuer`. *(Joins 1:1 with the
  metric.)*
- `idp_unavailable` — OIDC `IdpUnavailable`. *(Joins
  1:1 with the metric.)*
- `missing_header` — no `Authorization` header (or empty Bearer).
  *(Joins 1:1 with the metric.)*

The above strings are normative in the audit-event payload. The two
`local_*` values have no metric counterpart by design (the metric
covers the bearer-auth path; the local path is deprecated
bootstrap-only). All other values join 1:1 with
`hort_auth_attempts_total{result=...}`.

### Brute-force lockout on `authenticate_local` — **REMOVED**

`hort_auth_lockouts_total` and `hort_auth_lockout_total` were removed by
the producer-side cleanup that deleted `authenticate_local` and the
`AuthenticateUseCase::lockout` machinery they emitted from (the orphan
emitter helpers left `hort_app::metrics` and this catalog section at the
same time). The PAT-side bearer-path brute-force protection
(`PatValidationUseCase`, distinct mechanism) is unchanged; PAT lockout is
observable via `result="rate_limited"` on `hort_api_token_validation_total`
(see that metric's catalog entry).

### Persisted `is_admin` transition

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_is_admin_transition_total` | counter | `result` | — | `granted`, `revoked` |

Emitted by `hort-app::use_cases::authenticate_use_case` at the OIDC
recompute+persist site (`maybe_emit_admin_transition`), once per
persisted `User.is_admin` **flip**. The login path recomputes
`is_admin` from the IdP `groups` claim and persists it on every OIDC
login. This counter is observability only: a transient IdP outage
/ empty-groups response silently mutates the durable bit, and a
spurious flip must be visible to operators. The durable per-user
attribution (who, which IdP `sub`) lives in the companion
`AdminStatusChanged` domain event on the per-user stream
(`StreamId::user(user_id)`), not in this metric.

**`result` semantics:**

- `granted` — the bit flipped `false → true` (admin authority gained).
- `revoked` — the bit flipped `true → false` (admin authority lost).

**Emission discipline (no `unchanged` value by design).** The counter
fires **only** on an actual flip of an *existing* user row. A
JIT-provisioned user (no prior durable bit — first login sets an
initial value, it is not a transition) and an idempotent recompute
that leaves the bit unchanged (the common case — admins stay admins)
emit nothing at all. The metric counts transitions, not logins, so a
spurious flip stands out instead of being buried under per-login
volume. The `info!` log and this metric are unconditional once a flip
is observed; only the durable `AdminStatusChanged` append is
best-effort (an event-store error does not fail the OIDC login).

**Cardinality:** rank-1 in `result` (two values, fixed taxonomy).
`user_id` / `external_id` do NOT appear as labels (per-principal
dimensions are the architect's high-cardinality hard-block); they live
in the `AdminStatusChanged` event payload.

### JWKS refresh

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_jwks_refresh_total` | counter | `issuer`, `result` | — | `success`, `throttled`, `fetch_failed`, `body_too_large`, `parse_error`, `apply_warmup_failed` |

Emitted by `hort-adapters-oidc` on every JWKS refresh attempt + every
signature-mismatch eviction decision. Covers the forged-kid-flood DoS
mitigation (throttled refresh) and the body-cap hardening (oversize
upstream response → rejected before parsing).

**`issuer` label:**

- `<user-login>` — the sentinel emitted by the single-issuer
  user-login validation path (`OidcProvider`), which configures one
  issuer at startup, so there is no meaningful `OidcIssuer.name` to
  thread through; the sentinel keeps the multi-issuer dashboard
  interpretable when both code paths share `hort_jwks_refresh_total`. The
  `<` / `>` characters are forbidden by k8s DNS-1123 subdomain regex,
  so the sentinel cannot collide with an operator-declared
  `OidcIssuer.name`.
- `<OidcIssuer.name>` — the per-CRD issuer name for refreshes driven by
  the federation validator (`MultiIssuerJwksValidator`). One
  series per declared trusted issuer.

Cardinality is bounded by the operator's `OidcIssuer` CRD count + 1
for the user-login sentinel. Typical deployments have 1–10 trusted
issuers; the workspace ceiling for the `issuer` label is conservatively
held at the same level as the `repository` label's "10k max" — well
under any plausible operator scale.

**`result` semantics:**

- `success` — discovery + JWKS fetched within the body cap, parsed, and
  the in-memory cache was replaced. Also emitted on first-seen kid
  refetches (legitimate key rotation).
- `throttled` — a same-kid signature-mismatch eviction arrived within the
  `HORT_JWKS_EVICTION_BACKOFF_SECS` window (default 10 s). Cache is left
  intact, no upstream request fires. Bounded audit evidence for
  forged-kid flood detection. `KidNotInCache` evictions NEVER emit this —
  they always refresh. Currently fires only on the single-issuer
  user-login path; the multi-issuer federation validator does not
  implement per-kid eviction backoff (the forged-kid threat model
  does not apply because the federation path mints short-lived bearers,
  not session tokens).
- `fetch_failed` — discovery or JWKS HTTP request failed (transport
  error, non-2xx status, stream read error). Cache stays stale; the
  triggering request 401s (user-login path) or denies with `unknown_kid`
  (federation path — the JWKS unavailability surfaces in the deny
  taxonomy as "no key for this kid"). Log level: `warn!`.
- `body_too_large` — upstream response exceeded
  `HORT_JWKS_RESP_BODY_MAX_SIZE` (size string, default `1Mi`). Body is discarded
  un-parsed; the DoS vector (malicious IdP returns unbounded body to
  OOM hort-server) is closed. Log level: `warn!` with `bytes_read` and
  `cap` in span attrs.
- `parse_error` — bytes were received within the cap but failed
  JSON parsing (malformed discovery document or malformed JWKS).
- `apply_warmup_failed` —
  apply-time best-effort JWKS warm-up failed. Emitted by
  `MultiIssuerJwksValidator::refresh_issuer_impl` when invoked via
  `RefreshContext::ApplyWarmup` from
  `ApplyConfigUseCase::apply_oidc_issuers` after persisting a new or
  updated `OidcIssuer` row. Collapses every underlying failure mode
  (network error, body cap, parse error) so operator dashboards
  separate "the gitops apply pushed a config that the IdP can't
  serve" from "the IdP went down during normal serving"
  (`fetch_failed` / `body_too_large` / `parse_error`). **The apply
  proceeds; federation works lazily via the cache-miss path on first
  request.** Only the runtime `validate()` path emits the granular
  failure variants. Log level: `warn!`.

Cardinality: 6 series × (1 user-login sentinel + N trusted issuers).
For typical deployments (1–10 issuers): 6–66 series per scrape target.

Catalog source of truth for the `result` label values lives in
`crates/hort-adapters-oidc/src/metrics.rs::JwksRefreshResult` — adding a
variant requires updating this catalog in the same PR. The `issuer`
label values are not enumerable at catalog-time (one per
operator-declared `OidcIssuer.name` + the user-login sentinel); the
catalog declares the SHAPE only.

### OIDC key rotation observation

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_oidc_key_rotation_total` | counter | `result` | — | `success`, `failure` |

Emitted by `hort-adapters-oidc::OidcProvider` only when
`JwksCache::replace` actually changes the cached kid set — a no-op
TTL-driven refresh against a stable IdP does NOT emit. Supplements
the pre-existing `hort_jwks_refresh_total` (which fires on every
refresh attempt, irrespective of whether the key set changed) so a
SIEM can answer "how often did the IdP actually rotate" without
having to compare consecutive `success` counts.

**`result` semantics:**

- `success` — the rotation was observed AND the [`OidcKeyRotated`]
  domain event was successfully appended to the per-UTC-date
  auth-attempts stream (the documented stream choice — see
  `crates/hort-domain/src/events/auth_events.rs::OidcKeyRotated` doc
  comment for the smallest-blast-radius rationale). Also the value
  emitted on minimal deployments where no event-store is wired into
  the OIDC adapter (the rotation-count metric still reflects the
  observation; the immutable audit record is missing).
- `failure` — the rotation was observed but the audit append failed
  (event store down, optimistic-concurrency conflict on the daily
  stream, etc.). The rotation observation is NOT lost — the metric
  fires — but the durable audit record did not land. Operators
  should correlate this against `hort_event_store_*` failure counters.

Cardinality: 2 series per scrape target.

Catalog source of truth for the `result` label values lives in
`crates/hort-adapters-oidc/src/metrics.rs::OidcKeyRotationResult` —
adding a variant requires updating this catalog in the same PR.

### RBAC snapshot refresh

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_rbac_snapshot_reloads_total` | counter | `result` | — | `success`, `unchanged`, `failed` |

Emitted by `hort-server::cli::rbac_refresh::refresh_once` — invoked once
per poll of the role/grant snapshot by the background task spawned in
[`hort-server::cli::serve`](../crates/hort-server/src/cli/serve.rs).

**`result` semantics:**

- `success` — the DB snapshot differed from the last-swapped snapshot;
  the `Arc<ArcSwap<RbacEvaluator>>` held in `AuthContext::Enabled.rbac`
  was atomically replaced. Companion `tracing::info!` carries
  `added_roles` / `removed_roles` / `added_grants` / `removed_grants`
  counts — NEVER the role names or grant tuples (cardinality control +
  PII-adjacency; role names may encode department identifiers).
- `unchanged` — the DB snapshot matched the last-swapped snapshot; the
  pointer was not touched, readers keep the current snapshot. No log
  beyond `tracing::debug!`.
- `failed` — `RoleRepository::list_all_roles` or
  `list_grants_for_roles` returned an error. The previous snapshot is
  retained (stale-but-safe; no fail-open, no fail-closed — running
  requests continue to authorize against the last known good state).
  Companion `tracing::warn!` with the full error chain.

**Structural diff semantics.** A "diff" is over the set of
`role_id`s plus the set of `(role_id, repository_id_or_none,
permission)` grant keys. Grant uuids are NOT part of the key: re-seeding
an identical grant with a new uuid registers as `unchanged`. Role name
changes with a preserved id also register as `unchanged` — renaming a
role is a cosmetic op and should not flood dashboards.

Cardinality: 3 series per replica. Flat, well under any ceiling. Same
shape as `hort_jwks_refresh_total`.

**Poll cadence.** Controlled by `HORT_RBAC_REFRESH_SECS` (default 30).
Initial jitter in `[0, 5000) ms` desyncs replicas that share a Postgres
so they don't all hit the snapshot queries on the same edge
(thundering-herd mitigation).

### Claim-based RBAC

| Metric | Type | Labels | Unit | Description |
|---|---|---|---|---|
| `hort_dispatcher_principal_resolved_total` | counter | `source ∈ {snapshot_present, snapshot_empty_admin, snapshot_empty_no_admin}` | — | One increment per principal synthesis in the subscription-delivery dispatcher. 3-series. `snapshot_present` = `subscription.snapshot_claims` was non-empty and was used as the evaluation claim set; `snapshot_empty_admin` = `snapshot_claims` empty but the owner carries the admin bit (evaluates with admin authority); `snapshot_empty_no_admin` = `snapshot_claims` empty and owner is not an admin — the operator diagnostic for "subscription created via PAT by a non-admin user" (such a subscription can never match a claims-scoped grant). |
| `hort_apply_config_linter_total` | counter | `rule`, `result ∈ {pass, warn, reject}` | — | One increment per evaluated lint subject per rule. The subject depends on the rule: `single-claim-grant` / `direct-user-grant-without-justification` / `wildcard-repo-non-admin` / `claim-name-collision` fire per `PermissionGrant`; `trust_upstream_publish_time_requires_scan_backends` fires per `RepositoryUpstreamMapping` (the ADR 0016 cross-opt-in rule); `prefetch_max_age_days_not_implemented` fires per `PrefetchPolicy`-on-repository (the ADR 0015 inert-field rule). `rule` is one of the fixed lint-rule keys: `single-claim-grant`, `direct-user-grant-without-justification`, `wildcard-repo-non-admin`, `claim-name-collision`, `trust_upstream_publish_time_requires_scan_backends`, `prefetch_max_age_days_not_implemented` — cardinality is fixed at the rule count (6). `result`: `pass` = subject satisfied the rule (or the rule did not apply to this shape); `warn` = rule flagged the subject but the configured action is non-blocking (apply continues, CI surfaces the warning); `reject` = rule rejected the subject and the gitops apply fails. Max series = 6 rules × 3 results = 18. |
| `hort_effective_permissions_lookups_total` | counter | `result ∈ {ok, denied, not_found}` | — | One increment per call to the admin effective-permissions endpoint (`GET /api/v1/admin/users/:user_id/effective-permissions`). 3-series. `ok` = admin caller, inspected user resolved, view returned; `denied` = `require_admin()` rejected the caller (emitted before the early return; the inspected user was never resolved); `not_found` = caller was admin but the inspected `user_id` did not resolve to a user row. |

Emitted by
[`hort_app::metrics::emit_dispatcher_principal_resolved`](../crates/hort-app/src/metrics.rs)
(from the subscription-delivery dispatcher),
[`hort_app::metrics::emit_apply_config_linter`](../crates/hort-app/src/metrics.rs)
(from the `ApplyConfigUseCase` linter), and
[`hort_app::metrics::emit_effective_permissions_lookup`](../crates/hort-app/src/metrics.rs)
(from the effective-permissions use case).
Each label value set is bounded by a closed enum
(`DispatcherPrincipalSource`, `LinterResult`,
`EffectivePermissionsResult`) — adding a variant forces a deliberate
catalog update. The `rule` label is `&'static str` at the
emission-site signature so a free-form / operator-authored string
cannot reach it; the rule keys are compile-time constants at the
Item-10 emission site.

**No `claim_name`, `group_name`, `user_id`, `subscription_id`,
`inspected_user_id`, `grant_id`, or `owner_user_id` labels.** Claim
and group names are operator-authored and may carry organisational
topology; per-identity / per-grant detail belongs in `info!` /
`debug!` tracing spans and audit events. Counts only.

### Native API token issuance + revocation

| Metric | Type | Labels | Unit | Values |
|--------|------|--------|------|--------|
| `hort_api_token_issued_total` | counter | `kind`, `result` | — | `kind` ∈ {`pat`, `svc`, `cli`}; `result` ∈ {`success`, `cap_exceeds_authority`, `admin_disallowed`, `validation_error`} |
| `hort_api_token_revoked_total` | counter | `actor_kind` | — | `self`, `admin` |

Emitted by `hort-app::use_cases::api_token_use_case::ApiTokenUseCase`
exactly once per public-method invocation:

- `hort_api_token_issued_total` fires from the
  [`issue_self_token`](../crates/hort-app/src/use_cases/api_token_use_case.rs)
  and [`issue_for_service_account`](../crates/hort-app/src/use_cases/api_token_use_case.rs)
  public wrappers — every Ok and Err arm goes through one
  `emit_issued_metric` call. The wrapper pattern keeps the metric
  off every internal `return Err(…)` site (one wrapper, one emit).
- `hort_api_token_revoked_total` fires only on
  [`ApiTokenUseCase::revoke`](../crates/hort-app/src/use_cases/api_token_use_case.rs)
  success — after the repo `revoke()` call AND the
  `ApiTokenRevoked` event have been appended. Failure paths
  (`TokenNotFound`, `NotAuthorized`, infrastructure) deliberately
  do NOT increment; the metric counts successful revocations only.

**`kind` semantics** (mirrors the on-the-wire token prefixes): `pat`
for self-mint PATs, `svc` for admin-mint service-account tokens
(`ServiceAccount` schema-side, `svc` on the wire), `cli` for
`cli_session` tokens minted by the token-exchange path.

**`result` semantics** for `hort_api_token_issued_total` (source of
truth: `crates/hort-app/src/use_cases/api_token_use_case.rs::issuance_result_label`):

- `success` — `Ok(IssuedToken)`. Token persisted, `ApiTokenIssued`
  event appended.
- `cap_exceeds_authority` — declared permissions exceed the
  caller's grants on at least one (repo, permission) tuple.
  Carries `ApiTokenError::CapExceedsAuthority { failed }`; per-
  tuple detail lives in the `ApiTokenIssuanceDenied` event payload,
  not the metric.
- `admin_disallowed` — every reject path tied to admin-token
  gating: `AdminTokenDisallowed` (flag off), `AdminAuthorityRequired`
  (caller not admin), `AdminTokenExceedsThirtyDays` (out of
  `[1, 30]`), `AdminTokenUnboundedNotAllowed` (admin token without
  explicit expiry). One bucket because operators page on "admin
  token issuance attempted and refused" — the typed reason is in
  the denial event for SOC drill-down.
- `validation_error` — every other Err arm: `ServiceAccountSelfMint`,
  `UnboundedSvcTokenDisallowed`, `InvalidRepositorySet`,
  `NotServiceAccount`, `NotAuthorized`, `TokenNotFound`,
  `NameEmpty`/`NameTooLong`, `DescriptionTooLong`,
  `ExpiryZero`/`ExpiryTooLong`, `Infrastructure`. Catch-all bucket
  for malformed-input and authorization-shape rejects; per-error
  detail is in tracing spans + the `ApiTokenIssuanceDenied` event
  on the four denial-emitting paths.

**`actor_kind` semantics** for `hort_api_token_revoked_total`:

- `self` — caller's `user_id` equals the token's `user_id`. The
  default self-revoke path (`DELETE /users/me/tokens/:id`).
- `admin` — caller has admin authority AND the token belongs to a
  different user. The admin-revoke path
  (`DELETE /admin/tokens/:id`); same `user_id` self-revoke under
  admin authority still counts as `self`.

Cardinality: 3 `kind` × 4 `result` = 12 series for `hort_api_token_issued_total`;
2 `actor_kind` series for `hort_api_token_revoked_total`. Both closed
taxonomies.

**No `token_id`, `user_id`, `repo_id`, `repository_name`, or
`scope_string` labels.** Per the anti-pattern checklist —
per-token / per-user detail belongs in tracing spans (the
`token_id` / `actor_user_id` / `target_user_id` fields) and in the
`ApiTokenIssued` / `ApiTokenRevoked` / `ApiTokenIssuanceDenied`
event payloads, not metric labels.

### Native API token validation

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_api_token_validation_total` | counter | `result`, `cache` | — | `success`, `expired`, `revoked`, `user_deactivated`, `prefix_not_found`, `hash_mismatch`, `rate_limited` |
| `hort_api_token_validation_duration_seconds` | histogram | `result` | seconds | `success`, `expired`, `revoked`, `user_deactivated`, `prefix_not_found`, `hash_mismatch`, `rate_limited`, `infrastructure_error` |

Emitted by `hort-app::use_cases::pat_validation_use_case::PatValidationUseCase::validate_pat`
exactly once per validation attempt. The metric is the LAST step
before returning on every code path (cache hit, lockout
short-circuit, every miss-path outcome) so the increment cannot
become a covert timing oracle on the constant-time invariant.

**`result` semantics** (source of truth:
`crates/hort-app/src/use_cases/pat_validation_use_case.rs::ValidationMetric`):

- `success` — the token validated cleanly. Distinguished further by
  `cache` (see below).
- `expired` — `expires_at` is in the past. Hits both the cache-hit
  and miss paths; cache TTL revalidates expiry on every read.
- `revoked` — `revoked_at` is set. Same dual-path emission.
- `user_deactivated` — `users.is_active = false` for the token's
  owner. Re-resolved live on every validation.
- `prefix_not_found` — sentinel-verify path; no row matched the body
  prefix. Indistinguishable in wall time from `hash_mismatch` (the
  Argon2 verify ran either way) — only the metric label differs.
- `hash_mismatch` — prefix matched but the hash did not.
- `rate_limited` — per-IP brute-force lockout flag was set; Argon2
  verify was NOT called. Always `cache="miss"` because lockout
  decisions never come from the validation cache.

**`cache` label values:**

- `hit` — pinned to `result=success` only. The validator only caches
  successful validations (negative-cache is forbidden; caching
  `prefix_not_found` / `hash_mismatch` would itself be a timing
  oracle).
- `miss` — every other (`result`, `cache`) tuple. `success/miss` is
  the post-Argon2-verify cache-write path.

Cardinality: 7 `result` values × 2 `cache` values, but only one
`(success, hit)` and one `(success, miss)` pair are reachable on
the success arm — the other 5 result values pair only with `miss`.
Live cardinality: **7 `miss` series + 1 `hit` series = 8 series per
deployment** under the closed taxonomy. The catalog count of 14
above reflects the full grid for completeness; auditors should
count 8 in a steady-state scrape.

#### `hort_api_token_validation_duration_seconds`

Recorded by
`hort-app::use_cases::pat_validation_use_case::PatValidationUseCase::validate_pat`
around the **entire** validation closure (not just the verify call):
the window includes the metric increment itself — but every code path
increments exactly one counter, so the path lengths are equal. This
wrapping makes the
histogram a useful operator signal (P50/P99 of total validation cost,
including cache lookups + lockout consults) AND preserves the
constant-time invariant — the counter increment lives inside the
window so its CPU cost cannot become a covert timing oracle.

Default histogram buckets (from the `metrics` crate's recorder)
apply; hort-app does not override them. This is consistent with the
existing `hort_*_duration_seconds` histograms in the workspace
(`hort_download_duration_seconds`, `hort_ingest_duration_seconds`).

**`result` semantics** (source of truth:
`crates/hort-app/src/use_cases/pat_validation_use_case.rs::validation_duration_result_label`):

- `success` — `Ok(ApiTokenValidation)` on either the cache-hit or
  the post-verify cache-miss path.
- `expired`, `revoked`, `user_deactivated`, `prefix_not_found`,
  `hash_mismatch`, `rate_limited` — same wire forms as
  `hort_api_token_validation_total` (the histogram does NOT carry the
  `cache` label; cache hit/miss is already split on the counter and
  duplicating it on the histogram would inflate the per-bucket
  sample count without operational benefit).
- `infrastructure_error` — `PatValidationError::Infrastructure` (no
  corresponding row on the counter — Infrastructure short-circuits
  before any of the labeled paths). Operators alarm on a sustained
  climb here as "validation is hitting an outbound port outage,
  not a credential-shape issue."

Cardinality: 8 `result` series per deployment. No
`token_id`/`user_id`/`repo_id`/`repository_name`/`scope_string`
labels — same anti-pattern discipline as the counter.

### Token exchange

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_token_exchange_total` | counter | `kind`, `result` | — | `kind ∈ {cli_session, federated_jwt}` (`refresh` reserved for a future refresh-token phase). `result ∈ {success, source_token_invalid, source_token_expired, source_token_pat_rejected, idp_unavailable, bad_request, subject_not_authorised, cap_exceeds_authority, validation_error, infrastructure_error}` for `kind = cli_session`; `result ∈ {success, invalid_format, unknown_issuer, algorithm_not_allowed, unknown_kid, signature_invalid, aud_mismatch, expired, not_yet_valid, no_sa_match, multiple_sa_match, mint_failed, internal_error, bad_request}` for `kind = federated_jwt`. The per-kind sets are disjoint except for `success` and `bad_request` (shared wire-shape errors). |
| `hort_token_exchange_duration_seconds` | histogram | `kind`, `result` | seconds | same set as the counter |
| `hort_session_admin_issuance_total` | counter | `result` | — | `granted`, `denied_flag`, `denied_authority`, `denied_lifetime` |
| `hort_fed_sa_match_total` | counter | `result` | — | `matched`, `denied_audience`, `denied_empty_claims` |

Emitted by the `POST /api/v1/auth/exchange` handler in
`crates/hort-http-core/src/handlers/exchange.rs` exactly once per
request — both the counter and the histogram fire from a single
wrapper at the end of the handler so every exit path (success,
each error code, the catch-all infrastructure arm) records a
duration sample AND increments the counter on the way out. RFC
8693 §2.1 / §2.2.1 / §2.4 are the wire contract.

**`result` semantics** (source of truth:
`crates/hort-http-core/src/handlers/exchange.rs::metrics`):

- `success` — `/exchange` returned 200 with a freshly-minted
  `kind = 'cli_session'` token. Pairs with the
  `hort_api_token_issued_total{kind="cli", result="success"}`
  increment from the issuance pipeline (the two metrics count
  different things — see "Relationship to issuance metric" below).
- `source_token_invalid` — narrowed to OIDC
  validation rejects only: `OidcValidationError::{UnknownIssuer,
  Malformed, SignatureInvalid, ClaimMissing}`. Maps to HTTP 401
  `invalid_token`. Credential-abuse signal — the IdP token is
  forged, stale, or signed by an issuer Hort does not trust. The
  label deliberately excludes RFC 6749 wire-shape errors
  (`bad_request`) and post-validation 403 rejects
  (`subject_not_authorised`); collapsing all three onto one label
  would mean dashboards filtering on `source_token_invalid` could
  not distinguish credential abuse from buggy clients from
  RBAC-denial noise.
- `source_token_expired` — `OidcValidationError::Expired`
  specifically. Distinguished from `source_token_invalid` because
  it correlates with normal user behaviour (re-login on expiry),
  not credential abuse.
- `source_token_pat_rejected` — PAT-shape gate fired (the
  `subject_token` parsed as `hort_(pat|svc|cli)_<base32>`).
  Security-relevant counter; an upward trend may indicate a
  confused client trying to chain a PAT into a `cli_session`,
  which is explicitly unsupported.
- `idp_unavailable` — `OidcValidationError::IdpUnavailable` (JWKS
  / discovery fetch failed). Operator-actionable IdP outage
  signal. Also fires on the (composition-bug) path where the
  handler is reached with `AuthContext::Disabled`.
- `bad_request` — RFC 6749 wire-shape rejection: form parse
  failure, missing or wrong `grant_type`, missing or wrong
  `subject_token_type`, invalid `requested_token_type`,
  content-type mismatch. Maps to HTTP 400 with the appropriate
  OAuth `error` code (`unsupported_grant_type` / `invalid_request`
  / `invalid_target`). NOT a security signal — buggy clients,
  not credential abuse. A sustained climb here typically means a
  client (most commonly `hort-cli` itself or a CI-side wrapper)
  is constructing the form body wrong. Distinct from
  `source_token_invalid` (narrowed to OIDC validation rejects,
  the credential-abuse signal).
- `subject_not_authorised` — IdP-validated user rejected by
  the resource-server side post-validation: deactivated user
  (`is_active=false`), no role mapping for the JIT-resolved
  groups, or any other `AppError::Domain` / `AppError::Unauthorized`
  surfaced by `authenticate_bearer`. Maps to HTTP 403
  `access_denied`. Distinct from `cap_exceeds_authority`
  (which fires later in the flow, during `issue_cli_session`'s
  cap-vs-grants check) and from `source_token_invalid` (forged
  or stale IdP token). The three-way distinction lets dashboards
  separate "the IdP issued a token to someone we no longer trust"
  from "the IdP token is technically forged" from "we trust the
  user but they don't have grants on any repository."
- `cap_exceeds_authority` — `ApiTokenUseCase::issue_cli_session`
  rejected the issuance because the resolved user's role + grant
  set does not cover the hardcoded `[Read, Write, Delete]`
  declaration. Caller-side denial (the user's IdP token is valid
  and they exist, but their grants are insufficient for a
  `cli_session` token). Maps to HTTP 403 `access_denied`. NOT an
  outage signal — typically indicates a misconfigured
  `group_mapping` leaving the JIT user without `Read` / `Write` /
  `Delete`. Aligns with
  `hort_api_token_issued_total{kind="cli", result="cap_exceeds_authority"}`
  on the issuance metric.
- `validation_error` — `ApiTokenUseCase::issue_cli_session`
  returned a defensive validation error (`NameTooLong`,
  `DescriptionTooLong`, `InvalidRepositorySet`,
  `AdminTokenDisallowed`, etc.) that should not reach this code
  path because `issue_cli_session` hardcodes safe values for
  every input it controls. An increment indicates a server-side
  regression in the hardcoded-safe-value contract — dashboard-
  alertable. Maps to HTTP 500 `server_error` with the literal
  `"internal validation error"` body so internal taxonomy is not
  leaked on the wire. Aligns with
  `hort_api_token_issued_total{kind="cli", result="validation_error"}`.
- `infrastructure_error` — **reserved for
  `ApiTokenError::Infrastructure(_)` from
  `ApiTokenUseCase::issue_cli_session` only** (true downstream
  outage: event store, DB, secret port). Also fires on the
  catch-all `Err(_)` arm of the `authenticate_bearer` match
  (e.g. `AppError::Infrastructure`). Operator-actionable outage
  signal. Caller-side denials (`cap_exceeds_authority`) and
  defensive validation errors (`validation_error`) are NOT
  collapsed into this bucket — doing so generates false
  positives on outage dashboards. Reviewer-checked invariant.

Cardinality: 2 `kind` values (`cli_session`, `federated_jwt`) × ~14
distinct `result` values per kind (10 unique to `cli_session`,
14 unique to `federated_jwt`, with `success` and `bad_request`
shared) ≈ **~24 series per metric**, ~48 series
total across the two metrics. Closed taxonomy. (Operator dashboards
keyed on the historical label-less form of this metric stopped
incrementing when the `kind` label landed; add `kind=~".+"` filters
when upgrading. The disjoint-except-for-`success`-and-`bad_request`
rule keeps cardinality sub-linear in the number of kinds.)

A future refresh-token phase extends the `kind` label with `refresh` —
its `result` variants land alongside the emitting change (ADR 0013
records the CLI-session token direction).

**`kind = "federated_jwt"`** covers the federation
branch — the foreign-IdP JWT exchange path that mints a
`TokenKind::ServiceAccount` bearer. Its `result` taxonomy:

- `success` — JWT validated, exactly one `ServiceAccount` matched,
  short-lived bearer minted. Pairs with an
  `hort_api_token_issued_total{kind="svc", result="success"}` increment
  carrying `source_issuer / source_jti / source_sub` on the
  `ApiTokenIssued` event payload.
- `invalid_format` — `FederatedJwtValidator::validate` rejected the
  JWT before issuer lookup (bad base64, malformed payload JSON,
  missing `kid` / `alg`, etc.). Maps to HTTP 401 `invalid_grant`.
- `unknown_issuer` — `iss` claim did not match any trusted
  `OidcIssuer` row. Operator-actionable: declare the issuer via
  GitOps or fix the issuing platform's `iss` claim.
- `algorithm_not_allowed` — JWT header `alg` is not in
  `OidcIssuer.allowed_algorithms`. Pre-cryptographic gate; signature
  is never verified.
- `unknown_kid` — `kid` not in the issuer's JWKS after refresh.
  Operator-actionable: rotate the issuer's JWKS or refresh the cache.
- `signature_invalid` — signature failed verification. Distinct from
  `unknown_kid`: the key exists but the signature does not validate.
- `aud_mismatch` — `aud` claim does not intersect
  `OidcIssuer.audiences`.
- `expired` — `exp` in the past (with configured leeway).
- `not_yet_valid` — `nbf` in the future (with configured leeway).
- `no_sa_match` — JWT validated but no `ServiceAccount` matches the
  validated claims. Operator-actionable: declare a `ServiceAccount`
  with `federatedIdentities[].claims` covering this JWT shape.
- `multiple_sa_match` — JWT validated but multiple `ServiceAccount`s
  matched. Configuration error (silently picking one would be a
  footgun). INFO log additionally
  surfaces the matched SA names via `sa_candidates = ...`.
- `mint_failed` — JWT and SA validated, but the system-mint pipeline
  rejected the request (typed `ApiTokenError`). Distinct from
  `internal_error` so operator dashboards separate caller-side
  mint-gate denials from outages.
- `internal_error` — defensive catch-all: the validator port returned
  an unexpected error, SA listing failed, the federation ports are
  unwired (composition bug). Maps to HTTP 500 / 503.
- `bad_request` — RFC 6749 wire-shape rejection on the federation
  branch (typically `requested_token_type ≠ access_token`). Shared
  label with the `cli_session` branch — distinguished by the `kind`
  label.

The federation branch never emits the `cli_session` branch's labels
(`source_token_invalid`, `source_token_pat_rejected`, `idp_unavailable`,
`subject_not_authorised`, `cap_exceeds_authority`, `validation_error`,
`infrastructure_error`) and vice versa — `kind` is the discriminator.

**`hort_fed_sa_match_total{result}`**:
emitted by the federation SA-resolution step in
`crates/hort-http-core/src/handlers/exchange.rs` (the `collect_sa_matches`
call site). This is a SEPARATE metric from `hort_token_exchange_total`,
not a relabelling: the exchange counter classifies the protocol-level
outcome of the whole `/exchange` request (and keeps emitting
`no_sa_match` / `multiple_sa_match` exactly as before — the HTTP
contract is unchanged), whereas `hort_fed_sa_match_total` isolates the
SA-selection security decision so a reviewer can see
audience-confusion denies and empty-claims fail-closed skips
without disentangling them from the broader `no_sa_match` bucket.
`{result}`-only label, closed taxonomy:

- `matched` — exactly one `ServiceAccount` was selected (the only
  outcome that proceeds to mint). Emitted once per successful
  resolution.
- `denied_audience` — a `FederatedIdentity`
  pinned an `aud` claim selector that did not equal the
  validator-resolved audience (`ValidatedClaims.audience`, the single
  audience `match_audience` already intersected against
  `OidcIssuer.audiences`), and that audience binding was the *sole*
  reason no SA matched. The confused-deputy / token-redirection
  vector — a JWT minted for a different relying party whose
  other claims happen to satisfy the fragment. The protocol outcome on
  `hort_token_exchange_total` stays `no_sa_match` (401 `invalid_grant`);
  this counter carries the audience-denial-specific signal.
- `denied_empty_claims` — a `FederatedIdentity`
  row carried an empty `claims` map and that fail-closed skip was the
  *sole* reason no SA matched. Apply-time validation rejects this shape
  and migration 011 carries a DB CHECK, so a `{}`
  row reaching the runtime matcher means an out-of-band write (raw SQL
  / restore / pre-CHECK row). The empty exact-match set is
  vacuously-true (`[].iter().all() ⇒ true`) and would otherwise let
  any JWT from the issuer assume the SA — the runtime matcher and the
  `TryFrom<FederatedIdentityRow>` row-decode both fail closed. A
  structured `info!` (audit, not `err`) accompanies the skip. Protocol
  outcome on `hort_token_exchange_total` stays `no_sa_match`.

Cardinality: closed, exactly 3 series (`matched`, `denied_audience`,
`denied_empty_claims`). No `username`/`issuer`/`sa_name`/`aud`-value
labels — per-instance attribution lives in the structured `info!`
deny log and the existing audit events.

**`hort_session_admin_issuance_total{result}`**:
operator-visible counter on admin-cap CliSession issuance attempts.
Emitted exclusively by `ApiTokenUseCase::issue_cli_session` when the
request includes `Permission::Admin` in `requested_scope` — non-admin
issuance does not increment. Distinct from `hort_token_exchange_total`
(the exchange-protocol outcome) — this metric counts the
issuance-gate decision for admin scope specifically, so security
reviewers can correlate it against the `AdminTokenDisallowed` /
`AdminAuthorityRequired` denial-event audit trail and against
hort-cli's `--admin` invocations. Closed taxonomy of four result
values: `granted` (Ok), `denied_flag`
(`HORT_TOKEN_ALLOW_ADMIN=false`), `denied_authority` (caller is not
admin), `denied_lifetime` (clamp_lifetime returned
`LifetimeBelowMinimum`). Other failure modes (CapExceedsAuthority,
NameTooLong, Infrastructure) do NOT increment this counter — they
belong to the broader `hort_api_token_issued_total`. Cardinality: 4
series, closed.

**No `username`, `user_id`, `client_id`, `source_ip`, or
`external_id` labels.** Per-instance audit lives in tracing
spans (the `info!` on success and the security-relevant
`info!` on PAT-shape rejection) and in the `ApiTokenIssued`
event payload from the issuance pipeline, NOT
in metric labels. The `client_id` form field would be especially
unsafe as a label — clients can set it arbitrarily.

**Relationship to `hort_api_token_issued_total{kind="cli"}`:** the
two metrics count different stages of the same flow.
`hort_token_exchange_total` covers the exchange-path-specific
gates (form parsing, grant_type, PAT-shape, IdP validation) AND
the success pairing; `hort_api_token_issued_total{kind="cli"}` is
the per-issuance-pipeline metric and fires inside
`issue_cli_session` for every Ok and Err arm. On a 200 response,
BOTH increment exactly once: `hort_token_exchange_total{result="success"}`
AND `hort_api_token_issued_total{kind="cli", result="success"}`.
On a PAT-shape rejection or IdP failure, only
`hort_token_exchange_total` increments — `issue_cli_session` is
never called. On a cap-vs-grants issuance reject (rare —
typically a misconfigured group_mapping leaving the JIT user
without Read/Write/Delete), BOTH increment with the same label:
`hort_token_exchange_total{result="cap_exceeds_authority"}` AND
`hort_api_token_issued_total{kind="cli", result="cap_exceeds_authority"}`.
(Collapsing every `ApiTokenError` variant — including
`CapExceedsAuthority` — into `infrastructure_error` would generate
false-positive outage alerts; the buckets are split so the metrics
align across the two emission sites.)

### Federated-JWT replay guard

The federation branch of `/auth/token-exchange` is **public by
requirement**. Before any `ServiceAccount` bearer is
minted, the token-exchange use case atomically claims the presented
JWT's identity in the durable `jwt_replay_seen` seen-set. A replay
(second presentation of the same `jti`, or the `(iss,sub,iat,exp)`
composite when the issuer opted into `require_jti=false`) is denied with
no token minted. This counter is the operator-visible signal that a
captured JWT is being replayed.

| Metric | Type | Labels | Unit | Notes |
|--------|------|--------|------|-------|
| `hort_jwt_replay_rejected_total` | counter | `result` | rejections | One increment per detected replay. `result ∈ {replayed_jti, replayed_composite}` — exactly these two values, a per-metric closed enum mirroring `ReplayKey::replay_result_label` in `hort-domain`. `replayed_jti` = the JWT carried a `jti` and that `(issuer_name, jti)` was already in the seen-set; `replayed_composite` = the issuer is `require_jti=false` and the `(issuer_name, iss, sub, iat, exp)` composite was already seen. |

**Single emitter (architect "one metric, one layer, no double-count"):**
emitted **only** at the `hort-app` token-exchange use-case guard call
site (`crates/hort-app/src/use_cases/api_token_use_case.rs`,
`issue_for_service_account_system_inner`), once, exactly when
`ReplayGuardPort::claim` returns `Replayed`. The `hort-domain` port is
pure and emits nothing; the `hort-adapters-postgres` adapter emits
nothing (it logs the infra cause of an *outage* at `error!`, not a
metric); the `hort-http-core` handler does not re-emit it.

**Deliberately NOT on this counter** (no replay was *detected*, so they
would pollute the closed 2-value enum): `jti_required` (a pre-guard
validation deny — the issuer requires a `jti` and none was present, or
the composite was not constructible) and `replay_guard_unavailable`
(the fail-CLOSED 503 when the seen-set is unreachable). Both ride the
existing `hort_token_exchange_total{kind="federated_jwt", result=…}`
counter under those exact `result` values, keeping the federation deny
taxonomy unified exactly as the validator deny reasons already are.
Cardinality is fixed at ≤ 2 series here; adding any other label or
value is FORBIDDEN (per-metric closed-enum rule).

**Alert spec:** any `increase(hort_jwt_replay_rejected_total[5m]) > 0` is a
security-relevant event (a still-valid foreign JWT is being replayed
against the public mint surface) — surface it. A sustained climb in
`hort_token_exchange_total{kind="federated_jwt", result="replay_guard_unavailable"}`
means the seen-set backing store is down and every federation exchange
is failing closed (correct, but operator-actionable).

### OCI Distribution-Spec /v2/auth token exchange

| Metric | Type | Labels | Unit | Values |
|--------|------|--------|------|--------|
| `hort_oci_v2_auth_total` | counter | `result` | — | `full_grant`, `partial_grant`, `no_grant`, `invalid_scope`, `invalid_credential` |
| `hort_oci_v2_auth_scope_actions_granted_total` | counter | `action` | — | `pull`, `push`, `delete` |
| `hort_oci_auth_verify_total` | counter | `result` | — | `ok`, `service_mismatch`, `denied` |

Emitted by `hort-app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase`
— `hort_oci_v2_auth_total` once per `/v2/auth` request,
`hort_oci_v2_auth_scope_actions_granted_total` once per *granted*
action across all scopes in the request.

`hort_oci_auth_verify_total` is the
**verify-outcome** axis across BOTH the mint (`/v2/auth` —
`exchange`) and consume (`/v2/*` bearer — `verify_inbound`) paths,
emitted at `hort-app` (the layer that owns the verify decision — one
metric, one layer, no double-count). It is **orthogonal** to
`hort_oci_v2_auth_total` (grant breadth, mint-only): they answer
different questions (verify success vs grant breadth) and are both
retained. The `service_mismatch` outcome short-circuits before
grant evaluation, which is precisely why it has no
`hort_oci_v2_auth_total` equivalent.

**`hort_oci_auth_verify_total` `result` semantics** (source of truth:
`crates/hort-app/src/use_cases/oci_token_exchange_use_case.rs::VerifyResultLabel`):

- `ok` — a verify entrypoint succeeded: the **mint** path PAT
  validated + JWT minted, **OR** the **consume** path returned
  `OciVerifyOutcome::Verified`.
- `service_mismatch` — the pre-validation service gate fired (mint path only):
  the inbound `?service=` did not match the configured
  `OciTokenExchangeConfig.jwt_audience`. The 400 was returned; no PAT
  validated, no JWT minted. The requested/expected hosts are in the
  structured audit log (`event="oci_v2_auth_denied"`), never a label.
- `denied` — mint path: PAT invalid / scope invalid / mint failure.
  Consume path: `OciVerifyOutcome::Rejected` (expired / wrong aud).
  `OciVerifyOutcome::NotOurToken` is **NOT** counted `denied` — it is
  a fall-through to the IdP validator, not a denial (counting it
  would double-count against the IdP path's own telemetry).

Cardinality: 3 `result` series per deployment. No
`user_id`/`repository`/`service`/`scope` labels (architect
high-cardinality anti-pattern — per-instance detail belongs in
tracing spans / audit events).

Emitted by `hort-app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase::exchange`
on every `/v2/auth` request — `hort_oci_v2_auth_total` once per
request, `hort_oci_v2_auth_scope_actions_granted_total` once per
*granted* action across all scopes in the request.

**`result` semantics** (source of truth:
`crates/hort-app/src/use_cases/oci_token_exchange_use_case.rs::ResultLabel`):

- `full_grant` — every requested action across every scope was
  granted. The minted JWT carries a complete `access[]` matching the
  request.
- `partial_grant` — at least one action was granted AND at least one
  was denied. The JWT's `access[]` is the granted subset; entries
  with zero granted actions are omitted entirely (Distribution-Spec
  convention — the client treats the missing entry as "no grant on
  that resource").
- `no_grant` — zero actions granted (either every scope was denied,
  or no scopes were requested). The JWT is still minted with an
  empty `access[]` and is anonymous-equivalent.
- `invalid_scope` — at least one scope failed to parse against the
  Distribution-Spec grammar (missing colons, unknown resource_type,
  unknown action, or wildcard resource_name). Increments BEFORE
  PAT validation so a deterministic 400 surfaces without spending
  Argon2 cycles on broken scope strings.
- `invalid_credential` — every `PatValidationError` variant collapses
  here. The handler maps to 401 with the Bearer challenge re-emitted.

**`action` semantics** (closed enum — Distribution-Spec wire actions):

- `pull` — the user was authorised for a pull (mapped to
  `Permission::Read` internally).
- `push` — Permission::Write. Per spec, push implies pull, so a
  push grant is always paired with a pull grant on the same scope;
  this metric counts each granted action separately.
- `delete` — Permission::Delete.

Cardinality: 5 `result` values × 1 metric + 3 `action` values × 1
metric = 8 series total. Effectively flat; bounded by the closed
enums.

**No `token_id`, `user_id`, `scope_string`, `repository_name`, or
`repository_id` labels.** Per the anti-pattern checklist —
per-token / per-user / per-repo-name detail belongs in tracing
spans, not metric labels.

### Fallback PAT rotation reconciler

These metrics are emitted by
[`ServiceAccountRotationHandler::run`](../crates/hort-app/src/task_handlers/service_account_rotation.rs)
once per SA per reconciler tick. The handler is registered with the
worker dispatcher when both `KubernetesSecretWriter` wires successfully
(in-cluster auth or kubeconfig present) AND `HORT_PUBLIC_REGISTRY_HOST`
is set. Non-k8s deployments emit zero series.

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_rotation_total` | counter | `result` | — | `result ∈ {rotated, skipped_fresh, collision, namespace_not_authorized, mint_failed, write_failed}` |
| `hort_rotation_lag_seconds` | gauge | `service_account` | seconds | `service_account` is the SA's CRD `metadata.name`; cardinality bounded by the operator-declared SA count with `fallbackRotation:` set (typically <50). Disable per-SA breakdown via `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` — the gauge then emits `service_account="_all"` and operators retain only the aggregate. |
| `hort_service_account_authenticated_total` | counter | `service_account`, `source` | — | `source ∈ {federated, pat}`. `federated` is the federation branch on `/auth/token-exchange`; `pat` is `authenticate_pat` for `TokenKind::ServiceAccount` tokens. `service_account` is the SA's CRD `metadata.name` — cardinality bounded by the operator's CRD count (typically <50). Honours `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` the same as `hort_rotation_lag_seconds` — both metrics collapse to `service_account="_all"` when the toggle is off, so the rotation gauge and the auth counter stay in lock-step under operator-flipped cardinality control. |

Source of truth for the result enum:
- `hort_app::metrics::RotationResult` for `hort_rotation_total.result`.
  Adding a variant requires updating this catalog in the same change.
- `hort_app::metrics::SA_AUTH_SOURCE_FEDERATED` /
  `SA_AUTH_SOURCE_PAT` for the `source` label on
  `hort_service_account_authenticated_total`. Two values only;
  adding a third requires this catalog edit in the same change.

**`hort_rotation_total` result semantics** (closed taxonomy of 6; one
emission per ServiceAccount per reconciler tick):

- `rotated` — fresh PAT minted, target Secret written, audit event
  appended.
- `skipped_fresh` — existing Secret's `project-hort.de/last-rotated`
  annotation is within `rotation_interval` of now; no work needed.
- `collision` — existing Secret's `project-hort.de/managed-by` label is NOT
  `"hort-worker"` (operator-created, ArgoCD-managed, etc.). The
  reconciler refuses to overwrite; operator must `kubectl delete
  secret` to hand off management.
- `namespace_not_authorized` — the SA's
  `fallbackRotation.targetSecret.namespace` is not in the worker's
  `HORT_ROTATION_TARGET_NAMESPACES` set. Defence-in-depth against an SA
  pointing at an out-of-policy namespace.
- `mint_failed` — `ApiTokenUseCase::issue_for_service_account_system`
  returned an error (infrastructure, name/expiry shape, etc.). The
  tick continues with the next SA.
- `write_failed` — `KubernetesSecretWriter::read_managed` or
  `upsert_managed` returned an error, OR the post-write event append
  failed. The minted PAT (if any) persists in `api_tokens` and the
  next tick will see the stale Secret state and retry.

**`hort_rotation_lag_seconds` semantics** — set per SA on each
decide-branch that successfully reads the existing Secret. Fresh
rotations pass `0`; fresh-skip passes the observed `now -
last_rotated` age. Operators alarm on
`max_over_time(hort_rotation_lag_seconds[15m]) > rotation_interval +
grace` to detect a stuck reconciler. The `namespace_not_authorized`
branch short-circuits BEFORE the Secret is read, so it does NOT
update the gauge — the per-SA series simply does not advance for
SAs the worker isn't permitted to write.

Cardinality:
- `hort_rotation_total`: 6 result values → 6 series.
- `hort_rotation_lag_seconds`: ≤ N series where N is the
  operator-declared count of `ServiceAccount` CRDs with
  `fallbackRotation:` set (typically <50). At scale, disable the
  per-SA label with `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false`.
- `hort_service_account_authenticated_total`: ≤ M × 2 where M is the
  operator's total SA count (with OR without `fallbackRotation:`)
  and 2 is the `source` taxonomy. Same toggle, same `_all` sentinel.

Neither metric carries `token_id`, `user_id`, or
target Secret coordinates (`namespace`, `name`) as labels. Per-tick
per-SA detail goes in `tracing::info!` / `tracing::warn!` fields with
the SA's `service_account_name` and `token_id`.

Source: `hort_app::metrics::{emit_rotation_result,
set_rotation_lag_seconds, emit_service_account_authenticated,
RotationResult, SA_AUTH_SOURCE_FEDERATED, SA_AUTH_SOURCE_PAT,
SERVICE_ACCOUNT_ALL}`.

---

### Ingest / download / quarantine (use case layer)

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_ingest_total` | counter | `format`, `repository`, `result` | — | `success`, `duplicate`, `conflict`, `validation_error`, `storage_error`, `repository_not_found`, `metadata_too_large`, `registered_by_hash`, `declared_hash_mismatch`, `wheel_metadata_extract_failed` |
| `hort_ingest_duration_seconds` | histogram | `format` | seconds | — |
| `hort_ingest_size_bytes` | histogram | `format` | bytes | — |
| `hort_ingest_metadata_strategy_total` | counter | `format`, `strategy` | — | `strategy` ∈ `inline`, `hash_reference` |
| `hort_download_total` | counter | `format`, `repository`, `result` | — | `success`, `quarantined`, `rejected`, `not_found`, `storage_error` |
| `hort_download_audit_dropped` | counter | `format`, `repository`, `result` | — | `append_error` |
| `hort_api_token_used_audit_dropped` | counter | `result` | — | `throttled`, `append_error` |
| `hort_download_duration_seconds` | histogram | `format` | seconds | — |
| `hort_quarantine_triggered_total` | counter | `format`, `repository` | — | — |
| `hort_quarantine_released_total` | counter | `reason` | — | `reason` ∈ `timer`, `admin`, `policy_re_evaluation` |

**`IngestResult` semantics:**

- `success` — new content stored, event emitted
- `duplicate` — same hash at same path, early return (idempotent retry)
- `conflict` — different hash at same path (collision)
- `validation_error` — invalid coords, invalid format, malformed input
- `storage_error` — backend I/O failure (propagated from `StoragePort`)
- `repository_not_found` — caller supplied a non-existent `repository_id`
- `metadata_too_large` — `payload_metadata` serialized length exceeded
  the effective per-format cap (three-layer cap model).
  Distinct from `validation_error` so operators can alert on
  metadata-cap pressure without conflating with coords-shape issues.
- `registered_by_hash` — `IngestUseCase::register_by_hash` attached a
  pre-existing CAS object to the target repository by its hash without
  re-streaming bytes. Primary emitter is the OCI cross-repo
  blob mount (`POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<src>`).
  Dashboards treat this as a distinct operation from `success` because
  the storage- and network-cost profile is materially different — no
  new CAS write, no bandwidth to the client, just a metadata row + a
  new `ArtifactIngested` event pointing at the existing hash.
- `declared_hash_mismatch` — caller supplied `declared_sha256` on
  `IngestUseCase::ingest`, the fresh-insert path wrote the body to
  CAS, and the computed hash disagreed with the declared one. The use
  case returns `DomainError::Conflict` and rolls the CAS blob back
  via `StoragePort::delete` when no other row references the hash
  (rollback-skipped when shared; the uncommitted blob in that case
  is reaped by `CasScrubUseCase`). Split out
  from `conflict` so dashboards can distinguish
  client-supplied-wrong-hash (upstream integrity-contract violation)
  from the classic same-path-different-content collision.
- `wheel_metadata_extract_failed` — the PyPI wheel ingest
  succeeded and `ArtifactIngested` is durable, but the post-commit
  `FormatHandler::extract_wheel_metadata_bytes` call
  returned a `DomainError::Validation` — typically the wheel's
  `<dist-info>/METADATA` exceeds the 1 MiB cap, or the entry header
  claims a size that violates the cap before bytes are even read. The
  wheel itself remains downloadable and indexable; ONLY the PEP 658
  advertisement is suppressed for this wheel (the simple-index omits
  `data-dist-info-metadata`, pip falls back to whole-wheel download
  for `Requires-Dist` reads). Non-fatal by design; tick exists so
  operators can dashboard pathological wheels. Emitted in addition
  to (not instead of) the per-ingest result tick — a successful wheel
  ingest with an oversized METADATA ticks both `success` (or
  `duplicate`) AND `wheel_metadata_extract_failed`.

No `not_found` variant — `NotFound` on ingest can ONLY mean the repository
is missing, which is an upstream caller bug. Naming it `repository_not_found`
avoids conflating with the generic domain `NotFound`.

`hort_ingest_size_bytes` is emitted on **both** `success` and `duplicate`
(the size is known in both cases — from `PutResult` on success, from the
existing artifact on duplicate). Not emitted on errors (size is unknown
or incomplete).

**`hort_ingest_metadata_strategy_total` semantics:**

- Fires ONLY on successful `commit_transition` with a non-null
  `payload_metadata`. A null payload (proxy fetches, handlers that have
  nothing to extract) does NOT tick the counter — the metric answers
  "how many ingests persisted payload metadata via each strategy", not
  "how many tried". Failed ingests do NOT tick either.
- `strategy` values track what **actually happened**, not what the
  handler declared:
  - `inline` — full payload landed in the event + projection row
    verbatim. Emitted by Inline-strategy handlers AND by
    HashReference-strategy handlers whose payload stayed under the
    inline threshold (no split → no CAS blob → `inline`).
  - `hash_reference` — full payload was written to CAS and only the
    handler-extracted summary lives in the event + projection row.
    Emitted only on an actual split.

**`hort_download_audit_dropped` semantics:** emitted by
`ArtifactUseCase::download` on the **fail-open drop
path only** — when the served repository opted into download auditing
(`download_audit_enabled = true`) but the `ArtifactDownloaded`
event-store append failed. The download is still served (fail-open),
a `tracing::warn!(audit_write_failed=true, …)` accompanies it, and this
counter ticks `result="append_error"`. A *successful* audit append
produces NO metric and NO log (the served-download path is high-volume;
the opt-in flag is the volume control, not a counter). `hort_download_total`
is independent — it still records the served download regardless of the
audit outcome.

**`hort_api_token_used_audit_dropped` semantics:** emitted by
`PatValidationUseCase::validate_pat`'s wrapper on
the **non-append** outcomes of the throttled per-use token-use audit
emit, on the validation success path only. `result` is the ONLY label
(token use has no `format` / `repository` dimension, and
`user_id` / `token_id` are forbidden unbounded-cardinality
dimensions — the per-instance detail lives in the accompanying
`tracing` span). Two values:

- `throttled` — the per-`token_id` 1-hour throttle suppressed the
  append. This is the **expected steady state** for any actively used
  token (a hot CI token used thousands of times per hour produces one
  `ApiTokenUsed` event per hour and `throttled` on every other use);
  the throttle is the volume control, NOT an error. **Operators must
  not alert on `throttled`.**
- `append_error` — the throttle was won but the `ApiTokenUsed`
  event-store append failed. The validation still returned `Ok`
  (fail-open); a `tracing::warn!(audit_write_failed=true, …)`
  accompanies this increment.

A *successful* audit append produces NO metric and NO log (the
validation path is the auth hot path; routine-success info would
dominate). `hort_api_token_validation_total` /
`hort_api_token_validation_duration_seconds` are entirely independent —
the emit happens in the `validate_pat` wrapper *after* the duration
metric, best-effort; an audit throttle/append outcome never perturbs
the validation counters or the validation `Result`.

### Mutable-ref write path

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_ref_moved_total` | counter | `repository`, `result` | — | `created`, `moved`, `retired`, `no_op` |

### Artifact-group write path

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_artifact_groups_created_total` | counter | `repository`, `format` | — | — |
| `hort_artifact_group_members_added_total` | counter | `repository`, `format`, `role` | — | `role` ∈ `pom`, `jar`, `sources`, `javadoc`, `signature`, `sha256`, `md5`, `mod`, `zip`, `info`, `manifest`, `config`, `layer`, `deb`, `dsc`, `changes`, `orig`, `other` |

Emitted by `hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase`
on successful `add_member` calls (first placement for the `_created`
counter; every accepted member add for the `_members_added` counter).
The source of truth for the `role` enumeration is
`hort_app::metrics::GroupMemberRole`; adding a variant requires updating
this catalog in the same PR. Unknown roles (a handler declares a
role outside this taxonomy) collapse to `other` via
`GroupMemberRole::classify` — the raw string never reaches the
label, so cardinality stays bounded.

**Emission semantics:**

- A concurrent-create race loser does NOT tick either counter on its
  first attempt; the retry that attaches to the winner's group emits
  the `_members_added` counter (once), not `_created` (the winner
  already emitted it).
- An idempotent same-role re-add (same `(group_id, artifact_id, role)`)
  does NOT tick — the adapter short-circuits without appending
  events and the use case skips the emit.
- A primary-role-assign race loser returns `DomainError::Conflict`
  without ticking either counter — the whole transaction rolled back.

**`repository` label** follows the same sentinel rules as the other
use-case metrics: `_all` when `METRICS_INCLUDE_REPOSITORY_LABEL=false`,
`unknown` when the caller did not supply a key, otherwise the resolved
repository key. See [Sentinel label values](#sentinel-label-values).

Cardinality: 18 `role` values × ~10 `format` values × `repository`
cardinality. Well under the per-metric ceiling — the `other` fallback
guarantees the `role` axis cannot drift.

### Group-membership reconciliation sweep

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_group_reconcile_total` | counter | `repository`, `result` | — | `healed`, `already_linked`, `handler_declined`, `event_read_error` |

Emitted by
`hort_app::use_cases::group_reconcile_use_case::GroupReconcileUseCase`
once per processed `ArtifactIngested` event during an
operator-triggered sweep (`hort-server reconcile-groups`). Source of
truth for the `result` enum:
`hort_app::metrics::GroupReconcileResult`. Adding a variant requires
updating this catalog in the same PR.

**`result` semantics:**

- `healed` — the artifact was unlinked when the sweep observed it;
  the handler's `classify_group_member` returned a membership and the
  synthetic `ArtifactGroupMemberAdded` commit via
  `ArtifactGroupUseCase::add_member` succeeded. One increment per
  orphan fixed.
- `already_linked` — the handler returned a membership but
  `ArtifactGroupRepository::find_by_member` reported the artifact was
  already attached to a group. No synthetic event was emitted.
- `handler_declined` — covers three shapes that the metric treats
  identically (dashboard operators read tracing to disambiguate):
  1. no handler is wired for the event's format (e.g. a Maven event
     observed while only pypi/cargo/npm handlers are compiled in),
  2. the wired handler returned `None` from `classify_group_member`
     (single-file formats — PyPI sdist, Cargo `.crate`),
  3. the artifact's `Artifact` or `Repository` row could not be
     looked up (stale event feed / deleted artifact).
- `event_read_error` — covers two distinct infrastructure hazards
  that share this bucket by design:
  1. the event store's `read_category` call for a page returned an
     error; the sweep advances past the failing page (incrementing
     `from` by one) and continues.
  2. the `add_member` call for a single unlinked artifact failed;
     the sweep continues to the next event.

  Disambiguate via tracing `warn!` lines: `stage="read_category"` vs
  `stage="add_member"` vs `stage="find_by_member"`. The metric answers
  "how many events did the sweep fail to act on for reasons beyond
  its control?"; the tracing answers "which layer faulted?". Folding
  commit failures into this bucket (rather than introducing a fifth
  `commit_error` label) keeps the result taxonomy at its accepted
  four values.

**`repository` label** follows the standard sentinel rules: `_all`
when `METRICS_INCLUDE_REPOSITORY_LABEL=false`, `unknown` when the
repository row cannot be resolved for the event, otherwise the
resolved repository key. See [Sentinel label values](#sentinel-label-values).

Cardinality: 4 `result` values × `repository` cardinality. Bounded.

Emitted by `hort_app::use_cases::ref_use_case::RefUseCase` on every
`set` and `retire` call. Source of truth for the `result` enum:
`hort_app::metrics::RefMetricResult`. Adding a variant requires updating
this catalog in the same PR.

**`result` semantics:**

- `created` — `set` placed a ref for the first time. `RefMoved { from:
  None, to }` was appended and the `mutable_refs` projection row was
  inserted.
- `moved` — `set` re-pointed an existing ref at a different target.
  `RefMoved { from: Some(prior), to }` was appended and the projection
  row was updated.
- `retired` — `retire` deleted an existing ref. `RefRetired { last_target
  }` was appended and the projection row was removed.
- `no_op` — `set` was called with a target matching the current row's
  target; neither the event log nor the projection row was touched. The
  adapter's in-transaction `FOR UPDATE` re-read is the authoritative
  race defence; the use case's read-then-compare is an optimisation. The
  metric records the outcome, not which layer caught it.

**`repository` label** follows the same sentinel rules as the other use
case metrics: `_all` when `METRICS_INCLUDE_REPOSITORY_LABEL=false`,
`unknown` when the caller did not supply a key, otherwise the resolved
repository key. See [Sentinel label values](#sentinel-label-values).

Cardinality: 4 results × `repository` cardinality = well under ceilings.

### Content-reference index queries

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_content_reference_queries_total` | counter | `format`, `repository`, `result` | — | `success`, `not_found`, `digest_invalid`, `error` |

Emitted exactly once per call by the OCI Referrers-API handler
(`hort-http-oci::referrers::serve` — `GET /v2/<name>/referrers/<digest>`,
spec §referrers-api). The metric is generic (the table backing it
serves any future hash-reference query path), but the only emitter
today is the OCI handler — hence the `format="oci"` label value.

**`result` label semantics:**

- `success` — the handler emitted a 200 response. Per spec, this
  fires regardless of whether the response body listed zero or many
  manifests. Empty results are 200 with `manifests: []`, NEVER 404
  (a 404 would create an enumeration oracle); the counter therefore
  attributes "an empty response" to a successful query, not a
  not-found one.
- `not_found` — the repository lookup returned
  `DomainError::NotFound`. The handler emits 404 `NAME_UNKNOWN`. The
  `repository` label carries the requested key the operator asked
  for (cardinality stays bounded by operator-controlled repo keys
  even on misses; no client-supplied unbounded value reaches the
  label).
- `digest_invalid` — `digest_str` failed to parse. Covers both the
  malformed (`DigestParse::Invalid`) and well-formed-but-unsupported
  (`DigestParse::Unsupported`, e.g. `sha512:...`) branches; the
  HTTP envelope distinguishes them via `DIGEST_INVALID` vs.
  `UNSUPPORTED` codes, but the metric collapses both into one
  `result` value because both are client-input rejections at the
  same handler stage.
- `error` — any other infrastructure failure: a transient repo
  lookup error, a `ContentReferenceIndex::find_by_target` adapter
  error, or a transient `ArtifactRepository::find_by_id` error
  while resolving a referrer's source artifact. The handler
  emits 500 `INTERNAL`. Companion `tracing::error!` carries the
  full error chain.

The `repository` label honours the workspace-wide
`METRICS_INCLUDE_REPOSITORY_LABEL` toggle.

### Stateful upload sessions

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_stateful_upload_sessions_total` | counter | `format`, `repository`, `result` | — | `created` (Item 1); `aborted` (Items 2, 3); `finalized` (Item 3) |
| `hort_stateful_upload_session_bytes` | histogram | `format`, `repository` | bytes | — |
| `hort_stateful_upload_finalize_duration_seconds` | histogram | `format`, `repository` | seconds | — |

Emitted by format-specific upload-session coordinators in each
`hort-http-<format>` crate when a three-phase / chunked upload session
transitions state. First emitter is
`hort-http-oci::upload_session::initiate` (OCI
blob upload). The `format` axis future-proofs the metric for Maven
chunked PUT and Git LFS batch transfer — same shape, different
`format` label value.

**`result` label semantics:**

- `created` — a new upload session row was persisted to
  [`EphemeralStore`](../crates/hort-domain/src/ports/ephemeral_store.rs).
  Fires once per successful `initiate`. Does NOT fire on
  infrastructure failures (Redis error, bincode-encode failure) or on
  the cosmic-ray `put_if_absent` collision path — those paths surface
  as errors and the session counter stays at its previous value so
  operators see a session-creation-rate drop rather than a misleading
  spike.
- `aborted` — fires exactly once on every unrecoverable PATCH / PUT
  exit path. Emitting sites (PATCH + PUT):
  - `Content-Range` start did not match session `bytes_received` —
    `AppError::RangeInvalid` → HTTP 416.
  - `Content-Range` span disagreed with `Content-Length` —
    `AppError::BodyLengthMismatch` → HTTP 400.
  - Projected total would exceed the configured max-blob-bytes cap —
    `AppError::SizeExceeded` → HTTP 413.
  - Optimistic-concurrency CAS miss (concurrent PATCH won) —
    `DomainError::Conflict` → HTTP 400.
  - Session missing (unknown UUID, TTL-expired, or tenant-mismatch) —
    `DomainError::NotFound` → HTTP 404.
  - Infrastructure failure (EphemeralStore/staging adapter errored,
    bincode-decode corruption) — `DomainError::Invariant` → HTTP 500.
  - **(PUT)** Declared-digest mismatch after the streamed
    content was rehashed. `IngestUseCase::ingest`
    rolls back the CAS blob before returning `DomainError::Conflict`;
    `upload_session::finalize` then drops the session + staging and
    surfaces the Conflict as the `aborted` outcome. HTTP 400
    `DIGEST_INVALID`.

  Successful PATCH does NOT emit. The catalog reserves this counter
  for terminal-state transitions; a per-chunk `progressed` variant
  was deliberately not introduced — the PATCH cadence on a multi-GB
  push can reach thousands per session, and the dashboard signal is
  covered by `hort_http_requests_received_total{path="/v2/:repo_key/*tail"}`.
- `finalized` — fires once per successful PUT finalize. The
  session + staging are deleted as part of the successful exit;
  `IngestUseCase::ingest` has already committed the
  `ArtifactIngested` event + CAS blob. Infrastructure errors between
  ingest commit and session-row delete (the `warn!`-log path in
  `finalize`) do NOT change this terminal label — the artifact is
  durable and the orphaned session is reaped by the
  staging-orphan GC sweep.

The `repository` label honours the workspace-wide
`METRICS_INCLUDE_REPOSITORY_LABEL` toggle — the `_all` sentinel
applies when the label is disabled or the target repo lookup fails.

**Bytes + duration histograms.**

- `hort_stateful_upload_session_bytes` — observes the final
  `bytes_received` on every `finalized` session (OCI blob size in
  bytes). Labels mirror the counter's `format` + `repository`. Only
  recorded on success; `aborted` finalizes do NOT record a
  size observation because the "bytes" an abort produced is
  semantically ambiguous (chunks landed in staging but no blob was
  committed; reporting them would inflate the success distribution).
- `hort_stateful_upload_finalize_duration_seconds` — wall-clock from
  `finalize` method entry to return, recorded on **every** exit path
  (success AND failure). Covers the optional trailing-body PATCH if
  the client folded the last chunk into the PUT. Operators use this
  to dashboard finalize latency independently of the bulk of
  PATCH-time latency. `IngestUseCase::ingest`'s own
  `hort_ingest_duration_seconds` histogram covers the CAS-put +
  event-append sub-slice; this metric is a superset that additionally
  covers session + staging cleanup.

The bytes + duration histograms are distinct from the sessions
counter so operators can query size-distribution and latency SLOs
independently of terminal-state counts. Quantiles (p50 / p95 / p99)
on both histograms are the primary dashboards.

**No `hort_oci_pushes_total` double-emission.** `IngestUseCase::ingest`
fires its own `hort_ingest_total{format="oci"}` terminal counter on
every finalize — both success and failure paths. `finalize` does NOT
emit a parallel OCI-specific push counter; the combination
`hort_ingest_total` (success rate) + `hort_stateful_upload_sessions_total`
(session-level lifecycle) covers the dashboard space without
splitting the `format="oci"` attention across three metrics.

### OCI session-cap rejections

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_oci_session_cap_rejections_total` | counter | `repo`, `result` | — | `over_cap` |

Emitted by `hort-http-oci::upload_session::initiate` when the
per-`(repo, principal)` outstanding-session counter would exceed the
cap configured via `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL` (default 32).
The handler maps the rejection to `429 Too Many Requests` with the
OCI `TOOMANYREQUESTS` envelope; the cap counter naturally TTL-cleans
on the same window as `OCI_SESSION_TTL`.

**`repo` cardinality.** Same shape as the workspace-wide
`repository` label — bounded by the registry's repo count. Honours
`METRICS_INCLUDE_REPOSITORY_LABEL`: emits `_all` when disabled,
`unknown` on lookup failure (cardinality-safe sentinels). Named
`repo` (not `repository`); the name is pinned — renaming a label is
a breaking dashboard change. Operators dashboard both axes the same
way.

**`result` value space.** Reserves room for future variants (e.g.
`window_pressure` if a sliding-window rate-limit is added) but
emits only `over_cap` today — that's the lone rejection branch the
cap currently produces.

**No `principal_id` / `user_id` / `actor_id` label.** The architect
catalog forbids these as cardinality vectors. Per-principal abuse
investigation goes through tracing spans (`upload_session_initiate`
carries `repository_id` and the principal id is in the tracing
context) and the audit-event log, not the metrics surface.

### Staging-orphan sweep

| Metric | Type | Labels | Unit |
|--------|------|--------|------|
| `hort_stateful_upload_staging_orphans_cleaned_total` | counter | `format` | — |

Emitted by the staging-orphan sweep task once per orphaned staging
entry it deletes. **The sweep is a worker task** — the `StagingSweepHandler`
`TaskHandler` (`hort_app::task_handlers::staging_sweep`), not an
in-process `hort-server` scheduler; cadence is
driven by an external k8s CronJob (or operator host cron) POSTing
`/api/v1/admin/tasks/staging-sweep`, NOT an `HORT_STAGING_SWEEP_INTERVAL_SECS`
timer (that knob no longer exists; the historical 300 s default is now
the documented CronJob `schedule:`). Each tick reaps
`stateful_upload_staging` filesystem entries whose matching
`EphemeralStore` session key has already TTL'd out.

The metric has **no `result` axis** by design: every emission
represents exactly one successful orphan deletion. Errors during the
sweep (failed `list`, failed individual `delete`) are logged at
`warn!` / `error!` and do not increment any counter — the next sweep
tick retries the same entries.

**No `expired` variant on `hort_stateful_upload_sessions_total`.** TTL
eviction in the ephemeral store is silent: the in-memory adapter's
evictor and Redis's native TTL both drop expired keys without
notifying the application. Counting "expirations" would either
require polling the ephemeral side (defeats the point of TTL) or
inferring from this orphan-cleaned counter (an orphaned staging
entry implies an expired session, but the converse is not true —
sessions can expire without ever creating a staging file).

`format` cardinality is bounded by the format taxonomy in the
architectural-direction doc (~40 known formats). Today the
sweep emits only `format="oci"`; future formats with chunked upload
(Maven chunked PUT, Git LFS batch transfer) will pass their own
format token through `staging_sweep::session_key`.

### Staging-sweep liveness

| Metric | Type | Labels | Unit | Values |
|--------|------|--------|------|--------|
| `hort_staging_sweep_overdue` | gauge | — (no labels) | Boolean (0/1) | `0` = a `staging-sweep` job completed within the staleness window; `1` = overdue OR never ran |

Emitted **once at boot** by `hort-server::composition` (the
`emit_staging_sweep_liveness_signal` fn, mirroring the
`emit_pat_over_http_signal` / `evaluate_test_clock_guard` boot-signal
precedents). The composition root queries the newest `completed_at`
for a `kind='staging-sweep' AND status='completed'` row
(`JobsRepository::last_completed_at_by_kind`), feeds it through the
pure `hort_domain::policy::evaluate_staging_sweep_liveness` predicate,
and sets the gauge: `0.0` when a sweep completed within
`HORT_STAGING_SWEEP_STALENESS_MULTIPLIER × HORT_STAGING_SWEEP_EXPECTED_INTERVAL_SECS`
(defaults `3 × 300 s`), `1.0` when overdue or when no sweep has ever
completed. A `warn!` is logged on both the overdue and never-ran
paths naming the remediation (enable the `staging-sweep` CronJob —
`scheduledTasks.adminTasksEnabled=true` + `scheduledTasks.stagingSweep.enabled=true`
— or run `hort-cli admin task staging-sweep`).

**Why a boolean, why no labels, why boot-only.** `hort-server` is
deliberately scheduler-free (no in-process `tokio::time` scheduler);
a periodic in-process re-check would re-introduce exactly that
scheduler (architecturally forbidden — the scheduler-free
`hort-server` is load-bearing). The gauge is therefore set once at
boot and scraped continuously; operators alarm with
`max_over_time(hort_staging_sweep_overdue[6h]) > 0`, the same
boot-emit-then-Prometheus-alarms shape the other boot signals use. A
boolean (not a `_staleness_seconds`) is chosen deliberately: the value
is a boot-time snapshot, so a continuously-decaying seconds gauge
would be misleading between restarts, whereas the boolean correctly
reflects "as of the last boot, the sweep was/was not overdue" and is
the directly-actionable alert signal. **No labels** — there is one
global staging area per deployment; a per-anything label would be
unbounded-by-construction with no analytical value. The metric is
emitted on the healthy path too (`0.0`) so a fresh scrape always sees
the series (absence vs `0.0` is ambiguous to dashboards), matching the
`hort_unsafe_config_active` convention.

### Quarantine-aware index serve

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_index_versions_filtered_total` | counter | `format`, `repository` | — | — |

**`hort_index_versions_filtered_total` semantics:**

Emitted by the per-format index/metadata serve path on every served packument/index that drops at least one upstream version per the `IndexMode` filter (`ReleasedOnly` or `IncludePending`). The increment is the **count of versions filtered out** (`upstream_versions - served_versions`), not "1 per serve" — operators read versions/sec at the rate the filter is suppressing them. Not emitted when the filter drops zero versions (steady state for repos where every advertised version has been ingested and released, or for packages with no upstream rows to drop).

Labels:

- `format` — one of `npm`, `pypi`, `cargo`, `maven` (the remaining SimpleIndex formats join the set as their serve paths gain the filter).
- `repository` — the served repository key (subject to `METRICS_INCLUDE_REPOSITORY_LABEL`; falls back to the `_all` / `unknown` sentinels per the global rules).

No per-version or per-package label — those would explode cardinality per the *Forbidden labels* rule. Per-package context (`package`, the resolved `index_mode`, and raw upstream + served counts) lives in the accompanying `tracing::info!` event on the same code path.

The metric is emitted at the per-format serve site (npm: `hort-http-npm/src/packument.rs::rewrite_packument`; pypi/cargo/maven: their analogues), each with `format` set to the format literal. The `hort-app` `filter_served_versions` helper is format-agnostic and intentionally does NOT emit — the format is a per-call-site fact, mirroring the established `hort_ingest_*` / `hort_download_*` pattern.

### Prefetch triggers

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_prefetch_enqueued_total` | counter | `repository`, `trigger` | — | `trigger` ∈ `on_dist_tag_move`, `scheduled` (a historical `on_index_fetch` value is retired and no longer emitted) |
| `hort_prefetch_skipped_total` | counter | `repository`, `reason` | — | `reason` ∈ `disabled`, `trigger_not_enabled`, `already_held`, `not_newer` |

Both counters are emitted by
`hort_app::use_cases::prefetch_use_case::PrefetchUseCase::plan` —
the format-agnostic planner consumed by the per-format index/metadata
serve sites (`hort-http-npm/src/packument.rs::fire_prefetch_trigger_npm`,
`hort-http-cargo/src/index_cache.rs::fire_prefetch_trigger`). The planner
diffs the upstream version set against Hort's
`package_version_status` rows and emits the two counters below. The catalog
intentionally does NOT include a `format` label — the trigger surface is
operator-policy-driven (per-repository), and a per-format breakdown is
inferrable from `repository` (which maps 1:1 to `format` via the
`repositories` projection). Mirrors the `hort_pull_dedup_*` /
`hort_quarantine_*` shape; `format` is reserved for metrics where the
emission site genuinely carries cross-format meaning
(`hort_index_versions_filtered_total`, the pull-through counters).

**`hort_prefetch_enqueued_total` semantics** (per-version increment):

Emitted once per upstream version the planner adds to its return list.
The increment is `1` per planned version, not `1` per call — operators
read versions/sec at the rate the planner is selecting them for
warming. The format crate (npm / cargo in Item 7; PyPI in Item 7b)
iterates the returned plan and spawns
`tokio::spawn(try_upstream_<format>_pull(...))` per version; the spawn
itself rides `PullDedup`, so a concurrent client pull of the
same version collapses to a single upstream fetch (the dedup is
invisible to this counter — it ticks at *plan* time, not at *fetch
completion* time). For PyPI specifically the per-version spawn fans
out to one [`try_upstream_file_pull`](crates/hort-http-pypi/src/upstream_pull.rs)
call per distribution file in the per-version JSON manifest (sdist + N
wheels per version); the manifest fetch + per-file pulls all route
through the shared `PullDedup`.

Trigger label values:

- `on_dist_tag_move` — fired when the upstream's mutable-tag pointer
  (npm's `dist-tags.latest`; cargo's upstream-newest version, the
  implicit "latest" any unconstrained `cargo install` resolves to;
  PyPI's bare `pip install` resolution target — the newest served
  version per `Pep440Ordering`, since PyPI has no native dist-tags)
  points at a version Hort does not hold. Routes through the same
  planner; an enabled-both operator does not double-pull (the second
  call sees an in-flight pull via the artifacts catalog's
  `already_held` arm, or dedups inside the spawn).
- `scheduled` — emitted by the scheduled prefetch tick
  (`hort-app::task_handlers::prefetch_tick::PrefetchTickHandler`).

**`hort_prefetch_skipped_total` semantics** (per-reason increment):

Emitted at the planner; covers every reason a version (or whole call)
did not enter the returned plan. Each `reason` value increments by `1`
per skip:

- `disabled` — `prefetch_policy.enabled = false`. Emitted once per
  call (not per version) at the planner's top short-circuit.
  **In v1 this branch is unreachable from production**: every
  Item-7 / Item-8 call site pre-checks
  `prefetch_policy.enabled` before invoking the planner
  (`hort-http-npm/src/packument.rs::fire_prefetch_trigger_npm`,
  `hort-http-cargo/src/index_cache.rs::fire_prefetch_trigger`,
  `hort-app::task_handlers::prefetch_tick`). The planner-side check
  is defense-in-depth; the counter does not increment in
  production. The reason is retained in the catalog because the
  planner contract documents it and the planner's own tests
  exercise it directly.
- `trigger_not_enabled` — the requested trigger is not in
  `prefetch_policy.triggers`. Same defense-in-depth status as
  `disabled`: every production caller pre-checks
  `policy.triggers.contains(<trigger>)` before invoking, so this
  branch is unreachable from production and the counter does not
  increment there.
- `already_held` — Hort's `package_version_status` returned a row for
  this upstream version. Emitted once per skipped version. Any
  [`QuarantineStatus`](crates/hort-domain/src/entities/artifact.rs)
  counts: a `Quarantined` or `Rejected` row is still a row, and
  re-pulling the bytes would be a duplicate-fetch.
- `not_newer` — upstream version is older than or equal to Hort's
  newest held version per the per-format `VersionOrdering`. Emitted
  once per skipped version. Strict "<" / "==" inside this arm
  prevents double-counting with `already_held` (the held_set check
  runs first; equal-version always lands in `already_held`).

**`repository` label.** Always the served repository key — never the
`_all` sentinel. Per-repo visibility of which packages are warmed and
which are getting suppressed is the diagnostic the operator needs;
collapsing this counter to `_all` would defeat the purpose. The
catalog's global `METRICS_INCLUDE_REPOSITORY_LABEL=false` flag does
NOT apply to this counter pair — a deliberate exception, mirroring the
`hort_scan_jobs_*` per-repo carve-out (high diagnostic value,
bounded cardinality by `prefetch_policy.enabled = true` count).

**Forbidden labels.** No `package`, `version`, or `artifact_id` —
those would explode cardinality per the global rule. Per-
package context lives in the accompanying `tracing::info!` events on
the planner + spawn paths.

**PyPI wiring.** PyPI's per-version pull
(`try_upstream_file_pull`) is keyed on a *filename* (a version
typically publishes a sdist + N wheels recovered via a per-version
JSON manifest), so the per-version → per-file fan-out is structurally
heavier than npm / cargo's one-version-one-tarball pattern:
PyPI's `simple_index::fire_prefetch_trigger_pypi`
calls the planner with the upstream version set extracted from the PEP
503 HTML / PEP 691 JSON simple index, and each planned version's
spawned task fetches the per-version JSON manifest and drives a
`try_upstream_file_pull` per distribution file. Both
`hort_prefetch_enqueued_total` and `hort_prefetch_skipped_total` carry
PyPI-keyed `repository` labels alongside npm and cargo.

### Prefetch amplification

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_prefetch_amplification_total` | counter | `format`, `repository`, `result` | — | `result` ∈ `normal`, `cap_hit`, `resolver_failed` |

Emitted by
`hort_app::task_handlers::prefetch_dependencies::PrefetchDependenciesHandler::run`
exactly once at the end of each `prefetch-dependencies` walk, after
`plan_and_enqueue` returns the `WalkSummary`. Source of truth for the
`result` enum:
[`hort_app::metrics::PrefetchAmplificationResult`](../crates/hort-app/src/metrics.rs).
Adding a variant requires updating this catalog in the same PR
(architect anti-pattern hard-block — metric-and-catalog-atomic).

**`result` semantics:**

- `normal` — walk completed under the `PrefetchPolicy::max_descendants`
  cap AND every cold-cohort upstream resolution succeeded
  (`summary.cap_hit == false && summary.no_upstream_mapping == 0`).
  The happy path; the steady-state value on a healthy deployment.
- `cap_hit` — walk truncated by the cumulative-cap safety net
  (`summary.cap_hit == true`). The accompanying `tracing::warn!` at
  the truncation site carries `cap` / `current_descendants` /
  `attempted_to_enqueue` for per-instance diagnosis; the metric is
  the dashboard signal operators alert on. Used to surface runaway
  amplification — either an attacker (or an unlucky manifest)
  producing N distinct package coordinates per ingest, or an
  operator-misconfigured `max_descendants` value that legitimate
  traffic outgrows.
- `resolver_failed` — cold-cohort upstream resolution failed
  (`summary.no_upstream_mapping > 0`). Today this fires when the
  repo has no catch-all upstream mapping (`path_prefix=""`) — the
  cold cohort is silently skipped at the resolver site. The metric
  surfaces what was previously only a `summary.no_upstream_mapping`
  internal counter on the task's `result_summary` JSON, so operators
  can dashboard config-miss rates instead of grepping job rows.

**Precedence.** `cap_hit` wins over `resolver_failed` when both
flags happen to fire on the same walk (the cap is the load-bearing
safety net and the operator's primary signal; `resolver_failed` is a
secondary diagnostic). Each walk produces exactly one increment.

**`format` label.** One of the registered format-handler keys
(`"npm"`, `"pypi"`, `"cargo"`, `"maven"`, …); the value is the
repo's `Repository::format.to_string()` and matches the format keys
in `hort_index_versions_filtered_total`. The walk is per-format
because dependency-spec extraction is per-format —
`extract_dependency_specs` is a `FormatHandler` method.

**`repository` label.** Always the served repository key — never the
`_all` sentinel. Per-repo visibility of which cohorts are hitting
the cap or failing resolution is the diagnostic operators need;
collapsing this counter to `_all` would defeat its purpose. The
catalog's global `METRICS_INCLUDE_REPOSITORY_LABEL=false` flag does
NOT apply to this counter — a deliberate exception, mirroring the
`hort_prefetch_enqueued_total` / `hort_prefetch_skipped_total`
carve-out. Cardinality is bounded by the number of repos with
`prefetch_policy.enabled = true` AND `triggers.contains(TransitiveDeps)`
(default empty — operators opt in per repo), a strict subset of the
already-bounded prefetch-trigger repo population.

**Forbidden labels.** No `package`, `version`, `artifact_id`,
`user_id`, or concrete file paths — those would explode cardinality
per the global rule. Per-instance diagnostic context lives in the
accompanying `tracing::info!` "prefetch-dependencies walk complete"
event (which carries `artifact_id`, `current_depth`,
`current_descendants_so_far`, `cap_hit`, the full `WalkSummary`
counters) emitted immediately before the metric increment.

**Cardinality envelope.** `format` (≤ ~10) × `repository`
(prefetch-transitive-opt-in repos, typically < 50) × 3 `result`
values. Well under any per-metric ceiling.

### Discovery + self-service prefetch endpoints

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_discovery_list_versions_total` | counter | `format`, `repository`, `result` | — | `result` ∈ `success`, `not_found`, `unauthorized`, `rate_limited`, `upstream_4xx`, `upstream_5xx`, `network_error`, `timeout`, `parse_error`, `permission_denied`, `token_kind_denied`, `oci_unsupported` |
| `hort_prefetch_self_service_total` | counter | `format`, `repository`, `result` | — | `result` ∈ `success`, `not_found`, `unauthorized`, `rate_limited`, `upstream_4xx`, `upstream_5xx`, `network_error`, `timeout`, `parse_error`, `permission_denied`, `token_kind_denied`, `oci_unsupported`, `rejected_version`, `internal` |

`hort_discovery_list_versions_total {format, repository, result}`
— counter. One tick per discovery-endpoint HTTP call.
`result ∈ {success, not_found, unauthorized, rate_limited,
upstream_4xx, upstream_5xx, network_error, timeout,
parse_error, permission_denied, token_kind_denied,
oci_unsupported}`. Emitted exclusively from
`hort_app::use_cases::discovery_use_case::DiscoveryUseCase::list_versions`
(architect-doc *"Emission by layer"* — business metrics emit at
the hort-app use-case layer, never at the inbound handler).

`hort_prefetch_self_service_total {format, repository, result}`
— counter. Per-call ticks for short-circuit gates
(`permission_denied`, `token_kind_denied`, `oci_unsupported`);
per-item ticks for everything else.
`result ∈ {success, not_found, unauthorized, rate_limited,
upstream_4xx, upstream_5xx, network_error, timeout,
parse_error, permission_denied, token_kind_denied,
oci_unsupported, rejected_version, internal}`. Emitted exclusively from
`hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase::enqueue_self_service`.

#### `UpstreamErrorKind` taxonomy alignment

The eight upstream-fetch outcomes (`not_found`, `unauthorized`,
`rate_limited`, `upstream_4xx`, `upstream_5xx`, `network_error`,
`timeout`, `parse_error`) are the
[`UpstreamErrorKind`](../crates/hort-app/src/metrics.rs) variants
verbatim — see the *Upstream fetch error taxonomy* table at the end
of this catalog. These are the first endpoint-level metrics to consume
the canonical taxonomy (architect-doc rule: *"every format module that fetches from
upstream maps its errors to `UpstreamErrorKind` variants — no custom
labels"*). The eight values are emitted verbatim rather than coarsened
to a single `upstream_error` bucket so dashboards retain operator-
actionable distinctions (timeout → retriable; parse_error → code bug;
unauthorized → upstream-creds issue; rate_limited → backoff). Future
endpoint-level metric authors should mirror this taxonomy rather than
invent ad-hoc result strings.

`checksum_mismatch` is NOT in the result set — metadata fetches do not
verify checksums (that happens at ingest in the pull-through path,
not here). `body_too_large`, `pin_mismatch`, and `ca_unknown` are
similarly out-of-band: the discovery / prefetch use cases see those
via the dedicated `hort_upstream_tls_handshake_total` /
`hort_upstream_checksum_total` metrics, not via the upstream-fetch
result label. The
[`DiscoveryResult::from_upstream_error_kind`](../crates/hort-app/src/metrics.rs)
helper folds the four out-of-band variants to `network_error` as a
defensive bucket so the taxonomy stays closed.

#### Endpoint-local result variants

The three (resp. four) endpoint-local additions cover failure modes
the upstream taxonomy does not — they fire BEFORE the per-format
fetch port is called:

- `permission_denied` — RBAC denied (caller lacks `Permission::Read`
  for discovery, or `Permission::Read ∧ Permission::Prefetch` for
  self-service prefetch). Per-call tick from the use-case gate block.
- `token_kind_denied` — caller's `token_kind` is not
  `TokenKind::CliSession` (the amplification-surface gate).
  Per-call tick; first gate (cheapest — no repo resolution required).
- `oci_unsupported` — caller asked for discovery / self-service
  prefetch against an OCI-format repo. The
  [`UpstreamMetadataPort::list_versions`](../crates/hort-app/src/ports/upstream_metadata.rs)
  dispatch table returns `UpstreamFetchError::UnsupportedFormat`; the
  use case maps to this label and returns
  `DomainError::Validation`. Per-call tick.
- `rejected_version` (`hort_prefetch_self_service_total` ONLY) — Hort
  already holds the requested version in a terminal-non-installable
  state (`Rejected` or `ScanIndeterminate`); re-prefetch is refused
  (the auto-release-bypass anti-pattern). Per-item tick. Operator-
  facing distinction (`scan_rejected` vs. `scan_indeterminate`) lives
  in the `PrefetchOutcome.rejected_packages[].reason` payload, NOT in
  the metric label — the result-enum cardinality ceiling is already
  softer here at 13 values; further splitting would push past the
  architect-doc per-metric ceiling (5–10) without operator-actionable
  benefit (both terminal states share the same handling: "no
  automated path forward; needs human curator/admin override").
- `internal` (`hort_prefetch_self_service_total` ONLY) — Hort-side
  infrastructure failure: a DB / jobs-port / `package_version_status`
  error, including a `jobs_trigger_source_check` constraint violation.
  Per-item tick. Distinct from `network_error` so operators don't chase
  upstream egress / DNS for a server-side fault.

#### Tick semantics

All ticks emit from inside the use case (single-layer rule —
architect-doc *"Emission by layer"*). Per-call short-circuit denials
(`permission_denied`, `token_kind_denied`, `oci_unsupported`) tick
once per HTTP call from the gate block, then return `Err` before any
item iteration. All other `result` values tick **once per item**
processed: a prefetch batch of 100 items with 80 successes + 15
terminal-rejections + 5 timeouts produces 80 × `success` + 15 ×
`rejected_version` + 5 × `timeout` ticks, giving operator dashboards a
true item-level view. The discovery endpoint serves a single package
per call (no batch shape) so the per-call vs. per-item distinction
collapses for it — one tick per call.

#### `not_found` semantic rule

`hort_discovery_list_versions_total{result="not_found"}` ticks ONLY
when the *upstream* lookup returns 404 (the upstream's verdict on the
package). It does NOT tick when Hort has held versions but the upstream
call returns 404 — that is `result=success` (the listing assembled
cleanly; the response payload carries Hort-held versions + an empty
`unknown` set). It does NOT tick when the upstream call succeeds with
an empty version set and Hort has nothing either — that is also
`result=success` (the call succeeded; the answer is "no versions
known"). The discovery endpoint returns 200 in all three cases —
operators read the response payload to distinguish them; the metric
distinguishes "did the upstream call complete cleanly", not "is the
listing non-empty".

#### `format` label

One of the registered format-handler keys (`"npm"`, `"pypi"`,
`"cargo"`, `"oci"`, …); the value comes from the resolved
`Repository::format.to_string()`. For pre-repo-resolution gate ticks
(`token_kind_denied`) the format is unknown, so the label collapses
to the `unknown` sentinel (see *Sentinel label values* near the top of
this file). The `oci_unsupported` arm resolves the repo first so it
emits the real format key.

#### `repository` label

Follows the catalog convention: pass the resolved repo key from
`RepositoryAccessUseCase::metric_label(repo_id)`, which encapsulates
the `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse (returns
`_all`) and the resolve-failure fallback (returns `unknown`). For
pre-repo-resolution gate ticks (`token_kind_denied`) the label
collapses to `_all`. Never pass a raw UUID.

#### Cardinality envelope

`format` × `repository` × `result` =
~10 × N_repos × 12 (discovery) / 13 (prefetch). For a 1k-repo
deployment with `METRICS_INCLUDE_REPOSITORY_LABEL=true`, the worst-
case series count is ~120k discovery + ~130k prefetch; with the knob
disabled (default at scale) the `repository` label collapses to
`_all` and the bound is ~120 + ~130 series.

#### Forbidden labels

No `package_name`, `version`, `artifact_id`, `user_id`, or raw UUID
on any dimension. Per-instance attribution lives in the
`tracing::info!` spans on each use-case method — the gate-denial path
logs `caller_user_id` + `caller_token_kind` + `repository`; the OCI
rejection logs `repository` + `format`; the success path logs
`format` + `repo_key` + `version_count` at `debug!` (NOT the package
name — the high-cardinality rule).

### Upstream fetch (pull-through proxy)

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_upstream_fetch_total` | counter | `format`, `upstream`, `result` | — | see taxonomy below |
| `hort_upstream_fetch_duration_seconds` | histogram | `format`, `upstream`, `kind` | seconds | — |
| `hort_upstream_checksum_total` | counter | `format`, `result` | — | `verified`, `mismatch`, `checksum_missing` |
| `hort_upstream_insecure_total` | counter | `format`, `reason` | — | `scheme_http`, `mapping_legacy` |
| `hort_upstream_tls_handshake_total` | counter | `repository`, `result` | — | `success`, `mtls_required`, `ca_unknown`, `pin_mismatch`, `network_error` |

`hort_upstream_fetch_total` and `hort_upstream_fetch_duration_seconds`
are emitted by the `UpstreamProxy` adapter
(`hort_adapters_upstream_http::HttpUpstreamProxy`) on every
`fetch_blob` / `fetch_manifest` call — both success and failure
paths fire the counter exactly once. The histogram's `kind` label
is `blob` or `manifest`.

(Earlier drafts of the catalog listed this counter as
`hort_upstream_errors_total` and reserved `hort_upstream_fetch_total`
as a future alias; the counter ticks on every fetch outcome, success
and error alike, so `errors_total` was a misnomer and the reserved
alias became the canonical name.)

`format` is taken at adapter construction time
(`HttpUpstreamProxyConfig::format_label`) — the OCI composition
root passes `"oci"`; future format consumers (Maven, npm proxy,
…) construct their own instance with their own format string.
The worker builds two **subsystem-labelled** instances that fetch
through the same adapter but are not a single artifact format:
`prefetch_tick` (the scheduled prefetch tick / leaf-pull, which
walks npm/cargo/pypi) and `provenance` (the upstream
Sigstore-referrer fetch in the `provenance-verify` job). These are
intentional non-format `format` values so dashboards separate
background traffic from the OCI hot path; cloning one subsystem's
proxy for another would mis-attribute its `hort_upstream_fetch_*`
series (provenance traffic once emitted `format="prefetch_tick"`
exactly this way).
The `upstream` label is the mapping's `path_prefix` with a
trailing slash trimmed (`"dockerhub/"` → `"dockerhub"`); empty
prefixes (single-upstream catch-all) emit the `_default` sentinel.

`hort_upstream_checksum_total` is emitted by
`IngestUseCase::ingest_verified` (ADR 0006) for the
`verified` and `mismatch` arms — atomic with the `ChecksumVerified`
and `ChecksumMismatch` events respectively. The third value
`checksum_missing` is emitted by an inbound HTTP handler **before**
bytes reach the ingest use case, when the upstream response failed
to supply the required verification target. The canonical emission
site is `crates/hort-http-oci/src/manifests.rs::try_upstream_manifest_pull`
on a tag-mode pull whose upstream omitted `Docker-Content-Digest`:
the handler returns `502 Bad Gateway` and `ChecksumVerified` is intentionally
NOT emitted on this path, so that `ChecksumVerified` remains an
honest attestation that an upstream-supplied digest was checked.

The previously-reserved `unavailable` label value is removed — the
design no longer admits a "no checksum from upstream" case for the
*metadata* path: missing upstream metadata
fails at `parse_upstream_checksum` and surfaces as `502 Bad Gateway`
from the HTTP handler, never reaching the use case (ADR 0006 —
mandatory upstream verification).

`hort_upstream_redirect_blocked_total` was retired along with the
upstream-side connect-time `GuardedDnsResolver` and the
hop-by-hop redirect-policy SSRF re-validator. The remaining
redirect-layer defence is `reqwest::redirect::Policy::limited(N)`
(default 5 hops via `HttpUpstreamProxyConfig::max_redirect_hops`); the
retired metric has no replacement because the settled posture is to
accept operator-vetted upstream target trust
without per-hop SSRF re-validation. URL-input validation against
operator-supplied or upstream-metadata-derived URLs continues to flow
through `check_ssrf_safe` (`hort-net-egress::is_routable`) before fetch.

`hort_upstream_insecure_total` is emitted by the `UpstreamProxy`
adapter (`hort_adapters_upstream_http::HttpUpstreamProxy`) on every
fetch through a mapping that carries the `insecure_upstream_url:
true` opt-in. The opt-in is the operator-explicit acknowledgement that
the configured upstream URL is plaintext (`http://`), and the metric
plus a `tracing::warn!` line on every fetch make the posture
impossible to miss in a dashboard. Without the flag, the value-object
constructor `RepositoryUpstreamMapping::new` rejects an `http://`
upstream at apply time. Two `reason` values, fixed taxonomy owned by
`hort-app::metrics::UpstreamInsecureReason`:

- `scheme_http` — the mapping's `upstream_url` scheme is `http://` and
  the operator opted in via the per-mapping
  `insecure_upstream_url: true` flag (gitops YAML field
  `spec.insecureUpstreamUrl: true`). Every fetch through such a
  mapping emits one increment plus a WARN log line carrying the
  upstream label and format.
- `mapping_legacy` — reserved for a future migration that resurrects
  a pre-Item-6 row carrying the insecure posture by inheritance. No
  emission site uses this value today; the column is `NOT NULL
  DEFAULT FALSE` and the constructor enforces opt-in. Declared in
  the taxonomy so a follow-up does not have to re-touch the catalog.

`format` is the same value the per-instance
`HttpUpstreamProxyConfig::format_label` carries on
`hort_upstream_fetch_total` (`oci`, `pypi`, `npm`, `cargo`, …).
Cardinality envelope: 2 reason values × ~5 formats = ≤ 10 series.

`hort_upstream_tls_handshake_total` is emitted by the `UpstreamProxy`
adapter (`hort_adapters_upstream_http::HttpUpstreamProxy`) once per
outbound TLS handshake — every `fetch_blob` / `fetch_manifest` /
`fetch_artifact` / `fetch_metadata` call fires the counter exactly
once with the matching `result` label, success and failure paths
alike. The metric classifies the *transport-layer* outcome,
distinct from `hort_upstream_fetch_total` which classifies the
*application-layer* outcome (404, checksum mismatch, body-too-large,
…). A handshake that produces a 401 fires this counter with
`mtls_required` (the operator-explicit reading of "server demanded
client cert posture we do not have") and `hort_upstream_fetch_total`
with `unauthorized` — operators alert on whichever axis matches the
remediation surface they own. Five `result` values, fixed taxonomy
owned by `hort-app::metrics::UpstreamTlsHandshakeResult`:

- `success` — handshake completed; chain validated, name validated,
  and (when configured) the leaf-cert thumbprint matched the operator
  pin. The fetch then proceeds to its application-layer outcome.
- `mtls_required` — server demanded a client cert (`CertificateRequest`)
  and the mapping's `mtls_cert_ref` / `mtls_key_ref` pair was unset;
  surfaces as `Unauthorized` on `hort_upstream_fetch_total`.
  Operators set the pair (gitops YAML
  `spec.mtlsCertRef` + `spec.mtlsKeyRef`) to remediate.
- `ca_unknown` — server's certificate chain did not chain to a trust
  anchor in the configured root store. The `ca_bundle_ref`
  augmentation (gitops YAML `spec.caBundleRef`) is the operator's
  lever to extend trust without touching the system CA bundle.
- `pin_mismatch` — operator-pinned thumbprint
  (`pinned_cert_sha256`, gitops YAML `spec.pinnedCertSha256`)
  disagreed with the upstream's presented leaf cert. Either the
  upstream rotated to a new (legitimate) cert and the pin needs
  updating, or a MITM is in progress; the proxy refuses the
  connection on this signal alone.
- `network_error` — any other transport-layer failure: TCP refused,
  TLS handshake aborted by the peer, deadline exceeded mid-handshake.

`repository` carries the architect-skill cardinality discipline: the
proxy operates on `RepositoryUpstreamMapping` values that surface
only the repository's UUID, not its key, and the rule "no UUIDs in
metric labels" means the proxy emits the
[`values::REPOSITORY_ALL`](#sentinels) sentinel `_all` regardless of
the `METRICS_INCLUDE_REPOSITORY_LABEL` toggle. Other emitters of the
`repository` label (the OCI handler, the ingest path) honour the
toggle and emit the repository key when the toggle is enabled; this
metric collapses unconditionally because the source data simply does
not carry the key. Same governance as `hort_ingest_*` and
`hort_upstream_*`; reviewers do not need to budget it separately.
Cardinality envelope: 1 (`_all`) × 5 result values = 5 series total.

### Upstream bearer-challenge auth

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_upstream_bearer_token_total` | counter | `format`, `upstream`, `result` | — | `exchange`, `cache_hit`, `invalidate`, `fetch_failed`, `parse_failed` |

`hort_upstream_bearer_token_total` is emitted by the `UpstreamProxy`
adapter (`hort_adapters_upstream_http::HttpUpstreamProxy`) every time
a `BearerChallenge` mapping resolution makes a state transition in
the bearer-token cache. Exactly one increment per state transition;
the `result` label enumerates the transition kind:

- `exchange` — realm round-trip succeeded; a fresh
  `(realm, service, scope, cred_identity)` cache entry was
  populated. Fires inside the 401 dance after a successful
  `fetch_bearer_token`.
- `cache_hit` — `authorization_header` returned a cached bearer
  to the outer fetch, skipping the 401 round-trip. Fires once per
  resource fetch on a warm cache.
- `invalidate` — a 401 response carrying the Authorization the
  proxy had just sent caused the corresponding cache entry to be
  removed. Fires inside the 401 dance before the re-exchange.
- `fetch_failed` — the realm exchange itself returned a non-success
  status, transport-errored, or returned a JSON body the parser
  could not decode; OR the `SecretPort` returned `Err` while
  resolving the mapping's `secret_ref`. The bearer-flow surfaces a
  classified error to the caller; the outer `hort_upstream_fetch_total`
  counter also fires with the appropriate `UpstreamErrorKind`.
- `parse_failed` — the upstream's `WWW-Authenticate` header could
  not be parsed as a Bearer challenge (non-Bearer scheme, missing
  `realm`, malformed parameters). The 401 surfaces verbatim as
  `Unauthorized`.

`format` and `upstream` carry the same values as
`hort_upstream_fetch_total` — `format` from
`HttpUpstreamProxyConfig::format_label`, `upstream` from the
mapping's `path_prefix` (`_default` for empty prefixes). Cardinality
is bounded: ~40 formats × ~10k repository_label-values × 5 result
values is the worst-case product, identical to the cardinality
envelope of `hort_upstream_fetch_total`.

### Pull-through deduplication

| Metric | Type | Labels | Unit | `outcome` values |
|--------|------|--------|------|------------------|
| `hort_pull_dedup_total` | counter | `layer`, `format`, `outcome` | — | `leader_started`, `follower_waited_hit`, `follower_waited_failure`, `follower_fellthrough_503`, `negative_cache_hit`, `lock_expired_re_elected`, `follower_lagged`, `layer_b_unavailable` |
| `hort_pull_dedup_wait_seconds` | histogram | `layer`, `format` | seconds | — (buckets: `0.01, 0.05, 0.1, 0.5, 1, 5, 30, 60, 300`) |

Emitted by `hort_app::pull_dedup::PullDedup::coalesce_metadata` and
`coalesce_blob` when a format handler wraps an upstream-proxy fetch.
Two-layer coalescing:

- **Layer A** (`layer="in_process"`) — per-replica
  `DashMap<DedupKey, broadcast::Sender>`; followers join the in-flight
  broadcast on the same pod with zero round-trips.
- **Layer B** (`layer="cluster"`) — `EphemeralStore::put_if_absent`
  keyed lock + status broadcast. Cluster-wide; followers either
  short-circuit on a negative-cache hit, wait on the leader's CAS
  write, or re-attempt election when the lock TTL expires without a
  terminal outcome.

**`outcome` label semantics** (closed taxonomy of 8; source of truth:
`hort_app::metrics::DedupOutcomeLabel`):

- `leader_started` — this caller won leader election (Layer A
  vacant arm OR Layer B `put_if_absent → true`). The fetch closure
  ran exactly once across the coalescing window.
- `follower_waited_hit` — follower waited on either layer and then
  observed a `Succeeded*` outcome — the leader's fetch landed and
  the follower returned the cached result without contacting the
  upstream.
- `follower_waited_failure` — follower waited on either layer and
  then observed a `Failed` outcome from the leader (4xx, 5xx,
  timeout, checksum mismatch, …). Follower returned the same error
  to its client without contacting the upstream — the load-bearing
  negative-cache property.
- `follower_fellthrough_503` — follower waited up to
  `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS` (default `300`) and the leader
  still had not produced a terminal outcome. Fall-through is a
  `503 + Retry-After: 30` response —
  *not* an un-coalesced fetch.
- `negative_cache_hit` — caller arrived during a `Failed`-with-
  future-`expires_at` window and short-circuited on the cached
  failure WITHOUT re-attempting `put_if_absent`. Distinct from
  `follower_waited_failure` because no waiting actually happened.
- `lock_expired_re_elected` — Layer-B lock TTL expired without a
  terminal outcome (the previous leader pod died mid-fetch or its
  heartbeat task crashed). The caller won the re-election
  `put_if_absent` and became the new leader. Logged at `info!` —
  operationally interesting transition.
- `follower_lagged` — Layer-A `broadcast::Receiver` returned
  `Lagged(_)` because the channel capacity (64) was exceeded. The
  follower fell through to a Layer-B `get` on the same key —
  correctness preserved, the metric exists for visibility into a
  path that is implausible but defended.
- `layer_b_unavailable` — `EphemeralStore::put_if_absent` (or any
  other Layer-B call) returned an error. Caller proceeded as the
  leader anyway (fail-open by design); Layer A still
  provides per-replica coalescing for any other concurrent caller
  on the same pod. Cluster-wide coalescing is degraded; correctness
  is preserved by the existing CAS + path-conflict short-circuit.

**`format` label values:** match `hort_upstream_fetch_total`'s closed
taxonomy (`oci`, `pypi`, `npm`, `cargo`, …) for the metadata and
URL-keyed paths. Content-hash-keyed coalescing (`DedupKey::blob_by_hash`)
is cross-format — two callers of any shape asking for the same bytes
share a coalescing window — so the `format` label collapses to the
literal `_any` sentinel. This keeps the `format`-axis cardinality
bounded at the same envelope as `hort_upstream_fetch_total` plus one.

**Cardinality envelope:**
- `hort_pull_dedup_total`: 2 layers × ~10 formats (incl. `_any` sentinel)
  × 8 outcomes = ≤ 160 series. Flat per deployment.
- `hort_pull_dedup_wait_seconds`: 2 layers × ~10 formats × 9 buckets
  = ≤ 180 series. Flat per deployment.

**`hort_upstream_fetch_total` is unchanged.** Followers never reach
`hort-adapters-upstream-http` (`coalesce_*` short-circuits inside
`hort-app`), so the existing counter automatically means "actual
upstream HTTP requests issued" without any extension. Operators
compute coalescing efficiency by reading both metrics:

```
upstream_calls / (upstream_calls + sum(hort_pull_dedup_total{outcome=~"follower_.*|negative_cache_hit"}))
```

A ratio approaching `1.0` means coalescing is rarely catching anything
(no concurrent miss bursts); a ratio approaching `0.0` means most
client-visible requests are being absorbed by the dedup layer.

**Result-enum ownership:** the new label types live in
`hort_app::metrics::{DedupLayer, DedupOutcomeLabel}` per the architect-
skill rule "result enums live with the emitting layer".
`UpstreamErrorKind` is **not** extended.

**Tunable knobs** (parsed in `hort-server::config`):

- `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS` (default `30`) — `Failed(NotFound)` negative-cache TTL.
- `HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS` (default `10`) — `Failed(RateLimited | Upstream5xx | Upstream4xx | Unauthorized)`.
- `HORT_PULL_DEDUP_TTL_TIMEOUT_SECS` (default `10`) — `Failed(Timeout | NetworkError)`.
- `HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS` (default `60`) — `Failed(ChecksumMismatch | ParseError | BodyTooLarge | PinMismatch | CaUnknown)`.
- `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS` (default `300`) — follower 503 fall-through ceiling.

The leader heartbeat (30s) and Layer-A channel capacity (64) are
intentionally NOT operator-tunable.

### Vulnerability scanning

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_scan_jobs_total` | counter | `result` | — | `pending_claimed`, `completed`, `failed`, `retried` |
| `hort_scan_findings_total` | counter | `scanner`, `severity` | — | `scanner ∈ {trivy, osv, advisory, …registered backend names}`; `severity ∈ {critical, high, medium, low}` |
| `hort_scan_duration_seconds` | histogram | `scanner` | seconds | — |
| `hort_scan_queue_depth` | gauge | (none) | rows | — |
| `hort_advisory_query_total` | counter | `result` | — | `cache_hit`, `cache_miss`, `upstream_4xx`, `upstream_5xx`, `network_error`, `timeout` |
| `hort_sbom_extraction_total` | counter | `format`, `result` | — | `result ∈ {success, unsupported_format, parse_error}` |
| `hort_artifact_became_vulnerable_total` | counter | `repository`, `severity`, `ingest_source` | — | `severity ∈ {critical, high, medium, low}`; `ingest_source ∈ {direct, proxied}` |
| `hort_scan_record_outcome_failures_total` | counter | `result`, `scanner` | — | `result ∈ {failed_branch, report_too_large}`; `scanner ∈ {(none), trivy, osv, …registered backend names}` |

Source of truth for the result enums:
- `hort_app::metrics::ScanJobsResult` for `hort_scan_jobs_total.result`.
- `hort_app::metrics::ScanFailureResult` for
  `hort_scan_record_outcome_failures_total.result`.
- `hort_app::metrics::AdvisoryQueryResult` for
  `hort_advisory_query_total.result`.
- `hort_app::metrics::SbomExtractionResult` for
  `hort_sbom_extraction_total.result`.

Adding a variant to any of those enums requires updating this catalog
in the same change.

**`hort_scan_jobs_total.result` semantics** (one increment per state
transition; closed taxonomy of 4):

- `pending_claimed` — emitted by
  [`ScanOrchestrationUseCase::claim_pending`](../crates/hort-app/src/use_cases/scan_orchestration.rs)
  once per job returned from the `JobsRepository::claim_scan_jobs`
  call. A batch of N claimed jobs ticks the counter N times so the
  `pending → running` rate is observable on a single label.
- `completed` — emitted by
  `ScanOrchestrationUseCase::record_outcome` whenever the job is
  marked completed. Both `Completed { … }` and `SkippedNoBackends`
  reach `mark_completed` and tick this label; the wire reports the
  terminal happy-path outcome regardless of whether scanning ran.
- `failed` — emitted when `record_outcome` lands on the terminal
  `mark_failed` arm (the job exhausted `max_attempts` retries). One
  tick per terminal failure; never co-emitted with `retried` for the
  same observation.
- `retried` — emitted when `record_outcome` reschedules the job for
  a future attempt via `JobsRepository::reschedule`. One tick per
  reschedule call.

**`hort_scan_findings_total` semantics** — emitted by
`ScanOrchestrationUseCase::run_scan` once per (deduplicated) finding
contributed by a scanner backend. The increment fires after the
merge/dedup step so duplicate `(purl, vulnerability_id)` pairs across
backends count exactly once. The `scanner` label carries the
contributor name (`trivy`, `osv`, the `advisory` sentinel for
advisory-only entries, …); the `severity` label is the lowercase wire
form of `SeverityThreshold`. Per-finding identifiers (`purl`,
`vulnerability_id`) are NOT labels — they are tracing-span fields.

**`hort_scan_duration_seconds` semantics** — observed by
`ScanOrchestrationUseCase::run_scan` once per backend invocation.
Brackets only the `ScannerPort::scan` call (start `Instant::now()`
before the call, observe after); SBOM extraction, advisory
enrichment, dedup, and CAS persist all run outside the timer because
they are not in the scanner-perf hot path. One histogram per
registered backend name.

**`hort_scan_queue_depth` semantics** — emitted by the worker's
heartbeat tick (`hort-worker::heartbeat`) once every 60
seconds. Reads `count(*) FROM jobs WHERE kind='scan' AND
status='pending'`. Multi-worker deployments emit the same value from
each replica; gauge semantics handle the replication so dashboards
need no aggregation. No labels — the depth is a single global
signal.

**`hort_advisory_query_total.result` semantics** (closed taxonomy of 6;
emitted by `OsvAdvisoryAdapter`):

- `cache_hit` — per-component lookup short-circuited on the
  `EphemeralStore` cache. One tick per cached component (no upstream
  request fired).
- `cache_miss` — per-component lookup found nothing in the cache and
  the component is enqueued for the OSV batch. One tick per missed
  component, fired once before the upstream call regardless of the
  upstream's eventual outcome (the cache_miss documents cache state;
  the upstream tick documents request outcome — together they form
  the funnel).
- `upstream_4xx` — OSV `/v1/querybatch` POST returned a 4xx status.
  One tick per failed batch.
- `upstream_5xx` — OSV `/v1/querybatch` POST returned a 5xx status.
  One tick per failed batch.
- `network_error` — `reqwest::send()` returned an error before a
  status code was observed (DNS, TCP, TLS). One tick per failed batch.
- `timeout` — the per-request deadline elapsed before the batch
  responded. One tick per timed-out batch.

`upstream_4xx`, `upstream_5xx`, `network_error`, and `timeout` are
mutually exclusive at one batch boundary; they may co-emit with
`cache_miss` for the same call (cache_miss documents the cache state,
upstream_* documents request outcome). Successful upstream batches
are not labelled separately — they are accounted by the preceding
`cache_miss` ticks (every component eventually lands a `cache_hit` or
a `cache_miss`; a successful batch landed every prepared component
into the cache for next time).

**`hort_sbom_extraction_total.result` semantics** (closed taxonomy of
3; emitted by `ScanOrchestrationUseCase::try_extract_sbom`):

- `success` — `FormatHandler::extract_sbom` returned `Ok(Some(sbom))`.
- `unsupported_format` — handler returned `Ok(None)` (the
  `FormatHandler` default impl, used by Helm/Conda/Hex/Pub/Generic).
  Distinct from `parse_error` so the catalog can split "format does
  not produce an SBOM" from "format would produce an SBOM but the
  payload was malformed".
- `parse_error` — handler returned `Err(_)`. Tracing carries the
  underlying parse error; the metric only carries the result label.

The `format` label uses `ArtifactCoords.format.as_str()` (lowercase
short name: `npm`, `pypi`, `cargo`, `maven`, `oci`, …) so the label
matches the `format_key` used elsewhere in the catalog.

**`hort_artifact_became_vulnerable_total` semantics** — emitted by
[`QuarantineUseCase::record_scan_result`](../crates/hort-app/src/use_cases/quarantine_use_case.rs)
exactly once per `ArtifactBecameVulnerable` event appended ("the
metric and the event must rise together or one
is wrong"). The metric and the event share the same code path —
appending one without the other is a bug.

`severity` carries the **highest tier** present in `new_findings`
(`Critical > High > Medium > Low`); a single increment per event,
not one per finding. `ingest_source` mirrors the artifact's
`ArtifactIngested.source` (`direct` for client uploads, `proxied`
for pull-through fetches), read from the artifact's stream during
the prior-scan reverse scan in `record_scan_result`.

`repository` honours the `METRICS_INCLUDE_REPOSITORY_LABEL` operator
toggle (see also `hort_ingest_total`,
`hort_download_total`, `hort_upstream_tls_handshake_total`). When the
toggle is `false`, the use case emits `repository="_all"` (the
[`values::REPOSITORY_ALL`](../crates/hort-app/src/metrics.rs)
sentinel) rather than the raw repository key, dropping the
cardinality ceiling from `≤10k × 4 × 2 = 80k` to `4 × 2 = 8`.

**`hort_scan_record_outcome_failures_total` semantics** — emitted by
[`hort_worker::poll_loop::emit_failed_branch_alert`](../crates/hort-worker/src/poll_loop.rs)
once per Failed-branch `record_outcome` invocation that itself
returns `Err`. The Failed branch is the one the worker takes when
`run_scan` returned `Err(_)` (an infrastructure failure — artifact
load, SBOM extraction, etc.) and the orchestrator's
`record_outcome(&job, ScanRunOutcome::Failed(_))` then also failed
to persist the backoff or `mark_failed` transition. Distinct from
`hort_scan_jobs_total{result=failed}`, which counts jobs the
orchestrator successfully transitioned into the terminal `failed`
state — this counter only fires when that very transition could not
be written.

Operators alert on
`rate(hort_scan_record_outcome_failures_total[5m]) > 0` to surface
DB-side outages; sustained non-zero rate means scan jobs are
silently looping back into pending without their backoff state
landing.

`result` carries the failure classifier (closed taxonomy of 2):

- `failed_branch` — emitted by
  [`hort_worker::poll_loop::emit_failed_branch_alert`](../crates/hort-worker/src/poll_loop.rs)
  when a Failed-branch `record_outcome` call itself returned `Err`
  (the orchestrator could not persist the outcome — a DB-side
  outage). `scanner="(none)"`: the underlying error is not
  attributable to a single backend.
- `report_too_large` — emitted by
  [`ScanOrchestrationUseCase::run_scan`](../crates/hort-app/src/use_cases/scan_orchestration.rs)
  on the per-backend failure path when a scanner backend's report
  drain hit the `HORT_SCANNER_MAX_REPORT_SIZE` cap (size string, default `256Mi`):
  the adapter (`hort-adapters-scanner-{trivy,osv}`) bounded the
  stdout/stderr drain via `.take(cap + 1)`, killed the child, and
  returned the distinguishable
  `hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER` error.
  The backend failure still flows through the normal fail-closed path
  (`ScanIndeterminate` after retry exhaustion — never serve-unscanned;
  ADR 0007); this value only attributes *why*. `scanner` carries the
  originating backend name (`trivy` / `osv` / a registered backend),
  so an operator can tell which scanner produced the oversized report.

`scanner` carries the originating scanner backend's name when the
failure is attributable to one (the `report_too_large` path), otherwise
the `(none)` sentinel (the `failed_branch` path).

Cardinality:
- `hort_scan_jobs_total`: 4 result values → 4 series ceiling.
- `hort_scan_findings_total`: ~3 scanners × 4 severities → 12 series.
  Includes the `advisory` sentinel scanner emitted by
  advisory-only contributors.
- `hort_scan_duration_seconds`: 2 scanners (`trivy`, `osv`) → 2
  histograms in the v1 default deployment. Operators that register
  additional backends extend the axis.
- `hort_scan_queue_depth`: 1 series (no labels).
- `hort_advisory_query_total`: 6 result values → 6 series.
- `hort_sbom_extraction_total`: ~15 formats × 3 results → 45 series.
- `hort_artifact_became_vulnerable_total`: ≤10k repositories × 4
  severities × 2 ingest_source → 80k series ceiling. Honours the
  `METRICS_INCLUDE_REPOSITORY_LABEL=false` toggle — when disabled,
  the ceiling drops to `4 × 2 = 8` series. The toggle is the
  operator's escape hatch when scaling past 1k repositories.
- `hort_scan_record_outcome_failures_total`: 2 result values
  (`failed_branch`, `report_too_large`) × ≤3 scanner attributions
  (`(none)`, `trivy`, `osv`, plus any operator-registered backend) →
  small bounded ceiling. The metric is alerting-only — series count is
  bounded by the closed `result` taxonomy and the registered-backend
  count.

Per the architect skill's "high-cardinality metric labels" rule,
`artifact_id` is NOT a label on any of these metrics. Per-artifact
drill-down goes through `tracing::info_span!(artifact_id = %id, …)`
spans; `vulnerability_id`, `purl`, and CVE identifiers stay out of
metric label space entirely.

### Fail-closed scanner

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_scan_terminal_total` | counter | `result` | — | `completed`, `indeterminate`, `rejected` |

Source of truth for the result enum:
- `hort_app::metrics::ScanTerminalResult` for `hort_scan_terminal_total.result`.

Adding a variant to that enum requires updating this catalog in the
same change.

**`hort_scan_terminal_total.result` semantics** — emitted at exactly
**one layer**:
[`ScanOrchestrationUseCase::record_outcome`](../crates/hort-app/src/use_cases/scan_orchestration.rs).
One increment per **artifact-terminal scan decision**. Distinct from
`hort_scan_jobs_total` (per-job-attempt state) — this counts
artifact-terminal outcomes, never job attempts, and must NOT
double-count (architect "one metric, one layer"). Closed taxonomy of
3:

- `completed` — the scanner decided: clean. Ticks on the
  `Completed{findings: []}` arm and the `SkippedNoBackends` arm (the
  operator `scan_backends: []` waiver — a decision, not a failure).
- `indeterminate` — the scanner could not decide: terminal scan
  failure after retry exhaustion. Ticks on the retry-exhausted
  `Failed` arm; the artifact transitioned to `scan_indeterminate`
  (fail-closed — ADR 0007). Never co-emitted with `completed`/
  `rejected` for the same observation. An attacker who DoSes a
  configured scanner for a chosen artifact shows up here, distinctly
  from a clean rejection — a required audit signal.
- `rejected` — the scanner decided: bad content. Ticks on the
  `Completed{findings: [..]}` arm; the artifact transitioned to
  `rejected`.

Cardinality: 3 result values → 3 series ceiling. `artifact_id` is
NOT a label (architect "high-cardinality metric labels" rule);
per-artifact drill-down is the `info!` audit line on the
`→ scan_indeterminate` transition
(`QuarantineUseCase::record_scan_indeterminate`).

### Rescan and advisory watch

These metrics supplement the framework-level `hort_admin_tasks_*` series
that the admin-task framework provides automatically. They measure the rescan pipeline's
input pressure (how many scan jobs are landing per `trigger_source`) and
the advisory-watch I/O surface (per-ecosystem outcome and duration of
the OSV bulk diff).

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_scan_jobs_enqueued_total` | counter | `trigger_source` | — | `trigger_source ∈ {ingest, cron, advisory, manual}` — exact mirror of the SQL CHECK on `jobs.trigger_source` |
| `hort_advisory_diff_processed_total` | counter | `ecosystem`, `result` | — | OSV bulk-archive ecosystem labels (`npm`, `PyPI`, `crates.io`, `Maven`, `Go`, `RubyGems`, `NuGet`, `Packagist`, `Hex`, `Pub`, `Conda`); `result ∈ {ok, fetch_error, parse_error, timeout}` |
| `hort_advisory_diff_duration_seconds` | histogram | `ecosystem` | seconds | per OSV bulk-archive ecosystem label |
| `hort_cron_rescan_eligible_artifacts` | gauge | (none) | artifacts | set per `CronRescanTickHandler` invocation; operator alarms on sustained `> batch_size` (cron loop can't keep up) |
| `hort_patch_candidates_listed_total` | counter | `repository`, `result` | — | `repository ∈ {"_all", <key>}` for v1: `_all` for admin-wide scope (no `?repository` filter), the resolved repository key when the handler successfully resolved `?repository=<key>` to a row. `"unknown"` is reserved for future non-HTTP / dispatcher paths — the HTTP handler short-circuits to 404 on lookup failure before reaching the use case. `result ∈ {ok, denied, invalid, error}` |

Source of truth for the result enums:
- `hort_app::metrics::TriggerSourceLabel` for `hort_scan_jobs_enqueued_total.trigger_source`. Mirrors `hort_domain::ports::jobs_repository::TriggerSource` (the SQL wire form). The two MUST agree — a drift is enforced as a compile-equality test.
- `hort_app::metrics::AdvisoryDiffResult` for `hort_advisory_diff_processed_total.result`.
- `hort_app::metrics::PatchCandidateListResult` for `hort_patch_candidates_listed_total.result` (operator-action signal for `GET /admin/quarantine/patch-candidates`).

Adding a variant to either enum requires updating this catalog in the
same change.

**`hort_scan_jobs_enqueued_total` trigger_source semantics** (closed
taxonomy of 4; one increment per landed row, NOT per attempted enqueue
— Conflict-on-enqueue paths swallow the row and do NOT tick the
counter):

- `ingest` — first-scan at ingest time. Emitted by the ingest
  enqueue path (`IngestUseCase::ingest_verified` → `enqueue_scan` with
  `trigger_source="ingest"` and `priority=0`).
- `cron` — periodic eligibility sweep. Emitted by
  [`CronRescanTickHandler::run`](../crates/hort-app/src/task_handlers/cron_rescan_tick.rs)
  once per tick, with the count equal to the number of rows that
  successfully landed (Conflict swallowed by the partial unique index
  `(artifact_id) WHERE kind='scan'` is excluded). Default schedule
  `*/5 * * * *`; default `priority=10`.
- `advisory` — per-ecosystem advisory-watch fan-out. Emitted by
  [`AdvisoryWatchTickHandler::run`](../crates/hort-app/src/task_handlers/advisory_watch_tick.rs)
  once per tick with the landed-rows count. Default schedule
  `0 */6 * * *`; default `priority=5`. The wire string is `advisory`,
  NOT `advisory_watch` — it must match the SQL CHECK literal exactly.
- `manual` — operator-triggered rescan via `POST /api/v1/artifacts/:id/rescan`.
  Emitted by [`ManualRescanUseCase::trigger`](../crates/hort-app/src/use_cases/manual_rescan_use_case.rs)
  on success only — RBAC denial, in-flight conflict, and port-side
  conflict paths do NOT increment the counter. Default `priority=20`
  (jumps the queue ahead of cron and advisory).

**`hort_advisory_diff_processed_total` result semantics** (closed
taxonomy of 4; one emission per ecosystem per advisory-watch tick from
inside the OSV adapter's bulk loop —
[`OsvAdvisoryAdapter::pull_diff_since`](../crates/hort-adapters-advisory-osv/src/lib.rs)):

- `ok` — per-ecosystem fetch + parse succeeded; new advisories
  (possibly zero) were appended to the diff result.
- `fetch_error` — HTTP fetch failed: non-2xx status from the
  `osv-vulnerabilities` archive host, network error before status was
  observed (DNS, TCP, TLS), or body stream error during the
  spill-to-tempfile copy. The `hort_advisory_diff_duration_seconds`
  histogram for the same ecosystem still records — duration brackets
  the fetch attempt regardless of outcome.
- `parse_error` — fetch succeeded but the zip / archive payload could
  not be parsed at the per-archive boundary (zip-format error,
  `tempfile::reopen` failure on the parse side, blocking-task join
  failure during the sync zip walk). Distinct from per-record
  skip-on-malformed (which keeps processing the archive without
  surfacing here).
- `timeout` — the per-request deadline elapsed before the bulk archive
  responded. Surfaced separately from `fetch_error` so operators can
  split slow-upstream from upstream-broken on dashboards.

The handler aggregates per-ecosystem results into
`AdvisoryDiffResult.all_ecosystems_ok` for the checkpoint-advance
gate; the counter and histogram below are the operator-visible
breakdown.

**`hort_patch_candidates_listed_total` result semantics** (closed
taxonomy of 4; one emission per admin call to
[`PatchCandidateUseCase::list`](../crates/hort-app/src/use_cases/patch_candidate_use_case.rs).
The `repository` label is the resolved repository key when the HTTP
handler successfully looked up `?repository=<key>` via
`RepositoryRepository::find_by_key` and threaded it onto
`PatchCandidateFilter::repository_key_for_metric`, or the `_all`
sentinel when the request had no `?repository` filter (admin-wide
scope). `"unknown"` is reserved for future non-HTTP / dispatcher
callers — the HTTP handler short-circuits to 404 on lookup failure
before invoking the use case, so the use-case-side metric only ever
sees `_all` or a resolved key in v1):

- `ok` — admin call succeeded; repo returned a `Vec<PatchCandidate>`
  (possibly empty). Emitted on the success path after the audit log
  fires.
- `denied` — `require_admin()` rejected the caller. Emitted *before*
  the early return so dashboards count attempted-but-forbidden
  invocations distinctly from input-validation failures. Repo is
  never called.
- `invalid` — `filter.limit > MAX_LIMIT` (500). Caller-input rejection
  surfaced as `DomainError::Validation`. Repo is never called. The
  split between `invalid` and `error` is load-bearing — collapsing
  them destroys the "bad request vs unhealthy system" signal.
- `error` — repo call returned `Err` (adapter / infrastructure
  failure, e.g. Postgres unavailable, query timeout). The use case
  emits then propagates the error verbatim.

**`hort_advisory_diff_duration_seconds` semantics** — observed by
`OsvAdvisoryAdapter::pull_diff_since` once per ecosystem per tick.
Brackets the per-ecosystem `pull_one_ecosystem` call (HTTP fetch +
zip walk); fired regardless of result so the histogram captures both
healthy and degraded latency. One histogram per configured
bulk-archive ecosystem.

**`hort_cron_rescan_eligible_artifacts` semantics** — set by
`CronRescanTickHandler::run` at the start of every tick to the count
returned by `RescanCandidatesRepository::select_eligible(BATCH_SIZE,
now)`. The cap is `BATCH_SIZE = 1000` (pinned in
`crates/hort-app/src/task_handlers/cron_rescan_tick.rs`); a sustained
gauge value at the cap indicates the eligibility pool exceeds what
one tick can drain. Operators alert on
`avg_over_time(hort_cron_rescan_eligible_artifacts[1h]) >= 1000` as the
"queue can't keep up" signal — increase tick frequency or the batch
cap.

The earlier-drafted `hort_scheduler_leader_active` gauge does NOT exist.
Leader election was removed in favour of k8s CronJob
+ the admin-task framework — the `kube_job_status_*` metrics already
expose CronJob single-active enforcement; we don't reinvent it.

Cardinality:
- `hort_scan_jobs_enqueued_total`: 4 trigger_source values → 4 series.
- `hort_advisory_diff_processed_total`: ≤ 11 ecosystems (default 8) ×
  4 results = ≤ 44 series ceiling. Default deployment 8 × 4 = 32.
- `hort_advisory_diff_duration_seconds`: ≤ 11 histograms (one per
  configured ecosystem). Default deployment 8 histograms.
- `hort_cron_rescan_eligible_artifacts`: 1 gauge (no labels).
- `hort_patch_candidates_listed_total`: 1 + N repository values
  (`_all` sentinel plus one per repository the admin has ever
  scoped a listing call to) × 4 results. Deployments with few
  repositories (the typical operator topology) see a single-digit
  series count; the cardinality is bounded by the repository
  inventory, not the call volume.

None of these metrics carry `artifact_id`,
`vulnerability_id`, `purl`, `package_name`, or `version` labels. Per-
instance information goes in `tracing::info_span!` fields; metrics
stay bounded by the closed-taxonomy axes above.

Source: `hort_app::metrics::{emit_scan_jobs_enqueued, emit_advisory_diff,
observe_advisory_diff_duration, set_cron_rescan_eligible_artifacts,
emit_patch_candidates_listed, TriggerSourceLabel, AdvisoryDiffResult,
PatchCandidateListResult}`.

### Advisory ingest efficacy

NIS2 Art. 21(2)(f) requires operators to *assess the effectiveness* of security
controls — not just have them. The advisory ingest count metric is the machine-
readable evidence that the OSV bulk-sync pipeline is actually populating the
advisory database (and by extension that `ArtifactBecameVulnerable` /
`PolicyEvaluated(Fail)` detections can fire).

| Metric | Type | Labels | Unit | Notes |
|--------|------|--------|------|-------|
| `hort_advisory_ingest_count` | counter | `category` | advisories | Per-ecosystem count of `AdvisoryEntry` values ingested in each `pull_diff_since` tick. `category` is a bounded fixed set (see below). **Only incremented on successful per-ecosystem ingest** — zero increments indicate the pipeline is silent. |

**`category` label semantics** (closed taxonomy of 11 + `other`):

| `category` value | OSV ecosystem | Notes |
|---|---|---|
| `javascript` | `npm` | Node.js / npm registry |
| `python` | `PyPI` | Python Package Index |
| `rust` | `crates.io` | Rust crates registry |
| `jvm` | `Maven` | Maven Central / JVM ecosystems |
| `go` | `Go` | Go module proxy |
| `ruby` | `RubyGems` | RubyGems.org |
| `dotnet` | `NuGet` | NuGet (.NET) |
| `php` | `Packagist` | Packagist (Composer) |
| `beam` | `Hex` | Hex (Erlang/Elixir) |
| `dart` | `Pub` | Pub (Dart/Flutter) |
| `conda` | `Conda` | Conda / data-science |
| `other` | *(any new/unrecognised OSV label)* | Should never appear; presence is an alert signal that `ingest_metrics.rs` needs updating |

**Note on the `category` label:** `category` is a per-metric schema label
(see the global label table), not a single global value set. For this metric,
`category` holds the advisory ecosystem class (11 named values + `other`,
distinct from the event-stream `category` taxonomy used by other metrics such
as `hort_events_published_total`). Cardinality is bounded at ≤ 12 series
regardless of future OSV ecosystem additions. Adding a raw `ecosystem` label
or any open-ended label to this metric is FORBIDDEN — it would violate the
per-metric unbounded-label prohibition.

**Alert spec (under-floor — NIS2 21(2)(f) efficacy):**

Alert when `increase(hort_advisory_ingest_count{category="javascript"}[7d]) == 0`
(or any other category with historical traffic). Zero 7-day increase means
the advisory-watch bulk sync is either broken, misconfigured, or consistently
failing — the advisory database for that ecosystem is not being populated.

Tuning: the alert threshold is deployment-specific. A conservative starting
point is any category that has contributed advisories in the past 30 days
suddenly going silent for 7 days. Active ecosystems (npm, PyPI, Maven) receive
multiple new advisories per day; a 7-day window with zero increments is a high-
confidence signal of pipeline failure rather than a genuine "no new advisories"
outcome.

**Source and emitter:**
`hort-adapters-advisory-osv::ingest_metrics::emit_advisory_ingest_count` —
emitted inside `OsvAdvisoryAdapter::pull_diff_since` at the adapter layer,
NOT at `hort-app`. This placement is intentional: the adapter is the only layer
that knows the per-ecosystem ingest count; `hort-app` only sees the aggregate
`AdvisoryDiffResult`.

### Provenance verification

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_provenance_verify_total` | counter | `backend`, `mode`, `result` | — | `result` ∈ `verified`, `rejected`, `no_attestation` |
| `hort_provenance_reject_total` | counter | `backend`, `reason` | — | `reason` ∈ `unsigned`, `untrusted_identity`, `rekor_not_found`, `cert_chain_invalid`, `bundle_malformed` |

Both counters are emitted at exactly **one layer** — the orchestration
use case
[`ProvenanceOrchestrationUseCase::verify_artifact`](../crates/hort-app/src/use_cases/provenance_orchestration.rs)
(the domain stays metrics-free; the verdict + resolved mode are surfaced
to this layer at the emission site). One increment per **applied
provenance verdict**. Standing decisions: ADR 0027
(`docs/adr/0027-artifact-provenance-verification.md`).

**Scrape target — the worker `/metrics` listener.** These
counters run in **`hort-worker`** (the `provenance-verify` job), which
serves an opt-in `GET /metrics` listener — bound via `HORT_WORKER_METRICS_BIND`
(disabled by default; set a pod-reachable address to enable) — making
these series (and every other worker metric: scan counters, queue depth, …)
scrapeable. The listener has **no per-request auth**; the `repository`
labels carry repo names, so operators **must** restrict it with a
NetworkPolicy (see the how-to
`docs/architecture/how-to/enable-provenance-verification.md` → *Worker
metrics*). The companion per-job `result_summary`
(`verified` / `rejected:<reason>` / `no_attestation` / `skipped:<why>`) is
the per-artifact trail and is **not** a metric.

The verify counter ticks on every applied verdict;
the reject counter ticks **alongside** it (in addition, not instead) only
on a rejection, so a `rejected` row appears on both metrics and operators
can break the rejection down by `reason` without a per-reason `result`
value on the verify counter.

Source of truth for the label-value enums:
- `hort_app::metrics::ProvenanceVerifyResult` for
  `hort_provenance_verify_total.result`.
- `hort_app::metrics::provenance_reject_reason_label` (an exhaustive
  match over `hort_domain::ports::provenance::ProvenanceRejectReason`)
  for `hort_provenance_reject_total.reason`.

Adding a variant to either requires updating this catalog in the same
change (catalog-and-code-atomic; the `ProvenanceRejectReason` match is
non-wildcard so a new domain variant is a compile error until the label
mapping + this catalog row are extended).

**`backend` label.** The provenance verifier id — `cosign` in Tier 1
(the only registered `ProvenancePort`). Bounded by the registered
verifier set (cosign → OCI today; Tier-2 PGP / PEP-740 / cargo verifiers
add their own ids as they ship). Shares the `backend` label name with the
storage-backend metrics but a disjoint, closed value set — the per-metric
row is authoritative.

**`mode` label** (`hort_provenance_verify_total` only). The resolved
`provenance_mode` for the artifact's scope — the lowercase wire-form of
[`ProvenanceMode`](../crates/hort-domain/src/entities/scan_policy.rs)'s
`Display`: `off`, `verify_if_present`, `required`. `off` never reaches the
emission site in production (the ingest gate never enqueues a
`provenance-verify` job for an `Off` policy), but the value
is in the closed taxonomy so the defensive `SkippedOff` orchestrator arm
and a future direct-invoke path stay representable. Cardinality: 3 values.

**`result` semantics** (`hort_provenance_verify_total`):

- `verified` — a trusted signature was verified (`ProvenanceVerified`
  emitted). Under every mode this is a success record; it does NOT
  release the artifact early (mirrors `ScanCompleted(clean)`).
- `rejected` — a typed rejection (`ProvenanceRejected` emitted) — the
  per-reason breakdown is on `hort_provenance_reject_total`. Covers a
  forged/untrusted signature under any mode, a `Required`-mode unsigned
  artifact (mapped to `Rejected{Unsigned}` upstream), and a
  `Required`-mode fetch-exhaustion fail-closed (`Rejected{RekorNotFound}`).
- `no_attestation` — no bundle was found/passed and the mode allowed it
  (`VerifyIfPresent` no-op, no event). Strictly the allowed-unsigned
  case: an unsigned artifact under `Required` ticks `rejected` instead.

**`reason` semantics** (`hort_provenance_reject_total`) — one per
`ProvenanceRejectReason` variant:

- `unsigned` — `Required` mode, no attestation present (the orchestrator
  maps `NoAttestation` → `Rejected{Unsigned}`).
- `untrusted_identity` — a cryptographically valid signature whose
  `{issuer, san}` matched no allowed `provenance_identities` pattern.
- `rekor_not_found` — the bundle's Rekor inclusion proof / SET could not
  be validated offline (also the fail-closed verdict on a `Required`-mode
  bundle-fetch / CAS-read exhaustion). Never a fall-back to
  a live Rekor fetch.
- `cert_chain_invalid` — the Fulcio certificate chain failed validation
  against the cached trust root.
- `bundle_malformed` — the bundle is structurally malformed or carries no
  offline-verifiable material.

**Forbidden labels.** No `artifact_id`, `content_hash`, `version`,
`repository`, `package`, or signer identity (`issuer`/`san`) — those would
explode cardinality (and `issuer`/`san` are signer-attributable). Per-
artifact context (`artifact_id`, `backend`, `reason`) lives in the
accompanying `info!` audit line on the `ProvenanceVerified` /
`ProvenanceRejected` decision (a supply-chain audit signal,
not `err`).

Cardinality: `hort_provenance_verify_total` ≤ `backend` (~few) × `mode`
(3) × `result` (3); `hort_provenance_reject_total` ≤ `backend` × `reason`
(5). Both are tiny in Tier 1 (one backend).

### Admin task dispatcher

The `TaskDispatcher` (generalised multi-kind worker poll loop,
`hort-app::task_dispatcher`) emits the following metrics for every
task kind registered with the dispatcher. In the initial v1
deployment the only registered kind is `"scan"`.

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_admin_tasks_enqueued_total` | counter | `kind`, `result` | — | emitted by the HTTP handler (`hort-http-admin-tasks`) on every terminal path of `POST /api/v1/admin/tasks/{kind}`; not emitted by the dispatcher itself |
| `hort_admin_tasks_completed_total` | counter | `kind`, `result` | — | `result ∈ {completed, failed_retry, failed_terminal}` |
| `hort_admin_tasks_duration_seconds` | histogram | `kind` | seconds | wall-clock time from claim to outcome recording, wrapping `TaskHandler::run` |
| `hort_admin_tasks_in_flight` | gauge | `kind` | tasks | incremented before `TaskHandler::run`, decremented after; 0 when idle |

**`hort_admin_tasks_enqueued_total` result semantics** (implemented in `hort-http-admin-tasks`):

- `result="ok"` — 202 fresh enqueue **or** 200 idempotency cache-hit. Both
  map to `"ok"` because the operator's intent (enqueue the task) was
  semantically satisfied in both cases. The 202/200 distinction is
  visible in the HTTP status code; operators who need to distinguish
  cache-hits from fresh enqueues should consult the
  `Idempotency-Key`-keyed log line emitted by the handler.
- `result="rbac_denied"` — `TaskUseCase::enqueue` returned
  `AppError::Domain(DomainError::Forbidden)`.
- `result="validation_error"` — `params.validate()` returned
  `Err(ValidationError)` **or** the use case returned
  `AppError::Domain(DomainError::Validation)`.

Note: the 403 "no principal" path (missing auth middleware or
`AuthContext::Disabled`) does NOT emit the counter — that path indicates
a misconfigured caller, not an operator invocation attempt.

**`hort_admin_tasks_completed_total` result semantics** (emitted by the dispatcher):

- `result="completed"` — handler returned
  `TaskOutcome::Completed`; `mark_completed` was called on the jobs row.
- `result="failed_retry"` — handler returned
  `TaskOutcome::Failed { retry: true }`; `reschedule` was called with
  exponential backoff (base 30 s, cap 24 h).
- `result="failed_terminal"` — handler returned
  `TaskOutcome::Failed { retry: false }`; `mark_failed` was called.

Note: for `kind="scan"`, `ScanTaskHandler::run` also calls
`ScanOrchestrationUseCase::record_outcome` internally, which emits the
scan-specific `hort_scan_jobs_total` counters. The `hort_admin_tasks_*`
metrics count the dispatcher-level view (one increment per claimed row);
`hort_scan_jobs_total` counts the scan-specific state transition.

Cardinality:
- `hort_admin_tasks_enqueued_total`: `kind` × 3 result values.
  v1: 1 kind (`scan`) × 3 = 3 series max (fewer if error paths are never
  hit in steady state).
- `hort_admin_tasks_completed_total`: closed by `kind` × 3 result values.
  v1: 1 × 3 = 3 series.
- `hort_admin_tasks_duration_seconds`: 1 histogram per kind.
  v1: 1 histogram.
- `hort_admin_tasks_in_flight`: 1 gauge per kind.
  v1: 1 gauge.

Source: `hort-http-admin-tasks::handlers::invoke` constants
`METRIC_ENQUEUED`, `RESULT_OK`, `RESULT_RBAC_DENIED`, `RESULT_VALIDATION_ERROR`;
`hort_app::task_dispatcher` constants `METRIC_COMPLETED`, `METRIC_DURATION`,
`METRIC_IN_FLIGHT`.

### Policy enforcement

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_policy_evaluation_total` | counter | `decision_point`, `result` | — | `decision_point ∈ {scan_result, promotion, re_evaluation, curation, curation_retroactive}`; `result ∈ {pass, warn, require_approval, block, reject, still_rejected, reset_to_quarantined, reset_to_released, retro_warn, retro_block, no_change}` |
| `hort_policy_violations_total` | counter | `decision_point`, `rule` | — | `rule ∈ {cve-severity-threshold, license-compliance, license-policy-shape, require-signature, max-artifact-age, curation-block, curation-warn}` |

Emitted by the application-layer use cases that evaluate policy at
each lifecycle decision point. Source of truth for
the `result` enum: `hort_app::metrics::PolicyEvaluationResult`. Adding a
variant requires updating this catalog in the same PR.

**`decision_point` semantics** — one value per use case that hosts a
policy evaluation gate:

- `scan_result` — emitted by
  [`QuarantineUseCase::record_scan_result`](../crates/hort-app/src/use_cases/quarantine_use_case.rs)
  on every scan-completion. Result values it can carry: `pass` (clean),
  `reject` (above-threshold finding not cleared by an exclusion).
- `promotion` — emitted by
  [`PromotionUseCase::evaluate_and_promote`](../crates/hort-app/src/use_cases/promotion_use_case.rs).
  Result values: `pass` (Allow), `warn` (Warn — promotes with audit),
  `require_approval`, `reject`.
- `re_evaluation` — emitted by the post-exclusion-add re-evaluation
  pass in
  [`PolicyUseCase::add_exclusion`](../crates/hort-app/src/use_cases/policy_use_case.rs).
  Result values: `still_rejected`, `reset_to_quarantined`,
  `reset_to_released`. One increment per rejected artifact processed.
- `curation` — emitted by the pre-storage curation gate in
  [`IngestUseCase::ingest`](../crates/hort-app/src/use_cases/ingest_use_case.rs).
  Result values: `pass` (Allow — the high-volume happy path),
  `warn` (Warn — proceeds with audit log), `block` (Block —
  ingest rejected). The `pass` label is normative across all
  decision points; the use case's `Allow` outcome maps to it.
- `curation_retroactive` — emitted by the retroactive evaluation pass
  in
  [`ApplyConfigUseCase::run_retroactive_curation_for_rule`](../crates/hort-app/src/use_cases/apply_config_use_case.rs).
  Result values: `no_change`, `retro_warn`, `retro_block`. One
  increment per active artifact evaluated against the new/tightened
  rule.

**`hort_policy_violations_total` semantics** — emitted at most once per
`(decision_point, rule)` pair per use-case invocation. The helper
[`emit_policy_violations`](../crates/hort-app/src/metrics.rs) groups a
`Vec<PolicyViolation>` by `rule` so duplicate violations on the same
rule do not inflate the counter beyond one tick per call. Not emitted
for `pass` / `no_change` outcomes (no violations).

`rule` values are enumerated and pinned by the catalog:

- `cve-severity-threshold` — finding count above the policy's
  `severity_threshold` (after exclusion filtering). Emitted by
  scan-result and promotion decision points.
- `license-compliance` — license content violated the policy's
  `license_policy.denied_licenses`. Emitted by scan-result and
  promotion decision points.
- `license-policy-shape` — operator-supplied `license_policy` JSON in
  the gitops YAML failed shape validation. Emitted as a `Validation`
  violation rather than panicking, so an operator typo surfaces as an
  audit signal instead of a service-down outage.
- `require-signature` — promotion gate observed the artifact had no
  signature while the policy demanded one. Emitted by the promotion
  decision point.
- `max-artifact-age` — promotion gate observed the artifact was older
  than the policy's `max_artifact_age_secs`. Emitted by the promotion
  decision point.
- `curation-block` — curation rule with `action: Block` matched the
  ingest coords or a pre-existing artifact (retroactive pass). Emitted
  by curation and curation_retroactive decision points.
- `curation-warn` — curation rule with `action: Warn` matched. Emitted
  by curation and curation_retroactive decision points.

Cardinality:
- `hort_policy_evaluation_total`: 5 decision points × ~11 result values
  = 55 series ceiling. Most decision points only emit a subset of the
  result enum (e.g. `still_rejected` only on `re_evaluation`,
  `retro_warn` only on `curation_retroactive`); effective deployment
  cardinality is ~25 series.
- `hort_policy_violations_total`: 5 × 7 = 35 series ceiling. Effective
  cardinality is lower because most `(decision_point, rule)`
  combinations never fire (e.g. `decision_point=curation,
  rule=cve-severity-threshold` is structurally impossible).

Per the architect skill's "high-cardinality metric labels" rule,
`policy_id` is NOT a label on either metric. The default-policy
fallback uses `Uuid::nil()` in the audit event payload; that
convention belongs in audit-query docs and structured logs, not in
metrics. Use `tracing` spans (`policy_id = %policy_id_for_audit`) for
per-policy drill-down.

### Manual curation decisions

Curator-driven decision counter — emitted from two use cases:

- `CurationUseCase::{waive, block}` in
  `crates/hort-app/src/use_cases/curation_use_case.rs` — the `waive` /
  `block` decision arms.
- `PolicyUseCase::{add_exclusion, remove_exclusion}` in
  `crates/hort-app/src/use_cases/policy_use_case.rs` — the
  `exclude_finding` / `unexclude_finding` decision arms.

The `repository` label resolution: every
emission site that knows the relevant repository id calls
`RepositoryAccessUseCase::metric_label(repo_id)` — the existing read
helper that already encapsulates the cardinality knob and the
resolve-failure sentinel — and threads the result into
`emit_curation_decision`. No new port; the existing read path is the
chokepoint.

| Metric | Type | Labels | Unit | Label values |
|--------|------|--------|------|--------------|
| `hort_curation_decisions_total` | counter | `decision`, `repository`, `result` | events | `decision ∈ {waive, block, exclude_finding, unexclude_finding}`; `repository ∈ {"_all", <key>, "unknown"}`; `result ∈ {ok, denied, invalid, conflict, error}`. Full closed taxonomies below. |

Source of truth for the enums:
- `hort_app::metrics::CurationDecisionLabel` for `decision`.
- `hort_app::metrics::CurationDecisionResult` for `result`.
- Helper: `hort_app::metrics::emit_curation_decision(decision, repository, result)`.

Adding a variant to either enum requires updating this catalog in the
same change (architect anti-pattern checklist).

**`decision` semantics** (closed taxonomy of 4):

- `waive` — `CurationUseCase::waive`. Curator-driven release
  of a quarantined or held artifact, mirroring `admin_release`. One
  tick per call.
- `block` — `CurationUseCase::block`. Curator-driven
  rejection. For `BlockTarget::Artifact` emits one tick per call; for
  `BlockTarget::VersionList` (continue-on-error)
  emits **one tick per attempted append** so operators can dashboard
  per-append error rates on bulk operations.
- `exclude_finding` — `PolicyUseCase::add_exclusion` from the curator
  path. Emitted at every terminal outcome.
- `unexclude_finding` — `PolicyUseCase::remove_exclusion` from the
  curator path. Emitted at every terminal outcome.

**`repository` semantics** (sentinel-aware):

- `"_all"` — emitted when **either**:
  (a) the decision targets a `PolicyScope::Global` exclusion
  (cross-repo finding-exclusion has no single repository to
  label); OR
  (b) the decision failed before a `repository_id` was resolved
  (privilege denial, input validation rejection that fires
  pre-lookup); OR
  (c) `METRICS_INCLUDE_REPOSITORY_LABEL=false` is set at the
  composition root, which makes
  `RepositoryAccessUseCase::metric_label` short-circuit every call
  to the `_all` sentinel — the operator-facing cardinality knob.
- `"<key>"` (repository key — `repo-foo`, `npm-main`, etc.) — the
  resolved key when a `repository_id` is known and the lookup
  succeeded.
- `"unknown"` — fallback for the case where `metric_label` was called
  with a `repository_id` that did not resolve to any row in the
  repository table (race with delete, or a stale id from the
  artifact stream). NEVER the raw UUID — high-cardinality
  attacker-controlled dimensions on metrics are the architect's
  hard-block anti-pattern. The `unknown` collapse keeps cardinality
  bounded under any malformed input.

**`result` semantics** (closed taxonomy of 5):

- `ok` — successful decision (waive succeeded; block appended the
  `ArtifactRejected` event for a `BlockTarget::Artifact` or the
  per-append succeeded for a `BlockTarget::VersionList` entry;
  add/remove exclusion appended `ExclusionAdded` / `ExclusionRemoved`
  AND both projection upserts landed).
- `denied` — `require_curate_or_admin()` rejected the caller.
  Emitted before the early return so privilege failures dashboard
  distinctly from validation failures. The repo is never called.
- `invalid` — use-case input validation rejection (empty
  justification, oversized justification > 512 bytes, list empty,
  list oversize, wrong artifact state mapped to
  `DomainError::Validation`; non-existent parent policy or archived
  parent on add/remove exclusion). The append is never attempted.
- `conflict` — event-store version conflict (`DomainError::Conflict`
  or `DomainError::Invariant`) returned by `AppendEvents`. Surfaced
  as the "race lost, retry may succeed" signal — distinguished from
  generic `error` so operators can spot real contention without
  alarming on infrastructure failures.
- `error` — infrastructure failure (Postgres unavailable, adapter
  returned an unexpected `Err`, projection upsert failed after a
  successful append). The use case emits then propagates the error.

**Per-append emission contract** (`block(BlockTarget::VersionList)`):

The continue-on-error loop emits ONE tick per attempted
append, NOT one per call. A 5-version list where 4 transition and 1
fails the source-state guard produces:

```
hort_curation_decisions_total{decision="block", repository="<key>", result="ok"}      += 4
hort_curation_decisions_total{decision="block", repository="<key>", result="conflict"} += 1
```

This lets operators dashboard per-append outcomes on bulk operations
without resampling the call envelope. The same per-attempt contract
applies to the already-Rejected idempotent no-op (one `ok` tick per
no-op, since the operator intent succeeded — the artifact is in the
requested terminal state).

**Cardinality envelope.** With the `METRICS_INCLUDE_REPOSITORY_LABEL`
knob enabled (the production default for installations with <10k
repos), the worst-case series count is:

> 4 decisions × (N_repos + 2 sentinels) × 5 results = 20 × (N_repos + 2)

For a 1k-repo deployment that's ~20k series. With the knob disabled
(set by operators at scale), the repository label collapses to
`_all` and the upper bound is:

> 4 × 1 × 5 = 20 series

Both regimes are well under the architect-skill's per-metric series
cap. Compare against `hort_ingest_total` (same `repository × format ×
result` cardinality shape) and `hort_ref_moved_total` (same `repository
× result` shape) — the curation metric stays inside the
existing budget without inventing a new emission convention.

**Forbidden labels** (architect anti-pattern checklist): no
`artifact_id`, `actor_id`, `policy_id`, `exclusion_id`, `cve_id`,
`package_name`, `version`, or raw UUID on any of these dimensions.
Per-instance attribution lives in the `tracing::info!` spans on each
use-case method — every emission site is paired with an `info!` line
carrying the actor_id, artifact_id (where applicable), correlation_id,
and outcome string. Cardinality cannot drift from this catalog into
production via a future PR without removing the `as_str` impls on the
two enums.

### Artifact retention + GC

The retention evaluator (`RetentionUseCase::evaluate_policies`)
emits the first two rows. `hort_retention_purged_total` is emitted by
the storage-GC walk (`PurgeUseCase::process_expired`). The remaining
two (`hort_event_store_streams_archived_total`,
`hort_storage_blobs_deleted_bytes_total`) are emitted by the
audit-retention seal and the storage `delete` path — see
the "Audit-retention stream seal" and "Storage blob bytes
reclaimed" subsections below.

**`policy_id` is an allowed label here.** This is the one place in the
catalog where `policy_id` is a metric label.
Retention policies are a small operator-declared set (a handful of
named retention rules per deployment — unlike scan policies, where the
`hort_policy_evaluation_total` note forbids `policy_id` for cardinality).
The cardinality ceiling is `policy_count × result_arity (6)` for
`hort_retention_evaluations_total` and `policy_count × reason_arity (5)`
for `hort_retention_expired_total` — both bounded and small. Per-artifact
attribution (`artifact_id` / `content_hash` / `purl` /
`vulnerability_id`) is the architect anti-pattern hard-block and stays
in `tracing` fields, never on these series.

| Metric | Type | Labels | Unit | `result` / `reason` values |
|--------|------|--------|------|----------------------------|
| `hort_retention_evaluations_total` | counter | `policy_id`, `result` | — | `result ∈ {matched, no_match, skipped_stale_scan, skipped_quarantined, skipped_rejected, error}` |
| `hort_retention_expired_total` | counter | `policy_id`, `reason` | — | `reason ∈ {age_exceeded, unused_ttl, keep_last_n, manual, security_finding}` |

`result` value semantics (one emission per evaluated (policy,
artifact) pair; archived policies and the empty policy/candidate set
emit nothing):

- `matched` — the policy predicate matched and an `ArtifactExpired`
  was appended to the artifact stream this pass.
- `no_match` — the predicate was evaluated and did not match.
- `skipped_stale_scan` — a security-driven predicate
  could not evaluate because the artifact's most recent scan is older
  than `2 × resolved_rescan_interval` (resolved per the
  policy chain — repo-scoped → … → default 24 h). **Not an error**;
  the sweep proceeds and the artifact becomes eligible again after the
  next scan. **This label is the operator alarm path for "the rescan
  loop is lagging"** — operators alarm on its rate; a test asserts
  it fires (not just that it is absent). A score-read
  failure and a missing / null-`last_scan_at` score row all fail safe
  to this label (a security predicate must never expire an artifact
  whose scan freshness cannot be proven).
- `skipped_quarantined` — the artifact is
  `quarantined`; GC-protected, not evaluated.
- `skipped_rejected` — the artifact is `rejected` or
  `scan_indeterminate` (evidence / terminal-failure); content stays
  until manual admin override, not evaluated.
- `error` — a port read (`read_stream` / `list_findings` /
  `append_expired`) failed for this pair. The sweep records it and
  continues with the next pair (one bad row never aborts the pass;
  it is retried on the next sweep).

`reason` value semantics — the canonical
`hort_domain::retention::ExpirationReason::metric_label` string (the
domain owns the label vocabulary so emitter and catalog cannot drift):
`age_exceeded` / `unused_ttl` / `keep_last_n` / `manual` /
`security_finding`. The B3 evaluator currently emits `age_exceeded`
and `security_finding` (its in-scope predicates); `unused_ttl` /
`keep_last_n` / `manual` are reserved for the same metric and emitted
once the `UnusedFor` / `KeepLastN` / manual-expiry input ports are
wired (named follow-on; the reason vocabulary is locked now so the
catalog does not churn later).

Source: `hort_app::metrics::{emit_retention_evaluation,
emit_retention_expired, RetentionEvaluationResult}`;
`hort_domain::retention::ExpirationReason::metric_label`.

#### Storage-GC purge (`PurgeUseCase::process_expired`)

The two-stage split's second stage: for each `ArtifactExpired` event
with no following `ArtifactPurged`, the GC walk decrements
`content_references`, deletes the CAS blob when the cross-`kind`
refcount hits `0`, and emits `ArtifactPurged`. One
`hort_retention_purged_total` emission per content-hash decision.

**No `policy_id` label on this metric.** Unlike the two evaluation
rows above, the purge stage consumes the durable `ArtifactExpired`
decision (which already carries the authorising policy in its
payload + the `hort_retention_expired_total` series); attributing the
purge to a policy again would only duplicate that signal and is not in
the schema (`hort_retention_purged_total{result}` — `result` only).
Per-artifact attribution (`artifact_id` / `content_hash`) is the
architect anti-pattern hard-block and stays in `tracing` fields, never
on this series. Cardinality ceiling is a fixed `result_arity (3)`.

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_retention_purged_total` | counter | `result` | — | `result ∈ {success, blob_kept, storage_error}` |

`result` value semantics (one emission per content-hash purge
decision; an empty pending set emits nothing):

- `success` — the cross-`kind` `content_references` count for the hash
  reached `0`, the CAS blob was deleted via `StoragePort::delete`
  (idempotent: an already-absent blob is also `success`), and
  `ArtifactPurged{refs_remaining=0}` was appended.
- `blob_kept` — a still-live reference (a promoted ref, or an OCI
  `oci_subject` row) keeps the blob alive (`refs_remaining > 0`); only
  this artifact's reference was removed and the blob was deliberately
  NOT deleted. `ArtifactPurged{refs_remaining=N}` was appended.
- `storage_error` — `StoragePort::delete` failed transiently for a
  refcount-0 blob. **The `ArtifactExpired` decision is not lost**: no
  `ArtifactPurged` is emitted, the `content_references` rows are not
  removed (the deletion is rolled back with the failed transaction),
  and the next sweep retries this artifact (two-stage idempotency).

Source: `hort_app::metrics::{emit_retention_purged,
RetentionPurgedResult}`.

#### Audit-retention stream seal (`EventStoreRetentionUseCase::archive_terminal_streams`)

The audit-retention sweep: for each enumerated candidate stream
whose per-category retention rule + the compliance retention floor are
satisfied, the stream is sealed via the `seal_and_remove` chokepoint
(`delete_stream` for `StreamRetentionMode::Delete`, `archive_stream`
for `Archive`) — the `StreamSealed` tombstone is emitted by the
adapter, never by this metric path. One
`hort_event_store_streams_archived_total` emission per candidate-stream
decision (sealed or skipped).

**Emitting-layer note (prefix-vs-owner tension — recorded here per the
catalog rule).** The metric *name* is `hort_event_store_*`, and the
"Event store (`hort-adapters-postgres`)" ownership section normally
places `hort_event_store_*` series in the Postgres adapter. This one is
emitted from **`hort-app`** (`hort_app::metrics::emit_streams_archived`) on
purpose: the `skipped` outcomes (meta-stream guard, non-terminal tail,
C-1 floor not elapsed, already-sealed idempotent re-run, unregistered
category) never reach the adapter — the `EventStoreRetentionUseCase` is
the only layer that observes *all three* result values. Splitting the
emission across layers would double-count or silently drop `skipped`.
The emitter is therefore `hort-app::metrics` and
this note is the recorded reconciliation of the prefix-vs-ownership
tension (no `stream_id` / `category` label — those stay in `tracing`
fields; the only label is the bounded three-value `result`).

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_event_store_streams_archived_total` | counter | `result` | — | `result ∈ {archived, deleted, skipped}` |

`result` value semantics (one emission per candidate-stream seal
decision; an empty candidate set emits nothing):

- `archived` — the stream was sealed via `EventStore::archive_stream`
  (`StreamRetentionMode::Archive`); the chokepoint emitted the
  `StreamSealed` tombstone and moved the stream to the configured cold-
  storage target prefix (the cold-storage *write* is a named
  follow-on; v1 only threads the target through the chokepoint).
- `deleted` — the stream was sealed via `EventStore::delete_stream`
  (`StreamRetentionMode::Delete`, the v1 default); the chokepoint
  emitted the `StreamSealed` tombstone and removed the live rows.
- `skipped` — a precondition stopped the seal this pass: the meta-
  stream guard (`StreamId::eventstore_retention()`), a non-terminal
  tail (`TerminalGated`), the retention floor not yet elapsed, an already-
  sealed empty-read (idempotent re-run), or an unregistered category.
  One emission per skipped candidate regardless of which precondition
  fired — the precise reason is a `tracing` field, never a metric
  label (cardinality hard-block). A per-stream chokepoint failure is
  **not** counted here (it is a `tracing::error!` + a summary `errors`
  increment; the stream is retried next sweep — fail-safe, e.g. while
  `hort_retention_role` is not yet wired).

Source: `hort_app::metrics::{emit_streams_archived,
StreamsArchivedResult}`.

#### Storage blob bytes reclaimed (folded into the storage `delete` path)

The storage-reclamation counter, folded into the storage `delete`
path. Each real `StoragePort::delete` impl
(`hort-adapters-storage::{filesystem, object_store_backend}`) stats the
object size **before** the delete and, on a *successful* removal,
increments this counter by that size. An already-absent blob (the
`DomainError::NotFound` idempotent re-purge path) does
**not** increment it — re-running a purge on a gone blob reclaims
nothing, so double-counting on retry is impossible by construction.
Emitted from the **`hort-adapters-storage`** layer (the `hort_storage_*`
ownership row below) — its local `metrics` module owns
`emit_blob_deleted_bytes`; the `StoragePort::delete` trait signature is
unchanged (the trait default no-op stays for test doubles / WASM
stubs).

| Metric | Type | Labels | Unit | Notes |
|--------|------|--------|------|-------|
| `hort_storage_blobs_deleted_bytes_total` | counter | `backend` | bytes | Sum of CAS-blob bytes reclaimed by successful `StoragePort::delete` calls. `backend` is the only label (bounded — `filesystem` / `s3` / `gcs` / `azure` / `memory`); no `content_hash` / `artifact_id` (architect high-cardinality hard-block — those stay in `tracing`). |

Source: `hort_adapters_storage::metrics::emit_blob_deleted_bytes`
(called from `filesystem::FilesystemStorage::delete` and
`object_store_backend::ObjectStoreStorage::delete`).

#### Retention-set cardinality review + completeness closure (recorded 2026-05-18)

Every retention metric was catalogued and `DebuggingRecorder`-tested
in its emitting change (the "the metric's emitting PR adds its row"
rule). A reconciliation audit
of the reserved-name set against the emit-site code
(`hort_app::metrics` / `hort_adapters_storage::metrics`) found **no
catalog↔code label drift**; every `result` / `reason` /
`backend` label string in this catalog matches its enum `as_str()`
verbatim. The per-metric cardinality verdict required by the architect
anti-patterns checklist is recorded
here as the closure record:

| Metric | Labels | Ceiling | Verdict |
|--------|--------|---------|---------|
| `hort_retention_evaluations_total` | `policy_id`, `result` | `policy_count` × `result_arity (6)` | Bounded. `policy_id` is the operator-declared small retention-rule set (the one sanctioned `policy_id` use — rationale above); `result` is the fixed 6-value set. No `artifact_id` / `content_hash` / `purl` / `vulnerability_id`. |
| `hort_retention_expired_total` | `policy_id`, `reason` | `policy_count` × `reason_arity (5)` | Bounded. `reason` is the canonical `hort_domain::retention::ExpirationReason::metric_label` fixed 5-value vocabulary (domain-owned so emitter and catalog cannot drift). No per-artifact labels. |
| `hort_retention_purged_total` | `result` | `result_arity (3)` | Bounded. `result`-only by design (the durable `ArtifactExpired` decision already carries the authorising policy — no second `policy_id` attribution). No per-artifact / per-hash labels. |
| `hort_event_store_streams_archived_total` | `result` | `result_arity (3)` | Bounded. `result`-only; the precise skip precondition and `stream_id` / `category` stay in `tracing` fields, never on the series. Emitter is `hort-app` by the catalogued prefix-vs-owner reconciliation above. |
| `hort_storage_blobs_deleted_bytes_total` | `backend` | `backend_arity (~5)` | Bounded. `backend` ∈ `filesystem` / `s3` / `gcs` / `azure` / `memory`. No `content_hash` / `artifact_id` (those stay in `tracing`). |
| `hort_download_audit_dropped` | `format`, `repository`, `result` | `format (~40)` × `repository (≤10k, `_all` at scale)` × `result_arity (1)` | Bounded. Same `format` / `repository` envelope as `hort_download_total` (sentinels `_all` / `unknown`); `result` is the single fixed `append_error` drop value. No `user_id` / `artifact_id` / `content_hash`. |
| `hort_api_token_used_audit_dropped` | `result` | `result_arity (2)` | Bounded. `result`-only (token use has no `format` / `repository` dimension); `user_id` / `token_id` are forbidden unbounded dimensions — per-instance detail is in the accompanying `tracing` span. |

All §7 metrics: **labels reviewed — bounded, no high-cardinality
dimension** (no `artifact_id` / `user_id` / `actor_id` /
`content_hash` / `stream_id` / `purl` / `vulnerability_id` / version
string on any series; `policy_id` is the operator-declared bounded
exception justified above). Per-metric `DebuggingRecorder`
label-assertion coverage is complete:
`hort_retention_evaluations_total` — all six `result` arms
(`retention_use_case` `tests::metrics`);
`hort_retention_expired_total` — `age_exceeded`
+ `security_finding` (`unused_ttl` / `keep_last_n` /
`manual` are reserved, emitted once their input ports are wired —
named follow-on, vocabulary locked now);
`hort_retention_purged_total` (`purge_use_case` `tests`, all 3
values); `hort_event_store_streams_archived_total`
(`eventstore_retention_use_case` `tests`, all 3 values);
`hort_storage_blobs_deleted_bytes_total`
(`hort_adapters_storage::metrics` test);
`hort_download_audit_dropped` (`artifact_use_case`
`download_audit_b12`); `hort_api_token_used_audit_dropped`
(`pat_validation_use_case` `token_use_audit_b13` + `metrics.rs`, both
values). Retention-set metrics-catalog completeness: **closed**.

### Event store (`hort-adapters-postgres`)

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_event_store_appends_total` | counter | `category`, `result` | — | `success`, `conflict`, `error` |
| `hort_event_store_append_duration_seconds` | histogram | `category` | seconds | — |
| `hort_event_store_reads_total` | counter | `category`, `operation` | — | `operation` ∈ `read_stream`, `read_category` |
| `hort_audit_events_blocked_total` | counter | `attempted_op`, `decision_point` | — | `attempted_op` ∈ `update`, `delete`, `truncate`; `decision_point` ∈ `startup_probe`, `trigger_caught` |

**`category` label values** (source of truth:
`crates/hort-adapters-postgres/src/metrics.rs::values`):

- `artifact` — artifact-lifecycle streams (ingest, scan, quarantine,
  promotion).
- `policy` — policy-lifecycle streams.
- `admin` — admin-user lifecycle streams (`AdminBootstrapped`
  events emitted by `hort-server admin bootstrap`).
  Cardinality is by design minimal — a realistic deployment has a
  handful of admin users; series count stays well under any cardinality
  ceiling.
- `repository` — repository-aggregate streams.
  First event class: `ChecksumMismatch` emitted by
  `IngestUseCase::ingest_verified` when an upstream-published checksum
  disagrees with the bytes on the wire. The repository is the aggregate
  because no artifact row is minted on the mismatch path.
- `auth` — authentication-attempt audit streams. One stream per
  UTC date (daily rotation). Failures
  produce `AuthenticationAttempted` events on this category; successes
  do not (audit-value-per-byte). Throttled to ≤ 1 append per 60s per
  `(client_ip_bucket, result)` tuple via the `EphemeralStore`. See
  the "Auth-event store appends" section above for the
  `hort_auth_events_appended_total` metric and the closed taxonomy of
  event-payload `result` values.
- `download_audit` — opt-in per-`(repository, UTC-date)`
  download-audit streams. Emitted
  only for repositories whose `download_audit_enabled` flag is set;
  the opt-in flag is the volume control (no throttle). One
  `ArtifactDownloaded` event per served download from an opted-in
  repository. Cardinality is bounded by (opted-in repos × active
  days).
- `token_use` — throttled per-`(token_id, UTC-date)` token-use audit
  streams. One `ApiTokenUsed` event
  per successful PAT validation that wins the per-`token_id` 1-hour
  throttle; the throttle is the volume control (contrast
  `download_audit`'s opt-in flag). Cardinality is bounded by (active
  tokens × active days).
- `retention_policy` — event-sourced retention-policy lifecycle
  streams. One `RetentionPolicyChanged`
  event per gitops-authored create/update/archive plus the per-sweep
  `Evaluated` audit breadcrumb. Cardinality is bounded by the small,
  operator-authored retention-policy count (policy mutations are rare;
  the sweep breadcrumb is one per active policy per evaluate tick — no
  throttle needed).

Note: for `read_category`, the `category` label is technically redundant
(it's the lookup key). Kept for symmetry with `read_stream`; not a bug.

`hort_audit_events_blocked_total` is emitted by `PgEventStore`
at exactly two
sites; the Postgres `events_immutable` trigger does NOT emit metrics
itself, so the counter's `decision_point` label is the only signal
operators get for distinguishing the two failure shapes:

- `decision_point="startup_probe"` — `PgEventStore::new` ran
  `has_table_privilege(current_user, 'events', '<priv>')` for each of
  `UPDATE`, `DELETE`, `TRUNCATE` and one returned `true`. The binary
  refused to start; `attempted_op` carries the offending privilege.
  Operator action: REVOKE the privilege from the runtime role and
  restart. (Skipped without emission when `current_user` is a Postgres
  superuser, because superusers bypass ACL and the probe is
  semantically meaningless; a WARN-level tracing event is logged
  instead — operator should move the runtime to a non-superuser
  member of `hort_app_role` to enable the probe.)
- `decision_point="trigger_caught"` — the `events_immutable` trigger
  raised SQLSTATE `P0001` for an attempted `UPDATE`/`DELETE`/`TRUNCATE`
  reaching the `events` table at runtime; the adapter caught the
  error via `crate::event_store::inspect_audit_block`. Steady-state
  count is zero — every non-zero increment is a regression worth
  investigating (a code path bypassed the role guard but the trigger
  caught it as the backstop). Owner taxonomy:
  `hort-adapters-postgres::metrics::AuditBlockedOp` /
  `AuditBlockedDecisionPoint`.

Cardinality: 3 (ops) × 2 (decision points) = 6 series per deployment.
Flat, well under any ceiling.

### Event-chain tamper-evidence

NIS2 Art. 21(2) "tamper-resistant logging" and the GDPR
Art. 17(3)(b) erasure-exemption claim require *machine-readable evidence*
that the audit log's cryptographic chain has been verified, not merely
that a chain exists. `hort_event_chain_verify_total` is that evidence: it
is emitted exactly once per `hort-server verify-event-chain` run and maps
1:1 from the pure `ChainReport` the offline verifier computes.

| Metric | Type | Labels | Unit | Notes |
|--------|------|--------|------|-------|
| `hort_event_chain_verify_total` | counter | `result` | runs | One increment per `verify-event-chain` run. `result ∈ {ok, broken, missing_checkpoint}` — exactly these three values, a per-metric closed enum. `ok` = every per-stream hash chain intact **and** the anchored-checkpoint cross-check passed; `broken` = a detected integrity violation (per-event hash mismatch, dangling chain, position gap, or an unsealed/absent stream not justified by an anchored `StreamSealed`); `missing_checkpoint` = chain intact but external anchoring could not be fully attested (no checkpoint, a `checkpoint_seq` gap, or a stale anchor — a coverage gap, not a proven violation). |

**`result` label semantics** (closed taxonomy of exactly 3):

| `result` value | Maps from | Exit code |
|---|---|---|
| `ok` | `ChainReport::Ok` | `0` |
| `broken` | `ChainReport::Broken` | `2` |
| `missing_checkpoint` | `ChainReport::MissingCheckpoint` | `3` (when `--fail-on-missing-checkpoint`, the default) / `0` otherwise |

`result` is a per-metric schema label (see the global label table), not
the global value set; for this metric it holds exactly the three values
above. An operational error (DB unreachable, anchor store unreadable, a
deserialization failure not attributable to tampering) does **not**
emit this metric — the verifier could not run, so there is no verdict;
the subcommand exits `1`. Cardinality is fixed at ≤ 3 series. Adding any
other label or value is FORBIDDEN — it would violate the per-metric
closed-enum rule and break the attestation CI gate
(`scripts/check-g1-attestation-gate.sh`), which
keys on this exact `{metric, result-enum}` shape.

**Single emitter (architect "one metric, one layer, no double-count"):**
emitted **only** at the `hort-server` `verify-event-chain` subcommand
layer (`crates/hort-server/src/cli/verify_event_chain.rs::emit_metric`),
once per run. The `hort-domain` verify core is pure and emits nothing; the
`hort-adapters-postgres` append path does **not** emit this metric (the
reserved name `hort_event_chain_link_check_total` is held for a
*future* append-time self-check that is deliberately not implemented
— never reuse `hort_event_chain_verify_total` for it).

**Attestation gate (`scripts/check-g1-attestation-gate.sh`):** the
`docs/compliance/` tamper-resistant-logging attestation and the
`docs/compliance/GDPR.md` Art. 17(3)(b) wording are publishable only
while both halves of the compliance evidence hold: the audit-chain
verification telemetry (this `hort_event_chain_verify_total` row) and
the vulnerability-handling-efficacy telemetry (the
`hort_advisory_ingest_count` row), **plus** the named regression tests
in their source files. The CI gate fails unless both catalog rows are
present here and the named regression tests exist.
**Tamper-evidence status:** the chain, the offline verifier, and the
signed-checkpoint emission are all shipped with named regression tests
+ catalog rows. **The control is active at the tamper-EVIDENT bar** —
its deliverable is *detection* of audit-log tampering, which is
code-enforced and complete. The compliance attestation may be published
**only** with honestly-scoped wording — **tamper-evident, never
"tamper-proof"/"tamper-resistant" unqualified** (the gate's wording
check enforces this across `docs/compliance/`). The WORM /
anchor-immutability half is a **recommended operator deployment
control + accepted residual** (the storage layer is pluggable — the
core cannot enforce or verify a backend's WORM; `object_store 0.13`
cannot set per-object retention) and is **not** a blocker; the
unsigned-advisory `backfill_baseline`/`max_global_position` and a
`hort-evchain/v2` signed-baseline bump are **deliberately not
scheduled** (the bar is detection, not tamper-proofing vs privileged
insiders; artifact-byte integrity is a separate,
independently-enforced CAS concern). **The gate closes by honest
attestation wording matching the delivered property — not by
additional code.** The one live obligation is operational: the
operator enables the default-disabled `verify-event-chain` CronJob
and alarms its `broken`/`missing_checkpoint`/seq-gap result
(runbook, not engineering).

**Alert spec:** alert on any `increase(hort_event_chain_verify_total{result="broken"}[1h]) > 0`
(an integrity violation — page immediately) and on
`increase(hort_event_chain_verify_total{result="missing_checkpoint"}[period]) > 0`
once a checkpoint emitter is deployed (a sustained coverage gap means
the anchor cron stopped). `result="ok"` going silent (no increase over
the expected verify cadence) means the offline verifier itself is not
running — also alertable.

#### Event-chain checkpoint emission (external-anchor half)

The external-anchor half of the tamper-evidence control: a dedicated
`eventstore-checkpoint`
`TaskHandler` (driven by an external k8s CronJob via the
admin-task framework — **no** in-process scheduler; default **hourly**)
snapshots every live stream's chain head, assembles
the signed checkpoint (Merkle root over the `stream_id`-sorted
`(stream_id, final_stream_position, head_event_hash)` witness + monotonic
`checkpoint_seq` + the first-checkpoint `backfill_baseline` honesty
caveat), Ed25519-signs the shared `SignedBody` (the byte-identical
verifier↔emitter contract pin), and writes it to the S3-Object-Lock-WORM
anchor prefix. `hort_event_chain_checkpoint_total` is the emission
evidence — emitted exactly once per emission cycle (a periodic tick
**or** the pre-purge hook the retention purge calls).

| Metric | Type | Labels | Unit | Notes |
|--------|------|--------|------|-------|
| `hort_event_chain_checkpoint_total` | counter | `result` | cycles | One increment per checkpoint-emission cycle. `result ∈ {emitted, sign_failed, anchor_write_failed}` — exactly these three, a per-metric closed enum. `emitted` = the signed checkpoint was durably WORM-anchored; `anchor_write_failed` = the cycle could not anchor (anchor-store read/write or live-chain DB read failed — retryable, the CronJob retries next tick); `sign_failed` = a signing fault. **Distinct** from `hort_event_chain_verify_total` (a different metric at a different layer — the verifier; never conflated, architect one-metric-one-layer + reserved-name discipline). |

**`result` label semantics** (closed taxonomy of exactly 3):

| `result` value | Meaning | Outcome |
|---|---|---|
| `emitted` | signed checkpoint durably WORM-anchored | `TaskOutcome::Completed` |
| `sign_failed` | a signing fault (**reserved**: no v1 runtime path — the signing key is validated at adapter construction and ed25519 signing of an in-memory `Vec` is infallible, so a cycle cannot reach a sign fault at run time; the label is in the closed taxonomy and exercised by the `DebuggingRecorder` catalog test so the schema is complete and a future signing-fault surface has a pre-reserved label — documented, not faked) | `TaskOutcome::Failed { retry: true }` |
| `anchor_write_failed` | could not anchor this cycle (anchor-store read/write failure, or the live-chain DB snapshot failed — the taxonomy has no separate `db_read_failed`; "could not anchor this cycle" is `anchor_write_failed`) | `TaskOutcome::Failed { retry: true }` |

**Single emitter (architect "one metric, one layer, no double-count"):**
emitted **only** at the `hort-app` emission-task layer
(`crates/hort-app/src/task_handlers/eventstore_checkpoint.rs::emit_metric`),
once per emission cycle (both the periodic `TaskHandler::run` tick and
the pre-purge `CheckpointEmissionHook` calls route
through the same single `emit_metric`). The pure `hort-domain`
checkpoint-build core and the `hort-adapters-checkpoint-anchor` write
adapter emit nothing. `result` is a per-metric schema label holding
exactly the three values above; adding any other label/value is
FORBIDDEN (per-metric closed-enum rule). Cardinality ≤ 3 series.

**S3 Object-Lock WORM nuance (precise, not fudged):** `object_store`
0.13 exposes no API to set per-object Object-Lock retention on `put`
(`PutOptions` carries only `mode`/`TagSet`/a fixed `Attributes`
enum/opaque ignored `extensions`). The emitter does a plain `put`; the
WORM guarantee is the **operator-provisioned bucket default retention**
— the anchor bucket MUST be created with **S3 Object Lock enabled + a
COMPLIANCE-mode default retention** (S3 then stamps every new object
automatically). The residual: the application cannot enforce/verify the
bucket provisioning through `object_store`; the deployment hardening
guide states the requirement (see the `ObjectStoreCheckpointEmitter`
type doc). Tracing: `info!` on a successful emission (seq,
max_global_position, stream count, backfill flag — NO key material);
`error!` on sign / anchor-write failure (unrecoverable for that cycle).
No `#[instrument(err)]` (a failed cycle is a `TaskOutcome::Failed`, not
a `Result::Err`).

**Alert spec:** alert on
`increase(hort_event_chain_checkpoint_total{result="anchor_write_failed"}[period]) > 0`
(a sustained inability to anchor — the chain is no longer externally
attested; this is the condition `hort_event_chain_verify_total{result="missing_checkpoint"}`
will *also* eventually report from the verifier side). `result="emitted"`
going silent over the configured cadence (default hourly) means the
external CronJob stopped — alertable (the same coverage-gap class).

### Event-chain verifier liveness

| Metric | Type | Labels | Unit | Values |
|--------|------|--------|------|--------|
| `hort_event_chain_verify_overdue` | gauge | — (no labels) | Boolean (0/1) | `0` = a `verify-event-chain` run completed within the staleness window; `1` = overdue OR never ran |

Emitted **once at boot** by `hort-server::composition` (the
`emit_event_chain_verify_liveness_signal` fn, a deliberate parallel of
`emit_staging_sweep_liveness_signal`). The event-chain verifier
(`hort-server verify-event-chain`) is correct crypto but ships CLI-only;
the `scheduledTasks.verifyEventChain` CronJob (default-disabled)
schedules it, and on each completed run the subcommand records a
`kind='verify-event-chain' AND status='completed'` row via
`JobsRepository::record_run_completion`. The composition root queries the
newest `completed_at` for that kind
(`JobsRepository::last_completed_at_by_kind`), feeds it through the pure
`hort_domain::policy::evaluate_event_chain_verify_liveness` predicate, and
sets the gauge: `0.0` when a verify run completed within
`HORT_EVENT_CHAIN_VERIFY_STALENESS_MULTIPLIER × HORT_EVENT_CHAIN_VERIFY_EXPECTED_INTERVAL_SECS`
(defaults `3 × 86400 s` = three days), `1.0` when overdue or when no
verify run has ever completed. A `warn!` is logged on both the overdue
and never-ran paths naming the remediation (enable the
`scheduledTasks.verifyEventChain` CronJob — `scheduledTasks.adminTasksEnabled=true`
+ `scheduledTasks.verifyEventChain.enabled=true` — or run
`hort-server verify-event-chain` out of band).

**Alarm.** `max_over_time(hort_event_chain_verify_overdue[…]) > 0` — the
same boot-emit-then-Prometheus-alarms shape `hort_staging_sweep_overdue`
uses (e.g. `max_over_time(hort_event_chain_verify_overdue[2d]) > 0`,
window ≥ the configured cadence so a single skipped run does not page).

**Why a boolean, why no labels, why boot-only.** Identical rationale to
`hort_staging_sweep_overdue`: `hort-server` is deliberately
scheduler-free, so a periodic in-process re-check would re-introduce
exactly the scheduler that was removed (architecturally forbidden). The gauge is set once at boot and scraped continuously. A
boolean (not a `_staleness_seconds`) is a boot-time snapshot — a
continuously-decaying seconds gauge would be misleading between restarts.
**No labels** — one global event-store per deployment. The metric is
emitted on the healthy path too (`0.0`) so a fresh scrape always sees the
series (absence vs `0.0` is ambiguous to dashboards).

### Storage (`hort-adapters-storage`)

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_storage_operations_total` | counter | `backend`, `operation`, `result` | — | `success`, `not_found`, `error` |
| `hort_storage_operation_duration_seconds` | histogram | `backend`, `operation` | seconds | — |
| `hort_storage_dedup_total` | counter | `backend` | — | content already present during `put` |
| `hort_storage_integrity_failures_total` | counter | `backend` | — | streaming SHA-256 verification failed on a `get` read (ADR 0003) |

**`hort_storage_integrity_failures_total` semantics:**

- Fires from the `VerifyingReader` wrapper applied by every adapter's
  `get()`. On EOF, the accumulated SHA-256 is compared to the requested
  `ContentHash`; mismatch fires this counter exactly once, yields
  `io::ErrorKind::InvalidData` to the stream consumer, and the stream is
  considered exhausted.
- **Distinct from `hort_storage_operations_total{operation="get",result="error"}`**:
  the `get()` call itself still succeeded (the row existed, the stream
  opened). Verification failure is discovered later by the reader. The
  two metrics are complementary — a spike on integrity failures paired
  with steady operation-get counts is the shape of mid-flight corruption
  detection.
- A sustained non-zero rate signals either a compromised/misconfigured
  backend, bit rot on underlying media, or a bug in the CAS write path.
  Operator response: inspect backend health and cross-check with the
  background integrity sweep (when available).

### CAS integrity scrub

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_cas_scrub_checks_total` | counter | `backend`, `result` | — | `ok`, `hash_mismatch`, `missing`, `read_error` |

Emitted by `hort-app::use_cases::cas_scrub_use_case::CasScrubUseCase::run`
— invoked by the `hort-server scrub` CLI subcommand.

**`backend` label values** — a coarser granularity than the per-concrete
backend label on `hort_storage_operations_total`:

- `filesystem` — the local-filesystem adapter
  (`hort-adapters-storage::FilesystemStorage`).
- `object_store` — all object-store-family adapters (S3, GCS, Azure,
  in-memory for tests), surfaced via
  `hort-adapters-storage::ObjectStoreStorage`. All object-store variants
  collapse onto this single value because the scrub exercises the same
  `list_all` + `get` path regardless of the underlying object store.

**`result` semantics** (source of truth:
`crates/hort-app/src/metrics.rs::CasScrubResult`):

- `ok` — re-computed SHA-256 matched the CAS key. No log (per-blob
  success is high-volume; metric is the dashboard signal).
- `hash_mismatch` — re-computed SHA-256 differed from the CAS key.
  Companion `CasIntegrityMismatch` domain event appended to a per-hash
  synthetic artifact stream; companion `tracing::warn!` with
  `content_hash`, `backend`, and `observed_hash`. **Flag only — the
  scrubber never quarantines on mismatch** (the operator
  decides the response).
- `missing` — the hash appeared in `list_all` but `get(&hash)` returned
  `NotFound`. A concurrent GC, a racing delete, or an inconsistent
  backend listing. Companion `tracing::warn!`.
- `read_error` — either `list_all` yielded a `StreamItem::ReadError`
  (malformed key, EACCES on a shard directory) or the streaming read
  from `get()` failed mid-flight. Companion `tracing::warn!`.
  Integrity-reader EOF failures land here too, NOT under `hash_mismatch`
  — the re-hash short-circuited and the scrubber has no observed digest
  to attest; operators cross-reference
  `hort_storage_integrity_failures_total`, which DID fire for that blob.

**Exit code** (`hort-server scrub`): `0` when `result="hash_mismatch"`
count for the run was zero, `1` otherwise. `missing` and `read_error`
are observability-only and do not escalate the exit code — a
transient-listing blip should not page an operator. Cron-escalation is
a function of the mismatch count.

**Sampling.** `--sample-fraction N` (0.0..=1.0) probabilistically skips
blobs BEFORE the re-hash. Skipped blobs are not counted and do not
emit a metric; the metric answers "what did the scrubber actually
verify", not "what was in the CAS at scrub time." Set to `1.0` for
audit runs, lower for frequent schedules.

Cardinality: 2 backends × 4 results = 8 series per deployment. Flat,
well under any ceiling.

### Ephemeral store (`hort-adapters-ephemeral-*`)

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_ephemeral_store_operations_total` | counter | `operation`, `result`, `class` | — | `ok`, `cas_miss`, `not_found`, `error` |
| `hort_ephemeral_store_operation_duration_seconds` | histogram | `operation`, `class` | seconds | — |

Emitted by `MeteredEphemeralStore` (present in both
`hort-adapters-ephemeral-memory` and `hort-adapters-ephemeral-redis` — the
wrapper is intentionally duplicated to keep each adapter's dependency
graph minimal). Wraps the concrete backend and forwards every
[`EphemeralStore`](../crates/hort-domain/src/ports/ephemeral_store.rs) port
call.

**`operation` label values** — one per port method, bounded set:

- `get` — [`EphemeralStore::get`]
- `put` — [`EphemeralStore::put`]
- `put_if_absent` — [`EphemeralStore::put_if_absent`]
- `compare_and_swap` — [`EphemeralStore::compare_and_swap`]
- `delete` — [`EphemeralStore::delete`]
- `extend_ttl` — [`EphemeralStore::extend_ttl`]
- `try_increment_counter` — [`EphemeralStore::try_increment_counter`] (atomic counter increment with cap; emits `cas_miss` when the cap is reached)

**`result` label semantics** (source of truth:
`crates/hort-adapters-ephemeral-memory/src/metrics.rs` — the Redis crate
duplicates the taxonomy verbatim):

- `ok` — the operation completed successfully. For `get` this means a
  live value was returned; for `put` / `extend_ttl` the write landed;
  for `compare_and_swap` the expected version matched and the new
  version was returned; for `put_if_absent` the create succeeded; for
  `delete` an entry was actually removed; for `try_increment_counter`
  the counter was below the cap and incremented.
- `cas_miss` — optimistic-concurrency mismatch. Fires on
  `compare_and_swap` when the stored version ≠ `expected_version`, on
  `put_if_absent` when the key was already present (a CAS-miss
  analogue: both callers lost a race with another writer), and on
  `try_increment_counter` when the cap was reached (the increment
  did not happen — caller treats this as a CAS-miss).
- `not_found` — the key was absent or already-expired. Fires on `get`
  against a non-existent key, and on `delete` / `extend_ttl` against a
  key that had already expired / been removed (both are `Ok(())` per
  the port contract; the distinct label lets operators separate
  idempotent-cleanup traffic from genuine hits without growing the
  error taxonomy).
- `error` — adapter-level failure surfaced as
  `DomainError::Invariant`. Maps to a Redis `fred` error on the
  Redis backend, or (rare) a panic-recovery path on the memory
  backend.

Cardinality: 7 operations × 4 results × 2 classes = 56 series for the
counter; 7 operations × 2 classes = 14 series for the histogram.
Flat per deployment regardless of the number of distinct keys — the
key itself is NOT a label (uploads and idempotency tokens are
high-cardinality and must stay out of label space).

**Backend identification.** The `backend` axis is intentionally NOT a
label on these metrics. Operators select `hort_ephemeral_store_backend`
per-deployment via `HORT_EPHEMERAL_STORE_BACKEND`, so a single
timeseries uniquely identifies one adapter per replica. The startup
log line in `hort-server::composition::build_app_context` carries the
backend label if dashboards need to correlate across deployments.

**`class` label values** (closed taxonomy):
- `evictable` — cache consumers (Cargo/PyPI/npm sparse-index and packument caches, pull-through dedup). Loss is recoverable by re-fetching from upstream.
- `durable` — stateful and security-critical consumers (OCI upload session records, auth and PAT lockout flags + counters, OCI per-(repo, principal) session-count cap, auth-event throttle). Loss is tolerated only as defense-in-depth lower-tier degradation.

The single source of truth for prefix → class mapping is `hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY`, whose exhaustiveness is pinned by the `ephemeral_keyspace_exhaustive` guard test.

### Subscription delivery dispatcher

| Metric | Type | Labels | Description |
|---|---|---|---|
| `hort_notify_delivery_total` | counter | `target_kind ∈ {webhook, nats_jetstream}`, `result ∈ {delivered, downstream_rejected, failed}` | Counts each per-event delivery attempt by the dispatcher's per-subscription task. NO `subscription_id` label (cardinality). |
| `hort_notify_delivery_duration_seconds` | histogram | `target_kind`, `result` | Wraps the entire `EventNotifier::notify` call (one event → one transport send). |
| `hort_notify_broadcast_lagged_total` | counter | (none) | Increments on `tokio::sync::broadcast::error::RecvError::Lagged` in a per-subscription task. Operator signal that `HORT_NOTIFY_CHANNEL_CAPACITY` should be raised. |
| `hort_subscription_total` | gauge | `state ∈ {active, paused, disabled}` | Refreshed by the dispatcher's 30s reconcile. v1 surfaces the active count only — paused/disabled rows are not returned by `list_active`, so they're not enumerated by the reconcile. A future enhancement adds an explicit `list_by_state` call for full breakdown. |

Emitted by [`hort_app::metrics::emit_notify_delivery`](../crates/hort-app/src/metrics.rs)
and [`hort_app::metrics::emit_broadcast_lagged`](../crates/hort-app/src/metrics.rs)
from
[`hort_app::dispatcher::subscription_task`](../crates/hort-app/src/dispatcher/subscription_task.rs).
The `target_kind` and `result` label values are mapped from
[`SubscriptionTarget`](../crates/hort-domain/src/entities/subscription.rs)
and [`NotifyOutcome`](../crates/hort-domain/src/ports/event_notifier.rs)
via [`hort_app::metrics::target_kind_label`](../crates/hort-app/src/metrics.rs)
and [`hort_app::metrics::notify_outcome_label`](../crates/hort-app/src/metrics.rs)
— closed matches, no `_ =>` arm, so adding a new target / outcome
variant forces a deliberate catalog update.

**Cardinality discipline.** No `subscription_id`, `owner_user_id`,
`target_url`, `subject_string`, `event_id`, or `correlation_id`
labels. Per-subscription detail belongs in tracing spans + the per-row
`last_failure` JSONB.

**Deferred:** `hort_notify_dispatcher_lag{category}` is a v1.x follow-on
— it requires polling state across all per-subscription tasks; the
gauge would otherwise have stale-data semantics that operators have to
learn. Implemented when a concrete operator need surfaces.

### Subscription create-time SSRF block

| Metric | Type | Labels | Description |
|---|---|---|---|
| `hort_webhook_ssrf_block_total` | counter | `reason ∈ {ip_literal_not_routable, dns_resolved_not_routable, dns_resolution_failed}` | Increments when `SubscriptionUseCase::create` / `update` rejects a webhook target on the create-time SSRF check. Fires BEFORE the `subscriptions` row is written and BEFORE `SubscriptionCreationDenied` is appended. Cardinality is fixed (3 reasons). |

**Name.** This counter was historically named
`hort_subscription_ssrf_blocked_total`; it is
`hort_webhook_ssrf_block_total{reason}` so it reads as the pair of the
durable `SubscriptionCreationDenied{WebhookTargetNotRoutable}` event
appended on the same path (the SSRF block is durably
audited). There is exactly **one
emitter, one layer (`hort-app` subscription), one name** — no
double-count: the connect-time guarded resolver (see below) emits
no metric of its own (a rebind blocked at connect surfaces as a webhook
delivery failure on the existing dispatcher delivery metrics, not a
second SSRF counter).

Emitted by
[`hort_app::metrics::emit_ssrf_block`](../crates/hort-app/src/metrics.rs)
from
[`SubscriptionUseCase::create`](../crates/hort-app/src/use_cases/subscription_use_case.rs)
when the [`WebhookTargetGuard`](../crates/hort-domain/src/ports/webhook_target_guard.rs)
returns `Err(reason)` AND
`HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS=false`. The `reason` label value
is mapped from [`SsrfBlockReason`](../crates/hort-domain/src/entities/subscription.rs)
via [`hort_app::metrics::ssrf_reason_label`](../crates/hort-app/src/metrics.rs)
— a closed match, no `_ =>` arm, so adding a new SSRF reason variant
forces a deliberate catalog update.

**Ordering relative to the audit event.** The counter increments first,
then `SubscriptionCreationDenied` is appended to the requesting actor's
user stream, then the HTTP 400 is returned. Operators paging on
sustained counter growth can drill down via the audit event payload's
`denial_reason: WebhookTargetNotRoutable { ssrf_block_reason }` without
joining tracing.

**No `subscription_id`, `owner_user_id`, `target_url`, `host`, or
`actor_user_id` labels.** Per the anti-pattern checklist; per-request
detail belongs in tracing spans + the
`SubscriptionCreationDenied` event payload.

#### Connect-time guard + `HORT_WEBHOOK_ALLOWLIST_HOSTS`

The metric above fires only on the **create-time** SSRF check. The
connect-time guard closes the DNS-rebinding TOCTOU: the create-time
`is_routable` check is bypassable by flipping DNS between subscription
create and webhook delivery. A connect-time `GuardedDnsResolver`
(`crates/hort-notifier-webhook/src/dns_guard.rs`) re-runs
`hort_net_egress::is_routable` on the address **actually dialed**, for
every connect, for the lifetime of the webhook client.

**Scoping (load-bearing).** The guarded resolver is bound via
`ClientBuilder::dns_resolver(...)` to the **webhook `reqwest::Client`
only**, inside `WebhookNotifier::with_allowlist`. It is deliberately
NOT re-globalized to the upstream-http / S3 / OIDC clients — those stay
operator-vetted (a globally-guarded resolver is the exact pattern that
was deliberately removed). A connect blocked by the guard emits **no** new metric; it
surfaces as a webhook delivery failure on the existing
`hort_notify_delivery_*` dispatcher metrics.

**`HORT_WEBHOOK_ALLOWLIST_HOSTS`.** Comma-separated host names
and/or CIDR prefixes. A dialed address is permitted when `is_routable`
passes **OR** the resolved host name matches an allowlisted host entry
**OR** the dialed IP falls inside an allowlisted CIDR. The allowlist
bypasses `is_routable` **only for the listed entries** — every other
host still default-denies on a non-routable resolution. This is the
**targeted, intended control** for legitimate internal webhook
receivers (an in-DMZ forwarder, an in-cluster receiver).

**`HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` is a documented last resort.**
It is the pre-existing blanket opt-out and is unchanged. Its blast
radius: it disables the create-time SSRF host check **and this counter**
for **every** subscription, re-opening SSRF to IMDS / link-local /
RFC1918 across all targets — a sharp footgun. Operators with one
legitimate internal receiver MUST prefer `HORT_WEBHOOK_ALLOWLIST_HOSTS`
(scoped to that entry) over the blanket opt-out. The blanket knob
remains only for emergency / migration scenarios and should carry an
operator alarm.

### Events pull surface

| Metric | Type | Labels | Description |
|---|---|---|---|
| `hort_events_pull_total` | counter | `category`, `result ∈ {success, no_match, forbidden}` | Counts each `GET /api/v1/events` call by category and outcome. `success` = at least one event returned in the page; `no_match` = read completed but the `(category, after, max)` filter matched zero rows; `forbidden` = admin-only category requested by a non-admin caller (the request was rejected at the per-category authz gate before the read). |
| `hort_events_pull_duration_seconds` | histogram | `category` | Wraps the entire handler from start-of-call through metric emission. NO `result` label on the histogram — `category` only; the counter carries the outcome detail. |

Emitted by
[`hort_app::metrics::emit_events_pull`](../crates/hort-app/src/metrics.rs)
from the
[`get_events`](../crates/hort-http-events/src/handler.rs) handler. The
`category` label value is the wire form returned by
[`hort_http_events::dto::stream_category_wire`](../crates/hort-http-events/src/dto.rs)
— closed match, no `_ =>` arm, so adding a new `StreamCategory`
variant forces a deliberate catalog update. The `result` label value
is mapped from
[`hort_app::metrics::EventsPullResult`](../crates/hort-app/src/metrics.rs).

**Bad-request exits are NOT metered.** A request with an unknown
`?category=` value returns 400 before any read; the taxonomy
enumerates only `{success, no_match, forbidden}` — the
`bad_request` case is intentionally excluded from the catalog (the
request never entered the substrate). Operators detect 4xx via the
HTTP catalog's `http_requests_total{status="400"}` series.
Infrastructure failures (500) are likewise unmetered on this counter
— the HTTP histogram already surfaces the 5xx signal.

**No `subscription_id`, `owner_user_id`, `after`, `max`, or
`wait_ms` labels.** Per the anti-pattern checklist; per-request
detail belongs in tracing spans.

### Gitops apply

| Metric | Type | Labels | Owner | Description |
|--------|------|--------|-------|-------------|
| `hort_gitops_apply_total` | counter | `result` ∈ {`ok`, `parse_error`, `validation_error`, `apply_error`} | `hort-server::gitops_boot` — sole emitter; the use case never emits this metric (per "each metric at exactly one layer") | Boot-apply outcome. Fires exactly once per `apply_config_from_dir` call. |
| `hort_gitops_objects_total` | counter | `kind` ∈ {`repository`, `claim_mapping`, `permission_grant`, `curation_rule`, `scan_policy`, `retention_policy`, `exclusion`, `upstream_mapping`, `oidc_issuer`, `service_account`}, `result` ∈ {`created`, `updated`, `deleted`, `unchanged`, `rejected_not_in_allowlist`} | `hort-app::ApplyConfigUseCase` | Per-envelope outcome counter. Sum across `kind` per `result` matches the `ApplyReport` summary. For event-sourced kinds (`scan_policy`, `retention_policy`, `exclusion`) this counts envelopes — a `ScanPolicy` UPDATE that touches two fields ticks once with `result=updated`. The per-event count lives on `hort_gitops_events_emitted_total`. **`result=rejected_not_in_allowlist` is exclusive to `kind="upstream_mapping"`**: fires when `apply_upstream_mappings` rejects a mapping because the URL host is not in `HORT_UPSTREAM_ALLOWLIST_HOSTS`. The apply aborts with `AppError::Domain(Validation(_))` immediately after the increment; one increment per rejected mapping. See `docs/operator/upstream-trust-model.md`. The additive-claims `claim_mappings` model replaced the structural `group_mappings` table: the `group_mapping` kind label is renamed to `claim_mapping`, and the `role` kind is removed (no structural-RBAC `Role` exists, so no emitter passes `role`). `retention_policy` is event-sourced, same shape as `scan_policy`. |
| `hort_gitops_events_emitted_total` | counter | `kind` ∈ {`scan_policy`, `retention_policy`, `exclusion`}, `event_type` ∈ {`PolicyCreated`, `PolicyUpdated`, `ExclusionAdded`, `ExclusionRemoved`, `PolicyArchived`, `RetentionPolicyCreated`, `RetentionPolicyUpdated`, `RetentionPolicyArchived`} | `hort-app::ApplyConfigUseCase` | Number of `DomainEvent`s the gitops apply pipeline produced through `PolicyUseCase` / `RetentionPolicyUseCase` per event-sourced kind. Distinct from `hort_gitops_objects_total` which counts per-envelope outcomes — a 2-field `ScanPolicy` UPDATE emits two `event_type=PolicyUpdated` increments and one `objects_total{result=updated}`. The `event_type` label value is taken from the `DomainEvent` discriminant (`hort_domain::events::DomainEvent::event_type` — `&'static str` from a static table; for `kind=retention_policy` the value is the inner-discriminated `RetentionPolicyCreated`/`…Updated`/`…Archived`); free-form caller strings cannot reach the label. |
| `hort_gitops_apply_duration_seconds` | histogram | none | `hort-server::gitops_boot` | Wall-time of one apply. Recorded once per call regardless of outcome (success and failure both observed). |

`kind` on `hort_gitops_objects_total` is bounded by the gitops schema
(9 values × 5 results = 45 series max; the
`rejected_not_in_allowlist` `result`
value fires exclusively under `kind="upstream_mapping"` so the
realised combination count is closer to 9 × 4 + 1 = 37). `kind` on
`hort_gitops_events_emitted_total` is restricted to the two
event-sourced kinds (2 × 5 = 10 series max; some combinations
e.g. `kind=exclusion, event_type=PolicyCreated` never occur and
simply never fire). `result` values are exhaustive and pinned per
metric — implementer-invented labels are blocked by the catalog
rule above.

The apply sequence runs once per boot before the listener binds —
`hort_gitops_apply_total{result="ok"}` is therefore monotonically
increasing in normal operation; counters reset on process restart,
matching the wider Prometheus convention.

### Secret resolution

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_secret_resolve_total` | counter | `source`, `result` | — | `success`, `not_found`, `read_failure`, `decode_error` |

`hort_secret_resolve_total` is emitted by the secret-resolution adapters
in `hort_adapters_secrets` (`EnvVarSecretAdapter`,
`MountedFileSecretAdapter`) on every `SecretPort::resolve` call.
Exactly one increment per resolve attempt regardless of outcome.

Labels:
- `source` ∈ {`env_var`, `file`} — which adapter handled the resolve;
  matches `SecretRef::source` of the input.
- `result` enumerates the resolve outcome:
  - `success` — secret read; bytes returned to the caller.
  - `not_found` — env var not set, or file does not exist.
  - `read_failure` — file existed but could not be read (permission
    denied, mid-rotation race, generic I/O error). Always
    operator-actionable.
  - `decode_error` — env var contains non-UTF-8 bytes, or the
    dispatcher mis-routed a `SecretRef` to the wrong adapter
    (defensive — `DispatchSecretPort` is the trust boundary).

Cardinality: 2 sources × 4 results = 8 series ceiling. There is
deliberately no label for `location` — paths and env-var names are
unbounded; per-resolve detail lives in `tracing` spans (`source` and
`location` fields).

Bearer-flow correlation: when a secret resolution returns `Err(_)`
during `BearerChallenge` realm exchange, the
bearer-token cache emits `hort_upstream_bearer_token_total{result=fetch_failed}`
and the secret-resolve emits one of the error variants here. The two
metrics are therefore complementary: this one classifies *why* the
secret could not be obtained; the bearer one classifies *that* the
exchange could not proceed.

### Extra CA trust bundle

| Metric | Type | Labels | Unit | `result` values |
|--------|------|--------|------|-----------------|
| `hort_extra_ca_anchors` | gauge | none | count | — |
| `hort_extra_ca_load_total` | counter | `result` | — | `ok`, `unreadable`, `parse_failed` |

Emitted by `hort-server::composition::read_extra_ca_bundle` — invoked
exactly once per `serve` / `scrub` boot. The pair lets dashboards
distinguish "no bundle is configured" from "bundle is configured but
failed to load" without scraping log output.

**`hort_extra_ca_anchors`** — set on the success and unset paths:

- `0` — `HORT_EXTRA_CA_BUNDLE` env var unset (no bundle configured).
- `N` (>= 1) — env var set, file readable, PEM parsed to N
  certificates that rustls accepted as trust anchors.

Not set on the failure paths: the gauge keeps its previous value
(zero before any boot, or N from the prior successful boot of a
DIFFERENT process). The boot fails closed in either failure case
(`ExtraCaUnreadable` / `ExtraCaParse`), so a running Pod with
`gauge == 0` always means the env var was unset; a Pod that failed
to boot is in `CrashLoopBackOff` and not scraping.

**`hort_extra_ca_load_total{result=…}` semantics** (source of truth:
`crates/hort-server/src/composition.rs::EXTRA_CA_LOAD_RESULT_*`):

- `ok` — the env var was unset (no bundle configured) OR was set and
  the bundle loaded successfully. Distinguishable via the gauge:
  `gauge == 0` means unset; `gauge >= 1` means loaded.
- `unreadable` — env var set but `std::fs::read` failed. Boot aborts
  with `ConfigError::ExtraCaUnreadable`; the Pod restarts.
- `parse_failed` — env var set, file readable, but PEM parsing
  rejected the file (malformed PEM block) or found zero
  `CERTIFICATE` blocks. Boot aborts with `ConfigError::ExtraCaParse`;
  the Pod restarts.

Cardinality: 1 (gauge, unlabelled) + 3 (counter, three bounded
`result` values) = 4 series per process. Effectively flat.

Operator runbook: [`docs/architecture/how-to/deploy/extra-ca-bundle.md`](architecture/how-to/deploy/extra-ca-bundle.md)
"Operator escalation" section for the `gauge == 0 when one was expected`
flow.

### Unsafe config opt-ins

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hort_unsafe_config_active` | gauge | `kind ∈ {pat_over_http, plaintext_webhooks, webhook_nonroutable_targets, test_clock}` | Boolean (0/1). Set to 1 at boot for each unsafe-config opt-in flag the operator has flipped on. Operators page on any non-zero value in production. |

Emitted by `hort-server::composition` once at boot when the operator
has flipped one of the corresponding unsafe-config opt-in env vars.
The gauge signals "this deployment is running with a knob that
operations should never see in a production environment" —
dashboards alarm on any non-zero value.

**`kind` semantics** (extensible — every new entry requires a
matching env-var parser in `hort-server::config` and a paired catalog
edit):

- `pat_over_http` — `HORT_BEARER_ALLOW_OVER_HTTP=true` lets bearer auth
  (PAT-shaped tokens AND CliSession-family JWTs — the transport gate
  covers all bearers, not just PATs) proceed over plaintext HTTP. The
  default-OFF posture refuses with `426 Upgrade Required`. Enabling this
  on a public-facing deployment is a credential-leak vector; the gauge is
  the boot-time audit trail. (The metric `kind` label stays `pat_over_http`
  for continuity even though the knob now covers all bearers.)
- `plaintext_webhooks` — `HORT_WEBHOOK_ALLOW_PLAINTEXT=true` lets
  subscription webhook URLs use the `http://` scheme. The default-
  OFF posture rejects non-https URLs at subscription-create with
  `WebhookTargetNotRoutable`. Enabling this on a public-facing
  deployment leaks HMAC-signed event payloads in cleartext on every
  delivery — webhook signatures cover the body, not the channel.
- `webhook_nonroutable_targets` — `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS=true`
  skips the SSRF routability check on webhook target URLs. The
  default-OFF posture rejects URLs whose host resolves to RFC 1918 /
  CGNAT / link-local / loopback space at subscription-create. Operators
  with legitimate internal webhook receivers (in-cluster relays,
  sidecars) flip this deliberately; the gauge is the boot-time audit
  trail so accidental drift on a public-facing replica is visible on
  every dashboard.
- `test_clock` — `HORT_TEST_CLOCK_ENABLED=true` opts into the deliberate
  test-clock auth-bypass primitive (`POST /test/clock/advance`). The
  gauge is `1.0` whenever the runtime flag is set, regardless of the
  build, because it is an unsafe opt-in either way. This `kind` pairs
  with a **boot-time hard-fail**: if the flag is set in a binary built
  WITHOUT the `test-clock` cargo feature (the release / non-feature
  build condition), `hort-server::composition::evaluate_test_clock_guard`
  sets this gauge to `1.0`, emits an `error!`, and refuses to start —
  the double gate (`#[cfg(feature="test-clock")]` + the runtime flag)
  must never be half-broken. Source: auth-catalog Entry 10.

**Wire form.** Set to `1.0` when the corresponding env var is
flipped on; set to `0.0` on the safe path so a fresh scrape sees
the metric anyway (absence vs `0.0` would be ambiguous to
dashboards). Cardinality: bounded by the closed `kind` enum (one
entry per operator-visible unsafe knob).

## Upstream fetch error taxonomy

`UpstreamErrorKind` (enum in `hort-app::metrics`):

| Variant | `as_str()` | HTTP / condition |
|---------|-----------|------------------|
| `Success` | `success` | 2xx, checksum verified |
| `NotFound` | `not_found` | 404 |
| `Unauthorized` | `unauthorized` | 401, 403 |
| `RateLimited` | `rate_limited` | 429 |
| `Upstream4xx` | `upstream_4xx` | other 4xx |
| `Upstream5xx` | `upstream_5xx` | 500-599 |
| `NetworkError` | `network_error` | connection refused, DNS, TLS |
| `Timeout` | `timeout` | deadline exceeded |
| `ChecksumMismatch` | `checksum_mismatch` | content received, hash failed |
| `ParseError` | `parse_error` | malformed metadata response |
| `BodyTooLarge` | `body_too_large` | **Reserved (retired-from-this-path).** The fixed-cap buffer-and-bail path (`METADATA_BODY_CAP_BYTES = 10 MiB`, `MANIFEST_BODY_CAP_BYTES = 4 MiB`) was retired in favour of the configurable per-fetch-class storage backstops below (ADR 0026 — streaming metadata projection). The variant + label stay on `UpstreamErrorKind` so the catalog still recognises historical timeseries, but production code paths no longer emit it. |
| `MetadataTooLarge` | `metadata_too_large` | `fetch_metadata` storage backstop trip. The streamed upstream body crossed `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE` (default 64 MiB). Honest classification: emitted alongside a 502 with the structured `{"error":"upstream metadata too large", "fetch_class":"metadata", "bytes_read": N, "cap": M}` body — NOT folded into the generic "upstream unavailable" sanitisation. |
| `ManifestTooLarge` | `manifest_too_large` | `fetch_manifest` storage backstop trip. OCI-symmetric companion to `MetadataTooLarge`; threshold `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE` (default 16 MiB). |
| `VersionObjectTooLarge` | `version_object_too_large` | Per-version-object cap trip inside a streaming projector's `Visitor::visit_map`/`visit_seq` loop (npm `versions{}` value, PyPI `files[]` entry). Threshold `HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE` (default 2 MiB). **Emission stage:** unlike every other `result` value on this metric (emitted by `hort-adapters-upstream-http` at the HTTP fetch boundary), this one is emitted by the per-format inbound source (`ProxyNpmSource` / `ProxyPypiSource`) at the *projection* stage via `hort_app::metrics::emit_upstream_version_object_too_large` — the cap is enforced while parsing the already-fetched cached body, so the trip is observed downstream of the adapter (after that fetch already counted as `success`). A trip empties the served index (fail-closed); this metric is the signal that the empty serve was cap-induced rather than a genuine empty package. |
