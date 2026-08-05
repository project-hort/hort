# 0052 — Scoped metrics-read capability; `/metrics` served admin-listener-only

- **Status:** Accepted
- **Enforced by:** `Permission::ReadMetrics` (`crates/hort-domain/src/entities/rbac.rs`,
  DB enum literal `'read_metrics'` via migration `016_read_metrics_permission.sql`)
  checked by the `MetricsReaderPrincipal` extractor
  (`crates/hort-http-core/src/authz/extractors.rs`) on `render_metrics` — the
  handler cannot be mounted without the gate because the extractor *is* its
  argument. The orthogonality half (an `admin` claim does **not** imply
  `ReadMetrics`) is enforced by an explicit carve-out in
  `RbacEvaluator::user_grants_authorize` and mirrored in
  `RbacEvaluator::effective_grants`
  (`crates/hort-app/src/rbac.rs`), each with a permanent regression guard
  (`metrics_reader_admin_claim_without_explicit_grant_is_denied`,
  `effective_grants_agrees_with_authorize_per_cell`). Route placement is
  enforced structurally: no router built by `hort_http_core::router` registers
  `/metrics` at all, so the public listener 404s it
  (`get_metrics_on_main_listener_returns_404`). The linter's
  `every_permission_variant_is_classified` test has no wildcard arm, so a future
  `Permission` variant cannot silently inherit this one's classification.
- **Supersedes:** the `HORT_METRICS_REQUIRE_AUTH` / Helm `metrics.requireAuth`
  anonymous-scrape opt-out (removed end-to-end, no deprecation shim — see
  *Decision* D5).
- **Relates:** [0012](0012-claim-based-rbac-claimless-static-tokens.md) (the
  grant model this capability is expressed in, and the audited apply path that
  is the only way to provision it);
  [0017](0017-metrics-catalog-canonical.md) (the exposition whose label schema
  is the disclosure being gated);
  [0037](0037-gitops-service-account-grant.md) /
  [0044](0044-service-accounts-identity-only.md) (the scraper identity shape —
  `serviceAccount`-subject grant, cap snapshotted at mint/exchange);
  [0038](0038-admin-identity-model.md) (service accounts are strictly
  non-admin, which is *why* a scrape credential cannot be an admin one);
  issue #113 (the audit finding); issue #111 (the aud-only federation
  escalation this capability's provisioning guidance must not reproduce).

## Context

`/metrics` was gated by `require_principal` — **authentication only** — on both
the public main listener and the admin listener. Any authenticated principal
could scrape the full Prometheus exposition, including a zero-grant service
account whose token authorized nothing else on the instance.

That is a real disclosure, not a theoretical one, because of what the exposition
carries. Per [ADR 0017](0017-metrics-catalog-canonical.md) the `hort_*` series
are labelled with `repository` keys (up to ~10k values), plus auth-failure
rates, authz `result=deny` ratios, and request-rate shape. So the endpoint hands
over:

- **The complete repository roster** — which directly defeats the
  anti-enumeration posture the read path is built around. `RepositoryAccessUseCase`
  collapses an unauthorized read to `404 NotFound`, byte-identical to a missing
  repository, specifically so that private-repository *existence* does not leak.
  A single authenticated scrape of `/metrics` recovers the entire list the 404
  collapse exists to hide.
- **Reconnaissance signal** — auth-failure rates and traffic shape let an
  attacker time probes around real traffic.

The pre-existing controls were both network-shaped: `HORT_METRICS_BIND` (serve
`/metrics` on a separate listener) and `HORT_METRICS_PUBLIC_BIND` (refuse an
unspecified-address bind without an explicit opt-in). Useful, but neither is an
authz gate, and Hort's own standing posture is that this is not sufficient on
its own — **"network position is never a substitute for access control"**
(`docs/architecture/how-to/deploy/control-plane-tiers.md` §*Why this is not
sufficient alone*; mirrored on `build_admin_router` and `render_metrics`). The
same document records why: a single network-layer control does not cover the
insider or stolen-ordinary-token threat, and L7 path routing is fully bypassed
by anything that reaches the pod `IP:port` directly.

There was also a third control in the opposite direction:
`HORT_METRICS_REQUIRE_AUTH=false`, a legacy escape hatch that served the same
repository-labelled exposition with authorization removed entirely.

## Decision

**A scoped, non-admin capability is the primary control for `/metrics`. Network
isolation stays as defense-in-depth and is never the sole gate.** Five parts,
all shipped:

**D1 — New global domain permission `Permission::ReadMetrics`.** An eighth
`Permission` variant, DB enum literal `'read_metrics'`, `Display`/`FromStr`
round-tripping like the rest. It is **global**: always checked with
`repository = None`. A per-repository metrics permission would be meaningless —
the exposition is process-wide, not per-repository, so there is nothing for a
repository scope to narrow. The `hort_authz_decisions_total{permission}` label
gains the `read_metrics` value ([ADR 0017](0017-metrics-catalog-canonical.md)
catalog updated in the same change).

**D2 — Additive migration.** `016_read_metrics_permission.sql` is a standalone
`ALTER TYPE public.permission_type ADD VALUE IF NOT EXISTS 'read_metrics'`.
Additive and non-destructive: it passes the `no_sensitive_drops` guard trivially,
and it carries no same-file statement consuming the new value (Postgres forbids
`ALTER TYPE … ADD VALUE` and immediate use of the value in one transaction).

**D3 — `MetricsReaderPrincipal` extractor, orthogonal to `Admin`.**
`render_metrics` takes `_reader: MetricsReaderPrincipal`, which authorizes
`Permission::ReadMetrics` and nothing else.

**`Admin` does NOT implicitly satisfy `ReadMetrics`** — the load-bearing half of
this ADR, and the one thing here a future change is most likely to "simplify"
back. A Prometheus scraper must not be an admin (an always-on credential
mounted in a monitoring pod is the *worst* place to put instance-wide
authority), and symmetrically an admin credential is not implicitly a scrape
credential. An admin who also needs to scrape holds an explicit `read_metrics`
grant.

Orthogonality is not just the extractor declining an `Admin` fall-through in its
own control flow — that alone would have been defeated one layer down, because
`RbacEvaluator::user_grants_authorize` short-circuits `true` for any principal
carrying the lowercase `admin` claim, for *every* permission. So the carve-out
lives in the evaluator: `ReadMetrics` is excluded from the admin short-circuit
and falls through to the ordinary grant scan, identical to a non-admin
principal. `RbacEvaluator::effective_grants` mirrors it exactly — for a global
admin, `cells` is empty for every permission *except* a held `read_metrics`
grant, which surfaces as an ordinary cell — so a principal's self-view never
claims authority `authorize()` would deny.

That mirroring is surfaced on the wire. `GET /api/v1/auth/whoami`'s
`WhoamiEffectiveGrants::GlobalAdmin` variant renders
`{"global_admin": true, "read_metrics": <bool>}`: the additive `read_metrics`
field is `true` iff the admin *also* holds the explicit grant. Without it, the
`global_admin: true` marker — which by design stands in for "holds every
authority" rather than enumerating an unbounded repository × permission set —
would have silently swallowed the one permission it does not imply. (The
*capped*-admin path needs no parallel field: a narrowing cap never renders the
marker, so a held `read_metrics` grant already appears as an ordinary cell in
that enumeration.)

**D4 — `/metrics` is served on the admin listener only.** The
`metrics_require_auth && path == "/metrics"` carve-out in
`hort_http_core::router` is removed, and no router that module builds registers
`/metrics` at all — a request on the public main listener falls through to the
standard unmatched-route `404`, exactly like any unknown path. `/metrics` is
mounted exclusively by `hort_server::http::build_admin_router`, gated by D3's
extractor, bound per the existing `HORT_METRICS_BIND` / `HORT_METRICS_PUBLIC_BIND`
surface (both keep their meaning). One consequence is deliberate and worth
stating plainly: with `HORT_METRICS_BIND` unset, the admin listener does not
bind, so **`/metrics` is exposed nowhere at all** — there is no dev-mode
main-listener fallback. An operator who has not chosen where to expose the
exposition has not accidentally exposed it publicly.

**D5 — The `HORT_METRICS_REQUIRE_AUTH=false` anonymous escape hatch is retired
outright.** Removed end-to-end — config field and env parsing, Helm
`metrics.requireAuth` (values, schema, template), the startup bypass `WARN`, and
every operator-facing doc mention — with no deprecation cycle and no
accepted-but-ignored shim (pre-v1.0, so no compatibility debt is owed). A stale
`HORT_METRICS_REQUIRE_AUTH` in an operator's environment is *silently ignored*:
`Config::from_env` never reads the name, and there is no generic unknown-var
rejection to hit. A values file still setting `metrics.requireAuth` is rejected
by chart schema validation (`additionalProperties: false`).

The hatch served the same repository-labelled exposition with authz removed, and
keeping it would have made D1–D4 advisory. **If a genuinely open scrape is ever
needed** (a fully isolated network), that is an operator decision expressed by
*not granting a network path* to the listener — never by a server flag that
disables authorization. Reintroducing such a flag re-opens this decision.

### Rejected alternatives that specifically must stay rejected

**Gating `/metrics` on `Permission::Admin`.** Rejected, and it is the tempting
option because it is a one-line diff with no new permission, no migration, and
no new operator surface. It fails on the credential it forces into existence: a
Prometheus deployment would need an admin credential, standing, mounted, and
refreshed in a monitoring namespace — converting a read-only observability
consumer into an instance-wide administrative principal. That inverts
[ADR 0038](0038-admin-identity-model.md) (service accounts are strictly
non-admin; admin is IdP-assumed and short-lived) for the sake of one read
endpoint. The correct granularity for "may read the exposition" is its own
capability, which is what D1 adds.

**Ingress/network ACL as the *sole* control.** Rejected as insufficient, kept as
defense-in-depth. See *Context*: it does not cover the insider or
stolen-ordinary-token threat, and it is bypassed by anything reaching the pod
`IP:port` directly. Recommending an internal bind remains correct guidance — as
a second layer, not the layer.

**Reworking the metrics label schema to drop `repository` keys.** Rejected: it
would degrade operator observability (per-repository rates are the point of the
label) to work around an authz gap, and the label schema is
[ADR 0017](0017-metrics-catalog-canonical.md)'s concern. The authz gate is the
right fix; `METRICS_INCLUDE_REPOSITORY_LABEL=false` remains available as a
*cardinality* control, not a security one.

**A per-repository `ReadMetrics`.** Rejected as meaningless — see D1.

## Consequences

- **`GET /metrics` response matrix.** Anonymous → `401` (the admin listener's
  `require_principal` layer denies before the handler is reached, turning "no
  bearer" into a clean 401 rather than the extractor's missing-principal 500).
  Authenticated without the grant → `403`. Authenticated with the grant →
  `200`. On the public main listener → `404`, unconditionally. The denial logs
  at `tracing::info!`, never `error!` — a privilege denial is an audit line, not
  an infrastructure fault — and increments
  `hort_authz_decisions_total{permission="read_metrics", result="deny"}`, which
  is the alertable signal for a scraper whose grant was removed.
- **`AuthContext::BearerOnly` is covered too.** `authorize` / `evaluate_rbac`
  handle `Enabled` and `BearerOnly` alike, so the extractor closes the leak
  under the bearer-only configuration as well — which the bare
  `require_principal` it replaced did not.
- **Operators must provision a scrape identity before Prometheus works.** This
  is a breaking change for any deployment that scraped anonymously or with an
  ungranted token. The provisioning recipe is
  [`metrics-scraper-service-account.md`](../architecture/how-to/operate/metrics-scraper-service-account.md);
  the ServiceMonitor needs a `bearerTokenSecret` (or a
  `credentials_file` written by a refresh sidecar).
- **The grant is provisionable only through the audited apply path.** No new
  admin endpoint, no grant back door — `ApplyConfigUseCase` with
  `subject: {kind: serviceAccount}`, `permission: read_metrics`, `repository`
  omitted ([ADR 0037](0037-gitops-service-account-grant.md) shape, resolving to
  `GrantSubject::User(backing_user_id)`; the domain taxonomy stays two-variant,
  so [ADR 0012](0012-claim-based-rbac-claimless-static-tokens.md) is not
  re-opened).
- **The apply-time linter treats the two subject shapes differently, and that
  difference is load-bearing guidance.** An unscoped grant with a
  `serviceAccount` subject resolves to an SA-owned `User` grant and takes the
  linter's *provenance exemption* → `Pass`. The same unscoped grant with a
  `Claims` subject trips `wildcard-repo-non-admin` → **`Reject`** (a global
  claim-gated grant is instance-wide by construction), and a single-claim subject
  additionally trips `single-claim-grant`. This is the desired asymmetry: a
  scrape capability should be bound to one declared identity, not to whoever
  currently carries a claim. The how-to therefore features the
  `serviceAccount` form and does not offer the rule-downgrade escape hatch.
- **Scope boundary: this decision covers the `hort-server` exposition only.**
  `hort-worker` serves its own opt-in `GET /metrics` listener
  (`HORT_WORKER_METRICS_BIND`, **disabled by default**), and that listener is a
  bare one-route router with **no per-request auth** — its `repository` labels
  carry the same repository names, protected only by the NetworkPolicy the
  metrics catalog instructs operators to apply. That is the control this ADR
  rejects as a *sole* gate for the server surface, so the two surfaces are
  currently asymmetric. The gap is **pre-existing, consciously documented, and
  out of #113's scope** — closing it is not a doc change: `hort-worker` has no
  inbound-auth stack, no `AppContext`, and no `RbacEvaluator` wired for HTTP, so
  extending `ReadMetrics` to it is an initiative, not a patch. Recorded here so
  the asymmetry is visible rather than implied away by this ADR's framing.
- **No architectural surface was added.** No new port, no `AppContext` field, no
  adapter import in a format crate, no new metric name, no
  [ADR 0016](0016-cross-opt-in-interaction-matrix.md) cross-opt-in row —
  `ReadMetrics` does not influence the release-gate computation, so the
  interaction matrix is N/A (recorded explicitly rather than left silent).
- **No `docs/auth-catalog.md` entry.** `ReadMetrics` is an RBAC *permission*
  (the [ADR 0012](0012-claim-based-rbac-claimless-static-tokens.md) family), not
  an inbound authentication mechanism or a trust anchor. Recorded here so a
  reviewer does not read the absence as an omission.
- **A future `Permission` variant cannot silently inherit this classification.**
  The linter's `every_permission_variant_is_classified` test matches
  exhaustively with no wildcard arm, so adding a variant fails to compile until
  it is consciously classified admin-class or ordinary. `ReadMetrics` is
  classified **ordinary** (`is_admin_class → false`) — deliberately: it is
  read-only and non-admin by design.

## Alternatives considered

- **A deprecation cycle for `HORT_METRICS_REQUIRE_AUTH` (accept-and-warn for one
  release).** Rejected: pre-v1.0, and the flag's whole function was to disable
  the authorization this ADR adds. An accepted-but-ignored env var is also the
  exact "inert operator surface" shape
  [ADR 0015](0015-apply-time-linter-inert-fields-and-naming.md) treats as a
  footgun — an operator who sets it would believe they had re-opened anonymous
  scraping. Removal is the honest signal.
- **Keeping a main-listener `/metrics` mount for single-listener dev
  convenience.** Rejected: it re-creates the public-surface exposure D4 closes,
  and the "dev mode" default is exactly where an unreviewed deployment ends up.
  The cost is that `HORT_METRICS_BIND` must be set for `/metrics` to exist at
  all — accepted, and now stated in the config reference.
- **An `Admin`-OR-`ReadMetrics` two-leg extractor** (mirroring
  `CurateOrAdminPrincipal`'s precedence). Rejected: it is the same
  admin-as-scraper credential problem as admin-gating, just reached by a
  different path, and it would have made the evaluator carve-out pointless.
  `CurateOrAdminPrincipal` is a genuinely different case — curation is a
  day-to-day *administrative* decision role where admin-as-superuser is the
  intended fallback; scraping is not.
- **Deriving the scrape credential from the existing `cronjob-tasks`-style
  operator-provisioned SA** rather than a dedicated one. Rejected: it would
  bundle an unrelated authority (`admin_task_invoke`) into the monitoring
  credential. One SA per workload identity, one capability each.

## References

- `crates/hort-domain/src/entities/rbac.rs` — `Permission::ReadMetrics`.
- `migrations/016_read_metrics_permission.sql` — the additive enum value.
- `crates/hort-http-core/src/authz/extractors.rs` — `MetricsReaderPrincipal`
  and the `metrics_reader_admin_claim_without_explicit_grant_is_denied` guard.
- `crates/hort-app/src/rbac.rs` — the `ReadMetrics` carve-out in
  `user_grants_authorize` and `effective_grants`.
- `crates/hort-http-core/src/handlers/auth.rs` — the whoami
  `GlobalAdmin { global_admin, read_metrics }` wire shape.
- `crates/hort-http-core/src/handlers/metrics.rs`,
  `crates/hort-server/src/http.rs` — `render_metrics` and
  `build_admin_router`; the admin-listener-only mount.
- `crates/hort-server/tests/metrics_auth.rs` — the 401 / 403 / 404 matrix.
- `crates/hort-app/src/lint/permission_grants.rs` — `is_admin_class`, the
  `wildcard-repo-non-admin` / provenance-exemption asymmetry, and the
  no-wildcard classification guard.
- [`metrics-scraper-service-account.md`](../architecture/how-to/operate/metrics-scraper-service-account.md)
  — the operator provisioning recipe.
- `docs/metrics-catalog.md` — `hort_authz_decisions_total{permission}` gains
  `read_metrics`.
