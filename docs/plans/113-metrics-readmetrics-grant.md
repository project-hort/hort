# Design — Scoped `ReadMetrics` grant for `/metrics` (issue #113)

Branch-local planning doc (`docs/plans/`, deleted before any main merge; durable
decisions distilled into ADR 0051 + the RBAC how-to during the initiative).

## §1 Scope, deferred-items sweep, rationale re-validation

**What.** Close audit finding #113: `/metrics` is gated by `require_principal`
(authentication only) on both the public main listener and the admin listener,
so any authenticated principal — including a zero-grant service-account token —
scrapes the full Prometheus exposition, whose `hort_*` labels carry repository
keys. That hands over the complete repository roster and defeats the
anti-enumeration `NotFound` collapse (`RepositoryAccessUseCase`).

**Decision (human-approved on #113, 2026-08-05).** A **scoped, non-admin**
capability is the primary control; network isolation is defense-in-depth, never
the sole gate — because Hort's own posture (ADR 0012, `build_admin_router` doc)
states *network position is never a substitute for authz*. Admin-gating is
rejected: a Prometheus scraper must not be an admin.

**Deferred-items sweep (Step 0).** `docs/plans/` does not exist on `develop`
(branch-local by D7), so there is no prior-cycle plan/backlog to grep for
`deferred`/`follow-on` hits — recorded explicitly, not silence. The ADR
open-items register (`docs/adr/0000-historical-decisions-index.md`) has no open
metrics-auth item; ADR 0017 (metrics catalog canonical) and the existing
`HORT_METRICS_BIND`/`HORT_METRICS_PUBLIC_BIND`/`metrics_require_auth` surface are
the only adjacent prior work, both absorbed here (not deferred). **No inherited
deferred items.**

**Rationale re-validation.** The reused prior rationale is the
`build_admin_router` doc's "network position is never a substitute for authz"
(ADR 0012). Still valid — and it is precisely what makes option 1 (operator
ingress ACL) insufficient as a sole control on the repo-labelled exposition.
Re-verified against the as-built: the `metrics_require_auth` main-listener
carve-out (`router.rs`) and `build_admin_router`'s `require_principal` layer
both perform authN only; neither is an authz gate. Verdict: reuse still-valid;
this initiative supplies the missing authz leg. **No reversed rationale.**

**Explicitly out of scope.** (a) A per-repository metrics permission — the
exposition is process-global; a global grant is the correct granularity, a
repo-scoped one is meaningless here. (b) Reworking the metrics label schema to
drop repository keys — that would degrade operator observability and is a
separate ADR 0017 concern; the authz gate is the right fix. (c) mTLS on the
scrape path — remains an operator/ingress concern (defense-in-depth), not
changed here.

## §2 Design decisions

### D1 — New domain permission `Permission::ReadMetrics`

Add a seventh[/eighth] variant to `Permission`
(`crates/hort-domain/src/entities/rbac.rs`), DB enum literal `'read_metrics'`,
mirroring the existing coarse global permissions (`Admin`, `AdminTaskInvoke`).
It is a **global** permission — always checked with `repository = None`, never
repo-scoped.

```rust
pub enum Permission {
    Read, Write, Delete, Admin, AdminTaskInvoke, Curate, Prefetch,
    /// Gates the Prometheus scrape endpoint (`GET /metrics`). Global —
    /// the exposition is process-wide, never repo-scoped. DB enum literal:
    /// `'read_metrics'`. Granted via the audited `ApplyConfigUseCase` apply
    /// path to a dedicated scraper ServiceAccount (non-admin). No new admin
    /// endpoint, no grant back door.
    ReadMetrics,
}
```

`Display` → `"read_metrics"`, `FromStr` case-insensitive, exhaustive matches
updated (compiler flags every site). The `hort_authz_decisions_total{permission}`
label gains the `read_metrics` value → **metrics-catalog update required**
(ADR 0017) in the same item.

### D2 — Migration: extend the `permission_type` Postgres enum

New migration `016_read_metrics_permission.sql`: `ALTER TYPE permission_type
ADD VALUE IF NOT EXISTS 'read_metrics';` (additive, non-destructive — passes the
`no_sensitive_drops` guard trivially). Number confirmed free (`migrations/` tail
is `015_stranded_scan_recovery_index.sql`). Note the `ALTER TYPE ... ADD VALUE`
cannot run inside a transaction with immediate use in the same migration; keep
it a standalone statement (sqlx runs each migration file; no same-file INSERT
consuming the new value).

### D3 — New extractor `MetricsReaderPrincipal`

In `crates/hort-http-core/src/authz/extractors.rs`, mirror `AdminPrincipal`:

```rust
pub struct MetricsReaderPrincipal(pub CallerPrincipal);

impl FromRequestParts<Arc<AppContext>> for MetricsReaderPrincipal {
    async fn from_request_parts(parts, state) -> Result<Self, Response> {
        let principal = extract_principal(state, parts).await?;
        authorize(state, &principal, Permission::ReadMetrics, None,
                  PERMISSION_READ_METRICS).map_err(|b| *b)?;
        Ok(Self(principal))
    }
}
```

`render_metrics` takes `_reader: MetricsReaderPrincipal`. Admin does **not**
implicitly satisfy it (a scraper is not an admin, and an admin is not a scraper);
if operators want an admin to also scrape, they grant that SA `read_metrics`
explicitly. (Open refinement question for the human: should `Admin` short-circuit
`ReadMetrics` for operational convenience? Default proposal: **no** — keep the
capabilities orthogonal, matching the "admin is not the bar" decision.)

### D4 — Serve `/metrics` on the admin/observability listener only; drop the public-main-listener mount

Remove the `metrics_require_auth && path=="/metrics"` carve-out in
`crates/hort-http-core/src/router.rs` so the public main listener no longer
serves the repo-labelled exposition at all. `/metrics` is served solely by
`build_admin_router` (`crates/hort-server/src/http.rs`), gated by D3's extractor,
and bound per the existing `HORT_METRICS_BIND`/`HORT_METRICS_PUBLIC_BIND`
surface. Operators keep binding it to an internal interface as **defense-in-depth**.
Config migration: `metrics_require_auth` and the main-listener carve-out are
removed; document the change in the chart + `docs/`.

### D5 — Retire the `HORT_METRICS_REQUIRE_AUTH=false` anonymous escape hatch

The legacy hatch serves the same repo-labelled exposition with authz removed
entirely — inconsistent with D1–D4. Remove it. If a genuinely-open scrape is
ever needed (fully-isolated network), that is an operator decision expressed by
*not granting* a network path, not by a server flag that disables authz. Record
the removal in the ADR (reversing a prior escape hatch) and the auth surface.

## §3 Ports / layers touched

- Inbound port: `GET /metrics` (existing route; new extractor).
- Domain: `Permission` enum (pure; **100% coverage** — new `Display`/`FromStr`
  arms + round-trip test).
- No outbound port change. No `AppContext` field change. No adapter import in a
  format crate. The grant is provisioned via the existing audited
  `ApplyConfigUseCase` path (`GrantSubject::User(sa.id)`, `permission=read_metrics`,
  `repository=None`) — the service-account pattern (ADR 0037/0038/0044); no new
  grant mechanism, no `api_tokens.claims` (hard-blocked by ADR 0012).

## §4 Auth-catalog & ADR

- **auth-catalog.md:** no new entry — `ReadMetrics` is an RBAC *permission*
  (ADR 0012 family), not an inbound *auth mechanism* or trust anchor. Recorded
  here so the reviewer does not flag a missing catalog entry.
- **ADR 0051** (new): "Scoped metrics-read capability; `/metrics` served
  admin-listener-only." Documents D1–D5, the rejection of admin-gating and of
  pure-ingress-as-sole-control, and the retirement of the anon hatch. Authored
  during the initiative; distilled into `docs/architecture/` operate-page for
  the scraper-SA provisioning how-to. (ADR authoring is unblocked: #113 is an
  answered `agent:decision`.)
- **Cross-opt-in interaction matrix (ADR 0016):** N/A — `ReadMetrics` does not
  influence the release-gate computation. Recorded explicitly.

## §5 Observability

- `authorize(.., ReadMetrics, None, ..)` emits the existing
  `hort_authz_decisions_total{permission="read_metrics", result}` — catalog
  update in the D1 item; test asserts the metric fires with the new label
  (`metrics::with_local_recorder`).
- A `read_metrics` **denial** logs `tracing::info!` (audit trail: who tried to
  scrape without the grant), never `err`/ERROR — consistent with the
  privilege-denial rule.
- No new metric names; no new health check.

## §6 Edge cases / invariants

- Anonymous scrape → 401 (unchanged); authenticated-but-no-grant → 403 (new;
  today it is a 200 leak). Both covered by tests.
- The `AuthContext::BearerOnly` config (the sibling audit finding #109) must be
  gated too — `authorize`/`evaluate_rbac` already handle both `Enabled` and
  `BearerOnly`, so the extractor closes #113's leak under that config as well
  (unlike the bare `require_principal` it replaces). Add an explicit
  `BearerOnly` test.
- `AuthContext::Disabled` (mock-only; boot refuses it) → extractor 500s before
  authz, matching the existing pattern; acceptable.
