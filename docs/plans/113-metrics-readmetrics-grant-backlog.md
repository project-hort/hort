# Backlog — Scoped `ReadMetrics` grant for `/metrics` (issue #113)

PR-sized items, dependency-ordered. Design doc: `113-metrics-readmetrics-grant.md`.
All work lands on `agent/113-metrics-readmetrics-grant`. Items 1–2 are the
domain/schema foundation; 3 is the gate; 4–5 are the structural hardening; 6 is
the ADR + docs distillation (must land before main merge, per D7).

## Item 1 — `Permission::ReadMetrics` domain variant + migration 016

**Design doc section:** §2 D1, D2
**Read first:** `crates/hort-domain/src/entities/rbac.rs`, `migrations/001_users_roles_rbac.sql`, `migrations/015_stranded_scan_recovery_index.sql`, `docs/metrics-catalog.md` (`hort_authz_decisions_total`)
**Acceptance:**
- `Permission::ReadMetrics` added; `Display` → `"read_metrics"`, `FromStr` case-insensitive round-trips; every previously-exhaustive `match Permission` site updated (compiler-guided).
- `migrations/016_read_metrics_permission.sql` adds the enum value additively (`ADD VALUE IF NOT EXISTS 'read_metrics'`); migration numbering verified non-colliding.
- `docs/metrics-catalog.md` gains `read_metrics` as a permitted `permission` label value for `hort_authz_decisions_total` (same PR).
- **hort-domain 100% coverage** on the new arms (Display, FromStr ok + err, serde round-trip).
- No `api_tokens.claims`/`users.claims` surface introduced (ADR 0012 hard block).

### Starter prompt
```
/hort-architect

Implement Item 1 of docs/plans/113-metrics-readmetrics-grant-backlog.md (design §2 D1/D2).
Read first: crates/hort-domain/src/entities/rbac.rs, migrations/001_users_roles_rbac.sql,
the migrations/ tail, docs/metrics-catalog.md. Add Permission::ReadMetrics (DB literal
'read_metrics', global/non-repo-scoped), wire Display/FromStr and every exhaustive match,
add migration 016 (additive ALTER TYPE ADD VALUE), and add 'read_metrics' to the
metrics-catalog permission-label set in the same change. 100% coverage on hort-domain new
arms. Do NOT add any *.claims column (ADR 0012). Confirm the item's acceptance list, then
refine with the user before coding.
```

## Item 2 — `MetricsReaderPrincipal` extractor + gate `render_metrics`

**Design doc section:** §2 D3, §6
**Read first:** `crates/hort-http-core/src/authz/extractors.rs` (`AdminPrincipal`), `crates/hort-http-core/src/authz/mod.rs`, `crates/hort-http-core/src/handlers/metrics.rs`, `crates/hort-http-core/test_support`
**Acceptance:**
- `MetricsReaderPrincipal(pub CallerPrincipal)` mirrors `AdminPrincipal`, authorizing `Permission::ReadMetrics` with `repository = None` and a `PERMISSION_READ_METRICS` label.
- `render_metrics` takes `_reader: MetricsReaderPrincipal`.
- Tests (via `build_mock_ctx`): anonymous → 401; authenticated no-grant → 403; `read_metrics`-granted → 200; **and an explicit `AuthContext::BearerOnly` case** (closes #113 under the disabled-provider + native-tokens config, cf. #109). **Admin-without-`read_metrics` → 403** — orthogonality is DECIDED (human, 2026-08-05); the extractor has no `Admin` fall-through.
- `read_metrics` denial logs `info!` (not `err`); test or manual note confirms the tracing level.
- ≥85% coverage on new `hort-http-core` code.

### Starter prompt
```
/hort-architect

Implement Item 2 of docs/plans/113-metrics-readmetrics-grant-backlog.md (design §2 D3, §6).
Read first: crates/hort-http-core/src/authz/extractors.rs (mirror AdminPrincipal),
authz/mod.rs, handlers/metrics.rs, test_support::build_mock_ctx. Add MetricsReaderPrincipal
(authorize ReadMetrics, None), gate render_metrics with it. Tests: 401 anon / 403 no-grant /
200 granted / BearerOnly-config case / admin-without-grant 403. Denial logs info! not err.
Confirm acceptance, refine with the user, then implement. Depends on Item 1.
```

## Item 3 — Serve `/metrics` admin-listener-only; drop public-main-listener carve-out; retire the anon hatch

**Design doc section:** §2 D4, D5
**Read first:** `crates/hort-http-core/src/router.rs` (metrics carve-out ~306-311), `crates/hort-server/src/http.rs` (`build_admin_router`), `crates/hort-server/src/config.rs` (`metrics_require_auth`, `HORT_METRICS_BIND`, `HORT_METRICS_PUBLIC_BIND`), `deploy/helm/hort-server/`
**Acceptance:**
- The `metrics_require_auth && path=="/metrics"` main-listener carve-out is removed; the public main listener no longer serves `/metrics`.
- `build_admin_router` gates `/metrics` via `MetricsReaderPrincipal` (replacing bare `require_principal`); binding unchanged (`HORT_METRICS_BIND`/`HORT_METRICS_PUBLIC_BIND`).
- `HORT_METRICS_REQUIRE_AUTH` / `metrics_require_auth` removed end-to-end (config, chart, docs); a startup path that referenced the anon hatch fails no tests.
- Chart + `docs/` updated: scrape is admin-listener-only, grant-gated, internal-bind recommended as defense-in-depth.
- Existing metrics-auth tests updated (the `metrics_auth.rs` anon→401 test stays; add non-grant→403).

### Starter prompt
```
/hort-architect

Implement Item 3 of docs/plans/113-metrics-readmetrics-grant-backlog.md (design §2 D4/D5).
Read first: hort-http-core/src/router.rs (metrics carve-out), hort-server/src/http.rs
(build_admin_router), hort-server/src/config.rs (metrics_require_auth/HORT_METRICS_BIND),
deploy/helm/hort-server/. Remove the public-listener /metrics carve-out, gate the
admin-listener /metrics with MetricsReaderPrincipal, and remove the
HORT_METRICS_REQUIRE_AUTH anon hatch end-to-end (config+chart+docs). Update the
metrics_auth tests. Confirm acceptance, refine with the user, then implement. Depends on Item 2.
```

## Item 4 — ADR 0051 + scraper-SA provisioning how-to (D7 distillation)

**Design doc section:** §4, §3.1
**Read first:** `docs/adr/0000-historical-decisions-index.md`, `docs/adr/0012-claim-based-rbac.md`, `docs/adr/0037-gitops-service-account-grant.md`, `docs/adr/0038-admin-identity-model.md`, `crates/hort-config/src/service_account.rs` (`fallbackRotation`/`federatedIdentities`), `docs/architecture/how-to/declare-gitops-config.md`
**Acceptance:**
- `docs/adr/0051-scoped-metrics-read-capability.md`: records D1–D5, the rejection of admin-gating and of pure-ingress-as-sole-control (with the ADR 0012 "network ≠ authz" citation), and the anon-hatch retirement; registered in the ADR index (0000).
- A how-to (operate) page shows provisioning a non-admin scraper ServiceAccount + unscoped `read_metrics` `PermissionGrant` via gitops apply. **Featured worked example = §3.1 Model B** (per the human's one-Flux-repo setup): `federatedIdentities` pinned to Prometheus's K8s SA `sub` (subject-identifying, never aud-only — cf #111), building on the existing `docs/architecture/how-to/federate-k8s-workload-identity.md` exchange, with a ~10-line refresh-loop sidecar writing Prometheus's `authorization.credentials_file`. **Model A** (`fallbackRotation` → `targetSecret`; Hort mints/rotates the PAT into a k8s Secret) is documented as the alternative. **The git repo never contains a token** — only the declaration. Verify the exchanged `TokenKind::ServiceAccount` bearer carries the `read_metrics` grant (grant-snapshot behavior).
- **Read also:** `docs/architecture/how-to/federate-k8s-workload-identity.md`, `docs/architecture/how-to/rotating-service-account-tokens.md`.
- Design/backlog `docs/plans/` files deleted in the promotion (D7) — durable record is the ADR + how-to.

### Starter prompt
```
/hort-architect

Implement Item 4 of docs/plans/113-metrics-readmetrics-grant-backlog.md (design §4).
Write docs/adr/0051-scoped-metrics-read-capability.md (D1–D5, reject admin-gating +
pure-ingress-sole-control, retire anon hatch), register it in docs/adr/0000..index, and add
an operate how-to for provisioning a non-admin scraper ServiceAccount with an unscoped
read_metrics grant. Remember docs/plans/ files are deleted before the main promotion (D7).
Confirm acceptance, refine with the user, then write. Can proceed in parallel with Items 1–3
but must reflect their final shapes before merge.
```

## Sequencing / notes
- Merge order: 1 → 2 → 3, with 4 landing before the develop→main promotion (D7 delete of `docs/plans/`).
- Not architecture-eroding: no new port, no `AppContext` field, no adapter import in a format crate, no release-gate interaction. One additive migration.
- Pre-push gate per CLAUDE.md (`cargo fmt/clippy/test --workspace`, `cargo audit`, `cargo deny`); migration adds a non-workspace-crate-free change so no attribution regen needed.
