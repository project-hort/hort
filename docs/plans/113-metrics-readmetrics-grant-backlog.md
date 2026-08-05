# Backlog — Scoped `ReadMetrics` grant for `/metrics` (issue #113)

PR-sized items, dependency-ordered. Design doc: `113-metrics-readmetrics-grant.md`.
All work lands on `agent/113-metrics-readmetrics-grant`. Items 1–2 are the
domain/schema foundation; 2b closes the evaluator gap found during Item 2
review; 2c the whoami reporting follow-up; 3 is the gate; 4 is the ADR + docs distillation (must land before main
merge, per D7).

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

## Item 2b — `RbacEvaluator` `ReadMetrics` admin-claim carve-out (orthogonality enforcement)

**Added during Item 2 review (2026-08-05).** Item 2's extractor has no `Admin`
fall-through of its own, but `RbacEvaluator::user_grants_authorize`'s
pre-existing, unconditional `"admin"`-claim short-circuit still grants every
`Permission` — including `ReadMetrics` — so the DECIDED orthogonality
(admin-without-grant → 403; human, 2026-08-05) is unenforced until the shared
evaluator carves `ReadMetrics` out. Pinned by the characterization test
`metrics_reader_admin_claim_short_circuits_pending_113_evaluator_carveout`.

**Design doc section:** §2 D3 (orthogonality decision)
**Read first:** `crates/hort-app/src/rbac.rs` (`user_grants_authorize` admin
short-circuit ~line 249, `effective_grants` marker short-circuit ~line 325, the
`effective_grants_agrees_with_authorize_per_cell` G3-invariant test),
`crates/hort-app/src/use_cases/rbac_resolve_use_case.rs` (the
`effective_grants` consumer)
**Acceptance:**
- `user_grants_authorize`: admin-claim short-circuit no longer applies to
  `Permission::ReadMetrics` — an admin-claim principal needs an explicit
  `read_metrics` grant. Every other permission keeps the short-circuit
  unchanged (including the B1 fail-closed cap arm).
- `effective_grants` stays G3-consistent: under the admin marker it still never
  enumerates repos, but it must surface a `ReadMetrics` cell if (and only if)
  an explicit grant exists — an admin's self-view must agree with what
  `authorize` will actually answer for `/metrics`.
- `effective_grants_agrees_with_authorize_per_cell` extended with
  admin-marker × `ReadMetrics` cases (granted and ungranted); the
  `rbac_resolve_use_case.rs` consumer swept for marker-plus-cells handling.
- The Item 2 characterization test flips to assert 403 (per its own
  forward-motion instructions) and becomes the permanent orthogonality guard.
- 100% `hort-app` coverage on the changed branches.

## Item 2c — whoami surfaces the admin × `ReadMetrics` exception (wire-contract fix)

**Added during Item 2b review (2026-08-05).** Item 2b makes `effective_grants()`
carry an explicit `ReadMetrics` cell for admins, but the whoami HTTP handler
(`hort-http-core/src/handlers/auth.rs::resolve_effective_grants`) discards
`grant_set.cells` on the uncapped-admin path and returns the bare
`{"global_admin": true}` marker — so an admin's whoami cannot distinguish
"holds `read_metrics`" from "doesn't." Reporting-accuracy gap only;
`authorize()` is already correct.

**Wire-shape DECISION (architect, 2026-08-05):** extend the marker variant
additively — `WhoamiEffectiveGrants::GlobalAdmin { global_admin: true,
read_metrics: bool }` — rather than falling through to `Cells` when an
exception cell exists (which would hide global-admin status from clients
whenever the grant is held). Additive JSON field; existing clients unaffected.

**Design doc section:** §2 D3 (orthogonality decision, reporting consistency)
**Read first:** `crates/hort-http-core/src/handlers/auth.rs`
(`resolve_effective_grants`, `WhoamiEffectiveGrants`), Item 2b's
`effective_grants` semantics in `crates/hort-app/src/rbac.rs`, the capped-admin
branch (`cap_cells`) for whether the cap path needs the same treatment
**Acceptance:**
- `WhoamiEffectiveGrants::GlobalAdmin` gains `read_metrics: bool`, populated
  from the `ReadMetrics` cell(s) in `grant_set.cells` on the uncapped-admin
  path; serialization is additive (existing fields unchanged).
- Capped-admin path audited: cap cells already re-pass `authorize()` per Item
  2b's `derive_cli_session_cap` fix — confirm (test) that a capped admin whose
  cap advertises `read_metrics` actually held the grant at mint time, and that
  the whoami cap rendering needs no parallel field (document why if so).
- Tests: uncapped admin with grant → `read_metrics: true`; without →
  `read_metrics: false`; non-admin path byte-identical.
- API docs (whoami reference) updated with the new field + the one-permission
  exception rationale.
- ≥85% coverage on new `hort-http-core` code.

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

## Item 4 — capability ADR + scraper-SA provisioning how-to (D7 distillation)

**Design doc section:** §4, §3.1
**Read first:** `docs/adr/0000-historical-decisions-index.md`, `docs/adr/0012-claim-based-rbac.md`, `docs/adr/0037-gitops-service-account-grant.md`, `docs/adr/0038-admin-identity-model.md`, `crates/hort-config/src/service_account.rs` (`fallbackRotation`/`federatedIdentities`), `docs/architecture/how-to/declare-gitops-config.md`
**Acceptance:**
- `docs/adr/00XX-scoped-metrics-read-capability.md` — under the **then-next-free ADR number** (0051, reserved by the design doc, has since been claimed by `0051-self-contained-chart-and-hort-base-hosting.md`): records D1–D5, the rejection of admin-gating and of pure-ingress-as-sole-control (with the ADR 0012 "network ≠ authz" citation), and the anon-hatch retirement; registered in the ADR index (0000).
- A how-to (operate) page shows provisioning a non-admin scraper ServiceAccount + unscoped `read_metrics` `PermissionGrant` via gitops apply. **Featured worked example = §3.1 Model B** (per the human's one-Flux-repo setup): `federatedIdentities` pinned to Prometheus's K8s SA `sub` (subject-identifying, never aud-only — cf #111), building on the existing `docs/architecture/how-to/federate-k8s-workload-identity.md` exchange, with a ~10-line refresh-loop sidecar writing Prometheus's `authorization.credentials_file`. **Model A** (`fallbackRotation` → `targetSecret`; Hort mints/rotates the PAT into a k8s Secret) is documented as the alternative. **The git repo never contains a token** — only the declaration. Verify the exchanged `TokenKind::ServiceAccount` bearer carries the `read_metrics` grant (grant-snapshot behavior).
- **Read also:** `docs/architecture/how-to/federate-k8s-workload-identity.md`, `docs/architecture/how-to/rotating-service-account-tokens.md`.
- Design/backlog `docs/plans/` files deleted in the promotion (D7) — durable record is the ADR + how-to.

### Starter prompt
```
/hort-architect

Implement Item 4 of docs/plans/113-metrics-readmetrics-grant-backlog.md (design §4).
Write docs/adr/<next-free-number>-scoped-metrics-read-capability.md (D1–D5, reject admin-gating +
pure-ingress-sole-control, retire anon hatch), register it in docs/adr/0000..index, and add
an operate how-to for provisioning a non-admin scraper ServiceAccount with an unscoped
read_metrics grant. Remember docs/plans/ files are deleted before the main promotion (D7).
Confirm acceptance, refine with the user, then write. Can proceed in parallel with Items 1–3
but must reflect their final shapes before merge.
```

## Item 5 — Test harnesses gain a `read_metrics`-granted scrape identity (restore metric assertions)

**Design doc section:** §2 D1–D3 (consequence closure; groomed from directive-005 report escalations #1 + #2)
**Read first:** `handover/archive/005-113-item3-report.md` (escalations section — full call-site inventory), `scripts/native-tests/lib/common.sh` (`assert_metric_ingest` ~88-90), `scripts/native-tests/scenarios/proxy/pull-dedup.sh` (~66-67, the guard shape), `scripts/alpha-fixtures/alpha.env`, `scripts/alpha-fixtures/gitops-config/` (the existing `prefetch` grant for `dev-user` — the pattern to mirror), `docs/architecture/how-to/alpha-testing-runbook.md` §4.d/§9.a
**Context:** Since Item 2 landed on `develop`, every anonymous `/metrics` scrape denies (401/403), so ~10 native-test scenarios' metric-content assertions silently degrade to skip (their non-2xx guards skip, not fail) and the alpha runbook's metrics assertions describe a precondition with no runnable fixture path. Same root gap: no harness has a `read_metrics`-granted identity.
**Acceptance:**
- Alpha fixtures: a `read_metrics` grant lands in `scripts/alpha-fixtures/gitops-config/` (mirroring the existing `dev-user` `prefetch` grant shape); `alpha.env` sets `HORT_METRICS_BIND`; the runbook §4.d/§9.a assertions and triage-cheatsheet row become runnable commands again (no fabricated commands — they must work against the fixtures).
- Native tests: harness setup mints/derives a `read_metrics`-granted bearer (gitops fixture grant + the harness's existing token plumbing); `lib/common.sh`'s `assert_metric_ingest` and every per-scenario `curl … "$METRICS_URL"` call site send `Authorization`. With the granted token available, a non-2xx scrape is a **fail** (assertion power restored); the skip guard remains only for the genuinely-absent case (`METRICS_URL` unset, e.g. external-hort mode).
- Report inventories every `METRICS_URL` curl call site + disposition (the directive-005 report's escalation #2 list is the starting inventory).
- Shellcheck-clean; scenario contract conformance; workspace gate green (script-only change — gate covers the repo).

### Starter prompt
```
/hort-architect

Implement Item 5 of docs/plans/113-metrics-readmetrics-grant-backlog.md (groomed from the
directive-005 report's escalations #1+#2 — read that report's escalation section first for
the full call-site inventory). Give both test harnesses a read_metrics-granted scrape
identity: (a) alpha fixtures — add the grant to scripts/alpha-fixtures/gitops-config/
mirroring the dev-user prefetch grant, set HORT_METRICS_BIND in alpha.env, make the
runbook §4.d/§9.a metrics assertions runnable again; (b) native tests — mint a granted
bearer in harness setup and thread Authorization through lib/common.sh assert_metric_ingest
and every scenario METRICS_URL curl, flipping the non-2xx guard from skip to fail when the
token exists (keep skip only when METRICS_URL is unset). Confirm acceptance, then implement.
```

## Sequencing / notes
- Merge order: 1 → 2 → 2b → 2c → 3, with 4 landing before the develop→main promotion (D7 delete of `docs/plans/`). Item 5 (harness scrape identity) closes the coverage gap Items 2/3 opened — dispatch after Item 3 merges; independent of Item 4.
- Not architecture-eroding: no new port, no `AppContext` field, no adapter import in a format crate, no release-gate interaction. One additive migration.
- Pre-push gate per CLAUDE.md (`cargo fmt/clippy/test --workspace`, `cargo audit`, `cargo deny`); migration adds a non-workspace-crate-free change so no attribution regen needed.
