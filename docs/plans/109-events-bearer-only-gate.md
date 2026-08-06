# #109 — Events API admin-category gate skipped under `AuthContext::BearerOnly`

Issue: #109 (source: audit #106 finding H4, HIGH, adversarially verified; spec approved
by the human 2026-08-05). Feature branch: `agent/109-events-beareronly-gate`.
Single-item initiative — design note and backlog combined in this file (proportional to
a one-site fix; D7 branch-lifetime doc regardless). No ADR change: the fix restores the
documented BearerOnly authz contract; no decision changes.

## §1 Scope, sweep, verified shapes

`hort-http-events/src/handler.rs:86` gates admin-only event categories with a
single-arm `if let AuthContext::Enabled { rbac, .. }` — under `BearerOnly`
(`HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=true`, a
production-supported mode whose composition arm wires a FULLY POPULATED evaluator from
`permission_grant_repo.list_all()`), the `Permission::Admin` check never runs and the
per-event filter's `admin_required` else-branch (`:191-193`) then returns full
unredacted pages — its "already passed the upfront gate" assumption is exactly what
the skipped arm breaks. A zero-grant token reads all eight admin-only categories.

Verified during grooming (Explore sweep, 2026-08-05):
- **Sole instance.** A workspace-wide sweep for `if let AuthContext::Enabled` /
  single-arm shapes returns exactly this one site. Every other authz decision point
  uses the shared `Enabled | BearerOnly` match arm or `ctx.auth.rbac()`; the two
  intentional separate-arm sites (`exchange.rs:506` interactive-OIDC 4xx,
  `middleware/auth.rs:811` WWW-Authenticate challenge) are authN-shaped, not authz.
- The same file already has the correct exhaustive shape at `:156`
  (`Enabled { rbac, .. } | BearerOnly { rbac, .. }`).
- `AuthContext::rbac()` (`hort-http-core/src/context.rs:209-214`) covers both
  auth-on arms and returns `None` only under `Disabled` — the structurally
  unmissable accessor the defective site bypassed by raw-destructuring.
- Test gap: `crates/hort-http-events/tests/handler.rs` has ZERO `BearerOnly`
  coverage; `test_support::with_auth`/`rebuild` already handle all three arms, so
  the missing test needs no harness change. Prior art:
  `authz/extractors.rs:1653-1669` (`metrics_reader_extractor_denies_no_grant_under_bearer_only`,
  already tagged #109/#113) describes this exact leak class — the events path was
  missed in that sweep.

**Deferred-items sweep (Step 0):** no ADR-0000 open row covers this; no
`docs/plans/` deferrals apply (grep run 2026-08-05 — the #113/#115/#107 plans touch
metrics/quarantine, not the events read path). **Rationale re-validation:** the
handler comment's two-state framing ("Disabled ⇒ every extractor grants — preserve
that contract") predates BearerOnly's introduction and silently folded BearerOnly
into the Disabled-shaped fall-through — reversed here; the Disabled contract itself
is preserved unchanged.

**Explicitly out of scope:** a lint/structural guard banning raw
`AuthContext` destructuring (only one site existed; a guard is heavier than the
disease — reconsider if a second instance ever appears); any change to the
per-event filter shape at `:153-193` (its assumption becomes valid again once the
gate is fixed).

## §2 Decision

**D1 — route the gate through `ctx.auth.rbac()`.** Replace the raw
`if let AuthContext::Enabled` destructure with the accessor:
`Some(rbac)` → run the existing `Permission::Admin` check (Enabled AND BearerOnly);
`None` (Disabled) → skip, preserving the documented every-extractor-grants contract.
Chosen over merely two-arming the `if let` because the accessor makes the
Disabled-vs-auth-on distinction unmissable for future edits — the exact failure mode
this bug demonstrates.

## §3 Observability

None new. The denial path reuses the existing `emit_events_pull` + Forbidden flow
(privilege denial already logs at the established level).

## Item 1 — admin-category gate honours `BearerOnly` (+ regression pins)

**Design doc section:** §2 D1
**Read first:** `crates/hort-http-events/src/handler.rs` (:79-97 the defective gate
and its two-state comment; :153-193 the filter that assumes the gate),
`crates/hort-http-core/src/context.rs:206-214` (`rbac()`),
`crates/hort-http-events/tests/handler.rs` (`enable_auth_with` seeding, the
line-478/496/730 admin-category tests), `hort-http-core/src/test_support.rs`
`with_auth`/`rebuild` (three-arm support)
**Acceptance:**
- The admin-category gate runs whenever `ctx.auth.rbac()` returns `Some` (Enabled +
  BearerOnly); Disabled skip preserved; the `:79-83` comment rewritten to name all
  three arms.
- New tests in `tests/handler.rs`: BearerOnly × admin-only category × zero-grant
  token → 403 (the leak pin — mirrors the line-478 Enabled test); BearerOnly ×
  admin-only category × admin-claim grant → 200; existing Enabled/Disabled pins
  unchanged.
- Cross-reference comment linking the extractors.rs #109-tagged prior-art test.
- ≥85% coverage on touched `hort-http-events` code; full pre-push gate green.

### Starter prompt

/hort-architect

Implement Item 1 (the only item) of `docs/plans/109-events-bearer-only-gate.md`
(branch `agent/109-events-beareronly-gate`, issue #109 — HIGH). Read §1/§2 first.
Replace handler.rs:86's single-arm `if let AuthContext::Enabled` with the
`ctx.auth.rbac()` accessor per D1 (Some → existing Admin check for Enabled AND
BearerOnly; None/Disabled → skip, contract preserved), rewrite the :79-83 comment for
three arms, and add the BearerOnly regression pins (zero-grant → 403; admin-claim →
200) using the existing with_auth harness. No other files change. Run the full
pre-push gate.
