# 072 — #127: admin-mint of SA tokens checks the cap against the TARGET SA's authority

**Issue:** #127 (release-blocker; fix direction **(A)** human-confirmed on the issue,
2026-08-07). Unblocks the `v0.10.0-beta.x` public release gate (E2E harness setup).

**Read first:** the root-cause analysis on #127;
`crates/hort-app/src/use_cases/api_token_use_case.rs` — `issue_for_service_account_inner`
(~:799), `issue_inner`'s cap-vs-authority block (~:2150-2197), and the
`issue_for_service_account_system` doc comment (~:850-882) whose rationale this change
adopts for the REST path; `crates/hort-app/src/rbac.rs::authorize` (:183);
`scripts/native-tests/run.sh::mint_metrics_token` (:139 — must work UNCHANGED after
this fix; it is the acceptance vehicle).

## The change

In the **admin-mint-of-SA-token path only** (`issue_for_service_account_inner` →
`issue_inner`), the cap-vs-authority walk must authorize each declared permission
against the **target SA's backing user**, not the calling admin:

1. Thread an explicit authorization subject through `issue_inner` (e.g. an
   `authz_subject: &CallerPrincipal` parameter distinct from the audit
   actor/caller). **Self-mint (`/users/me/tokens`) passes the caller as subject —
   behavior unchanged.** Admin-SA-mint passes a principal built from the target SA's
   user row (`user_id = target.id`, identity fields from the row, `claims` = the SA's
   own resolved set — never the admin's, never a synthetic `admin` claim,
   `token_cap = None`).
2. **Add the unconditional `Permission::Admin` cap rejection to the admin-SA-mint
   path** (mirror `issue_for_service_account_system`'s check at ~:922,
   `ApiTokenError::AdminAuthorityRequired`). Previously the caller-authority walk
   plus the declaration-layer ban covered this implicitly; with the subject switched
   to the SA it must be explicit. (SAs cannot hold admin — ADR 0018 — so the walk
   would also deny, but the explicit rejection is the documented defence-in-depth
   shape and gives the right error.)
3. `principal_is_admin(admin)` gate, audit attribution (`actor = admin.user_id`,
   `minted_by_admin_id`), denial events, and expiry handling all stay as-is.
4. Update the in-code doc comments: `issue_inner`'s cap-check comment states the
   subject rule ("self-mint: caller; SA-mint: target SA — effective authority is
   bounded by the SA's live grants at request time, same invariant as the
   system-mint path"). No issue numbers in comments.

## Why this is safe (context for the report, not new analysis)

The token's effective authority is `cap ∩ SA's live grants` evaluated per request
(`RbacEvaluator::authorize` cap-leg AND user-leg). A cap the SA cannot exercise is
inert. The system-mint path has operated on exactly this rationale since #113. ADR
0052 remains intact: the SA's `read_metrics` authority still originates solely from
the audited gitops apply path.

## Tests (hort-app is a 100%-coverage crate — every new branch)

- Admin mints SA token declaring `read_metrics`; SA **holds** the grant → issued.
- Same, SA does **not** hold the grant → `CapExceedsAuthority` (the failed tuple
  names `(None, ReadMetrics)`), denial event emitted.
- Per-repo variant: declared `(perm, repo)` authorized against the SA's per-repo
  grants, not the admin's.
- Declared `Admin` cap on the admin-SA-mint path → `AdminAuthorityRequired`.
- Self-mint regression: caller-authority semantics byte-identical (existing tests
  must not change their assertions; add one pinning test that a non-admin
  self-minter still cannot declare beyond their own authority).
- Existing `post_admin_token_*` handler tests in
  `hort-http-core/src/handlers/api_tokens.rs` updated only where the mock grants
  need to move from caller to target.

## Out of scope

- `mint_metrics_token` in the harness: NO change — it must pass as-is (that is the
  point of (A)).
- The rotation/system path, exchange path, self-mint semantics, MR !63's warn idea.

## Scope / acceptance

- One MR off this branch. Gate: `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit --deny
  warnings`, `cargo deny check`.
- Report must include the new/changed test list (coverage tier) and confirm the
  harness helper was untouched.

**Model hint:** sonnet (tightly specified single-path change; the test matrix is the
bulk of the work).
