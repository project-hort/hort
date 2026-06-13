# 0012 — Claim-based RBAC; long-lived static tokens stay claimless

- **Status:** Accepted
- **Enforced by:** the `GrantSubject` sum type is closed at two variants — `Claims(Vec<String>)` and `User(Uuid)`; permission grants are applied only through the audited `ApplyConfigUseCase` linter. Claim sets are **not** persisted on `api_tokens`/`users`/`machine_identities`. Token-kind is a typed `CallerPrincipal.token_kind`, never a string in the claim set.
- **Supersedes:** the retired `GroupMapping` model (operator-defined group→role mappings).

## Context

RBAC needs to grant authority to identities that arrive with claims from an IdP (groups, roles) without an operator-bypassable mapping invented at runtime, and without a server-side `roles` table that re-creates an RBAC-vs-ABAC split. It also must not silently give long-lived static tokens (PATs, service-account bearers) broad authority they could leak.

## Decision

Authority is granted by **`PermissionGrant` rows whose subject is one of exactly two kinds**: `Claims([...])` (matched against claims resolved from declared `claim_mappings`) or `User(uuid)` (a direct grant). Claim **names** come only from `claim_mappings` — code never synthesises claim names from string patterns. The single synthetic claim allowed is `admin`, derived from `user.is_admin = true`.

**Long-lived static tokens stay claimless** for non-admin authority: a PAT-authenticated principal carries `claims: []` (or `["admin"]` only when the user is admin). To give a long-lived-token actor non-admin authority, use a direct `PermissionGrant { subject: User(sa.id) }` — never mapped-claim inheritance on the token. The only native token kind that carries non-admin claims is the short-lived, IdP-backed `CliSession` (see [0013](0013-idp-authoritative-cli-sessions.md)).

Token-kind discriminators (`cli_session`, `service_account`, `refresh`) are facts on the typed `CallerPrincipal.token_kind`, never folded into the claim set.

## Consequences

- A leaked PAT cannot carry broad mapped-claim authority — it was claimless by construction.
- The grant subject taxonomy is structurally load-bearing for the evaluator's match logic; adding a third variant (`Group`, `ServiceAccountToken`, …) requires re-opening this decision.
- All grants flow through one audited path (the apply linter); a direct DB insert or a back-door admin endpoint bypasses the audit story and is forbidden.
- Role bundling lives in operator-side templating (YAML anchors / Helm), not a server `roles` table.

## Alternatives considered

- **Persist claim sets on `api_tokens`/`users`.** Rejected: re-introduces the leaked-long-lived-token blast radius this decision exists to prevent.
- **Synthesise claims from patterns** ("groups starting with `team-`"). Rejected: re-creates the operator-bypass that explicit `claim_mappings` declaration removes.
- **A server-side `roles` table.** Rejected: re-introduces the RBAC-vs-ABAC bifurcation this collapsed.

## References

- `crates/hort-domain/src/` — `GrantSubject`, `CallerPrincipal.token_kind`; `crates/hort-adapters-postgres/src/claim_mapping_repo.rs`, `permission_grant_repo.rs`.
- The architect skill → the claim-based-RBAC review checklist.
