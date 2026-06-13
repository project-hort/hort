# 0013 — IdP-authoritative, short-lived CLI sessions

- **Status:** Accepted
- **Enforced by:** the `CliSession` token kind is short-lived (≤ 15 min) and IdP-backed; it is the only native token kind carrying non-admin claims. The admin-capability cap (≤ 1 h) and the refresh model are paired — neither half is reversible alone without re-opening the blast-radius analysis.
- **Supersedes:** the retired long-lived limited CLI-token model.

## Context

Interactive CLI access needs to be both convenient and safe. The original model issued long-lived but limited tokens. A long-lived token is a standing liability if leaked; a short-lived one with no refresh is a usability problem. And a CLI session that carries authority must reflect the operator's *current* IdP standing, not a snapshot frozen at login.

## Decision

CLI sessions are **short-lived (≤ 15 min) and IdP-backed**, with a refresh mechanism rather than a long lifetime. `CliSession` is the **only** native token kind that carries non-admin claims (PAT/service-account/refresh stay claimless — see [0012](0012-claim-based-rbac-claimless-static-tokens.md)), which is what lets a `GrantSubject::Claims` grant authorize CLI-session-gated endpoints.

Retiring the long-lived limited token is a **paired** change: short lifetimes + an admin-capability cap (≤ 1 h) + refresh. Reversing one half (re-introducing a long default lifetime, or removing the admin cap) without the other re-opens the blast-radius concern the original invariant guarded.

## Consequences

- A leaked CLI session is useful to an attacker for minutes, not days.
- CLI authority tracks current IdP claims (the direction of travel is fully IdP-backed refresh), rather than a stale login snapshot.
- Re-introducing a >24 h CLI lifetime, or dropping the ≤ 1 h admin cap, is a hard-block in review absent a re-opened design.

## Alternatives considered

- **Long-lived limited CLI tokens (the original model).** Rejected: a standing liability if leaked; the short-lived + refresh model gives the same usability with a far smaller blast radius.
- **Short-lived with no refresh.** Rejected: forces re-login every few minutes; refresh keeps it usable while keeping each token short-lived.

## References

- `crates/hort-domain/src/` — `TokenKind::CliSession`, `CallerPrincipal.token_kind`.
- `docs/auth-catalog.md` — the CliSession entry.
- The architect skill → anti-pattern *re-introducing a long-default CLI session lifetime / removing the ≤1 h admin cap*.
