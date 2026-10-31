# 0013 — IdP-authoritative, short-lived CLI sessions

- **Status:** Accepted, **amended 2026-10-28** — the refresh half is retired and the
  admin-cap figure below is corrected. Read the amendment at the end before acting on
  any statement about refresh or about a "≤ 1 h" cap.
- **Enforced by:** the `CliSession` token kind is short-lived (≤ 15 min) and IdP-backed; it is the only native token kind carrying non-admin claims. The admin-capability cap (≤ 1 h) and the refresh model are paired — neither half is reversible alone without re-opening the blast-radius analysis.
- **Supersedes:** the retired long-lived limited CLI-token model.

## Context

Interactive CLI access needs to be both convenient and safe. The original model issued long-lived but limited tokens. A long-lived token is a standing liability if leaked; a short-lived one with no refresh is a usability problem. And a CLI session that carries authority must reflect the operator's *current* IdP standing, not a snapshot frozen at login.

## Decision

CLI sessions are **short-lived (≤ 15 min) and IdP-backed**, with a refresh mechanism rather than a long lifetime. `CliSession` is the **only** native token kind that carries non-admin claims (PAT/service-account/refresh stay claimless — see [0012](0012-claim-based-rbac-claimless-static-tokens.md)), which is what lets a `GrantSubject::Claims` grant authorize CLI-session-gated endpoints.

Retiring the long-lived limited token is a **paired** change: short lifetimes + an admin-capability cap (≤ 1 h) + refresh. Reversing one half (re-introducing a long default lifetime, or removing the admin cap) without the other re-opens the blast-radius concern the original invariant guarded.

> **Amended 2026-10-28.** Refresh was never built and is now retired, so this pairing has no second half. What remains is the cap alone. See the amendment below.

## Consequences

- A leaked CLI session is useful to an attacker for minutes, not days.
- CLI authority tracks current IdP claims (the direction of travel is fully IdP-backed refresh), rather than a stale login snapshot.
- Re-introducing a >24 h CLI lifetime, or dropping the ≤ 1 h admin cap, is a hard-block in review absent a re-opened design.

## Alternatives considered

- **Long-lived limited CLI tokens (the original model).** Rejected: a standing liability if leaked; the short-lived + refresh model gives the same usability with a far smaller blast radius.
- **Short-lived with no refresh.** Rejected at the time: forces re-login every few minutes; refresh keeps it usable while keeping each token short-lived. **This is the chosen model as of the 2026-10-28 amendment** — the rejection rested on an assumption about re-login that does not hold. See the amendment below.

## References

- `crates/hort-domain/src/` — `TokenKind::CliSession`, `CallerPrincipal.token_kind`.
- `docs/auth-catalog.md` — the CliSession entry.
- The architect skill → anti-pattern *re-introducing a long-default CLI session lifetime / removing the ≤1 h admin cap*.

### Amendment 2026-10-28 — refresh is retired; the rejected alternative is the chosen one

*Authorised by the maintainer, 2026-10-28: "Ich entscheide, dass wir die
Refresh-Funktion streichen."*

**The decision.** CLI sessions remain short-lived and IdP-backed. The refresh
mechanism this ADR paired with the admin cap is **not built and will not be**.
"Short-lived with no refresh", listed above under *Alternatives considered* as
rejected, is the model hort ships.

**Why the original rejection does not hold.** It was rejected because it
"forces re-login every few minutes". That reasoning assumed re-login means
re-entering a credential. On the path that carries the case, it does not: the
mediated login's authorize request sends **no `prompt` parameter**
(`crates/hort-cli/src/auth/loopback.rs`), so where the IdP session is still
live the IdP redirects straight back. A repeat login is credential-silent; its
visible cost is a browser tab opening and closing.

That is the same mechanism a browser-based OIDC client uses for silent
renewal. The long-lived credential in that model is **the IdP's own session**,
held by the user agent and owned by the IdP — not a token held by the relying
party. The usability the original decision wanted was already available
without issuing a second credential.

**What refresh would have cost.** A registry-held refresh token re-mints a
session from a claim set frozen at login. Claims resolve from IdP groups, and
`idp_groups` is persisted nowhere, so a rotation cannot re-resolve them: an IdP
group membership withdrawn mid-session would survive for the whole refresh
window. The short access lifetime had been doing double duty as the
IdP-reconciliation interval, and refresh would have widened that interval to
the session's absolute deadline. For an ADR whose premise is that a session
reflects *current* IdP standing, that is the wrong direction — the mechanism
meant to serve the premise would have undermined it.

Two further costs, both measured while the feature was being built and both
gone with it: a long-lived credential at rest on the client, and a rotation
path on which a cleared `users.is_admin` would not have taken effect until the
window expired.

**The pairing is retired with it.** *Enforced by* and the Decision described
the admin-capability cap and refresh as paired, "neither half reversible
alone". With refresh gone there is no second half. The cap stands on its own
and is not weakened by the removal — it is the only bound on a leaked session,
which is now its whole justification. The mirrored anti-pattern entries in
`CLAUDE.md` and the architect skill are updated to match.

**Correction of fact, in the same edit.** This ADR states the admin cap as
"≤ 1 h" in four places. The enforced value is **900 s — 15 minutes — for both
admin and non-admin sessions** (`MAX_ADMIN_CLI_SESSION_LIFETIME_SECS` and
`MAX_NON_ADMIN_CLI_SESSION_LIFETIME_SECS` in
`crates/hort-app/src/use_cases/api_token_use_case.rs`). The code has always
been tighter than the record. The record is corrected; the code is not
relaxed, and `clamp_lifetime`'s own doc comment already warns against
"reconciling" the figure upward.

**What is accepted rather than overlooked.** A human working over SSH on a
host with no browser has nothing to borrow, and keeps the RFC 8628 device-code
flow at each re-login. That cost is accepted. If it becomes real, the answer
is renewal **re-authorized against the IdP** — which re-resolves claims every
time and so has no reconciliation interval at all — not a registry-held
refresh token. Reaching for one again re-opens this amendment.
