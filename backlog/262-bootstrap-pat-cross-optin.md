# 262 — A break-glass credential must not compose into a standing one

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0016 (any new operator opt-in that can
influence a gate enumerates its interaction with every other such opt-in in
a cross-opt-in matrix *before* implementation; the close is fail-closed
rejection, never a degraded runtime path) · ADR 0038 (bootstrap is the
short-lived, single-active, no-standing-admin path) ·
`docs/auth-catalog.md` Entry 2 (opt-in admin PATs up to 30 days) and
Entry 9.

**The decision is answered.** The human, 2026-10-03: *"Ja, ADR 38 sollte
auch fuer ein aus dem Bootstrap abgeleitetes PAT gelten."* ADR 0038 governs
a bootstrap-derived PAT. The section below is kept as the reasoning behind
that answer, not as an open question.

## Why

`bootstrap-session` is deliberately short: it requires
`HORT_TOKEN_ALLOW_ADMIN=true`, reuses the non-service-account
`bootstrap-admin` principal, revokes a prior token named
`bootstrap-session`, and clamps the issued full-admin PAT to **one hour**
(`crates/hort-server/src/cli/admin.rs:875-878,899-989`;
`crates/hort-app/src/use_cases/api_token_use_case.rs:1333-1339`).

With the server's admin-PAT opt-in also enabled, that one-hour token is
accepted by the public authenticated self-mint route
(`crates/hort-http-core/src/handlers/api_tokens.rs:137-151,257-274`). The
self-mint use case rejects service accounts — and the bootstrap user is
deliberately not one (`api_token_use_case.rs:746-780`). Its admin gate
checks the same opt-in and the admin principal, then permits an explicit
admin-PAT expiry of **1 to 30 days** (`:2013-2054,2065-2111`). The new PAT
carries an operator-chosen name, while the next bootstrap run looks only
for the reserved `bootstrap-session` name in the first token page
(`admin.rs:739-754,942-966`) — so routine bootstrap rotation does not
revoke it.

Possession of a one-hour break-glass credential therefore yields a 30-day
full-admin credential, with no further DSN access and nothing to revoke it.

Each half is accepted. Entry 2 permits the 30-day admin PAT; ADR 0038
describes bootstrap as short-lived with no standing admin. **The defect is
the composition** — which is precisely the situation ADR 0016 was adopted
for, after `trust_upstream_publish_time` × `scan_backends: []` collapsed
the Gate-2 window between two individually safe opt-ins. The matrix was
never applied to the auth opt-ins.

## The question, and how it was answered

Which contract governs a **bootstrap-derived** principal: Entry 2's 30-day
admin PAT, or ADR 0038's no-standing-admin posture?

**Answered: ADR 0038 governs** (the human, 2026-10-03). A break-glass path whose whole design
is a one-hour clamp plus single-active rotation does not stop being
break-glass because the credential it issued is presented to a different
route. The one-hour clamp is only meaningful if it bounds what the
credential can *reach*, and a derived 30-day admin PAT that bootstrap
rotation cannot see makes it bound nothing. The general admin-PAT feature
is not in question — only its reachability from the bootstrap principal.

This changes `docs/auth-catalog.md`, the canonical inbound-auth control
spec, which is why it was asked before implementation rather than decided
in the course of it.

## What to do

1. **Write the matrix entry first.** ADR 0016 requires the cross-opt-in
   interaction entry in the architect doc *before* the implementation, not
   alongside it. Entry: `HORT_TOKEN_ALLOW_ADMIN` (bootstrap) ×
   server-side admin-PAT opt-in → a bootstrap-derived principal reaching
   self-mint. Record the resolution there.
2. **Close it fail-closed**: the bootstrap principal cannot mint through
   the self-mint route. Rejection, not a shortened expiry and not a warning
   — ADR 0016 is explicit that a degraded runtime path is not the close.
3. **Fix the revoke blind spot regardless.** Bootstrap rotation matching
   only the reserved name in the first token page is a second, independent
   weakness: any token the bootstrap principal owns under another name
   survives rotation. Rotation should revoke by principal, not by name.
4. **Update `docs/auth-catalog.md`** to state the resolution, so the next
   reader of Entry 2 sees the bootstrap exception beside it.

## Explicitly out of scope

- The general admin-PAT feature and its 1–30 day window. Not in question.
- Any change to the bootstrap one-hour clamp itself.
- Service-account token lifetimes and the mint-time cap (ADR 0012).
- A survey of other opt-in pairs. Worthwhile, and it is its own piece of
  work on #332's list — not smuggled in here.

## Acceptance

- The cross-opt-in matrix entry exists in the architect doc and names the
  resolution, with the date and who decided.
- A token issued by `bootstrap-session` is refused by the self-mint route,
  proven by a test that composes the two opt-ins — both enabled — rather
  than testing either clamp alone.
- A token owned by the bootstrap principal under a non-reserved name is
  revoked by the next bootstrap rotation, proven by a test.
- `docs/auth-catalog.md` Entry 2 carries the exception.
- No new knob, and no configuration that re-opens the composition.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
