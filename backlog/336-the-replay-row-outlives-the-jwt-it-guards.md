# 336 — The replay row outlives the JWT it guards

**Issue:** #349 · **Branch:** `agent/349-the-predicate-of-the-purpose`
**Governing decisions:** `docs/auth-catalog.md` Entry 6 (canonical inbound-auth
control spec, ADR 0018 — the anti-replay control and its "sole control on this
surface" claim) · ADR 0022 as amended 2026-08-16 (an applied migration is never
edited: non-wipeable databases exist) · ADR 0008.

**Depends on nothing.** One expiry value, its error branch, and the prose that
states the rule.

## 1. The seen-set row expires before the JWT it is guarding against

`crates/hort-app/src/use_cases/api_token_use_case.rs:1071` takes the seen-set
row's TTL from `token.expires_at`, and the comment above it says so
(`:1061-1063`): *"the seen-set row reuses the resolved token `expires_at` =
min(jwt_remaining, fed_max)"*. `FEDERATION_MAX_LIFETIME_SECS = 3600`
(`crates/hort-http-core/src/handlers/exchange.rs:930`) caps that at one hour,
applied at `:1249`. The prune
is `DELETE FROM jwt_replay_seen WHERE expires_at < now()`
(`crates/hort-adapters-postgres/src/replay_guard_repo.rs:64`).

**The predicate of the purpose** is how long the **source JWT** can still be
presented — its own `exp`. That value is already in hand at the claim:
`FederationSource.exp: i64`, documented *"Always present (the validator
enforced `exp`)"* (`api_token_use_case.rs:284-287`) — the very struct whose
presence switches the guard on.

**What happens instead.** A source JWT with 24 hours of life outlives its
anti-replay row by 23. After the prune, the same signed JWT mints again. The
24-hour shape is supported and pinned by the corpus itself:
`federation_validity_cap_clamps_to_1h_when_jwt_exp_far_away`
(`crates/hort-http-core/src/handlers/exchange.rs:4427`) fixes `exp = now + 24 h`
against the one-hour cap the seen-set row draws its TTL from.

**The rationale that licensed this is half an argument.** Migration 011 says
(`migrations/011_gitops_machine_identity.sql:313-318`): *"a not-yet-pruned
expired row is harmless (the validator already rejects an expired JWT upstream
with `Expired`)"*. True — a **left-over** row is harmless. The prune needs the
converse, that a **removed** row means an expired JWT, and because the horizon
takes the minimum with the bearer cap, "row gone" precisely does not mean "JWT
expired".

**Impact.** An intercepted, still-valid source JWT is redeemable again after
the prune — the replay the control exists to stop, on a surface the auth
catalog calls *"public-by-requirement; no network backstop — anti-replay is
the **sole** control"* (`docs/auth-catalog.md:133`). Preconditions: a source
`exp` beyond one hour (usual for CI identities) and a running prune —
`scheduledTasks.adminTasksEnabled` defaults to `false`
(`deploy/helm/hort-server/values.yaml:1376`), but `replaySeenPrune` is one of
only two tasks that are **immediately on** when that umbrella is flipped,
hourly (`values.yaml:2007-2015`).

## 2. The change

The seen-set TTL comes from `fs.exp`, not from `token.expires_at` — a value
already present instead of a wrong one, no new wiring.

The existing `None` branch (`:1071-1078`, "an unbounded expiry is an invariant
violation") loses its subject: `fs.exp` is an `i64` that is always present.
What replaces it is the conversion duty — turn `fs.exp` (a NumericDate in
seconds) into a `DateTime<Utc>` and treat an unconvertible value
**fail-closed**, in the same shape as the branch it replaces: the exchange is
denied, no token row, no event. The guard's fail-closed posture
(`docs/auth-catalog.md:135`) admits no other answer.

## 3. Where the corrected rationale goes — and where it may not

**Migration 011 is not edited.** An applied migration can never be changed in
place: `sqlx::migrate!` rejects the altered checksum
(`crates/hort-domain/src/events/authorization_events.rs:598-601`;
`crates/hort-server/src/migrate.rs:57-59` — *"`MigrateError::VersionMismatch`
still fires"*), and ADR 0022's 2026-08-16 amendment records that non-wipeable
databases holding real published artifacts exist. Editing that file would
break every one of them at boot.

The correction therefore lands where the rule is **live**:

- **`api_token_use_case.rs:1061-1078`** — the comment that states the wrong
  rule today and is rewritten with the code anyway. It names the superseded
  column note from migration 011 (*"`expires_at` — TTL horizon =
  `min(jwt_remaining, federation_max)`"*) explicitly, so that a grep for the
  false claim reaches the correction.
- **`docs/auth-catalog.md` Entry 6** — the canonical spec for this control.
  Its anti-replay paragraph (`:131`) says a second presentation *"within its
  TTL window"* is denied without saying what the window is; after this change
  it states that the window is the source JWT's own `exp`, which is what makes
  the "sole control on this surface" claim at `:133` true.
- **`deploy/helm/hort-server/values.yaml:2010-2011`** — the cadence comment
  ("one row per distinct federated exchange per hour") no longer describes the
  growth it is measured against.

**Rejected:** a new migration setting `COMMENT ON COLUMN
public.jwt_replay_seen.expires_at`. It is the only way to correct the column's
documentation *inside the database*, but it repairs the sentence in 011 no
better than a code comment does, and it makes migrations a prose channel —
a direction, not a detail. The rule lives in the code and is looked for there.

## 4. The price, named — and why it is paid

A row now lives as long as its source JWT, so with 24-hour CI identities the
table holds roughly 24× what the hourly cadence was sized for. It stays
**finite and measured**: one row per distinct exchange per JWT lifetime. That
is not an unfortunate side effect; it is exactly the quantity an anti-replay
set must retain to keep its promise. A seen-set that expires before its
subject is cheaper because it does less.

## Acceptance

- A test that **kills the wrong predicate**: a federated exchange whose source
  JWT has `exp = now + 24 h` writes a seen-set row whose `expires_at` is that
  `exp` — not the one-hour bearer cap — so the prune's
  `expires_at < now()` cannot remove it while the JWT is still presentable.
- A test for the fail-closed conversion: an `exp` that cannot be converted
  denies the exchange, with no token row and no event.
- The existing cap test
  (`federation_validity_cap_clamps_to_1h_when_jwt_exp_far_away`) still passes
  unchanged — the **bearer's** lifetime is still capped at one hour; only the
  seen-set row's horizon moves.
- `docs/auth-catalog.md` Entry 6, the `api_token_use_case.rs` comment and the
  chart cadence comment say what the code does, and the code comment names the
  superseded migration-011 note.
- **No file under `migrations/` is changed.**
- Full gate green (`CHECK/FMT/CLIPPY/TEST/AUDIT/DENY/ATTR`). No issue/MR
  references in code comments.

## Out of scope

- The two other findings on this issue (items 334 and 335).
- The bearer lifetime cap, `require_jti`, the composite-key fallback, and the
  prune task's schedule or batch size.
- Any retention or sizing work on `jwt_replay_seen` beyond naming the growth
  in the chart comment.
