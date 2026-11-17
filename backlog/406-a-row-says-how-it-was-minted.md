# 406 — A row says how it was minted

**Issue:** #271 · **Branch:** `agent/271-api-tokens-hygiene` · item 1 of 2.

**Governing decisions:** ADR 0012 (authorisation is grant **and** cap, and
the cap lives in this row — which is why this row has to be readable),
ADR 0013 (lifetimes — untouched), ADR 0030 (adding a column is expand, so no
`CONTRACTIONS.toml` entry), ADR 0022 (migrations are frozen once applied —
a new numbered file, never an edit).

## The property

**A credential row says where it came from, so the operator query that
establishes an identity's authority can exclude the ones that are not
identities.**

The query an operator needs is
`SELECT name, declared_permissions, repository_ids FROM api_tokens WHERE
revoked_at IS NULL`, because the cap is in the row and not in an envelope
(ADR 0012). On the reporting instance that returned about ten durable
identities inside 9 498 expired exchange rows. The rows are inert — expired
is expired — so this is not an authorisation defect; it is that the only
instrument for reading authority is unusable.

And it cannot be fixed by filtering today: `kind` is `service_account` for
both sorts, because `kind` carries authorisation semantics and provenance is
orthogonal to it. The only provenance marker in the row is the free-text
`description` ("Federated via /exchange from …").

## Where it stands on `develop` (verified at `bdc502d1`)

- `issued_via` does not exist anywhere in the tree.
- `api_tokens` (`migrations/008_api_tokens.sql:38`) has
  `kind … CHECK (kind IN ('pat','service_account','cli_session'))` at `:50`,
  `declared_permissions` `:54`, `repository_ids` `:55`, `revoked_at` `:57`,
  `last_used_{at,ip,user_agent}` `:58-60`.
- Rows are minted only on the federation branch of `/exchange`:
  `FederationSource` (`crates/hort-app/src/use_cases/api_token_use_case.rs:259`)
  reaches the mint request at `:344` and is recorded in the
  `ApiTokenIssued` event (`crates/hort-domain/src/events/api_token_events.rs:128`),
  **not** in the row.
- `cli_session` is a permitted `kind` value but no row is minted with it:
  a CLI session is a JWT (`crates/hort-app/src/cli_session_signing.rs`,
  `CLI_SESSION_TOKEN_KIND` at `:90` is a payload claim). The CHECK value is
  legacy headroom, which matters only as context for item 2's "all kinds".

## What to build

**`issued_via` as a required field on every mint path**, with the value set
`unknown | admin_cli | http_mint | federation_exchange | bootstrap`:

1. **Column** — a new numbered migration adding `issued_via`, plus the
   **backfill** of existing rows from the exact `/exchange` description text.
   Purely additive: no `CONTRACTIONS.toml` entry (ADR 0030), and a new file
   rather than an edit of 008 (ADR 0022 — `sqlx::migrate!` checksums every
   applied migration, and any edit, comment-only included, makes a migrated
   database refuse to boot with `VersionMismatch`).
2. **A compile error, not a review finding.** The field is **required** on
   the issuance request type, so every mint path must name its origin and a
   new path cannot forget to. `unknown` exists for the backfill's benefit,
   not as a default a caller may pick.
3. **The DTO and the event** — the field on the token DTO, and *additively*
   on `ApiTokenIssued`, so historical events stay byte-identical and chain
   verification keeps passing.
4. **No new `kind`.** `kind` is authorisation semantics; provenance is a
   separate axis. The operator query becomes
   `… WHERE revoked_at IS NULL AND issued_via <> 'federation_exchange'`.

`api_tokens` is on the `no_sensitive_drops` sensitive-table list (the
credential store), so the migration adds and never drops: an
`ALTER TABLE api_tokens DROP CONSTRAINT …` would be rejected by that guard
unless it is a paired same-name `_check` widening, and nothing here needs
one.

## Acceptance

- Every mint path sets `issued_via`; removing one is a compile error, shown
  by naming the paths and the type that forces it.
- The backfill marks exactly the `/exchange` rows, matched on the exact
  description text, and leaves every other row `unknown` — asserted over a
  fixture carrying both sorts plus a near-miss description.
- `ApiTokenIssued` events written before this change deserialise unchanged
  and the chain verification passes over a stream containing both shapes.
- The operator query distinguishes durable identities from exchange rows in
  a test that seeds both.
- 100 % coverage on the new `hort-domain` / `hort-app` branches, including
  every `issued_via` arm.
