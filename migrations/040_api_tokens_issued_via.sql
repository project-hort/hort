-- Migration 040 — a credential row says which issuance path minted it.
--
-- The cap a token carries lives in its `api_tokens` row rather than in an
-- envelope (ADR 0012), so the query that establishes an identity's
-- effective authority is a read of this table:
--
--   SELECT name, declared_permissions, repository_ids
--     FROM public.api_tokens
--    WHERE revoked_at IS NULL
--      AND issued_via <> 'federation_exchange';
--
-- Without the last predicate that query is unusable in practice: the
-- federation branch of `/auth/token-exchange` mints one short-lived row
-- per workload exchange, so the handful of durable identities an operator
-- administers sits inside a far larger population of expired exchange
-- rows. `kind` cannot separate them — it is `service_account` for both,
-- because `kind` carries authorisation semantics and provenance is a
-- different axis — and the only other marker in the row is the free-text
-- `description`.
--
-- Purely additive, so ADR 0030's expand half applies as written: a column
-- is added and nothing is dropped, renamed or narrowed. No
-- `CONTRACTIONS.toml` entry, and the previous release's binaries keep
-- serving against this schema because they never name the column.
--
-- `DEFAULT 'unknown'` is what allows a NOT NULL column on a table that
-- already has rows, and it is the honest answer for those rows: nothing
-- in a row written before this migration records its origin.
--
-- The backfill recovers the one origin that IS recoverable. The federation
-- branch writes a description of the form
-- `Federated via /exchange from <ip> (client=<label>)`, so a prefix match
-- anchored on that exact text identifies those rows and nothing else. A
-- `LIKE '%exchange%'` would also match any description an operator
-- happened to type the word into — the CLI-session path's own
-- `Issued via /exchange from <ip>` among them — and would label a durable
-- identity as exchange residue, which is the one direction in which the
-- query above becomes dangerous: an identity silently missing from an
-- authority review.
--
-- Every mint path from here on supplies its own value, so the default is
-- never the answer for a new row: the field is required on the issuance
-- request type in `hort-app` and on the `ApiToken` entity itself, which
-- makes a mint path that fails to name its origin a compile error.

ALTER TABLE public.api_tokens
    ADD COLUMN issued_via character varying(32) NOT NULL DEFAULT 'unknown'
        CONSTRAINT api_tokens_issued_via_check CHECK (
            issued_via IN (
                'unknown',
                'admin_cli',
                'http_mint',
                'federation_exchange',
                'bootstrap',
                'service_account_rotation'
            )
        );

UPDATE public.api_tokens
   SET issued_via = 'federation_exchange'
 WHERE description LIKE 'Federated via /exchange from %';
