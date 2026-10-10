-- Operator-declared allowlist of hosts that may be named as the realm
-- of a *credentialed* bearer-challenge exchange.
--
-- The realm arrives verbatim in the upstream's `WWW-Authenticate`
-- header, so it is upstream-controlled data, and the exchange is the
-- one request that carries
-- `Authorization: Basic base64("oauth2:<secret>")`. Scheme (`https`)
-- and routability bound where that credential may travel but not to
-- whom. This column is how the operator states the latter; the
-- mapping's own origin is always allowed and is never listed here.
--
-- Expansion only: a new nullable-by-default column with a safe default.
-- `'{}'` — the empty list — reproduces today's behaviour exactly,
-- because the consuming gate applies the list only when `secret_ref`
-- is set and an anonymous exchange has no credential to leak.

ALTER TABLE public.repository_upstream_mappings
    ADD COLUMN allowed_realm_hosts text[] DEFAULT '{}'::text[] NOT NULL;

-- Mirrors `allowed_realm_host_reason` in
-- `crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs`:
-- every entry is a bare hostname (ASCII alphanumerics, `.` and `-`,
-- no empty label, no leading/trailing `.` or `-`). A scheme, a port or
-- a path in an entry can never match the host the consumer compares
-- against, so an entry carrying one is an allowance the operator wrote
-- and would not get.
--
-- Expressed over the comma-joined array because a CHECK constraint may
-- not contain a subquery, so `unnest` is unavailable here. `,` is
-- outside the per-entry charset, which is what makes the joined form an
-- exact restatement of the per-entry rule.
ALTER TABLE public.repository_upstream_mappings
    ADD CONSTRAINT chk_repository_upstream_mappings_allowed_realm_hosts CHECK (
        (allowed_realm_hosts = '{}'::text[])
        OR (array_to_string(allowed_realm_hosts, ',') ~
                '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(,[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)*$'
            -- The charset above admits `a..b`; an empty label does not
            -- survive the domain's per-label check, so it must not
            -- survive here either.
            AND array_to_string(allowed_realm_hosts, ',') !~ '\.\.')
    );

-- Mirrors the value-object invariant: only `bearer_challenge` has a
-- realm, so the list has no reachable consumer on the other auth
-- variants and accepting it there would leave the operator believing a
-- control is in force that nothing enforces (ADR 0015).
ALTER TABLE public.repository_upstream_mappings
    ADD CONSTRAINT chk_repository_upstream_mappings_realm_hosts_auth CHECK (
        (allowed_realm_hosts = '{}'::text[])
        OR (upstream_auth_type = 'bearer_challenge'::text)
    );
