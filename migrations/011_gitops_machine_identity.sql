-- Migration 011 — GitOps machine-identity schema (ADR 0018).
--
-- Adds the four new tables that back the machine-identity domain types:
--
--   * `oidc_issuers` — trusted external OIDC issuer (workload identity
--     federation: k8s ServiceAccount JWTs, GitHub Actions OIDC,
--     GitLab CI OIDC, Keycloak service-account clients). One row per
--     trusted issuer; drives JWKS fetch, signature verification, and
--     audience/algorithm gating on the federation branch of
--     `/auth/token-exchange`.
--   * `service_accounts` — declared non-human identity. Backed by a
--     `users` row carrying `is_service_account = true` and
--     `username = 'sa:' || sa.name` (backing-user pattern, ADR 0018).
--   * `service_account_federated_identities` — N:1 trust relationship
--     rows. A federated JWT may assume the SA only when (issuer match
--     AND every claim matches exactly). `position` preserves the
--     declaration order so the matcher evaluates predictably.
--   * `service_account_fallback_rotations` — 0..1 rotation target per
--     SA. The reconciler (`ServiceAccountRotationHandler`) reads
--     `(target_namespace, target_name)`, mints a fresh PAT when stale,
--     and writes the new token in `format`.
--
-- Domain types:
--   crates/hort-domain/src/entities/oidc_issuer.rs
--   crates/hort-domain/src/entities/service_account.rs
--
-- ---------------------------------------------------------------------------
-- Design decisions captured here for review traceability:
-- ---------------------------------------------------------------------------
--
-- 1. `service_accounts.backing_user_id` → `users(id)` `ON DELETE RESTRICT`.
--    The `ApplyConfigUseCase` is the single writer of
--    these rows and is responsible for the backing-user lifecycle. A
--    CASCADE would let a manual `DELETE FROM users` silently drop SA
--    rows the apply use case still considers live; RESTRICT forces the
--    operator to delete the SA first (apply pipeline emits
--    `ServiceAccountDeleted` plus the user-row cleanup, in that order).
--    Mirrors the `api_tokens.created_by_user_id` ON DELETE RESTRICT
--    precedent in `008_api_tokens.sql`.
--
-- 2. `service_account_federated_identities.issuer_name` is a **logical
--    FK**, not a SQL `REFERENCES`. The apply order is `OidcIssuer` →
--    `ServiceAccount`, and operator-facing apply-time validation rejects
--    unknown issuers — but during the same diff sweep an issuer rename is
--    `Updated` (non-identity), so a SQL FK would force an unnecessary
--    delete-recreate dance. Keeping it logical leaves diff semantics
--    intact. Apply-time validation is the only writer of these rows, so
--    the dangling case is not observable through any code path.
--
-- 3. `service_account_fallback_rotations.format` is `TEXT` with an inline
--    CHECK rather than a dedicated PG enum. Two-value enums add migration
--    overhead disproportionate to the gain; the inline CHECK matches the
--    `api_tokens.kind` precedent (migration 008).
--
-- 4. `validity >= 2 * rotation_interval` is enforced by an inline CHECK.
--    This invariant is load-bearing — short validity relative to rotation
--    breaks consumer-side reload latency tolerance. Apply-time validation
--    also enforces it, but the DB CHECK is defense-in-depth against
--    out-of-band SQL.
--
-- 5. No `managed_by` column on `oidc_issuers` or `service_accounts`.
--    These aggregates are exclusively gitops-managed (ADR 0018): the apply
--    use case is the only writer. Unlike `repositories` and
--    `group_mappings`, which have both a public CRUD API (`Local`
--    provenance) and the gitops apply path (`GitOps`), the machine-
--    identity tables have no REST CRUD surface — gitops-only by design. A
--    future extension that wants to add a `POST /oidc-issuers` API would
--    ALTER these tables to add the column then; the current schema stays
--    minimal.
--
-- 6. No length CHECK on `name` / `issuer_url` / claim keys. The
--    existing schema convention is to add length CHECKs only where
--    GDPR data-minimisation review identified a need (e.g.
--    `api_tokens.description`). Names and URLs here have no
--    operator-facing free-text component that would warrant the
--    constraint.
--
-- 7. `service_account_federated_identities.claims` carries an inline
--    CHECK `jsonb_typeof(claims) = 'object' AND claims <> '{}'::jsonb`.
--    An empty `claims` map is vacuously-true at the runtime exact-match
--    matcher (`[].iter().all() ⇒ true`) and would let ANY JWT from the
--    issuer assume the SA — the privilege-escalation footgun the
--    CLAUDE.md anti-pattern list names. Apply-time validation rejects it
--    (ADR 0018) and the runtime matcher + row-decode fail closed too;
--    this CHECK is the DB layer of that defense-in-depth, blocking the
--    out-of-band `INSERT … '{}'` / restore / migration-bug path the apply
--    validator never sees. It is the exact analogue of decision (4)'s
--    FallbackRotation CHECK — the equally load-bearing empty-claims
--    invariant had none. This DDL is applied ONLY by the `migrate` (DDL)
--    role, never the least-privilege runtime DSN (ADR 0009 anti-pattern).
--
-- Reversal: sqlx::migrate! runs UP-only; the project does not maintain
-- paired *.down.sql files. Manual reversal command if ever needed:
--
--   DROP TABLE IF EXISTS public.jwt_replay_seen                       CASCADE;
--   DROP TABLE IF EXISTS public.service_account_fallback_rotations    CASCADE;
--   DROP TABLE IF EXISTS public.service_account_federated_identities  CASCADE;
--   DROP TABLE IF EXISTS public.service_accounts                      CASCADE;
--   DROP TABLE IF EXISTS public.oidc_issuers                          CASCADE;
--
-- GRANTs / role wiring: the four machine-identity tables ship NO explicit
-- `GRANT … TO hort_app_role` statements. Per the post-004 convention
-- (ADR 0009, mirrored from 005, 006, 007, 008, 009, 010), operators run
-- the role-bootstrap recipe before applying migrations, and
-- `ALTER DEFAULT PRIVILEGES … FOR ROLE hort_admin` auto-grants
-- `SELECT, INSERT, UPDATE, DELETE` on FUTURE tables created by
-- `hort_admin`. Those four tables are exactly that case. The
-- `jwt_replay_seen` table is the ONE exception: it ships an explicit
-- REVOKE-then-minimal-`GRANT INSERT, SELECT, DELETE` (no UPDATE) so the
-- runtime DSN's surface on the replay seen-set is pinned to the DML it
-- actually needs (ADR 0009 — DDL via the `migrate` role only). See the
-- block adjacent to that table below.
--
-- Pre-v1.0 (per `feedback_pre_release_migrations`): if the schema
-- needs adjusting before GA, edit THIS file in place rather than
-- appending 012_*_alter.sql on top.

-- ---------------------------------------------------------------------------
-- oidc_issuers (§2 OidcIssuer aggregate)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `name` — UNIQUE, matches CRD `metadata.name`. Diff identity is
--     `name` (ADR 0018); the unique constraint enforces this on the DB
--     side.
--   * `issuer_url` — canonical `iss` claim value. Apply-time validator
--     rejects HTTP (§3); the column accepts both shapes because the
--     validation lives one layer up.
--   * `audiences` — TEXT[] of acceptable `aud` claim values. Apply
--     validator gates non-empty (§3).
--   * `jwks_refresh_interval` — INTERVAL, default 1h (ADR 0018). Adapter
--     layer maps this to `std::time::Duration` via PgInterval
--     (`scanner_registry_repository.rs` precedent).
--   * `allowed_algorithms` — TEXT[] of accepted JWT `alg` values
--     (RFC 7518). Default `{RS256}` per §2; apply validator gates
--     against `JwtAlg::from_str` (Item 1).

--   * `require_jti` — BOOLEAN, default TRUE. When TRUE a federated JWT
--     from this issuer that lacks a `jti` claim is rejected
--     (`jti_required`) before any replay claim or mint; when FALSE the
--     issuer is opted into the weaker `(iss,sub,iat,exp)` composite
--     anti-replay fallback. DEFAULT TRUE is the secure-by-default
--     posture: an `OidcIssuer` envelope written before this column
--     existed has no `requireJti:` key, so `#[serde(default)]` resolves
--     it to `true` and the row is born `require_jti = TRUE`. This is an
--     intentional silent-apply security tightening — jti-less JWTs from
--     a pre-existing issuer start being rejected on next apply unless the
--     operator explicitly sets `requireJti: false`.

CREATE TABLE public.oidc_issuers (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT NOT NULL UNIQUE,
    issuer_url            TEXT NOT NULL,
    audiences             TEXT[] NOT NULL,
    jwks_refresh_interval INTERVAL NOT NULL DEFAULT INTERVAL '1 hour',
    allowed_algorithms    TEXT[] NOT NULL DEFAULT ARRAY['RS256'],
    require_jti           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Federation-branch lookup: the handler matches the JWT `iss` claim
-- against `issuer_url` to find the validator config. §4 expects this
-- to be O(1) — the index gives a btree lookup against the column.
CREATE INDEX idx_oidc_issuers_issuer_url ON public.oidc_issuers (issuer_url);

-- ---------------------------------------------------------------------------
-- service_accounts (§2 ServiceAccount aggregate)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `name` — UNIQUE, matches CRD `metadata.name`. The backing
--     `users.username` is `'sa:' || name` (collision-prevention prefix
--     per §2).
--   * `backing_user_id` — REFERENCES users(id) ON DELETE RESTRICT.
--     See design decision (1) above for the RESTRICT rationale.
--   * `role` — TEXT (not enum). Apply validator gates to
--     `{developer, reader}` (admin SA forbidden — admin is reserved for
--     short-lived interactive sessions, ADR 0013). Storing the wire form
--     keeps the schema flat — the role enum lives in
--     `crates/hort-domain/src/security`.
--   * `repositories` — TEXT[] of repository keys. Apply validator
--     gates non-empty per §3 (no global SA grants).

CREATE TABLE public.service_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    backing_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    role            TEXT NOT NULL,
    repositories    TEXT[] NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- service_account_federated_identities (§2 FederatedIdentity sub-aggregate)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `service_account_id` — REFERENCES service_accounts(id) ON DELETE
--     CASCADE — the federated identity belongs to the SA aggregate;
--     deleting the SA must drop the trust relationships.
--   * `issuer_name` — logical FK on `oidc_issuers.name` (see decision
--     (2) above). Apply validator rejects unknown names; no SQL FK.
--   * `claims` — JSONB. The domain type is `BTreeMap<String, String>`
--     for order-stable serialisation; JSONB stores the key/value tuples
--     without imposing extra row machinery. Inline CHECK pins it to a
--     NON-EMPTY JSON object (decision (7) — ADR 0018 defense-in-depth
--     against an out-of-band empty-claims write).
--   * `position` — declaration order. UNIQUE(service_account_id,
--     position) prevents duplicates; the matcher walks the rows in
--     ORDER BY position so per-SA evaluation is deterministic.

CREATE TABLE public.service_account_federated_identities (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES public.service_accounts(id) ON DELETE CASCADE,
    issuer_name        TEXT NOT NULL,
    claims             JSONB NOT NULL,
    position           INT NOT NULL,
    UNIQUE (service_account_id, position),
    -- Empty claims = "any JWT from this issuer can assume the SA"
    -- (vacuously-true exact-match). Mirrors the apply-time reject
    -- (ADR 0018) and the runtime/row-decode fail-closed layers; this is
    -- the DB layer of that defense-in-depth. Analogue of
    -- chk_validity_at_least_two_rotations.
    CONSTRAINT chk_federated_claims_non_empty_object
        CHECK (jsonb_typeof(claims) = 'object' AND claims <> '{}'::jsonb)
);

-- Federation match scan: §4 walks rows whose `issuer_name` matches the
-- validated issuer. Per-issuer cardinality is small (a handful of SAs
-- per CI system in practice), but the index keeps the scan cheap on
-- larger deployments and matches the backlog Item 2 acceptance.
CREATE INDEX idx_service_account_federated_identities_issuer_name
    ON public.service_account_federated_identities (issuer_name);

-- ---------------------------------------------------------------------------
-- service_account_fallback_rotations (§2 FallbackRotation sub-aggregate)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `service_account_id` — PRIMARY KEY (1:1 with the SA — the
--     domain type carries `Option<FallbackRotation>`). REFERENCES
--     service_accounts(id) ON DELETE CASCADE so deleting the SA
--     drops the rotation target alongside.
--   * `target_namespace` / `target_name` — k8s Secret reference.
--     Apply-time does NOT validate against
--     `worker.rotation.targetNamespaces` (§3) — that's a runtime
--     concern handled by the reconciler.
--   * `format` — TEXT + inline CHECK pinning to the two supported
--     wire-form values (see decision (3) above).
--   * `rotation_interval` / `validity` — both INTERVAL. The
--     `validity >= 2 * rotation_interval` invariant is enforced by
--     an inline CHECK (decision (4)) — this constraint is
--     load-bearing for security and ships with a dedicated mapper
--     test (`migration_011_*_check_constraint_rejects_short_validity`).

CREATE TABLE public.service_account_fallback_rotations (
    service_account_id UUID PRIMARY KEY REFERENCES public.service_accounts(id) ON DELETE CASCADE,
    target_namespace   TEXT NOT NULL,
    target_name        TEXT NOT NULL,
    format             TEXT NOT NULL CHECK (format IN ('dockerconfigjson', 'opaque')),
    rotation_interval  INTERVAL NOT NULL,
    validity           INTERVAL NOT NULL,
    CONSTRAINT chk_validity_at_least_two_rotations CHECK (validity >= 2 * rotation_interval)
);

-- ---------------------------------------------------------------------------
-- jwt_replay_seen (JWT anti-replay seen-set — ADR 0018)
-- ---------------------------------------------------------------------------
-- Durable anti-replay seen-set for the federation branch of
-- `/auth/token-exchange`. Before any `ServiceAccount` bearer is minted,
-- the token-exchange use case atomically *claims* the presented JWT's
-- identity here. First presentation → row inserted → mint proceeds.
-- Any subsequent presentation of the same `jti`/composite within its
-- TTL window → the INSERT conflicts, no row returned → the use case
-- denies, no token minted.
--
-- DURABLE class — explicitly NOT an evictable/ephemeral cache. A
-- negative cache in the evictable keyspace can be `allkeys-lru`-evicted
-- under the exact burst it exists to handle. An evicted `jti` row
-- silently re-permits the replay it was recording, so the seen-set MUST
-- be a durable relational table (ADR 0018). A cleanup outage degrades
-- SAFE (the set never forgets within TTL; only storage grows); a
-- guard-port outage fails CLOSED (the use case denies 503, never mints).
--
-- Why this file (`git tag --contains` rigor, mirroring the
-- `004_events.sql` precedent): the commit that introduced/last-
-- restructured this migration (`b49393b57353142e6da18d7caf45dd300a0ce8ca`)
-- is contained by NO release tag — not even a `v2.0.0-rc.*` pre-release
-- (verified via `git log -- backend/migrations/011_gitops_machine_identity.sql`
-- → `git tag --contains b49393b5` → empty). Since 011 has never shipped
-- under ANY tag (let alone a GA non-`-rc` tag), the pre-release
-- edit-in-place convention (ADR 0022) applies. A GA tag would have
-- forced a forward ALTER migration instead; that boundary was checked
-- and does not apply. 011 owns the federation/OIDC trust model
-- (`oidc_issuers`, `service_account_federated_identities`); the replay
-- seen-set and the `oidc_issuers.require_jti` knob are part of that
-- trust model and belong here semantically.
--
-- Columns:
--   * `issuer_name` — the *resolved* `OidcIssuer.name`
--     (`ValidatedClaims.issuer_name`), NOT the raw `iss` URL. Scopes
--     the seen-set per trusted issuer; renaming an issuer (a deliberate
--     operator act) starts a fresh namespace (a re-declared issuer is a
--     new trust root — acceptable, spec §3).
--   * `key_kind` — discriminator `'jti' | 'composite'`. Keeps both key
--     shapes in one table with one PK; the unused columns are NULL,
--     gated by the CHECK below.
--   * `jti` — non-NULL iff `key_kind='jti'`.
--   * `sub`/`iss`/`iat`/`exp` — non-NULL iff `key_kind='composite'`;
--     stored verbatim for audit/forensics and to satisfy the CHECK.
--   * `key_id` — the single comparable PK component. For `'jti'` rows
--     it is the `jti` itself (already opaque). For `'composite'` rows
--     it is `lower(hex(sha256(iss US sub US iat US exp)))` (US = 0x1F
--     unit separator, injective) computed in
--     `crates/hort-domain` (`ReplayKey::key_id`) — never in SQL.
--   * `expires_at` — TTL horizon = `min(jwt_remaining, federation_max)`
--     (spec §4). Cleanup is the `replay-seen-prune` worker task
--     (default-ENABLED, spec §12 R4) issuing
--     `DELETE … WHERE expires_at < now()`. The claim INSERT does NOT
--     gate on `expires_at` — `ON CONFLICT` is the whole check; a
--     not-yet-pruned expired row is harmless (the validator already
--     rejects an expired JWT upstream with `Expired`).
--
-- PK `(issuer_name, key_kind, key_id)`: including `key_kind` prevents a
-- pathological collision between a `jti` value and a composite digest.
-- The atomic claim is a single
-- `INSERT … ON CONFLICT (issuer_name, key_kind, key_id) DO NOTHING
-- RETURNING key_id` — a returned row ⇒ FirstSeen, zero rows ⇒ Replayed.
-- The database arbitrates concurrent replays; no application lock, no
-- read-then-write window.

CREATE TABLE public.jwt_replay_seen (
    issuer_name  TEXT        NOT NULL,
    key_kind     TEXT        NOT NULL,
    jti          TEXT,
    sub          TEXT,
    iss          TEXT,
    iat          BIGINT,
    exp          BIGINT,
    key_id       TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer_name, key_kind, key_id),
    CONSTRAINT jwt_replay_seen_kind CHECK (
        (key_kind = 'jti'       AND jti IS NOT NULL
                                AND sub IS NULL AND iss IS NULL
                                AND iat IS NULL AND exp IS NULL)
     OR (key_kind = 'composite' AND jti IS NULL
                                AND sub IS NOT NULL AND iss IS NOT NULL
                                AND iat IS NOT NULL AND exp IS NOT NULL)
    )
);

-- Cleanup-by-expiry support (spec §4): a btree on expires_at lets the
-- `replay-seen-prune` delete-expired sweep range-scan instead of
-- seqscan.
CREATE INDEX idx_jwt_replay_seen_expires_at
    ON public.jwt_replay_seen (expires_at);

-- Runtime-DSN privilege surface (ADR 0009).
-- The runtime application role NEVER issues DDL against this table —
-- the table + index + CHECK are created/altered ONLY by the `migrate`
-- subcommand running as the DDL owner. The runtime only does DML: the
-- atomic `INSERT … ON CONFLICT` claim, `SELECT` (defensive /
-- diagnostics), and the `DELETE` prune. Strip everything and re-grant
-- exactly INSERT, SELECT, DELETE — no UPDATE (a recorded replay row is
-- never mutated), no TRUNCATE/REFERENCES/TRIGGER, no CREATE/ALTER.
-- Mirrors the `004_events.sql` REVOKE-then-minimal-GRANT precedent.
-- The DO block tolerates `hort_app_role` not existing yet (fresh dev DB
-- before the role bootstrap — ADR 0009) — the post-004 convention's
-- `ALTER DEFAULT PRIVILEGES` path still covers the future-table case;
-- this explicit pair pins the *minimal* surface for the security review
-- and for operators who bootstrapped roles by hand.
DO $$
BEGIN
    REVOKE ALL ON public.jwt_replay_seen FROM PUBLIC;
    REVOKE ALL ON public.jwt_replay_seen FROM hort_app_role;
    GRANT INSERT, SELECT, DELETE ON public.jwt_replay_seen TO hort_app_role;
EXCEPTION
    WHEN undefined_object THEN
        RAISE NOTICE 'hort_app_role absent; skipping explicit jwt_replay_seen grant (ALTER DEFAULT PRIVILEGES covers the future-table case once roles are bootstrapped)';
END
$$;
