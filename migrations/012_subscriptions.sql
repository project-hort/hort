-- Migration 013 — event notifications (subscriptions).
--
-- Renumbered 011 → 013 during the merge of origin/feature/v2-enterprise-
-- rewrite: machine-identity independently took 011 (gitops machine
-- identity) + 012 (jobs kind), so this migration moved to the next free
-- slot. Subscriptions has no forward dependency on the machine-identity
-- schema, so ordering after 011/012 is safe.
--
-- Adds the `subscriptions` table that backs the event-notification CRUD
-- and dispatcher infrastructure.
--
-- One row per operator-authored subscription. The dispatcher (a
-- `crates/hort-app` background task spawned at composition root)
-- loads every `state = 'active'` row at startup and refreshes the
-- cache every 30 s via `SubscriptionRepository::list_active`; the
-- `idx_subscriptions_active` partial index makes that refresh cheap.
--
-- Domain types:
--   crates/hort-domain/src/entities/subscription.rs
--     (`SubscriptionTarget`, `SubscriptionFilter`, `SubscriptionState`,
--     `DisableReason`)
--
-- FK + JSONB + unique-constraint precedent: migrations/008_api_tokens.sql
--
-- FK choices:
--   * `owner_user_id` → `users(id) ON DELETE CASCADE` — the
--     subscription is the user's; if the user row is removed, the
--     subscription row vanishes with it. Same convention as
--     `api_tokens.user_id` (ADR 0012).
--   * `created_by_token_id` → `api_tokens(id) ON DELETE SET NULL` —
--     audit attribution only. Rotating or deleting the authoring token
--     does NOT cascade-delete the
--     subscription (the cap snapshot lives in `filter.repositories`,
--     not in a token reference). When the token is removed, the
--     attribution column nulls out — the subscription stays live.
--
-- JSONB shape:
--   * `target` — `{"kind": "webhook", "url": ...,
--     "secret_ref": {"source": "env_var"|"file", "location": ...}}`
--     or `{"kind": "nats_jetstream", "subject": ...}`. The adapter
--     (`crates/hort-adapters-postgres/src/subscription_repo.rs`)
--     enforces this shape via typed-DTO encode/decode. Domain types
--     in `crates/hort-domain` do NOT derive `Deserialize`
--     (`static_assertions::assert_not_impl_any!` invariant) — the wire
--     boundary is the only place wire-shaped JSON is parsed. The webhook
--     signing secret is stored as a `SecretRef` LOCATOR (env-var name /
--     file path), never the secret material or any hash of it. The HMAC
--     key is resolved at delivery time via `SecretPort` (mirrors
--     `repository_upstream_mappings.secret_ref`). A reader of this
--     column holds a pointer, not the key — closing the "DB/backup read →
--     forge signed webhook deliveries" exposure. Wire format unchanged.
--   * `filter` — flat struct: `categories` list, `event_types`
--     (`{"kind": "all"}` or `{"kind": "some", "kinds": [...]}`),
--     `repositories` (`{"kind": "owned_by_actor" | "some" | "all"}`),
--     `named_predicates` (empty in v1; reserved as the audited
--     extension point).
--   * `last_failure` — `{"at": <RFC3339>, "reason": <NotifyFailureReason JSON>,
--     "consecutive_failures": <u32>}` overwritten on each new failure
--     (visibility aid, NOT delivery semantics).
--   This is typed Rust DTOs in the adapter — NOT operator-typed YAML.
--   Schemas evolve via deliberate Rust code changes, not opaque blob
--   edits.
--
-- Closed-enum constraints:
--   * `target_kind ∈ {webhook, nats_jetstream}` mirrors the two v1
--     `SubscriptionTarget` variants.
--   * `state ∈ {active, paused, disabled}` mirrors `SubscriptionState`.
--   * `disable_reason ∈ {owner_deactivated, delivery_failure_budget_exhausted,
--     operator_disabled}` OR NULL mirrors `DisableReason`.
--     `NULL` is the steady-state value when `state != 'disabled'`.
--
-- GRANTs / role wiring: this migration ships NO explicit
-- `GRANT … TO hort_app_role` statements. The post-004 convention
-- (ADR 0009, mirrored from 005, 006, 007, 008, 009, 010) is that
-- operators run the role-bootstrap recipe before applying migrations,
-- and `ALTER DEFAULT PRIVILEGES` then auto-grants `SELECT, INSERT,
-- UPDATE, DELETE` on FUTURE tables created by `hort_admin`. The
-- `subscriptions` table is exactly that case.
--
-- Reversal: sqlx::migrate! runs UP-only; the project does not maintain
-- paired *.down.sql files anywhere in `backend/migrations/`. Manual
-- reversal command if ever needed (operator runs against the DB
-- directly):
--
--   DROP TABLE IF EXISTS public.subscriptions CASCADE;
--   -- The CASCADE-dropped table also takes its two indexes:
--   --   idx_subscriptions_owner, idx_subscriptions_active
--
-- Pre-v1.0 (per `feedback_pre_release_migrations`): if the schema
-- needs adjusting before GA, edit THIS file in place rather than
-- appending 012_subscriptions_alter_*.sql on top.
--
-- Idempotence: this migration runs exactly once via the
-- `_sqlx_migrations` bookkeeping table. CREATE TABLE deliberately has
-- NO `IF NOT EXISTS` guard — if a half-migrated database somehow
-- already carries a `subscriptions` table, the migration must fail
-- fast with `relation "subscriptions" already exists` so the operator
-- notices. `IF NOT EXISTS` would silently mask the divergence.

CREATE TABLE public.subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_by_token_id uuid REFERENCES public.api_tokens(id) ON DELETE SET NULL,
    name character varying(255) NOT NULL,
    description text,
    -- 1 KB cap on description — same data-minimisation discipline as
    -- `api_tokens.description` (GDPR review). The use case maps the
    -- constraint to `400 invalid_description`; raw INSERT bypassing the
    -- use case still gets caught at the schema layer.
    CONSTRAINT subscriptions_description_length_check CHECK (
        description IS NULL OR length(description) <= 1024
    ),
    target_kind character varying(32) NOT NULL
        CHECK (target_kind IN ('webhook', 'nats_jetstream')),
    target jsonb NOT NULL,
    filter jsonb NOT NULL,
    -- The owner's resolved claim set captured at create and full-replaced
    -- on every update (ADR 0012). The dispatcher synthesises the delivery
    -- principal from this snapshot (it does NOT re-resolve
    -- `claim_mappings` at delivery time) so events deliver under the
    -- authority floor the creator had at the most recent fresh-session
    -- interaction. Brand-new column — no prior `snapshot_*` field ever
    -- shipped. `DEFAULT '{}'` covers the pre-v1.0 in-place re-migrate
    -- (dev environments drop and re-create `subscriptions`; the default
    -- is also the correct under-privileged value for a PAT-created
    -- subscription).
    snapshot_claims text[] NOT NULL DEFAULT '{}'::text[],
    state character varying(32) NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'paused', 'disabled')),
    disable_reason character varying(64),
    -- Mirror the closed-enum `DisableReason` at the
    -- schema layer so out-of-band SQL cannot land a nonsense reason
    -- that the adapter's `disable_reason_from_text` would later
    -- surface as a corrupt-row Invariant.
    CONSTRAINT subscriptions_disable_reason_check CHECK (
        disable_reason IS NULL OR disable_reason IN (
            'owner_deactivated',
            'delivery_failure_budget_exhausted',
            'operator_disabled'
        )
    ),
    disabled_since timestamp with time zone,
    last_delivered_position bigint,
    last_failure jsonb,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (owner_user_id, name)
);

CREATE INDEX idx_subscriptions_owner ON public.subscriptions(owner_user_id);
CREATE INDEX idx_subscriptions_active ON public.subscriptions(state) WHERE state = 'active';
