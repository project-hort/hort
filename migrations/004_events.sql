-- Squashed baseline — event store (ADR 0002 + ADR 0004) + role hardening
-- (ADR 0009) + tamper-evident event chain (ADR 0002).
--
-- The events-role REVOKE lives inside this file directly after
-- the table + trigger so the audit invariant is grouped with the table
-- that carries it.
--
-- Tamper-evident chain (ADR 0002) — edit-in-place: the `git tag
-- --contains` GA-flip guard was run and the commit that introduced/last-
-- restructured this file (872f5b44 / b7b81651) is contained ONLY by
-- pre-release tags — no GA (non-`-rc`) tag — so the edit-in-place path
-- applies (ADR 0022; a GA tag would have required a forward ALTER
-- migration instead). The tamper-evident chain is the same class of
-- audit invariant as the trigger + REVOKE and is co-located here by the
-- same principle (immutability + integrity story in one file).
--
-- Backfill note: the nullable→backfill→SET NOT NULL recipe is the
-- *forward-ALTER-on-a-populated-table* pattern. This is the
-- edit-in-place path: the columns are part of the
-- `CREATE TABLE events` body, so the table is born with them and has
-- zero pre-existing rows to backfill (a freshly-created table is
-- empty). The columns are therefore `NOT NULL` directly, with no
-- nullable window. The per-event hash value is `SHA-256(
-- canonical_event_bytes(typed DomainEvent))` — computed in Rust on the
-- append path (hort-adapters-postgres event_store), never in SQL,
-- because the canonical form is a typed-`DomainEvent` serialization that
-- pure SQL cannot reproduce. No row is inserted without the
-- Rust-computed hash, so the `NOT NULL` + `CHECK` always hold from the
-- first INSERT forward.
--
-- Tables:
--   events — append-only domain event log. UPDATE blocked for every
--            role at two layers: (1) the events_immutable trigger;
--            (2) the hort_app_role privilege strip (defense in depth).
--            DELETE is the sanctioned whole-stream retention path
--            (ADR 0020): permitted ONLY for the dedicated
--            hort_retention_role (ADR 0009) and refused for every
--            other role at BOTH layers. The trigger is amended for that
--            role exemption but stays ENABLED at all times — app code
--            never `DISABLE TRIGGER`s it. Per-stream tamper-evident hash
--            chain via prev_event_hash/event_hash (ADR 0002; the
--            cryptographic primitive, with trigger+REVOKE demoted to
--            defense-in-depth).

-- ---------------------------------------------------------------------------
-- Immutability function
-- ---------------------------------------------------------------------------
--
-- This function blocks **UPDATE for every role** (ADR 0002: the audit
-- log is append-only; no role may rewrite a persisted event) and blocks
-- **DELETE for every role EXCEPT `hort_retention_role`** (ADR 0009 /
-- ADR 0020). The trigger stays ENABLED at all times and is NEVER
-- disabled by application code (`ALTER TABLE … DISABLE TRIGGER` is the
-- exact attack vector ADR 0002 names). Sanctioned whole-stream retention
-- removal goes through a dedicated, DELETE-capable `hort_retention_role`
-- (created below) whose DELETE the still-active trigger lets through
-- because `current_user = 'hort_retention_role'`. Under any other role
-- (notably the runtime `hort_app_role`) the trigger raises and the seal
-- transaction rolls back fail-safe — zero rows removed, no orphan
-- `StreamSealed` tombstone. UPDATE is exempted for NO role.

CREATE FUNCTION public.prevent_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- UPDATE is forbidden for every role, no exceptions: a persisted
    -- event is never rewritten.
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'events table is append-only: % not allowed', TG_OP;
    END IF;
    -- DELETE is the sanctioned whole-stream retention path (ADR 0020)
    -- and is permitted ONLY for the dedicated hort_retention_role. Every
    -- other role (including hort_app_role and a bare default role) is
    -- refused here — defense in depth on top of the table-privilege
    -- REVOKE below.
    IF TG_OP = 'DELETE' AND current_user <> 'hort_retention_role' THEN
        RAISE EXCEPTION 'events table is append-only: % not allowed', TG_OP;
    END IF;
    -- Reached only for a DELETE under hort_retention_role: allow the row
    -- removal to proceed (BEFORE-trigger returns the old row).
    RETURN OLD;
END;
$$;

-- ---------------------------------------------------------------------------
-- events
-- ---------------------------------------------------------------------------

CREATE SEQUENCE public.events_global_position_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE public.events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    stream_id text NOT NULL,                                       -- "artifact-{uuid}" / "policy-{uuid}"
    stream_category text NOT NULL,                                 -- "artifact" / "policy"
    stream_position bigint NOT NULL,                               -- 0-based, per-stream
    global_position bigint DEFAULT nextval('public.events_global_position_seq'::regclass) NOT NULL,
    event_type text NOT NULL,                                      -- "ArtifactIngested", etc.
    event_version integer DEFAULT 1 NOT NULL,
    event_data jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,                                             -- event_id of the causing event
    actor_type text NOT NULL,
    actor_id uuid,                                                 -- non-null when actor_type='api'
    -- Gitops-actor metadata. Stored as separate columns rather than a
    -- JSON blob so audit queries that group by source-of-truth file or
    -- look up "what files touched this stream" stay cheap.
    actor_source_file text,                                        -- path under $HORT_CONFIG_DIR
    actor_spec_digest bytea,                                       -- SHA-256 of canonicalised spec
    stored_at timestamp with time zone DEFAULT now() NOT NULL,
    -- Per-stream tamper-evident hash chain (ADR 0002).
    -- prev_event_hash = predecessor event's event_hash, or the genesis
    -- sentinel SHA-256('hort-event-chain/v1/genesis') for stream_position
    -- 0 (NOT the zero array). event_hash =
    -- SHA-256(canonical_event_bytes(typed DomainEvent)), computed in Rust
    -- on the append path. Both are 32 raw bytes and NOT NULL: the adapter
    -- binds them on every INSERT, and this is a table-defining migration
    -- so there are no pre-existing rows (edit-in-place path — see the
    -- header backfill note).
    prev_event_hash bytea NOT NULL,
    event_hash bytea NOT NULL,
    -- 64 KB max payload (ADR 0002)
    CONSTRAINT events_event_data_check CHECK (
        (pg_column_size(event_data) <= 65536)
    ),
    -- Cheap structural guard that both chain hashes are exactly 32 bytes
    -- (SHA-256 width) — defense-in-depth (ADR 0002). NOT a substitute
    -- for the offline cryptographic verifier; the verifier recomputes
    -- and compares the actual hash.
    CONSTRAINT events_chain_hash_width_check CHECK (
        (octet_length(prev_event_hash) = 32 AND octet_length(event_hash) = 32)
    ),
    -- Per-actor-kind shape:
    --   api    => actor_id NOT NULL, source_file/spec_digest NULL
    --   system|timer|retention_scheduler => everything NULL except actor_type
    --   gitops => actor_id NULL, source_file/spec_digest NOT NULL
    -- 'retention_scheduler' (the retention task-handler actor) joins the
    -- no-actor-id internal-actor group (ADR 0020), added in place per
    -- the pre-release squashed-baseline policy (ADR 0022).
    CONSTRAINT chk_actor_id CHECK (
        ((actor_type = 'api'::text)
         AND (actor_id IS NOT NULL)
         AND (actor_source_file IS NULL)
         AND (actor_spec_digest IS NULL))
        OR ((actor_type = ANY (ARRAY['system'::text, 'timer'::text, 'retention_scheduler'::text]))
            AND (actor_id IS NULL)
            AND (actor_source_file IS NULL)
            AND (actor_spec_digest IS NULL))
        OR ((actor_type = 'gitops'::text)
            AND (actor_id IS NULL)
            AND (actor_source_file IS NOT NULL)
            AND (actor_spec_digest IS NOT NULL))
    ),
    CONSTRAINT events_actor_type_check CHECK (
        (actor_type = ANY (ARRAY['api'::text, 'system'::text, 'timer'::text, 'gitops'::text, 'retention_scheduler'::text]))
    )
);

ALTER SEQUENCE public.events_global_position_seq OWNED BY public.events.global_position;

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_global_position_key UNIQUE (global_position);

-- Optimistic concurrency: each (stream_id, stream_position) is unique.
CREATE UNIQUE INDEX idx_events_stream_position
    ON public.events USING btree (stream_id, stream_position);

-- Category reads (projections that consume all events of a category).
CREATE INDEX idx_events_category_global
    ON public.events USING btree (stream_category, global_position);

-- Correlation lookups (tracing a full operation across streams).
CREATE INDEX idx_events_correlation
    ON public.events USING btree (correlation_id);

-- Causation lookups (tracing event chains).
CREATE INDEX idx_events_causation
    ON public.events USING btree (causation_id)
    WHERE (causation_id IS NOT NULL);

CREATE TRIGGER events_immutable
    BEFORE DELETE OR UPDATE ON public.events
    FOR EACH ROW EXECUTE FUNCTION public.prevent_event_mutation();

-- ---------------------------------------------------------------------------
-- Role hardening (ADR 0009)
-- ---------------------------------------------------------------------------
-- Two-role split closes the audit invariant gap (ADR 0002): a compromised
-- application role MUST NOT be able to `DROP TRIGGER events_immutable`,
-- `TRUNCATE events`, `DELETE FROM events`, or `UPDATE events`. The trigger
-- alone is necessary but not sufficient — only ownership of the
-- table/function blocks the DROP.
--
-- Roles:
--   hort_admin     — owns the events table, the prevent_event_mutation()
--                  function, and the events_immutable trigger. NOLOGIN —
--                  only the migration role; the runtime never connects
--                  as hort_admin.
--   hort_app_role  — INSERT, SELECT only on events. Explicitly stripped
--                  of UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER.
--                  The runtime user is granted membership in this role.
--   hort_retention_role — SELECT, DELETE on events (NO UPDATE/TRUNCATE).
--                  NOLOGIN (ADR 0009 + ADR 0020): the dedicated,
--                  DELETE-capable role the sanctioned whole-stream
--                  retention sweep connects as. Distinct from the DML
--                  hort_app_role — same least-privilege split philosophy.
--                  The amended-but-always-ENABLED events_immutable trigger
--                  lets THIS role's DELETE through (current_user check)
--                  and no other's; the trigger is never disabled by app
--                  code. **DSN/pool composition (wiring a connection that
--                  authenticates as a member of hort_retention_role into
--                  the worker) is the retention-scheduler's wiring concern
--                  — this migration only delivers the role +
--                  trigger-function exemption + the adapter removal path
--                  keyed to it. Until that wiring is active, the seal runs
--                  under hort_app_role and fails fail-safe (the trigger
--                  blocks the DELETE, the transaction rolls back, zero rows
--                  removed) — which is correct.**
--
-- Re-runnability: every statement is idempotent.
--   - CREATE ROLE wrapped in DO blocks (PG has no CREATE ROLE IF NOT EXISTS).
--   - ALTER ... OWNER TO is a no-op when the target is already the owner.
--   - REVOKE is silent when the privilege was not held.
--   - GRANT is silent when the privilege was already held.
--
-- Defense in depth: `hort-server migrate` re-runs `harden_events_role`
-- after every migrate to re-assert the REVOKE in case an out-of-band
-- bulk grant re-granted UPDATE/DELETE on events. See
-- crates/hort-server/src/migrate.rs::harden_events_role.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'hort_admin') THEN
        CREATE ROLE hort_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'hort_app_role') THEN
        CREATE ROLE hort_app_role NOLOGIN;
    END IF;
    -- The dedicated retention-sweep role (ADR 0020). NOLOGIN — operators
    -- GRANT it to the worker's runtime user; it is never logged into
    -- directly.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'hort_retention_role') THEN
        CREATE ROLE hort_retention_role NOLOGIN;
    END IF;
END
$$;

-- Grant the migrating role membership in hort_app_role so the dev/test
-- single-role bootstrap inherits the constrained permission set rather
-- than the bootstrap superuser's full access. In production deployments
-- where the runtime connects as a third user, the operator GRANTs
-- hort_app_role explicitly to that runtime user.
DO $$
BEGIN
    EXECUTE format('GRANT hort_app_role TO %I', current_user);
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'could not grant hort_app_role to current_user (insufficient privilege); operator must GRANT hort_app_role TO <runtime_user> manually';
END
$$;

-- Transfer ownership of the events table, sequence, and immutability
-- function to hort_admin. After this the application role cannot
-- DROP TRIGGER, ALTER TABLE, or otherwise disable the audit invariant.
ALTER TABLE public.events                        OWNER TO hort_admin;
ALTER SEQUENCE public.events_global_position_seq OWNER TO hort_admin;
ALTER FUNCTION public.prevent_event_mutation()   OWNER TO hort_admin;

-- Strip PUBLIC and the application role of every mutation privilege.
REVOKE ALL ON public.events FROM PUBLIC;
REVOKE ALL ON public.events FROM hort_app_role;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.events FROM hort_app_role;

-- Re-grant the minimal allowed surface: append (INSERT) and read (SELECT).
GRANT INSERT, SELECT ON public.events TO hort_app_role;
-- INSERT uses RETURNING global_position, which reads the sequence;
-- without USAGE, INSERT itself fails.
GRANT USAGE, SELECT ON SEQUENCE public.events_global_position_seq TO hort_app_role;

-- Sanctioned whole-stream retention path (ADR 0020). hort_retention_role
-- gets SELECT (it must
-- read each sealed stream's chain head to build the StreamSealed
-- tombstone) and DELETE — and nothing else: NO UPDATE (the audit log
-- stays append-only; the still-ENABLED trigger ALSO blocks UPDATE for
-- this role), NO TRUNCATE, NO REFERENCES/TRIGGER. The trigger function
-- above lets THIS role's DELETE through via the current_user check;
-- every other role's DELETE is refused at BOTH the privilege wall
-- (REVOKE'd from hort_app_role / PUBLIC) and the trigger.
-- `harden_events_role` (crates/hort-server/src/migrate.rs) only
-- re-REVOKEs from hort_app_role, so it does NOT strip this grant.
REVOKE ALL ON public.events FROM hort_retention_role;
GRANT SELECT, DELETE ON public.events TO hort_retention_role;
