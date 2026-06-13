-- Squashed baseline — curation rules.
--
-- Replaces prototype migration 071_curation.sql (initial) plus the
-- gitops managed_by columns added later. Curation rules (allow / warn
-- / block patterns per format) are evaluated by the curation engine
-- in `crates/hort-app/src/use_cases/curation*` during ingest.
--
-- Tables:
--   curation_rules            — rule library. `format` NULL means the
--                                rule applies to every format.
--                                `package_pattern` is a glob; matching
--                                lives in the curation engine, not SQL.
--   repository_curation_rules — repo↔rule junction. Per-repository
--                                opt-in to a rule from the library.

-- ---------------------------------------------------------------------------
-- curation_rules
-- ---------------------------------------------------------------------------

CREATE TABLE public.curation_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    format text,
    package_pattern text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL,
    managed_by text DEFAULT 'local'::text NOT NULL,
    managed_by_digest bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_curation_rules_managed_digest CHECK (
        (((managed_by = 'gitops'::text) AND (managed_by_digest IS NOT NULL))
         OR ((managed_by = 'local'::text) AND (managed_by_digest IS NULL)))
    ),
    CONSTRAINT curation_rules_action_check CHECK (
        (action = ANY (ARRAY['block'::text, 'warn'::text, 'allow'::text]))
    ),
    CONSTRAINT curation_rules_managed_by_check CHECK (
        (managed_by = ANY (ARRAY['local'::text, 'gitops'::text]))
    )
);

ALTER TABLE ONLY public.curation_rules
    ADD CONSTRAINT curation_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.curation_rules
    ADD CONSTRAINT curation_rules_name_key UNIQUE (name);

CREATE INDEX idx_curation_rules_format
    ON public.curation_rules USING btree (format)
    WHERE (format IS NOT NULL);

CREATE INDEX idx_curation_rules_managed_by
    ON public.curation_rules USING btree (managed_by)
    WHERE (managed_by = 'gitops'::text);

-- ---------------------------------------------------------------------------
-- repository_curation_rules
-- ---------------------------------------------------------------------------

CREATE TABLE public.repository_curation_rules (
    repository_id uuid NOT NULL,
    curation_rule_id uuid NOT NULL
);

ALTER TABLE ONLY public.repository_curation_rules
    ADD CONSTRAINT repository_curation_rules_pkey PRIMARY KEY (repository_id, curation_rule_id);

ALTER TABLE ONLY public.repository_curation_rules
    ADD CONSTRAINT repository_curation_rules_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.repository_curation_rules
    ADD CONSTRAINT repository_curation_rules_curation_rule_id_fkey
    FOREIGN KEY (curation_rule_id) REFERENCES public.curation_rules(id) ON DELETE CASCADE;

CREATE INDEX idx_repository_curation_rules_rule
    ON public.repository_curation_rules USING btree (curation_rule_id);
