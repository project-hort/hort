-- 042 — retention_policy_projections.held_states
--
-- The held-state opt-in: which quarantine states a retention policy may
-- expire an artifact out of. `[]` is "none", and that is the value every
-- existing policy has — the column changes no decision until an operator
-- writes `heldStates` into a policy's YAML.
--
-- Additive (expand): no existing code names this column, and the
-- serving binaries of the previous release never read it, so this
-- migration is safe to run while they are still up. It registers no
-- CONTRACTIONS.toml entry because it removes and narrows nothing.
--
-- `jsonb` with a `'[]'` default, matching the two columns beside it
-- (`predicate`, `scope`): the value is the serde form of
-- `BTreeSet<hort_domain::retention::HeldState>`, a JSON array of state
-- names (`["Rejected","ScanIndeterminate"]`). NOT NULL so a reader never
-- has to decide what a NULL opt-in means — absent and empty are one
-- state, and it is the restrictive one.
--
-- Not indexed. The only reader is `list_active()` / `list_active_rows()`,
-- which the evaluate sweep calls once per tick over the whole (small)
-- table; there is no lookup by opt-in.

ALTER TABLE public.retention_policy_projections
    ADD COLUMN IF NOT EXISTS held_states jsonb DEFAULT '[]'::jsonb NOT NULL;

COMMENT ON COLUMN public.retention_policy_projections.held_states IS
    'Held quarantine states this policy may expire an artifact out of '
    '(serde of BTreeSet<HeldState>; [] = none, the default). A non-empty '
    'value requires a predicate whose every successful branch carries a '
    'positive AgeExceeds, enforced at gitops apply and at event replay.';
