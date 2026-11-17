-- Migration 043 — `destroy_content` / `destroy_record` permissions.
--
-- Adds the two destructive-task authorities to `permission_type`. Both
-- are global permissions — admin-task invocation is a global capability,
-- always checked with `repository = None`, mirroring
-- `admin`/`admin_task_invoke`/`read_metrics`.
--
-- They are two and not one because they are split by *what* is
-- destroyed: `destroy_content` gates `retention-purge` and
-- `retention-evaluate` in execute mode, whose removal of artifact
-- content leaves a record behind by design (`ArtifactPurged` stays on
-- the stream); `destroy_record` gates `eventstore-archive`, which
-- removes the record itself — authentication audit, download audit,
-- token use — and nothing reconstructs that. An identity trusted to
-- reclaim storage is therefore not thereby trusted to cut audit history.
--
-- Domain type:
--   crates/hort-domain/src/entities/rbac.rs
--   (`Permission::DestroyContent` / `Permission::DestroyRecord`)
--
-- Both are in `ADMIN_ORTHOGONAL_PERMISSIONS`: the `admin` claim does not
-- imply either, so an invocation needs an explicit `permission_grants`
-- row whichever identity makes it.
--
-- `ALTER TYPE ... ADD VALUE` cannot be used in the same transaction as a
-- statement that reads the new value, so this migration is standalone —
-- no same-file INSERT/grant provisioning that would consume it.

ALTER TYPE public.permission_type ADD VALUE IF NOT EXISTS 'destroy_content';
ALTER TYPE public.permission_type ADD VALUE IF NOT EXISTS 'destroy_record';
