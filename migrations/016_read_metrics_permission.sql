-- Migration 016 — `read_metrics` permission (issue #113).
--
-- Adds the `read_metrics` value to `permission_type`, gating the
-- Prometheus scrape endpoint (`GET /metrics`). Global permission — always
-- checked with `repository = None`, mirroring `admin`/`admin_task_invoke`.
--
-- Domain type:
--   crates/hort-domain/src/entities/rbac.rs (`Permission::ReadMetrics`)
--
-- `ALTER TYPE ... ADD VALUE` cannot be used in the same transaction as a
-- statement that reads the new value, so this migration is standalone —
-- no same-file INSERT/grant provisioning that would consume it.

ALTER TYPE public.permission_type ADD VALUE IF NOT EXISTS 'read_metrics';
