-- Migration 014 — service_accounts is identity-only.
--
-- A `service_accounts` row is the identity + federation binding for a
-- non-human principal: `name`, `backing_user_id`, and the sub-aggregate
-- tables (`service_account_federated_identities`,
-- `service_account_fallback_rotations`). It carries no authority.
-- Authority lives exclusively in explicit `permission_grants` rows
-- targeting the backing user (`GrantSubject::User(backing_user_id)`,
-- ADR 0037); the issued-token cap snapshots those grants at issuance.
--
-- Domain type:
--   crates/hort-domain/src/entities/service_account.rs (`ServiceAccount`)
-- Adapter:
--   crates/hort-adapters-postgres/src/service_account_repo.rs

ALTER TABLE public.service_accounts DROP COLUMN role;
ALTER TABLE public.service_accounts DROP COLUMN repositories;
