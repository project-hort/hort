-- Per-upstream negative-cache TTL for a `404` from this upstream, in
-- seconds.
--
-- Absence is a property of the upstream, not of the deployment. A
-- release upstream never gains a coordinate it refused — an immutable
-- release that is absent today is absent tomorrow — so a long TTL
-- costs nothing there. A snapshot upstream gains coordinates
-- constantly, and the same long TTL answers `404` for a snapshot that
-- has since been published. One deployment-wide number cannot be right
-- for both, and a virtual repository routinely mixes them. This column
-- is how the operator states the upstream's own behaviour.
--
-- Expansion only: a new nullable column with no backfill. `NULL` — the
-- default for every existing row and every mapping that omits the
-- field — means the deployment-wide
-- `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS`, so an absent value reproduces
-- today's behaviour exactly.

ALTER TABLE public.repository_upstream_mappings
    ADD COLUMN not_found_cache_seconds integer;

-- Mirrors `not_found_cache_seconds_reason` in
-- `crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs`
-- (the one definition the value-object constructor and the gitops
-- validator both call): a present value is a positive number of
-- seconds. Zero is refused because a zero TTL would re-fetch on every
-- retry within the negative-cache window, defeating the coalescing
-- benefit on 404 storms — the same reason
-- `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS` refuses it. Restated here so a
-- row inserted by raw SQL cannot escape the guard; the upper bound the
-- domain also enforces is this column's own type, so it needs no
-- clause.
ALTER TABLE public.repository_upstream_mappings
    ADD CONSTRAINT chk_repository_upstream_mappings_not_found_cache_seconds CHECK (
        not_found_cache_seconds IS NULL OR not_found_cache_seconds > 0
    );
