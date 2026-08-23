# 103 — Remove the inert `artifacts.is_deleted` column

**Issue:** #93 · **Branch:** `agent/93-remove-is-deleted` · **Scope:** `migrations/018_*.sql`, `crates/hort-domain`, `crates/hort-adapters-postgres`, `crates/hort-app`, `crates/hort-http-{cargo,npm,pypi}`

## Why

`artifacts.is_deleted` is never written in production. Deletion is a hard
`DELETE FROM artifacts WHERE id = $1` (`artifact_repo.rs:202-219`), reached from
the OCI manifest `DELETE` route via `ArtifactUseCase::delete`. The only
`UPDATE artifacts SET is_deleted = true` statements in the workspace live in
`artifact_repo.rs`'s own `#[cfg(test)]` module.

So every `is_deleted = false` / `NOT is_deleted` predicate in the read path is a
no-op, and both partial indexes predicated on it cover the whole table. The
column reads as a working soft-delete mechanism to anyone opening the file. It
is not one — and the single read where it would actually matter for ingest,
`find_by_path` (`artifact_repo.rs:221-240`), is the one that omits the filter.

An inert surface that looks protective is the hazard. Removing the column makes
`find_by_path`'s consistency true by construction rather than by convention.

The event-sourced half of this question — deletion emits no domain event at all
— is **out of scope here** and tracked as its own issue. Do not add an event in
this item.

## The trap to avoid

Do **not** "fix" this by filtering `is_deleted` in `find_by_path` and expecting a
post-delete re-push to mint a fresh artifact. `migrations/003_artifacts_cas.sql:105`
declares `UNIQUE (repository_id, path)`: a soft-deleted row keeps occupying its
path, so hiding it from the lookup drives the ingest insert into a constraint
violation. That is why the column goes rather than the filter arriving.

## Change

1. **Migration `018`** — verify the number is still free (`ls migrations/ | tail -5`;
   `017_scan_policy_scope_unique.sql` is current).
   - `ALTER TABLE public.artifacts DROP COLUMN is_deleted;`
   - **Recreate both partial indexes without the predicate.** Postgres drops any
     index that references a dropped column, so this is mandatory, not cleanup:
     - `idx_artifacts_name_as_published` — `btree (repository_id, name_as_published)`
     - `idx_artifacts_repo_name_status_covering` — `btree (repository_id, name)
       INCLUDE (version, quarantine_status)`

     The second is the covering index behind the highest-QPS servability read
     (`ArtifactRepository::package_version_status`, fired dozens to hundreds of
     times per client `install`). Losing it would be a silent serve-path
     regression, so keep the key columns and the `INCLUDE` payload identical and
     only drop the `WHERE` clause. Their original definitions are at
     `migrations/003_artifacts_cas.sql:118-120` and `:153-155`; the surrounding
     comments explain the index-only-scan intent and need updating, since they
     currently justify the predicate by "the (in steady state, large)
     soft-deleted tail" — a tail that has never existed.

2. **Domain** — drop the field from `Artifact`
   (`crates/hort-domain/src/entities/artifact.rs:177`). Update the port
   doc-comments that describe the filter as part of the read contract:
   `ports/artifact_repository.rs` (four sites) and
   `ports/quarantine_release_candidates.rs` (two).

3. **Adapters** — remove the column from `SELECT_COLS`, the insert/upsert column
   lists and the `ArtifactRow` mapper (`mappers.rs:272, 318`), and drop the
   predicate from every read in `artifact_repo.rs`, `rescan_candidates.rs`,
   `curation_queue_repository.rs`, `patch_candidate_repo.rs`,
   `retention_candidate_reader.rs`, `quarantine_release_candidates.rs`.

4. **Fixtures** — remove the `is_deleted: false` struct literals across
   `hort-app`, `hort-http-cargo`, `hort-http-npm`, `hort-http-pypi`,
   `hort-domain` and the adapter tests.

5. **Tests that assert soft-delete behaviour must go, not be patched.** The
   adapter test
   `package_version_status_returns_repo_scoped_pairs_excluding_deleted_and_null_version`
   seeds a soft-deleted row and asserts its exclusion. With the column gone that
   arm asserts nothing — drop the soft-deleted fixture and the arm, keep the
   null-version and repo/name boundary arms, and rename the test to match what
   it still covers.

## Verification

- `cargo test --workspace` green (includes the DB-free structural guards).
- Every DB-touching adapter test still carries `#[serial(hort_pg_db)]` — a
  DB-gated test without it is a blocking review finding (`CLAUDE.md`).
- Confirm the migration applies against a live DB and both indexes exist
  afterwards with the expected shape (`\d+ artifacts`), not merely that the
  column is gone.
- `grep -rn is_deleted --include='*.rs' crates/` returns nothing; the only
  surviving references are in `migrations/003_*.sql` (history) and `018`.

## Notes

Roughly 113 references, most mechanical: 62 in `hort-adapters-postgres`, 30 in
`hort-app`, 16 in `hort-domain`, 5 across the format crates. The judgement calls
are the index recreation and the test rewrite; the rest is deletion.
