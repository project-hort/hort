# 365 — The valid trigger-source set, spoken once

**Issue:** #402 · **Branch:** `agent/402-trigger-source-single-source` · single item.

Pulled forward from #331 on the maintainer's decision (2026-11-02). Found as a
side observation by the #399 unit-363 run, which reported it rather than
touching it; the chain below was then read link by link.

## The reachable consequence

**The OCI cross-repository blob mount answers `500` whenever the gate requests
a scan for the mounted blob.**

That is `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` — the spec
optimization "link the blob instead of re-uploading it". Both query parameters
are mandatory (`hort-http-oci/src/uploads.rs:211`, `:228`), so an ordinary push
into one repository never reaches this path. It fires on `skopeo copy` between
repositories of the same registry, on cross-repository re-tagging, and on a
push whose layers the client locates elsewhere.

The spec expects `201` (mounted) or `202` (fall back to a normal upload).
`500` is neither, so the client cannot cleanly degrade.

## The chain, verified on `develop` `8ada0a69`

1. `hort-http-oci/src/uploads.rs` builds `IngestRequest { … quarantine_anchor_override: None … }`
   and calls `register_by_hash`.
2. `register_by_hash_inner` (`hort-app/src/use_cases/ingest_use_case.rs:4979-4983`)
   stamps `trigger_source = "register-by-hash"` when there is no anchor override.
3. `enqueue_scan_in_tx` (`hort-adapters-postgres/src/jobs_repository.rs:48-62`)
   binds that value **verbatim** into `INSERT INTO public.jobs (… trigger_source …)`.
4. The CHECK from migration 009 (`009_scan_jobs_and_findings.sql:118`) admits
   **eight** literals: `manual, cron, advisory, ingest, seed-import, prefetch,
   self_service, scheduled`. `register-by-hash` is not among them —
   `grep -rn register-by-hash migrations/` finds nothing.
5. The call is `.await?` inside the unit of work
   (`hort-adapters-postgres/src/artifact_lifecycle.rs:291-301`), so a CHECK
   violation aborts the transaction.
6. `map_register_error` (`uploads.rs`) routes everything that is not `NotFound`
   or `Conflict` into a catch-all `OciError::Internal` → `500`.

**Why it survived:** the row is only enqueued when the gate requests a scan.
With no `scan_backends` configured the mount works — the path functions
precisely where nothing is scanned.

## The cause: one set, spoken three times, no two agreeing

| Where | Set |
|---|---|
| SQL CHECK (`009_scan_jobs_and_findings.sql:118`) | 8 literals |
| `hort_domain::ports::jobs_repository::TriggerSource` | **4** — and its doc claims it mirrors the CHECK |
| The writers | produce `register-by-hash` among others, which is in neither |

This is the class the project otherwise single-sources behind a guard
(`https_rule_is_single_sourced` is the model).

## The second reachable consequence

`TriggerSource::FromStr` rejects the four literals it does not know.
`kind='scan'` rows **are** written with `trigger_source='seed-import'`, and
**both** scan-row mappers parse through `FromStr` and turn a miss into
`DomainError::Invariant`: `hort-adapters-postgres/src/jobs_repository.rs:657`
(`claim_scan_jobs`' row mapper) and `hort-app/src/task_handlers/scan.rs:148`
(the dispatcher's `ScanJob` reconstruction). A seed-imported artifact therefore
looks as though its first scan cannot be claimed.

**Neither consequence has been run against a database.** Both are read from
source and schema. The proof is the first step of the work, not the last.

## The delivery route is precedented — do not improvise

**Do not edit migration 009 in place.** Once a database exists that cannot be
wiped, the changed checksum makes `sqlx::migrate!` reject that database.

**A redefining `ALTER` in a new migration is the documented mechanism**, and
the `no_sensitive_drops` guard exempts exactly this shape: a
`DROP CONSTRAINT <name>_check` immediately followed by an `ADD CONSTRAINT` of
the **same** `_check` name on the **same** table is an enum-CHECK widening
(`crates/hort-app/tests/no_sensitive_drops.rs:40-60`).
`018_jobs_kind_oci_edge_backfill.sql` runs that exact shape on
`jobs_kind_check`; migration 009 declares this CHECK inline, so PostgreSQL
names it `jobs_trigger_source_check`.

This is not destructive DDL under ADR 0030 and does not touch the
expand/contract arithmetic: the value set is **widened**, nothing loses its
cover.

## Acceptance

1. **Proof before change.** A DB-backed test showing today's failure: two
   repositories, a blob in one, a gate that requests a scan, then the mount. It
   must be **red before** the fix, and the report quotes the error. Carries
   `#[serial(hort_pg_db)]` like every DB-backed test in the workspace.
2. The same for the second consequence: a `kind='scan'` row with
   `trigger_source='seed-import'`, read through `claim_scan_jobs`.
3. **The valid set is spoken once.** Afterwards exactly one definition exists,
   from which both the CHECK and the domain type follow or against which both
   are checked — plus a guard in the family of the existing structural scans
   that makes a divergence red. The guard carries a counter-assertion: it
   demonstrably fails when a literal is added in only one place.
4. **The writers are censused and reported untruncated**, and every value they
   produce is in the set afterwards. The census also names the **consumers**
   that match on a literal — `ingest_use_case.rs:15155` matches
   `"register-by-hash"` — because a literal with a consumer gets admitted, not
   renamed.
5. The widening ships as a **new** migration in migration 018's shape.
   Migration 009 is untouched.
6. After the fix the mount answers `201` even when a scan is enqueued.
7. **No error handling is loosened** to hide the `500`: `map_register_error`'s
   catch-all stays; it simply has nothing left to catch.

## Not in this unit

- What the scan read paths should do with the other three unknown literals if
  single-sourcing turns them from `Invariant` errors into successes. If that is
  a behaviour change beyond the mount, **report it** rather than taking it.
- ADR changes. If single-sourcing touches a standing decision, that is its own
  conversation.
