# 056 — #88: read_expected_version capped-read audit + safe version derivation

**Issue:** #88 (spec approved on the issue). Context: #87 (the production instance of the bug),
!260 (the token-path fix establishing the Any+bounded-retry pattern).
**Read first:** `crates/hort-app/src/use_cases/mod.rs::read_expected_version` +
`STREAM_EVENT_CAP` (~190-220); `crates/hort-adapters-postgres/src/event_store.rs::append_with_conn`
(true-tail validation, ~985-1005); the !260 diff in `api_token_use_case.rs`
(`append_any_with_conflict_retry` — the fix pattern); every remaining
`read_expected_version(` caller (grep; ~26 sites across curation, promotion, quarantine,
provenance, ingest, policy, subscription use cases).

## Defect (settled on #87/#88)

`read_expected_version` reads `read_stream(id, ReadFrom::Start, STREAM_EVENT_CAP + 1)`
(201 events) and takes `.last().stream_position` as the current version. For any stream
with >201 events this returns a stale 201 while the adapter validates `Exact` against the
true tail → every versioned append fails `Conflict`, deterministically and permanently.
Token paths (user streams) were fixed by !260; the same latent bug exists for any OTHER
caller doing an `Exact` append on an unbounded stream.

## Work

1. **Audit table** (deliverable on the issue + in the report): caller → target stream →
   bounded-by-design? → verdict. Artifact-lifecycle streams are bounded and the cap is
   their intended abuse guard — document those as fine.
2. **Fix every unbounded-stream CAS caller**: if the append protects no decision made from
   read stream state → `ExpectedVersion::Any` + `append_any_with_conflict_retry` (the !260
   pattern; consider promoting that helper out of api_token_use_case.rs if a second file
   needs it — 3+ dup rule counts !258's local loop in task_use_case.rs too). If the CAS
   genuinely guards a read-fold decision → replace the capped read with a correct tail
   read (new `EventStore` port method e.g. `stream_version(stream_id)` implemented as a
   tail query, or ReadFrom::End) — do NOT silently widen the cap.
3. **Structural guard**: make the capped-read-as-version-source unrepresentable — e.g.
   `read_expected_version` keeps the cap ONLY behind the artifact-guard flag and derives
   the version from a true tail read; or split into `artifact_stream_guarded_version()`
   vs `stream_version()`. A DB-free structural test pinning the choice is welcome
   (runs via cargo test --workspace automatically).

## Scope / acceptance

- Audit table complete (every caller has a verdict, none skipped).
- All unbounded-stream `Exact` appends fixed per above; hort-app 100% coverage on changed
  paths; any DB-backed test carries #[serial(hort_pg_db)].
- The structural guard exists and fails if a future caller derives a version from a capped read.
- Gate: fmt, clippy -D warnings, cargo test --workspace.

**Model hint:** capable (event-store discipline, cross-cutting audit).
