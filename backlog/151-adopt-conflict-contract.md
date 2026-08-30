# 151 — adopt the append-conflict contract at group attach + ref set

**Issue:** #221 · **Branch:** `agent/221-append-conflict-contract` · Item 2 of 2 (needs item 150 merged into the branch).

## Problem

The two contract-violating sites (both journal-evidenced on the
v0.12.2-beta.1 mirror failure):

1. `ArtifactGroupUseCase::add_member` — a concurrent *different-member*
   append to the same `artifact_group` stream surfaces `Domain(Conflict)`;
   the OCI manifest PUT maps it to 500 (`stage=group_attach_layer`), the
   generic ingest hook (Maven GAV groups) swallows it to a warn and loses
   the membership link silently until an operator reconcile sweep.
2. `RefUseCase::set` — any error including a ref-stream append conflict
   maps to 500 at the OCI edge (`stage=ref_set`); concurrent same-tag PUTs
   (mirror re-runs, client retries) can hit it.

## Task

1. **`add_member` adopts the item-150 primitive**: on Conflict → re-read the
   group (`find_by_coords`/`find_by_member`), if the member is already
   present with the same role → idempotent success; otherwise rebuild the
   batch against the refreshed group version and re-append; bounded.
   Exhaustion → the retryable-busy error. The existing *sanctioned*
   non-retries stay exactly as they are: the primary-role race still
   surfaces `Conflict` to the caller (ADR 0060 exception), and the
   GroupAlreadyExists single-retry (create race) keeps its current shape.
2. **`RefUseCase::set` adopts the primitive**: on Conflict → re-read the
   ref; same target already set → idempotent success; different target →
   rebuild against refreshed version and re-append (last-writer-wins is the
   established ref semantic — setting a tag is an overwrite operation);
   bounded; exhaustion → retryable-busy.
3. **OCI edge mapping**: the two `stage=group_attach_*` / `stage=ref_set`
   500 returns become the 503 + `Retry-After` contention response on the
   retryable-busy error (reuse the `manifest_write_contention` vocabulary);
   the site comments change from "genuine error" to stating the contract
   (same-member replay = idempotent non-error; different-member conflict =
   retried; exhaustion = busy).
4. **Ingest hook (Maven path)**: no structural change — with the retry
   inside `add_member` the hook's warn becomes the crash-window backstop it
   was designed to be (reconcile sweep unchanged). Update its comment to
   say exactly that.

## Tests

- **Real-Postgres concurrency test** (`#[serial(hort_pg_db)]`, !443 class):
  race N parallel `add_member` calls for distinct members of one group —
  assert zero Conflict escapes, all members present, group stream
  version-consistent. Race two `RefUseCase::set` for the same ref — assert
  no error and a deterministic final target.
- **HTTP-edge test** (mock ctx): exhausted contention on group attach and
  ref set yields 503 + `Retry-After`, never 500.
- Unit tests for the idempotent-equal paths (member-present recheck,
  ref-same-target recheck).

## Acceptance

- The journal-evidenced failure shape (concurrent attestation-manifest PUTs)
  cannot produce a 500: proven by the concurrency tests.
- Maven-path silent-unlink closed by the same retry (assert via a unit test
  on the hook path that a first-attempt Conflict with member-now-present
  resolves without the warn branch).
- `hort-app` stays at 100% coverage; full pre-push gate green.
- Comment discipline: invariants only.

## Governing decisions

ADR 0060 (item 150) · `commit_member_added` idempotency contract
(same-member replays stay non-errors) · ref last-writer-wins semantics ·
DB-test isolation contract (`#[serial(hort_pg_db)]`).
