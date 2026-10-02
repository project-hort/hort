# 224 — Give `KeepLastN` its sibling rank, so it can match at all

**Issue:** #287 (part 1 of 2) · **Branch:** `agent/287-predicate-inputs`
**Governing decisions:** the retention concept — this is what unlocks the
count-based population.

## Why

`crates/hort-app/src/use_cases/retention_use_case.rs:387-396` hands the pure
evaluator `keep_rank: None`, with its own note that the input is out of that
increment's scope. The evaluator then fails it safe
(`crates/hort-domain/src/retention/evaluate.rs:122-125`):

```rust
PolicyPredicate::KeepLastN(keep) => match inputs.keep_rank {
    // No ranking resolved → fail safe, never expire.
    None => false,
    Some((rank, _total)) => rank > *keep,
},
```

So `KeepLastN(n)` **never matches anything**. The fail-safe is right; the missing
input is the defect. In production this is the predicate the whole count-based
population depends on — one repository holds 36 894 artifacts across ~32 distinct
names, one of them 2 645 versions at 69 GB.

## Read first

- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the
  candidate query and its keyset pagination; the rank belongs here.
- `crates/hort-domain/src/ports/retention_candidate_reader.rs` — the row DTO to
  extend.
- `crates/hort-app/src/use_cases/retention_use_case.rs:380-400` — where the
  inputs are assembled.
- `crates/hort-domain/src/retention/evaluate.rs:112-130` — the predicate.
- `migrations/003_artifacts_cas.sql:287-324` — the `mutable_refs` table, its two
  target kinds and its repository-scoped indexes.
- `crates/hort-domain/src/ports/ref_registry.rs` — the read side over that
  projection, including the by-target lookups.

## Scope

1. **Resolve rank and total in the candidate query** via a window function over
   `(repository_id, name)`, in the same statement that already enumerates
   candidates — no new port, no second round trip, no new data source.
2. **Fix the ordering criterion explicitly and document it.** Which N survive is
   decided by this ordering, so it is part of the contract, not an implementation
   detail: newest first by creation time, with ties broken deterministically (the
   artifact id is the obvious tiebreaker) so two artifacts created in the same
   instant cannot swap places between runs.
3. **Pass it through** instead of `None`, and keep the fail-safe for the case
   where no rank can be resolved.
4. **Rank over the LIVE sibling set.** A retired row must not occupy a top-N slot —
   otherwise it shields itself and pushes an extra live artifact over the edge.
   This is the same live-set definition the candidate reader gets when its
   `deleted_at IS NULL` exclusion lands; the two must agree, not merely coexist.
5. **Rank alone does not satisfy the tag rule**, and the tag lookup has three
   ways to look right and be wrong. The concept decides that tag targets survive
   regardless of N, and nothing in a rank knows about tags. Tags live in
   `mutable_refs` (`migrations/003_artifacts_cas.sql:287-324`), and the exemption
   must:

   - **Resolve per repository.** The table is keyed
     `(repository_id, namespace, ref_name)` and even its target index is
     `(repository_id, target_hash)`. Content hashes are shared across
     repositories by construction — that is what CAS is — so a hash-global
     lookup would exempt an untagged artifact in one repository because
     identical content happens to be tagged in another. It would also do the
     reverse under `PackageNamePattern`: protect nothing where the tag lives in
     a repository the policy does not scope.
   - **Cover both target kinds.** `target_kind='hash'` points at a content hash
     — the OCI tag case (`crates/hort-http-oci/src/manifests.rs:439-447`);
     `target_kind='version'` points at a version string
     (`crates/hort-adapters-postgres/src/ref_registry_repo.rs:230`), which is how
     an npm dist-tag or any non-OCI mutable pointer resolves. A hash-only
     exemption silently protects nothing outside OCI, and the production
     instance's largest repositories are not OCI.
   - **Survive the gap between expiry and purge.** Evaluation and purge are
     separate CronJobs. A tag added in between finds the artifact already
     carrying `ArtifactExpired`, and the purge does not re-ask — so the steady
     state is correct and the interval is not. Either the exemption is
     re-checked before the purge deletes, or the window is closed some other
     way. Say which, and test the interval rather than only the steady state.

   Either the exemption lands here or the predicate is not safe to enable — say
   which, and test it.
6. Mind the interaction with keyset pagination: the rank is computed over the
   whole sibling group, not over the current page. A rank that changes with the
   page boundary would expire the wrong artifacts — this is the one thing to get
   demonstrably right.

## Acceptance

- `KeepLastN(n)` leaves exactly the n newest versions per `(repository, name)`
  and marks the rest.
- The ordering, including the tiebreak, is documented and covered by a test with
  two artifacts sharing a creation timestamp.
- Rank is stable across page boundaries: a test with a sibling group larger than
  the batch size expires the same set as an unpaginated run.
- An artifact that is the target of a tag does **not** expire under `KeepLastN`,
  even when its rank exceeds N. A fixture with a tagged oldest version pins it,
  and a second fixture pins the `target_kind='version'` form — a hash-only
  exemption must fail this one.
- An artifact whose identical content is tagged in a **different** repository
  does expire: the exemption is repository-scoped, not hash-global. The fixture
  needs two repositories holding the same content hash.
- An artifact tagged **after** its `ArtifactExpired` and before the purge runs is
  not purged. A test walks that interval; steady-state fixtures pass without it.
- A retired (soft-deleted) sibling does not occupy a rank slot; a fixture with a
  deleted newer sibling pins it.
- The predicate still fails safe when no rank is resolvable.
- DB-backed tests carry `#[serial(hort_pg_db)]`; `hort-domain` and `hort-app`
  stay at 100 %; gate green; no issue, MR or backlog numbers in code comments.

## Explicitly not in this item

Nothing about `UnusedFor` or download data (part 2), no new predicates, no change
to the evaluator's fail-safe behaviour.
