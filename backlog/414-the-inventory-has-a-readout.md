# 414 — The inventory has a readout, not a gauge

**Issue:** #280 (gap 3) · **Branch:** `agent/280-the-inventory-has-a-readout` ·
the only item. **No ADR change.**

**Governing decisions:** **#260** (two hold gauges removed, *"no replacement
metric; the operator's view of the held set is the admin curation queue"* —
the precedent that sets the shape), ADR 0054 (CAS shares bytes across
artifacts, so rows are not bytes), ADR 0052 (`ReadMetrics` is a separate,
admin-orthogonal capability — why a metric is not the cheap option), ADR 0030
(soft delete: a live count filters `deleted_at IS NULL`), ADR 0008 (the query
belongs in an adapter, the decision in a use case).

**Maintainer decision (2026-11-09):** cut it, have the approach reviewed once
by Codex, then queue the implementation behind #421.

## The property

**A retention concept without a before/after measurement is not verifiable** —
and today no API and no metric says how many artifacts and how many bytes lie
in each repository. #280 is the inventory that had to be taken by hand, with
read-only SQL against the production database, precisely because the product
cannot answer it.

## Why this is a readout and not the two gauges #280 proposed

#280 proposes `hort_repository_artifacts` and `hort_repository_bytes`. Neither
exists. Before building them, the standing decision that governs this shape:

**#260 removed exactly this kind of gauge.** `CHANGELOG.md` under
`### Removed` for `[0.14.0]`: the two provenance-hold gauges went, with *"no
replacement metric; the operator's view of the held set is the admin curation
queue."* `backlog/187-remove-held-gauges.md` adds the part that matters for
placement — they lived in the **worker's** recorder, whose `/metrics` is
opt-in and default-off, so *"the gated server endpoint never carried them."*
A ticket then waited weeks on metrics that did not exist and that the server
port had never served.

**The difference is real and must be stated rather than glossed:** #260's
gauges were set from the candidate batch of a single sweep tick, so they could
not describe the population at all. A full per-repository count does not share
that defect. So #260 does not condemn an inventory metric on its own terms.

**What it settles is narrower than an earlier draft of this item claimed, and
the correction came from an outside review of this approach.** #260 and
`backlog/187-remove-held-gauges.md` decide that **the held set's** operator
view is the authoritative surface over the projection rather than a metric —
`187` says it in those terms and points at this very overview. They decide
nothing about an inventory metric.

And this project plainly does use **complete-population gauges** where they
are the right instrument: `hort_policy_reevaluation_population`
(`docs/metrics-catalog.md`) is *"set once at the completion of a
`policy-reevaluation` pass to the in-scope population it walked … the
**completeness** signal"*, and `hort_cron_rescan_eligible_artifacts` /
`hort_cron_rescan_stranded_eligible_artifacts` are the same shape. ADR 0052
makes scraping a separate grant but does not forbid an inventory metric, and
an admin may hold that grant explicitly.

**So: build the readout because it answers the interactive question an
operator asks, not because a gauge is barred.** Whether the two gauges #280
proposes are worth having is a separate decision on their own merits —
freshness, scrape cost, and whether anyone needs to alert on this — and this
item neither builds nor forecloses them.

## What to build

**An admin readout of what each repository holds**, as its own endpoint beside
the existing repository surfaces.

Per repository, three numbers and not two, and the first two **keep the names
#244 already put on the wire**:

- **`artifact_count`** — live rows only, `deleted_at IS NULL` (ADR 0030);
- **`distinct_content_count`** — the count of distinct `checksum_sha256`;
- **bytes** — summed over **distinct contents**, not over rows.

**Do not widen `HeldSetReader` to carry this.** Its name, its query and its
`HeldCandidateBucket` are about the held slice; the inventory is a different
question over a different population, so it gets its own reader and its own
use case (ADR 0008 — the query in the adapter, the decision in the use case).
Reuse the two field names and the bucket-cell shape; do not reuse the port.

**And #244 deliberately omitted a byte figure** — *"What a disposal would
actually free is a different question again, decided by the CAS refcount"*
(`overview.rs:17-23`). That is not a precedent against this field; it is the
reason for its name. #244's surface previews a **disposal**, where the honest
number is refcount-gated and therefore not computable from the rows. This
readout reports a **catalog weight**, which is computable and is not
reclaimable space — so the omission over there and the naming discipline
below are the same decision applied to two different questions.

**The third one is the point, and the outside review's sharpest finding is
that it still cannot mean what "bytes" implies.** Both halves matter:

*It is computable.* One query groups live `artifacts` by
`(repository_id, checksum_sha256)`, takes one `size_bytes` per hash and sums
the groups — all three columns are on the row, and the ingest records the CAS
result's hash and size together. **`SUM(DISTINCT size_bytes)` is the wrong
spelling** and would be a real defect: two different hashes can have equal
sizes, so distinctness has to be on the hash, not on the number.

*But it is not a repository's storage share.* One CAS entry can carry artifact
rows in several repositories, so each repository's distinct-hash sum counts
that same physical blob, and **adding repository figures double-counts it.
There is no unique per-repository physical ownership to report.** It also
omits CAS-resident metadata and other content-reference target kinds, and a
soft-deleted row's bytes can stay resident until refcount-gated GC — so it is
not reclaimable space either. What is actually reclaimable depends on every
surviving claim, which is what the retention preview and purge GC already
model.

**Someone wrote this distinction down before I did, and the review found it
where this item had not looked.** `RepositoryRepository::get_storage_usage`
exists and its Postgres implementation sums `size_bytes` over live **rows**,
with a comment that says: *"The sum is a catalog weight, not a measurement of
bytes at rest: dedup means two artifacts sharing one blob are both counted, so
this was never the figure that answers 'how much disk does the repository
hold'."* It is not routed anywhere. **Do not reuse its value or its name** —
but take its warning as settled.

So: **name the field `live_primary_content_bytes`** (or something equally
unwilling to be misread), and state in the response documentation that it is
**non-additive across repositories** and is **neither disk usage nor
reclaimable space**. The row count and the distinct-content count stay
alongside it; the first dry run measured 3 647 rows against 3 608 contents, so
they differ in practice.

## What already exists, which this item had wrong

An earlier draft asserted that no API and no metric reports per-repository
artifact or byte counts. Three partial answers exist, and the nearest one
**landed on `develop` after this item was written**:

- **#244's held-set overview already serves two of these three numbers, per
  repository.** `GET /api/v1/admin/retention/overview` returns one cell per
  `(repository, bucket)` carrying `artifact_count`, `distinct_content_count`
  and the oldest hold's age
  (`crates/hort-http-core/src/handlers/admin/retention/overview.rs:1-35,56-72`),
  behind `CurateOrAdminPrincipal`, reading
  `hort_domain::ports::held_set_reader::HeldCandidateBucket` through
  `held_set_use_case`. It is scoped to the **held-pending-signature**
  population, so it answers nothing about the live estate — but the shape,
  the two field names and the "rows are not bytes" reasoning are already on
  the wire, and this item must not invent a second vocabulary for the same
  two numbers.

- **Per-repository status counts are already served.** `GET
  /api/v1/repositories/{name}/security-score` and the paginated
  `GET /api/v1/security-score` expose `quarantined`, `rejected` and `released`
  per repository. They cover neither every live artifact nor any bytes, so
  they do not replace this readout — but the claim "nothing answers this" was
  too strong.
- **`get_storage_usage` is the row-sum, unrouted**, with the caveat quoted
  above.

The gap is real; it is narrower than stated, and the item says so now.

## The quota field, stated accurately

#280 says `repositories.quota_bytes` *"existiert im Schema, ist aber ohne
Ist-Wert nicht überwachbar."* Verified, and it is worse than not monitorable:

- it is **operator-settable** through gitops — `quotaBytes` on the
  `ArtifactRepository` envelope (`crates/hort-config/src/repository.rs:115`),
  with apply-time validation that rejects a non-positive value
  (`validate_quota_bytes_field`, `:758-766`);
- it is **echoed back** on the admin repository response
  (`crates/hort-http-core/src/handlers/admin/mod.rs:330,376`);
- it **is** carried by production code in `hort-app`, which an earlier draft
  of this item denied: `RepositoryUseCase::create` persists
  `quota_bytes: cmd.quota_bytes` and `::update` assigns it. Those two methods
  have **no caller anywhere** — their `CreateRepository` / `UpdateRepository`
  command types are referenced only in their own file — so the value is
  persisted by a path nothing invokes, which is not the same as "no production
  code touches it"; and
- **nothing enforces it** — no use case compares it to anything; and
- **no document mentions it** (zero hits under `docs/`).

So an operator can declare a quota, have the apply validate it, read it back
from the API, and have it do nothing. That is the shape CLAUDE.md names as a
hard block — *"a new field must be either enforced by the consuming use case
or rejected at gitops apply; accepting the field while the consumer silently
ignores it is a hard block — operators set risk-significant values on the
assumption the field is load-bearing"* — and unlike the canonical exemplar
(`max_age_days`, which the apply-time linter rejects outright), this one is
accepted *and* validated, which actively signals that it works.

**This item does not fix that, and must not quietly half-fix it.** Reporting
the quota beside the usage would make the readout look like quota monitoring
while nothing enforces anything. So: **the readout reports usage and does not
report `quota_bytes` at all**, and the item's report states the finding so the
decision — enforce, reject at apply, or document as advisory — is taken
deliberately and separately. It is the maintainer's call, not this item's.

## The cost is unmeasured, and the bound has a direction

The review could not settle query cost from the tree, which is the right
answer: there is no final SQL and no plan on representative data. Two things
it did establish, and this item adopts both:

- the existing artifact indexes are on checksum, or on repository plus
  path/name — **not** a live `(repository_id, checksum_sha256)` index covering
  size — so an exact inventory must visit the live rows or a maintained
  projection. Whether an index is warranted needs
  `EXPLAIN (ANALYZE, BUFFERS)` on representative data, not an inference from
  #280's 142 GB figure, which describes **CAS content** while this aggregate
  reads relational columns;
- and if a bound turns out to be needed, **page the repository keys before
  aggregating their artifacts.** Paginating an already-global aggregate does
  not bound its work. Existing precedents cap repository pages at 1 000 and
  the security-score list at 500.

**So: one set-based aggregate query and a measured plan, before any claim
that this endpoint is cheap and before adding an index or pagination.**

## Explicitly not in scope

No gauge. No quota enforcement and no quota field in the response. No
deletion, no retention predicate, no change to what retention evaluates. Not
the other two open gaps on #280 — the per-format reachability measure (a
concept decision for #281: until "unreferenced" has a per-format meaning, no
retention may be built on it) and the unfinished multipart uploads.

## Acceptance

- One admin endpoint returns, per repository: live artifact rows, distinct
  contents, and bytes **summed over distinct contents**, the last named so it
  cannot be read as disk usage. A fixture in which two artifacts share one
  content within one repository proves rows ≠ contents and proves the byte sum
  counts the shared content once — **and a second fixture in which one content
  is referenced from two different repositories** proves the figure is
  non-additive, with the documentation saying so.
- The distinctness is on the **hash**, not on the size: a test with two
  different contents of equal size proves `SUM(DISTINCT size_bytes)` was not
  what was written.
- Soft-deleted artifacts are excluded, asserted against a seeded
  soft-deleted row rather than by reading the SQL.
- The response's field names say which number is which; nothing in the
  response or the docs calls a row count a byte count.
- `quota_bytes` does not appear in the response.
- The authority is the existing admin gate; no new `Permission`.
- Gate green; the change adds no uncovered lines; no ticket numbers in code
  comments.
