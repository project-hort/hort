# 408 — The held set has a surface

**Issue:** #244 · **Branch:** `agent/244-the-held-set-has-a-surface` ·
item 1 of 2, and the only one in scope. Read-only; item 2 (disposal) stays
unscoped behind #2.

**Governing decisions:** ADR 0007 (invariant 1, the GC protection — **not**
changed here), ADR 0039 D4 (the hold is indefinite and this overview is the
surface it names, by issue number at
`docs/adr/0039-keyed-provenance-verification.md:828`), ADR 0027/0041 (the
provenance conjunct is computed in exactly **one** place), ADR 0054 (CAS
shares bytes across artifacts), ADR 0020 (two-stage retention), ADR 0012
(the token cap is frozen at issuance), #2 (propose → confirm → execute).

## The property

**An artifact the gate holds indefinitely is only defensible if an operator
can see the held set, with its age.** ADR 0039 D4 argues "no deadline"
precisely on that ground and names two surfaces: today's admin curation
queue, and *"once it exists, retention's overview (#244), where disposal is
operator-confirmed and never decided automatically."* This item builds that
overview. Nothing else in the ticket's family does: every unit cut so far
keeps invariant 1 verbatim, which is correct and is also why the exit never
appeared.

## This is a new read path, not a widened old one

Invariant 1 stays exactly as it is. Its filter is single-sourced in
`GC_PROTECTED_QUARANTINE_STATUSES`
(`crates/hort-adapters-postgres/src/lib.rs:146`, all three statuses, read by
four sites), bound into the candidate query through
`gc_protected_quarantine_status_names` (`:153`, predicate at
`retention_candidate_reader.rs:273`) and re-checked in the evaluator
(`crates/hort-app/src/use_cases/retention_use_case.rs:350-370`, both arms
carrying the `inv1:` log prefix).

**The enumeration therefore gets its own port and its own query.** Widening
the candidate query would put the GC protection and the overview on one code
path, and the first change that wants one would silently get the other. A
test asserts that no protected artifact reaches the retention candidates —
and it asserts it **against `GC_PROTECTED_QUARANTINE_STATUSES`**, not against
a restated list, so the assertion cannot drift from the constant.

## The category

An artifact counts when all four hold:

- `quarantine_status = 'quarantined'`;
- the quarantine window has **expired** — `quarantine_window_start +
  effective duration < now`, resolved with the same precedence the curation
  queue uses (the repository's own non-archived policy before the global
  one). **With no resolvable policy there is no deadline, so the row is not
  in the category**;
- the effective `provenance_mode` is `Required`;
- there is **no** `ProvenanceVerified` on `artifact-<id>`.

## D1 — two precisions, and each wears its own name

`release_clearance.rs` exists because two independent provenance
computations produced exactly the drift that was found as a HIGH finding. An
SQL re-implementation of the release conjunct would be that second
computation. So:

- **The aggregate (count + age)** is a pure-SQL **superset** of the four
  conditions. It is named in the API, the response and the docs after what it
  measures — `held_pending_signature_candidates` — and **not** "artifacts the
  gate is holding". One query, no per-row event read.
- **The drill-down** (the list an operator acts on) is authoritative per row
  through **`provenance_clearance_from`**
  (`crates/hort-app/src/use_cases/release_clearance.rs:118`) — the one
  source. It is `pub(crate)`, which settles where the authority runs: in a
  `hort-app` use case, never in the HTTP handler (ADR 0008). Capped like the
  curation queue and keyset-paginated — and **the curation queue rejects
  rather than clamps**, which is a behavioural choice and not a detail. Its
  use case refuses a `limit` above its own `MAX_QUEUE_LIMIT`
  (`crates/hort-app/src/use_cases/curation_use_case.rs:91`, refusal at
  `:356`) and its handler validates `1..=500` with a default of 100 and a
  `400` on anything outside (`crates/hort-http-core/src/handlers/admin/curation/queue.rs:19`,
  message at `:187`). A silent clamp returns fewer rows than asked for and
  says nothing; a refusal tells the caller. Follow the refusal.
  **Do not reach for a constant called `MAX_LIST_LIMIT`**: the workspace has
  two of that name with different values — 1000 in
  `crates/hort-app/src/use_cases/ref_use_case.rs:47` and 500 in
  `crates/hort-app/src/use_cases/security_score_use_case.rs:49` — and
  neither is the curation queue's. Name the one you mean, in the layer it
  belongs to.

One authority per artifact stays true; the count is an honestly named
approximation.

## D2 — bucketing without a second rule

The split is `is_parent_gated_blob_constituent`
(`crates/hort-app/src/use_cases/referenced_descendant.rs:181`): a constituent
is held because its parent manifest is unsigned (ADR 0039 — a blob cannot
carry its own attestation), an artifact in its own right is not. The operator
action differs, so the overview distinguishes.

**The rule is not re-implemented in SQL.** The two kind lists —
`PARENT_GATE_BLOB_KINDS` (`:138`) and `SELF_REFERENTIAL_KINDS` (`:47`) — go
into the query as `text[]` parameters and SQL forms only the boolean
(`bool_or(kind = ANY($blob)) AND bool_and(kind = ANY($blob) OR kind =
ANY($self))`, reference-less ⇒ false, identical to the Rust predicate). For
that, `referenced_descendant.rs` gains a kind-based primitive the existing
function delegates to, and a **DB-backed parity test** (`#[serial(hort_pg_db)]`,
mandatory) drives both paths over the same kind sets.

## D3 — age, and bytes are not rows

- **Age per bucket:** `now - min(quarantine_window_start)`, falling back to
  `created_at` where no window start is set. The age is the number D4's
  "no deadline" rests on; it appears in every response.
- **Rows are not bytes** (ADR 0054): several artifact rows share content. The
  aggregate reports **both** per bucket — the row count and the number of
  distinct `checksum_sha256` — so nobody reads "4152 artifacts" as reclaimable
  storage. What a disposal would actually free is item 2's question, decided
  by the CAS refcount.
  *This is not theoretical: the first real retention dry run (2026-11-08)
  reported 3 647 rows against 3 608 distinct contents, so the two differ in
  practice.*

## D4 — surface and permission

`GET /api/v1/admin/retention/overview` (aggregate) and
`GET /api/v1/admin/retention/held?bucket=…` (drill-down), registered as their
own nest beside `curation_routes()` in `crates/hort-server/src/http.rs`.
Neither exists today.

Gate: `CurateOrAdminPrincipal` — **no new permission.** `Curate` is already
defined as decision authority over quarantined/rejected artifacts, which is
exactly the set this shows. A new permission costs a DB enum migration, grant
upkeep and a token rotation (the cap is frozen at issuance, ADR 0012 — the
cause of #257) without separating an authority that should be separate.

## D5 — the operator-facing documentation is part of the surface

Two endpoints an operator is expected to reach for mid-incident are not a
surface until something tells them the set exists, what its age means, and
why it has no deadline. `docs/architecture/how-to/curator-workflow.md` is
where the adjacent authority is already documented (`Curate` gates both, and
the curation queue is ADR 0039 D4's *other* named surface), so the section
goes there rather than into a new page.

It carries four things and stops: what the held set is, that the hold is
indefinite **and why that is defensible only because this view exists**, what
the two precisions mean — and the warning that an artifact count is not a
byte count, because CAS shares content across artifacts. Any term that needed
clarifying while specifying this goes into `docs/glossary.md` before the item
is done.

This is not decoration. ADR 0039 D4 declines to put a deadline on an
indefinite hold *by pointing at this overview*; an overview nobody is told
about leaves that argument resting on something an operator never finds.

## D6 — no gauge

No new Prometheus value. The old hold gauges went with #260; the overview is
the surface, not the metric. If a gauge follows later it is a trigger, not an
authority. ADR 0039 D4 already names this overview, so **no ADR text
changes** in this item.

## Acceptance

- The category is exactly the four conditions: an artifact with no resolved
  policy (no deadline) is absent, and a `ProvenanceVerified` on the stream
  removes it.
- `retention_candidate_reader` and invariant 1 are unchanged, asserted
  against `GC_PROTECTED_QUARANTINE_STATUSES` rather than a restated filter —
  a test shows no protected artifact reaches the retention candidates.
- Aggregate: row count, distinct-content count and oldest age per bucket
  (bucket = repository × constituent/in-own-right), in one query, with no
  per-row event read.
- Drill-down: resolved per row through `provenance_clearance_from`,
  keyset-paginated, and a `limit` above the maximum is **refused** — in the
  use case and at the boundary — rather than silently clamped, matching the
  curation queue. The bound is this view's own named constant, not a
  re-used `MAX_LIST_LIMIT`.
- The kind predicate exists exactly once in Rust; the parity test covers the
  SQL and the Rust path and carries `#[serial(hort_pg_db)]`.
- Both endpoints answer `403` without `Curate`/`Admin` and `200` with.
- The aggregate's name says what it measures, in the route, the response and
  the docs.
- The curator how-to carries the held-set section, including the
  rows-are-not-bytes warning, and every term that needed clarifying is in
  `docs/glossary.md`.
- No new permission, no new gauge, no ADR edit, no change to invariant 1.
