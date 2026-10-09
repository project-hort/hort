# 282 — An authority change commits with its audit event

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0012 (grants flow through **one** audited apply
path) · ADR 0007 (`EventStore` is backend-agnostic — the port must not grow a
transaction concept) · ADR 0018 (federated-identity claims; the issuer rows
this item touches are trust anchors).

Two audit findings, one contract, three sites.

## What is true today

Three apply paths write a security-relevant row, commit it, and then append
the audit event that attests it in a separate call:

| Site | Row write | Audit append |
|---|---|---|
| Permission grants | `PgPermissionGrantRepository::save_managed` — deletes and reinserts the **entire** GitOps partition in one SQL transaction (`permission_grant_repo.rs`) | `apply_permission_grants` calls `append_grouped_authorization_events(...)` after it returns, potentially across several streams (`apply_config_use_case/permission_grants.rs`) |
| Claim mappings | `claim_mapping_repo.rs`, same whole-partition shape | `apply_config_use_case/claim_mappings.rs`, same sequence |
| OIDC issuers | `oidc_issuers.upsert(&issuer)` per issuer, each an independent committed statement (`oidc_issuer_repo.rs`) | `apply_config_use_case/oidc_issuers.rs` accumulates events and appends the batch to `StreamId::authorization()` at the end |

An append failure — or a process termination — after the SQL commit leaves the
grant, claim mapping or issuer **active, with nothing in the authorization
stream attesting the mutation**. Serving validators read the issuer repository
on validation, so surviving pods act on the new trust state while the stream
is silent about it.

**And the retry cannot repair it.** The next apply derives its events from the
*prior rows*, which already contain the change, so it emits nothing. The
claim-mapping path says so in its own comment: an unchanged digest is a no-op,
no audit event. For issuers a reapply may emit an `Updated` because the issuer
snapshot has no persisted digest — but it cannot restore the original
`Created`/`Deleted`, nor the record that the change was live without one.

Two smaller facts belong to the same finding:

- `oidc_issuers.rs` logs **`oidc_issuer audit events committed` before the
  append runs**. The operator-visible statement is emitted on a path that has
  not yet done the thing it claims.
- A grouped append that fails part-way can leave **some** repository streams
  audited and others not.

## Why this is the shape of the fix

This is the audit's first structural result again — *one missing contract, not
three bugs* — and the primitive it needs **already exists**, twice over.

`crates/hort-adapters-postgres/src/event_store.rs` defines `PgUnitOfWork`, "a
PostgreSQL transaction handle for cross-port transactional writes", used by
`PgEventStore::append_in_tx` and `PgArtifactLifecycle::commit_transition`. The
domain side of that pattern is a **lifecycle port**: `ArtifactLifecyclePort`
(`crates/hort-domain/src/ports/artifact_lifecycle.rs`) exposes one method that
commits a state change and its events together, and the app layer calls that
single method. There are already three such ports — artifact, artifact group,
ref — and the app layer depends on them as ports, so the transaction stays
inside the adapter and the hexagon is intact. ADR 0007 is satisfied for the
same reason: `EventStore::append` does not grow a transaction parameter.

So the correction is **adoption of an established pattern at a fourth site**,
not a new mechanism: an authority-side lifecycle port whose one method commits
the rows and appends their audit events in a single `PgUnitOfWork`.

A retry-side repair (comparing desired state against the event stream rather
than against the rows) is the other conceivable answer and is **not** this
item: grants, claim mappings and issuers are deliberately CRUD in this
architecture, with events as the audit trail, and making the stream a second
source of truth for them is a decision nobody has taken.

## What to do

1. **Add the port.** One trait in `hort-domain/src/ports/`, mirroring
   `ArtifactLifecyclePort`'s shape: a method per authority write that takes the
   desired rows **and** the events to append, and commits both or neither.
   Read all three existing lifecycle ports first and follow the one closest in
   shape; do not invent a fourth style.
2. **Implement it in `hort-adapters-postgres`** over `PgUnitOfWork`, the way
   `PgArtifactLifecycle::commit_transition` does. The whole-partition
   delete-and-reinsert stays exactly as it is — it is already one statement
   group in one transaction; the audit append joins that transaction.
3. **Move the three call sites onto it.** The app layer loses its
   `save_managed` + `append_*` pair and gains one call. The event derivation
   (prior-vs-desired diff) does not change.
4. **Fix the premature log line.** `oidc_issuer audit events committed` moves
   after the commit, or says what it actually knows at the point it is emitted.
5. **Keep the grouped append's partial-failure property in view.** If the
   grouped multi-stream append cannot be made atomic within the one
   transaction, say so explicitly in the report with what it would take —
   do not silently narrow the item to the single-stream case.

## Explicitly out of scope

- Making grants, claim mappings or issuers event-sourced. They stay CRUD.
- The apply pipeline's staged validation and the preflight line list (that was
  block 0's unit 0.3, already merged).
- The non-blocking JWKS warm-up. Its failure persists the issuer **by design**,
  and the former-key-still-trusted case is a separate open audit finding.
- Any new configuration.

## Behaviour changes to surface in the report

- An event-store failure during a grant, claim-mapping or issuer apply now
  leaves the rows **unchanged** — the apply fails closed instead of half-done.
  This is a change in what a failed apply leaves behind, and an operator who
  has seen the old behaviour will notice it.

## Acceptance

- Per site, a test in which the append fails and the row is afterwards **not**
  in effect. A test that only asserts the happy path proves nothing here.
- A test that the grouped multi-stream case commits as one unit, or an explicit
  report statement that it cannot and why.
- No log line claims an append that has not happened.
- The diff adds no uncovered lines: for every line the diff adds in `hort-app`
  or `hort-adapters-postgres`, `cargo llvm-cov --show-missing-lines` does not
  list it.
- Every DB-backed test added here carries `#[serial(hort_pg_db)]`
  (CLAUDE.md → *DB-backed test isolation*); `db_tests_are_serialized` will
  fail the gate otherwise, and it has no allow-list.
- Gate green, one-shot capture, exit codes separate from the output:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace`, `cargo-audit audit -D warnings`,
  `cargo-deny check`.
