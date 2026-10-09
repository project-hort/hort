# 283 — The authority contract covers every write, and the old path stops compiling

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0012 (one audited apply path for grants) ·
ADR 0018 (federated identity; the service-account and issuer rows are trust
anchors) · ADR 0007 (`EventStore` stays backend-agnostic — the port must not
grow a transaction concept).

Item 282 built the contract and moved three call sites onto it. This item
finishes the adoption and then removes the path it replaced. The two halves are
one unit because the order is forced: a write method can only leave its trait
once nothing needs it.

## What is true today (after item 282)

`AuthorityLifecyclePort` (`crates/hort-domain/src/ports/authority_lifecycle.rs`)
commits authority rows and their attesting audit events in one
`PgUnitOfWork` transaction. Permission grants, claim mappings and OIDC issuers
go through it.

**Two apply branches still carry the old shape:**

| Branch | Row write | Audit append |
|---|---|---|
| `apply_config_use_case/upstream_mappings.rs` | `self.upstream_mappings.save_managed(&mapping)` **per mapping**, each independently committed (line ~67) | `append_grouped_authorization_events(...)` at the end (line ~217) |
| `apply_config_use_case/service_accounts.rs` | the service-account rows through their own repository | `.append(AppendEvents { … })` afterwards (line ~89) |

Both fail the same way: the row commits, the append fails or the process dies,
the authority is live with nothing attesting it, and the next apply's
prior-vs-desired diff sees the written row and emits nothing. For upstream
mappings there is a second property the port already fixes elsewhere — the
grouped append is one transaction *per stream*, so a part-way failure leaves
some streams audited and others not.

**And the four replaced write methods are still on their traits** with no
production caller left: `PermissionGrantRepository::save_managed`,
`ClaimMappingRepository::save_managed`, `OidcIssuerRepository::upsert` and
`::delete_by_name`. A new apply branch can reintroduce exactly the defect
item 282 closed, and only review would catch it. The anti-patterns checklist
in `.claude/commands/hort-architect.md` says so today, and says explicitly
that it is a review rule rather than a compile error.

**Curation is NOT this shape — checked, not assumed.**
`apply_config_use_case/curation.rs` also calls `save_managed`, and its
docstring carries a "Strict-atomic" note about append failures. That note is
about the **retroactive** pass: a tightened rule appends `ArtifactRejected`
for already-ingested artifacts, and an append failure aborts the apply so the
operator's restart re-resolves a consistent state. That is a decided posture
about artifact events, not a missing audit attestation for the rule row. Out
of scope. *If* you find an audit event for the rule change itself appended
after its row, that is in scope — say so in the report rather than fixing it
silently.

## Why both halves, and why this project closes it structurally

This codebase does not leave a closed defect reachable by convention:

- A format crate touching `ctx.repositories` is an unresolved-import compile
  error, and CLAUDE.md says "that is intentional".
- `db_tests_are_serialized` has **no allow-list, by design** — a site that
  should not be flagged is a review conversation, not a table entry.

A write method with no caller that re-opens an audit-integrity finding belongs
in the same category. The checklist entry is the stopgap for the window
between item 282 and this item, not the answer.

## What to do

1. **Extend the port to the two branches.** Mirror what is already there: the
   upstream-mapping write is a set of per-mapping upserts, so it needs a named
   write-intent struct the way `OidcIssuerChange` does; the service-account
   write follows whichever of the two existing shapes fits its repository. Do
   not invent a third style — read the port and its adapter first.
2. **Assert the multi-stream property for upstream mappings.** N batches on
   one `PgUnitOfWork` are one unit; item 282 proved that for grants with a
   first-accepted / second-refused test. The same test shape applies here, and
   it closes the per-stream partial-append property the branch's docstring
   currently documents as a known gap. Remove that docstring sentence when it
   stops being true.
3. **Then remove every write method this unit leaves without a production
   caller** from its trait, and carry the mock implementations with it. At
   minimum the four named above; enumerate in the report what you actually
   removed — a hand-counted list in this item would be wrong by the time you
   read it. The real bodies already exist as the `*_in_tx` helpers, so only the
   trait wrappers go. The **read** surfaces stay: `ApplyConfigUseCase` and the
   RBAC resolve / effective-permissions / rotation / `rbac_refresh` paths all
   legitimately read through these ports.
4. **Re-point the orphaned DB tests.** `permission_grant_repo.rs` and
   `claim_mapping_repo.rs` have `save_managed` tests; they move onto the
   `commit_*` path, which is strictly better coverage because it also exercises
   the audit append.
5. **Update the checklist entry.** The last sentence of the
   `AuthorityLifecyclePort` bullet in `.claude/commands/hort-architect.md`
   currently says the rule is a review rule because the methods still exist.
   After this item it is a compile error — say that, and drop the sentence
   naming the two branches as still-outstanding.

## Explicitly out of scope

- Atomicity **across** apply stages. Each stage is atomic in itself; the
  pipeline has no cross-stage rollback and this item does not add one.
- Making any of these aggregates event-sourced. They stay CRUD with an audit
  trail.
- `RepositoryRepository::save_managed` and `CurationRuleRepository::save_managed`
  — different ports, different concerns, and curation is explained above.
- The non-blocking JWKS warm-up posture.
- Any new configuration.

## Acceptance

- Per branch, a test in which the append fails and the rows are afterwards
  **not** in effect.
- A test that the upstream-mapping multi-stream case commits as one unit.
- The four (or more) write methods are gone from their traits, and the build
  proves it: a `grep` for them in `crates/*/src` returns only the `*_in_tx`
  helpers.
- Every DB-backed test added here carries `#[serial(hort_pg_db)]`
  (CLAUDE.md → *DB-backed test isolation*; `db_tests_are_serialized` has no
  allow-list).
- The diff adds no uncovered lines: for every line the diff adds in
  `hort-app`, `hort-domain` or `hort-adapters-postgres`,
  `cargo llvm-cov --show-missing-lines` does not list it. Where a moved-verbatim
  error region cannot be forced, name it rather than claiming a clean number —
  item 282's report is the model for how to present that.
- Gate green, one-shot capture, exit codes separate from the output:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace`, `cargo-audit audit -D warnings`,
  `cargo-deny check`.
