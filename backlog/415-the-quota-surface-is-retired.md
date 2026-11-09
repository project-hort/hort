# 415 — The quota surface is retired, not enforced

**Issue:** #280 · **Branch:** `agent/280-the-inventory-has-a-readout` ·
independent of `backlog/414` — neither depends on the other, and 414
deliberately does not report the quota.
**No ADR change. No DDL in this change.**

**Governing decisions:** CLAUDE.md's accepted-at-apply/inert-at-runtime
anti-pattern and its canonical exemplar
(`validate_prefetch_max_age_days_not_implemented`), ADR 0030 (expand/
contract — the column drop, if it ever comes, ships a release *after* the
last code reference goes), ADR 0015 (the operator surface is either
enforced or rejected), #194 (the admin config-inspection surface shows the
*effective applied* config).

**Maintainer decision (2026-11-09):** *"ja, wir entfernen das operator
surface."* The scope decision is his and is made; the mechanism below is
the project's own close for this class.

## The property

**An operator cannot declare a value that does nothing.**

`quotaBytes` is settable on the `ArtifactRepository` envelope
(`crates/hort-config/src/repository.rs:115`) **and validated at apply** —
`validate_quota_bytes_field` (`:758-766`) rejects a non-positive value with
`"quotaBytes must be > 0, got {qb}"`. It is echoed back by the admin
repository response (`crates/hort-http-core/src/handlers/admin/mod.rs:352,398`).
It **is** carried by production code in `hort-app` — an earlier draft of this
item said every occurrence there was a test fixture, and an outside review of
the sibling item caught that: `RepositoryUseCase::create` persists
`quota_bytes: cmd.quota_bytes` and `::update` assigns it. But **nothing
enforces it**: no use case compares it to any usage figure.

No document mentions it; no example or deploy file sets it.

So an operator can declare a quota, watch the apply validate it, read it
back from the API, and have it do nothing. Validating a field is a stronger
signal that it works than merely accepting one — which makes this a sharper
case than the exemplar, where the linter refuses outright.

**Provenance, because it decides the direction:** nobody asked for it. The
column arrived with the original import (`c0d72682`); migration 002's own
header lists the prototype migrations it squashes, including *"008–009
(storage backend / quota)"*. The envelope field and its validation came in
with that same import — the rebrand (`844733b0`) renamed it and `b1fcd05a`
(#220) only *extracted* the validator during a complexity refactor. The one
deliberate decision on top is #194's config-inspection surface, whose job is
to echo the applied config and which therefore makes no claim about
enforcement. This is prototype residue, not a feature with a requester.

## What to build

**The apply refuses it, in the shape of the canonical exemplar.**

Mirror `validate_prefetch_max_age_days_not_implemented`
(`crates/hort-config/src/desired.rs:973-993`) exactly: a pure function of
`DesiredState`, one `ValidationError::Invalid` per offending repository,
naming the repository and the operator's recourse. Wire it where the
exemplar is wired (`crates/hort-app/src/lint/static_validate.rs:639`,
alongside its siblings after the snapshot-validation stage), with a `rule`
label constant beside `RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED` (`:87`)
and **the `docs/metrics-catalog.md` entry in the same change**, which that
constant's own doc comment requires.

The message differs from the exemplar's in one way that matters: `maxAgeDays`
is *deferred* (*"not yet implemented"*), this is **retired**. Say so — that
the quota was never enforced, that the field is going, and that removing it
lets the apply re-run cleanly.

### The CRUD command path is the second surface, and it is unreachable

Because `RepositoryUseCase::create` and `::update` carry the value, "remove
the operator surface" has to account for them or the retirement is
incomplete. Checked, and further than the review did: their command types —
`CreateRepository` and `UpdateRepository` — are referenced **only in their own
file**. No HTTP handler, no other crate and no composition root builds either
one. So that path persists a quota for nobody, because nothing invokes it.

**The consequence here is scope, not extra work:** the gitops envelope is the
only *reachable* operator surface, so refusing it at apply is the whole
retirement. Removing `Repository::quota_bytes` forces those two methods to
change anyway, and the command fields come off with them. Say in the report
that the CRUD path was checked and why it needed no separate refusal —
otherwise the next reader re-derives it, or assumes it was missed.

### The envelope field stays, solely so the refusal can be legible

Deleting it from the struct is the obvious reading of "remove the surface"
and it is the worse mechanism. The spec carries `deny_unknown_fields`
(`repository.rs:40`), so a deleted field makes an envelope that still
declares it fail with `unknown field `quotaBytes`` — which tells an operator
they may have mistyped something or be on the wrong version, and nothing
about why. Keeping the field and refusing it is what produces an error that
explains itself.

It also makes re-enabling a **visible act**: enforcing a quota later means
deleting a named linter rule, not quietly populating a column that was
already being accepted.

Note what this does *not* become: a deprecation. The `path` key on the same
envelope is *"deprecated, not removed"* (`repository.rs:145-149`, with a test
pinning that it must keep parsing) because it still **functions**. A
deprecation that keeps accepting an inert field is the anti-pattern, not a
retirement of it.

### The admin response stops echoing it

#194's surface exists to show the **effective applied** configuration. Once
no apply can set the field, echoing a value — necessarily a pre-existing row's
leftover — reports as effective config something that is neither effective
nor applicable. Remove `quota_bytes` from that response.

### The entity field and the SELECTs go; the column does not

Removing `Repository::quota_bytes`
(`crates/hort-domain/src/entities/repository.rs:749`) and every SQL site that
names the column is **the last-code-reference step** ADR 0030 requires
*before* any DDL. Do that here.

**The census is wider than reads, and the write sites are where this breaks.**
An earlier wording of this item named only the reading SQL. Measured against
this branch's tip:

- **reads** — `repository_repo.rs:47` (the shared column list),
  `curation_rule_repo.rs:495`, `mappers.rs:102` (the row struct) and
  `mappers.rs:228` (the row → entity mapping);
- **writes** — **two** UPSERTs in `repository_repo.rs`, each naming the
  column three times: the `INSERT` column list (`:247`, `:566`), the
  `ON CONFLICT … SET quota_bytes = EXCLUDED.quota_bytes` clause (`:285`,
  `:606`), and the positional `.bind(repo.quota_bytes)` (`:311`, `:634`).

**Dropping a bind renumbers every positional parameter after it.** That is
the one change here that can compile, pass clippy and still write the wrong
column into the wrong field, because `$N` is not type-checked against the
column list. Re-count the placeholders in both statements after the edit and
say in the report that you did, with the before/after parameter count.

Fixture occurrences (`repository_repo.rs:728`, `mappers.rs:1173`) come off
with the field; the compiler reaches them.

**Do not add a migration and do not touch `CONTRACTIONS.toml`.** The column
drop, if it is ever wanted, ships a release strictly after this one, and
whether to spend a contraction on a nullable `bigint` nobody reads is a
separate decision. State in the report that this change is what makes that
drop schedulable.

## Explicitly not in scope

Quota **enforcement** in any form — no usage comparison, no ingest refusal,
no warning threshold. That needs the actual usage figure (which is
`backlog/414`) and then a decision about what happens on breach, and it is
not what was decided. No DDL. No change to `backlog/414`'s response shape,
which already omits the quota.

## Acceptance

- An `ArtifactRepository` envelope declaring any `quotaBytes` value —
  including a positive one — is **refused at apply**, with a message naming
  the repository and saying the field is retired and unenforced. One test
  per shape: a positive value, and the pre-existing non-positive rejection
  still firing (whichever the implementation reaches first, both must refuse).
- The `rule` label constant exists beside its siblings and
  `docs/metrics-catalog.md` carries its entry in this change.
- An envelope **without** the field applies cleanly — asserted, so the
  refusal cannot be over-broad.
- The admin repository response no longer carries `quota_bytes`; a test
  asserts its absence rather than its value.
- `Repository::quota_bytes` and **every** SQL site naming the column are
  gone — the four read sites and both UPSERTs' three occurrences each — the
  `CreateRepository` / `UpdateRepository` fields go with them, and the
  workspace builds, which is the proof the last code reference went.
- **Both UPSERTs' positional parameters are re-counted after the bind comes
  out**, with the before/after count in the report. A round-trip test that
  writes a repository and reads back every remaining field is what proves no
  parameter slid by one.
- The report states that the CRUD command path was checked for reachability
  and what was found, rather than leaving it to be re-derived.
- **No migration file, no `CONTRACTIONS.toml` entry**, and the report states
  that the contraction is now schedulable and why it was not taken here.
- The `path` key's deprecation is untouched — it is a different case and the
  tests pinning that it keeps parsing must still pass.
- Gate green; no uncovered added lines; no ticket numbers in code comments.
