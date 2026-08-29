# 144 — Expand/contract policy + structural guard for destructive migrations

Issue: #214 (incident record: #215 — the 0.11.0→0.12.1 self-lock outage).

A migration set must be applicable while the previous release's binaries are
still running. Migration 020 dropped `artifacts.is_deleted` in the same
release (0.12.0) that removed the last code reference — so the still-running
0.11.0 fleet failed on every artifact query the moment the pre-upgrade hook
completed, and in a self-hosting deployment the broken old pod was
load-bearing for the new pod's image pull (~22 min outage).

**Governing decisions:** ADR 0030 (fail-closed structural guards over
`migrations/` — this item amends it and extends its guard family), ADR 0022
(pre-1.0 migration-editing rules), ADR 0048 (deploy model / mixed-version
windows). The refined→ready confirmation on #214 is the human decision
authorizing the ADR 0030 amendment.

## Deliverables

### 1. ADR 0030 amendment: the expand/contract policy

Destructive DDL — `DROP COLUMN`, `DROP TABLE`, `RENAME` (table or column),
type narrowing, `SET NOT NULL` on an existing column — may ship only in a
release **strictly after** the last release whose code references the
affected identifier. Expand and contract never share a release. Contractions
are deliberate, scheduled, release-notes-flagged events (deliverable 3).

### 2. Structural guard (`no_sensitive_drops` family, DB-free, workspace gate)

Mechanism (hermetic — no git dependency in the test):

- A checked-in manifest `migrations/CONTRACTIONS.toml`: every migration
  containing destructive DDL gets an entry naming the migration file, the
  affected identifier(s), and `reference_removed_in = "<X.Y.Z>"` (the
  release whose code last referenced it is the one before this).
- The guard test fails when:
  a. destructive DDL appears in a migration with no manifest entry
     (token-aware scan, same style as `no_sensitive_drops` — not substring);
  b. the current workspace version (Cargo.toml) is **not strictly greater**
     than a manifest entry's `reference_removed_in` for a migration added in
     the current cycle — i.e. the contraction is trying to ship in the same
     release that removed the reference;
  c. the current source tree still references the identifier (workspace
     grep) — a consistency check that the "removed" claim is at least true
     of the present.
- Existing migrations (001–022) are seeded into the manifest as historical
  entries (020 documented as the incident exemplar) so the guard is green on
  the current tree.
- Weakening the matcher or manifest to make a failure pass is a blocking
  review finding (ADR 0030's standing rule).

The guard's limits are documented in the ADR: (b) enforces the timing gap
mechanically; the reviewer verifies `reference_removed_in` is honest (the
guard cannot see past releases without git) — that check is one
`git grep <identifier> v<claimed-release>` per entry, named in the ADR as
the mandatory review step.

### 3. Release-notes flag convention

CHANGELOG discipline (documented in the ADR + RELEASING.md): a release whose
migration set contains destructive DDL carries a prominent
`### Migration notice` entry naming the dropped/renamed object and the
minimum binary version that tolerates the change, so operators can plan a
maintenance window. RELEASING.md's promotion checklist gains the check.

### 4. Self-hosting upgrade note (docs)

A short section in the upgrade how-to (`docs/architecture/how-to/`, fit the
existing Diátaxis structure): deployments that mirror their own images have
no safety net during API-degrading windows — the old pod both serves errors
and is load-bearing for its replacement's image pull. Names the
expand/contract guarantee as what makes routine upgrades safe, and a
maintenance window as the answer for flagged contraction releases. Also
names the Flux-remediation interplay: automated chart rollback against a
forward-only contraction pins the outage — suspend remediation for flagged
releases.

## Read first

- `crates/hort-app/tests/no_sensitive_drops.rs` — the guard style to extend
  (token-aware SQL scan, sensitive-table list).
- `docs/adr/0030-sensitive-surface-structural-guards.md` — the ADR to amend.
- `migrations/020_drop_artifacts_is_deleted.sql` + `021` + `022` — the
  exemplar entries for the seeded manifest.
- `RELEASING.md` — where the promotion-checklist line lands.

## Acceptance

- Guard red on a synthetic 020-shaped case (destructive migration, manifest
  entry claiming `reference_removed_in` == current release), red on a
  missing manifest entry, red on a still-referenced identifier; green on the
  seeded current tree and on expand-only migrations.
- Runs DB-free under `cargo test --workspace` (auto-included as a `tests/`
  target — no gate-list edit needed).
- ADR 0030 amended with policy, guard mechanism, guard limits + the
  mandatory reviewer step; RELEASING.md + upgrade how-to updated.
- Comment discipline: invariants, no issue refs (ADR/docs prose may cite
  issues — they are the durable record).
