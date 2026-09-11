# 176 — a structural close that can be silently skipped is not structural

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` · Item 4 of 4
(depends on item 171; independent of items 172 and 173).

## Problem

Item 171's rejection is wired through an **optional** capability set:
`version_discovery_capable_formats: Option<Arc<HashSet<String>>>`, defaulting
to `None`, and `None` means the rule is skipped entirely. Both production
entry points wire it, and both are tested — but a third one added later
inherits `None` and the rejection silently stops applying.

That is fail-open, and it is the wrong property for this particular rule. ADR
0015's structural close exists so an inert operator surface **cannot** be
reintroduced by omission. A close that a future composition point can skip
without noticing is a convention, not a structure.

## Why the obvious alternative is worse, and what the right one is

The sibling field `provenance_capable_formats` is required and default-empty,
which is fail-closed there: empty means "no format can do provenance", i.e.
deny everything. Copying that shape here would invert the meaning — an empty
capability set would reject `transitive_deps` on npm, cargo and pypi too, in
every test and harness that does not wire it. The implementer was right to
refuse that.

But there is no *runtime* default that is both safe and correct, because "we
do not know which formats are capable" cannot answer a rejection question in
either direction. So the obligation belongs at **compile time**: make the
capability set a required constructor parameter rather than an optional field.
A new composition point then fails to build until it supplies one, which is
exactly the property the close is supposed to have.

## Read first

- `crates/hort-app/src/use_cases/apply_config_use_case.rs` — the field, its
  builder, and the neighbouring required `provenance_capable_formats` whose
  shape must **not** simply be copied.
- `crates/hort-app/src/lint/static_validate.rs` — row 6b and how it consumes
  the set.
- `crates/hort-server/src/format_capabilities.rs` — the production derivation.
- `crates/hort-server/src/gitops_boot.rs` and
  `crates/hort-server/src/cli/validate_config.rs` — the two wired entry
  points.

## What to change

Make the capability set a required parameter of the constructors that need it,
removing the `Option` and the skip branch. Production keeps passing the derived
set. Test and harness call sites pass an explicit one.

**Format literals in test call sites are fine** — the rule that keeps them out
of the rejection *logic* is about the logic, not about a test declaring the
world it is testing. Do not invent an indirection to avoid them.

Keep the guard that pins the derived set against the handlers' own
declarations; it is what stops the production set drifting from reality, and
this item does not replace it.

## Explicitly not in this item

- Any change to which triggers require the capability, to the rejection
  message, or to `on_dist_tag_move`.
- Any change to `provenance_capable_formats`.
- Any Maven parsing.

## Acceptance

- The capability set is required; omitting it is a compile error, not a silent
  skip.
- No `Option`-shaped skip branch for row 6b remains.
- Both production entry points behave exactly as before.
- A test asserts the rejection fires for a non-capable format and does not for
  a capable one, driven through a constructor that had to supply the set.
- Full local gate green per the pre-push checklist, `cargo test --workspace`,
  with the `DATABASE_URL` state and skipped-for-no-database count reported.
