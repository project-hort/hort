# 405 — One verb, three ways to name its target

**Issue:** #176 · **Branch:** `agent/176-a-decision-binds-to-the-bytes` ·
item 3 of 3. Part B of the issue spec, client side and docs. **Depends on
item 2** — the CLI calls the routes it adds.

**Governing decisions:** none beyond item 2's. This is the operator surface
for decisions item 2 already made.

## The property

**The two curation verbs are addressed the same way.** `block` is already a
sub-subcommand tree; `waive` is a flat command taking a UUID
(`crates/hort-cli/src/curation/mod.rs:94`). An operator who has learned
`block versions` cannot guess `waive`'s shape, and the shape they would
guess is the one that does not exist.

## What to build

- `curation waive artifact <id>` — the existing behaviour, moved.
- `curation waive versions --repo <key> --package <name> --versions v1,v2,… --justification …`
- `curation waive digests --repo <key> --digests d1,d2,… --justification …`
- `curation block digests --repo <key> --digests d1,d2,… --justification …`

`--versions` and `--digests` use clap's comma `value_delimiter`, as
`block versions` does today. The DTO shapes stay single-sourced the way
`crates/hort-cli/src/curation/mod.rs:56` already describes for the block
outcome.

**The flat `curation waive <artifact_id>` form is removed**, not deprecated.
Pre-1.0, and keeping a positional that only one of three addressing modes
can use is the inconsistency this item exists to end. It goes in the
changelog under `### Changed`, phrased for someone whose script breaks — what
to write instead, in one line.

**Docs:** `docs/architecture/how-to/curator-workflow.md` gains the
bulk-waive and digest flows, the batch-abort contract, and the role-table
rows — **and the queue row's two new fields from item 1**, which this item
owns because item 1 deliberately did not write them. The natural sentence
there is "read the digest off the queue row and hand it to `waive digests`",
and that command does not exist until item 2, so writing it earlier would
have documented a path the reader could not take. The doc already describes
queue fields in prose (`finding_count` / `max_severity` and the OCI row's
own identification), so this is an extension of a passage that exists, not a
new column table: the digest is the addressing key, and the tags are an
annotation that is never one. The fail-open-versus-fail-safe asymmetry — cap 25 against 100,
all-or-nothing against continue-on-error — is stated there as prose, because
it is the invariant a future editor would otherwise "tidy up" into symmetry.

## Two additions the item-2 run surfaced

**1. The CLI's block-outcome DTO needs `not_found_digests`.** The server
envelope gained the field; the CLI's mirror DTO in
`crates/hort-cli/src/curation/block.rs` does not carry it and has no
`deny_unknown_fields`, so nothing breaks — but `curation block versions
--output json` drops the key on re-serialisation. Harmless while the field is
always empty for a versions call, and exactly the sync-required pair that
DTO's own doc comment names.

**2. The docs state plainly that a multi-file release is addressed by
digest.** `waive-versions` resolves a version string the way
`block-versions` already does — first match — and a PyPI release can hold an
sdist *and* a wheel under one version. So a version-addressed waiver on such
a package releases one of the two rows and leaves the other held. That
direction is safe (it releases *less* than the curator may have intended,
never more), and the right instrument for the case already exists in the same
command tree. Growing a stricter resolver for the waive side alone would put
a second resolution rule into the one resolver item 2 exists to single-source,
and changing `block-versions`' long-standing behaviour is not this issue's to
make. So: document it, and point at `waive digests`.

## Acceptance

- `hort-cli curation waive --help` advertises exactly the three
  sub-subcommands, and each one's `--help` names its addressing mode.
- The removed positional form fails with a message that names the
  replacement, not with a bare clap error.
- A digest list given with and without `sha256:` prefixes produces the same
  request body.
- `--output json` passes the server's outcome DTO through verbatim, both
  arms; the table arm renders `already_released`/`failed` distinguishably —
  an operator must not read a converged re-apply as a release that just
  happened.
- `curator-workflow.md` documents the abort contract, the asymmetry, the queue
  row's two new fields, and that a multi-file release is addressed by digest
  rather than by version; the changelog entry is two lines at most.
- `hort-cli curation block versions --output json` round-trips
  `not_found_digests` instead of dropping it.
