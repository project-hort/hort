# 316 — The differential harness pins today's parse, before anything is swapped

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Governing decisions:** ADR 0015 (a policy field accepted at apply and inert
at runtime is a hard block — it rests on parse strictness), ADR 0018
(`ServiceAccount` apply-time validation).

**This unit swaps nothing.** It builds the instrument that makes the swap
provable, and it must be green against the **current** parser before unit 318
touches a dependency. A harness written after the swap proves only that it
agrees with itself.

## What to build

A test target that, for every gitops envelope YAML in the repository,
deserialises it **twice** — once through `hort-config`'s current entry points,
once through the replacement parser — and asserts the two results are equal.

- **Corpus, derived not listed.** Walk the repository for `*.yaml` / `*.yml`
  (389 files today, 37 of them under `fixtures`/`tests` — re-measure), and
  keep the ones that parse as a gitops envelope. A file that is not an
  envelope (CI config, Helm templates, compose files) is skipped **by a stated
  rule**, not by an allow-list of paths, and the count of kept/skipped files is
  asserted so a corpus that silently empties fails loudly. The sibling guards
  under `crates/hort-app/tests/` set the pattern for a counter-assertion of
  this kind.
- **Compare the deserialised value, never the text.** The envelope types are
  the contract; formatting is not.
- **Both parsers present, deliberately temporary.** The replacement goes in as
  a normal dependency and the incumbent stays as a `dev-dependency` for the
  duration. Unit 319 removes the incumbent **and this harness together** — a
  differential test that outlives the migration is a permanent dependency on an
  abandoned crate, which is what this ticket exists to end. Say that in the
  module doc so the next reader does not "preserve" it.
- Keep it DB-free and sub-second-ish, so `cargo test --workspace` runs it with
  no database, like the other structural guards.

## Acceptance

- Green on the current tree with **both** parsers wired, before any production
  call site changes.
- The corpus census is asserted (kept count, skipped count) and the test fails
  if the walk finds nothing.
- A deliberately corrupted fixture makes it fail — show that, so the harness is
  not vacuous.
- No change to any `crates/hort-config/src/*.rs` production parse call.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>`. Judge by the
  output, not the rc. Do **not** run `cargo test --workspace`, `cargo audit`,
  `cargo deny` or the attribution script.

**Note on the red gate:** `cargo audit` / `cargo deny` are red on every branch
until unit 319 lands (RUSTSEC-2024-0449). That is expected and is **not** this
unit's problem; do not add an ignore to make them green.
