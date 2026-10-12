# 317 — The six semantic answers are measured and pinned at the old parser

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Depends on:** 316 (the harness), though these tests stand alone.

Unit 316 proves the two parsers agree on the **corpus we have**. It cannot
prove they agree on the inputs we do not have but an operator can write. These
six questions are where YAML implementations are known to differ, and each has
a security direction. **Measure the current answer and pin it**, still on the
old parser, so the swap has something to be compared against instead of an
opinion.

## First, before any measurement: the version is wrong

**Correction (architect, 2026-10-12), and it invalidates evidence rather than
style.** Unit 316 wired `serde-saphyr` as **`0.0.29`**, because that version
was already in the active build graph as an optional transitive of
`kube-client 4.2.0` (which requires `^0.0.29`, i.e. pinned to that patch line
and never unifiable with 1.x). The appeal was real — one `Cargo.lock` line, no
new `[[package]]`, no new third-party code. It is still the wrong version:

- `serde-saphyr`'s maintained line is **1.3.0** (2026-09-16). `0.0.29` is a
  pre-1.0 version 29 releases back; fixes land on 1.x, not there. Shipping it
  would replace an abandoned component with a stale one, which is most of the
  point of this ticket undone.
- It fails the test this ticket already applied to another candidate:
  `serde_yml` was refused for being `0.0.13` on a `0.0.5` backend. `0.0.29` on
  `granit-parser 0.0.7` is the same objection. "Already in the graph" is
  availability, not suitability.
- **The divergence probe in unit 316's report was run against `0.0.29`**, so
  its four findings and its long agree-list are evidence about a version we
  will not ship.

So: **move the dependency to `1.3.0` first** (default features only — no
`figment`, `figment2`, `validator`, `garde`, `miette`), then do everything
below against that. Two consequences, both accepted:

- `Cargo.lock` will carry **two** `serde-saphyr` versions (kube's `0.0.29` and
  ours `1.3.0`). `deny.toml` sets `multiple-versions = "warn"`, so this is
  visible-but-non-blocking — consistent with the project's standing posture on
  duplicates. **Do not add a `skip` entry**; `skip = []` stays empty, and the
  warning is the honest record.
- The attribution therefore *does* gain crates (the 1.x line's
  `granit-parser` and friends), so unit 319's regeneration covers an addition
  as well as the removal.
- The API may differ from `0.0.29`. If `from_slice` has moved or changed shape,
  report exactly how — that is unit 318's design input, not something to paper
  over.

**Re-run unit 316's harness against `1.3.0` as the first act of this unit.** If
it goes red, that is the most important finding available: the corpus itself
changes meaning under the version we intend to ship, and it must be reported
before anything is pinned.

## Second: the one kind the corpus cannot reach

Unit 316 measured that **`PermissionGrantLintConfig`** has no envelope anywhere
in the repository — ten of eleven kinds are exercised, that one is not. It is a
cluster-wide singleton carrying the grant linter's opt-*out* surface, and every
checked-in tree wants the secure default of its absence (ADR 0015).

**Architect's call: add a targeted two-sided parse of a hand-written envelope
of that kind here, as a test fixture.** Do **not** add an envelope to a
checked-in gitops tree — that would change what the deployed tree means in
order to test a parser. One hand-written document in this unit's own test,
parsed through both sides exactly as the harness does, closes the gap without
touching an operator-visible tree.

## What to measure and pin, one test each

**Unit 316's probe list is a starting point, not an answer** — it was measured
on `0.0.29`. Re-measure each of these on `1.3.0`. Its findings there were: a
merge key into a struct **without** `deny_unknown_fields` silently changes a
value (the only silent divergence, and it landed on `PrefetchPolicy`); merge
keys into a strict struct, surrogate-pair escapes, digit separators (`1_000`)
and a leading BOM all diverge **loudly**, with the replacement being the more
permissive side in every case. It found agreement on duplicate keys, unknown
fields, YAML 1.1 booleans, anchors without merge, block scalars and tags.

1. **Duplicate keys.** Last-wins, first-wins, or an error? Last-wins on a
   permission or policy document is a silent overwrite. The test name states
   the measured answer.
2. **`deny_unknown_fields` across the shapes that break it.** `hort-config`
   relies on it throughout (`service_account.rs` six times,
   `permission_grant.rs` and `scan_policy.rs` three each — re-measure).
   Exercise it on a plain struct, a `#[serde(flatten)]`, an untagged enum and
   an enum variant, because that is where serde implementations diverge. A
   typo'd field name must be rejected; ADR 0015's hard block depends on it.
3. **YAML 1.1 vs 1.2 scalars.** `yes` / `no` / `on` / `off` into a `bool` and
   into a `String`; a leading-zero integer; `~` vs `null` vs an absent key into
   an `Option`.
4. **Anchors, aliases, merge keys, multi-document.** Measured in the tree
   today: one `<<:`, anchors in three files, `---` in 41. Pin that each still
   parses, and pin what happens to an **unbounded alias expansion** — if there
   is no bound, that is a finding for the collector, not something to fix here.
5. **Error shape.** Pin the operator-visible message for the two failures an
   operator actually makes: an unknown field and a type mismatch. These are
   what the apply-time linter surfaces.
6. **`to_string` output.** Pin the serialised form used by the lint path and
   the fixtures (quoting, block style, key order), so unit 318 sees any change
   as a failing test rather than a silent reformat.

## Acceptance

- Six tests (or small groups), each named for the answer it pins, each green on
  the current parser.
- Every answer that turns out to be **weaker than expected** is reported in the
  run's report with its impact — in particular a last-wins duplicate key or an
  unbounded alias expansion. Those become collector entries, not silent
  findings.
- No production call site changes.
- Gate: the **unit gate**, one-shot capture, as in 316.
