# 320 — A comment block must not fail the boot

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Governing decisions:** ADR 0015 (operator-facing config surfaces fail loudly
and for stated reasons), and this ticket's own promise that the swap preserves
semantics.

## The finding, measured in unit 319

Through the **production** entry point (`hort_config::parse_repository`), on a
complete `ArtifactRepository` envelope:

```
leading run  31 lines: accepted
leading run  32 lines: accepted
leading run  33 lines: yaml parse error: too many consecutive comments before
                       resolving collection entry at line 38, column 3
between-entries run  33 / 64 / 200 lines: all accepted
```

So **33 or more consecutive comment lines immediately before a collection's
first entry are rejected**, while the same run between two entries has no limit
at all. The retired parser had no such budget anywhere.

This is a fifth operator-visible change the swap introduced, and it is the one
that best fits the ticket's own worry: a tree that booted yesterday fails
today. A heavily-commented hand-written envelope is exactly where it lands, the
position dependence makes it look arbitrary from outside, and the message
suggests no remedy.

## The decision: close it, do not document it

**hort consumes no YAML comments.** Every parse deserialises into a typed
envelope; a comment is never data on this path. A budget that rejects an
operator's comment block in one syntactic position, with a message that offers
no remedy, is not a safety property we gain — it is a failure we would be
asking operators to work around. Writing it into the changelog instead of
closing it is defending against the gap rather than closing it.

So the changelog's operator-impact list stays at four bullets, because after
this unit there is no fifth change.

## What to do

1. **Find the knob and measure it, do not assume it.** Unit 319 suggested
   `emit_comments: false` in `gitops_options()`. Verify that it actually
   removes the budget rather than merely suppressing comment *collection*: the
   budget may be counted during parsing regardless. Measure, in **both**
   positions, runs of **31, 32, 33, 64 and 200** lines, through
   `parse_repository` — the production entry point, not a test-only parser
   construction.
2. **If `emit_comments: false` closes it**, set it in the single `Options`
   definition (`crates/hort-config/src/yaml.rs`) with the derivation written
   there: hort reads no comments, so collecting them buys nothing and the
   budget they bring costs an operator their file.
3. **If it does not close it**, stop and report before changing anything else.
   A budget we cannot disable is a different decision — raising it, or
   accepting it with a changelog bullet and a better error — and it is not
   yours to pick.
4. **Pin it.** A test with a comment run comfortably past the old limit in the
   failing position (say 64 lines before the first entry) that parses, named
   for the property rather than the number. Include the between-entries
   position too, so a future `Options` change that re-introduces a budget in
   either position goes red.

## Explicitly out of scope

- Any other `Options` change. The four decided flags stand.
- Comment *preservation* on re-emit. hort does not round-trip operator files.
- The `RetentionPolicySpec::predicate` question and the `#[cfg(test)]`
  conversions — both settled or separately decided.

## Acceptance

- A 64-line comment run immediately before a collection's first entry parses
  through `parse_repository`.
- The between-entries position still parses at 200 lines.
- The test is named for the property and fails if the flag is removed from
  `gitops_options()`.
- The semantics tests and the four changelog bullets are unchanged — **no new
  changelog entry**, because the change this unit removes is the one that would
  have needed one.
- `cargo deny check` still green; `.cargo/audit.toml` and `deny.toml` still
  untouched.
- Gate: the **unit gate**, one-shot capture,
  `bash handover/gate-unit.sh -p hort-config`. Judge by the output, not the rc.
