# 342 — An undecodable archive entry name

**Issue:** #278 · **Branch:** `agent/278-archive-entry-names-and-client-image`
**Governing decisions:** ADR 0039 D4 as read by #350 (unreadable material is
refused at the door where a door exists, and otherwise not taken into account —
never reinterpreted into an assertion) · ADR 0006 (all archive extraction goes
through the audited extractors) · `deny.toml` `[bans] wrappers` for `zip`.

## 1. What changed under us

`zip` 9 makes `ZipFile::name()` **fallible**: it returns
`Result<Cow<'_, str>, zip::result::ZipError>` instead of `&str`. The reason is
in the format: a ZIP entry name need not be UTF-8. The new signature forces
every caller to say what it does with a name it cannot decode.

The crate is read at three sites; two are production:

| Site | What the name decides |
|---|---|
| `crates/hort-formats/src/archive_bounds.rs:453` | **which entry a format handler reads** — `*.dist-info/METADATA`, the POM, an OSV feed member |
| `crates/hort-adapters-scanner-trivy/src/extract.rs:418` | **a filesystem path** under the extraction root, checked by `contained_relative_path` |
| `crates/hort-formats/src/test_support.rs:109` | `#[cfg(test)]` only |

Both one-line escapes are wrong, and identically so: `unwrap_or_default()`
invents an empty name, `to_string_lossy()` invents one carrying U+FFFD. Each
turns input we could not read into a claim about what it said.

## 2. One rule, two halves — and which half applies is decided by the door

The rule is the one #350 settled: unreadable material is refused at the door
where a door exists, and otherwise left out of the reckoning. The two sites get
different answers because only one of them is standing at a door.

**`archive_bounds::iter_zip_entries` has no door.** The archive is already
accepted for ingest, and the only thing this loop does is find entries a
handler asked for by name. Refusing the whole artifact because some unrelated
entry carries a CP437 name would reject correct artifacts over a fact nobody
needs. So: **skip the entry, and count the skip.** It is then handled exactly
as an entry that breaches the size bounds. If the skipped entry *was* the one
the handler wanted, the handler fails on its own terms ("no METADATA found")
rather than reading something else under an invented name.

**`extract_zip` is standing at one, and already uses it.** The name becomes a
path, and a name that fails `contained_relative_path` refuses the **whole
archive** (`ExtractError::UncontainedPath`) rather than dropping one entry. A
name we cannot evaluate against that rule at all is not a weaker case than one
that fails it. And a silent skip would have a consequence it does not have in
the metadata path: the scanner would then judge a tree with a file missing from
it that nobody looked at — a "clean" spoken over unexamined material. **So:
refuse the archive**, with its own error variant.

## 3. The skip has to be legible where the conclusion changes

`iter_zip_entries` returns `Result<(), ZipIterError>` today, and four
production callers consume it (`pypi.rs:397`, `pypi.rs:1187`,
`maven/mod.rs:729`, `hort-adapters-advisory-osv/src/bulk.rs:232`).

A `warn!` inside the helper is **not** sufficient, and the reason is not
severity but attribution: `iter_zip_entries` does not know which artifact it is
reading, so a log line from inside it cannot be correlated with the conclusion
it changed. The entity that has to be able to explain "this wheel has no
METADATA" is the handler.

**So the count travels in the `Ok` value** — `iter_zip_entries` returns a small
stats struct carrying the number of entries skipped for an undecodable name,
and at minimum the PyPI metadata reader names it in its not-found diagnosis. A
log line in addition is fine; it does not replace this.

Nothing attacker-controlled goes into a message. The module already states that
rule for `BoundsError::NestedArchiveRejected`; the entry **index** and the
decode-error kind are enough, the raw bytes are not reproduced.

## 4. A probe that does not fail proves nothing — corrected after measurement

**This section originally predicted a condition that does not exist, and the
correction is the more interesting result.** It said: with general-purpose bit
11 (the UTF-8 flag) clear, `zip` decodes the name as CP437 and every byte
sequence succeeds, so a probe must set bit 11 to make `name()` return `Err`.

Measured against `zip` 9.0.3, in its own source and by running it:

- `ZipFileData::name` (`src/types.rs:122`) **never consults bit 11**. It tries
  UTF-8 and otherwise calls `from_cp437`.
- `from_cp437` (`src/cp437.rs`) is **total**. Its mapping enumerates all 256
  byte values, 128 of them for `0x80..=0xff`, and **none maps to an ASCII
  character**. Its single error path is a `from_utf8` over an all-under-`0x80`
  slice, which cannot fail — and is unreachable anyway, since the function is
  only entered after `from_utf8` already failed, which requires a byte
  `>= 0x80`.

So **`ZipFile::name()` is fallible in signature and unconditionally `Ok` in
body**: no archive makes it return `Err`, with or without bit 11.

The two fail-closed arms in §2 are therefore correct and currently
*unreachable*. They stay — the signature demands a decision and that decision
is the one §2 argues for — and each probe becomes a **tripwire** instead of a
demonstration: it builds the crafted entry faithfully (invalid UTF-8 name bytes
in both the local header and the central directory, bit 11 set in both) and
asserts what `zip` 9.0.3 actually does, naming in its failure message the arm
that becomes live if a future version makes the decode fail. A probe asserting
`Err` would assert a condition no input can produce, and the only way to make
it pass would be to delete the assertion.

One probe per production site, pinning the measured behaviour:

- `archive_bounds` — the invented name is offered to the visitor and the skip
  count is zero, with a sibling entry still visited.
- `extract_zip` — a file is materialised under the transliterated path.

**The hazard §1 names is real and lives in the `Ok` branch**, not behind the
`Err` branch this item was scoped to: a non-UTF-8 name is CP437-transliterated
and both sites act on the transliteration. Its reach is bounded, measured: no
high byte maps to ASCII, so the transliteration cannot introduce `/` or `..`
and cannot produce an ASCII-only name — path containment sees the same
structure the raw bytes had, and a transliterated name can never equal an
ASCII target such as `METADATA`. Closing it properly means hort checking bit 11
itself (bit 11 set + bytes not UTF-8 = the producer contradicting itself), an
ingest-behaviour change outside this item.

## 5. Acceptance

- `zip` is at 9 in `Cargo.toml` and `Cargo.lock`; the workspace compiles and is
  clippy-clean with `-D warnings`.
- Both production sites state the decision in a comment that gives the
  **invariant**, not its provenance.
- `iter_zip_entries` reports skipped-undecodable-name entries to its caller;
  the PyPI metadata reader's not-found path names it.
- `extract_zip` refuses the archive on an undecodable name, through an error
  variant of its own rather than a reused `Malformed` string.
- Both probes exist, build the crafted entry faithfully, and assert the
  behaviour measured in §4 — including that the skip count is zero — so a
  change in `zip`'s decoding turns them red.
- No other behaviour moves: bounds, caps, nested-archive rejection, containment
  and symlink handling are untouched.

## 6. Not in this item

- **Attribution regeneration.** The bump adds `nix` to `Cargo.lock`, so
  `THIRD-PARTY-LICENSES.{md,json}` must be regenerated before the MR — that is
  the architect's step on this branch, not this unit's.
- Any change to `deny.toml`'s wrapper list. The two permitted extractor homes
  stay the two permitted extractor homes.
