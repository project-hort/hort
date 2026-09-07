# Item 157 — cargo index `pubtime`: emit cargo's exact wire format

**Issue:** #225 · **Branch:** `agent/225-pubtime-wire-format`
**Read first:** `crates/hort-formats/src/cargo/index.rs` (builder, module rustdoc + `build()`),
`crates/hort-app/src/use_cases/index_serve.rs` (`CargoVersionPayload` docs),
`crates/hort-formats/src/cargo/projection.rs` (`CargoVersionLine::pubtime` docs),
`crates/hort-http-cargo/src/serve.rs` (pubtime tests around lines 1120–1260 and 1543)

## Context / root cause

cargo has a **typed `pubtime` index field since 1.93** (`cargo-util-schemas`
`IndexPackage.pubtime: Option<jiff::Timestamp>` with a custom `serde_pubtime`
deserializer). The accepted wire format is a **strict subset of ISO 8601:
exactly `yyyy-mm-ddThh:mm:ssZ`** — 20 characters, zero-padded, `Z` only (no
timezone offsets), no fractional seconds.

Hort's cargo sparse-index builder emits `DateTime::<Utc>::to_rfc3339()`
(`crates/hort-formats/src/cargo/index.rs`, the single production emission
point). That renders `2026-08-20T09:09:56+00:00` — an offset instead of `Z` —
and, for Postgres-sourced timestamps with sub-second precision, fractional
seconds on top. Both violate cargo's parser. In cargo, a field-level parse
failure invalidates the **whole index line** (`IndexSummary::Invalid`), and
the resolver reports "version X's index entry is invalid" for whichever
version resolution needs. Net effect: every served line carrying a `pubtime`
(every locally ingested version — hosted, proxy, and virtual passthrough) is
invalid for every cargo ≥ 1.93 client.

The current unit tests are green because they pin `to_rfc3339()` — the
implementation is self-consistent but protocol-incorrect. The protocol schema
(cargo's `cargo-util-schemas`) is authoritative.

Reality check that anchors the target format: crates.io itself now serves
`pubtime` on every index line in exactly the strict `Z` format (e.g.
`https://index.crates.io/bl/ak/blake3`), and the in-repo E2E fixtures
(`scripts/native-tests/fixtures/cargo-upstream/__files/cfg-if-index.ndjson`)
already carry that shape.

## Changes

1. **`crates/hort-formats/src/cargo/index.rs` — `CargoIndexBuilder::build()`**:
   emit `pubtime` as cargo's exact wire format. UTC value, seconds precision,
   `Z` suffix: `pubtime.format("%Y-%m-%dT%H:%M:%SZ")` (chrono's UTC formatter;
   sub-second precision is truncated by the format string). Update the
   module-level rustdoc `# pubtime` section: the format contract is cargo's
   `serde_pubtime` subset-ISO 8601, not RFC 3339.
2. **Doc-comment truth sweep** (no behavior change): the claims that "no cargo
   registry serves this field today" are overtaken — crates.io serves it. Fix
   the doc comments on `CargoVersionLine::pubtime`
   (`crates/hort-formats/src/cargo/projection.rs`),
   `CargoVersionPayload::pubtime` and the payload struct-level docs
   (`crates/hort-app/src/use_cases/index_serve.rs` — "RFC 3339 UTC" → cargo's
   subset format), and the builder rustdoc. State the invariant (cargo parses
   the field strictly; a bad value invalidates the whole line), not the
   history.
3. **Tests — pin the protocol, not the producer:**
   - Builder test (in `index.rs`): served `pubtime` value matches
     `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` **including for an input
     timestamp with microseconds** (the Postgres case) — this is the
     regression the old `to_rfc3339` pin missed. Assert the exact expected
     string for a known input, e.g. `2026-08-20T09:09:56.123456Z` (input) →
     `"2026-08-20T09:09:56Z"` (wire).
   - Update the existing pins: `crates/hort-http-cargo/src/serve.rs` (the
     hosted/virtual pubtime tests and the `json!` fixture near line 1543
     currently compare against `to_rfc3339()`); any builder tests in
     `index.rs` that do the same. Comparisons of a *parsed* `DateTime` value
     (`projection.rs` round-trip test) may keep `to_rfc3339` — only the
     emitted wire bytes are contractual.
4. **Out of scope (explicit):**
   - No change to the pubtime *source precedence*. crates.io now serving
     `pubtime` natively means the proxy should eventually pass the upstream
     line value through (`CargoVersionLine::pubtime`, today deliberately
     unread) — that is a design amendment to the #217 precedence, specified
     separately, not part of this format fix.
   - No config knob. The field stays unconditional; only its format changes.

## Acceptance

- Every emitted `pubtime` in the served cargo sparse index is exactly
  `yyyy-mm-ddThh:mm:ssZ` (20 chars), for hosted, proxy, and virtual, including
  microsecond-precision inputs.
- New regression test pins the wire format by regex/exact string, not via
  `to_rfc3339()`.
- Doc comments no longer claim RFC 3339 for the wire format nor that no
  registry serves the field.
- Full gate green: `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`,
  `cargo deny check`.
- No changes outside the files named in *Changes* (plus their tests).
