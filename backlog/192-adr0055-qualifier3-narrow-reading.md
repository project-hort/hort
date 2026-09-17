# 192 — ADR 0055 qualifier 3: resolution documents only; refusal reasons are diagnostics, not access

**Issue:** #255 · **Branch:** `agent/255-adr0055-qualifier3` · single item · **documentation only**
(one ADR, one docstring). Decision (human, 2026-09-13 on #254): the narrow reading holds.

## Problem

ADR 0055 qualifier 3 says a terminal verdict (`Rejected`, `ScanIndeterminate`) "stays hidden from
every caller, publisher included" — absolute wording. The built behaviour never was: every byte
route answers `Quarantined` with `503 {"error":"artifact is quarantined"}` + `Retry-After` and a
terminal verdict with `403 {"error":"artifact is rejected"}` to any caller holding `Read`
(`hort-http-npm/src/lib.rs` ~456, `hort-http-maven/src/lib.rs` ~495/504, `hort-http-cargo/src/lib.rs`
~435/443, `hort-http-pypi/src/metadata_endpoint.rs` ~457, `hort-http-oci/src/error.rs` ~327);
`render_artifact_response` takes an `actor` and never consults it. Qualifier 2 already scopes
"metadata" to *the resolution document a client reads to learn a version exists and what its bytes
hash to*, and the "Enforced by" list names exactly those surfaces. Only the one sentence in
qualifier 3 overreaches. The wide reading (answer `404` for a rejected artifact) is rejected — it
would replace "we withhold this" with "this does not exist", the confusion #251 removed elsewhere.

## Change (text only)

1. **Qualifier 3**: the sentence governs resolution documents — a terminal verdict makes the version
   unresolvable there for everyone, publisher included. It does **not** govern the refusal reason:
   the byte routes name `Quarantined` and the terminal verdicts to every `Read`-authorized caller,
   deliberately, and npm's `hort.held` block is the same information in enumerable form.
2. **State the boundary positively**: resolvability is gated, diagnosability is not. *What* a
   caller can obtain depends on authority; *why* they cannot obtain it is information, not access.
3. **Name enumerability as an accepted consequence** (#251's one real addition): previously a
   caller needed the version number to ask; now the list is served. For a proxy those numbers are
   upstream's; for a hosted repository a `Read` holder learns a number they could not have
   guessed. Accepted knowingly; belongs in the ADR, not in an MR footnote.
4. **"Enforced by"**: add `crates/hort-formats/src/npm/index.rs` (`HeldReason` / `HeldVersion`)
   and `crates/hort-http-npm/src/serve.rs` (`collect_held`).
5. **`serve_npm_version_unified` docstring** (`crates/hort-http-npm/src/serve.rs`): the claim
   "unknown tag, unknown version, held version, unknown package, and invisible repo are therefore
   indistinguishable on the wire" stays true for the abbreviated version route and is no longer
   true for the packument — delimit precisely, do not delete.

## Must not change

Qualifiers 1 and 2; any byte route; any other format (a `hort.held` equivalent for PyPI/Maven/Cargo
is a separate question). No code beyond the docstring.

## Acceptance

- Qualifier 3 distinguishes resolution document from refusal reason; enumerability is recorded as a
  consequence; "Enforced by" names the npm sites; the docstring delimits packument vs. abbreviated
  route; ADR and byte routes read side by side show no contradiction.
- Gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (docstring change compiles into the crate), `cargo-audit audit -D warnings`,
  `cargo-deny check`. No `CHANGELOG.md` entry (documentation of existing behaviour).
