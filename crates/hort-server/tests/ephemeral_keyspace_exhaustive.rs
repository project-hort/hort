//! # Keyspace exhaustiveness CI gate.
//!
//! This integration test is the **load-bearing safety net** that
//! converts "remember to register your keyspace" from a code-review
//! item into a CI gate. It walks every Rust source file under
//! `crates/`, finds every write-side `EphemeralStore` call site, and
//! asserts the constructed key matches at least one prefix in
//! [`hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY`]. A new keyspace
//! introduced without a registry edit fails the test.
//!
//! ## What the walker does
//!
//! For each `.rs` file under `crates/` (skipping `target/`, `.git/`,
//! and this test file itself), the walker scans for the five
//! write-side `EphemeralStore` method names — `put`, `put_if_absent`,
//! `compare_and_swap`, `try_increment_counter`, `extend_ttl` — and for
//! each match attempts to extract the first argument expression.
//!
//! The receiver filter is **heuristic**: a call site is checked when
//! its receiver expression either (a) contains the substring
//! `ephemeral` (case-insensitive — matches
//! `ctx.ephemeral_evictable.put(...)`,
//! `mocks.ephemeral_durable.compare_and_swap(...)`,
//! `self.ephemeral.try_increment_counter(...)`, and the bare
//! `ephemeral.put_if_absent(...)` parameter pattern in
//! `maybe_append_auth_event`), or (b) is on the small explicit
//! allowlist of `EphemeralStore`-typed receivers whose names lack
//! "ephemeral" in source — today only `gate.store` (the
//! `LockoutGate::store: Arc<dyn EphemeralStore>` field in
//! `crates/hort-app/src/use_cases/authenticate_use_case.rs`). A method
//! named `put` exists on many types (axum `Router`, `Storage`,
//! builders, etc.); the explicit allowlist plus the "ephemeral" word
//! filter together exclude all known false positives while reaching
//! every known real `EphemeralStore` write site. Adding a new
//! ambiguous receiver shape (e.g. `gate.events.put(...)`) requires
//! extending [`RECEIVER_ALLOWLIST`] with a comment naming the type
//! it resolves to.
//!
//! ## First-argument extraction
//!
//! Five statically-resolvable shapes are supported:
//!
//! 1. **String literal** — `.put("foo:bar", ...)`. The literal is
//!    used verbatim.
//! 2. **`format!("prefix...{...}", …)`** — the substring up to the
//!    first `{` is extracted. `{{` (a literal brace) is treated as
//!    not-an-interpolation and the search continues; in practice no
//!    `EphemeralStore` key starts with literal `{`, so the simple
//!    "first `{`" rule never produces a false positive today.
//! 3. **`format!("{CONST}{...}", …)` where `CONST` is a
//!    file-local `const`** — the const is resolved by scanning the
//!    same file for a matching `const IDENT: &str = "...";` line and
//!    its value used as the prefix. Used by lockout keys built via
//!    `format!("{LOCKOUT_COUNTER_PREFIX}{...}")` etc.
//! 4. **`&IDENT` or `IDENT`** where `IDENT` is bound by a
//!    `let IDENT = format!("...")` / `let IDENT = "..."` /
//!    `let IDENT = func_name(...)` earlier in the same file — the
//!    binding is resolved by scanning forward; the most recent
//!    binding wins. When the RHS is a function call to a same-file
//!    `fn func_name`, the body is recursively scanned for its
//!    `format!(...)` return value (one level of indirection).
//! 5. **`&IDENT.field`** where `field` is a struct field assigned by
//!    `field: format!("...")` somewhere in the same file — the
//!    field's format-string prefix is used. This handles
//!    `LockoutKeys { counter_key: format!("..."), flag_key: ... }`
//!    patterns where the call site reads `&keys.counter_key`.
//!
//! Anything else — cross-file `const` references, function calls
//! whose body is not in the same file, and runtime-only string
//! constructions — is classified as **dynamic** and contributes to
//! the dynamic-warning counter rather than producing a hard failure.
//!
//! ## Maintenance
//!
//! - **Adding a new keyspace.** Add the prefix to
//!   `crates/hort-app/src/ephemeral_keyspace.rs` and re-run this test.
//!   The test passes once the new prefix is registered; reviewers know
//!   the registry stayed exhaustive.
//! - **Adding a write site whose key cannot be statically resolved.**
//!   If the new call site appears as a fresh "dynamic" warning, raise
//!   [`EXPECTED_DYNAMIC_COUNT`] by 1 AND add a comment in the
//!   `expected_dynamic_call_sites` list naming the file:line and the
//!   reason it cannot be made static (e.g. "key returned by
//!   cross-file helper `session_key()`"). If you are tempted to bump
//!   the count without justification, prefer making the key
//!   statically resolvable instead — that is what keeps the gate
//!   sharp.
//! - **Removing a write site.** If the removed site was on the
//!   dynamic list, drop the count by 1 and remove the corresponding
//!   comment line.
//! - **Failure-mode discipline.** This test was verified against a
//!   deliberately-introduced unregistered prefix during PR
//!   development; the failure path is exercised, not merely
//!   asserted-into-existence. If you suspect the gate has stopped
//!   firing, repeat the exercise: add a `format!("never_registered:
//!   {x}", ...)` key on an `ephemeral` receiver in any source file,
//!   run the test, confirm it fails with a file:line + prefix error
//!   message, then revert.
//!
//! ## Why no `regex` / `walkdir` dep
//!
//! The walker uses `std::fs::read_dir` recursively and string-only
//! parsing. The expression "first arg of `.method(`" is extractable
//! by following balanced parens / brackets / braces / quotes — well
//! within what hand-rolled scanning can do safely, and avoids
//! introducing a `regex` dev-dep just for this test.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use hort_app::ephemeral_keyspace::keyspace_class;

/// Number of write-side call sites whose key the walker cannot
/// statically resolve even with same-file const / let / function /
/// struct-field resolution. Each entry on the list below names a
/// file:line that produced one dynamic warning when this test was
/// authored. Bumping this constant without adding a justified
/// comment for the new entry is a review red flag.
///
/// **The current dynamic call sites** (file:line :: reason):
///
/// 1. `crates/hort-app/src/use_cases/authenticate_use_case.rs:1253`
///    (`gate.store.put(key, ...)` in `fn increment_counter`) — the
///    helper takes `key: &str` as a parameter and passes it through
///    verbatim. Inter-procedural key flow is out of scope for the
///    walker; real callers always pass `&keys.counter_key` or
///    `&ip_keys.counter_key`, both of which the registry's
///    `auth:lockout:` head prefix subsumes. The boundary case is
///    independently exercised by the `auth_lockout_resolves_to_durable`
///    unit test in `crates/hort-app/src/ephemeral_keyspace.rs` plus the
///    statically-resolved sister write site at line 1042 in this
///    same file (`gate.store.put(&keys.flag_key, ...)`, allowlisted
///    via `RECEIVER_ALLOWLIST` and resolved via struct-field flow
///    on the `LockoutKeys` definition).
/// 2. `crates/hort-http-oci/src/uploads.rs:2266`
///    (`h.ctx.ephemeral_durable.put(&key, ...)`, where
///    `let key = upload_session::session_key("oci", session_id)`) —
///    the function call is **module-qualified** (`upload_session::session_key`),
///    and the walker's `fn` resolver only follows same-file
///    function definitions. The same prefix is verified through the
///    in-module sites in `crates/hort-http-oci/src/upload_session.rs`
///    (which DO statically resolve via the same-file `fn session_key`).
/// 3. `crates/hort-app/src/pull_dedup.rs:792` (`self.ephemeral.put(&key.serialised, ...)`),
/// 4. `crates/hort-app/src/pull_dedup.rs:814` (`self.ephemeral.put_if_absent(&key.serialised, ...)`),
/// 5. `crates/hort-app/src/pull_dedup.rs:926` (`self.ephemeral.put(&key.serialised, ...)`).
///    All three call sites pass `&key.serialised` where `key:
///    &DedupKey` is a function parameter. `DedupKey::serialised` IS
///    constructed in this same file via
///    `let serialised = format!("pulldedup:meta:{...}", ...)` (and
///    `pulldedup:blob_by_url:`, `pulldedup:blob_by_hash:`) inside the
///    constructors, but the walker's struct-field resolver does not
///    follow constructor calls that return a struct. The
///    `pulldedup:` prefix is therefore registered as forward-blind
///    in [`FORWARD_REGISTERED_PREFIXES`]. Refactoring the call sites
///    to format the key inline (`let key = format!("pulldedup:meta:
///    {...}", ...); self.ephemeral.put(&key, ...)`) would let the
///    walker resolve the prefix and graduate `pulldedup:` out of
///    `FORWARD_REGISTERED_PREFIXES`; that is a worthwhile follow-up
///    for the pull-dedup implementation but is intentionally not
///    bundled here.
///
/// See the printed warnings on `--nocapture` for the exact file:line
/// list. The runtime count is asserted against this constant.
// Dropped from 5 → 4 when `authenticate_local`'s
// `record_failed_attempt` chain was deleted (the
// `increment_counter` helper had a `key: &str` write site that the
// walker classified as dynamic).
const EXPECTED_DYNAMIC_COUNT: usize = 4;

/// Prefixes that are registered in `KEYSPACE_REGISTRY` but not yet
/// reachable from any write-side call site. Today only `pulldedup:`
/// is here — pull-through deduplication registers it forward; the
/// first writes against it land with the pull-dedup implementation.
const FORWARD_REGISTERED_PREFIXES: &[&str] = &["pulldedup:"];

/// Writable methods on `EphemeralStore` that this walker scans for.
const WRITE_METHODS: &[&str] = &[
    "put",
    "put_if_absent",
    "compare_and_swap",
    "try_increment_counter",
    "extend_ttl",
];

/// Explicit allowlist of receiver expressions that ARE
/// `EphemeralStore` write sites but lack the substring "ephemeral"
/// in their identifier. Each entry's comment must name the type the
/// receiver resolves to, so a future contributor can spot a
/// misclassification on review. Adding to this list relaxes the
/// walker's heuristic — do it only when grep confirms the new
/// receiver shape is exclusively bound to an `Arc<dyn
/// EphemeralStore>` field.
///
/// Today: three entries.
///
/// 1. `gate.store` is the `LockoutGate::store: Arc<dyn EphemeralStore>`
///    field used by `crates/hort-app/src/use_cases/authenticate_use_case.rs`
///    for the per-username lockout counter / flag writes
///    (lines ~994, 1014, 1041, 1054, 1253, 1262 today).
/// 2. `self.cache` is the `OsvAdvisoryAdapter::cache: Arc<dyn
///    EphemeralStore>` field used by
///    `crates/hort-adapters-advisory-osv/src/lib.rs` for the OSV
///    advisory-batch result cache (see
///    `docs/architecture/explanation/scanning-pipeline.md`). Verified workspace-
///    wide: `self.cache.put(...)` is exclusively bound to this
///    `EphemeralStore` field. Other `self.cache.*` receivers in the
///    workspace (e.g. `PatValidationUseCase.cache`) use `.insert` /
///    `.get` rather than the ephemeral write methods this walker
///    scans, so the allowlist remains precise.
/// 3. `cache` (bare identifier) is the `cache: &dyn EphemeralStore`
///    parameter on the three per-format `fetch_raw_with_cache`
///    helpers (cycle-avoidance signature refactor — see
///    `crates/hort-http-npm/src/packument.rs`,
///    `crates/hort-http-pypi/src/simple_index.rs`,
///    `crates/hort-http-cargo/src/index_cache.rs`). Verified workspace-
///    wide: the three helpers are the ONLY functions in the workspace
///    that take a bare `cache` parameter typed as `&dyn EphemeralStore`
///    and call write methods on it. The cycle-avoidance refactor
///    rationale requires this shape — `Arc<AppContext>`
///    cannot be threaded through (composition-root construction
///    cycle), so the explicit `&dyn` parameter is the supported
///    surface.
const RECEIVER_ALLOWLIST: &[&str] = &["gate.store", "self.cache", "cache"];

// ---------------------------------------------------------------------------
// Walker
// ---------------------------------------------------------------------------

/// Discovered write-side call site in the workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallSite {
    file: PathBuf,
    line: usize,
    method: String,
    /// Verbatim receiver expression as it appears in source, with
    /// trailing whitespace trimmed.
    receiver: String,
    /// Outcome of first-argument extraction.
    extraction: Extraction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Extraction {
    /// Statically-resolved prefix. The string is the prefix used for
    /// `keyspace_class` lookup.
    Static(String),
    /// Could not be statically resolved.
    Dynamic { raw_first_arg: String },
}

/// Recursively collect every `.rs` file under `root`, excluding
/// `target/` and `.git/` directories and this test file itself.
fn collect_source_files(root: &Path, self_path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, self_path, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, self_path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if file_name == "target" || file_name == ".git" || file_name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            walk(&path, self_path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // Skip the test file itself — its assertion strings
            // would otherwise self-match.
            if path == self_path {
                continue;
            }
            out.push(path);
        }
    }
}

/// Scan a source string for write-side `EphemeralStore` call sites.
fn scan_file(source: &str, path: &Path) -> Vec<CallSite> {
    let mut out = Vec::new();
    for method in WRITE_METHODS {
        // Look for `.METHOD(` token sequence. `find_all_occurrences`
        // returns byte-offset starts of `.METHOD(` in the source.
        let needle = format!(".{method}(");
        let mut search_from = 0usize;
        while let Some(rel_idx) = source[search_from..].find(&needle) {
            let dot_idx = search_from + rel_idx;
            let paren_idx = dot_idx + needle.len() - 1;
            search_from = dot_idx + 1;

            // Confirm the byte before `.` is a non-identifier char so
            // we don't match things like `mismatch_method.put(` where
            // `_method` doesn't matter — but also so we don't match
            // identifier suffixes like `lput` becoming `.put(`. Wait:
            // `.METHOD(` already requires a literal `.` before METHOD,
            // so the ident-suffix concern doesn't apply. We also need
            // to confirm the char AFTER METHOD is `(` (already
            // enforced by the needle).
            //
            // What we DO need to guard: `.put_if_absent(` shouldn't
            // also be flagged as `.put(` — Rust's `.put_if_absent`
            // contains `put` followed by `_`, not `(`, so the needle
            // `.put(` won't match it. Good.

            // Skip if this match is inside a comment line, a doc
            // comment, or a string literal. Check the line and
            // confirm the dot isn't preceded by `//` or `///` after a
            // preceding line break.
            if is_in_comment_or_string(source, dot_idx) {
                continue;
            }

            // Recover the line number.
            let line_no = source[..dot_idx].bytes().filter(|b| *b == b'\n').count() + 1;

            // Walk back to find the receiver expression.
            let receiver = extract_receiver(source, dot_idx);
            let lc = receiver.to_lowercase();
            let receiver_ok = lc.contains("ephemeral")
                || RECEIVER_ALLOWLIST
                    .iter()
                    .any(|allowed| receiver == *allowed);
            if !receiver_ok {
                continue;
            }

            // Scan forward to find the first argument expression
            // delimited by the matching close-paren or the first
            // top-level `,`.
            let Some(first_arg) = extract_first_arg(source, paren_idx) else {
                continue;
            };

            let extraction = classify_first_arg(source, &first_arg, dot_idx);

            out.push(CallSite {
                file: path.to_path_buf(),
                line: line_no,
                method: (*method).to_string(),
                receiver,
                extraction,
            });
        }
    }
    out
}

/// Heuristic comment / string detection: walk backward from `idx`
/// to the previous newline; if a `//` appears in that range NOT
/// inside a string, the position is in a line comment. Block
/// comments (`/* ... */`) and string-literal handling are simpler:
/// we count unescaped `"` characters since the start of the file —
/// odd count means the position is inside a string.
///
/// This is conservative — false positives (skipping a real call)
/// would be silent failures, so the implementation errs toward
/// INCLUDING uncertain matches. The walker further filters by
/// "ephemeral" in the receiver, which gives a second layer of
/// false-positive defense. Block-comment handling is the one
/// concession: `/* .put( */` would pass through as a real call,
/// but we have no `/* */` blocks containing fake `.put(` calls in
/// the tree today.
fn is_in_comment_or_string(source: &str, idx: usize) -> bool {
    // 1. Check line comment: walk back to previous newline, look
    //    for `//`.
    let line_start = source[..idx].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_prefix = &source[line_start..idx];
    if let Some(comment_idx) = line_prefix.find("//") {
        // Confirm the `//` itself isn't inside a string literal on
        // this line.
        let pre = &line_prefix[..comment_idx];
        if !is_inside_string(pre) {
            return true;
        }
    }
    // 2. Check string literal — count unescaped `"` since the most
    //    recent line break (string literals usually don't span
    //    lines in Rust outside of raw strings; treating the start
    //    of the line as the boundary is conservative enough).
    if is_inside_string(line_prefix) {
        return true;
    }
    false
}

/// Returns true when `prefix` ends inside an open `"..."` string
/// literal — i.e. an odd count of unescaped `"` characters.
fn is_inside_string(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && in_str {
            // Skip escape sequence — `\\`, `\"`, `\n`, etc.
            i += 2;
            continue;
        }
        if c == b'"' {
            in_str = !in_str;
        }
        i += 1;
    }
    in_str
}

/// Walk back from `dot_idx` to recover the receiver expression. The
/// expression is everything between the `.` and the start of the
/// chain — typically a sequence of identifiers, dots, and possibly
/// whitespace / newlines. We grab the last "word group" — the
/// continuous sequence of identifier characters and `.` separators,
/// possibly preceded by whitespace.
///
/// For chained syntax like
/// ```text
///     ctx
///         .ephemeral_durable
///         .put(...)
/// ```
/// the receiver string we return is `ctx.ephemeral_durable` (with the
/// chain dots and intermediate identifiers).
fn extract_receiver(source: &str, dot_idx: usize) -> String {
    // Walk back from dot_idx-1 over whitespace, identifier characters,
    // and inner dots. Stop at any other character (operator,
    // semicolon, paren, brace, etc.).
    let bytes = source.as_bytes();
    let mut i = dot_idx;
    // We want characters strictly before the dot at dot_idx — start
    // by stepping over the dot itself.
    while i > 0 {
        i -= 1;
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            continue;
        }
        if c.is_ascii_whitespace() {
            // Consume whitespace inside a chain — but only if the
            // previous non-whitespace char was identifier-like or a
            // dot. Probe back over more whitespace.
            continue;
        }
        // Hit a non-receiver char (`(`, `;`, `=`, `&`, etc.).
        i += 1;
        break;
    }
    let raw = &source[i..dot_idx];
    // Collapse internal whitespace so the receiver string is single-line.
    raw.split_whitespace().collect::<Vec<&str>>().join("")
}

/// Returns the substring of the first argument expression starting
/// at `paren_idx` (the index of the `(` that opens the call). The
/// returned string is the verbatim first argument, with leading
/// whitespace trimmed and trailing whitespace stripped at the first
/// top-level `,` or matching `)`.
fn extract_first_arg(source: &str, paren_idx: usize) -> Option<String> {
    let bytes = source.as_bytes();
    if paren_idx >= bytes.len() || bytes[paren_idx] != b'(' {
        return None;
    }
    // Walk forward, tracking nesting in `(` `[` `{` and string state.
    let start = paren_idx + 1;
    let mut depth_paren = 0i32;
    let mut depth_brack = 0i32;
    let mut depth_brace = 0i32;
    let mut in_str = false;
    let mut in_char = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            if c == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if c == b'\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'\'' => {
                // Lifetime annotations (`'a`, `'static`) are NOT
                // char literals; ditch the char-literal tracker if
                // the next char is alphabetic and the one after
                // isn't `'`. Conservative: we only enter char-state
                // when the char looks like an actual char literal
                // (next two chars are `X'` or `\X'`).
                if i + 2 < bytes.len() && bytes[i + 2] == b'\'' {
                    in_char = true;
                }
                // Otherwise leave in_char=false and continue.
            }
            b'(' => depth_paren += 1,
            b')' => {
                if depth_paren == 0 && depth_brack == 0 && depth_brace == 0 {
                    // End of the call args — first arg is the only arg.
                    return Some(source[start..i].trim().to_string());
                }
                depth_paren -= 1;
            }
            b'[' => depth_brack += 1,
            b']' => depth_brack -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b',' => {
                if depth_paren == 0 && depth_brack == 0 && depth_brace == 0 {
                    return Some(source[start..i].trim().to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Given the verbatim first-argument expression, classify it as a
/// statically-resolvable prefix or a dynamic key. `call_offset` is
/// the byte offset of the call site within `source`; used to scope
/// `let` resolution to bindings that appear before the call.
fn classify_first_arg(source: &str, raw: &str, call_offset: usize) -> Extraction {
    let trimmed = raw.trim();

    // 1. String literal — `"prefix:..."`.
    if let Some(literal) = parse_string_literal(trimmed) {
        return Extraction::Static(literal);
    }

    // 2. format! macro — `format!("prefix:{...}...", ...)`. The
    //    source-aware variant resolves a leading `{CONST}`
    //    interpolation against a same-file `const` declaration.
    if let Some(prefix) = parse_format_prefix_with_source(source, trimmed) {
        return Extraction::Static(prefix);
    }

    // 3. `&IDENT.field` or `IDENT.field` — resolve via same-file
    //    struct field assignment (`field: format!("...")`).
    let bare = trimmed.trim_start_matches('&').trim();
    if let Some((_recv, field)) = bare.split_once('.') {
        if is_simple_ident(field) && !field.contains('.') {
            if let Some(prefix) = resolve_struct_field(source, field) {
                return Extraction::Static(prefix);
            }
        }
    }

    // 4. `&IDENT` or `IDENT` — resolve via `let IDENT = ...` binding
    //    in the same file. Supports format! literals AND function
    //    calls whose body lives in the same file.
    let ident = trimmed.trim_start_matches('&').trim();
    if is_simple_ident(ident) {
        if let Some(prefix) = resolve_let_binding(source, ident, call_offset) {
            return Extraction::Static(prefix);
        }
    }

    Extraction::Dynamic {
        raw_first_arg: trimmed.to_string(),
    }
}

/// Search the source file for `field_name: format!("...")` (or the
/// `field_name: &str = "..."` const-style) assignments and return
/// the resolved prefix from the first match. This handles patterns
/// like
/// ```text
///     LockoutKeys {
///         counter_key: format!("{LOCKOUT_COUNTER_PREFIX}{full_hash}"),
///         flag_key:    format!("{LOCKOUT_FLAG_PREFIX}{full_hash}"),
///         ...
///     }
/// ```
/// where the call site reads `&keys.counter_key`. The walker picks
/// the first `field: format!(...)` in the file — multiple shapes for
/// the same field name are not currently distinguished (none exist
/// today; if a future contributor introduces them, the resolver
/// needs to be tightened).
fn resolve_struct_field(source: &str, field: &str) -> Option<String> {
    let needle = format!("{field}:");
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(&needle) {
        let abs = search_from + rel;
        // Confirm `field:` is at a token boundary — preceded by
        // whitespace or `{`.
        let before_ok = abs == 0
            || matches!(
                source.as_bytes()[abs - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'{' | b','
            );
        if !before_ok {
            search_from = abs + 1;
            continue;
        }
        // Confirm `:` is followed by a single space (Rust struct
        // field syntax) and then either `format!` or `"...".
        let rhs_start = abs + needle.len();
        let rhs = source[rhs_start..].trim_start();
        if let Some(prefix) =
            parse_string_literal(rhs).or_else(|| parse_format_prefix_with_source(source, rhs))
        {
            return Some(prefix);
        }
        search_from = abs + needle.len();
    }
    None
}

/// Parse a Rust string literal. Returns the contents (with simple
/// escape handling) or `None` if `s` is not a literal expression.
/// Handles `"..."` and `r"..."`/`r#"..."#` raw strings.
fn parse_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == b'"' {
        // Plain string literal — extract until the matching `"`.
        let inner = &s[1..];
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    match next {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        other => out.push(other),
                    }
                }
                continue;
            }
            if c == '"' {
                return Some(out);
            }
            out.push(c);
        }
        return None;
    }
    if bytes[0] == b'r' {
        // Raw string — `r"..."` or `r#"..."#` etc.
        let mut hash_count = 0;
        let mut idx = 1;
        while idx < bytes.len() && bytes[idx] == b'#' {
            hash_count += 1;
            idx += 1;
        }
        if idx >= bytes.len() || bytes[idx] != b'"' {
            return None;
        }
        let close: String = std::iter::once('"')
            .chain(std::iter::repeat_n('#', hash_count))
            .collect();
        let body_start = idx + 1;
        if let Some(rel) = s[body_start..].find(&close) {
            return Some(s[body_start..body_start + rel].to_string());
        }
    }
    None
}

/// Parse a `format!("...", ...)` invocation and return the static
/// prefix portion of the format string. With `source` provided, also
/// resolves a leading `{IDENT}` interpolation against a same-file
/// `const IDENT: &str = "..."` declaration so format strings of the
/// shape `format!("{CONST}{...}", ...)` produce the const's literal
/// value as the prefix.
fn parse_format_prefix_with_source(source: &str, s: &str) -> Option<String> {
    let s = s.trim();
    let bang_idx = s.find("format!")?;
    if bang_idx != 0 {
        return None;
    }
    let after = s[7..].trim_start();
    let bytes = after.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let open = bytes[0];
    if open != b'(' && open != b'[' && open != b'{' {
        return None;
    }
    let body = &after[1..];
    // The first argument of format! is the format string. Parse it
    // as a string literal.
    let lit = parse_string_literal(body.trim_start())?;
    // If the format string starts with `{IDENT}` (no embedded
    // formatting spec), resolve IDENT against same-file const decls.
    if !source.is_empty() && lit.starts_with('{') {
        if let Some(end) = lit.find('}') {
            let inner = &lit[1..end];
            // No formatting spec (`:`) and the identifier looks like
            // an UPPER_SNAKE / camelCase `const`.
            if !inner.contains(':') && is_simple_ident(inner) {
                if let Some(const_value) = resolve_const(source, inner) {
                    // Append any literal text following the
                    // `{IDENT}` up to the next `{` (also handling
                    // `{{` escapes the same way).
                    let after_brace = &lit[end + 1..];
                    let mut appended_end = after_brace.len();
                    let chars: Vec<char> = after_brace.chars().collect();
                    let mut i = 0;
                    while i < chars.len() {
                        if chars[i] == '{' {
                            if i + 1 < chars.len() && chars[i + 1] == '{' {
                                i += 2;
                                continue;
                            }
                            appended_end = after_brace
                                .char_indices()
                                .nth(i)
                                .map(|(b, _)| b)
                                .unwrap_or(0);
                            break;
                        }
                        i += 1;
                    }
                    let mut combined = const_value;
                    combined.push_str(&after_brace[..appended_end]);
                    return Some(combined);
                }
            }
        }
    }
    // Find the substring up to the first `{` that isn't `{{`.
    let mut prefix_end = lit.len();
    let chars: Vec<char> = lit.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            if i + 1 < chars.len() && chars[i + 1] == '{' {
                i += 2;
                continue;
            }
            prefix_end = lit
                .char_indices()
                .nth(i)
                .map(|(b, _)| b)
                .unwrap_or(lit.len());
            break;
        }
        i += 1;
    }
    Some(lit[..prefix_end].to_string())
}

/// Resolve a `const IDENT: &str = "...";` (or `pub const ...`) in
/// the same source file. Returns the literal value if found.
fn resolve_const(source: &str, ident: &str) -> Option<String> {
    let needle = format!("const {ident}");
    // Visibility modifiers (`pub`, `pub(crate)`) are not part of the
    // needle; we just confirm a token boundary before `const`.
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(&needle) {
        let abs = search_from + rel;
        let before_ok =
            abs == 0 || matches!(source.as_bytes()[abs - 1], b' ' | b'\t' | b'\n' | b'\r');
        if !before_ok {
            search_from = abs + 1;
            continue;
        }
        // Confirm the next char after `const IDENT` is not an
        // identifier continuation (so `const FOO_BAR` doesn't match
        // `FOO`).
        let after = abs + needle.len();
        if let Some(c) = source.as_bytes().get(after) {
            if !c.is_ascii_alphanumeric() && *c != b'_' {
                // Find the `=` after the type.
                if let Some(eq) = source[after..].find('=') {
                    let rhs_start = after + eq + 1;
                    let rhs = extract_until_stmt_end(source, rhs_start);
                    if let Some(value) = parse_string_literal(rhs.trim()) {
                        return Some(value);
                    }
                }
            }
        }
        search_from = abs + needle.len();
    }
    None
}

/// Returns true when `s` is a Rust simple identifier (alphanum +
/// `_`, doesn't start with a digit, no embedded dots).
fn is_simple_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Search the source file for `let IDENT = format!("...")` or
/// `let IDENT = "..."` bindings and return the static prefix the
/// binding would produce.
///
/// Most-recent (last) binding before `call_offset` wins so a
/// function that re-binds a local resolves to the latest in-scope
/// value, and bindings AFTER the call site are ignored. Cross-file
/// resolution is not supported — callers fall back to the dynamic
/// warning path.
fn resolve_let_binding(source: &str, ident: &str, call_offset: usize) -> Option<String> {
    // Build a regex-free scan: find every occurrence of
    // `let IDENT` (possibly with `mut`), advance past `=`, then
    // attempt to parse the RHS as either a string literal or a
    // `format!` invocation.
    let mut last_resolved: Option<String> = None;
    let pattern_simple = format!("let {ident} ");
    let pattern_mut = format!("let mut {ident} ");
    let mut search_from = 0usize;
    loop {
        let next_simple = source[search_from..].find(&pattern_simple);
        let next_mut = source[search_from..].find(&pattern_mut);
        let (start_rel, pattern_len) = match (next_simple, next_mut) {
            (Some(a), Some(b)) if a <= b => (a, pattern_simple.len()),
            (Some(_), Some(b)) => (b, pattern_mut.len()),
            (Some(a), None) => (a, pattern_simple.len()),
            (None, Some(b)) => (b, pattern_mut.len()),
            (None, None) => break,
        };
        let abs = search_from + start_rel;
        // Only consider bindings that appear before the call site.
        // A `let key = format!(...)` declared AFTER the `.put(&key, ...)`
        // is unreachable and would produce a misleading prefix.
        if abs >= call_offset {
            break;
        }
        // Confirm the byte before `let` is whitespace or start-of-file
        // (so we don't match `pub_let` or similar).
        let before_ok = abs == 0
            || matches!(
                source.as_bytes()[abs - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'{' | b';' | b','
            );
        if !before_ok {
            search_from = abs + 1;
            continue;
        }
        // Find the `=` after the binding (ignoring `==`).
        let after_pattern = abs + pattern_len;
        let mut eq_idx = None;
        let mut probe = after_pattern;
        while probe < source.len() {
            if source.as_bytes()[probe] == b'=' {
                let next = source.as_bytes().get(probe + 1).copied();
                if next != Some(b'=') {
                    eq_idx = Some(probe);
                    break;
                }
                probe += 2;
                continue;
            }
            if source.as_bytes()[probe] == b';' || source.as_bytes()[probe] == b'\n' {
                // Pattern destructuring without `=`, or end of stmt.
                if source.as_bytes()[probe] == b';' {
                    break;
                }
            }
            probe += 1;
        }
        let Some(eq) = eq_idx else {
            search_from = abs + pattern_len;
            continue;
        };
        // RHS expression — extract until the next `;` at top-level
        // (ignoring nested parens).
        let rhs_start = eq + 1;
        let rhs = extract_until_stmt_end(source, rhs_start);
        let trimmed = rhs.trim();
        // Try string literal, then format! prefix, then resolve a
        // bare function call against same-file `fn` declarations.
        let prefix = parse_string_literal(trimmed)
            .or_else(|| parse_format_prefix_with_source(source, trimmed))
            .or_else(|| resolve_fn_call(source, trimmed));
        if let Some(p) = prefix {
            last_resolved = Some(p);
        }
        search_from = abs + pattern_len;
    }
    last_resolved
}

/// If `expr` looks like `func_name(arg1, arg2, ...)` (a bare
/// function call), find `fn func_name(...) -> T { ... }` in the
/// same file and extract the first `format!(...)` literal in its
/// body. This is one level of indirection — it intentionally does
/// NOT recurse into helper functions called from within the
/// resolved function's body.
///
/// Used to resolve patterns like
/// ```text
///     let key = session_key("oci", session_id);
///     ctx.ephemeral_durable.put(&key, ...).await?;
/// ```
/// where `fn session_key(format: &str, session_id: Uuid) -> String {
///     format!("stateful_upload:{token}:{session_id}") }` lives in
/// the same file. Cross-file function calls (e.g.
/// `upload_session::session_key(...)`) fall through to the dynamic
/// classification.
fn resolve_fn_call(source: &str, expr: &str) -> Option<String> {
    let expr = expr.trim();
    // Only handle bare `IDENT(` shape — module paths like `foo::bar(`
    // are intentionally rejected.
    let paren_idx = expr.find('(')?;
    let head = expr[..paren_idx].trim();
    if !is_simple_ident(head) {
        return None;
    }
    // Find `fn HEAD(` in the source.
    let fn_needle = format!("fn {head}(");
    let abs = source.find(&fn_needle)?;
    // Confirm `fn` is at a token boundary.
    if abs > 0 {
        let prev = source.as_bytes()[abs - 1];
        if prev != b' ' && prev != b'\t' && prev != b'\n' && prev != b'\r' && prev != b'(' {
            // Could be `unsafe fn`, `async fn`, etc. — just confirm
            // the previous run of whitespace/keywords doesn't break
            // boundary.
        }
    }
    // Locate the `{` that opens the body. Need to skip the parameter
    // list and any `-> ReturnType` clause.
    let mut probe = abs + fn_needle.len();
    let mut depth = 1i32; // we just stepped past the opening `(`.
    let bytes = source.as_bytes();
    while probe < bytes.len() && depth > 0 {
        match bytes[probe] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        probe += 1;
    }
    // Skip ahead to `{`.
    while probe < bytes.len() && bytes[probe] != b'{' {
        probe += 1;
    }
    if probe >= bytes.len() {
        return None;
    }
    // Walk forward in the body and find the first `format!(` we can
    // resolve to a static prefix. The body's closing `}` bounds the
    // search.
    let body_start = probe + 1;
    let mut depth_brace = 1i32;
    let mut i = body_start;
    while i < bytes.len() && depth_brace > 0 {
        match bytes[i] {
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            _ => {}
        }
        i += 1;
    }
    let body_end = i;
    let body = &source[body_start..body_end.saturating_sub(1)];
    // Find the first `format!` invocation in the body.
    let bang_idx = body.find("format!")?;
    let candidate = &body[bang_idx..];
    // Use the source-aware parser so a leading `{CONST}` resolves.
    parse_format_prefix_with_source(source, candidate)
}

/// Extract the RHS of a `let` binding — everything from `start` up
/// to the next top-level `;`. Tracks balanced parens / brackets /
/// braces and string state.
fn extract_until_stmt_end(source: &str, start: usize) -> String {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut in_char = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            if c == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if c == b'\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'\'' => {
                if i + 2 < bytes.len() && bytes[i + 2] == b'\'' {
                    in_char = true;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' => {
                if depth == 0 {
                    return source[start..i].to_string();
                }
            }
            _ => {}
        }
        i += 1;
    }
    source[start..].to_string()
}

// ---------------------------------------------------------------------------
// Self-tests for the extractor (no I/O).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod self_check {
    use super::*;

    #[test]
    fn literal_extraction() {
        let raw = r#""test_prefix:foo""#;
        let cls = classify_first_arg("", raw, usize::MAX);
        assert_eq!(cls, Extraction::Static("test_prefix:foo".to_string()));
    }

    #[test]
    fn format_with_braces_yields_prefix() {
        let raw = r#"format!("test_prefix:{}", id)"#;
        let cls = classify_first_arg("", raw, usize::MAX);
        assert_eq!(cls, Extraction::Static("test_prefix:".to_string()));
    }

    #[test]
    fn format_with_named_arg_yields_prefix() {
        let raw = r#"format!("foo:{id}", id = 7)"#;
        let cls = classify_first_arg("", raw, usize::MAX);
        assert_eq!(cls, Extraction::Static("foo:".to_string()));
    }

    #[test]
    fn format_no_braces_yields_full_string() {
        let raw = r#"format!("static_only")"#;
        let cls = classify_first_arg("", raw, usize::MAX);
        assert_eq!(cls, Extraction::Static("static_only".to_string()));
    }

    #[test]
    fn pure_runtime_format_classifies_dynamic() {
        // `format!("{}", id)` — no static prefix at all.
        let raw = r#"format!("{}", id)"#;
        let cls = classify_first_arg("", raw, usize::MAX);
        assert_eq!(cls, Extraction::Static(String::new()));
        // An empty-string static prefix is not a real keyspace; the
        // outer assertion in `main_test` will treat it as a failure
        // (no prefix matches), which is the correct outcome — the
        // call site is using a runtime-only key with no static head.
    }

    #[test]
    fn unresolved_ident_classifies_dynamic() {
        // `&keys.flag_key` — field access, not a let binding.
        let raw = "&keys.flag_key";
        let cls = classify_first_arg("", raw, usize::MAX);
        assert!(matches!(cls, Extraction::Dynamic { .. }));
    }

    #[test]
    fn ident_resolves_via_let_binding() {
        let source =
            "fn x() { let key = format!(\"resolved_prefix:{x}\", x = 1); store.put(&key); }";
        let cls = classify_first_arg(source, "&key", source.len());
        assert_eq!(cls, Extraction::Static("resolved_prefix:".to_string()));
    }

    #[test]
    fn ident_resolves_via_let_with_string_literal() {
        let source = "fn x() { let key = \"static_only_prefix:\"; store.put(&key); }";
        let cls = classify_first_arg(source, "&key", source.len());
        assert_eq!(cls, Extraction::Static("static_only_prefix:".to_string()));
    }

    #[test]
    fn let_binding_after_call_site_is_ignored() {
        // The `.put(&key, ...)` call site comes BEFORE the
        // re-binding `let key = "wrong:"` so the resolver must
        // ignore the later binding and pick the earlier one.
        let source = "fn x() { let key = \"right:\"; store.put(&key, ...); let key = \"wrong:\"; }";
        // Compute the offset of `.put(` to feed as `call_offset`.
        let call_offset = source.find(".put(").unwrap();
        let cls = classify_first_arg(source, "&key", call_offset);
        assert_eq!(cls, Extraction::Static("right:".to_string()));
    }

    #[test]
    fn const_interpolation_resolves() {
        // `format!("{PREFIX}foo")` where `const PREFIX: &str = "p:"`
        // resolves to "p:foo".
        let source = "const PREFIX: &str = \"p:\";\nlet _ = format!(\"{PREFIX}foo\");";
        // Ask the parser to resolve the format expression.
        let cls = classify_first_arg(source, r#"format!("{PREFIX}foo")"#, source.len());
        assert_eq!(cls, Extraction::Static("p:foo".to_string()));
    }

    #[test]
    fn struct_field_resolves_via_same_file_assignment() {
        // `&handle.flag_key` — `flag_key:` is assigned via
        // `format!("{LOCKOUT_FLAG_PREFIX}...")` and the const is in
        // the same source.
        let source = "const LOCKOUT_FLAG_PREFIX: &str = \"lck:\";\n\
                      fn build() -> Keys { Keys { flag_key: format!(\"{LOCKOUT_FLAG_PREFIX}{x}\"), } }";
        let cls = classify_first_arg(source, "&handle.flag_key", source.len());
        assert_eq!(cls, Extraction::Static("lck:".to_string()));
    }

    #[test]
    fn fn_call_resolves_via_same_file_definition() {
        // `let key = build_key("oci", id);` resolves through the
        // same-file `fn build_key`'s `format!(...)` body.
        let source = "fn build_key(t: &str, id: u32) -> String { format!(\"upload:{t}:{id}\") }\n\
                      fn x() { let key = build_key(\"oci\", 1); store.put(&key); }";
        let call_offset = source.find(".put(").unwrap();
        let cls = classify_first_arg(source, "&key", call_offset);
        assert_eq!(cls, Extraction::Static("upload:".to_string()));
    }

    #[test]
    fn extract_receiver_picks_dotted_chain() {
        let src = "    ctx.ephemeral_durable.put(";
        let dot_idx = src.find(".put(").unwrap();
        let r = extract_receiver(src, dot_idx);
        assert_eq!(r, "ctx.ephemeral_durable");
    }

    #[test]
    fn extract_receiver_handles_multiline_chain() {
        let src = "    ctx\n        .ephemeral_durable\n        .put(";
        let dot_idx = src.find(".put(").unwrap();
        let r = extract_receiver(src, dot_idx);
        assert_eq!(r, "ctx.ephemeral_durable");
    }

    #[test]
    fn extract_first_arg_string_literal() {
        let src = r#"foo.put("a:b", value, ttl)"#;
        let paren = src.find('(').unwrap();
        let arg = extract_first_arg(src, paren).unwrap();
        assert_eq!(arg, r#""a:b""#);
    }

    #[test]
    fn extract_first_arg_with_nested_parens() {
        let src = r#"foo.put(format!("a:{}", make(x, y)), value, ttl)"#;
        let paren = src.find(".put(").unwrap() + ".put".len();
        let arg = extract_first_arg(src, paren).unwrap();
        assert_eq!(arg, r#"format!("a:{}", make(x, y))"#);
    }

    #[test]
    fn comment_line_is_skipped() {
        // `is_in_comment_or_string` should return true for an idx
        // that follows a `//` on the same line.
        let src = "ok // ctx.ephemeral.put(\nnext\n";
        let idx = src.find(".put(").unwrap();
        assert!(is_in_comment_or_string(src, idx));
    }

    #[test]
    fn string_literal_position_is_skipped() {
        let src = "let s = \"ctx.ephemeral.put(\";";
        let idx = src.find(".put(").unwrap();
        assert!(is_in_comment_or_string(src, idx));
    }

    #[test]
    fn raw_string_literal_extracted() {
        let lit = parse_string_literal(r##"r#"hello:world"#"##);
        assert_eq!(lit.as_deref(), Some("hello:world"));
    }
}

// ---------------------------------------------------------------------------
// The actual exhaustiveness test.
// ---------------------------------------------------------------------------

/// Locate the workspace `crates/` directory by walking up from
/// `CARGO_MANIFEST_DIR`. `CARGO_MANIFEST_DIR` is the manifest dir of
/// the crate this test belongs to (`crates/hort-server/`), so its
/// parent is `crates/`.
fn workspace_crates_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let parent = manifest.parent().expect("CARGO_MANIFEST_DIR has a parent");
    assert!(
        parent.ends_with("crates"),
        "expected CARGO_MANIFEST_DIR's parent to end in 'crates', got {parent:?}"
    );
    parent.to_path_buf()
}

#[test]
fn every_write_side_call_uses_a_registered_keyspace() {
    let crates_root = workspace_crates_dir();
    let self_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("ephemeral_keyspace_exhaustive.rs");

    let files = collect_source_files(&crates_root, &self_path);
    assert!(
        !files.is_empty(),
        "walker found no source files under {crates_root:?}"
    );

    let mut all_sites = Vec::new();
    for path in &files {
        let source = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => panic!("failed to read {path:?}: {e}"),
        };
        all_sites.extend(scan_file(&source, path));
    }

    // Track which load-bearing prefixes were seen on at least one
    // call site. A registered prefix that the walker never observes
    // (other than the forward-registered `pulldedup:`) is a sign
    // that either the walker is missing call sites or the registry
    // has gone stale.
    let mut seen_prefixes: BTreeSet<String> = BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();
    let mut dynamic_sites: Vec<String> = Vec::new();
    let mut static_sites: Vec<String> = Vec::new();

    for site in &all_sites {
        let location = format!(
            "{}:{}",
            site.file
                .strip_prefix(&crates_root)
                .unwrap_or(&site.file)
                .display(),
            site.line
        );
        match &site.extraction {
            Extraction::Static(prefix) => {
                static_sites.push(format!(
                    "{location} :: method={} :: prefix={:?}",
                    site.method, prefix
                ));
                if prefix.is_empty() {
                    failures.push(format!(
                        "{location}: write-side EphemeralStore call uses an EMPTY static \
                         prefix (the format! string starts with '{{') — make the prefix \
                         literal or refactor to a registered head prefix."
                    ));
                    continue;
                }
                match keyspace_class(prefix) {
                    Some(_) => {
                        // Identify which registered prefix matched.
                        let matched = hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY
                            .iter()
                            .find(|(p, _)| prefix.starts_with(p))
                            .map(|(p, _)| (*p).to_string())
                            .unwrap_or_default();
                        seen_prefixes.insert(matched);
                    }
                    None => failures.push(format!(
                        "{location}: write-side EphemeralStore call uses key '{prefix}...' \
                         which is not in KEYSPACE_REGISTRY. Add the prefix to \
                         crates/hort-app/src/ephemeral_keyspace.rs."
                    )),
                }
            }
            Extraction::Dynamic { raw_first_arg } => {
                dynamic_sites.push(format!(
                    "{location} :: method={} :: raw={}",
                    site.method, raw_first_arg
                ));
            }
        }
    }

    // Emit progress to stderr so `cargo test -- --nocapture` users
    // can see the discovered call-site landscape.
    eprintln!(
        "[keyspace gate] scanned {} files, found {} write-side call sites with an 'ephemeral' \
         receiver ({} static / {} dynamic).",
        files.len(),
        all_sites.len(),
        static_sites.len(),
        dynamic_sites.len()
    );
    eprintln!("[keyspace gate] static call sites:");
    for s in &static_sites {
        eprintln!("    {s}");
    }
    eprintln!("[keyspace gate] dynamic call sites:");
    for d in &dynamic_sites {
        eprintln!("    {d}");
    }

    // ---- Failures: any unregistered prefix is a hard fail. -----------------
    if !failures.is_empty() {
        let mut msg = String::from(
            "ephemeral_keyspace_exhaustive: unregistered or invalid keyspace prefixes detected:\n",
        );
        for f in &failures {
            msg.push_str(&format!("  - {f}\n"));
        }
        panic!("{msg}");
    }

    // ---- Load-bearing assertions: every registered prefix is reachable -----
    //      from a call site, EXCEPT the forward-registered set.
    for (prefix, _class) in hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY {
        if FORWARD_REGISTERED_PREFIXES.contains(prefix) {
            continue;
        }
        assert!(
            seen_prefixes.contains(*prefix),
            "registered prefix {prefix:?} has no reachable write-side call site in the workspace; \
             either the walker is missing it (bug in this test), the prefix is dead code (remove \
             from KEYSPACE_REGISTRY), or it is forward-registered (add it to \
             FORWARD_REGISTERED_PREFIXES)."
        );
    }

    // ---- Boundary cases (load-bearing registry sibling pairs). -------------
    //      Both `pat-attempt:` and `pat-attempt-counter:` MUST be reached;
    //      same for `cargo_index_proj:` and `cargo_index_config:` (the
    //      streaming-metadata projection rename, ADR 0026:
    //      `cargo_index:` → `cargo_index_proj:`). If
    //      either of a sibling pair falls to zero call sites, the registry
    //      entry is either dead code OR the walker missed it; either way we
    //      want a red test.
    for required in [
        "pat-attempt:",
        "pat-attempt-counter:",
        "cargo_index_proj:",
        "cargo_index_config:",
    ] {
        assert!(
            seen_prefixes.contains(required),
            "load-bearing sibling prefix {required:?} has no reachable write-side call site; \
             the registry sibling-pair invariant is unverified."
        );
    }

    // ---- Dynamic-warning count: locked. ------------------------------------
    assert_eq!(
        dynamic_sites.len(),
        EXPECTED_DYNAMIC_COUNT,
        "dynamic-warning count drifted: expected {} but observed {}. \
         Investigate the new entry on stderr — prefer making the new write \
         site statically resolvable (use `let key = format!(\"prefix:{{...}}\", ...)` \
         IN THE SAME FUNCTION as the .put call) over bumping the count.",
        EXPECTED_DYNAMIC_COUNT,
        dynamic_sites.len()
    );
}
