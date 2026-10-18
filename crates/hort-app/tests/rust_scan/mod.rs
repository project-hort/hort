//! Shared token-aware Rust scanning primitives for the `crates/`
//! structural guards.
//!
//! Three guard targets read the same tree for different structural shapes
//! — `db_tests_are_serialized.rs` (a test that reaches a real Postgres
//! connection without the workspace serialization key),
//! `cas_reads_are_verified.rs` (a storage adapter whose `StoragePort::get`
//! hands back an unverified stream) and
//! `condemning_rule_is_single_sourced.rs` (a second reader of a finding's
//! component relation re-deriving the release-authority rule). All three
//! need the identical lexical
//! discipline, and a second verbatim copy of it would be the exact
//! duplication that lets one copy drift into weakness while the other
//! stays honest. The lexer therefore lives here once; each guard keeps its
//! own matcher, its own maintained list, and its own self-checks — those
//! are the parts that encode a policy and must stay reviewable in one
//! file. Same split, and the same reason, as `tests/sql_scan/mod.rs` for
//! the `migrations/` guards.
//!
//! [`production_region`] — comments and literals blanked, then every
//! `#[cfg(test)]` item — is part of that shared discipline rather than a
//! policy: a guard that read test code would be satisfied by a fixture's
//! assertions about itself, and a guard that truncated at the first
//! `#[cfg(test)]` would blank the production code that follows a
//! test-only struct field.
//!
//! The discipline this module implements, and why naive substring
//! matching is wrong for Rust:
//!
//!   * **Comments and string/char literals are blanked first.** A guard's
//!     own prose, and a doc comment explaining the shape a function
//!     deliberately does *not* have, legitimately spell out the very
//!     token the matcher looks for. Neither is code. Blanking replaces
//!     them with spaces, so byte offsets and line numbers survive and a
//!     hit still maps back to a line.
//!   * **Braces are matched on blanked text only.** A `{` inside a SQL
//!     string literal, a `format!` placeholder or a doc comment is not a
//!     block opener, and this workspace's files are full of all three. A
//!     brace matcher run over raw source silently swallows the item that
//!     follows.
//!   * **Identifiers match as whole tokens.** The `r` of `for` is not a
//!     raw-string prefix and the `b` of `verbose` is not a byte-string
//!     prefix; `is_ident_byte` + `starts_a_token` are what keep that
//!     straight.
//!
//! No `regex` / `syn` / `walkdir` dependency: `std::fs` plus byte walking,
//! matching the sibling structural guards.

// Each guard binary compiles this module and uses the subset of it that
// its own matcher needs, so an item unused by one binary is expected
// rather than dead.
#![allow(dead_code)]
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// Item modifiers that may sit between the attribute run and the `fn`
/// keyword.
pub const FN_MODIFIERS: [&str; 6] = ["pub", "async", "const", "unsafe", "extern", "default"];

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-app`).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Walk `dir` recursively, calling `visit` on every `.rs` file.
pub fn walk_rust(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            walk_rust(&path, visit);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}

pub fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Overwrite `from..to` with spaces, leaving newlines so line numbers
/// and byte offsets survive.
pub fn blank_range(out: &mut [u8], from: usize, to: usize) {
    for byte in out.iter_mut().take(to).skip(from) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// True when the byte at `i` starts a token rather than continuing an
/// identifier — the `r` of `for` must not read as a raw-string opener,
/// nor the `b` of `verbose` as a byte-string prefix.
pub fn starts_a_token(src: &[u8], i: usize) -> bool {
    i == 0 || !is_ident_byte(src[i - 1])
}

/// True when `src` carries `first` immediately followed by `second` at
/// `i` — the two-byte markers this lexer turns on (`//`, `/*`, `*/`,
/// `b"`) all read this way.
pub fn is_pair(src: &[u8], i: usize, first: u8, second: u8) -> bool {
    src[i] == first && i + 1 < src.len() && src[i + 1] == second
}

/// The offset just past a `//` line comment starting at `i`, or `None`
/// when one does not start there. The terminating newline stays outside
/// the range, so the line structure survives the blanking.
pub fn line_comment_end(src: &[u8], i: usize) -> Option<usize> {
    if !is_pair(src, i, b'/', b'/') {
        return None;
    }
    let mut end = i;
    while end < src.len() && src[end] != b'\n' {
        end += 1;
    }
    Some(end)
}

/// The offset just past a `/* … */` block comment starting at `i`, or
/// `None` when one does not start there. Nesting counts, as rustc allows
/// it; an unterminated comment blanks to the end of the input.
pub fn block_comment_end(src: &[u8], i: usize) -> Option<usize> {
    if !is_pair(src, i, b'/', b'*') {
        return None;
    }
    let mut depth = 1usize;
    let mut end = i + 2;
    while end < src.len() && depth > 0 {
        if is_pair(src, end, b'/', b'*') {
            depth += 1;
            end += 2;
        } else if is_pair(src, end, b'*', b'/') {
            depth -= 1;
            end += 2;
        } else {
            end += 1;
        }
    }
    Some(end)
}

/// The offset just past a `\`-escaped literal whose body starts at
/// `from` and runs to the next unescaped `terminator`. Shared by the
/// string and char forms, which differ only in that byte.
///
/// An unterminated literal runs to the end of the input, and a trailing
/// escape can put the answer one byte past it — `blank_range` clamps, so
/// the overshoot costs nothing and the walk still terminates.
pub fn escaped_literal_end(src: &[u8], from: usize, terminator: u8) -> usize {
    let mut j = from;
    while j < src.len() {
        if src[j] == b'\\' {
            j += 2;
        } else if src[j] == terminator {
            return j + 1;
        } else {
            j += 1;
        }
    }
    j
}

/// The offset just past the `"##…` that closes a raw string whose opener
/// carried `hashes` hashes, scanning from `from`. Unterminated blanks to
/// the end of the input.
pub fn raw_string_close(src: &[u8], from: usize, hashes: usize) -> usize {
    let n = src.len();
    let mut j = from;
    while j < n {
        if src[j] == b'"' && j + hashes < n && src[j + 1..=j + hashes].iter().all(|c| *c == b'#') {
            return j + 1 + hashes;
        }
        j += 1;
    }
    n
}

/// The offset just past a raw string starting at `i` — `r"…"`, `r#"…"#`,
/// `br#"…"#` — or `None` when `i` starts something else. A raw string
/// honours no escapes, so only a `"` trailed by as many `#` as the
/// opener carried can close it.
pub fn raw_string_end(src: &[u8], i: usize) -> Option<usize> {
    if !starts_a_token(src, i) {
        return None;
    }
    let r_at = match src[i] {
        b'r' => i,
        // The `b` of a byte-raw string shifts the `r` one byte right.
        b'b' if i + 1 < src.len() && src[i + 1] == b'r' => i + 1,
        _ => return None,
    };
    let mut hashes = 0usize;
    let mut k = r_at + 1;
    while k < src.len() && src[k] == b'#' {
        hashes += 1;
        k += 1;
    }
    // No quote after the hash run: a plain identifier such as `r` or
    // `br`, not a literal.
    if k >= src.len() || src[k] != b'"' {
        return None;
    }
    Some(raw_string_close(src, k + 1, hashes))
}

/// The offset just past an ordinary or byte string starting at `i`
/// (`"…"`, `b"…"`), or `None` when `i` starts something else. Only
/// reached after `raw_string_end`, which owns the `r`-prefixed forms.
pub fn quoted_string_end(src: &[u8], i: usize) -> Option<usize> {
    let body_at = if src[i] == b'"' {
        i + 1
    } else if starts_a_token(src, i) && is_pair(src, i, b'b', b'"') {
        i + 2
    } else {
        return None;
    };
    Some(escaped_literal_end(src, body_at, b'"'))
}

/// The offset just past a char literal starting at `i`, or `None` when
/// the `'` opens a lifetime instead.
///
/// `'\…'` and `'x'` are literals; `'static` is not. A multi-byte char
/// literal reads here as a lifetime, which is harmless: the bytes it
/// could otherwise hide from the brace matcher (`{`, `}`, `"`, `/`) are
/// all single-byte and so all take the literal branch.
pub fn char_literal_end(src: &[u8], i: usize) -> Option<usize> {
    if src[i] != b'\'' {
        return None;
    }
    let escaped = i + 1 < src.len() && src[i + 1] == b'\\';
    let one_char = i + 2 < src.len() && src[i + 2] == b'\'';
    if !escaped && !one_char {
        return None;
    }
    Some(escaped_literal_end(src, i + 1, b'\''))
}

/// The offset just past the comment or literal starting at `i`, or
/// `None` when code starts there.
///
/// The order is load-bearing. Comments come first, because a `/*` is not
/// a division followed by a glob. The raw-string form precedes the
/// ordinary one, because `r#"…"#` would otherwise read as an identifier
/// followed by a string that ends at the first inner `"` — and a raw
/// string is exactly where an unescaped `"` lives. The char literal
/// comes last, being the only form a `'` can open.
///
/// Every arm reports an end strictly past `i`, which is what keeps the
/// caller's walk advancing.
pub fn noncode_token_end(src: &[u8], i: usize) -> Option<usize> {
    line_comment_end(src, i)
        .or_else(|| block_comment_end(src, i))
        .or_else(|| raw_string_end(src, i))
        .or_else(|| quoted_string_end(src, i))
        .or_else(|| char_literal_end(src, i))
}

/// Replace every comment and every string/char literal with spaces,
/// preserving byte offsets and line breaks so the result can still be
/// scanned structurally and mapped back to a line number.
///
/// Blanking is what lets the brace matcher below be a byte scan: a `{`
/// inside a doc comment or a SQL string literal is not a block opener,
/// and this repository's test files are full of both.
pub fn blank_noncode(source: &str) -> String {
    let src = source.as_bytes();
    let mut out = src.to_vec();
    let mut i = 0usize;
    while i < src.len() {
        match noncode_token_end(src, i) {
            Some(end) => {
                blank_range(&mut out, i, end);
                i = end;
            }
            None => i += 1,
        }
    }
    String::from_utf8(out).expect("blanking replaces whole tokens with ASCII spaces")
}

/// The offset of the `}` closing the block whose `{` sits at `open`, or
/// `None` when the braces do not balance before the end of the input.
///
/// A byte scan, which is only sound on text `blank_noncode` has already
/// been through: a `{` inside a doc comment, a `format!` placeholder or a
/// SQL literal is not a block opener.
pub fn block_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The 1-based line `offset` falls on.
pub fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1
}

/// One `fn` item found in a blanked source file.
pub struct FnItem {
    pub name: String,
    /// 1-based line of the `fn` keyword.
    pub line: usize,
    /// The contiguous run of `#[…]` attributes immediately preceding the
    /// item.
    pub attrs: Vec<String>,
    /// The item's body, braces included. Empty for a bodiless
    /// declaration (a trait method signature).
    pub body: String,
}

/// Match the opener that the `close` byte at `at` belongs to, returning
/// its offset. `None` when the source is unbalanced.
pub fn match_back(bytes: &[u8], at: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut cursor = at;
    loop {
        if bytes[cursor] == close {
            depth += 1;
        } else if bytes[cursor] == open {
            depth -= 1;
            if depth == 0 {
                return Some(cursor);
            }
        }
        if cursor == 0 {
            return None;
        }
        cursor -= 1;
    }
}

/// The attribute run immediately preceding the `fn` keyword at `fn_at`,
/// walking back over the item's modifiers (`pub`, `pub(crate)`, `async`,
/// `const`, `unsafe`, `extern "C"` — whose string literal is already
/// blanked to spaces).
pub fn preceding_attrs(blanked: &str, fn_at: usize) -> Vec<String> {
    let bytes = blanked.as_bytes();
    let mut attrs = Vec::new();
    let mut i = fn_at;
    loop {
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 {
            break;
        }
        match bytes[i - 1] {
            b']' => {
                let Some(open) = match_back(bytes, i - 1, b'[', b']') else {
                    break;
                };
                // `#[…]`; anything else ending in `]` is not an
                // attribute and ends the run.
                if open == 0 || bytes[open - 1] != b'#' {
                    break;
                }
                attrs.push(blanked[open - 1..i].to_string());
                i = open - 1;
            }
            b')' => {
                // `pub(crate)` / `pub(super)`: step over the restriction.
                let Some(open) = match_back(bytes, i - 1, b'(', b')') else {
                    break;
                };
                i = open;
            }
            byte if is_ident_byte(byte) => {
                let mut start = i;
                while start > 0 && is_ident_byte(bytes[start - 1]) {
                    start -= 1;
                }
                if !FN_MODIFIERS.contains(&&blanked[start..i]) {
                    break;
                }
                i = start;
            }
            _ => break,
        }
    }
    attrs
}

/// Every `fn` item in `blanked`, with its attributes and body.
pub fn parse_fns(blanked: &str) -> Vec<FnItem> {
    let bytes = blanked.as_bytes();
    let n = bytes.len();
    let mut items = Vec::new();
    let mut i = 0usize;
    // `fn` offsets only ever move forward, so the line number is a
    // running count rather than a re-scan of the prefix per item —
    // which on this workspace's larger files is the difference between
    // a quadratic walk and a linear one.
    let mut counted_to = 0usize;
    let mut line = 1usize;
    while i + 2 < n {
        // The `fn` keyword on a token boundary, followed by a name —
        // which is what rules out the `fn(&str) -> bool` pointer type.
        if !(bytes[i] == b'f'
            && bytes[i + 1] == b'n'
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && bytes[i + 2].is_ascii_whitespace())
        {
            i += 1;
            continue;
        }
        let fn_at = i;
        let mut j = i + 2;
        while j < n && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let name_start = j;
        while j < n && is_ident_byte(bytes[j]) {
            j += 1;
        }
        if j == name_start {
            i += 1;
            continue;
        }
        let name = blanked[name_start..j].to_string();
        // Walk the signature to the body's `{`, or to the `;` of a
        // bodiless declaration. Generic bounds and `where` clauses carry
        // neither at paren/bracket depth zero.
        let mut parens = 0usize;
        let mut brackets = 0usize;
        let mut body = String::new();
        while j < n {
            match bytes[j] {
                b'(' => parens += 1,
                b')' => parens = parens.saturating_sub(1),
                b'[' => brackets += 1,
                b']' => brackets = brackets.saturating_sub(1),
                b';' if parens == 0 && brackets == 0 => break,
                b'{' if parens == 0 && brackets == 0 => {
                    // Unbalanced input keeps the rest of the file as the
                    // body, which is what the caller wants: a truncated
                    // body would read as a function that does nothing.
                    let end = block_end(bytes, j).map_or(n, |close| close + 1);
                    body = blanked[j..end].to_string();
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        line += bytes[counted_to..fn_at]
            .iter()
            .filter(|b| **b == b'\n')
            .count();
        counted_to = fn_at;
        items.push(FnItem {
            name,
            line,
            attrs: preceding_attrs(blanked, fn_at),
            body,
        });
        i = fn_at + 2;
    }
    items
}

/// The path of an attribute — everything before its argument list, so
/// `#[tokio::test(flavor = "multi_thread")]` reads as `tokio::test`.
pub fn attr_path(attr: &str) -> &str {
    let inner = attr
        .trim()
        .trim_start_matches('#')
        .trim_start_matches('[')
        .trim_end_matches(']');
    inner.split(['(', '=']).next().unwrap_or("").trim()
}

/// The attribute that marks an item as test-only.
pub const CFG_TEST: &str = "#[cfg(test)]";

/// The offset of the first non-whitespace byte at or after `from`.
pub fn skip_ws(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// The offset of the byte that ends the item an attribute applies to,
/// counting from `from`, with which byte it is: a `{` opening the item's
/// block, or the `;` / `,` terminating a block-less one.
///
/// All three are needed, and `,` is the one that is easy to forget. The
/// adapter crates attach `#[cfg(test)]` to **struct fields** and
/// struct-literal fields (`hort-adapters-postgres/src/purge_gc.rs`'s
/// `interrupt_after_append: AtomicBool,`), which end at a comma; a rule
/// looking only for `{` or `;` runs past the field, past the struct's own
/// closing brace, and blanks the whole `impl` block that follows it —
/// over-blanking, which in this guard means a silent false negative.
///
/// Depth matters because the item may carry any of the three nested:
/// `fn f(a: u8, b: u8)` carries commas inside parens, `const X: [u8; 2]`
/// a `;` inside brackets, and `use a::b::{C, D};` a comma inside the
/// brace group — the last one being why the `{` is reported first and the
/// caller then matches it.
pub fn item_delimiter(bytes: &[u8], from: usize) -> Option<(usize, u8)> {
    let mut parens = 0usize;
    let mut brackets = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(from) {
        match byte {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'{' | b';' | b',' if parens == 0 && brackets == 0 => return Some((at, *byte)),
            _ => {}
        }
    }
    None
}

/// Blank every `#[cfg(test)]`-attributed item, leaving the file's
/// production code.
///
/// Scoped **per item** rather than "from the first `#[cfg(test)]` to the
/// end of the file", which is the shape `capped_stream_reads` can afford
/// because it scans files whose inline test module comes last. The
/// adapter crates do not honour that: `purge_gc.rs` attaches the
/// attribute to a test-only `use`, a test-only field and a test-only
/// method with 850 lines of production code after them, and a truncating
/// rule would read that file — and `artifact_repo.rs`, and
/// `upstream-http/src/lib.rs` — as having almost no code at all.
///
/// Only the exact `#[cfg(test)]` spelling counts.
/// `#[cfg(any(test, feature = "test-support"))]` deliberately does not:
/// in this workspace it gates individual *production-file* items (a
/// `pub mod test_support;` declaration, a `wrap_for_test` constructor),
/// and treating it as a test marker would blank production code.
pub fn blank_cfg_test_items(blanked: &str) -> String {
    let bytes = blanked.as_bytes();
    let mut out = bytes.to_vec();
    let mut cursor = 0usize;
    while let Some(found) = blanked[cursor..].find(CFG_TEST) {
        let at = cursor + found;
        let after_attr = at + CFG_TEST.len();
        let end = match item_delimiter(bytes, after_attr) {
            // A block item: the attribute covers it to the matching brace.
            Some((brace, b'{')) => match block_end(bytes, brace) {
                Some(close) => {
                    // `use a::{A, B};` and `struct S { … };` both leave a
                    // terminator past the brace; absorb it so no stray
                    // fragment survives as code.
                    let next = skip_ws(bytes, close + 1);
                    if bytes.get(next) == Some(&b';') {
                        next + 1
                    } else {
                        close + 1
                    }
                }
                None => bytes.len(),
            },
            // A block-less item: `#[cfg(test)] use std::…::{…};` reaches
            // the arm above, `#[cfg(test)] const X: u8 = 1;` and
            // `#[cfg(test)] probe: AtomicBool,` this one.
            Some((terminator, _)) => terminator + 1,
            None => bytes.len(),
        };
        blank_range(&mut out, at, end);
        cursor = end;
    }
    String::from_utf8(out).expect("blanking replaces whole items with ASCII spaces")
}

/// The scannable production text of a source file: comments and literals
/// blanked, then the `#[cfg(test)]` items. Byte offsets and line numbers
/// survive both passes.
pub fn production_region(source: &str) -> String {
    blank_cfg_test_items(&blank_noncode(source))
}
