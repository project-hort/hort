//! Shared token-aware SQL scanning primitives for the `migrations/`
//! structural guards (ADR 0030,
//! `docs/adr/0030-sensitive-surface-structural-guards.md`).
//!
//! Two guard targets scan the same tree for different destructive shapes —
//! `no_sensitive_drops.rs` (drops / de-constrains of a security-critical
//! table) and `expand_contract_guard.rs` (contractions that would break the
//! previous release's still-running binaries). Both need the identical
//! lexical discipline, and a second verbatim copy of it would be the exact
//! duplication that lets one copy drift into weakness while the other stays
//! honest. The lexer therefore lives here once; each guard keeps its own
//! matcher, its own maintained list, and its own self-checks — those are the
//! parts that encode a policy and must stay reviewable in one file.
//!
//! The discipline this module implements, and why naive substring matching
//! is wrong for SQL:
//!
//!   * **Comments and string literals are stripped first.** A migration's
//!     reversal-runbook comment legitimately spells out `DROP TABLE IF
//!     EXISTS public.jobs`, and an `information_schema` probe legitimately
//!     compares against the string `'is_deleted'`. Neither is a statement,
//!     and neither may trip a guard.
//!   * **Identifiers match as whole tokens.** `repo_security_scores` is not
//!     `repositories`; `user_preferences` is not `users`. The tokenizer
//!     emits words, punctuation and double-quoted identifiers, so a
//!     comparison is always identifier-to-identifier.
//!   * **Formatting-independent.** Whitespace is a separator and is never
//!     part of a token, so re-indenting or collapsing spaces inside a
//!     statement cannot change a verdict.
//!
//! No `regex` / `walkdir` dependency: `std::fs` plus token walking, matching
//! the sibling structural guards.

// Each guard binary compiles this module and uses the subset of it that its
// own matcher needs, so an item unused by one binary is expected rather than
// dead.
#![allow(dead_code)]

use std::path::PathBuf;

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-app`), so two levels up is the root. Mirrors how the
/// sibling guards resolve their scan roots.
pub fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)")
        .to_path_buf()
}

/// The workspace-root `migrations/` directory — the scanned tree.
pub fn migrations_dir() -> PathBuf {
    workspace_root().join("migrations")
}

// ---------------------------------------------------------------------------
// Comment / string stripping.
// ---------------------------------------------------------------------------

/// Strip `/* … */` block comments, `--` line comments, and `'…'` SQL string
/// literals from a SQL source, replacing the stripped span with a single
/// space so token boundaries are preserved. This is what makes the matchers
/// token-aware rather than naive-substring: a `DROP TABLE IF EXISTS
/// public.jobs` inside a reversal-runbook comment is removed before any
/// pattern scan, and a column name quoted as a SQL *value*
/// (`column_name = 'is_deleted'`) is removed before any identifier scan.
///
/// SQL identifier double-quotes (`"…"`) are NOT stripped — they are part of
/// the identifier and [`parse_table_name`] handles them.
///
/// Block comments are stripped first (they can contain `--` and `'`), then a
/// single linear pass handles line comments and string literals.
pub fn strip_comments_and_strings(source: &str) -> String {
    // Pass 1: remove `/* ... */` block comments. SQL block comments do
    // not nest in the standard; treat the first `*/` as the close.
    let mut without_block = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Find the closing `*/`.
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            // Replace the whole comment with a space.
            without_block.push(' ');
            // Advance past the closing `*/` (or to EOF if unterminated).
            i = if j + 1 < bytes.len() {
                j + 2
            } else {
                bytes.len()
            };
            continue;
        }
        without_block.push(bytes[i] as char);
        i += 1;
    }

    // Pass 2: remove `--` line comments and `'...'` string literals in a
    // single linear walk. A `--` only starts a comment when NOT inside a
    // string literal; a `'` only opens a string when NOT inside a line
    // comment. SQL escapes a single quote inside a string by doubling it
    // (`''`), which this walk handles by toggling twice (open then close)
    // — the net effect (an empty inter-quote span) is harmless for our
    // purpose since we never read string contents.
    let mut out = String::with_capacity(without_block.len());
    let bytes = without_block.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    let mut in_line_comment = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_line_comment {
            if c == b'\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                // Preserve column-ish spacing as a single space.
                out.push(' ');
            }
            i += 1;
            continue;
        }
        if in_str {
            if c == b'\'' {
                in_str = false;
            }
            // Replace string contents (and the quotes) with spaces so a
            // `--` or table name inside a literal cannot trip the scan.
            out.push(' ');
            i += 1;
            continue;
        }
        // Not in a comment or string.
        if c == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            in_line_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }
        if c == b'\'' {
            in_str = true;
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Tokenizer.
// ---------------------------------------------------------------------------

/// A SQL token: either an identifier/keyword word, a punctuation char, or a
/// double-quoted identifier. Whitespace is the separator and is not emitted.
/// Tokens carry the byte offset of their start in the (comment-stripped)
/// source so a match can be mapped back to a line.
#[derive(Debug, Clone)]
pub struct Token {
    /// For a word: the lower-cased text. For a quoted identifier: the raw
    /// inner text (case preserved, but compared case-insensitively
    /// downstream). For punctuation: the single char as a string.
    pub text: String,
    /// `true` when this token came from a `"..."` quoted identifier.
    pub quoted: bool,
    /// Byte offset of the token start within the stripped source.
    pub offset: usize,
}

/// Tokenize the comment-stripped source. Words are runs of `[A-Za-z0-9_]`,
/// double-quoted identifiers are `"..."`, and `.`, `(`, `)`, `,`, `;` are
/// emitted as single-char punctuation tokens. Anything else (operators,
/// etc.) is skipped — it never participates in the statement shapes the
/// matchers recognise.
pub fn tokenize(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            // Quoted identifier — read until the closing quote.
            let start = i;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            let inner = source[i + 1..j.min(bytes.len())].to_string();
            tokens.push(Token {
                text: inner,
                quoted: true,
                offset: start,
            });
            i = if j < bytes.len() { j + 1 } else { bytes.len() };
            continue;
        }
        if c.is_ascii_alphanumeric() || c == b'_' {
            let start = i;
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            tokens.push(Token {
                text: source[start..j].to_ascii_lowercase(),
                quoted: false,
                offset: start,
            });
            i = j;
            continue;
        }
        if matches!(c, b'.' | b'(' | b')' | b',' | b';') {
            tokens.push(Token {
                text: (c as char).to_string(),
                quoted: false,
                offset: i,
            });
        }
        i += 1;
    }
    tokens
}

/// `true` when a token can serve as a SQL identifier (a word that is not
/// punctuation, or any quoted identifier).
pub fn is_identifier_token(t: &Token) -> bool {
    if t.quoted {
        return true;
    }
    !matches!(t.text.as_str(), "." | "(" | ")" | "," | ";")
}

/// Lower-cased unqualified name of an identifier token.
pub fn unqualified(t: &Token) -> String {
    t.text.to_ascii_lowercase()
}

/// Given the token stream and an index pointing at the token that should
/// begin a (possibly schema-qualified, possibly quoted) table name, return
/// `(unqualified_lowercase_name, next_index)`. Handles `schema . name`
/// (3 tokens) and bare `name` (1 token), where either part may be a quoted
/// identifier. Returns `None` if no identifier token is at `idx`.
pub fn parse_table_name(tokens: &[Token], idx: usize) -> Option<(String, usize)> {
    let first = tokens.get(idx)?;
    if first.text == "."
        || first.text == "("
        || first.text == ")"
        || first.text == ";"
        || first.text == ","
    {
        return None;
    }
    // Is this `schema . name`? Look for a `.` immediately following.
    if let (Some(dot), Some(name)) = (tokens.get(idx + 1), tokens.get(idx + 2)) {
        if dot.text == "." && !dot.quoted && is_identifier_token(name) {
            return Some((unqualified(name), idx + 3));
        }
    }
    if is_identifier_token(first) {
        return Some((unqualified(first), idx + 1));
    }
    None
}

/// Recover a 1-based line number for a byte offset in `source`.
pub fn line_of(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}
