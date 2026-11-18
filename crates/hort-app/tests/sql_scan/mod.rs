//! Shared token-aware SQL scanning primitives for the structural guards
//! that read SQL — the `migrations/` pair (ADR 0030,
//! `docs/adr/0030-sensitive-surface-structural-guards.md`) and the guards
//! that read SQL out of the Rust string literals it is embedded in.
//!
//! Two guard targets scan `migrations/` for different destructive shapes —
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
//!     and neither may trip a guard. A guard whose subject IS a literal
//!     value — the admitted set of an enum `CHECK` only means anything as a
//!     set of values — takes the [`strip_comments`] view instead, where the
//!     literals survive as their own token kind that no identifier or
//!     keyword test accepts. Erased or typed, a literal is never read as an
//!     identifier.
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
/// This is the view for a matcher that reads identifiers. A matcher that
/// reads literal *values* wants [`strip_comments`] instead.
pub fn strip_comments_and_strings(source: &str) -> String {
    strip(source, Literals::Blank)
}

/// Strip comments but KEEP the `'…'` SQL string literals — the view for a
/// matcher whose subject is a literal **value** rather than an identifier.
/// An enum `CHECK`'s admitted set is only a set of values, so comparing two
/// of them is impossible in the blanked view above.
///
/// Keeping them does not loosen the discipline. [`tokenize`] emits each
/// surviving literal as its own token, flagged [`Token::string_literal`],
/// and every identifier and keyword test here rejects such a token
/// ([`is_identifier_token`], [`parse_table_name`]) — so a literal still
/// cannot be read as an identifier, which is the entire reason the other
/// view blanks it. Comments are gone in both views, and in both views a
/// literal's `--` is not a comment and a comment's `'` is not a literal, so
/// the two views never disagree about which bytes are code.
pub fn strip_comments(source: &str) -> String {
    strip(source, Literals::Keep)
}

/// What [`strip`] does with a SQL string literal: blank it (so no matcher
/// can see it at all) or keep it (so [`tokenize`] can hand its value over).
/// Comments are removed either way — a comment is prose, never a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Literals {
    Blank,
    Keep,
}

/// The one comment walk both views share.
///
/// Block comments are stripped first (they can contain `--` and `'`), then a
/// single linear pass handles line comments and string literals together —
/// which it must, because a `--` inside a literal does not open a comment
/// and a `'` inside a line comment does not open a literal. Splitting that
/// pass into two independent ones is how the two views would come to
/// disagree about where a statement ends.
fn strip(source: &str, literals: Literals) -> String {
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

    // Pass 2: remove `--` line comments, and blank `'...'` string literals
    // when the caller asked for it, in a single linear walk. A `--` only
    // starts a comment when NOT inside a string literal; a `'` only opens a
    // string when NOT inside a line comment. SQL escapes a single quote
    // inside a string by doubling it (`''`), which this walk handles by
    // toggling twice (open then close) — the net effect (an empty
    // inter-quote span) is harmless for the blanked view, and for the kept
    // view [`tokenize`] re-reads the doubling as the escape it is.
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
            // In the blanked view, string contents (and the quotes) become
            // spaces so a `--` or a table name inside a literal cannot trip
            // the scan.
            out.push(if literals == Literals::Blank {
                ' '
            } else {
                c as char
            });
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
            out.push(if literals == Literals::Blank {
                ' '
            } else {
                '\''
            });
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

/// A SQL token: an identifier/keyword word, a punctuation char, a
/// double-quoted identifier, or — only in the [`strip_comments`] view — a
/// `'…'` string literal. Whitespace is the separator and is not emitted.
/// Tokens carry the byte offset of their start in the stripped source they
/// were read from, so a match can be mapped back to a line.
#[derive(Debug, Clone)]
pub struct Token {
    /// For a word: the lower-cased text. For a quoted identifier: the raw
    /// inner text (case preserved, but compared case-insensitively
    /// downstream). For a string literal: the literal's VALUE with case
    /// preserved and any `''` escape resolved — a literal is a value, and
    /// `'Scan'` is not `'scan'`. For punctuation: the single char as a
    /// string.
    pub text: String,
    /// `true` when this token came from a `"..."` quoted identifier.
    pub quoted: bool,
    /// `true` when this token came from a `'…'` SQL string literal, which
    /// survives only the [`strip_comments`] view — the other view blanks it
    /// before tokenizing, so a matcher reading that view never sees one.
    ///
    /// A literal is never an identifier and never a keyword:
    /// [`is_identifier_token`] and [`parse_table_name`] both reject it, and
    /// a matcher comparing `text` against a keyword must do the same (a
    /// `DEFAULT 'table'` would otherwise read as the `TABLE` keyword). That
    /// rejection is what makes keeping literals safe; it is the typed form
    /// of the same rule the blanked view enforces by erasure.
    pub string_literal: bool,
    /// Byte offset of the token start within the stripped source.
    pub offset: usize,
}

/// Tokenize a stripped source. Words are runs of `[A-Za-z0-9_]`,
/// double-quoted identifiers are `"..."`, `'…'` string literals are emitted
/// as [`Token::string_literal`] tokens carrying their value, and `.`, `(`,
/// `)`, `,`, `;` are emitted as single-char punctuation tokens. Anything
/// else (operators, etc.) is skipped — it never participates in the
/// statement shapes the matchers recognise.
///
/// Fed the [`strip_comments_and_strings`] view there are no literals left to
/// emit, so that caller sees exactly what it always did; fed the
/// [`strip_comments`] view it gets the literal values too.
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
                string_literal: false,
                offset: start,
            });
            i = if j < bytes.len() { j + 1 } else { bytes.len() };
            continue;
        }
        if c == b'\'' {
            // A `'…'` string literal, which only the `strip_comments` view
            // still contains. `''` is SQL's escape for one quote inside the
            // literal, so it continues the same token rather than closing
            // it — the thing being read here is the VALUE, and a value that
            // contains a quote is still one value.
            let start = i;
            let mut value = String::new();
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'\'' {
                    if bytes.get(j + 1) == Some(&b'\'') {
                        value.push('\'');
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                // Copy whole characters, not bytes: a literal's value is
                // compared as text.
                let Some(ch) = source[j..].chars().next() else {
                    break;
                };
                value.push(ch);
                j += ch.len_utf8();
            }
            tokens.push(Token {
                text: value,
                quoted: false,
                string_literal: true,
                offset: start,
            });
            i = j;
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
                string_literal: false,
                offset: start,
            });
            i = j;
            continue;
        }
        if matches!(c, b'.' | b'(' | b')' | b',' | b';') {
            tokens.push(Token {
                text: (c as char).to_string(),
                quoted: false,
                string_literal: false,
                offset: i,
            });
        }
        i += 1;
    }
    tokens
}

/// `true` when a token can serve as a SQL identifier (a word that is not
/// punctuation, or any quoted identifier).
///
/// A `'…'` string literal never can, whatever its value spells: it is the
/// one token kind that carries arbitrary text, so admitting it would let a
/// `DEFAULT 'artifacts'` read as a table reference.
pub fn is_identifier_token(t: &Token) -> bool {
    if t.string_literal {
        return false;
    }
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
    if !is_identifier_token(first) {
        return None;
    }
    // Is this `schema . name`? Look for a `.` immediately following. The
    // separator must be real punctuation: a `'.'` string literal carries the
    // same `text` and is not a qualifier.
    if let (Some(dot), Some(name)) = (tokens.get(idx + 1), tokens.get(idx + 2)) {
        if dot.text == "." && !dot.quoted && !dot.string_literal && is_identifier_token(name) {
            return Some((unqualified(name), idx + 3));
        }
    }
    if is_identifier_token(first) {
        return Some((unqualified(first), idx + 1));
    }
    None
}

/// Everything in `lower` before the table name at `at`, with a trailing
/// `<schema>.` qualifier and trailing whitespace removed — so the result
/// ends with whatever keyword or punctuation introduced the reference.
/// `lower` must already be lowercased.
///
/// `None` when nothing separates the identifier from what precedes it (a
/// longer identifier that merely contains the table name, or a match at
/// offset 0), and when a `.` has no identifier before it to be a
/// qualifier.
pub fn before_table_name(lower: &str, at: usize) -> Option<&str> {
    let raw = &lower[..at];
    let trimmed = raw.trim_end();
    if let Some(without_dot) = trimmed.strip_suffix('.') {
        let qualifier_start = without_dot
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |found| found + 1);
        if qualifier_start == without_dot.len() {
            // A `.` with no identifier before it — not a qualifier.
            return None;
        }
        return Some(without_dot[..qualifier_start].trim_end());
    }
    if trimmed.len() == raw.len() {
        // No separator at all.
        return None;
    }
    Some(trimmed)
}

/// The SQL keyword introducing the table reference at `at`, lowercased —
/// stepping over an optional `<schema>.` qualifier first. `lower` must
/// already be lowercased.
///
/// This is what tells a table *reference* (`FROM artifacts`, `JOIN
/// public.artifacts`) apart from the same identifier in some other
/// position (`INSERT INTO artifacts`, a prose mention, a longer
/// identifier that merely contains it).
///
/// `None` when nothing separates the identifier from what precedes it (a
/// longer identifier that merely contains the table name, or a match at
/// offset 0), which is not a table reference after a keyword.
pub fn preceding_keyword(lower: &str, at: usize) -> Option<String> {
    let before = before_table_name(lower, at)?;
    let word = before.rsplit(|c: char| c.is_whitespace()).next()?;
    if word.is_empty() {
        return None;
    }
    Some(word.to_string())
}

/// Recover a 1-based line number for a byte offset in `source`.
pub fn line_of(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}
