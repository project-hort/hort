//! Migration sensitive-table drop guard (ADR 0030,
//! `docs/adr/0030-sensitive-surface-structural-guards.md`).
//!
//! This DB-free, network-free source-scan is the **committed proof**
//! (in the spirit of `ephemeral_keyspace_exhaustive` / `no_bcrypt` /
//! `alpha_fixtures` / `streaming_metadata_port`) that no SQL migration
//! under `migrations/` ever issues a destructive statement against a
//! security-critical ("sensitive") table.
//!
//! ## Why a guard and not just operator guidance
//!
//! Before this guard, the invariant was doc-only: the migration
//! runbooks say "do not drop sensitive tables in a migration," but
//! nothing enforced it. A migration that `DROP TABLE users` (or drops the primary-key
//! constraint of `api_tokens`, or `DROP TABLE IF EXISTS
//! permission_grants`) would destroy the authorization model, the audit
//! event store, or the credential store — and would sail through CI,
//! because the migration runner is happy to execute it. This guard
//! converts the runbook prose into a red test: the destructive shapes
//! against the maintained sensitive set below are a hard failure.
//!
//! ## What it asserts
//!
//! Every `*.sql` file under the workspace-root `migrations/` directory
//! is scanned (comments and string literals stripped first — see the
//! matcher discipline below) for these three destructive statement
//! shapes against any table in [`SENSITIVE_TABLES`] (or the `events_`
//! prefix family):
//!
//!   1. `DROP TABLE <name>`
//!   2. `DROP TABLE IF EXISTS <name>`
//!   3. `ALTER TABLE <name> DROP CONSTRAINT <cname>` (de-constrain) —
//!      **unless** the same migration re-adds a constraint of the same
//!      `_check` name (a DROP + re-ADD of a `_check` constraint is an
//!      enum-CHECK *widening*, not a de-constrain).
//!
//! A match in any migration is a hard failure naming the file:line.
//!
//! ## The DROP+re-ADD redefinition exception — `_check`-only (ADR 0030 intent)
//!
//! ADR 0030's stated boundary is "no migration may **drop or
//! de-constrain** a sensitive table" — the canonical breach is
//! `DROP CONSTRAINT api_tokens_pkey`, which leaves the table *less*
//! protected (identity / integrity gone). The one legitimate
//! drop-and-re-add-under-the-same-name is widening an enum `CHECK`:
//! PostgreSQL has no in-place `CHECK` alter, so the only way to extend an
//! allowed-value set (e.g. adding a task kind to `jobs.kind`, migration 016)
//! is to drop and re-add the same named constraint over a superset of
//! values, and PostgreSQL auto-names such a constraint `<table>_<col>_check`.
//!
//! The exemption is therefore an **allow-list restricted to constraint
//! names ending in `_check`** (case-insensitive — see
//! [`is_widenable_check_name`]): a `DROP CONSTRAINT <name>_..._check`
//! immediately paired with an `ADD CONSTRAINT` of the **same `_check`
//! name** on the **same table** is an enum-CHECK widening and is exempt.
//! Any other dropped name — `_pkey` / `_fkey` / `_key` / `_unique`, or any
//! non-`_check` name — does **not** earn the exemption *even if* the same
//! migration re-adds a same-named constraint, because integrity constraints
//! are never legitimately drop+re-added to widen: a same-name re-add can be
//! a no-op or weaker constraint (`DROP CONSTRAINT api_tokens_pkey;
//! ADD CONSTRAINT api_tokens_pkey CHECK (true);` drops a primary key and
//! re-adds a no-op same-named CHECK — the table emerges LESS protected while
//! the shape looks like a redefinition). The allow-list is **fail-closed**:
//! an unconventionally-named integrity constraint cannot slip through under
//! the redefinition cover (a deny-list would be fail-open). The exemption is
//! also **table-scoped**: a same-name `ADD CONSTRAINT` on a *different* table
//! does NOT exempt the de-constrain (that would be a false negative). A bare
//! `DROP CONSTRAINT` with no matching same-table same-`_check`-name re-add
//! is still a hard failure.
//!
//! ## Matcher discipline (mirror of `streaming_metadata_port.rs`)
//!
//! Naive substring matching is wrong here: migration `009` legitimately
//! `DROP TABLE IF EXISTS public.scans` (a NON-sensitive prototype table),
//! several migrations mention `DROP TABLE IF EXISTS public.jobs` inside a
//! `--` reversal-runbook comment, and table names like `repo_security_scores`
//! must NOT be confused with the sensitive `repositories` /
//! `repository_upstream_mappings`. So the matcher is token-aware:
//!
//!   * **Comments and string literals are stripped first.** `/* … */`
//!     block comments, then `--` line comments, then `'…'` SQL string
//!     literals are removed before any pattern scan. A reversal-runbook
//!     comment mentioning `DROP TABLE IF EXISTS public.jobs` therefore
//!     cannot trip the guard.
//!   * **Identifiers match as whole tokens**, not substrings. The table
//!     name is parsed as a SQL identifier (optionally schema-qualified
//!     `public.users`, optionally double-quoted `"users"`), and compared
//!     against the sensitive set by exact, case-insensitive equality (SQL
//!     keywords and identifiers are case-insensitive when unquoted). So a
//!     longer identifier such as `repo_security_scores` or
//!     `service_account_federated_identities` does NOT match
//!     `repositories` / `service_accounts`.
//!   * **`events_` prefix family.** Any table whose unqualified name
//!     starts with `events_` (e.g. a future `events_archive`) is treated
//!     as sensitive, plus the bare `events` event-store table itself.
//!   * **rustfmt / SQL-formatter survival.** The scan normalizes runs of
//!     whitespace, so reformatting a migration (re-indenting, collapsing
//!     or expanding spaces around `DROP CONSTRAINT`) does not change the
//!     verdict.
//!
//! ## Maintenance — the sensitive list is permanent and audited
//!
//! [`SENSITIVE_TABLES`] is INLINE in this test on purpose: adding a new
//! sensitive table later is a self-contained, deliberate, reviewable
//! edit. The list is the ADR 0030 set — it is a security boundary, not a
//! convenience, so removing an entry or weakening a matcher to make a
//! drop pass is a blocking review finding, not a fix. If a migration
//! legitimately must drop a sensitive table (it almost never should), the
//! correct response is to question the migration, not to edit this list.
//!
//! ## Why no `regex` / `walkdir` dep
//!
//! `std::fs` + string scanning, identical to the sibling guards. The
//! three statement shapes are recognisable by token walking; a `regex`
//! dev-dep is not warranted.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

/// The maintained sensitive-table set (ADR 0030).
///
/// **This is a permanent, audited security boundary.** Each table here
/// carries authorization state, credentials, the immutable audit event
/// store, repository/upstream configuration, or the task queue. A
/// migration that drops one of these (or its primary-key constraint)
/// destroys a security-critical invariant. Adding a new sensitive table
/// is a deliberate edit; removing one or weakening the matcher to let a
/// drop through is a blocking review finding.
///
/// In addition to these exact names, the bare event-store table `events`
/// AND any table whose unqualified name starts with `events_` are treated
/// as sensitive (see [`is_sensitive_table`]). `_sqlx_migrations` (the sqlx
/// migration ledger) is in the list verbatim.
const SENSITIVE_TABLES: &[&str] = &[
    // Authorization model.
    "users",
    "claim_mappings",
    "permission_grants",
    "oidc_issuers",
    "service_accounts",
    // Credential store.
    "api_tokens",
    // Repository + upstream configuration.
    "repositories",
    "repository_upstream_mappings",
    // Task queue.
    "jobs",
    // Event store ledger. The event-store table itself is `events`
    // (handled as an exact + `events_` prefix match in `is_sensitive_table`);
    // `_sqlx_migrations` is the sqlx applied-migration ledger.
    "_sqlx_migrations",
];

/// Returns `true` when `name` (an unqualified, unquoted, lower-cased SQL
/// table identifier) is sensitive: it is an exact member of
/// [`SENSITIVE_TABLES`], OR it is the bare event-store table `events`, OR
/// it starts with the `events_` prefix family.
fn is_sensitive_table(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if name == "events" || name.starts_with("events_") {
        return true;
    }
    SENSITIVE_TABLES
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&name))
}

/// Locate the workspace-root `migrations/` directory from
/// `CARGO_MANIFEST_DIR` (`<root>/crates/hort-app`), so two levels up is
/// the workspace root. Mirrors how the sibling guards resolve their scan
/// roots relative to `CARGO_MANIFEST_DIR`.
fn migrations_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)");
    root.join("migrations")
}

// ---------------------------------------------------------------------------
// Comment / string stripping.
// ---------------------------------------------------------------------------

/// Strip `/* … */` block comments, `--` line comments, and `'…'` SQL
/// string literals from a migration source, replacing the stripped span
/// with a single space so token boundaries are preserved. This is what
/// makes the matcher token-aware rather than naive-substring: a
/// `DROP TABLE IF EXISTS public.jobs` inside a reversal-runbook comment
/// is removed before any pattern scan.
///
/// SQL identifier double-quotes (`"…"`) are NOT stripped — they are part
/// of the identifier and the table-name parser handles them.
///
/// Block comments are stripped first (they can contain `--` and `'`),
/// then a single linear pass handles line comments and string literals.
fn strip_comments_and_strings(source: &str) -> String {
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
// Tokenizer + statement matcher.
// ---------------------------------------------------------------------------

/// A SQL token: either an identifier/keyword word, a punctuation char, or
/// a double-quoted identifier. Whitespace is the separator and is not
/// emitted. Tokens carry the byte offset of their start in the
/// (comment-stripped) source so a match can be mapped back to a line.
#[derive(Debug, Clone)]
struct Token {
    /// For a word: the lower-cased text. For a quoted identifier: the
    /// raw inner text (case preserved, but compared case-insensitively
    /// downstream). For punctuation: the single char as a string.
    text: String,
    /// `true` when this token came from a `"..."` quoted identifier.
    quoted: bool,
    /// Byte offset of the token start within the stripped source.
    offset: usize,
}

/// Tokenize the comment-stripped source. Words are runs of
/// `[A-Za-z0-9_]`, double-quoted identifiers are `"..."`, and `.`, `(`,
/// `)`, `,`, `;` are emitted as single-char punctuation tokens. Anything
/// else (operators, etc.) is skipped — it never participates in the three
/// statement shapes we match.
fn tokenize(source: &str) -> Vec<Token> {
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

/// Given the token stream and an index pointing at the token that should
/// begin a (possibly schema-qualified, possibly quoted) table name,
/// return `(unqualified_lowercase_name, next_index)`. Handles
/// `schema . name` (3 tokens) and bare `name` (1 token), where either
/// part may be a quoted identifier. Returns `None` if no identifier token
/// is at `idx`.
fn parse_table_name(tokens: &[Token], idx: usize) -> Option<(String, usize)> {
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

/// `true` when a token can serve as a SQL identifier (a word that is not
/// punctuation, or any quoted identifier).
fn is_identifier_token(t: &Token) -> bool {
    if t.quoted {
        return true;
    }
    !matches!(t.text.as_str(), "." | "(" | ")" | "," | ";")
}

/// Lower-cased unqualified name of an identifier token.
fn unqualified(t: &Token) -> String {
    t.text.to_ascii_lowercase()
}

/// A destructive statement matched against a sensitive table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    /// `"DROP TABLE"` or `"ALTER TABLE ... DROP CONSTRAINT"`.
    shape: String,
    /// The matched sensitive table name (unqualified, lower-cased).
    table: String,
    /// Byte offset of the matched statement's first keyword in the
    /// stripped source — used to recover a line number.
    offset: usize,
}

/// Scan a comment-stripped, tokenized migration for the three destructive
/// statement shapes against a sensitive table. Returns every match.
///
/// Shapes (case-insensitive keywords, already lower-cased by the tokenizer):
///   1. `drop table [ if exists ] <name>`
///   2. `alter table <name> ... drop constraint <pkey>`
///
/// For shape 2 we flag any `DROP CONSTRAINT` on a sensitive table — the
/// ADR 0030 intent is the primary-key drop, but dropping any constraint on
/// a sensitive table is at least as alarming and warrants the same red test.
/// Does the migration re-add constraint `cname` **on the same table**
/// `table` that a `DROP CONSTRAINT` removed it from? Used to distinguish an
/// enum-CHECK *widening* (DROP + re-ADD the same name on the same table —
/// exempt only when `cname` is a `_check` name, see
/// [`is_widenable_check_name`] at the call site) from a bare de-constraining
/// DROP. This helper answers only the same-name/same-table re-add question;
/// the `_check`-only gate is applied by the caller, so a `_pkey` / `_fkey` /
/// `_key` / `_unique` drop is never exempted regardless of a same-name
/// re-add. The re-add is conventionally a separate `ALTER TABLE <table> …
/// ADD CONSTRAINT <cname> …` statement, so this walks the whole migration
/// for `ALTER TABLE` statements whose target table equals `table` and scans
/// each such statement (up to its terminating `;`) for `ADD CONSTRAINT
/// <cname>`.
///
/// The table scoping is load-bearing: a same-name `ADD CONSTRAINT` on a
/// *different* table must NOT exempt a sensitive de-constrain — that would
/// be a false negative (a genuine de-constrain of the sensitive table
/// passing because some unrelated table happens to add a constraint of the
/// same name). Both the table and the constraint name are compared
/// case-insensitively (SQL identifiers are case-insensitive when unquoted).
/// `true` when a dropped-constraint name is eligible for the DROP+re-ADD
/// redefinition exemption: an **allow-list** of names ending in `_check`
/// (case-insensitive).
///
/// This is the load-bearing tightening of the exemption (ADR 0030
/// amendment): the *only* legitimate drop-and-re-add-under-the-same-name on
/// a sensitive table is widening an enum `CHECK`, which PostgreSQL
/// auto-names `<table>_<col>_check`. Restricting the exemption to `_check`
/// names is **fail-closed** — an integrity constraint (`_pkey` / `_fkey` /
/// `_key` / `_unique`, or any unconventionally-named constraint) can never
/// slip through under the redefinition cover. The danger the allow-list
/// closes: `DROP CONSTRAINT api_tokens_pkey; ADD CONSTRAINT api_tokens_pkey
/// CHECK (true);` — a primary key dropped, re-added as a no-op same-named
/// CHECK — leaves the table LESS protected while the same-name shape looks
/// like a benign redefinition. A deny-list (flag known-bad suffixes) would
/// be fail-open: a future unconventionally-named integrity constraint would
/// not match any deny entry and would wrongly earn the exemption. The
/// allow-list cannot be slipped past.
fn is_widenable_check_name(cname: &str) -> bool {
    cname.to_ascii_lowercase().ends_with("_check")
}

fn readds_constraint(tokens: &[Token], table: &str, cname: &str) -> bool {
    let target_table = table.to_ascii_lowercase();
    let target_cname = cname.to_ascii_lowercase();
    let n = tokens.len();
    let mut i = 0;
    while i < n {
        // Find the start of an `ALTER TABLE [IF EXISTS] [ONLY] <name>`.
        if tokens[i].text == "alter" && !tokens[i].quoted {
            if let Some(next) = tokens.get(i + 1) {
                if next.text == "table" && !next.quoted {
                    let mut name_idx = i + 2;
                    // Optional `IF EXISTS`.
                    if let (Some(a), Some(b)) = (tokens.get(name_idx), tokens.get(name_idx + 1)) {
                        if a.text == "if" && b.text == "exists" && !a.quoted && !b.quoted {
                            name_idx += 2;
                        }
                    }
                    // Optional `ONLY`.
                    if let Some(a) = tokens.get(name_idx) {
                        if a.text == "only" && !a.quoted {
                            name_idx += 1;
                        }
                    }
                    if let Some((name, after_name)) = parse_table_name(tokens, name_idx) {
                        if name == target_table {
                            // Scan this ALTER statement (to the terminating
                            // `;`) for `ADD CONSTRAINT <cname>`.
                            let mut k = after_name;
                            while k + 2 < n && tokens[k].text != ";" {
                                if tokens[k].text == "add"
                                    && !tokens[k].quoted
                                    && tokens[k + 1].text == "constraint"
                                    && !tokens[k + 1].quoted
                                    && tokens[k + 2].text.eq_ignore_ascii_case(&target_cname)
                                {
                                    return true;
                                }
                                k += 1;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    false
}

fn find_sensitive_drops(tokens: &[Token]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let n = tokens.len();
    let mut i = 0;
    while i < n {
        let w = tokens[i].text.as_str();
        // Skip past quoted identifiers when matching keyword sequences.
        let is_word = !tokens[i].quoted
            && tokens[i]
                .text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');

        // ---- Shape 1: DROP TABLE [IF EXISTS] <name> --------------------
        if is_word && w == "drop" {
            if let Some(next) = tokens.get(i + 1) {
                if next.text == "table" && !next.quoted {
                    // Optional `IF EXISTS`.
                    let mut name_idx = i + 2;
                    if let (Some(a), Some(b)) = (tokens.get(i + 2), tokens.get(i + 3)) {
                        if a.text == "if" && b.text == "exists" && !a.quoted && !b.quoted {
                            name_idx = i + 4;
                        }
                    }
                    if let Some((name, _next)) = parse_table_name(tokens, name_idx) {
                        if is_sensitive_table(&name) {
                            findings.push(Finding {
                                shape: "DROP TABLE".to_string(),
                                table: name,
                                offset: tokens[i].offset,
                            });
                        }
                    }
                }
            }
        }

        // ---- Shape 2: ALTER TABLE <name> ... DROP CONSTRAINT <pkey> ----
        if is_word && w == "alter" {
            if let Some(next) = tokens.get(i + 1) {
                if next.text == "table" && !next.quoted {
                    // `ALTER TABLE [IF EXISTS] [ONLY] <name>`.
                    let mut name_idx = i + 2;
                    // Skip an optional `IF EXISTS`.
                    if let (Some(a), Some(b)) = (tokens.get(name_idx), tokens.get(name_idx + 1)) {
                        if a.text == "if" && b.text == "exists" && !a.quoted && !b.quoted {
                            name_idx += 2;
                        }
                    }
                    // Skip an optional `ONLY`.
                    if let Some(a) = tokens.get(name_idx) {
                        if a.text == "only" && !a.quoted {
                            name_idx += 1;
                        }
                    }
                    if let Some((name, after_name)) = parse_table_name(tokens, name_idx) {
                        if is_sensitive_table(&name) {
                            // Look ahead within this ALTER statement (up to
                            // the terminating `;`) for `DROP CONSTRAINT
                            // <cname>`.
                            let mut k = after_name;
                            while k + 1 < n && tokens[k].text != ";" {
                                if tokens[k].text == "drop"
                                    && !tokens[k].quoted
                                    && tokens[k + 1].text == "constraint"
                                    && !tokens[k + 1].quoted
                                {
                                    // The constraint name token (skip an
                                    // optional `IF EXISTS`).
                                    let mut cn = k + 2;
                                    if let (Some(a), Some(b)) = (tokens.get(cn), tokens.get(cn + 1))
                                    {
                                        if a.text == "if" && b.text == "exists" {
                                            cn += 2;
                                        }
                                    }
                                    let cname = tokens.get(cn).map(|t| t.text.clone());

                                    // A DROP+re-ADD of the SAME constraint
                                    // name in this migration is a constraint
                                    // *redefinition*, not a de-constrain — the
                                    // table emerges still constrained, so it
                                    // does not breach ADR 0030's "no migration
                                    // may drop or de-constrain a sensitive
                                    // table" boundary (the stated intent is the
                                    // primary-key / integrity drop that leaves
                                    // the table *less* protected). The canonical
                                    // case is widening an enum `CHECK` (e.g.
                                    // `jobs.kind`) to add a value: PostgreSQL
                                    // has no in-place CHECK alter, so the only
                                    // way to extend it is drop + re-add the same
                                    // named constraint over a superset of
                                    // allowed values. A bare DROP CONSTRAINT
                                    // with no matching re-add IS still flagged
                                    // (genuine de-constrain).
                                    //
                                    // The exemption is **`_check`-only** (fail-
                                    // closed allow-list, see
                                    // [`is_widenable_check_name`]): only a
                                    // PostgreSQL auto-named enum `CHECK`
                                    // (`<table>_<col>_check`) is ever
                                    // legitimately dropped + re-added under the
                                    // same name to *widen* an allowed-value set.
                                    // Integrity constraints — `_pkey` / `_fkey`
                                    // / `_key` / `_unique`, or any non-`_check`
                                    // name — are never legitimately drop+re-added
                                    // to widen: a same-name re-add can silently
                                    // be a no-op or weaker constraint (e.g. DROP
                                    // a PRIMARY KEY, re-ADD a same-named
                                    // `CHECK (true)`), leaving the table LESS
                                    // protected while the shape looks like a
                                    // redefinition. So a non-`_check` dropped
                                    // name does NOT earn the exemption and is
                                    // always flagged, regardless of any
                                    // same-name re-add.
                                    let redefined = cname
                                        .as_deref()
                                        .map(|c| {
                                            is_widenable_check_name(c)
                                                && readds_constraint(tokens, &name, c)
                                        })
                                        .unwrap_or(false);
                                    if !redefined {
                                        findings.push(Finding {
                                            shape: "ALTER TABLE ... DROP CONSTRAINT".to_string(),
                                            table: name.clone(),
                                            offset: tokens[i].offset,
                                        });
                                    }
                                    break;
                                }
                                k += 1;
                            }
                        }
                    }
                }
            }
        }

        i += 1;
    }
    findings
}

/// Recover a 1-based line number for a byte offset in `source`.
fn line_of(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

/// Full scan of one migration source: strip comments/strings, tokenize,
/// match. Returns `(line, shape, table)` findings.
fn scan_migration(source: &str) -> Vec<(usize, String, String)> {
    let stripped = strip_comments_and_strings(source);
    let tokens = tokenize(&stripped);
    find_sensitive_drops(&tokens)
        .into_iter()
        .map(|f| (line_of(&stripped, f.offset), f.shape, f.table))
        .collect()
}

// ---------------------------------------------------------------------------
// The actual guard test over the real migrations/ tree.
// ---------------------------------------------------------------------------

#[test]
fn no_migration_drops_a_sensitive_table() {
    let dir = migrations_dir();
    assert!(
        dir.is_dir(),
        "migrations directory not found at {dir:?} — the guard's path layout drifted; \
         CARGO_MANIFEST_DIR is expected to be <root>/crates/hort-app and migrations/ at the root."
    );

    let mut sql_files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("sql"))
        .collect();
    sql_files.sort();

    assert!(
        !sql_files.is_empty(),
        "no *.sql files found under {dir:?} — a path error would otherwise let this guard \
         pass vacuously."
    );

    let mut hits: Vec<String> = Vec::new();
    for path in &sql_files {
        let source = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        for (line, shape, table) in scan_migration(&source) {
            hits.push(format!(
                "{}:{}: {} on sensitive table '{}'",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                line,
                shape,
                table
            ));
        }
    }

    assert!(
        hits.is_empty(),
        "ADR 0030: a migration issues a destructive statement against a sensitive table. \
         Sensitive tables (the ADR 0030 set) carry the authorization model, credential store, \
         immutable event store, repository config, or task queue — dropping one (or its \
         primary-key constraint) destroys a security-critical invariant. If a drop is genuinely \
         required, question the migration; do NOT weaken this guard. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Self-tests for the matcher (no I/O) — seed deliberately-bad and
// deliberately-benign migration strings and pin the verdict, so a future
// refactor cannot silently weaken the guard.
// ---------------------------------------------------------------------------

/// `true` if the scan of `sql` produced at least one finding.
fn trips(sql: &str) -> bool {
    !scan_migration(sql).is_empty()
}

// ---- POSITIVE self-checks: the matcher MUST flag these. -------------------

#[test]
fn self_check_drop_table_users_trips() {
    assert!(trips("DROP TABLE users;"));
}

#[test]
fn self_check_drop_table_if_exists_schema_qualified_trips() {
    assert!(trips("DROP TABLE IF EXISTS public.permission_grants;"));
}

#[test]
fn self_check_alter_table_drop_pkey_constraint_trips() {
    assert!(trips(
        "ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_pkey;"
    ));
}

#[test]
fn self_check_lowercase_keywords_trip() {
    // SQL keywords are case-insensitive; a lower-cased drop must trip.
    assert!(trips("drop table oidc_issuers cascade;"));
}

#[test]
fn self_check_quoted_identifier_trips() {
    // A double-quoted sensitive identifier must still be recognised.
    assert!(trips(r#"DROP TABLE "users";"#));
    assert!(trips(r#"DROP TABLE public."service_accounts";"#));
}

#[test]
fn self_check_events_prefix_family_trips() {
    // The `events_` prefix family is sensitive (event store).
    assert!(trips("DROP TABLE IF EXISTS public.events_archive;"));
    // The bare event-store table too.
    assert!(trips("DROP TABLE events;"));
    assert!(trips("DROP TABLE _sqlx_migrations;"));
}

#[test]
fn self_check_alter_table_with_if_exists_and_only_trips() {
    // Optional `IF EXISTS` / `ONLY` qualifiers between TABLE and the name
    // must not hide the sensitive table.
    assert!(trips(
        "ALTER TABLE IF EXISTS ONLY repositories DROP CONSTRAINT repositories_pkey;"
    ));
}

#[test]
fn self_check_whitespace_reformat_survives() {
    // Reformatting (extra / collapsed whitespace, newlines) must not
    // change the verdict — rustfmt/SQL-formatter survival.
    assert!(trips(
        "ALTER  TABLE\n   jobs\n   DROP   CONSTRAINT   jobs_pkey ;"
    ));
}

#[test]
fn self_check_drop_constraint_with_unrelated_readd_still_trips() {
    // A DROP CONSTRAINT whose name is NOT re-added (a different name is
    // added) is a genuine de-constrain → still flagged. The exception is
    // scoped to a same-NAME redefinition, not "any ADD CONSTRAINT exists".
    assert!(trips(
        "ALTER TABLE jobs DROP CONSTRAINT jobs_pkey;\n\
         ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('scan'));"
    ));
}

#[test]
fn self_check_drop_constraint_with_same_name_readd_on_other_table_still_trips() {
    // The redefinition exemption is TABLE-SCOPED: a same-NAME
    // `ADD CONSTRAINT` on a DIFFERENT table must NOT exempt a sensitive
    // de-constrain. Here the sensitive `api_tokens` is genuinely
    // de-constrained (its constraint is dropped and never re-added on
    // `api_tokens`); the matching name is re-added only on the unrelated
    // `other_table`. Without table scoping this would be a false negative;
    // it MUST still trip.
    assert!(trips(
        "ALTER TABLE api_tokens DROP CONSTRAINT shared_name;\n\
         ALTER TABLE other_table ADD CONSTRAINT shared_name CHECK (x IN ('a'));"
    ));
}

#[test]
fn self_check_drop_pkey_readd_same_name_noop_check_still_trips() {
    // The reviewer's exact attack (ADR 0030 amendment): drop a PRIMARY KEY
    // and re-add a NO-OP same-named CHECK. The shape (same-name DROP +
    // re-ADD on the same table) is exactly the redefinition shape, but the
    // dropped name `api_tokens_pkey` is NOT a `_check` name, so it does NOT
    // earn the `_check`-only exemption. The table emerges LESS protected
    // (its primary key gone, replaced by a no-op CHECK) — this MUST trip.
    assert!(trips(
        "ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_pkey;\n\
         ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_pkey CHECK (true);"
    ));
}

#[test]
fn self_check_drop_unique_readd_same_name_non_check_still_trips() {
    // Same fail-closed property for a `_key` / `_unique` integrity
    // constraint: a same-name re-add of a non-`_check` constraint does NOT
    // exempt the de-constrain. (A `_key`/`_unique` name is never a widenable
    // enum CHECK.)
    assert!(trips(
        "ALTER TABLE users DROP CONSTRAINT users_email_key;\n\
         ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);"
    ));
}

// ---- NEGATIVE self-checks: the matcher must NOT flag these. ---------------

#[test]
fn self_check_check_widen_drop_and_readd_same_name_does_not_trip() {
    // ADR 0030 redefinition exception: dropping and re-adding the SAME
    // named CHECK constraint (the only way to widen an enum CHECK in
    // PostgreSQL — e.g. adding a `jobs.kind` value) leaves the table still
    // constrained, so it is NOT a de-constrain and must NOT trip. This is
    // exactly the shape of migration 016 (policy-reevaluation job kind).
    assert!(!trips(
        "ALTER TABLE public.jobs DROP CONSTRAINT jobs_kind_check;\n\
         ALTER TABLE public.jobs ADD CONSTRAINT jobs_kind_check \
         CHECK (kind IN ('scan', 'policy-reevaluation'));"
    ));
}

#[test]
fn self_check_check_widen_redefinition_survives_reformat_and_case() {
    // The redefinition exception is whitespace- and case-insensitive on the
    // constraint name (SQL identifiers are case-insensitive unquoted).
    assert!(!trips(
        "alter  table\n  JOBS\n  drop  constraint  Jobs_Kind_Check ;\n\
         ALTER TABLE jobs ADD   CONSTRAINT   jobs_kind_check CHECK (kind IN ('x'));"
    ));
}

#[test]
fn self_check_comment_mentioning_drop_does_not_trip() {
    // A `--` reversal-runbook comment mentioning a sensitive drop must be
    // stripped before scanning (this is the real migration-009 shape).
    assert!(!trips(
        "--   DROP TABLE IF EXISTS public.jobs CASCADE;\nCREATE TABLE foo (id int);"
    ));
}

#[test]
fn self_check_block_comment_mentioning_drop_does_not_trip() {
    assert!(!trips(
        "/* reversal: DROP TABLE users; */\nCREATE TABLE foo (id int);"
    ));
}

#[test]
fn self_check_string_literal_mentioning_drop_does_not_trip() {
    // A sensitive-looking phrase inside a SQL string literal is not a
    // statement.
    assert!(!trips(
        "INSERT INTO audit (msg) VALUES ('DROP TABLE users');"
    ));
}

#[test]
fn self_check_drop_of_non_sensitive_table_does_not_trip() {
    assert!(!trips("DROP TABLE IF EXISTS public.scans CASCADE;"));
    assert!(!trips("DROP TABLE IF EXISTS public.scan_findings CASCADE;"));
    assert!(!trips(
        "DROP TABLE IF EXISTS public.repo_security_scores CASCADE;"
    ));
    assert!(!trips("DROP TABLE IF EXISTS public.scan_configs CASCADE;"));
}

#[test]
fn self_check_substring_table_name_does_not_trip() {
    // A longer identifier that merely CONTAINS a sensitive name as a
    // substring must not false-positive (token-aware, not substring).
    assert!(!trips("DROP TABLE repo_security_scores;")); // not `repositories`
    assert!(!trips(
        "DROP TABLE service_account_federated_identities;" // not `service_accounts`
    ));
    assert!(!trips("DROP TABLE user_preferences;")); // not `users`
    assert!(!trips("DROP TABLE eventsourcing_config;")); // not `events`/`events_`
}

#[test]
fn self_check_column_named_with_sensitive_word_does_not_trip() {
    // A CREATE/ALTER referencing a column whose name embeds a sensitive
    // table word must not trip — we only match the DROP TABLE / DROP
    // CONSTRAINT shapes, not arbitrary identifier mentions.
    assert!(!trips(
        "CREATE TABLE foo (users_count int, jobs_total int);"
    ));
    assert!(!trips("ALTER TABLE foo ADD COLUMN api_tokens_seen int;"));
}

#[test]
fn self_check_drop_column_on_sensitive_table_does_not_trip() {
    // `DROP COLUMN` is not in scope (the ADR 0030 shapes are DROP TABLE and
    // DROP CONSTRAINT). A column drop is non-destructive to the table's
    // existence/identity, so it is intentionally NOT flagged.
    assert!(!trips("ALTER TABLE users DROP COLUMN nickname;"));
}

#[test]
fn self_check_create_table_sensitive_does_not_trip() {
    // Creating a sensitive table is exactly what migrations do; only
    // destructive statements are flagged.
    assert!(!trips(
        "CREATE TABLE users (id uuid PRIMARY KEY, name text);"
    ));
}

#[test]
fn self_check_alter_table_add_constraint_does_not_trip() {
    // The real migration-008 shape: ADD CONSTRAINT pkey is benign.
    assert!(!trips(
        "ALTER TABLE ONLY public.events ADD CONSTRAINT events_pkey PRIMARY KEY (event_id);"
    ));
}

// ---- Unit checks for the matcher primitives. ------------------------------

#[test]
fn self_check_is_sensitive_table_membership() {
    assert!(is_sensitive_table("users"));
    assert!(is_sensitive_table("USERS")); // case-insensitive
    assert!(is_sensitive_table("repository_upstream_mappings"));
    assert!(is_sensitive_table("events"));
    assert!(is_sensitive_table("events_archive"));
    assert!(is_sensitive_table("_sqlx_migrations"));
    assert!(!is_sensitive_table("repositories_backup_2026")); // not exact
    assert!(!is_sensitive_table("repo_security_scores"));
    assert!(!is_sensitive_table("scan_findings"));
    assert!(!is_sensitive_table("eventsourcing")); // not `events`/`events_`
}

#[test]
fn self_check_is_widenable_check_name_allow_list() {
    // Allow-list: only `_check` names (case-insensitive) are widenable.
    assert!(is_widenable_check_name("jobs_kind_check"));
    assert!(is_widenable_check_name("Jobs_Kind_Check")); // case-insensitive
    assert!(is_widenable_check_name("foo_check"));
    // Integrity constraints are NOT widenable — never exempt.
    assert!(!is_widenable_check_name("api_tokens_pkey"));
    assert!(!is_widenable_check_name("users_fk_org"));
    assert!(!is_widenable_check_name("users_email_key"));
    assert!(!is_widenable_check_name("repositories_name_unique"));
    // An unconventionally-named constraint (no recognised suffix at all)
    // is fail-closed: not `_check`, so not exempt.
    assert!(!is_widenable_check_name("my_weird_constraint"));
    assert!(!is_widenable_check_name("checkmate")); // substring, not suffix
}

#[test]
fn self_check_strip_comments_removes_line_comment_drop() {
    let stripped = strip_comments_and_strings("--   DROP TABLE users;\nCREATE TABLE foo (id int);");
    assert!(!stripped.to_ascii_lowercase().contains("drop table users"));
    assert!(stripped.contains("CREATE TABLE foo"));
}

#[test]
fn self_check_strip_comments_preserves_real_statement_after_comment() {
    let stripped =
        strip_comments_and_strings("-- comment\nDROP TABLE IF EXISTS public.scans CASCADE;\n");
    assert!(stripped
        .to_ascii_lowercase()
        .contains("drop table if exists"));
}

#[test]
fn self_check_parse_table_name_schema_qualified() {
    let tokens = tokenize("public.users");
    let (name, next) = parse_table_name(&tokens, 0).expect("parsed");
    assert_eq!(name, "users");
    assert_eq!(next, 3);
}

#[test]
fn self_check_parse_table_name_bare() {
    let tokens = tokenize("jobs ;");
    let (name, next) = parse_table_name(&tokens, 0).expect("parsed");
    assert_eq!(name, "jobs");
    assert_eq!(next, 1);
}
