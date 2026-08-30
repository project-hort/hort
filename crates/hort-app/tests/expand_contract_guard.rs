//! Expand/contract migration guard (ADR 0030,
//! `docs/adr/0030-sensitive-surface-structural-guards.md`).
//!
//! This DB-free, network-free, git-free source-scan is the **committed
//! proof** (in the spirit of `no_sensitive_drops` / `ephemeral_keyspace_exhaustive`
//! / `no_bcrypt` / `streaming_metadata_port`) that no migration ships a
//! **contraction** — destructive DDL against an identifier the previous
//! release's binaries still reference.
//!
//! ## The invariant
//!
//! A migration set runs against the database *while the previous release's
//! binaries are still serving*. Every rolling upgrade — Helm, Flux, a plain
//! `kubectl rollout` — has a window in which the new schema and the old code
//! coexist. So schema change is **expand/contract**:
//!
//!   * **Expand** — add the new column/table, dual-write, migrate readers.
//!     Additive DDL is safe in the same release as the code that uses it,
//!     because the old binary simply never names the new identifier.
//!   * **Contract** — drop the old column/table, rename it, narrow its type,
//!     or make it `NOT NULL`. This breaks any binary that still names it, so
//!     it may ship only in a release **strictly after** the last release
//!     whose code referenced the identifier. Expand and contract never share
//!     a release.
//!
//! Violating this is not a degraded upgrade, it is an outage of the *old*
//! fleet at the instant the migration commits — before a single new pod is
//! Ready. In a self-hosting deployment (hort mirroring the images hort itself
//! is upgraded from) the broken old pod is also load-bearing for the new
//! pod's image pull, so the failure is self-pinning: the exemplar entry in
//! `migrations/CONTRACTIONS.toml` records the incident that motivated this
//! guard.
//!
//! ## What it asserts
//!
//! Every `*.sql` file under the workspace-root `migrations/` tree is scanned
//! (comments and string literals stripped first, identifiers matched as
//! whole tokens — the shared discipline in `tests/sql_scan/mod.rs`) for the
//! destructive shapes below, and cross-checked against the checked-in
//! manifest `migrations/CONTRACTIONS.toml`:
//!
//!   a. **Every contraction is declared.** Destructive DDL in a migration
//!      with no manifest entry is a hard failure — and so is the reverse: an
//!      entry whose declared `identifiers` do not *exactly* equal the set the
//!      scanner extracts from that migration. The two-way equality is what
//!      keeps the manifest from decaying into stale prose, and makes an edit
//!      to a migration that adds a second contraction fail until the manifest
//!      catches up.
//!   b. **The timing gap is real.** The current workspace version (parsed
//!      from the root `Cargo.toml`) must be **strictly greater** than the
//!      entry's `reference_removed_in`. This is the mechanical half of the
//!      policy: a contraction authored in the same cycle that removed the
//!      last code reference fails, because a `X.Y.Z-dev` tree is not greater
//!      than `X.Y.Z`.
//!   c. **The "removed" claim is true of the present.** No SQL text in the
//!      workspace's production sources may still name a removed identifier.
//!
//! ## What this guard can and cannot see (read this before trusting it)
//!
//! The guard is **hermetic on purpose** — no `git`, no network, sub-second —
//! which means it can only inspect the tree in front of it. It therefore
//! cannot verify the one thing `reference_removed_in` actually claims: that
//! the release *before* that version was the last one whose code named the
//! identifier. Check (c) is the consistency check it *can* do — the claim is
//! at least true of the present — and check (b) enforces the arithmetic. The
//! honesty of the version itself is a **mandatory reviewer step**, recorded
//! in ADR 0030: for each new manifest entry, run
//!
//! ```text
//! git grep <identifier> v<reference_removed_in>
//! ```
//!
//! and confirm it comes back empty. That single command is what the guard
//! delegates; skipping it makes the manifest a wish rather than a record.
//!
//! Two further limits, stated so nobody mistakes a green run for a proof:
//!
//!   * **Check (c) reads SQL that appears as Rust string literals in
//!     `crates/*/src/`.** A query assembled at runtime from a column name
//!     held in a `const`, or one built by `format!` from fragments, is
//!     invisible to it. Test sources are deliberately out of the corpus:
//!     an `information_schema` probe asserting a column is *gone*
//!     legitimately names it, and a stale query in a test fails loudly
//!     against a real database anyway.
//!   * **The scanner recognises statement shapes, not effects.** A
//!     `TYPE` change is flagged whether it narrows or widens, because
//!     deciding that needs type semantics the guard does not have — the
//!     fail-closed direction. A `DROP TABLE` immediately followed by a
//!     `CREATE TABLE` of the same name in the same migration is *not* a
//!     contraction (the identifier survives the migration), which is what
//!     lets the pre-1.0 prototype-replacement migrations stay out of the
//!     manifest; dropping a *sensitive* table that way remains an
//!     unconditional failure in the sibling `no_sensitive_drops` guard, so
//!     the two compose rather than overlap.
//!
//! ## Maintenance — weakening this is a blocking review finding
//!
//! Deleting a manifest entry, widening `reference_removed_in` to whatever
//! makes the arithmetic pass, or relaxing a matcher so a destructive shape
//! stops being recognised, are all ways of making a real contraction
//! invisible. ADR 0030's standing rule applies: if a contraction genuinely
//! must ship now, the answer is to schedule it for the next release (and
//! flag it in the changelog per RELEASING.md), not to edit this guard.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

mod sql_scan;

use sql_scan::{
    line_of, migrations_dir, parse_table_name, strip_comments_and_strings, tokenize,
    workspace_root, Token,
};

/// Manifest file name, resolved inside the scanned `migrations/` tree.
///
/// It lives next to the migrations it describes rather than under `docs/` so
/// that the diff which adds a destructive migration and the diff which
/// declares it are the same diff.
const MANIFEST_FILE: &str = "CONTRACTIONS.toml";

// ---------------------------------------------------------------------------
// The manifest.
// ---------------------------------------------------------------------------

/// `migrations/CONTRACTIONS.toml` — one entry per migration containing
/// destructive DDL.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    /// `[[contraction]]` entries. Absent when the tree has no destructive
    /// migration at all, which is a legitimate (if currently untrue) state.
    #[serde(default)]
    contraction: Vec<ManifestEntry>,
}

/// One declared contraction.
///
/// `deny_unknown_fields` is load-bearing: a mistyped key in a fail-closed
/// guard's own input must be an error, never a silently-dropped declaration
/// that leaves the entry looking complete.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    /// File name (not a path) of the migration under `migrations/`.
    migration: String,
    /// Every identifier this migration destroys or narrows. A table is
    /// written unqualified (`scans`); a column is written `table.column`
    /// (`artifacts.is_deleted`). The set must equal exactly what the scanner
    /// extracts from the migration.
    identifiers: Vec<String>,
    /// The release whose code no longer references these identifiers — i.e.
    /// the release *before* this one is the last that did. A plain
    /// `X.Y.Z`; a pre-release is rejected, because the policy is stated in
    /// terms of releases operators actually upgrade between.
    reference_removed_in: String,
    /// Why this contraction was safe (or, for a historical entry, what
    /// happened). Required and non-empty: the reviewer step this guard
    /// delegates is unreviewable without it.
    note: String,
}

// ---------------------------------------------------------------------------
// Versions.
// ---------------------------------------------------------------------------

/// The `major.minor.patch` core of a version, with any pre-release or build
/// metadata discarded.
///
/// Ordering is the tuple ordering, which is all the policy needs. The
/// pre-release suffix is deliberately *dropped* rather than compared: a
/// development tree at `X.Y.Z-dev` is working towards `X.Y.Z`, so its core is
/// `X.Y.Z`, and "strictly greater than `reference_removed_in`" then reads
/// exactly as the policy states — a contraction may ship one release after
/// the reference disappeared, and `X.Y.Z-dev` is not one release after
/// `X.Y.Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VersionCore {
    major: u64,
    minor: u64,
    patch: u64,
}

impl std::fmt::Display for VersionCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse the `X.Y.Z` core of a version string, ignoring any `-pre` /
/// `+build` suffix.
fn parse_version_core(raw: &str) -> Result<VersionCore, String> {
    let core = raw.split(['-', '+']).next().unwrap_or(raw);
    let mut parts = core.split('.');
    let mut next = |which: &str| -> Result<u64, String> {
        parts
            .next()
            .ok_or_else(|| format!("version {raw:?} is missing its {which} component"))?
            .parse::<u64>()
            .map_err(|e| format!("version {raw:?} has a non-numeric {which} component: {e}"))
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if parts.next().is_some() {
        return Err(format!(
            "version {raw:?} has more than three dot-separated components"
        ));
    }
    Ok(VersionCore {
        major,
        minor,
        patch,
    })
}

/// Parse a `reference_removed_in` value, which must be a plain release —
/// no pre-release suffix, no build metadata.
///
/// A pre-release would make the claim ambiguous: `0.12.0-alpha.3` is not a
/// release operators upgrade *between*, so "the code stopped referencing
/// this identifier in 0.12.0-alpha.3" does not identify a release boundary
/// the policy can reason about.
fn parse_release_version(raw: &str) -> Result<VersionCore, String> {
    if raw.contains('-') || raw.contains('+') {
        return Err(format!(
            "{raw:?} is not a plain release version — `reference_removed_in` must be `X.Y.Z` \
             with no pre-release or build suffix"
        ));
    }
    parse_version_core(raw)
}

/// Read `[workspace.package] version` out of the root `Cargo.toml`.
fn workspace_version(cargo_toml: &str) -> Result<String, String> {
    let doc: toml::Value =
        toml::from_str(cargo_toml).map_err(|e| format!("parsing root Cargo.toml: {e}"))?;
    doc.get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "root Cargo.toml has no [workspace.package] version".to_string())
}

// ---------------------------------------------------------------------------
// The destructive-DDL scanner.
// ---------------------------------------------------------------------------

/// What a destructive statement does to the identifier it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reach {
    /// The identifier ceases to exist: `DROP TABLE`, `DROP COLUMN`, or the
    /// source side of a `RENAME`. Old code that names it errors.
    Removed,
    /// The identifier survives with a tighter contract: a `TYPE` change or
    /// `SET NOT NULL`. Old code that *reads* it still works; old code that
    /// writes the old shape errors.
    Narrowed,
}

/// One destructive statement found in a migration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Contraction {
    /// `table` for a table, `table.column` for a column — unqualified and
    /// lower-cased, matching the manifest's convention.
    identifier: String,
    reach: Reach,
    /// The recognised statement shape, for the failure message.
    shape: &'static str,
    /// 1-based line in the comment-stripped source.
    line: usize,
}

/// Words that may sit between `CREATE` and `TABLE`.
const CREATE_TABLE_MODIFIERS: &[&str] = &["unlogged", "temporary", "temp", "global", "local"];

/// `true` when `t` is an unquoted word equal to `kw`.
fn kw(tokens: &[Token], idx: usize, keyword: &str) -> bool {
    tokens
        .get(idx)
        .is_some_and(|t| !t.quoted && t.text == keyword)
}

/// Advance past an optional `IF EXISTS` at `idx`.
fn skip_if_exists(tokens: &[Token], idx: usize) -> usize {
    if kw(tokens, idx, "if") && kw(tokens, idx + 1, "exists") {
        idx + 2
    } else {
        idx
    }
}

/// Advance past an optional `IF NOT EXISTS` at `idx`.
fn skip_if_not_exists(tokens: &[Token], idx: usize) -> usize {
    if kw(tokens, idx, "if") && kw(tokens, idx + 1, "not") && kw(tokens, idx + 2, "exists") {
        idx + 3
    } else {
        idx
    }
}

/// Every table name this migration `CREATE TABLE`s.
///
/// A `DROP TABLE x` paired with a `CREATE TABLE x` in the same migration is a
/// *replacement*, not a contraction: the identifier is present both before
/// and after the migration, so no binary that names it breaks on the name's
/// account. (Whether the replacement's *shape* is compatible is a different
/// question, and one the pre-1.0 wipe contract of ADR 0022 answers for the
/// migrations that use this form.) Dropping a security-critical table this
/// way is still an unconditional failure in the sibling `no_sensitive_drops`
/// guard.
fn created_tables(tokens: &[Token]) -> BTreeSet<String> {
    let mut created = BTreeSet::new();
    for i in 0..tokens.len() {
        if !kw(tokens, i, "create") {
            continue;
        }
        let mut j = i + 1;
        while tokens
            .get(j)
            .is_some_and(|t| !t.quoted && CREATE_TABLE_MODIFIERS.contains(&t.text.as_str()))
        {
            j += 1;
        }
        if !kw(tokens, j, "table") {
            continue;
        }
        let name_idx = skip_if_not_exists(tokens, j + 1);
        if let Some((name, _)) = parse_table_name(tokens, name_idx) {
            created.insert(name);
        }
    }
    created
}

/// Does the `ALTER TABLE` sub-action starting at `idx` contain a `TYPE`
/// change or a `SET NOT NULL`?
///
/// Sub-actions are comma-separated, but commas also appear inside
/// parentheses (`CHECK (kind IN ('a','b'))`), so the walk tracks depth and
/// stops only at a top-level comma or the statement's `;`.
fn action_narrows(tokens: &[Token], idx: usize) -> Option<&'static str> {
    let mut depth: usize = 0;
    let mut j = idx;
    while j < tokens.len() {
        let t = &tokens[j];
        if !t.quoted {
            match t.text.as_str() {
                "(" => depth += 1,
                ")" => depth = depth.saturating_sub(1),
                ";" => break,
                "," if depth == 0 => break,
                "type" => return Some("ALTER COLUMN ... TYPE"),
                "set" if kw(tokens, j + 1, "not") && kw(tokens, j + 2, "null") => {
                    return Some("ALTER COLUMN ... SET NOT NULL")
                }
                _ => {}
            }
        }
        j += 1;
    }
    None
}

/// Scan one migration's SQL for destructive DDL.
///
/// Recognised shapes, all case-insensitive and formatting-independent:
///
///   * `DROP TABLE [IF EXISTS] <t>` → `Removed(t)`, unless the same
///     migration also `CREATE TABLE`s `<t>`;
///   * `ALTER TABLE <t> … DROP COLUMN [IF EXISTS] <c>` → `Removed(t.c)`;
///   * `ALTER TABLE <t> … RENAME TO <new>` → `Removed(t)`;
///   * `ALTER TABLE <t> … RENAME [COLUMN] <c> TO <new>` → `Removed(t.c)`;
///   * `ALTER TABLE <t> … ALTER [COLUMN] <c> … TYPE …` → `Narrowed(t.c)`;
///   * `ALTER TABLE <t> … ALTER [COLUMN] <c> … SET NOT NULL` →
///     `Narrowed(t.c)`.
///
/// Deliberately NOT recognised, because no application query names them and
/// no binary breaks when they change: `DROP INDEX`, `DROP CONSTRAINT`,
/// `RENAME CONSTRAINT`. Constraint drops on a security-critical table are
/// covered unconditionally by the sibling `no_sensitive_drops` guard.
/// `DROP TABLE [IF EXISTS] <t>` at `i`, unless `t` was created earlier in the
/// same migration (create-then-drop is not a contraction of prior releases).
fn scan_drop_table(
    tokens: &[Token],
    i: usize,
    created: &BTreeSet<String>,
    stripped: &str,
) -> Option<Contraction> {
    if !(kw(tokens, i, "drop") && kw(tokens, i + 1, "table")) {
        return None;
    }
    let name_idx = skip_if_exists(tokens, i + 2);
    let (name, _) = parse_table_name(tokens, name_idx)?;
    if created.contains(&name) {
        return None;
    }
    Some(Contraction {
        identifier: name,
        reach: Reach::Removed,
        shape: "DROP TABLE",
        line: line_of(stripped, tokens[i].offset),
    })
}

/// `DROP COLUMN [IF EXISTS] <c>` inside an `ALTER TABLE` body at `k`.
/// Returns the index to resume scanning from when this shape matched.
fn scan_drop_column(
    tokens: &[Token],
    k: usize,
    table: &str,
    stripped: &str,
    out: &mut Vec<Contraction>,
) -> Option<usize> {
    if !(kw(tokens, k, "drop") && kw(tokens, k + 1, "column")) {
        return None;
    }
    let cn = skip_if_exists(tokens, k + 2);
    if let Some((column, _)) = parse_table_name(tokens, cn) {
        out.push(Contraction {
            identifier: format!("{table}.{column}"),
            reach: Reach::Removed,
            shape: "ALTER TABLE ... DROP COLUMN",
            line: line_of(stripped, tokens[k].offset),
        });
    }
    Some(cn + 1)
}

/// `RENAME TO <new>` | `RENAME [COLUMN] <c> TO <new>` inside an `ALTER TABLE`
/// body at `k`. Returns the index to resume scanning from when this shape
/// matched.
fn scan_rename_clause(
    tokens: &[Token],
    k: usize,
    table: &str,
    stripped: &str,
    out: &mut Vec<Contraction>,
) -> Option<usize> {
    if !kw(tokens, k, "rename") {
        return None;
    }
    if kw(tokens, k + 1, "to") {
        out.push(Contraction {
            identifier: table.to_string(),
            reach: Reach::Removed,
            shape: "ALTER TABLE ... RENAME TO",
            line: line_of(stripped, tokens[k].offset),
        });
    } else if !kw(tokens, k + 1, "constraint") {
        let cn = if kw(tokens, k + 1, "column") {
            k + 2
        } else {
            k + 1
        };
        if let Some((column, _)) = parse_table_name(tokens, cn) {
            out.push(Contraction {
                identifier: format!("{table}.{column}"),
                reach: Reach::Removed,
                shape: "ALTER TABLE ... RENAME COLUMN",
                line: line_of(stripped, tokens[k].offset),
            });
        }
    }
    Some(k + 2)
}

/// `ALTER [COLUMN] <c> … TYPE …` | `… SET NOT NULL` inside an `ALTER TABLE`
/// body at `k`. Returns the index to resume scanning from when this shape
/// matched.
fn scan_column_alter(
    tokens: &[Token],
    k: usize,
    table: &str,
    stripped: &str,
    out: &mut Vec<Contraction>,
) -> Option<usize> {
    if !kw(tokens, k, "alter") {
        return None;
    }
    let cn = if kw(tokens, k + 1, "column") {
        k + 2
    } else {
        k + 1
    };
    let Some((column, after_col)) = parse_table_name(tokens, cn) else {
        return Some(cn + 1);
    };
    if let Some(shape) = action_narrows(tokens, after_col) {
        out.push(Contraction {
            identifier: format!("{table}.{column}"),
            reach: Reach::Narrowed,
            shape,
            line: line_of(stripped, tokens[k].offset),
        });
    }
    Some(cn + 1)
}

/// The full clause body of one `ALTER TABLE <table> …` statement, from just
/// after the table name to the terminating `;`.
fn scan_alter_table_body(
    tokens: &[Token],
    start: usize,
    n: usize,
    table: &str,
    stripped: &str,
) -> Vec<Contraction> {
    let mut out = Vec::new();
    let mut k = start;
    while k < n && tokens[k].text != ";" {
        if let Some(next) = scan_drop_column(tokens, k, table, stripped, &mut out) {
            k = next;
            continue;
        }
        if let Some(next) = scan_rename_clause(tokens, k, table, stripped, &mut out) {
            k = next;
            continue;
        }
        if let Some(next) = scan_column_alter(tokens, k, table, stripped, &mut out) {
            k = next;
            continue;
        }
        k += 1;
    }
    out
}

/// `ALTER TABLE [ONLY] <t> …` starting at `i`; resolves the table name and
/// delegates the clause body to [`scan_alter_table_body`].
fn scan_alter_table_statement(
    tokens: &[Token],
    i: usize,
    n: usize,
    stripped: &str,
) -> Vec<Contraction> {
    let mut name_idx = skip_if_exists(tokens, i + 2);
    if kw(tokens, name_idx, "only") {
        name_idx += 1;
    }
    let Some((table, after_name)) = parse_table_name(tokens, name_idx) else {
        return Vec::new();
    };
    scan_alter_table_body(tokens, after_name, n, &table, stripped)
}

fn scan_migration(sql: &str) -> Vec<Contraction> {
    let stripped = strip_comments_and_strings(sql);
    let tokens = tokenize(&stripped);
    let created = created_tables(&tokens);
    let mut out: Vec<Contraction> = Vec::new();
    let n = tokens.len();

    let mut i = 0;
    while i < n {
        if let Some(c) = scan_drop_table(&tokens, i, &created, &stripped) {
            out.push(c);
        }
        if kw(&tokens, i, "alter") && kw(&tokens, i + 1, "table") {
            out.extend(scan_alter_table_statement(&tokens, i, n, &stripped));
        }
        i += 1;
    }

    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Rust-source SQL extraction (check c).
// ---------------------------------------------------------------------------

/// Extract every Rust string literal from `src` — normal `"…"` (honouring
/// backslash escapes) and raw `r"…"` / `r#"…"#` forms — skipping Rust line
/// and block comments and char literals.
///
/// Skipping char literals matters for correctness, not tidiness: `'"'` is a
/// perfectly ordinary Rust token and, read naively, its quote would open a
/// bogus "string" that swallows the rest of the file. Lifetimes (`'a`) are
/// distinguished from char literals by looking for the closing quote.
/// A `//` line comment starting at `i`; returns the index just past its
/// trailing newline (or end of input).
fn skip_line_comment(chars: &[char], i: usize, n: usize) -> Option<usize> {
    if !(chars[i] == '/' && i + 1 < n && chars[i + 1] == '/') {
        return None;
    }
    let mut i = i;
    while i < n && chars[i] != '\n' {
        i += 1;
    }
    Some(i)
}

/// A (possibly nested) `/* … */` block comment starting at `i`; returns the
/// index just past its close.
fn skip_block_comment(chars: &[char], i: usize, n: usize) -> Option<usize> {
    if !(chars[i] == '/' && i + 1 < n && chars[i + 1] == '*') {
        return None;
    }
    let mut depth = 1usize;
    let mut i = i + 2;
    while i < n && depth > 0 {
        if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
            depth += 1;
            i += 2;
        } else if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
            depth -= 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    Some(i)
}

/// A raw string `r` then zero or more `#` then `"…"` starting at `i`; pushes
/// its body onto `out` and returns the index just past the closing quote.
fn scan_raw_string(chars: &[char], i: usize, n: usize, out: &mut Vec<String>) -> Option<usize> {
    if chars[i] != 'r' {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0usize;
    while j < n && chars[j] == '#' {
        hashes += 1;
        j += 1;
    }
    if j >= n || chars[j] != '"' {
        return None;
    }
    let body_start = j + 1;
    let mut k = body_start;
    let mut end = None;
    while k < n {
        if chars[k] == '"' {
            let mut h = 0usize;
            while h < hashes && k + 1 + h < n && chars[k + 1 + h] == '#' {
                h += 1;
            }
            if h == hashes {
                end = Some(k);
                break;
            }
        }
        k += 1;
    }
    let stop = end.unwrap_or(n);
    out.push(chars[body_start..stop].iter().collect());
    Some(stop + 1 + hashes)
}

/// A char literal or lifetime starting at `i` — `'"'`, `'\\''`, or a bare
/// `'a` lifetime. Returns the index just past whichever was consumed.
///
/// Skipping char literals matters for correctness, not tidiness: `'"'` is a
/// perfectly ordinary Rust token and, read naively, its quote would open a
/// bogus "string" that swallows the rest of the file. Lifetimes (`'a`) are
/// distinguished from char literals by looking for the closing quote.
fn scan_char_or_lifetime(chars: &[char], i: usize, n: usize) -> Option<usize> {
    if chars[i] != '\'' {
        return None;
    }
    if i + 1 < n && chars[i + 1] == '\\' {
        // Escaped char literal — skip to the closing quote.
        let mut k = i + 2;
        while k < n && chars[k] != '\'' {
            k += 1;
        }
        return Some(k + 1);
    }
    if i + 2 < n && chars[i + 2] == '\'' {
        // Simple char literal such as `'"'`.
        return Some(i + 3);
    }
    // A lifetime — consume only the quote.
    Some(i + 1)
}

/// A normal `"…"` string literal starting at `i`, honouring backslash
/// escapes; pushes its body onto `out` and returns the index just past the
/// closing quote (or end of input if unterminated).
fn scan_normal_string(chars: &[char], i: usize, n: usize, out: &mut Vec<String>) -> Option<usize> {
    if chars[i] != '"' {
        return None;
    }
    let mut body = String::new();
    let mut k = i + 1;
    while k < n {
        if chars[k] == '\\' {
            // Keep the escaped character verbatim; we only ever tokenize
            // the result, so an unresolved `\n` is a harmless `n`.
            if k + 1 < n {
                body.push(chars[k + 1]);
            }
            k += 2;
            continue;
        }
        if chars[k] == '"' {
            break;
        }
        body.push(chars[k]);
        k += 1;
    }
    out.push(body);
    Some(k + 1)
}

/// Extract every Rust string literal from `src` — normal `"…"` (honouring
/// backslash escapes) and raw `r"…"` / `r#"…"#` forms — skipping Rust line
/// and block comments and char literals.
fn rust_string_literals(src: &str) -> Vec<String> {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if let Some(next) = skip_line_comment(&chars, i, n) {
            i = next;
            continue;
        }
        if let Some(next) = skip_block_comment(&chars, i, n) {
            i = next;
            continue;
        }
        if let Some(next) = scan_raw_string(&chars, i, n, &mut out) {
            i = next;
            continue;
        }
        if let Some(next) = scan_char_or_lifetime(&chars, i, n) {
            i = next;
            continue;
        }
        if let Some(next) = scan_normal_string(&chars, i, n, &mut out) {
            i = next;
            continue;
        }
        i += 1;
    }
    out
}

/// A manifest identifier, split into the form the source scan needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Table(String),
    Column { table: String, column: String },
}

impl Ident {
    fn parse(raw: &str) -> Result<Self, String> {
        let lower = raw.to_ascii_lowercase();
        let mut parts = lower.split('.');
        let first = parts.next().unwrap_or_default().to_string();
        let second = parts.next().map(str::to_string);
        if parts.next().is_some() || first.is_empty() {
            return Err(format!(
                "identifier {raw:?} must be `table` or `table.column` (unqualified, no schema)"
            ));
        }
        match second {
            None => Ok(Ident::Table(first)),
            Some(column) if !column.is_empty() => Ok(Ident::Column {
                table: first,
                column,
            }),
            Some(_) => Err(format!("identifier {raw:?} has an empty column part")),
        }
    }

    /// Substrings that must ALL appear in a file before it is worth lexing.
    ///
    /// A pure cheap-reject: the co-occurrence check (c) requires both parts
    /// inside one string literal, so a file missing either part textually
    /// cannot possibly match. Without it the guard would lex 20+ MB of
    /// sources in a debug build; with it, only the handful of files that
    /// mention the identifier at all are touched.
    fn prefilter(&self) -> Vec<&str> {
        match self {
            Ident::Table(t) => vec![t.as_str()],
            Ident::Column { table, column } => vec![table.as_str(), column.as_str()],
        }
    }

    /// Is this identifier named, as SQL identifiers, inside one statement?
    ///
    /// For a table: the table token appears. For a column: the table token
    /// AND the column token appear in the same string literal — the column
    /// name alone is far too generic (`role`, `path`, `name`) to carry a
    /// verdict, while a query that names both is unambiguously about that
    /// table's column.
    fn named_in(&self, sql_tokens: &BTreeSet<String>) -> bool {
        match self {
            Ident::Table(t) => sql_tokens.contains(t),
            Ident::Column { table, column } => {
                sql_tokens.contains(table) && sql_tokens.contains(column)
            }
        }
    }
}

/// Lower-cased word tokens of a candidate SQL string, with SQL comments and
/// SQL string literals stripped first.
///
/// Stripping SQL string literals is what separates a *reference* from a
/// *mention*: `SELECT is_deleted FROM artifacts` names the column as an
/// identifier and must trip check (c), while
/// `WHERE column_name = 'is_deleted'` — the shape an `information_schema`
/// probe takes — names it as a value and must not.
fn sql_identifier_tokens(candidate: &str) -> BTreeSet<String> {
    tokenize(&strip_comments_and_strings(candidate))
        .into_iter()
        .filter(|t| {
            !t.quoted
                && t.text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|t| t.text)
        .collect()
}

// ---------------------------------------------------------------------------
// The checks.
// ---------------------------------------------------------------------------

/// Everything the checks need, so the real filesystem-backed test and the
/// fixture-driven self-checks run the *same* code.
struct Inputs {
    /// `[workspace.package] version` of the tree under test.
    current_version: String,
    /// `(migration file name, SQL)`, in any order.
    migrations: Vec<(String, String)>,
    /// Raw `CONTRACTIONS.toml` text.
    manifest_toml: String,
    /// `(display path, Rust source)` for the production-source corpus.
    sources: Vec<(String, String)>,
}

/// Run every check. Returns one human-readable line per violation; empty
/// means the tree satisfies the expand/contract policy as far as a hermetic
/// scan can tell.
fn violations(inputs: &Inputs) -> Vec<String> {
    let mut out = Vec::new();

    let manifest: Manifest = match toml::from_str(&inputs.manifest_toml) {
        Ok(m) => m,
        Err(e) => {
            return vec![format!("migrations/{MANIFEST_FILE} does not parse: {e}")];
        }
    };

    let current = match parse_version_core(&inputs.current_version) {
        Ok(v) => v,
        Err(e) => return vec![format!("workspace version: {e}")],
    };

    // Index the declared entries, rejecting duplicates: two entries for one
    // migration would let the set-equality check below pass against whichever
    // one happened to be found first.
    let mut declared: BTreeMap<&str, &ManifestEntry> = BTreeMap::new();
    for entry in &manifest.contraction {
        if declared.insert(entry.migration.as_str(), entry).is_some() {
            out.push(format!(
                "{MANIFEST_FILE}: duplicate entry for migration {:?}",
                entry.migration
            ));
        }
    }

    let scanned: BTreeMap<&str, Vec<Contraction>> = inputs
        .migrations
        .iter()
        .map(|(name, sql)| (name.as_str(), scan_migration(sql)))
        .collect();

    // ---- (a) every contraction is declared, and every declaration is real.
    for (name, found) in &scanned {
        if found.is_empty() {
            continue;
        }
        let Some(entry) = declared.get(name) else {
            out.push(format!(
                "{name}: contains destructive DDL but has no entry in migrations/{MANIFEST_FILE} \
                 — {}. Expand/contract policy (ADR 0030): declare the affected identifier(s) and \
                 the release whose code stopped referencing them, or make the migration additive.",
                describe(found)
            ));
            continue;
        };
        let expected: BTreeSet<String> = found.iter().map(|c| c.identifier.clone()).collect();
        let declared_ids: BTreeSet<String> = entry
            .identifiers
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if declared_ids != expected {
            out.push(format!(
                "{name}: migrations/{MANIFEST_FILE} declares identifiers {:?} but the migration's \
                 destructive DDL affects {:?} — the manifest must name exactly what the SQL does \
                 ({}).",
                declared_ids,
                expected,
                describe(found)
            ));
        }
    }
    for (name, entry) in &declared {
        match scanned.get(name) {
            None => out.push(format!(
                "migrations/{MANIFEST_FILE}: entry names migration {:?}, which does not exist \
                 under migrations/.",
                entry.migration
            )),
            Some(found) if found.is_empty() => out.push(format!(
                "migrations/{MANIFEST_FILE}: entry for {:?} declares a contraction, but that \
                 migration contains no destructive DDL — a stale entry hides the next real one.",
                entry.migration
            )),
            Some(_) => {}
        }
        if entry.note.trim().is_empty() {
            out.push(format!(
                "migrations/{MANIFEST_FILE}: entry for {:?} has an empty `note` — the reviewer \
                 step this guard delegates (git grep the identifier at the claimed release) is \
                 unreviewable without the rationale.",
                entry.migration
            ));
        }
    }

    // ---- (b) the timing gap is real. -------------------------------------
    for entry in &manifest.contraction {
        let removed_in = match parse_release_version(&entry.reference_removed_in) {
            Ok(v) => v,
            Err(e) => {
                out.push(format!(
                    "migrations/{MANIFEST_FILE}: entry for {:?}: {e}",
                    entry.migration
                ));
                continue;
            }
        };
        if current <= removed_in {
            out.push(format!(
                "{}: contraction would ship in {} (workspace version {}), which is not strictly \
                 after {} — the release whose code stopped referencing {:?}. Expand and contract \
                 must not share a release: the previous release's binaries are still serving when \
                 this migration commits. Ship the contraction in the NEXT release.",
                entry.migration, current, inputs.current_version, removed_in, entry.identifiers,
            ));
        }
    }

    // ---- (c) the "removed" claim is true of the present. ------------------
    let mut idents: Vec<(&ManifestEntry, Ident)> = Vec::new();
    for entry in &manifest.contraction {
        let removed: BTreeSet<String> = scanned
            .get(entry.migration.as_str())
            .map(|found| {
                found
                    .iter()
                    .filter(|c| c.reach == Reach::Removed)
                    .map(|c| c.identifier.clone())
                    .collect()
            })
            .unwrap_or_default();
        for raw in &entry.identifiers {
            // A narrowed identifier still exists, so the source legitimately
            // names it; only removals are subject to check (c).
            if !removed.contains(&raw.to_ascii_lowercase()) {
                continue;
            }
            match Ident::parse(raw) {
                Ok(id) => idents.push((entry, id)),
                Err(e) => out.push(format!(
                    "migrations/{MANIFEST_FILE}: entry for {:?}: {e}",
                    entry.migration
                )),
            }
        }
    }
    for (path, source) in &inputs.sources {
        let relevant: Vec<&(&ManifestEntry, Ident)> = idents
            .iter()
            .filter(|(_, id)| id.prefilter().iter().all(|needle| source.contains(needle)))
            .collect();
        if relevant.is_empty() {
            continue;
        }
        for literal in rust_string_literals(source) {
            let tokens = sql_identifier_tokens(&literal);
            if tokens.is_empty() {
                continue;
            }
            for (entry, id) in &relevant {
                if id.named_in(&tokens) {
                    out.push(format!(
                        "{path}: SQL still names {:?}, which migration {} removes. Either the \
                         source has not finished migrating off it, or \
                         `reference_removed_in = \"{}\"` is not true.",
                        render(id),
                        entry.migration,
                        entry.reference_removed_in,
                    ));
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Render an identifier back to its manifest spelling.
fn render(id: &Ident) -> String {
    match id {
        Ident::Table(t) => t.clone(),
        Ident::Column { table, column } => format!("{table}.{column}"),
    }
}

/// One-line summary of what a migration's destructive DDL does.
fn describe(found: &[Contraction]) -> String {
    found
        .iter()
        .map(|c| format!("line {}: {} on {}", c.line, c.shape, c.identifier))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// The guard over the real tree.
// ---------------------------------------------------------------------------

/// Recursively collect `*.rs` files under `dir`.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// The production-source corpus for check (c): `crates/*/src/**/*.rs`.
///
/// `tests/` is out of scope by construction — see the module header's second
/// limit.
fn production_sources(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let Ok(crates) = fs::read_dir(root.join("crates")) else {
        return files;
    };
    let mut paths = Vec::new();
    for entry in crates.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            collect_rs(&src, &mut paths);
        }
    }
    paths.sort();
    for path in paths {
        if let Ok(text) = fs::read_to_string(&path) {
            let display = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            files.push((display, text));
        }
    }
    files
}

#[test]
fn no_migration_contracts_ahead_of_its_release() {
    let root = workspace_root();
    let dir = migrations_dir();
    assert!(
        dir.is_dir(),
        "migrations directory not found at {dir:?} — the guard's path layout drifted."
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
        "no *.sql files found under {dir:?} — a path error would otherwise let this guard pass \
         vacuously."
    );

    let manifest_path = dir.join(MANIFEST_FILE);
    let manifest_toml = fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        panic!(
            "the destructive-DDL manifest {manifest_path:?} is missing or unreadable ({e}). It is \
             a checked-in, permanent part of the expand/contract guard; recreate it rather than \
             deleting it."
        )
    });

    let cargo_toml = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap_or_else(|e| panic!("read root Cargo.toml: {e}"));
    let current_version =
        workspace_version(&cargo_toml).unwrap_or_else(|e| panic!("workspace version: {e}"));

    let migrations = sql_files
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("migration file name is valid UTF-8")
                .to_string();
            let sql = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            (name, sql)
        })
        .collect();

    let sources = production_sources(&root);
    assert!(
        !sources.is_empty(),
        "no crates/*/src/**/*.rs sources found under {root:?} — check (c) would pass vacuously."
    );

    let inputs = Inputs {
        current_version,
        migrations,
        manifest_toml,
        sources,
    };
    let hits = violations(&inputs);
    assert!(
        hits.is_empty(),
        "ADR 0030 expand/contract policy: {} violation(s). A destructive migration that ships \
         alongside (or ahead of) the code change that stopped referencing the identifier breaks \
         the PREVIOUS release's still-running binaries the moment the migration commits. Do not \
         weaken this guard or edit migrations/{MANIFEST_FILE} to make the arithmetic pass — \
         schedule the contraction for the next release.\n{}",
        hits.len(),
        hits.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Fixture-driven self-checks: synthetic trees whose verdict is pinned, so a
// refactor cannot silently weaken the guard.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod self_checks {
    use super::*;

    /// A tree with no sources and no migrations beyond what a case supplies.
    fn tree(
        version: &str,
        migrations: &[(&str, &str)],
        manifest: &str,
        sources: &[(&str, &str)],
    ) -> Inputs {
        Inputs {
            current_version: version.to_string(),
            migrations: migrations
                .iter()
                .map(|(n, s)| ((*n).to_string(), (*s).to_string()))
                .collect(),
            manifest_toml: manifest.to_string(),
            sources: sources
                .iter()
                .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
                .collect(),
        }
    }

    // ---- The three red cases the policy exists to catch. ------------------

    #[test]
    fn red_when_contraction_ships_in_the_release_that_removed_the_reference() {
        // The 020 shape: the migration drops a column in the SAME release
        // whose code stopped referencing it. `0.12.0-dev` is not strictly
        // after `0.12.0`, so the previous release (0.11.x) is still running
        // when this commits.
        let hits = violations(&tree(
            "0.12.0-dev",
            &[(
                "020_drop_artifacts_is_deleted.sql",
                "ALTER TABLE public.artifacts DROP COLUMN is_deleted;",
            )],
            r#"
[[contraction]]
migration = "020_drop_artifacts_is_deleted.sql"
identifiers = ["artifacts.is_deleted"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[],
        ));
        assert_eq!(
            hits.len(),
            1,
            "expected exactly the timing violation: {hits:?}"
        );
        assert!(hits[0].contains("not strictly after"), "{hits:?}");
    }

    #[test]
    fn green_when_the_same_contraction_waits_one_release() {
        // Identical tree, one release later. This is the whole policy.
        let hits = violations(&tree(
            "0.12.1-dev",
            &[(
                "020_drop_artifacts_is_deleted.sql",
                "ALTER TABLE public.artifacts DROP COLUMN is_deleted;",
            )],
            r#"
[[contraction]]
migration = "020_drop_artifacts_is_deleted.sql"
identifiers = ["artifacts.is_deleted"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn red_when_a_destructive_migration_has_no_manifest_entry() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            "",
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("no entry in migrations/"), "{hits:?}");
    }

    #[test]
    fn red_when_the_source_still_references_a_removed_identifier() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[(
                "crates/hort-adapters-postgres/src/artifact_repo.rs",
                r#"let q = "SELECT id, legacy_flag FROM artifacts WHERE id = $1";"#,
            )],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("SQL still names"), "{hits:?}");
    }

    // ---- Green cases. -----------------------------------------------------

    #[test]
    fn green_on_an_expand_only_migration() {
        // Additive DDL needs no entry at all: the old binary never names the
        // new identifier, so there is nothing to sequence.
        let hits = violations(&tree(
            "0.12.2-dev",
            &[(
                "021_artifacts_soft_delete.sql",
                "ALTER TABLE public.artifacts ADD COLUMN deleted_at timestamptz;\n\
                 CREATE UNIQUE INDEX artifacts_live_key ON public.artifacts (repository_id, path)\n\
                 WHERE (deleted_at IS NULL);",
            )],
            "",
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn green_when_an_information_schema_probe_mentions_the_column_as_a_value() {
        // A probe asserting the column is GONE names it as a SQL *string*,
        // not as an identifier. Stripping SQL string literals before the
        // token scan is what keeps check (c) from flagging the very test
        // that proves the contraction landed.
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[(
                "crates/hort-adapters-postgres/src/probe.rs",
                r#"let q = "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name = 'artifacts' AND column_name = 'legacy_flag')";"#,
            )],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn green_when_only_the_column_word_appears_without_its_table() {
        // Column names are generic. `role` in a query about `users` says
        // nothing about `service_accounts.role`; requiring BOTH tokens in one
        // statement is what makes check (c) usable on names like this.
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "014_service_accounts_identity_only.sql",
                "ALTER TABLE public.service_accounts DROP COLUMN role;",
            )],
            r#"
[[contraction]]
migration = "014_service_accounts_identity_only.sql"
identifiers = ["service_accounts.role"]
reference_removed_in = "0.9.7"
note = "n/a"
"#,
            &[(
                "crates/hort-adapters-postgres/src/user_repo.rs",
                r#"let q = "SELECT id, role FROM users WHERE id = $1";
                   let other = "SELECT name FROM service_accounts WHERE id = $1";"#,
            )],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn green_when_a_dropped_table_is_recreated_in_the_same_migration() {
        // `DROP TABLE x; CREATE TABLE x (...)` leaves `x` present before and
        // after, so no binary breaks on the NAME. (Shape compatibility is a
        // separate question, answered pre-1.0 by the wipe contract; dropping
        // a SENSITIVE table this way stays an unconditional failure in
        // `no_sensitive_drops`.)
        let hits = violations(&tree(
            "0.12.2-dev",
            &[(
                "009_scan_jobs_and_findings.sql",
                "DROP TABLE IF EXISTS public.scan_findings CASCADE;\n\
                 CREATE TABLE public.scan_findings (id uuid PRIMARY KEY);",
            )],
            "",
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn green_when_a_comment_mentions_a_drop() {
        // The reversal-runbook comment shape that real migrations carry.
        let hits = violations(&tree(
            "0.12.2-dev",
            &[(
                "010_rescan_and_advisory.sql",
                "--   DROP TABLE IF EXISTS public.advisory_sync_state CASCADE;\n\
                 CREATE TABLE public.advisory_sync_state (id uuid PRIMARY KEY);",
            )],
            "",
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    // ---- Manifest integrity. ---------------------------------------------

    #[test]
    fn red_when_the_manifest_understates_what_the_migration_does() {
        // Two columns dropped, one declared. Without the two-way set
        // equality, the second drop would ride in undeclared under cover of
        // the first one's entry.
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "014_service_accounts_identity_only.sql",
                "ALTER TABLE public.service_accounts DROP COLUMN role;\n\
                 ALTER TABLE public.service_accounts DROP COLUMN repositories;",
            )],
            r#"
[[contraction]]
migration = "014_service_accounts_identity_only.sql"
identifiers = ["service_accounts.role"]
reference_removed_in = "0.9.7"
note = "n/a"
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("must name exactly"), "{hits:?}");
    }

    #[test]
    fn red_when_an_entry_names_a_migration_that_does_not_exist() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[],
            r#"
[[contraction]]
migration = "999_imaginary.sql"
identifiers = ["artifacts.gone"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("does not exist"), "{hits:?}");
    }

    #[test]
    fn red_when_an_entry_is_stale() {
        // The migration was rewritten to be additive but the entry stayed.
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_additive.sql",
                "ALTER TABLE public.artifacts ADD COLUMN x int;",
            )],
            r#"
[[contraction]]
migration = "023_additive.sql"
identifiers = ["artifacts.x"]
reference_removed_in = "0.12.0"
note = "n/a"
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("no destructive DDL"), "{hits:?}");
    }

    #[test]
    fn red_when_the_note_is_empty() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_in = "0.12.0"
note = "   "
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("empty `note`"), "{hits:?}");
    }

    #[test]
    fn red_when_the_manifest_declares_a_duplicate_entry() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_in = "0.12.0"
note = "first"

[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.something_else"]
reference_removed_in = "0.12.0"
note = "second"
"#,
            &[],
        ));
        assert!(
            hits.iter().any(|h| h.contains("duplicate entry")),
            "{hits:?}"
        );
    }

    #[test]
    fn red_when_an_unknown_manifest_key_is_present() {
        // `deny_unknown_fields`: a mistyped key must be an error, not a
        // silently-ignored declaration.
        let hits = violations(&tree(
            "0.13.0-dev",
            &[],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_id = "0.12.0"
note = "typo in the version key"
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("does not parse"), "{hits:?}");
    }

    #[test]
    fn red_when_reference_removed_in_is_a_pre_release() {
        let hits = violations(&tree(
            "0.13.0-dev",
            &[(
                "023_drop_a_column.sql",
                "ALTER TABLE public.artifacts DROP COLUMN legacy_flag;",
            )],
            r#"
[[contraction]]
migration = "023_drop_a_column.sql"
identifiers = ["artifacts.legacy_flag"]
reference_removed_in = "0.12.0-alpha.3"
note = "n/a"
"#,
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("not a plain release version"), "{hits:?}");
    }

    // ---- Scanner shape coverage. -----------------------------------------

    fn ids(sql: &str) -> Vec<(String, Reach)> {
        scan_migration(sql)
            .into_iter()
            .map(|c| (c.identifier, c.reach))
            .collect()
    }

    #[test]
    fn scanner_recognises_drop_table() {
        assert_eq!(
            ids("DROP TABLE IF EXISTS public.scan_configs CASCADE;"),
            vec![("scan_configs".to_string(), Reach::Removed)]
        );
    }

    #[test]
    fn scanner_recognises_drop_column() {
        assert_eq!(
            ids("ALTER TABLE public.artifacts DROP COLUMN IF EXISTS is_deleted;"),
            vec![("artifacts.is_deleted".to_string(), Reach::Removed)]
        );
    }

    #[test]
    fn scanner_recognises_table_and_column_renames() {
        assert_eq!(
            ids("ALTER TABLE public.artifacts RENAME TO artefacts;"),
            vec![("artifacts".to_string(), Reach::Removed)]
        );
        assert_eq!(
            ids("ALTER TABLE artifacts RENAME COLUMN path TO storage_path;"),
            vec![("artifacts.path".to_string(), Reach::Removed)]
        );
        // PostgreSQL allows the `COLUMN` keyword to be omitted.
        assert_eq!(
            ids("ALTER TABLE artifacts RENAME path TO storage_path;"),
            vec![("artifacts.path".to_string(), Reach::Removed)]
        );
    }

    #[test]
    fn scanner_recognises_type_change_and_set_not_null_as_narrowing() {
        assert_eq!(
            ids("ALTER TABLE artifacts ALTER COLUMN name TYPE varchar(64);"),
            vec![("artifacts.name".to_string(), Reach::Narrowed)]
        );
        assert_eq!(
            ids("ALTER TABLE artifacts ALTER COLUMN name SET DATA TYPE varchar(64);"),
            vec![("artifacts.name".to_string(), Reach::Narrowed)]
        );
        assert_eq!(
            ids("ALTER TABLE artifacts ALTER COLUMN deleted_at SET NOT NULL;"),
            vec![("artifacts.deleted_at".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn scanner_ignores_non_contracting_alters() {
        // Widening a column to nullable, setting a default, dropping an
        // index or a constraint, and renaming a constraint all leave every
        // identifier an application query can name exactly as it was.
        assert!(ids("ALTER TABLE artifacts ALTER COLUMN name DROP NOT NULL;").is_empty());
        assert!(ids("ALTER TABLE artifacts ALTER COLUMN name SET DEFAULT 'x';").is_empty());
        assert!(ids("DROP INDEX public.idx_artifacts_name_as_published;").is_empty());
        assert!(
            ids("ALTER TABLE artifacts DROP CONSTRAINT artifacts_repository_id_path_key;")
                .is_empty()
        );
        assert!(ids("ALTER TABLE artifacts RENAME CONSTRAINT a TO b;").is_empty());
        assert!(ids("ALTER TABLE artifacts ADD COLUMN deleted_at timestamptz;").is_empty());
    }

    #[test]
    fn scanner_is_case_and_whitespace_insensitive() {
        assert_eq!(
            ids("alter  table\n   PUBLIC.Artifacts\n   drop   column   Is_Deleted ;"),
            vec![("artifacts.is_deleted".to_string(), Reach::Removed)]
        );
    }

    #[test]
    fn scanner_ignores_a_narrowing_inside_a_check_expression() {
        // A `CHECK (kind IN ('a','b'))` sub-action contains commas at depth
        // one; the top-level comma walk must not mistake them for the end of
        // the ALTER COLUMN action it is inspecting.
        assert_eq!(
            ids("ALTER TABLE jobs ALTER COLUMN kind TYPE text,\n\
                 ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('scan', 'noop'));"),
            vec![("jobs.kind".to_string(), Reach::Narrowed)]
        );
    }

    // ---- Rust string-literal extraction. ---------------------------------

    #[test]
    fn rust_literals_skip_comments_and_char_literals() {
        let src = r##"
            // "not a string"
            /* "also not" /* nested */ "still not" */
            let quote = '"';
            let sql = "SELECT 1 FROM artifacts";
            let raw = r#"SELECT 2 FROM jobs"#;
        "##;
        let lits = rust_string_literals(src);
        assert!(
            lits.iter().any(|l| l.contains("SELECT 1 FROM artifacts")),
            "{lits:?}"
        );
        assert!(
            lits.iter().any(|l| l.contains("SELECT 2 FROM jobs")),
            "{lits:?}"
        );
        assert!(!lits.iter().any(|l| l.contains("not a string")), "{lits:?}");
        assert!(!lits.iter().any(|l| l.contains("also not")), "{lits:?}");
        assert!(!lits.iter().any(|l| l.contains("still not")), "{lits:?}");
    }

    #[test]
    fn rust_literals_survive_a_lifetime_before_a_string() {
        let src = r#"fn f<'a>(s: &'a str) -> &'a str { "SELECT 1 FROM artifacts" }"#;
        let lits = rust_string_literals(src);
        assert!(
            lits.iter().any(|l| l.contains("SELECT 1 FROM artifacts")),
            "{lits:?}"
        );
    }

    // ---- Version arithmetic. ---------------------------------------------

    #[test]
    fn version_core_drops_pre_release_and_build_metadata() {
        assert_eq!(
            parse_version_core("0.12.2-dev").expect("parses"),
            parse_version_core("0.12.2").expect("parses")
        );
        assert_eq!(
            parse_version_core("1.0.0+build.5").expect("parses"),
            parse_version_core("1.0.0").expect("parses")
        );
        assert!(parse_version_core("0.12").is_err());
        assert!(parse_version_core("0.12.2.1").is_err());
        assert!(parse_version_core("x.y.z").is_err());
    }

    #[test]
    fn version_core_orders_by_component() {
        let v = |s| parse_version_core(s).expect("parses");
        assert!(v("0.12.2") > v("0.12.1"));
        assert!(v("0.13.0") > v("0.12.99"));
        assert!(v("1.0.0") > v("0.99.99"));
        // The load-bearing case: a dev tree is NOT after the release it is
        // working towards.
        assert!(v("0.12.0-dev") <= v("0.12.0"));
    }

    #[test]
    fn workspace_version_is_read_from_the_root_manifest() {
        let toml =
            "[workspace]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"0.12.2-dev\"\n";
        assert_eq!(workspace_version(toml).expect("parses"), "0.12.2-dev");
        assert!(workspace_version("[workspace]\n").is_err());
    }

    #[test]
    fn identifier_parsing_rejects_schema_qualified_and_empty_forms() {
        assert_eq!(
            Ident::parse("artifacts").expect("parses"),
            Ident::Table("artifacts".to_string())
        );
        assert_eq!(
            Ident::parse("Artifacts.Is_Deleted").expect("parses"),
            Ident::Column {
                table: "artifacts".to_string(),
                column: "is_deleted".to_string()
            }
        );
        assert!(Ident::parse("public.artifacts.is_deleted").is_err());
        assert!(Ident::parse("artifacts.").is_err());
        assert!(Ident::parse("").is_err());
    }
}
