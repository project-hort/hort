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
//! Three further limits, stated so nobody mistakes a green run for a proof:
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
//!   * **The two exceptions, and why neither is an effects analysis.**
//!     An enum `CHECK` replaced by the same `IN` list plus a new literal
//!     is not reported (see [`only_widens`]), and a uniqueness key
//!     replaced by one that is provably no stricter is not reported (see
//!     [`only_widens_key`]). Both verdicts are **containment over two
//!     enumerated sets** — literal values in the first case, key columns
//!     in the second — a syntactic comparison of two statements, bounded
//!     to one shape, and not a claim about what either constraint forbids.
//!     Everything the comparison cannot make fails closed and is reported.
//!     They exist because a reach that only grew tightens no write
//!     contract at all, so declaring one would fence the routine rolling
//!     upgrade ADR 0030 exempts in as many words: "an expand-only pending
//!     set is never fenced, so routine rolling upgrades stay hook-driven
//!     and unattended."
//!   * **A `CHECK` body is read as tokens, resolved against the columns the
//!     migration set creates.** A reference the scanner cannot see as a
//!     column — one assembled by a function the guard does not evaluate, or
//!     spelled through a view or a domain — is not reported. The filter is
//!     derived rather than enumerated (see [`ColumnUniverse::known`]), so
//!     the escape is a blind spot rather than an exemption: there is nothing
//!     to add to make a finding go away. The same holds for the widening
//!     comparison: the previous definition is harvested from the migration
//!     set ([`CheckDefs`]) and nothing can be added anywhere to produce
//!     one, so the only way past it is a statement that genuinely is the
//!     same list plus more. The uniqueness comparison is bounded the same
//!     way: the predecessor is harvested from the migration set
//!     ([`KeyDefs`]) and the nullability a `PRIMARY KEY` widening must
//!     prove is harvested from it too ([`not_null_after`]), with nothing
//!     to add anywhere to produce either.
//!   * **The lock-duration remedies are not escapes.** `ADD … NOT VALID`
//!     plus a later `VALIDATE`, and `CREATE UNIQUE INDEX CONCURRENTLY`,
//!     are what `strong_migrations` and `squawk` prescribe for these same
//!     statements — and they are about the LOCK the statement takes, which
//!     is availability *during* the migration and a separate question from
//!     release sequencing. Neither discharges this obligation: they exempt
//!     existing ROWS, never a future `INSERT` from a binary that is still
//!     running. A finding here is never fixed by adding one of them.
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
    is_identifier_token, line_of, migrations_dir, parse_table_name, strip_comments,
    strip_comments_and_strings, tokenize, unqualified, workspace_root, Token,
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
    /// The release whose code no longer produces what this migration takes
    /// away — i.e. the release *before* this one is the last that did. For a
    /// `Removed` identifier that is the release whose code stopped naming
    /// it. For a `Narrowed` one the identifier stays, so what the code
    /// stopped producing is the forbidden **values**: the release whose
    /// write paths can no longer emit a value the new type, `NOT NULL` or
    /// `CHECK` refuses. A plain `X.Y.Z`; a pre-release is rejected, because
    /// the policy is stated in terms of releases operators actually upgrade
    /// between.
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
    /// The identifier survives with a tighter contract: a `TYPE` change, a
    /// `SET NOT NULL`, or a new `CHECK`, `UNIQUE`, `PRIMARY KEY`,
    /// `FOREIGN KEY`, `EXCLUDE` or unique index on a pre-existing column.
    /// Old code that *reads* it still works; old code that writes the old
    /// shape errors.
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

/// `true` when `t` is plain SQL text — a word or a punctuation character,
/// not a double-quoted identifier and not a `'…'` string literal.
///
/// Every keyword and punctuation comparison in this file goes through this
/// or through [`kw`]. The string-literal half is load-bearing, because this
/// scanner reads the [`strip_comments`] view (it has to: an enum `CHECK`'s
/// admitted set is a set of literal VALUES, and the other view blanks
/// them). In that view a `DEFAULT 'table'` carries `text == "table"`, and a
/// literal `','` carries `text == ","` — so a depth walk or a keyword match
/// that only excluded quoted identifiers would read a value as syntax.
fn plain(t: &Token) -> bool {
    !t.quoted && !t.string_literal
}

/// `true` when the token at `idx` is plain SQL text equal to `keyword`.
///
/// Also the punctuation test (`kw(tokens, i, ";")`): a punctuation token is
/// plain text whose `text` is that one character, so the comparison is
/// identical and there is no second predicate to keep in step.
fn kw(tokens: &[Token], idx: usize, keyword: &str) -> bool {
    tokens
        .get(idx)
        .is_some_and(|t| plain(t) && t.text == keyword)
}

/// `true` when the token at `idx` is plain SQL text in `words`.
fn kw_in(tokens: &[Token], idx: usize, words: &[&str]) -> bool {
    tokens
        .get(idx)
        .is_some_and(|t| plain(t) && words.contains(&t.text.as_str()))
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
    create_tables(tokens)
        .into_iter()
        .map(|(table, _)| table)
        .collect()
}

/// Every `CREATE TABLE` in the migration, as `(table, index just past the
/// table name)`.
///
/// The index is where a parenthesised column list would start; the
/// `AS SELECT` and `PARTITION OF` forms have none, and a caller that needs
/// the body tests for the `(` itself. One definition of "this is a
/// `CREATE TABLE`" serves the table set, the column harvest and the
/// constraint harvest, so the three cannot come to disagree about what a
/// migration creates.
fn create_tables(tokens: &[Token]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for i in 0..tokens.len() {
        if !kw(tokens, i, "create") {
            continue;
        }
        let mut j = i + 1;
        while kw_in(tokens, j, CREATE_TABLE_MODIFIERS) {
            j += 1;
        }
        if !kw(tokens, j, "table") {
            continue;
        }
        let name_idx = skip_if_not_exists(tokens, j + 1);
        if let Some((name, after_name)) = parse_table_name(tokens, name_idx) {
            out.push((name, after_name));
        }
    }
    out
}

/// Items inside a `CREATE TABLE` body that are table constraints or a
/// table-copy clause rather than column definitions.
const NON_COLUMN_TABLE_ITEMS: &[&str] = &[
    "constraint",
    "primary",
    "unique",
    "foreign",
    "check",
    "exclude",
    "like",
];

/// Keywords that may follow `ADD` in an `ALTER TABLE` sub-action that is NOT
/// a column addition — the table-constraint forms, plus the identity clause
/// of `ALTER COLUMN … ADD GENERATED`.
const NON_COLUMN_ADD_ITEMS: &[&str] = &[
    "constraint",
    "primary",
    "unique",
    "foreign",
    "check",
    "exclude",
    "generated",
];

/// The depth-1 comma-separated item ranges of the parenthesised body whose
/// `(` sits at `open`.
///
/// Body items are comma-separated, but commas also appear inside a column's
/// own parentheses (`numeric(12, 2)`, `CHECK (kind IN ('a','b'))`), so the
/// walk tracks depth and treats only a depth-1 comma as an item boundary.
/// One definition of "where does this item end" serves both the column
/// harvest and the constraint harvest below.
fn body_items(tokens: &[Token], open: usize) -> Vec<std::ops::Range<usize>> {
    let mut items = Vec::new();
    if !kw(tokens, open, "(") {
        return items;
    }
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut j = open;
    let push = |items: &mut Vec<std::ops::Range<usize>>, from: usize, to: usize| {
        if from < to {
            items.push(from..to);
        }
    };
    while j < tokens.len() {
        if plain(&tokens[j]) {
            match tokens[j].text.as_str() {
                "(" => {
                    depth += 1;
                    j += 1;
                    continue;
                }
                ")" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        push(&mut items, start, j);
                        return items;
                    }
                    j += 1;
                    continue;
                }
                "," if depth == 1 => {
                    push(&mut items, start, j);
                    start = j + 1;
                    j += 1;
                    continue;
                }
                ";" => {
                    push(&mut items, start, j);
                    return items;
                }
                _ => {}
            }
        }
        j += 1;
    }
    push(&mut items, start, tokens.len());
    items
}

/// Column definitions in the `CREATE TABLE` body whose `(` sits at `open`,
/// collected as `table.column`.
///
/// An item whose first token is a table-constraint keyword defines no
/// column.
fn collect_create_table_columns(
    tokens: &[Token],
    open: usize,
    table: &str,
    out: &mut BTreeSet<String>,
) {
    for item in body_items(tokens, open) {
        if let Some(column) = item_column(tokens, &item) {
            out.insert(format!("{table}.{column}"));
        }
    }
}

/// The column a `CREATE TABLE` body item defines, or `None` when the item
/// is a table constraint or a table-copy clause rather than a column.
fn item_column(tokens: &[Token], item: &std::ops::Range<usize>) -> Option<String> {
    if kw_in(tokens, item.start, NON_COLUMN_TABLE_ITEMS) {
        return None;
    }
    parse_table_name(tokens, item.start).map(|(column, _)| column)
}

/// Columns added by the `ALTER TABLE <table> …` body starting at `start`,
/// collected as `table.column`.
///
/// Recognises `ADD COLUMN [IF NOT EXISTS] <c>` and PostgreSQL's
/// `COLUMN`-less `ADD <c> <type>`; an `ADD` followed by a table-constraint
/// keyword adds no column.
fn collect_added_columns(tokens: &[Token], start: usize, table: &str, out: &mut BTreeSet<String>) {
    let mut depth = 0usize;
    let mut j = start;
    while j < tokens.len() {
        if plain(&tokens[j]) {
            match tokens[j].text.as_str() {
                "(" => {
                    depth += 1;
                    j += 1;
                    continue;
                }
                ")" => {
                    depth = depth.saturating_sub(1);
                    j += 1;
                    continue;
                }
                ";" => return,
                _ => {}
            }
        }
        if depth == 0 && kw(tokens, j, "add") {
            let cn = if kw(tokens, j + 1, "column") {
                skip_if_not_exists(tokens, j + 2)
            } else {
                j + 1
            };
            if !kw_in(tokens, cn, NON_COLUMN_ADD_ITEMS) {
                if let Some((column, _)) = parse_table_name(tokens, cn) {
                    out.insert(format!("{table}.{column}"));
                }
            }
        }
        j += 1;
    }
}

/// Every column this migration creates, as `table.column`.
///
/// Two sources, which together are every way a migration in this tree brings
/// a column into existence: the body of a `CREATE TABLE`, and an
/// `ALTER TABLE … ADD [COLUMN]`.
fn created_columns(tokens: &[Token]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (table, after_name) in create_tables(tokens) {
        collect_create_table_columns(tokens, after_name, &table, &mut out);
    }
    for (table, after_name) in alter_tables(tokens) {
        collect_added_columns(tokens, after_name, &table, &mut out);
    }
    out
}

/// Whether an `ALTER TABLE … ADD PRIMARY KEY` in THIS migration counts as
/// evidence that its key columns are `NOT NULL`.
///
/// It does for the NEXT migration — PostgreSQL enforces `NOT NULL` on every
/// primary-key column whether the column's own definition said so — and it
/// must not for this one: the statement whose exemption
/// [`only_widens_key`] is deciding cannot be its own evidence that it
/// imposes no new `NOT NULL`. Without the distinction a key widening onto
/// a nullable column reads as exempt because it made the column
/// non-nullable itself, which is the narrowing rather than a reason to
/// forgive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddedKeys {
    Excluded,
    Included,
}

/// The nullability the migration set has established by the time the
/// migration whose tokens these are has run, given `before`.
///
/// Both directions, because membership is a proof obligation for
/// [`only_widens_key`]: a column kept in the set after an
/// `ALTER COLUMN … DROP NOT NULL` would exempt a `PRIMARY KEY` widening
/// that silently re-imposes `NOT NULL` on it.
///
/// Three ways a column becomes `NOT NULL` in this tree, and one way it
/// stops: a `NOT NULL` in its definition (`CREATE TABLE` body item or
/// `ADD [COLUMN]` sub-action), an `ALTER COLUMN … SET NOT NULL`, and
/// membership of a `PRIMARY KEY` — which PostgreSQL enforces as `NOT NULL`
/// whether or not the column said so. A primary key declared inside a
/// `CREATE TABLE` always counts: its columns are created by this migration
/// and so are never the subject of an exemption decision here.
fn not_null_after(
    tokens: &[Token],
    before: &BTreeSet<String>,
    added: AddedKeys,
) -> BTreeSet<String> {
    let mut out = before.clone();
    for (table, after_name) in create_tables(tokens) {
        for item in body_items(tokens, after_name) {
            match item_column(tokens, &item) {
                Some(column) => {
                    if declares_not_null(tokens, item.start, item.end) {
                        out.insert(format!("{table}.{column}"));
                    }
                }
                None => out.extend(primary_key_columns(tokens, &item, &table)),
            }
        }
    }
    for (table, after_name) in alter_tables(tokens) {
        for action in alter_actions(tokens, after_name) {
            apply_action_nullability(tokens, &action, &table, added, &mut out);
        }
    }
    out
}

/// Does the token range declare `NOT NULL` (or an inline `PRIMARY KEY`) at
/// its own paren depth?
///
/// Depth matters: a `CHECK (x IS NOT NULL)` on another column, and a
/// `DEFAULT NULL`, both put the words inside the same item.
fn declares_not_null(tokens: &[Token], start: usize, end: usize) -> bool {
    let mut depth = 0usize;
    for j in start..end.min(tokens.len()) {
        if !plain(&tokens[j]) {
            continue;
        }
        match tokens[j].text.as_str() {
            "(" => depth += 1,
            ")" => depth = depth.saturating_sub(1),
            "not" if depth == 0 && kw(tokens, j + 1, "null") => return true,
            "primary" if depth == 0 && kw(tokens, j + 1, "key") => return true,
            _ => {}
        }
    }
    false
}

/// The `table.column` set of a `PRIMARY KEY (…)` table constraint item,
/// named or anonymous; empty for any other item.
fn primary_key_columns(
    tokens: &[Token],
    item: &std::ops::Range<usize>,
    table: &str,
) -> BTreeSet<String> {
    let mut at = item.start;
    if kw(tokens, at, "constraint") {
        match parse_table_name(tokens, at + 1) {
            Some((_, after_name)) => at = after_name,
            None => return BTreeSet::new(),
        }
    }
    match key_keyword(tokens, at) {
        Some((KeyKind::PrimaryKey, open)) if kw(tokens, open, "(") => {
            plain_column_list(tokens, open, table).unwrap_or_default()
        }
        _ => BTreeSet::new(),
    }
}

/// The comma-separated sub-action ranges of the `ALTER TABLE` clause body
/// starting at `start`, stopping at the statement's `;`.
///
/// Sub-actions are comma-separated, but commas also appear inside
/// parentheses (`CHECK (kind IN ('a','b'))`, a key column list), so only a
/// depth-0 comma is a boundary — the same walk [`action_narrows`] makes,
/// hoisted so the nullability harvest reads the same sub-action shape the
/// matchers do.
fn alter_actions(tokens: &[Token], start: usize) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut from = start;
    let mut j = start;
    while j < tokens.len() {
        if plain(&tokens[j]) {
            match tokens[j].text.as_str() {
                "(" => depth += 1,
                ")" => depth = depth.saturating_sub(1),
                "," if depth == 0 => {
                    if from < j {
                        out.push(from..j);
                    }
                    from = j + 1;
                }
                ";" => {
                    if from < j {
                        out.push(from..j);
                    }
                    return out;
                }
                _ => {}
            }
        }
        j += 1;
    }
    if from < tokens.len() {
        out.push(from..tokens.len());
    }
    out
}

/// Apply one `ALTER TABLE` sub-action's effect on nullability to `out`.
fn apply_action_nullability(
    tokens: &[Token],
    action: &std::ops::Range<usize>,
    table: &str,
    added: AddedKeys,
    out: &mut BTreeSet<String>,
) {
    let at = action.start;
    if kw(tokens, at, "add") {
        if let Some(columns) = added_primary_key_columns(tokens, at, table) {
            if added == AddedKeys::Included {
                out.extend(columns);
            }
            return;
        }
        let cn = if kw(tokens, at + 1, "column") {
            skip_if_not_exists(tokens, at + 2)
        } else {
            at + 1
        };
        if kw_in(tokens, cn, NON_COLUMN_ADD_ITEMS) {
            return;
        }
        if let Some((column, after_column)) = parse_table_name(tokens, cn) {
            if declares_not_null(tokens, after_column, action.end) {
                out.insert(format!("{table}.{column}"));
            }
        }
        return;
    }
    if !kw(tokens, at, "alter") {
        return;
    }
    let cn = if kw(tokens, at + 1, "column") {
        at + 2
    } else {
        at + 1
    };
    let Some((column, after_column)) = parse_table_name(tokens, cn) else {
        return;
    };
    let identifier = format!("{table}.{column}");
    for j in after_column..action.end.min(tokens.len()) {
        if !kw(tokens, j + 1, "not") || !kw(tokens, j + 2, "null") {
            continue;
        }
        if kw(tokens, j, "set") {
            out.insert(identifier);
            return;
        }
        if kw(tokens, j, "drop") {
            out.remove(&identifier);
            return;
        }
    }
}

/// The key columns of an `ADD [CONSTRAINT <n>] PRIMARY KEY (…)` sub-action
/// at `at`, or `None` when the sub-action is not one.
fn added_primary_key_columns(tokens: &[Token], at: usize, table: &str) -> Option<BTreeSet<String>> {
    let mut after_add = at + 1;
    if kw(tokens, after_add, "constraint") {
        let (_, after_name) = parse_table_name(tokens, after_add + 1)?;
        after_add = after_name;
    }
    match key_keyword(tokens, after_add)? {
        (KeyKind::PrimaryKey, open) if kw(tokens, open, "(") => {
            Some(plain_column_list(tokens, open, table).unwrap_or_default())
        }
        _ => None,
    }
}

/// Every `ALTER TABLE [IF EXISTS] [ONLY] <t>` in the migration, as
/// `(table, index just past the table name)` — the start of its clause
/// body.
fn alter_tables(tokens: &[Token]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for i in 0..tokens.len() {
        if !(kw(tokens, i, "alter") && kw(tokens, i + 1, "table")) {
            continue;
        }
        let mut name_idx = skip_if_exists(tokens, i + 2);
        if kw(tokens, name_idx, "only") {
            name_idx += 1;
        }
        if let Some((table, after_name)) = parse_table_name(tokens, name_idx) {
            out.push((table, after_name));
        }
    }
    out
}

/// The column universe one migration's `CHECK` bodies are resolved against.
///
/// "Did this column exist before this migration?" is the whole question a
/// `CHECK` addition turns on, and it is answerable from the tree the guard
/// already walks — the migration set applies in file-name order, so the
/// columns in existence when migration N runs are exactly the ones
/// migrations 1..N created.
struct ColumnUniverse {
    /// `table.column` for every column THIS migration creates. A `CHECK` on
    /// storage the same migration creates is an invariant on new storage: no
    /// previous release ever wrote a value it forbids, so there is no mixed
    /// window to protect and nothing to declare.
    created_here: BTreeSet<String>,
    /// `table.column` for every column created at or before this migration.
    ///
    /// This is what keeps the extraction honest rather than heuristic. A
    /// `CHECK` body is an arbitrary expression: it carries function names,
    /// cast target types, operators and keywords, and treating every bare
    /// identifier in it as a column would report identifiers that are not
    /// columns at all — leaving an operator no way out but a manifest entry
    /// naming a non-column. A token that is in neither set is not a column
    /// and is ignored. Derived from the migration set, so there is nothing
    /// anyone can add to make a finding go away.
    ///
    /// Columns an earlier migration created and then dropped stay in here.
    /// That over-approximation is harmless: a `CHECK` cannot reference a
    /// column that no longer exists, because the migration would not apply.
    known: BTreeSet<String>,
    /// `table.column` for every column this guard can see is `NOT NULL` by
    /// the time this migration's statements run.
    ///
    /// Read by exactly one decision: a `PRIMARY KEY` makes every column of
    /// its key `NOT NULL`, so a key widening that admits more rows can
    /// still narrow a column's write contract through nullability alone.
    /// Membership is therefore a *proof obligation*, and the set is
    /// maintained in both directions — a `DROP NOT NULL` removes a column
    /// again, because an over-approximation here would exempt a real
    /// narrowing rather than report a harmless one.
    not_null: BTreeSet<String>,
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
        if plain(t) {
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
///     `Narrowed(t.c)`;
///   * `ALTER TABLE <t> … ADD CONSTRAINT <name> CHECK (…)`, and the
///     anonymous `ALTER TABLE <t> … ADD CHECK (…)` → `Narrowed(t.c)` for
///     every column the CHECK body names that EXISTED BEFORE this
///     migration — unless the statement only WIDENS the constraint it
///     replaces, which is [`only_widens`];
///   * `ALTER TABLE <t> … ADD [CONSTRAINT <name>] UNIQUE (…)`,
///     `… PRIMARY KEY (…)`, `… FOREIGN KEY (…) REFERENCES …`,
///     `… EXCLUDE [USING <m>] (…)`, and
///     `CREATE UNIQUE INDEX [CONCURRENTLY] [IF NOT EXISTS] [<name>] ON <t>
///     …` → `Narrowed(t.c)` for every column the constraint's own column
///     list names that EXISTED BEFORE this migration — unless the
///     statement only WIDENS a key it replaces, which is
///     [`only_widens_key`]. For a `FOREIGN KEY` that is the REFERENCING
///     list and not the `REFERENCES` one; a `CREATE INDEX` without
///     `UNIQUE` is not recognised at all, because it constrains no write.
///
/// A constraint **drop** and a `CHECK` **addition** point opposite ways, and
/// a reader who finds only one of the three statements below will draw the
/// wrong conclusion about the others, so they stand side by side:
///
///   * Dropping a constraint WIDENS the write contract. Every value the
///     previous release's code produced is still accepted afterwards, and no
///     query names a constraint, so nothing breaks — hence the exclusion
///     below.
///   * Adding a `CHECK` to a pre-existing column NARROWS it. From the
///     instant the migration hook commits — before a single new pod is
///     Ready — the still-running previous release's write paths can produce
///     a value PostgreSQL now refuses. `SET NOT NULL` is the special case
///     `CHECK (c IS NOT NULL)`; this is the general form, and it is the same
///     `Narrowed` reach. A `NOT VALID` suffix does not change that: it
///     exempts EXISTING ROWS from the check, not future INSERTs and
///     UPDATEs, so it is not an escape.
///   * Replacing an enum `CHECK` with the SAME list plus a new literal —
///     the `DROP CONSTRAINT <t>_<c>_check` + re-`ADD` shape that is how a
///     new task kind reaches an already-migrated database — narrows
///     nothing. No writer that has ever existed loses a value it could
///     produce. That is not a contraction and is not reported; see
///     [`only_widens`] for the four conditions, and for why the comparison
///     is syntactic rather than the effects analysis the bullet above
///     refuses.
///   * Adding a `UNIQUE`, `PRIMARY KEY`, `FOREIGN KEY` or `EXCLUDE`
///     constraint, or a `UNIQUE` index, to a pre-existing column NARROWS
///     it, for the identical reason and in the identical window: a
///     duplicate and a dangling reference are values the still-running
///     previous release's write paths can produce and PostgreSQL refuses
///     from the instant the hook commits. This is mainstream
///     expand/contract doctrine rather than a local reading — the
///     pattern's own recipes put it as "application code must write to the
///     column before enforcement constraints are applied" — and
///     `SET NOT NULL`, the special case `CHECK (c IS NOT NULL)`, has been
///     recognised here all along. The lock-duration remedies named in the
///     module header do not discharge it.
///   * Replacing a uniqueness key with one that is provably no stricter —
///     a key over MORE columns, or the same key over a SUBSET of the rows
///     — narrows nothing, for the same reason the `CHECK` widening does.
///     `013_content_references_multivalue_pk.sql` and
///     `021_artifacts_soft_delete.sql` are the two shapes on disk; see
///     [`only_widens_key`] for the four conditions.
///
/// So a `DROP CONSTRAINT c` paired with an `ADD CONSTRAINT c CHECK (…)` in
/// one migration is never a removal plus an addition: the drop contributes
/// nothing, and the addition is either one narrowing or — when the
/// comparison can be made and the set only grew — nothing at all.
///
/// Two blind spots in the constraint class, stated so a green run is not
/// mistaken for a proof. `ADD CONSTRAINT <n> PRIMARY KEY USING INDEX <idx>`
/// carries no parenthesised column list and is not recognised — the
/// `CREATE UNIQUE INDEX` it promotes is, so the uniqueness half is caught
/// where it is declared and only the primary key's implicit `NOT NULL`
/// escapes. And an inline column constraint on an `ADD COLUMN`
/// (`ADD COLUMN c integer UNIQUE`, `… REFERENCES other (id)`) is not
/// recognised either; that one costs nothing, because the column it
/// constrains is created by the same migration and so is exempt anyway.
///
/// Deliberately NOT recognised, because every item on this list WIDENS the
/// write contract or leaves it alone, and no application query names any of
/// them: `DROP INDEX`, `DROP CONSTRAINT`, `RENAME CONSTRAINT`, and
/// `CREATE INDEX` without `UNIQUE`. That the list holds only widenings is
/// the property to preserve when adding to it — a constraint ADDITION is
/// never on it, however harmless it looks, because "the old code never
/// produced a duplicate" is a semantic claim and this guard trades it for
/// one release of sequencing. Constraint drops on a security-critical table
/// are covered unconditionally by the sibling `no_sensitive_drops` guard.
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

/// The half-open token range inside the parenthesised group whose `(` sits
/// at `open`, plus the index just past its closing `)`.
fn parenthesised(tokens: &[Token], open: usize) -> (std::ops::Range<usize>, usize) {
    let mut depth = 0usize;
    let mut j = open;
    while j < tokens.len() {
        let t = &tokens[j];
        if plain(t) {
            if t.text == "(" {
                depth += 1;
            } else if t.text == ")" {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (open + 1..j, j + 1);
                }
            }
        }
        j += 1;
    }
    (open + 1..tokens.len(), tokens.len())
}

/// Every `table.column` a `CHECK` body names, resolved against `universe`.
///
/// A reference is a dotted identifier chain, resolved to the unqualified
/// `table.column` spelling the manifest uses: a bare `c` is a column of the
/// `ALTER TABLE`'s own table, `t.c` and `schema.t.c` carry their own. A
/// chain that resolves to something `universe.known` does not contain is not
/// a column — see [`ColumnUniverse::known`] for why that filter, and not a
/// keyword list, is what bounds this extraction.
fn referenced_columns(
    tokens: &[Token],
    body: std::ops::Range<usize>,
    table: &str,
    universe: &ColumnUniverse,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut j = body.start;
    while j < body.end {
        let (candidate, next) = column_chain(tokens, j, body.end, table);
        if let Some(candidate) = candidate {
            if !universe.created_here.contains(&candidate) && universe.known.contains(&candidate) {
                out.insert(candidate);
            }
        }
        j = next;
    }
    out
}

/// The dotted identifier chain at `at`, resolved to the unqualified,
/// lower-cased `table.column` spelling the manifest uses, plus the index
/// just past the whole chain.
///
/// A bare `c` is a column of the `ALTER TABLE`'s own table; `t.c` and
/// `schema.t.c` carry their own. A chain deeper than that is not something
/// a table `CHECK` can name, and resolves to `None`.
///
/// Returning the chain's end even when it does not resolve is load-bearing,
/// not tidiness: a caller that resumed one token later would re-read
/// `db.public.t.col`'s tail as `public.t.col` and invent the very column
/// the chain's depth denied.
fn column_chain(tokens: &[Token], at: usize, end: usize, table: &str) -> (Option<String>, usize) {
    if at >= end || !is_identifier_token(&tokens[at]) {
        return (None, at + 1);
    }
    let mut parts = vec![unqualified(&tokens[at])];
    let mut k = at + 1;
    while k + 1 < end && kw(tokens, k, ".") && is_identifier_token(&tokens[k + 1]) {
        parts.push(unqualified(&tokens[k + 1]));
        k += 2;
    }
    let resolved = match parts.as_slice() {
        [column] => Some(format!("{table}.{column}")),
        [t, column] => Some(format!("{t}.{column}")),
        [_schema, t, column] => Some(format!("{t}.{column}")),
        _ => None,
    };
    (resolved, k)
}

// ---------------------------------------------------------------------------
// Constraint definitions: the one shape whose admitted set can be compared.
// ---------------------------------------------------------------------------

/// The `<col> IN (<literal>, …)` reading of a `CHECK` body.
///
/// This is the only constraint shape two statements can be *compared* over,
/// which is what the replacement rule below needs. Everything else is a
/// predicate, and deciding whether one predicate admits everything another
/// admits is general implication — not decidable, and not something a token
/// scan should pretend to do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InListCheck {
    /// `table.column`, the manifest's spelling.
    column: String,
    /// Every literal the list admits.
    literals: BTreeSet<String>,
}

/// What `CHECK` definition each `<table>.<constraint name>` carries.
///
/// `None` is "there is a definition under this name and this guard cannot
/// read its admitted set" — a predicate body, or a name defined twice in
/// one migration. It is deliberately NOT the same as a missing key, but it
/// leads to the same verdict: both are undecidable, and undecidable reports
/// the narrowing. What it must not do is leave an older, readable
/// definition standing as though it were still the one in force.
///
/// A name whose constraint was DROPPED and not re-added stays in the map.
/// That over-approximation is harmless in the same way
/// [`ColumnUniverse::known`]'s is: the only statement that consults an
/// entry is an `ADD … CHECK` paired with a `DROP CONSTRAINT` of that name
/// in the same migration, and such a `DROP` against a constraint the
/// database no longer has fails the migration itself. The pairing
/// requirement in [`only_widens`] is what makes that so — without it, a
/// re-`ADD` one release after the drop would be compared against a
/// definition that had not been in force in between, over a window in
/// which the column accepted anything.
type CheckDefs = BTreeMap<String, Option<InListCheck>>;

/// Record one constraint definition under `key`.
///
/// A key defined twice in the SAME migration becomes `None` rather than
/// last-wins: two definitions under one name cannot both be the constraint
/// in force afterwards, which one is depends on the `DROP`s between them,
/// and a comparison must not pick one on its own authority.
fn record_check(defs: &mut CheckDefs, key: String, def: Option<InListCheck>) {
    match defs.entry(key) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(def);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            slot.insert(None);
        }
    }
}

/// Read a `CHECK` body as `<col> IN ('a', 'b', …)`, or `None` when it is
/// anything else at all.
///
/// The strictness is the point, and it mirrors
/// `jobs_trigger_source_check_lockstep_guard`'s parser for the same reason:
/// a reader that accepts the part it understood once read
/// `IN (<the nine>) OR trigger_source = 'other'` back as the unchanged
/// nine. So the body must be the IN-list and *end* there — a bolted-on
/// disjunct, a `NOT IN`, a non-literal member, a second predicate or a
/// second column all answer `None`, and the caller treats `None` as
/// undecidable.
fn in_list_check(
    tokens: &[Token],
    body: std::ops::Range<usize>,
    table: &str,
) -> Option<InListCheck> {
    let (column, after_column) = column_chain(tokens, body.start, body.end, table);
    let column = column?;
    if !kw(tokens, after_column, "in") {
        return None;
    }
    let open = after_column + 1;
    if !kw(tokens, open, "(") {
        return None;
    }
    let mut literals = BTreeSet::new();
    let mut want_literal = true;
    let mut j = open + 1;
    loop {
        if j >= body.end {
            return None;
        }
        if want_literal {
            let t = tokens.get(j)?;
            if !t.string_literal {
                return None;
            }
            literals.insert(t.text.clone());
            want_literal = false;
            j += 1;
            continue;
        }
        if kw(tokens, j, ",") {
            want_literal = true;
            j += 1;
            continue;
        }
        if kw(tokens, j, ")") {
            j += 1;
            break;
        }
        return None;
    }
    // The list must be the WHOLE body.
    if j != body.end {
        return None;
    }
    Some(InListCheck { column, literals })
}

/// The `CHECK` definitions every `CREATE TABLE` in this migration declares
/// inline, recorded into `defs`.
///
/// Both inline forms, because both are how a constraint this tree later
/// redefines came into existence: a named table constraint
/// (`CONSTRAINT artifacts_quarantine_status_check CHECK (…)` in
/// `003_artifacts_cas.sql`) and an anonymous column constraint
/// (`kind text NOT NULL CHECK (kind IN (…))` in
/// `009_scan_jobs_and_findings.sql`, which PostgreSQL auto-names
/// `jobs_kind_check` — the name every later redefinition drops).
fn created_checks(tokens: &[Token], defs: &mut CheckDefs) {
    for (table, after_name) in create_tables(tokens) {
        for item in body_items(tokens, after_name) {
            let column = item_column(tokens, &item);
            record_item_checks(tokens, &item, &table, column.as_deref(), defs);
        }
    }
}

/// Every `CHECK` in one `CREATE TABLE` body item, recorded into `defs`.
///
/// `column` is the column the item defines, or `None` for a table
/// constraint. An unnamed `CHECK` takes the name PostgreSQL would give it —
/// `<table>_<column>_check` on a column, `<table>_check` on the table — so
/// that a later migration's `DROP CONSTRAINT jobs_kind_check` finds the
/// definition it is replacing. PostgreSQL appends a digit when that name is
/// already taken; this guard does not model the collision, and a wrong
/// guess only means a later replacement finds no previous definition, which
/// fails closed.
fn record_item_checks(
    tokens: &[Token],
    item: &std::ops::Range<usize>,
    table: &str,
    column: Option<&str>,
    defs: &mut CheckDefs,
) {
    let mut j = item.start;
    while j < item.end {
        let named = kw(tokens, j, "constraint")
            .then(|| parse_table_name(tokens, j + 1))
            .flatten()
            .filter(|(_, after_name)| kw(tokens, *after_name, "check"))
            .map(|(name, after_name)| (name, after_name + 1));
        let (name, open) = match named {
            Some(found) => found,
            None if kw(tokens, j, "check") => (auto_check_name(table, column), j + 1),
            None => {
                j += 1;
                continue;
            }
        };
        if !kw(tokens, open, "(") {
            j += 1;
            continue;
        }
        let (body, resume) = parenthesised(tokens, open);
        record_check(
            defs,
            format!("{table}.{name}"),
            in_list_check(tokens, body, table),
        );
        j = resume;
    }
}

/// The uniqueness keys every `CREATE TABLE` in this migration declares
/// inline, recorded into `defs`.
///
/// Both forms, for [`created_checks`]' reason: a table constraint
/// (`CONSTRAINT content_references_pkey PRIMARY KEY (…)`) and a column
/// constraint (`id uuid PRIMARY KEY`, which PostgreSQL auto-names
/// `<table>_pkey` — the name a later re-key drops).
fn created_keys(tokens: &[Token], defs: &mut KeyDefs) {
    for (table, after_name) in create_tables(tokens) {
        for item in body_items(tokens, after_name) {
            record_item_keys(
                tokens,
                &item,
                &table,
                item_column(tokens, &item).as_deref(),
                defs,
            );
        }
    }
}

/// The uniqueness key one `CREATE TABLE` body item declares, recorded into
/// `defs`. `column` is the column the item defines, or `None` for a table
/// constraint.
fn record_item_keys(
    tokens: &[Token],
    item: &std::ops::Range<usize>,
    table: &str,
    column: Option<&str>,
    defs: &mut KeyDefs,
) {
    let mut at = item.start;
    let mut named = None;
    if kw(tokens, at, "constraint") {
        match parse_table_name(tokens, at + 1) {
            Some((name, after_name)) => {
                named = Some(name);
                at = after_name;
            }
            None => return,
        }
    }
    // A table constraint carries its own column list.
    if let Some((kind, open)) = key_keyword(tokens, at) {
        if kw(tokens, open, "(") {
            let columns = plain_column_list(tokens, open, table);
            let name = named.unwrap_or_else(|| auto_key_name(table, kind, columns.as_ref()));
            record_key(
                defs,
                name,
                Some(KeyDef {
                    table: table.to_string(),
                    kind,
                    columns,
                    partial: false,
                }),
            );
        }
        return;
    }
    // A column constraint has none: the key is the column it sits on.
    let Some(column) = column else {
        return;
    };
    let qualified: BTreeSet<String> = [format!("{table}.{column}")].into_iter().collect();
    let mut depth = 0usize;
    for j in item.start..item.end.min(tokens.len()) {
        if !plain(&tokens[j]) {
            continue;
        }
        match tokens[j].text.as_str() {
            "(" => depth += 1,
            ")" => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                if let Some((kind, after)) = key_keyword(tokens, j) {
                    if kw(tokens, after, "(") {
                        continue;
                    }
                    record_key(
                        defs,
                        auto_key_name(table, kind, Some(&qualified)),
                        Some(KeyDef {
                            table: table.to_string(),
                            kind,
                            columns: Some(qualified.clone()),
                            partial: false,
                        }),
                    );
                    return;
                }
            }
            _ => {}
        }
    }
}

/// The name PostgreSQL gives an unnamed `CHECK` constraint.
fn auto_check_name(table: &str, column: Option<&str>) -> String {
    match column {
        Some(column) => format!("{table}_{column}_check"),
        None => format!("{table}_check"),
    }
}

/// `<table>.<constraint name>` for every `ALTER TABLE … DROP CONSTRAINT` in
/// this migration.
///
/// A constraint drop is not itself a contraction — it widens the write
/// contract, which is why the scanner ignores it (see the scanner's doc
/// comment) — and this set is read for exactly one purpose: an
/// `ADD … CHECK` under a name this migration just dropped is a
/// *replacement*, and only a replacement has a previous definition to be
/// compared against.
fn dropped_constraints(tokens: &[Token]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (table, after_name) in alter_tables(tokens) {
        let mut k = after_name;
        while k < tokens.len() && !kw(tokens, k, ";") {
            if kw(tokens, k, "drop") && kw(tokens, k + 1, "constraint") {
                let cn = skip_if_exists(tokens, k + 2);
                if let Some((name, _)) = parse_table_name(tokens, cn) {
                    out.insert(format!("{table}.{name}"));
                }
            }
            k += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Uniqueness keys: the non-`CHECK` constraint shapes, and the one of them
// whose reach can be compared.
// ---------------------------------------------------------------------------

/// Which uniqueness constraint a statement declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    /// `UNIQUE (…)`, or a `CREATE UNIQUE INDEX`.
    Unique,
    /// `PRIMARY KEY (…)`, which additionally makes every key column
    /// `NOT NULL` — a second narrowing riding along with the first, and the
    /// reason [`only_widens_key`] asks about nullability at all.
    PrimaryKey,
}

/// The uniqueness key one constraint or unique index enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyDef {
    /// Unqualified, lower-cased table the key is on. A replacement is only
    /// comparable against a predecessor on the SAME table.
    table: String,
    kind: KeyKind,
    /// `table.column` for every key element, when every element is a plain
    /// column reference. `None` when any element is an expression this
    /// guard does not read as a column list, which makes two keys
    /// incomparable and so fails closed.
    columns: Option<BTreeSet<String>>,
    /// `true` when the key constrains a SUBSET of the rows — a partial
    /// unique index's `WHERE`. A partial predecessor is one this guard
    /// cannot compare against: deciding that one row-subset contains
    /// another is predicate implication, which is the analysis the scanner
    /// refuses everywhere else.
    partial: bool,
}

/// What uniqueness key each constraint-or-index NAME carries.
///
/// Keyed by the bare name rather than `<table>.<name>`, because that is
/// exactly what a `DROP CONSTRAINT` and a `DROP INDEX` hand over — an index
/// name is schema-scoped and carries no table. The table lives inside the
/// value and every comparison checks it, so two tables that genuinely share
/// a name collapse to `None` through [`record_key`] and fail closed rather
/// than comparing two unrelated keys.
///
/// `None` means what it means in [`CheckDefs`]: there is a definition under
/// this name and this guard cannot read its key.
type KeyDefs = BTreeMap<String, Option<KeyDef>>;

/// Record one key definition under `name`, collapsing a name defined twice
/// in one migration to `None` for [`record_check`]'s reason.
fn record_key(defs: &mut KeyDefs, name: String, def: Option<KeyDef>) {
    match defs.entry(name) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(def);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            slot.insert(None);
        }
    }
}

/// `UNIQUE` | `PRIMARY KEY` at `idx`, plus the index just past the keyword.
fn key_keyword(tokens: &[Token], idx: usize) -> Option<(KeyKind, usize)> {
    if kw(tokens, idx, "unique") {
        Some((KeyKind::Unique, idx + 1))
    } else if kw(tokens, idx, "primary") && kw(tokens, idx + 1, "key") {
        Some((KeyKind::PrimaryKey, idx + 2))
    } else {
        None
    }
}

/// Read the parenthesised key list whose `(` sits at `open` as a plain
/// column list, resolved to the manifest's `table.column` spelling.
///
/// `None` when any depth-1 item is anything other than exactly one dotted
/// identifier chain — an expression, a collation, an operator class, the
/// `WITH <operator>` element of an `EXCLUDE`. The strictness is the point,
/// for [`in_list_check`]'s reason: a reader that kept the part it
/// understood would compare two key lists that are not the lists.
fn plain_column_list(tokens: &[Token], open: usize, table: &str) -> Option<BTreeSet<String>> {
    let items = body_items(tokens, open);
    if items.is_empty() {
        return None;
    }
    let mut out = BTreeSet::new();
    for item in items {
        let (column, next) = column_chain(tokens, item.start, item.end, table);
        if next != item.end {
            return None;
        }
        out.insert(column?);
    }
    Some(out)
}

/// The name PostgreSQL gives an unnamed uniqueness constraint: `<t>_pkey`
/// for a primary key, `<t>_<col>…_key` for a unique one.
///
/// PostgreSQL joins a unique constraint's columns in DECLARATION order and
/// this guess joins them sorted, so a multi-column anonymous `UNIQUE` can
/// be guessed wrong. Like [`auto_check_name`], a wrong guess only means a
/// later replacement finds no previous definition to compare against,
/// which is the fail-closed direction.
fn auto_key_name(table: &str, kind: KeyKind, columns: Option<&BTreeSet<String>>) -> String {
    match kind {
        KeyKind::PrimaryKey => format!("{table}_pkey"),
        KeyKind::Unique => {
            let mut name = table.to_string();
            for column in columns.into_iter().flatten() {
                name.push('_');
                name.push_str(column.rsplit('.').next().unwrap_or(column));
            }
            name.push_str("_key");
            name
        }
    }
}

/// Bare names of every constraint and index this migration drops.
///
/// Both, under one set, because both are how the uniqueness a replacement
/// supersedes was spelled: `003_artifacts_cas.sql` declares path uniqueness
/// as a table CONSTRAINT and `021_artifacts_soft_delete.sql` replaces it
/// with an INDEX, so a scan that only read one of the two spellings would
/// find no predecessor for the commonest real widening in this tree.
fn dropped_key_names(tokens: &[Token]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, after_name) in alter_tables(tokens) {
        let mut k = after_name;
        while k < tokens.len() && !kw(tokens, k, ";") {
            if kw(tokens, k, "drop") && kw(tokens, k + 1, "constraint") {
                let cn = skip_if_exists(tokens, k + 2);
                if let Some((name, _)) = parse_table_name(tokens, cn) {
                    out.insert(name);
                }
            }
            k += 1;
        }
    }
    for i in 0..tokens.len() {
        if !(kw(tokens, i, "drop") && kw(tokens, i + 1, "index")) {
            continue;
        }
        let mut j = i + 2;
        if kw(tokens, j, "concurrently") {
            j += 1;
        }
        j = skip_if_exists(tokens, j);
        if let Some((name, _)) = parse_table_name(tokens, j) {
            out.insert(name);
        }
    }
    out
}

/// What one `ALTER TABLE … ADD` sub-action declares, when it declares a
/// non-`CHECK` constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddedConstraint {
    /// `UNIQUE (…)` | `PRIMARY KEY (…)` — a uniqueness key, the one shape
    /// a replacement can be compared over.
    Key(KeyKind),
    /// `FOREIGN KEY (…) REFERENCES …`. The narrowed identifier is the
    /// REFERENCING column, whose admissible values shrink to the referenced
    /// column's current contents; the referenced column loses nothing.
    ForeignKey,
    /// `EXCLUDE [USING <method>] (…)`.
    Exclude,
}

/// The constraint class an `ALTER TABLE … ADD [CONSTRAINT <n>]` declares at
/// `at`, plus the index of its parenthesised column list.
fn added_constraint(tokens: &[Token], at: usize) -> Option<(AddedConstraint, usize)> {
    if let Some((kind, open)) = key_keyword(tokens, at) {
        return Some((AddedConstraint::Key(kind), open));
    }
    if kw(tokens, at, "foreign") && kw(tokens, at + 1, "key") {
        return Some((AddedConstraint::ForeignKey, at + 2));
    }
    if kw(tokens, at, "exclude") {
        let mut open = at + 1;
        if kw(tokens, open, "using") {
            open += 2;
        }
        return Some((AddedConstraint::Exclude, open));
    }
    None
}

/// The recognised statement shape, for the failure message an author acts
/// on.
fn add_constraint_shape(named: bool, class: AddedConstraint) -> &'static str {
    match (named, class) {
        (true, AddedConstraint::Key(KeyKind::Unique)) => {
            "ALTER TABLE ... ADD CONSTRAINT ... UNIQUE"
        }
        (false, AddedConstraint::Key(KeyKind::Unique)) => "ALTER TABLE ... ADD UNIQUE",
        (true, AddedConstraint::Key(KeyKind::PrimaryKey)) => {
            "ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY"
        }
        (false, AddedConstraint::Key(KeyKind::PrimaryKey)) => "ALTER TABLE ... ADD PRIMARY KEY",
        (true, AddedConstraint::ForeignKey) => "ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY",
        (false, AddedConstraint::ForeignKey) => "ALTER TABLE ... ADD FOREIGN KEY",
        (true, AddedConstraint::Exclude) => "ALTER TABLE ... ADD CONSTRAINT ... EXCLUDE",
        (false, AddedConstraint::Exclude) => "ALTER TABLE ... ADD EXCLUDE",
    }
}

/// What one migration's statements are resolved against, beyond the token
/// stream itself.
struct MigrationContext<'a> {
    /// The comment-stripped source, for line numbers.
    stripped: &'a str,
    universe: &'a ColumnUniverse,
    /// `<table>.<constraint name>` for every constraint this migration
    /// drops.
    dropped: &'a BTreeSet<String>,
    /// The definition each `<table>.<constraint name>` carried BEFORE this
    /// migration.
    in_force: &'a CheckDefs,
    /// Bare names of every constraint AND index this migration drops — the
    /// candidate predecessors a uniqueness key can be compared against.
    dropped_keys: &'a BTreeSet<String>,
    /// The uniqueness key each name carried BEFORE this migration.
    keys_in_force: &'a KeyDefs,
}

/// The same, narrowed to one `ALTER TABLE`'s own table. The table is the
/// only thing a statement adds to its migration's context, so it is the
/// only field here.
struct TableContext<'a> {
    /// Unqualified, lower-cased name of the `ALTER TABLE`'s table.
    table: &'a str,
    mig: &'a MigrationContext<'a>,
}

impl<'a> MigrationContext<'a> {
    fn on<'s>(&'s self, table: &'s str) -> TableContext<'s>
    where
        'a: 's,
    {
        TableContext { table, mig: self }
    }
}

/// Does this `ADD … CHECK` only *widen* the constraint it replaces?
///
/// A `CHECK` whose admitted set grew and lost nothing tightens no write
/// contract: no writer that has ever existed loses a value it could
/// produce, so there is no mixed window to protect and nothing for the
/// expand/contract policy to schedule. ADR 0030 says as much about the
/// runtime half — "an expand-only pending set is never fenced, so routine
/// rolling upgrades stay hook-driven and unattended" — and declaring one
/// would fence exactly the upgrade that sentence exempts.
///
/// All four conditions hold, or the statement is a narrowing:
///
///   * this migration drops a constraint of the same name — the
///     `DROP CONSTRAINT` + re-`ADD` replacement shape, the only shape with
///     a previous definition to compare against;
///   * that name's previous definition is findable in the migration set
///     before this migration;
///   * both definitions are the `<col> IN (<literal>, …)` form over the
///     same single column;
///   * the new literal set is a superset of the old one. Equality counts: a
///     re-`ADD` of the identical list takes nothing away either.
///
/// This is set containment over two enumerated lists, which is a syntactic
/// comparison of two statements — not the effects analysis the scanner
/// refuses elsewhere. Every other case **fails closed** and reports: a
/// guard that goes quiet when it cannot decide is worse than one that asks
/// for an entry it did not need.
fn only_widens(ctx: &TableContext<'_>, key: &str, new: Option<&InListCheck>) -> bool {
    let Some(new) = new else {
        return false;
    };
    if !ctx.mig.dropped.contains(key) {
        return false;
    }
    let Some(Some(old)) = ctx.mig.in_force.get(key) else {
        return false;
    };
    old.column == new.column && old.literals.is_subset(&new.literals)
}

/// Does this uniqueness key only *widen* the one it replaces?
///
/// The same posture as [`only_widens`], over the other comparable shape.
/// A uniqueness key forbids a ROW given its neighbours rather than a value
/// given itself, so "no stricter" is a containment question about two key
/// column sets, and it is decidable syntactically in one direction only:
///
///   * **a key over MORE columns admits strictly more rows.** Two rows that
///     agree on the wider tuple agree on the narrower one, so the narrower
///     key already forbade them. `NULL` does not disturb that — a `UNIQUE`
///     exempts any row with a `NULL` in the key, and a wider tuple can only
///     contain more `NULL`s.
///   * **a key over a SUBSET of the rows admits strictly more rows** than
///     the same key over all of them.
///
/// So all four conditions hold, or the statement is a narrowing:
///
///   * this migration drops a constraint or index whose previous definition
///     is findable in the migration set and sits on the same table — the
///     replacement shape, the only one with a predecessor to compare
///     against;
///   * that predecessor is NOT partial. A partial predecessor would make
///     the comparison "does this row-subset contain that one", which is
///     predicate implication;
///   * both key column lists are readable as plain column lists
///     ([`plain_column_list`]), and the predecessor's is a subset of this
///     one. Equality counts: re-stating the same key takes nothing away;
///   * if the new key is a `PRIMARY KEY`, every one of its columns is
///     already `NOT NULL`. Otherwise the statement smuggles in a
///     `SET NOT NULL` that the row-admission argument above says nothing
///     about.
///
/// Every other case **fails closed** and is reported, including the one the
/// ecosystem's lock-duration advice would "fix": `ADD … NOT VALID` plus a
/// later `VALIDATE`, and `CREATE UNIQUE INDEX CONCURRENTLY`, shorten the
/// lock and do not discharge this obligation at all — they exempt existing
/// rows, never a future `INSERT` from a binary that is still running.
fn only_widens_key(table: &str, mig: &MigrationContext<'_>, new: &KeyDef) -> bool {
    let Some(new_columns) = new.columns.as_ref() else {
        return false;
    };
    if new.kind == KeyKind::PrimaryKey
        && !new_columns
            .iter()
            .all(|column| mig.universe.not_null.contains(column))
    {
        return false;
    }
    mig.dropped_keys.iter().any(|name| {
        matches!(
            mig.keys_in_force.get(name),
            Some(Some(old))
                if old.table == table
                    && !old.partial
                    && old
                        .columns
                        .as_ref()
                        .is_some_and(|old_columns| old_columns.is_subset(new_columns))
        )
    })
}

/// `ADD [CONSTRAINT <name>] UNIQUE | PRIMARY KEY | FOREIGN KEY | EXCLUDE`
/// inside an `ALTER TABLE` body at `k`. Returns the index to resume
/// scanning from when this shape matched — just past the constraint's own
/// column list, which for a `FOREIGN KEY` is the REFERENCING list and
/// deliberately not the `REFERENCES` one.
///
/// Records the uniqueness key it adds into `defs` whatever the verdict,
/// because a later migration's replacement is compared against it.
fn scan_add_constraint(
    tokens: &[Token],
    k: usize,
    ctx: &TableContext<'_>,
    out: &mut Vec<Contraction>,
    defs: &mut KeyDefs,
) -> Option<usize> {
    if !kw(tokens, k, "add") {
        return None;
    }
    let (named, at) = if kw(tokens, k + 1, "constraint") {
        let (name, after_name) = parse_table_name(tokens, k + 2)?;
        (Some(name), after_name)
    } else {
        (None, k + 1)
    };
    let (class, open) = added_constraint(tokens, at)?;
    if !kw(tokens, open, "(") {
        return None;
    }
    let shape = add_constraint_shape(named.is_some(), class);
    let (body, resume) = parenthesised(tokens, open);
    if let AddedConstraint::Key(kind) = class {
        let def = KeyDef {
            table: ctx.table.to_string(),
            kind,
            columns: plain_column_list(tokens, open, ctx.table),
            partial: false,
        };
        let name = named.unwrap_or_else(|| auto_key_name(ctx.table, kind, def.columns.as_ref()));
        record_key(defs, name, Some(def.clone()));
        if only_widens_key(ctx.table, ctx.mig, &def) {
            return Some(resume);
        }
    }
    for identifier in referenced_columns(tokens, body, ctx.table, ctx.mig.universe) {
        out.push(Contraction {
            identifier,
            reach: Reach::Narrowed,
            shape,
            line: line_of(ctx.mig.stripped, tokens[k].offset),
        });
    }
    Some(resume)
}

/// `CREATE UNIQUE INDEX [CONCURRENTLY] [IF NOT EXISTS] [<name>] ON <t>
/// [USING <method>] ( … )` starting at `i`. Returns the index to resume
/// scanning from when this shape matched.
///
/// The `UNIQUE` form only: a non-unique index constrains no write at all,
/// so it is additive DDL whatever it covers. The reported columns come from
/// the KEY list and not from an `INCLUDE` payload or a partial `WHERE` — a
/// payload column is not constrained, and a predicate selects WHICH rows
/// the uniqueness covers rather than forbidding a value in the predicate's
/// own columns.
fn scan_create_unique_index(
    tokens: &[Token],
    i: usize,
    mig: &MigrationContext<'_>,
    out: &mut Vec<Contraction>,
    defs: &mut KeyDefs,
) -> Option<usize> {
    if !(kw(tokens, i, "create") && kw(tokens, i + 1, "unique") && kw(tokens, i + 2, "index")) {
        return None;
    }
    let mut j = i + 3;
    if kw(tokens, j, "concurrently") {
        j += 1;
    }
    j = skip_if_not_exists(tokens, j);
    // PostgreSQL lets the index name be omitted, in which case `ON` follows
    // immediately and there is no name to record a definition under.
    let named = if kw(tokens, j, "on") {
        None
    } else {
        let (name, after_name) = parse_table_name(tokens, j)?;
        j = after_name;
        Some(name)
    };
    if !kw(tokens, j, "on") {
        return None;
    }
    j += 1;
    if kw(tokens, j, "only") {
        j += 1;
    }
    let (table, after_table) = parse_table_name(tokens, j)?;
    let mut open = after_table;
    if kw(tokens, open, "using") {
        open += 2;
    }
    if !kw(tokens, open, "(") {
        return None;
    }
    let (body, resume) = parenthesised(tokens, open);
    let def = KeyDef {
        table: table.clone(),
        kind: KeyKind::Unique,
        columns: plain_column_list(tokens, open, &table),
        partial: statement_has_where(tokens, resume),
    };
    if let Some(name) = named {
        record_key(defs, name, Some(def.clone()));
    }
    if !only_widens_key(&table, mig, &def) {
        for identifier in referenced_columns(tokens, body, &table, mig.universe) {
            out.push(Contraction {
                identifier,
                reach: Reach::Narrowed,
                shape: "CREATE UNIQUE INDEX",
                line: line_of(mig.stripped, tokens[i].offset),
            });
        }
    }
    Some(resume)
}

/// Does the statement that continues at `from` carry a top-level `WHERE`?
///
/// For a `CREATE INDEX` that is the partial-index predicate, which is what
/// makes the index constrain a subset of the rows.
fn statement_has_where(tokens: &[Token], from: usize) -> bool {
    let mut depth = 0usize;
    for token in tokens.iter().skip(from) {
        if !plain(token) {
            continue;
        }
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => depth = depth.saturating_sub(1),
            ";" => return false,
            "where" if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// `ADD CONSTRAINT <name> CHECK ( … )` | `ADD CHECK ( … )` inside an
/// `ALTER TABLE` body at `k`. Returns the index to resume scanning from when
/// this shape matched — just past the CHECK body, so no other matcher reads
/// the expression inside it.
///
/// Records the definition it adds into `defs` whatever the verdict, because
/// a later migration's replacement is compared against it.
fn scan_add_check(
    tokens: &[Token],
    k: usize,
    ctx: &TableContext<'_>,
    out: &mut Vec<Contraction>,
    defs: &mut CheckDefs,
) -> Option<usize> {
    if !kw(tokens, k, "add") {
        return None;
    }
    let (shape, name, open) = if kw(tokens, k + 1, "check") {
        (
            "ALTER TABLE ... ADD CHECK",
            auto_check_name(ctx.table, None),
            k + 2,
        )
    } else if kw(tokens, k + 1, "constraint") {
        let (name, after_name) = parse_table_name(tokens, k + 2)?;
        if !kw(tokens, after_name, "check") {
            return None;
        }
        (
            "ALTER TABLE ... ADD CONSTRAINT ... CHECK",
            name,
            after_name + 1,
        )
    } else {
        return None;
    };
    if !kw(tokens, open, "(") {
        return None;
    }
    let (body, resume) = parenthesised(tokens, open);
    let key = format!("{}.{name}", ctx.table);
    let added = in_list_check(tokens, body.clone(), ctx.table);
    record_check(defs, key.clone(), added.clone());
    if only_widens(ctx, &key, added.as_ref()) {
        return Some(resume);
    }
    for identifier in referenced_columns(tokens, body, ctx.table, ctx.mig.universe) {
        out.push(Contraction {
            identifier,
            reach: Reach::Narrowed,
            shape,
            line: line_of(ctx.mig.stripped, tokens[k].offset),
        });
    }
    Some(resume)
}

/// The full clause body of one `ALTER TABLE <table> …` statement, from just
/// after the table name to the terminating `;`.
fn scan_alter_table_body(
    tokens: &[Token],
    start: usize,
    n: usize,
    ctx: &TableContext<'_>,
    sink: &mut MigrationSink,
) {
    let (table, stripped) = (ctx.table, ctx.mig.stripped);
    let out = &mut sink.contractions;
    let mut k = start;
    while k < n && !kw(tokens, k, ";") {
        if let Some(next) = scan_drop_column(tokens, k, table, stripped, out) {
            k = next;
            continue;
        }
        if let Some(next) = scan_rename_clause(tokens, k, table, stripped, out) {
            k = next;
            continue;
        }
        if let Some(next) = scan_column_alter(tokens, k, table, stripped, out) {
            k = next;
            continue;
        }
        if let Some(next) = scan_add_check(tokens, k, ctx, out, &mut sink.checks) {
            k = next;
            continue;
        }
        if let Some(next) = scan_add_constraint(tokens, k, ctx, out, &mut sink.keys) {
            k = next;
            continue;
        }
        k += 1;
    }
}

/// `ALTER TABLE [ONLY] <t> …` starting at `i`; resolves the table name and
/// delegates the clause body to [`scan_alter_table_body`].
fn scan_alter_table_statement(
    tokens: &[Token],
    i: usize,
    n: usize,
    mig: &MigrationContext<'_>,
    sink: &mut MigrationSink,
) {
    let mut name_idx = skip_if_exists(tokens, i + 2);
    if kw(tokens, name_idx, "only") {
        name_idx += 1;
    }
    let Some((table, after_name)) = parse_table_name(tokens, name_idx) else {
        return;
    };
    scan_alter_table_body(tokens, after_name, n, &mig.on(&table), sink);
}

/// What one migration's scan accumulates.
#[derive(Default)]
struct MigrationSink {
    contractions: Vec<Contraction>,
    /// The `CHECK` definitions this migration establishes — what the NEXT
    /// migration's replacements are compared against.
    checks: CheckDefs,
    /// The uniqueness keys this migration establishes, for the same reason.
    keys: KeyDefs,
}

/// One migration's scan result: what it contracts, and what it adds to the
/// column universe and the constraint definitions the NEXT migration is
/// read against.
struct MigrationScan {
    contractions: Vec<Contraction>,
    created_columns: BTreeSet<String>,
    checks: CheckDefs,
    keys: KeyDefs,
    /// Nullability as it stands AFTER this migration — carried forward
    /// whole rather than as a delta, because a `DROP NOT NULL` removes a
    /// column and a delta the caller unions in could not express that.
    not_null: BTreeSet<String>,
}

/// Scan one migration, resolving its `CHECK` bodies against the columns that
/// existed before it (`known_before`) plus the ones it creates itself, and
/// its `CHECK` replacements against the definitions in force before it
/// (`in_force`).
///
/// The scan reads the [`strip_comments`] view rather than the fully-stripped
/// one, because an enum `CHECK`'s admitted set is a set of literal VALUES
/// and the other view blanks them. Every keyword and punctuation test here
/// goes through [`plain`] / [`kw`], which reject a string-literal token, so
/// a literal still cannot be read as syntax.
fn scan_migration(sql: &str, before: &SchemaBefore<'_>) -> MigrationScan {
    let stripped = strip_comments(sql);
    let tokens = tokenize(&stripped);
    let created = created_tables(&tokens);
    let created_here = created_columns(&tokens);
    let mut known = before.columns.clone();
    known.extend(created_here.iter().cloned());
    let universe = ColumnUniverse {
        created_here: created_here.clone(),
        known,
        not_null: not_null_after(&tokens, before.not_null, AddedKeys::Excluded),
    };
    let dropped = dropped_constraints(&tokens);
    let dropped_keys = dropped_key_names(&tokens);
    let mig = MigrationContext {
        stripped: &stripped,
        universe: &universe,
        dropped: &dropped,
        in_force: before.checks,
        dropped_keys: &dropped_keys,
        keys_in_force: before.keys,
    };
    let mut sink = MigrationSink::default();
    created_checks(&tokens, &mut sink.checks);
    created_keys(&tokens, &mut sink.keys);
    let n = tokens.len();

    let mut i = 0;
    while i < n {
        if let Some(c) = scan_drop_table(&tokens, i, &created, &stripped) {
            sink.contractions.push(c);
        }
        if let Some(next) =
            scan_create_unique_index(&tokens, i, &mig, &mut sink.contractions, &mut sink.keys)
        {
            i = next;
            continue;
        }
        if kw(&tokens, i, "alter") && kw(&tokens, i + 1, "table") {
            scan_alter_table_statement(&tokens, i, n, &mig, &mut sink);
        }
        i += 1;
    }

    // A key this migration dropped and did not re-add stops being a
    // comparable predecessor. `CheckDefs` leaves a dropped name standing on
    // the grounds that a `DROP CONSTRAINT` against a constraint the database
    // does not have fails the migration — but `DROP INDEX IF EXISTS`
    // succeeds against nothing, so a later migration could otherwise be
    // compared against a key that was not in force. In the gap the columns
    // accepted anything, so a writer in the gap could have produced a row the
    // replacement refuses, and being wider than the old key says nothing
    // about that. `None` is "not comparable", which reports.
    for name in &dropped_keys {
        if !sink.keys.contains_key(name) {
            record_key(&mut sink.keys, name.clone(), None);
        }
    }

    sink.contractions.sort();
    sink.contractions.dedup();
    MigrationScan {
        contractions: sink.contractions,
        created_columns: created_here,
        checks: sink.checks,
        keys: sink.keys,
        not_null: not_null_after(&tokens, before.not_null, AddedKeys::Included),
    }
}

/// The schema as it stands BEFORE one migration's statements run — what
/// every "did this exist already?" question in the scan is resolved
/// against.
///
/// One struct rather than four parameters, because the four move together:
/// each is the accumulation of the migrations in front of this one, and a
/// caller that threaded three of them would ask the scan to decide the
/// fourth on its own authority.
struct SchemaBefore<'a> {
    /// `table.column` for every column created at or before this point.
    columns: &'a BTreeSet<String>,
    /// `table.column` for every column known to be `NOT NULL`.
    not_null: &'a BTreeSet<String>,
    /// The `CHECK` definition each `<table>.<constraint name>` carries.
    checks: &'a CheckDefs,
    /// The uniqueness key each constraint-or-index name carries.
    keys: &'a KeyDefs,
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
            plain(t)
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
    /// `(migration file name, SQL)`, in any order — the checks sort by file
    /// name themselves, because that is the order `sqlx::migrate!` applies
    /// them and therefore the order in which columns come into existence
    /// (see [`ColumnUniverse`]).
    migrations: Vec<(String, String)>,
    /// Raw `CONTRACTIONS.toml` text.
    manifest_toml: String,
    /// `(display path, Rust source)` for the production-source corpus.
    sources: Vec<(String, String)>,
}

/// Scan every migration in apply order (file name), carrying the column
/// universe forward.
///
/// The order is load-bearing and not a tidiness choice: whether a `CHECK`
/// lands on a pre-existing column is a question about the migrations BEFORE
/// it, and file-name order is the order `sqlx::migrate!` applies them.
fn scan_in_apply_order(migrations: &[(String, String)]) -> BTreeMap<&str, Vec<Contraction>> {
    let mut in_order: Vec<(&str, &String)> = migrations
        .iter()
        .map(|(name, sql)| (name.as_str(), sql))
        .collect();
    in_order.sort_by_key(|(name, _)| *name);
    let mut known_columns: BTreeSet<String> = BTreeSet::new();
    let mut not_null: BTreeSet<String> = BTreeSet::new();
    let mut checks_in_force: CheckDefs = BTreeMap::new();
    let mut keys_in_force: KeyDefs = BTreeMap::new();
    let mut scanned = BTreeMap::new();
    for (name, sql) in in_order {
        let scan = scan_migration(
            sql,
            &SchemaBefore {
                columns: &known_columns,
                not_null: &not_null,
                checks: &checks_in_force,
                keys: &keys_in_force,
            },
        );
        known_columns.extend(scan.created_columns);
        not_null = scan.not_null;
        checks_in_force.extend(scan.checks);
        keys_in_force.extend(scan.keys);
        scanned.insert(name, scan.contractions);
    }
    scanned
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

    let scanned = scan_in_apply_order(&inputs.migrations);

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

/// Everything the real tree supplies to [`violations`], so the green test
/// and the mutation probes that perturb one input run against the SAME
/// corpus.
fn real_tree_inputs() -> Inputs {
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

    Inputs {
        current_version,
        migrations,
        manifest_toml,
        sources,
    }
}

#[test]
fn no_migration_contracts_ahead_of_its_release() {
    let inputs = real_tree_inputs();
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
        // Additive DDL needs no entry at all, and the reason is specific to
        // what "additive" means: the old binary never NAMES the new
        // identifier, so no query it issues can break on the name's
        // account. `ADD COLUMN` and a non-unique index are additive in
        // exactly that sense — neither forbids a write either.
        //
        // This fixture used to carry 021's statement pair, with that same
        // sentence as the justification. The sentence is true of the index
        // NAME and says nothing about the constraint the index imposes, so
        // it justified the wrong half: a unique index on pre-existing
        // columns narrows a write contract whatever its name. 021's pair
        // stays green, but on the widening exemption and not on this
        // claim — see
        // [`a_full_unique_constraint_replaced_by_a_partial_index_only_widens`],
        // which asserts it with the reason that is actually load-bearing.
        let hits = violations(&tree(
            "0.12.2-dev",
            &[(
                "022_artifacts_release_attempt_at.sql",
                "ALTER TABLE public.artifacts ADD COLUMN release_attempt_at timestamptz;\n\
                 CREATE INDEX idx_artifacts_release_attempt_at\n\
                     ON public.artifacts (release_attempt_at);",
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

    /// `(identifier, reach)` for one migration read as the FIRST in the
    /// tree — no column exists before it, so every `CHECK` it adds is a
    /// `CHECK` on storage it created itself.
    fn ids(sql: &str) -> Vec<(String, Reach)> {
        ids_after(&[], sql)
    }

    /// `(identifier, reach)` for one migration read after `earlier` — the
    /// shape every `CHECK`-narrowing case needs, because "did this column
    /// exist before?" is a question about the migrations in front of it.
    fn ids_after(earlier: &[&str], sql: &str) -> Vec<(String, Reach)> {
        scan(earlier, sql)
            .contractions
            .into_iter()
            .map(|c| (c.identifier, c.reach))
            .collect()
    }

    /// Full scan of `sql` read after `earlier`, for the cases that assert on
    /// the reported shape or line as well as the identifier.
    ///
    /// Carries the column universe AND the constraint definitions forward
    /// exactly as [`scan_in_apply_order`] does, so a fixture reads the same
    /// way a real migration set does.
    fn scan(earlier: &[&str], sql: &str) -> MigrationScan {
        let mut known = BTreeSet::new();
        let mut not_null = BTreeSet::new();
        let mut checks = CheckDefs::new();
        let mut keys = KeyDefs::new();
        let before = |known: &BTreeSet<String>,
                      not_null: &BTreeSet<String>,
                      checks: &CheckDefs,
                      keys: &KeyDefs,
                      sql: &str| {
            scan_migration(
                sql,
                &SchemaBefore {
                    columns: known,
                    not_null,
                    checks,
                    keys,
                },
            )
        };
        for prior in earlier {
            let scan = before(&known, &not_null, &checks, &keys, prior);
            known.extend(scan.created_columns);
            not_null = scan.not_null;
            checks.extend(scan.checks);
            keys.extend(scan.keys);
        }
        before(&known, &not_null, &checks, &keys, sql)
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

    // ---- CHECK additions: the narrowing the scanner used to miss. --------

    /// A migration that creates `t.col`, so a later one's CHECK on it is a
    /// CHECK on storage that already existed.
    const CREATES_T_COL: &str = "CREATE TABLE public.t (id uuid PRIMARY KEY, col integer);";

    #[test]
    fn check_on_a_pre_existing_column_is_a_narrowing() {
        let scanned = scan(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col >= 0);",
        );
        assert_eq!(scanned.contractions.len(), 1, "{:?}", scanned.contractions);
        let found = &scanned.contractions[0];
        assert_eq!(found.identifier, "t.col");
        assert_eq!(found.reach, Reach::Narrowed);
        assert_eq!(found.shape, "ALTER TABLE ... ADD CONSTRAINT ... CHECK");
        // The failure message is what an author acts on, so it must carry
        // the identifier and the shape, not just a count.
        let message = describe(&scanned.contractions);
        assert!(message.contains("t.col"), "{message}");
        assert!(message.contains("ADD CONSTRAINT ... CHECK"), "{message}");
    }

    #[test]
    fn an_anonymous_add_check_is_the_same_narrowing() {
        // `ADD CONSTRAINT <name> CHECK (…)` and `ADD CHECK (…)` differ only
        // in whether PostgreSQL has to invent the constraint name; the write
        // contract they impose is identical.
        let scanned = scan(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CHECK (col >= 0);",
        );
        assert_eq!(scanned.contractions.len(), 1, "{:?}", scanned.contractions);
        assert_eq!(scanned.contractions[0].identifier, "t.col");
        assert_eq!(scanned.contractions[0].reach, Reach::Narrowed);
        assert_eq!(scanned.contractions[0].shape, "ALTER TABLE ... ADD CHECK");
    }

    #[test]
    fn check_on_a_column_created_in_the_same_migration_is_not_a_narrowing() {
        // (a) the column arrives by ADD COLUMN in this very migration.
        assert!(
            ids_after(
                &["CREATE TABLE public.t (id uuid PRIMARY KEY);"],
                "ALTER TABLE public.t ADD COLUMN col integer NOT NULL DEFAULT 0;\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col >= 0);",
            )
            .is_empty(),
            "a CHECK on a column added by the same migration forbids nothing any \
             previous release could have written"
        );
        // (b) the whole table arrives by CREATE TABLE in this migration —
        // both with the CHECK declared inline and bolted on afterwards.
        assert!(
            ids("CREATE TABLE public.t (id uuid PRIMARY KEY, col integer CHECK (col >= 0));")
                .is_empty()
        );
        assert!(ids(
            "CREATE TABLE public.t (id uuid PRIMARY KEY, col integer);\n\
             ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col >= 0);"
        )
        .is_empty());
    }

    #[test]
    fn a_check_naming_several_columns_reports_each_pre_existing_one() {
        // `old_a` and `old_b` pre-exist; `fresh` is added by this migration.
        // One statement, three references, two findings.
        assert_eq!(
            ids_after(
                &["CREATE TABLE public.t (old_a integer, old_b integer);"],
                "ALTER TABLE public.t ADD COLUMN fresh integer;\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_consistent CHECK (\n\
                     old_a >= 0 AND old_b >= old_a AND fresh >= old_b\n\
                 );",
            ),
            vec![
                ("t.old_a".to_string(), Reach::Narrowed),
                ("t.old_b".to_string(), Reach::Narrowed),
            ]
        );
    }

    #[test]
    fn non_column_tokens_in_a_check_body_are_not_columns() {
        // A CHECK body is an arbitrary expression. Function names, cast
        // target types, keywords and string literals all tokenize exactly
        // like a column reference; what separates them is membership in the
        // column universe the migration set derives. Without this filter the
        // scanner would demand manifest entries for `char_length` and
        // `text`, and the only way out would be declaring a non-column.
        assert_eq!(
            ids_after(
                &["CREATE TABLE public.t (name text, status text, kind text);"],
                "ALTER TABLE public.t ADD CONSTRAINT t_shape CHECK (\n\
                     char_length(name) > 0\n\
                     AND status::text = 'x'\n\
                     AND kind IN ('a','b')\n\
                 );",
            ),
            vec![
                ("t.kind".to_string(), Reach::Narrowed),
                ("t.name".to_string(), Reach::Narrowed),
                ("t.status".to_string(), Reach::Narrowed),
            ]
        );
    }

    #[test]
    fn a_qualified_reference_resolves_to_the_manifest_spelling() {
        // `t.col` and `public.t.col` are the same identifier the manifest
        // names, unqualified and lower-cased.
        for body in [
            "CHECK (t.col >= 0)",
            "CHECK (public.t.col >= 0)",
            "CHECK (COL >= 0)",
        ] {
            assert_eq!(
                ids_after(
                    &[CREATES_T_COL],
                    &format!("ALTER TABLE public.t ADD CONSTRAINT t_c {body};"),
                ),
                vec![("t.col".to_string(), Reach::Narrowed)],
                "{body}"
            );
        }
    }

    #[test]
    fn not_valid_does_not_change_the_verdict() {
        // `NOT VALID` exempts EXISTING ROWS from the check. Every INSERT and
        // UPDATE is constrained from the migration hook onward, which is the
        // whole of the mixed-window exposure — so it must not read as an
        // escape.
        let plain = ids_after(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col >= 0);",
        );
        let not_valid = ids_after(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col >= 0) NOT VALID;",
        );
        assert_eq!(plain, not_valid);
        assert_eq!(plain, vec![("t.col".to_string(), Reach::Narrowed)]);
    }

    #[test]
    fn a_drop_constraint_paired_with_a_re_add_is_one_narrowing() {
        // A constraint DROP on its own widens the write contract and is
        // deliberately invisible to this scanner.
        assert!(ids_after(
            &[CREATES_T_COL],
            "ALTER TABLE public.t DROP CONSTRAINT t_col_nonnegative;",
        )
        .is_empty());
        // Paired with a re-ADD of the same name it is ONE narrowing, not a
        // removal plus an addition: the drop contributes nothing, and the
        // addition is classified on its own terms. Here the predicate body
        // is not an `IN` list, so there is no admitted set to compare and
        // the pair fails closed; the replacement cases below cover the
        // comparison that CAN be made.
        assert_eq!(
            ids_after(
                &[CREATES_T_COL],
                "ALTER TABLE public.t DROP CONSTRAINT t_col_nonnegative;\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_col_nonnegative CHECK (col > 0);",
            ),
            vec![("t.col".to_string(), Reach::Narrowed)]
        );
    }

    // ---- The literals view this scanner reads. ---------------------------

    #[test]
    fn a_literal_is_never_read_as_syntax_in_the_literals_view() {
        // The hazard of reading the view that keeps string literals: a
        // literal tokenizes exactly like a word, so a `DEFAULT 'table'`
        // could be read as the `TABLE` keyword and a literal `','` could
        // end a `CREATE TABLE` body item. Every keyword and punctuation
        // test goes through `plain` / `kw`, which reject a literal token.
        let tokens = |sql: &str| tokenize(&strip_comments(sql));
        // `'table'` must not make this look like a second CREATE TABLE, and
        // `','` must not split the column item it sits in.
        let sql = "CREATE TABLE public.t (\n\
                       a text DEFAULT 'create table other (x int)',\n\
                       b text DEFAULT ','\n\
                   );";
        assert_eq!(
            created_tables(&tokens(sql)),
            ["t".to_string()].into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            created_columns(&tokens(sql)),
            ["t.a".to_string(), "t.b".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        // A literal `';'` must not end the ALTER statement early, so the
        // DROP COLUMN after it is still seen.
        assert_eq!(
            ids("ALTER TABLE public.t ALTER COLUMN a SET DEFAULT ';', DROP COLUMN b;"),
            vec![("t.b".to_string(), Reach::Removed)]
        );
        // And a literal naming a column is not a reference to it.
        assert!(ids_after(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CONSTRAINT t_c CHECK ('col' = 'col');",
        )
        .is_empty());
    }

    #[test]
    fn a_literals_value_survives_the_lexer_intact() {
        let value = |sql: &str| {
            tokenize(&strip_comments(sql))
                .into_iter()
                .filter(|t| t.string_literal)
                .map(|t| t.text)
                .collect::<Vec<_>>()
        };
        // Case is preserved: a literal is a value, and `'Scan'` is not
        // `'scan'`, so a set comparison must not fold them together.
        assert_eq!(value("CHECK (k IN ('Scan', 'scan'))"), ["Scan", "scan"]);
        // Hyphens and underscores are part of the value, not separators —
        // every task kind in this tree is hyphen-separated.
        assert_eq!(
            value("CHECK (k IN ('cron-rescan-tick'))"),
            ["cron-rescan-tick"]
        );
        // `''` is SQL's escape for one quote INSIDE the literal, not the
        // end of it followed by the start of another.
        assert_eq!(value("CHECK (k = 'it''s one')"), ["it's one"]);
        // A `--` inside a literal does not open a comment, so the rest of
        // the statement survives; a `'` inside a comment does not open a
        // literal, so the comment's text contributes nothing.
        assert_eq!(
            value("CHECK (k IN ('a--b')) -- it's prose with 'quotes'\nAND (j IN ('c'))"),
            ["a--b", "c"]
        );
    }

    #[test]
    fn the_two_stripped_views_agree_about_which_bytes_are_code() {
        // The claim the shared lexer makes: blanking a literal and typing
        // it are two readings of the SAME code, so dropping the literal
        // tokens from the kept view must leave exactly the blanked view's
        // token stream — same texts, same kinds, same offsets. Asserted
        // over the real migration tree, because that is the corpus whose
        // comments and literals actually contain the awkward cases (a
        // reversal runbook quoting a DROP, a comment containing an
        // apostrophe). If the two walks ever diverge, this goes red before
        // a guard silently reads a different statement than its sibling.
        let inputs = real_tree_inputs();
        for (name, sql) in &inputs.migrations {
            let blanked = tokenize(&strip_comments_and_strings(sql));
            let kept: Vec<Token> = tokenize(&strip_comments(sql))
                .into_iter()
                .filter(|t| !t.string_literal)
                .collect();
            let shape = |tokens: &[Token]| -> Vec<(String, bool, usize)> {
                tokens
                    .iter()
                    .map(|t| (t.text.clone(), t.quoted, t.offset))
                    .collect()
            };
            assert_eq!(shape(&blanked), shape(&kept), "{name}");
        }
    }

    // ---- CHECK replacements: when the admitted set only grew. ------------

    /// A migration that creates `t.kind` with an inline enum `CHECK`, which
    /// PostgreSQL auto-names `t_kind_check`. This is the
    /// `009_scan_jobs_and_findings.sql` shape that every `jobs.kind`
    /// widening in this tree replaces by that auto-generated name.
    const CREATES_T_KIND: &str =
        "CREATE TABLE public.t (id uuid PRIMARY KEY, kind text NOT NULL CHECK (kind IN ('a', 'b')));";

    /// The `DROP CONSTRAINT` + re-`ADD` replacement shape over `body`.
    fn replaces_t_kind_check(body: &str) -> String {
        format!(
            "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
             ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK ({body});"
        )
    }

    #[test]
    fn a_replacement_whose_admitted_set_only_grew_is_not_a_narrowing() {
        // The shape 018 / 023 / 024 / 027 / 036 / 037 / 041 all have: the
        // same list plus one new literal. No writer that has ever existed
        // loses a value it could produce, so nothing is narrowed and
        // nothing is owed a manifest entry — and declaring one would fence
        // a rolling upgrade ADR 0030 exempts.
        assert!(
            ids_after(
                &[CREATES_T_KIND],
                &replaces_t_kind_check("kind IN ('a', 'b', 'c')")
            )
            .is_empty(),
            "a list that grew by one admits everything it used to"
        );
        // Equality counts as a superset: a re-ADD of the identical list,
        // order and all, also takes nothing away.
        assert!(
            ids_after(
                &[CREATES_T_KIND],
                &replaces_t_kind_check("kind IN ('b', 'a')")
            )
            .is_empty(),
            "an identical re-ADD takes nothing away either"
        );
        // And the whole check is green with NO manifest entry, which is the
        // operator-visible half: an undeclared widening is not a failure.
        let widened = replaces_t_kind_check("kind IN ('a', 'b', 'c')");
        let hits = violations(&tree(
            "0.15.0-dev",
            &[
                ("003_create.sql", CREATES_T_KIND),
                ("044_widen.sql", &widened),
            ],
            "",
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn a_replacement_that_drops_a_literal_is_still_a_narrowing() {
        assert_eq!(
            ids_after(&[CREATES_T_KIND], &replaces_t_kind_check("kind IN ('a')")),
            vec![("t.kind".to_string(), Reach::Narrowed)],
            "a list that lost 'b' refuses a value the previous release could write"
        );
    }

    #[test]
    fn a_disjoint_replacement_is_reported() {
        // `('a','b')` → `('b','c')`: neither superset nor subset. The
        // scanner does not have to decide which half matters — a set that
        // is not a superset is not a widening, and that is the whole test.
        assert_eq!(
            ids_after(
                &[CREATES_T_KIND],
                &replaces_t_kind_check("kind IN ('b', 'c')")
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_replacement_with_no_findable_previous_definition_is_reported() {
        // The `DROP` + re-`ADD` shape with nothing to compare against: no
        // earlier migration defines `t_kind_check`. Fail closed — the set
        // may well have grown, but this guard cannot see that it did.
        let creates = "CREATE TABLE public.t (id uuid PRIMARY KEY, kind text NOT NULL);";
        assert_eq!(
            ids_after(&[creates], &replaces_t_kind_check("kind IN ('a', 'b')")),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_replacement_either_side_of_which_is_not_an_in_list_is_reported() {
        // New side a predicate: there is no admitted set to compare.
        assert_eq!(
            ids_after(
                &[CREATES_T_KIND],
                &replaces_t_kind_check("char_length(kind) > 0")
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
        // Old side a predicate, new side an IN-list: same verdict, and this
        // is the direction that matters most — `>= 0` replaced by
        // `IN ('a','b')` could forbid anything.
        let predicate_before =
            "CREATE TABLE public.t (id uuid PRIMARY KEY, kind text CHECK (char_length(kind) > 0));";
        assert_eq!(
            ids_after(
                &[predicate_before],
                &replaces_t_kind_check("kind IN ('a', 'b')")
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_disjunct_bolted_onto_the_in_list_is_not_an_in_list() {
        // The escape `jobs_trigger_source_check_lockstep_guard`'s module
        // header records, one level up: a reader that takes the IN-list it
        // understood and ignores the rest reads
        // `IN (<the old list>) OR kind = 'z'` back as a widening. Both
        // directions of the bolt-on, and a `NOT IN`, must read as "not an
        // IN-list" and report.
        for body in [
            "kind IN ('a', 'b', 'c') OR kind = 'z'",
            "kind = 'z' OR kind IN ('a', 'b', 'c')",
            "kind NOT IN ('z')",
            "kind IN ('a', 'b', 'c') AND char_length(kind) > 0",
        ] {
            assert_eq!(
                ids_after(&[CREATES_T_KIND], &replaces_t_kind_check(body)),
                vec![("t.kind".to_string(), Reach::Narrowed)],
                "{body}"
            );
        }
    }

    #[test]
    fn a_replacement_must_carry_the_same_name_and_the_same_column() {
        // A different constraint NAME is not a replacement: this migration
        // drops `t_kind_check` and adds `t_kind_allowed`, so afterwards the
        // column carries a constraint whose predecessor is unknown.
        assert_eq!(
            ids_after(
                &[CREATES_T_KIND],
                "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_kind_allowed CHECK (kind IN ('a','b','c'));",
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
        // A different COLUMN under the same name is not one either: the
        // superset test would otherwise compare two unrelated sets.
        let creates = "CREATE TABLE public.t (\n\
                           kind text NOT NULL CHECK (kind IN ('a', 'b')),\n\
                           flavour text\n\
                       );";
        assert_eq!(
            ids_after(
                &[creates],
                "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK (flavour IN ('a','b','c'));",
            ),
            vec![("t.flavour".to_string(), Reach::Narrowed)]
        );
        // And an `ADD … CHECK` with no paired `DROP` at all is a brand-new
        // rule on the column — the 031 shape — with nothing to compare.
        assert_eq!(
            ids_after(
                &[CREATES_T_KIND],
                "ALTER TABLE public.t ADD CONSTRAINT t_kind_more CHECK (kind IN ('a','b','c'));",
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_re_add_in_a_later_migration_than_the_drop_is_not_a_replacement() {
        // 009 defines the list, 044 drops the constraint and leaves the
        // column unconstrained, 045 adds a superset of 009's list back.
        // That is NOT a replacement: between the two releases the column
        // accepted anything, so a writer in the gap could have produced a
        // value 045 now refuses, and the superset relation to 009 says
        // nothing about it. The pairing condition — the same migration
        // drops the name — is what keeps this reported.
        let drop_only = "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;";
        let re_add =
            "ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b','c'));";
        assert!(
            ids_after(&[CREATES_T_KIND], drop_only).is_empty(),
            "a lone constraint DROP widens and is invisible to this scanner"
        );
        assert_eq!(
            ids_after(&[CREATES_T_KIND, drop_only], re_add),
            vec![("t.kind".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn the_anonymous_forms_are_compared_under_the_name_postgresql_gives_them() {
        // A table-level unnamed `CHECK` is `<table>_check`, a column-level
        // one is `<table>_<column>_check`, and an `ALTER … ADD CHECK` is
        // `<table>_check`. The replacement comparison has to use the same
        // names PostgreSQL does, or a `DROP CONSTRAINT` would never find
        // the definition it replaces.
        let table_level = "CREATE TABLE public.t (kind text, CHECK (kind IN ('a', 'b')));";
        assert!(ids_after(
            &[table_level],
            "ALTER TABLE public.t DROP CONSTRAINT t_check;\n\
             ALTER TABLE public.t ADD CHECK (kind IN ('a', 'b', 'c'));",
        )
        .is_empty());
        // The column-level name, replaced by the named form.
        assert!(ids_after(
            &[CREATES_T_KIND],
            "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
             ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b','c'));",
        )
        .is_empty());
        // Named in the CREATE, which is `003_artifacts_cas.sql`'s shape.
        let named = "CREATE TABLE public.t (\n\
                         kind text,\n\
                         CONSTRAINT t_kind_allowed CHECK (kind IN ('a', 'b'))\n\
                     );";
        assert!(ids_after(
            &[named],
            "ALTER TABLE public.t DROP CONSTRAINT t_kind_allowed;\n\
             ALTER TABLE public.t ADD CONSTRAINT t_kind_allowed CHECK (kind IN ('a','b','c'));",
        )
        .is_empty());
    }

    #[test]
    fn the_definition_compared_against_is_the_newest_one_before_the_migration() {
        // The real tree's shape: 009 defines the list, 018 widens it, 023
        // widens 018's, 024 widens 023's. Each step compares against the
        // migration BEFORE it, not against the original — so a step that
        // re-adds the ORIGINAL list after two widenings has dropped two
        // literals and must be reported, even though it is a superset of
        // what 009 declared.
        let widen_1 = replaces_t_kind_check("kind IN ('a', 'b', 'c')");
        let widen_2 = replaces_t_kind_check("kind IN ('a', 'b', 'c', 'd')");
        assert!(
            ids_after(&[CREATES_T_KIND, &widen_1], &widen_2).is_empty(),
            "each step widens the one before it"
        );
        let back_to_009 = replaces_t_kind_check("kind IN ('a', 'b')");
        assert_eq!(
            ids_after(&[CREATES_T_KIND, &widen_1, &widen_2], &back_to_009),
            vec![("t.kind".to_string(), Reach::Narrowed)],
            "comparing against 009 instead of the newest definition would \
             call this a widening"
        );
    }

    #[test]
    fn a_name_defined_twice_in_one_migration_is_not_comparable() {
        // Which of two same-named definitions is the constraint in force
        // afterwards depends on the DROPs between them, so the comparison
        // must not pick one: the later replacement fails closed.
        let ambiguous = "ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
                         ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b','c'));\n\
                         ALTER TABLE public.t DROP CONSTRAINT t_kind_check;\n\
                         ALTER TABLE public.t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b','c','d'));";
        assert!(
            ids_after(&[CREATES_T_KIND], ambiguous).is_empty(),
            "both steps widen, read in order"
        );
        assert_eq!(
            ids_after(
                &[CREATES_T_KIND, ambiguous],
                &replaces_t_kind_check("kind IN ('a','b','c','d','e')")
            ),
            vec![("t.kind".to_string(), Reach::Narrowed)],
            "a name the previous migration defined twice is not a set this \
             guard can claim to know"
        );
    }

    #[test]
    fn the_quarantine_status_narrowing_is_enterable() {
        // The acceptance criterion for this CHECK replacement, expressed
        // against a small independent fixture: its DROP + re-ADD shape must be BOTH
        // recognised (so check (a) demands a declaration) and declarable
        // (so the entry the policy asks for turns the guard green rather
        // than red). Before the CHECK shape was recognised it was neither:
        // the migration carried no destructive DDL the scanner saw, so its
        // correct entry failed check (a) as a stale declaration.
        let creates = "CREATE TABLE public.artifacts (\n\
                           id uuid PRIMARY KEY,\n\
                           quarantine_status text CHECK (quarantine_status IN ('unscanned'))\n\
                       );";
        let narrows = "ALTER TABLE public.artifacts\n\
                           DROP CONSTRAINT artifacts_quarantine_status_check;\n\
                       ALTER TABLE public.artifacts\n\
                           ADD CONSTRAINT artifacts_quarantine_status_check CHECK (\n\
                               quarantine_status IN ('quarantined', 'released',\n\
                                                     'rejected', 'scan_indeterminate')\n\
                           );";
        assert_eq!(
            ids_after(&[creates], narrows),
            vec![("artifacts.quarantine_status".to_string(), Reach::Narrowed)],
            "the narrowing must be recognised, or no entry for it can be correct"
        );
        let hits = violations(&tree(
            "0.15.0-dev",
            &[
                ("003_artifacts_cas.sql", creates),
                ("044_artifacts_quarantine_status_narrow.sql", narrows),
            ],
            r#"
[[contraction]]
migration = "044_artifacts_quarantine_status_narrow.sql"
identifiers = ["artifacts.quarantine_status"]
reference_removed_in = "0.14.1"
note = "the deferred narrowing, landed"
"#,
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn red_when_a_check_narrowing_has_no_manifest_entry() {
        let hits = violations(&tree(
            "0.15.0-dev",
            &[
                ("003_create.sql", CREATES_T_COL),
                (
                    "044_narrow.sql",
                    "ALTER TABLE public.t ADD CONSTRAINT t_c CHECK (col >= 0) NOT VALID;",
                ),
            ],
            "",
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("no entry in migrations/"), "{hits:?}");
        assert!(hits[0].contains("t.col"), "{hits:?}");
    }

    #[test]
    fn migrations_are_read_in_apply_order_whatever_order_they_arrive_in() {
        // "Did this column exist before?" is a question about the migrations
        // IN FRONT of this one, so the answer must not depend on the order
        // the caller happened to hand them over.
        let later = (
            "044_narrow.sql",
            "ALTER TABLE public.t ADD CHECK (col >= 0);",
        );
        let earlier = ("003_create.sql", CREATES_T_COL);
        let forwards = violations(&tree("0.15.0-dev", &[earlier, later], "", &[]));
        let backwards = violations(&tree("0.15.0-dev", &[later, earlier], "", &[]));
        assert_eq!(forwards, backwards);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
    }

    #[test]
    fn the_column_universe_is_harvested_from_both_sources_and_nothing_else() {
        // `known_columns` is the filter that bounds every CHECK verdict, so
        // what goes into it is as load-bearing as the matcher itself. Too
        // little and a real narrowing reads as a reference to a non-column;
        // too much and a token that is not a column suppresses one.
        let columns = |sql: &str| created_columns(&tokenize(&strip_comments(sql)));
        let set = |items: &[&str]| -> BTreeSet<String> {
            items.iter().map(|s| (*s).to_string()).collect()
        };

        // CREATE TABLE: column definitions yes, table constraints no, and a
        // comma inside a column's own parentheses is not an item boundary.
        assert_eq!(
            columns(
                "CREATE TABLE IF NOT EXISTS public.t (\n\
                     id uuid PRIMARY KEY,\n\
                     amount numeric(12, 2) NOT NULL,\n\
                     kind text CHECK (kind IN ('a','b')),\n\
                     CONSTRAINT t_kind_key UNIQUE (kind),\n\
                     PRIMARY KEY (id),\n\
                     FOREIGN KEY (id) REFERENCES other (id),\n\
                     CHECK (amount >= 0)\n\
                 );"
            ),
            set(&["t.amount", "t.id", "t.kind"])
        );

        // ALTER TABLE: both the `COLUMN` keyword and PostgreSQL's omission
        // of it, and no column from a constraint or identity sub-action.
        assert_eq!(
            columns(
                "ALTER TABLE public.t ADD COLUMN IF NOT EXISTS a integer;\n\
                 ALTER TABLE ONLY public.t ADD b text NOT NULL DEFAULT 'x';\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_c CHECK (a >= 0);\n\
                 ALTER TABLE public.t ADD PRIMARY KEY (a);\n\
                 ALTER TABLE public.t ADD UNIQUE (b);\n\
                 ALTER TABLE public.t ADD FOREIGN KEY (a) REFERENCES other (id);\n\
                 ALTER TABLE public.t ADD CHECK (a <> 0);\n\
                 ALTER TABLE public.t ALTER COLUMN a ADD GENERATED ALWAYS AS IDENTITY;"
            ),
            set(&["t.a", "t.b"])
        );

        // Forms that create no column at all: a table-copy clause, and the
        // `AS SELECT` / `PARTITION OF` shapes whose definition is not a
        // parenthesised column list.
        assert!(columns("CREATE TABLE public.copy (LIKE public.t INCLUDING ALL);").is_empty());
        assert!(columns("CREATE TABLE public.derived AS SELECT id FROM public.t;").is_empty());
        assert!(columns("CREATE TABLE public.part PARTITION OF public.t DEFAULT;").is_empty());
    }

    #[test]
    fn a_reference_too_deep_to_be_a_column_is_ignored() {
        // A chain longer than `schema.table.column` is not something a table
        // CHECK can name; there is no sensible resolution and guessing one
        // would invent an identifier the manifest could never match.
        assert!(ids_after(
            &[CREATES_T_COL],
            "ALTER TABLE public.t ADD CONSTRAINT t_c CHECK (db.public.t.col >= 0);",
        )
        .is_empty());
    }

    // ---- Uniqueness and referential constraints. -------------------------

    /// A migration that creates `t` with two pre-existing, nullable
    /// columns plus a `NOT NULL` one — the state every case below reads a
    /// later migration's constraint against.
    const CREATES_T_KEYS: &str = "CREATE TABLE public.t (\n\
                                      id uuid PRIMARY KEY,\n\
                                      a integer,\n\
                                      b integer,\n\
                                      c integer NOT NULL\n\
                                  );";

    #[test]
    fn every_uniqueness_constraint_spelling_on_a_pre_existing_column_is_a_narrowing() {
        // One class, eight spellings, one verdict. A duplicate and a
        // dangling reference are values the still-running previous release
        // can produce and PostgreSQL refuses from the instant the hook
        // commits — the same reach a `CHECK` has, reached a different way.
        for (statement, shape) in [
            (
                "ALTER TABLE public.t ADD CONSTRAINT t_a_key UNIQUE (a);",
                "ALTER TABLE ... ADD CONSTRAINT ... UNIQUE",
            ),
            (
                "ALTER TABLE public.t ADD UNIQUE (a);",
                "ALTER TABLE ... ADD UNIQUE",
            ),
            (
                "ALTER TABLE public.t ADD CONSTRAINT t_a_pk PRIMARY KEY (a);",
                "ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY",
            ),
            (
                "ALTER TABLE public.t ADD PRIMARY KEY (a);",
                "ALTER TABLE ... ADD PRIMARY KEY",
            ),
            (
                "ALTER TABLE public.t ADD CONSTRAINT t_a_fk FOREIGN KEY (a) \
                 REFERENCES public.other (id);",
                "ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY",
            ),
            (
                "ALTER TABLE public.t ADD FOREIGN KEY (a) REFERENCES public.other (id);",
                "ALTER TABLE ... ADD FOREIGN KEY",
            ),
            (
                "ALTER TABLE public.t ADD CONSTRAINT t_a_excl EXCLUDE USING gist (a WITH =);",
                "ALTER TABLE ... ADD CONSTRAINT ... EXCLUDE",
            ),
            (
                "ALTER TABLE public.t ADD EXCLUDE (a WITH =);",
                "ALTER TABLE ... ADD EXCLUDE",
            ),
            (
                "CREATE UNIQUE INDEX t_a_uq ON public.t (a);",
                "CREATE UNIQUE INDEX",
            ),
            (
                "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS t_a_uq \
                 ON public.t USING btree (a);",
                "CREATE UNIQUE INDEX",
            ),
        ] {
            let scanned = scan(&[CREATES_T_KEYS], statement);
            assert_eq!(
                scanned.contractions.len(),
                1,
                "{statement}: {:?}",
                scanned.contractions
            );
            let found = &scanned.contractions[0];
            assert_eq!(found.identifier, "t.a", "{statement}");
            assert_eq!(found.reach, Reach::Narrowed, "{statement}");
            assert_eq!(found.shape, shape, "{statement}");
            // The failure message is what an author acts on.
            let message = describe(&scanned.contractions);
            assert!(message.contains("t.a"), "{statement}: {message}");
            assert!(message.contains(shape), "{statement}: {message}");
        }
    }

    #[test]
    fn a_key_on_a_column_created_in_the_same_migration_is_not_a_narrowing() {
        // The same mechanism the `CHECK` case uses, and deliberately not a
        // second statement of it: a column no previous release could write
        // to cannot lose a value a previous release wrote.
        //
        // (a) the column arrives by `ADD COLUMN` in this very migration.
        assert!(ids_after(
            &[CREATES_T_KEYS],
            "ALTER TABLE public.t ADD COLUMN fresh integer;\n\
             ALTER TABLE public.t ADD CONSTRAINT t_fresh_key UNIQUE (fresh);\n\
             CREATE UNIQUE INDEX t_fresh_uq ON public.t (fresh);",
        )
        .is_empty());
        // (b) the whole table arrives in this migration, inline and bolted
        // on afterwards.
        assert!(ids("CREATE TABLE public.u (id uuid PRIMARY KEY, x integer UNIQUE);").is_empty());
        assert!(ids("CREATE TABLE public.u (id uuid, x integer);\n\
             ALTER TABLE public.u ADD CONSTRAINT u_pkey PRIMARY KEY (id);\n\
             ALTER TABLE public.u ADD CONSTRAINT u_x_fk FOREIGN KEY (x) \
                 REFERENCES public.other (id);\n\
             CREATE UNIQUE INDEX u_x_uq ON public.u (x);")
        .is_empty());
    }

    #[test]
    fn a_non_unique_index_constrains_nothing_and_is_not_reported() {
        // An index without `UNIQUE` forbids no write at all, however many
        // pre-existing columns it covers, and whatever shape it takes.
        for statement in [
            "CREATE INDEX t_a_idx ON public.t (a);",
            "CREATE INDEX t_a_idx ON public.t USING btree (a, b) WHERE (c > 0);",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS t_a_idx ON public.t (a) INCLUDE (b);",
            "CREATE INDEX ON public.t (a);",
        ] {
            assert!(
                ids_after(&[CREATES_T_KEYS], statement).is_empty(),
                "{statement}"
            );
        }
        // The same index with `UNIQUE` is the narrowing — so the verdict
        // turns on the keyword and not on anything else about the shape.
        assert_eq!(
            ids_after(
                &[CREATES_T_KEYS],
                "CREATE UNIQUE INDEX t_a_idx ON public.t (a);"
            ),
            vec![("t.a".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_foreign_keys_narrowed_column_is_the_referencing_one() {
        // The referencing column's admissible values shrink to whatever the
        // referenced column currently holds; the referenced column loses
        // nothing and must not be reported — an entry naming it would send
        // an operator looking at the wrong table.
        let creates = "CREATE TABLE public.parent (id uuid PRIMARY KEY);\n\
                       CREATE TABLE public.child (id uuid PRIMARY KEY, parent_id uuid);";
        assert_eq!(
            ids_after(
                &[creates],
                "ALTER TABLE ONLY public.child ADD CONSTRAINT child_parent_fk\n\
                     FOREIGN KEY (parent_id) REFERENCES public.parent (id) ON DELETE CASCADE;",
            ),
            vec![("child.parent_id".to_string(), Reach::Narrowed)],
            "the REFERENCES list is not a narrowing and must stay out of the report"
        );
        // A composite foreign key reports each referencing column.
        let composite = "CREATE TABLE public.parent (a uuid, b uuid);\n\
                         CREATE TABLE public.child (x uuid, y uuid);";
        assert_eq!(
            ids_after(
                &[composite],
                "ALTER TABLE public.child ADD CONSTRAINT child_fk\n\
                     FOREIGN KEY (x, y) REFERENCES public.parent (a, b);",
            ),
            vec![
                ("child.x".to_string(), Reach::Narrowed),
                ("child.y".to_string(), Reach::Narrowed),
            ]
        );
    }

    #[test]
    fn a_partial_unique_index_that_replaces_nothing_is_reported() {
        // `017_scan_policy_scope_unique.sql`'s shape, as an independent
        // fixture: a partial unique index over an expression on a
        // pre-existing column, with no predecessor constraint anywhere.
        // Partial is not a widening on its own — there has to be something
        // it is wider THAN.
        let creates = "CREATE TABLE public.policy_projections (\n\
                           policy_id uuid PRIMARY KEY,\n\
                           scope jsonb NOT NULL,\n\
                           archived boolean DEFAULT false NOT NULL\n\
                       );";
        let narrows = "CREATE UNIQUE INDEX idx_policy_projections_active_scope\n\
                           ON public.policy_projections USING btree (\n\
                               (COALESCE(scope->>'Repository', 'Global'))\n\
                           )\n\
                           WHERE (archived = false);";
        assert_eq!(
            ids_after(&[creates], narrows),
            vec![("policy_projections.scope".to_string(), Reach::Narrowed)],
            "the narrowing must be recognised, or no entry for it can be correct"
        );
        // And it is declarable: the entry the policy asks for turns the
        // guard green rather than red, which is the other half of the
        // acceptance criterion.
        let hits = violations(&tree(
            "0.18.0-dev",
            &[
                ("005_policy.sql", creates),
                ("017_scan_policy_scope_unique.sql", narrows),
            ],
            r#"
[[contraction]]
migration = "017_scan_policy_scope_unique.sql"
identifiers = ["policy_projections.scope"]
reference_removed_in = "0.10.0"
note = "the historical narrowing, declared"
"#,
            &[],
        ));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn a_wider_primary_key_replacing_a_narrower_one_only_widens() {
        // `013_content_references_multivalue_pk.sql`'s shape. Two rows that
        // agree on the four-column key agree on the three-column one, so
        // the old key already forbade them: the wider key admits strictly
        // more rows. Every column of the new key was already `NOT NULL`, so
        // no implicit `NOT NULL` rides along either.
        let creates = "CREATE TABLE public.cr (\n\
                           repository_id uuid NOT NULL,\n\
                           source_artifact_id uuid NOT NULL,\n\
                           target_content_hash text NOT NULL,\n\
                           kind text NOT NULL\n\
                       );\n\
                       ALTER TABLE ONLY public.cr ADD CONSTRAINT cr_pkey\n\
                           PRIMARY KEY (repository_id, source_artifact_id, kind);";
        let widens = "ALTER TABLE ONLY public.cr DROP CONSTRAINT cr_pkey;\n\
                      ALTER TABLE ONLY public.cr ADD CONSTRAINT cr_pkey\n\
                          PRIMARY KEY (repository_id, source_artifact_id,\n\
                                       target_content_hash, kind);";
        assert!(
            ids_after(&[creates], widens).is_empty(),
            "a key over more columns admits strictly more rows"
        );
        // Restating the identical key takes nothing away either.
        assert!(ids_after(
            &[creates],
            "ALTER TABLE public.cr DROP CONSTRAINT cr_pkey;\n\
             ALTER TABLE public.cr ADD CONSTRAINT cr_pkey\n\
                 PRIMARY KEY (repository_id, source_artifact_id, kind);",
        )
        .is_empty());
        // The other direction is a narrowing: a key over FEWER columns
        // forbids pairs the old one admitted.
        assert_eq!(
            ids_after(
                &[creates],
                "ALTER TABLE public.cr DROP CONSTRAINT cr_pkey;\n\
                 ALTER TABLE public.cr ADD CONSTRAINT cr_pkey\n\
                     PRIMARY KEY (repository_id, source_artifact_id);",
            ),
            vec![
                ("cr.repository_id".to_string(), Reach::Narrowed),
                ("cr.source_artifact_id".to_string(), Reach::Narrowed),
            ]
        );
    }

    #[test]
    fn a_primary_key_widening_onto_a_nullable_column_is_still_a_narrowing() {
        // A `PRIMARY KEY` imposes `NOT NULL` as well as uniqueness, so a
        // wider key whose new column is nullable smuggles in the
        // `SET NOT NULL` this guard has recognised all along. The
        // row-admission argument says nothing about it, so the exemption
        // must not reach it.
        let creates = "CREATE TABLE public.t (a uuid NOT NULL, b uuid);\n\
                       ALTER TABLE public.t ADD CONSTRAINT t_pkey PRIMARY KEY (a);";
        let widens = "ALTER TABLE public.t DROP CONSTRAINT t_pkey;\n\
                      ALTER TABLE public.t ADD CONSTRAINT t_pkey PRIMARY KEY (a, b);";
        assert_eq!(
            ids_after(&[creates], widens),
            vec![
                ("t.a".to_string(), Reach::Narrowed),
                ("t.b".to_string(), Reach::Narrowed),
            ],
            "a nullable column joining a primary key loses NULL as a value"
        );
        // The same widening over a `NOT NULL` column is exempt — so the
        // verdict turns on the nullability and on nothing else.
        let not_null = "CREATE TABLE public.t (a uuid NOT NULL, b uuid NOT NULL);\n\
                        ALTER TABLE public.t ADD CONSTRAINT t_pkey PRIMARY KEY (a);";
        assert!(ids_after(&[not_null], widens).is_empty());
        // A `UNIQUE` key imposes no `NOT NULL`, so the same widening over
        // the same nullable column is exempt in that spelling.
        let unique_before = "CREATE TABLE public.t (a uuid, b uuid);\n\
                             ALTER TABLE public.t ADD CONSTRAINT t_a_key UNIQUE (a);";
        assert!(ids_after(
            &[unique_before],
            "ALTER TABLE public.t DROP CONSTRAINT t_a_key;\n\
             ALTER TABLE public.t ADD CONSTRAINT t_a_key UNIQUE (a, b);",
        )
        .is_empty());
    }

    #[test]
    fn a_nullability_that_was_dropped_does_not_exempt_a_primary_key_widening() {
        // The nullability set is maintained in BOTH directions, which is
        // the difference between a proof and an assumption: a column that
        // was `NOT NULL` and has since been made nullable is one a
        // `PRIMARY KEY` would re-constrain.
        let creates = "CREATE TABLE public.t (a uuid NOT NULL, b uuid NOT NULL);\n\
                       ALTER TABLE public.t ADD CONSTRAINT t_pkey PRIMARY KEY (a);";
        let relaxes = "ALTER TABLE public.t ALTER COLUMN b DROP NOT NULL;";
        let widens = "ALTER TABLE public.t DROP CONSTRAINT t_pkey;\n\
                      ALTER TABLE public.t ADD CONSTRAINT t_pkey PRIMARY KEY (a, b);";
        assert!(
            ids_after(&[creates], widens).is_empty(),
            "without the relaxation the widening is exempt"
        );
        assert_eq!(
            ids_after(&[creates, relaxes], widens),
            vec![
                ("t.a".to_string(), Reach::Narrowed),
                ("t.b".to_string(), Reach::Narrowed),
            ],
            "a column made nullable again cannot carry a primary key's implicit NOT NULL"
        );
        // And a `SET NOT NULL` puts it back — the set tracks the statements
        // rather than remembering only the declaration.
        let restores = "ALTER TABLE public.t ALTER COLUMN b SET NOT NULL;";
        assert!(ids_after(&[creates, relaxes, restores], widens).is_empty());
    }

    #[test]
    fn a_full_unique_constraint_replaced_by_a_partial_index_only_widens() {
        // `021_artifacts_soft_delete.sql`'s shape, and the claim the old
        // green test did not make: the same key over a SUBSET of the rows
        // admits strictly more rows, because every pair the partial index
        // leaves alone was already forbidden by the full constraint.
        // Duplicates among soft-deleted rows become admissible — nothing
        // becomes inadmissible.
        let creates = "CREATE TABLE public.artifacts (\n\
                           id uuid PRIMARY KEY,\n\
                           repository_id uuid NOT NULL,\n\
                           path text NOT NULL\n\
                       );\n\
                       ALTER TABLE ONLY public.artifacts\n\
                           ADD CONSTRAINT artifacts_repository_id_path_key\n\
                           UNIQUE (repository_id, path);";
        let widens = "ALTER TABLE public.artifacts ADD COLUMN deleted_at timestamptz;\n\
                      ALTER TABLE public.artifacts\n\
                          DROP CONSTRAINT artifacts_repository_id_path_key;\n\
                      CREATE UNIQUE INDEX artifacts_repository_id_path_live_key\n\
                          ON public.artifacts USING btree (repository_id, path)\n\
                          WHERE (deleted_at IS NULL);";
        assert!(
            ids_after(&[creates], widens).is_empty(),
            "a full uniqueness constraint becoming partial takes nothing away"
        );
        // The pairing is what earns it. Without the `DROP CONSTRAINT` the
        // index replaces nothing and is reported — which is also what
        // happens when the replacement lands one migration LATER than the
        // drop, because in between the column pair accepted anything.
        let index_only = "ALTER TABLE public.artifacts ADD COLUMN deleted_at timestamptz;\n\
                          CREATE UNIQUE INDEX artifacts_repository_id_path_live_key\n\
                              ON public.artifacts USING btree (repository_id, path)\n\
                              WHERE (deleted_at IS NULL);";
        assert_eq!(
            ids_after(&[creates], index_only),
            vec![
                ("artifacts.path".to_string(), Reach::Narrowed),
                ("artifacts.repository_id".to_string(), Reach::Narrowed),
            ]
        );
        let drop_only = "ALTER TABLE public.artifacts\n\
                             DROP CONSTRAINT artifacts_repository_id_path_key;";
        assert!(
            ids_after(&[creates], drop_only).is_empty(),
            "a lone constraint DROP widens and is invisible to this scanner"
        );
        assert_eq!(
            ids_after(&[creates, drop_only], index_only).len(),
            2,
            "a replacement one migration after the drop is not a replacement"
        );
    }

    #[test]
    fn a_dropped_index_is_as_good_a_predecessor_as_a_dropped_constraint() {
        // Uniqueness is spelled both ways in this tree — `003` declares
        // path uniqueness as a table CONSTRAINT and `021` replaces it with
        // an INDEX — so a scan that only read one spelling would find no
        // predecessor for the commonest real widening here. The symmetric
        // case has to work too.
        let creates = "CREATE TABLE public.t (a uuid NOT NULL, b uuid NOT NULL);\n\
                       CREATE UNIQUE INDEX t_a_uq ON public.t (a);";
        assert!(ids_after(
            &[creates],
            "DROP INDEX public.t_a_uq;\n\
             CREATE UNIQUE INDEX t_a_b_uq ON public.t (a, b);",
        )
        .is_empty());
        // A partial predecessor is NOT comparable: deciding one row-subset
        // contains another is predicate implication.
        let partial_before = "CREATE TABLE public.t (a uuid NOT NULL, b uuid);\n\
                              CREATE UNIQUE INDEX t_a_uq ON public.t (a) WHERE (b IS NULL);";
        assert_eq!(
            ids_after(
                &[partial_before],
                "DROP INDEX public.t_a_uq;\n\
                 CREATE UNIQUE INDEX t_a_uq ON public.t (a) WHERE (b IS NOT NULL);",
            ),
            vec![("t.a".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_key_dropped_in_an_earlier_migration_is_not_a_predecessor() {
        // The uniqueness counterpart of
        // [`a_re_add_in_a_later_migration_than_the_drop_is_not_a_replacement`],
        // and the reason the key side tombstones a dropped name where the
        // `CHECK` side can leave one standing: `DROP CONSTRAINT` against a
        // constraint the database does not have fails the migration, but
        // `DROP INDEX IF EXISTS` succeeds against nothing. Without the
        // tombstone a vacuous re-drop would resurrect a key that had not
        // been in force since an earlier release — and in that gap the
        // columns accepted anything, so a writer could have produced a row
        // the replacement now refuses.
        let creates = "CREATE TABLE public.t (a uuid NOT NULL, b uuid NOT NULL);\n\
                       CREATE UNIQUE INDEX t_a_uq ON public.t (a);";
        let drop_only = "DROP INDEX public.t_a_uq;";
        let wider = "DROP INDEX IF EXISTS public.t_a_uq;\n\
                     CREATE UNIQUE INDEX t_a_b_uq ON public.t (a, b);";
        assert!(
            ids_after(&[creates], wider).is_empty(),
            "with the key still in force the wider one is exempt"
        );
        assert_eq!(
            ids_after(&[creates, drop_only], wider),
            vec![
                ("t.a".to_string(), Reach::Narrowed),
                ("t.b".to_string(), Reach::Narrowed),
            ],
            "a key dropped one migration earlier was not in force in between"
        );
    }

    #[test]
    fn a_key_the_scan_cannot_read_as_a_column_list_is_not_comparable() {
        // An expression key has no column set to contain or be contained
        // by, in either position, so neither side of the comparison can be
        // made and both fail closed.
        let expression_before = "CREATE TABLE public.t (a text NOT NULL, b text NOT NULL);\n\
             CREATE UNIQUE INDEX t_expr_uq ON public.t (lower(a));";
        // Old side an expression, new side a plain list.
        assert_eq!(
            ids_after(
                &[expression_before],
                "DROP INDEX public.t_expr_uq;\n\
                 CREATE UNIQUE INDEX t_a_uq ON public.t (a, b);",
            ),
            vec![
                ("t.a".to_string(), Reach::Narrowed),
                ("t.b".to_string(), Reach::Narrowed),
            ]
        );
        // New side an expression, old side a plain list.
        let plain_before = "CREATE TABLE public.t (a text NOT NULL, b text NOT NULL);\n\
                            CREATE UNIQUE INDEX t_a_uq ON public.t (a);";
        assert_eq!(
            ids_after(
                &[plain_before],
                "DROP INDEX public.t_a_uq;\n\
                 CREATE UNIQUE INDEX t_expr_uq ON public.t (lower(a));",
            ),
            vec![("t.a".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn a_predecessor_on_another_table_is_not_a_predecessor() {
        // The comparison would otherwise pair two unrelated keys that
        // happen to be dropped and added in one migration.
        let creates = "CREATE TABLE public.t (a uuid NOT NULL);\n\
                       CREATE TABLE public.u (a uuid NOT NULL, b uuid NOT NULL);\n\
                       ALTER TABLE public.t ADD CONSTRAINT t_a_key UNIQUE (a);";
        assert_eq!(
            ids_after(
                &[creates],
                "ALTER TABLE public.t DROP CONSTRAINT t_a_key;\n\
                 ALTER TABLE public.u ADD CONSTRAINT u_key UNIQUE (a, b);",
            ),
            vec![
                ("u.a".to_string(), Reach::Narrowed),
                ("u.b".to_string(), Reach::Narrowed),
            ]
        );
        // And a disjoint key on the same table is not a widening either.
        assert_eq!(
            ids_after(
                &[creates],
                "ALTER TABLE public.t DROP CONSTRAINT t_a_key;\n\
                 CREATE TABLE public.v (id uuid PRIMARY KEY);\n\
                 ALTER TABLE public.t ADD CONSTRAINT t_other_key UNIQUE (missing);",
            )
            .len(),
            0,
            "`missing` is not a column this migration set creates, so it is not reported — \
             the column universe bounds this extraction exactly as it bounds a CHECK's"
        );
    }

    #[test]
    fn the_reported_columns_come_from_the_key_and_not_from_the_payload() {
        // An `INCLUDE` payload is stored in the leaf and constrained by
        // nothing; a partial `WHERE` selects WHICH rows the uniqueness
        // covers rather than forbidding a value in its own columns.
        // Reporting either would send an author to declare a column whose
        // write contract did not change.
        assert_eq!(
            ids_after(
                &[CREATES_T_KEYS],
                "CREATE UNIQUE INDEX t_uq ON public.t USING btree (a)\n\
                     INCLUDE (b)\n\
                     WHERE (c > 0);",
            ),
            vec![("t.a".to_string(), Reach::Narrowed)]
        );
    }

    #[test]
    fn not_valid_and_concurrently_do_not_change_a_key_verdict() {
        // The ecosystem's advice on these statements is predominantly about
        // LOCK duration, and its remedies are `ADD … NOT VALID` plus a
        // later `VALIDATE` and `CREATE UNIQUE INDEX CONCURRENTLY`. Both
        // shorten the outage DURING the migration and discharge none of
        // this obligation: they exempt existing rows, never a future INSERT
        // from a binary that is still running. If either read as an escape,
        // a future finding would get "fixed" with it and believed.
        let plain = ids_after(
            &[CREATES_T_KEYS],
            "ALTER TABLE public.t ADD CONSTRAINT t_a_fk FOREIGN KEY (a) \
             REFERENCES public.other (id);",
        );
        let not_valid = ids_after(
            &[CREATES_T_KEYS],
            "ALTER TABLE public.t ADD CONSTRAINT t_a_fk FOREIGN KEY (a) \
             REFERENCES public.other (id) NOT VALID;",
        );
        assert_eq!(plain, not_valid);
        assert_eq!(plain, vec![("t.a".to_string(), Reach::Narrowed)]);

        let index = ids_after(
            &[CREATES_T_KEYS],
            "CREATE UNIQUE INDEX t_uq ON public.t (a);",
        );
        let concurrently = ids_after(
            &[CREATES_T_KEYS],
            "CREATE UNIQUE INDEX CONCURRENTLY t_uq ON public.t (a);",
        );
        assert_eq!(index, concurrently);
        assert_eq!(index, vec![("t.a".to_string(), Reach::Narrowed)]);
    }

    #[test]
    fn red_when_a_key_narrowing_has_no_manifest_entry() {
        let hits = violations(&tree(
            "0.18.0-dev",
            &[
                ("003_create.sql", CREATES_T_KEYS),
                (
                    "045_narrow.sql",
                    "CREATE UNIQUE INDEX t_a_uq ON public.t (a);",
                ),
            ],
            "",
            &[],
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("no entry in migrations/"), "{hits:?}");
        assert!(hits[0].contains("t.a"), "{hits:?}");
        assert!(hits[0].contains("CREATE UNIQUE INDEX"), "{hits:?}");
    }

    // ---- Mutation probes against the real on-disk tree. ------------------

    /// The real manifest text with one entry excised, for the probes that
    /// must watch the real scan go red.
    ///
    /// The cut runs from the entry's own `[[contraction]]` header to the
    /// close of its `note` block, so it does not depend on another entry
    /// following it — an earlier version split on the next
    /// `[[contraction]]` and, once the entry under test became the last
    /// one, cut into the prose that *names* that header and produced a
    /// manifest that would not parse. A probe whose failure mode is
    /// "unparseable input" proves nothing about the scanner.
    fn without_entry(manifest: &str, migration: &str) -> String {
        let at = manifest
            .find(&format!("migration = \"{migration}\""))
            .unwrap_or_else(|| panic!("{migration} has no entry in the real manifest"));
        let header = "[[contraction]]\n";
        let start = manifest[..at]
            .rfind(header)
            .unwrap_or_else(|| panic!("{migration}'s entry has no [[contraction]] header"));
        let note = manifest[at..]
            .find("note = \"\"\"\n")
            .map(|found| at + found + "note = \"\"\"\n".len())
            .unwrap_or_else(|| panic!("{migration}'s entry has no note block"));
        let end = manifest[note..]
            .find("\"\"\"\n")
            .map(|found| note + found + "\"\"\"\n".len())
            .unwrap_or_else(|| panic!("{migration}'s note block is unterminated"));
        format!("{}{}", &manifest[..start], &manifest[end..])
    }

    #[test]
    fn real_tree_scan_still_finds_the_known_destructive_shapes() {
        // A counter-assertion: the green verdict above is only worth
        // something if the scanner still recognises the shapes the tree is
        // known to carry. A renamed matcher, a changed `Reach`, or a
        // path error would otherwise make the whole guard vacuously green.
        let inputs = real_tree_inputs();
        let by_migration = scan_in_apply_order(&inputs.migrations);
        let found = |migration: &str, identifier: &str, reach: Reach, shape: &str| {
            let hits = by_migration
                .get(migration)
                .unwrap_or_else(|| panic!("{migration} is not in the scanned tree"));
            assert!(
                hits.iter().any(|c| c.identifier == identifier
                    && c.reach == reach
                    && c.shape.contains(shape)),
                "{migration} no longer reports {identifier} as {reach:?} via {shape}: {hits:?}"
            );
        };
        found(
            "009_scan_jobs_and_findings.sql",
            "scan_configs",
            Reach::Removed,
            "DROP TABLE",
        );
        found(
            "020_drop_artifacts_is_deleted.sql",
            "artifacts.is_deleted",
            Reach::Removed,
            "DROP COLUMN",
        );
        found(
            "039_policy_projections_quarantine_duration_nonnegative.sql",
            "policy_projections.quarantine_duration_secs",
            Reach::Narrowed,
            "ADD CONSTRAINT ... CHECK",
        );
        found(
            "044_artifacts_quarantine_status_storable_set.sql",
            "artifacts.quarantine_status",
            Reach::Narrowed,
            "ADD CONSTRAINT ... CHECK",
        );
        found(
            "002_repositories.sql",
            "permission_grants.repository_id",
            Reach::Narrowed,
            "ADD CONSTRAINT ... FOREIGN KEY",
        );
        found(
            "017_scan_policy_scope_unique.sql",
            "policy_projections.scope",
            Reach::Narrowed,
            "CREATE UNIQUE INDEX",
        );
        // And the column universe itself: a replacement CHECK's column
        // must remain visible as a pre-existing column.
        let mut known: BTreeSet<String> = BTreeSet::new();
        for (_, sql) in &inputs.migrations {
            known.extend(created_columns(&tokenize(&strip_comments(sql))));
        }
        assert!(
            known.contains("artifacts.quarantine_status"),
            "the column universe lost a column the tree demonstrably creates"
        );
    }

    #[test]
    fn the_real_trees_check_narrowings_are_exactly_the_three_declared_ones() {
        // The census, pinned. Ten statements in this tree carry the
        // `ADD … CHECK` shape; seven of them replace an enum `CHECK` with
        // the same list plus one new literal and are therefore not
        // narrowings at all. If the widening comparison ever stopped
        // reaching one of those seven, the manifest would start demanding
        // an entry that fences a routine rolling upgrade; if it ever
        // started reaching 031, 039 or 044, a real narrowing would go
        // undeclared. Both directions are failures, so both are asserted.
        let inputs = real_tree_inputs();
        let by_migration = scan_in_apply_order(&inputs.migrations);
        let census: Vec<(String, String)> = by_migration
            .iter()
            .flat_map(|(migration, found)| {
                found
                    .iter()
                    .filter(|c| c.shape.contains("CHECK"))
                    .map(move |c| ((*migration).to_string(), c.identifier.clone()))
            })
            .collect();
        assert_eq!(
            census,
            vec![
                (
                    "031_upstream_mappings_allowed_realm_hosts.sql".to_string(),
                    "repository_upstream_mappings.upstream_auth_type".to_string(),
                ),
                (
                    "039_policy_projections_quarantine_duration_nonnegative.sql".to_string(),
                    "policy_projections.quarantine_duration_secs".to_string(),
                ),
                (
                    "044_artifacts_quarantine_status_storable_set.sql".to_string(),
                    "artifacts.quarantine_status".to_string(),
                ),
            ],
            "the real tree's CHECK narrowings changed"
        );
        // The seven widening replacements, named: each drops a
        // `jobs_{kind,trigger_source}_check` and re-adds it over the same
        // list plus one new literal, and so contracts nothing whatsoever.
        for migration in [
            "018_jobs_kind_oci_edge_backfill.sql",
            "023_jobs_kind_scan_row_retention_sweep.sql",
            "024_jobs_kind_oci_index_child_ingest.sql",
            "027_jobs_kind_jobs_row_retention_sweep.sql",
            "036_jobs_trigger_source_register_by_hash.sql",
            "037_jobs_trigger_source_clearance.sql",
            "041_jobs_kind_api_token_retention_sweep.sql",
        ] {
            let found = by_migration
                .get(migration)
                .unwrap_or_else(|| panic!("{migration} is not in the scanned tree"));
            assert!(
                found.is_empty(),
                "{migration} only widens an admitted set and must not be \
                 reported: {found:?}"
            );
        }
    }

    #[test]
    fn real_tree_goes_red_when_a_check_narrowings_entry_is_removed() {
        // The other half of the green run: strip the declaration for the
        // CHECK narrowing the real tree carries out of the real manifest
        // text, and the real scan must report it. This is what proves the
        // green verdict is the entry's doing rather than the scanner's
        // silence.
        for (migration, identifier) in [
            (
                "039_policy_projections_quarantine_duration_nonnegative.sql",
                "policy_projections.quarantine_duration_secs",
            ),
            (
                "044_artifacts_quarantine_status_storable_set.sql",
                "artifacts.quarantine_status",
            ),
        ] {
            let mut inputs = real_tree_inputs();
            inputs.manifest_toml = without_entry(&inputs.manifest_toml, migration);
            let hits = violations(&inputs);
            // Exactly one, so a splice that excised a neighbouring entry too
            // cannot pass this off as the probe working.
            assert_eq!(hits.len(), 1, "{hits:?}");
            assert!(
                hits[0].starts_with(migration)
                    && hits[0].contains(identifier)
                    && hits[0].contains("no entry in migrations/"),
                "stripping the entry must make the real scan report the narrowing: {hits:?}"
            );
        }
    }

    #[test]
    fn real_tree_goes_red_on_an_undeclared_check_narrowing() {
        // The same probe from the other direction: a new migration that adds
        // a CHECK to a column the real tree created long ago, with no
        // manifest entry, against the real corpus.
        let mut inputs = real_tree_inputs();
        inputs.migrations.push((
            "999_undeclared_check.sql".to_string(),
            "ALTER TABLE public.artifacts\n\
                 ADD CONSTRAINT artifacts_path_nonempty CHECK (char_length(path) > 0);"
                .to_string(),
        ));
        let hits = violations(&inputs);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].starts_with("999_undeclared_check.sql"), "{hits:?}");
        assert!(hits[0].contains("artifacts.path"), "{hits:?}");
    }

    /// Replace `from` with `to` throughout one named migration of `inputs`.
    ///
    /// Asserts the text was there and that the replacement changed
    /// something: a mutation probe that mutates nothing proves nothing, and
    /// is the way a renamed identifier turns one of these into a test that
    /// passes by accident.
    fn mutate_migration(inputs: &mut Inputs, migration: &str, from: &str, to: &str) {
        let slot = inputs
            .migrations
            .iter_mut()
            .find(|(name, _)| name == migration)
            .unwrap_or_else(|| panic!("{migration} is not in the real tree"));
        let mutated = slot.1.replace(from, to);
        assert_ne!(
            mutated, slot.1,
            "{migration} no longer contains {from:?} — this probe mutates nothing"
        );
        slot.1 = mutated;
    }

    #[test]
    fn the_real_trees_key_narrowings_are_exactly_the_two_declared_ones() {
        // The census for the non-`CHECK` constraint class, pinned in both
        // directions like its `CHECK` sibling. Four migrations in this tree
        // add a uniqueness or referential constraint to a column that
        // existed before them. Two are narrowings and are declared; two are
        // widenings and must never be, because the runtime fence keys on
        // whether a pending migration is declared and declaring a widening
        // would fence a routine rolling upgrade ADR 0030 exempts.
        let inputs = real_tree_inputs();
        let by_migration = scan_in_apply_order(&inputs.migrations);
        let census: Vec<(String, String, &'static str)> = by_migration
            .iter()
            .flat_map(|(migration, found)| {
                found
                    .iter()
                    .filter(|c| !c.shape.contains("CHECK") && c.reach == Reach::Narrowed)
                    .filter(|c| {
                        c.shape.contains("UNIQUE")
                            || c.shape.contains("KEY")
                            || c.shape.contains("EXCLUDE")
                    })
                    .map(move |c| ((*migration).to_string(), c.identifier.clone(), c.shape))
            })
            .collect();
        assert_eq!(
            census,
            vec![
                (
                    "002_repositories.sql".to_string(),
                    "permission_grants.repository_id".to_string(),
                    "ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY",
                ),
                (
                    "017_scan_policy_scope_unique.sql".to_string(),
                    "policy_projections.scope".to_string(),
                    "CREATE UNIQUE INDEX",
                ),
            ],
            "the real tree's uniqueness / referential narrowings changed"
        );
        // The two widenings, named: 013 widens a primary key from three
        // columns to four, 021 replaces a full unique constraint with a
        // partial index on the same columns. Neither takes anything away.
        for migration in [
            "013_content_references_multivalue_pk.sql",
            "021_artifacts_soft_delete.sql",
        ] {
            let found = by_migration
                .get(migration)
                .unwrap_or_else(|| panic!("{migration} is not in the scanned tree"));
            assert!(
                found.is_empty(),
                "{migration} only widens a uniqueness key and must not be reported: {found:?}"
            );
        }
    }

    #[test]
    fn the_real_trees_nullability_harvest_reads_the_tree_it_scans() {
        // The nullability set is the evidence 013's exemption rests on, and
        // an over-broad one would exempt a real narrowing — so the
        // non-membership half is the load-bearing assertion here, not the
        // membership half. An empty or absent set only makes the guard
        // report 013, which is the safe direction.
        let inputs = real_tree_inputs();
        let mut in_order: Vec<(&str, &String)> = inputs
            .migrations
            .iter()
            .map(|(name, sql)| (name.as_str(), sql))
            .collect();
        in_order.sort_by_key(|(name, _)| *name);
        let mut columns = BTreeSet::new();
        let mut not_null = BTreeSet::new();
        let mut checks = CheckDefs::new();
        let mut keys = KeyDefs::new();
        for (_, sql) in in_order {
            let scan = scan_migration(
                sql,
                &SchemaBefore {
                    columns: &columns,
                    not_null: &not_null,
                    checks: &checks,
                    keys: &keys,
                },
            );
            columns.extend(scan.created_columns);
            not_null = scan.not_null;
            checks.extend(scan.checks);
            keys.extend(scan.keys);
        }
        for declared in [
            "content_references.target_content_hash",
            "content_references.kind",
            "artifacts.repository_id",
            "artifacts.path",
        ] {
            assert!(
                not_null.contains(declared),
                "the harvest lost {declared}, which the tree declares NOT NULL"
            );
        }
        for nullable in [
            "artifacts.deleted_at",
            "policy_projections.last_evaluated_at",
        ] {
            assert!(
                !not_null.contains(nullable),
                "the harvest claims {nullable} is NOT NULL, which the tree never says — an \
                 over-broad nullability set exempts a primary-key widening that really does \
                 impose NOT NULL"
            );
        }
    }

    #[test]
    fn real_tree_goes_red_when_a_key_narrowings_entry_is_removed() {
        // The same probe the `CHECK` narrowings carry, for the two
        // uniqueness / referential entries: strip the declaration out of
        // the real manifest text and the real scan must report it. This is
        // what proves each entry is load-bearing rather than decorative —
        // the green run above would look identical if the scanner had
        // simply gone quiet.
        for (migration, identifier) in [
            ("002_repositories.sql", "permission_grants.repository_id"),
            (
                "017_scan_policy_scope_unique.sql",
                "policy_projections.scope",
            ),
        ] {
            let mut inputs = real_tree_inputs();
            inputs.manifest_toml = without_entry(&inputs.manifest_toml, migration);
            let hits = violations(&inputs);
            assert_eq!(hits.len(), 1, "{hits:?}");
            assert!(
                hits[0].starts_with(migration)
                    && hits[0].contains(identifier)
                    && hits[0].contains("no entry in migrations/"),
                "stripping the entry must make the real scan report the narrowing: {hits:?}"
            );
        }
    }

    #[test]
    fn real_tree_goes_red_when_a_widening_loses_what_makes_it_one() {
        // The mutation counter-assertion for the exemption, run over REAL
        // on-disk migration SQL rather than a fixture: over a clean tree
        // the exemption and a scanner that never saw these statements agree
        // on the verdict and differ only in what they read, so nothing else
        // here can tell them apart. Each mutation removes exactly one of
        // the exemption's conditions and the statement must report.
        let clean = violations(&real_tree_inputs());
        assert!(
            clean.is_empty(),
            "the real tree must be green before it is mutated: {clean:?}"
        );

        // (a) 013's pairing: without the `DROP CONSTRAINT` of the same
        // name, the wider primary key has no predecessor to be wider than.
        let mut inputs = real_tree_inputs();
        mutate_migration(
            &mut inputs,
            "013_content_references_multivalue_pk.sql",
            "DROP CONSTRAINT content_references_pkey;",
            "DROP CONSTRAINT content_references_some_other_name;",
        );
        let hits = violations(&inputs);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].starts_with("013_content_references_multivalue_pk.sql"),
            "{hits:?}"
        );
        for column in [
            "content_references.repository_id",
            "content_references.source_artifact_id",
            "content_references.target_content_hash",
            "content_references.kind",
        ] {
            assert!(hits[0].contains(column), "{column} missing from {hits:?}");
        }

        // (b) 013's nullability: with `target_content_hash` nullable, the
        // same widening imposes a NOT NULL the row-admission argument says
        // nothing about.
        let mut inputs = real_tree_inputs();
        mutate_migration(
            &mut inputs,
            "003_artifacts_cas.sql",
            "target_content_hash text NOT NULL",
            "target_content_hash text",
        );
        let hits = violations(&inputs);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].starts_with("013_content_references_multivalue_pk.sql")
                && hits[0].contains("content_references.target_content_hash"),
            "{hits:?}"
        );

        // (c) 021's pairing: without the `DROP CONSTRAINT`, the partial
        // unique index replaces nothing — which is 017's shape, and the
        // property a tree holding only 021 does not pin.
        let mut inputs = real_tree_inputs();
        mutate_migration(
            &mut inputs,
            "021_artifacts_soft_delete.sql",
            "DROP CONSTRAINT artifacts_repository_id_path_key;",
            "DROP CONSTRAINT artifacts_some_other_name;",
        );
        let hits = violations(&inputs);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].starts_with("021_artifacts_soft_delete.sql")
                && hits[0].contains("artifacts.repository_id")
                && hits[0].contains("artifacts.path"),
            "{hits:?}"
        );

        // (d) and the keyword the index verdict turns on: without `UNIQUE`
        // the same statement constrains nothing, so it must go quiet even
        // with the pairing gone.
        let mut inputs = real_tree_inputs();
        mutate_migration(
            &mut inputs,
            "021_artifacts_soft_delete.sql",
            "DROP CONSTRAINT artifacts_repository_id_path_key;",
            "DROP CONSTRAINT artifacts_some_other_name;",
        );
        mutate_migration(
            &mut inputs,
            "021_artifacts_soft_delete.sql",
            "CREATE UNIQUE INDEX artifacts_repository_id_path_live_key",
            "CREATE INDEX artifacts_repository_id_path_live_key",
        );
        assert!(
            violations(&inputs).is_empty(),
            "a non-unique index constrains nothing: {:?}",
            violations(&inputs)
        );
    }

    #[test]
    fn the_017_entry_is_what_keeps_the_real_tree_green() {
        // Stated as its own test because it is the acceptance criterion for
        // this unit, and the two halves have to be asserted together: the
        // real corpus is green WITH the entry and red WITHOUT it. Either
        // half alone is satisfied by a guard that reports nothing.
        let inputs = real_tree_inputs();
        assert!(
            inputs
                .manifest_toml
                .contains("017_scan_policy_scope_unique.sql"),
            "the manifest must declare 017 for this test to mean anything"
        );
        assert!(violations(&inputs).is_empty());
        let mut stripped = real_tree_inputs();
        stripped.manifest_toml =
            without_entry(&stripped.manifest_toml, "017_scan_policy_scope_unique.sql");
        assert_eq!(violations(&stripped).len(), 1);
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
