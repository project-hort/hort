//! Structural guard: **`subscriptions.last_delivered_position` has one
//! writer, and that writer cannot lower it.**
//!
//! ## The invariant
//!
//! The column is a delivery cursor, not a reported statistic. A dispatcher
//! task that starts, restarts or moves replica reads it and resumes
//! *strictly above* it
//! (`hort_app::dispatcher::subscription_task`), so the value is a promise
//! about what has already been handled: written backwards it is
//! re-delivery of everything in between, written forwards by mistake it is
//! silent loss. `hort_domain::ports::subscription_repository` states both
//! halves on the two methods that own them —
//! `advance_delivered_position` (never lower the stored value) and
//! `retained_delivered_position` (a whole-row write persists the stored
//! value, never the one its caller is carrying).
//!
//! ## How it was lost, and why a scan rather than a convention
//!
//! The column had three write statements and nothing ordering them.
//! `update_last_delivered` assigned through a `COALESCE`, which guards
//! against NULL and not against going backwards; `update` — the whole-row
//! write behind PATCH, pause, resume and disable — persisted whatever
//! position its own `find_by_id` had seen, while the dispatcher advances
//! that column concurrently from another task and, at `replicaCount > 1`,
//! another process. Last writer won.
//!
//! The fix is one SQL function name (`COALESCE` → `GREATEST`) and one
//! absent `SET`-list entry. Neither is visible to the type system, to
//! clippy, or to a reader who is editing the whole-row write for an
//! unrelated field — and the `SET` list is exactly where an unrelated
//! field gets added. The live-database test that proves the rewind is
//! refused (`hort-adapters-postgres/tests/subscription_repo.rs::
//! a_late_writer_cannot_rewind_the_delivery_cursor`) can only attempt it
//! through statements it already knows to call, and it self-skips
//! entirely without `DATABASE_URL`: a *fourth* statement added next month
//! is outside both its reach and the local gate's. Convention is also
//! measurably not enough here — the sibling one-writer incident
//! (`jobs_row_has_one_owner`) had a writer census that grew from one to
//! six under convention alone.
//!
//! ## The property
//!
//! For every production SQL statement in `crates/*/src` that writes the
//! [`TABLE`] table, the stance it takes on [`COLUMN`] is one of:
//!
//!   * [`Verdict::Advance`] — it assigns `GREATEST(…, last_delivered_
//!     position)`, reading the stored value back inside the same atomic
//!     statement, so the write cannot lower it. This is
//!     `update_last_delivered`, the one permitted writer.
//!   * [`Verdict::Seed`] — a plain `INSERT` naming the column. A row that
//!     did not exist has no prior value to rewind, so this establishes the
//!     cursor rather than moving it.
//!   * [`Verdict::Untouched`] — it writes the table and leaves the column
//!     alone. This is `update`.
//!   * [`Verdict::Overwrite`] — anything else. **The finding.**
//!
//! The two halves of "one writer that cannot lower it" are held by
//! different assertions, and a reviewer should not read either as the
//! whole property. [`the_delivery_cursor_has_one_writer`] holds the
//! **direction**: no statement writes the column in a way that can lower
//! it. The **count** is held by the census
//! ([`the_scanned_corpus_is_real`]) together with
//! [`greatest_is_still_the_permitted_writers_form`] and
//! [`the_seed_insert_is_still_pinned_with_its_reason`], which require
//! exactly one `Advance` and exactly one `Seed` — so a *second* monotonic
//! writer, which is harmless to the cursor's value but splits ownership of
//! it, is a review conversation rather than a silent pass.
//!
//! `Seed` is *pinned* rather than forbidden — the way
//! `jobs_row_has_one_owner` pins the adapter's terminal resolve of an
//! unmappable claimed row instead of banning it. The pin lives in
//! [`PINNED_SEED`], with its reason, where a reviewer reading this guard
//! reads the reason; it is a **counter-assertion and not an allow-list**,
//! because the main assertion never consults it. Deleting that entry
//! cannot make a finding go away — it fails
//! [`the_seed_insert_is_still_pinned_with_its_reason`] instead. The `Seed`
//! verdict itself is derived from the statement's shape: an `INSERT`
//! carrying `ON CONFLICT … DO UPDATE SET` *can* reach an existing row's
//! value, so it is classified as the `UPDATE` it contains and not as a
//! seed.
//!
//! ## Scope — derived, not enumerated
//!
//! Scoped by **what the statement touches**: any SQL string literal in any
//! `crates/*/src` tree whose statement writes [`TABLE`]. Not by a file
//! list — the question is "does any production statement in this workspace
//! move this cursor", and the answer must not depend on which crate
//! someone put the statement in. ADR 0008 keeps the relational schema
//! behind `hort-adapters-*`, so in practice every hit lands in
//! `subscription_repo.rs`; [`the_scanned_corpus_is_real`] pins that as an
//! observed census rather than this file assuming it. `#[cfg(test)]` items
//! are out by how they are compiled, not by an entry. **There is no
//! allow-list**: a third writer that genuinely should exist is a review
//! conversation about who owns the cursor, not an exemption entry.
//!
//! Three deliberate boundaries, all because they are not the hazard:
//!
//!   * **Reads are not writes.** `SELECT … FROM subscriptions` carries the
//!     column into memory; only `INSERT`/`UPDATE` can persist one.
//!   * **`DELETE FROM subscriptions` is not a column write.** It removes
//!     the row, cursor included, which is `delete`'s subject matter.
//!   * **`migrations/` is out of scope.** A migration is a one-time,
//!     single-flight schema or backfill step rather than a runtime writer
//!     racing another replica's flush, and that tree has its own guards
//!     (ADR 0030: `no_sensitive_drops`, `expand_contract_guard`).
//!     [`the_column_still_exists`] is what this guard reads there.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The ones every scan in this family has:
//!
//!   * **A statement assembled from fragments is not seen as one
//!     statement.** A `format!` template interpolating a `const` column
//!     list — `subscription_repo.rs`'s own `SELECT_COLS` is exactly that
//!     shape for its reads — or a `QueryBuilder` composing a `SET` list at
//!     runtime, is invisible to this scan. The fix for a write built that
//!     way is to spell it in one literal, not to teach the scan to chase
//!     fragments.
//!   * **A write reached through a differently-named helper, or through a
//!     macro**, is likewise invisible. The review check survives alongside
//!     this guard.
//!   * **The shared SQL tokenizer does not emit `=`**, so a `SET` list is
//!     read positionally (the target is the first identifier after `SET`
//!     or after a depth-0 comma). The row-wise `SET (a, b) = (…)` form
//!     cannot be read that way, so a segment of that shape naming the
//!     column is reported rather than guessed about — fail-closed, and a
//!     false positive is a review conversation.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `jobs_row_has_one_owner`, `live_reads_exclude_deleted` and
//! `capped_stream_writes`.

#![allow(clippy::expect_used)]

use std::path::Path;

mod rust_scan;
mod sql_scan;

use rust_scan::{
    blank_cfg_test_items, line_of, mark_literals, parse_fns, walk_rust, workspace_root, FnItem,
    LITERAL_MARK,
};
use sql_scan::{
    is_identifier_token, parse_table_name, strip_comments_and_strings, tokenize, Token,
};

/// The table whose cursor column is under contract.
const TABLE: &str = "subscriptions";

/// The delivery cursor itself.
const COLUMN: &str = "last_delivered_position";

/// The only SQL function that writes the column without being able to
/// lower it: it takes the greater of the incoming value and the stored
/// one, in one statement with no read-modify-write window, and ignores
/// NULL arguments so a "no advance to record" write leaves the column
/// alone. `COALESCE` is deliberately **not** accepted — it guards against
/// NULL and not against direction, which is the defect this guard holds
/// closed.
const MONOTONIC: &str = "greatest";

/// The pseudo-table an upsert's `DO UPDATE SET` uses for the *proposed*
/// row. `GREATEST(EXCLUDED.last_delivered_position, …)` reads the incoming
/// value, not the stored one, so a reference qualified this way does not
/// make an assignment monotonic.
const PROPOSED: &str = "excluded";

/// Which statement form the write takes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verb {
    Insert,
    Update,
}

/// The stance one write statement takes on [`COLUMN`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Assigns `GREATEST(…, last_delivered_position)` — monotonic by
    /// construction.
    Advance,
    /// A plain `INSERT` naming the column: a fresh row, no prior value.
    Seed,
    /// Writes the table and not the column.
    Untouched,
    /// Writes the column some other way. The finding.
    Overwrite,
}

/// One production SQL statement that writes [`TABLE`].
#[derive(Debug, Clone)]
struct Write {
    /// Workspace-relative path, forward slashes.
    file: String,
    /// 1-based line the Rust string literal holding the statement opens
    /// on. For a message only — the census names statements by function,
    /// because a line number moves on any edit above it.
    line: usize,
    /// The innermost `fn` the literal sits in.
    function: String,
    verb: Verb,
    verdict: Verdict,
    /// How the column is assigned, as the scan read it. Empty when the
    /// statement does not assign it.
    assignment: String,
}

// ---------------------------------------------------------------------------
// The matcher.
// ---------------------------------------------------------------------------

/// One `SET`-list assignment to [`COLUMN`].
struct Assignment {
    /// True when the right-hand side takes `GREATEST` over the stored
    /// value.
    monotonic: bool,
    /// The assignment as it reads in the SQL, for the failure message.
    rendered: String,
}

/// The token index just past the `SET` keyword of an `UPDATE` whose table
/// name ends at `after_table`, or `None` when the statement does not take
/// that shape.
///
/// At most two tokens may sit between the table name and `SET` — an
/// optional `AS` and an alias — so a `SET` belonging to some later clause
/// cannot be mistaken for this statement's.
fn set_list_start(tokens: &[Token], after_table: usize) -> Option<usize> {
    for probe in after_table..=after_table + 2 {
        match tokens.get(probe) {
            Some(token) if token.text == "set" => return Some(probe + 1),
            Some(token) if is_identifier_token(token) => continue,
            _ => return None,
        }
    }
    None
}

/// The assignment segments of the `SET` list starting at `from`: the token
/// runs between depth-0 commas, stopping at whatever clause ends the list.
fn set_assignments(tokens: &[Token], from: usize) -> Vec<Vec<Token>> {
    let mut out: Vec<Vec<Token>> = Vec::new();
    let mut current: Vec<Token> = Vec::new();
    let mut depth = 0i32;
    for token in tokens.iter().skip(from) {
        match token.text.as_str() {
            "(" => {
                depth += 1;
                current.push(token.clone());
            }
            ")" if depth == 0 => break,
            ")" => {
                depth -= 1;
                current.push(token.clone());
            }
            "," if depth == 0 => out.push(std::mem::take(&mut current)),
            "where" | "returning" | "from" | ";" if depth == 0 => break,
            _ => current.push(token.clone()),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The text of `segment` as it reads in `sql`, whitespace collapsed.
fn render(segment: &[Token], sql: &str) -> String {
    let Some(first) = segment.first() else {
        return String::new();
    };
    let last = segment.last().unwrap_or(first);
    sql.get(first.offset..last.offset + last.text.len())
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// True when `rest` reads the **stored** column back — any reference to it
/// that is not qualified by the upsert's [`PROPOSED`] pseudo-table.
fn reads_stored_column(rest: &[Token]) -> bool {
    rest.iter().enumerate().any(|(at, token)| {
        token.text == COLUMN
            && !(at >= 2 && rest[at - 1].text == "." && rest[at - 2].text == PROPOSED)
    })
}

/// How `segment` assigns [`COLUMN`], or `None` when it does not assign it.
fn column_assignment(segment: &[Token], sql: &str) -> Option<Assignment> {
    let target = segment.first()?;
    if !is_identifier_token(target) {
        // The row-wise `SET (a, b) = (…)` form; see this module's blind
        // spots. Fail closed: a segment naming the column at all is
        // reported.
        return segment
            .iter()
            .any(|token| token.text == COLUMN)
            .then(|| Assignment {
                monotonic: false,
                rendered: render(segment, sql),
            });
    }
    if target.text != COLUMN {
        return None;
    }
    let rest = &segment[1..];
    let monotonic =
        rest.first().is_some_and(|token| token.text == MONOTONIC) && reads_stored_column(rest);
    Some(Assignment {
        monotonic,
        rendered: render(segment, sql),
    })
}

/// `(every assignment is monotonic, rendered assignments)` for the `SET`
/// list starting at `from`, or `None` when it does not assign [`COLUMN`].
fn set_list_stance(tokens: &[Token], from: usize, sql: &str) -> Option<(bool, String)> {
    let found: Vec<Assignment> = set_assignments(tokens, from)
        .iter()
        .filter_map(|segment| column_assignment(segment, sql))
        .collect();
    if found.is_empty() {
        return None;
    }
    Some((
        found.iter().all(|assignment| assignment.monotonic),
        found
            .iter()
            .map(|assignment| assignment.rendered.clone())
            .collect::<Vec<_>>()
            .join(" / "),
    ))
}

/// The lower-cased identifiers of the parenthesised column list opening at
/// `from`, or `None` when no list opens there (`INSERT … DEFAULT VALUES`,
/// `INSERT INTO t SELECT …`).
fn column_list(tokens: &[Token], from: usize) -> Option<Vec<String>> {
    if tokens.get(from)?.text != "(" {
        return None;
    }
    let mut cols = Vec::new();
    let mut depth = 0i32;
    for token in tokens.iter().skip(from) {
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    return Some(cols);
                }
            }
            _ if depth == 1 && is_identifier_token(token) => {
                cols.push(token.text.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    Some(cols)
}

/// The token index just past the `SET` of an `ON CONFLICT … DO UPDATE SET`
/// at or after `from`, or `None` when the statement has none.
fn do_update_set(tokens: &[Token], from: usize) -> Option<usize> {
    (from..tokens.len())
        .find(|&at| {
            tokens[at].text == "do"
                && tokens.get(at + 1).map(|t| t.text.as_str()) == Some("update")
                && tokens.get(at + 2).map(|t| t.text.as_str()) == Some("set")
        })
        .map(|at| at + 3)
}

/// Every write statement against [`TABLE`] in one SQL text, with its
/// stance on [`COLUMN`].
///
/// A `DO UPDATE`'s own `update` token is skipped by the `UPDATE` arm
/// without a special case: the token after it is `set`, which is not the
/// table name, so the upsert is classified once — by the `INSERT` arm that
/// owns it.
fn statement_writes(sql: &str, tokens: &[Token]) -> Vec<(Verb, Verdict, String)> {
    let mut out = Vec::new();
    for at in 0..tokens.len() {
        match tokens[at].text.as_str() {
            "update" => {
                let Some((table, after)) = parse_table_name(tokens, at + 1) else {
                    continue;
                };
                if table != TABLE {
                    continue;
                }
                let Some(set_at) = set_list_start(tokens, after) else {
                    continue;
                };
                out.push(match set_list_stance(tokens, set_at, sql) {
                    None => (Verb::Update, Verdict::Untouched, String::new()),
                    Some((true, rendered)) => (Verb::Update, Verdict::Advance, rendered),
                    Some((false, rendered)) => (Verb::Update, Verdict::Overwrite, rendered),
                });
            }
            "insert" => {
                if tokens.get(at + 1).map(|t| t.text.as_str()) != Some("into") {
                    continue;
                }
                let Some((table, after)) = parse_table_name(tokens, at + 2) else {
                    continue;
                };
                if table != TABLE {
                    continue;
                }
                let seeds = column_list(tokens, after)
                    .is_some_and(|cols| cols.iter().any(|col| col == COLUMN));
                let upsert = do_update_set(tokens, after)
                    .and_then(|set_at| set_list_stance(tokens, set_at, sql));
                out.push(match (upsert, seeds) {
                    (Some((false, rendered)), _) => (Verb::Insert, Verdict::Overwrite, rendered),
                    (Some((true, rendered)), _) => (Verb::Insert, Verdict::Advance, rendered),
                    (None, true) => (Verb::Insert, Verdict::Seed, String::new()),
                    (None, false) => (Verb::Insert, Verdict::Untouched, String::new()),
                });
            }
            _ => {}
        }
    }
    out
}

/// The SQL inside a Rust string literal: the span [`mark_literals`] reports
/// includes the literal's own delimiters, and a `"` reaching the SQL
/// tokenizer opens a quoted *identifier* that swallows the whole statement.
/// Peels an optional `b` prefix, an optional `r` with its `#` run, and the
/// quotes.
fn literal_body(raw: &str) -> &str {
    let trimmed = raw.trim_start_matches('b');
    let (hashes, rest) = match trimmed.strip_prefix('r') {
        Some(after_r) => (true, after_r.trim_start_matches('#')),
        None => (false, trimmed),
    };
    let inner = rest.strip_prefix('"').unwrap_or(rest);
    let inner = if hashes {
        inner.trim_end_matches('#')
    } else {
        inner
    };
    inner.strip_suffix('"').unwrap_or(inner)
}

/// The innermost `fn` whose span contains `at`.
fn enclosing_fn(fns: &[FnItem], at: usize) -> String {
    fns.iter()
        .filter(|item| item.span.0 <= at && at < item.span.1)
        .max_by_key(|item| item.span.0)
        .map_or_else(|| "<file scope>".to_owned(), |item| item.name.clone())
}

/// Every production write against [`TABLE`] in one file's `source`.
///
/// Takes the source rather than reading it, so
/// [`mutating_a_writer_fails_the_scan`] can run the real classifier over
/// real on-disk source it has edited.
fn analyse(rel: &str, source: &str) -> Vec<Write> {
    let (marked, spans) = mark_literals(source);
    let production = blank_cfg_test_items(&marked);
    let fns = parse_fns(&production);
    let production_bytes = production.as_bytes();
    let mut out = Vec::new();
    for (start, end) in spans {
        // The mark survives only outside `#[cfg(test)]`.
        if production_bytes.get(start) != Some(&LITERAL_MARK) {
            continue;
        }
        let raw = &source[start..end];
        if !raw.contains(TABLE) {
            continue;
        }
        let sql = strip_comments_and_strings(literal_body(raw));
        let tokens = tokenize(&sql);
        for (verb, verdict, assignment) in statement_writes(&sql, &tokens) {
            out.push(Write {
                file: rel.to_owned(),
                line: line_of(source, start),
                function: enclosing_fn(&fns, start),
                verb,
                verdict,
                assignment,
            });
        }
    }
    out
}

/// Every production write against [`TABLE`] under `crates/*/src`, sorted
/// so a failure message is stable.
fn collect_writes() -> Vec<Write> {
    let root = workspace_root();
    let mut found: Vec<Write> = Vec::new();
    walk_rust(&root.join("crates"), &mut |path: &Path| {
        // Only `src` trees: a `tests/` target is test code by
        // construction, the same way a `#[cfg(test)]` item is.
        if !path.components().any(|c| c.as_os_str() == "src") {
            return;
        }
        let Ok(source) = std::fs::read_to_string(path) else {
            return;
        };
        if !source.contains(TABLE) {
            return;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        found.extend(analyse(&rel, &source));
    });
    found.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    found
}

// ---------------------------------------------------------------------------
// The census and the pin, measured when this guard was introduced.
// ---------------------------------------------------------------------------

/// `(file, function, verb, verdict)` — every production statement that
/// writes [`TABLE`], as reviewed when this guard was introduced.
///
/// Named by **function** rather than by line: a line number moves on any
/// edit above it, whereas "which method writes this table, and what it
/// does about the cursor" is the reviewable fact. The whole corpus is
/// three statements, so this is an equality and not a floor — a statement
/// that vanishes from the scan fails here rather than leaving the main
/// assertion green over a corpus with a hole in it, and a *fourth* writer
/// arriving is the review conversation this list exists to force.
///
/// `delete`'s `DELETE FROM subscriptions` is deliberately absent: it
/// removes the row, cursor included, and cannot write a column value.
const CENSUS: [(&str, &str, Verb, Verdict); 3] = [
    (
        "crates/hort-adapters-postgres/src/subscription_repo.rs",
        "create",
        Verb::Insert,
        Verdict::Seed,
    ),
    (
        "crates/hort-adapters-postgres/src/subscription_repo.rs",
        "update",
        Verb::Update,
        Verdict::Untouched,
    ),
    (
        "crates/hort-adapters-postgres/src/subscription_repo.rs",
        "update_last_delivered",
        Verb::Update,
        Verdict::Advance,
    ),
];

/// `(file, function, reason)` — the one `INSERT` that establishes the
/// column, pinned with the reason it is permitted.
///
/// The main assertion does **not** read this: the [`Verdict::Seed`]
/// verdict is derived from the statement's shape, so this is not an
/// allow-list entry and deleting it cannot silence a finding. It is here
/// so a reviewer reading the guard reads the reason, and so a rename or a
/// deletion of the seed itself fails
/// [`the_seed_insert_is_still_pinned_with_its_reason`] instead of making
/// the scan vacuously green.
const PINNED_SEED: (&str, &str, &str) = (
    "crates/hort-adapters-postgres/src/subscription_repo.rs",
    "create",
    "a fresh row has no prior value to rewind. `create` establishes the \
     cursor at the position the caller starts from; a `create` that met an \
     existing row would fail on the primary key rather than overwrite its \
     progress, and the statement carries no `ON CONFLICT … DO UPDATE` that \
     could reach one.",
);

/// The migration that creates the table, for [`the_column_still_exists`].
const SCHEMA_MIGRATION: &str = "012_subscriptions.sql";

// ---------------------------------------------------------------------------
// The property.
// ---------------------------------------------------------------------------

#[test]
fn the_delivery_cursor_has_one_writer() {
    let offenders: Vec<String> = collect_writes()
        .into_iter()
        .filter(|write| write.verdict == Verdict::Overwrite)
        .map(|write| {
            format!(
                "  - {}:{} ({}, {:?}) — writes the cursor as `{}`",
                write.file, write.line, write.function, write.verb, write.assignment
            )
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these SQL statements write `{TABLE}.{COLUMN}` in a way that can \
         lower it:\n{}\n\n\
         The column is a delivery cursor, not a statistic: a dispatcher \
         task resumes strictly above it, so a value written backwards is \
         re-delivery of everything in between and a value written forwards \
         is loss. It is flushed from an in-memory cursor held per task, one \
         task per replica with no leader election, so writers arrive out of \
         order in ordinary operation — a read-modify-write that assigns \
         what its own earlier read saw is a rewind, not a race.\n\n\
         If this statement advances the cursor, assign \
         `{}($n, {COLUMN})` so the write cannot lower it — see \
         `update_last_delivered`. If it writes the row for some other \
         reason, leave the column out of its `SET` list, as `update` does, \
         and take the stored value from \
         `hort_domain::ports::subscription_repository::\
         retained_delivered_position`. There is no allow-list in this file \
         to add to: a third writer that genuinely should exist is a review \
         conversation about who owns the cursor.",
        offenders.join("\n"),
        MONOTONIC.to_uppercase()
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions — the scan is answering about something.
// ---------------------------------------------------------------------------

/// The corpus is real, and is the one that was reviewed.
///
/// Without this the main assertion stays green by finding nothing: rename
/// the table, break the statement matcher, or change the literals' shape
/// so `mark_literals` no longer yields them, and "no statement overwrites
/// the cursor" is satisfied trivially.
#[test]
fn the_scanned_corpus_is_real() {
    let observed: Vec<(String, String, Verb, Verdict)> = collect_writes()
        .iter()
        .map(|write| {
            (
                write.file.clone(),
                write.function.clone(),
                write.verb,
                write.verdict,
            )
        })
        .collect();
    let expected: Vec<(String, String, Verb, Verdict)> = CENSUS
        .iter()
        .map(|(file, function, verb, verdict)| {
            ((*file).to_owned(), (*function).to_owned(), *verb, *verdict)
        })
        .collect();

    assert!(
        !observed.is_empty(),
        "the scan found no statement writing `{TABLE}` at all. The main \
         assertion is then vacuous. Either the table was renamed, or the \
         statements are no longer single string literals the scan can read \
         (see this module's blind spots)"
    );
    assert_eq!(
        observed, expected,
        "the write census for `{TABLE}` was reviewed as these three \
         statements. A statement that MOVED is fine — update the census \
         after reading its stance. A statement that VANISHED means the scan \
         no longer sees it; a statement whose stance CHANGED, or a FOURTH \
         writer, is the review conversation this list exists to force"
    );
}

/// `GREATEST` over the stored value is still what the one permitted writer
/// does.
///
/// [`the_scanned_corpus_is_real`] pins the verdict, but would be satisfied
/// by a census edited to match. This states the mechanism: the real SQL of
/// the `Advance` statement names the function AND reads the column back
/// inside it, which is the only thing that makes the verdict mean
/// "monotonic" rather than "assigned".
#[test]
fn greatest_is_still_the_permitted_writers_form() {
    let advancing: Vec<Write> = collect_writes()
        .into_iter()
        .filter(|write| write.verdict == Verdict::Advance)
        .collect();
    assert_eq!(
        advancing.len(),
        1,
        "exactly one statement may advance the cursor; found {advancing:#?}"
    );
    let advance = &advancing[0];
    assert_eq!(
        (advance.file.as_str(), advance.function.as_str()),
        (
            "crates/hort-adapters-postgres/src/subscription_repo.rs",
            "update_last_delivered"
        ),
        "the advancing statement moved to {advance:#?} — the port method \
         that owns the cursor is `update_last_delivered`"
    );
    let lowered = advance.assignment.to_ascii_lowercase();
    assert!(
        lowered.contains(MONOTONIC),
        "the advancing assignment no longer names `{}`: `{}`. `COALESCE` \
         reads the same way at a glance and guards only against NULL — it \
         is the defect this guard holds closed",
        MONOTONIC.to_uppercase(),
        advance.assignment
    );
    assert_eq!(
        lowered.matches(COLUMN).count(),
        2,
        "the advancing assignment must name `{COLUMN}` twice — once as the \
         target, once as the argument that reads the stored value back — \
         and reads `{}`. `{}($n, 0)` assigns without reading the stored \
         value and is not monotonic",
        advance.assignment,
        MONOTONIC.to_uppercase()
    );
}

/// The seeding `INSERT` is still there, still a seed, and still carries
/// the reason it is permitted.
#[test]
fn the_seed_insert_is_still_pinned_with_its_reason() {
    let (file, function, reason) = PINNED_SEED;
    assert!(
        reason.trim().len() > 40,
        "the pin's reason IS the declaration — a blank one is an allow-list \
         entry wearing a `const`"
    );
    let seeds: Vec<Write> = collect_writes()
        .into_iter()
        .filter(|write| write.verdict == Verdict::Seed)
        .collect();
    assert_eq!(
        seeds.len(),
        1,
        "exactly one statement may seed the cursor; found {seeds:#?}"
    );
    assert_eq!(
        (
            seeds[0].file.as_str(),
            seeds[0].function.as_str(),
            seeds[0].verb
        ),
        (file, function, Verb::Insert),
        "the seeding statement is pinned as {file}'s `{function}` INSERT, \
         with this reason: {reason}\n\nThe scan now sees {:#?}. If the seed \
         moved, move the pin after re-reading whether the reason still \
         holds — an `INSERT` that can reach an existing row (`ON CONFLICT \
         … DO UPDATE`) is not a seed and is not covered by it",
        seeds[0]
    );
}

/// The column the whole property is about still exists in the schema.
///
/// A guard about how a column may be written is nonsense if the column was
/// dropped: the writers would not compile, but this scan would keep
/// passing on whatever still spelled the name.
#[test]
fn the_column_still_exists() {
    let dir = workspace_root().join("migrations");
    let entries = std::fs::read_dir(&dir).expect("migrations/ exists under the workspace root");
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    paths.sort();
    let mut found_in: Vec<String> = Vec::new();
    for path in paths {
        let Ok(sql) = std::fs::read_to_string(&path) else {
            continue;
        };
        let tokens = tokenize(&strip_comments_and_strings(&sql));
        for at in 0..tokens.len() {
            if tokens[at].text != "create"
                || tokens.get(at + 1).map(|t| t.text.as_str()) != Some("table")
            {
                continue;
            }
            let Some((table, next)) = parse_table_name(&tokens, at + 2) else {
                continue;
            };
            if table != TABLE {
                continue;
            }
            let declares =
                column_list(&tokens, next).is_some_and(|cols| cols.iter().any(|col| col == COLUMN));
            if declares {
                found_in.push(
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    // Named rather than merely counted: a second migration declaring the
    // same column would mean the first one's table was dropped somewhere in
    // between, which is a different schema history than this guard's
    // reasoning rests on.
    assert_eq!(
        found_in,
        vec![SCHEMA_MIGRATION.to_owned()],
        "`{TABLE}.{COLUMN}` is expected to be declared by \
         `migrations/{SCHEMA_MIGRATION}` and nowhere else. A guard that \
         rules on how a column may be written says nothing once the column \
         is gone — if the cursor was replaced, this guard and \
         `hort_domain::ports::subscription_repository`'s two rule functions \
         are what have to change with it"
    );
}

/// The mutation counter-assertion: put the thing the guard looks for back
/// (or take it away) and the guard must go red.
///
/// Run over **real on-disk source** rather than a hand-written fixture,
/// and in both directions. Over a clean tree an honest classifier and one
/// that returns `Untouched` for everything agree on the verdict and differ
/// only in what they read; nothing else in this file can tell them apart.
#[test]
fn mutating_a_writer_fails_the_scan() {
    let root = workspace_root();
    let rel = "crates/hort-adapters-postgres/src/subscription_repo.rs";
    let source = std::fs::read_to_string(root.join(rel)).expect("readable UTF-8");
    let clean = analyse(rel, &source);
    assert!(
        clean
            .iter()
            .all(|write| write.verdict != Verdict::Overwrite),
        "{rel} must be clean before it is mutated: {clean:#?}"
    );

    // Direction 1 — the whole-row write takes the column back into its
    // `SET` list. This is the edit the guard exists to catch: it is what a
    // reader adding an unrelated field to that list does by reflex.
    let mutated = splice_into_set_list(&source, &clean, "update", &format!("{COLUMN} = $99,"));
    assert_ne!(mutated, source, "the mutation changed nothing");
    let reported = analyse(rel, &mutated);
    let named: Vec<&Write> = reported
        .iter()
        .filter(|write| write.verdict == Verdict::Overwrite)
        .collect();
    assert_eq!(
        named.len(),
        1,
        "with `{COLUMN}` back in `update`'s SET list the scan must name \
         exactly that statement; it reported {reported:#?}"
    );
    assert_eq!(
        named[0].function, "update",
        "the scan named the wrong statement: {:#?}",
        named[0]
    );

    // Direction 2 — the permitted writer loses `GREATEST`, which is the
    // `COALESCE` defect restated. The assignment survives; only its
    // monotonicity does not.
    let downgraded = source.replace(
        &format!("{COLUMN} = GREATEST($2, {COLUMN})"),
        &format!("{COLUMN} = $2"),
    );
    assert_ne!(
        downgraded, source,
        "the advancing assignment is no longer spelled as this mutation \
         expects — if it moved, re-point the mutation; a mutation that \
         changes nothing proves nothing"
    );
    let reported = analyse(rel, &downgraded);
    assert_eq!(
        reported
            .iter()
            .filter(|write| write.verdict == Verdict::Overwrite)
            .map(|write| write.function.as_str())
            .collect::<Vec<_>>(),
        vec!["update_last_delivered"],
        "a bare assignment in the one permitted writer must report; the \
         scan saw {reported:#?}"
    );
}

/// `source` with `insert` spliced into the `SET` list of the statement in
/// `function`, by editing the real literal the scan found.
///
/// Anchored on the statement's own `SET` token rather than on a copy of
/// the surrounding text, so reformatting the adapter cannot turn this
/// mutation into a no-op that still passes.
fn splice_into_set_list(source: &str, writes: &[Write], function: &str, insert: &str) -> String {
    let write = writes
        .iter()
        .find(|write| write.function == function)
        .unwrap_or_else(|| panic!("no write statement found in `{function}`"));
    let (_, spans) = mark_literals(source);
    let (start, end) = spans
        .iter()
        .find(|(at, _)| line_of(source, *at) == write.line)
        .copied()
        .unwrap_or_else(|| panic!("no string literal opens at the line of {write:#?}"));
    let raw = &source[start..end];
    let set_at = raw
        .find("SET")
        .unwrap_or_else(|| panic!("no `SET` keyword in the statement at {function}"))
        + "SET".len();
    format!(
        "{}{} {insert}{}{}",
        &source[..start],
        &raw[..set_at],
        &raw[set_at..],
        &source[end..]
    )
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's and classifier's behaviour.
// ---------------------------------------------------------------------------

/// The verdicts the matcher reaches for one SQL statement.
fn verdicts(sql: &str) -> Vec<(Verb, Verdict)> {
    let stripped = strip_comments_and_strings(sql);
    let tokens = tokenize(&stripped);
    statement_writes(&stripped, &tokens)
        .into_iter()
        .map(|(verb, verdict, _)| (verb, verdict))
        .collect()
}

#[test]
fn the_matcher_finds_writes_against_the_table_and_only_them() {
    assert_eq!(
        verdicts("UPDATE subscriptions SET name = $2 WHERE id = $1"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts("UPDATE public.subscriptions SET name = $2"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts("update subscriptions AS s set name = $2"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts("INSERT INTO subscriptions (id, name) VALUES ($1, $2)"),
        vec![(Verb::Insert, Verdict::Untouched)]
    );

    // Reads are not writes, and neither is removing the row.
    assert_eq!(
        verdicts("SELECT last_delivered_position FROM subscriptions"),
        vec![]
    );
    assert_eq!(verdicts("DELETE FROM subscriptions WHERE id = $1"), vec![]);

    // Identifier boundaries: a neighbouring table is a different table.
    assert_eq!(
        verdicts("UPDATE subscriptions_archive SET last_delivered_position = $2"),
        vec![]
    );
    assert_eq!(
        verdicts("UPDATE subscription_changes SET last_delivered_position = $2"),
        vec![]
    );
    assert_eq!(
        verdicts("INSERT INTO my_subscriptions (last_delivered_position) VALUES ($1)"),
        vec![]
    );
}

#[test]
fn the_classifier_accepts_only_the_monotonic_form() {
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET last_delivered_position = GREATEST($2, \
             last_delivered_position), last_failure = $3 WHERE id = $1"
        ),
        vec![(Verb::Update, Verdict::Advance)]
    );
    // A bare assignment: the whole hazard.
    assert_eq!(
        verdicts("UPDATE subscriptions SET last_delivered_position = $2 WHERE id = $1"),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
    // `COALESCE` guards against NULL, not against direction. This is the
    // statement the fix replaced, and it must not read as permitted.
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET last_delivered_position = \
             COALESCE($2, last_delivered_position) WHERE id = $1"
        ),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
    // `GREATEST` that does not read the stored value back is not an
    // advance either.
    assert_eq!(
        verdicts("UPDATE subscriptions SET last_delivered_position = GREATEST($2, 0)"),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
    // Nor is the opposite reduction.
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET last_delivered_position = \
             LEAST($2, last_delivered_position)"
        ),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
    // One non-monotonic assignment among several decides the verdict.
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET last_failure = $3, \
             last_delivered_position = $2"
        ),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
}

/// A column whose name merely starts with the cursor's is a different
/// column.
#[test]
fn the_classifier_matches_the_column_as_a_whole_identifier() {
    assert_eq!(
        verdicts("UPDATE subscriptions SET last_delivered_position_v2 = $2"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts("INSERT INTO subscriptions (id, last_delivered_position_v2) VALUES ($1, $2)"),
        vec![(Verb::Insert, Verdict::Untouched)]
    );
}

/// An `INSERT` naming the column seeds a row that did not exist; an upsert
/// can reach one that did, and is classified by the `SET` list it carries.
#[test]
fn an_insert_seeds_the_cursor_and_an_upsert_does_not() {
    assert_eq!(
        verdicts("INSERT INTO subscriptions (id, last_delivered_position) VALUES ($1, $2)"),
        vec![(Verb::Insert, Verdict::Seed)]
    );
    assert_eq!(
        verdicts(
            "INSERT INTO subscriptions (id, last_delivered_position) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING"
        ),
        vec![(Verb::Insert, Verdict::Seed)]
    );
    // The upsert that would rewind an existing row's cursor.
    assert_eq!(
        verdicts(
            "INSERT INTO subscriptions (id, last_delivered_position) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET \
             last_delivered_position = EXCLUDED.last_delivered_position"
        ),
        vec![(Verb::Insert, Verdict::Overwrite)]
    );
    // `GREATEST` over the PROPOSED row alone is still not a read of the
    // stored one.
    assert_eq!(
        verdicts(
            "INSERT INTO subscriptions (id, last_delivered_position) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET last_delivered_position = \
             GREATEST(EXCLUDED.last_delivered_position, 0)"
        ),
        vec![(Verb::Insert, Verdict::Overwrite)]
    );
    // The monotonic upsert, which would be permitted.
    assert_eq!(
        verdicts(
            "INSERT INTO subscriptions (id, last_delivered_position) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET last_delivered_position = \
             GREATEST(EXCLUDED.last_delivered_position, subscriptions.last_delivered_position)"
        ),
        vec![(Verb::Insert, Verdict::Advance)]
    );
}

/// The row-wise `SET (a, b) = (…)` form, which the shared tokenizer's
/// dropped `=` makes unreadable positionally. Fail closed.
#[test]
fn a_row_wise_assignment_naming_the_column_is_reported() {
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET (last_delivered_position, last_failure) = ($2, $3) \
             WHERE id = $1"
        ),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
    assert_eq!(
        verdicts("UPDATE subscriptions SET (name, description) = ($2, $3) WHERE id = $1"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
}

/// A clause after the `SET` list is not part of it — the shape that would
/// otherwise let a `WHERE last_delivered_position = $2` read as an
/// assignment.
#[test]
fn the_set_list_ends_where_the_statement_says_it_does() {
    assert_eq!(
        verdicts("UPDATE subscriptions SET name = $2 WHERE last_delivered_position = $3"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET name = s.name FROM seed s \
             WHERE s.last_delivered_position = $2"
        ),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    assert_eq!(
        verdicts("UPDATE subscriptions SET name = $2 RETURNING last_delivered_position"),
        vec![(Verb::Update, Verdict::Untouched)]
    );
    // A sub-select's own commas and keywords are at depth and do not end
    // the list.
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET name = (SELECT max(last_delivered_position) \
             FROM subscriptions WHERE id = $1), last_delivered_position = $2"
        ),
        vec![(Verb::Update, Verdict::Overwrite)]
    );
}

/// An SQL comment inside the statement is not the statement. The real
/// `update` carries its explanation in a *Rust* comment, which
/// `mark_literals` blanks; this is the other half.
#[test]
fn a_comment_naming_the_column_is_not_a_write() {
    assert_eq!(
        verdicts(
            "UPDATE subscriptions SET\n\
             -- last_delivered_position = $9 is deliberately absent: it has\n\
             -- another owner.\n\
             name = $2 WHERE id = $1"
        ),
        vec![(Verb::Update, Verdict::Untouched)]
    );
}

/// A statement held in a module-level `const` has no enclosing `fn`, and
/// the census names it `<file scope>` rather than dropping it. That shape
/// is already in the scanned file — `SELECT_COLS` is a `const` — so a
/// `const` write is reachable and is in the corpus like any other.
#[test]
fn a_module_level_statement_is_named_by_file_scope() {
    let found = analyse(
        "planted.rs",
        "const FLUSH: &str = \"UPDATE subscriptions SET last_delivered_position = $2\";",
    );
    assert_eq!(
        found
            .iter()
            .map(|write| (write.function.as_str(), write.verdict))
            .collect::<Vec<_>>(),
        vec![("<file scope>", Verdict::Overwrite)]
    );
}

/// The file-level discipline: a write in a `#[cfg(test)]` item is test
/// code and is out of the corpus, while the same statement in production
/// is in it. Planted Rust source, run through the real [`analyse`].
#[test]
fn a_test_only_statement_is_not_in_the_corpus() {
    let production = r#"
        fn flush(&self) {
            sqlx::query("UPDATE subscriptions SET last_delivered_position = $2").bind(1);
        }
    "#;
    let found = analyse("planted.rs", production);
    assert_eq!(
        found
            .iter()
            .map(|write| (write.function.as_str(), write.verdict))
            .collect::<Vec<_>>(),
        vec![("flush", Verdict::Overwrite)]
    );

    let test_only = r#"
        #[cfg(test)]
        mod tests {
            fn flush(&self) {
                sqlx::query("UPDATE subscriptions SET last_delivered_position = $2").bind(1);
            }
        }
    "#;
    assert!(
        analyse("planted.rs", test_only).is_empty(),
        "a `#[cfg(test)]` statement is test code and must not be in the corpus"
    );
}
