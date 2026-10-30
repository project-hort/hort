//! Structural guard: **every SQL statement that reads the `artifacts`
//! table either excludes soft-deleted rows or says, in its own SQL, why
//! it does not.**
//!
//! ## The invariant, and how it was lost
//!
//! `Artifact::deleted_at` states it outright
//! (`crates/hort-domain/src/entities/artifact.rs`): *"Every live read
//! filters `deleted_at IS NULL`, so an artifact materialised by a normal
//! lookup always carries `None` here."* `migrations/021_artifacts_soft_
//! delete.sql` says the same sentence from the schema side, and predicates
//! three indexes on it. Nothing in the tree enforced either statement.
//!
//! The way it broke is worth recording, because it is why this is a scan
//! and not a convention. Deletion used to be a hard `DELETE`, alongside an
//! inert `is_deleted` column. One commit dropped that inert column and the
//! filters that named it; the commit **one day later** introduced real
//! soft delete under a *different* column name, `deleted_at`, and
//! re-filtered some of the readers that had just lost their predicate. The
//! rename severed the link between "reader that lost the filter" and
//! "reader that must regain it", and three readers stayed unfiltered
//! from 2026-08-24 until this guard landed: the curator queue, the
//! rescan sweeps, and the patch-candidate worklist. Each of those is a surface an operator acts
//! on, so each soft-deleted row showed up as live work — and, being
//! `LIMIT`-bounded, consumed a slot that a real candidate then did not get.
//!
//! No type can require a column name in a string literal. Hence the scan.
//!
//! ## The property
//!
//! For every production SQL string literal that names [`TABLE`] after
//! `FROM` or `JOIN`, one of:
//!
//!   1. the same literal carries the [`FILTER`] predicate, or
//!   2. the same literal carries an SQL comment opening [`MARKER`],
//!      followed by a non-empty reason.
//!
//! **Scoped to the literal — not to a line range, a function or a file.**
//! That is the whole point rather than an implementation detail: the
//! declaration belongs where the query is, so a second statement added to
//! a file that already carries one is not covered by its neighbour's
//! reason. A file-scoped scan is the mistake `cas_reads_are_verified`
//! was written to avoid making twice.
//!
//! The predicate is looked for in the literal's **code**, with SQL
//! comments stripped first ([`sql_scan::strip_comments_and_strings`]) —
//! so a comment that merely discusses `deleted_at IS NULL`, including the
//! marker's own reason text, cannot satisfy requirement 1. The marker is
//! looked for in the raw literal, where the comment it lives in is still
//! there. Same discipline, opposite direction, and both halves are needed:
//! without the first, "we deliberately do not filter here because
//! `deleted_at IS NULL` would be wrong" would read as a filter.
//!
//! ## Why a marker rather than an allow-list
//!
//! Retention, purge and the audit log legitimately read deleted rows —
//! that is their subject matter. A blanket filter across every reader
//! would break them, so the guard cannot simply demand the predicate
//! everywhere. **There is no allow-list**, as with the sibling guards, and
//! so no entry anyone can add in this file to make a finding go away: a
//! reader that should see deleted rows declares it in its own SQL, with a
//! reason, where the next person to read that query will see it.
//!
//! ## Scope — derived, not enumerated
//!
//! Every `crates/*/src` tree, the same scope
//! `findings_reads_are_last_scan_scoped` uses and for the same reason: the
//! question is "does any production SQL in this workspace read this table
//! without declaring its stance on deleted rows", and the answer must not
//! depend on which crate someone put the query in. ADR 0008 puts the
//! relational schema behind `hort-adapters-*`, so in practice every hit
//! lands in `hort-adapters-postgres` — [`the_scanned_corpus_is_real`] pins
//! that as an observed census rather than this file assuming it.
//! `#[cfg(test)]` items are out by how they are compiled, not by an entry;
//! `migrations/` is out because it creates the table rather than reading
//! it (and is where [`the_column_still_exists`] looks instead).
//!
//! Writes are not reads: `INSERT INTO artifacts`, `UPDATE artifacts SET`
//! and `DELETE FROM artifacts` are out of scope by the matcher, which
//! requires the `FROM`/`JOIN` keyword and rejects the `DELETE FROM` form.
//! A soft-delete write has to be able to name the row it is marking.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has, in both directions:
//!
//!   * **A statement assembled from fragments is not seen as one
//!     statement.** A `format!` template that interpolates a `const &str`
//!     carrying the predicate reads as unfiltered — a false positive, and
//!     the fix is to put the predicate in the statement rather than to
//!     teach this guard to chase fragments. (`artifact_repo.rs`'s
//!     `list_active_for_policy` was exactly that shape and now spells its
//!     own filter.) A `QueryBuilder` assembling a statement at runtime is
//!     invisible, as is one reached through a macro. Either is a review
//!     conversation, not an exemption.
//!   * **One verdict per literal.** A statement with several `artifacts`
//!     legs that wants to filter one and include deleted rows on another
//!     cannot express that here; it would pass on the filter alone. No
//!     such statement exists today — every multi-leg literal in the
//!     corpus takes one stance for all its legs — and a mixed-stance
//!     statement arriving is a review conversation about whether it should
//!     be two statements.
//!   * A predicate spelled around the column rather than on it
//!     (`COALESCE(deleted_at, …) IS NULL`) is not recognised.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `findings_reads_are_last_scan_scoped`, `cas_reads_are_verified`,
//! `status_decode_fails_closed` and `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

mod rust_scan;
mod sql_scan;

use rust_scan::{line_of, mark_literals, walk_rust, workspace_root, LITERAL_MARK};
use sql_scan::{
    before_table_name, parse_table_name, preceding_keyword, strip_comments_and_strings, tokenize,
};

/// The table whose readers are under contract.
const TABLE: &str = "artifacts";

/// The liveness predicate, as the domain and the migration both spell it.
/// Compared against whitespace-normalised, lowercased SQL, so
/// `a.deleted_at IS NULL` and a line-wrapped spelling both match while
/// `deleted_at IS NOT NULL` — a deleted-*only* read — deliberately does
/// not.
const FILTER: &str = "deleted_at is null";

/// The opt-out declaration. An SQL comment, so it travels with the
/// statement into every log line and `EXPLAIN` a reader ever sees.
const MARKER: &str = "-- DELETED-INCLUSIVE:";

/// The soft-delete column, for the migration-side counter-assertion.
const COLUMN: &str = "deleted_at";

/// What one SQL literal does about soft-deleted rows.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// The statement's own SQL carries the liveness predicate.
    Filtered,
    /// The statement declares itself deleted-inclusive, with a reason.
    Declared,
    /// The marker is there but carries no reason — the one thing it is
    /// for. Reported separately so the message can say which half is
    /// missing.
    ReasonMissing,
    /// Neither. The finding this guard exists for.
    Undeclared,
}

/// One production SQL literal that reads [`TABLE`].
#[derive(Debug)]
struct Read {
    /// Workspace-relative path, forward slashes.
    file: String,
    /// 1-based line the literal opens on.
    line: usize,
    /// How many `FROM`/`JOIN` references to the table it carries. Pinned
    /// by the census so a leg that silently disappears is visible.
    refs: usize,
    verdict: Verdict,
}

/// True when `byte` can continue a SQL identifier.
fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// How many times `sql` names [`TABLE`] in a read position — after `FROM`
/// or `JOIN`, bare or `<schema>.`-qualified.
///
/// `DELETE FROM artifacts` is excluded: the keyword before `FROM` is what
/// tells a read apart from a targeted delete, and the only other statement
/// forms that could name the table (`INSERT INTO`, `UPDATE … SET`) carry
/// neither keyword and so never match.
///
/// Both identifier boundaries are checked. The leading one keeps
/// `my_artifacts_view` from reading as the table; the trailing one keeps
/// `artifacts_audit` from doing so, which matters because `artifacts` is a
/// plausible prefix for a future companion table.
fn table_refs(sql: &str) -> usize {
    let lower = sql.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    lower
        .match_indices(TABLE)
        .filter(|(at, _)| {
            if *at > 0 && is_ident_byte(bytes[at - 1]) {
                return false;
            }
            let after = at + TABLE.len();
            if bytes.get(after).is_some_and(|b| is_ident_byte(*b)) {
                return false;
            }
            match preceding_keyword(&lower, *at).as_deref() {
                Some("join") => true,
                Some("from") => !delete_targets_it(&lower, *at),
                _ => false,
            }
        })
        .count()
}

/// True when the `FROM` introducing the reference at `at` is a `DELETE`'s
/// own `FROM` rather than a query's.
///
/// Reached only when [`preceding_keyword`] already reported `from`, so the
/// text before the (possibly `<schema>.`-qualified) table name ends with
/// that keyword; asking what precedes *it* answers the question.
fn delete_targets_it(lower: &str, at: usize) -> bool {
    let Some(before) = before_table_name(lower, at) else {
        return false;
    };
    if !before.ends_with("from") {
        return false;
    }
    let from_at = before.len() - "from".len();
    preceding_keyword(lower, from_at).as_deref() == Some("delete")
}

/// Collapse all whitespace to single spaces so a predicate rustfmt or the
/// query's author wrapped across lines reads as one phrase.
fn normalise(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The stance `raw` — one SQL string literal, verbatim — takes.
///
/// The predicate is read from the comment-stripped text and the marker
/// from the raw text, for the reason in this module's docs.
fn classify(raw: &str) -> Verdict {
    let code = normalise(&strip_comments_and_strings(raw)).to_ascii_lowercase();
    if code.contains(FILTER) {
        return Verdict::Filtered;
    }
    match raw.find(MARKER) {
        None => Verdict::Undeclared,
        Some(at) => {
            let rest = raw[at + MARKER.len()..].lines().next().unwrap_or("").trim();
            if rest.is_empty() {
                Verdict::ReasonMissing
            } else {
                Verdict::Declared
            }
        }
    }
}

/// Every production SQL literal under `crates/*/src` that reads [`TABLE`],
/// with its verdict. Sorted so a failure message is stable.
fn collect_reads() -> Vec<Read> {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut found: Vec<Read> = Vec::new();
    walk_rust(&crates, &mut |path: &Path| {
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
        let (marked, spans) = mark_literals(&source);
        let production = rust_scan::blank_cfg_test_items(&marked);
        let production_bytes = production.as_bytes();
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for (start, end) in spans {
            // The mark survives only outside `#[cfg(test)]`.
            if production_bytes.get(start) != Some(&LITERAL_MARK) {
                continue;
            }
            let raw = &source[start..end];
            let refs = table_refs(raw);
            if refs == 0 {
                continue;
            }
            found.push(Read {
                file: rel.clone(),
                line: line_of(&source, start),
                refs,
                verdict: classify(raw),
            });
        }
    });
    found.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    found
}

// ---------------------------------------------------------------------------
// The census, measured when this guard was introduced.
// ---------------------------------------------------------------------------

/// `(file, literals, table_references, filtered, declared)` — the whole
/// corpus as it was reviewed when this guard was introduced.
///
/// Pinned per file rather than per line, and by **counts** rather than by
/// scan order: a line number moves on any edit above it and an order
/// shifts when a statement is added anywhere earlier, whereas the
/// reviewable facts are how many statements in that file read the table,
/// across how many `FROM`/`JOIN` legs, and how that splits between the two
/// stances. A statement that vanishes from the scan — because the table,
/// the keywords or the literal's shape changed — moves a count and fails
/// here rather than leaving the main assertion green over a corpus with a
/// hole in it. A stance that flips in either direction fails here too,
/// which is the point: a reader going from filtered to declared is a
/// review conversation, not an edit made on the way past.
const CENSUS: [(&str, usize, usize, usize, usize); 16] = [
    // -- the two proven defects, now filtered -----------------------------
    //
    // One literal, two legs: the `effective_policy_duration` CTE's
    // `DISTINCT repository_id` scan and the listing itself.
    (
        "crates/hort-adapters-postgres/src/curation_queue_repository.rs",
        1,
        2,
        1,
        0,
    ),
    // `select_eligible` and `select_stranded`, one literal each.
    (
        "crates/hort-adapters-postgres/src/rescan_candidates.rs",
        2,
        2,
        2,
        0,
    ),
    // -- the five readers assessed one at a time alongside them -----------
    //
    // The quarantined candidate and its released predecessor; both legs
    // are catalog reads an operator acts on.
    (
        "crates/hort-adapters-postgres/src/patch_candidate_repo.rs",
        1,
        2,
        1,
        0,
    ),
    // `get_storage_usage` — a catalog weight, so live rows only.
    (
        "crates/hort-adapters-postgres/src/repository_repo.rs",
        1,
        1,
        1,
        0,
    ),
    // The curator decision audit log: a `LEFT JOIN` reached only for the
    // `--repository` / `--package` filters, where a liveness predicate
    // would drop the decision row rather than hide the artifact.
    (
        "crates/hort-adapters-postgres/src/curation_decisions_repository.rs",
        1,
        1,
        0,
        1,
    ),
    // The purge simulation, which must see what purge sees.
    (
        "crates/hort-adapters-postgres/src/retention_preview.rs",
        1,
        1,
        0,
        1,
    ),
    // The last-scan anchor join, where an empty findings list reads as
    // "clean".
    (
        "crates/hort-adapters-postgres/src/retention_scan_reader.rs",
        1,
        1,
        0,
        1,
    ),
    // -- the rest of the corpus, by observed stance -----------------------
    //
    // Every `ArtifactRepository` statement. The three declared ones are
    // the content first-seen anchor, the name-squatting guard and the
    // verdict write's existence probe; `list_active_for_policy` and its
    // count twin used to reach the predicate through an interpolated
    // `const` and now spell it themselves (see this module's blind spots).
    // The 24th filtered statement is `package_file_digests`: a proxy index
    // serve asks it which files hort holds so it can advertise its own
    // digest for them, and a soft-deleted row is not a file hort serves.
    (
        "crates/hort-adapters-postgres/src/artifact_repo.rs",
        27,
        27,
        24,
        3,
    ),
    // `protected_claimants` is a live read (both legs); the purge worklist,
    // the pre-purge row lock and the protection-fact read taken under that
    // lock all exist to act on deleted rows. The lock and the facts are two
    // statements because a subquery answers from its own statement's
    // snapshot — see `purge_artifact_refs` — so the declaration travels
    // with both.
    ("crates/hort-adapters-postgres/src/purge_gc.rs", 4, 5, 1, 3),
    // The tag write's `FOR SHARE` on the artifact rows its target names,
    // one statement per `target_kind`. A lock, not a read: it has to cover
    // every row the purge's own deleted-inclusive `FOR UPDATE` can name.
    (
        "crates/hort-adapters-postgres/src/ref_lifecycle.rs",
        2,
        2,
        0,
        2,
    ),
    // The two refcount-drift scans filter; the repository enumeration and
    // the rejected-source edge sweep are deliberately inclusive.
    (
        "crates/hort-adapters-postgres/src/refcount_reconcile.rs",
        4,
        4,
        2,
        2,
    ),
    // The event-aggregate → repository resolver, whose module docs already
    // carried the reason; it now travels with the statement too.
    (
        "crates/hort-adapters-postgres/src/event_repository_resolver.rs",
        1,
        1,
        0,
        1,
    ),
    (
        "crates/hort-adapters-postgres/src/constituent_status.rs",
        1,
        1,
        1,
        0,
    ),
    (
        "crates/hort-adapters-postgres/src/list_deliverability.rs",
        1,
        2,
        1,
        0,
    ),
    (
        "crates/hort-adapters-postgres/src/quarantine_release_candidates.rs",
        2,
        2,
        2,
        0,
    ),
    (
        "crates/hort-adapters-postgres/src/retention_candidate_reader.rs",
        1,
        4,
        1,
        0,
    ),
];

/// The total number of literals the scan found at introduction. A floor,
/// not an equality: a new reader is expected and is already covered by the
/// main assertion, whereas a *shrinking* corpus means the scan stopped
/// seeing things. [`CENSUS`] is what pins the per-file detail.
const CENSUS_FLOOR: usize = 48;

// ---------------------------------------------------------------------------
// The property.
// ---------------------------------------------------------------------------

#[test]
fn every_live_read_of_artifacts_excludes_soft_deleted_rows() {
    let offenders: Vec<String> = collect_reads()
        .into_iter()
        .filter_map(|read| match read.verdict {
            Verdict::Filtered | Verdict::Declared => None,
            Verdict::ReasonMissing => Some(format!(
                "  - {}:{} — carries `{MARKER}` with nothing after it. The \
                 reason IS the declaration; a bare marker is an allow-list \
                 entry wearing a comment",
                read.file, read.line
            )),
            Verdict::Undeclared => Some(format!("  - {}:{}", read.file, read.line)),
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these SQL statements read `{TABLE}` without saying what they do \
         about soft-deleted rows:\n{}\n\n\
         `Artifact::deleted_at` and `migrations/021_artifacts_soft_delete.sql` \
         both state that every live read filters `{FILTER}`, and three \
         indexes are predicated on it. A reader that drops the predicate \
         surfaces rows that are no longer in the repository's served catalog \
         — and because these statements are `LIMIT`-bounded worklists, a \
         deleted row does not merely appear, it consumes a slot a real \
         candidate then does not get.\n\n\
         Add `AND <alias>.{COLUMN} IS NULL` to the statement. If this \
         reader genuinely acts ON deleted rows — retention, purge, the \
         audit log — put `{MARKER} <why>` in its SQL instead. There is no \
         allow-list in this file to add to: the reason belongs in the \
         query, where whoever reads it next will see it.",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions — the scan is answering about something.
// ---------------------------------------------------------------------------

/// The corpus is real, and is the one that was reviewed.
///
/// Without this the main assertion stays green by finding nothing: rename
/// the table, break the `FROM`/`JOIN` matcher, or change the literals'
/// shape so `mark_literals` no longer yields them, and an empty corpus
/// satisfies "every read declares its stance" trivially.
#[test]
fn the_scanned_corpus_is_real() {
    let reads = collect_reads();
    assert!(
        reads.len() >= CENSUS_FLOOR,
        "the scan found {} SQL literal(s) reading `{TABLE}`, below the {} \
         measured when this guard was written. A read that MOVED is fine — \
         update the census. A read that VANISHED means the scan no longer \
         sees it, and the main assertion is answering about a corpus with a \
         hole in it. Census: {:#?}",
        reads.len(),
        CENSUS_FLOOR,
        per_file(&reads)
    );

    let census = per_file(&reads);
    for (file, literals, refs, filtered, declared) in CENSUS {
        let found = census.get(file).unwrap_or_else(|| {
            panic!("no `{TABLE}` read found in {file} at all; census {census:#?}")
        });
        let observed = (
            found.len(),
            found.iter().map(|r| r.refs).sum::<usize>(),
            found
                .iter()
                .filter(|r| r.verdict == Verdict::Filtered)
                .count(),
            found
                .iter()
                .filter(|r| r.verdict == Verdict::Declared)
                .count(),
        );
        assert_eq!(
            observed,
            (literals, refs, filtered, declared),
            "{file} was reviewed as {literals} literal(s) reading `{TABLE}` \
             across {refs} `FROM`/`JOIN` leg(s), {filtered} filtered and \
             {declared} declared deleted-inclusive; the scan now sees \
             {found:#?}. A statement that moved or was added is fine — \
             update the census after reading its stance. A statement whose \
             stance CHANGED, or one that vanished, is the review \
             conversation this list exists to force"
        );
    }
}

/// The two corrected defects' statements are seen, and seen as filtered.
///
/// [`the_scanned_corpus_is_real`] already pins their verdicts, but it
/// would be satisfied by a census this file had been edited to match. This
/// states the fix itself: the predicate is in those literals' **code**,
/// which is the only thing that makes the main assertion's `Filtered`
/// verdict mean the query filters rather than discusses filtering.
#[test]
fn the_corrected_defects_carry_the_predicate_in_their_sql() {
    let corrected = [
        "crates/hort-adapters-postgres/src/curation_queue_repository.rs",
        "crates/hort-adapters-postgres/src/rescan_candidates.rs",
        "crates/hort-adapters-postgres/src/patch_candidate_repo.rs",
    ];
    let reads = collect_reads();
    let mut checked = 0usize;
    for read in &reads {
        if !corrected.contains(&read.file.as_str()) {
            continue;
        }
        let raw = literal_at(&read.file, read.line);
        let code = normalise(&strip_comments_and_strings(&raw)).to_ascii_lowercase();
        // One occurrence per leg: a single predicate cannot cover two
        // independently-aliased references to the table.
        assert_eq!(
            code.matches(FILTER).count(),
            read.refs,
            "{}:{} reads `{TABLE}` {} time(s) but carries {} `{FILTER}` \
             predicate(s) — each leg needs its own",
            read.file,
            read.line,
            read.refs,
            code.matches(FILTER).count()
        );
        checked += 1;
    }
    assert_eq!(
        checked, 4,
        "expected to check the 4 corrected statements (the curation queue's \
         listing with its CTE, both rescan sweeps, the patch-candidate \
         listing); checked {checked}"
    );
}

/// Removing the predicate from any corrected statement trips the guard.
///
/// The main assertion's value rests entirely on this: a classifier that
/// said `Filtered` for everything would pass every test above. Here the
/// real SQL of every corrected statement is taken, the predicate stripped
/// out of it, and the verdict required to flip.
#[test]
fn stripping_the_predicate_from_a_corrected_statement_trips_the_guard() {
    let corrected = [
        "crates/hort-adapters-postgres/src/curation_queue_repository.rs",
        "crates/hort-adapters-postgres/src/rescan_candidates.rs",
        "crates/hort-adapters-postgres/src/patch_candidate_repo.rs",
    ];
    let mut flipped = 0usize;
    for read in collect_reads() {
        if !corrected.contains(&read.file.as_str()) {
            continue;
        }
        let raw = literal_at(&read.file, read.line);
        let stripped = strip_filter(&raw);
        assert_ne!(
            stripped, raw,
            "{}:{} — nothing was stripped, so this check proves nothing",
            read.file, read.line
        );
        assert_eq!(
            classify(&stripped),
            Verdict::Undeclared,
            "{}:{} still classifies as filtered with every `{FILTER}` \
             removed — the classifier is not reading what it claims to",
            read.file,
            read.line
        );
        flipped += 1;
    }
    assert_eq!(flipped, 4, "expected 4 corrected statements, saw {flipped}");
}

/// At least one statement passes through the marker, not the predicate.
///
/// The marker path is the half an allow-list would replace, so it has to
/// be load-bearing in the real corpus and not merely implemented.
#[test]
fn the_marker_path_is_exercised_by_real_statements() {
    let declared: Vec<String> = collect_reads()
        .iter()
        .filter(|r| r.verdict == Verdict::Declared)
        .map(|r| format!("{}:{}", r.file, r.line))
        .collect();
    let expected: usize = CENSUS.iter().map(|entry| entry.4).sum();
    assert_eq!(
        declared.len(),
        expected,
        "{expected} production statement(s) were reviewed as reaching their \
         verdict through `{MARKER}` and {} do. The marker path is the half \
         an allow-list would otherwise be, so it has to stay load-bearing \
         in the real corpus rather than merely implemented: zero here means \
         either the marker is spelled differently in the SQL now, or the \
         deliberate deleted-inclusive readers (retention, purge, the audit \
         log) stopped declaring themselves. Declared: {declared:#?}",
        declared.len()
    );
}

/// The column the whole property is about still exists in the schema.
///
/// A guard that demands `{FILTER}` of every reader is nonsense if the
/// column was dropped — the readers would not compile, but the scan would
/// keep passing on the files that still carry the string. Asserted
/// token-wise against the migration that adds it, so a reformat of that
/// file cannot break it and a comment mentioning it cannot satisfy it.
#[test]
fn the_column_still_exists() {
    let dir = workspace_root().join("migrations");
    let mut found_in: Option<String> = None;
    let entries = std::fs::read_dir(&dir).expect("migrations/ exists under the workspace root");
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    paths.sort();
    for path in paths {
        let Ok(sql) = std::fs::read_to_string(&path) else {
            continue;
        };
        let tokens = tokenize(&strip_comments_and_strings(&sql));
        for at in 0..tokens.len() {
            if tokens[at].text != "alter"
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
            let adds_column = tokens.get(next).map(|t| t.text.as_str()) == Some("add")
                && tokens.get(next + 1).map(|t| t.text.as_str()) == Some("column")
                && tokens.get(next + 2).map(|t| t.text.as_str()) == Some(COLUMN);
            if adds_column {
                found_in = Some(
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into(),
                );
            }
        }
    }
    assert!(
        found_in.is_some(),
        "no migration adds `{TABLE}.{COLUMN}`. This guard requires every \
         reader of `{TABLE}` to filter on a column that no longer exists, \
         which makes its green verdict meaningless. If soft delete was \
         replaced, this guard and the `Artifact::{COLUMN}` doc comment are \
         what have to change with it"
    );
    // Named rather than merely counted: a second migration adding the
    // same column would mean the first one's `ADD COLUMN` was undone
    // somewhere in between, which is a different schema history than the
    // one this guard's reasoning rests on.
    assert_eq!(
        found_in.as_deref(),
        Some("021_artifacts_soft_delete.sql"),
        "`{TABLE}.{COLUMN}` is added by a migration other than the one \
         whose header states the invariant this guard enforces"
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's and classifier's behaviour.
// ---------------------------------------------------------------------------

#[test]
fn the_matcher_counts_reads_and_only_reads() {
    assert_eq!(table_refs("SELECT 1 FROM artifacts WHERE id = $1"), 1);
    assert_eq!(table_refs("select 1 from artifacts a"), 1);
    assert_eq!(table_refs("SELECT 1 FROM public.artifacts a"), 1);
    assert_eq!(table_refs("JOIN artifacts v ON v.id = q.id"), 1);
    assert_eq!(table_refs("JOIN  public.artifacts"), 1);
    assert_eq!(table_refs("SELECT 1\n  FROM\n    artifacts"), 1);
    // Two legs, two references — what makes the per-leg predicate count
    // in `the_corrected_defects_carry_the_predicate_in_their_sql` real.
    assert_eq!(
        table_refs("FROM artifacts q JOIN artifacts v ON v.name = q.name"),
        2
    );

    // Writes.
    assert_eq!(table_refs("INSERT INTO artifacts (id) VALUES ($1)"), 0);
    assert_eq!(table_refs("INSERT INTO public.artifacts (id)"), 0);
    assert_eq!(table_refs("UPDATE artifacts SET deleted_at = now()"), 0);
    assert_eq!(table_refs("DELETE FROM artifacts WHERE id = $1"), 0);
    assert_eq!(table_refs("delete from public.artifacts where id = $1"), 0);

    // Not a table reference at all.
    assert_eq!(table_refs("artifacts"), 0);
    assert_eq!(table_refs("the artifacts projection"), 0);
    // Identifier boundaries, both sides.
    assert_eq!(table_refs("FROM my_artifacts_view"), 0);
    assert_eq!(table_refs("FROM artifacts_audit a"), 0);
    assert_eq!(table_refs("JOIN artifact_metadata am"), 0);
    assert_eq!(table_refs("FROM artifact_groups g"), 0);
}

#[test]
fn the_classifier_accepts_the_predicate() {
    assert_eq!(
        classify("SELECT 1 FROM artifacts a WHERE a.deleted_at IS NULL"),
        Verdict::Filtered
    );
    // Case and line wrapping are not part of the predicate.
    assert_eq!(
        classify("select 1 from artifacts a where a.deleted_at\n   is   null"),
        Verdict::Filtered
    );
}

/// A deleted-*only* read is not a filtered read. `IS NOT NULL` selects
/// exactly the rows the invariant is about, so it has to declare itself
/// like any other inclusive reader.
#[test]
fn the_classifier_does_not_read_is_not_null_as_the_filter() {
    assert_eq!(
        classify("SELECT 1 FROM artifacts a WHERE a.deleted_at IS NOT NULL"),
        Verdict::Undeclared
    );
}

/// The shape the real corpus is full of: prose about the predicate sitting
/// in the same statement that lacks it. A classifier that read comments
/// would be satisfied by the marker's own reason text.
#[test]
fn the_classifier_is_not_satisfied_by_a_comment_naming_the_predicate() {
    assert_eq!(
        classify(
            "SELECT 1 FROM artifacts a\n\
             -- Deliberately no `deleted_at IS NULL` here.\n\
             WHERE a.id = $1"
        ),
        Verdict::Undeclared
    );
    assert_eq!(
        classify(
            "SELECT 1 FROM artifacts a\n\
             /* deleted_at IS NULL would be wrong for this read */\n\
             WHERE a.id = $1"
        ),
        Verdict::Undeclared
    );
}

/// A SQL *value* that happens to spell the predicate is not a predicate
/// either — the shape `no_sensitive_drops` had to get right for
/// `information_schema` probes.
#[test]
fn the_classifier_is_not_satisfied_by_a_string_literal_naming_the_predicate() {
    assert_eq!(
        classify("SELECT 'deleted_at IS NULL' AS note FROM artifacts a"),
        Verdict::Undeclared
    );
}

#[test]
fn the_classifier_accepts_the_marker_with_a_reason() {
    assert_eq!(
        classify(
            "SELECT 1 FROM artifacts a\n\
             -- DELETED-INCLUSIVE: purge acts on deleted rows; this IS the\n\
             -- worklist that collects them.\n\
             WHERE a.id = $1"
        ),
        Verdict::Declared
    );
}

/// The reason is the declaration. A bare marker is an allow-list entry in
/// disguise and is reported as its own kind of finding.
#[test]
fn the_classifier_rejects_a_bare_marker() {
    assert_eq!(
        classify("SELECT 1 FROM artifacts a\n-- DELETED-INCLUSIVE:\nWHERE a.id = $1"),
        Verdict::ReasonMissing
    );
    assert_eq!(
        classify("SELECT 1 FROM artifacts a\n-- DELETED-INCLUSIVE:   \nWHERE a.id = $1"),
        Verdict::ReasonMissing
    );
}

/// Literal scoping, which is the rule this guard is built around: a
/// neighbour's declaration does not reach this statement. Two literals,
/// judged apart.
#[test]
fn a_neighbours_declaration_does_not_cover_the_next_statement() {
    let declared = "SELECT 1 FROM artifacts a\n-- DELETED-INCLUSIVE: the purge worklist.\n";
    let bare = "SELECT 2 FROM artifacts b WHERE b.id = $1";
    assert_eq!(classify(declared), Verdict::Declared);
    assert_eq!(classify(bare), Verdict::Undeclared);
    // Concatenated — i.e. ONE literal — the declaration would cover both,
    // which is exactly why the unit of judgement is the literal and the
    // census pins how many legs each one has.
    assert_eq!(
        classify(&format!("{declared}{bare}")),
        Verdict::Declared,
        "one literal takes one stance; see this module's blind spots"
    );
}

#[test]
fn a_statement_that_does_not_read_the_table_is_not_in_the_corpus() {
    assert_eq!(table_refs("SELECT 1 FROM repositories r"), 0);
    assert_eq!(table_refs("SELECT 1 FROM scan_findings sf"), 0);
}

// ---------------------------------------------------------------------------
// Helpers for the counter-assertions above.
// ---------------------------------------------------------------------------

/// The scan's findings grouped by file, in scan order within each file.
fn per_file(reads: &[Read]) -> BTreeMap<String, Vec<&Read>> {
    let mut out: BTreeMap<String, Vec<&Read>> = BTreeMap::new();
    for read in reads {
        out.entry(read.file.clone()).or_default().push(read);
    }
    out
}

/// The verbatim text of the string literal opening on `line` of `file`.
///
/// `collect_reads` keeps only what the verdict needs; the checks that
/// re-derive a verdict from the real SQL need the literal itself.
fn literal_at(file: &str, line: usize) -> String {
    let path = workspace_root().join(file);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (_, spans) = mark_literals(&source);
    spans
        .iter()
        .find(|(start, _)| line_of(&source, *start) == line)
        .map(|(start, end)| source[*start..*end].to_string())
        .unwrap_or_else(|| panic!("no string literal opens on {file}:{line}"))
}

/// Every spelling of [`FILTER`] removed from `sql`, whatever the alias,
/// the case or the internal whitespace.
///
/// Works on the normalised text and maps the cut back onto the original by
/// cutting the same token run, so the result is still the statement minus
/// its predicate rather than a reflowed copy of it.
fn strip_filter(sql: &str) -> String {
    let mut words: Vec<&str> = sql.split_whitespace().collect();
    let needle: Vec<&str> = FILTER.split_whitespace().collect();
    let mut at = 0usize;
    while at + needle.len() <= words.len() {
        let window = &words[at..at + needle.len()];
        let matches = window
            .iter()
            .zip(&needle)
            .enumerate()
            .all(|(idx, (word, want))| {
                let lower = word.to_ascii_lowercase();
                // The column may carry an alias prefix (`a.deleted_at`).
                if idx == 0 {
                    lower == *want || lower.ends_with(&format!(".{want}"))
                } else {
                    lower == *want
                }
            });
        if matches {
            words.drain(at..at + needle.len());
        } else {
            at += 1;
        }
    }
    words.join(" ")
}
