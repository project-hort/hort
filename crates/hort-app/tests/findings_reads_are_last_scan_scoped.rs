//! Structural guard: **every SQL statement that reads `scan_findings`
//! scopes itself to the artifact's last scan.**
//!
//! `scan_findings` is per-scan history. Every scan run writes its rows
//! under a fresh `scan_id` and nothing removes the previous run's, which
//! is intended — the table is append-only evidence. The consequence is
//! that a read filtered on `artifact_id` alone answers about *every scan
//! the artifact ever had*, and its numbers grow with the rescan count.
//! Three readers were written that way and all three were wrong:
//!
//!   * the curation queue's `finding_count` / `max_severity`,
//!   * the patch-candidate listing, which also **orders by** them, and
//!   * the retention evaluator's findings read, whose predicate appends
//!     `ArtifactExpired` — a read that drives a deletion.
//!
//! Meanwhile the release verdict derivation (`scan_history::last_findings`)
//! consults the newest scan and only the newest. So the system already had
//! a position on which scan counts, and three projections contradicted it.
//!
//! Three sites out of three got it wrong, which is the signal that
//! convention does not hold this. Nothing in the compiler stops a fourth
//! reader from being added with the same shape; the column it would need
//! to mention is not one the type system can require. Hence the scan.
//!
//! ## The property
//!
//! Across the production Rust of every crate, a SQL statement that names
//! `scan_findings` after `FROM` or `JOIN` also names [`ANCHOR_COLUMN`].
//!
//! `artifacts.last_scan_at` is the anchor because it is the only thing in
//! the schema that carries the scan's *identity* rather than the presence
//! of its findings:
//! `PgArtifactLifecycle::commit_scan_result_with_score` writes that column
//! and inserts the per-finding rows in ONE transaction, from the same
//! `DateTime<Utc>` the rows carry as `detected_at`. An anchor taken from
//! inside `scan_findings` — the newest `scan_id` present, the `MAX`
//! `detected_at` — cannot work: a scan that found nothing writes no row,
//! so such an anchor hands back the previous, dirty run for an artifact
//! that has since come clean. That is the same defect, quieter.
//!
//! The counter-assertions below pin that pairing in
//! [`PAIRING_FILE`], so a future change that splits the two writes apart
//! — or stops making them from one timestamp — fails here rather than
//! silently emptying every last-scan-scoped read in the system.
//!
//! ## Scope — derived, not enumerated
//!
//! Every `crates/*/src` tree, because the question is "does any
//! production SQL in this workspace read this table without the anchor"
//! and the answer must not depend on which crate someone put the query
//! in. `#[cfg(test)]` items are excluded by how they are compiled rather
//! than by an entry: a fixture that counts rows across the whole history
//! is asserting about the history, which is a legitimate thing for a test
//! to do. `migrations/` is out of scope — it creates the table, it does
//! not read it.
//!
//! **No allow-list.** A production read that genuinely wants the whole
//! history is a review conversation, not an exemption entry: it would be
//! the first one, and the reason would belong in that file's docs.
//!
//! ## Blind spots
//!
//! The one every source scan has. A statement assembled across more than
//! one string literal (`QueryBuilder`, `format!` over fragments) is not
//! seen as one statement, so the anchor could sit in a fragment this scan
//! reads separately — or be missing from one it never joins. A read in a
//! crate outside `crates/*/src`, or reached through a macro, is invisible
//! the same way. The review check survives alongside this guard.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

mod rust_scan;
mod sql_scan;

use rust_scan::{line_of, mark_literals, walk_rust, workspace_root, LITERAL_MARK};
use sql_scan::preceding_keyword;

/// The column a `scan_findings` read must name to be scoped to one scan.
const ANCHOR_COLUMN: &str = "last_scan_at";

/// The column on the findings side of the comparison. Named separately so
/// a counter-assertion can require the known reads to compare *something*
/// against the anchor rather than merely mention the word.
const FINDINGS_COLUMN: &str = "detected_at";

/// The file whose single transaction makes the anchor true: it writes
/// `artifacts.last_scan_at` and inserts the per-finding rows together.
const PAIRING_FILE: &str = "crates/hort-adapters-postgres/src/artifact_lifecycle.rs";

/// The two halves of that pairing, as they are spelled in [`PAIRING_FILE`],
/// and the method whose one transaction has to hold both.
const PAIRING_WRITE: &str = "UPDATE artifacts SET last_scan_at";
const PAIRING_INSERT: &str = "insert_findings_in_tx";
const COMMIT_FN: &str = "commit_scan_result_with_score";

/// The production reads this guard knows about, by repo-relative path.
/// A counter-assertion requires the scan to still find exactly these, so
/// renaming the table, the files, or the SQL keywords cannot make the
/// property vacuously true.
const KNOWN_READS: [(&str, usize); 3] = [
    // The curator worklist's finding summary.
    (
        "crates/hort-adapters-postgres/src/curation_queue_repository.rs",
        1,
    ),
    // The patch-candidate listing, which ranks on that summary.
    (
        "crates/hort-adapters-postgres/src/patch_candidate_repo.rs",
        1,
    ),
    // The retention evaluator's findings read.
    (
        "crates/hort-adapters-postgres/src/retention_scan_reader.rs",
        1,
    ),
];

/// One SQL string literal that reads `scan_findings`.
struct Read {
    file: String,
    line: usize,
    sql: String,
}

/// True when `sql` names `scan_findings` as a table being read — i.e.
/// after `FROM` or `JOIN`, rather than after `INTO` (`INSERT INTO
/// scan_findings`, the one production write, which is not in scope).
///
/// Both the bare and the schema-qualified spellings count: the seeders and
/// the migrations write `public.scan_findings`, and a reader in that style
/// must not slip past.
fn reads_the_table(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    lower.match_indices("scan_findings").any(|(at, _)| {
        matches!(
            preceding_keyword(&lower, at).as_deref(),
            Some("from") | Some("join")
        )
    })
}

/// Every production SQL literal in the workspace's crates that reads
/// `scan_findings`.
fn collect_reads() -> Vec<Read> {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut found = Vec::new();
    walk_rust(&crates, &mut |path: &Path| {
        // Only `src` trees: a `tests/` target is test code by construction,
        // the same way a `#[cfg(test)]` item is.
        if !path.components().any(|c| c.as_os_str() == "src") {
            return;
        }
        let Ok(source) = std::fs::read_to_string(path) else {
            return;
        };
        if !source.contains("scan_findings") {
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
            let sql = &source[start..end];
            if !reads_the_table(sql) {
                continue;
            }
            found.push(Read {
                file: rel.clone(),
                line: line_of(&source, start),
                sql: sql.to_string(),
            });
        }
    });
    found
}

#[test]
fn every_findings_read_scopes_to_the_last_scan() {
    let offenders: Vec<String> = collect_reads()
        .iter()
        .filter(|r| !r.sql.contains(ANCHOR_COLUMN))
        .map(|r| format!("  - {}:{}", r.file, r.line))
        .collect();

    assert!(
        offenders.is_empty(),
        "these SQL statements read `scan_findings` without scoping to the \
         artifact's last scan (no `{ANCHOR_COLUMN}`):\n{}\n\n\
         `scan_findings` is per-scan history — every run writes under a \
         fresh `scan_id` and nothing removes the previous run's rows — so \
         a read filtered on `artifact_id` alone answers about every scan \
         the artifact ever had, and its numbers grow with the rescan \
         count. The release verdict derivation consults the newest scan \
         and only the newest; a projection that disagrees mis-reports a \
         curator worklist at best and drives a retention deletion on a \
         retracted vulnerability at worst.\n\n\
         The fix is to compare `scan_findings.{FINDINGS_COLUMN}` against \
         the scanned artifact's `artifacts.{ANCHOR_COLUMN}`. Do NOT anchor \
         inside `scan_findings` (newest `scan_id`, `MAX({FINDINGS_COLUMN})`) \
         — a scan that found nothing writes no row, so such an anchor \
         returns the previous dirty run for an artifact that has since \
         come clean.",
        offenders.join("\n")
    );
}

/// Counter-assertion: the scan still finds the reads it is about.
///
/// Every predicate here is one a rename could quietly break — the table
/// name, the SQL keywords, the file paths. Without this the guard above
/// stays green by finding nothing at all.
#[test]
fn the_scanned_corpus_is_real() {
    let reads = collect_reads();
    assert!(
        !reads.is_empty(),
        "no production SQL read of `scan_findings` was found at all — the \
         scan is vacuous; check the table name, the FROM/JOIN matcher and \
         the `crates/*/src` scope"
    );

    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    for read in &reads {
        *per_file.entry(read.file.clone()).or_default() += 1;
    }
    for (file, expected) in KNOWN_READS {
        assert_eq!(
            per_file.get(file).copied().unwrap_or(0),
            expected,
            "expected {expected} `scan_findings` read(s) in {file}; the \
             per-file census is {per_file:?}. A read that moved is fine — \
             update this list. A read that vanished means the scan no \
             longer sees it."
        );
    }

    // Each known read must actually COMPARE something: naming the anchor
    // column in a comment would satisfy the guard above on its own.
    for read in &reads {
        assert!(
            read.sql.contains(FINDINGS_COLUMN),
            "{}:{} names `{ANCHOR_COLUMN}` but not `{FINDINGS_COLUMN}` — \
             the anchor is an equality between the two columns, not a \
             mention of one",
            read.file,
            read.line
        );
    }
}

/// Counter-assertion: the pairing the anchor rests on is still a single
/// transaction.
///
/// `artifacts.last_scan_at` is only a usable anchor because the lifecycle
/// adapter writes it and inserts the per-finding rows together, from one
/// timestamp. Split those apart and every read above still looks correct
/// while matching no row — which reads as "every artifact is clean",
/// including a rejected one. `hort-app`'s
/// `scan_rows_carry_the_last_scan_at_they_commit_with_*` tests pin the
/// "one timestamp" half; this pins the "one place" half.
#[test]
fn the_anchor_is_written_with_the_rows_it_anchors() {
    let path = workspace_root().join(PAIRING_FILE);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (marked, spans) = mark_literals(&source);
    let production = rust_scan::blank_cfg_test_items(&marked);
    let production_bytes = production.as_bytes();

    // The `UPDATE` lives in a string literal; the call does not. Check
    // each against the text it is actually in.
    let anchor_write_in_production = spans.iter().any(|(start, end)| {
        production_bytes.get(*start) == Some(&LITERAL_MARK)
            && source[*start..*end].contains(PAIRING_WRITE)
    });
    assert!(
        anchor_write_in_production,
        "{PAIRING_FILE} no longer contains `{PAIRING_WRITE}` in production \
         code. Three SQL readers select an artifact's last scan by \
         comparing `scan_findings.{FINDINGS_COLUMN}` against this column; \
         if it is written somewhere else now, the anchor's atomicity \
         argument has to be re-made there."
    );
    assert!(
        production.contains(PAIRING_INSERT),
        "{PAIRING_FILE} no longer calls `{PAIRING_INSERT}`. The anchor is \
         sound because the `{ANCHOR_COLUMN}` write and the per-finding \
         insert share one transaction; they have to stay in one place for \
         that to keep being checkable."
    );

    // And the two have to be in the SAME function, not merely the same
    // file — a write moved into a sibling method is a different
    // transaction. `parse_fns` gives the function's own body for the code
    // half and, with the next item's line, its line range for the SQL
    // half (the SQL is inside a literal, which the lexer the parser needs
    // has already blanked).
    let fns = rust_scan::parse_fns(&production);
    let at = fns
        .iter()
        .position(|f| f.name == COMMIT_FN)
        .unwrap_or_else(|| panic!("{PAIRING_FILE} no longer defines `{COMMIT_FN}`"));
    assert!(
        fns[at].body.contains(PAIRING_INSERT),
        "`{PAIRING_INSERT}` is no longer called inside `{COMMIT_FN}` — the \
         single transaction is what makes the `{ANCHOR_COLUMN}` anchor \
         agree with the rows it selects"
    );

    let body_from = fns[at].line;
    let body_to = fns.get(at + 1).map_or(usize::MAX, |next| next.line);
    let write_line = spans
        .iter()
        .filter(|(start, end)| {
            production_bytes.get(*start) == Some(&LITERAL_MARK)
                && source[*start..*end].contains(PAIRING_WRITE)
        })
        .map(|(start, _)| line_of(&source, *start))
        .next()
        .expect("the anchor write was located above");
    assert!(
        write_line > body_from && write_line < body_to,
        "the `{ANCHOR_COLUMN}` write is on line {write_line}, outside \
         `{COMMIT_FN}`'s body (lines {body_from}..{body_to}) — it has to \
         share that function's transaction with `{PAIRING_INSERT}`"
    );
}

/// The matcher itself, against the spellings it has to tell apart. A
/// predicate this guard's whole verdict rests on is worth its own test:
/// `reads_the_table` silently answering `false` is how a scan goes
/// vacuous in a way the census counter-assertion would only catch for the
/// three reads it already knows about.
#[test]
fn the_read_matcher_distinguishes_reads_from_writes() {
    assert!(reads_the_table("FROM scan_findings sf WHERE x"));
    assert!(reads_the_table("from scan_findings"));
    assert!(reads_the_table("JOIN scan_findings sf ON true"));
    assert!(reads_the_table("FROM public.scan_findings sf"));
    assert!(reads_the_table("JOIN  public.scan_findings"));
    assert!(reads_the_table("SELECT 1\n  FROM\n    scan_findings"));

    assert!(!reads_the_table("INSERT INTO scan_findings (artifact_id)"));
    assert!(!reads_the_table(
        "INSERT INTO public.scan_findings (artifact_id)"
    ));
    assert!(!reads_the_table("scan_findings"));
    // A longer identifier that merely contains the table name.
    assert!(!reads_the_table("FROM my_scan_findings_view"));
    // A prose mention, which is what a SQL-free literal would carry.
    assert!(!reads_the_table("the scan_findings projection"));
}
