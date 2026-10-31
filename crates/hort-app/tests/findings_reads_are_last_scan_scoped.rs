//! Structural guard: **every SQL statement that reads `scan_findings`
//! scopes itself to the artifact's last scan, or says in that statement
//! why it cannot.**
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
//! `scan_findings` after `FROM` or `JOIN` either names [`ANCHOR_COLUMN`]
//! in its own code, or declares itself history-wide with
//! [`MARKER`] **and a reason**, in that same statement.
//!
//! The declaration is not an exemption list and is deliberately not one.
//! It is the form the sibling guard `live_reads_exclude_deleted` already
//! uses for the same shape of question, and it has the same two
//! properties: the verdict is **per literal**, so a statement added
//! beside a declared one is not covered by its neighbour's reason, and
//! the reason is mandatory, so a bare marker fails. There is no
//! allow-list keyed on a file or a function — a read that genuinely
//! wants the whole history says so where it stands, in an SQL comment
//! that travels with it into every log line and `EXPLAIN` a reader ever
//! sees.
//!
//! **What the declaration is for, and what it is not for.** The three
//! readers above *count and rank*: `finding_count`, `max_severity`, and
//! the orderings over them. Those numbers are wrong when they are summed
//! across scans, and no reason makes them right — a declaration on one
//! of them is a bug wearing a comment. A read that *dates* a named
//! `vulnerability_id` and counts nothing is a different question, and
//! the last-scan anchor does not merely narrow it but destroys it: every
//! row of one scan carries that scan's `detected_at`, so a
//! last-scan-scoped `MIN(detected_at)` answers "when was the last scan".
//! Such a read is safe for the reason the anchor exists — a vulnerability
//! a later scan no longer reports must drive no retention decision —
//! only because its caller keys it on the ids the **last** scan
//! reported, so a retracted vulnerability is never asked about. That
//! keying is what a reviewer reads the declared reason to check.
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
//! history declares itself at the statement, with the reason; there is
//! no entry anywhere in this file that excuses a file, a function or a
//! query by name.
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
use sql_scan::{preceding_keyword, strip_comments_and_strings};

/// The column a `scan_findings` read must name to be scoped to one scan.
const ANCHOR_COLUMN: &str = "last_scan_at";

/// The opt-out declaration, for a read whose question the last-scan
/// anchor cannot express. An SQL comment, so it travels with the
/// statement; mandatory reason, because the reason IS the declaration.
const MARKER: &str = "-- HISTORY-WIDE:";

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

/// The production reads this guard knows about, by repo-relative path,
/// with the per-file count. A counter-assertion requires the scan to
/// still find exactly these, so renaming the table, the files, or the
/// SQL keywords cannot make the property vacuously true.
///
/// This is a **census**, not an allow-list: every entry still has to
/// satisfy the property on its own, and a file listed here with the
/// wrong verdict fails the test above exactly as an unlisted one would.
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
    // The retention evaluator's findings read, and beside it the
    // first-observation read that dates one named vulnerability across
    // scans (declared, see `KNOWN_DECLARED`).
    (
        "crates/hort-adapters-postgres/src/retention_scan_reader.rs",
        2,
    ),
];

/// The declared history-wide reads, by repo-relative path and count.
/// Pinned so a declaration that spreads to a second statement — or a
/// read that quietly acquires one — is visible here rather than only in
/// a diff.
const KNOWN_DECLARED: [(&str, usize); 1] = [(
    "crates/hort-adapters-postgres/src/retention_scan_reader.rs",
    1,
)];

/// What one SQL literal does about the per-scan history it is reading.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// The statement's own code names the last-scan anchor.
    Scoped,
    /// The statement declares itself history-wide, with a reason.
    Declared,
    /// The marker is there but carries no reason — the one thing it is
    /// for. Reported separately so the message can say which half is
    /// missing.
    ReasonMissing,
    /// Neither. The finding this guard exists for.
    Undeclared,
}

/// One SQL string literal that reads `scan_findings`.
struct Read {
    file: String,
    line: usize,
    sql: String,
    verdict: Verdict,
}

/// Whitespace-collapse, so a line-wrapped `sf.detected_at =\n
/// a.last_scan_at` reads the same as a one-line spelling.
fn normalise(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The stance `raw` — one SQL string literal, verbatim — takes.
///
/// The anchor is read from the **comment-stripped** text and the marker
/// from the raw text. A statement that merely *mentions* `last_scan_at`
/// in a comment explaining why it does not use it would otherwise pass
/// the property by talking about it, which is how this guard goes quietly
/// vacuous; the three known reads all name the anchor in their code and
/// are unaffected.
fn classify(raw: &str) -> Verdict {
    let code = normalise(&strip_comments_and_strings(raw)).to_ascii_lowercase();
    if code.contains(ANCHOR_COLUMN) {
        return Verdict::Scoped;
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
                verdict: classify(sql),
            });
        }
    });
    found
}

#[test]
fn every_findings_read_scopes_to_the_last_scan() {
    let reads = collect_reads();
    let offenders: Vec<String> = reads
        .iter()
        .filter(|r| r.verdict == Verdict::Undeclared)
        .map(|r| format!("  - {}:{}", r.file, r.line))
        .collect();

    assert!(
        offenders.is_empty(),
        "these SQL statements read `scan_findings` without scoping to the \
         artifact's last scan (no `{ANCHOR_COLUMN}`) and without \
         declaring themselves history-wide:\n{}\n\n\
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
         come clean.\n\n\
         If — and only if — the read asks a question the last-scan anchor \
         cannot express (it DATES a named `vulnerability_id` across scans \
         and counts nothing), declare it in the statement with \
         `{MARKER} <reason>`, and make the reason say what bounds the \
         history it reads. A counting or ranking read is never this case.",
        offenders.join("\n")
    );

    let bare: Vec<String> = reads
        .iter()
        .filter(|r| r.verdict == Verdict::ReasonMissing)
        .map(|r| format!("  - {}:{}", r.file, r.line))
        .collect();
    assert!(
        bare.is_empty(),
        "these SQL statements carry `{MARKER}` with no reason after \
         it:\n{}\n\n\
         The reason IS the declaration; a bare marker is an allow-list \
         entry spelled as a comment. Say what question the read is \
         asking and what bounds the history it reads.",
        bare.join("\n")
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

    // Each SCOPED read must actually COMPARE something: the anchor is an
    // equality between two columns, and a read naming only one of them
    // is not scoped by anything.
    for read in reads.iter().filter(|r| r.verdict == Verdict::Scoped) {
        assert!(
            read.sql.contains(FINDINGS_COLUMN),
            "{}:{} names `{ANCHOR_COLUMN}` but not `{FINDINGS_COLUMN}` — \
             the anchor is an equality between the two columns, not a \
             mention of one",
            read.file,
            read.line
        );
    }

    // And the declared reads are pinned by file and count, so a
    // declaration spreading to a second statement is visible here.
    let mut declared: BTreeMap<String, usize> = BTreeMap::new();
    for read in reads.iter().filter(|r| r.verdict == Verdict::Declared) {
        *declared.entry(read.file.clone()).or_default() += 1;
    }
    let expected: BTreeMap<String, usize> = KNOWN_DECLARED
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        declared, expected,
        "the set of history-wide-declared `scan_findings` reads changed. \
         Each one opts out of the property this guard exists for, so a \
         new entry is a review conversation about whether its question \
         really cannot be asked within one scan — not a list to top up."
    );
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
/// The classifier itself, against the spellings it has to tell apart.
/// Every verdict this guard can reach is exercised here, because a
/// `classify` that silently answered `Scoped` for everything would make
/// the property vacuous in a way the census above cannot see.
#[test]
fn the_classifier_separates_scoped_declared_and_bare() {
    assert_eq!(
        classify(
            "SELECT 1 FROM scan_findings sf JOIN artifacts a ON a.id = sf.artifact_id \
                  WHERE sf.detected_at = a.last_scan_at"
        ),
        Verdict::Scoped
    );
    // Line-wrapped, which is how the real statements are written.
    assert_eq!(
        classify("SELECT 1 FROM scan_findings sf\n  WHERE sf.detected_at =\n    a.last_scan_at"),
        Verdict::Scoped
    );
    assert_eq!(
        classify(
            "SELECT MIN(sf.detected_at) FROM scan_findings sf\n\
                  -- HISTORY-WIDE: dates one named vulnerability; the ids\n\
                  -- come from the last scan, so a retracted one is never\n\
                  -- asked about.\n\
                  WHERE sf.artifact_id = $1"
        ),
        Verdict::Declared
    );
    assert_eq!(
        classify("SELECT 1 FROM scan_findings\n-- HISTORY-WIDE:\nWHERE artifact_id = $1"),
        Verdict::ReasonMissing,
        "the reason IS the declaration"
    );
    assert_eq!(
        classify("SELECT 1 FROM scan_findings\n-- HISTORY-WIDE:   \nWHERE artifact_id = $1"),
        Verdict::ReasonMissing
    );
    assert_eq!(
        classify("SELECT count(*) FROM scan_findings WHERE artifact_id = $1"),
        Verdict::Undeclared
    );
    // Naming the anchor only in a comment is talking about the property,
    // not satisfying it.
    assert_eq!(
        classify(
            "SELECT 1 FROM scan_findings\n\
             -- unlike the others this one ignores last_scan_at\n\
             WHERE artifact_id = $1"
        ),
        Verdict::Undeclared
    );
}

/// A neighbour's declaration does not reach the next statement: the
/// verdict is per literal, which is what keeps the marker from becoming
/// a file-scoped allow-list.
#[test]
fn a_neighbours_declaration_does_not_cover_the_next_statement() {
    let declared = "SELECT MIN(detected_at) FROM scan_findings\n\
                    -- HISTORY-WIDE: dates one vulnerability.\n";
    let bare = "SELECT count(*) FROM scan_findings WHERE artifact_id = $1";
    assert_eq!(classify(declared), Verdict::Declared);
    assert_eq!(classify(bare), Verdict::Undeclared);
    // Concatenated — i.e. ONE literal — the declaration would cover
    // both, which is exactly why the scan classifies literals and not
    // files.
    assert_eq!(
        classify(&format!("{declared}{bare}")),
        Verdict::Declared,
        "within one literal a declaration covers the whole statement; the \
         per-literal verdict is what keeps that from reaching a sibling"
    );
}

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
