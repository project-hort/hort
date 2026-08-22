//! `jobs.kind` CHECK / `EVENT_TASK_KINDS` lock-step guard.
//!
//! DB-free, network-free source-scan — the committed proof (in the spirit
//! of `ephemeral_keyspace_exhaustive` / `no_bcrypt` / `alpha_fixtures` /
//! `streaming_metadata_port` / `no_sensitive_drops`) that the `jobs.kind`
//! SQL CHECK list **in force** and
//! `hort_domain::events::EVENT_TASK_KINDS` never drift apart.
//!
//! ## Why a guard and not just a doc comment
//!
//! The migration's `kind IN (…)` CHECK and the Rust-side kind vocabulary
//! are two independently-edited artifacts describing the same set. Before
//! `EVENT_TASK_KINDS` existed there was no committed proof that they
//! agreed — only doc comments asserting "keep in lock-step." A kind added
//! to one side and not the other would enqueue fine in every mock-based
//! unit test (which never touches the SQL CHECK) and surface only against
//! a real Postgres — exactly the gap `EVENT_TASK_KINDS` and this guard
//! close without needing a database.
//!
//! ## Which migration the guard reads — the effective list
//!
//! Not `009_scan_jobs_and_findings.sql` unconditionally. A migration
//! chain is applied in order and the constraint can be redefined by a
//! later `ALTER TABLE public.jobs DROP CONSTRAINT jobs_kind_check; ADD
//! CONSTRAINT jobs_kind_check CHECK (kind IN (…))`, which is how a kind
//! reaches a database that has already applied 009 (editing 009 in place
//! changes its checksum and makes `sqlx::migrate!` reject every
//! already-migrated database with `VersionMismatch`). So the list in
//! force — the *effective* list, the only one a running database
//! actually enforces — is the one defined by the **newest** migration
//! that defines it: today `018_jobs_kind_oci_edge_backfill.sql`,
//! tomorrow whichever migration redefines it next, with no edit to this
//! guard required.
//!
//! Reading 009 unconditionally would make the guard assert against a
//! list no live database enforces: it would go red on a legitimate
//! redefinition and, worse, stay green while the effective list and
//! `EVENT_TASK_KINDS` disagreed.
//!
//! ## What it asserts
//!
//! The `kind IN (…)` list parsed out of the newest migration that
//! defines the `jobs.kind` CHECK equals `EVENT_TASK_KINDS` exactly —
//! same members, order-independent. A mismatch fails naming both sites:
//! the migration file (with the extra/missing kinds found there) and
//! `EVENT_TASK_KINDS` (with the extra/missing kinds found there), so a
//! reviewer does not have to diff the two lists by hand.
//!
//! ## Parser scope
//!
//! Deliberately narrow — this is not a general SQL parser (see
//! `no_sensitive_drops.rs` for that shape when the full generality is
//! actually needed). `--` line comments are stripped first, so prose
//! (a reversal runbook spelling out the reverse `CHECK (kind IN (…))`,
//! a comment quoting a `kind IN ('prefetch', …)` predicate) can neither
//! be mistaken for the definition nor contribute members. The scan then
//! locates a whole-word `kind IN (` marker — whole-word so
//! `target_kind IN (` in an unrelated table's CHECK does not match — and
//! walks the parenthesised list tracking paren depth, so it stops at the
//! list's own closing `)` rather than at any earlier or later paren.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use hort_domain::events::EVENT_TASK_KINDS;

/// Locate the workspace-root `migrations/` directory from
/// `CARGO_MANIFEST_DIR` (`<root>/crates/hort-adapters-postgres`), so two
/// levels up is the workspace root. Mirrors how the sibling guards
/// resolve their scan roots relative to `CARGO_MANIFEST_DIR`.
fn migrations_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)");
    root.join("migrations")
}

/// Every `*.sql` file under `dir`, as `(file_name, source)` pairs. Order
/// is unspecified — [`effective_kind_check`] orders by migration number.
fn read_migration_sources(dir: &Path) -> Vec<(String, String)> {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    let mut out = Vec::new();
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("read_dir entry in {dir:?}: {e}"))
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| panic!("migration file name is not UTF-8: {path:?}"))
            .to_string();
        let source = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        out.push((name, source));
    }
    out
}

// ---------------------------------------------------------------------------
// Source scanning.
// ---------------------------------------------------------------------------

/// Replace every `--` line comment with spaces (newlines preserved) so
/// prose cannot be mistaken for SQL. Single-quoted literals are left
/// intact — they are what the list parser collects — which is safe here
/// because no migration embeds a `--` sequence inside a `kind` literal.
fn strip_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        match line.find("--") {
            Some(idx) => {
                out.push_str(&line[..idx]);
                for c in line[idx..].chars() {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `true` when `bytes[idx..]` starts with `word` (ASCII, case-insensitive)
/// as a whole token — i.e. neither neighbour is an identifier character.
fn word_at(bytes: &[u8], idx: usize, word: &str) -> bool {
    let end = idx + word.len();
    if end > bytes.len() || !bytes[idx..end].eq_ignore_ascii_case(word.as_bytes()) {
        return false;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if idx > 0 && ident(bytes[idx - 1]) {
        return false;
    }
    !bytes.get(end).copied().is_some_and(ident)
}

/// Byte offset just past the `(` of the first whole-word `kind IN (`
/// marker in an already-comment-stripped source, or `None`.
///
/// Whole-word matching on `kind` is load-bearing: `target_kind IN (` in
/// `012_subscriptions.sql` is a different table's CHECK and must not be
/// mistaken for this one.
fn find_kind_in_marker(stripped: &str) -> Option<usize> {
    let bytes = stripped.as_bytes();
    let skip_ws = |mut i: usize| {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        i
    };
    for i in 0..bytes.len() {
        if !word_at(bytes, i, "kind") {
            continue;
        }
        let j = skip_ws(i + "kind".len());
        if !word_at(bytes, j, "in") {
            continue;
        }
        let k = skip_ws(j + "in".len());
        if bytes.get(k) == Some(&b'(') {
            return Some(k + 1);
        }
    }
    None
}

/// Parse the `kind IN (…)` list out of a migration's `jobs.kind` CHECK
/// constraint. Returns the quoted literals in file order, or `None` when
/// the migration defines no such list.
///
/// Walks the parenthesised list from the marker tracking paren depth
/// starting at 1 (the `(` right after `IN`) so the walk stops exactly at
/// that list's matching `)` — not at some other paren elsewhere in the
/// statement. `'…'` string literals are collected as members.
fn parse_kind_check_list(source: &str) -> Option<Vec<String>> {
    let stripped = strip_line_comments(source);
    let start = find_kind_in_marker(&stripped)?;
    let rest = &stripped[start..];
    let bytes = rest.as_bytes();

    let mut members = Vec::new();
    let mut depth: i32 = 1;
    let mut in_string = false;
    let mut current = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' {
            if in_string {
                members.push(current.clone());
            }
            current.clear();
            in_string = !in_string;
            i += 1;
            continue;
        }
        if in_string {
            current.push(c);
            i += 1;
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    assert_ne!(
        depth, 1,
        "a `kind IN (…)` list never closed — parser drift or a malformed \
         migration; the scan walked to EOF without finding the matching `)`"
    );
    Some(members)
}

/// `true` when an already-comment-stripped source contains a statement
/// against the `jobs` table (`CREATE TABLE public.jobs`, `ALTER TABLE
/// ONLY jobs`, …). Paired with a `kind IN (` marker this identifies a
/// migration that defines the `jobs.kind` CHECK, and excludes another
/// table's `kind` CHECK (`008_api_tokens.sql`).
fn references_jobs_table(stripped: &str) -> bool {
    let words: Vec<&str> = stripped.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        if !words[i].eq_ignore_ascii_case("table") {
            i += 1;
            continue;
        }
        // Skip the optional `IF EXISTS` / `ONLY` qualifiers between
        // `TABLE` and the table name.
        let mut j = i + 1;
        while words.get(j).is_some_and(|w| {
            ["if", "exists", "only"]
                .iter()
                .any(|q| w.eq_ignore_ascii_case(q))
        }) {
            j += 1;
        }
        if let Some(name) = words.get(j) {
            // Trim a schema qualifier and any trailing punctuation
            // (`public.jobs (`, `public.jobs;`).
            let bare = name
                .rsplit('.')
                .next()
                .unwrap_or(name)
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            if bare.eq_ignore_ascii_case("jobs") {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Leading numeric prefix of a migration file name (`018_foo.sql` → 18).
fn migration_number(file_name: &str) -> Option<u32> {
    let digits: String = file_name.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The `jobs.kind` CHECK list **in force**: the one defined by the
/// highest-numbered migration that defines it, as `(file_name, kinds)`.
///
/// Pure over `(file_name, source)` pairs so the selection rule is
/// testable without touching the filesystem.
fn effective_kind_check(files: &[(String, String)]) -> Option<(String, Vec<String>)> {
    let mut defining: Vec<(u32, &str, Vec<String>)> = files
        .iter()
        .filter_map(|(name, source)| {
            let number = migration_number(name)?;
            let stripped = strip_line_comments(source);
            if !references_jobs_table(&stripped) {
                return None;
            }
            let kinds = parse_kind_check_list(source)?;
            Some((number, name.as_str(), kinds))
        })
        .collect();
    defining.sort_by_key(|(number, _, _)| *number);
    defining
        .pop()
        .map(|(_, name, kinds)| (name.to_string(), kinds))
}

/// The lock-step comparison. Returns `None` when the two sides agree, or
/// the failure message naming **both** sites when they have drifted.
fn drift_report(
    file_name: &str,
    from_migration: &[String],
    from_constant: &[String],
) -> Option<String> {
    let mut migration: Vec<String> = from_migration.to_vec();
    let mut constant: Vec<String> = from_constant.to_vec();
    migration.sort();
    migration.dedup();
    constant.sort();
    constant.dedup();
    if migration == constant {
        return None;
    }
    let only_in_migration: Vec<&String> =
        migration.iter().filter(|k| !constant.contains(k)).collect();
    let only_in_constant: Vec<&String> =
        constant.iter().filter(|k| !migration.contains(k)).collect();
    Some(format!(
        "the `jobs.kind` CHECK in force (migrations/{file_name} — the newest migration that \
         defines the constraint, i.e. the list a migrated database actually enforces) and \
         `hort_domain::events::EVENT_TASK_KINDS` \
         (crates/hort-domain/src/events/authorization_events.rs) have drifted apart.\n\
         Only in migrations/{file_name}: {only_in_migration:?}\n\
         Only in EVENT_TASK_KINDS: {only_in_constant:?}\n\
         Keep both lists in lock-step — a kind added to one must be added to the other. \
         Widen the SQL side by appending a new numbered migration that redefines \
         `jobs_kind_check` over the full list; never by editing an applied migration in place \
         (that changes its checksum and makes `sqlx::migrate!` reject every already-migrated \
         database)."
    ))
}

// ---------------------------------------------------------------------------
// The guard.
// ---------------------------------------------------------------------------

#[test]
fn effective_jobs_kind_check_matches_event_task_kinds() {
    let dir = migrations_dir();
    let files = read_migration_sources(&dir);
    let (file_name, kinds) = effective_kind_check(&files).unwrap_or_else(|| {
        panic!(
            "no migration under {dir:?} defines a `jobs.kind` CHECK list — a path or parser \
                error would otherwise let this guard pass vacuously"
        )
    });
    assert!(
        !kinds.is_empty(),
        "parsed zero kinds out of migrations/{file_name}'s `kind IN (…)` list — a parser error \
         would otherwise let this guard pass vacuously"
    );

    let from_constant: Vec<String> = EVENT_TASK_KINDS.iter().map(ToString::to_string).collect();
    if let Some(message) = drift_report(&file_name, &kinds, &from_constant) {
        panic!("{message}");
    }
}

// ---------------------------------------------------------------------------
// Self-tests (no I/O) — pin the selection and parsing behaviour against
// deliberately-shaped snippets so a future refactor cannot silently break
// the comparison above into a false pass.
// ---------------------------------------------------------------------------

fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, source)| ((*name).to_string(), (*source).to_string()))
        .collect()
}

#[test]
fn self_check_parses_simple_list() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT c CHECK (kind IN (\n 'a',\n 'b',\n 'c'\n))";
    assert_eq!(
        parse_kind_check_list(src),
        Some(vec!["a".into(), "b".into(), "c".into()])
    );
}

#[test]
fn self_check_skips_line_comments() {
    let src = "kind IN (\n    'a', -- comment mentioning 'z'\n    'b'\n))";
    assert_eq!(
        parse_kind_check_list(src),
        Some(vec!["a".into(), "b".into()])
    );
}

#[test]
fn self_check_stops_at_matching_close_paren() {
    // A nested paren inside the list (not present in the real migration,
    // but the walk must still stop at the correct depth-0 close) must not
    // truncate early or run past the list's own closing paren.
    let src = "kind IN (\n    'a',\n    'b'\n)) trailer-that-must-not-be-scanned";
    assert_eq!(
        parse_kind_check_list(src),
        Some(vec!["a".into(), "b".into()])
    );
}

#[test]
fn self_check_ignores_a_kind_list_quoted_in_a_comment() {
    // A reversal runbook spells out the reverse constraint in prose. The
    // real definition follows it, and is the one that must be parsed.
    let src = "-- Reversal: ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('old-a', 'old-b'));\n\
               ALTER TABLE public.jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN (\n\
               'a',\n 'b'\n));";
    assert_eq!(
        parse_kind_check_list(src),
        Some(vec!["a".into(), "b".into()])
    );
}

#[test]
fn self_check_does_not_match_another_columns_kind_check() {
    // `target_kind IN (…)` is a different column on a different table;
    // whole-word matching keeps it out of this guard's reach.
    let src = "CREATE TABLE public.subscriptions (\n target_kind text CHECK (target_kind IN \
               ('webhook', 'nats_jetstream'))\n);";
    assert_eq!(parse_kind_check_list(src), None);
}

#[test]
fn self_check_effective_list_is_the_newest_definer() {
    // The guard must follow a redefinition: the newer migration's list is
    // the one in force, whatever the older one still says, and whatever
    // order the directory happens to be read in.
    let base = "CREATE TABLE public.jobs (kind text CHECK (kind IN ('a', 'b')));";
    let redefinition = "ALTER TABLE public.jobs DROP CONSTRAINT jobs_kind_check;\n\
                        ALTER TABLE public.jobs ADD CONSTRAINT jobs_kind_check \
                        CHECK (kind IN ('a', 'b', 'c'));";
    let expected = Some((
        "018_redefine.sql".to_string(),
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
    ));
    assert_eq!(
        effective_kind_check(&owned(&[
            ("009_base.sql", base),
            ("018_redefine.sql", redefinition)
        ])),
        expected
    );
    assert_eq!(
        effective_kind_check(&owned(&[
            ("018_redefine.sql", redefinition),
            ("009_base.sql", base)
        ])),
        expected
    );
}

#[test]
fn self_check_effective_list_ignores_other_tables_and_prose() {
    // Higher-numbered migrations that touch a different table's `kind`
    // CHECK, or only mention `jobs` in a comment, must not be mistaken
    // for a redefinition of the effective list.
    let base = "CREATE TABLE public.jobs (kind text CHECK (kind IN ('a', 'b')));";
    let other_table = "CREATE TABLE public.api_tokens (kind text CHECK (kind IN ('pat')));";
    let prose_only = "-- Reversal: ALTER TABLE public.jobs ADD CONSTRAINT jobs_kind_check \
                      CHECK (kind IN ('a'));\nCREATE INDEX i ON public.jobs (created_at);";
    let selected = effective_kind_check(&owned(&[
        ("009_base.sql", base),
        ("019_other.sql", other_table),
        ("020_prose.sql", prose_only),
    ]));
    assert_eq!(
        selected,
        Some((
            "009_base.sql".to_string(),
            vec!["a".to_string(), "b".to_string()]
        ))
    );
}

#[test]
fn self_check_drift_report_names_both_sites() {
    // The proof that the guard would fail on drift between the effective
    // migration's list and `EVENT_TASK_KINDS` — and that the failure
    // still points at both sites plus the two offending kinds.
    let message = drift_report(
        "018_jobs_kind_oci_edge_backfill.sql",
        &["a".to_string(), "only-in-sql".to_string()],
        &["a".to_string(), "only-in-rust".to_string()],
    )
    .expect("differing lists must produce a drift report");
    assert!(
        message.contains("migrations/018_jobs_kind_oci_edge_backfill.sql"),
        "drift report must name the effective migration: {message}"
    );
    assert!(
        message.contains("EVENT_TASK_KINDS"),
        "drift report must name the Rust-side constant: {message}"
    );
    assert!(
        message.contains("only-in-sql") && message.contains("only-in-rust"),
        "drift report must name the drifting kinds: {message}"
    );
    assert_eq!(
        drift_report(
            "018_x.sql",
            &["b".to_string(), "a".to_string()],
            &["a".to_string(), "b".to_string()]
        ),
        None,
        "agreeing lists must not report drift, whatever their order"
    );
}
