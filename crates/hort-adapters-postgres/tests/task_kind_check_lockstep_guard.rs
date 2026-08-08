//! `jobs.kind` CHECK / `EVENT_TASK_KINDS` lock-step guard (backlog 092,
//! issue #134).
//!
//! DB-free, network-free source-scan — the committed proof (in the spirit
//! of `ephemeral_keyspace_exhaustive` / `no_bcrypt` / `alpha_fixtures` /
//! `streaming_metadata_port` / `no_sensitive_drops`) that migration 009's
//! `jobs.kind` SQL CHECK list and
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
//! ## What it asserts
//!
//! Migration 009's `kind text NOT NULL CHECK (kind IN (…))` list, parsed
//! by token-scanning the migration source (comments and whitespace do not
//! affect the result), equals `EVENT_TASK_KINDS` exactly — same members,
//! order-independent. A mismatch fails naming both sites: the migration
//! file (with the extra/missing kinds found there) and
//! `EVENT_TASK_KINDS` (with the extra/missing kinds found there), so a
//! reviewer does not have to diff the two lists by hand.
//!
//! ## Parser scope
//!
//! Deliberately narrow — this is not a general SQL parser (see
//! `no_sensitive_drops.rs` for that shape when the full generality is
//! actually needed). It locates the literal `kind IN (` marker specific
//! to migration 009's `jobs` table definition, then walks the
//! parenthesised list tracking paren depth (so it stops at the list's own
//! closing `)`, not at any earlier or later paren in the file), skipping
//! `--` line comments and collecting single-quoted string literals as
//! members.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use hort_domain::events::EVENT_TASK_KINDS;

/// Locate the workspace-root `migrations/` directory from
/// `CARGO_MANIFEST_DIR` (`<root>/crates/hort-adapters-postgres`), so two
/// levels up is the workspace root. Mirrors how the sibling guards
/// resolve their scan roots relative to `CARGO_MANIFEST_DIR`.
fn migration_009_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)");
    root.join("migrations")
        .join("009_scan_jobs_and_findings.sql")
}

/// Parse the `kind IN (…)` list out of migration 009's `jobs.kind` CHECK
/// constraint. Returns the quoted literals in file order.
///
/// Locates the `kind IN (` marker, then walks the parenthesised list
/// tracking paren depth starting at 1 (the `(` right after `IN`) so the
/// walk stops exactly at that list's matching `)` — not at some other
/// paren elsewhere in the CREATE TABLE. `--` line comments are skipped;
/// `'…'` string literals are collected as members.
fn parse_kind_check_list(source: &str) -> Vec<String> {
    let marker = "kind IN (";
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("migration 009 has no `{marker}` marker — parser drift?"))
        + marker.len();
    let rest = &source[start..];
    let bytes = rest.as_bytes();

    let mut members = Vec::new();
    let mut depth: i32 = 1;
    let mut in_string = false;
    let mut current = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if !in_string && c == '-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == '\'' {
            if in_string {
                members.push(current.clone());
                current.clear();
            } else {
                current.clear();
            }
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
        "migration 009's `kind IN (…)` list never closed — parser drift or a malformed \
         migration; the scan walked to EOF without finding the matching `)`"
    );
    members
}

#[test]
fn migration_009_kind_check_matches_event_task_kinds() {
    let path = migration_009_path();
    let source = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

    let mut from_migration = parse_kind_check_list(&source);
    assert!(
        !from_migration.is_empty(),
        "parsed zero kinds out of migration 009's `kind IN (…)` list at {path:?} — \
         a path or parser error would otherwise let this guard pass vacuously"
    );

    let mut from_constant: Vec<String> = EVENT_TASK_KINDS.iter().map(ToString::to_string).collect();

    from_migration.sort();
    from_migration.dedup();
    from_constant.sort();
    from_constant.dedup();

    if from_migration != from_constant {
        let only_in_migration: Vec<&String> = from_migration
            .iter()
            .filter(|k| !from_constant.contains(k))
            .collect();
        let only_in_constant: Vec<&String> = from_constant
            .iter()
            .filter(|k| !from_migration.contains(k))
            .collect();
        panic!(
            "migration 009's `jobs.kind` CHECK ({path:?}) and \
             `hort_domain::events::EVENT_TASK_KINDS` \
             (crates/hort-domain/src/events/authorization_events.rs) have drifted apart.\n\
             Only in migration 009's CHECK: {only_in_migration:?}\n\
             Only in EVENT_TASK_KINDS: {only_in_constant:?}\n\
             Keep both lists in lock-step — a kind added to one must be added to the other."
        );
    }
}

// ---------------------------------------------------------------------------
// Self-tests for the parser (no I/O) — pin the parsing behaviour against
// deliberately-shaped snippets so a future refactor cannot silently break
// the comparison above into a false pass.
// ---------------------------------------------------------------------------

#[test]
fn self_check_parses_simple_list() {
    let src = "kind IN (\n    'a',\n    'b',\n    'c'\n))";
    assert_eq!(parse_kind_check_list(src), vec!["a", "b", "c"]);
}

#[test]
fn self_check_skips_line_comments() {
    let src = "kind IN (\n    'a', -- comment mentioning 'z'\n    'b'\n))";
    assert_eq!(parse_kind_check_list(src), vec!["a", "b"]);
}

#[test]
fn self_check_stops_at_matching_close_paren() {
    // A nested paren inside the list (not present in the real migration,
    // but the walk must still stop at the correct depth-0 close) must not
    // truncate early or run past the list's own closing paren.
    let src = "kind IN (\n    'a',\n    'b'\n)) trailer-that-must-not-be-scanned";
    assert_eq!(parse_kind_check_list(src), vec!["a", "b"]);
}

#[test]
fn self_check_real_migration_marker_present() {
    let path = migration_009_path();
    assert!(path.is_file(), "migration 009 not found at {path:?}");
}
