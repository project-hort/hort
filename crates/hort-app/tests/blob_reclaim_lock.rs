//! Structural guard: **every production write to `content_references`
//! takes the blob-reclamation lock, and the storage-GC sweep never
//! waits for it.**
//!
//! CAS deduplicates, so a content hash belongs to as many artifacts as
//! happen to carry those bytes. The storage-GC walk destroys the bytes;
//! everything else lays claim to them by writing a `content_references`
//! row. An artifact-row lock is the wrong granularity for that
//! serialisation — it is a lock on one of the owners, not on the thing
//! being destroyed — which is precisely the defect this guard's subject
//! fixed: the sweep counted zero references, an ingest deduplicated onto
//! the same hash (`exists(hash)` true, so nothing written) and recorded
//! its reference, and the delete that followed left the new artifact
//! pointing at bytes that no longer existed.
//!
//! The fix is a hash-scoped Postgres advisory lock
//! (`hort-adapters-postgres/src/blob_lock.rs`) that **both** sides take.
//! A lock only the deleting side takes protects nothing, and a lock the
//! *reference writer* forgets is the same hole reopened one call site at
//! a time — a new `kind`, a new backfill handler, a new repair sweep.
//! Convention does not hold a property whose violation is invisible in
//! review and only observable as a 404 on somebody else's artifact, so
//! the property is checked here instead.
//!
//! ## The properties
//!
//! 1. Every `INSERT INTO content_references` in production Rust under
//!    `crates/*/src` sits in a function that calls `lock_blob_in_tx` or
//!    `lock_blobs_in_tx` **before** the insert. The plural form is the
//!    multi-blob acquisition one transaction needs when it claims several
//!    hashes at once (an ingest's own content plus its CAS-resident metadata
//!    blob) — same lock, same keyspace, taken in a total order so two
//!    overlapping writers cannot each hold the other's next one.
//! 2. The advisory-lock SQL is spelled in exactly one file. One
//!    keyspace, one derivation: two spellings is how two processes come
//!    to lock different keys for the same blob.
//! 3. The sweep never takes the **waiting** form. `purge_gc.rs` uses
//!    `try_lock_blob_in_tx` only — a destructive sweep that queued
//!    behind a live ingest would be housekeeping outranking a request,
//!    and contention is already an answer it knows how to act on.
//!
//! Property 1 carries a counter-assertion on the number of insert sites
//! it found, so a rename of the table or of the helper cannot turn the
//! scan vacuously green.
//!
//! ## Scope, and what this cannot see
//!
//! Production code only — test fixtures seed `content_references` rows
//! directly and legitimately, and a guard that argued with them would be
//! arguing about test data. The blind spot every source scan has
//! applies: an insert assembled through a macro, or a lock taken by a
//! helper in another file, is invisible here. The DB-backed proofs that
//! the two sides contend on the same key live beside the sweep
//! (`purge_gc.rs`'s `the_ingest_write_waits_on_the_very_lock_the_sweep_holds`
//! and `the_reconcile_repair_waits_on_the_same_lock`); this guard is
//! what keeps a *future* writer from being added without one.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `db_gate_not_silent` and
//! `capped_stream_reads`.

use std::fs;
use std::path::{Path, PathBuf};

/// The table whose every production insert must be locked.
const GUARDED_INSERT: &str = "INSERT INTO content_references";

/// The waiting lock helpers, taken by reference writers: the single-hash
/// form and the multi-hash form. Both end in `lock_blob…_in_tx(` so the
/// `try_` exclusion in the sweep check below applies to each.
/// `try_lock_blob_in_tx(` contains the first of them as a substring, which
/// is why the sweep check excludes the `try_` prefix explicitly.
const LOCK_HELPERS: [&str; 2] = ["lock_blob_in_tx(", "lock_blobs_in_tx("];

/// The non-waiting lock helper, taken by the destructive sweep.
const TRY_LOCK_HELPER: &str = "try_lock_blob_in_tx(";

/// The one file allowed to spell the advisory-lock SQL.
const LOCK_SQL_FILE: &str = "crates/hort-adapters-postgres/src/blob_lock.rs";

/// The destructive sweep, which must never wait on the lock.
const SWEEP_FILE: &str = "crates/hort-adapters-postgres/src/purge_gc.rs";

/// Production reference-writing sites known today: the ingest/OCI/
/// provenance/curation write path (`PgContentReferenceRepo::insert`) and
/// the refcount-reconcile repair (`PgRefcountReconcile::upsert_row`).
/// The count is asserted so a rename cannot make the scan vacuous.
const EXPECTED_INSERT_SITES: usize = 2;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rs(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Drop the inline test module (and everything after it) plus whole-line
/// comments, replacing each dropped line with an empty one so byte
/// offsets still map back to original line numbers.
///
/// A column-0 `#[cfg(test)]` only starts the test module when the item
/// it guards is a `mod` — the workspace convention is that inline test
/// modules come last, so everything from there on is test code. It is
/// **not** enough on its own: `purge_gc.rs` carries a column-0
/// `#[cfg(test)] use std::sync::atomic::…` two thirds of the way up the
/// file, for a test-only interruption seam, and reading that as the
/// module boundary hides the entire production body below it — including
/// the sweep's own lock call, which is what this guard came here to
/// find.
fn production_region(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for (i, line) in lines.iter().enumerate() {
        if !in_tests && line.starts_with("#[cfg(test)]") && guards_a_module(&lines, i) {
            in_tests = true;
        }
        let is_comment = line.trim_start().starts_with("//");
        if in_tests || is_comment {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Does the attribute at `index` guard a `mod` item? Skips any further
/// attribute lines between it and the item (`#[cfg(test)] #[path = …]
/// mod tests;`).
fn guards_a_module(lines: &[&str], index: usize) -> bool {
    lines[index + 1..]
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with("#["))
        .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod "))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Byte range of the function body enclosing `offset`: from the `fn`
/// keyword of the nearest preceding declaration to its matching close
/// brace. `None` when the declaration or the braces cannot be found,
/// which the caller reports as a violation rather than a pass — a site
/// the scan cannot place is a site it cannot vouch for.
fn enclosing_fn_body(text: &str, offset: usize) -> Option<(usize, usize)> {
    let start = text[..offset].rfind("fn ")?;
    let open = text[start..].find('{')? + start;
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start, i));
                }
            }
            _ => {}
        }
    }
    None
}

/// Files whose prose quotes the tokens this guard scans for.
fn is_self_referential(rel: &str) -> bool {
    rel.ends_with("tests/blob_reclaim_lock.rs")
}

#[test]
fn every_content_reference_write_takes_the_blob_lock_first() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();
    let mut sites: Vec<String> = Vec::new();

    for path in production_sources(&root) {
        let rel = relative(&root, &path);
        if is_self_referential(&rel)
            || rel.ends_with("_tests.rs")
            || rel.ends_with("test_support.rs")
        {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let text = production_region(&source);

        let mut search = 0usize;
        while let Some(found) = text[search..].find(GUARDED_INSERT) {
            let at = search + found;
            search = at + GUARDED_INSERT.len();
            let line = line_of(&text, at);
            sites.push(format!("{rel}:{line}"));

            let Some((body_start, body_end)) = enclosing_fn_body(&text, at) else {
                violations.push(format!(
                    "{rel}:{line} — this `{GUARDED_INSERT}` is not inside a \
                     function body the guard can delimit, so it cannot be \
                     shown to hold the blob lock"
                ));
                continue;
            };
            if at > body_end {
                violations.push(format!(
                    "{rel}:{line} — this `{GUARDED_INSERT}` falls outside the \
                     function body the guard delimited"
                ));
                continue;
            }
            // The lock has to be taken *before* the insert: taking it
            // afterwards leaves the row visible to a sweep that counted
            // in between, which is the whole window being closed.
            let prefix = &text[body_start..at];
            if !LOCK_HELPERS.iter().any(|h| prefix.contains(h)) {
                violations.push(format!(
                    "{rel}:{line} — writes `content_references` without \
                     first calling one of {LOCK_HELPERS:?} on the target \
                     hash(es). A \
                     reference recorded outside the blob-reclamation lock \
                     can be written between the storage-GC sweep's \
                     refcount-zero re-check and its delete, leaving this \
                     row pointing at bytes that no longer exist."
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "unlocked content_references writes:\n  {}",
        violations.join("\n  ")
    );
    assert_eq!(
        sites.len(),
        EXPECTED_INSERT_SITES,
        "expected exactly {EXPECTED_INSERT_SITES} production \
         `{GUARDED_INSERT}` sites, found {}: {sites:?}. A new one is a \
         review conversation (does it take the lock?); a missing one means \
         the scan has gone vacuous and is no longer checking anything.",
        sites.len()
    );
}

#[test]
fn the_advisory_lock_sql_is_spelled_in_exactly_one_file() {
    let root = workspace_root();
    let mut spellings: Vec<String> = Vec::new();

    for path in production_sources(&root) {
        let rel = relative(&root, &path);
        if is_self_referential(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let text = production_region(&source);
        if text.contains("pg_advisory_xact_lock") || text.contains("pg_try_advisory_xact_lock") {
            spellings.push(rel);
        }
    }

    assert_eq!(
        spellings,
        vec![LOCK_SQL_FILE.to_owned()],
        "the blob-lock keyspace and its key derivation live in one file. \
         A second spelling is two derivations waiting to disagree — and a \
         rolling upgrade where the old process and the new one lock \
         different keys for the same blob is exactly the window the lock \
         exists to close."
    );
}

#[test]
fn the_destructive_sweep_never_waits_on_the_blob_lock() {
    let root = workspace_root();
    let sweep = root.join(SWEEP_FILE);
    let source = fs::read_to_string(&sweep).expect("the sweep adapter is readable UTF-8");
    let text = production_region(&source);

    assert!(
        text.contains(TRY_LOCK_HELPER),
        "{SWEEP_FILE} must take the blob lock with `{TRY_LOCK_HELPER})` \
         before deleting bytes; the counter-assertion that keeps this \
         guard honest"
    );

    // `try_lock_blob_in_tx(` contains `lock_blob_in_tx(`, so the waiting
    // form is only genuinely present where it is not preceded by `try_`.
    // Both waiting forms are checked — the plural one would block the sweep
    // just as thoroughly as the singular.
    let mut waiting = LOCK_HELPERS
        .iter()
        .flat_map(|helper| {
            text.match_indices(helper)
                .filter(|(at, _)| !text[..*at].ends_with("try_"))
                .map(|(at, _)| line_of(&text, at))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    waiting.sort_unstable();
    assert!(
        waiting.is_empty(),
        "{SWEEP_FILE} takes the WAITING form of the blob lock at line(s) \
         {waiting:?}. The sweep must never block on it: an ingest holding \
         the lock is a request being served, byte reclamation is \
         housekeeping the event model explicitly allows to be late, and \
         contention is already an outcome the sweep records \
         (`blobs_deferred`) and retries."
    );
}
