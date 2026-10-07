//! Structural guard: **one repository-visibility primitive, and exactly
//! the two gates consume it.**
//!
//! `GET /api/v1/events` and the subscription delivery filter are two
//! call sites of one question — *which repositories does this event
//! disclose, and may this principal read all of them?* They used to
//! answer it locally, each from an `Option<Uuid>` whose `None` each of
//! them read as "visible". One rule, two implementations, and both
//! copies wrong the same way: an authenticated account with no `Read`
//! grant anywhere could pull every repository's scanner names, severity
//! counts, findings-blob hashes and release justifications off the read
//! endpoint, and the same absent value made a correctly restricted
//! `RepositoryScope::Some([repo])` subscriber lose that repository's
//! whole lifecycle feed.
//!
//! The fix is one primitive — `hort_app::use_cases::event_visibility` —
//! and the thing that can silently undo it is not a wrong answer but a
//! *third answer*: a new consumer that reaches past the primitive to the
//! raw classifier and re-derives the rule. Nothing in the compiler stops
//! that; the classifier and the ref enum are `pub`, because the
//! primitive lives in a different crate than the domain. So the property
//! is scanned.
//!
//! ## The property
//!
//! In production Rust under `crates/*/src`:
//!
//! 1. `EventTypeKind::disclosed_repositories` — the payload classifier —
//!    is referenced only in its own definition file and in
//!    [`PRIMITIVE_FILE`]. A second caller is a second resolution.
//! 2. `RepositoryRef::` — the "resolve this aggregate" question the
//!    classifier answers with — is likewise matched only in those two
//!    files. Matching it elsewhere means resolving an aggregate by hand,
//!    which is how a per-event round trip gets onto the read hot path
//!    and how the fail-closed disposition gets forgotten.
//! 3. `EventDisclosure::` — the primitive's resolved answer — is read
//!    only in [`PRIMITIVE_FILE`] and in the two gate files listed in
//!    [`ALLOWED_GATES`]. A third gate is a third place that has to get
//!    the conjunction, the `Global` pass-through and the `Unresolved`
//!    fail-closed right on its own.
//!
//! A genuinely new consumer is a review conversation — it will usually
//! want the primitive, not an exemption entry — so there is no
//! allow-list beyond the two gates that exist.
//!
//! ## Counter-assertion
//!
//! A scan for symbols that no longer exist is vacuously green, which is
//! the failure mode of every guard in this family. So the test also
//! asserts the corpus is real: the classifier is referenced in the
//! primitive, and **both** gate files actually match on
//! `EventDisclosure`. Rename either half and this fails loudly instead
//! of passing silently.
//!
//! ## Scope, and what this cannot see
//!
//! Production code only — test code legitimately builds indices and
//! disclosures by hand. Whole-line comments are dropped so this file's
//! own prose, and the prose at the call sites, stays readable; the
//! inline test module (everything from a column-0 `#[cfg(test)]` on) is
//! dropped too, per the workspace convention that such modules come
//! last.
//!
//! The blind spot every source scan has applies: a consumer that reaches
//! the classifier through a re-export under another name, or through a
//! macro, is invisible here. The review check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads` and
//! `db_gate_not_silent`.

use std::fs;
use std::path::{Path, PathBuf};

/// The one place the classifier is consumed and the batch resolution
/// happens.
const PRIMITIVE_FILE: &str = "crates/hort-app/src/use_cases/event_visibility.rs";

/// Where the classifier and the reference enum are defined. Their own
/// definition file necessarily names them.
const CLASSIFIER_DEFINITION_FILE: &str = "crates/hort-domain/src/entities/subscription.rs";

/// The two gates allowed to consume the primitive's answer: the
/// events-read handler and the subscription delivery filter.
const ALLOWED_GATES: &[&str] = &[
    "crates/hort-http-events/src/handler.rs",
    "crates/hort-app/src/use_cases/subscription_filter.rs",
];

/// The payload classifier. One consumer only.
const CLASSIFIER: &str = "disclosed_repositories";

/// The "resolve this aggregate" question. Matched only where the batch
/// resolution lives.
const REFERENCE_ENUM: &str = "RepositoryRef::";

/// The primitive's resolved answer. Read only by the two gates.
const DISCLOSURE_ENUM: &str = "EventDisclosure::";

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
    let crates = fs::read_dir(root.join("crates")).expect("crates/ must exist");
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

/// Retain only production, non-comment lines. Dropped lines become empty
/// so reported line numbers still match the original file.
fn production_lines(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_tests = false;
    for (i, line) in source.lines().enumerate() {
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        let is_comment = line.trim_start().starts_with("//");
        if in_tests || is_comment {
            out.push((i + 1, String::new()));
        } else {
            out.push((i + 1, line.to_string()));
        }
    }
    out
}

/// Repo-relative path, with forward slashes, for comparison against the
/// constants above.
fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `(file, line)` in production code mentioning `needle`, with the
/// files in `allowed` excluded.
fn hits_outside(root: &Path, needle: &str, allowed: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    // `test_support.rs` harnesses are test rigging that happens to live
    // under `src/`; they build fixtures, not gates.
    for path in production_sources(root) {
        let relative = rel(root, &path);
        if allowed.contains(&relative.as_str()) || relative.ends_with("/test_support.rs") {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        for (line_no, line) in production_lines(&source) {
            if line.contains(needle) {
                out.push(format!("{relative}:{line_no}: {}", line.trim()));
            }
        }
    }
    out
}

/// Count of production, non-comment lines in `file` mentioning `needle`.
fn hits_in(root: &Path, file: &str, needle: &str) -> usize {
    let source = fs::read_to_string(root.join(file))
        .unwrap_or_else(|e| panic!("{file} must be readable: {e}"));
    production_lines(&source)
        .into_iter()
        .filter(|(_, line)| line.contains(needle))
        .count()
}

#[test]
fn the_payload_classifier_has_exactly_one_consumer() {
    let root = workspace_root();
    let stray = hits_outside(
        &root,
        CLASSIFIER,
        &[PRIMITIVE_FILE, CLASSIFIER_DEFINITION_FILE],
    );
    assert!(
        stray.is_empty(),
        "`{CLASSIFIER}` is classification, not a visibility decision: its one \
         consumer is the shared primitive ({PRIMITIVE_FILE}), which batches the \
         page's aggregate lookups into a single round trip and fixes the \
         fail-closed dispositions in one place. A second caller is a second \
         answer to one rule — exactly the drift that let a grantless account \
         read every repository's artifact lifecycle. Call \
         `EventVisibilityUseCase::index` and match on `EventDisclosure` \
         instead.\nStray references:\n  {}",
        stray.join("\n  ")
    );
}

#[test]
fn aggregate_resolution_happens_only_in_the_primitive() {
    let root = workspace_root();
    let stray = hits_outside(
        &root,
        REFERENCE_ENUM,
        &[PRIMITIVE_FILE, CLASSIFIER_DEFINITION_FILE],
    );
    assert!(
        stray.is_empty(),
        "`{REFERENCE_ENUM}` names an aggregate still to be resolved. Resolving \
         one outside {PRIMITIVE_FILE} means a lookup that is not part of the \
         page batch — one database round trip per event on the read hot path — \
         and a hand-written miss case that has to remember to fail \
         closed.\nStray references:\n  {}",
        stray.join("\n  ")
    );
}

#[test]
fn only_the_two_gates_consume_the_disclosure() {
    let root = workspace_root();
    let mut allowed: Vec<&str> = ALLOWED_GATES.to_vec();
    allowed.push(PRIMITIVE_FILE);
    let stray = hits_outside(&root, DISCLOSURE_ENUM, &allowed);
    assert!(
        stray.is_empty(),
        "a third consumer of `{DISCLOSURE_ENUM}` is a third place that has to \
         get all of it right on its own: `Read` on EVERY disclosed repository \
         (the promotion chain names two and the payload carries both), the \
         `Global` pass-through, and the `Unresolved` fail-closed onto live \
         Admin. Today the gates are the events-read handler and the \
         subscription delivery filter; a new one is a review conversation, not \
         an allow-list entry.\nStray consumers:\n  {}",
        stray.join("\n  ")
    );
}

/// Counter-assertion: the scan is looking at something. A rename that
/// left the three needles matching nothing would make all three tests
/// above pass by finding no code at all.
#[test]
fn the_scanned_corpus_is_real() {
    let root = workspace_root();
    assert!(
        hits_in(&root, CLASSIFIER_DEFINITION_FILE, CLASSIFIER) > 0,
        "the classifier must still be defined in {CLASSIFIER_DEFINITION_FILE}"
    );
    assert!(
        hits_in(&root, PRIMITIVE_FILE, CLASSIFIER) > 0,
        "the primitive must still consume the classifier; if it stopped, the \
         batch resolution moved somewhere this guard is not watching"
    );
    assert!(
        hits_in(&root, PRIMITIVE_FILE, REFERENCE_ENUM) > 0,
        "the primitive must still be the place that resolves aggregate references"
    );
    for gate in ALLOWED_GATES {
        assert!(
            hits_in(&root, gate, DISCLOSURE_ENUM) > 0,
            "{gate} must still decide visibility from the shared primitive's \
             `EventDisclosure`; if it no longer matches on one, it is either \
             gone or answering the question itself again"
        );
    }
}
