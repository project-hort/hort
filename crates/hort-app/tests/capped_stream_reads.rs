//! Structural guard: **a bounded `EventStore::read_stream` in production
//! code exists in exactly one place.**
//!
//! An artifact stream is bounded by `hort_app::use_cases::STREAM_EVENT_CAP`,
//! and that bound is what lets a single capped `ReadFrom::Start` read stand
//! in for "the whole stream". The bound is only useful if the reader can tell
//! the two apart: a read that comes back with as many events as its budget
//! allowed proves nothing about what follows them, so a reverse scan over the
//! result answers "the latest X among the oldest N" while looking exactly like
//! "the latest X". That is how a superseded scan verdict reads as current, and
//! how the rejection that superseded it becomes invisible to the release
//! authorization.
//!
//! `read_artifact_stream` is the one correct way to do it — read
//! `STREAM_EVENT_CAP + 1` events, return the stream when at most
//! `STREAM_EVENT_CAP` came back (the budget was not exhausted, so the tail was
//! reached), refuse otherwise. The idiom existed before this guard did, in
//! `read_expected_version`, and **convention alone did not hold it**: ten
//! capped-read sites across seven files got it wrong — nine read exactly
//! `200` with no overflow detection at all, each of six files carrying its own
//! copy of the constant, and the tenth read `cap + 1` correctly but discarded
//! the overflow signal. This guard is what makes the single reader durable
//! rather than a sweep that gets re-swept.
//!
//! ## The property
//!
//! Every `.read_stream(` call in production Rust under `crates/*/src` passes a
//! `max_count` of one of exactly three forms:
//!
//! 1. **`u64::MAX`** — a genuinely unbounded read of an unbounded stream
//!    category (the gitops apply path reads whole `authorization` /
//!    `repository` streams this way). No budget, so no truncation: allowed
//!    anywhere.
//! 2. **`STREAM_EVENT_CAP + 1`** — the audited bounded read, allowed *only*
//!    in [`ALLOWED_CAPPED_READ_FILE`]. Both readers there consume the `+ 1`
//!    as overflow detection. A second copy of this expression elsewhere would
//!    be a second reader that has to get the refusal right on its own, which
//!    is the situation this guard exists to end — so the location is part of
//!    the property, not an exemption.
//! 3. **a forwarded `max_count` parameter**, and only inside a
//!    `fn read_stream(` — i.e. an `EventStore` decorator implementing the
//!    trait by delegation (`EventStorePublisher`). Forwarding adds no policy:
//!    whatever budget the caller chose is the budget that applies, and the
//!    caller is covered by this guard in its own right.
//!
//! Anything else — a literal, a module-local constant, a computed expression —
//! is a new bounded read whose completeness nobody proved. That is a review
//! conversation, not an allow-list entry: either it reads a bounded artifact
//! stream (use `read_artifact_stream`) or it reads an unbounded one (a budget
//! is the wrong tool; page it or read it whole).
//!
//! ## Scope, and what this cannot see
//!
//! Production code only. Test code legitimately reads with arbitrary budgets
//! — a fixture asserting "the stream did not change" picks a number large
//! enough for its own fixture, and a guard that argued with it would be
//! arguing about test data. So the scan drops `*_tests.rs` files, the
//! `test_support.rs` harnesses, and everything at or after a file's first
//! column-0 `#[cfg(test)]` attribute (the convention in this workspace is that
//! inline test modules come last in the file).
//!
//! The blind spot every source scan has applies: a call assembled through a
//! macro, or a `max_count` that is a parameter of some *other* function
//! forwarding on behalf of a caller this scan cannot follow, is invisible
//! here. The review check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `db_gate_not_silent` and
//! `db_tests_are_serialized`.

use std::fs;
use std::path::{Path, PathBuf};

/// The one file allowed to spell a bounded artifact-stream read:
/// `read_artifact_stream` (the full read every consumer of an artifact's
/// history goes through) and `read_expected_version` (the append-version
/// derivation, which refuses over-cap streams for its capping callers).
const ALLOWED_CAPPED_READ_FILE: &str = "crates/hort-app/src/use_cases/mod.rs";

/// The audited bounded budget, as written at the call site. Compared
/// textually after whitespace normalisation — the guard is a source scan, so
/// the expression's *shape* is what it can check.
const CAPPED_BUDGET: &str = "STREAM_EVENT_CAP + 1";

/// An unbounded read: no budget, so nothing to truncate.
const UNBOUNDED_BUDGET: &str = "u64::MAX";

/// The `EventStore::read_stream` parameter name a decorator forwards.
const FORWARDED_BUDGET: &str = "max_count";

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
    let Ok(crates) = fs::read_dir(root.join("crates")) else {
        panic!("crates/ must exist under the workspace root");
    };
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

/// Drop everything a bounded-read rule must not police: the inline test
/// module (and anything after it), plus whole-line comments so prose about
/// `.read_stream(` stays readable.
///
/// Returns the retained text with each dropped line replaced by an empty one,
/// so byte offsets still map back to the original line numbers.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for line in source.lines() {
        // A column-0 `#[cfg(test)]` attribute starts the inline test module;
        // the workspace convention is that such modules come last, so
        // everything from the first one on is test code.
        //
        // `#[cfg(any(test, feature = "test-support"))]` is deliberately NOT a
        // marker: in this workspace it guards individual *items* — a
        // `pub mod test_support;` declaration, a `wrap_for_test` constructor —
        // in the middle of a production file, and treating it as one hid every
        // production read in `use_cases/mod.rs` behind the `test_support`
        // module declaration near the top. Whole test-support module files are
        // dropped by filename instead.
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        let trimmed = line.trim_start();
        let is_comment = trimmed.starts_with("//");
        if in_tests || is_comment {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Split a call's argument text on top-level commas (ignoring commas nested
/// in parens, brackets or angle brackets).
fn split_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in args.chars() {
        match ch {
            '(' | '[' | '<' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_owned());
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    out
}

/// The argument text of the call whose opening paren is at `open`, or `None`
/// when the parens do not balance inside the retained region.
fn call_args(text: &str, open: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open + 1..i].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// The name of the nearest `fn <name>(` declaration before `offset`. Used to
/// confirm that a forwarded `max_count` really is the trait method's own
/// parameter and not a same-named local.
fn enclosing_fn_name(text: &str, offset: usize) -> Option<String> {
    let before = &text[..offset];
    let at = before.rfind("fn ")?;
    let rest = &before[at + 3..];
    let end = rest.find('(')?;
    Some(rest[..end].trim().to_owned())
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Collapse whitespace so `STREAM_EVENT_CAP\n    + 1` compares equal to
/// `STREAM_EVENT_CAP + 1`.
fn normalise(expr: &str) -> String {
    expr.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn bounded_stream_reads_live_only_in_the_audited_reader() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();
    let mut audited_capped_reads = 0usize;

    for path in production_sources(&root) {
        let rel = path
            .strip_prefix(&root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");

        // This guard's own module docs quote the forms it looks for.
        if rel.ends_with("tests/capped_stream_reads.rs") {
            continue;
        }
        // Test-only harnesses: `test_support.rs` is compiled under
        // `cfg(any(test, feature = "test-support"))` and exists to give tests
        // mock `EventStore`s, so its reads are test data by construction.
        if rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs") {
            continue;
        }

        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let text = production_region(&source);

        let mut search = 0usize;
        while let Some(found) = text[search..].find(".read_stream(") {
            let at = search + found;
            let open = at + ".read_stream".len();
            search = open + 1;

            let Some(args) = call_args(&text, open) else {
                violations.push(format!(
                    "{rel}:{} — could not parse the argument list of this \
                     `.read_stream(` call; the guard cannot check its budget",
                    line_of(&text, at)
                ));
                continue;
            };
            let args = split_args(&args);
            let Some(budget) = args.get(2).map(|a| normalise(a)) else {
                violations.push(format!(
                    "{rel}:{} — `.read_stream(` call with fewer than three \
                     arguments; the guard cannot find its budget",
                    line_of(&text, at)
                ));
                continue;
            };

            if budget == UNBOUNDED_BUDGET {
                continue;
            }
            if budget == FORWARDED_BUDGET
                && enclosing_fn_name(&text, at).as_deref() == Some("read_stream")
            {
                continue;
            }
            if budget == CAPPED_BUDGET {
                if rel == ALLOWED_CAPPED_READ_FILE {
                    audited_capped_reads += 1;
                } else {
                    violations.push(format!(
                        "{rel}:{} — a second bounded artifact-stream read. \
                         `{CAPPED_BUDGET}` belongs only in \
                         {ALLOWED_CAPPED_READ_FILE}; call \
                         `use_cases::read_artifact_stream` instead of \
                         re-deriving the overflow check here",
                        line_of(&text, at)
                    ));
                }
                continue;
            }

            violations.push(format!(
                "{rel}:{} — `.read_stream(.., {budget})` bounds the read with \
                 a budget nobody proved sufficient. A read that returns as \
                 many events as its budget allowed cannot tell a complete \
                 stream from a truncated one, so any reverse scan over it \
                 silently answers about the oldest {budget} events. For a \
                 bounded artifact stream call \
                 `use_cases::read_artifact_stream`; for an unbounded stream \
                 category pass `{UNBOUNDED_BUDGET}` or page it explicitly",
                line_of(&text, at)
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "bounded EventStore::read_stream calls outside the audited reader \
         ({} found):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );

    // Counter-assertion: the scan must actually be finding the two audited
    // reads. Without it, a rename of `read_stream` or a change to the
    // truncation heuristic would make this test vacuously green — the way a
    // source-scan guard usually dies.
    assert_eq!(
        audited_capped_reads, 2,
        "expected exactly the two audited bounded reads in \
         {ALLOWED_CAPPED_READ_FILE} (`read_artifact_stream` and \
         `read_expected_version`); found {audited_capped_reads}. If a reader \
         was legitimately added or removed there, update this count \
         deliberately — a drifting count means the scan stopped seeing them"
    );
}
