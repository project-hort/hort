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
//! `capped_artifact_read` is the one correct way to do it — read
//! `STREAM_EVENT_CAP + 1` events and carry the "was the budget exhausted?"
//! bit out with them, so each of its three consumers
//! (`read_artifact_stream`, `read_unpaired_append_version`, `ArtifactAtVersion`)
//! refuses or tolerates deliberately rather than by accident. The idiom
//! existed before this guard did, and **convention alone did not hold it**:
//! ten capped-read sites across seven files got it wrong — nine read exactly
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
//!    in [`ALLOWED_CAPPED_READ_FILE`], where it is spelled exactly **once**.
//!    That single read consumes the `+ 1` as overflow detection and hands the
//!    result on. A second copy of this expression anywhere would be a second
//!    reader that has to get the refusal right on its own, which is the
//!    situation this guard exists to end — so the location is part of the
//!    property, not an exemption.
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
//! arguing about test data. So the scan drops `*_tests.rs` files and the
//! `test_support.rs` harnesses by filename, and reads the rest through
//! [`rust_scan::production_region`] — comments and literals blanked, then
//! every `#[cfg(test)]` item blanked **per item**.
//!
//! Per item, not "from the first `#[cfg(test)]` to the end of the file",
//! and the difference is the whole reach of this guard. The truncating form
//! shipped here from the day the guard landed, on the premise that an inline
//! test module comes last in the file. That premise does not hold: a
//! `#[cfg(test)] use std::sync::atomic::…` seam, a `#[cfg(test)]` struct
//! field or a `#[cfg(test)]` interruption hook sits in the *middle* of a
//! production file, and from the first one on the truncating rule read the
//! rest of the file as test code. Measured over `crates/*/src` when this was
//! corrected: **14 files, 3 635 lines of production code** the guard had
//! never looked at — `purge_gc.rs` alone contributing 487 below its atomics
//! `use`. No `.read_stream(` call was hiding in any of them, so the reach was
//! the defect and not a find; a violation landing in one of those 3 635 lines
//! would have been invisible while this test reported green.
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

mod rust_scan;

use rust_scan::{line_of, production_region, walk_rust, workspace_root};

/// The one file allowed to spell a bounded artifact-stream read, and the one
/// function in it that does: `capped_artifact_read`. Everything that asks a
/// question of an artifact's stream goes through it —
/// `read_artifact_stream` (the full read), `read_unpaired_append_version` (the
/// append-version derivation) and `ArtifactAtVersion` (the two together, as
/// one observation).
const ALLOWED_CAPPED_READ_FILE: &str = "crates/hort-app/src/use_cases/mod.rs";

/// The audited bounded budget, as written at the call site. Compared
/// textually after whitespace normalisation — the guard is a source scan, so
/// the expression's *shape* is what it can check.
const CAPPED_BUDGET: &str = "STREAM_EVENT_CAP + 1";

/// An unbounded read: no budget, so nothing to truncate.
const UNBOUNDED_BUDGET: &str = "u64::MAX";

/// The `EventStore::read_stream` parameter name a decorator forwards.
const FORWARDED_BUDGET: &str = "max_count";

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(crates) = fs::read_dir(root.join("crates")) else {
        panic!("crates/ must exist under the workspace root");
    };
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
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

    // Counter-assertion: the scan must actually be finding the audited read.
    // Without it, a rename of `read_stream` or a change to the truncation
    // heuristic would make this test vacuously green — the way a source-scan
    // guard usually dies.
    //
    // The count is **one**, not two: `read_artifact_stream` and
    // `read_unpaired_append_version` used to spell the read each, which is also why
    // a caller needing both paid for two round trips and could observe the
    // stream at two different moments. They now share
    // `capped_artifact_read`, and `ArtifactAtVersion` is the third consumer
    // of that single read.
    assert_eq!(
        audited_capped_reads, 1,
        "expected exactly one audited bounded read in \
         {ALLOWED_CAPPED_READ_FILE} (`capped_artifact_read`, which \
         `read_artifact_stream`, `read_unpaired_append_version` and \
         `ArtifactAtVersion` all go through); found {audited_capped_reads}. \
         If a reader was legitimately added or removed there, update this \
         count deliberately — a drifting count means the scan stopped \
         seeing it"
    );
}

/// The reach of the scan above, pinned: a violation below a mid-file
/// `#[cfg(test)]` item is production code and must be seen.
///
/// This is the defect that shipped with the guard. The region rule used to
/// treat the first column-0 `#[cfg(test)]` as the start of the inline test
/// module and blank everything after it, so a `#[cfg(test)] use …` seam —
/// the shape `hort-adapters-postgres/src/purge_gc.rs` carries at line 202,
/// with 487 lines of production code below it — hid every read in the rest
/// of the file. Seeding a `.read_stream(.., 200)` there left the guard
/// green. The scan over the real tree cannot catch a regression to that
/// rule on its own: with no violation in the tree, the truncating and the
/// per-item rule agree on the verdict and disagree only on how much they
/// read.
///
/// The second half is the opposite error, and it matters just as much: a
/// read inside a `#[cfg(test)]` module is test data (a fixture picks a
/// budget large enough for its own fixture), so a region rule that stopped
/// blanking test code would turn this guard into an argument about
/// fixtures.
#[test]
fn the_scan_reads_production_code_below_a_cfg_test_item() {
    let source = "\
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

async fn production_reader(&self) {
    self.event_store.read_stream(&id, ReadFrom::Start, 200).await;
}

#[cfg(test)]
mod tests {
    async fn fixture(&self) {
        self.event_store.read_stream(&id, ReadFrom::Start, 4096).await;
    }
}
";
    let region = production_region(source);
    assert!(
        region.contains("read_stream(&id, ReadFrom::Start, 200)"),
        "the production read below the `#[cfg(test)] use` seam must survive \
         the region pass — blanking it is the blind spot this guard shipped \
         with, and a violation there reads as green:\n{region}"
    );
    assert!(
        !region.contains("4096"),
        "the read inside the `#[cfg(test)] mod` must be blanked — a fixture \
         chooses its own budget and this guard has no business policing \
         it:\n{region}"
    );
}
