//! Structural guard: **no production file reads an artifact's stream and
//! separately derives the version its append must carry.**
//!
//! A site that decides an artifact's lifecycle outcome from stored evidence
//! and commits that decision behind an optimistic append has exactly one
//! correct order: read the expected stream version *beside* the state the
//! decision rests on, then derive, then append. Read the version afterwards
//! and the append stops protecting the decision — a verdict that committed in
//! between is already contained in the version just read, so the append does
//! not conflict, it succeeds, and the stale decision's status lands on top of
//! the newer one.
//!
//! `hort_app::use_cases::ArtifactAtVersion` is the shape that makes that order
//! inexpressible: the artifact, the complete stream and the `ExpectedVersion`
//! come back from ONE capped read, so a caller holding the evidence already
//! holds the version that read proves. There is no "before" left to get wrong.
//! (`read_artifact_stream_at_version` is the same pairing for a caller that
//! needs no artifact row.)
//!
//! What a type cannot prevent is a NEW site declining to use it — reaching for
//! `read_artifact_stream` for the evidence and the unpaired version read for
//! the version, as four call sites did before the pairing existed. That
//! combination in one file is what this guard rejects.
//!
//! ## The property
//!
//! No file under `crates/*/src` calls both `read_artifact_stream(` and
//! `read_unpaired_append_version(` in production code.
//!
//! The two have disjoint legitimate audiences, and the disjointness is the
//! point:
//!
//! - `read_artifact_stream` is for readers that derive **no append** from what
//!   they read (a retention sweep deciding whether a stream is already
//!   expired, the release-gate clearance behind a read-path candidacy check).
//! - `read_unpaired_append_version` is for appends that protect **no decision**
//!   read from the stream, and says so at every call site: its mandatory
//!   `UnpairedAppend` witness makes the caller name *why* there is no evidence
//!   to pair with (a freshly minted artifact's genesis event, a follow-up on a
//!   stream the same call created, an append whose content comes entirely from
//!   the caller's request).
//!
//! A file wanting both is, with high likelihood, a site deriving a decision
//! from one and protecting it with the other — across two reads, with a
//! window between them. That is a review conversation, not an allow-list
//! entry: either the site pairs the two reads (use `ArtifactAtVersion`) or it
//! genuinely has two unrelated concerns and wants splitting. **This guard has
//! no allow-list, by design.**
//!
//! ## Scope, and what this cannot see
//!
//! Production code only, and the definition site itself is excluded —
//! `use_cases/mod.rs` declares both functions and the pairing that unifies
//! them. Whole-line comments are dropped so prose naming either function stays
//! readable, and everything from a file's first column-0 `#[cfg(test)]` on is
//! dropped (the workspace convention is that inline test modules come last).
//!
//! The blind spot every source scan has applies, and it is why the names
//! rather than this scan carry the weight. A file that reads the stream
//! through a helper in *another* file is invisible here — the one such helper
//! is `release_clearance::read_path_provenance_clearance`, and a new caller
//! could compose it with an unpaired version read of its own without tripping
//! anything below. Deriving a version by hand from
//! `persisted.last().stream_position` instead of calling the reader is
//! likewise invisible; that is what `provenance_cascade::read_clearance_state`
//! used to do.
//!
//! Adding a literal per newly-discovered spelling is a losing game, so the
//! close for both is in the names, not here: the read-path clearance helper
//! says *read path*, the unpaired version reader says *unpaired* and demands a
//! witness, and none of that witness's variants is true of a caller that just
//! read evidence. The composition stays writable; it stops being writable by
//! accident. This guard keeps the cheap case — both reads in one file — a hard
//! failure, and the review check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads`.

use std::fs;
use std::path::{Path, PathBuf};

/// The full-stream reader, for consumers that derive no append.
const FULL_STREAM_READ: &str = "read_artifact_stream(";

/// The append-version derivation, for appends that protect no decision read
/// from the stream. Named for its unpairedness, and it takes an
/// `UnpairedAppend` witness: a caller reaches it only by declaring that it
/// read no evidence.
const VERSION_READ: &str = "read_unpaired_append_version(";

/// Where both live, together with the `ArtifactAtVersion` pairing that unifies
/// them. Excluded because defining the two is not using them.
const DEFINITION_FILE: &str = "crates/hort-app/src/use_cases/mod.rs";

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

/// Drop the inline test module (and everything after it) plus whole-line
/// comments, so the scan sees only production code and no prose. Dropped lines
/// become empty ones, keeping byte offsets aligned with line numbers.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for line in source.lines() {
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        if in_tests || line.trim_start().starts_with("//") {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A whole-file-path test-support marker: these files are harnesses, and a
/// fixture may legitimately do either read with arbitrary intent.
fn is_test_support(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name == "test_support.rs" || name.ends_with("_tests.rs")
}

fn line_of(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].matches('\n').count() + 1
}

#[test]
fn evidence_and_append_version_are_never_read_separately() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let mut full_stream_read_files = 0usize;
    let mut version_read_files = 0usize;

    for path in production_sources(&root) {
        if is_test_support(&path) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == DEFINITION_FILE {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let text = production_region(&source);

        let stream_at = text.find(FULL_STREAM_READ);
        let version_at = text.find(VERSION_READ);
        if stream_at.is_some() {
            full_stream_read_files += 1;
        }
        if version_at.is_some() {
            version_read_files += 1;
        }
        if let (Some(s), Some(v)) = (stream_at, version_at) {
            violations.push(format!(
                "{rel}: reads the artifact stream at line {} and derives an \
                 append version at line {} — two reads of the same stream with \
                 a window between them. If a decision here is derived from the \
                 stream and committed behind that append, pair them: \
                 `use_cases::ArtifactAtVersion` (or \
                 `read_artifact_stream_at_version` when no artifact row is \
                 needed) returns both from one read. If the two are genuinely \
                 unrelated concerns, they do not belong in one file",
                line_of(&text, s),
                line_of(&text, v),
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "artifact-stream evidence read separately from the append version \
         ({} file(s)):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );

    // Counter-assertion: the scan must still be finding both populations.
    // Without it, a rename of either function — or a change to the
    // production-region heuristic — makes this test vacuously green, the way a
    // source-scan guard usually dies.
    assert!(
        full_stream_read_files > 0 && version_read_files > 0,
        "expected to find production callers of BOTH `{FULL_STREAM_READ}` \
         ({full_stream_read_files} file(s)) and `{VERSION_READ}` \
         ({version_read_files} file(s)); a zero on either side means the scan \
         stopped seeing them and this guard is no longer checking anything"
    );
}
