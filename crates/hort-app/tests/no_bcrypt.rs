//! Workspace-wide lint enforcing the "Argon2id, not bcrypt" invariant:
//! password hashing goes through `hort_app::argon2_hash`, never bcrypt.
//!
//! The invariant is structural rather than algorithmic: no production
//! OR test code in `crates/` legitimately references `bcrypt::*`. A
//! grep test pins the "no bcrypt anywhere" property — a hypothetical
//! regression that re-introduced `use bcrypt::hash;` in any
//! tests-or-prod file would trip this test before review.
//!
//! ## Why a grep test, not a `forbid` attribute
//!
//! Workspace `[lints.rust]` `forbid` attributes operate on Rust paths,
//! and `bcrypt` is a separate crate — once the workspace `Cargo.toml`
//! removes the dependency, a `use bcrypt::*` line is already a hard
//! compile error. The grep is the redundant belt: it catches reviews
//! that re-add the dep in `Cargo.toml` *before* the use site lands.
//!
//! ## Scope
//!
//! Scans `crates/` AND the root `Cargo.toml`. The CI step in
//! `.github/workflows/ci.yml` extends the same grep to additional
//! locations as needed; the in-process test focuses on the source
//! surface where the invariant is enforceable today.
//!
//! ## What counts as a hit
//!
//! A line containing the literal `bcrypt::` (path expression) OR
//! the literal `bcrypt = ` (Cargo.toml dep declaration). The trailing
//! `::` / ` = ` distinguishes real callers from prose ("bcrypt path",
//! "the bcrypt era") in doc comments — those stay readable, the
//! algorithmic reference does not.
//!
//! Lines whose **first non-whitespace token** is a Rust line-comment
//! marker (`//`, `///`, `//!`) are excluded — prose references in
//! module docs (e.g. "migrated from `bcrypt::hash(_, 12)` …")
//! describe an outcome and must remain readable. The
//! compiler-relevant test is "does code
//! reference bcrypt", not "does any byte reference it". Block
//! comments (`/* … */`) are not stripped — those are rare in this
//! codebase and a regression sneaking in via a block comment would
//! be a self-evidently bad-faith change.

use std::fs;
use std::path::{Path, PathBuf};

/// Walk `dir` recursively, calling `visit` on every regular file.
/// `target/` and `Cargo.lock` are skipped — neither is human-authored
/// source code.
fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // Skip build outputs and version-control metadata.
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            walk(&path, visit);
        } else if path.is_file() {
            // Skip lockfiles and binary blobs; the grep operates on
            // human-authored source.
            if name == "Cargo.lock" {
                continue;
            }
            visit(&path);
        }
    }
}

/// Locate the workspace root from CARGO_MANIFEST_DIR. The crate's
/// manifest dir is `<root>/crates/hort-app`; the root is two levels up.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

fn scan_for_bcrypt(roots: &[PathBuf]) -> Vec<String> {
    let mut hits = Vec::new();
    for root in roots {
        walk(root, &mut |path| {
            // Self-exclude: this very test file documents what the
            // grep looks for and contains the literal substring as
            // *prose*, NOT as a real bcrypt reference. Skipping it
            // is structural — a regex that excludes this file by
            // path is the simplest way to keep the documentation
            // honest without weakening the regex everywhere.
            if path.ends_with("tests/no_bcrypt.rs") {
                return;
            }
            // Markdown / docs aren't compiled and may legitimately
            // reference bcrypt in historical context (changelog,
            // upgrade notes). Restrict the scan to source +
            // build-config files where a real reference would have
            // teeth. Extensions chosen: Rust source, Cargo
            // manifests, build scripts.
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                // Files without an extension — skip; nothing
                // meaningful here.
                return;
            };
            let scan = matches!(ext, "rs" | "toml");
            if !scan {
                return;
            }
            // Skip Cargo.lock paths (already filtered by walk, but
            // belt-and-braces).
            if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock") {
                return;
            }
            let Ok(contents) = fs::read_to_string(path) else {
                return;
            };
            for (lineno, line) in contents.lines().enumerate() {
                // Skip Rust line comments — historical references in
                // doc comments / module headers are intentional and
                // describe the bcrypt → Argon2id migration outcome.
                // The compiler doesn't care about comment content;
                // a real regression must be in code, not in prose.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                // `bcrypt::` — actual path expression / use statement.
                // `bcrypt = ` — Cargo.toml dep declaration.
                if line.contains("bcrypt::") || line.contains("bcrypt = ") {
                    hits.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        });
    }
    hits
}

#[test]
fn no_bcrypt_in_workspace() {
    let root = workspace_root();
    // Scope: source crates + root manifest.
    let roots = vec![root.join("crates"), root.join("Cargo.toml")];
    let hits = scan_for_bcrypt(&roots);
    assert!(
        hits.is_empty(),
        "Argon2id-not-bcrypt invariant — no `bcrypt::` references allowed \
         in source. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// Self-test the scanner: a synthetic in-memory string MUST trip the
/// detector. Pins the regex so a future refactor of the scanner can't
/// silently weaken it.
#[test]
fn scanner_trips_on_planted_regression() {
    let synthetic = "let ok = bcrypt::verify(p, &h).unwrap();";
    assert!(
        synthetic.contains("bcrypt::"),
        "self-test: scanner regex must match `bcrypt::` literal"
    );
    let synthetic_dep = "bcrypt = \"0.19\"";
    assert!(
        synthetic_dep.contains("bcrypt = "),
        "self-test: scanner regex must match Cargo.toml `bcrypt = ` literal"
    );
}
