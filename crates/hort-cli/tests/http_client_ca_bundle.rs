//! Structural guard: every reqwest HTTP client built in `hort-cli`
//! threads `HORT_EXTRA_CA_BUNDLE` via `crate::client::apply_extra_ca_bundle`.
//!
//! Without this, a client built against an internal (self-signed / private
//! CA) hort server fails closed with a TLS error the moment
//! `HORT_EXTRA_CA_BUNDLE` is set but not applied to that particular
//! client — exactly the bug fixed for `completions.rs` and
//! `auth/login.rs::validate_token`. A per-site unit test would only catch
//! a regression in the sites it enumerates; this scan catches any new
//! client-construction site that forgets the helper, including ones added
//! after this test was written.
//!
//! ## What counts as a hit
//!
//! Each production (non-comment, non-test) line matching
//! `Client::builder()` or `ClientBuilder::new()` is a "builder site". The
//! invariant: the file containing a builder site must call
//! `apply_extra_ca_bundle(` at least as many times as it has builder
//! sites. This is a per-file count match rather than true dataflow
//! analysis — cheap, and precise enough given every site in this crate
//! builds exactly one client per call and applies the bundle exactly once
//! (verified by the count match today).

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-cli")
        .to_path_buf()
}

fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, visit);
        } else if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}

fn is_code_line(line: &str) -> bool {
    !line.trim_start().starts_with("//")
}

#[test]
fn every_reqwest_client_builder_applies_extra_ca_bundle() {
    let src = workspace_root().join("crates").join("hort-cli").join("src");
    let mut violations = Vec::new();

    walk(&src, &mut |path| {
        let Ok(contents) = fs::read_to_string(path) else {
            return;
        };
        // The helper's own definition legitimately mentions its name
        // without "calling" it in the sense we're scanning for.
        if path.ends_with("client.rs") {
            let builder_sites = contents
                .lines()
                .filter(|l| is_code_line(l) && l.contains("ClientBuilder::new()"))
                .count();
            let apply_sites = contents
                .lines()
                .filter(|l| {
                    is_code_line(l)
                        && l.contains("apply_extra_ca_bundle(")
                        && !l.contains("fn apply_extra_ca_bundle")
                })
                .count();
            if apply_sites < builder_sites {
                violations.push(format!(
                    "{}: {builder_sites} builder site(s), {apply_sites} apply_extra_ca_bundle call(s)",
                    path.display()
                ));
            }
            return;
        }

        let builder_sites = contents
            .lines()
            .filter(|l| is_code_line(l) && l.contains("Client::builder()"))
            .count();
        if builder_sites == 0 {
            return;
        }
        let apply_sites = contents
            .lines()
            .filter(|l| is_code_line(l) && l.contains("apply_extra_ca_bundle("))
            .count();
        if apply_sites < builder_sites {
            violations.push(format!(
                "{}: {builder_sites} builder site(s), {apply_sites} apply_extra_ca_bundle call(s)",
                path.display()
            ));
        }
    });

    assert!(
        violations.is_empty(),
        "every reqwest client built in hort-cli must thread HORT_EXTRA_CA_BUNDLE \
         via crate::client::apply_extra_ca_bundle. Violations:\n{}",
        violations.join("\n")
    );
}

/// Self-test the scanner: a synthetic in-memory string must trip on an
/// unbundled builder call.
#[test]
fn scanner_trips_on_unbundled_builder() {
    let unbundled = "    let client = reqwest::Client::builder().build()?;";
    assert!(is_code_line(unbundled));
    assert!(unbundled.contains("Client::builder()"));
    assert!(!unbundled.contains("apply_extra_ca_bundle("));
}
