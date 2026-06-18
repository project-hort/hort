//! Streaming-metadata contract structural guard
//! (ADR 0026 — `docs/adr/0026-streaming-metadata-projection.md`).
//!
//! This DB-free, network-free source-scan is the **committed proof**
//! (in the spirit of `ephemeral_keyspace_exhaustive` / `no_bcrypt`)
//! that the upstream-metadata ingest path never buffers the whole body.
//! ADR 0026 makes the no-buffering guarantee a STRUCTURAL property of
//! the `FormatHandler` port: the three metadata methods take a
//! streaming reader (`&mut dyn std::io::Read`) rather than a buffered
//! byte slice (`&[u8]`), and the transitional `metadata_body_bytes`
//! helper that recovered the full-`Vec<u8>` shape was deleted.
//!
//! Coverage % is necessary but not sufficient to keep this property:
//! a refactor could swap a signature back to `&[u8]` (re-buffering at
//! the port boundary) or reintroduce a `metadata_body_bytes(...)` call
//! on a consumer (re-buffering at a call site) and every existing test
//! would still pass. This guard pins both surfaces so the regression
//! is a red test, not a silent erosion.
//!
//! ## What it asserts
//!
//! 1. **Port signatures stream.** In
//!    `crates/hort-domain/src/ports/format_handler.rs`, each of the
//!    three metadata methods —
//!    `parse_upstream_checksum`, `extract_upstream_versions`,
//!    `extract_dependency_specs` — has a body/content parameter typed
//!    `&mut dyn ... Read`, and the file contains NO `body: &[u8]` /
//!    `content: &[u8]` parameter (the retired buffered shape).
//!
//! 2. **No consumer re-buffers via a deleted helper.** No production
//!    (non-test) source under `crates/hort-http-{npm,cargo,pypi}/src`
//!    or `crates/hort-app/src/task_handlers/prefetch_*` invokes
//!    `metadata_body_bytes(`, and no production source under
//!    `crates/hort-http-oci/src` invokes `manifest_body_bytes(` — both
//!    helpers were deleted (ADR 0026); any call is a buffering
//!    regression (and would not even compile, but the source-scan
//!    catches a re-add *before* the use site or in a branch CI does not
//!    build).
//!
//! ## OCI carve-out CLOSED
//!
//! The OCI manifest path used to buffer via `manifest_body_bytes`.
//! ADR 0026 retired it: the manifest pull-through now streams the
//! fetch tempfile straight into CAS, and the tag-pull leg broadcasts the
//! resolved content hash (not the manifest bytes). This guard therefore
//! ALSO bans `manifest_body_bytes(` on the OCI path — the carve-out is
//! gone, and re-introducing the buffered helper there is a regression.
//!
//! ## Why a source-scan and not a type-level trick
//!
//! A `&[u8]` vs `&mut dyn Read` parameter change is a coding-time
//! choice with no runtime artifact to assert against; the only durable,
//! non-flaky proof is to read the port definition and the call sites.
//! No `regex`/`walkdir` dep — `std::fs` recursion + substring scans,
//! same as the sibling guards.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// The three `FormatHandler` metadata methods whose body/content
/// parameter must be a streaming reader (ADR 0026).
const STREAMING_METADATA_METHODS: &[&str] = &[
    "parse_upstream_checksum",
    "extract_upstream_versions",
    "extract_dependency_specs",
];

/// Locate the workspace `crates/` directory from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-domain`), so its parent is `crates/`.
fn crates_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let parent = manifest.parent().expect("CARGO_MANIFEST_DIR has a parent");
    assert!(
        parent.ends_with("crates"),
        "expected CARGO_MANIFEST_DIR's parent to end in 'crates', got {parent:?}"
    );
    parent.to_path_buf()
}

/// Strip Rust line comments (`//`, `///`, `//!`) so prose mentioning a
/// signature or a retired helper name does not self-match. Block
/// comments are not stripped — there are none containing fake
/// signatures or call sites in the scanned files, and one sneaking in
/// would be a self-evidently bad-faith change.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Return the parameter-list substring of `fn <method>(...)` starting
/// at the method declaration: from the `fn method` token to the first
/// top-level `)` that closes the parameter list. `None` if the method
/// is not declared in `source`.
fn fn_param_list<'a>(source: &'a str, method: &str) -> Option<&'a str> {
    let needle = format!("fn {method}(");
    let start = source.find(&needle)?;
    let open = start + needle.len() - 1; // index of the `(`
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open..=i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Recursively collect `.rs` files under `dir` (skipping `target/`,
/// `.git/`, hidden dirs) into `out`.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "target" || name == ".git" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Heuristic: is this path a test file (inline `#[cfg(test)]` lives in
/// `src/` files, but the scan below already strips comments and the
/// only metadata_body_bytes mentions in production source are prose;
/// a real call in a `#[cfg(test)]` block of a production file is still
/// a regression we want to catch, so we do NOT exclude `src/` files —
/// only the dedicated `tests/` integration targets, which are guard
/// tests like this one). Returns true for `.../tests/...` paths.
fn is_integration_test_path(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "tests")
}

/// `true` if `line` contains a call to `ident` — the identifier followed
/// by **optional whitespace** and then `(`. A plain `line.contains("ident(")`
/// is bypassed by a hand-edit that inserts a space before the paren
/// (`metadata_body_bytes (...)` is still a valid Rust call), so the matcher
/// skips any run of spaces/tabs between the identifier and the `(`. It also
/// requires the char immediately before `ident` to NOT be an identifier
/// char, so a longer name ending in `ident` (e.g. `foo_metadata_body_bytes`)
/// does not false-positive.
fn line_calls_ident(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = line[search_from..].find(ident) {
        let start = search_from + rel;
        let end = start + ident.len();
        // Boundary before: the preceding byte must not be an identifier char.
        let boundary_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        if boundary_ok {
            // Skip whitespace (space / tab) between the ident and `(`.
            let mut j = end;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                return true;
            }
        }
        search_from = end;
    }
    false
}

/// Identifier-byte test for the call-matcher boundary check (ASCII
/// alphanumeric or `_`).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[test]
fn format_handler_metadata_methods_take_streaming_readers() {
    let port_path = crates_dir()
        .join("hort-domain")
        .join("src")
        .join("ports")
        .join("format_handler.rs");
    let raw = fs::read_to_string(&port_path).unwrap_or_else(|e| panic!("read {port_path:?}: {e}"));
    let source = strip_line_comments(&raw);

    // (1) The retired buffered parameter shape must not reappear.
    assert!(
        !source.contains("body: &[u8]"),
        "format_handler.rs reintroduced a buffered `body: &[u8]` parameter — \
         the ADR 0026 streaming contract requires `&mut dyn std::io::Read`. \
         The whole-body-never-buffered guarantee is structural at this port boundary."
    );
    assert!(
        !source.contains("content: &[u8]"),
        "format_handler.rs reintroduced a buffered `content: &[u8]` parameter — \
         the ADR 0026 streaming contract requires `&mut dyn std::io::Read`."
    );

    // (2) Each of the three metadata methods must declare a streaming
    //     `&mut dyn ... Read` body/content parameter.
    for method in STREAMING_METADATA_METHODS {
        let params = fn_param_list(&source, method).unwrap_or_else(|| {
            panic!(
                "FormatHandler::{method} not found in {port_path:?} — the streaming \
                 metadata contract guard cannot locate the method it pins. If the \
                 method was renamed, update STREAMING_METADATA_METHODS in this guard."
            )
        });
        let streams = params.contains("&mut dyn")
            && params.contains("Read")
            && (params.contains("body: &mut dyn") || params.contains("content: &mut dyn"));
        assert!(
            streams,
            "FormatHandler::{method} does not take a streaming `&mut dyn ... Read` \
             body/content parameter (ADR 0026). Found parameter list: {params}"
        );
    }
}

#[test]
fn no_metadata_consumer_calls_the_deleted_metadata_body_bytes_helper() {
    let crates = crates_dir();
    // Scan the metadata-consumer production source roots only. The OCI
    // manifest path (`manifest_body_bytes`) has its own dedicated test
    // below and is intentionally NOT scanned here.
    let roots = [
        crates.join("hort-http-npm").join("src"),
        crates.join("hort-http-cargo").join("src"),
        crates.join("hort-http-pypi").join("src"),
        crates.join("hort-app").join("src").join("task_handlers"),
    ];

    let mut files = Vec::new();
    for root in &roots {
        assert!(
            root.exists(),
            "scan root {root:?} does not exist — the guard's path layout drifted; \
             update the roots list in this test."
        );
        collect_rs(root, &mut files);
    }
    files.sort();

    let mut hits: Vec<String> = Vec::new();
    let mut scanned_prefetch = false;
    for path in &files {
        // The dedicated integration-test targets (this guard's siblings)
        // are not consumer source; skip them. Inline `#[cfg(test)]` in
        // `src/` files IS scanned — a call there is still a regression.
        if is_integration_test_path(path) {
            continue;
        }
        // Restrict the task_handlers scan to the prefetch_* handlers
        // (the metadata consumers) per the contract; other task
        // handlers do not touch the metadata fetch path.
        let in_task_handlers = path.components().any(|c| c.as_os_str() == "task_handlers");
        let is_prefetch = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("prefetch_"))
            .unwrap_or(false);
        if in_task_handlers {
            if !is_prefetch {
                continue;
            }
            scanned_prefetch = true;
        }

        let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        for (lineno, line) in raw.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue; // prose referencing the retired helper is allowed
            }
            // Match the CALL form only — `metadata_body_bytes` followed by
            // optional whitespace and `(` — so a doc-comment or identifier
            // mention without the paren does not trip, the OCI
            // `manifest_body_bytes(` sibling is never matched, and a
            // hand-edited `metadata_body_bytes (` (space before paren, still
            // a valid call) cannot slip past the guard.
            if line_calls_ident(line, "metadata_body_bytes") {
                hits.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(&crates).unwrap_or(path).display(),
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        scanned_prefetch,
        "the prefetch_* task-handler scan matched zero files — the guard's \
         prefetch path layout drifted; verify crates/hort-app/src/task_handlers."
    );
    assert!(
        hits.is_empty(),
        "`metadata_body_bytes` was deleted (ADR 0026); a metadata consumer \
         reintroduced a call to it (re-buffering the whole upstream body). \
         The streaming path is `hort_app::project::fetch_and_project` / the \
         per-format projectors. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

#[test]
fn no_oci_manifest_consumer_calls_the_deleted_manifest_body_bytes_helper() {
    // ADR 0026: `manifest_body_bytes` was retired and the OCI manifest
    // pull-through now streams the fetch tempfile into CAS. The
    // carve-out is closed, so a re-added `manifest_body_bytes(` call on
    // the OCI path is a buffering regression — pin it as a red test.
    let crates = crates_dir();
    let root = crates.join("hort-http-oci").join("src");
    assert!(
        root.exists(),
        "scan root {root:?} does not exist — the guard's path layout drifted; \
         update this test."
    );

    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    files.sort();

    let mut hits: Vec<String> = Vec::new();
    for path in &files {
        // Dedicated integration-test targets are not consumer source;
        // skip them. Inline `#[cfg(test)]` in `src/` files IS scanned —
        // a call there is still a regression.
        if is_integration_test_path(path) {
            continue;
        }
        let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        for (lineno, line) in raw.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue; // prose referencing the retired helper is allowed
            }
            // Match the CALL form only — `manifest_body_bytes` followed by
            // optional whitespace and `(` — so a doc-comment or identifier
            // mention without the paren does not trip, and a hand-edited
            // `manifest_body_bytes (` (space before paren) cannot slip past.
            if line_calls_ident(line, "manifest_body_bytes") {
                hits.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(&crates).unwrap_or(path).display(),
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "`manifest_body_bytes` was deleted; an OCI manifest \
         consumer reintroduced a call to it (re-buffering the whole upstream \
         manifest body). The streaming path opens the fetch tempfile as a \
         `tokio::fs::File` and hands it to `ingest_verified`. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Self-tests for the scanner primitives (no I/O) — pin the matcher so a
// future refactor cannot silently weaken it.
// ---------------------------------------------------------------------------

#[test]
fn self_check_fn_param_list_extracts_balanced_parens() {
    let src = "fn extract_upstream_versions(&self, body: &mut dyn std::io::Read) -> X { 0 }";
    let params = fn_param_list(src, "extract_upstream_versions").expect("found");
    assert!(params.contains("body: &mut dyn"));
    assert!(params.contains("Read"));
    assert!(params.ends_with(')'));
}

#[test]
fn self_check_fn_param_list_handles_nested_parens() {
    let src = "fn f(&self, x: Foo<(A, B)>, body: &mut dyn Read) { }";
    let params = fn_param_list(src, "f").expect("found");
    assert!(params.contains("Foo<(A, B)>"));
    assert!(params.contains("body: &mut dyn Read"));
}

#[test]
fn self_check_strip_line_comments_drops_prose_mentions() {
    let src = "// the retired metadata_body_bytes( helper\nlet x = real_call();";
    let stripped = strip_line_comments(src);
    assert!(!stripped.contains("metadata_body_bytes("));
    assert!(stripped.contains("real_call()"));
}

#[test]
fn self_check_streaming_match_rejects_buffered_shape() {
    // A buffered `body: &[u8]` param must NOT satisfy the streaming
    // predicate the test uses.
    let buffered = "(&self, body: &[u8], coords: &C)";
    let streams = buffered.contains("&mut dyn")
        && buffered.contains("Read")
        && (buffered.contains("body: &mut dyn") || buffered.contains("content: &mut dyn"));
    assert!(
        !streams,
        "buffered &[u8] shape must not pass the streaming check"
    );
}

#[test]
fn self_check_line_calls_ident_matches_bare_call() {
    assert!(line_calls_ident(
        "    let b = metadata_body_bytes(handle).await?;",
        "metadata_body_bytes"
    ));
}

#[test]
fn self_check_line_calls_ident_matches_whitespace_before_paren() {
    // The documented bypass: a hand-edited space before the paren is
    // still a valid Rust call and MUST be caught.
    assert!(line_calls_ident(
        "    let b = metadata_body_bytes (handle).await?;",
        "metadata_body_bytes"
    ));
    assert!(line_calls_ident(
        "    let b = metadata_body_bytes\t(handle);",
        "metadata_body_bytes"
    ));
}

#[test]
fn self_check_line_calls_ident_ignores_mention_without_paren() {
    // A bare identifier mention (no call) must NOT trip — e.g. a `use`
    // path or a fn-pointer reference.
    assert!(!line_calls_ident(
        "    let f = metadata_body_bytes;",
        "metadata_body_bytes"
    ));
}

#[test]
fn self_check_line_calls_ident_respects_left_boundary() {
    // A longer identifier ending in the needle must NOT false-positive.
    assert!(!line_calls_ident(
        "    let b = wrap_metadata_body_bytes(handle);",
        "metadata_body_bytes"
    ));
}
