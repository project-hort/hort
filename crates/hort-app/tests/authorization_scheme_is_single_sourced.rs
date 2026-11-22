//! Structural guard: the inbound `Authorization` auth-scheme rule has one definition.
//!
//! RFC 7235 §2.1 matches the scheme token ASCII-case-insensitively and uses
//! `1*SP` before a credential. Six inbound consumers used to re-type that
//! decision as `strip_prefix("Bearer ")` or `strip_prefix("Basic ")`.
//! All six copies were case-sensitive and consumed exactly one space, while
//! the outbound challenge reader got the token rule right. A conforming
//! credential then fell through to an anonymous response with no signal
//! identifying the scheme mismatch. Convention did not keep the copies in
//! agreement; [`strip_auth_scheme`] now answers both parts together.
//!
//! ## The property
//!
//! In production Rust of the inbound HTTP auth pipeline, a scheme-exclusive
//! comparison against an `Authorization` value belongs only in
//! [`DEFINITION_FILE`]. [`REJECTED_FORMS`] names the old prefix idiom and
//! equivalent comparisons. The literal classifier accepts any RFC 7235
//! token followed by `1*SP`, so adding `Digest`, `Negotiate`, or a later
//! scheme with the old idiom fails without updating this guard's vocabulary.
//! A bare token compared to a variable named for the scheme is also caught.
//!
//! Constructing a `WWW-Authenticate` value, such as
//! `format!("Bearer realm=…")`, emits a challenge rather than testing a
//! credential. The existing comparison in `unauthorized_invalid_token`
//! reads a challenge returned by `www_authenticate_for` to append an error
//! parameter; it does not read `Authorization`. The OCI `Content-Range`
//! parser's `bytes ` prefix is likewise a different header grammar.
//!
//! ## Scope — derived, not enumerated
//!
//! [`INBOUND_PIPELINE`] follows ADR 0008's layers: `hort-http-core` is
//! shared inbound middleware, `hort-http-*` are per-format inbound
//! adapters, `hort-app` orchestrates them, and `hort-formats` parses format
//! payloads. The latter two should not see an HTTP `Authorization` value;
//! a scheme comparison there would also expose a layering error. An
//! `hort-adapters-*` crate is outbound, so its `challenge.rs` is outside
//! this pipeline by derivation: it parses someone else's `challenge` ABNF,
//! not inbound `credentials`, and ADR 0008 forbids depending on the inbound
//! core from that adapter. No path exemption is needed.
//!
//! Test code is excluded by compilation: `tests/` is outside `src/`,
//! `#[cfg(test)]` items are blanked by the shared lexer, and separate
//! `src/test_*` / `src/*_tests` modules are compiled only under that cfg.
//!
//! ## Counter-assertions and limits
//!
//! A missing rule name or a missing one of the six known calls makes the
//! guard fail even if no duplicate exists. The source scan also checks
//! that a new scheme spelled with the old prefix idiom is classified.
//! A comparison assembled through a macro, or one written against a
//! separately split token under an unrelated variable name, still needs
//! review; a source scan cannot prove arbitrary data flow.
//!
//! DB-free, so the workspace test gate runs it without PostgreSQL.
//!
//! [`strip_auth_scheme`]: hort_http_core::auth_scheme::strip_auth_scheme

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{blank_cfg_test_items, line_of, mark_literals, production_region, walk_rust};

/// The one file allowed to define how an inbound scheme is matched.
const DEFINITION_FILE: &str = "crates/hort-http-core/src/auth_scheme.rs";
const RULE_FN: &str = "strip_auth_scheme";
const RULE_ENUM: &str = "AuthScheme";

/// Method and operator spellings that can re-type the scheme decision.
/// `format!` is absent because it constructs a value rather than comparing one.
const REJECTED_FORMS: &[&str] = &[
    "strip_prefix",
    "starts_with",
    "split_once",
    "eq_ignore_ascii_case",
    "==",
    "!=",
];

/// Crate families capable of receiving or incorrectly taking over inbound
/// auth work under ADR 0008. Outbound adapters do not match these prefixes.
const INBOUND_PIPELINE: &[&str] = &[
    "crates/hort-http-",
    "crates/hort-app/src/",
    "crates/hort-formats/src/",
];

/// Production consumers, measured per file. A missing call is a missing
/// rule application, which a duplicate-definition scan alone cannot see.
const EXPECTED_CALL_SITES: &[(&str, usize)] = &[
    ("crates/hort-http-core/src/middleware/auth.rs", 3),
    ("crates/hort-http-oci/src/middleware/oci_auth.rs", 2),
    ("crates/hort-http-oci/src/v2_auth.rs", 1),
];

#[derive(Debug)]
struct Comparison {
    file: String,
    line: usize,
    form: &'static str,
    literal: String,
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned file is under workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = fs::read_dir(root.join("crates")).expect("crates/ exists");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// Test-only source files are included through `#[cfg(test)]` module
/// declarations; the attribute is in their parent file, not their body.
fn is_separate_test_module(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.starts_with("test_") || stem.ends_with("_tests"))
}

/// Return the contents of an ordinary or raw string literal. The scheme
/// spellings contain no escapes, so an escaped literal is not a token test.
fn literal_content(raw: &str) -> Option<&str> {
    let first = raw.find('"')?;
    let last = raw.rfind('"')?;
    (last > first).then(|| &raw[first + 1..last])
}

/// RFC 7235 `token` followed by one or more literal spaces, with no
/// credential bytes in the literal. This is open to future scheme names.
fn is_scheme_prefix(value: &str) -> bool {
    let token = value.trim_end_matches(' ');
    !token.is_empty() && token.len() < value.len() && token.bytes().all(is_token_byte)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_bare_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_token_byte)
}

/// The method and receiver immediately before a literal argument.
fn method_and_receiver(code: &str, start: usize) -> Option<(&str, &str)> {
    let before = code[..start].trim_end();
    let before = before.strip_suffix('(')?.trim_end();
    let dot = before.rfind('.')?;
    let method = before[dot + 1..].trim();
    let left = before[..dot].trim_end();
    let receiver_start = left
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .map_or(0, |at| at + 1);
    Some((method, &left[receiver_start..]))
}

/// An exact exception for a comparison whose input is demonstrably another
/// header production, not an `Authorization` credential. Neither exception
/// suppresses a different scheme literal added in the same function.
fn compares_other_header(rel: &str, code: &str, at: usize, receiver: &str, literal: &str) -> bool {
    let in_fn = rust_scan::parse_fns(code)
        .into_iter()
        .find(|item| item.span.0 <= at && at < item.span.1)
        .map(|item| item.name);
    matches!(
        (rel, in_fn.as_deref(), receiver, literal),
        (
            "crates/hort-http-core/src/middleware/auth.rs",
            Some("unauthorized_invalid_token"),
            "challenge",
            "Bearer "
        ) | (
            "crates/hort-http-oci/src/uploads.rs",
            Some("parse_content_range"),
            "trimmed",
            "bytes "
        )
    )
}

/// Compare a string literal against scheme-test syntax in the surrounding
/// code. The shared lexer keeps literal offsets while blanking comments and
/// `#[cfg(test)]` items, so prose and fixtures cannot satisfy the scan.
fn comparison_form(
    code: &str,
    at: usize,
    end: usize,
    literal: &str,
) -> Option<(&'static str, String)> {
    if is_scheme_prefix(literal) {
        if let Some((method, receiver)) = method_and_receiver(code, at) {
            for form in &REJECTED_FORMS[..4] {
                if method == *form {
                    return Some((form, receiver.to_owned()));
                }
            }
        }
        let before = code[..at].trim_end();
        let after = code[end..].trim_start();
        for form in &REJECTED_FORMS[4..] {
            if before.ends_with(form) || after.starts_with(form) {
                return Some((form, String::new()));
            }
        }
    }

    // A separately split scheme token can be compared without the SP.
    // Its receiver has to name the scheme to distinguish it from ordinary
    // token comparisons elsewhere in the HTTP and format crates.
    if is_bare_token(literal) {
        if let Some(("eq_ignore_ascii_case", receiver)) = method_and_receiver(code, at) {
            if receiver.contains("scheme") {
                return Some(("eq_ignore_ascii_case", receiver.to_owned()));
            }
        }
    }
    None
}

fn comparisons_in_source(rel: &str, source: &str) -> Vec<Comparison> {
    let (marked, spans) = mark_literals(source);
    let code = blank_cfg_test_items(&marked);
    let mut out = Vec::new();
    for (start, end) in spans {
        if code.as_bytes().get(start) != Some(&rust_scan::LITERAL_MARK) {
            continue;
        }
        let Some(literal) = literal_content(&source[start..end]) else {
            continue;
        };
        let Some((form, receiver)) = comparison_form(&code, start, end, literal) else {
            continue;
        };
        if compares_other_header(rel, &code, start, &receiver, literal) {
            continue;
        }
        out.push(Comparison {
            file: rel.to_owned(),
            line: line_of(&code, start),
            form,
            literal: literal.to_owned(),
        });
    }
    out
}

fn comparisons(root: &Path) -> Vec<Comparison> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        if !INBOUND_PIPELINE
            .iter()
            .any(|prefix| rel.starts_with(prefix))
            || is_separate_test_module(&path)
        {
            continue;
        }
        let source = fs::read_to_string(&path).expect("production Rust is readable UTF-8");
        out.extend(comparisons_in_source(&rel, &source));
    }
    out
}

fn count_rule_calls(root: &Path, rel: &str) -> usize {
    let source = fs::read_to_string(root.join(rel)).expect("known source exists and is readable");
    let code = production_region(&source);
    code.match_indices(RULE_FN)
        .filter(|(at, _)| {
            code[at + RULE_FN.len()..].trim_start().starts_with('(')
                && (*at == 0 || !rust_scan::is_ident_byte(code.as_bytes()[at - 1]))
        })
        .count()
}

#[test]
fn the_inbound_scheme_rule_has_one_definition() {
    let root = rust_scan::workspace_root();
    let stray: Vec<String> = comparisons(&root)
        .into_iter()
        .filter(|hit| hit.file != DEFINITION_FILE)
        .map(|hit| {
            format!(
                "{}:{} — {}({:?})",
                hit.file, hit.line, hit.form, hit.literal
            )
        })
        .collect();
    assert!(
        stray.is_empty(),
        "an inbound Authorization scheme is compared outside {DEFINITION_FILE}. \
         Call `hort_http_core::auth_scheme::{RULE_FN}` instead.\n{}",
        stray.join("\n")
    );
}

#[test]
fn every_known_consumer_calls_the_shared_rule() {
    let root = rust_scan::workspace_root();
    for (rel, expected) in EXPECTED_CALL_SITES {
        assert_eq!(
            count_rule_calls(&root, rel),
            *expected,
            "{rel}: the call-site census changed; review any missing or new consumer"
        );
    }
}

#[test]
fn the_definition_and_scan_are_real() {
    let root = rust_scan::workspace_root();
    let source = fs::read_to_string(root.join(DEFINITION_FILE)).expect("definition file exists");
    let code = production_region(&source);
    assert_eq!(count_rule_calls(&root, DEFINITION_FILE), 1);
    assert_eq!(code.matches(&format!("pub fn {RULE_FN}(")).count(), 1);
    assert_eq!(code.matches(&format!("pub enum {RULE_ENUM}")).count(), 1);
    assert!(code.contains("candidate.eq_ignore_ascii_case(token)"));
    assert!(code.contains("trim_start_matches"));

    // Both the old spelling and a newly introduced scheme must go red.
    for scheme in ["Bearer", "Basic", "Digest", "Negotiate", "FutureScheme"] {
        let source = format!("fn parse(raw: &str) {{ let _ = raw.strip_prefix(\"{scheme} \"); }}");
        assert_eq!(
            comparisons_in_source("crates/hort-http-core/src/new.rs", &source).len(),
            1
        );
    }
    assert!(comparisons_in_source(
        "crates/hort-http-core/src/new.rs",
        "// raw.strip_prefix(\"Digest \")\n#[cfg(test)] mod tests { fn x() { raw.strip_prefix(\"Digest \"); } }"
    )
    .is_empty());
    assert_eq!(
        comparisons_in_source(
            "crates/hort-http-core/src/new.rs",
            "fn parse(raw: &str) { let _ = raw.starts_with(\"Digest \" ); }"
        )
        .len(),
        1
    );
    assert_eq!(
        comparisons_in_source(
            "crates/hort-http-core/src/new.rs",
            "fn parse(raw: &str) { let _ = raw.split_once(\"Negotiate \" ); }"
        )
        .len(),
        1
    );
    assert_eq!(
        comparisons_in_source(
            "crates/hort-http-core/src/new.rs",
            "fn parse(raw: &str) { let _ = raw == \"Digest \"; }"
        )
        .len(),
        1
    );
    assert!(comparisons_in_source(
        "crates/hort-http-core/src/new.rs",
        "fn challenge() { let _ = format!(\"Bearer realm=x\"); }"
    )
    .is_empty());
}
