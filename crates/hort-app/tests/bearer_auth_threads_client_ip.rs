//! Source guard over every `crates/*/src` file: a production bearer-auth
//! call site threads the trust-resolved client IP.
//!
//! ## The invariant
//!
//! `AuthenticateUseCase` has two bearer entry points.
//! `authenticate_bearer_with_client_ip(token, client_ip)` is the real
//! one: on a PAT-shaped token it reaches
//! `PatValidationUseCase::validate_pat`, which keys a per-IP
//! brute-force lockout (30 failures / 5 min → 15 min) on the bucketed
//! client IP. `authenticate_bearer(token)` delegates to it with `None`,
//! and `None` **disables that lockout** — `validate_pat` builds no
//! `LockoutKeys` at all, so it neither consults the flag nor counts the
//! failure.
//!
//! So a production credential path calling the two-argument form is not
//! a style question. It silently removes the only per-IP bound on
//! Argon2id-cost credential guessing, and it does so without changing
//! any response, metric or log — which is precisely how all four
//! production call sites came to use it while the client-IP-aware entry
//! point had no caller outside its own file at all, and while the
//! two-argument form's own doc comment asserted the opposite.
//!
//! Convention did not hold this. A doc comment did not hold it either.
//! A scan does.
//!
//! ## What counts as a hit
//!
//! A call to `authenticate_bearer(` in the production region (comments,
//! string literals and `#[cfg(test)]` items blanked) of any
//! `crates/*/src/**/*.rs`, except the single delegation inside
//! `AuthenticateUseCase::authenticate_bearer` itself, which is the
//! definition of the convenience wrapper rather than a consumer of it.
//! That exception is **structural, not an allow-list entry**: it is
//! recognised by being the call inside the `fn authenticate_bearer`
//! item, so moving the wrapper does not move an exemption and planting
//! a second call beside it is still a hit.
//!
//! Test code keeps the two-argument form — in-process callers have no
//! request and therefore no client IP to thread, and ~50 of them read
//! better for it. `production_region` is what draws that line, so it is
//! drawn by how the code is compiled rather than by a list.
//!
//! ## The read path is not an exemption, it is a named decision
//!
//! One production credential path deliberately does not attribute:
//! `extract_optional_principal`, the read path, where a per-IP lockout
//! would let an unauthenticated caller deny its whole /24's *writes*
//! for fifteen minutes. It does not get an entry here. It calls
//! `AuthenticateUseCase::authenticate_bearer_read_path_without_ip_lockout`,
//! whose name states the decision at the call site and whose doc
//! carries the reasoning — the same posture as
//! `mint_authenticated_principal_for_format_middleware` in
//! `hort-http-core`. Keeping that decision in the code rather than in
//! this file is what lets the guard run with no allow-list: a reviewer
//! reads the choice where the choice is made.
//!
//! ## What this guard cannot see
//!
//! It is a source scan. A call reached through a trait object typed as
//! something else, or assembled by a macro, is invisible to it — the
//! same limit every guard in this family accepts. The behavioural
//! tests beside it (`/v2/auth` bucket attribution in
//! `hort-http-oci/tests/v2_auth_e2e.rs`, the write-path lockout in
//! `hort-http-core`) cover the paths where a wrong IP is observable;
//! this covers the paths where it is not, which is where the defect
//! survived.
//!
//! ## Where the lexer lives
//!
//! `tests/rust_scan/mod.rs`, shared with the sibling guards. What stays
//! here is this guard's policy: the two entry-point names, the
//! structural exception, the per-file census and the self-checks.

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{is_ident_byte, line_of, parse_fns, production_region, walk_rust, workspace_root};

/// The entry point that disables the per-IP lockout by delegating with
/// `None`. Banned in production code.
const UNTHREADED: &str = "authenticate_bearer";

/// The entry point that arms it.
const THREADED: &str = "authenticate_bearer_with_client_ip";

/// The file that defines both, and the only place the unthreaded call
/// may appear in production source.
const DEFINITION_FILE: &str = "crates/hort-app/src/use_cases/authenticate_use_case.rs";

/// Every production credential path that must thread the client IP.
/// Asserted as a census so a path that stops threading — by being
/// deleted, renamed, or rewritten back onto the unthreaded form — fails
/// here rather than going quiet.
const EXPECTED_THREADED_SITES: [&str; 4] = [
    "crates/hort-http-core/src/handlers/exchange.rs",
    "crates/hort-http-core/src/middleware/auth.rs",
    "crates/hort-http-oci/src/middleware/oci_auth.rs",
    DEFINITION_FILE,
];

#[derive(Debug, PartialEq, Eq)]
struct Hit {
    rel: String,
    line: usize,
}

/// True when the identifier at `at` is the name in a `fn` declaration
/// rather than a call: the preceding token is the `fn` keyword. Without
/// this, `fn authenticate_bearer(` reads as a call to itself and every
/// file defining the method reports a finding.
fn is_declaration(bytes: &[u8], at: usize) -> bool {
    let mut end = at;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    &bytes[start..end] == b"fn"
}

/// Offsets of every call to `name` in `text`: the identifier on a token
/// boundary, followed (modulo whitespace) by `(`, and not the name in a
/// `fn` declaration. Matching the call and not the bare name keeps a doc
/// link, a field or an import out of the result; requiring the left
/// boundary is what stops `THREADED` from also matching as `UNTHREADED`
/// plus a suffix.
fn call_offsets(text: &str, name: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = text[from..].find(name) {
        let at = from + offset;
        from = at + name.len();
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        if is_declaration(bytes, at) {
            continue;
        }
        let mut after = at + name.len();
        if after < bytes.len() && is_ident_byte(bytes[after]) {
            // A longer identifier starting with `name` — notably
            // `authenticate_bearer_with_client_ip`. Not this call.
            continue;
        }
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if after < bytes.len() && bytes[after] == b'(' {
            out.push(at);
        }
    }
    out
}

/// Byte range of the `fn authenticate_bearer` item's body in `text`, if
/// the file defines it. The one call inside it is the wrapper's own
/// delegation.
fn wrapper_body_range(text: &str) -> Option<(usize, usize)> {
    let item = parse_fns(text)
        .into_iter()
        .find(|item| item.name == UNTHREADED)?;
    let at = text.find(&item.body)?;
    Some((at, at + item.body.len()))
}

/// Unthreaded calls in one file's production region.
fn unthreaded_calls(source: &str) -> Vec<usize> {
    let text = production_region(source);
    let wrapper = wrapper_body_range(&text);
    call_offsets(&text, UNTHREADED)
        .into_iter()
        .filter(|at| match wrapper {
            Some((from, to)) => *at < from || *at >= to,
            None => true,
        })
        .map(|at| line_of(&text, at))
        .collect()
}

/// Whether one file's production region threads the client IP anywhere.
fn threads_client_ip(source: &str) -> bool {
    !call_offsets(&production_region(source), THREADED).is_empty()
}

/// Every `crates/*/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let crates = root.join("crates");
    let mut out = Vec::new();
    let entries = fs::read_dir(&crates).expect("crates/ exists under the workspace root");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

fn rel_of(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

fn scan_unthreaded(root: &Path) -> Vec<Hit> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        for line in unthreaded_calls(&source) {
            out.push(Hit {
                rel: rel_of(root, &path),
                line,
            });
        }
    }
    out
}

fn scan_threaded(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        if threads_client_ip(&source) {
            out.push(rel_of(root, &path));
        }
    }
    out
}

#[test]
fn no_production_bearer_call_site_drops_the_client_ip() {
    let hits = scan_unthreaded(&workspace_root());
    assert!(
        hits.is_empty(),
        "these production call sites authenticate a bearer credential without a \
         client IP, which disables the PAT per-IP brute-force lockout (a `None` \
         client_ip builds no LockoutKeys, so the failure is neither counted nor \
         consulted). Read `RequestTrust.client_ip` from the request extensions \
         and call `{THREADED}`:\n{}",
        hits.iter()
            .map(|hit| format!("  {}:{}", hit.rel, hit.line))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_expected_credential_path_still_threads_the_client_ip() {
    // Counter-assertion: the ban above goes green the moment the calls
    // disappear, including when they disappear because the method was
    // renamed or a credential path was rewritten to skip the use case.
    // Pin the census so that reads as a failure here.
    let found = scan_threaded(&workspace_root());
    for expected in EXPECTED_THREADED_SITES {
        assert!(
            found.iter().any(|rel| rel == expected),
            "{expected} no longer calls {THREADED}; if that path moved, move this \
             census entry with it — do not delete it. Found: {found:?}"
        );
    }
}

#[test]
fn the_definition_file_still_defines_both_entry_points() {
    // The other half of the same counter-assertion: a rename of either
    // method would otherwise make the scan vacuously green.
    let source = fs::read_to_string(workspace_root().join(DEFINITION_FILE))
        .expect("the authenticate use case is readable UTF-8");
    let text = production_region(&source);
    let names: Vec<String> = parse_fns(&text).into_iter().map(|item| item.name).collect();
    assert!(
        names.iter().any(|name| name == UNTHREADED),
        "{DEFINITION_FILE} no longer defines `{UNTHREADED}`"
    );
    assert!(
        names.iter().any(|name| name == THREADED),
        "{DEFINITION_FILE} no longer defines `{THREADED}`"
    );
}

#[test]
fn the_scanner_trips_on_an_unthreaded_production_call() {
    let planted = "async fn require_principal(req: Request) -> Response {\n    \
                   match authenticate.authenticate_bearer(&token).await {\n        \
                   Ok(p) => accept(p),\n        \
                   Err(e) => reject(e),\n    }\n}";
    assert_eq!(unthreaded_calls(planted).len(), 1);
}

#[test]
fn the_scanner_accepts_a_threaded_production_call() {
    let planted = "async fn require_principal(req: Request) -> Response {\n    \
                   match authenticate.authenticate_bearer_with_client_ip(&token, ip).await {\n    \
                   Ok(p) => accept(p),\n    }\n}";
    assert!(unthreaded_calls(planted).is_empty());
    assert!(threads_client_ip(planted));
}

#[test]
fn the_scanner_exempts_only_the_wrapper_body() {
    // The wrapper's own delegation is not a finding; a second call
    // beside it, outside the wrapper, is.
    let wrapper = "pub async fn authenticate_bearer(&self, token: &str) -> R {\n    \
                   self.authenticate_bearer_with_client_ip(token, None).await\n}";
    assert!(unthreaded_calls(wrapper).is_empty());

    let also_a_consumer = format!(
        "{wrapper}\n\npub async fn authenticate_legacy(&self, token: &str) -> R {{\n    \
         self.authenticate_bearer(token).await\n}}"
    );
    assert_eq!(unthreaded_calls(&also_a_consumer).len(), 1);
}

#[test]
fn the_scanner_is_not_satisfied_by_a_comment_or_a_doc_link() {
    let prose = "/// Validates via [`AuthenticateUseCase::authenticate_bearer`].\n\
                 // then authenticate_bearer(token) is called\n\
                 fn documented() {\n    accept()\n}";
    assert!(unthreaded_calls(prose).is_empty());
}

#[test]
fn the_scanner_ignores_test_code() {
    let planted = "#[cfg(test)]\nmod tests {\n    \
                   #[tokio::test]\n    \
                   async fn in_process_login() {\n        \
                   uc.authenticate_bearer(\"tok\").await.unwrap();\n    }\n}";
    assert!(unthreaded_calls(planted).is_empty());
}

#[test]
fn the_scanner_does_not_read_a_declaration_as_a_call() {
    let decl = "pub async fn authenticate_bearer(&self, token: &str) -> R {\n    \
                self.authenticate_bearer_with_client_ip(token, None).await\n}";
    assert!(call_offsets(decl, UNTHREADED).is_empty());
    // …and the declaration of the threaded form is not a call either,
    // so it cannot discharge the census on its own definition file.
    let threaded_decl =
        "pub async fn authenticate_bearer_with_client_ip(&self, t: &str) -> R {\n    \
                         dispatch(t)\n}";
    assert!(call_offsets(threaded_decl, THREADED).is_empty());
}

#[test]
fn the_threaded_call_does_not_read_as_an_unthreaded_one() {
    // `authenticate_bearer` is a prefix of
    // `authenticate_bearer_with_client_ip`; a matcher without a
    // right-hand token boundary would report every correct call site.
    assert!(call_offsets("x.authenticate_bearer_with_client_ip(t, ip)", UNTHREADED).is_empty());
    assert_eq!(
        call_offsets("x.authenticate_bearer_with_client_ip(t, ip)", THREADED).len(),
        1
    );
}
