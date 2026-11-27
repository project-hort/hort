//! Structural guard: **a credential decision reads `transport`, never an
//! address.**
//!
//! ## The invariant
//!
//! Whether a credential may travel on a request is a question about the
//! wire, and the only thing in this system that answers it is
//! [`RequestTrust::transport`] — evidence derived once, in the trust
//! layer, from what a *trusted* peer reported. Every inbound credential
//! surface asks that question through one predicate,
//! [`PREDICATE`]: it takes the extension lookup itself, so a missing
//! trust context reads as a refusal rather than as an allow, and it
//! consumes the operator's waiver as a separate field so a waiver never
//! becomes evidence.
//!
//! The predicate it replaced asked a different question and got a
//! different answer: it read `RequestTrust.public_url.scheme() ==
//! "https"`, which is the **emitted** URL. That value is pinned by
//! `HORT_PUBLIC_BASE_URL` and synthesised from `Host` on the fallback
//! branch, so it answers "what URLs do we hand out" and says nothing
//! about how the bytes arrived: an `https://`-pinned deployment behind a
//! plaintext hop read as proven, and an `http://`-pinned one behind real
//! TLS read as unproven. An address is not transport evidence, and the
//! two are easy to confuse precisely because both are fields of the same
//! struct.
//!
//! ## The two halves, and why both are needed
//!
//! * [`every_credential_surface_decides_or_declares_why_not`] — the
//!   surface census. Every route class that presents or issues a
//!   credential either calls the predicate **in the function that owns
//!   the surface**, or is declared here as not deciding yet, with its
//!   reason beside it. A seventh surface cannot appear without one of the
//!   two.
//! * [`a_credential_decision_reads_no_address`] and
//!   [`every_address_read_in_the_inbound_auth_crates_is_named`] — the
//!   address half. A decision function may not read an address at all,
//!   and every address read anywhere in the inbound-auth crates is named
//!   here with the reason it is legitimate.
//!
//! Address reads are **explicitly allowed and named, not forbidden**, and
//! that is the design rather than a concession: a URL resolver must read
//! the URL, the trust layer must log it, HSTS must check its origin per
//! RFC 6797 §7.2, and the evidence derivation must read the scheme a
//! trusted peer reported — that read is where a scheme legitimately
//! *becomes* evidence. A scan that rejected every address read with no
//! list would fire on all four and teach whoever hit it to weaken the
//! scan. The exact census is the point: a *new* address read in these
//! crates goes red and gets read by a human, which is the only control
//! that would have caught the original defect.
//!
//! ## Scope — derived, not enumerated
//!
//! [`INBOUND_AUTH_CRATES`] is `hort-http-core` plus `hort-http-oci`,
//! which is where ADR 0008 puts inbound auth: the shared middleware in
//! the core, and the one per-format crate that runs its own credential
//! boundary because the Distribution Spec gives it its own challenge and
//! error shapes. The other `hort-http-*` crates authenticate through the
//! core's middleware and have no credential decision to make.
//!
//! The surface corpus is derived too: it is the variants of the closed
//! [`ENTRY_POINT_ENUM`], read out of [`DEFINITION_FILE`]. Adding a route
//! class means adding a variant, and
//! [`the_entry_point_enum_is_the_corpus`] fails if a variant is attributed
//! to no function — so the census cannot go quietly vacuous by a rename.
//!
//! Test code is out of scope by how it is compiled: `#[cfg(test)]` items
//! are blanked by the shared lexer and `tests/` targets are outside
//! `src/`. There is **no allow-list** for either half beyond the named
//! address reads and the declared non-deciding surfaces, both of which
//! carry their reason at the assertion — a site that genuinely needs an
//! exception is a review conversation held here, in front of whoever
//! edits the list next.
//!
//! ## Counter-assertions
//!
//! [`the_predicate_and_the_scan_are_real`] pins the predicate's
//! definition, that it is defined exactly once, and that the evidence
//! field it reads still exists.
//! [`stripping_the_decision_or_planting_an_address_read_fails_the_scan`]
//! mutates **real on-disk source** in both directions: remove the
//! predicate call and the enforcing surfaces must report; put the
//! historical `public_url.scheme() == "https"` read back inside the
//! decision and the address half must report it.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The ones every source scan has. A decision reached through a
//! differently-named local helper reads as not deciding — a false
//! positive, and the fix is a conversation about where the decision
//! belongs, not an entry here. A call assembled through a macro is
//! invisible. On the address half, the literal arm matches the scheme
//! *tokens* `"http"` and `"https"`, not a URL literal like
//! `"https://example"`, because the latter constructs a value rather than
//! testing one; a decision that compared the address as a whole string is
//! still caught, by the `public_url` arm, which is the backstop that does
//! not depend on how the comparison is spelled.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `cas_reads_are_verified`, `authorization_scheme_is_single_sourced` and
//! `https_rule_is_single_sourced`.
//!
//! [`RequestTrust::transport`]: hort_http_core::middleware::trust::RequestTrust::transport

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    blank_cfg_test_items, is_ident_byte, line_of, mark_literals, parse_fns, production_region,
    skip_ws, walk_rust, workspace_root,
};

/// The file that defines both the predicate and the closed set of route
/// classes it is called from.
const DEFINITION_FILE: &str = "crates/hort-http-core/src/middleware/credential_transport.rs";

/// The one predicate a credential decision goes through.
const PREDICATE: &str = "credential_transport_verdict";

/// The closed enum of route classes on which a credential is presented or
/// issued. Its variants are this guard's corpus.
const ENTRY_POINT_ENUM: &str = "CredentialEntryPoint";

/// The evidence field a decision is allowed to read.
const EVIDENCE_FIELD: &str = "transport";

/// Crates that host an inbound credential boundary under ADR 0008.
const INBOUND_AUTH_CRATES: &[&str] = &["hort-http-core", "hort-http-oci"];

/// Field and method spellings that read an address rather than evidence.
const ADDRESS_READS: &[&str] = &["public_url", "scheme", "scheme_str"];

/// Scheme tokens, as a comparison spells them.
const SCHEME_TOKENS: &[&str] = &["http", "https"];

/// What a credential surface does about the transport decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// The function that owns the surface calls the predicate.
    Decides,
    /// It observes the evidence but does not decide yet.
    ObservesOnly,
}

/// One production function that names a route class of
/// [`ENTRY_POINT_ENUM`].
#[derive(Debug, PartialEq, Eq)]
struct Surface {
    /// Workspace-relative path, forward slashes.
    rel: String,
    /// The function that owns the surface.
    function: String,
    /// Route classes named in its body, in the order the enum declares
    /// them — so the census does not churn when a label moves within a
    /// function.
    classes: Vec<String>,
    decision: Decision,
}

/// One production read of an address in the scanned crates.
#[derive(Debug, PartialEq, Eq)]
struct AddressRead {
    rel: String,
    function: String,
    /// The spelling that matched: a field, a method, or a scheme token.
    read: String,
    line: usize,
}

/// The surfaces this guard expects, with a reason for every one that does
/// not decide yet.
///
/// The census is every surface, deciding or not, because that is what
/// makes a *new* surface report as well. So a surface that starts
/// deciding fails here too, and the fix is to flip its [`Decision`] and
/// replace its reason — not to delete its line, which would leave the
/// census short and fail just as loudly. A line is deleted only when its
/// function stops naming a route class at all. Each
/// still-observing reason says what the remaining work is in terms a
/// reader can check against the code, because it is not an oversight: it
/// needs a refusal in an error envelope this function does not currently
/// build.
fn expected_surfaces() -> Vec<(&'static str, &'static str, Vec<&'static str>, Decision)> {
    vec![
        // The token endpoint. Decides as the first step after form
        // parsing — before `grant_type`, before the token-type checks,
        // before the PAT-shape gate, before the IdP call, before
        // `handle_federated_jwt`, and so before both of its mints —
        // and answers in its own `{"error","error_description"}`
        // envelope. It is the one caller that passes the unscoped flag
        // forced off: RFC 6749 §3.2 binds the authorization server on
        // the token endpoint, so the operator's blunt instrument does
        // not reach a surface that mints a credential. That asymmetry
        // lives at its call site and nowhere in the predicate.
        (
            "crates/hort-http-core/src/handlers/exchange.rs",
            "run",
            vec!["Exchange"],
            Decision::Decides,
        ),
        // The shared non-OCI write path. `Metrics` is the same function
        // under a different label: `GET /metrics` on the admin listener
        // is served through it, and only its label differs.
        (
            "crates/hort-http-core/src/middleware/auth.rs",
            "require_principal",
            vec!["Require", "Metrics"],
            Decision::Decides,
        ),
        // The shared non-OCI read path. The decision runs on the
        // credential-present branches only, so an anonymous read is
        // untouched.
        (
            "crates/hort-http-core/src/middleware/auth.rs",
            "extract_optional_principal",
            vec!["Optional"],
            Decision::Decides,
        ),
        // The OCI consume surface. Decides on the credential-present
        // branch and answers in the Distribution Spec's own error
        // envelope; the anonymous pass-through and the anonymous-write
        // challenge are untouched.
        (
            "crates/hort-http-oci/src/middleware/oci_auth.rs",
            "oci_bearer_auth",
            vec!["OciConsume"],
            Decision::Decides,
        ),
        // The OCI mint. Decides before the credential is parsed and
        // before anything is minted, on the anonymous path as well — the
        // response is a credential either way, which is the position the
        // handler states at the call.
        (
            "crates/hort-http-oci/src/v2_auth.rs",
            "handle_v2_auth",
            vec!["OciMint"],
            Decision::Decides,
        ),
    ]
}

/// Every production address read in the scanned crates, each with the
/// reason it is legitimate.
///
/// Keyed by (file, function, spelling) rather than by line, so rustfmt and
/// unrelated edits above them do not churn this list while a *new* read
/// still reports.
fn named_address_reads() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // The URL resolver's whole job: hand back the public base URL for
        // absolute-URL emission in packuments, index documents and
        // `config.json`.
        (
            "crates/hort-http-core/src/url_resolver.rs",
            "resolve",
            "public_url",
        ),
        // HSTS reads transport evidence and the public origin. RFC 6797
        // §7.2 requires a secure transport; the `https` origin makes the
        // header meaningful for the host a client will revisit. These
        // three address reads are the origin condition, not a credential
        // decision or a substitute for the transport field.
        (
            "crates/hort-http-core/src/middleware/security_headers.rs",
            "should_emit_hsts",
            "public_url",
        ),
        (
            "crates/hort-http-core/src/middleware/security_headers.rs",
            "should_emit_hsts",
            "scheme",
        ),
        (
            "crates/hort-http-core/src/middleware/security_headers.rs",
            "should_emit_hsts",
            "https",
        ),
        // The trust layer's `debug!`. This is the only instrument that
        // answers "what peer and what public URL does this server
        // actually observe for this caller", which is what an operator
        // needs before choosing a waiver range — the metrics carry
        // `entry_point` and `evidence` and no address at all.
        (
            "crates/hort-http-core/src/middleware/trust.rs",
            "trust_middleware_fn",
            "public_url",
        ),
        // The evidence derivation itself: the one place a scheme
        // legitimately becomes `TransportSecurity`, reading what a
        // trusted peer reported in `Forwarded` / `X-Forwarded-Proto`.
        (
            "crates/hort-http-core/src/middleware/trust.rs",
            "parse_scheme",
            "https",
        ),
        (
            "crates/hort-http-core/src/middleware/trust.rs",
            "parse_scheme",
            "http",
        ),
        // URL *construction* for emission, on the two branches that
        // synthesise a public URL rather than using a pinned one: the
        // trusted-peer branch, which prefers the forwarded scheme, and
        // the `Host`-only backstop. Listed once per read, so a third
        // statement here is not covered by these two reasons.
        (
            "crates/hort-http-core/src/middleware/trust.rs",
            "resolve_public_url",
            "https",
        ),
        (
            "crates/hort-http-core/src/middleware/trust.rs",
            "resolve_public_url",
            "https",
        ),
    ]
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned file is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `crates/<inbound auth crate>/src/**/*.rs`, sorted so failures are
/// stable.
fn inbound_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for crate_name in INBOUND_AUTH_CRATES {
        let src = root.join("crates").join(crate_name).join("src");
        assert!(
            src.is_dir(),
            "{} is not a directory — the scanned scope moved or the crate was renamed",
            src.display()
        );
        walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
    }
    out.sort();
    out
}

/// True when `needle` sits at `at` as a whole token.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return false;
    }
    let after = at + needle.len();
    after >= bytes.len() || !is_ident_byte(bytes[after])
}

/// Offsets of every whole-token occurrence of `needle` in `text`.
fn token_offsets(text: &str, needle: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(needle) {
        let at = from + found;
        from = at + needle.len();
        if is_token(bytes, at, needle) {
            out.push(at);
        }
    }
    out
}

/// The variants of [`ENTRY_POINT_ENUM`], read out of its definition.
fn entry_point_classes(root: &Path) -> Vec<String> {
    let source = fs::read_to_string(root.join(DEFINITION_FILE)).expect("definition file exists");
    let code = production_region(&source);
    let header = format!("pub enum {ENTRY_POINT_ENUM}");
    let at = code
        .find(&header)
        .expect("the entry-point enum is declared in the definition file");
    let open = at
        + code[at..]
            .find('{')
            .expect("the enum has a brace-delimited body");
    let close = rust_scan::block_end(code.as_bytes(), open).expect("the enum body is balanced");
    code[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|variant| !variant.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every production function in `source` that names a route class, with
/// whether it calls the predicate.
fn surfaces_in_source(rel: &str, source: &str, classes: &[String]) -> Vec<Surface> {
    let code = production_region(source);
    parse_fns(&code)
        .into_iter()
        .filter_map(|item| {
            let named: Vec<String> = classes
                .iter()
                .filter(|class| {
                    !token_offsets(&item.body, &format!("{ENTRY_POINT_ENUM}::{class}")).is_empty()
                })
                .cloned()
                .collect();
            if named.is_empty() {
                return None;
            }
            let decides = token_offsets(&item.body, PREDICATE)
                .into_iter()
                .any(|at| is_call(&item.body, at));
            Some(Surface {
                rel: rel.to_owned(),
                function: item.name,
                classes: named,
                decision: if decides {
                    Decision::Decides
                } else {
                    Decision::ObservesOnly
                },
            })
        })
        .collect()
}

/// True when the identifier at `at` is immediately followed by a call's
/// `(` — a mention in a doc link or an import is not a call.
fn is_call(text: &str, at: usize) -> bool {
    let bytes = text.as_bytes();
    let after = at
        + text[at..]
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .unwrap_or(text.len() - at);
    bytes.get(skip_ws(bytes, after)) == Some(&b'(')
}

fn surfaces(root: &Path) -> Vec<Surface> {
    let classes = entry_point_classes(root);
    let mut out = Vec::new();
    for path in inbound_sources(root) {
        let rel = relative(root, &path);
        let source = fs::read_to_string(&path).expect("production Rust is readable UTF-8");
        out.extend(surfaces_in_source(&rel, &source, &classes));
    }
    out
}

/// Every production address read in `source`, attributed to the function
/// it sits in.
///
/// Three arms. A field or method read (`.public_url`, `.scheme()`,
/// `.scheme_str()`) is matched after a `.` so a local binding of the same
/// name is not a hit — `let public_url = resolve_public_url(…)` builds the
/// value rather than reading it off the trust extension. A scheme token
/// is matched as the whole content of a string literal, which is how a
/// comparison spells it.
fn address_reads_in_source(rel: &str, source: &str) -> Vec<AddressRead> {
    let (marked, spans) = mark_literals(source);
    let code = blank_cfg_test_items(&marked);
    let functions = parse_fns(&code);
    let at_function = |offset: usize| -> Option<String> {
        functions
            .iter()
            .rfind(|item| item.span.0 <= offset && offset < item.span.1)
            .map(|item| item.name.clone())
    };

    let mut out = Vec::new();
    for read in ADDRESS_READS {
        for at in token_offsets(&code, read) {
            let before = code[..at].trim_end();
            if !before.ends_with('.') {
                continue;
            }
            // `..` is a range, not a field access.
            if before.ends_with("..") {
                continue;
            }
            let Some(function) = at_function(at) else {
                continue;
            };
            out.push(AddressRead {
                rel: rel.to_owned(),
                function,
                read: (*read).to_owned(),
                line: line_of(&code, at),
            });
        }
    }
    for (start, end) in spans {
        if code.as_bytes().get(start) != Some(&rust_scan::LITERAL_MARK) {
            continue;
        }
        let literal = &source[start..end];
        let content = literal
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'));
        let Some(content) = content else { continue };
        if !SCHEME_TOKENS.contains(&content) {
            continue;
        }
        let Some(function) = at_function(start) else {
            continue;
        };
        out.push(AddressRead {
            rel: rel.to_owned(),
            function,
            read: content.to_owned(),
            line: line_of(&code, start),
        });
    }
    out.sort_by_key(|read| read.line);
    out
}

fn address_reads(root: &Path) -> Vec<AddressRead> {
    let mut out = Vec::new();
    for path in inbound_sources(root) {
        let rel = relative(root, &path);
        let source = fs::read_to_string(&path).expect("production Rust is readable UTF-8");
        out.extend(address_reads_in_source(&rel, &source));
    }
    out
}

/// `(file, function, spelling)` — the shape both censuses compare on.
fn read_shape(read: &AddressRead) -> (String, String, String) {
    (read.rel.clone(), read.function.clone(), read.read.clone())
}

#[test]
fn every_credential_surface_decides_or_declares_why_not() {
    let measured = surfaces(&workspace_root());
    let expected: Vec<Surface> = expected_surfaces()
        .into_iter()
        .map(|(rel, function, classes, decision)| Surface {
            rel: rel.to_owned(),
            function: function.to_owned(),
            classes: classes.into_iter().map(str::to_owned).collect(),
            decision,
        })
        .collect();
    assert_eq!(
        measured, expected,
        "the credential-surface census changed. Every route class of \
         `{ENTRY_POINT_ENUM}` must call `{PREDICATE}` in the function that owns \
         the surface, or be declared here as not deciding yet with the reason \
         beside it. A new surface that only *observes* the evidence accepts a \
         credential on an unproven transport, which is the defect this guard \
         is about; a declared surface that has started deciding gets its \
         `Decision` flipped and its reason replaced, never its line deleted — \
         the census lists every surface, so a deletion leaves it short and \
         fails here just as loudly."
    );
}

#[test]
fn the_entry_point_enum_is_the_corpus() {
    let root = workspace_root();
    let classes = entry_point_classes(&root);
    assert_eq!(
        classes,
        vec![
            "Require",
            "Optional",
            "Metrics",
            "OciConsume",
            "OciMint",
            "Exchange"
        ],
        "the route classes are this guard's corpus, read out of \
         {DEFINITION_FILE}. A variant added here must appear in \
         `expected_surfaces`; one removed must disappear from it"
    );
    let attributed: Vec<String> = surfaces(&root)
        .into_iter()
        .flat_map(|surface| surface.classes)
        .collect();
    for class in &classes {
        assert!(
            attributed.contains(class),
            "no production function names `{ENTRY_POINT_ENUM}::{class}`, so the \
             census says nothing about that route class — either it lost its \
             observation, or the matcher stopped finding it and this guard is \
             answering about a smaller corpus than its name claims"
        );
    }
}

#[test]
fn a_credential_decision_reads_no_address() {
    let root = workspace_root();
    let decisions: Vec<(String, String)> = surfaces(&root)
        .into_iter()
        .map(|surface| (surface.rel, surface.function))
        .collect();
    let violations: Vec<String> = address_reads(&root)
        .into_iter()
        .filter(|read| decisions.contains(&(read.rel.clone(), read.function.clone())))
        .map(|read| format!("{}:{} — reads `{}`", read.rel, read.line, read.read))
        .collect();
    assert!(
        violations.is_empty(),
        "a credential surface reads an address. An address answers \"what URLs \
         do we hand out\" — it is pinned by `HORT_PUBLIC_BASE_URL` and \
         synthesised from `Host` on the fallback branch — and says nothing \
         about how the bytes arrived. Read `RequestTrust::{EVIDENCE_FIELD}` \
         through `{PREDICATE}` instead:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn every_address_read_in_the_inbound_auth_crates_is_named() {
    let measured: Vec<(String, String, String)> = address_reads(&workspace_root())
        .iter()
        .map(read_shape)
        .collect();
    let mut expected: Vec<(String, String, String)> = named_address_reads()
        .into_iter()
        .map(|(rel, function, read)| (rel.to_owned(), function.to_owned(), read.to_owned()))
        .collect();
    let mut measured_sorted = measured.clone();
    measured_sorted.sort();
    expected.sort();
    assert_eq!(
        measured_sorted, expected,
        "the address-read census in {INBOUND_AUTH_CRATES:?} changed. Each read \
         is legitimate for a stated reason — emitting a URL, logging what this \
         server observes, HSTS's RFC 6797 origin check, or the evidence \
         derivation itself — and a new one is a review conversation, not an \
         entry to add on the way past. Measured reads are listed above with \
         the function they sit in"
    );
}

#[test]
fn the_predicate_and_the_scan_are_real() {
    let root = workspace_root();
    let source = fs::read_to_string(root.join(DEFINITION_FILE)).expect("definition file exists");
    let code = production_region(&source);
    assert_eq!(
        code.matches(&format!("pub fn {PREDICATE}(")).count(),
        1,
        "{PREDICATE} must be defined exactly once, in {DEFINITION_FILE}"
    );
    assert!(
        code.contains(&format!("trust.{EVIDENCE_FIELD}")),
        "the predicate must read the evidence field it is about; if that field \
         was renamed, this guard's address census is answering about the wrong \
         thing"
    );
    assert!(
        code.contains("tls_requirement_waived"),
        "the predicate must consume the waiver as a separate field — a waiver \
         that became evidence is the shape this whole guard exists to prevent"
    );
    let trust = fs::read_to_string(root.join("crates/hort-http-core/src/middleware/trust.rs"))
        .expect("the trust layer exists");
    assert!(
        production_region(&trust).contains(&format!("pub {EVIDENCE_FIELD}: TransportSecurity")),
        "`RequestTrust::{EVIDENCE_FIELD}` is the evidence a decision reads; a \
         rename makes every assertion here vacuous"
    );
}

/// Every file in which a surface decides today, with how many deciding
/// surfaces it holds.
///
/// Derived from [`expected_surfaces`] rather than retyped, so a surface
/// that starts or stops deciding moves this corpus with it and the
/// mutation below cannot keep mutating a file that no longer decides —
/// which is how a mutation check goes quietly vacuous.
fn deciding_files() -> Vec<(&'static str, usize)> {
    let mut out: Vec<(&'static str, usize)> = Vec::new();
    for (rel, _, _, decision) in expected_surfaces() {
        if decision != Decision::Decides {
            continue;
        }
        match out.iter_mut().find(|(seen, _)| *seen == rel) {
            Some((_, count)) => *count += 1,
            None => out.push((rel, 1)),
        }
    }
    out
}

/// The mutation counter-assertion, over **real on-disk source** in both
/// directions. On a clean tree the scan and a broken scan agree on the
/// verdict and differ only in what they read, so nothing else here can
/// tell them apart.
///
/// The stripping half runs over **every** file that decides — the shared
/// non-OCI middleware and both OCI boundaries — because each reaches the
/// predicate through its own expression, and a scan that found the call
/// in one spelling and missed another would still be green here if only
/// the first were mutated. The planting half stays on `auth.rs`, which is
/// where the historical `public_url.scheme() == "https"` read actually
/// lived.
#[test]
fn stripping_the_decision_or_planting_an_address_read_fails_the_scan() {
    let root = workspace_root();
    let classes = entry_point_classes(&root);

    for (rel, deciding) in deciding_files() {
        let source = fs::read_to_string(root.join(rel)).expect("readable UTF-8");

        // Baseline: the file's surfaces decide, and none reads an address.
        let clean = surfaces_in_source(rel, &source, &classes);
        assert_eq!(
            clean
                .iter()
                .filter(|surface| surface.decision == Decision::Decides)
                .count(),
            deciding,
            "{rel} must hold {deciding} deciding surface(s) before this \
             mutation proves anything: {clean:?}"
        );
        assert!(
            address_reads_in_source(rel, &source).is_empty(),
            "{rel} reads an address, so the planting half below could not \
             tell a planted read from a standing one"
        );

        // Remove the decision: every surface in the file must report.
        let stripped = source.replace(PREDICATE, "assume_transport_is_fine");
        assert_ne!(stripped, source, "{rel} must name the predicate");
        for surface in surfaces_in_source(rel, &stripped, &classes) {
            assert_eq!(
                surface.decision,
                Decision::ObservesOnly,
                "{rel}::{} must report once its call to the predicate is \
                 gone — if it does not, the scan is not reading the call it \
                 claims to check",
                surface.function
            );
        }
    }

    let rel = "crates/hort-http-core/src/middleware/auth.rs";
    let source = fs::read_to_string(root.join(rel)).expect("readable UTF-8");

    // Put the historical address read back where it used to live: inside
    // the decision, on the trust extension this function already holds.
    let planted = source.replace(
        &format!("let verdict = {PREDICATE}(trust, ctx.pat_over_http_allowed);"),
        "let verdict = legacy(trust.map(|t| t.public_url.scheme() == \"https\"));",
    );
    assert_ne!(planted, source, "the planted anchor must exist in the file");
    let reads = address_reads_in_source(rel, &planted);
    assert_eq!(
        reads.len(),
        6,
        "the planted read must be found at both entry points, as all three \
         spellings: {reads:?}"
    );
    for read in &reads {
        assert!(
            ["require_principal", "extract_optional_principal"].contains(&read.function.as_str()),
            "the planted read must be attributed to the function it sits in, \
             not to a neighbour: {read:?}"
        );
    }
}
