//! Structural guard: **every production artifact-lifecycle adapter checks
//! that the pair it commits is about one artifact**, by calling
//! `hort_domain::ports::artifact_lifecycle::require_paired_artifact_stream`
//! inside each `commit_*` method it writes.
//!
//! ## The invariant
//!
//! Every method on `ArtifactLifecyclePort` takes an `&Artifact` and an
//! `AppendEvents` that each name an artifact independently — the row's `id`
//! and the batch's `StreamId` — and persists both in one transaction. The
//! atomicity is the port's whole purpose, and it is also what makes a
//! mismatched pair worse than a dual write: a pair that disagrees commits
//! **durably and in full**. The `artifacts` row then says one thing and the
//! stream it is supposed to be derived from says another, with no
//! intermediate state for anything to observe, and nothing downstream
//! recovers from it — `verify-event-chain` checks the chain against itself
//! and against its anchors and never reads the projection, so both halves
//! verify individually while contradicting each other.
//!
//! So the rule is prevention: the pair is refused before anything is
//! written. One predicate in `hort-domain` states it; this guard is what
//! makes calling it a property of the port's production implementations
//! rather than a convention one author happened to follow.
//!
//! ## Why a guard and not just the predicate
//!
//! There is exactly **one** implementation today. That is precisely the
//! condition under which a second one inherits the absence of a rule
//! without ever seeing it: a new adapter that opens its transaction and
//! writes both halves compiles, passes clippy and passes the whole suite,
//! and the only thing it breaks is a guarantee no test states. Same hazard
//! class as `cas_reads_are_verified`, whose module doc makes the argument
//! at length for the CAS read wrap.
//!
//! ## Why the scope is derived rather than exempted
//!
//! The scan covers `crates/hort-adapters-*/src/**/*.rs`. That is a
//! structural statement, not a table of files to skip: an outbound adapter
//! lives in an `hort-adapters-*` crate because the dep graph puts it there
//! (ADR 0008 — nothing else in the workspace may depend on a backend SDK),
//! so scanning those crates' `src` trees *is* the statement "every
//! production lifecycle adapter". **There is no allow-list**, as with the
//! sibling guards, and so no entry anyone can add to make a finding go
//! away; a site that genuinely should not carry the call is a review
//! conversation.
//!
//! Test doubles fall out for a derived reason too, and it is worth being
//! exact about which. The doubles inside `hort-domain`'s own port tests are
//! `#[cfg(test)]` items, which [`rust_scan::production_region`] blanks — a
//! property of how they are compiled. `MockArtifactLifecycle`
//! (`hort-app/src/use_cases/test_support.rs`) is **not** `cfg(test)`-gated
//! and is out of scope only because it is not in an adapter crate; it
//! nonetheless calls the predicate, because it round-trips the pair (see
//! its own doc) and a double that accepts what production refuses lets a
//! test assert over a state the system cannot reach. That is a review
//! obligation on round-tripping doubles, not something this scan can see.
//!
//! ## Method-scoped, not file-scoped or impl-scoped
//!
//! A `commit_*` method that forgets the call must be found even when its
//! five siblings in the same block carry it — a mismatched pair reaching
//! *any* one of them commits. So the predicate is looked for in the body of
//! each `fn commit_*` belonging to the `impl` block, individually.
//! Comments and literals are blanked first (`rust_scan::blank_noncode`), so
//! a doc comment naming the predicate in order to discuss it cannot satisfy
//! the guard — which matters here, because the adapter's struct doc does
//! exactly that.
//!
//! A method the adapter does **not** write is correctly not scanned: three
//! of the port's methods default to forwarding to `commit_transition`, and
//! `commit_transition` carries no default body, so an implementation that
//! omits them still reaches the check through the one it cannot omit.
//!
//! ## Counter-assertion
//!
//! [`the_scan_still_finds_the_adapters_commit_methods`] pins the scan's own
//! reach: the known production implementation and the exact set of commit
//! methods it writes. Without it, renaming the port, the predicate or the
//! methods would leave the main assertion green over an empty corpus — the
//! way a source-scan guard usually dies.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has. A `commit_*` that delegates to a helper
//! which checks (`self.checked_pair(artifact, &events)?`) reads as
//! unchecked and is a false positive — correct to flag, since the guard
//! cannot see that the helper checks, but the fix is a review conversation
//! about where the check belongs rather than a mechanical edit. A call
//! assembled through a macro is invisible. And the guard says nothing about
//! *when* within the method the call happens: placing it after the
//! transaction opens would still read as present, which is why the port
//! doc, not this scan, is where "before anything is written" is stated.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as `cas_reads_are_verified`,
//! `capped_stream_reads` and `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    block_end, is_ident_byte, line_of, parse_fns, production_region, skip_ws, workspace_root,
};

/// The crate-name prefix that makes a crate an outbound adapter, and so
/// defines the scanned scope.
const ADAPTER_CRATE_PREFIX: &str = "hort-adapters-";

/// The port whose commit methods are under contract.
const PORT: &str = "ArtifactLifecyclePort";

/// The prefix every method on the port shares. Scanning by prefix rather
/// than by an enumerated list is deliberate: a sixth commit method added
/// to the port is in scope the moment an adapter writes it, with no edit
/// here.
const COMMIT_PREFIX: &str = "commit_";

/// The predicate, as it is called. Pinned as the call rather than the bare
/// name so a mention in a doc comment or a `use` cannot satisfy the guard
/// (the comments are blanked anyway; this is the second line of defence).
const PREDICATE: &str = "require_paired_artifact_stream";

/// One `fn commit_*` in a production `impl ArtifactLifecyclePort for …`.
#[derive(Debug, PartialEq, Eq)]
struct CommitFn {
    /// The method name as written.
    name: String,
    /// 1-based line of its `fn` keyword.
    line: usize,
    /// Whether its own body calls [`PREDICATE`].
    checks: bool,
}

/// One production `impl ArtifactLifecyclePort for …` block.
#[derive(Debug, PartialEq, Eq)]
struct PortImpl {
    /// The implementing type as written, e.g. `PgArtifactLifecycle`.
    self_ty: String,
    /// 1-based line of the `impl` keyword.
    line: usize,
    /// Every `commit_*` method the block writes, in source order.
    commits: Vec<CommitFn>,
}

/// One scanned block, with the file it was found in.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    /// Workspace-relative path, forward slashes.
    rel: String,
    imp: PortImpl,
}

/// True when `needle` sits at `at` as a whole token — neither side
/// continuing an identifier. `"simple"` contains `"impl"`; this is what
/// keeps it from reading as the keyword.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return false;
    }
    let after = at + needle.len();
    after >= bytes.len() || !is_ident_byte(bytes[after])
}

/// Collapse whitespace, so a type rustfmt wrapped across lines reads as
/// one name.
fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The portion of an `impl` header before its `where` clause.
fn before_where(header: &str) -> &str {
    let bytes = header.as_bytes();
    let mut from = 0usize;
    while let Some(found) = header[from..].find("where") {
        let at = from + found;
        from = at + "where".len();
        if is_token(bytes, at, "where") {
            return &header[..at];
        }
    }
    header
}

/// The implementing type, when `header` — the text between the `impl`
/// keyword and the block's opening `{` — is a [`PORT`] implementation.
///
/// The port must sit in the **trait** position: the occurrence is followed
/// by nothing but whitespace before the `for` keyword. That ordering is
/// what tells `impl ArtifactLifecyclePort for X` apart from the shapes that
/// also name the port in an `impl` header and are not implementations of it
/// — `impl<L: ArtifactLifecyclePort> SomeTrait for Wrapper<L>` (another
/// trait name intervenes) and `impl SomeTrait for Arc<dyn
/// ArtifactLifecyclePort>` (the `for` precedes). A path-qualified trait is
/// accepted, the `::` not being an identifier byte. The port is not
/// generic, so no generic-argument list is skipped here.
fn lifecycle_port_self_type(header: &str) -> Option<String> {
    let header = before_where(header);
    let bytes = header.as_bytes();
    let mut from = 0usize;
    while let Some(found) = header[from..].find(PORT) {
        let at = from + found;
        from = at + PORT.len();
        if !is_token(bytes, at, PORT) {
            continue;
        }
        let cursor = skip_ws(bytes, at + PORT.len());
        if !header[cursor..].starts_with("for") || !is_token(bytes, cursor, "for") {
            continue;
        }
        let self_ty = normalise(&header[cursor + "for".len()..]);
        if self_ty.is_empty() {
            continue;
        }
        return Some(self_ty);
    }
    None
}

/// True when `body` calls the predicate: [`PREDICATE`] on a token
/// boundary, followed by a call's `(`.
fn calls_the_predicate(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0usize;
    while let Some(found) = body[from..].find(PREDICATE) {
        let at = from + found;
        from = at + PREDICATE.len();
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        if bytes.get(skip_ws(bytes, at + PREDICATE.len())) == Some(&b'(') {
            return true;
        }
    }
    false
}

/// Every production `impl ArtifactLifecyclePort for …` block in `source`,
/// with a verdict per `commit_*` method it writes.
fn lifecycle_port_impls(source: &str) -> Vec<PortImpl> {
    let text = production_region(source);
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = text[cursor..].find("impl") {
        let at = cursor + found;
        cursor = at + "impl".len();
        if !is_token(bytes, at, "impl") {
            continue;
        }
        // An `impl` header carries no `{` of its own — generics, a path
        // and a `where` clause are all other punctuation — so on blanked
        // text the first one is the block opener.
        let Some(rel) = text[cursor..].find('{') else {
            continue;
        };
        let brace = cursor + rel;
        let Some(self_ty) = lifecycle_port_self_type(&text[cursor..brace]) else {
            continue;
        };
        let body = match block_end(bytes, brace) {
            Some(close) => &text[brace..=close],
            None => &text[brace..],
        };
        // `parse_fns` reports lines relative to `body`; shift them onto
        // the file so a failure names a line a reader can open.
        let body_line = line_of(&text, brace) - 1;
        let commits = parse_fns(body)
            .into_iter()
            .filter(|item| item.name.starts_with(COMMIT_PREFIX))
            .map(|item| CommitFn {
                checks: calls_the_predicate(&item.body),
                name: item.name,
                line: item.line + body_line,
            })
            .collect();
        out.push(PortImpl {
            self_ty,
            line: line_of(&text, at),
            commits,
        });
    }
    out
}

/// Every `crates/hort-adapters-*/src/**/*.rs`, sorted so failures are
/// stable. See the module doc on why this scope is derived rather than
/// exempted.
fn adapter_sources(root: &Path) -> Vec<PathBuf> {
    let crates = root.join("crates");
    let mut out = Vec::new();
    let entries = fs::read_dir(&crates).expect("crates/ exists under the workspace root");
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(ADAPTER_CRATE_PREFIX)
        {
            continue;
        }
        let src = entry.path().join("src");
        if src.is_dir() {
            rust_scan::walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// Scan the adapter crates.
fn scan(root: &Path) -> Vec<Found> {
    let mut out = Vec::new();
    for path in adapter_sources(root) {
        let rel = path
            .strip_prefix(root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&path).expect("adapter source is readable UTF-8");
        for imp in lifecycle_port_impls(&source) {
            out.push(Found {
                rel: rel.clone(),
                imp,
            });
        }
    }
    out
}

#[test]
fn every_adapter_lifecycle_commit_checks_the_pairs_identity() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();
    for found in scan(&root) {
        if found.imp.commits.is_empty() {
            violations.push(format!(
                "{}:{} — `impl {PORT} for {}`: no `{COMMIT_PREFIX}*` method found \
                 in the block, which the port has no all-defaulted shape for — the \
                 scan failed to parse this impl",
                found.rel, found.imp.line, found.imp.self_ty
            ));
            continue;
        }
        for commit in found.imp.commits.iter().filter(|c| !c.checks) {
            violations.push(format!(
                "{}:{} — `{}::{}` commits a pair it never checked",
                found.rel, commit.line, found.imp.self_ty, commit.name
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "every production artifact-lifecycle commit must refuse a pair whose \
         `AppendEvents.stream_id` is not the handed-in artifact's stream: call \
         `{PREDICATE}(artifact, &events)?` before the method writes anything. \
         This is not defensive tidiness — the method's single transaction is \
         what makes a disagreeing pair commit in full and stay committed, and \
         the chain verifier never reads the projection, so the `artifacts` row \
         and its stream contradict each other with both halves verifying. \
         There is no allow-list; a commit method that genuinely must accept a \
         foreign stream is a review conversation about whether it belongs on \
         this port. {} site(s) below:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

/// Counter-assertion: the scan still reaches the implementation it is
/// about, and the methods within it.
///
/// Every sibling guard carries one, and for the same reason: a rename of
/// the port, the predicate or the methods would otherwise leave
/// [`every_adapter_lifecycle_commit_checks_the_pairs_identity`] green over
/// an empty corpus. The pair is deliberately exact rather than a non-empty
/// check — a new production lifecycle adapter must be read by a human
/// against this contract, and an added entry here is that reading.
#[test]
fn the_scan_still_finds_the_adapters_commit_methods() {
    let found = scan(&workspace_root());
    let shape: Vec<(String, String, Vec<String>)> = found
        .iter()
        .map(|f| {
            (
                f.rel.clone(),
                f.imp.self_ty.clone(),
                f.imp.commits.iter().map(|c| c.name.clone()).collect(),
            )
        })
        .collect();

    assert!(
        !shape.is_empty(),
        "the scan found no `impl {PORT} for …` anywhere under \
         crates/{ADAPTER_CRATE_PREFIX}*/src — it is answering about an empty \
         corpus, so its green verdict means nothing. Either the port or the \
         adapter crates were renamed, or the matcher broke"
    );
    assert_eq!(
        shape,
        vec![(
            "crates/hort-adapters-postgres/src/artifact_lifecycle.rs".to_string(),
            "PgArtifactLifecycle".to_string(),
            vec![
                "commit_transition".to_string(),
                "commit_transition_with_score".to_string(),
                "commit_scan_result_with_score".to_string(),
                "commit_transition_with_enqueues".to_string(),
                "commit_provenance_verdict".to_string(),
            ],
        )],
        "the one production lifecycle adapter, and the five commit methods it \
         writes, are the corpus this guard is about. A changed list is not a \
         thing to edit on the way past: read the new or renamed method against \
         the port's pairing contract first, then record it here"
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's own behaviour.
// ---------------------------------------------------------------------------

/// Adapter-shaped source whose single commit method checks. The baseline:
/// without it, every trip-wire below could be passing for the wrong
/// reason.
#[test]
fn the_scanner_accepts_a_commit_that_calls_the_predicate() {
    let planted = "impl ArtifactLifecyclePort for PgArtifactLifecycle {\n    \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   Box::pin(async move {\n            \
                   require_paired_artifact_stream(a, &e)?;\n            \
                   write(a, e).await\n        \
                   })\n    \
                   }\n}";
    assert_eq!(
        lifecycle_port_impls(planted),
        vec![PortImpl {
            self_ty: "PgArtifactLifecycle".to_string(),
            line: 1,
            commits: vec![CommitFn {
                name: "commit_transition".to_string(),
                line: 2,
                checks: true,
            }],
        }]
    );
}

/// The same source with the call removed is a finding — the scan can fail.
#[test]
fn the_scanner_rejects_a_commit_that_skips_the_predicate() {
    let planted = "impl ArtifactLifecyclePort for PgArtifactLifecycle {\n    \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   Box::pin(async move { write(a, e).await })\n    \
                   }\n}";
    let impls = lifecycle_port_impls(planted);
    assert_eq!(impls.len(), 1);
    assert_eq!(impls[0].commits.len(), 1);
    assert!(!impls[0].commits[0].checks);
}

/// One checked sibling does not cover an unchecked one: the verdict is per
/// method, which is the whole reason the scan is method-scoped. A
/// mismatched pair reaching *either* method commits.
#[test]
fn the_scanner_judges_each_commit_method_separately() {
    let planted = "impl ArtifactLifecyclePort for PgArtifactLifecycle {\n    \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   require_paired_artifact_stream(a, &e)?;\n        \
                   write(a, e)\n    \
                   }\n    \
                   fn commit_provenance_verdict(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   write(a, e)\n    \
                   }\n}";
    let impls = lifecycle_port_impls(planted);
    let verdicts: Vec<(String, bool)> = impls[0]
        .commits
        .iter()
        .map(|c| (c.name.clone(), c.checks))
        .collect();
    assert_eq!(
        verdicts,
        vec![
            ("commit_transition".to_string(), true),
            ("commit_provenance_verdict".to_string(), false),
        ]
    );
}

/// A doc comment naming the predicate does not satisfy the guard. Not
/// hypothetical: the adapter's own struct doc names it in order to say
/// where the check happens, and a scan that read comments would stay green
/// after the call itself was deleted.
#[test]
fn the_scanner_ignores_the_predicate_named_only_in_a_comment() {
    let planted = "impl ArtifactLifecyclePort for PgArtifactLifecycle {\n    \
                   /// Checks the pair via `require_paired_artifact_stream` first.\n    \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   // require_paired_artifact_stream(a, &e)?;\n        \
                   write(a, e)\n    \
                   }\n}";
    let impls = lifecycle_port_impls(planted);
    assert!(
        !impls[0].commits[0].checks,
        "prose about the predicate is not a call to it"
    );
}

/// A `#[cfg(test)]` double inside an adapter crate is out of scope — a
/// property of how it is compiled, not an entry in this file.
#[test]
fn the_scanner_skips_a_cfg_test_double() {
    let planted = "#[cfg(test)]\nmod tests {\n    \
                   impl ArtifactLifecyclePort for Fake {\n        \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n            \
                   record(a, e)\n        \
                   }\n    \
                   }\n}";
    assert!(lifecycle_port_impls(planted).is_empty());
}

/// A generic bound naming the port, and a blanket impl *for* a wrapper
/// around it, are not implementations of it.
#[test]
fn the_scanner_ignores_the_port_outside_the_trait_position() {
    let bound = "impl<L: ArtifactLifecyclePort> Cascade for Wrapper<L> {\n    \
                 fn commit_transition(&self) {}\n}";
    assert!(lifecycle_port_impls(bound).is_empty());
    let wrapped = "impl Cascade for Arc<dyn ArtifactLifecyclePort> {\n    \
                   fn commit_transition(&self) {}\n}";
    assert!(lifecycle_port_impls(wrapped).is_empty());
}

/// A method that is not a `commit_*` is not scanned — the port's
/// constructor and any helper beside it owe nothing to this rule.
#[test]
fn the_scanner_scans_only_the_commit_methods() {
    let planted = "impl ArtifactLifecyclePort for PgArtifactLifecycle {\n    \
                   fn helper(&self) -> u8 {\n        1\n    }\n    \
                   fn commit_transition(&self, a: &Artifact, e: AppendEvents) -> Fut {\n        \
                   require_paired_artifact_stream(a, &e)?;\n        \
                   write(a, e)\n    \
                   }\n}";
    let impls = lifecycle_port_impls(planted);
    assert_eq!(
        impls[0]
            .commits
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["commit_transition"]
    );
}
