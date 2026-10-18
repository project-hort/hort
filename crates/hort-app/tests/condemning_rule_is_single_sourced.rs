//! Structural guard: **"may this finding condemn its artifact?" has
//! exactly one definition**, and nothing re-derives it by reading a
//! finding's component relation.
//!
//! ## The invariant
//!
//! A finding names a component. Whether that component's code is *in* the
//! artifact decides whether the finding may hold the artifact's release
//! (ADR 0056 as amended 2026-10-15), and that question is answered in one
//! place: [`Finding::may_condemn_artifact`] in [`DEFINITION_FILE`], with
//! [`ComponentRelation::more_condemning`] beside it as the order two
//! disagreeing relations reconcile to.
//!
//! The rule is three lines of `match`, and every place that needs it sits
//! in a different file from the field: the threshold walk in
//! `hort-domain/src/policy/scan.rs`, the re-evaluation of a `Rejected`
//! artifact over its stored findings in
//! `hort-domain/src/policy/re_evaluation.rs`, the merge tie-break in
//! `hort-app/src/use_cases/scan_orchestration.rs`. Matching on
//! `component_relation` inline at any of them is shorter than calling the
//! predicate, compiles, and passes the suite — and a second copy answers
//! the same question in a second voice, which is how the copies come to
//! disagree.
//!
//! Convention alone does not hold this shape in this codebase, measured:
//! the https-metadata rule was re-typed five times before
//! `https_rule_is_single_sourced.rs` was written, and the sixth consumer
//! carried no copy at all. Which direction a stray copy would be wrong in
//! is not symmetric either — `ComponentRelation::NotEstablished` is the
//! `Default`, so a copy that forgets an arm most naturally drops the
//! condemning reading of absent evidence and disarms the whole stored
//! corpus (a fail-open regression against ADR 0007).
//!
//! ## The property
//!
//! Across every crate's production Rust, a **decision form** read of
//! `.component_relation` appears only in [`DEFINITION_FILE`].
//!
//! A *decision form* is the field read used to decide something — the
//! needle immediately followed by:
//!
//! * `{` — the scrutinee of a `match`, or of an `if let
//!   ComponentRelation::… =` binding;
//! * `==` or `!=` — a comparison against a variant;
//! * `,` inside a statement that also carries `matches!(` — the same
//!   comparison written as the macro.
//!
//! Everything else the field is reached for is deliberately **not** a hit,
//! because none of it re-answers the question:
//!
//! * `f.component_relation = relation;` — a write. The tagging site writes
//!   the fact; the fact is not the verdict.
//! * `component_relation: ComponentRelation::NotEstablished,` — a
//!   struct-literal initialiser, which carries no leading `.` and so does
//!   not match the needle at all. There are a dozen production ones, and
//!   each is a producer stating what it observed.
//! * `existing.component_relation.more_condemning(…)` and
//!   `component_relation_label(relation)` — handing the fact *to* the
//!   defining file's own API, which is the correct idiom and the thing the
//!   guard wants to see more of.
//!
//! ## Scope — derived, not enumerated
//!
//! Every `crates/*/src/**/*.rs`. `Finding` is a `hort-domain` type that
//! every layer above it can see (ADR 0008), so "which crates could
//! re-derive this rule?" has one honest answer — all of them — and the
//! scope is the workspace's production Rust rather than a hand-picked
//! subset. **No allow-list**, as with the sibling guards: a site that
//! genuinely needs to match on the relation is a review conversation (it
//! will almost always want the predicate), not an exemption entry.
//!
//! Test code is out of scope by how it is compiled, not by a line in this
//! file. A `#[cfg(test)]` item is blanked by
//! [`rust_scan::production_region`], and a `src/**/*_tests.rs` file is an
//! inline test module the workspace includes through `#[cfg(test)] #[path
//! = "…"]` — [`every_skipped_test_file_is_really_compiled_out`] asserts
//! that pairing rather than trusting the filename, so the exclusion cannot
//! come to cover a file that is actually compiled in. Test code
//! legitimately asserts
//! `assert_eq!(f.component_relation, ComponentRelation::Subject)` about
//! its own fixtures, which is a `==` decision form and would otherwise be
//! a hit at a dozen sites. A `src/**/test_support.rs` is **in** scope: it
//! is gated `#[cfg(any(test, feature = "test-support"))]`, so a
//! feature-enabled build ships it.
//!
//! ## Counter-assertions
//!
//! A scan whose needle no longer matches anything is vacuously green,
//! which is how guards in this family die. So:
//!
//! * [`the_scanned_corpus_is_real`] — the definition file still holds
//!   exactly one decision-form read (the predicate's own `match`) and
//!   still defines the predicate, the enum, the order and its rank
//!   function. A rename of any of them turns this red, which is the moment
//!   to re-read what the single definition is.
//! * [`every_consumer_reaches_the_rule_rather_than_its_own_copy`] — the
//!   census of production call sites, with per-file counts, matched
//!   **exactly**: a call that disappeared is a consumer that stopped
//!   applying the rule, which the single-definition scan cannot see
//!   because deleting a call removes no copy. A call that appeared is a
//!   new consumer — welcome, but pin it here deliberately so the next
//!   deletion is visible too.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has: a read reached through a differently
//! named binding or helper (`let rel = f.component_relation; match rel {
//! … }`, or `fn condemns(f: &Finding) -> bool` wrapping its own match)
//! reads as a plain field access and is missed. A comparison assembled
//! through a macro is likewise invisible. And the guard says nothing about
//! whether a call to the predicate is in the *right place* — only that the
//! rule is not re-typed; that the narrowing actually happens before the
//! threshold walk, in each of the two verdict functions, is pinned by the
//! behavioural tests in `hort_domain::policy::scan` and
//! `hort_domain::policy::re_evaluation`.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `https_rule_is_single_sourced`, `cas_reads_are_verified` and
//! `capped_stream_reads`.
//!
//! [`Finding::may_condemn_artifact`]: hort_domain::types::Finding::may_condemn_artifact
//! [`ComponentRelation::more_condemning`]: hort_domain::types::ComponentRelation::more_condemning

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{is_ident_byte, line_of, production_region, skip_ws, walk_rust, workspace_root};

/// The one production file allowed to answer the question.
const DEFINITION_FILE: &str = "crates/hort-domain/src/types/finding.rs";

/// The field whose reads are policed.
const FIELD: &str = ".component_relation";

/// The predicate, the order, its rank function and the enum that carries
/// the four observations. Named so a rename fails the counter-assertion
/// rather than quietly emptying the scan.
const PREDICATE_FN: &str = "may_condemn_artifact";
const ORDER_FN: &str = "more_condemning";
const RANK_FN: &str = "containment_claim_rank";
const RELATION_ENUM: &str = "ComponentRelation";

/// Every production consumer of the rule, with the number of calls each
/// makes. Pinned counts, not a presence check — see the module docs.
///
/// **Two** verdict functions read the predicate, and that is the ceiling.
/// A workspace that computes a blocking verdict from a finding list in two
/// places has to apply the rule in both or they answer differently about
/// one list — which is why the second row below was added deliberately
/// rather than by relaxing the scan above. A *third* verdict function
/// asking the same question is not another row to add: it is the signal to
/// collapse the verdict functions, because three readers of one rule is
/// two more chances for the narrowing to be applied at the wrong point and
/// the census cannot see that at all (see the module docs' blind spots).
const EXPECTED_CALL_SITES: &[(&str, &str, usize)] = &[
    // The threshold walk: the condemning set is narrowed before any tier
    // is compared.
    ("crates/hort-domain/src/policy/scan.rs", PREDICATE_FN, 1),
    // The re-evaluation of a `Rejected` artifact over its stored findings
    // — the second function that computes a blocking verdict from a
    // finding list, narrowing at the point the first one does. Without
    // this call the two disagree in the loosening direction: the leftover
    // non-carried finding reads as blocking and the artifact is held on a
    // verdict a fresh scan of the same findings would not reach.
    (
        "crates/hort-domain/src/policy/re_evaluation.rs",
        PREDICATE_FN,
        1,
    ),
    // The cross-backend merge: the surviving row keeps the more condemning
    // of the two relations, whichever row won on severity.
    (
        "crates/hort-app/src/use_cases/scan_orchestration.rs",
        ORDER_FN,
        1,
    ),
];

/// One decision-form read of the field.
#[derive(Debug, PartialEq, Eq)]
struct Read {
    /// Workspace-relative path, forward slashes.
    rel: String,
    /// 1-based line of the read.
    line: usize,
    /// The form that classified it, for the failure message.
    form: &'static str,
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// True for a `src/**/*_tests.rs` file — an inline test module the
/// workspace includes behind `#[cfg(test)] #[path = "…"]`, so its contents
/// are test code even though no attribute appears inside the file itself.
/// [`every_skipped_test_file_is_really_compiled_out`] checks that pairing
/// rather than taking the name's word for it.
///
/// A `test_support.rs` is deliberately **not** excluded: it is gated
/// `#[cfg(any(test, feature = "test-support"))]`, so a feature-enabled
/// build compiles it, and a rule it re-derived would be a rule shipped.
/// None of the four holds a read of the field today.
fn is_inline_test_module(rel: &str) -> bool {
    rel.ends_with("_tests.rs")
}

/// The statement around `offset`: the text between the nearest `;`, `{` or
/// `}` on each side. Enough to tell a `matches!` comparison from a bare
/// field read passed as an argument.
fn enclosing_statement(text: &str, offset: usize) -> &str {
    let start = text[..offset].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let end = text[offset..]
        .find([';', '{', '}'])
        .map_or(text.len(), |i| offset + i);
    &text[start..end]
}

/// Which decision form, if any, the read at `at` is part of. `at` is the
/// offset of the `.` opening [`FIELD`] in already-blanked `text`.
///
/// Classified by what immediately follows the field — see the module docs
/// for why a write, a struct-literal initialiser and a method call on the
/// relation are all deliberately not decisions.
fn decision_form(text: &str, at: usize) -> Option<&'static str> {
    let bytes = text.as_bytes();
    let after = at + FIELD.len();
    // `.component_relation_label` is a different identifier, not this
    // field.
    if bytes.get(after).copied().is_some_and(is_ident_byte) {
        return None;
    }
    let next = skip_ws(bytes, after);
    let rest = &text[next.min(text.len())..];
    if rest.starts_with('{') {
        return Some("match / if-let scrutinee");
    }
    if rest.starts_with("==") || rest.starts_with("!=") {
        return Some("comparison against a variant");
    }
    if rest.starts_with(',') && enclosing_statement(text, at).contains("matches!(") {
        return Some("matches! comparison");
    }
    None
}

/// Every decision-form read of the field in the production sources under
/// `root`, excluding nothing by name except the inline test modules.
fn decision_reads(root: &Path) -> Vec<Read> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        if is_inline_test_module(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let text = production_region(&source);
        let mut search = 0usize;
        while let Some(found) = text[search..].find(FIELD) {
            let at = search + found;
            search = at + 1;
            if let Some(form) = decision_form(&text, at) {
                out.push(Read {
                    rel: rel.clone(),
                    line: line_of(&text, at),
                    form,
                });
            }
        }
    }
    out
}

/// How many times `rel`'s production region names `needle` as a whole
/// token.
///
/// Counted as a *reference*, not as a `needle(` call: `.retain(Finding::
/// may_condemn_artifact)` hands the predicate over as a function path with
/// no argument list, and that is a consumer of the rule exactly as a
/// parenthesised call is. Comments and literals are already blanked, so a
/// rustdoc mention of the name cannot inflate the count.
fn reference_count(root: &Path, rel: &str, needle: &str) -> usize {
    let source = fs::read_to_string(root.join(rel))
        .unwrap_or_else(|e| panic!("{rel} must exist and be readable UTF-8: {e}"));
    let text = production_region(&source);
    let bytes = text.as_bytes();
    let mut count = 0usize;
    let mut search = 0usize;
    while let Some(found) = text[search..].find(needle) {
        let at = search + found;
        search = at + 1;
        let before_is_ident = at > 0 && is_ident_byte(bytes[at - 1]);
        let after_is_ident = bytes
            .get(at + needle.len())
            .copied()
            .is_some_and(is_ident_byte);
        if !before_is_ident && !after_is_ident {
            count += 1;
        }
    }
    count
}

#[test]
fn the_condemning_rule_has_exactly_one_definition() {
    let root = workspace_root();
    let stray: Vec<String> = decision_reads(&root)
        .into_iter()
        .filter(|read| read.rel != DEFINITION_FILE)
        .map(|read| format!("{}:{} — {}", read.rel, read.line, read.form))
        .collect();

    assert!(
        stray.is_empty(),
        "a finding's component relation is read to decide something outside \
         {DEFINITION_FILE} ({} site(s)). Whether a finding may hold an \
         artifact's release is one question with one answer: call \
         `Finding::{PREDICATE_FN}()`, or `{RELATION_ENUM}::{ORDER_FN}()` to \
         reconcile two relations reported for one advisory. A second copy of \
         the match is a second answer, and the arm it will be missing is \
         `{RELATION_ENUM}::NotEstablished` — the `Default`, and the one \
         whose condemning reading protects every finding already \
         persisted.\nStray readers:\n  {}",
        stray.len(),
        stray.join("\n  "),
    );
}

/// Every production reference to the rule's two entry points, as the
/// census shape [`EXPECTED_CALL_SITES`] is written in: `(file, entry
/// point, count)`, sorted, sites with no reference omitted. The
/// definition file is excluded — it holds the definitions, not calls.
fn actual_call_sites(root: &Path) -> Vec<(String, &'static str, usize)> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        if rel == DEFINITION_FILE || is_inline_test_module(&rel) {
            continue;
        }
        for needle in [PREDICATE_FN, ORDER_FN] {
            let found = reference_count(root, &rel, needle);
            if found > 0 {
                out.push((rel.clone(), needle, found));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_consumer_reaches_the_rule_rather_than_its_own_copy() {
    let root = workspace_root();
    let mut pinned: Vec<(String, &'static str, usize)> = EXPECTED_CALL_SITES
        .iter()
        .map(|(rel, needle, count)| ((*rel).to_string(), *needle, *count))
        .collect();
    pinned.sort();

    let actual = actual_call_sites(&root);
    assert_eq!(
        actual, pinned,
        "the census of the rule's production consumers no longer matches the \
         tree. A reference that disappeared is a consumer that stopped applying \
         the rule — which the single-definition scan CANNOT see, because \
         deleting a call removes no copy. A reference that appeared is a new \
         consumer: welcome, but pin it in EXPECTED_CALL_SITES so the next \
         deletion is visible too.\nfound:  {actual:#?}\npinned: {pinned:#?}",
    );
}

/// Counter-assertion: the scan is looking at something. A rename of the
/// field, the predicate, the order or the enum would otherwise make both
/// tests above pass by finding no code at all.
#[test]
fn the_scanned_corpus_is_real() {
    let root = workspace_root();

    let definitions: Vec<Read> = decision_reads(&root)
        .into_iter()
        .filter(|read| read.rel == DEFINITION_FILE)
        .collect();
    assert_eq!(
        definitions.len(),
        1,
        "expected exactly one decision-form read in {DEFINITION_FILE} — \
         `Finding::{PREDICATE_FN}`'s own match. Found {}: {:?}. Zero means the \
         needle no longer matches the rule and the single-definition test \
         above is vacuously green; more than one means the file grew a second \
         reader that needs reading before this count is updated",
        definitions.len(),
        definitions,
    );

    let source = fs::read_to_string(root.join(DEFINITION_FILE))
        .expect("the definition file is readable UTF-8");
    let text = production_region(&source);
    for (what, needle) in [
        ("the predicate", format!("pub fn {PREDICATE_FN}(")),
        ("the reconciliation order", format!("pub fn {ORDER_FN}(")),
        ("its rank function", format!("fn {RANK_FN}(")),
        ("the relation enum", format!("pub enum {RELATION_ENUM}")),
        ("the field", format!("pub {}: {RELATION_ENUM}", &FIELD[1..])),
    ] {
        assert_eq!(
            text.matches(&needle).count(),
            1,
            "{DEFINITION_FILE} must still define {what} exactly once \
             (`{needle}`); if it moved, this guard is watching the wrong file",
        );
    }
}

/// The test-code exclusion is derived, not conventional: every
/// `src/**/*_tests.rs` the scan skips is declared behind a `#[cfg(test)]`
/// in a sibling module, so skipping it cannot hide production code. A
/// `*_tests.rs` compiled into the binary would be exactly that.
#[test]
fn every_skipped_test_file_is_really_compiled_out() {
    let root = workspace_root();
    let sources = production_sources(&root);
    let mut unexplained: Vec<String> = Vec::new();

    for path in &sources {
        let rel = relative(&root, path);
        if !is_inline_test_module(&rel) {
            continue;
        }
        let file_name = path
            .file_name()
            .expect("a scanned path has a file name")
            .to_string_lossy()
            .to_string();
        let declaration = format!("#[path = \"{file_name}\"]");
        let declared_test_only = sources.iter().any(|sibling| {
            if sibling.parent() != path.parent() {
                return false;
            }
            let Ok(source) = fs::read_to_string(sibling) else {
                return false;
            };
            // Read raw, not through `production_region`: the declaration
            // being blanked as a `#[cfg(test)]` item is exactly the thing
            // being looked for, and it is checked as the attribute run it
            // is written as.
            source.contains(&format!("#[cfg(test)]\n{declaration}"))
                || source.contains(&format!("{declaration}\n#[cfg(test)]"))
        });
        if !declared_test_only {
            unexplained.push(rel);
        }
    }

    assert!(
        unexplained.is_empty(),
        "these files are skipped as inline test modules but nothing shows them \
         compiled out, so the exclusion may be hiding production code. Either \
         the module declaration lost its `#[cfg(test)]`, or the file is \
         misnamed.\nUnexplained:\n  {}",
        unexplained.join("\n  "),
    );
}

// ---------------------------------------------------------------------------
// The matcher's own behaviour — asserted on fixture text, so a change to
// the classification is visible here rather than only as a verdict about
// the tree.
// ---------------------------------------------------------------------------

/// `decision_form` over `fixture`, at the first occurrence of the field.
fn classify(fixture: &str) -> Option<&'static str> {
    let text = production_region(fixture);
    let at = text.find(FIELD).expect("fixture names the field");
    decision_form(&text, at)
}

#[test]
fn the_matcher_catches_a_match_on_the_field() {
    assert!(classify("let x = match f.component_relation { _ => 1 };").is_some());
}

#[test]
fn the_matcher_catches_a_rustfmt_wrapped_match() {
    assert!(classify("let x = match f\n    .component_relation\n{ _ => 1 };").is_some());
}

#[test]
fn the_matcher_catches_an_equality_comparison() {
    assert!(classify("if f.component_relation == ComponentRelation::NotContained {}").is_some());
    assert!(classify("if f.component_relation != ComponentRelation::Subject {}").is_some());
}

#[test]
fn the_matcher_catches_an_if_let_binding() {
    assert!(classify("if let ComponentRelation::Subject = f.component_relation {}").is_some());
}

#[test]
fn the_matcher_catches_a_matches_macro() {
    assert!(
        classify("let x = matches!(f.component_relation, ComponentRelation::Subject);").is_some()
    );
}

#[test]
fn the_matcher_ignores_a_write() {
    assert_eq!(classify("f.component_relation = relation;"), None);
    assert_eq!(
        classify("out[idx].component_relation = ComponentRelation::Subject;"),
        None,
        "a write that names a variant is still a write, not a decision",
    );
}

#[test]
fn the_matcher_ignores_a_struct_literal_initialiser() {
    let fixture = "Finding { purl: p, component_relation: ComponentRelation::NotEstablished }";
    assert_eq!(
        production_region(fixture).find(FIELD),
        None,
        "an initialiser carries no leading dot, so it is not even a read",
    );
}

#[test]
fn the_matcher_ignores_handing_the_fact_to_the_defining_api() {
    assert_eq!(
        classify("let r = existing.component_relation.more_condemning(f.component_relation);"),
        None,
    );
    assert_eq!(
        classify("emit(component_relation_label(f.component_relation));"),
        None
    );
}

#[test]
fn the_matcher_does_not_read_the_field_out_of_a_longer_identifier() {
    assert_eq!(
        classify("let l = x.component_relation_label == \"subject\";"),
        None,
        "`.component_relation_label` is a different identifier",
    );
}

#[test]
fn the_matcher_ignores_a_comparison_inside_a_comment_or_a_literal() {
    assert_eq!(
        production_region("// if f.component_relation == ComponentRelation::Subject {}")
            .find(FIELD),
        None,
    );
    assert_eq!(
        production_region("let s = \"f.component_relation == x\";").find(FIELD),
        None,
    );
}

#[test]
fn the_matcher_ignores_a_cfg_test_item() {
    let fixture =
        "#[cfg(test)]\nmod tests {\n    fn t() { match f.component_relation { _ => 1 } }\n}\n";
    assert_eq!(production_region(fixture).find(FIELD), None);
}
