//! Structural guard: **`AnchorEvidence` is assembled in exactly two
//! places, and a `DerivedAnchor` can only come out of the derivation.**
//!
//! ## The invariant
//!
//! A quarantine window begins at the point hort can prove the artifact
//! was already published, so the anchor is a property of **the artifact**
//! and `hort_domain::policy::derive_quarantine_anchor` is the single rule
//! that decides it (ADR 0054). A pure rule is only single-sourced if the
//! *evidence* it consumes is: a second assembly site is a second reading
//! of the same facts, and two readings that disagree are two anchors for
//! one artifact — which is the defect the sibling guard
//! `quarantine_anchor_is_artifact_time` was written for, one level up.
//!
//! There are two situations and no more:
//!
//! * a **mint** — a row coming into existence, whose evidence includes
//!   request data (the mint instant, the resolved window, the seed-import
//!   override, the serving mapping's `trust_upstream_publish_time`
//!   opt-in) that no later path can recover; and
//! * a **re-entry** — an artifact already stored being returned to the
//!   hold, whose evidence is read entirely from the row and the ports.
//!
//! Both live in
//! `crates/hort-app/src/use_cases/quarantine_anchor_assembly.rs`
//! ([`ASSEMBLY_FILE`]), one function each. A third site would be a third
//! rule, whatever its author intended.
//!
//! ## Why convention would not hold it
//!
//! It did not. The two minting paths each assembled their own
//! `AnchorEvidence` inline — `IngestUseCase::decide_and_apply_quarantine`
//! and `apply_register_gate` — and the second carried a comment
//! asserting it ran "the SAME derivation `ingest_inner` runs, over the
//! same sources". The derivation *was* shared; the assembly was copied,
//! and the copies were already not the same code: only one of them
//! short-circuited the two probes on an explicit override.
//!
//! The re-entry side had no assembly at all. Four production sites read
//! the mint instant straight off the row instead — the three `Artifact`
//! methods that re-enter the hold, each spelling
//! `self.quarantine_window_start.unwrap_or(self.created_at)`, and
//! `QuarantineUseCase::hold_for_unproduced_composition`, which took
//! `paired.artifact().created_at`. `created_at` IS the derivation's
//! `minted_at` evidence, so each of those four was the same decision
//! taken again outside the function that holds the rule, by a reader
//! that could see one source of the four.
//!
//! ## What the scan asks
//!
//! Over `crates/*/src` production code: every **struct-literal
//! expression** `AnchorEvidence { … }`, by file and enclosing function.
//! A literal is the only way to build one — the type has public fields
//! and no constructor — so this is the complete set of assembly sites a
//! byte scan can see.
//!
//! The paired half, and the reason this guard carries both: every
//! `DerivedAnchor { … }` literal, which must not exist anywhere outside
//! the module that defines the type. That is **compiler**-enforced
//! (`DerivedAnchor::anchor` is a private field), and the assertion here
//! is what states the property rather than leaving a reader to infer it
//! from a missing `pub`. The honest form of "this cannot be constructed
//! outside its module" is a compile-fail fixture; the workspace has no
//! such harness (no `trybuild` in `Cargo.lock`), so the next best thing
//! is asserted instead — the field is declared without `pub`, the type
//! offers no other way in, and no literal exists outside the module.
//!
//! ## Why the scope is derived rather than exempted
//!
//! There is **no allow-list**:
//!
//! * The application layer owns the I/O every source needs, so an
//!   assembly site can only live in `hort-app` (ADR 0008). The scan still
//!   reads every crate's `src`, because a site appearing elsewhere is the
//!   finding, not an exclusion.
//! * **`#[cfg(test)]` items** are blanked by
//!   [`rust_scan::production_region`], so a unit test building its own
//!   evidence is out of scope because of how it is compiled, not because
//!   of an entry here. The derivation is pure and exhaustively tested
//!   over hand-built evidence in `hort-domain`; that is the point of its
//!   public fields.
//! * **`src/**/*_tests.rs`, `src/**/tests.rs` and `src/**/test_support.rs`**
//!   are test code the workspace compiles behind a `#[cfg(test)]` or a
//!   dev-only feature, and are skipped on the same grounds the sibling
//!   guard skips them (see its module docs, which pin both halves).
//!
//! ## Counter-assertions
//!
//! * [`the_scan_still_finds_both_assembly_sites`] — the census, by file
//!   and function. An empty or shrunken list means a rename took the
//!   scan's corpus with it.
//! * [`a_third_assembly_site_fails_the_scan`] — a mutation over **real
//!   on-disk source**: plant a third `AnchorEvidence` literal in a real
//!   production file and watch the scan go red.
//! * [`the_derived_anchor_has_no_other_way_in`] — the anchor field is
//!   declared private, and the type exposes no constructor, no `Default`
//!   and no setter.
//! * [`removing_the_privacy_fails_the_scan`] — the mutation for that
//!   half: put `pub` back on the field and the assertion must fail.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! * **An `AnchorEvidence` assembled through a macro** is invisible, as
//!   in every sibling guard.
//! * **A literal spelled through a type alias or a re-export under
//!   another name** (`use … as Evidence;`) is not matched. The scan pins
//!   the type's own name, which is the only spelling the workspace uses.
//! * **A function that takes an `AnchorEvidence` apart and rebuilds it
//!   with `..evidence`** reads as an assembly site, which is the right
//!   answer: changing a field is deciding an anchor differently.
//! * **The privacy half is a source read, not a type-system query.** It
//!   cannot see a `#[cfg(...)]`-gated `pub(crate)` constructor added for
//!   one build, and it is pinned to the declaration's spelling.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `quarantine_anchor_is_artifact_time`, `capped_stream_writes` and
//! `cas_reads_are_verified`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    block_end, is_ident_byte, line_of, parse_fns, production_region, skip_ws, walk_rust,
    workspace_root, FnItem,
};

/// The evidence struct whose literals are the assembly sites.
const EVIDENCE_TYPE: &str = "AnchorEvidence";

/// The derived result, which may only come out of the derivation.
const DERIVED_TYPE: &str = "DerivedAnchor";

/// The one file both assembly sites live in.
const ASSEMBLY_FILE: &str = "crates/hort-app/src/use_cases/quarantine_anchor_assembly.rs";

/// Where [`DERIVED_TYPE`] is defined — the only module a literal of it
/// may appear in.
const DERIVATION_FILE: &str = "crates/hort-domain/src/policy/quarantine_anchor.rs";

/// One struct-literal site in production source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    /// Workspace-relative path, forward slashes.
    rel: String,
    /// 1-based line of the literal.
    line: usize,
    /// The innermost enclosing `fn`, or `<item>` outside one.
    func: String,
}

/// True when `needle` sits at `at` as a whole token — neither side
/// continuing an identifier. A leading `::` is fine (a path-qualified
/// spelling is the same type), which is why only identifier bytes
/// disqualify.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return false;
    }
    let after = at + needle.len();
    after >= bytes.len() || !is_ident_byte(bytes[after])
}

/// The last token before `at`, ignoring whitespace — an identifier, or a
/// run of up to two punctuation bytes (enough for `->`).
///
/// This is how a literal is told apart from the four non-expression
/// positions the same token appears in: a declaration (`struct`), an
/// inherent impl (`impl`), a return type (`->`) and a destructuring
/// pattern (`let`).
fn preceding_token(text: &str, at: usize) -> String {
    let head = text[..at].trim_end();
    let bytes = head.as_bytes();
    let end = bytes.len();
    if end == 0 {
        return String::new();
    }
    if is_ident_byte(bytes[end - 1]) {
        let mut start = end;
        while start > 0 && is_ident_byte(bytes[start - 1]) {
            start -= 1;
        }
        return head[start..end].to_string();
    }
    let mut start = end;
    while start > 0
        && !is_ident_byte(bytes[start - 1])
        && !bytes[start - 1].is_ascii_whitespace()
        && end - start < 2
    {
        start -= 1;
    }
    head[start..end].to_string()
}

/// The tokens that make `TYPE {` something other than a struct literal.
///
/// `struct` / `impl` are the type's own declaration and inherent impl;
/// `->` is a return type immediately followed by the function body's
/// brace; `let` is a destructuring pattern, which reads a value apart
/// rather than building one. None of them decides an anchor.
const NON_EXPRESSION_PRECEDERS: [&str; 6] = ["struct", "impl", "->", "let", "enum", "union"];

/// The innermost `fn` whose body contains `offset`.
fn enclosing_fn(items: &[FnItem], offset: usize) -> Option<&FnItem> {
    items
        .iter()
        .filter(|item| item.span.0 <= offset && offset < item.span.1)
        .max_by_key(|item| item.span.0)
}

/// Every `TYPE { … }` struct-literal expression in one production file.
///
/// A literal is `TYPE` on a token boundary followed by a `{` that opens a
/// balanced block, and whose preceding token is not one of
/// [`NON_EXPRESSION_PRECEDERS`] — which is what keeps the declaration,
/// the inherent impl, a return type and a destructuring pattern out.
fn literal_sites(rel: &str, source: &str, type_name: &str) -> Vec<Site> {
    let text = production_region(source);
    let bytes = text.as_bytes();
    let items = parse_fns(&text);
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(type_name) {
        let at = from + found;
        from = at + type_name.len();
        if !is_token(bytes, at, type_name) {
            continue;
        }
        if NON_EXPRESSION_PRECEDERS.contains(&preceding_token(&text, at).as_str()) {
            continue;
        }
        let brace = skip_ws(bytes, at + type_name.len());
        if bytes.get(brace) != Some(&b'{') {
            continue;
        }
        if block_end(bytes, brace).is_none() {
            continue;
        }
        let item = enclosing_fn(&items, at);
        out.push(Site {
            rel: rel.to_string(),
            line: line_of(&text, at),
            func: item.map_or_else(|| "<item>".to_string(), |item| item.name.clone()),
        });
    }
    out
}

/// True for an inline test module the workspace includes behind a
/// `#[cfg(test)]` in a sibling, so no attribute appears inside the file
/// itself — and for the dev-only fixture builders. Both exclusions are
/// pinned by the sibling guard
/// (`quarantine_anchor_is_artifact_time::every_skipped_test_file_is_really_compiled_out`
/// and `::every_test_support_file_is_dev_only`), which is why they are
/// not re-derived here.
fn is_test_code(rel: &str) -> bool {
    rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs") || rel.ends_with("/test_support.rs")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `crates/*/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(root.join("crates")).expect("crates/ exists under the root");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.retain(|path| !is_test_code(&relative(root, path)));
    out.sort();
    out
}

/// Scan the production tree for literals of `type_name`.
fn scan(root: &Path, type_name: &str) -> Vec<Site> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        out.extend(literal_sites(&rel, &source, type_name));
    }
    out.sort();
    out
}

fn describe(site: &Site) -> String {
    format!("{}:{} — in `{}`", site.rel, site.line, site.func)
}

// ---------------------------------------------------------------------------
// The two assertions.
// ---------------------------------------------------------------------------

#[test]
fn anchor_evidence_is_assembled_only_in_the_assembly_module() {
    let strays: Vec<String> = scan(&workspace_root(), EVIDENCE_TYPE)
        .iter()
        .filter(|site| site.rel != ASSEMBLY_FILE)
        .map(describe)
        .collect();

    assert!(
        strays.is_empty(),
        "`AnchorEvidence` is assembled in exactly two places — one for a row being \
         minted, one for an artifact re-entering the hold — and both live in \
         `{ASSEMBLY_FILE}`. A third site is a third reading of the same facts, and two \
         readings that disagree are two anchors for one artifact: a quarantine begins \
         where hort can prove the artifact was already published (ADR 0054), so one \
         artifact has one anchor whichever path asks. If a new hold path needs an \
         anchor, call `derive_mint_anchor` or \
         `QuarantineAnchorResolver::derive_for_re_entry`; if it needs evidence neither \
         of them assembles, add it there. There is no allow-list — a site that \
         genuinely must assemble its own is a review conversation. {} stray site(s) \
         below:\n  {}",
        strays.len(),
        strays.join("\n  ")
    );
}

#[test]
fn a_derived_anchor_is_built_only_by_the_derivation() {
    let strays: Vec<String> = scan(&workspace_root(), DERIVED_TYPE)
        .iter()
        .filter(|site| site.rel != DERIVATION_FILE)
        .map(describe)
        .collect();

    assert!(
        strays.is_empty(),
        "a `DerivedAnchor` may only come out of `derive_quarantine_anchor`. Its anchor \
         is a private field precisely so the three `Artifact` methods that re-enter \
         the hold can take a `DerivedAnchor` instead of a `DateTime<Utc>` — a bare \
         instant parameter accepts a wall-clock reading taken at the moment of the \
         hold, which renews a window that must never renew, and no source scan can see \
         a clock that arrives through an argument. A literal outside \
         `{DERIVATION_FILE}` would mean that privacy was removed. {} stray site(s) \
         below:\n  {}",
        strays.len(),
        strays.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions — the scan's own reach.
// ---------------------------------------------------------------------------

/// The census: both assembly sites, by file and function. A shrunken list
/// means a rename emptied the scan's corpus and the assertion above is
/// answering about nothing.
#[test]
fn the_scan_still_finds_both_assembly_sites() {
    let census: Vec<(String, String)> = scan(&workspace_root(), EVIDENCE_TYPE)
        .into_iter()
        .map(|site| (site.rel, site.func))
        .collect();

    assert_eq!(
        census,
        vec![
            (ASSEMBLY_FILE.to_string(), "derive_mint_anchor".to_string()),
            (ASSEMBLY_FILE.to_string(), "derive_for_re_entry".to_string()),
        ],
        "the two assembly sites are this guard's whole corpus: one for a mint, one for \
         a re-entry. If this list is empty or short, the type, the functions or the \
         scan's matcher was renamed and the main assertion is answering about less \
         than it claims"
    );
}

/// …and the derivation's own literals, for the same reason.
#[test]
fn the_scan_still_finds_the_derivations_own_literals() {
    let root = workspace_root();
    let source =
        fs::read_to_string(root.join(DERIVATION_FILE)).expect("the derivation is readable UTF-8");
    let sites: Vec<String> = literal_sites(DERIVATION_FILE, &source, DERIVED_TYPE)
        .into_iter()
        .map(|site| site.func)
        .collect();

    assert_eq!(
        sites,
        vec!["derive_quarantine_anchor".to_string(); 2],
        "`derive_quarantine_anchor` builds a `DerivedAnchor` twice — the override \
         short-circuit and the composed minimum. Both in one function, which is the \
         property the privacy exists to create; if this list has changed, the scan is \
         no longer reading the derivation"
    );
}

/// The mutation counter-assertion: plant a third assembly site in **real
/// on-disk source** and the scan must go red.
///
/// The file chosen is the one the sites were lifted out of, so the
/// mutation reproduces the shape the defect actually had rather than an
/// invented one.
#[test]
fn a_third_assembly_site_fails_the_scan() {
    let root = workspace_root();
    let rel = "crates/hort-app/src/use_cases/ingest_use_case.rs";
    let source = fs::read_to_string(root.join(rel)).expect("the ingest path is readable UTF-8");

    assert!(
        literal_sites(rel, &source, EVIDENCE_TYPE).is_empty(),
        "the ingest path must assemble no evidence of its own before it is mutated — \
         it calls `derive_mint_anchor`"
    );

    // The shape the two minting paths carried inline before the assembly
    // moved: a literal inside the function that decides the quarantine.
    let anchor = "let derived = derive_mint_anchor(";
    assert_eq!(
        source.matches(anchor).count(),
        2,
        "both minting paths call into the shared assembly, so this file must still \
         hold exactly two such calls — `decide_and_apply_quarantine`'s and \
         `apply_register_gate`'s. The mutation is planted at the first of them"
    );
    let planted = format!("let _planted = AnchorEvidence {{ minted_at: now }};\n        {anchor}");
    let mutated = source.replacen(anchor, &planted, 1);

    let reported: Vec<String> = literal_sites(rel, &mutated, EVIDENCE_TYPE)
        .iter()
        .map(describe)
        .collect();
    assert_eq!(
        reported.len(),
        1,
        "a third `AnchorEvidence` literal planted in real production source must be \
         reported; the scan found {reported:?}"
    );
    assert!(
        reported[0].contains("decide_and_apply_quarantine"),
        "the report must name the function the literal was planted in: {reported:?}"
    );
}

/// The privacy half, stated rather than left to a reader noticing a
/// missing `pub`.
///
/// The honest form is a compile-fail fixture, which the workspace has no
/// harness for (no `trybuild` in `Cargo.lock`) — so this asserts the
/// three things that together make the type unconstructible from outside
/// its module: the anchor field is declared private, the type derives no
/// `Default`, and its inherent impl exposes no constructor or setter.
/// [`a_derived_anchor_is_built_only_by_the_derivation`] is the fourth,
/// over the whole tree.
#[test]
fn the_derived_anchor_has_no_other_way_in() {
    let root = workspace_root();
    let source =
        fs::read_to_string(root.join(DERIVATION_FILE)).expect("the derivation is readable UTF-8");
    let text = production_region(&source);

    assert!(
        text.contains("pub struct DerivedAnchor {"),
        "the type must still be declared here, or this test is asserting about a type \
         that moved"
    );
    assert!(
        text.contains("\n    anchor: DateTime<Utc>,"),
        "`DerivedAnchor::anchor` must be declared WITHOUT `pub`: a public field makes \
         `DerivedAnchor {{ anchor, source, upstream_clamp_fired }}` constructible \
         anywhere, and the type's whole purpose is that the three `Artifact` methods \
         which re-enter the hold cannot be handed an anchor nothing derived"
    );
    assert!(
        !text.contains("pub anchor:"),
        "no field of any type in this module may be named `anchor` and public — the \
         assertion above would then be reading the wrong declaration"
    );

    // No second way in: the inherent impl must expose readers only.
    let impl_at = text
        .find("impl DerivedAnchor {")
        .expect("the type's inherent impl is where a constructor would be added");
    let open = impl_at + "impl DerivedAnchor ".len();
    let close = block_end(text.as_bytes(), open).expect("the inherent impl block is balanced");
    let body = &text[open..close];
    for forbidden in ["fn new(", "fn with_", "fn set_", "fn from_"] {
        assert!(
            !body.contains(forbidden),
            "`DerivedAnchor` must expose no constructor or setter (`{forbidden}…`): \
             every one of them is a second route to an anchor the derivation did not \
             produce"
        );
    }
    assert!(
        !text.contains("Default)]") && !text.contains("Default,"),
        "`DerivedAnchor` must not derive `Default`: a default anchor is the UNIX epoch, \
         i.e. an already-elapsed window on no evidence at all"
    );
}

/// The mutation for the privacy half: make the field public again in
/// **real on-disk source** and
/// [`the_derived_anchor_has_no_other_way_in`]'s predicate must fail.
///
/// Without this the three `assert!`s above could be passing because the
/// strings they look for are absent for some other reason.
#[test]
fn removing_the_privacy_fails_the_scan() {
    let root = workspace_root();
    let source =
        fs::read_to_string(root.join(DERIVATION_FILE)).expect("the derivation is readable UTF-8");

    let private = "\n    anchor: DateTime<Utc>,";
    assert_eq!(
        source.matches(private).count(),
        1,
        "the private declaration must appear exactly once, or the mutation below is \
         substituting something else"
    );
    let mutated = source.replace(private, "\n    pub anchor: DateTime<Utc>,");
    let text = production_region(&mutated);

    assert!(
        !text.contains(private),
        "the mutation must actually remove the private declaration"
    );
    assert!(
        text.contains("pub anchor:"),
        "and must introduce the public one — which is the condition \
         `the_derived_anchor_has_no_other_way_in` rejects"
    );
}
