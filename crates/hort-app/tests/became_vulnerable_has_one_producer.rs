//! Structural guard: **every production `ArtifactBecameVulnerable` is
//! built by the bounded constructor**, and the only struct literals of
//! the event live inside the type's own `impl` block in the file that
//! defines it.
//!
//! ## The invariant
//!
//! `ArtifactBecameVulnerable.new_findings` is filled from a scan delta,
//! which is unbounded, and the event is stored in an envelope that is
//! not: `DomainEvent::validate_for_storage` refuses anything past
//! `MAX_EVENT_JSON_BYTES`, and `migrations/004_events.sql`'s
//! `events_event_data_check` refuses it a second time on
//! `pg_column_size(event_data)`. A caller that assembles the literal
//! itself therefore writes an event that *may* be unstorable, and the
//! failure does not land where the mistake was made: the append refuses
//! the whole batch, the scan that produced it ends with no verdict at
//! all, and the artifacts worst affected are precisely the ones with the
//! most findings. That is measured rather than hypothetical — eleven scan
//! jobs died terminally inside one quarter-hour on a running instance,
//! with serialised payloads from 1.1x to 19x the cap.
//!
//! `ArtifactBecameVulnerable::retaining_most_severe` is the answer: it
//! orders the findings most-severe-first, bisects the retained count
//! against the real stored envelope, records the true total in
//! `truncated_from_total`, and returns a `DomainError::Validation` for
//! the one input shape no retained set can represent. Every event it
//! returns satisfies `validate_for_storage`.
//!
//! Nothing in the language holds that. The struct is `pub` with `pub`
//! fields of necessity — it is serialised, deserialised, matched on and
//! asserted over in four crates — so the next caller can build the
//! literal directly, and it compiles, passes clippy, and passes the
//! whole suite. What it does not do is survive contact with a large
//! delta. This guard is what makes "one producer" a property of the
//! tree rather than a convention the current authors happen to follow.
//!
//! ## The property
//!
//! Across every crate's production Rust, a struct literal of the event
//! — spelled as the type name, or as `Self` inside an `impl` block whose
//! self type is the event — appears only inside the type's own `impl`
//! block in [`DEFINING_FILE`].
//!
//! A literal is the type (or `Self`) on a token boundary followed by `{`.
//! The forms that are **not** literals are deliberately not hits:
//!
//! * `pub struct ArtifactBecameVulnerable {` and
//!   `impl ArtifactBecameVulnerable {` — the declaration and the impl
//!   header, told apart by the keyword that precedes the name.
//! * `DomainEvent::ArtifactBecameVulnerable(e)` — the enum variant, which
//!   carries the payload rather than constructing it, and is followed by
//!   `(` and not `{`. Every consumer in the workspace reaches the event
//!   this way, and none of them is a producer.
//! * A `Self { … }` inside an `impl` block of any **other** type.
//!
//! ## Why the permitted region is derived rather than exempted
//!
//! The permitted region is not a list of blessed call sites: it is
//! "inside the type's own `impl` block, in the file that declares the
//! type". That is where `validate()`, the cap, the payload budget and
//! the bisection already live, and it is the region the severity
//! ranking the fill depends on is visible from: `severity_tier` is
//! `pub(crate)` to `hort-domain`, so no layer above the domain can put
//! the findings in the order the truncation needs even if it wanted to.
//! So the statement is structural, and **there is no allow-list** — no
//! entry anyone can add to make a finding go away. A site outside that
//! region which genuinely must build the literal is a review
//! conversation about whether the constructor should grow an argument.
//!
//! Test code is out of scope by how it is compiled, not by a line in
//! this file. A `#[cfg(test)]` item is blanked by
//! [`rust_scan::production_region`], and a `src/**/*_tests.rs` or
//! `src/**/tests.rs` is an inline test module the workspace includes
//! behind a `#[cfg(test)] mod` declaration —
//! [`every_skipped_test_file_is_really_compiled_out`] asserts that
//! pairing rather than taking the filename's word for it, so the
//! exclusion cannot come to cover a file that is actually compiled in.
//! Test code legitimately builds the literal to assert about
//! `validate()`, about the recorded total and about the wire form — at
//! twelve sites across five files, measured — and a guard that argued
//! with it would be arguing about fixtures. A
//! `src/**/test_support.rs` is deliberately **in** scope: it is gated
//! `#[cfg(any(test, feature = "test-support"))]`, so a feature-enabled
//! build ships it, and a round-tripping double that accepted an event no
//! producer can write would be the hazard `CLAUDE.md`'s "a test double
//! that round-trips must refuse what production refuses" names.
//!
//! ## Counter-assertions
//!
//! A scan whose needle no longer matches anything is vacuously green,
//! which is how guards in this family die. So:
//!
//! * [`the_defining_file_still_declares_the_type_and_its_constructor`] —
//!   the struct, its own `impl` block and the constructor are all still
//!   there under the names this file names. A rename turns this red,
//!   which is the moment to re-read where the one producer is.
//! * [`the_permitted_sites_are_still_found`] — the scan still finds
//!   literals in the permitted region, and the functions holding them
//!   are **exactly** [`PERMITTED_SITES`]. Pinned with each one's reason
//!   rather than counted: a third constructing function inside the impl
//!   block is not a line to add on the way past, it is the question
//!   "does this one bound the payload?" put in front of whoever adds it.
//! * [`the_scan_reports_a_planted_literal`] and
//!   [`the_real_definition_is_only_permitted_where_it_lives`] — the
//!   mutation checks. The first plants a literal in a fixture tree and
//!   watches the scan go red; the second transplants the **real**
//!   defining file to another path and watches its own literals become
//!   violations, which is what shows the location half of the permit is
//!   load-bearing rather than decorative.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The ones every source scan has. A literal assembled through a macro
//! is invisible. A literal built behind a type alias or a `use … as`
//! rename is spelled with a name this file does not know and is missed.
//! An event cloned from another and mutated field-by-field
//! (`let mut e = other.clone(); e.new_findings = …;`) constructs no
//! literal and is likewise missed — the honest close for that one is
//! `validate()`, which every such event still has to pass on append.
//!
//! In the other direction, a `match`/`if let` pattern that destructures
//! the event by name (`ArtifactBecameVulnerable { artifact_id, .. }`)
//! reads as a literal and would be reported. There is no production one
//! today; if one appears, it is a false positive and a review
//! conversation about whether to teach the matcher patterns, not an
//! exemption entry.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as
//! `capped_stream_writes`, `jobs_row_has_one_owner` and
//! `cas_reads_are_verified`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    block_end, is_ident_byte, line_of, parse_fns, production_region, skip_ws, starts_a_token,
    walk_rust, workspace_root,
};

/// The file that declares the event, holds its `impl` block, its
/// `validate()`, the payload budget and the bisection — the one region a
/// literal may appear in.
const DEFINING_FILE: &str = "crates/hort-domain/src/events/artifact_events.rs";

/// The event whose construction is policed.
const EVENT: &str = "ArtifactBecameVulnerable";

/// The bounded constructor: the only producer.
const CONSTRUCTOR: &str = "retaining_most_severe";

/// The functions inside the type's own `impl` block that build a literal,
/// each with the reason it is one — pinned where the assertion stands, so
/// a reader of this guard reads the reasons and a reason that has stopped
/// being true sits in front of whoever next edits the list.
///
/// Two, and both are the bounding machinery rather than exceptions to it:
/// a third entry means a method that builds the event without going
/// through the fill, which is the defect this guard exists for even
/// though it would be inside the impl block.
const PERMITTED_SITES: &[(&str, &str)] = &[
    (
        CONSTRUCTOR,
        "the bounded constructor: orders most-severe-first, bisects the \
         retained count against the real stored envelope, records the true \
         total, and returns every event through `validate()`",
    ),
    (
        "fits_budget",
        "the measurement the bisection fills to — it builds a probe only to \
         serialise it and compare against the budget, and never returns or \
         appends one; it is how the constructor is bounded, not a second \
         producer",
    ),
];

/// Keywords that, immediately before the event's name, mean the
/// occurrence is an item header rather than a literal: the declaration,
/// an inherent `impl`, and the self-type position of a trait `impl`.
const ITEM_KEYWORDS: &[&str] = &["struct", "enum", "union", "trait", "impl", "for"];

/// How a literal was spelled, for the failure message — the two forms
/// are the same construction and the shorter one is the easy miss.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Spelling {
    /// `ArtifactBecameVulnerable { … }`.
    TypeName,
    /// `Self { … }` inside an `impl` block whose self type is the event.
    SelfInImpl,
}

/// One struct literal of the event.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Literal {
    /// Workspace-relative path, forward slashes.
    rel: String,
    /// 1-based line of the literal's name token.
    line: usize,
    spelling: Spelling,
    /// Whether the literal sits inside an `impl` block whose self type is
    /// the event.
    in_own_impl: bool,
    /// The `fn` the literal sits in, when the scan can attribute one. A
    /// literal in a `const` initialiser or at item scope has none.
    function: Option<String>,
}

impl Literal {
    /// A literal is permitted exactly where the construction is bounded:
    /// inside the type's own `impl` block, in the file that declares it.
    fn is_permitted(&self) -> bool {
        self.rel == DEFINING_FILE && self.in_own_impl
    }
}

// ---------------------------------------------------------------------------
// Source enumeration
// ---------------------------------------------------------------------------

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn all_sources(root: &Path) -> Vec<PathBuf> {
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

/// True for an inline test module this workspace keeps in its own file
/// under `src/` — `*_tests.rs` and `tests.rs`, both declared behind a
/// `#[cfg(test)] mod` in a sibling, so no attribute appears inside the
/// file itself for [`production_region`] to blank.
/// [`every_skipped_test_file_is_really_compiled_out`] checks that pairing
/// rather than trusting the name.
///
/// `test_support.rs` is **not** here — see the module docs.
fn is_inline_test_module(rel: &str) -> bool {
    rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// The matcher
// ---------------------------------------------------------------------------

/// Collapse whitespace, so a type rustfmt wrapped across lines reads as
/// one name.
fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// True when `needle` sits at `at` as a whole token — neither side
/// continuing an identifier.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    starts_a_token(bytes, at)
        && !bytes
            .get(at + needle.len())
            .copied()
            .is_some_and(is_ident_byte)
}

/// Every offset at which `needle` sits in `text` as a whole token.
fn token_offsets(text: &str, needle: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(found) = text[search..].find(needle) {
        let at = search + found;
        search = at + 1;
        if is_token(bytes, at, needle) {
            out.push(at);
        }
    }
    out
}

/// The identifier token immediately before `at`, skipping whitespace.
fn preceding_ident(text: &str, at: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut end = at;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 || !is_ident_byte(bytes[end - 1]) {
        return None;
    }
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    Some(&text[start..end])
}

/// True when the name token at `at` is followed by a literal's `{`.
fn opens_a_literal(text: &str, at: usize, name: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.get(skip_ws(bytes, at + name.len())) == Some(&b'{')
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

/// True when an `impl` header — the text between the `impl` keyword and
/// the block's opening `{` — names the event as its **self type**, which
/// is what makes a `Self { … }` inside the block a literal of the event.
///
/// Read as "the header ends with the event's name", which is where a
/// self type sits in both forms that matter:
/// `impl ArtifactBecameVulnerable` is the real one, and
/// `impl Default for ArtifactBecameVulnerable { fn default() -> Self {
/// Self { … } } }` would be a production literal in the shortest
/// possible spelling — a matcher that understood only the inherent form
/// would not see it.
///
/// Ending there is also what tells those apart from the three headers
/// that name the event somewhere else and do not implement it:
/// `impl<T: Into<ArtifactBecameVulnerable>> Foo for Bar`,
/// `impl Foo<ArtifactBecameVulnerable> for Bar` and
/// `impl Foo for Wrapper<ArtifactBecameVulnerable>` all end with
/// something else. A `where` clause is dropped first, and the preceding
/// byte must not continue an identifier, so a hypothetical
/// `PendingArtifactBecameVulnerable` is not a match while a
/// path-qualified `impl crate::events::ArtifactBecameVulnerable` is.
fn impl_targets_the_event(header: &str) -> bool {
    let head = normalise(before_where(header));
    let Some(start) = head.len().checked_sub(EVENT.len()) else {
        return false;
    };
    head[start..] == *EVENT
        && !head.as_bytes()[..start]
            .last()
            .copied()
            .is_some_and(is_ident_byte)
}

/// The `(brace, close)` spans of every `impl` block in `text` whose self
/// type is the event.
fn own_impl_blocks(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for at in token_offsets(text, "impl") {
        let after = at + "impl".len();
        // On blanked text an `impl` header carries no `{` of its own —
        // generics, a path and a `where` clause are all other
        // punctuation — so the first one is the block opener.
        let Some(rel) = text[after..].find('{') else {
            continue;
        };
        let brace = after + rel;
        if !impl_targets_the_event(&text[after..brace]) {
            continue;
        }
        let close = block_end(bytes, brace).unwrap_or(bytes.len() - 1);
        out.push((brace, close));
    }
    out
}

/// The innermost `fn` whose body contains `at`, by name.
fn enclosing_fn(fns: &[rust_scan::FnItem], at: usize) -> Option<String> {
    fns.iter()
        .filter(|item| item.span.0 <= at && at < item.span.1)
        .max_by_key(|item| item.span.0)
        .map(|item| item.name.clone())
}

/// Every struct literal of the event in one file's production region.
fn literals_in(rel: &str, source: &str) -> Vec<Literal> {
    let text = production_region(source);
    let fns = parse_fns(&text);
    let blocks = own_impl_blocks(&text);
    let inside = |at: usize| blocks.iter().any(|(open, close)| *open < at && at < *close);

    let mut out = Vec::new();
    for at in token_offsets(&text, EVENT) {
        if !opens_a_literal(&text, at, EVENT) {
            continue;
        }
        // `pub struct ArtifactBecameVulnerable {`,
        // `impl ArtifactBecameVulnerable {`,
        // `impl Serialize for ArtifactBecameVulnerable {` — headers, not
        // literals.
        if preceding_ident(&text, at).is_some_and(|kw| ITEM_KEYWORDS.contains(&kw)) {
            continue;
        }
        out.push(Literal {
            rel: rel.to_string(),
            line: line_of(&text, at),
            spelling: Spelling::TypeName,
            in_own_impl: inside(at),
            function: enclosing_fn(&fns, at),
        });
    }
    for (open, close) in &blocks {
        for at in token_offsets(&text[*open..*close], "Self") {
            let at = open + at;
            if !opens_a_literal(&text, at, "Self") {
                continue;
            }
            out.push(Literal {
                rel: rel.to_string(),
                line: line_of(&text, at),
                spelling: Spelling::SelfInImpl,
                in_own_impl: true,
                function: enclosing_fn(&fns, at),
            });
        }
    }
    out.sort_by_key(|lit| lit.line);
    out
}

/// Every struct literal of the event in the production sources under
/// `root`.
fn scan(root: &Path) -> Vec<Literal> {
    let mut out = Vec::new();
    for path in all_sources(root) {
        let rel = relative(root, &path);
        if is_inline_test_module(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        out.extend(literals_in(&rel, &source));
    }
    out
}

/// A literal, as a failure line.
fn describe(lit: &Literal) -> String {
    format!(
        "{}:{} — `{} {{ … }}`{}",
        lit.rel,
        lit.line,
        match lit.spelling {
            Spelling::TypeName => EVENT,
            Spelling::SelfInImpl => "Self",
        },
        match &lit.function {
            Some(name) => format!(" in `fn {name}`"),
            None => " at item scope".to_string(),
        }
    )
}

// ---------------------------------------------------------------------------
// The assertion
// ---------------------------------------------------------------------------

#[test]
fn every_became_vulnerable_literal_is_the_bounded_constructor() {
    let violations: Vec<String> = scan(&workspace_root())
        .iter()
        .filter(|lit| !lit.is_permitted())
        .map(describe)
        .collect();

    assert!(
        violations.is_empty(),
        "a production `{EVENT}` is assembled as a struct literal outside the \
         one place that bounds it ({} site(s)). Call \
         `{EVENT}::{CONSTRUCTOR}(artifact_id, &new_findings, \
         previously_clean_at)?` instead. The findings a scan delta produces \
         are unbounded and the stored envelope is not, so a hand-assembled \
         literal is an event the append path MAY refuse — and when it does, \
         it refuses the whole batch: the scan ends with no verdict, for \
         exactly the artifacts that have the most findings. There is no \
         allow-list; a site that genuinely cannot use the constructor is a \
         review conversation about whether the constructor needs another \
         argument.\nLiterals:\n  {}",
        violations.len(),
        violations.join("\n  "),
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions — a scan that matches nothing is vacuously green
// ---------------------------------------------------------------------------

/// The names this guard is written in terms of are still the tree's.
#[test]
fn the_defining_file_still_declares_the_type_and_its_constructor() {
    let root = workspace_root();
    let source =
        fs::read_to_string(root.join(DEFINING_FILE)).expect("the defining file is readable UTF-8");
    let text = production_region(&source);

    for (what, needle) in [
        ("the event struct", format!("pub struct {EVENT} {{")),
        ("its own impl block", format!("impl {EVENT} {{")),
        ("the bounded constructor", format!("pub fn {CONSTRUCTOR}(")),
    ] {
        assert_eq!(
            text.matches(&needle).count(),
            1,
            "{DEFINING_FILE} must still define {what} exactly once \
             (`{needle}`). If it moved or was renamed, this guard is watching \
             the wrong file and the scan above is vacuously green"
        );
    }

    assert_eq!(
        own_impl_blocks(&text).len(),
        1,
        "the event has more than one `impl` block in {DEFINING_FILE}. That is \
         not wrong in itself, but the permitted region is 'inside the type's \
         own impl block' — read each one against the payload budget before \
         widening it"
    );
}

/// The permitted region really holds literals, and the functions that
/// build them are exactly [`PERMITTED_SITES`].
///
/// Pinned rather than counted: a method added to the impl block that
/// builds the event without going through the fill is the defect this
/// guard exists for, and it would sit inside the permitted region. This
/// is the assertion that puts it in front of a reader.
#[test]
fn the_permitted_sites_are_still_found() {
    let permitted: Vec<Literal> = scan(&workspace_root())
        .into_iter()
        .filter(Literal::is_permitted)
        .collect();

    assert!(
        !permitted.is_empty(),
        "the scan found no `{EVENT}` literal in the permitted region at all, \
         so its green verdict means nothing: the type, the spelling or the \
         defining file changed under it"
    );

    let mut found: Vec<String> = permitted
        .iter()
        .map(|lit| {
            lit.function.clone().unwrap_or_else(|| {
                panic!("{} holds a literal outside any fn", describe(lit));
            })
        })
        .collect();
    found.sort();
    found.dedup();

    let mut pinned: Vec<String> = PERMITTED_SITES
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    pinned.sort();

    assert_eq!(
        found, pinned,
        "the functions building an `{EVENT}` literal inside the type's own \
         impl block no longer match what this guard pins. A name that \
         disappeared means the construction moved — follow it, because the \
         scan above cannot see a producer that left the region. A name that \
         appeared is a new construction site inside the permitted region: \
         read it against the payload budget, then pin it in PERMITTED_SITES \
         with the reason it is bounded.\nfound:  {found:?}\npinned: {pinned:?}"
    );
}

/// The test-code exclusion is derived, not conventional: every file the
/// scan skips by name is declared behind a `#[cfg(test)]` in a sibling,
/// so skipping it cannot hide production code.
#[test]
fn every_skipped_test_file_is_really_compiled_out() {
    let root = workspace_root();
    let sources = all_sources(&root);
    let mut unexplained: Vec<String> = Vec::new();

    for path in &sources {
        let rel = relative(&root, path);
        if !is_inline_test_module(&rel) {
            continue;
        }
        let name = path
            .file_name()
            .expect("a scanned path has a file name")
            .to_string_lossy()
            .to_string();
        let stem = name.trim_end_matches(".rs").to_string();
        let declared_test_only = sources.iter().any(|sibling| {
            if sibling.parent() != path.parent() || *sibling == *path {
                return false;
            }
            let Ok(source) = fs::read_to_string(sibling) else {
                return false;
            };
            // Read raw, not through `production_region`: the declaration
            // being blanked as a `#[cfg(test)]` item is exactly the thing
            // being looked for, and it is checked as the attribute run it
            // is written as. Both spellings the workspace uses —
            // `#[cfg(test)] #[path = "x_tests.rs"] mod tests;` and
            // `#[cfg(test)] mod tests;`.
            source.contains(&format!("#[cfg(test)]\n#[path = \"{name}\"]"))
                || source.contains(&format!("#[path = \"{name}\"]\n#[cfg(test)]"))
                || source.contains(&format!("#[cfg(test)]\nmod {stem};"))
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
// Mutation checks — the scan goes red against a planted literal
// ---------------------------------------------------------------------------

/// A throwaway `crates/<crate>/src` tree holding `files`, removed by the
/// caller.
fn fixture_tree(tag: u32, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hort-became-vulnerable-guard-{}-{tag}",
        std::process::id()
    ));
    let src = dir.join("crates/hort-app/src");
    fs::create_dir_all(&src).expect("fixture tree is creatable");
    for (name, body) in files {
        fs::write(src.join(name), body).expect("fixture file is writable");
    }
    dir
}

/// The scan reports a planted literal, and leaves the forms that are not
/// literals alone. Without this, every green run above could be a matcher
/// that recognises nothing.
#[test]
fn the_scan_reports_a_planted_literal() {
    let cases: &[(&str, &str, bool)] = &[
        (
            "planted.rs",
            "fn emit(id: Uuid, f: Vec<Finding>) -> DomainEvent {\n    \
             DomainEvent::ArtifactBecameVulnerable(ArtifactBecameVulnerable {\n        \
             artifact_id: id,\n        new_findings: f,\n        \
             previously_clean_at: Utc::now(),\n        \
             truncated_from_total: None,\n    })\n}\n",
            true,
        ),
        (
            "wrapped.rs",
            "fn emit() -> ArtifactBecameVulnerable {\n    \
             ArtifactBecameVulnerable\n    { artifact_id: Uuid::nil() }\n}\n",
            true,
        ),
        (
            "self_in_trait_impl.rs",
            "impl Default for ArtifactBecameVulnerable {\n    \
             fn default() -> Self {\n        Self { artifact_id: Uuid::nil() }\n    \
             }\n}\n",
            true,
        ),
        (
            "declaration.rs",
            "pub struct ArtifactBecameVulnerable {\n    pub artifact_id: Uuid,\n}\n",
            false,
        ),
        (
            "variant.rs",
            "fn kind(e: &DomainEvent) -> bool {\n    \
             matches!(e, DomainEvent::ArtifactBecameVulnerable(_))\n}\n",
            false,
        ),
        (
            "prose.rs",
            "/// Builds an `ArtifactBecameVulnerable { … }` for the caller.\n\
             fn emit() -> &'static str {\n    \
             \"ArtifactBecameVulnerable { artifact_id }\"\n}\n",
            false,
        ),
        (
            "cfg_test.rs",
            "#[cfg(test)]\nmod t {\n    fn f() -> ArtifactBecameVulnerable {\n        \
             ArtifactBecameVulnerable { artifact_id: Uuid::nil() }\n    }\n}\n",
            false,
        ),
        (
            "other_self.rs",
            "impl ScanCompleted {\n    fn new() -> Self {\n        \
             Self { artifact_id: Uuid::nil() }\n    }\n}\n",
            false,
        ),
        // The three headers that name the event somewhere other than
        // the self-type position. A `Self { … }` in any of them builds
        // a different type, so treating the block as the event's own
        // would report a literal that does not exist.
        (
            "event_in_a_bound.rs",
            "impl<T: Into<ArtifactBecameVulnerable>> Builder for Wrap<T> {\n    \
             fn build(&self) -> Self {\n        Self { inner: 1 }\n    }\n}\n",
            false,
        ),
        (
            "event_as_a_trait_argument.rs",
            "impl From<ArtifactBecameVulnerable> for Dto {\n    \
             fn from(e: ArtifactBecameVulnerable) -> Self {\n        \
             Self { id: e.artifact_id }\n    }\n}\n",
            false,
        ),
        (
            "event_inside_the_self_type.rs",
            "impl Describe for Vec<ArtifactBecameVulnerable> {\n    \
             fn describe(&self) -> Self {\n        Self { n: 0 }\n    }\n}\n",
            false,
        ),
        // A longer identifier ending in the event's name is a different
        // type.
        (
            "longer_ident.rs",
            "impl PendingArtifactBecameVulnerable {\n    \
             fn new() -> Self {\n        Self { artifact_id: Uuid::nil() }\n    \
             }\n}\n",
            false,
        ),
        // A path-qualified inherent impl is the same block.
        (
            "path_qualified.rs",
            "impl crate::events::ArtifactBecameVulnerable {\n    \
             fn new() -> Self {\n        Self { artifact_id: Uuid::nil() }\n    \
             }\n}\n",
            true,
        ),
        // A brace inside a string literal must not open a block: if it
        // did, the impl body would end early and the literal inside it
        // would be lost.
        (
            "braces_in_literals.rs",
            "impl ArtifactBecameVulnerable {\n    \
             fn new() -> Self {\n        \
             let _probe = \"{\";\n        \
             let _msg = format!(\"{}\", 1);\n        \
             Self { artifact_id: Uuid::nil() }\n    }\n}\n",
            true,
        ),
    ];
    let files: Vec<(&str, &str)> = cases.iter().map(|(n, b, _)| (*n, *b)).collect();
    let dir = fixture_tree(line!(), &files);

    let found: Vec<String> = scan(&dir).iter().map(|lit| lit.rel.clone()).collect();
    for (name, _, is_literal) in cases {
        let rel = format!("crates/hort-app/src/{name}");
        assert_eq!(
            found.contains(&rel),
            *is_literal,
            "{name}: the matcher must {} this form\nfound: {found:?}",
            if *is_literal { "report" } else { "ignore" },
        );
    }
    // And every literal it did find is a violation: none of them is in
    // the defining file.
    assert!(
        scan(&dir).iter().all(|lit| !lit.is_permitted()),
        "a planted literal outside {DEFINING_FILE} must not read as permitted"
    );

    fs::remove_dir_all(&dir).expect("fixture tree is removable");
}

/// The location half of the permit is load-bearing: the **real**
/// defining file, transplanted to another path, has its own literals
/// reported as violations.
///
/// This is the mutation check run against real on-disk source rather
/// than a fixture — it shows at once that the matcher finds the
/// production literals as they are actually written (`Self { … }` across
/// two functions, rustfmt's line breaks and all) and that what permits
/// them is where they live, not that the scan cannot see them.
#[test]
fn the_real_definition_is_only_permitted_where_it_lives() {
    let root = workspace_root();
    let source =
        fs::read_to_string(root.join(DEFINING_FILE)).expect("the defining file is readable UTF-8");

    let at_home = literals_in(DEFINING_FILE, &source);
    assert!(
        !at_home.is_empty() && at_home.iter().all(Literal::is_permitted),
        "the real defining file's own literals must all be permitted: {:?}",
        at_home.iter().map(describe).collect::<Vec<_>>()
    );

    let dir = fixture_tree(line!(), &[("transplanted.rs", source.as_str())]);
    let moved = scan(&dir);
    assert_eq!(
        moved.len(),
        at_home.len(),
        "the same file read from another path must yield the same literals; \
         the matcher is not reading the path"
    );
    assert!(
        moved.iter().all(|lit| !lit.is_permitted()),
        "the defining file's literals, moved out of {DEFINING_FILE}, must all \
         be violations — otherwise the permit is not about location at \
         all: {:?}",
        moved.iter().map(describe).collect::<Vec<_>>()
    );

    fs::remove_dir_all(&dir).expect("fixture tree is removable");
}
