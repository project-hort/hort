//! Structural guard: **every repeatable append to an artifact stream
//! refuses before it crosses the event cap, or states at the site why it
//! cannot.**
//!
//! This is the write-side counterpart to `capped_stream_reads`. The two
//! halves protect one property: `hort_app::use_cases::STREAM_EVENT_CAP` is
//! an *enforced* bound, so a single capped `ReadFrom::Start` read of an
//! artifact stream is the whole stream. The read side pins that a bounded
//! read exists in exactly one place and detects its own overflow. That is
//! only half the bargain — a read that refuses an over-cap stream is
//! fail-closed, not fixed. Once a stream is past the cap **every** capped
//! reader refuses it, so the artifact can no longer be released,
//! re-scanned, promoted or re-evaluated, and no operator instrument makes
//! a stream shorter. The write side is what keeps a stream from getting
//! there.
//!
//! ## The property
//!
//! For every **artifact-stream append** in production Rust under
//! `crates/*/src`, the function containing it either
//!
//! 1. calls `refuse_append_past_cap` (or its `…_at_version` sibling) —
//!    the single definition of the predicate, in
//!    `hort-app/src/use_cases/mod.rs` — or
//! 2. carries a [`ONCE_ONLY_MARKER`] line stating why the append cannot
//!    accumulate: a genesis append on a stream minted in the same call,
//!    an append gated by its own output already being on the stream, or a
//!    terminal event after which the stream takes nothing further.
//!
//! Anything else fails. There is **no allow-list**: a site that should
//! carry neither is a review conversation, not an entry someone can add.
//!
//! ### Why "repeatable" is the whole criterion
//!
//! A once-per-artifact writer cannot reach 1 000 events no matter how
//! many of them exist — the census that produced this guard found eight,
//! and their combined contribution to one stream is a handful of events.
//! A *repeatable* writer can: a sweep that ticks, a rescan that records,
//! an API verb with no idempotency of its own. So the rule is not "every
//! append refuses" but "every append that can run again refuses", and the
//! declaration is how the once-only sites say which they are — in a form
//! the next reader of that function sees without reconstructing the
//! census.
//!
//! ### Why the refusal has to be in the appending function
//!
//! Deliberately not transitive: a refusal one call away is a refusal the
//! reader of the append cannot see, and a helper that refuses on its
//! caller's behalf is exactly how the retry hazard returns — the refusal
//! is a `DomainError::Conflict` that re-reading can never clear, so a
//! conflict-retry loop wrapped around it spends its whole budget. A site
//! that genuinely wants the refusal in a helper reads as a violation
//! here, which is the same false positive `cas_reads_are_verified` takes
//! for the same reason: a review conversation about where the check
//! belongs.
//!
//! ## What counts as an artifact-stream append, and how it is derived
//!
//! Nothing here is a hand-kept list of call sites. Two derivations:
//!
//! - **Every method declared on `ArtifactLifecyclePort`** is an
//!   artifact-stream append by the port's own contract: each one takes an
//!   `&Artifact` and an `AppendEvents`, and
//!   `require_paired_artifact_stream` refuses the pair unless the batch
//!   targets that artifact's stream (pinned by the
//!   `lifecycle_pairs_are_checked` guard). The method names are read out
//!   of the `trait` block, so adding a sixth commit method extends this
//!   guard's corpus without anyone editing it.
//! - **Every other append entry point that takes an `AppendEvents`** —
//!   `EventStore::append`, the adapter's `append_in_tx`, and the port
//!   methods whose signatures mention the type (`complete_artifact_purge`
//!   is the one that matters, because the terminal `ArtifactPurged` batch
//!   reaches the store through it rather than through an append call) —
//!   is classified from the batch it is handed. The batch must be an
//!   `AppendEvents` literal this function builds; its `stream_id`
//!   resolves to `StreamId::artifact(`, a `StreamCategory::Artifact`
//!   literal, or an `ArtifactAtVersion`'s `.stream_id()` to count.
//!
//! A call handed a batch it did not build adds no policy and is out of
//! scope: whatever the caller assembled is what applies, and that caller
//! is covered by this guard in its own right. This is the same forwarding
//! rule `capped_stream_reads` applies to a delegated `max_count`, and it
//! is what keeps the `EventStorePublisher` decorator, the shared
//! `append_any_with_conflict_retry`, and each adapter's
//! persist-what-you-were-given method out of the corpus — along with
//! every unrelated `Vec::append` / `HeaderMap::append` in the tree.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! A `stream_id` that reaches the appending function as a **parameter** is
//! unclassifiable, so such a site is treated as in-corpus (fail-closed:
//! it must refuse or declare). The one site like that today is
//! `RetentionUseCase::append_expired`, and
//! [`the_refusal_is_called_where_the_census_says_it_is`] pins it by name
//! so deleting its refusal fails this test even though the classifier
//! cannot see which stream it writes.
//!
//! The usual source-scan limits apply: a call assembled through a macro
//! is invisible, a `stream_id` built from fragments across statements
//! resolves to nothing, and a batch built in one function and appended in
//! another reads as forwarding at the append and as nothing at the
//! builder. The `ONCE-ONLY-APPEND:` declarations are read from the raw
//! source (comments are blanked for the structural pass, so the marker is
//! looked for in the original bytes over the same span) — which means a
//! declaration is exactly as trustworthy as the sentence someone wrote
//! next to it. That is the point: it is reviewable, not machine-checkable.
//!
//! ## Counter-assertions
//!
//! Three, because a source-scan guard's usual death is silent vacuity:
//! [`the_scan_still_finds_every_known_append_site`] pins the census
//! per file, [`the_refusal_is_called_where_the_census_says_it_is`] pins
//! the refusal's definition and its call sites, and
//! [`stripping_a_refusal_or_a_declaration_fails_the_scan`] removes each
//! from real on-disk source and asserts the classifier goes red.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as `capped_stream_reads`,
//! `lifecycle_pairs_are_checked` and `cas_reads_are_verified`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    block_end, call_args, is_ident_byte, production_region, split_args, walk_rust, workspace_root,
    FnItem,
};

/// The single definition of the cap's write-side predicate. Matched as a
/// prefix so `refuse_append_past_cap_at_version` — the entry point for a
/// site whose only observation of the stream is the `ExpectedVersion` a
/// capped read derived — counts too.
const CAP_REFUSAL: &str = "refuse_append_past_cap";

/// Where the predicate and the cap are defined. Excluded from the append
/// scan: it declares the helpers rather than appending anything.
const REFUSAL_DEFINITION_FILE: &str = "crates/hort-app/src/use_cases/mod.rs";

/// How a once-only append site declares itself. Followed by the reason, in
/// a comment inside the appending function.
const ONCE_ONLY_MARKER: &str = "ONCE-ONLY-APPEND:";

/// The port whose every method is an artifact-stream append by contract.
const LIFECYCLE_PORT_FILE: &str = "crates/hort-domain/src/ports/artifact_lifecycle.rs";

/// The `trait` whose method names are read out of that file. Matched as
/// `trait <name>` and then the block it opens, so a change to the trait's
/// own supertrait bounds or visibility does not silently empty the corpus.
const LIFECYCLE_PORT_TRAIT: &str = "trait ArtifactLifecyclePort";

/// Where the outbound port traits live — the directory whose
/// `AppendEvents`-taking methods form the rest of the corpus.
const PORTS_DIR: &str = "crates/hort-domain/src/ports";

/// The adapter-internal append used by every lifecycle implementation.
/// Not a port method, so it is named rather than derived.
const APPEND_IN_TX: &str = "append_in_tx";

/// The type a batch has to be a literal of to be classifiable.
const BATCH_LITERAL: &str = "AppendEvents";

/// The artifact-stream constructor.
const ARTIFACT_CTOR: &str = "StreamId::artifact(";

/// The artifact stream category, for the one site that builds a
/// `StreamId` literal rather than calling the constructor.
const ARTIFACT_CATEGORY: &str = "StreamCategory::Artifact";

/// `ArtifactAtVersion::stream_id` — the only `stream_id()` accessor in the
/// workspace, and an artifact stream by construction.
const PAIRING_ACCESSOR: &str = ".stream_id()";

/// Any other stream constructor: a positive statement that this append is
/// not about an artifact.
const STREAM_CTOR: &str = "StreamId::";

// ---------------------------------------------------------------------------
// The census this guard was written against
// ---------------------------------------------------------------------------

/// Every production artifact-stream append site the scan finds, by file.
///
/// A maintained number, exactly as `capped_stream_reads` maintains the
/// count of audited bounded reads: a new append path is expected to move
/// it, and moving it is a deliberate edit a reviewer sees. What it buys is
/// the thing a source-scan guard cannot otherwise have — proof that the
/// corpus is not empty. Rename the port, the methods or the batch type and
/// the main assertion below would pass over nothing at all.
const EXPECTED_SITES: &[(&str, usize)] = &[
    ("crates/hort-adapters-postgres/src/artifact_repo.rs", 1),
    (
        "crates/hort-app/src/use_cases/apply_config_use_case/curation.rs",
        1,
    ),
    ("crates/hort-app/src/use_cases/cas_scrub_use_case.rs", 2),
    ("crates/hort-app/src/use_cases/curation_use_case.rs", 4),
    ("crates/hort-app/src/use_cases/ingest_use_case.rs", 4),
    ("crates/hort-app/src/use_cases/policy_use_case.rs", 2),
    ("crates/hort-app/src/use_cases/promotion_use_case.rs", 7),
    ("crates/hort-app/src/use_cases/provenance_cascade.rs", 1),
    (
        "crates/hort-app/src/use_cases/provenance_misrejection_repair.rs",
        1,
    ),
    (
        "crates/hort-app/src/use_cases/provenance_orchestration.rs",
        2,
    ),
    ("crates/hort-app/src/use_cases/purge_use_case.rs", 1),
    // 5: `quarantine_artifact`, `commit_scan_result_dual_write`,
    // `release_expired`, `record_scan_indeterminate` and
    // `hold_for_unproduced_composition` — the last being the recoverable
    // hold a scan takes when the manifest's composition was never
    // produced inside the attempt budget. Repeatable like
    // `quarantine_artifact` beside it: the sweep or a curator can release
    // the artifact and a later exhausted composite scan reaches it again.
    ("crates/hort-app/src/use_cases/quarantine_use_case.rs", 5),
    ("crates/hort-app/src/use_cases/retention_use_case.rs", 1),
];

/// Every production file that calls the refusal, and how many calls it
/// makes.
///
/// The second counter-assertion, and the one that closes this guard's
/// named blind spot: `retention_use_case::append_expired` takes its
/// `StreamId` as a parameter, so the classifier cannot prove it writes an
/// artifact stream — but it is listed here, so deleting its refusal turns
/// this test red regardless.
const EXPECTED_REFUSAL_CALLS: &[(&str, usize)] = &[
    (
        "crates/hort-app/src/use_cases/apply_config_use_case/curation.rs",
        1,
    ),
    ("crates/hort-app/src/use_cases/cas_scrub_use_case.rs", 1),
    ("crates/hort-app/src/use_cases/curation_use_case.rs", 4),
    ("crates/hort-app/src/use_cases/policy_use_case.rs", 2),
    ("crates/hort-app/src/use_cases/promotion_use_case.rs", 4),
    (
        "crates/hort-app/src/use_cases/provenance_misrejection_repair.rs",
        1,
    ),
    (
        "crates/hort-app/src/use_cases/provenance_orchestration.rs",
        1,
    ),
    ("crates/hort-app/src/use_cases/quarantine_use_case.rs", 5),
    ("crates/hort-app/src/use_cases/retention_use_case.rs", 1),
];

// ---------------------------------------------------------------------------
// Source enumeration
// ---------------------------------------------------------------------------

/// Every `crates/<crate>/src/**/*.rs` that is production code, sorted so
/// failures are stable.
///
/// Test code is dropped by filename (`*_tests.rs`, `test_support.rs`,
/// `tests.rs` — the inline-module files this workspace uses) on top of the
/// per-item `#[cfg(test)]` blanking every file goes through: a fixture that
/// seeds a thousand events legitimately appends without refusing, and a
/// guard that argued with it would be arguing about test data.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(crates) = fs::read_dir(root.join("crates")) else {
        panic!("crates/ must exist under the workspace root");
    };
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.retain(|path| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        !(name.ends_with("_tests.rs") || name == "test_support.rs" || name == "tests.rs")
    });
    out.sort();
    out
}

/// The workspace-relative, forward-slashed path of `path`.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// The derived method sets
// ---------------------------------------------------------------------------

/// The append entry points, derived rather than enumerated.
struct AppendMethods {
    /// Declared on `ArtifactLifecyclePort`: an artifact-stream append by
    /// contract, so a call needs no batch inference at all.
    lifecycle: BTreeSet<String>,
    /// Every other method that takes an `AppendEvents`, plus
    /// `EventStore::append` and the adapter's `append_in_tx`. A call is in
    /// the corpus only if the batch it is handed resolves to an artifact
    /// stream.
    batch_taking: BTreeSet<String>,
}

/// The `fn` names declared directly inside `trait <name> … { … }`.
fn trait_method_names(source: &str, trait_header: &str) -> BTreeSet<String> {
    let region = production_region(source);
    let Some(at) = region.find(trait_header) else {
        return BTreeSet::new();
    };
    let Some(brace) = region[at..].find('{').map(|offset| at + offset) else {
        return BTreeSet::new();
    };
    let Some(close) = block_end(region.as_bytes(), brace) else {
        return BTreeSet::new();
    };
    rust_scan::parse_fns(&region[brace..close])
        .into_iter()
        .map(|item| item.name)
        .collect()
}

/// Resolve the append entry points from the port definitions themselves.
fn append_methods(root: &Path) -> AppendMethods {
    let lifecycle_source = fs::read_to_string(root.join(LIFECYCLE_PORT_FILE))
        .expect("the artifact-lifecycle port file is readable UTF-8");
    let lifecycle = trait_method_names(&lifecycle_source, LIFECYCLE_PORT_TRAIT);

    let mut batch_taking: BTreeSet<String> = BTreeSet::new();
    batch_taking.insert(APPEND_IN_TX.to_owned());
    let ports = root.join(PORTS_DIR);
    let mut port_files = Vec::new();
    walk_rust(&ports, &mut |path| port_files.push(path.to_path_buf()));
    port_files.sort();
    for path in port_files {
        let source = fs::read_to_string(&path).expect("port source is readable UTF-8");
        let region = production_region(&source);
        for item in rust_scan::parse_fns(&region) {
            let signature = signature_of(&region, &item);
            if signature.contains(BATCH_LITERAL) && !lifecycle.contains(&item.name) {
                batch_taking.insert(item.name);
            }
        }
    }
    AppendMethods {
        lifecycle,
        batch_taking,
    }
}

/// The text from the `fn` keyword up to the body's opening brace, or to
/// the `;` of a bodiless declaration.
///
/// Walked forward rather than derived from the span, because a trait
/// method signature — which is exactly what the port files are made of —
/// has no body and so spans nothing at all.
fn signature_of(text: &str, item: &FnItem) -> String {
    let (start, _) = item.span;
    let bytes = text.as_bytes();
    let mut parens = 0usize;
    let mut brackets = 0usize;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        match byte {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'{' | b';' if parens == 0 && brackets == 0 => {
                return text[start..offset].to_owned();
            }
            _ => {}
        }
    }
    text[start..].to_owned()
}

// ---------------------------------------------------------------------------
// Stream classification
// ---------------------------------------------------------------------------

/// What a batch's `stream_id` expression resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    /// Provably an artifact stream.
    Artifact,
    /// Provably some other stream category.
    Other,
    /// The expression could not be followed. Treated as in-corpus:
    /// fail-closed is the only safe reading when the guard cannot tell.
    Unresolved,
}

/// Strip the wrappers that do not change which stream an expression names.
fn peel(expr: &str) -> String {
    let mut text = expr.trim();
    loop {
        let before = text;
        text = text.trim();
        text = text.trim_start_matches('&');
        text = text.trim_start_matches("mut ");
        if let Some(stripped) = text.strip_suffix(".clone()") {
            text = stripped;
        }
        if text == before {
            break;
        }
    }
    text.to_owned()
}

/// The `let <name> = <expr>;` initialiser for `name` inside `body`, if the
/// function binds it.
fn local_binding(body: &str, name: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let mut search = 0usize;
    while let Some(found) = body[search..].find("let ") {
        let at = search + found;
        search = at + 4;
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        let rest = &body[at + 4..];
        let rest = rest
            .trim_start()
            .strip_prefix("mut ")
            .unwrap_or(rest.trim_start());
        let ident_len = rest.bytes().take_while(|byte| is_ident_byte(*byte)).count();
        if &rest[..ident_len] != name {
            continue;
        }
        // Skip an optional type ascription, then take everything up to the
        // statement's `;` at depth zero.
        let after = &rest[ident_len..];
        let Some(eq) = after.find('=') else { continue };
        let value = &after[eq + 1..];
        let mut depth = 0i32;
        for (index, byte) in value.bytes().enumerate() {
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b';' if depth == 0 => return Some(value[..index].to_owned()),
                _ => {}
            }
        }
        return Some(value.to_owned());
    }
    None
}

/// The last path segment of a call expression — `TaskUseCase::foo(x)` and
/// `Self::foo(x)` and `foo(x)` all answer `foo`.
fn called_fn_name(expr: &str) -> Option<String> {
    let open = expr.find('(')?;
    let path = &expr[..open];
    let name = path.rsplit("::").next()?.trim();
    if name.is_empty() || !name.bytes().all(is_ident_byte) {
        return None;
    }
    Some(name.to_owned())
}

/// Classify a batch's `stream_id` expression.
///
/// `helpers` maps the name of every production `fn … -> StreamId` to its
/// body, which is what lets a shared constructor helper
/// (`TaskUseCase::task_audit_stream`) resolve instead of reading as
/// unknown. `depth` bounds the `let`-chain walk.
fn classify_stream(
    expr: &str,
    fn_body: &str,
    helpers: &BTreeMap<String, String>,
    depth: usize,
) -> StreamKind {
    if depth == 0 {
        return StreamKind::Unresolved;
    }
    let text = peel(expr);
    if text.contains(ARTIFACT_CTOR) || text.contains(ARTIFACT_CATEGORY) {
        return StreamKind::Artifact;
    }
    if text.ends_with(PAIRING_ACCESSOR) {
        return StreamKind::Artifact;
    }
    if text.contains(STREAM_CTOR) {
        return StreamKind::Other;
    }
    if let Some(name) = called_fn_name(&text) {
        if let Some(body) = helpers.get(&name) {
            return classify_stream(body, fn_body, helpers, depth - 1);
        }
        return StreamKind::Unresolved;
    }
    if text.bytes().all(is_ident_byte) && !text.is_empty() {
        if let Some(value) = local_binding(fn_body, &text) {
            return classify_stream(&value, fn_body, helpers, depth - 1);
        }
    }
    StreamKind::Unresolved
}

/// Every production `fn <name>(…) -> StreamId`, by name, with its body.
///
/// Derived, not listed: there is exactly one such helper in the workspace
/// today, and the index is how a second one resolves without anyone
/// editing this guard. A `-> &StreamId` accessor is deliberately excluded —
/// the one of those is `ArtifactAtVersion::stream_id`, which
/// [`PAIRING_ACCESSOR`] answers for directly.
fn stream_helpers(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for path in production_sources(root) {
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let region = production_region(&source);
        for item in rust_scan::parse_fns(&region) {
            let signature = signature_of(&region, &item);
            if signature.contains("-> StreamId") && !item.body.is_empty() {
                out.insert(item.name.clone(), item.body.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Batch resolution
// ---------------------------------------------------------------------------

/// Split a struct literal's field list on top-level commas. Braces count
/// here (a field value may be another struct literal), which is why this
/// is not [`split_args`]'s job.
fn split_fields(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in body.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_owned());
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    out
}

/// The `stream_id` field expression of the first `AppendEvents { … }`
/// literal in `text`, or `None` when `text` holds no such literal.
///
/// Field shorthand (`stream_id,`) answers the identifier itself, which the
/// classifier then resolves against the function's own bindings — the idiom
/// almost every call site in this workspace uses.
fn batch_stream_expr(text: &str) -> Option<String> {
    let at = text.find(BATCH_LITERAL)?;
    let brace = text[at..].find('{')? + at;
    let close = block_end(text.as_bytes(), brace)?;
    for field in split_fields(&text[brace + 1..close]) {
        let (name, value) = match field.split_once(':') {
            Some((name, value)) => (name.trim(), value.trim().to_owned()),
            None => (field.trim(), field.trim().to_owned()),
        };
        if name == "stream_id" {
            return Some(value);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Per-file analysis
// ---------------------------------------------------------------------------

/// One artifact-stream append site, as `<fn>@<line>`.
///
/// Carried rather than just counted so a census that moves names the
/// sites it found — a bare count tells a reviewer that the corpus
/// changed and nothing about which path appeared or vanished.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site(String);

/// What the scan made of one file.
struct FileReport {
    sites: Vec<Site>,
    violations: Vec<String>,
}

/// The innermost parsed `fn` whose span contains `offset`.
fn enclosing(items: &[FnItem], offset: usize) -> Option<&FnItem> {
    items
        .iter()
        .filter(|item| item.span.0 <= offset && offset < item.span.1)
        .max_by_key(|item| item.span.0)
}

/// Every offset in `region` at which `.<name>(` appears.
fn method_call_offsets(region: &str, name: &str) -> Vec<usize> {
    let needle = format!(".{name}(");
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(found) = region[search..].find(&needle) {
        let at = search + found;
        search = at + 1;
        out.push(at);
    }
    out
}

/// Analyse one production file.
fn analyse(
    rel: &str,
    source: &str,
    methods: &AppendMethods,
    helpers: &BTreeMap<String, String>,
) -> FileReport {
    let region = production_region(source);
    let items = rust_scan::parse_fns(&region);
    let mut sites = Vec::new();
    let mut violations = Vec::new();

    let mut offsets: Vec<(usize, bool)> = Vec::new();
    for name in &methods.lifecycle {
        // A lifecycle commit is an artifact-stream append by contract, so
        // the batch is not inspected: a forwarder that hands the batch on
        // to the port is still the call that commits it.
        offsets.extend(
            method_call_offsets(&region, name)
                .into_iter()
                .map(|at| (at, true)),
        );
    }
    for name in &methods.batch_taking {
        offsets.extend(
            method_call_offsets(&region, name)
                .into_iter()
                .map(|at| (at, false)),
        );
    }
    offsets.sort_unstable();

    for (at, by_contract) in offsets {
        let Some(item) = enclosing(&items, at) else {
            continue;
        };
        if !by_contract {
            // Resolve the batch this call was handed. No literal in this
            // function ⇒ forwarding ⇒ out of scope.
            let open = region[at..]
                .find('(')
                .map(|offset| at + offset)
                .unwrap_or(at);
            let Some(args) = call_args(&region, open) else {
                continue;
            };
            // An inline literal first, read off the whole (balanced)
            // argument text: `split_args` does not track braces, so a
            // literal's own field commas would otherwise shred it.
            let literal = batch_stream_expr(&args).or_else(|| {
                // Otherwise the batch is a name this function bound. Here
                // the arguments carry no braces, so splitting them is
                // sound.
                split_args(&args).iter().find_map(|arg| {
                    let name = peel(arg);
                    if name.is_empty() || !name.bytes().all(is_ident_byte) {
                        return None;
                    }
                    local_binding(&item.body, &name).and_then(|value| batch_stream_expr(&value))
                })
            });
            let Some(stream_expr) = literal else {
                continue;
            };
            if classify_stream(&stream_expr, &item.body, helpers, 8) == StreamKind::Other {
                continue;
            }
        }

        let line = rust_scan::line_of(&region, at);
        let refuses = item.body.contains(CAP_REFUSAL);
        // The declaration lives in a comment, which the structural pass
        // blanked — so it is read from the raw source over the same span.
        // Both passes of `production_region` preserve byte offsets, which
        // is what makes the span transferable.
        let (start, end) = item.span;
        let declares = source
            .get(start..end)
            .is_some_and(|raw| raw.contains(ONCE_ONLY_MARKER));

        if !refuses && !declares {
            violations.push(format!(
                "{rel}:{line} — `{}` appends to an artifact stream and neither refuses \
                 before the cap nor declares itself once-only. Either call \
                 `{CAP_REFUSAL}(…)` with the length this function's own observation of the \
                 stream saw and the number of events the batch carries, or — if the path \
                 genuinely cannot run twice on one artifact — say why in a \
                 `{ONCE_ONLY_MARKER} …` comment in this function. A repeatable append with \
                 no refusal takes the stream past the cap, and past the cap every capped \
                 reader refuses it, so the artifact can never be released, re-scanned or \
                 re-evaluated again",
                item.name
            ));
        }
        sites.push(Site(format!("{}@{line}", item.name)));
    }

    FileReport { sites, violations }
}

/// The whole tree, analysed once.
fn scan(root: &Path) -> (BTreeMap<String, Vec<Site>>, Vec<String>) {
    let methods = append_methods(root);
    let helpers = stream_helpers(root);
    let mut census: BTreeMap<String, Vec<Site>> = BTreeMap::new();
    let mut violations = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        if rel == REFUSAL_DEFINITION_FILE || rel == LIFECYCLE_PORT_FILE {
            // The first defines the predicate and the cap; the second
            // defines the port, three of whose default method bodies
            // forward to a sibling. Declaring either is not appending.
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let report = analyse(&rel, &source, &methods, &helpers);
        violations.extend(report.violations);
        if !report.sites.is_empty() {
            census.insert(rel, report.sites);
        }
    }
    (census, violations)
}

// ---------------------------------------------------------------------------
// The assertions
// ---------------------------------------------------------------------------

#[test]
fn every_artifact_stream_append_refuses_or_declares_once_only() {
    let root = workspace_root();
    let (_, violations) = scan(&root);
    assert!(
        violations.is_empty(),
        "artifact-stream appends with neither a cap refusal nor a once-only declaration \
         ({} found):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

#[test]
fn the_scan_still_finds_every_known_append_site() {
    let root = workspace_root();
    let (census, _) = scan(&root);
    let found: Vec<(String, usize)> = census
        .iter()
        .map(|(file, sites)| (file.clone(), sites.len()))
        .collect();
    let expected: Vec<(String, usize)> = EXPECTED_SITES
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    let detail: Vec<String> = census
        .iter()
        .map(|(file, sites)| {
            let names: Vec<&str> = sites.iter().map(|site| site.0.as_str()).collect();
            format!("{file}: {}", names.join(", "))
        })
        .collect();
    assert_eq!(
        found,
        expected,
        "the artifact-stream append census moved. Every entry is a production append path \
         this guard is responsible for, so a change here is expected whenever one is added, \
         removed or relocated — update `EXPECTED_SITES` deliberately. What this assertion \
         exists to catch is the other case: a census that SHRANK because the scan stopped \
         seeing sites (a renamed port method, a changed batch type, a stream expression it \
         can no longer follow), which would leave the main assertion green over nothing.\n\
         found:\n  {}",
        detail.join("\n  ")
    );

    // The three derivations the census rests on, pinned by name. Each one
    // silently empties the corpus if it breaks.
    let methods = append_methods(&root);
    assert!(
        methods.lifecycle.contains("commit_transition")
            && methods.lifecycle.contains("commit_scan_result_with_score")
            && methods.lifecycle.contains("commit_provenance_verdict"),
        "the `ArtifactLifecyclePort` trait block no longer yields its commit methods, so \
         every call to one is now invisible to this guard; found {:?}",
        methods.lifecycle
    );
    assert!(
        methods.batch_taking.contains("append")
            && methods.batch_taking.contains(APPEND_IN_TX)
            && methods.batch_taking.contains("complete_artifact_purge"),
        "the `AppendEvents`-taking port methods no longer resolve — `complete_artifact_purge` \
         in particular, which is how the terminal `ArtifactPurged` batch reaches the store; \
         found {:?}",
        methods.batch_taking
    );
    let helpers = stream_helpers(&root);
    assert!(
        helpers.contains_key("task_audit_stream"),
        "the `fn … -> StreamId` helper index is empty, so a shared stream constructor now \
         reads as unclassifiable and its call sites would be reported as artifact appends"
    );
}

#[test]
fn the_refusal_is_called_where_the_census_says_it_is() {
    let root = workspace_root();

    // The predicate and its version-shaped sibling are defined exactly
    // once, in the file that owns the cap.
    let definition = fs::read_to_string(root.join(REFUSAL_DEFINITION_FILE))
        .expect("the use-case module is readable UTF-8");
    let definition = production_region(&definition);
    assert_eq!(
        definition.matches(&format!("fn {CAP_REFUSAL}(")).count(),
        1,
        "`{CAP_REFUSAL}` must be defined exactly once in {REFUSAL_DEFINITION_FILE}"
    );
    assert_eq!(
        definition
            .matches(&format!("fn {CAP_REFUSAL}_at_version("))
            .count(),
        1,
        "`{CAP_REFUSAL}_at_version` must be defined exactly once in \
         {REFUSAL_DEFINITION_FILE}"
    );
    assert!(
        definition.contains("STREAM_EVENT_CAP: u64") && definition.contains("> STREAM_EVENT_CAP"),
        "the cap and the one comparison against it both live in \
         {REFUSAL_DEFINITION_FILE}; a second copy of the number anywhere is the \
         duplication both halves of this guard exist to prevent"
    );

    // And it is called where the census says. This is what closes the
    // named blind spot: `retention_use_case::append_expired` takes its
    // `StreamId` as a parameter, so the append scan cannot classify it,
    // but it is listed here.
    let mut found: Vec<(String, usize)> = Vec::new();
    for path in production_sources(&root) {
        let rel = relative(&root, &path);
        if rel == REFUSAL_DEFINITION_FILE {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let region = production_region(&source);
        let count = region.matches(&format!("{CAP_REFUSAL}(")).count()
            + region
                .matches(&format!("{CAP_REFUSAL}_at_version("))
                .count();
        if count > 0 {
            found.push((rel, count));
        }
    }
    found.sort();
    let expected: Vec<(String, usize)> = EXPECTED_REFUSAL_CALLS
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        found, expected,
        "the set of files calling the cap refusal moved. Update \
         `EXPECTED_REFUSAL_CALLS` deliberately when an append path is added or removed; a \
         file DISAPPEARING from it is a refusal that was deleted — including from \
         `retention_use_case`, whose site the append scan itself cannot see.\n\
         found: {found:#?}"
    );

    // The accessor `.stream_id()` classification rests on, and the length
    // reader every paired site passes to the refusal.
    assert!(
        definition.contains("fn stream_id(&self) -> &StreamId")
            && definition.contains("fn stream_len(&self) -> u64"),
        "`ArtifactAtVersion` must still expose both halves of one observation: the stream \
         id (which is what makes `{PAIRING_ACCESSOR}` provably an artifact stream) and the \
         length the refusal is asked about"
    );
}

/// The mutation counter-assertion: strip the thing the guard looks for and
/// the guard must go red.
///
/// Run over **real on-disk source** rather than a hand-written fixture, in
/// both directions. Over a clean tree the classifier and a broken
/// classifier agree on the verdict and differ only in what they read, so
/// nothing else here can tell them apart.
#[test]
fn stripping_a_refusal_or_a_declaration_fails_the_scan() {
    let root = workspace_root();
    let methods = append_methods(&root);
    let helpers = stream_helpers(&root);

    // A corrected site: remove the refusal call and the site must report.
    let refusing = "crates/hort-app/src/use_cases/promotion_use_case.rs";
    let source = fs::read_to_string(root.join(refusing)).expect("readable UTF-8");
    let clean = analyse(refusing, &source, &methods, &helpers);
    assert!(
        clean.violations.is_empty(),
        "{refusing} must be clean before it is mutated: {:?}",
        clean.violations
    );
    assert!(
        !clean.sites.is_empty(),
        "{refusing} must contribute append sites for this mutation to prove anything"
    );
    let stripped = source.replace(CAP_REFUSAL, "assume_room_for");
    let mutated = analyse(refusing, &stripped, &methods, &helpers);
    assert_eq!(
        mutated.violations.len(),
        clean.sites.len(),
        "every append site in {refusing} must report once its refusal is gone — if it does \
         not, the scan is not reading the refusal it claims to check"
    );

    // A declared site: remove the marker and the site must report.
    let declaring = "crates/hort-app/src/use_cases/purge_use_case.rs";
    let source = fs::read_to_string(root.join(declaring)).expect("readable UTF-8");
    let clean = analyse(declaring, &source, &methods, &helpers);
    assert!(
        clean.violations.is_empty(),
        "{declaring} must be clean before it is mutated: {:?}",
        clean.violations
    );
    assert_eq!(
        clean.sites.len(),
        1,
        "{declaring} holds the one terminal `ArtifactPurged` append"
    );
    let stripped = source.replace(ONCE_ONLY_MARKER, "once only append");
    let mutated = analyse(declaring, &stripped, &methods, &helpers);
    assert_eq!(
        mutated.violations.len(),
        1,
        "the terminal purge append must report once its once-only declaration is gone — if \
         it does not, a declaration is not what this guard is reading"
    );
}
