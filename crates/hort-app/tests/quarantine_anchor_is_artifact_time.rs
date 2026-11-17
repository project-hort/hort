//! Structural guard: **a quarantine window anchor is the artifact's own
//! time evidence, never a wall-clock reading taken at the moment of the
//! hold.**
//!
//! ## The invariant
//!
//! A quarantine window begins at the point hort can prove the artifact was
//! already published — it is the period in which the artifact is known to
//! the public and can be checked. So the anchor is a property of **the
//! artifact**, not of the run that happens to look at it, and it therefore
//! cannot renew. ADR 0054 implements exactly that as a minimum over
//! evidence (the mint instant, first-seen, a clamped trusted upstream
//! publish time, an explicit override): the earliest instant hort can
//! prove.
//!
//! Nothing in the design renews a window. What a wall-clock fallback does
//! is renew one: the stored anchor is absent for an artifact that never
//! had a window — the permissive-ingest population, downloadable under
//! `quarantineDuration: 0` — the fallback reaches for the clock, and
//! because the fallback is taken again on every pass the observable effect
//! is a window that restarts each tick. An artifact that has been serving
//! for months then answers `503` for a full `quarantineDuration`, over and
//! over.
//!
//! ## Why convention did not hold it
//!
//! Measured: `Artifact`'s three methods that re-enter the hold —
//! `supersede_absent_verdict`, `re_evaluate`'s re-quarantine arm and
//! `repair_provenance_misrejection` — all carried
//! `self.quarantine_window_start.unwrap_or(now)`, and **two of the three
//! documented the correct rule in a comment directly above the line that
//! broke it** ("the observation window is unchanged, not restarted"; "the
//! observation window is restored, not restarted"). Both comments are true
//! of the `Some` branch and were false of the fallback. Meanwhile the
//! sibling site written for the same population,
//! `QuarantineUseCase::hold_for_unproduced_composition`, took
//! `paired.artifact().created_at` and said why. One population, two
//! contradictory anchors, and a comment is not a check.
//!
//! Replacing the clock with `created_at` closed the renewal, and left a
//! **second rule for deciding an anchor** standing beside
//! `derive_quarantine_anchor`: `created_at` is the derivation's own
//! `minted_at` evidence, so a fallback that reaches for it outside the
//! derivation is the same decision taken twice, in two places, with only
//! one of them reading the rest of the evidence. All three methods now
//! take a `DerivedAnchor` and stamp
//! `DerivedAnchor::re_entry_anchor(self.quarantine_window_start)` —
//! `min(existing window, derived anchor)`, which generalises "an existing
//! window is kept" because ADR 0054's evidence moves an anchor earlier and
//! never later.
//!
//! ## What the scan asks, and of which expressions
//!
//! Over `crates/*/src` production code, two kinds of site decide an
//! anchor, and the scan reads the **expression** at each:
//!
//! * an argument to [`ANCHOR_SETTER`] / [`ANCHOR_SETTER_UFCS`] —
//!   `Artifact::quarantine` is the only writer of the entity's
//!   `quarantine_window_start` from outside the entity, and its parameter
//!   *is* the anchor;
//! * an assignment or struct-literal initialiser of [`ANCHOR_FIELD`] —
//!   which reaches both the entity's own field and the
//!   `ArtifactQuarantined` event that carries the anchor to every reader.
//!
//! An expression is rejected when it **is or derives from** a clock read
//! ([`CLOCK_READS`]) — including through a local `let` binding in the same
//! function, resolved to a fixed point, which is the reach
//! `db_tests_are_serialized` already demonstrates for helper chains. That
//! reach is the one that matters here: all three defect sites read their
//! anchor out of a local binding (`let anchor = …;`) rather than inline,
//! and all three still do.
//!
//! ## Why the scope is derived rather than exempted
//!
//! There is **no allow-list**, and none is needed, because the scope falls
//! out of structure rather than a table:
//!
//! * **Type declarations are not expressions.** A site inside a `struct`
//!   item body or inside a `fn` signature is a `NAME: TYPE` declaration —
//!   seven of them across the workspace, all `Option<DateTime<Utc>>`-shaped
//!   — and declaring the field's type decides no anchor. Excluding them
//!   keeps the census readable; it cannot hide a violation, since a type is
//!   not a clock read.
//! * **`#[cfg(test)]` items** are blanked by
//!   [`rust_scan::production_region`], so an inline test fixture stamping
//!   `Utc::now()` is out of scope because of how it is compiled, not
//!   because of an entry here.
//! * **`src/**/*_tests.rs` and `src/**/tests.rs`** are inline test modules
//!   the workspace includes behind a `#[cfg(test)]` in a sibling, so no
//!   attribute appears inside the file itself.
//!   [`every_skipped_test_file_is_really_compiled_out`] checks that pairing
//!   rather than taking the filename's word for it.
//! * **`test_support.rs`** is skipped, and this is the one judgement call
//!   in the scope. The sibling guard `condemning_rule_is_single_sourced`
//!   deliberately *includes* it, because that file is gated
//!   `#[cfg(any(test, feature = "test-support"))]` and a *rule* re-derived
//!   there would be a rule shipped. This guard is not about a rule being
//!   re-derived; it is about which instant a **hold** is taken on. A
//!   fixture builder takes no hold — its whole job is to hand back an
//!   artifact already in an arbitrary state, so the instant it stamps is
//!   test data. [`every_test_support_file_is_dev_only`] pins the half that
//!   makes that safe: every crate enabling the `test-support` feature does
//!   so from `[dev-dependencies]`, so no shipped binary compiles these
//!   files.
//!
//! ## Where a clock reading IS the anchor, and why the predicate still fits
//!
//! The two ingest sites pass an anchor that ultimately derives from a
//! clock: `derive_quarantine_anchor(&AnchorEvidence { minted_at: now, … })`.
//! That is correct and is not a hole. At **mint** the clock reading is the
//! artifact's ingest instant — it is evidence about the artifact, because
//! the artifact is coming into existence at that moment — and ADR 0054's
//! other evidence only ever moves the anchor *earlier* than it. The
//! predicate fits without an exemption because at both sites `now` arrives
//! as a **function parameter**, which the scan does not follow: the rule it
//! enforces is precisely *"no anchor expression may read a clock in the
//! function that decides it"*, and an anchor assembled from declared
//! evidence does not.
//!
//! The paired half of that, and the reason the parameter boundary is a
//! close rather than a gap: **the type closes it.** The three methods
//! that re-enter the hold take a
//! [`DerivedAnchor`](hort_domain::policy::DerivedAnchor), whose anchor is
//! a private field, so the only way to obtain one is to call
//! `derive_quarantine_anchor` over declared
//! [`AnchorEvidence`](hort_domain::policy::AnchorEvidence). A caller
//! cannot hand any of them a bare instant, which is what a scan over
//! expressions structurally cannot see — a clock arriving through an
//! argument is invisible to it, and handing a `DateTime<Utc>` parameter
//! back would be a silent reversal no guard here could catch.
//! `re_evaluate` keeps `now` for its deadline comparison and that is now
//! harmless: `now` has no route to the anchor, because the anchor comes
//! out of a type `now` cannot build.
//!
//! The companion guard on the assembly side is
//! `anchor_evidence_is_assembled_once`, which holds that `AnchorEvidence`
//! is built at exactly two places. Together: one rule, two assembly
//! sites, one type out, and this scan as defence-in-depth behind all
//! three.
//!
//! ## Counter-assertions
//!
//! Four, because a source scan usually dies by going quietly vacuous:
//!
//! * [`the_scan_still_finds_every_artifact_quarantine_call`] — the four
//!   production `Artifact::quarantine` calls, by file, function and
//!   argument.
//! * [`the_scan_still_finds_every_domain_anchor_write`] — every anchor
//!   write in the entity, which pins all three methods that re-enter the
//!   hold plus `quarantine` itself.
//! * [`the_scan_reads_a_real_corpus`] — a per-file site census, so a
//!   renamed field or method cannot empty the scan silently.
//! * [`re_introducing_a_clock_read_fails_the_scan`] — a mutation over
//!   **real on-disk source**, not a planted fixture: put `Utc::now()` back
//!   where it was and watch six sites report, every one of them reached
//!   only through the local binding.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! * **An anchor assembled through a macro** is invisible, as in every
//!   sibling guard.
//! * **An anchor reached through a helper in another file** is not
//!   followed. `db_tests_are_serialized` has the same limit, and for the
//!   same reason: a cross-file call graph is `syn`'s job, not a byte scan's.
//! * **An anchor arriving as a function parameter or a struct field**
//!   (`ctx.now`) is not followed either. For the ingest path that is the
//!   right answer (above); for a future method it is a real gap, and the
//!   thing that closes it is not widening this scan but declining to
//!   accept an instant at all — which is what the `DerivedAnchor`
//!   parameter type does for the three methods that re-enter the hold.
//! * **A `quarantine_window_start` shorthand struct initialiser** is read
//!   as the local binding of the same name it is, so it is covered only
//!   when that `let` is in the same function.
//! * **A clock read spelled other than [`CLOCK_READS`]** — an aliased
//!   import, `SystemTime::now()`, an injected clock port — is not matched.
//!   The two spellings pinned here are the two the workspace uses.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as `capped_stream_writes`,
//! `cas_reads_are_verified` and `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    block_end, call_args, is_ident_byte, line_of, parse_fns, production_region, skip_ws,
    split_args, walk_rust, workspace_root, FnItem,
};

/// The method call that hands `Artifact` its observation-window anchor.
/// `Artifact::quarantine` is the only writer of the entity's anchor from
/// outside the entity, so its one argument *is* the anchor.
const ANCHOR_SETTER: &str = ".quarantine(";

/// The same call spelled as an associated function, where the anchor is
/// the second argument because the receiver is the first.
const ANCHOR_SETTER_UFCS: &str = "Artifact::quarantine(";

/// The field that stores the anchor, on the entity and on the
/// `ArtifactQuarantined` event alike.
const ANCHOR_FIELD: &str = "quarantine_window_start";

/// The clock reads an anchor may not be or derive from. Pinned as the
/// `Type::now` prefix so `chrono::Utc::now()` is the same hit;
/// `Utc.timestamp_opt(0, 0)` deliberately is not one, being a fixed
/// instant rather than a reading.
const CLOCK_READS: [&str; 2] = ["Utc::now", "Local::now"];

/// How an anchor expression reached its site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SiteKind {
    /// An argument to `Artifact::quarantine`.
    QuarantineCall,
    /// `… = EXPR;` — the entity's field, or a local named after it.
    Assignment,
    /// `… : EXPR,` inside a struct literal — the event's field.
    FieldInit,
}

impl SiteKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::QuarantineCall => "quarantine-call",
            Self::Assignment => "assignment",
            Self::FieldInit => "field-init",
        }
    }
}

/// What the anchor expression at a site is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Evidence about the artifact: its stored window, its `created_at`,
    /// a forwarded parameter, a pass-through of the same field.
    ArtifactTime,
    /// A clock read, directly or through a local binding in the same
    /// function.
    WallClock,
}

/// One anchor-deciding expression in production source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    /// Workspace-relative path, forward slashes.
    rel: String,
    /// 1-based line of the site.
    line: usize,
    /// The innermost enclosing `fn`, or `<item>` outside one.
    func: String,
    kind: SiteKind,
    /// The anchor expression, whitespace-collapsed.
    expr: String,
    verdict: Verdict,
}

/// Collapse whitespace so an expression rustfmt wrapped across lines reads
/// as one string.
fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// True when `needle` sits at `at` as a whole token — neither side
/// continuing an identifier.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return false;
    }
    let after = at + needle.len();
    after >= bytes.len() || !is_ident_byte(bytes[after])
}

/// Every offset at which `needle` appears in `text` as a whole token.
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

/// True when `expr` reads a clock: a [`CLOCK_READS`] prefix on a token
/// boundary, followed by a call's `(`.
///
/// The trailing `(` is what keeps a type path or a function item mention
/// from counting, and the leading token boundary is what stops
/// `Utc::nowhere` reading as one.
fn reads_a_clock(expr: &str) -> bool {
    let bytes = expr.as_bytes();
    CLOCK_READS.iter().any(|clock| {
        let mut from = 0usize;
        while let Some(found) = expr[from..].find(clock) {
            let at = from + found;
            from = at + clock.len();
            if at > 0 && is_ident_byte(bytes[at - 1]) {
                continue;
            }
            if bytes.get(skip_ws(bytes, at + clock.len())) == Some(&b'(') {
                return true;
            }
        }
        false
    })
}

/// The end of the expression starting at `from`, stopping at the first
/// `terminators` byte at nesting depth zero.
///
/// Depth counts `(`, `[` and `{` only. Angle brackets are deliberately not
/// counted — `a > b` would unbalance them — and a generic argument list
/// carries no terminator of its own, so leaving them uncounted is free.
/// The `{` of a nested `match` or struct literal is what keeps an
/// initialiser like `let a = match s { … };` running to its real `;`.
fn expression_end(bytes: &[u8], from: usize, terminators: &[u8]) -> usize {
    let mut depth = 0i32;
    for (at, byte) in bytes.iter().enumerate().skip(from) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            _ => {}
        }
        if depth == 0 && terminators.contains(byte) {
            return at;
        }
    }
    bytes.len()
}

/// Every `let` binding in a function body, as `(name, initialiser)`.
///
/// Only simple `let NAME [: TYPE] = EXPR;` bindings are returned. A
/// destructuring `let` (`let (a, b) = …`, `let Some(x) = …`) is skipped:
/// its binding names are not resolvable by a byte scan, and that is a
/// documented blind spot rather than a silent one — every anchor binding
/// in the workspace is simple.
fn local_bindings(body: &str) -> Vec<(String, String)> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    for at in token_offsets(body, "let") {
        let mut cursor = skip_ws(bytes, at + "let".len());
        // `let mut x` — step over the modifier.
        if body[cursor..].starts_with("mut") && is_token(bytes, cursor, "mut") {
            cursor = skip_ws(bytes, cursor + "mut".len());
        }
        let name_start = cursor;
        while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            continue;
        }
        let name = body[name_start..cursor].to_string();
        let mut eq = skip_ws(bytes, cursor);
        // `let x: Type = …` — skip the annotation to the `=` that follows
        // it. A `;` first means a declaration with no initialiser.
        if bytes.get(eq) == Some(&b':') {
            let stop = expression_end(bytes, eq + 1, b"=;");
            if bytes.get(stop) != Some(&b'=') {
                continue;
            }
            eq = stop;
        }
        // Anything else here is a pattern (`(`, `{`) or a `let`-else, not
        // a simple binding.
        if bytes.get(eq) != Some(&b'=') {
            continue;
        }
        let init_start = eq + 1;
        let init_end = expression_end(bytes, init_start, b";");
        out.push((name, normalise(&body[init_start..init_end])));
    }
    out
}

/// Every identifier token in `expr`.
fn identifiers(expr: &str) -> BTreeSet<String> {
    let bytes = expr.as_bytes();
    let mut out = BTreeSet::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if !is_ident_byte(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && is_ident_byte(bytes[at]) {
            at += 1;
        }
        out.insert(expr[start..at].to_string());
    }
    out
}

/// The names of a function's local bindings that are or derive from a
/// clock read, to a fixed point: a binding that reads a clock, a binding
/// initialised from such a binding, and so on.
fn clock_bound_locals(body: &str) -> BTreeSet<String> {
    let bindings = local_bindings(body);
    let mut bound: BTreeSet<String> = BTreeSet::new();
    loop {
        let mut grew = false;
        for (name, init) in &bindings {
            if bound.contains(name) {
                continue;
            }
            if reads_a_clock(init) || identifiers(init).iter().any(|id| bound.contains(id)) {
                bound.insert(name.clone());
                grew = true;
            }
        }
        if !grew {
            return bound;
        }
    }
}

/// `ArtifactTime` unless the expression reads a clock itself or names a
/// local binding that does.
fn classify(expr: &str, clock_locals: &BTreeSet<String>) -> Verdict {
    if reads_a_clock(expr) || identifiers(expr).iter().any(|id| clock_locals.contains(id)) {
        Verdict::WallClock
    } else {
        Verdict::ArtifactTime
    }
}

/// The `[start, end)` byte ranges of every `struct` item body in `text`.
///
/// A site inside one is a `NAME: TYPE` field declaration, not an anchor
/// expression. Tuple structs (`struct S(T);`) carry no named field and so
/// contribute no range.
fn struct_declaration_bodies(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for at in token_offsets(text, "struct") {
        let mut cursor = at + "struct".len();
        while cursor < bytes.len() && !matches!(bytes[cursor], b'{' | b'(' | b';') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'{') {
            continue;
        }
        if let Some(close) = block_end(bytes, cursor) {
            out.push((cursor, close));
        }
    }
    out
}

/// The `[start, end)` byte ranges of every `fn` signature in `items` — a
/// site inside one is a parameter declaration.
fn signature_ranges(items: &[FnItem]) -> Vec<(usize, usize)> {
    items
        .iter()
        .map(|item| (item.span.0, item.span.0 + item.signature.len()))
        .collect()
}

/// The innermost `fn` whose body contains `offset`.
fn enclosing_fn(items: &[FnItem], offset: usize) -> Option<&FnItem> {
    items
        .iter()
        .filter(|item| item.span.0 <= offset && offset < item.span.1)
        .max_by_key(|item| item.span.0)
}

/// Every anchor-deciding site in one production file.
fn anchor_sites(rel: &str, source: &str) -> Vec<Site> {
    let text = production_region(source);
    let bytes = text.as_bytes();
    let items = parse_fns(&text);
    let signatures = signature_ranges(&items);
    let declarations = struct_declaration_bodies(&text);
    let in_declaration = |offset: usize| {
        declarations
            .iter()
            .chain(signatures.iter())
            .any(|(start, end)| *start <= offset && offset <= *end)
    };

    // Resolved lazily per function, since most functions hold no site.
    let mut locals_cache: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut raw: Vec<(usize, SiteKind, String)> = Vec::new();

    // `Artifact::quarantine` calls, in both spellings. The anchor is the
    // only argument of the method form and the second of the associated
    // form, whose first argument is the receiver.
    for (needle, anchor_index) in [(ANCHOR_SETTER, 0usize), (ANCHOR_SETTER_UFCS, 1usize)] {
        let mut from = 0usize;
        while let Some(found) = text[from..].find(needle) {
            let at = from + found;
            from = at + needle.len();
            let open = at + needle.len() - 1;
            let Some(args) = call_args(&text, open) else {
                continue;
            };
            let args = split_args(&args);
            let Some(anchor) = args.get(anchor_index) else {
                continue;
            };
            raw.push((at, SiteKind::QuarantineCall, normalise(anchor)));
        }
    }

    // Writes of the anchor field, on the entity and on the event.
    for at in token_offsets(&text, ANCHOR_FIELD) {
        if in_declaration(at) {
            continue;
        }
        let after = skip_ws(bytes, at + ANCHOR_FIELD.len());
        let (kind, expr_start, terminators): (SiteKind, usize, &[u8]) = match bytes.get(after) {
            // `… = EXPR;`, and not the `==` of a comparison.
            Some(&b'=') if bytes.get(after + 1) != Some(&b'=') => {
                (SiteKind::Assignment, after + 1, b";")
            }
            // `… : EXPR,` in a struct literal, and not a `::` path.
            Some(&b':') if bytes.get(after + 1) != Some(&b':') => {
                (SiteKind::FieldInit, after + 1, b",}")
            }
            // A read (`self.quarantine_window_start.unwrap_or(…)`), or a
            // shorthand initialiser, which is the local binding of the
            // same name and is reported as that binding's `let`.
            _ => continue,
        };
        let end = expression_end(bytes, expr_start, terminators);
        raw.push((at, kind, normalise(&text[expr_start..end])));
    }

    raw.sort();
    raw.into_iter()
        .map(|(at, kind, expr)| {
            let item = enclosing_fn(&items, at);
            let clock_locals = match item {
                Some(item) => locals_cache
                    .entry(item.span.0)
                    .or_insert_with(|| clock_bound_locals(&item.body)),
                None => locals_cache.entry(usize::MAX).or_default(),
            };
            Site {
                rel: rel.to_string(),
                line: line_of(&text, at),
                func: item.map_or_else(|| "<item>".to_string(), |item| item.name.clone()),
                kind,
                verdict: classify(&expr, clock_locals),
                expr,
            }
        })
        .collect()
}

/// True for an inline test module the workspace includes behind a
/// `#[cfg(test)]` in a sibling, so no attribute appears inside the file
/// itself. [`every_skipped_test_file_is_really_compiled_out`] checks the
/// pairing rather than taking the name's word for it.
fn is_inline_test_module(rel: &str) -> bool {
    rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

/// True for a fixture builder — see the module doc on why this one is
/// skipped where `condemning_rule_is_single_sourced` includes it.
fn is_test_support(rel: &str) -> bool {
    rel.ends_with("/test_support.rs")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `crates/*/src/**/*.rs`, sorted so failures are stable. Test
/// modules and fixture builders are dropped here; `#[cfg(test)]` items
/// inside the rest are dropped by [`production_region`].
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(root.join("crates")).expect("crates/ exists under the root");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.retain(|path| {
        let rel = relative(root, path);
        !is_inline_test_module(&rel) && !is_test_support(&rel)
    });
    out.sort();
    out
}

/// Scan the production tree.
fn scan(root: &Path) -> Vec<Site> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        out.extend(anchor_sites(&rel, &source));
    }
    out
}

fn describe(site: &Site) -> String {
    format!(
        "{}:{} — {} in `{}`: `{}`",
        site.rel,
        site.line,
        site.kind.as_str(),
        site.func,
        site.expr
    )
}

#[test]
fn every_quarantine_anchor_is_the_artifacts_own_time() {
    let violations: Vec<String> = scan(&workspace_root())
        .iter()
        .filter(|site| site.verdict == Verdict::WallClock)
        .map(describe)
        .collect();

    assert!(
        violations.is_empty(),
        "a quarantine window anchor must be the artifact's own time evidence — its \
         existing window, or its ingest instant (`created_at`) when it has none — and \
         never a wall-clock reading taken at the moment of the hold. A quarantine \
         begins where hort can prove the artifact was already published, so the anchor \
         is a property of the artifact and cannot renew; a clock fallback renews it on \
         every pass, and an artifact that has been serving for months then answers 503 \
         for a full `quarantineDuration`, tick after tick. If the anchor genuinely is \
         the mint instant, assemble it from declared evidence through \
         `derive_quarantine_anchor(&AnchorEvidence {{ .. }})` (ADR 0054) rather than \
         reading the clock where the hold is taken. There is no allow-list; a site \
         that genuinely must read a clock is a review conversation. {} site(s) \
         below:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions — the scan's own reach.
// ---------------------------------------------------------------------------

/// The four production `Artifact::quarantine` calls, by file, function and
/// argument. A fifth is not a reason to edit this list on the way past:
/// read its anchor against the invariant above first, then add it.
#[test]
fn the_scan_still_finds_every_artifact_quarantine_call() {
    let calls: Vec<(String, String, String)> = scan(&workspace_root())
        .into_iter()
        .filter(|site| site.kind == SiteKind::QuarantineCall)
        .map(|site| (site.rel, site.func, site.expr))
        .collect();

    assert_eq!(
        calls,
        vec![
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                "decide_and_apply_quarantine".to_string(),
                "anchor".to_string(),
            ),
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                "apply_register_gate".to_string(),
                "anchor".to_string(),
            ),
            (
                "crates/hort-app/src/use_cases/quarantine_use_case.rs".to_string(),
                "quarantine_artifact".to_string(),
                "window_start".to_string(),
            ),
            (
                "crates/hort-app/src/use_cases/quarantine_use_case.rs".to_string(),
                "hold_for_unproduced_composition".to_string(),
                "window_start".to_string(),
            ),
        ],
        "`Artifact::quarantine` is the only writer of the entity's anchor from outside \
         the entity, so these four calls are half this guard's corpus. An empty or \
         shrunken list means the method, the entity or the scan's matcher was renamed \
         and the main assertion is answering about less than it claims"
    );
}

/// Every anchor write inside the entity. This is the counter-assertion
/// that pins all **three** methods which re-enter the hold — the three
/// that carried `unwrap_or(now)` — beside `quarantine` itself, which takes
/// its anchor as a parameter and is the one the four calls above feed.
#[test]
fn the_scan_still_finds_every_domain_anchor_write() {
    let root = workspace_root();
    let rel = "crates/hort-domain/src/entities/artifact.rs";
    let source = fs::read_to_string(root.join(rel)).expect("the entity is readable UTF-8");
    let writes: Vec<(String, &str, String)> = anchor_sites(rel, &source)
        .into_iter()
        .map(|site| (site.func, site.kind.as_str(), site.expr))
        .collect();

    assert_eq!(
        writes,
        vec![
            (
                "quarantine".to_string(),
                "assignment",
                "Some(window_start)".to_string()
            ),
            (
                "quarantine".to_string(),
                "field-init",
                "window_start".to_string()
            ),
            (
                "supersede_absent_verdict".to_string(),
                "assignment",
                "Some(anchor)".to_string()
            ),
            (
                "supersede_absent_verdict".to_string(),
                "field-init",
                "anchor".to_string()
            ),
            (
                "re_evaluate".to_string(),
                "assignment",
                "Some(anchor)".to_string()
            ),
            (
                "re_evaluate".to_string(),
                "field-init",
                "anchor".to_string()
            ),
            (
                "repair_provenance_misrejection".to_string(),
                "assignment",
                "Some(anchor)".to_string()
            ),
            (
                "repair_provenance_misrejection".to_string(),
                "field-init",
                "anchor".to_string()
            ),
        ],
        "the entity's anchor writes are the sites the defect lived at. \
         `supersede_absent_verdict`, `re_evaluate` and \
         `repair_provenance_misrejection` each re-enter the hold, and each must stamp \
         `DerivedAnchor::re_entry_anchor` over the window the artifact already \
         carries — never a clock, and never a second rule of its own. Each writes the \
         anchor twice, on the row and on the event, because a `Quarantined` row with a \
         NULL anchor is invisible to the release-candidacy query and a row whose \
         anchor disagrees with the event that announced it describes a window no \
         reader can confirm. If this list has shrunk, the scan stopped reading one of \
         them"
    );
}

/// A per-file census, so a renamed field or a broken matcher cannot leave
/// the main assertion green over an empty corpus.
#[test]
fn the_scan_reads_a_real_corpus() {
    let sites = scan(&workspace_root());
    assert!(
        !sites.is_empty(),
        "the scan found no anchor site anywhere under crates/*/src — it is answering \
         about an empty corpus, so its green verdict means nothing"
    );

    let mut census: BTreeMap<String, usize> = BTreeMap::new();
    for site in &sites {
        *census.entry(site.rel.clone()).or_default() += 1;
    }
    let census: Vec<(String, usize)> = census.into_iter().collect();

    assert_eq!(
        census,
        vec![
            (
                "crates/hort-adapters-postgres/src/curation_queue_repository.rs".to_string(),
                1
            ),
            (
                "crates/hort-adapters-postgres/src/mappers.rs".to_string(),
                1
            ),
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                5
            ),
            (
                "crates/hort-app/src/use_cases/provenance_orchestration.rs".to_string(),
                1
            ),
            (
                "crates/hort-app/src/use_cases/quarantine_use_case.rs".to_string(),
                2
            ),
            ("crates/hort-domain/src/entities/artifact.rs".to_string(), 8),
            (
                "crates/hort-domain/src/retention/held_state_entry.rs".to_string(),
                1
            ),
            (
                "crates/hort-http-core/src/handlers/admin/curation/queue.rs".to_string(),
                1
            ),
        ],
        "the per-file census is what makes the main assertion's green verdict mean \
         something. A file dropping out means the scan stopped reading it; a new file \
         appearing means a new anchor decision that a human should read against the \
         invariant before this list is updated"
    );
}

/// The mutation counter-assertion: put the defect back into **real
/// on-disk source** and the scan must go red.
///
/// Over a clean tree the classifier and a broken classifier agree on the
/// verdict and differ only in what they read, so nothing else here can
/// tell them apart. One substitution exercises both halves of the
/// predicate at once, which is why it is the one chosen: the composed
/// stamp appears three times in the entity, once per method that
/// re-enters the hold, and each time as the initialiser of the `let
/// anchor` that method's two anchor writes read. So **all six** reports
/// are reached only through the local binding — if any is missing, the
/// scan is not following a binding and the defect's actual shape would
/// pass it.
///
/// The substituted expression is the `Option` the composition takes, not
/// the whole call: a clock reading smuggled in as "the window the
/// artifact already carries" is precisely the shape the retired
/// `unwrap_or(now)` fallback had, and `min(now, derived)` would still
/// pick the derived anchor, so the *defect* here is the clock reaching
/// the expression at all rather than the value it produces.
#[test]
fn re_introducing_a_clock_read_fails_the_scan() {
    let root = workspace_root();
    let rel = "crates/hort-domain/src/entities/artifact.rs";
    let source = fs::read_to_string(root.join(rel)).expect("the entity is readable UTF-8");

    let clean = anchor_sites(rel, &source);
    assert!(
        clean
            .iter()
            .all(|site| site.verdict == Verdict::ArtifactTime),
        "the entity must be clean before it is mutated: {:?}",
        clean
            .iter()
            .filter(|site| site.verdict == Verdict::WallClock)
            .map(describe)
            .collect::<Vec<_>>()
    );

    let composed = "derived.re_entry_anchor(self.quarantine_window_start)";
    assert_eq!(
        source.matches(composed).count(),
        3,
        "the mutation substitutes the re-entry composition, so the entity must still \
         spell it the way this test does — once per method that re-enters the hold, as \
         the initialiser of that method's `let anchor`"
    );
    let mutated = source.replace(composed, "derived.re_entry_anchor(Some(Utc::now()))");

    let reported: Vec<(String, SiteKind)> = anchor_sites(rel, &mutated)
        .into_iter()
        .filter(|site| site.verdict == Verdict::WallClock)
        .map(|site| (site.func, site.kind))
        .collect();

    assert_eq!(
        reported,
        vec![
            ("supersede_absent_verdict".to_string(), SiteKind::Assignment),
            ("supersede_absent_verdict".to_string(), SiteKind::FieldInit),
            ("re_evaluate".to_string(), SiteKind::Assignment),
            ("re_evaluate".to_string(), SiteKind::FieldInit),
            (
                "repair_provenance_misrejection".to_string(),
                SiteKind::Assignment
            ),
            (
                "repair_provenance_misrejection".to_string(),
                SiteKind::FieldInit
            ),
        ],
        "re-introducing the clock read must report all six sites, every one of them \
         reached ONLY through the `let anchor` binding. A short list means the scan \
         stopped following a local binding, which is the one reach the defect's actual \
         shape needed"
    );
}

/// The test-code exclusion is derived, not conventional: every
/// `src/**/*_tests.rs` and `src/**/tests.rs` the scan skips is declared
/// behind a `#[cfg(test)]` in a sibling module, so skipping it cannot hide
/// production code. One compiled into the binary would be exactly that.
#[test]
fn every_skipped_test_file_is_really_compiled_out() {
    let root = workspace_root();
    let mut scanned = Vec::new();
    let entries = fs::read_dir(root.join("crates")).expect("crates/ exists under the root");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| scanned.push(path.to_path_buf()));
        }
    }

    let mut unexplained: Vec<String> = Vec::new();
    for path in &scanned {
        let rel = relative(&root, path);
        if !is_inline_test_module(&rel) {
            continue;
        }
        let file_name = path
            .file_name()
            .expect("a scanned path has a file name")
            .to_string_lossy()
            .to_string();
        let stem = file_name.trim_end_matches(".rs").to_string();
        let declared_test_only = scanned.iter().any(|sibling| {
            if sibling.parent() != path.parent() || sibling == path {
                return false;
            }
            let Ok(source) = fs::read_to_string(sibling) else {
                return false;
            };
            // Read raw, not through `production_region`: the declaration
            // being blanked as a `#[cfg(test)]` item is exactly the thing
            // being looked for, and it is checked as the attribute run it
            // is written as. Both forms the workspace uses — a `#[path]`
            // override and a plain `mod <stem>;`.
            for declaration in [format!("#[path = \"{file_name}\"]"), format!("mod {stem};")] {
                if source.contains(&format!("#[cfg(test)]\n{declaration}"))
                    || source.contains(&format!("{declaration}\n#[cfg(test)]"))
                {
                    return true;
                }
            }
            false
        });
        if !declared_test_only {
            unexplained.push(rel);
        }
    }
    unexplained.sort();

    assert!(
        unexplained.is_empty(),
        "every test file the scan skips by name must be declared `#[cfg(test)]` by a \
         sibling module, or the skip is hiding production code rather than test code. \
         {} unexplained:\n  {}",
        unexplained.len(),
        unexplained.join("\n  ")
    );
}

/// The other half of the scope, pinned the same way: `test_support.rs` is
/// skipped because no shipped binary compiles it. Every crate that enables
/// the `test-support` feature does so from `[dev-dependencies]`, so the
/// fixture builders are test code in every build that exists.
///
/// A lexical check of the manifests, not a resolved feature graph — the
/// guard has no cargo-metadata dependency, in keeping with its siblings.
/// It reads the table headings in file order and asks which one an
/// enablement sits under, which is exactly how the manifests are written;
/// a `[features]` entry that re-exported the feature under another name
/// would slip past it, and that would be a review conversation about this
/// scope rather than a silent change.
#[test]
fn every_test_support_file_is_dev_only() {
    let root = workspace_root();
    let mut offenders: Vec<String> = Vec::new();
    let entries = fs::read_dir(root.join("crates")).expect("crates/ exists under the root");
    for entry in entries.flatten() {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(source) = fs::read_to_string(&manifest) else {
            continue;
        };
        // The dependency tables, in file order: an enablement counts as
        // dev-only when the nearest preceding table heading is a
        // dev-dependencies one.
        let mut dev_only = false;
        for line in source.lines() {
            // A trailing comment is not an enablement, so it comes off
            // before the line is read.
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.starts_with('[') {
                dev_only = trimmed.contains("dev-dependencies");
                continue;
            }
            if !trimmed.contains("\"test-support\"") {
                continue;
            }
            // The feature's own declaration (`test-support = [...]`) is
            // not an enablement of it.
            if trimmed.starts_with("test-support") {
                continue;
            }
            if !dev_only {
                offenders.push(format!("{}: {trimmed}", relative(&root, &manifest)));
            }
        }
    }
    offenders.sort();

    assert!(
        offenders.is_empty(),
        "the scan skips `src/**/test_support.rs` on the grounds that no shipped binary \
         compiles it. A non-dev dependency enabling the `test-support` feature breaks \
         that, and the fixture builders' anchors would then be production anchors. {} \
         enablement(s) outside `[dev-dependencies]`:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's own behaviour.
// ---------------------------------------------------------------------------

/// The verdict at each site of a planted source fragment, in file order.
fn verdicts(planted: &str) -> Vec<Verdict> {
    anchor_sites("planted.rs", planted)
        .iter()
        .map(|site| site.verdict)
        .collect()
}

/// The same, carrying how each site was reached — for the checks that are
/// about the matcher classifying the *shape* and not only the expression.
fn shapes(planted: &str) -> Vec<(SiteKind, Verdict)> {
    anchor_sites("planted.rs", planted)
        .iter()
        .map(|site| (site.kind, site.verdict))
        .collect()
}

/// The baseline: without it, every trip-wire below could be passing for
/// the wrong reason.
#[test]
fn the_scanner_accepts_the_artifacts_own_time() {
    let planted = "fn supersede(&mut self) -> Event {\n    \
                   let anchor = self.quarantine_window_start.unwrap_or(self.created_at);\n    \
                   self.quarantine_window_start = Some(anchor);\n    \
                   Event { quarantine_window_start: anchor }\n}";
    let sites = anchor_sites("planted.rs", planted);
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites.iter().all(|s| s.verdict == Verdict::ArtifactTime));
}

#[test]
fn the_scanner_trips_on_an_inline_clock_read() {
    let planted = "fn supersede(&mut self) -> Event {\n    \
                   Event { quarantine_window_start: self.quarantine_window_start.unwrap_or(Utc::now()) }\n}";
    assert_eq!(
        shapes(planted),
        vec![(SiteKind::FieldInit, Verdict::WallClock)]
    );
}

/// The reach that matters: the defect's actual shape read its anchor out
/// of a local binding, so a scan that only looked at the site's own text
/// would have stayed green over all three sites.
#[test]
fn the_scanner_follows_a_local_binding_to_the_clock() {
    let planted = "fn supersede(&mut self) -> Event {\n    \
                   let anchor = self.quarantine_window_start.unwrap_or(Utc::now());\n    \
                   self.quarantine_window_start = Some(anchor);\n    \
                   Event { quarantine_window_start: anchor }\n}";
    let sites = anchor_sites("planted.rs", planted);
    assert_eq!(sites.len(), 2);
    assert!(
        sites.iter().all(|s| s.verdict == Verdict::WallClock),
        "{sites:?}"
    );
}

/// A binding chain, to a fixed point — one hop is not enough.
#[test]
fn the_scanner_follows_a_binding_chain() {
    let planted = "fn hold(&mut self) -> Event {\n    \
                   let observed = Utc::now();\n    \
                   let fallback = observed;\n    \
                   let anchor = self.quarantine_window_start.unwrap_or(fallback);\n    \
                   self.quarantine_window_start = Some(anchor);\n}";
    assert_eq!(verdicts(planted), vec![Verdict::WallClock]);
}

/// A binding declared with a type annotation is still a binding.
#[test]
fn the_scanner_follows_an_annotated_binding() {
    let planted = "fn hold(&mut self) -> Event {\n    \
                   let observed: DateTime<Utc> = Utc::now();\n    \
                   self.quarantine_window_start = Some(observed);\n}";
    assert_eq!(verdicts(planted), vec![Verdict::WallClock]);
}

/// The call half, through a binding, in both spellings of the call.
#[test]
fn the_scanner_reads_the_quarantine_call_in_both_spellings() {
    let method = "fn hold(&self) {\n    let anchor = Utc::now();\n    \
                  artifact.quarantine(anchor)?;\n}";
    assert_eq!(
        shapes(method),
        vec![(SiteKind::QuarantineCall, Verdict::WallClock)]
    );

    // The receiver is the first argument, so the anchor is the second.
    let ufcs = "fn hold(&self) {\n    \
                Artifact::quarantine(&mut artifact, Utc::now())?;\n}";
    assert_eq!(
        shapes(ufcs),
        vec![(SiteKind::QuarantineCall, Verdict::WallClock)]
    );
}

/// `quarantine_artifact` is not `quarantine`: the matcher requires the
/// call's `(` immediately after the method name.
#[test]
fn the_scanner_does_not_read_the_call_out_of_a_longer_name() {
    let planted = "fn hold(&self) {\n    let anchor = Utc::now();\n    \
                   uc.quarantine_artifact(id, anchor, actor).await?;\n}";
    assert!(
        anchor_sites("planted.rs", planted).is_empty(),
        "only `Artifact::quarantine` writes the entity's anchor; the use case \
         forwards to it and is read at that call instead"
    );
}

/// The anchor the ingest path uses: assembled from declared evidence,
/// with the clock reading arriving as a parameter the scan does not
/// follow. This is the shape the module doc argues is correct, and it
/// must not report.
#[test]
fn the_scanner_accepts_an_anchor_derived_from_declared_evidence() {
    let planted = "fn decide_and_apply_quarantine(&self, now: DateTime<Utc>) {\n    \
                   let derived = derive_quarantine_anchor(&AnchorEvidence {\n        \
                   minted_at: now,\n        \
                   first_seen_at,\n    \
                   });\n    \
                   let anchor = derived.anchor;\n    \
                   artifact.quarantine(anchor)?;\n}";
    assert_eq!(verdicts(planted), vec![Verdict::ArtifactTime]);
}

/// A fixed instant built through `Utc` is not a clock reading — the
/// matcher pins `Utc::now`, not the type.
#[test]
fn the_scanner_does_not_read_a_fixed_instant_as_a_clock() {
    let planted = "fn seed(&mut self) -> Event {\n    \
                   Event { quarantine_window_start: Utc.timestamp_opt(0, 0).unwrap() }\n}";
    let sites = anchor_sites("planted.rs", planted);
    assert_eq!(
        sites.iter().map(|s| s.verdict).collect::<Vec<_>>(),
        vec![Verdict::ArtifactTime]
    );

    let epoch = "fn seed(&mut self) -> Event {\n    \
                 Event { quarantine_window_start: DateTime::<Utc>::UNIX_EPOCH }\n}";
    assert_eq!(verdicts(epoch), vec![Verdict::ArtifactTime]);
}

/// `Local::now()` is the other spelling, and is the same finding.
#[test]
fn the_scanner_reads_the_local_clock_too() {
    let planted = "fn hold(&mut self) {\n    \
                   self.quarantine_window_start = Some(Local::now().with_timezone(&Utc));\n}";
    assert_eq!(verdicts(planted), vec![Verdict::WallClock]);
}

/// Two of the three defect sites documented the correct rule in a comment
/// directly above the line that broke it, so a scan that read comments
/// would be satisfied by the prose and stay green after the fix was
/// reverted. Comments and literals are blanked before anything structural
/// is read.
#[test]
fn the_scanner_is_not_satisfied_by_a_comment_naming_the_rule() {
    let planted = "fn supersede(&mut self) -> Event {\n    \
                   // The original anchor — the observation window is restored,\n    \
                   // not restarted, and never `Utc::now()`.\n    \
                   let note = \"anchor is never Utc::now()\";\n    \
                   self.quarantine_window_start = Some(Utc::now());\n}";
    assert_eq!(
        verdicts(planted),
        vec![Verdict::WallClock],
        "a comment stating the rule must not discharge the line below it, and a \
         literal naming the clock must not read as one"
    );
}

/// A struct field declaration names a type, not an anchor. Seven of these
/// exist across the workspace; counting them would make the census
/// unreadable.
#[test]
fn the_scanner_ignores_a_field_declaration() {
    let planted = "pub struct ArtifactQuarantined {\n    \
                   pub artifact_id: Uuid,\n    \
                   pub quarantine_window_start: DateTime<Utc>,\n}";
    assert!(anchor_sites("planted.rs", planted).is_empty());
}

/// A function parameter is a declaration too — and the real one is a
/// `fn` whose body holds no site.
#[test]
fn the_scanner_ignores_a_parameter_declaration() {
    let planted = "fn row(id: Uuid, quarantine_window_start: Option<DateTime<Utc>>) -> Row {\n    \
                   Row { id }\n}";
    assert!(anchor_sites("planted.rs", planted).is_empty());
}

/// A read is not a write. `self.quarantine_window_start.unwrap_or(…)`
/// appears on the right of every corrected site, and the field name there
/// is followed by a `.`, not an `=` or a `:`.
#[test]
fn the_scanner_ignores_a_read_of_the_field() {
    let planted = "fn elapsed(&self, now: DateTime<Utc>) -> bool {\n    \
                   self.quarantine_window_start.is_some_and(|a| a <= now)\n}";
    assert!(anchor_sites("planted.rs", planted).is_empty());
}

/// A pass-through carries whatever its source held and decides nothing,
/// so it is a site with an `ArtifactTime` verdict rather than a
/// non-site — a clock read substituted there would still report.
#[test]
fn the_scanner_reads_a_pass_through_as_a_site() {
    let planted = "fn to_entry(&self) -> Entry {\n    \
                   Entry { quarantine_window_start: self.quarantine_window_start }\n}";
    assert_eq!(
        shapes(planted),
        vec![(SiteKind::FieldInit, Verdict::ArtifactTime)]
    );
}

/// A `#[cfg(test)]` fixture inside a production file is out of scope
/// because of how it is compiled.
#[test]
fn the_scanner_ignores_a_cfg_test_fixture() {
    let planted = "#[cfg(test)]\nmod tests {\n    \
                   fn seed() -> Event {\n        \
                   Event { quarantine_window_start: Utc::now() }\n    \
                   }\n}";
    assert!(anchor_sites("planted.rs", planted).is_empty());
}

/// Blanking must be per item: the adapter crates attach `#[cfg(test)]` to
/// struct fields and statements with production code after them, and a
/// truncating rule would blank the site below them — which in this guard
/// is a silent pass.
#[test]
fn the_scanner_keeps_production_code_after_a_cfg_test_item() {
    let planted = "#[cfg(test)]\nuse std::sync::atomic::AtomicBool;\n\n\
                   fn hold(&mut self) {\n    \
                   self.quarantine_window_start = Some(Utc::now());\n}";
    assert_eq!(verdicts(planted), vec![Verdict::WallClock]);
}

/// A `match` initialiser carries `{`, `,` and `}` inside it, so the
/// expression walk has to count depth or it stops at the first arm and
/// reads the clock out of none of them.
#[test]
fn the_scanner_reads_a_braced_initialiser_whole() {
    let planted = "fn seed(status: Status) -> Artifact {\n    \
                   let quarantine_window_start = match status {\n        \
                   Status::Quarantined => Some(Utc::now()),\n        \
                   _ => None,\n    \
                   };\n    \
                   Artifact { quarantine_window_start }\n}";
    assert_eq!(
        shapes(planted),
        vec![(SiteKind::Assignment, Verdict::WallClock)],
        "the shorthand initialiser below is the same binding and is reported as its \
         `let`, which is why it is not a second site"
    );
}

/// The innermost enclosing function owns the binding resolution: a nested
/// closure or `fn` must not inherit an outer `let` of the same name, nor
/// lose its own.
#[test]
fn the_scanner_resolves_bindings_in_the_innermost_function() {
    let planted = "fn outer() {\n    \
                   let anchor = Utc::now();\n    \
                   fn inner(&mut self, anchor: DateTime<Utc>) {\n        \
                   self.quarantine_window_start = Some(anchor);\n    \
                   }\n}";
    assert_eq!(
        anchor_sites("planted.rs", planted)
            .iter()
            .map(|s| (s.func.clone(), s.verdict))
            .collect::<Vec<_>>(),
        vec![("inner".to_string(), Verdict::ArtifactTime)],
        "`inner` takes its anchor as a parameter; the outer binding of the same name \
         is not in its scope"
    );
}

/// A destructuring `let` is not resolved, and the blind spot must be a
/// documented false *negative* rather than a crash or a false positive on
/// the sibling bindings.
#[test]
fn the_scanner_skips_a_destructuring_binding() {
    let planted = "fn hold(&mut self) {\n    \
                   let (anchor, _source) = (Utc::now(), Source::Mint);\n    \
                   self.quarantine_window_start = Some(anchor);\n}";
    assert_eq!(
        verdicts(planted),
        vec![Verdict::ArtifactTime],
        "a documented blind spot: a tuple pattern's names are not resolvable by a \
         byte scan, so this reads as artifact time"
    );
}
