//! Structural guard: **a deduplicated ingest success is built in exactly
//! one function**, `dedup_ok`, which runs the request's own upstream
//! comparison before the success exists.
//!
//! ## The invariant
//!
//! A same-path dedup hit returns `Ok` to a caller that may have declared
//! an upstream-published SHA-512 / SHA-1 digest, and
//! `ingest_with_verification` ticks
//! `hort_upstream_checksum_total{result=verified}` on that `Ok`. The bytes
//! already in CAS were verified against whatever digest the *first* ingest
//! declared, which says nothing about the algorithm or the value *this*
//! request declared, and ADR 0006 admits no operator opt-out and no
//! "already verified once, by someone else" clause. So the comparison runs
//! on the dedup path too: `dedup_ok` calls `verify_sha512_upstream` +
//! `verify_sha1_upstream` and only then builds the success tuple, which is
//! what makes a success carrying `was_duplicate = true` unable to exist
//! without the comparison having run (`48a09e69`).
//!
//! **Nothing held that.** The funnel is a shape two call sites happen to
//! use: a third dedup exit can hand-build the tuple, the comparison is
//! skipped again, and every test stays green — because the tests assert
//! the behaviour of the paths that exist rather than the shape of the ones
//! that could. The sibling guards in this directory all exist because the
//! same reasoning turned out to be optimistic: the `VerifyingReader` wrap
//! was hand-written at two sites with nothing holding it, ten capped-read
//! sites got the budget wrong, nine of them identically, and the serial
//! key was missing from 29 tests that fell through a crate-scoped wording.
//!
//! ## The property
//!
//! Inside a function whose signature names the success shape, every tuple
//! expression of that shape whose `was_duplicate` slot is **not** the
//! literal `false` sits inside `fn dedup_ok`.
//!
//! Three verdicts, and the third is the one that makes this fail closed:
//!
//! 1. **`false` in the flag slot** — a success that disclaims
//!    deduplication. It makes no claim about a comparison, so it is
//!    allowed anywhere; the fresh-insert tail of `ingest_inner` is this.
//! 2. **`true`** — a deduplicated success. Allowed only in [`FUNNEL`].
//! 3. **anything else** — an identifier, a call, a computed expression.
//!    The scan cannot evaluate it, so it cannot tell the tuple apart from
//!    a dedup success, and a dedup success whose provenance the reader
//!    cannot see is exactly the hazard. Allowed only in [`FUNNEL`] as
//!    well. A construction that genuinely cannot be a dedup hit can say so
//!    by writing the literal.
//!
//! ## Scoping: a function, inside a corpus derived from the shape
//!
//! **Function-scoped**, and that is load-bearing rather than fastidious.
//! The property is *which function the construction is in* — a file-scoped
//! scan would be discharged by `dedup_ok` merely existing in the same file
//! as a hand-built tuple, which is precisely the regression. So every
//! construction is attributed to the innermost enclosing function whose
//! signature names the shape, and the funnel's name is checked there.
//!
//! **The corpus is derived, not a path.** The scan walks every
//! `crates/*/src/**/*.rs`, keeps the files whose production code names
//! [`SUCCESS_ALIAS`], and reads the alias's own declaration for the tuple's
//! arity and for which slot carries the flag (the single `bool`). Nothing
//! in the predicate is a line number or a file name, so the guard survives
//! the function moving within its file, the file moving within the crate,
//! and a fifth element being added to the tuple. A signature that spells
//! the tuple out instead of naming the alias counts too — inside the file
//! that declares the alias, that is the natural way to route around a scan
//! keyed on the name.
//!
//! **There is no allow-list**, as with the siblings: no entry anyone can
//! add to make a finding go away. A construction that genuinely belongs
//! outside the funnel is a review conversation about whether the funnel
//! still means anything.
//!
//! ## Counter-assertion
//!
//! [`the_scan_still_finds_the_funnel_and_the_claim_it_builds`] pins the
//! corpus as real: the alias is declared exactly once, its shape still has
//! one `bool` slot (the premise that "the flag slot is the dedup claim"),
//! the candidate functions are exactly the four known ones, `dedup_ok`
//! still carries both comparison calls, both exits still route through it,
//! and the scan still finds the two constructions it is about.
//!
//! The division of labour between the two tests is worth being exact
//! about, because each covers a direction the other cannot. Renaming the
//! funnel does **not** go quiet: the construction is then attributed to a
//! function that is not `dedup_ok` and the main assertion reports it by
//! name. What the main assertion cannot see is a corpus that emptied — the
//! alias renamed, or the success shape ceasing to be a named tuple — and a
//! `dedup_ok` kept by name but hollowed of its comparisons, which leaves
//! the construction exactly where the main assertion wants it while the
//! property is gone. Those two are the counter-assertion's whole job.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! * **A pattern reads as a construction.** `Ok((artifact, dup, key, id))`
//!   is lexically identical in pattern and expression position, so a
//!   destructure of the success tuple *inside a candidate function* is
//!   reported as a construction. It is a false positive and correct to
//!   flag: the fix is to route the success whole rather than to take it
//!   apart and rebuild it. (`let (a, b, c, d) = …` is excluded — `let` is
//!   not a [`TUPLE_KEYWORDS`] entry — because a `let` destructure can
//!   never be a construction.) A tuple *type* written inside a body
//!   (`let ok: (Artifact, bool, String, Uuid) = …`) reads the same way and
//!   lands in verdict 3, its `bool` being no literal; the same answer
//!   applies, and the same fail-closed direction — the scan reports what
//!   it cannot read rather than assuming it is harmless.
//! * **The one every source scan has.** A construction assembled through a
//!   macro is invisible. So is one in a function whose signature names
//!   neither the alias nor the tuple — it would have to leave that function
//!   through some other type, and that type is the review conversation.
//! * A helper in **another crate** cannot be in the corpus unless it names
//!   the alias, which today is private to its file.
//!
//! The review check survives alongside the guard, exactly as it does for
//! `db_tests_are_serialized` and `cas_reads_are_verified`.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as `capped_stream_reads`,
//! `status_decode_fails_closed` and `cas_reads_are_verified`.

#![allow(clippy::expect_used)]

use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{blank_noncode, blank_range, is_ident_byte, line_of, walk_rust, workspace_root};

/// The type alias naming `ingest_inner`'s success shape. The subject of
/// the whole guard: the corpus is the files that name it, the arity and
/// the flag slot are read from its declaration. Renaming it turns the
/// counter-assertion red by design — the rename is exactly the moment to
/// re-read what a deduplicated success promises.
const SUCCESS_ALIAS: &str = "IngestInnerOk";

/// The one function allowed to build a deduplicated success.
const FUNNEL: &str = "dedup_ok";

/// The comparisons [`FUNNEL`] runs before the success exists. Pinned by
/// the counter-assertion: a funnel that no longer compares is a funnel
/// worth nothing, and this guard would still be green over it.
const COMPARISONS: [&str; 2] = ["verify_sha512_upstream", "verify_sha1_upstream"];

/// The element type of the `was_duplicate` slot, and so how the slot is
/// located in the declared shape rather than by index.
const FLAG_TYPE: &str = "bool";

/// The flag value that disclaims deduplication — a success that promises
/// nothing about a comparison.
const NOT_DEDUPLICATED: &str = "false";

/// The flag value that claims it.
const DEDUPLICATED: &str = "true";

/// The keywords a tuple expression may directly follow inside a function
/// body. Everything else ending in an identifier before a `(` is a call.
///
/// `let` is deliberately absent: `let (a, b, c, d) = …` is a destructure,
/// and a destructure cannot be a construction. `return` is the entry that
/// must never be dropped — `return (existing, true, key, id)` is the
/// plainest way to hand-build a dedup success.
const TUPLE_KEYWORDS: [&str; 5] = ["return", "break", "match", "in", "else"];

/// The attribute that opens an inline test module.
const CFG_TEST: &str = "#[cfg(test)]";

/// What a construction claims about deduplication, as far as the source
/// says.
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// The flag slot is the literal [`NOT_DEDUPLICATED`].
    Disclaimed,
    /// The flag slot is the literal [`DEDUPLICATED`].
    Deduplicated,
    /// The flag slot is an expression the scan cannot evaluate, carried
    /// verbatim for the failure message.
    Unproven(String),
}

/// One tuple expression of the success shape, and the function it is in.
#[derive(Debug, PartialEq, Eq)]
struct Construction {
    /// The innermost enclosing function whose signature names the shape.
    func: String,
    /// 1-based line of the tuple's opening paren.
    line: usize,
    claim: Claim,
}

/// Everything the scan reads out of one file's production text.
#[derive(Debug, PartialEq, Eq)]
struct FileScan {
    /// Functions whose signature names the success shape, in source order.
    candidates: Vec<String>,
    /// Constructions inside them.
    constructions: Vec<Construction>,
    /// `self.dedup_ok(` call sites: the funnel's reach.
    funnel_calls: usize,
}

/// A construction with the file it was found in.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    /// Workspace-relative path, forward slashes.
    rel: String,
    construction: Construction,
}

/// The whole scan, assembled so both tests read the same corpus once.
struct Scan {
    /// Corpus files, in path order.
    corpus: Vec<String>,
    /// Files declaring the alias. More than one is a finding in itself.
    declared_in: Vec<String>,
    /// The declared tuple's elements, from the first file declaring it.
    shape: Vec<String>,
    /// Candidate functions as `(file, fn name)`.
    candidates: Vec<(String, String)>,
    constructions: Vec<Found>,
    funnel_calls: usize,
    /// Files whose production region could not be determined — fail-closed,
    /// because a file the scan cannot read is a file it cannot police.
    unreadable: Vec<String>,
}

// ---------------------------------------------------------------------------
// Lexical helpers. The shared token-aware primitives live in `rust_scan`;
// what is here is this guard's own matcher, as with every sibling.
// ---------------------------------------------------------------------------

/// True when `needle` sits at `at` as a whole token.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return false;
    }
    let after = at + needle.len();
    after >= bytes.len() || !is_ident_byte(bytes[after])
}

/// True when `text` names `needle` as a whole token somewhere.
fn names_token(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(needle) {
        let at = from + found;
        from = at + needle.len();
        if is_token(bytes, at, needle) {
            return true;
        }
    }
    false
}

fn skip_space(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// The offset of the last non-whitespace byte before `at`.
fn before(bytes: &[u8], at: usize) -> Option<usize> {
    let mut cursor = at;
    while cursor > 0 {
        cursor -= 1;
        if !bytes[cursor].is_ascii_whitespace() {
            return Some(cursor);
        }
    }
    None
}

/// The identifier run ending at `at` inclusive.
fn word_ending_at(text: &str, at: usize) -> &str {
    let bytes = text.as_bytes();
    let mut start = at;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    &text[start..=at]
}

/// The offset of the `)` closing the parens opened at `open`, or `None`
/// when they do not balance. Sound only on text `blank_noncode` has been
/// through — a `(` inside a `format!` placeholder is not a group opener.
fn paren_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// Collapse whitespace, so an expression rustfmt wrapped across lines
/// reads as one sequence.
fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split a group's interior on top-level commas, dropping the empty tail a
/// trailing comma leaves. Angle brackets count towards depth so a
/// `Foo::<A, B>` argument does not read as two elements.
fn top_level_elements(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' | '>' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                out.push(normalise(&current));
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    out.push(normalise(&current));
    out.retain(|element| !element.is_empty());
    out
}

/// True when the `(` at `open` opens a **tuple expression** rather than a
/// call's argument list, a macro invocation or a type.
///
/// The distinction is the whole reason this guard can afford to treat an
/// unevaluable flag slot as a violation: a four-argument call is extremely
/// common in these functions and a four-element tuple is not.
fn opens_a_tuple(text: &str, open: usize) -> bool {
    let bytes = text.as_bytes();
    let Some(prev) = before(bytes, open) else {
        return true;
    };
    match bytes[prev] {
        // `f(…)`, `Ok(…)`, `let (…)`: an identifier before the paren is a
        // call or a binding — unless it is a keyword a tuple may follow.
        byte if is_ident_byte(byte) => TUPLE_KEYWORDS.contains(&word_ending_at(text, prev)),
        // `f()(…)`, `v[0](…)`, `m!(…)`, `f()?(…)`, `t.0(…)`: all calls.
        b')' | b']' | b'!' | b'?' | b'.' => false,
        // `=> (a, b, c, d)` is an arm's value; `-> (A, B, C, D)` is a
        // return type, and a type is not a construction. Everything else
        // ending in `>` closes a generic argument list, so it is a call.
        b'>' => prev > 0 && bytes[prev - 1] == b'=',
        _ => true,
    }
}

/// One `fn` item in blanked text, with the byte extent of its body.
///
/// `rust_scan::parse_fns` is the shared walker and this guard cannot use
/// it: it drops the signature and hands the body back as a copy, and this
/// guard needs the signature (that is how the corpus is derived) and the
/// body's offsets (that is how a construction is attributed to the
/// innermost enclosing candidate, and how a hit maps back to a line).
#[derive(Debug, PartialEq, Eq)]
struct Fun {
    name: String,
    /// Text between the name and the body's `{`: generics, parameters,
    /// return type, `where` clause.
    signature: String,
    /// The body, braces included.
    body: Range<usize>,
}

/// Every `fn` item in `text`, nested ones included.
fn functions(text: &str) -> Vec<Fun> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 2 < bytes.len() {
        // The `fn` keyword on a token boundary, followed by a name — which
        // is what rules out the `fn(&str) -> bool` pointer type.
        if !(bytes[at] == b'f'
            && bytes[at + 1] == b'n'
            && (at == 0 || !is_ident_byte(bytes[at - 1]))
            && bytes[at + 2].is_ascii_whitespace())
        {
            at += 1;
            continue;
        }
        let name_start = skip_space(bytes, at + 2);
        let mut name_end = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            at += 1;
            continue;
        }
        // Walk the signature to the body's `{`, or to the `;` of a bodiless
        // declaration. Generic bounds and `where` clauses carry neither at
        // paren/bracket depth zero.
        let mut parens = 0usize;
        let mut brackets = 0usize;
        let mut cursor = name_end;
        let mut brace = None;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'(' => parens += 1,
                b')' => parens = parens.saturating_sub(1),
                b'[' => brackets += 1,
                b']' => brackets = brackets.saturating_sub(1),
                b';' if parens == 0 && brackets == 0 => break,
                b'{' if parens == 0 && brackets == 0 => {
                    brace = Some(cursor);
                    break;
                }
                _ => {}
            }
            cursor += 1;
        }
        if let Some(brace) = brace {
            // Unbalanced input keeps the rest of the text as the body,
            // which is what the caller wants: a truncated body would read
            // as a function that constructs nothing.
            let close = rust_scan::block_end(bytes, brace).map_or(bytes.len(), |end| end + 1);
            out.push(Fun {
                name: text[name_start..name_end].to_string(),
                signature: text[name_end..brace].to_string(),
                body: brace..close,
            });
        }
        at = name_end;
    }
    out
}

/// The elements of the tuple [`SUCCESS_ALIAS`] declares, in order, or
/// `None` when `text` declares no such alias.
fn declared_shape(text: &str) -> Option<Vec<String>> {
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(SUCCESS_ALIAS) {
        let at = from + found;
        from = at + SUCCESS_ALIAS.len();
        if !is_token(bytes, at, SUCCESS_ALIAS) {
            continue;
        }
        // The declaration, not a use: `type IngestInnerOk = (…);`.
        let is_declaration =
            before(bytes, at).is_some_and(|prev| word_ending_at(text, prev) == "type");
        if !is_declaration {
            continue;
        }
        let mut cursor = skip_space(bytes, from);
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_space(bytes, cursor + 1);
        if bytes.get(cursor) != Some(&b'(') {
            continue;
        }
        let Some(close) = paren_end(bytes, cursor) else {
            continue;
        };
        let elements = top_level_elements(&text[cursor + 1..close]);
        if elements.len() > 1 {
            return Some(elements);
        }
    }
    None
}

/// The index of the single [`FLAG_TYPE`] element — the `was_duplicate`
/// claim. `None` when the shape carries no such element or more than one,
/// in which case "the flag slot" is not a well-defined thing and the
/// counter-assertion says so.
fn flag_slot(shape: &[String]) -> Option<usize> {
    let mut slots = shape
        .iter()
        .enumerate()
        .filter(|(_, element)| *element == FLAG_TYPE);
    match (slots.next(), slots.next()) {
        (Some((at, _)), None) => Some(at),
        _ => None,
    }
}

/// The production text of one file: comments and literals blanked first
/// (prose naming the construction must not read as code), then the inline
/// test module dropped — test code legitimately builds whatever shape its
/// fixture needs, and a guard arguing with it would be arguing about test
/// data.
///
/// Fail-closed on the boundary rather than assuming it. The convention in
/// this workspace is one column-0 `#[cfg(test)]` with the test module last,
/// and `ingest_use_case.rs` holds to it (one marker, 5k lines of production
/// code above it, 11k of tests below). A file that breaks the convention
/// gets an `Err` and is **reported**, not silently truncated: over-blanking
/// here would read as a file with no constructions at all, which is a
/// silent pass. Only the exact `#[cfg(test)]` spelling counts;
/// `#[cfg(any(test, feature = "test-support"))]` guards individual
/// production items in this workspace and is not a test marker.
fn production_region(source: &str) -> Result<String, String> {
    let blanked = blank_noncode(source);
    let markers: Vec<usize> = {
        let mut out = Vec::new();
        let mut from = 0usize;
        while let Some(found) = blanked[from..].find(CFG_TEST) {
            let at = from + found;
            from = at + CFG_TEST.len();
            out.push(at);
        }
        out
    };
    match markers.as_slice() {
        [] => Ok(blanked),
        [at] if *at == 0 || blanked.as_bytes()[at - 1] == b'\n' => {
            let mut bytes = blanked.into_bytes();
            let end = bytes.len();
            blank_range(&mut bytes, *at, end);
            Ok(String::from_utf8(bytes).expect("blanking replaces code with ASCII spaces"))
        }
        many => Err(format!(
            "{} `{CFG_TEST}` marker(s), not one at column 0 — this guard \
             separates production code from test code by dropping everything \
             from a single column-0 marker to the end of the file, and it \
             cannot do that here. Keep the inline test module last and \
             spelled once, or teach this guard the per-item blanking rule \
             `cas_reads_are_verified::blank_cfg_test_items` uses",
            many.len()
        )),
    }
}

/// Read one file's production text: the candidate functions, the
/// constructions inside them, and the funnel's call sites.
fn scan_text(text: &str, shape: &[String]) -> FileScan {
    let spelled = format!("({})", shape.join(", "));
    let candidates: Vec<Fun> = functions(text)
        .into_iter()
        .filter(|fun| {
            names_token(&fun.signature, SUCCESS_ALIAS)
                || normalise(&fun.signature).contains(&spelled)
        })
        .collect();

    let mut constructions = Vec::new();
    for (at, elements) in tuples_of_shape(text, shape.len()) {
        // Attribute to the innermost enclosing candidate: a nested
        // candidate must not also be reported against the function it
        // sits in.
        let Some(func) = candidates
            .iter()
            .filter(|fun| fun.body.contains(&at))
            .min_by_key(|fun| fun.body.end - fun.body.start)
        else {
            continue;
        };
        let claim = flag_slot(shape).map_or_else(
            || Claim::Unproven(String::new()),
            |slot| match elements.get(slot).map(String::as_str) {
                Some(NOT_DEDUPLICATED) => Claim::Disclaimed,
                Some(DEDUPLICATED) => Claim::Deduplicated,
                Some(other) => Claim::Unproven(other.to_string()),
                None => Claim::Unproven(String::new()),
            },
        );
        constructions.push(Construction {
            func: func.name.clone(),
            line: line_of(text, at),
            claim,
        });
    }

    FileScan {
        candidates: candidates.into_iter().map(|fun| fun.name).collect(),
        constructions,
        funnel_calls: funnel_call_sites(text),
    }
}

/// Every tuple expression of `arity` top-level elements in `text`.
fn tuples_of_shape(text: &str, arity: usize) -> Vec<(usize, Vec<String>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for at in 0..bytes.len() {
        if bytes[at] != b'(' || !opens_a_tuple(text, at) {
            continue;
        }
        let Some(close) = paren_end(bytes, at) else {
            continue;
        };
        let elements = top_level_elements(&text[at + 1..close]);
        if elements.len() == arity {
            out.push((at, elements));
        }
    }
    out
}

/// `self.dedup_ok(` call sites — a method call on the funnel, which the
/// definition (`async fn dedup_ok(`) is not.
fn funnel_call_sites(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(found) = text[from..].find(FUNNEL) {
        let at = from + found;
        from = at + FUNNEL.len();
        if !is_token(bytes, at, FUNNEL) {
            continue;
        }
        let called = before(bytes, at).is_some_and(|prev| bytes[prev] == b'.');
        if called && bytes.get(skip_space(bytes, from)) == Some(&b'(') {
            count += 1;
        }
    }
    count
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for entry in crates.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// Walk the corpus: the production files that name the success alias.
fn scan(root: &Path) -> Scan {
    let mut corpus = Vec::new();
    let mut unreadable = Vec::new();
    let mut texts = Vec::new();
    for path in production_sources(root) {
        let rel = path
            .strip_prefix(root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        if !source.contains(SUCCESS_ALIAS) {
            continue;
        }
        match production_region(&source) {
            Ok(text) => {
                if names_token(&text, SUCCESS_ALIAS) {
                    corpus.push(rel.clone());
                    texts.push((rel, text));
                }
            }
            Err(why) => unreadable.push(format!("{rel} — {why}")),
        }
    }

    let declared_in: Vec<String> = texts
        .iter()
        .filter(|(_, text)| declared_shape(text).is_some())
        .map(|(rel, _)| rel.clone())
        .collect();
    let shape = texts
        .iter()
        .find_map(|(_, text)| declared_shape(text))
        .unwrap_or_default();

    let mut candidates = Vec::new();
    let mut constructions = Vec::new();
    let mut funnel_calls = 0usize;
    if !shape.is_empty() {
        for (rel, text) in &texts {
            let file = scan_text(text, &shape);
            funnel_calls += file.funnel_calls;
            for name in file.candidates {
                candidates.push((rel.clone(), name));
            }
            for construction in file.constructions {
                constructions.push(Found {
                    rel: rel.clone(),
                    construction,
                });
            }
        }
    }

    Scan {
        corpus,
        declared_in,
        shape,
        candidates,
        constructions,
        funnel_calls,
        unreadable,
    }
}

// ---------------------------------------------------------------------------
// The assertion.
// ---------------------------------------------------------------------------

#[test]
fn every_deduplicated_success_is_built_inside_the_funnel() {
    let scan = scan(&workspace_root());

    let mut violations = scan.unreadable.clone();
    for found in &scan.constructions {
        if found.construction.func == FUNNEL || found.construction.claim == Claim::Disclaimed {
            continue;
        }
        let what = match &found.construction.claim {
            Claim::Deduplicated => format!(
                "builds a success claiming `{DEDUPLICATED}` in the \
                 `was_duplicate` slot"
            ),
            Claim::Unproven(flag) if flag.is_empty() => {
                "builds a success shape whose `was_duplicate` slot the scan \
                 could not read"
                    .to_string()
            }
            Claim::Unproven(flag) => format!(
                "builds a success whose `was_duplicate` slot is `{flag}` — \
                 not a literal, so the scan cannot tell it from a dedup hit"
            ),
            Claim::Disclaimed => unreachable!("disclaimed constructions are skipped above"),
        };
        violations.push(format!(
            "{}:{} — `fn {}` {what}",
            found.rel, found.construction.line, found.construction.func
        ));
    }

    assert!(
        violations.is_empty(),
        "a deduplicated ingest success must be built only inside `fn \
         {FUNNEL}`, which runs this request's own {} + {} comparison before \
         the success exists (ADR 0006: no operator opt-out, and no \"already \
         verified once, by someone else\" clause). A success carrying \
         `was_duplicate = true` built anywhere else reports a verification \
         nobody performed — `ingest_with_verification` ticks \
         `hort_upstream_checksum_total{{result=verified}}` on it — and does \
         so silently, with every behavioural test still green. Call `{FUNNEL}` \
         and return what it gives you; a construction that genuinely cannot \
         be a dedup hit writes the literal `{NOT_DEDUPLICATED}` in the flag \
         slot. There is no allow-list: a construction that belongs outside \
         the funnel is a review conversation about whether the funnel still \
         means anything. {} site(s) below:\n  {}",
        COMPARISONS[0],
        COMPARISONS[1],
        violations.len(),
        violations.join("\n  ")
    );
}

/// Counter-assertion: the corpus is real and the scan still reaches what it
/// is about.
///
/// Every sibling guard carries one, for the reason a source-scan guard
/// usually dies: a rename of the alias, the funnel or the comparisons would
/// otherwise leave [`every_deduplicated_success_is_built_inside_the_funnel`]
/// green over an empty corpus. The pins are deliberately exact rather than
/// non-empty checks — a new function in the success-shape corpus must be
/// read by a human against this contract, and an added entry here is that
/// reading.
#[test]
fn the_scan_still_finds_the_funnel_and_the_claim_it_builds() {
    let scan = scan(&workspace_root());

    assert_eq!(
        scan.corpus,
        vec!["crates/hort-app/src/use_cases/ingest_use_case.rs"],
        "the corpus is the production files naming `{SUCCESS_ALIAS}`. An \
         empty or drifted corpus means the scan above is answering about \
         nothing: either the alias was renamed, the file moved, or the \
         success shape stopped being a named alias at all"
    );
    assert_eq!(
        scan.declared_in,
        vec!["crates/hort-app/src/use_cases/ingest_use_case.rs"],
        "`type {SUCCESS_ALIAS} = (…)` must be declared exactly once — the \
         scan reads the tuple's arity and flag slot from that declaration"
    );
    assert_eq!(
        scan.shape.len(),
        4,
        "the success shape is a 4-tuple `(artifact, was_duplicate, repo_key, \
         ingested_event_id)`; found {:?}. A changed shape is not a reason to \
         edit this number on the way past: the guard's premise is that one \
         slot carries the dedup claim, so re-read the new shape against it \
         first",
        scan.shape
    );
    assert_eq!(
        flag_slot(&scan.shape),
        Some(1),
        "the `was_duplicate` claim is the shape's single `{FLAG_TYPE}` \
         element. Two of them, or none, and \"the flag slot\" is not a \
         well-defined thing — which is the guard's whole premise, so it \
         fails here rather than classifying on a guess. Shape: {:?}",
        scan.shape
    );

    assert_eq!(
        scan.candidates,
        vec![
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                FUNNEL.to_string()
            ),
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                "find_existing_and_check_declared_dedup".to_string()
            ),
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                "put_and_check_post_dedup".to_string()
            ),
            (
                "crates/hort-app/src/use_cases/ingest_use_case.rs".to_string(),
                "ingest_inner".to_string()
            ),
        ],
        "these four functions are the corpus this guard polices: the funnel, \
         the two dedup exits that route through it, and `ingest_inner` \
         itself. A fifth is not a reason to extend this list on the way \
         past — read its success construction against ADR 0006 first, then \
         add it"
    );

    // The funnel still compares. Without this, a `dedup_ok` reduced to a
    // bare tuple constructor would satisfy every assertion above while
    // the property they are about — a dedup success cannot exist without
    // the comparison having run — was gone.
    let funnel = fs::read_to_string(
        workspace_root().join("crates/hort-app/src/use_cases/ingest_use_case.rs"),
    )
    .expect("the corpus file is readable UTF-8");
    let funnel = production_region(&funnel).expect("the corpus file's test boundary is readable");
    let body = functions(&funnel)
        .into_iter()
        .find(|fun| fun.name == FUNNEL)
        .map(|fun| funnel[fun.body].to_string())
        .unwrap_or_else(|| panic!("`fn {FUNNEL}` must exist — it is the funnel this guard pins"));
    for comparison in COMPARISONS {
        assert!(
            body.contains(comparison),
            "`fn {FUNNEL}` no longer calls `{comparison}`. Routing every \
             deduplicated success through it is only worth something because \
             it runs this request's own upstream comparison first; without \
             the call the funnel is a tuple constructor and this guard pins \
             nothing"
        );
    }

    assert_eq!(
        scan.funnel_calls, 2,
        "both dedup exits must still route through `{FUNNEL}`: the \
         declared-hash short-circuit in `find_existing_and_check_declared_dedup` \
         and the post-put hit in `put_and_check_post_dedup`. A third exit is \
         not a reason to bump this count on the way past — it is the review \
         this guard exists to force"
    );

    let claims: Vec<(&str, &Claim)> = scan
        .constructions
        .iter()
        .map(|found| (found.construction.func.as_str(), &found.construction.claim))
        .collect();
    assert_eq!(
        claims,
        vec![
            (FUNNEL, &Claim::Deduplicated),
            ("ingest_inner", &Claim::Disclaimed),
        ],
        "the scan must still find the two constructions it is about — the \
         funnel's deduplicated success and `ingest_inner`'s fresh-insert \
         success. Finding neither is how this guard would pass vacuously \
         while a hand-built dedup success sat in the file"
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's own behaviour.
// ---------------------------------------------------------------------------

/// The alias declaration every planted fixture carries, because the
/// matcher derives the arity and the flag slot from the source rather than
/// from a number written in this file.
const PLANTED_SHAPE: &str = "type IngestInnerOk = (Artifact, bool, String, Uuid);\n";

/// Run the matcher over planted source exactly as the scan runs it over a
/// corpus file.
fn scan_planted(planted: &str) -> FileScan {
    let text = production_region(planted).expect("planted source has a readable test boundary");
    let shape = declared_shape(&text).expect("planted source declares the success shape");
    scan_text(&text, &shape)
}

/// The baseline: the real funnel's shape. Without it every trip-wire below
/// could be passing for the wrong reason.
#[test]
fn the_scanner_accepts_the_funnel_building_a_deduplicated_success() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn dedup_ok(&self, existing: Artifact) -> Result<IngestInnerOk, E> {{\n    \
         self.verify_sha512_upstream(v, &h, k).await?;\n    \
         Ok((existing, true, repo_key.to_string(), Uuid::new_v4()))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted),
        FileScan {
            candidates: vec!["dedup_ok".to_string()],
            constructions: vec![Construction {
                func: "dedup_ok".to_string(),
                line: 4,
                claim: Claim::Deduplicated,
            }],
            funnel_calls: 0,
        }
    );
}

/// The regression this guard exists for: a third dedup exit that
/// hand-builds the success instead of calling the funnel.
#[test]
fn the_scanner_trips_on_a_hand_built_deduplicated_success() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         Ok((existing, true, repo_key.to_string(), Uuid::new_v4()))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions,
        vec![Construction {
            func: "third_exit".to_string(),
            line: 3,
            claim: Claim::Deduplicated,
        }]
    );
}

/// The same exit, written with a variable in the flag slot. The scan
/// cannot evaluate it, so it cannot tell the tuple from a dedup success —
/// and a `was_duplicate` the reader cannot trace is the hazard itself.
#[test]
fn the_scanner_trips_on_a_flag_it_cannot_evaluate() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         Ok((existing, was_duplicate, repo_key, id))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions,
        vec![Construction {
            func: "third_exit".to_string(),
            line: 3,
            claim: Claim::Unproven("was_duplicate".to_string()),
        }]
    );
}

/// A success that disclaims deduplication promises nothing about a
/// comparison, so it is allowed anywhere — `ingest_inner`'s fresh-insert
/// tail is exactly this.
#[test]
fn the_scanner_allows_a_success_that_disclaims_deduplication() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn ingest_inner(&self) -> Result<IngestInnerOk, E> {{\n    \
         Ok((artifact, false, repo_key, artifact_ingested_event_id))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions,
        vec![Construction {
            func: "ingest_inner".to_string(),
            line: 3,
            claim: Claim::Disclaimed,
        }]
    );
}

/// Prose is not code. The corpus file's own doc comments spell the
/// construction out in order to explain it, and a scan that read comments
/// would be satisfied — or tripped — by a sentence.
#[test]
fn the_scanner_is_not_satisfied_by_prose_naming_the_construction() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         /// Builds `(existing, true, repo_key.to_string(), Uuid::new_v4())`.\n\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         // Was: Ok((existing, true, repo_key, Uuid::new_v4()))\n    \
         let text = \"(existing, true, repo_key, id)\";\n    \
         self.dedup_ok(existing).await\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted),
        FileScan {
            candidates: vec!["third_exit".to_string()],
            constructions: vec![],
            funnel_calls: 1,
        },
        "comments and string literals are blanked before anything structural \
         is read"
    );
}

/// A four-argument call is not a four-element tuple. These functions are
/// full of them, and reading one as a construction is what would make
/// treating an unevaluable flag slot as a violation unaffordable.
#[test]
fn the_scanner_does_not_read_a_four_argument_call_as_a_tuple() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         self.find_existing(repository_id, coords, declared, verification).await\n\
         }}\n"
    );
    assert_eq!(scan_planted(&planted).constructions, vec![]);
}

/// Nor is a macro invocation, whose `!` is what gives it away.
#[test]
fn the_scanner_does_not_read_a_macro_invocation_as_a_tuple() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         tracing::debug!(id = %existing.id, dup = true, key = %k, v = %n);\n\
         }}\n"
    );
    assert_eq!(scan_planted(&planted).constructions, vec![]);
}

/// A `let` destructure takes the shape apart; it never builds one.
#[test]
fn the_scanner_does_not_read_a_let_destructure_as_a_construction() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         let (artifact, was_duplicate, repo_key, id) = self.dedup_ok(e).await?;\n    \
         Ok((artifact, was_duplicate, repo_key, id))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted)
            .constructions
            .into_iter()
            .map(|c| c.line)
            .collect::<Vec<_>>(),
        vec![4],
        "the destructure on line 3 is not a construction; the rebuild on \
         line 4 is, and is reported — route the success whole instead"
    );
}

/// The blind spot this guard cannot close, asserted so it stays visible:
/// a match-arm pattern is lexically identical to a construction.
/// `Ok((a, b, c, d))` reads the same either way, so a destructure of the
/// success inside a candidate function is a false positive — correct to
/// flag, and a review conversation about routing the value whole rather
/// than a mechanical edit.
#[test]
fn the_scanner_cannot_tell_a_match_arm_pattern_from_a_construction() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         match self.dedup_ok(e).await {{\n        \
         Ok((artifact, dup, key, id)) => Ok((artifact, dup, key, id)),\n        \
         Err(e) => Err(e),\n    \
         }}\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions.len(),
        2,
        "the arm's pattern and the arm's value are indistinguishable to a \
         source scan; both are reported"
    );
}

/// `return (existing, true, …)` — the plainest hand-build there is, and
/// the one a keyword-blind "an identifier before `(` means a call" rule
/// would miss entirely.
#[test]
fn the_scanner_reads_a_bare_return_tuple() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> IngestInnerOk {{\n    \
         return (existing, true, repo_key.to_string(), Uuid::new_v4());\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions,
        vec![Construction {
            func: "third_exit".to_string(),
            line: 3,
            claim: Claim::Deduplicated,
        }]
    );
}

/// The arity and the flag slot come from the declaration, not from a
/// number in this file: a shape that grew an element and moved the flag is
/// followed, and the old arity stops matching.
#[test]
fn the_scanner_follows_the_shape_the_source_declares() {
    let planted = "type IngestInnerOk = (Artifact, String, bool, Uuid, u64);\n\
                   async fn third_exit(&self) -> Result<IngestInnerOk, E> {\n    \
                   Ok((existing, repo_key, true, Uuid::new_v4(), size))\n    \
                   }\n";
    let scan = scan_planted(planted);
    assert_eq!(
        scan.constructions,
        vec![Construction {
            func: "third_exit".to_string(),
            line: 3,
            claim: Claim::Deduplicated,
        }],
        "five elements, flag in the third slot — both read from the \
         declaration"
    );
}

/// The scoping limit, stated rather than discovered: a function whose
/// signature names neither the alias nor the tuple is outside the corpus.
/// Such a construction would have to leave the function through some other
/// type, and that type is the review conversation — see the module doc's
/// blind spots.
#[test]
fn the_scanner_ignores_a_function_that_does_not_name_the_shape() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         fn unrelated(&self) -> Something {{\n    \
         (existing, true, repo_key.to_string(), Uuid::new_v4())\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted),
        FileScan {
            candidates: vec![],
            constructions: vec![],
            funnel_calls: 0,
        }
    );
}

/// Spelling the tuple out instead of naming the alias is the natural way
/// to route around a scan keyed on the name, so the signature check reads
/// both.
#[test]
fn the_scanner_reads_a_signature_that_spells_the_tuple_out() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         async fn third_exit(&self) -> Result<(Artifact, bool, String, Uuid), E> {{\n    \
         Ok((existing, true, repo_key.to_string(), Uuid::new_v4()))\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted).constructions,
        vec![Construction {
            func: "third_exit".to_string(),
            line: 3,
            claim: Claim::Deduplicated,
        }]
    );
}

/// Test code builds whatever shape its fixture needs; a guard arguing with
/// it would be arguing about test data.
#[test]
fn the_scanner_drops_the_inline_test_module() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         #[cfg(test)]\n\
         mod tests {{\n    \
         fn fixture() -> IngestInnerOk {{\n        \
         (artifact(), true, \"repo\".to_string(), Uuid::new_v4())\n    \
         }}\n\
         }}\n"
    );
    assert_eq!(
        scan_planted(&planted),
        FileScan {
            candidates: vec![],
            constructions: vec![],
            funnel_calls: 0,
        }
    );
}

/// Fail-closed on the boundary: a file whose test module the scan cannot
/// delimit is reported, not silently truncated. Over-blanking here would
/// read as a file with no constructions at all — a silent pass.
#[test]
fn the_scanner_refuses_a_file_whose_test_boundary_it_cannot_find() {
    let planted = format!(
        "{PLANTED_SHAPE}\
         #[cfg(test)]\n\
         use std::sync::atomic::AtomicBool;\n\n\
         async fn third_exit(&self) -> Result<IngestInnerOk, E> {{\n    \
         Ok((existing, true, repo_key.to_string(), Uuid::new_v4()))\n\
         }}\n\n\
         #[cfg(test)]\n\
         mod tests {{}}\n"
    );
    let refusal = production_region(&planted).expect_err("two markers must be refused");
    assert!(
        refusal.contains("marker(s), not one at column 0"),
        "the refusal must say what it could not do: {refusal}"
    );
}
