//! Structural guard: **a `serde_saphyr::Options` value is constructed in
//! exactly one place in the workspace's production code, and that place is
//! `gitops_options`.**
//!
//! ## The invariant
//!
//! Every operator-authored gitops envelope reaches the registry through
//! this crate's `yaml::from_slice`, which parses with the options
//! `gitops_options` builds. That one value concentrates six field
//! assignments — the five decisions the `yaml` module documents, the
//! snippet decision being spelled in two fields — and they are not
//! preferences. One of them is a security control: at the parser's stock
//! options a rendered syntax error carries a rustc-style echo of the
//! offending source line plus its neighbours, `ParseError::Yaml` renders
//! into the boot log and the apply-time linter output, and a syntax error
//! near a plaintext credential reproduces that credential verbatim.
//! `with_snippet: false` together with `crop_radius: 0` is what suppresses
//! the echo.
//!
//! The parse therefore has one meaning and one definition. **Nothing in
//! the compiler holds that.** A new parse call written beside its own
//! `serde_saphyr::options! { … }` compiles, passes clippy and passes the
//! whole suite, and carries none of the six assignments — including the
//! one that keeps a credential out of the log. The two sites would not
//! drift *from each other* in any way a test could see, because each
//! stays internally consistent; what drifts is what an operator's file
//! means, per call site. The `yaml` module states the single-definition
//! rule in prose, and prose is a compensating control rather than a close.
//!
//! The closest analogue in this workspace is instructive about the failure
//! mode: `hort-app/tests/https_rule_is_single_sourced.rs` exists because
//! one rule had been re-typed per consumer five times and the sixth
//! consumer carried no copy at all — the consumer with no request behind
//! it, where a miss produced no signal anyone was watching. This guard
//! closes the same shape before a second copy exists rather than after.
//!
//! ## The property
//!
//! Across every workspace crate's production Rust (`crates/*/src`), each
//! expression that brings a fresh `serde_saphyr::Options` value into
//! existence sits inside the body of a function named [`SANCTIONED_FN`].
//!
//! `serde_saphyr::Options` is `#[non_exhaustive]`, so a struct literal is
//! a compile error outside the parser crate and needs no scanning. That
//! leaves exactly two spellings a downstream crate can write, and
//! [`CONSTRUCTION_FORMS`] holds both:
//!
//! * the `options!` macro, which expands to `Options::default()` plus
//!   field assignments; and
//! * `Options::default()` itself, from which the builder methods
//!   (`with_properties`, `with_include_resolver`, …) take `self` and
//!   therefore cannot start a value of their own.
//!
//! Both match as whole tokens, which is what distinguishes them from the
//! neighbours that are not this type: `ser_options!` and
//! `render_options!` are the parser's *serializer* macros and are
//! preceded by `_`, an identifier byte; `SimpleFileOptions::default()`
//! and `PgPoolOptions::default()` are other crates' types and are
//! preceded by a letter. A type annotation is deliberately not a
//! construction — `fn gitops_options() -> serde_saphyr::Options` names
//! the type without building one, so matching the bare type name would
//! report the definition's own signature.
//!
//! ## Function-scoped, and why not file-scoped
//!
//! The scope is the **function**, anchored on [`SANCTIONED_FN`]'s name
//! rather than on a path, and both halves of that matter.
//!
//! *Why a function and not a file.* The hazard is a parse call that
//! builds its own options, and the place someone needing a parse looks
//! first is the file that already has one. A file-scoped rule — "only
//! `yaml.rs` may construct" — is satisfied by a `fn lenient_options()`
//! added twelve lines below `gitops_options`, which is precisely the
//! second definition the invariant forbids. Function scope reports it.
//! `cas_reads_are_verified` chose function scope for a related but
//! different reason (a file-scoped scan there was satisfied by a doc
//! comment naming the thing it looked for); here the comment hazard is
//! handled by blanking rather than by scoping, and function scope is
//! doing the work of locating *which* definition a construction belongs
//! to.
//!
//! *Why a name and not a path.* Nothing in the predicate is a file name
//! or a line number, so the guard survives `gitops_options` moving within
//! its file, the file moving within the crate, and the whole decision
//! moving to another crate. A rename of the function does not go quiet
//! either: the construction is then attributed to a function that is not
//! [`SANCTIONED_FN`] and the main assertion reports it by name.
//!
//! **There is no allow-list**, as with the siblings — no entry anyone can
//! add to make a finding go away. A second construction that genuinely
//! belongs is a review conversation about whether the gitops parse still
//! has one meaning.
//!
//! ## Counter-assertions
//!
//! A scan whose needle has been renamed out of existence is vacuously
//! green, which is how guards in this family die. So
//! [`the_scanned_corpus_is_real`] proves the corpus:
//!
//! * [`SANCTIONED_FN`] is defined exactly once in the scanned tree;
//! * the scan still finds exactly one construction, and it is inside that
//!   definition;
//! * the definition still assigns all six fields in
//!   [`SETTING_FIELDS`] **by name**, so a hollowed-out
//!   `gitops_options` returning stock options is not vacuously green.
//!
//! That last one is why comments must be blanked before anything
//! structural is read, and here the hazard is certain rather than
//! hypothetical: the `yaml` module's own documentation names all six
//! fields in prose, several of them more than once. A scan that read
//! comments would find the whole census in the doc comment and stay green
//! over a definition that had been emptied.
//!
//! The division of labour is worth being exact about, because each test
//! covers a direction the other cannot. The main assertion cannot see a
//! corpus that emptied — the macro renamed upstream, the needle no longer
//! matching — and cannot see a `gitops_options` kept by name but hollowed
//! of its assignments, which leaves the one construction exactly where
//! the main assertion wants it while the property is gone. Those two are
//! the counter-assertion's whole job. The counter-assertion in turn
//! cannot see a *second* construction, which is the main assertion's.
//!
//! ## What is test code, and how that is decided
//!
//! A test building its own `Options` is its own business, and it is
//! excluded by **how it is compiled** rather than by an entry. Two
//! mechanisms, because this workspace uses both:
//!
//! * an inline `#[cfg(test)]` item is blanked per item
//!   ([`blank_cfg_test_items`]). Per item rather than "from the first
//!   marker to the end of the file": 22 files under `crates/*/src` carry
//!   production code *after* a column-0 `#[cfg(test)]` item — a
//!   test-only `use`, a test-only constructor, a second inline module —
//!   and a truncating rule would read them as having almost no code at
//!   all. In this guard a blanked file is a silent pass, so over-blanking
//!   is the dangerous direction.
//! * a whole file compiled only under test because a *parent* module
//!   declares it so (`#[cfg(test)] #[path = "x_tests.rs"] mod tests;`,
//!   and the same without the `#[path]`). The `#[cfg(test)]` is real but
//!   sits in the declaring file, so [`cfg_test_module_files`] resolves
//!   each declaration to the file it compiles and drops that file from
//!   the corpus. A declaration this resolver cannot follow leaves its
//!   file in the corpus — the safe direction, a loud false positive —
//!   and [`every_test_only_module_declaration_resolves`] says so.
//!
//! `#[cfg(any(test, feature = "test-support"))]` is deliberately *not* a
//! test marker: in this workspace it gates production-file items that
//! ship under a feature, and treating it as test code would blank
//! production code.
//!
//! The two `serde_saphyr::options!` values that exist in `tests/` targets
//! today — the GitHub-workflow parse in
//! `hort-app/tests/publish_chain_is_gated.rs` and the deployment-manifest
//! parse in this crate's `tests/deploy_schedule_parity.rs` — are outside
//! `crates/*/src` entirely, and deliberately so: a CI workflow is not a
//! gitops envelope, and borrowing decisions made about an operator's
//! envelope would be the wrong reuse rather than the right one.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! * **The adjacent hole, which this guard does not cover.** A parse at
//!   the parser's *stock* options constructs no `Options` at all:
//!   `serde_saphyr::from_slice` / `from_str` without the `_with_options`
//!   suffix build the default internally, `with_snippet` included. Such a
//!   call reintroduces the credential echo while leaving this guard
//!   green, because the guard's subject is the number of `Options`
//!   values, not the number of parse entry points. What would close it is
//!   a different property — that this crate's only deserialising
//!   `serde_saphyr::from_*` call is the one in `from_slice` — and it is
//!   not asserted here.
//! * **The one every source scan has.** A construction assembled through
//!   a macro of our own is invisible, and so is one whose spelling has
//!   been renamed out of the matcher's reach — `use serde_saphyr::options
//!   as opts;` followed by `opts! { … }`. So are the two spellings that
//!   reach `Default` without naming the type beside it:
//!   `<serde_saphyr::Options as Default>::default()` and
//!   `let o: serde_saphyr::Options = Default::default();`. None is how
//!   any construction in this tree has ever been written, and all four
//!   are harder to write than the parse call this guard points at.
//! * **False positives, which are loud and are review conversations.**
//!   Another crate's `options!` macro, or another type named exactly
//!   `Options` whose `::default()` is called, both read as hits. So does
//!   a construction in a file whose test-only compilation this guard's
//!   resolver could not follow.
//!
//! The review check survives alongside the guard, exactly as it does for
//! `db_tests_are_serialized` and `cas_reads_are_verified`.
//!
//! No database, no dev-dependency and sub-second, so `cargo test
//! --workspace` runs it with no database and no gate-list entry — same
//! family as `https_rule_is_single_sourced`, `cas_reads_are_verified` and
//! `dedup_success_is_funnelled`. The lexical primitives are re-derived
//! here rather than borrowed from `hort-app/tests/rust_scan`: this crate
//! declares no dev-dependencies by design, it is published, and the
//! dependency graph runs `hort-app` → `hort-config`, so a `#[path]`
//! reaching up into another crate's test tree would both invert that
//! direction and leave the published package carrying a test target that
//! cannot compile.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// The one function allowed to build the value. Pinned by name rather
/// than by path so the guard survives the definition moving; a rename
/// turns the counter-assertion red, which is the moment to re-read what
/// the gitops parse promises.
const SANCTIONED_FN: &str = "gitops_options";

/// How a fresh `serde_saphyr::Options` can be spelled, with the label a
/// violation is reported under.
///
/// `Options` is `#[non_exhaustive]`, so these two are the whole set for a
/// downstream crate: the macro (which expands to `Options::default()` and
/// a run of field assignments) and `Default` itself. The builder methods
/// take `self`, so they transform a value rather than start one.
///
/// `Options::default` is matched without requiring the call's `(`, which
/// is the fail-closed direction: passing it as a function value
/// (`unwrap_or_else(Options::default)`) produces the same fresh value.
const CONSTRUCTION_FORMS: &[(&str, &str)] = &[
    ("options!", "the `options!` macro"),
    ("Options::default", "`Options::default`"),
];

/// The fields [`SANCTIONED_FN`] assigns. Six fields carrying the five
/// decisions the `yaml` module documents — `with_snippet` and
/// `crop_radius` are one decision, the suppressed source echo, spelled in
/// two fields because either value alone re-enables it.
///
/// Pinned by name only. What the values must *be* is the behavioural
/// tests' subject, measured through the production entry points; this
/// guard is about there being one place, and a census of names is what
/// keeps a hollowed-out definition from being vacuously green.
const SETTING_FIELDS: &[&str] = &[
    "duplicate_keys",
    "merge_keys",
    "strict_booleans",
    "with_snippet",
    "crop_radius",
    "emit_comments",
];

/// The attribute that marks an item as compiled only under test. Only
/// this exact spelling counts — see the module docs on
/// `#[cfg(any(test, feature = "test-support"))]`.
const CFG_TEST: &str = "#[cfg(test)]";

// ---------------------------------------------------------------------------
// Lexer: comments and literals, so everything structural runs on code.
// ---------------------------------------------------------------------------

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// True when the byte at `at` starts a token rather than continuing an
/// identifier — the `r` of `for` must not read as a raw-string opener,
/// nor the `b` of `verbose` as a byte-string prefix.
fn starts_a_token(src: &[u8], at: usize) -> bool {
    at == 0 || !is_ident_byte(src[at - 1])
}

/// True when `src` carries `first` immediately followed by `second` at
/// `at`. The two-byte markers this lexer turns on (`//`, `/*`, `*/`,
/// `b"`) all read this way.
fn is_pair(src: &[u8], at: usize, first: u8, second: u8) -> bool {
    src[at] == first && src.get(at + 1) == Some(&second)
}

/// Overwrite `from..to` with spaces, leaving newlines so byte offsets and
/// line numbers survive the pass.
fn blank_range(out: &mut [u8], from: usize, to: usize) {
    for byte in out.iter_mut().take(to).skip(from) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// The offset just past a `\`-escaped literal whose body starts at `from`
/// and runs to the next unescaped `terminator`. Shared by the string and
/// char forms, which differ only in that byte. An unterminated literal
/// runs to the end of the input.
fn escaped_literal_end(src: &[u8], from: usize, terminator: u8) -> usize {
    let mut at = from;
    while at < src.len() {
        if src[at] == b'\\' {
            at += 2;
        } else if src[at] == terminator {
            return at + 1;
        } else {
            at += 1;
        }
    }
    at
}

/// The offset just past the `"##…` closing a raw string whose opener
/// carried `hashes` hashes. A raw string honours no escapes, so only a
/// `"` trailed by as many `#` as the opener carried can close it.
fn raw_string_close(src: &[u8], from: usize, hashes: usize) -> usize {
    let mut at = from;
    while at < src.len() {
        if src[at] == b'"'
            && at + hashes < src.len()
            && src[at + 1..=at + hashes].iter().all(|byte| *byte == b'#')
        {
            return at + 1 + hashes;
        }
        at += 1;
    }
    src.len()
}

/// The offset just past the comment or literal starting at `at`, or
/// `None` when code starts there.
///
/// The order is load-bearing. Comments come first, because a `/*` is not
/// a division followed by a glob. The raw-string form precedes the
/// ordinary one, because `r#"…"#` would otherwise read as an identifier
/// followed by a string ending at the first inner `"` — and a raw string
/// is exactly where an unescaped `"` lives. The char literal comes last,
/// being the only form a `'` can open. Every arm reports an end strictly
/// past `at`, which is what keeps the caller's walk advancing.
fn noncode_token_end(src: &[u8], at: usize) -> Option<usize> {
    if is_pair(src, at, b'/', b'/') {
        let mut end = at;
        while end < src.len() && src[end] != b'\n' {
            end += 1;
        }
        return Some(end);
    }
    if is_pair(src, at, b'/', b'*') {
        // Nesting counts, as rustc allows it.
        let mut depth = 1usize;
        let mut end = at + 2;
        while end < src.len() && depth > 0 {
            if is_pair(src, end, b'/', b'*') {
                depth += 1;
                end += 2;
            } else if is_pair(src, end, b'*', b'/') {
                depth -= 1;
                end += 2;
            } else {
                end += 1;
            }
        }
        return Some(end);
    }
    if starts_a_token(src, at) {
        // `r"…"`, `r#"…"#`, `br#"…"#` — the `b` shifts the `r` one byte.
        let r_at = match src[at] {
            b'r' => Some(at),
            b'b' if src.get(at + 1) == Some(&b'r') => Some(at + 1),
            _ => None,
        };
        if let Some(r_at) = r_at {
            let mut hashes = 0usize;
            let mut cursor = r_at + 1;
            while src.get(cursor) == Some(&b'#') {
                hashes += 1;
                cursor += 1;
            }
            if src.get(cursor) == Some(&b'"') {
                return Some(raw_string_close(src, cursor + 1, hashes));
            }
        }
    }
    if src[at] == b'"' {
        return Some(escaped_literal_end(src, at + 1, b'"'));
    }
    if starts_a_token(src, at) && is_pair(src, at, b'b', b'"') {
        return Some(escaped_literal_end(src, at + 2, b'"'));
    }
    if src[at] == b'\'' {
        // `'\…'` and `'x'` are literals; `'static` is a lifetime. A
        // multi-byte char literal reads here as a lifetime, which is
        // harmless: every byte it could hide from the brace matcher
        // (`{`, `}`, `"`, `/`) is single-byte and takes the literal arm.
        let escaped = src.get(at + 1) == Some(&b'\\');
        let one_char = src.get(at + 2) == Some(&b'\'');
        if escaped || one_char {
            return Some(escaped_literal_end(src, at + 1, b'\''));
        }
    }
    None
}

/// Walk `source`, blanking every comment and — when `literals` — every
/// string and char literal, preserving byte offsets and line breaks.
///
/// Literals are always *recognised* even when they are not blanked, which
/// is what keeps a `//` inside `"https://…"` from reading as a comment
/// and swallowing the rest of its line.
fn blank(source: &str, literals: bool) -> String {
    let src = source.as_bytes();
    let mut out = src.to_vec();
    let mut at = 0usize;
    while at < src.len() {
        match noncode_token_end(src, at) {
            Some(end) => {
                let comment = is_pair(src, at, b'/', b'/') || is_pair(src, at, b'/', b'*');
                if literals || comment {
                    // `blank_range` clamps, so an unterminated token
                    // reporting an end past the input costs nothing.
                    blank_range(&mut out, at, end);
                }
                at = end;
            }
            None => at += 1,
        }
    }
    String::from_utf8(out).expect("blanking replaces whole tokens with ASCII spaces")
}

/// Comments and literals blanked. Everything structural runs on this: a
/// `{` inside a doc comment, a `format!` placeholder or a SQL string
/// literal is not a block opener, and this workspace's files are full of
/// all three.
fn blank_noncode(source: &str) -> String {
    blank(source, true)
}

/// The offset of the `}` closing the block whose `{` sits at `open`, or
/// `None` when the braces do not balance before the end of the input.
/// Sound only on text [`blank_noncode`] has been through.
fn block_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
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

/// The offset of the `]` closing the bracket group whose `[` sits at
/// `open`, or `None` when they do not balance. The attribute forms this
/// guard reads nest (`#[cfg(any(test, feature = "x"))]`,
/// `#[derive(A, B)]`), so the match has to count depth rather than take
/// the first `]`.
fn bracket_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'[' => depth += 1,
            b']' => {
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

/// The 1-based line `offset` falls on.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1
}

fn skip_ws(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// True when `needle` sits at `at` as a whole token — neither side
/// continuing an identifier. `SimpleFileOptions` contains `Options` and
/// `ser_options!` contains `options!`; this is what keeps both from
/// reading as the parser's own.
fn is_token(bytes: &[u8], at: usize, needle: &str) -> bool {
    starts_a_token(bytes, at) && {
        let after = at + needle.len();
        after >= bytes.len() || !is_ident_byte(bytes[after])
    }
}

// ---------------------------------------------------------------------------
// Test-only code, excluded by how it is compiled.
// ---------------------------------------------------------------------------

/// The offset of the byte ending the item an attribute applies to, with
/// which byte it is: a `{` opening the item's block, or the `;` / `,`
/// terminating a block-less one.
///
/// All three are needed and `,` is the one easy to forget: this workspace
/// attaches `#[cfg(test)]` to struct fields and struct-literal fields,
/// which end at a comma, and a rule looking only for `{` or `;` runs past
/// the field, past the struct's own closing brace, and blanks the `impl`
/// or `fn` that follows it.
///
/// Depth matters because the item may carry any of the three nested:
/// `fn f(a: u8, b: u8)` has commas inside parens, `const X: [u8; 2]` a
/// `;` inside brackets, and `use a::b::{C, D};` a comma inside the brace
/// group — the last being why the `{` is reported and the caller then
/// matches it.
fn item_delimiter(bytes: &[u8], from: usize) -> Option<(usize, u8)> {
    let mut parens = 0usize;
    let mut brackets = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(from) {
        match byte {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'{' | b';' | b',' if parens == 0 && brackets == 0 => return Some((at, *byte)),
            _ => {}
        }
    }
    None
}

/// Blank every `#[cfg(test)]`-attributed item, leaving the file's
/// production code and its offsets intact.
fn blank_cfg_test_items(blanked: &str) -> String {
    let bytes = blanked.as_bytes();
    let mut out = bytes.to_vec();
    let mut cursor = 0usize;
    while let Some(found) = blanked[cursor..].find(CFG_TEST) {
        let at = cursor + found;
        let after_attr = at + CFG_TEST.len();
        let end = match item_delimiter(bytes, after_attr) {
            // A block item: the attribute covers it to the matching brace.
            Some((brace, b'{')) => match block_end(bytes, brace) {
                Some(close) => {
                    // `use a::{A, B};` and `struct S { … };` both leave a
                    // terminator past the brace; absorb it so no fragment
                    // survives as code.
                    let next = skip_ws(bytes, close + 1);
                    if bytes.get(next) == Some(&b';') {
                        next + 1
                    } else {
                        close + 1
                    }
                }
                None => bytes.len(),
            },
            // A block-less item: `#[cfg(test)] use …;`,
            // `#[cfg(test)] const X: u8 = 1;`, `#[cfg(test)] probe: Flag,`.
            Some((terminator, _)) => terminator + 1,
            None => bytes.len(),
        };
        blank_range(&mut out, at, end);
        cursor = end;
    }
    String::from_utf8(out).expect("blanking replaces whole items with ASCII spaces")
}

/// A source file's scannable production text: comments and literals
/// blanked, then the `#[cfg(test)]` items. Byte offsets and line numbers
/// survive both passes.
fn production_region(source: &str) -> String {
    blank_cfg_test_items(&blank_noncode(source))
}

/// One `#[cfg(test)]` module declaration that compiles a whole other
/// file, as found in a declaring file's raw source.
#[derive(Debug, PartialEq, Eq)]
struct TestModuleDecl {
    /// The declaring file, workspace-relative.
    declared_in: String,
    /// 1-based line of the `#[cfg(test)]`.
    line: usize,
    /// The `#[path = "…"]` value, when the declaration carries one.
    path: Option<String>,
    /// The module's name.
    name: String,
}

/// Every `#[cfg(test)] … mod <name>;` in `source` — the block-less form,
/// which is the one that compiles another file. The inline
/// `#[cfg(test)] mod tests { … }` form is handled by
/// [`blank_cfg_test_items`] instead.
///
/// Read off text with comments blanked but **literals kept**: the
/// `#[path]` value is the one string literal this guard has to read, and
/// a prose mention of the declaration shape in a doc comment must not
/// drop a production file out of the corpus.
fn test_module_decls(rel: &str, source: &str) -> Vec<TestModuleDecl> {
    let text = blank(source, false);
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = text[cursor..].find(CFG_TEST) {
        let at = cursor + found;
        cursor = at + CFG_TEST.len();
        let mut path = None;
        let mut scan = skip_ws(bytes, cursor);
        // The attribute run between `#[cfg(test)]` and the item, keeping
        // the `#[path]` value if one is in it.
        while bytes.get(scan) == Some(&b'#') && bytes.get(scan + 1) == Some(&b'[') {
            let open = scan + 1;
            let Some(close) = bracket_end(bytes, open) else {
                break;
            };
            let attr = &text[open + 1..close];
            if let Some(value) = attr.trim().strip_prefix("path") {
                path = value
                    .trim_start()
                    .strip_prefix('=')
                    .and_then(|rest| rest.trim().strip_prefix('"'))
                    .and_then(|rest| rest.strip_suffix('"'))
                    .map(str::to_owned);
            }
            scan = skip_ws(bytes, close + 1);
        }
        // Step over the visibility modifier, then require `mod <name>;`.
        if text[scan..].starts_with("pub") && is_token(bytes, scan, "pub") {
            let mut after = scan + "pub".len();
            // `pub(crate)` / `pub(super)`: step over the restriction.
            if bytes.get(after) == Some(&b'(') {
                match text[after..].find(')') {
                    Some(offset) => after += offset + 1,
                    None => continue,
                }
            }
            scan = skip_ws(bytes, after);
        }
        let Some(rest) = text[scan..].strip_prefix("mod") else {
            continue;
        };
        if !rest.starts_with(|ch: char| ch.is_whitespace()) {
            continue;
        }
        let name_start = skip_ws(bytes, scan + "mod".len());
        let mut name_end = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start || bytes.get(skip_ws(bytes, name_end)) != Some(&b';') {
            continue;
        }
        out.push(TestModuleDecl {
            declared_in: rel.to_owned(),
            line: line_of(&text, at),
            path,
            name: text[name_start..name_end].to_owned(),
        });
    }
    out
}

/// The file a declaration compiles, by rustc's module resolution: a
/// `#[path]` value resolves against the declaring file's own directory,
/// and without one the module directory is the declaring file's directory
/// for `mod.rs` / `lib.rs` / `main.rs` and `<dir>/<stem>` otherwise.
///
/// `None` when nothing is there, which leaves the file in the corpus —
/// the safe direction, reported by
/// [`every_test_only_module_declaration_resolves`].
fn resolve_test_module(root: &Path, decl: &TestModuleDecl) -> Option<PathBuf> {
    let declared = root.join(&decl.declared_in);
    let dir = declared.parent()?;
    if let Some(path) = &decl.path {
        let target = dir.join(path);
        return target.is_file().then_some(target);
    }
    let stem = declared.file_stem()?.to_string_lossy().to_string();
    let module_dir = if matches!(stem.as_str(), "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    [
        module_dir.join(format!("{}.rs", decl.name)),
        module_dir.join(&decl.name).join("mod.rs"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// Every declaration found across the corpus, paired with the file it
/// resolves to.
fn test_module_declarations(root: &Path) -> Vec<(TestModuleDecl, Option<PathBuf>)> {
    production_sources(root)
        .into_iter()
        .flat_map(|path| {
            let rel = relative(root, &path);
            let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
            test_module_decls(&rel, &source)
        })
        .map(|decl| {
            let resolved = resolve_test_module(root, &decl);
            (decl, resolved)
        })
        .collect()
}

/// The files that exist only as test modules of another file.
fn cfg_test_module_files(root: &Path) -> BTreeSet<PathBuf> {
    test_module_declarations(root)
        .into_iter()
        .filter_map(|(_, resolved)| resolved)
        .collect()
}

// ---------------------------------------------------------------------------
// Function extents, so a construction can be attributed to a definition.
// ---------------------------------------------------------------------------

/// One `fn` item in blanked text, with the byte extent of its body.
#[derive(Debug, PartialEq, Eq)]
struct Fun {
    name: String,
    /// The body, braces included.
    body: Range<usize>,
}

/// Every `fn` item in `text`, nested ones included — a construction
/// inside a helper defined inside another function is attributed to the
/// helper, which is the innermost definition it belongs to.
fn functions(text: &str) -> Vec<Fun> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 2 < bytes.len() {
        // The `fn` keyword on a token boundary, followed by a name —
        // which is what rules out the `fn(&str) -> bool` pointer type.
        if !(bytes[at] == b'f'
            && bytes[at + 1] == b'n'
            && starts_a_token(bytes, at)
            && bytes[at + 2].is_ascii_whitespace())
        {
            at += 1;
            continue;
        }
        let name_start = skip_ws(bytes, at + 2);
        let mut name_end = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            at += 1;
            continue;
        }
        // Walk the signature to the body's `{`, or to the `;` of a
        // bodiless declaration. Generic bounds and `where` clauses carry
        // neither at paren/bracket depth zero.
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
            // which is what the caller wants here: a truncated body would
            // read as a function that constructs nothing.
            let close = block_end(bytes, brace).map_or(bytes.len(), |end| end + 1);
            out.push(Fun {
                name: text[name_start..name_end].to_owned(),
                body: brace..close,
            });
        }
        at = name_end;
    }
    out
}

/// The innermost function whose body encloses `at`.
fn innermost_fn(funs: &[Fun], at: usize) -> Option<&Fun> {
    funs.iter()
        .filter(|fun| fun.body.contains(&at))
        .min_by_key(|fun| fun.body.end - fun.body.start)
}

// ---------------------------------------------------------------------------
// The matcher.
// ---------------------------------------------------------------------------

/// One expression that brings a fresh `Options` value into existence.
#[derive(Debug, PartialEq, Eq)]
struct Site {
    /// The spelling, as [`CONSTRUCTION_FORMS`] labels it.
    form: String,
    /// 1-based line of the construction.
    line: usize,
    /// The innermost enclosing function's name; `None` when the
    /// construction sits outside every function body.
    in_fn: Option<String>,
}

/// Everything this guard reads out of one file's production text.
#[derive(Debug, PartialEq, Eq, Default)]
struct FileScan {
    sites: Vec<Site>,
    /// The body text of every [`SANCTIONED_FN`] definition in the file.
    definitions: Vec<String>,
}

/// Scan one file's source.
fn scan_source(source: &str) -> FileScan {
    let text = production_region(source);
    let needles_present = CONSTRUCTION_FORMS
        .iter()
        .any(|(needle, _)| text.contains(needle))
        || text.contains(SANCTIONED_FN);
    if !needles_present {
        return FileScan::default();
    }
    let bytes = text.as_bytes();
    let funs = functions(&text);
    // Collected with their offsets and sorted on them, so a file with
    // more than one construction reports them in source order rather than
    // grouped by which spelling the matcher looked for first.
    let mut located: Vec<(usize, Site)> = Vec::new();
    for (needle, label) in CONSTRUCTION_FORMS {
        let mut cursor = 0usize;
        while let Some(found) = text[cursor..].find(needle) {
            let at = cursor + found;
            cursor = at + 1;
            // `options!` ends in `!`, which is not an identifier byte, so
            // the token test is about the left edge for that form and
            // about both edges for `Options::default`.
            if !is_token(bytes, at, needle) {
                continue;
            }
            located.push((
                at,
                Site {
                    form: (*label).to_owned(),
                    line: line_of(&text, at),
                    in_fn: innermost_fn(&funs, at).map(|fun| fun.name.clone()),
                },
            ));
        }
    }
    located.sort_by_key(|(at, _)| *at);
    let sites: Vec<Site> = located.into_iter().map(|(_, site)| site).collect();
    let definitions = funs
        .iter()
        .filter(|fun| fun.name == SANCTIONED_FN)
        .map(|fun| text[fun.body.clone()].to_owned())
        .collect();
    FileScan { sites, definitions }
}

// ---------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/<crate>")
        .to_path_buf()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

fn walk_rust(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rust(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
///
/// The scope is derived rather than enumerated: a crate's `src` tree *is*
/// its production code, and a `tests/` target is outside it by
/// construction rather than by an entry.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut out);
        }
    }
    out.sort();
    out
}

/// One scanned site with the file it was found in.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    rel: String,
    site: Site,
}

/// The whole scan, assembled so every test reads the same corpus once.
#[derive(Debug, Default)]
struct Scan {
    sites: Vec<Found>,
    /// `(file, body)` for every [`SANCTIONED_FN`] definition.
    definitions: Vec<(String, String)>,
    /// How many files were read, so a collapsed corpus is visible.
    files: usize,
}

fn scan(root: &Path) -> Scan {
    let test_only = cfg_test_module_files(root);
    let mut out = Scan::default();
    for path in production_sources(root) {
        if test_only.contains(&path) {
            continue;
        }
        out.files += 1;
        let rel = relative(root, &path);
        let source = fs::read_to_string(&path).expect("production source is readable UTF-8");
        let scanned = scan_source(&source);
        for site in scanned.sites {
            out.sites.push(Found {
                rel: rel.clone(),
                site,
            });
        }
        for body in scanned.definitions {
            out.definitions.push((rel.clone(), body));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The assertions.
// ---------------------------------------------------------------------------

#[test]
fn the_options_value_is_constructed_only_in_the_gitops_definition() {
    let scan = scan(&workspace_root());
    let strays: Vec<String> = scan
        .sites
        .iter()
        .filter(|found| found.site.in_fn.as_deref() != Some(SANCTIONED_FN))
        .map(|found| {
            let where_ = match &found.site.in_fn {
                Some(name) => format!("in `fn {name}`"),
                None => "outside every function body".to_owned(),
            };
            format!(
                "{}:{} — {} {where_}",
                found.rel, found.site.line, found.site.form
            )
        })
        .collect();

    assert!(
        strays.is_empty(),
        "a `serde_saphyr::Options` value is constructed outside \
         `fn {SANCTIONED_FN}` ({} site(s)). A second construction is a \
         second definition of what an operator's gitops file means, and \
         the two cannot drift from each other in a way any test can see — \
         each stays internally consistent while the *meaning* differs per \
         call site. It also silently drops the six field assignments the \
         one definition carries, one of which is a security control: at \
         the parser's stock options a rendered syntax error echoes the \
         offending source line and its neighbours into the boot log and \
         the apply-time linter output, reproducing a plaintext credential \
         near the error verbatim. Parse through this crate's \
         `yaml::from_slice` instead, or move the decision — the predicate \
         is `fn {SANCTIONED_FN}` by name, not a path, so the definition \
         may live wherever it belongs. There is no allow-list: a second \
         construction that genuinely belongs is a review conversation \
         about whether the gitops parse still has one meaning.\n\
         Stray constructions:\n  {}",
        strays.len(),
        strays.join("\n  ")
    );
}

/// Counter-assertion: the scan is looking at something real.
///
/// Without it, renaming the macro upstream, renaming [`SANCTIONED_FN`] or
/// emptying its body would leave the assertion above green over a corpus
/// that says nothing.
#[test]
fn the_scanned_corpus_is_real() {
    let scan = scan(&workspace_root());

    // A floor rather than an exact pin: the count moves with every file
    // added or moved, and nothing about the invariant depends on its
    // value — what it has to catch is the corpus collapsing, which is a
    // drop of two orders of magnitude (the `crates/` walk breaking, or
    // the test-only exclusion swallowing the tree), not a drift of ten.
    assert!(
        scan.files > 500,
        "the scan read {} production file(s) under crates/*/src — far \
         fewer than this workspace has, so it is answering about a corpus \
         that collapsed and its green verdict means nothing",
        scan.files
    );

    let definitions: Vec<&String> = scan.definitions.iter().map(|(rel, _)| rel).collect();
    assert_eq!(
        definitions.len(),
        1,
        "expected exactly one `fn {SANCTIONED_FN}` under crates/*/src, \
         found {}: {definitions:?}. Zero means the function was renamed \
         or removed and every assertion in this file is now vacuous — the \
         rename is the moment to re-read what the gitops parse promises. \
         More than one means the single definition became several, which \
         is the invariant itself failing",
        definitions.len()
    );

    assert_eq!(
        scan.sites.len(),
        1,
        "expected exactly one `serde_saphyr::Options` construction under \
         crates/*/src, found {}: {:?}. Zero means the scan's needles no \
         longer match how the value is built — the parser's `options!` \
         macro renamed, say — which makes the single-source assertion \
         above vacuously green",
        scan.sites.len(),
        scan.sites
    );

    let found = &scan.sites[0];
    assert_eq!(
        found.site.in_fn.as_deref(),
        Some(SANCTIONED_FN),
        "the one construction is at {}:{} and this guard expects it inside \
         `fn {SANCTIONED_FN}`",
        found.rel,
        found.site.line
    );

    let (rel, body) = &scan.definitions[0];
    let missing: Vec<&str> = SETTING_FIELDS
        .iter()
        .copied()
        .filter(|field| !body.contains(&format!("{field}:")))
        .collect();
    assert!(
        missing.is_empty(),
        "`fn {SANCTIONED_FN}` in {rel} no longer assigns {missing:?}. The \
         six assignments are the whole reason the definition exists, so a \
         definition that kept the name and lost them returns the parser's \
         stock options while the single-source assertion above stays \
         green — and the stock options are the ones that echo an \
         operator's source line into a service log. What the values must \
         be is the behavioural tests' subject; that they are set by name \
         is this one's. Note that the fields are read from code only: the \
         module documentation names all six in prose, and comments are \
         blanked before this census runs"
    );
}

/// Counter-assertion on the other exclusion mechanism: whole files
/// compiled only under `#[cfg(test)]` by a parent module's declaration.
///
/// A declaration this resolver cannot follow leaves its file in the
/// corpus, so the failure direction is a loud false positive rather than
/// a silent pass — but it is still worth naming, because the fix is to
/// teach the resolver rather than to work around the finding.
#[test]
fn every_test_only_module_declaration_resolves() {
    let root = workspace_root();
    let declarations = test_module_declarations(&root);

    assert!(
        !declarations.is_empty(),
        "no `{CFG_TEST} … mod <name>;` declaration was found under \
         crates/*/src. This workspace has them, so the matcher has \
         stopped recognising the form and whole test-only files are now \
         being scanned as production code"
    );

    let unresolved: Vec<String> = declarations
        .iter()
        .filter(|(_, resolved)| resolved.is_none())
        .map(|(decl, _)| {
            format!(
                "{}:{} — mod {}{}",
                decl.declared_in,
                decl.line,
                decl.name,
                decl.path
                    .as_deref()
                    .map(|path| format!(" (#[path = \"{path}\"])"))
                    .unwrap_or_default()
            )
        })
        .collect();
    assert!(
        unresolved.is_empty(),
        "{} test-only module declaration(s) resolve to no file, so the \
         file each one compiles stays in the production corpus and an \
         `Options` a test builds there would be reported as a \
         violation:\n  {}",
        unresolved.len(),
        unresolved.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's own behaviour.
// ---------------------------------------------------------------------------

/// The real definition's shape. The baseline: without it every trip-wire
/// below could be passing for the wrong reason.
#[test]
fn the_scanner_accepts_the_definition_as_the_one_construction() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! {\n        \
                   strict_booleans: true,\n        \
                   with_snippet: false,\n    \
                   }\n}";
    let scan = scan_source(planted);
    assert_eq!(
        scan.sites,
        vec![Site {
            form: "the `options!` macro".to_owned(),
            line: 2,
            in_fn: Some("gitops_options".to_owned()),
        }]
    );
    assert_eq!(scan.definitions.len(), 1);
}

/// The hazard this guard exists for: a new parse call beside its own
/// options value.
#[test]
fn the_scanner_trips_on_a_second_construction_in_another_function() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { strict_booleans: true }\n}\n\n\
                   fn parse_lenient(bytes: &[u8]) -> Result<Spec, Error> {\n    \
                   let opts = serde_saphyr::options! { merge_keys: Merge };\n    \
                   serde_saphyr::from_slice_with_options(bytes, opts)\n}";
    let scan = scan_source(planted);
    assert_eq!(
        scan.sites
            .iter()
            .map(|site| site.in_fn.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("gitops_options"), Some("parse_lenient")],
        "both constructions must be seen, each attributed to its own function"
    );
    let strays: Vec<&Site> = scan
        .sites
        .iter()
        .filter(|site| site.in_fn.as_deref() != Some(SANCTIONED_FN))
        .collect();
    assert_eq!(
        strays.len(),
        1,
        "the construction outside the sanctioned definition is the finding"
    );
}

/// Function scope, stated as a failing case: a second construction in the
/// **same file** as the sanctioned one — twelve lines below it, which is
/// where someone needing a parse would put it. A file-scoped rule is
/// satisfied by this and that is why the scope is the function.
#[test]
fn the_scanner_is_not_satisfied_by_the_right_file() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { with_snippet: false }\n}\n\n\
                   fn lenient_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::Options::default()\n}";
    let scan = scan_source(planted);
    assert_eq!(
        scan.sites
            .iter()
            .map(|site| (site.form.as_str(), site.in_fn.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("the `options!` macro", Some("gitops_options")),
            ("`Options::default`", Some("lenient_options")),
        ]
    );
}

/// `Options::default()` is the second spelling, and the builder methods
/// hang off it rather than starting a value of their own.
#[test]
fn the_scanner_reads_the_default_spelling_and_its_builders() {
    let planted = "fn opts() -> Options {\n    \
                   Options::default().with_properties(map)\n}";
    assert_eq!(
        scan_source(planted)
            .sites
            .iter()
            .map(|site| site.form.as_str())
            .collect::<Vec<_>>(),
        vec!["`Options::default`"],
        "one construction, not one per builder call"
    );
}

/// Passing `Options::default` as a function value produces the same fresh
/// value, so it is a construction even with no call parens beside it.
#[test]
fn the_scanner_reads_default_passed_as_a_function_value() {
    let planted = "fn opts(cached: Option<Options>) -> Options {\n    \
                   cached.unwrap_or_else(Options::default)\n}";
    assert_eq!(scan_source(planted).sites.len(), 1);
}

/// The prose hazard, and here it is certain rather than hypothetical: the
/// `yaml` module's documentation is itself about this invariant and names
/// the macro and every field. A scan that read comments would find a
/// whole census in the doc comment.
#[test]
fn the_scanner_is_not_satisfied_by_a_comment_naming_the_macro() {
    let planted = "//! A second `serde_saphyr::options! { … }` beside another\n\
                   //! parse call would be a second definition. Do not add one.\n\
                   /// Builds the options. Never call `Options::default()` instead.\n\
                   fn gitops_options() -> serde_saphyr::Options {\n    \
                   /* serde_saphyr::options! { emit_comments: true } used to be here */\n    \
                   serde_saphyr::options! { emit_comments: false }\n}";
    let scan = scan_source(planted);
    assert_eq!(
        scan.sites.len(),
        1,
        "comments are blanked before anything structural is read"
    );
    assert_eq!(scan.sites[0].line, 6);
}

/// A string literal naming the macro is not code either — and an
/// unblanked raw string is also where an unescaped `"` and a stray brace
/// live, which would break every body extent after it.
#[test]
fn the_scanner_is_not_fooled_by_a_literal_naming_the_macro() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   let _hint = r#\"write serde_saphyr::options! { } here\"#;\n    \
                   let _also = \"Options::default() is wrong\";\n    \
                   serde_saphyr::options! { crop_radius: 0 }\n}";
    let scan = scan_source(planted);
    assert_eq!(scan.sites.len(), 1);
    assert_eq!(scan.sites[0].in_fn.as_deref(), Some("gitops_options"));
}

/// Naming the type is not building one. The definition's own signature is
/// the case that matters: a matcher keyed on the bare type name would
/// report it.
#[test]
fn the_scanner_does_not_read_a_type_annotation_as_a_construction() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { strict_booleans: true }\n}\n\n\
                   fn parse(bytes: &[u8], options: serde_saphyr::Options) -> Out {\n    \
                   let reused: &serde_saphyr::Options = &options;\n    \
                   serde_saphyr::from_slice_with_options(bytes, reused.clone())\n}";
    assert_eq!(scan_source(planted).sites.len(), 1);
}

/// The neighbours that are not this type: the parser's serializer macros
/// and other crates' option builders, all excluded by the token boundary
/// rather than by an entry.
#[test]
fn the_scanner_ignores_other_options_types_and_macros() {
    let planted = "fn other() -> Mixed {\n    \
                   let a = serde_saphyr::ser_options! { indent: 2 };\n    \
                   let b = serde_saphyr::render_options! { width: 80 };\n    \
                   let c = zip::write::SimpleFileOptions::default();\n    \
                   let d = PgPoolOptions::default();\n    \
                   let e = my_options!(1);\n    \
                   (a, b, c, d, e)\n}";
    assert_eq!(scan_source(planted).sites, Vec::new());
}

/// A test building its own value is its own business, excluded by how it
/// is compiled.
#[test]
fn the_scanner_ignores_a_cfg_test_construction() {
    let planted = "fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { emit_comments: false }\n}\n\n\
                   #[cfg(test)]\nmod tests {\n    \
                   use super::*;\n    \
                   #[test]\n    \
                   fn stock_options_differ() {\n        \
                   let stock = serde_saphyr::Options::default();\n        \
                   assert!(stock.emit_comments);\n    \
                   }\n}";
    let scan = scan_source(planted);
    assert_eq!(scan.sites.len(), 1);
    assert_eq!(scan.sites[0].in_fn.as_deref(), Some("gitops_options"));
}

/// 22 files under `crates/*/src` carry production code after a column-0
/// `#[cfg(test)]` item, so blanking must be per item. A rule that
/// truncated at the first marker would lose everything below it — and in
/// this guard a blanked file is a silent pass.
#[test]
fn the_scanner_keeps_production_code_after_a_cfg_test_item() {
    let planted = "#[cfg(test)]\nuse std::sync::atomic::AtomicBool;\n\n\
                   #[cfg(test)]\nconst PROBE: u8 = 1;\n\n\
                   fn lenient_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::Options::default()\n}";
    let scan = scan_source(planted);
    assert_eq!(
        scan.sites
            .iter()
            .map(|site| (site.line, site.in_fn.as_deref()))
            .collect::<Vec<_>>(),
        vec![(8, Some("lenient_options"))],
        "the function below the markers must survive blanking"
    );
}

/// The shape that makes over-blanking a real hazard rather than a
/// theoretical one: a `#[cfg(test)]` **struct field**, which ends at a
/// comma. An item-extent rule looking only for `{` or `;` would run past
/// the field, past the struct's closing brace, and blank the function
/// below it.
#[test]
fn the_scanner_does_not_over_blank_a_cfg_test_struct_field() {
    let planted = "pub struct Parser {\n    \
                   strict: bool,\n    \
                   #[cfg(test)]\n    \
                   interrupt_after_parse: AtomicBool,\n\
                   }\n\n\
                   fn lenient_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::Options::default()\n}";
    assert_eq!(
        scan_source(planted)
            .sites
            .iter()
            .map(|site| site.line)
            .collect::<Vec<_>>(),
        vec![8]
    );
}

/// `#[cfg(any(test, feature = "test-support"))]` gates production-file
/// items that ship under a feature in this workspace, and is not a test
/// marker.
#[test]
fn the_scanner_does_not_treat_the_test_support_gate_as_a_test_marker() {
    let planted = "#[cfg(any(test, feature = \"test-support\"))]\n\
                   pub fn lenient_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::Options::default()\n}";
    assert_eq!(scan_source(planted).sites.len(), 1);
}

/// A brace inside a literal must not open a block: if it did, the body
/// extents after it would be wrong and a construction could be attributed
/// to the wrong function — or to none.
#[test]
fn the_scanner_survives_braces_inside_literals() {
    let planted = "fn describe(name: &str) -> String {\n    \
                   format!(\"{{{name}}} }} {{\")\n}\n\n\
                   fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { crop_radius: 0 }\n}";
    let scan = scan_source(planted);
    assert_eq!(scan.sites.len(), 1);
    assert_eq!(scan.sites[0].in_fn.as_deref(), Some("gitops_options"));
}

/// A construction outside every function body — a `static` initialiser,
/// say — is reported rather than silently attributed to nothing.
#[test]
fn the_scanner_reports_a_construction_outside_every_function() {
    let planted = "static STOCK: Lazy<serde_saphyr::Options> =\n    \
                   Lazy::new(serde_saphyr::Options::default);\n\n\
                   fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! { with_snippet: false }\n}";
    let scan = scan_source(planted);
    assert_eq!(scan.sites[0].in_fn, None);
    assert_eq!(scan.sites[0].line, 2);
}

/// The innermost enclosing definition is the one a construction belongs
/// to: a helper defined inside another function is not its parent.
#[test]
fn the_scanner_attributes_to_the_innermost_function() {
    let planted = "fn outer() -> serde_saphyr::Options {\n    \
                   fn inner() -> serde_saphyr::Options {\n        \
                   serde_saphyr::Options::default()\n    \
                   }\n    \
                   inner()\n}";
    assert_eq!(
        scan_source(planted).sites[0].in_fn.as_deref(),
        Some("inner")
    );
}

/// The settings census reads code, not prose: a definition whose fields
/// survive only in its doc comment must not satisfy it.
#[test]
fn the_settings_census_is_not_satisfied_by_a_doc_comment() {
    let planted = "/// Sets duplicate_keys: Error, merge_keys: AsOrdinary,\n\
                   /// strict_booleans: true, with_snippet: false,\n\
                   /// crop_radius: 0 and emit_comments: false.\n\
                   fn gitops_options() -> serde_saphyr::Options {\n    \
                   serde_saphyr::options! {}\n}";
    let scan = scan_source(planted);
    assert_eq!(scan.definitions.len(), 1);
    let body = &scan.definitions[0];
    let found: Vec<&str> = SETTING_FIELDS
        .iter()
        .copied()
        .filter(|field| body.contains(&format!("{field}:")))
        .collect();
    assert_eq!(
        found,
        Vec::<&str>::new(),
        "a hollowed-out definition must not be vacuously green"
    );
}

/// The declaration matcher, on the two forms this workspace writes.
#[test]
fn the_scanner_reads_both_test_only_module_declaration_forms() {
    let planted = "#[cfg(test)]\n#[path = \"thing_tests.rs\"]\nmod tests;\n\n\
                   #[cfg(test)]\npub(crate) mod test_util;\n\n\
                   #[cfg(test)]\nmod inline {\n    fn helper() {}\n}";
    let decls = test_module_decls("crates/x/src/thing.rs", planted);
    assert_eq!(
        decls
            .iter()
            .map(|decl| (decl.path.as_deref(), decl.name.as_str()))
            .collect::<Vec<_>>(),
        vec![(Some("thing_tests.rs"), "tests"), (None, "test_util")],
        "the block-less forms compile another file; the inline module does not"
    );
}

/// Prose describing the declaration shape must not drop a production file
/// out of the corpus.
#[test]
fn the_declaration_matcher_ignores_a_comment_describing_the_shape() {
    let planted = "//! Declared with `#[cfg(test)] #[path = \"x.rs\"] mod tests;`\n\
                   //! in the parent file.\n\
                   fn production() {}";
    assert_eq!(
        test_module_decls("crates/x/src/thing.rs", planted),
        Vec::new()
    );
}
