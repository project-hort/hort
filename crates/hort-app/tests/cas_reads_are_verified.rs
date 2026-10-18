//! Structural guard: **every production CAS adapter verifies the bytes it
//! serves**, by constructing a `VerifyingReader` inside its own
//! `StoragePort::get`.
//!
//! ## The invariant
//!
//! A CAS read is only content-addressed if someone checks the address.
//! `StoragePort::get(hash)` promises a reader that accumulates SHA-256 as
//! bytes flow and, at EOF, fails the read rather than signalling a clean
//! end-of-stream when the accumulated digest differs — and that the
//! failure arrives as an `io::Error` carrying a
//! `hort_domain::ports::storage::CasIntegrityFailure { expected, computed }`
//! payload, so a consumer can tell at-rest corruption from a backend read
//! failure and can read back the digest the delivered bytes actually
//! hashed to.
//!
//! That promise was kept by hand at two sites, in two files, with nothing
//! holding it. A third adapter returning the backend's raw stream from
//! `get` compiles, passes clippy and passes the whole suite, and the only
//! thing it breaks is a guarantee no test states: `CasScrubUseCase`
//! silently loses the verifier's verdict, every corrupt blob reads as a
//! clean EOF, and the scrub's own independent re-hash becomes the sole
//! remaining control. This guard is what makes the wrap a property of the
//! port's production implementations rather than a convention two authors
//! happened to follow.
//!
//! ## One assertion, both halves of the contract
//!
//! The guard checks only that the wrap is constructed. It covers the
//! *distinguishable failure carrying the computed digest* half too, and
//! the reason is a measured fact rather than an argument:
//! `VerifyingReader::poll_read` is the **single production construction
//! point** of `CasIntegrityFailure` (`crates/hort-adapters-storage/src/
//! integrity.rs`; the only other spellings in the workspace are the
//! domain type's own `#[cfg(test)]` tests and `hort-app`'s test-support
//! mock, and `CasIntegrityFailure::into_io_error` is the single wrap into
//! an `io::Error`). So "the wrap is present" *implies* "a mismatch is
//! reported distinguishably and carries the digest", because there is one
//! component that can report it and one way for it to do so.
//!
//! **If that stops being true, this guard's reasoning breaks before the
//! guard does.** A second producer of the verdict — an adapter formulating
//! its own `CasIntegrityFailure`, or a second verifying reader — would
//! leave the guard green while the implication it rests on no longer
//! holds. Whoever adds one owns extending this file to name both
//! producers, or the guard becomes a check of a weaker property than its
//! name claims.
//!
//! ## Why the scope is derived rather than exempted
//!
//! The scan covers `crates/hort-adapters-*/src/**/*.rs`. That is a
//! structural statement, not a table of files to skip: an outbound
//! adapter lives in an `hort-adapters-*` crate because the dep graph puts
//! it there (ADR 0008 — nothing else in the workspace may depend on a
//! backend SDK), so scanning those crates' `src` trees *is* the statement
//! "every production storage adapter". **There is no allow-list**, as
//! with the sibling guards, and so no entry anyone can add to make a
//! finding go away; a site that genuinely should not carry the wrap is a
//! review conversation.
//!
//! Test doubles fall out for the same derived reason, and it is worth
//! being exact about which one, because two of them do live inside
//! adapter crates (`hort-adapters-postgres/src/purge_gc.rs`,
//! `hort-adapters-scanner-trivy/src/workspace.rs`). They are out of scope
//! because they are `#[cfg(test)]` items, which [`production_region`]
//! blanks — a property of how they are compiled, not a line in this file.
//! The rest are in `tests/` targets, outside `src` entirely.
//!
//! ## Function-scoped, not file-scoped
//!
//! A file that merely mentions `VerifyingReader` must not satisfy the
//! guard, and here that is not a hypothetical: **both** adapters carry a
//! doc comment on `get_range` that names `VerifyingReader` precisely in
//! order to say it is *not* applied there, and the `get` bodies carry
//! explanatory comments naming it as well. A file-scoped scan — or a
//! function-scoped one that read comments — would be satisfied by that
//! prose alone, and would stay green after the wrap itself was deleted.
//! So comments and literals are blanked first (`rust_scan::blank_noncode`),
//! the `#[cfg(test)]` items after them, and the wrap is then looked for in
//! the body of the `fn get` belonging to that specific `impl` block.
//!
//! ## Counter-assertion
//!
//! [`the_scan_still_finds_both_adapter_get_implementations`] pins the
//! scan's own reach: exactly the two known production implementations,
//! by implementing type and file. Without it, renaming the port, the
//! method or the reader would make the main assertion vacuously green —
//! the way a source-scan guard usually dies.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has. A `get` that delegates to a helper
//! which does the wrapping (`self.verified_reader(file, hash)`) reads as
//! unverified and is a false positive — correct to flag, since the guard
//! cannot see that the helper verifies, but it means the fix is a review
//! conversation about where the wrap belongs rather than a mechanical
//! edit. A wrap assembled through a macro is invisible. And the guard says
//! nothing about `get_range`, which deliberately does not verify (the
//! verifier hashes from offset 0 and compares at EOF, so a slice can only
//! ever mismatch) — that gap is recorded in the decision index as an
//! accepted risk, not closed here.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database and no gate-list entry — same family as `capped_stream_reads`,
//! `status_decode_fails_closed` and `db_tests_are_serialized`.

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

/// The port whose read method is under contract.
const PORT: &str = "StoragePort";

/// The method that must verify. `get_range` is deliberately not included
/// — see this module's blind-spot note.
const VERIFIED_METHOD: &str = "get";

/// The verifying wrap, as it is constructed. Pinned as the construction
/// expression rather than the bare type name so a mention in a type
/// annotation cannot satisfy the guard. Renaming the constructor turns
/// this red by design: the rename is exactly the moment to re-read what
/// the single construction point of `CasIntegrityFailure` is.
const VERIFIER: &str = "VerifyingReader::new";

/// What an `impl StoragePort for …` block does about read verification.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The block's own `fn get` constructs the verifier.
    Verifies,
    /// The block has a `fn get` and it does not.
    Unverified,
    /// The block has no `fn get` at all. `StoragePort::get` carries no
    /// default body, so a production implementation without one does not
    /// compile — reaching this means the scan stopped parsing the block,
    /// which is a finding about the guard and must not pass quietly.
    NoGet,
}

/// One production `impl StoragePort for …` block.
#[derive(Debug, PartialEq, Eq)]
struct PortImpl {
    /// The implementing type as written, e.g. `FilesystemStorage`.
    self_ty: String,
    /// 1-based line of the `impl` keyword.
    line: usize,
    verdict: Verdict,
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

/// The offset of the `>` closing the generic argument list whose `<` sits
/// at `open`, or `None` when they do not balance.
fn angle_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'<' => depth += 1,
            b'>' => {
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

/// The implementing type, when `header` — the text between the `impl`
/// keyword and the block's opening `{` — is a `StoragePort`
/// implementation.
///
/// `StoragePort` must sit in the **trait** position: the occurrence is
/// followed by nothing but whitespace and an optional balanced generic
/// argument list before the `for` keyword. That ordering is what tells
/// `impl StoragePort for X` apart from the two shapes that also name the
/// port in an `impl` header and are not implementations of it —
/// `impl<S: StoragePort> SomeTrait for Wrapper<S>` (an unbalanced `>` and
/// another trait name intervene) and `impl SomeTrait for Box<dyn
/// StoragePort>` (the `for` precedes). A path-qualified trait
/// (`impl hort_domain::ports::storage::StoragePort for X`) is accepted,
/// the `::` not being an identifier byte.
fn storage_port_self_type(header: &str) -> Option<String> {
    let header = before_where(header);
    let bytes = header.as_bytes();
    let mut from = 0usize;
    while let Some(found) = header[from..].find(PORT) {
        let at = from + found;
        from = at + PORT.len();
        if !is_token(bytes, at, PORT) {
            continue;
        }
        let mut cursor = skip_ws(bytes, at + PORT.len());
        if bytes.get(cursor) == Some(&b'<') {
            let Some(close) = angle_end(bytes, cursor) else {
                continue;
            };
            cursor = skip_ws(bytes, close + 1);
        }
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

/// True when `body` constructs the verifier: [`VERIFIER`] on a token
/// boundary, followed by a call's `(`.
fn constructs_the_verifier(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0usize;
    while let Some(found) = body[from..].find(VERIFIER) {
        let at = from + found;
        from = at + VERIFIER.len();
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        if bytes.get(skip_ws(bytes, at + VERIFIER.len())) == Some(&b'(') {
            return true;
        }
    }
    false
}

/// Every production `impl StoragePort for …` block in `source`, with the
/// verdict on its own `fn get`.
fn storage_port_impls(source: &str) -> Vec<PortImpl> {
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
        let Some(self_ty) = storage_port_self_type(&text[cursor..brace]) else {
            continue;
        };
        let body = match block_end(bytes, brace) {
            Some(close) => &text[brace..=close],
            None => &text[brace..],
        };
        let verdict = match parse_fns(body)
            .into_iter()
            .find(|item| item.name == VERIFIED_METHOD)
        {
            Some(get) if constructs_the_verifier(&get.body) => Verdict::Verifies,
            Some(_) => Verdict::Unverified,
            None => Verdict::NoGet,
        };
        out.push(PortImpl {
            self_ty,
            line: line_of(&text, at),
            verdict,
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
        for imp in storage_port_impls(&source) {
            out.push(Found {
                rel: rel.clone(),
                imp,
            });
        }
    }
    out
}

#[test]
fn every_adapter_storage_port_get_verifies_what_it_serves() {
    let root = workspace_root();
    let violations: Vec<String> = scan(&root)
        .into_iter()
        .filter(|found| found.imp.verdict != Verdict::Verifies)
        .map(|found| match found.imp.verdict {
            Verdict::Unverified => format!(
                "{}:{} — `impl {PORT} for {}`: its `fn {VERIFIED_METHOD}` hands \
                 back a stream it never verified",
                found.rel, found.imp.line, found.imp.self_ty
            ),
            _ => format!(
                "{}:{} — `impl {PORT} for {}`: no `fn {VERIFIED_METHOD}` found in \
                 the block, which `{PORT}` has no default body for — the scan \
                 failed to parse this impl",
                found.rel, found.imp.line, found.imp.self_ty
            ),
        })
        .collect();

    assert!(
        violations.is_empty(),
        "every production CAS adapter must verify the bytes it serves: wrap \
         the backend reader in `{VERIFIER}(reader, expected_hash, …)` before \
         returning it from `{PORT}::{VERIFIED_METHOD}` (ADR 0003, the \
         read-verification amendment). The wrap is not an optimisation and \
         not per-backend taste — it is the only production producer of the \
         `CasIntegrityFailure` verdict, so an adapter without it does not \
         merely skip a check: it makes at-rest corruption indistinguishable \
         from a clean read for every consumer, and `CasScrubUseCase` sweeps \
         corrupt storage reporting success. There is no allow-list; an \
         adapter that genuinely cannot verify is a review conversation about \
         whether it may serve CAS reads at all. {} adapter(s) below:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

/// Counter-assertion: the scan still reaches the implementations it is
/// about.
///
/// Every sibling guard carries one, and for the same reason: a rename of
/// the port, the method or the reader would otherwise leave
/// [`every_adapter_storage_port_get_verifies_what_it_serves`] green over
/// an empty corpus. The pair is deliberately exact rather than a
/// non-empty check — a new production storage adapter must be read by a
/// human against this contract, and an added entry here is that reading.
#[test]
fn the_scan_still_finds_both_adapter_get_implementations() {
    let found = scan(&workspace_root());
    let shape: Vec<(String, String)> = found
        .iter()
        .map(|f| (f.rel.clone(), f.imp.self_ty.clone()))
        .collect();

    assert!(
        !shape.is_empty(),
        "the scan found no `impl {PORT} for …` anywhere under \
         crates/{ADAPTER_CRATE_PREFIX}*/src — it is answering about an empty \
         corpus, so its green verdict means nothing. Either the port, the \
         method or the adapter crates were renamed, or the matcher broke"
    );
    assert_eq!(
        shape,
        vec![
            (
                "crates/hort-adapters-storage/src/filesystem.rs".to_string(),
                "FilesystemStorage".to_string()
            ),
            (
                "crates/hort-adapters-storage/src/object_store_backend.rs".to_string(),
                "ObjectStoreStorage".to_string()
            ),
        ],
        "the two production CAS adapters are the corpus this guard is about. \
         A third one is not a reason to edit this list on the way past: read \
         its `{VERIFIED_METHOD}` against ADR 0003's read-verification \
         amendment first, then add it"
    );
}

// ---------------------------------------------------------------------------
// Self-checks on planted source — the matcher's own behaviour.
// ---------------------------------------------------------------------------

/// An adapter-shaped `get` that wraps. The baseline: without it, every
/// trip-wire below could be passing for the wrong reason.
#[test]
fn the_scanner_accepts_a_get_that_constructs_the_verifier() {
    let planted = "impl StoragePort for FilesystemStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   let file = open(hash);\n        \
                   Ok(Box::new(VerifyingReader::new(file, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "FilesystemStorage".to_string(),
            line: 1,
            verdict: Verdict::Verifies,
        }]
    );
}

#[test]
fn the_scanner_trips_on_a_get_that_returns_the_raw_backend_stream() {
    let planted = "impl StoragePort for ThirdPartyStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "ThirdPartyStorage".to_string(),
            line: 1,
            verdict: Verdict::Unverified,
        }]
    );
}

/// The shape both real adapters actually carry: a doc comment on
/// `get_range` that names the verifier in order to say it does not apply
/// there. A file-scoped scan is satisfied by this sentence alone.
#[test]
fn the_scanner_is_not_satisfied_by_a_comment_naming_the_verifier() {
    let planted = "impl StoragePort for ThirdPartyStorage {\n    \
                   /// Note: range reads SKIP the `VerifyingReader::new` check\n    \
                   /// that `get` applies.\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   // VerifyingReader::new(file, hash, None) used to live here.\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted)[0].verdict,
        Verdict::Unverified,
        "comments are blanked before anything structural is read"
    );
}

/// Function scoping, the other direction: a wrap that is present in the
/// same impl block but in `get_range` does not discharge `get`.
#[test]
fn the_scanner_does_not_let_get_range_discharge_get() {
    let planted = "impl StoragePort for ThirdPartyStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n    \
                   fn get_range(&self, hash: &ContentHash, r: ByteRange) -> Reader {\n        \
                   Ok(Box::new(VerifyingReader::new(self.backend.open(hash)?, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(storage_port_impls(planted)[0].verdict, Verdict::Unverified);
}

/// `get_range` is not `get`: an impl whose only wrapped method is the
/// range read reports a missing `get`, not a satisfied one.
#[test]
fn the_scanner_reports_an_impl_with_no_get_at_all() {
    let planted = "impl StoragePort for ThirdPartyStorage {\n    \
                   fn exists(&self, hash: &ContentHash) -> bool { true }\n}";
    assert_eq!(storage_port_impls(planted)[0].verdict, Verdict::NoGet);
}

/// A `#[cfg(test)]` test double inside an adapter crate is out of scope
/// because of how it is compiled — the shape of
/// `hort-adapters-postgres/src/purge_gc.rs` and
/// `hort-adapters-scanner-trivy/src/workspace.rs`.
#[test]
fn the_scanner_ignores_a_cfg_test_double() {
    let planted = "#[cfg(test)]\nmod tests {\n    \
                   use super::*;\n    \
                   impl StoragePort for StubStorage {\n        \
                   fn get(&self, hash: &ContentHash) -> Reader { unimplemented!() }\n    \
                   }\n}";
    assert!(storage_port_impls(planted).is_empty());
}

/// The adapter crates attach `#[cfg(test)]` to individual items with
/// production code after them, so blanking must be per-item. A rule that
/// truncated at the first marker would lose the impl below it.
#[test]
fn the_scanner_keeps_production_code_after_a_cfg_test_item() {
    let planted = "#[cfg(test)]\nuse std::sync::atomic::{AtomicBool, Ordering};\n\n\
                   #[cfg(test)]\nconst PROBE: [u8; 2] = [1, 2];\n\n\
                   impl StoragePort for FilesystemStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "FilesystemStorage".to_string(),
            line: 7,
            verdict: Verdict::Unverified,
        }],
        "a per-item blanking rule keeps the impl that follows the markers"
    );
}

/// The shape that makes over-blanking a real hazard rather than a
/// theoretical one: `hort-adapters-postgres/src/purge_gc.rs` attaches
/// `#[cfg(test)]` to a **struct field**, which ends at a comma. An
/// item-extent rule that looked only for `{` or `;` would run past the
/// field, past the struct's closing brace, and blank the whole `impl`
/// block below it — and in this guard a blanked impl is a silent pass,
/// not a visible error.
#[test]
fn the_scanner_does_not_over_blank_a_cfg_test_struct_field() {
    let planted = "pub struct PgBackedStorage {\n    \
                   pool: PgPool,\n    \
                   #[cfg(test)]\n    \
                   interrupt_after_append: AtomicBool,\n\
                   }\n\n\
                   impl StoragePort for PgBackedStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "PgBackedStorage".to_string(),
            line: 7,
            verdict: Verdict::Unverified,
        }],
        "the impl below a comma-terminated `#[cfg(test)]` field must survive \
         blanking, or the guard passes by not looking"
    );
}

/// The same hazard in expression position: a `#[cfg(test)]` struct-literal
/// field and a `#[cfg(test)]` statement, both from `purge_gc.rs`.
#[test]
fn the_scanner_does_not_over_blank_a_cfg_test_statement_or_literal_field() {
    let planted = "impl PgBackedStorage {\n    \
                   fn new(pool: PgPool) -> Self {\n        \
                   Self {\n            \
                   pool,\n            \
                   #[cfg(test)]\n            \
                   interrupt_after_append: AtomicBool::new(false),\n        \
                   }\n    \
                   }\n    \
                   fn append(&self) -> Result<()> {\n        \
                   #[cfg(test)]\n        \
                   if self.interrupt_after_append.swap(false, Ordering::SeqCst) {\n            \
                   return Err(injected());\n        \
                   }\n        \
                   Ok(())\n    \
                   }\n}\n\n\
                   impl StoragePort for PgBackedStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(VerifyingReader::new(file, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "PgBackedStorage".to_string(),
            line: 18,
            verdict: Verdict::Verifies,
        }]
    );
}

/// `#[cfg(any(test, feature = "test-support"))]` gates production-file
/// items in this workspace and is not a test marker.
#[test]
fn the_scanner_does_not_treat_the_test_support_gate_as_a_test_marker() {
    let planted = "#[cfg(any(test, feature = \"test-support\"))]\npub mod test_support;\n\n\
                   impl StoragePort for FilesystemStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(storage_port_impls(planted)[0].verdict, Verdict::Unverified);
}

/// The port named in a generic bound is not the trait being implemented.
#[test]
fn the_scanner_ignores_the_port_in_a_generic_bound() {
    let planted = "impl<S: StoragePort> MetadataMirror for Mirror<S> {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader { self.inner.get(hash) }\n}";
    assert!(storage_port_impls(planted).is_empty());
}

/// The port named in the self type is not the trait being implemented
/// either.
#[test]
fn the_scanner_ignores_the_port_in_a_self_type() {
    let planted = "impl Describe for Box<dyn StoragePort> {\n    \
                   fn get(&self) -> &str { \"storage\" }\n}";
    assert!(storage_port_impls(planted).is_empty());
}

/// A path-qualified trait is the same implementation.
#[test]
fn the_scanner_reads_a_path_qualified_port() {
    let planted = "impl hort_domain::ports::storage::StoragePort for S3Storage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(VerifyingReader::new(r, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted)[0].self_ty,
        "S3Storage",
        "`::` is not an identifier byte, so the qualified path still reads as \
         the trait position"
    );
}

/// Generics on both the impl and the self type, plus a `where` clause —
/// the self type must come back without it.
#[test]
fn the_scanner_reads_a_generic_impl_with_a_where_clause() {
    let planted = "impl<R> StoragePort for Tiered<R>\nwhere\n    R: Backend,\n{\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(VerifyingReader::new(r, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted),
        vec![PortImpl {
            self_ty: "Tiered<R>".to_string(),
            line: 1,
            verdict: Verdict::Verifies,
        }]
    );
}

/// A brace inside a string literal must not open a block: if it did, the
/// impl body would end early and the wrap inside it would be lost. Both
/// real adapters build staging paths with `format!`.
#[test]
fn the_scanner_survives_braces_inside_literals() {
    let planted = "impl StoragePort for FilesystemStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   let probe = \"{\";\n        \
                   let staging = format!(\".tmp.{}\", id);\n        \
                   Ok(Box::new(VerifyingReader::new(file, hash.clone(), None)))\n    \
                   }\n}";
    assert_eq!(storage_port_impls(planted)[0].verdict, Verdict::Verifies);
}

/// The construction expression, not the type name: a type annotation
/// mentioning the reader does not wrap anything.
#[test]
fn the_scanner_requires_a_construction_not_a_mention() {
    let planted = "impl StoragePort for ThirdPartyStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   let _unused: Option<VerifyingReader<File>> = None;\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(storage_port_impls(planted)[0].verdict, Verdict::Unverified);
}

/// `impl` is a substring of ordinary identifiers; the keyword only
/// counts on a token boundary.
#[test]
fn the_scanner_does_not_read_the_keyword_out_of_an_identifier() {
    let planted = "fn simple_storage_port_for_tests() -> bool { true }";
    assert!(storage_port_impls(planted).is_empty());
}

/// An inherent `impl` block carries no `for` and is not an
/// implementation of anything.
#[test]
fn the_scanner_ignores_an_inherent_impl() {
    let planted = "impl FilesystemStorage {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader { self.open(hash) }\n}";
    assert!(storage_port_impls(planted).is_empty());
}

/// Two adapters in one file are two findings, each judged on its own
/// `get` — the reason the verdict is per-impl rather than per-file.
#[test]
fn the_scanner_judges_each_impl_in_a_file_separately() {
    let planted = "impl StoragePort for Verified {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(VerifyingReader::new(file, hash.clone(), None)))\n    \
                   }\n}\n\n\
                   impl StoragePort for Raw {\n    \
                   fn get(&self, hash: &ContentHash) -> Reader {\n        \
                   Ok(Box::new(self.backend.open(hash)?))\n    \
                   }\n}";
    assert_eq!(
        storage_port_impls(planted)
            .into_iter()
            .map(|imp| (imp.self_ty, imp.verdict))
            .collect::<Vec<_>>(),
        vec![
            ("Verified".to_string(), Verdict::Verifies),
            ("Raw".to_string(), Verdict::Unverified),
        ]
    );
}
