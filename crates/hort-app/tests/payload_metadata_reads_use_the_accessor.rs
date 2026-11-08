//! Structural guard: **where an artifact's payload metadata lives is a
//! question exactly one function answers.**
//!
//! `ArtifactMetadata` carries the payload two ways. `metadata_blob ==
//! None` means `metadata` IS the full payload; `Some(hash)` means
//! `metadata` holds at most the handler's summary and the full payload
//! is a CAS object at `hash`. `ArtifactUseCase::load_full_metadata` is
//! the accessor that resolves the difference, and its three documented
//! cases — return the row's value, stream and deserialise the blob,
//! surface a malformed blob as `AppError::Storage` — are the whole of
//! what a reader needs to know.
//!
//! A reader that branches on `metadata_blob` itself takes on all three.
//! The npm packument hydrator did:
//!
//! ```ignore
//! let block = if row.metadata_blob.is_some() {
//!     ctx.artifact_use_case.load_full_metadata(row).await?
//! } else {
//!     row.metadata.clone()
//! };
//! ```
//!
//! and bought nothing by it — the accessor's `None` arm is that same
//! clone with no I/O, so the branch saved no round trip and only moved
//! the knowledge of the two shapes into a second place. What it cost is
//! what every second copy costs: the set of rows that are blob-backed
//! is not fixed. It grew when the spill decision started reading the
//! event cap, and it will grow again whenever a format's summary stops
//! fitting an event — a row with `metadata = Null` and a blob beside it
//! is now an ordinary outcome, and a hand-rolled `else` arm serving
//! `row.metadata` for it serves nothing at all. Through the accessor
//! that row reads the same as any other.
//!
//! ## The property, in two halves
//!
//! In production Rust under `crates/*/src`, outside the outbound
//! adapters:
//!
//! 1. [`ACCESSOR_FILE`] is the only file that reads the
//!    `metadata_blob` field.
//! 2. The accessor is the only function that reads an
//!    `ArtifactMetadata`'s `metadata` field.
//!
//! The scope is derived rather than enumerated, so there is **no
//! allow-list**. An `hort-adapters-*` crate is where an outbound port
//! is implemented (ADR 0008): the Postgres adapter binds the column on
//! the way out and reconciles the refcount edge that keeps the blob
//! alive, both of which are about the *reference* and neither of which
//! is a reader asking where an artifact's metadata lives. Every other
//! crate — `hort-app`, the per-format HTTP adapters, `hort-formats`,
//! the binaries — reaches the payload as a consumer, and a consumer
//! calls the accessor. A site that genuinely should not is a review
//! conversation, not an exemption entry.
//!
//! Writes are not reads and are not matched: `metadata_blob: value` in
//! a struct literal, a field declaration, a function parameter and the
//! `metadata_blob_max_bytes` config knob all stay green, because the
//! matcher takes only a field *access* — the token preceded by `.` —
//! and only as a whole token.
//!
//! ## Why half 2 needs its own scan
//!
//! Half 1 catches a reader that *announces itself*: branching on
//! `metadata_blob` is visible at the call site, so a reviewer reading
//! the hunk sees a second answer being written. Half 2 catches the
//! shape with no tell at all —
//!
//! ```ignore
//! let requires_python = metadata_map
//!     .get(&artifact.id)
//!     .and_then(|m| m.metadata.get("pkg_info"))
//!     .and_then(|p| p.get("requires_python"));
//! ```
//!
//! — which reads as an ordinary JSON field access and is only wrong
//! because of what the receiver is. It is the more dangerous of the
//! two, because it does not *branch*: it silently takes the no-blob
//! arm for every row, so a spilled row yields `None` and the caller
//! renders that as absence rather than as a failure. Three production
//! readers were doing it — PyPI's `data-requires-python`, OCI's pull
//! `Content-Type`, and the SBOM input the scan orchestrator threads
//! onto `ArtifactCoords` — and each turned a payload too large to
//! inline into a confident wrong answer: a release with no stated
//! Python requirement, a manifest served as the default media type, an
//! artifact scanned as having no dependencies.
//!
//! **`metadata` is not a summary.** The tempting defence is that a
//! reader wanting one field may read the row's own `metadata`, because
//! a spilled row still carries the handler's summary. It does not: a
//! format whose strategy is `MetadataStrategy::Inline` declares no
//! summary extractor at all (the trait default returns the full
//! payload, which by construction does not fit beside the hash either),
//! so the spill leaves `metadata` as `Null`. PyPI and OCI are both
//! `Inline`. Even for `HashReference`, a summary over the cap is
//! dropped to `Null` rather than trimmed. There is no row shape for
//! which the direct read is reliably cheaper *and* correct.
//!
//! ## How half 2 is scoped, with no allow-list
//!
//! `metadata` is a common field name — `ArtifactCoords`,
//! `ContentReference`, every gitops envelope and `tracing`'s own
//! `event.metadata()` all have one — so the scan cannot key on the
//! field name alone. It keys on the **receiver's provenance** instead,
//! at function granularity:
//!
//! - A **doorway** is a function that hands an `ArtifactMetadata` to a
//!   caller. The set is *derived*, not listed: every `fn` in
//!   [`PORT_FILE`] or [`ACCESSOR_FILE`] whose signature names
//!   [`TYPE`] after a `->` is one. Today that is
//!   `find_by_artifact_id`, `list_by_artifact_ids` and
//!   `batch_metadata`; a fourth added tomorrow is picked up without
//!   editing this file.
//! - A production function is **in scope** when its body calls a
//!   doorway, or its own signature names [`TYPE`] (so a future helper
//!   taking `&ArtifactMetadata` is covered too).
//! - Inside an in-scope function, any whole-token `.metadata` field
//!   access is a hit.
//!
//! Function granularity is what makes this precise rather than merely
//! conservative, and it is load-bearing in both directions.
//! `scan_orchestration.rs` reads `.metadata` three times in production:
//! twice off an `ArtifactCoords` in `try_extract_sbom` /
//! `extract_sbom_from_stored_payload`, which touch no doorway and are
//! correctly ignored, and once in `subject_for_artifact`, which is the
//! site that was wrong. A file-scoped scan would have had to choose
//! between missing the third and flagging the first two.
//!
//! The same granularity is why `hort-http-oci/src/referrers.rs` is
//! absent from this guard entirely: its `row.metadata.get(
//! "artifact_type")` reads a `ContentReference`'s own JSON sidecar —
//! a different type, written by the manifest PUT, with no
//! `metadata_blob` beside it and no spill path to follow — and nothing
//! in that file touches a doorway.
//!
//! ## Counter-assertions
//!
//! A scan for a symbol that no longer exists is vacuously green, the
//! failure mode of every guard in this family. So this one also asserts
//! that the accessor file still reads both fields, that the accessor is
//! still defined there, that something outside it still calls the
//! accessor (an accessor nobody calls is not single-sourcing anything),
//! that the derived doorway set still contains the three known
//! doorways by name, that the in-scope function census is still
//! non-empty and still reaches every crate it reaches today, and that
//! both matchers can still produce a hit at all.
//!
//! ## Blind spots
//!
//! The one every source scan has: a read reached through a macro, or
//! through a local helper in another file that hands back the two
//! shapes under a different name, is invisible here. For half 2 there
//! is one more: an in-scope function that hands its row to a
//! *differently-named* same-crate helper which does the reading. That
//! helper is not in scope unless its own signature names [`TYPE`] —
//! which, for a helper taking the row, it must. Test modules that
//! live under `src/` as their own file are skipped — see
//! [`is_test_module_file`] for why that is a compilation fact rather
//! than an exemption.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads` and
//! `cas_reads_are_verified`.

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    is_ident_byte, line_of, parse_fns, production_region, walk_rust, workspace_root, FnItem,
};

/// The one file allowed to read the field, because it holds the one
/// function that resolves what the field means.
const ACCESSOR_FILE: &str = "crates/hort-app/src/use_cases/artifact_use_case.rs";

/// The accessor every other reader calls instead.
const ACCESSOR: &str = "load_full_metadata";

/// The field. Matched as a whole token after a `.`, which is what keeps
/// `metadata_blob_max_bytes` and every struct-literal write out.
const FIELD: &str = "metadata_blob";

/// The *other* field of the pair — the payload itself. A common name,
/// so half 2 of the property scopes by receiver provenance rather than
/// by this token; see the module docstring.
const PAYLOAD_FIELD: &str = "metadata";

/// The type whose `metadata` field half 2 is about.
const TYPE: &str = "ArtifactMetadata";

/// Where the outbound port that hands out [`TYPE`] is declared. Read
/// together with [`ACCESSOR_FILE`] to derive the doorway set.
const PORT_FILE: &str = "crates/hort-domain/src/ports/artifact_metadata_repository.rs";

/// The doorways the derivation must still find, by name. Not an
/// allow-list — the opposite: a counter-assertion that the derived set
/// did not quietly go empty because a signature was reworded.
const KNOWN_DOORWAYS: [&str; 3] = [
    "find_by_artifact_id",
    "list_by_artifact_ids",
    "batch_metadata",
];

/// Crates whose `src/` is an outbound-adapter implementation (ADR
/// 0008): they bind and reconcile the column rather than read through
/// it.
const ADAPTER_CRATE_PREFIX: &str = "hort-adapters-";

/// Every in-scope `crates/<crate>/src/**/*.rs`, sorted so failures are
/// stable.
fn scanned_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = fs::read_dir(root.join("crates")).expect("crates/ must exist");
    for crate_dir in crates.flatten() {
        let name = crate_dir.file_name().to_string_lossy().to_string();
        if name.starts_with(ADAPTER_CRATE_PREFIX) {
            continue;
        }
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// Whether `relative` names a file that is test code despite living
/// under `src/`.
///
/// Two shapes, and neither is an exemption: `production_region` blanks
/// `#[cfg(test)]` *items*, so it cannot reach a test module declared as
/// its own file (`#[cfg(test)] mod tests;` — the workspace has several,
/// `hort-domain/src/events/tests.rs` and the `*_tests.rs` siblings in
/// `hort-app/src/use_cases/`), and a `test_support.rs` harness is
/// compiled under a feature rather than `cfg(test)`. Both build
/// fixtures by hand, which is legitimate and is what the guard in
/// `event_visibility_is_single_sourced` skips them for too. The
/// exclusion is about how a file is compiled, not about what it is
/// allowed to do.
fn is_test_module_file(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    name == "tests.rs" || name.ends_with("_tests.rs") || name == "test_support.rs"
}

/// Repo-relative path with forward slashes, for comparison against the
/// constants above.
fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Byte offsets in `production` of every `.`-prefixed whole-token
/// occurrence of [`FIELD`] — a field *access*, which is the read this
/// guard is about.
///
/// Both halves of the property run on [`reads_of`]: the read/write
/// discrimination is the same question for either field, and a second
/// copy of it is how one half would start accepting what the other
/// rejects.
fn field_reads(production: &str) -> Vec<usize> {
    reads_of(production, FIELD)
}

/// Every `file:line` outside [`ACCESSOR_FILE`] that reads the field.
fn reads_outside_the_accessor(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for path in scanned_sources(root) {
        let relative = rel(root, &path);
        if relative == ACCESSOR_FILE || is_test_module_file(&relative) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let production = production_region(&source);
        for at in field_reads(&production) {
            let line_no = line_of(&production, at);
            let line = source.lines().nth(line_no - 1).unwrap_or("").trim();
            out.push(format!("{relative}:{line_no}: {line}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Half 2: an `ArtifactMetadata`'s `metadata` field
// ---------------------------------------------------------------------------

/// Byte offsets in `production` of every `.`-prefixed whole-token
/// occurrence of `field`.
///
/// Generalises [`field_reads`] over the field name so both halves share
/// one matcher: the write/read discrimination that keeps
/// `metadata_blob_max_bytes` and struct-literal writes out is the same
/// discrimination that keeps `metadata: value` and
/// `event.metadata()` out, and stating it twice is how the two halves
/// would drift. The `(` exclusion is what rules out a *method* of the
/// same name — `tracing`'s `event.metadata()` is not a field.
fn reads_of(production: &str, field: &str) -> Vec<usize> {
    let bytes = production.as_bytes();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = production[cursor..].find(field) {
        let at = cursor + found;
        cursor = at + field.len();
        // Whole token: `metadata_blob` is not a read of `metadata`, and
        // `metadata_blob_max_bytes` is not a read of `metadata_blob`.
        if bytes.get(cursor).copied().is_some_and(is_ident_byte) {
            continue;
        }
        // A method call of the same name is not a field access.
        if bytes.get(cursor).copied() == Some(b'(') {
            continue;
        }
        // A read is a field access. `metadata:` (struct literal, field
        // declaration, parameter) and a bare `metadata` (init
        // shorthand, local binding) are writes or declarations.
        if at > 0 && bytes[at - 1] == b'.' {
            out.push(at);
        }
    }
    out
}

/// Every function in `blanked` whose signature names [`TYPE`] after a
/// `->`, i.e. that hands one to a caller.
///
/// `->` and not merely "names the type": a method *taking*
/// `&ArtifactMetadata` (the accessor itself) consumes a row rather than
/// sourcing one, and treating it as a doorway would put every caller of
/// the accessor in scope — which is every reader this guard wants to
/// see succeed.
fn doorways_declared_in(blanked: &str) -> Vec<String> {
    parse_fns(blanked)
        .into_iter()
        .filter(|item| {
            item.signature
                .split("->")
                .skip(1)
                .any(|ret| ret.contains(TYPE))
        })
        .map(|item| item.name)
        .collect()
}

/// The derived doorway set: every function in [`PORT_FILE`] or
/// [`ACCESSOR_FILE`] that returns a [`TYPE`].
fn doorways(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for file in [PORT_FILE, ACCESSOR_FILE] {
        let source = fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        out.extend(doorways_declared_in(&production_region(&source)));
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `item` holds an [`TYPE`] — it calls a doorway, or its own
/// signature names the type (a helper handed the row).
fn holds_a_row(item: &FnItem, doorways: &[String]) -> bool {
    if item.signature.contains(TYPE) {
        return true;
    }
    doorways
        .iter()
        .any(|door| item.body.contains(&format!("{door}(")))
}

/// Every in-scope production function outside the accessor, as
/// `(relative path, fn name, line)`.
fn in_scope_functions(root: &Path, doorways: &[String]) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    for path in scanned_sources(root) {
        let relative = rel(root, &path);
        if relative == ACCESSOR_FILE || is_test_module_file(&relative) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        for item in parse_fns(&production_region(&source)) {
            if holds_a_row(&item, doorways) {
                out.push((relative.clone(), item.name, item.line));
            }
        }
    }
    out.sort();
    out
}

/// Every `file:line` outside [`ACCESSOR_FILE`] where an in-scope
/// function reads a `.metadata` field.
fn payload_reads_outside_the_accessor(root: &Path, doorways: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for path in scanned_sources(root) {
        let relative = rel(root, &path);
        if relative == ACCESSOR_FILE || is_test_module_file(&relative) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let production = production_region(&source);
        for item in parse_fns(&production) {
            if !holds_a_row(&item, doorways) {
                continue;
            }
            for at in reads_of(&item.body, PAYLOAD_FIELD) {
                // `item.line` is the `fn` keyword's line and the body
                // starts at its `{`, so the offset inside the body
                // lands within one line of the real site — close
                // enough to navigate to, and the function name is the
                // precise anchor.
                let line_no = item.line + line_of(&item.body, at) - 1;
                out.push(format!(
                    "{relative}:{line_no}: in `fn {}` — {}",
                    item.name,
                    item.body
                        .lines()
                        .nth(line_of(&item.body, at) - 1)
                        .unwrap_or("")
                        .trim()
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn only_the_accessor_reads_an_artifact_metadata_payload_field() {
    let root = workspace_root();
    let doors = doorways(&root);
    let stray = payload_reads_outside_the_accessor(&root, &doors);
    assert!(
        stray.is_empty(),
        "a production function that holds an `{TYPE}` must not read its `{PAYLOAD_FIELD}` \
         field — that field is the full payload only when the payload fit in the \
         `ArtifactIngested` event. Past the cap it holds the handler's summary, or `Null` \
         where the format declares no summary extractor (every `MetadataStrategy::Inline` \
         format, which is PyPI, cargo and OCI), and a direct read then yields `None` with \
         no way to tell that from a field the publisher never set. The caller renders it \
         as absence: an omitted `data-requires-python`, a default pull media type, an \
         SBOM with no dependencies. Call `ArtifactUseCase::{ACCESSOR}` (or the free \
         `{ACCESSOR}` in {ACCESSOR_FILE}, if you hold a `StoragePort` rather than the use \
         case) — its no-blob arm is a clone with no I/O, so asking costs an unspilled row \
         nothing.\nDoorways in scope: {}\nStray reads:\n  {}",
        doors.join(", "),
        stray.join("\n  ")
    );
}

/// Counter-assertion: the doorway derivation still finds the doorways
/// it is supposed to. If a signature were reworded so that [`TYPE`]
/// stopped appearing after the `->`, the set would go empty, nothing
/// would be in scope, and the scan above would pass over a codebase
/// full of direct reads.
#[test]
fn the_doorway_derivation_still_finds_the_known_doorways() {
    let doors = doorways(&workspace_root());
    for known in KNOWN_DOORWAYS {
        assert!(
            doors.contains(&known.to_string()),
            "`{known}` must still be derived as a doorway — it hands out an `{TYPE}`, and \
             a doorway the derivation misses is a whole family of readers out of scope. \
             Derived set: {doors:?}"
        );
    }
}

/// Counter-assertion: the in-scope census is real and still reaches
/// every crate that holds a row today.
///
/// This is the half that a rename cannot make vacuously green. The
/// doorway assertion above proves the *names* survive; this proves the
/// names still match call sites. `batch_metadata` renamed at its
/// definition and every call site would keep
/// [`the_doorway_derivation_still_finds_the_known_doorways`] failing,
/// but a *new* reader in a crate that had none would otherwise slip in
/// unnoticed — so the crate set is asserted as an exact equality, and
/// widening it is a deliberate edit by whoever adds the reader.
#[test]
fn the_in_scope_census_is_real() {
    let root = workspace_root();
    let doors = doorways(&root);
    let scope = in_scope_functions(&root, &doors);
    assert!(
        !scope.is_empty(),
        "no production function outside {ACCESSOR_FILE} holds an `{TYPE}` — either every \
         reader went away, or the doorway derivation stopped matching call sites and this \
         guard is scanning nothing. Derived doorways: {doors:?}"
    );
    let mut crates: Vec<&str> = scope
        .iter()
        .map(|(relative, _, _)| relative.split('/').nth(1).unwrap_or(relative))
        .collect();
    crates.sort_unstable();
    crates.dedup();
    assert_eq!(
        crates,
        [
            "hort-app",
            // The port and lifecycle declarations themselves: bodiless
            // trait methods whose signatures name the type, so they are
            // in scope and trivially clean. They are what keeps the
            // derivation honest — if `hort-domain` vanished from this
            // list the doorway scan had stopped reading the port.
            "hort-domain",
            "hort-http-cargo",
            "hort-http-npm",
            "hort-http-oci",
            "hort-http-pypi",
        ],
        "the set of crates holding an `{TYPE}` changed. Every one of them is a reader that \
         must go through `{ACCESSOR}`; a crate appearing here for the first time is a new \
         read path, and a crate disappearing means the derivation stopped seeing it. \
         In-scope functions: {scope:#?}"
    );
}

/// Counter-assertion: half 2's matcher and scoping can still fail. Each
/// case is a shape the guard exists to reject or to let through.
#[test]
fn the_payload_matcher_and_the_scoping_discriminate() {
    // Reads of the payload field.
    assert_eq!(
        reads_of("m.metadata.get(\"pkg_info\")", PAYLOAD_FIELD).len(),
        1
    );
    assert_eq!(reads_of("|row| row.metadata", PAYLOAD_FIELD).len(), 1);

    // Writes, declarations and a method of the same name.
    assert!(reads_of("metadata: Value::Null,", PAYLOAD_FIELD).is_empty());
    assert!(reads_of("pub metadata: serde_json::Value,", PAYLOAD_FIELD).is_empty());
    assert!(reads_of("ArtifactCoords { metadata, .. }", PAYLOAD_FIELD).is_empty());
    assert!(
        reads_of("event.metadata().level()", PAYLOAD_FIELD).is_empty(),
        "`tracing`'s `event.metadata()` is a method, not a field"
    );
    // The paired field is a different token, both ways round.
    assert!(reads_of("row.metadata_blob.is_some()", PAYLOAD_FIELD).is_empty());
    assert_eq!(reads_of("row.metadata_blob.is_some()", FIELD).len(), 1);

    // Doorway derivation: a `->` mention is a doorway, a parameter
    // mention is not.
    let port = "fn find_by_artifact_id(&self, id: Uuid) \
                -> BoxFuture<'_, DomainResult<Option<ArtifactMetadata>>>;";
    assert_eq!(doorways_declared_in(port), ["find_by_artifact_id"]);
    let consumer = "fn load_full_metadata(&self, row: &ArtifactMetadata) -> AppResult<Value> {}";
    assert!(
        doorways_declared_in(consumer).is_empty(),
        "a function taking a row consumes one; it does not hand one out"
    );

    // Scoping, both ways round: a doorway call puts a function in
    // scope, a `.metadata` read with no doorway in sight does not.
    let doors = vec!["batch_metadata".to_string()];
    let reader = &parse_fns(
        "fn fetch() { let m = ctx.artifact_use_case.batch_metadata(&ids).await?; \
         let x = m.metadata.get(\"k\"); }",
    )[0];
    assert!(holds_a_row(reader, &doors));
    assert_eq!(reads_of(&reader.body, PAYLOAD_FIELD).len(), 1);

    let bystander =
        &parse_fns("fn extract(subject: &ScanSubject) { f(&subject.coords.metadata); }")[0];
    assert!(
        !holds_a_row(bystander, &doors),
        "a `.metadata` read on an `ArtifactCoords` in a function that touches no doorway \
         is not a hit — this is what makes the scan precise rather than merely \
         conservative"
    );
}

#[test]
fn only_the_accessor_reads_the_metadata_blob_field() {
    let root = workspace_root();
    let stray = reads_outside_the_accessor(&root);
    assert!(
        stray.is_empty(),
        "reading `{FIELD}` is asking where an artifact's payload metadata lives, \
         and `ArtifactUseCase::{ACCESSOR}` ({ACCESSOR_FILE}) is the one place that \
         answers it — row value, CAS blob, or a malformed blob as \
         `AppError::Storage`. A second answer is a second place that has to stay \
         right as the set of blob-backed rows grows: a spilled summary leaves \
         `metadata = Null`, and an `else` arm serving it hands a client nothing \
         while the accessor hands it the same fields as any other row. Call the \
         accessor — its no-blob arm is the same clone with no I/O, so asking \
         unconditionally costs an inline row nothing.\nStray reads:\n  {}",
        stray.join("\n  ")
    );
}

/// Counter-assertion: the accessor file still reads the field, and the
/// accessor is still defined there. Rename either and the scan above
/// would pass by finding no code at all.
#[test]
fn the_accessor_still_resolves_the_field_it_owns() {
    let root = workspace_root();
    let source = fs::read_to_string(root.join(ACCESSOR_FILE))
        .unwrap_or_else(|e| panic!("{ACCESSOR_FILE} must be readable: {e}"));
    let production = production_region(&source);
    assert!(
        !field_reads(&production).is_empty(),
        "{ACCESSOR_FILE} must still read `{FIELD}` — if it stopped, resolving the \
         two shapes moved somewhere this guard is not watching"
    );
    assert!(
        !reads_of(&production, PAYLOAD_FIELD).is_empty(),
        "{ACCESSOR_FILE} must still read `{PAYLOAD_FIELD}` — the no-blob arm returning \
         the row's own payload is half of what the accessor resolves, and a file that \
         stopped reading it is not resolving the pair any more"
    );
    assert!(
        production.contains(&format!("fn {ACCESSOR}")),
        "`{ACCESSOR}` must still be defined in {ACCESSOR_FILE}"
    );
}

/// Counter-assertion: something outside the accessor's own file calls
/// it. An accessor with no callers single-sources nothing, and would
/// leave the scan above green over a codebase that had gone back to
/// branching under another name.
#[test]
fn the_accessor_has_callers_outside_its_own_file() {
    let root = workspace_root();
    let mut callers = Vec::new();
    for path in scanned_sources(&root) {
        let relative = rel(&root, &path);
        if relative == ACCESSOR_FILE {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        if production_region(&source).contains(ACCESSOR) {
            callers.push(relative);
        }
    }
    assert!(
        !callers.is_empty(),
        "no production file outside {ACCESSOR_FILE} calls `{ACCESSOR}` — either \
         every reader went back to branching on the field, or the accessor is dead"
    );
}

/// Counter-assertion: the matcher can still fail. Each of these is the
/// shape the guard exists to reject or to let through, so a predicate
/// that had stopped discriminating shows up here rather than as a
/// silently green scan.
#[test]
fn the_matcher_discriminates_reads_from_writes() {
    // Reads.
    assert_eq!(field_reads("if row.metadata_blob.is_some() {}").len(), 1);
    assert_eq!(field_reads("match &row.metadata_blob {}").len(), 1);
    assert_eq!(field_reads("m.metadata_blob.as_ref()").len(), 1);

    // Writes and declarations.
    assert!(field_reads("metadata_blob: None,").is_empty());
    assert!(field_reads("pub metadata_blob: Option<ContentHash>,").is_empty());
    assert!(field_reads("ArtifactMetadata { metadata_blob, .. }").is_empty());

    // A different name that happens to start with this one.
    assert!(field_reads("self.metadata_blob_max_bytes > 0").is_empty());

    // Comments and literals are not code — `production_region` blanks
    // them, which is why the prose in this file does not fail it.
    assert!(field_reads(&production_region("// row.metadata_blob\n")).is_empty());
    assert!(field_reads(&production_region("let sql = \".metadata_blob\";")).is_empty());

    // The test-module classifier, both ways round: a file-level test
    // module is skipped, an ordinary production file is not.
    assert!(is_test_module_file(
        "crates/hort-domain/src/events/tests.rs"
    ));
    assert!(is_test_module_file(
        "crates/hort-app/src/use_cases/purge_use_case_tests.rs"
    ));
    assert!(is_test_module_file(
        "crates/hort-app/src/use_cases/test_support.rs"
    ));
    assert!(!is_test_module_file(
        "crates/hort-http-npm/src/index_source.rs"
    ));
}
