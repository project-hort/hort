//! Structural guard: **the https rule for a metadata-supplied download URL
//! is defined in exactly one production location.**
//!
//! "A download URL recovered from an upstream metadata document must be
//! `https://`" is one rule with three kinds of consumer, and until the
//! consumers shared a definition it was written out at the call site five
//! separate times — twice in `hort-formats`' buffered helpers, once in
//! `NpmFormatHandler::resolve_download_url_from_metadata`, and once each in
//! the npm / PyPI inbound pull-through paths. The sixth consumer, the
//! prefetch task handler, had **no** copy at all: it read `urls[].url` and
//! `dist.tarball` raw and handed them to `UpstreamProxy::fetch_artifact`.
//!
//! That is not a coincidence of which site got forgotten. The consumer
//! without the check was the one with **no request behind it** — nothing
//! returns a 502 to a client, so a plaintext fetch on the autonomous path
//! produced no signal anyone was looking at. A rule that has to be
//! re-typed per consumer gets typed where someone is watching.
//!
//! So the fix is one definition — [`require_https_metadata_url`] in
//! `hort-domain` — and the thing that can silently undo it is **another
//! copy**: a new call site that re-spells the prefix test instead of
//! calling the rule. Nothing in the compiler stops that, which is why the
//! property is scanned.
//!
//! [`require_https_metadata_url`]: hort_domain::ports::format_handler::require_https_metadata_url
//!
//! ## The property
//!
//! Across the production Rust of the **upstream-metadata → fetch
//! pipeline** (see *Scope* below), an https-exclusive scheme comparison
//! against a URL string appears only in [`DEFINITION_FILE`].
//!
//! A *scheme comparison* is one of the [`SCHEME_TEST_FORMS`] — the prefix
//! test as all five pre-unit copies spelled it, plus the two
//! equality/remainder spellings of the same test. Building an https URL
//! (`format!("https://{host}")`) is deliberately not one: constructing an
//! https URL is not a rule about an untrusted one.
//!
//! *https-exclusive* means the enclosing statement does not also name
//! `"http://"`. A test that admits both schemes is an "is this an absolute
//! URL?" check, which is a different question with a different answer:
//! cargo's index `config.json` `dl` field accepts `http://` today, and
//! promoting that to an https-only rule would be a new operator contract
//! rather than the closing of a gap. Two production sites rely on this
//! distinction (`hort-formats/src/cargo.rs`, and the upstream-HTTP
//! adapter's absolute-URL detection) and neither is a defect.
//!
//! ## Scope — derived, not enumerated
//!
//! [`PIPELINE_CRATE_PATTERNS`] is the set of crates that can hold a
//! metadata-supplied download URL at all, and each entry is there because
//! of what the crate *is* under ADR 0008's layering:
//!
//! * `hort-domain` — the domain layer every other layer depends on, and
//!   therefore the only place a rule shared by `hort-app` and an
//!   `hort-http-*` crate can live. It holds the definition.
//! * `hort-formats` — the format handlers that parse upstream metadata
//!   documents (ADR 0005). The URL is born here.
//! * `hort-http-*` — the inbound adapters. The per-format ones drive
//!   pull-through and re-derive the URL off their own cached projections;
//!   the rest are in scope because the pattern is the crate family, not a
//!   hand-picked subset of it.
//! * `hort-app` — the application layer, whose prefetch task handlers
//!   resolve the same URL on the autonomous path.
//!
//! Every other crate is out of scope by the same derivation rather than by
//! an entry. An `hort-adapters-*` crate performs the fetch and never reads
//! a metadata document. `hort-config` and `hort-server` validate
//! **operator-declared** URLs — a gitops envelope's `upstream_url`, an
//! `OidcIssuer`'s `issuer_url`, the S3 endpoint env var. Those carry their
//! own https rules (`hort-config/src/upstream_mapping.rs` and
//! `oidc_issuer.rs` both spell one), and they are *different rules over a
//! different input*: an operator declaring a plaintext upstream has made a
//! decision, where an upstream *registry* asserting a plaintext download
//! URL is untrusted input. Folding them together would make "the one https
//! rule" a claim about two unrelated things.
//!
//! **No allow-list.** A site inside the pipeline that genuinely should
//! spell its own scheme test is a review conversation — it will almost
//! always want the rule instead — not an exemption entry.
//!
//! ## Counter-assertions
//!
//! A scan whose needle has been renamed out of existence is vacuously
//! green, which is how guards in this family die. So the test also asserts
//! the corpus is real:
//!
//! * the definition file still contains exactly one scheme comparison, and
//!   still defines the rule and its subject enum;
//! * every known call site still calls the rule, with the per-file counts
//!   pinned in [`EXPECTED_CALL_SITES`]. Deleting the call from the
//!   prefetch handler — the regression this unit closed — fails here even
//!   though the single-definition scan would still be green.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has: a scheme test assembled through a macro,
//! or written in a form outside [`SCHEME_TEST_FORMS`] (a parsed
//! `Url::scheme() != "https"` comparison, say — not a string-prefix test,
//! and not how any copy of this rule was ever written). And the scope: a
//! sixth copy appearing in a crate outside the pipeline would be missed,
//! which is the price of not policing the operator-configuration rules
//! that legitimately live there. The review check survives alongside it.
//!
//! Rust whole-line comments are dropped first so this file's own prose and
//! the prose at the call sites stay readable, and so does the inline test
//! module (everything from a column-0 `#[cfg(test)]` on, per the workspace
//! convention that such modules come last) — test code legitimately writes
//! scheme assertions about its own fixtures.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads`,
//! `cas_reads_are_verified` and `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// The one production file allowed to spell the rule.
const DEFINITION_FILE: &str = "crates/hort-domain/src/ports/format_handler.rs";

/// The rule, and the enum that carries the refusal wording. Named so a
/// rename of either fails the counter-assertion rather than quietly
/// emptying the scan.
const RULE_FN: &str = "require_https_metadata_url";
const RULE_SUBJECT_ENUM: &str = "MetadataUrlSubject";

/// How a URL *string* gets tested against the `https` scheme. The prefix
/// test is what all five pre-unit copies spelled; `strip_prefix` is the
/// same test written for its remainder, and the equality forms are it
/// written as a comparison.
const SCHEME_TEST_FORMS: &[&str] = &[
    "starts_with(\"https://\")",
    "strip_prefix(\"https://\")",
    "== \"https://\"",
    "!= \"https://\"",
];

/// The scheme literal whose presence in the same statement marks a test as
/// an absolute-URL check rather than this rule.
const PLAINTEXT_SCHEME: &str = "\"http://\"";

/// Path fragments selecting the upstream-metadata → fetch pipeline. See
/// the module docs for why each is in scope and why everything else is
/// not.
const PIPELINE_CRATE_PATTERNS: &[&str] = &[
    "crates/hort-domain/src/",
    "crates/hort-formats/src/",
    "crates/hort-http-",
    "crates/hort-app/src/",
];

/// Every production call site of the rule, with the number of calls each
/// makes. Pinned counts, not a presence check: the whole point of the
/// unit was that one consumer had **no** call, and a presence check cannot
/// tell "the npm arm still calls it" from "the npm arm and the PyPI
/// fan-out both do".
const EXPECTED_CALL_SITES: &[(&str, usize)] = &[
    // The format handlers that parse the metadata: npm's streaming
    // `resolve_download_url_from_metadata` and the buffered
    // `extract_upstream_tarball_url` / `extract_upstream_file_url` helpers.
    ("crates/hort-formats/src/npm.rs", 2),
    ("crates/hort-formats/src/pypi.rs", 1),
    // The inbound pull-through paths, re-deriving the URL off their own
    // cached projections.
    ("crates/hort-http-npm/src/upstream_pull.rs", 1),
    ("crates/hort-http-pypi/src/upstream_pull.rs", 1),
    // The autonomous path — the consumer that had no copy of the rule.
    ("crates/hort-app/src/task_handlers/prefetch_ingest.rs", 2),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rs(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Drop everything a rule about untrusted upstream input must not police:
/// the inline test module (and anything after it) plus whole-line
/// comments. Dropped lines become empty ones so line numbers still map
/// back to the original file.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for line in source.lines() {
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        if in_tests || line.trim_start().starts_with("//") {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The statement around `offset`: the text between the nearest `;`, `{` or
/// `}` on each side. Enough to tell `!x.starts_with("https://")` from
/// `!(x.starts_with("https://") || x.starts_with("http://"))`.
fn enclosing_statement(text: &str, offset: usize) -> &str {
    let start = text[..offset].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let end = text[offset..]
        .find([';', '{', '}'])
        .map_or(text.len(), |i| offset + i);
    &text[start..end]
}

/// Collapse whitespace so a call rustfmt split across lines reads as one
/// token sequence.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// [`squash`], but carrying for every retained byte the source line it came
/// from — so a scheme test rustfmt wrapped still matches AND the violation
/// still names a line a reader can open.
fn squash_with_lines(region: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(region.len());
    let mut lines: Vec<usize> = Vec::with_capacity(region.len());
    let mut line = 1usize;
    let mut pending_space = false;
    for ch in region.chars() {
        if ch == '\n' {
            line += 1;
        }
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            lines.push(line);
            pending_space = false;
        }
        out.push(ch);
        lines.resize(out.len(), line);
    }
    (out, lines)
}

/// `(relative path, line, statement)` for every https-exclusive scheme
/// comparison in the pipeline's production sources.
fn scheme_comparisons(root: &Path) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for path in production_sources(root) {
        let rel = relative(root, &path);
        if !PIPELINE_CRATE_PATTERNS.iter().any(|p| rel.starts_with(p)) {
            continue;
        }
        // Test-only harnesses: compiled under `cfg(any(test,
        // feature = "test-support"))`, so their fixtures are test data.
        if rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let (text, lines) = squash_with_lines(&production_region(&source));
        for form in SCHEME_TEST_FORMS {
            let mut search = 0usize;
            while let Some(found) = text[search..].find(form) {
                let at = search + found;
                search = at + 1;
                let statement = enclosing_statement(&text, at);
                if statement.contains(PLAINTEXT_SCHEME) {
                    continue;
                }
                out.push((rel.clone(), lines[at], statement.to_owned()));
            }
        }
    }
    out
}

fn count_in_file(root: &Path, rel: &str, needle: &str) -> usize {
    let source = fs::read_to_string(root.join(rel))
        .unwrap_or_else(|e| panic!("{rel} must exist and be readable UTF-8: {e}"));
    squash(&production_region(&source)).matches(needle).count()
}

#[test]
fn the_https_rule_has_exactly_one_definition() {
    let root = workspace_root();
    let stray: Vec<String> = scheme_comparisons(&root)
        .into_iter()
        .filter(|(rel, _, _)| rel != DEFINITION_FILE)
        .map(|(rel, line, statement)| format!("{rel}:{line} — {statement}"))
        .collect();

    assert!(
        stray.is_empty(),
        "a metadata-supplied download URL's `https://` rule is spelled \
         outside {DEFINITION_FILE} ({} site(s)). A second copy is a second \
         answer to one question, and the copies drift from their consumers \
         rather than from each other: the consumer that ended up with NO \
         copy was the prefetch task handler, the one with no request behind \
         it to turn a plaintext fetch into a 502 anyone would notice. Call \
         `hort_domain::ports::format_handler::{RULE_FN}` with the \
         appropriate `{RULE_SUBJECT_ENUM}` instead.\n\
         If the new site is testing whether a URL is ABSOLUTE rather than \
         whether it is https (cargo's `dl` field deliberately admits \
         `http://`), say so in the same statement and this guard will \
         recognise it as the different rule it is.\nStray definitions:\n  {}",
        stray.len(),
        stray.join("\n  ")
    );
}

#[test]
fn every_consumer_reaches_the_rule_rather_than_its_own_copy() {
    let root = workspace_root();
    let mut wrong: Vec<String> = Vec::new();
    for (rel, expected) in EXPECTED_CALL_SITES {
        let found = count_in_file(&root, rel, &format!("{RULE_FN}("));
        if found != *expected {
            wrong.push(format!(
                "{rel} — expected {expected} call(s), found {found}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the census of call sites no longer matches the tree. A call that \
         disappeared is a consumer that stopped applying the rule — which \
         the single-definition scan CANNOT see, because deleting a check \
         removes no copy. A call that appeared is a new consumer: welcome, \
         but pin it here deliberately so the next deletion is visible \
         too.\nMismatches:\n  {}",
        wrong.join("\n  ")
    );
}

/// Counter-assertion: the scan is looking at something. A rename of the
/// rule, the subject enum or the prefix-test spelling would otherwise make
/// both tests above pass by finding no code at all.
#[test]
fn the_scanned_corpus_is_real() {
    let root = workspace_root();

    let definitions: Vec<_> = scheme_comparisons(&root)
        .into_iter()
        .filter(|(rel, _, _)| rel == DEFINITION_FILE)
        .collect();
    assert_eq!(
        definitions.len(),
        1,
        "expected exactly one scheme comparison in {DEFINITION_FILE} — the \
         rule's own body. Found {}: {:?}. Zero means the scan's needle no \
         longer matches the rule (the single-definition test above is then \
         vacuously green); more than one means the rule grew a second \
         branch that needs reading before this count is updated",
        definitions.len(),
        definitions
    );

    assert!(
        count_in_file(&root, DEFINITION_FILE, &format!("pub fn {RULE_FN}(")) == 1,
        "{DEFINITION_FILE} must still define `{RULE_FN}` as a public free \
         function; if it moved, this guard is watching the wrong file"
    );
    assert!(
        count_in_file(
            &root,
            DEFINITION_FILE,
            &format!("pub enum {RULE_SUBJECT_ENUM}")
        ) == 1,
        "{DEFINITION_FILE} must still define `{RULE_SUBJECT_ENUM}`, the \
         closed set that carries each format's refusal wording"
    );

    // And the subject enum is actually used at the call sites — a rule
    // called with a single hard-coded subject would render one format's
    // wording for the other's refusal.
    for (rel, _) in EXPECTED_CALL_SITES {
        assert!(
            count_in_file(&root, rel, &format!("{RULE_SUBJECT_ENUM}::")) > 0,
            "{rel} calls the rule but names no `{RULE_SUBJECT_ENUM}` variant"
        );
    }
}
