//! Source guard over every `.rs` file under `crates/`: an error on a
//! **quarantine-status** read or decode is never flattened into a
//! substituted status.
//!
//! A sibling of `db_gate_not_silent` in the same family and for the same
//! reason. That guard refuses a discarded error on a Postgres *connect*,
//! because a thrown-away error reports "no state" where the truth is
//! "state not readable". The mechanism had never been carried to the
//! decoding of security-relevant state, and the gap cost exactly what it
//! sounds like it would.
//!
//! ## The invariant
//!
//! `artifacts.quarantine_status` is the column every serving decision in
//! the system is a function of. [`QuarantineStatus::None`] — "nothing is
//! holding this artifact" — is simultaneously the most permissive state
//! (`Artifact::is_downloadable` admits it, and the default
//! `ReleasedOnly` index mode serves it) and the *default* a swallowed
//! decode naturally reaches for. So a discarded error on this column
//! does not degrade gracefully; it inverts. The row mapper did exactly
//! that:
//!
//! ```text
//! row.quarantine_status.as_deref().and_then(|s| s.parse().ok())
//!     .unwrap_or(QuarantineStatus::None)
//! ```
//!
//! and migration `003`'s CHECK accepts three prototype-era spellings
//! (`unscanned`, `clean`, `flagged`) the domain cannot parse — so a
//! schema-valid row was advertised and served with no release authority
//! behind it and no `ArtifactReleased` in its stream. The same
//! substitution appeared again on the two hot index-serve reads, and
//! again — as `unwrap_or_else(…) → Vec::new()`, "degrade to no status
//! known" — on the npm / PyPI / cargo proxy index sources, where an
//! empty status map re-advertises every version hort is deliberately
//! holding back.
//!
//! The rule this guard holds: a read that cannot classify an artifact
//! must not produce a classification. The error propagates and the
//! request fails.
//!
//! ## What counts as a hit
//!
//! One of the four discarding idioms — `.ok()`, `.unwrap_or(…)`,
//! `.unwrap_or_else(…)`, `.unwrap_or_default()` — applied where
//! **either** the receiver it discards **or** the fallback it
//! substitutes names the quarantine status ([`STATUS_NAMES`]).
//!
//! Both halves are load-bearing, and each catches a shape the other
//! misses:
//!
//! * **The receiver.** `…package_version_status(…).await.unwrap_or_else(…)`
//!   names nothing about a status in its fallback (the fallback is
//!   `Vec::new()`), but what it throws away is the status read itself.
//! * **The fallback.** `status_str.as_deref().and_then(|s| s.parse().ok())
//!   .unwrap_or(QuarantineStatus::None)` has a receiver that mentions no
//!   status name at all (`status_str`), but substitutes one.
//!
//! Asking about the *receiver* rather than the whole statement is what
//! keeps the guard honest instead of merely loud. Two real sites in the
//! tree discard something next to a status without discarding a status,
//! and neither is a defect:
//!
//! * a CLI table row whose `version` cell falls back to `"-"` while a
//!   `quarantine_status` cell sits beside it in the same `vec![]`;
//! * `ScanOrchestration`'s retry-exhausted arm, which discards an
//!   *artifact load* error and documents where the resulting `None`
//!   routes — into `record_scan_indeterminate`, the stricter outcome,
//!   which re-loads and propagates the same error.
//!
//! A statement-scoped scan calls both of those findings. A
//! receiver-scoped one does not, and needs no allow-list to avoid
//! them — which matters, because an allow-list is how the next real
//! site gets added to a file instead of to a review.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! The one every source scan has: a decode reached through a
//! differently-named local helper (`map_status(raw).ok()` would pass),
//! or built by a macro. The review check survives alongside the guard,
//! exactly as it does for `db_tests_are_serialized`.
//!
//! [`QuarantineStatus::None`] carries no `Default` impl today, so
//! `unwrap_or_default()` cannot currently produce one; the idiom is
//! scanned anyway, because adding that impl is a one-line change and
//! the guard should not need updating on the same day.
//!
//! Rust line comments (`//`, `///`, `//!`) are stripped first — prose
//! describing the fixed pattern must stay readable, and the compiler
//! does not read comments. Whitespace is then squashed, so a call
//! rustfmt split across five lines reads as one token sequence.
//!
//! [`QuarantineStatus::None`]: hort_domain::entities::artifact::QuarantineStatus::None

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// Identifiers that make an expression a quarantine-status expression:
/// the domain type, the column/field, and the two port reads that
/// project it for the index-serve and discovery paths.
///
/// Inline on purpose, like `no_sensitive_drops`'s sensitive-table set:
/// extending it later is a self-contained, reviewable edit, and removing
/// an entry to make a new swallow pass is a blocking review finding
/// rather than a fix.
const STATUS_NAMES: &[&str] = &[
    "QuarantineStatus",
    "quarantine_status",
    "package_version_status",
    "package_version_anchors",
];

/// The four ways a `Result`/`Option` outcome gets thrown away in favour
/// of a value the caller chose. `.ok()` erases the error; the three
/// `unwrap_or*` forms erase it *and* name the substitute.
const DISCARDING_IDIOMS: &[&str] = &[
    ".ok()",
    ".unwrap_or(",
    ".unwrap_or_else(",
    ".unwrap_or_default()",
];

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-app`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Walk `dir` recursively, calling `visit` on every `.rs` file.
fn walk_rust(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            walk_rust(&path, visit);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}

/// Drop Rust line comments, then all whitespace, so a call split across
/// lines by rustfmt reads as one token sequence.
fn code_tokens(source: &str) -> String {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Does `text` name the quarantine status?
fn names_a_status(text: &str) -> bool {
    STATUS_NAMES.iter().any(|name| text.contains(name))
}

/// Start index of the receiver expression whose outcome the method call
/// at `dot` discards.
///
/// Walks left from the `.`, counting brackets so a nested call or
/// closure stays inside the receiver, and stops at the first
/// depth-zero opening bracket or expression separator — i.e. at the
/// point where the receiver chain began.
fn receiver_start(squashed: &str, dot: usize) -> usize {
    let bytes = squashed.as_bytes();
    let mut depth = 0usize;
    let mut cursor = dot;
    while cursor > 0 {
        cursor -= 1;
        match bytes[cursor] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth == 0 {
                    return cursor + 1;
                }
                depth -= 1;
            }
            // Depth-zero expression separators: the receiver cannot
            // reach past one of these.
            //
            // `<` and `>` are deliberately NOT separators. They would
            // read as comparison operators and stop the walk in the
            // middle of a turbofish — `x.parse::<QuarantineStatus>()
            // .ok()` would hand back a receiver of `()` and the hit
            // would be missed, which is the most natural spelling of
            // the very shape this guard is about. Treating them as
            // path characters instead only ever lengthens a receiver,
            // and a longer receiver can only add hits: erring wide
            // costs a false alarm a reviewer resolves in a minute,
            // erring narrow costs the next swallow. Measured against
            // the whole tree, widening them in adds no hit at all.
            b';' | b',' | b'=' | b'|' | b'&' | b'+' | b'!' if depth == 0 => {
                return cursor + 1;
            }
            _ => {}
        }
    }
    0
}

/// Index of the bracket closing the one opened at `open_at`, or `None`
/// when the source is truncated mid-expression.
fn matching_close(squashed: &str, open_at: usize) -> Option<usize> {
    let bytes = squashed.as_bytes();
    let mut depth = 0usize;
    for (offset, byte) in bytes.iter().enumerate().skip(open_at) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// One discarded quarantine-status outcome, rendered for the failure
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Swallow {
    /// The idiom that discarded it, e.g. `.unwrap_or(`.
    idiom: &'static str,
    /// The receiver chain whose outcome was discarded, truncated.
    receiver: String,
    /// The substituted fallback, truncated. Empty for `.ok()` /
    /// `.unwrap_or_default()`.
    fallback: String,
}

/// Every discarded quarantine-status outcome in `source`.
fn discarded_status_outcomes(source: &str) -> Vec<Swallow> {
    let squashed = code_tokens(source);
    let mut found = Vec::new();
    for idiom in DISCARDING_IDIOMS {
        let mut from = 0usize;
        while let Some(offset) = squashed[from..].find(idiom) {
            let at = from + offset;
            from = at + 1;
            let receiver = &squashed[receiver_start(&squashed, at)..at];
            // The fallback lives inside the idiom's own parentheses.
            // `.ok()` and `.unwrap_or_default()` substitute nothing a
            // caller wrote, so they have none to inspect.
            let fallback = if idiom.ends_with('(') {
                let open = at + idiom.len() - 1;
                matching_close(&squashed, open)
                    .map(|close| &squashed[open + 1..close])
                    .unwrap_or_default()
            } else {
                ""
            };
            if names_a_status(receiver) || names_a_status(fallback) {
                found.push(Swallow {
                    idiom,
                    receiver: truncate(receiver, 140),
                    fallback: truncate(fallback, 80),
                });
            }
        }
    }
    found
}

/// Keep a rendered fragment short enough to read in an assertion
/// message, on a char boundary.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let tail: String = text
        .chars()
        .skip(text.chars().count().saturating_sub(max))
        .collect();
    format!("…{tail}")
}

// ---------------------------------------------------------------------------
// The guard over the real tree.
// ---------------------------------------------------------------------------

#[test]
fn a_quarantine_status_outcome_is_never_discarded() {
    let crates_dir = workspace_root().join("crates");
    let mut hits = Vec::new();
    walk_rust(&crates_dir, &mut |path| {
        // Self-exclude: this file spells the banned shapes out as prose
        // and plants them in the scanner self-tests below.
        if path.ends_with("tests/status_decode_fails_closed.rs") {
            return;
        }
        let Ok(source) = fs::read_to_string(path) else {
            return;
        };
        for swallow in discarded_status_outcomes(&source) {
            hits.push(format!(
                "{}: `{}` discards `{}`{}",
                path.display(),
                swallow.idiom,
                swallow.receiver,
                if swallow.fallback.is_empty() {
                    String::new()
                } else {
                    format!(" in favour of `{}`", swallow.fallback)
                }
            ));
        }
    });
    assert!(
        hits.is_empty(),
        "an error on a quarantine-status read or decode must never be discarded: \
         `QuarantineStatus::None` is the most permissive state in the system, so a \
         substituted status does not degrade a serving decision, it inverts it — the \
         artifact becomes downloadable and index-servable with no release authority \
         behind it. Propagate the error; the request fails instead of serving. The \
         stored vocabulary has exactly one codec, \
         `hort_adapters_postgres::quarantine_status_sql`, and it returns a \
         `DomainError`. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// Counter-assertion over the real tree: the scan is not vacuously
/// green.
///
/// A source scan whose corpus silently emptied — a path that drifted, a
/// renamed codec, a decode that moved — passes. This pins the three
/// things that must stay true for the scan above to mean anything: the
/// corpus is real, the codec exists at the path the invariant names, and
/// the read paths that feed serving decisions go through it.
#[test]
fn the_scan_still_reaches_the_decode_it_is_about() {
    let root = workspace_root();
    let crates_dir = root.join("crates");

    let mut scanned = 0usize;
    let mut mentioning_a_status = 0usize;
    walk_rust(&crates_dir, &mut |path| {
        let Ok(source) = fs::read_to_string(path) else {
            return;
        };
        scanned += 1;
        if names_a_status(&code_tokens(&source)) {
            mentioning_a_status += 1;
        }
    });
    assert!(
        scanned > 200,
        "the corpus collapsed to {scanned} files — the guard's path layout drifted"
    );
    assert!(
        mentioning_a_status > 20,
        "only {mentioning_a_status} files name a quarantine status; the scan has lost \
         sight of the thing it is about"
    );

    // The codec, at the path the module header and the failure message
    // both name.
    let codec = root.join("crates/hort-adapters-postgres/src/quarantine_status_sql.rs");
    let codec_source = fs::read_to_string(&codec).unwrap_or_else(|e| {
        panic!(
            "the quarantine-status codec must stay at {} (the invariant names it, and \
             every read path delegates to it): {e}",
            codec.display()
        )
    });
    for symbol in ["quarantine_status_to_sql", "quarantine_status_from_sql"] {
        assert!(
            codec_source.contains(&format!("fn {symbol}")),
            "the codec no longer defines `{symbol}` — encode and decode are an inverse \
             pair and must stay one"
        );
    }

    // And the read paths that feed serving decisions still decode
    // through it. A rename that left these calling something else would
    // make the scan above green while reopening the hole.
    for relative in [
        "crates/hort-adapters-postgres/src/mappers.rs",
        "crates/hort-adapters-postgres/src/artifact_repo.rs",
        "crates/hort-adapters-postgres/src/purge_gc.rs",
        "crates/hort-adapters-postgres/src/curation_queue_repository.rs",
        "crates/hort-adapters-postgres/src/patch_candidate_repo.rs",
    ] {
        let source = fs::read_to_string(root.join(relative))
            .unwrap_or_else(|e| panic!("read {relative}: {e}"));
        assert!(
            source.contains("quarantine_status_from_sql"),
            "{relative} no longer decodes through the codec — every reader of \
             `artifacts.quarantine_status` goes through it, so that the column has \
             one stored vocabulary and not one per reader"
        );
    }
}

// ---------------------------------------------------------------------------
// Scanner self-tests. Each planted snippet is the verbatim pre-fix
// shape, so a matcher relaxed into uselessness fails here.
// ---------------------------------------------------------------------------

#[test]
fn the_scanner_trips_on_the_row_mapper_substitution() {
    let planted = "let quarantine_status = row\n    \
                   .quarantine_status\n    \
                   .as_deref()\n    \
                   .and_then(|s| s.parse().ok())\n    \
                   .unwrap_or(QuarantineStatus::None);";
    let found = discarded_status_outcomes(planted);
    assert_eq!(
        found.len(),
        1,
        "the row mapper's substitution must be one hit, got {found:?}"
    );
    assert_eq!(found[0].idiom, ".unwrap_or(");
    assert_eq!(found[0].fallback, "QuarantineStatus::None");
}

#[test]
fn the_scanner_trips_on_a_substitution_whose_receiver_names_no_status() {
    // The hot index-serve read: the receiver is `status_str…`, which
    // names no status at all. Only the fallback gives it away — which
    // is why the fallback half of the predicate exists.
    let planted = "let status = status_str\n    \
                   .as_deref()\n    \
                   .and_then(|s| s.parse().ok())\n    \
                   .unwrap_or(QuarantineStatus::None);";
    let found = discarded_status_outcomes(planted);
    assert_eq!(found.len(), 1, "expected one hit, got {found:?}");
    assert!(!names_a_status(&found[0].receiver));
    assert!(names_a_status(&found[0].fallback));
}

#[test]
fn the_scanner_trips_on_the_proxy_index_source_degradation() {
    // The mirror case: the fallback is `Vec::new()` and names no
    // status. What was discarded is the status read itself — which is
    // why the receiver half of the predicate exists.
    let planted = "let pkg_status = ctx\n    \
                   .artifact_use_case\n    \
                   .package_version_status(repo.id, package_name)\n    \
                   .await\n    \
                   .unwrap_or_else(|e| {\n        \
                   tracing::warn!(error = %e, \"degrading to no status\");\n        \
                   Vec::new()\n    });";
    let found = discarded_status_outcomes(planted);
    assert_eq!(found.len(), 1, "expected one hit, got {found:?}");
    assert_eq!(found[0].idiom, ".unwrap_or_else(");
    assert!(names_a_status(&found[0].receiver));
    assert!(!names_a_status(&found[0].fallback));
}

#[test]
fn the_scanner_trips_on_a_bare_ok_on_a_status_decode() {
    // The shape the acceptance criterion names: a newly introduced
    // `.ok()` on a status decode.
    let planted = "let status = row.quarantine_status.parse().ok();";
    let found = discarded_status_outcomes(planted);
    assert_eq!(found.len(), 1, "expected one hit, got {found:?}");
    assert_eq!(found[0].idiom, ".ok()");
}

#[test]
fn the_scanner_trips_on_a_turbofished_parse() {
    // The most natural spelling of a status decode, and the one a
    // `<`/`>`-stopping receiver walk silently misses: the walk ends
    // inside the turbofish and hands back `()`.
    let planted = "let status = raw.parse::<QuarantineStatus>().ok();";
    let found = discarded_status_outcomes(planted);
    assert_eq!(found.len(), 1, "expected one hit, got {found:?}");
    assert!(
        found[0].receiver.contains("parse::<QuarantineStatus>"),
        "the receiver must span the whole turbofish; got {:?}",
        found[0].receiver
    );
}

#[test]
fn the_scanner_trips_on_a_default_handed_back_by_the_codec() {
    // Routing through the codec is not enough on its own — a caller
    // that discards its `Result` reopens the hole from one layer up.
    let planted =
        "let status = quarantine_status_from_sql(raw, || ctx).unwrap_or(QuarantineStatus::None);";
    assert_eq!(discarded_status_outcomes(planted).len(), 1);
}

#[test]
fn the_scanner_ignores_a_fallback_on_a_neighbouring_field() {
    // A CLI table row: the `version` cell falls back to "-" while a
    // `quarantine_status` cell sits beside it in the same `vec![]`.
    // Nothing about a status was discarded.
    let benign = "vec![r.version.clone().unwrap_or_else(|| \"-\".to_string()), \
                  r.quarantine_status.clone()];";
    assert!(
        discarded_status_outcomes(benign).is_empty(),
        "falling back on the field next to a status is not falling back on a status"
    );
}

#[test]
fn the_scanner_ignores_a_discarded_artifact_load() {
    // `ScanOrchestration`'s retry-exhausted arm discards an artifact
    // *load* error, and the resulting `None` routes into
    // `record_scan_indeterminate` — the stricter outcome, which
    // re-loads and propagates the same error. What was discarded is a
    // load, not a status.
    let benign = "let current_status = self.artifacts.find_by_id(id).await.ok()\
                  .map(|a| a.quarantine_status);";
    assert!(
        discarded_status_outcomes(benign).is_empty(),
        "discarding a load is a different claim from discarding a status"
    );
}

#[test]
fn the_scanner_ignores_a_propagated_decode() {
    let handled = "let status = quarantine_status_from_sql(row.quarantine_status.as_deref(), \
                   || format!(\"artifact {}\", row.id))?;";
    assert!(
        discarded_status_outcomes(handled).is_empty(),
        "a propagated decode error is the shape this guard is asking for"
    );
}

#[test]
fn the_scanner_ignores_a_matched_decode() {
    let handled = "let status = match quarantine_status_from_sql(raw, || ctx) {\n    \
                   Ok(status) => status,\n    Err(err) => return Err(err),\n};";
    assert!(
        discarded_status_outcomes(handled).is_empty(),
        "a handled decode error is the shape this guard is asking for"
    );
}

#[test]
fn the_scanner_ignores_an_unrelated_swallow() {
    let benign = "let cap = env::var(\"CAP\").ok().and_then(|v| v.parse().ok())\
                  .unwrap_or(DEFAULT_CAP);";
    assert!(
        discarded_status_outcomes(benign).is_empty(),
        "this guard is about one column, not about `.ok()` in general"
    );
}

#[test]
fn the_scanner_stays_on_char_boundaries_around_non_ascii() {
    // `truncate` and the receiver walk both index into the squashed
    // source; a byte-step off a multi-byte character would panic, and
    // in a guard a panic is a false alarm that looks like a finding.
    let with_multibyte = "let s = \"—\"; let status = row.quarantine_status.parse().ok();";
    assert_eq!(discarded_status_outcomes(with_multibyte).len(), 1);
    assert_eq!(truncate("—————", 2), "…——");
}

#[test]
fn the_scanner_reads_no_comments() {
    let commented = "// let status = row.quarantine_status.parse().ok();\n\
                     /// Replaced: `.unwrap_or(QuarantineStatus::None)`.\n\
                     let status = quarantine_status_from_sql(raw, || ctx)?;";
    assert!(
        discarded_status_outcomes(commented).is_empty(),
        "prose describing the fixed pattern must stay writable"
    );
}
