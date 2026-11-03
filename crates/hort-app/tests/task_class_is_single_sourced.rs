//! Structural guard: **the `(kind, trigger_source) → class` mapping has
//! exactly one definition, and SQL is not a second one.**
//!
//! ADR 0066 D6 — "the vocabulary is defined once, in the domain layer."
//! The definition is
//! [`hort_domain::types::task_tier::TaskTier::classify`]; its write face
//! (`queue_priority`) is derived from it, and `no_producer_names_an_ordinal`
//! is the guard that keeps producers from naming a number instead of a
//! class.
//!
//! ## Why this guard, and why now
//!
//! Non-displacement at the claim (ADR 0066 D4) is a *per-class*
//! reservation, and the claim is SQL. The obvious way to write it would
//! have been to teach the query which trigger sources are client-waited
//! — a `CASE WHEN trigger_source IN ('ingest', 'register-by-hash', …)`
//! — and that is precisely the defect this family of changes exists to
//! remove: the trigger-source set had been written down three times with
//! no two copies agreeing, and the ordinal had been re-typed at twelve
//! producers. A copy in SQL is worse than a copy in Rust, because no
//! exhaustive `match` can fail the build over it.
//!
//! So the reservation is expressed on `jobs.priority` with the band
//! bounds passed **in as bind parameters** from the domain
//! (`ClaimReservation`, built from `waited_on_bands`). The adapter binds
//! three numbers per band and never learns what a class is. That is a
//! property of today's statement, nothing in the type system holds it,
//! and the cheapest regression — one `CASE` arm added to the claim
//! because a band boundary was inconvenient — compiles, runs, and passes
//! every behavioural test in the tree.
//!
//! ## The property
//!
//! Two halves, which is the scope the backlog item states: **no
//! `(kind, trigger_source)` → class table in any SQL literal, and none
//! in `crates/hort-adapters-postgres`.**
//!
//! 1. **SQL literals** (every production string literal under
//!    `crates/*/src` that names [`COLUMN`]): the literal may *project*
//!    the column — a column list, a `RETURNING`, a `VALUES` placeholder
//!    — and may not *decide* anything from it. Deciding is a comparison
//!    ([`COMPARISONS`]), a `CASE`, or a quoted literal from the
//!    trigger-source vocabulary.
//! 2. **The Postgres adapter** (production code under
//!    `crates/hort-adapters-postgres/src`): may not name [`TIER_TYPE`]
//!    or its module at all. The adapter is the layer handed the band
//!    bounds, so it is the layer with a motive to re-derive the class
//!    they came from; a legitimate need for the type there is a review
//!    conversation about which layer the decision belongs in.
//!
//! Scoped to the literal, not to the file: a statement added beside a
//! clean one is judged on its own text.
//!
//! ## Why no allow-list
//!
//! Same reason as the sibling guards. The alternative to a copy is not
//! an exemption — it is passing the number in, which the port already
//! supports, or calling `classify` from a layer that is allowed to. A
//! site that genuinely needs the mapping in SQL is a decision to amend
//! ADR 0066 with, not an entry anyone can add in this file to make a
//! finding go away.
//!
//! ## Scope, and what this cannot see
//!
//! Production code only, read through [`rust_scan::mark_literals`] plus
//! [`rust_scan::blank_cfg_test_items`]: a test fixture legitimately
//! inserts `trigger_source = 'cron'` rows, and a guard arguing with that
//! would be arguing about test data. For the same reason — and as the
//! sibling `no_producer_names_an_ordinal` already does — `*_tests.rs`
//! and the `test_support.rs` harnesses are dropped by filename, because
//! a harness is test code however it happens to be compiled: the
//! adapter's is `#[doc(hidden)]` but always built, and its job includes
//! handing every DB-backed test the production reservation, which means
//! naming the domain's default. `migrations/` is deliberately out of
//! scope — the `jobs_trigger_source_check` CHECK *is* the column's
//! vocabulary rather than a copy of the mapping, and
//! `jobs_trigger_source_check_lockstep_guard` is what holds it against
//! [`TriggerSource`].
//!
//! Blind spots, the ones every source scan has: a statement assembled
//! from fragments at runtime, a comparison spelled through a function
//! (`lower(trigger_source) = …` is caught; `my_class_of(trigger_source)`
//! in a stored function is not), and a mapping written against `kind`
//! alone. The review check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `no_producer_names_an_ordinal` and
//! `live_reads_exclude_deleted`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use hort_domain::ports::jobs_repository::TriggerSource;

mod rust_scan;
mod sql_scan;

use rust_scan::{blank_cfg_test_items, line_of, mark_literals, walk_rust, LITERAL_MARK};
use sql_scan::strip_comments_and_strings;

/// The one module allowed to decide a class. Named in failure messages
/// so a hit points at the fix rather than at the rule.
const DEFINITION: &str = "crates/hort-domain/src/types/task_tier.rs";

/// The type the classification answers with, as spelled in source.
const TIER_TYPE: &str = "TaskTier";

/// The module path a second definition would most likely reach for.
const TIER_MODULE: &str = "task_tier";

/// The column a classification keys on, and therefore the column whose
/// appearance in a SQL literal brings that literal into scope.
const COLUMN: &str = "trigger_source";

/// The adapter tree the backlog item names: the layer handed the band
/// bounds, and so the layer with a motive to re-derive the class.
const ADAPTER_SRC: &str = "crates/hort-adapters-postgres/src";

/// Comparison shapes that make a SQL statement *decide* from
/// [`COLUMN`] rather than merely project it.
///
/// Spelled with the column on each side, because `$1 = trigger_source`
/// is the same statement written backwards.
const COMPARISONS: [&str; 10] = [
    "trigger_source =",
    "trigger_source!=",
    "trigger_source <>",
    "trigger_source in",
    "trigger_source not in",
    "trigger_source is",
    "trigger_source like",
    "trigger_source similar",
    "= trigger_source",
    "in trigger_source",
];

/// `CASE`, which in a statement that names [`COLUMN`] is a mapping
/// table in all but name.
const CASE: &str = "case";

/// One production SQL literal that names [`COLUMN`], and what it does
/// with it.
#[derive(Debug, Clone)]
struct Statement {
    file: String,
    line: usize,
    /// The deciding shapes found in it; empty means it only projects.
    decides: Vec<String>,
}

/// Strip SQL `--` and `/* … */` comments, keeping `'…'` string
/// literals.
///
/// The shared [`strip_comments_and_strings`] cannot serve this half: it
/// removes the quoted literals that the vocabulary check is *looking
/// for*. Same discipline, opposite direction, and both halves are
/// needed — without comment stripping, a statement's own prose
/// explaining that it deliberately does not key on `'cron'` would read
/// as a hit; without the shared stripper on the other half, a `'cron'`
/// appearing as a *value* would read as a comparison.
fn strip_sql_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            out.push(' ');
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Collapse whitespace so a rustfmt-wrapped statement compares as one
/// line, and lower-case it so SQL keyword casing cannot change a
/// verdict.
fn normalise(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Every deciding shape `raw` carries, in a stable order.
fn decisions(raw: &str) -> Vec<String> {
    let mut found = Vec::new();
    // Comparisons and `CASE` are read from the code, with comments AND
    // string literals removed, so neither prose nor a value can trip
    // them.
    let code = normalise(&strip_comments_and_strings(raw));
    if code.contains(COLUMN) {
        for shape in COMPARISONS {
            if code.contains(shape) {
                found.push(shape.to_string());
            }
        }
        if code.contains(CASE) {
            found.push(CASE.to_string());
        }
    }
    // The vocabulary is read from the code WITH its literals intact —
    // that is what a re-typed mapping is made of — and off the one
    // definition rather than a list of this file's own.
    let with_literals = normalise(&strip_sql_comments(raw));
    for source in TriggerSource::ALL {
        let quoted = format!("'{}'", source.as_str());
        if with_literals.contains(&quoted) {
            found.push(quoted);
        }
    }
    found
}

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources() -> Vec<PathBuf> {
    let root = rust_scan::workspace_root();
    let mut out = Vec::new();
    let crates = fs::read_dir(root.join("crates")).expect("crates/ exists under the root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// A test harness compiled as production code.
///
/// Dropped from both halves by filename, for the reason in this
/// module's docs and matching `no_producer_names_an_ordinal`'s own
/// exclusion.
fn is_test_harness(rel: &str) -> bool {
    rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs")
}

/// Repo-relative path, with forward slashes.
fn relative(path: &Path) -> String {
    let root = rust_scan::workspace_root();
    path.strip_prefix(&root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every production SQL literal under `crates/*/src` that names
/// [`COLUMN`], with its verdict.
fn statements() -> Vec<Statement> {
    let mut found = Vec::new();
    for path in production_sources() {
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        if !source.contains(COLUMN) {
            continue;
        }
        let (marked, spans) = mark_literals(&source);
        let production = blank_cfg_test_items(&marked);
        let production_bytes = production.as_bytes();
        let rel = relative(&path);
        if is_test_harness(&rel) {
            continue;
        }
        for (start, end) in spans {
            // The mark survives only outside a `#[cfg(test)]` item.
            if production_bytes.get(start) != Some(&LITERAL_MARK) {
                continue;
            }
            let raw = &source[start..end];
            if !raw.contains(COLUMN) {
                continue;
            }
            found.push(Statement {
                file: rel.clone(),
                line: line_of(&source, start),
                decides: decisions(raw),
            });
        }
    }
    found.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    found
}

// ---------------------------------------------------------------------------
// Half one — no SQL literal decides a class
// ---------------------------------------------------------------------------

#[test]
fn no_sql_literal_decides_a_class_from_the_trigger_source() {
    let offenders: Vec<Statement> = statements()
        .into_iter()
        .filter(|s| !s.decides.is_empty())
        .collect();
    assert!(
        offenders.is_empty(),
        "these production SQL statements decide something from `{COLUMN}` or name a \
         trigger-source literal, which is a second copy of the \
         `(kind, trigger_source)` → class mapping (ADR 0066 D6). The mapping is \
         `{DEFINITION}`'s; a claim or sweep that needs a class boundary takes it as a \
         bind parameter, the way `ClaimReservation` passes the band bounds in. \
         Offenders:\n{offenders:#?}"
    );
}

/// Counter-assertion: the corpus is real.
///
/// The scan above only means something if production SQL names
/// [`COLUMN`] at all. If a refactor moved every such statement behind a
/// query builder, this guard would go silently green over a tree it no
/// longer reads — so the corpus size is asserted, and a projection is
/// asserted to be *allowed*, which is the half a blanket ban would get
/// wrong.
#[test]
fn the_sql_corpus_is_not_empty_and_projection_is_allowed() {
    let found = statements();
    assert!(
        found.len() >= 5,
        "production SQL must still name `{COLUMN}` for the scan above to read anything \
         — found {} statements:\n{found:#?}",
        found.len()
    );
    assert!(
        found.iter().any(|s| s.decides.is_empty()),
        "at least one statement must merely PROJECT the column — a tree in which every \
         statement decides from it would mean this guard is reporting the normal case \
         as a defect:\n{found:#?}"
    );
}

/// Counter-assertion: the classifier can still fail.
///
/// Each deciding shape is injected into a statement that is otherwise
/// clean, and each must be caught. Without this, a typo in
/// [`COMPARISONS`] — or a `normalise` that lower-cased the wrong side —
/// would leave the scan above green for the wrong reason.
#[test]
fn the_classifier_catches_every_deciding_shape() {
    for shape in COMPARISONS {
        let injected = format!("SELECT id FROM public.jobs WHERE {shape} $1");
        assert!(
            !decisions(&injected).is_empty(),
            "the comparison `{shape}` must be caught: {injected}"
        );
    }
    assert!(
        !decisions("SELECT CASE WHEN trigger_source = 'cron' THEN 0 ELSE 60 END FROM public.jobs")
            .is_empty(),
        "a CASE over the column is a mapping table and must be caught"
    );
    for source in TriggerSource::ALL {
        let injected = format!(
            "INSERT INTO public.jobs (trigger_source) VALUES ('{}')",
            source.as_str()
        );
        assert!(
            !decisions(&injected).is_empty(),
            "the trigger-source literal '{}' must be caught",
            source.as_str()
        );
    }
    // And the shape the claim actually uses is NOT caught — a band
    // bound compared against a bind parameter is the correct idiom, and
    // a guard that rejected it would have nothing to offer instead.
    assert!(
        decisions(
            "SELECT id FROM public.jobs WHERE priority >= band.lowest AND priority <= \
             band.highest ORDER BY priority DESC, trigger_source"
        )
        .is_empty(),
        "the parameterised band comparison is the idiom this guard exists to protect, \
         not a hit"
    );
    // Nor is a comment that discusses the forbidden shape.
    assert!(
        decisions(
            "-- Deliberately does not key on trigger_source = 'cron'\n\
             SELECT trigger_source FROM public.jobs"
        )
        .is_empty(),
        "prose about the shape is not the shape"
    );
    assert!(
        !TriggerSource::ALL.is_empty(),
        "the vocabulary must be non-empty, or the literal scan is vacuous"
    );
}

// ---------------------------------------------------------------------------
// Half two — the Postgres adapter does not classify
// ---------------------------------------------------------------------------

/// Production files under [`ADAPTER_SRC`] that name the class type or
/// its module, with the line of the first mention.
fn adapter_mentions() -> Vec<(String, usize, String)> {
    let root = rust_scan::workspace_root();
    let mut found = Vec::new();
    walk_rust(&root.join(ADAPTER_SRC), &mut |path| {
        let rel = relative(path);
        if is_test_harness(&rel) {
            return;
        }
        let Ok(source) = fs::read_to_string(path) else {
            return;
        };
        let production = rust_scan::production_region(&source);
        for needle in [TIER_TYPE, TIER_MODULE] {
            if let Some(at) = production.find(needle) {
                found.push((rel.clone(), line_of(&production, at), needle.to_string()));
            }
        }
    });
    found.sort();
    found
}

#[test]
fn the_postgres_adapter_does_not_name_the_class_type() {
    let found = adapter_mentions();
    assert!(
        found.is_empty(),
        "production code under {ADAPTER_SRC} must not name `{TIER_TYPE}` or \
         `{TIER_MODULE}`: the adapter is handed the `jobs.priority` band bounds as bind \
         parameters precisely so the `(kind, trigger_source)` → class mapping stays in \
         `{DEFINITION}` (ADR 0066 D6). A genuine need for the class in this layer is a \
         conversation about where the decision belongs, not an exemption. \
         Mentions:\n{found:#?}"
    );
}

/// Counter-assertion: [`ADAPTER_SRC`] is a real tree this scan reads,
/// and the needles are the right ones.
///
/// A path typo would make the assertion above pass over nothing; a
/// renamed domain type would make the needles match nothing. Both are
/// pinned against the definition itself.
#[test]
fn the_adapter_scan_reads_a_real_tree_for_real_needles() {
    let root = rust_scan::workspace_root();
    let mut files = 0usize;
    walk_rust(&root.join(ADAPTER_SRC), &mut |_| files += 1);
    assert!(
        files >= 10,
        "{ADAPTER_SRC} must be the adapter's source tree — found {files} files"
    );

    let definition = fs::read_to_string(root.join(DEFINITION))
        .unwrap_or_else(|e| panic!("{DEFINITION} must exist: {e}"));
    assert!(
        definition.contains(&format!("pub enum {TIER_TYPE}")),
        "`{TIER_TYPE}` must still be the type `{DEFINITION}` defines, or the adapter \
         scan looks for a name nothing uses"
    );
    assert!(
        definition.contains("pub fn classify("),
        "`{DEFINITION}` must still carry the one `classify`, or this guard is asserting \
         the uniqueness of nothing"
    );
    assert!(
        root.join(DEFINITION)
            .to_string_lossy()
            .contains(TIER_MODULE),
        "`{TIER_MODULE}` must still be the definition's module name"
    );
    // The definition really is a `(kind, trigger_source)` table: it
    // names every literal of the vocabulary's type, wildcard-free.
    for source in TriggerSource::ALL {
        let variant = format!("TriggerSource::{source:?}");
        assert!(
            definition.contains(&variant),
            "`{DEFINITION}` must give {variant} a class — otherwise the mapping this \
             guard calls single-sourced is incomplete at its one source"
        );
    }

    // Mutation check: the adapter scan can still find something. Run
    // the same needles over the definition's own tree, where they are
    // present by construction.
    let domain_src = root.join("crates/hort-domain/src");
    let mut hits = 0usize;
    walk_rust(&domain_src, &mut |path| {
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        if rust_scan::production_region(&text).contains(TIER_TYPE) {
            hits += 1;
        }
    });
    assert!(
        hits >= 1,
        "the needle `{TIER_TYPE}` must be findable where it IS defined, or the adapter \
         scan is vacuously green"
    );
}
