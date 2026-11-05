//! Structural guard: **every entry point that writes a scan policy's
//! projection refuses a negative quarantine window before it appends.**
//!
//! ## The invariant
//!
//! `policy_projections.quarantine_duration_secs` carries a `CHECK (… >= 0)`
//! that is `NOT VALID`: it refuses every write from its migration onwards
//! and leaves rows written before it exactly as they stand. So a legacy
//! negative value is still in the row, and the row is what an upsert
//! carries — every column of it, not just the field the mutation was
//! about. Any projection write over such a policy therefore reaches that
//! `CHECK`, and what comes back is SQLSTATE 23514 wrapped as a
//! `DomainError::Invariant` — which the HTTP edge answers as an opaque
//! `500 internal error` (the constraint name stays in the server log) and
//! which fails a whole gitops apply pass on the declared path.
//!
//! The upsert runs **after** the event append, so that refusal arrives too
//! late to prevent anything: the stream states the mutation and the row
//! does not. What that costs differs per writer and none of it is benign —
//! a reactivation leaves the row archived while its stream says active and
//! every retry fails the same upsert; an exclusion add suppresses the CVE
//! and then skips the loosen re-evaluation at the tail of the method; an
//! exclusion removal drops the row and skips the TIGHTEN pass that was the
//! security-relevant half of it.
//!
//! `hort_app::use_cases::policy_use_case`'s
//! [`require_nonnegative_quarantine_duration`] is the one rule that says
//! so before any of that happens, naming the field, the value and the way
//! out. This guard is what makes asking it a property of the write surface
//! rather than a convention the next writer may not read.
//!
//! ## The property
//!
//! In `crates/hort-app/src/use_cases/policy_use_case.rs`, every production
//! entry point (`pub` — `pub(crate)` counts, a crate-visible writer owes
//! the same question) that **reaches** a policy-projection write calls
//! `require_nonnegative_quarantine_duration` earlier in its own body.
//!
//! "Reaches" is derived rather than listed: a write is an `upsert` on a
//! field this file declares as `Arc<dyn PolicyProjectionRepository>`, and
//! any function that calls a function that reaches one reaches one too
//! (transitively, within the file). That is what puts the private funnel
//! `write_projection` in the reaching set without naming it, and what
//! makes the five writers that delegate to it writers (`create_policy`
//! is the one that calls the port itself).
//!
//! **No allow-list.** A writer that genuinely should not ask is a review
//! conversation, not an entry — the same reason
//! `jobs_row_has_one_owner` and `live_reads_exclude_deleted` have none.
//!
//! ## Why the check cannot live at the funnel instead
//!
//! Every delegating writer goes through one private `write_projection`, so
//! a single runtime check there looks like the cheaper answer. It is not:
//! that function runs after the append, so its refusal would *describe* a
//! split brain rather than prevent one — strictly more confusing than the
//! constraint name it replaced. The obligation is upstream of the funnel by
//! construction, which is why this guard is phrased over entry points and
//! why `write_projection`'s own doc comment says so where a reader stands.
//!
//! ## Why this is scoped to one file
//!
//! `quarantine_duration_secs` is a column of the `ScanPolicyProjection`
//! row, written through `PolicyProjectionRepository::upsert`, and
//! [`the_window_rule_has_one_write_surface`] holds that this file is the
//! only production consumer in `crates/hort-app/src` that writes through
//! that port. (`retention_policy_use_case.rs` spells its own write
//! `self.projections.upsert(row)` on a *different* port and a different
//! table with no quarantine window, which is exactly why the needle is
//! resolved from the field's declared type rather than from its name.)
//!
//! ## What this cannot see
//!
//! The blind spot every source scan in this family has: a write reached
//! through a helper in **another** file, or through a macro. And one
//! false-positive shape worth knowing — an entry point that reaches the
//! write only by delegating to another entry point that does ask reads as
//! a violation here, because the scan reads one body at a time. That is a
//! review conversation about whether the delegation should carry the
//! question itself, not an exemption entry.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_writes` and
//! `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{
    call_args, is_ident_byte, line_of, match_back, parse_fns, production_region, split_args,
    walk_rust, workspace_root, FN_MODIFIERS,
};

/// The file that owns the scan policy write surface.
const WRITE_SURFACE: &str = "crates/hort-app/src/use_cases/policy_use_case.rs";

/// The one rule, as it is spelled at a call site.
const WINDOW_RULE: &str = "require_nonnegative_quarantine_duration";

/// The outbound port whose `upsert` writes the row carrying
/// `quarantine_duration_secs`. A field declared as `Arc<dyn …>` of this
/// port is what makes an `upsert` on it a policy-projection write.
const PROJECTION_PORT: &str = "PolicyProjectionRepository";

/// The column the rule is about, and the type that carries it.
const WINDOW_FIELD: &str = "quarantine_duration_secs";
const PROJECTION_TYPE: &str = "ScanPolicyProjection";

/// The census this guard pins. Six entry points write the projection;
/// `create_policy` writes through the port directly and the other five
/// reach it through the private `write_projection` funnel.
///
/// Spelled out rather than counted because the count has been wrong twice,
/// in both directions, and a number says nothing about *which* writer went
/// missing. A legitimately added or removed writer updates this list in
/// the same change — deliberately, in front of a reviewer.
const WRITER_CENSUS: [&str; 6] = [
    "add_exclusion",
    "archive_policy",
    "create_policy",
    "reactivate_policy",
    "remove_exclusion",
    "update_policy",
];

/// The private funnel the delegating writers reach the port through. Not
/// an entry point, so not in the census — asserted to be in the *reaching*
/// set, which is what proves the transitive edge is real rather than the
/// census being five names and a direct hit.
const PROJECTION_FUNNEL: &str = "write_projection";

/// How many distinct remedy tails the six askers carry. The tails are not
/// interchangeable: a write has a value in hand, archival has none, an
/// exclusion change has one ordinary apply, and reactivation has no route
/// at all and says so. Collapsing them is how a message starts naming a
/// way out that does not exist.
const DISTINCT_REMEDIES: usize = 4;

/// The prefix/suffix of a remedy constant, so a site handing the rule a
/// bare literal is a violation rather than a new tail nobody reviewed.
const REMEDY_PREFIX: &str = "NONNEGATIVE_WINDOW_";
const REMEDY_SUFFIX: &str = "_REMEDY";

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel} must be readable: {e}"))
}

/// Where a writer stands with respect to the rule.
#[derive(Debug, PartialEq, Eq)]
enum Posture {
    /// Asks before it writes, handing the rule the named remedy tail.
    Asks(String),
    /// Reaches a write and never asks.
    Never,
    /// Asks, but after the write it was supposed to prevent.
    TooLate { write_line: usize, ask_line: usize },
}

#[derive(Debug)]
struct Writer {
    name: String,
    line: usize,
    /// `(start, end)` in the original source — `production_region`
    /// preserves offsets, so the span addresses both texts.
    span: (usize, usize),
    posture: Posture,
}

#[derive(Debug)]
struct Analysis {
    /// Every function in the production region that reaches a write,
    /// entry point or not.
    reaching: BTreeSet<String>,
    /// The entry points among them.
    writers: Vec<Writer>,
    violations: Vec<String>,
}

/// True when `needle` stands at `at` as a whole token rather than inside a
/// longer identifier — so `my_projections` does not read as `projections`,
/// nor `require_nonnegative_quarantine_duration_v2` as the rule.
///
/// Each boundary is checked only on the side where the needle's own edge
/// byte is part of an identifier. Half of these needles end in `(`, whose
/// next byte is the first argument and so an identifier byte almost every
/// time, and half begin with `.`, whose previous byte is the receiver
/// (`self`) — checking those sides rejects every real call site.
fn token_at(bytes: &[u8], at: usize, needle: &str) -> bool {
    let edges = needle.as_bytes();
    let starts_in_ident = edges.first().is_some_and(|b| is_ident_byte(*b));
    let ends_in_ident = edges.last().is_some_and(|b| is_ident_byte(*b));
    let after = at + needle.len();
    let before_ok = !starts_in_ident || at == 0 || !is_ident_byte(bytes[at - 1]);
    let after_ok = !ends_in_ident || after >= bytes.len() || !is_ident_byte(bytes[after]);
    before_ok && after_ok
}

/// Offsets of `needle` in `text` where it stands as a whole token.
fn token_hits(text: &str, needle: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(needle) {
        let at = from + found;
        if token_at(bytes, at, needle) {
            out.push(at);
        }
        from = at + 1;
    }
    out
}

/// The field names a file declares as `Arc<dyn PolicyProjectionRepository>`
/// — the receivers whose `upsert` writes the row this rule is about.
///
/// Resolved from the declared type rather than from the field's name
/// because the name is not distinctive: `retention_policy_use_case.rs`
/// writes `self.projections.upsert(row)` into a different table through a
/// different port.
fn projection_fields(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut out = BTreeSet::new();
    let decl = format!("Arc<dyn {PROJECTION_PORT}>");
    for at in token_hits(text, &decl) {
        // Walk back over `: ` to the field or parameter name.
        let mut i = at;
        while i > 0 && (bytes[i - 1].is_ascii_whitespace() || bytes[i - 1] == b':') {
            i -= 1;
        }
        let end = i;
        while i > 0 && is_ident_byte(bytes[i - 1]) {
            i -= 1;
        }
        if i < end {
            out.insert(text[i..end].to_owned());
        }
    }
    out
}

/// True when the `fn` keyword at `fn_at` belongs to an item visible
/// outside its module.
///
/// Walks back over the modifier run the way `rust_scan::preceding_attrs`
/// does, so `pub(crate) async fn` and `pub async fn` both read as one.
fn is_entry_point(text: &str, fn_at: usize) -> bool {
    let bytes = text.as_bytes();
    let mut i = fn_at;
    loop {
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 {
            return false;
        }
        match bytes[i - 1] {
            // `pub(crate)` / `pub(super)`: step over the restriction.
            b')' => match match_back(bytes, i - 1, b'(', b')') {
                Some(open) => i = open,
                None => return false,
            },
            byte if is_ident_byte(byte) => {
                let mut start = i;
                while start > 0 && is_ident_byte(bytes[start - 1]) {
                    start -= 1;
                }
                let token = &text[start..i];
                if token == "pub" {
                    return true;
                }
                if !FN_MODIFIERS.contains(&token) {
                    return false;
                }
                i = start;
            }
            _ => return false,
        }
    }
}

/// Offsets, within one body, of every call that reaches a projection
/// write: an `upsert` on a port-typed field, or a call to a function
/// already known to reach one.
fn write_offsets(body: &str, fields: &BTreeSet<String>, reaching: &BTreeSet<String>) -> Vec<usize> {
    let mut out = Vec::new();
    for field in fields {
        out.extend(token_hits(body, &format!("{field}.upsert(")));
    }
    for name in reaching {
        out.extend(token_hits(body, &format!(".{name}(")));
        out.extend(token_hits(body, &format!("Self::{name}(")));
    }
    out.sort_unstable();
    out
}

/// The remedy constant a `require_nonnegative_quarantine_duration` call at
/// `at` was handed, or the argument text when it is not a constant.
fn remedy_argument(body: &str, at: usize) -> String {
    let open = at + WINDOW_RULE.len();
    let args = call_args(body, open).unwrap_or_default();
    split_args(&args).get(1).map_or_else(
        || "<no remedy argument>".to_owned(),
        |a| a.trim().to_owned(),
    )
}

/// Read one file's write surface: who reaches a projection write, and
/// whether each entry point asks the rule before it does.
fn analyse(rel: &str, source: &str) -> Analysis {
    let text = production_region(source);
    let fields = projection_fields(&text);
    let fns = parse_fns(&text);

    // The reaching set, closed transitively over same-file calls. Starting
    // from the port call rather than from `write_projection` is what keeps
    // the funnel derived: renaming it cannot drop the five writers that go
    // through it out of the scan.
    let mut reaching: BTreeSet<String> = BTreeSet::new();
    loop {
        let mut grew = false;
        for item in &fns {
            if reaching.contains(&item.name) {
                continue;
            }
            let others: BTreeSet<String> = reaching
                .iter()
                .filter(|n| **n != item.name)
                .cloned()
                .collect();
            if !write_offsets(&item.body, &fields, &others).is_empty() {
                reaching.insert(item.name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let mut writers = Vec::new();
    let mut violations = Vec::new();
    for item in &fns {
        if !reaching.contains(&item.name) || !is_entry_point(&text, item.span.0) {
            continue;
        }
        let others: BTreeSet<String> = reaching
            .iter()
            .filter(|n| **n != item.name)
            .cloned()
            .collect();
        let Some(&write_at) = write_offsets(&item.body, &fields, &others).first() else {
            continue;
        };
        let asks = token_hits(&item.body, WINDOW_RULE);
        // Offsets are into the body; the line they fall on is the body's
        // own start plus that, and NOT the `fn` keyword's line — a
        // signature this file wraps over five lines would skew every
        // reported line by four.
        let body_at = item.span.1 - item.body.len();
        let line_in_body = |off: usize| line_of(&text, body_at + off);
        let posture = match asks.first() {
            None => Posture::Never,
            Some(&ask_at) if ask_at > write_at => Posture::TooLate {
                write_line: line_in_body(write_at),
                ask_line: line_in_body(ask_at),
            },
            Some(&ask_at) => Posture::Asks(remedy_argument(&item.body, ask_at)),
        };
        match &posture {
            Posture::Asks(_) => {}
            Posture::Never => violations.push(format!(
                "{rel}:{} — `{}` writes the policy projection (first write at line {}) and \
                 never calls `{WINDOW_RULE}`. The upsert carries every column of the row, \
                 so a legacy negative `{WINDOW_FIELD}` this mutation never touched still \
                 reaches the column's CHECK — and it reaches it AFTER the append, where the \
                 refusal can only describe the split brain it was too late to prevent. Ask \
                 the rule before the append, with the remedy tail this writer's way out \
                 actually is",
                item.line,
                item.name,
                line_in_body(write_at),
            )),
            Posture::TooLate {
                write_line,
                ask_line,
            } => violations.push(format!(
                "{rel}:{} — `{}` calls `{WINDOW_RULE}` at line {ask_line}, after its first \
                 projection write at line {write_line}. A refusal there has already let the \
                 append through: the stream states the mutation and the row does not. Move \
                 the call ahead of the append",
                item.line, item.name,
            )),
        }
        writers.push(Writer {
            name: item.name.clone(),
            line: item.line,
            span: item.span,
            posture,
        });
    }
    writers.sort_by(|a, b| a.name.cmp(&b.name));

    Analysis {
        reaching,
        writers,
        violations,
    }
}

fn analyse_write_surface(root: &Path) -> (String, Analysis) {
    let source = read(root, WRITE_SURFACE);
    let analysis = analyse(WRITE_SURFACE, &source);
    (source, analysis)
}

#[test]
fn every_policy_projection_writer_asks_the_window_rule_first() {
    let root = workspace_root();
    let (_, analysis) = analyse_write_surface(&root);

    assert!(
        analysis.violations.is_empty(),
        "policy projection writers that do not refuse a negative quarantine window before \
         appending ({} found):\n  {}",
        analysis.violations.len(),
        analysis.violations.join("\n  "),
    );
}

#[test]
fn the_writer_census_is_still_these_six() {
    let root = workspace_root();
    let (_, analysis) = analyse_write_surface(&root);

    assert!(
        !analysis.writers.is_empty(),
        "{WRITE_SURFACE} must contain policy projection writers; finding none means the scan \
         stopped resolving the `{PROJECTION_PORT}` field or the file moved, and the test \
         above is then vacuously green"
    );
    let found: Vec<&str> = analysis.writers.iter().map(|w| w.name.as_str()).collect();
    let at: Vec<String> = analysis
        .writers
        .iter()
        .map(|w| format!("{}:{} {:?}", WRITE_SURFACE, w.line, w.posture))
        .collect();
    assert_eq!(
        found,
        WRITER_CENSUS,
        "the policy projection writer census changed. A writer this scan no longer sees is a \
         writer nothing holds the window rule over — and the census has been short twice. If \
         one was legitimately added or removed, update WRITER_CENSUS in the same change. \
         Found:\n  {}",
        at.join("\n  ")
    );

    // The transitive edge, pinned: five of the six reach the port through
    // the private funnel, so the funnel itself must be in the reaching
    // set. Without this, a scan that only ever matched the direct port
    // call would report one writer and look healthy.
    assert!(
        analysis.reaching.contains(PROJECTION_FUNNEL),
        "`{PROJECTION_FUNNEL}` is no longer derived as reaching a projection write (reaching \
         set: {:?}). The five delegating writers are only in scope because the closure walks \
         from the port call through it",
        analysis.reaching
    );
}

#[test]
fn the_rule_still_takes_a_projection_and_a_remedy() {
    let root = workspace_root();
    let (source, analysis) = analyse_write_surface(&root);
    let text = production_region(&source);

    let rule = parse_fns(&text)
        .into_iter()
        .find(|f| f.name == WINDOW_RULE)
        .unwrap_or_else(|| {
            panic!(
                "{WRITE_SURFACE} must define `fn {WINDOW_RULE}`. Every assertion here scans \
                 for calls to it by name, so a rename makes them vacuously green: rename \
                 WINDOW_RULE in the same change"
            )
        });
    let params = call_args(&rule.signature, rule.signature.find('(').expect("params"))
        .expect("the rule's parameter list balances");
    let params = split_args(&params);
    assert_eq!(
        params.len(),
        2,
        "`{WINDOW_RULE}` must keep both parameters — the projection it judges and the remedy \
         tail its caller supplies. Got {params:?}"
    );
    assert!(
        params[0].contains(PROJECTION_TYPE),
        "`{WINDOW_RULE}`'s first parameter must be the whole `{PROJECTION_TYPE}`, not one \
         field of a command: a legacy negative value a mutation leaves alone is still in the \
         row the upsert carries. Got {:?}",
        params[0]
    );
    assert!(
        rule.body.contains(WINDOW_FIELD),
        "`{WINDOW_RULE}` must still read `{WINDOW_FIELD}` — the one column the `CHECK` is on"
    );

    // Every asker hands it a named tail, and the tails are not collapsed.
    let mut tails: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for writer in &analysis.writers {
        let Posture::Asks(remedy) = &writer.posture else {
            continue;
        };
        assert!(
            remedy.starts_with(REMEDY_PREFIX) && remedy.ends_with(REMEDY_SUFFIX),
            "`{}` hands `{WINDOW_RULE}` {remedy:?} rather than a \
             `{REMEDY_PREFIX}…{REMEDY_SUFFIX}` constant. The tail is the way out an operator \
             reads; it belongs beside the other tails where a reviewer can see whether it is \
             true",
            writer.name
        );
        tails
            .entry(remedy.as_str())
            .or_default()
            .push(writer.name.as_str());
    }
    assert_eq!(
        tails.len(),
        DISTINCT_REMEDIES,
        "expected {DISTINCT_REMEDIES} distinct remedy tails across the writers; found {tails:?}. \
         The tails are not interchangeable — a write has a value in hand, archival has none, \
         an exclusion change has one ordinary apply, and reactivation has no route at all. A \
         collapsed tail names a way out that does not exist"
    );
}

/// The mutation counter-assertion: take the rule away from each writer in
/// turn, over **real on-disk source**, and the scan must report exactly
/// that writer. Over a clean tree the scan and a scan that reads nothing
/// agree on the verdict, so nothing else here can tell them apart.
#[test]
fn stripping_the_rule_from_a_writer_fails_the_scan() {
    let root = workspace_root();
    let (source, clean) = analyse_write_surface(&root);
    assert!(
        clean.violations.is_empty(),
        "{WRITE_SURFACE} must be clean before it is mutated: {:?}",
        clean.violations
    );

    for writer in &clean.writers {
        let (start, end) = writer.span;
        let mutated = format!(
            "{}{}{}",
            &source[..start],
            source[start..end].replace(WINDOW_RULE, "assume_a_nonnegative_quarantine_window"),
            &source[end..],
        );
        let after = analyse(WRITE_SURFACE, &mutated);
        let reported: Vec<&str> = after
            .writers
            .iter()
            .filter(|w| w.posture == Posture::Never)
            .map(|w| w.name.as_str())
            .collect();
        assert_eq!(
            reported,
            vec![writer.name.as_str()],
            "stripping `{WINDOW_RULE}` out of `{}` must make the scan report exactly that \
             writer; it reported {reported:?}. If it reports nothing, the scan is not reading \
             the call it claims to check",
            writer.name
        );
    }

    // And the ordering half: the same call, moved after the write it was
    // supposed to prevent, must still report. A scan that only asked
    // "is the name present in this body?" would stay green here while
    // every refusal arrived too late to stop an append.
    let late = clean
        .writers
        .iter()
        .find(|w| w.name == "archive_policy")
        .expect("archive_policy is in the census");
    let (start, end) = late.span;
    let body = &source[start..end];
    let stripped = body.replace(WINDOW_RULE, "assume_a_nonnegative_quarantine_window");
    let last_brace = stripped
        .rfind('}')
        .expect("a function body ends with a brace");
    let moved = format!(
        "{}{WINDOW_RULE}(&outcome.projection, NONNEGATIVE_WINDOW_ARCHIVE_REMEDY)?;{}",
        &stripped[..last_brace],
        &stripped[last_brace..],
    );
    let mutated = format!("{}{moved}{}", &source[..start], &source[end..]);
    let after = analyse(WRITE_SURFACE, &mutated);
    let too_late: Vec<&str> = after
        .writers
        .iter()
        .filter(|w| matches!(w.posture, Posture::TooLate { .. }))
        .map(|w| w.name.as_str())
        .collect();
    assert_eq!(
        too_late,
        vec!["archive_policy"],
        "a rule call moved after the projection write must report as too late; the scan said \
         {too_late:?}. The refusal has to precede the append or it describes a split brain \
         instead of preventing one"
    );
}

#[test]
fn the_window_rule_has_one_write_surface() {
    let root = workspace_root();
    let mut writers: Vec<String> = Vec::new();
    walk_rust(&root.join("crates/hort-app/src"), &mut |path| {
        let rel = path
            .strip_prefix(&root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        // Test harnesses: `test_support.rs` exists to hand tests mock
        // repositories, and a `*_tests.rs` sibling is a test module in its
        // own file (this workspace's convention for long ones).
        if rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs") {
            return;
        }
        let text = production_region(&fs::read_to_string(path).expect("readable UTF-8"));
        let fields = projection_fields(&text);
        if fields.is_empty() {
            return;
        }
        let hits = write_offsets(&text, &fields, &BTreeSet::new());
        if !hits.is_empty() {
            writers.push(format!("{rel}:{}", line_of(&text, hits[0])));
        }
    });
    writers.sort();

    assert_eq!(
        writers.len(),
        1,
        "`{PROJECTION_PORT}::upsert` must have exactly one production write surface in \
         crates/hort-app/src, and it is {WRITE_SURFACE}; found {writers:?}. The window rule \
         is scoped to that one file, so a second writer elsewhere is a projection write no \
         guard reads — widen the scan to it, or route the write through the use case that \
         owns the rule"
    );
    assert!(
        writers[0].starts_with(WRITE_SURFACE),
        "the one production write surface moved to {:?}; re-point WRITE_SURFACE at it",
        writers[0]
    );
}

/// The column's own half, named where the guard stands: the application
/// rule is a better message, not the enforcement. If the `CHECK` goes, a
/// hand-edited row or a restored dump walks straight past every assertion
/// above.
#[test]
fn the_column_still_carries_its_own_check() {
    let root = workspace_root();
    let mut found: Vec<PathBuf> = Vec::new();
    let dir = root.join("migrations");
    for entry in fs::read_dir(&dir)
        .expect("migrations/ is readable")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let sql = fs::read_to_string(&path).expect("readable UTF-8");
        if sql.contains("policy_projections_quarantine_duration_secs_nonnegative") {
            found.push(path);
        }
    }
    assert!(
        !found.is_empty(),
        "no migration defines `policy_projections_quarantine_duration_secs_nonnegative`. The \
         application rule names the field and the way out; the column's CHECK is what refuses \
         a write that never passes through the use case"
    );
}
