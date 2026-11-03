//! Structural guard: **no producer of queued work names a `jobs.priority`
//! ordinal.**
//!
//! ADR 0066 D6 — "the vocabulary is defined once, in the domain layer; a
//! producer of work names a class, no producer names a number." The
//! ordinal a fresh `jobs` row carries is decided in exactly one place,
//! `hort_domain::types::task_tier::queue_priority` (and its
//! `kind='scan'` convenience `scan_queue_priority`), keyed on the
//! `(kind, trigger_source)` the row already carries.
//!
//! ## Why a guard, and why convention did not hold it
//!
//! The ordinal used to be re-typed at every producer — twelve named
//! constants in eleven files plus twelve bare literals, with no shared
//! type and no shared module — so nothing existed for a reviewer to
//! check an assignment against, and "maintenance outranks publishing"
//! got written down in several places without ever reading as wrong. The
//! sweep that introduced the vocabulary moved every producer onto the
//! table but **one**: the two clearance-gating `provenance-verify`
//! enqueues, which could not, because the pair they stamped
//! (`('provenance-verify', 'ingest')`) was the same pair the ingest-time
//! verify stamps and the two write different numbers. No derivation
//! keyed on the row could answer both, so the sites named a constant
//! instead. They now stamp `'clearance'` and the table answers.
//!
//! That is the shape this guard is for: a producer that cannot say what
//! its work *is* compensates by saying what rank it wants, and the rank
//! is then unreviewable — nothing relates it to the class, and the next
//! producer copies the number rather than the reasoning. A guard is what
//! keeps the next one from being written that way, because the
//! alternative (a second named constant beside the call) compiles,
//! passes clippy and passes the suite.
//!
//! ## The property
//!
//! Every production ordinal that reaches `jobs.priority` is one of three
//! forms:
//!
//! 1. **the table, called in place** — `queue_priority(…)` or
//!    `scan_queue_priority(…)`;
//! 2. **a local bound from the table in the same function** — `let
//!    priority = queue_priority(…);`, then `priority` at the call. The
//!    seven `hort-server` CronJob subcommands are this shape, because
//!    each also logs the number it enqueued at;
//! 3. **a forwarded parameter**, and only inside a `fn enqueue_task(` /
//!    `fn enqueue_scan(` — an adapter or decorator implementing the port
//!    by delegation. Forwarding names no number: whatever the caller
//!    chose applies, and the caller is covered by this guard in its own
//!    right.
//!
//! Anything else — a literal, a named constant, an arithmetic expression
//! — is a producer naming a number. That is a review conversation, not
//! an allow-list entry, so this guard has **no allow-list**: either the
//! row can say what the work is (give it a `TriggerSource`, which is two
//! edits and a migration) or the number belongs in `task_tier`'s table
//! where a reviewer can see it beside every other one.
//!
//! ## The two surfaces the ordinal reaches the column through
//!
//! Both are checked, because checking only the first would make this
//! file's own claim false by a technicality:
//!
//! * [`JobsRepository::enqueue_task`] / [`JobsRepository::enqueue_scan`]
//!   — the direct enqueues. The argument position is **derived from the
//!   port's own signature** rather than hard-coded, so a parameter
//!   inserted ahead of `priority` cannot leave this guard reading the
//!   wrong argument (see
//!   [`the_scan_reads_the_priority_argument_the_port_declares`]).
//! * `IngestEnqueue::Scan` / `IngestEnqueue::ProvenanceVerify` — the
//!   ingest-time gates, whose ordinal rides a struct into
//!   `ArtifactLifecyclePort::commit_transition_with_enqueues` and is
//!   bound to the INSERT by the adapter's `enqueue_scan_in_tx`. A
//!   literal there is as much a producer naming a number as a literal at
//!   an `enqueue_task` call, and it is invisible to a scan of the
//!   enqueue methods alone.
//!
//! ## Scope, and what this cannot see
//!
//! Production code only, read through [`rust_scan::production_region`] —
//! comments and literals blanked, then every `#[cfg(test)]` item blanked
//! per item (not truncated at the first one, so production code below a
//! mid-file `#[cfg(test)]` seam is still read). A test legitimately
//! enqueues at whatever ordinal its fixture needs, and a guard arguing
//! with that would be arguing about test data, so `*_tests.rs` and the
//! `test_support.rs` harnesses are dropped by filename too.
//!
//! Blind spots, the ones every source scan has: a call assembled through
//! a macro; a `priority` local initialised through a helper this scan
//! cannot follow (it reads the `let` in the same file); and an ordinal
//! laundered through a function parameter of some other name. The review
//! check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `jobs_row_has_one_owner` and
//! `capped_stream_reads`.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

mod rust_scan;

use rust_scan::{line_of, production_region, walk_rust, workspace_root};

/// The port that declares the two enqueue entry points, and therefore
/// where the `priority` argument's position is read from.
const PORT_SOURCE: &str = "crates/hort-domain/src/ports/jobs_repository.rs";

/// The one module allowed to decide an ordinal. Named in failure
/// messages so a hit points at the fix rather than at the rule.
const ORDINAL_TABLE: &str = "hort_domain::types::task_tier";

/// The table's two entry points, as spelled at a call site.
const TABLE_CALLS: [&str; 2] = ["queue_priority(", "scan_queue_priority("];

/// The `IngestEnqueue` variants that carry an ordinal into
/// `commit_transition_with_enqueues`.
const INGEST_ENQUEUE_VARIANTS: [&str; 2] =
    ["IngestEnqueue::Scan {", "IngestEnqueue::ProvenanceVerify {"];

/// The enqueue entry points this guard reads, with the parameter whose
/// position it resolves out of [`PORT_SOURCE`].
const ENQUEUE_METHODS: [&str; 2] = ["enqueue_task", "enqueue_scan"];

/// The parameter every enqueue entry point carries the ordinal in.
const ORDINAL_PARAM: &str = "priority";

/// Every `crates/<crate>/src/**/*.rs`, sorted so failures are stable.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates =
        fs::read_dir(root.join("crates")).expect("crates/ exists under the workspace root");
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rust(&src, &mut |path| out.push(path.to_path_buf()));
        }
    }
    out.sort();
    out
}

/// Collapse whitespace so a rustfmt-wrapped expression compares as one
/// line.
fn normalise(expr: &str) -> String {
    expr.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The offset just past the delimiter that closes the one opened at
/// `open`, or `None` when it does not close inside `text`.
fn balanced_end(text: &str, open: usize, opener: u8, closer: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == opener {
            depth += 1;
        } else if b == closer {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Split a comma-separated list on top-level commas only — commas nested
/// in parens, brackets, braces or angle brackets belong to a nested
/// expression.
fn split_top_level(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            '(' | '[' | '<' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '>' | '}' => {
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

/// The zero-based position of the `priority` parameter in `fn <method>`'s
/// declaration in `port_source`, as the port declares it today.
///
/// Read rather than written down so that inserting a parameter ahead of
/// the ordinal cannot leave this guard checking the argument next door —
/// which would be the quiet failure, not the loud one: the neighbouring
/// argument at both entry points is a `&str`, so the guard would start
/// rejecting every compliant call site and get "fixed" by relaxing it.
fn ordinal_arg_index(port_source: &str, method: &str) -> Option<usize> {
    let header = format!("fn {method}<'a>(");
    let at = port_source.find(&header)?;
    let open = at + header.len() - 1;
    let close = balanced_end(port_source, open, b'(', b')')?;
    let params = split_top_level(&port_source[open + 1..close]);
    params
        .iter()
        // `&'a self` is the receiver, not an argument the call site
        // supplies.
        .filter(|p| !p.ends_with("self"))
        .position(|p| p.split(':').next().map(str::trim) == Some(ORDINAL_PARAM))
}

/// How an ordinal expression reaches the column — the three accepted
/// forms, and the one that is not.
#[derive(Debug, PartialEq, Eq)]
enum Ordinal {
    /// `queue_priority(…)` / `scan_queue_priority(…)` at the call.
    Table,
    /// A local the same file binds from the table.
    TableLocal,
    /// A parameter forwarded by a port implementation.
    Forwarded,
    /// A number this producer chose itself.
    Named,
}

/// True when `text` binds `ident` from the ordinal table anywhere in the
/// same file.
///
/// File-scoped rather than function-scoped deliberately: a `let priority
/// = queue_priority(…)` in one function and a literal `let priority = 10`
/// in another would read as compliant here, which is the blind spot the
/// module docs name. Narrowing it to the enclosing function would need a
/// brace-accurate function extent at an arbitrary offset, and the
/// *reason* the local exists at all — the CronJob subcommands log the
/// number they enqueued at — is a one-function-per-file shape where the
/// distinction cannot arise.
fn binds_from_the_table(text: &str, ident: &str) -> bool {
    let binding = format!("let {ident} =");
    let mut search = 0usize;
    while let Some(found) = text[search..].find(&binding) {
        let at = search + found;
        search = at + binding.len();
        let rest = normalise(&text[search..text.len().min(search + 200)]);
        if TABLE_CALLS.iter().any(|call| rest.starts_with(call)) {
            return true;
        }
    }
    false
}

/// Classify the ordinal expression `expr`, written at `offset` in
/// `text`.
fn classify_ordinal(text: &str, offset: usize, expr: &str) -> Ordinal {
    let expr = normalise(expr);
    if TABLE_CALLS.iter().any(|call| expr.starts_with(call)) {
        return Ordinal::Table;
    }
    // A bare identifier is either a local bound from the table, or a
    // parameter a port implementation is forwarding.
    let is_ident = !expr.is_empty()
        && expr
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'*');
    if is_ident {
        let ident = expr.trim_start_matches('*');
        if binds_from_the_table(text, ident) {
            return Ordinal::TableLocal;
        }
        if ident == ORDINAL_PARAM && in_a_port_implementation(text, offset) {
            return Ordinal::Forwarded;
        }
    }
    Ordinal::Named
}

/// True when `offset` sits inside a `fn enqueue_task(` / `fn
/// enqueue_scan(` — i.e. an implementation of the port forwarding its own
/// parameter on.
///
/// The nearest preceding `fn ` is enough: a forwarding implementation is
/// a thin wrapper, and a nested `fn` between the signature and the
/// forwarded call would put *its* name here and read as a violation —
/// which is the safe direction for a scan to err in.
fn in_a_port_implementation(text: &str, offset: usize) -> bool {
    let before = &text[..offset];
    let Some(at) = before.rfind("fn ") else {
        return false;
    };
    let rest = &before[at + 3..];
    let Some(end) = rest.find(['(', '<']) else {
        return false;
    };
    ENQUEUE_METHODS.contains(&rest[..end].trim())
}

/// One ordinal this scan found, with how it was written.
struct Site {
    location: String,
    shape: &'static str,
    ordinal: Ordinal,
    expr: String,
}

/// Every ordinal reaching `jobs.priority` from production code under
/// `crates/*/src`.
fn ordinal_sites(root: &Path) -> Vec<Site> {
    let port_source = fs::read_to_string(root.join(PORT_SOURCE))
        .unwrap_or_else(|e| panic!("read {PORT_SOURCE}: {e}"));
    let arg_index: Vec<(&str, usize)> = ENQUEUE_METHODS
        .iter()
        .map(|method| {
            let index = ordinal_arg_index(&port_source, method).unwrap_or_else(|| {
                panic!(
                    "no `{ORDINAL_PARAM}` parameter on `fn {method}` in {PORT_SOURCE} — the port \
                     changed shape under this guard, and a guessed argument position would check \
                     the wrong argument"
                )
            });
            (*method, index)
        })
        .collect();

    let mut sites = Vec::new();
    for path in production_sources(root) {
        let rel = path
            .strip_prefix(root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        // Test-only harnesses: a fixture picks the ordinal its own
        // assertions need, and that is test data, not a producer.
        if rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
        let text = production_region(&source);

        for (method, index) in &arg_index {
            let marker = format!(".{method}(");
            let mut search = 0usize;
            while let Some(found) = text[search..].find(&marker) {
                let at = search + found;
                let open = at + marker.len() - 1;
                search = open + 1;
                let line = line_of(&text, at);
                let Some(close) = balanced_end(&text, open, b'(', b')') else {
                    panic!(
                        "{rel}:{line} — the argument list of this `.{method}(` call does not \
                         close inside the production region; this guard will not guess at which \
                         argument is the ordinal"
                    );
                };
                let args = split_top_level(&text[open + 1..close]);
                let Some(expr) = args.get(*index) else {
                    panic!(
                        "{rel}:{line} — `.{method}(` called with {} arguments; the port declares \
                         `{ORDINAL_PARAM}` at position {index}",
                        args.len()
                    );
                };
                sites.push(Site {
                    location: format!("{rel}:{line}"),
                    shape: "enqueue",
                    ordinal: classify_ordinal(&text, at, expr),
                    expr: normalise(expr),
                });
            }
        }

        for variant in INGEST_ENQUEUE_VARIANTS {
            let mut search = 0usize;
            while let Some(found) = text[search..].find(variant) {
                let at = search + found;
                let open = at + variant.len() - 1;
                search = open + 1;
                let line = line_of(&text, at);
                let Some(close) = balanced_end(&text, open, b'{', b'}') else {
                    // An `IngestEnqueue::Scan {` whose brace does not
                    // close inside the region is a match arm the region
                    // pass cut, not a construction.
                    continue;
                };
                let fields = split_top_level(&text[open + 1..close]);
                // A pattern binds `priority` without a value; only a
                // construction assigns one.
                let Some(expr) = fields.iter().find_map(|f| {
                    f.split_once(':')
                        .filter(|(name, _)| name.trim() == ORDINAL_PARAM)
                        .map(|(_, value)| value)
                }) else {
                    continue;
                };
                sites.push(Site {
                    location: format!("{rel}:{line}"),
                    shape: "ingest-enqueue",
                    ordinal: classify_ordinal(&text, at, expr),
                    expr: normalise(expr),
                });
            }
        }
    }
    sites
}

/// **The guard.** No production producer names an ordinal.
#[test]
fn no_producer_names_a_queue_ordinal() {
    let sites = ordinal_sites(&workspace_root());

    let violations: Vec<String> = sites
        .iter()
        .filter(|s| s.ordinal == Ordinal::Named)
        .map(|s| {
            format!(
                "{} — this producer names the ordinal `{}` itself. The number a fresh `jobs` row \
                 carries is decided in `{ORDINAL_TABLE}` from the `(kind, trigger_source)` the \
                 row already carries (ADR 0066 D6: a producer names a class, never a number). If \
                 no `(kind, trigger_source)` pair describes this work, that is the finding: give \
                 it a `TriggerSource` literal and a migration widening \
                 `jobs_trigger_source_check`, then call `queue_priority(kind, trigger_source)` \
                 like every other producer",
                s.location, s.expr
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "producers naming a `jobs.priority` ordinal ({} found):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );

    // Counter-assertions: a scan that stopped finding call sites must not
    // read as compliance, and each accepted form must still be exercised
    // by the tree — an arm nothing reaches is an arm nobody would notice
    // going wrong.
    let count = |want: Ordinal, shape: &str| {
        sites
            .iter()
            .filter(|s| s.ordinal == want && s.shape == shape)
            .count()
    };
    assert!(
        count(Ordinal::Table, "enqueue") >= 4,
        "the scan found {} in-place table calls at an enqueue entry point; the producers that \
         call the table directly are at least the admin invoke, the policy re-evaluation, the \
         self-service prefetch root and the two clearance verifies",
        count(Ordinal::Table, "enqueue")
    );
    assert_eq!(
        count(Ordinal::TableLocal, "enqueue"),
        7,
        "the scan found {} locals bound from the table; the seven `hort-server` CronJob \
         subcommands are that shape, each because it also logs the ordinal it enqueued at. If \
         one was legitimately added or removed, move this count deliberately — a drifting count \
         means the `let` resolution stopped working and every one of them would then read as a \
         producer naming a number",
        count(Ordinal::TableLocal, "enqueue")
    );
    assert_eq!(
        count(Ordinal::Table, "ingest-enqueue"),
        4,
        "the scan found {} ordinals on `IngestEnqueue` constructions; the ingest-time gates are \
         the scan and the provenance verify, each built on both the `ingest` and the \
         `register_by_hash` path",
        count(Ordinal::Table, "ingest-enqueue")
    );
    assert_eq!(
        count(Ordinal::Forwarded, "enqueue"),
        0,
        "a forwarded `{ORDINAL_PARAM}` turned up at an enqueue call site: {:?}. The arm exists \
         for a decorator implementing the port by delegation; nothing in the tree is one today, \
         and the Postgres adapter binds the parameter into its INSERT rather than calling the \
         port back",
        sites
            .iter()
            .filter(|s| s.ordinal == Ordinal::Forwarded)
            .map(|s| s.location.clone())
            .collect::<Vec<_>>()
    );
}

/// The argument position this guard reads is the one the port declares.
///
/// Both entry points carry a `&str` immediately beside `priority`
/// (`trigger_source` after it, `format` before it on `enqueue_scan`), so
/// a guard reading a hard-coded position after a parameter was inserted
/// would reject every compliant call site at once — and the natural
/// repair for a guard that fails everywhere is to relax it.
#[test]
fn the_scan_reads_the_priority_argument_the_port_declares() {
    let port_source = fs::read_to_string(workspace_root().join(PORT_SOURCE))
        .unwrap_or_else(|e| panic!("read {PORT_SOURCE}: {e}"));
    assert_eq!(
        ordinal_arg_index(&port_source, "enqueue_task"),
        Some(3),
        "`enqueue_task(kind, params, actor_id, priority, trigger_source, idempotency_key)`"
    );
    assert_eq!(
        ordinal_arg_index(&port_source, "enqueue_scan"),
        Some(4),
        "`enqueue_scan(artifact_id, repository_id, content_hash, format, priority, \
         trigger_source)`"
    );
    // And the resolution really is a read, not a constant dressed up as
    // one: a signature without the parameter resolves to nothing.
    assert_eq!(
        ordinal_arg_index(
            "fn enqueue_task<'a>(&'a self, kind: &'a str) -> X;",
            "enqueue_task"
        ),
        None
    );
}

/// The classifier can still fail, and fails on the shape this unit
/// removed.
///
/// Without this the guard would be satisfied by a tree that happens to
/// have no violation, with no evidence that it could tell one from a
/// compliant call. The literal and the named constant below are exactly
/// what the two clearance-gating verifies wrote before they had a
/// trigger source of their own.
#[test]
fn the_classifier_refuses_a_literal_and_a_named_constant() {
    let named = "\
async fn producer(&self) {
    self.jobs
        .enqueue_task(KIND, &params, None, CLEARANCE_GATING_VERIFY_PRIORITY, SOURCE, None)
        .await;
}
";
    let sites: Vec<Ordinal> = [
        "10",
        "CLEARANCE_GATING_VERIFY_PRIORITY",
        "CRON_PRIORITY + 1",
    ]
    .iter()
    .map(|expr| classify_ordinal(named, named.len() - 1, expr))
    .collect();
    assert_eq!(
        sites,
        vec![Ordinal::Named, Ordinal::Named, Ordinal::Named],
        "the classifier must refuse a literal, a named constant and an arithmetic expression"
    );

    // The three accepted forms, each accepted for its own reason.
    assert_eq!(
        classify_ordinal(named, 0, "queue_priority(KIND, SOURCE)"),
        Ordinal::Table
    );
    assert_eq!(
        classify_ordinal(named, 0, "scan_queue_priority(SOURCE)"),
        Ordinal::Table
    );
    let with_local = "fn main() { let priority = queue_priority(KIND, SOURCE); enqueue(priority) }";
    assert_eq!(
        classify_ordinal(with_local, with_local.len() - 1, "priority"),
        Ordinal::TableLocal
    );
    let literal_local = "fn main() { let priority = 10; enqueue(priority) }";
    assert_eq!(
        classify_ordinal(literal_local, literal_local.len() - 1, "priority"),
        Ordinal::Named,
        "a local bound from a literal is the same producer naming the same number one line up"
    );
    let forwarding =
        "fn enqueue_task<'a>(&'a self, priority: i16) { inner.enqueue_task(priority) }";
    assert_eq!(
        classify_ordinal(forwarding, forwarding.len() - 1, "priority"),
        Ordinal::Forwarded
    );
    let not_forwarding = "fn some_other_fn(priority: i16) { inner.enqueue_task(priority) }";
    assert_eq!(
        classify_ordinal(not_forwarding, not_forwarding.len() - 1, "priority"),
        Ordinal::Named,
        "the forwarding arm is scoped to the port's own methods; anywhere else a `priority` \
         parameter is an ordinal someone chose upstream of the table"
    );
}

/// The reach of the scan, pinned: a producer below a mid-file
/// `#[cfg(test)]` item is production code and must be seen, while a
/// fixture inside a `#[cfg(test)] mod` must not be.
///
/// The second half is as load-bearing as the first. A test enqueues at
/// whatever ordinal its own assertions need — `priority: 0` on a `JobRow`
/// fixture, a bare `10` standing in for a production path — and a region
/// rule that stopped blanking test code would turn this guard into an
/// argument about test data, which it would lose.
#[test]
fn the_scan_reads_production_code_below_a_cfg_test_item() {
    let source = "\
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

async fn production_producer(&self) {
    self.jobs.enqueue_task(KIND, &params, None, 7, SOURCE, None).await;
}

#[cfg(test)]
mod tests {
    async fn fixture(&self) {
        self.jobs.enqueue_task(KIND, &params, None, 4096, SOURCE, None).await;
    }
}
";
    let region = production_region(source);
    assert!(
        region.contains("None, 7, SOURCE"),
        "the production enqueue below the `#[cfg(test)] use` seam must survive the region \
         pass — blanking it would hide a producer naming a number:\n{region}"
    );
    assert!(
        !region.contains("4096"),
        "the enqueue inside the `#[cfg(test)] mod` must be blanked — a fixture chooses its own \
         ordinal and this guard has no business policing it:\n{region}"
    );
}
