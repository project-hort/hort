//! Structural guard: **in the application layer, exactly one file writes a
//! `jobs` row's result state.**
//!
//! `JobsRepository::{mark_completed, reschedule, mark_failed}` are the three
//! fenced result writes. The fence is `AND attempts = $2` and deliberately
//! *not* the status (a guard test in the Postgres adapter pins that), so two
//! writers racing on one execution's attempt both pass it and the later one
//! wins. That is not a theoretical hazard: `ScanOrchestrationUseCase::
//! record_outcome` closed its own row out at six call sites while
//! `ScanTaskHandler::run` returned a blanket `TaskOutcome::Completed`, so the
//! dispatcher wrote the same row a second time and overwrote the first. A
//! scan that had just been scheduled for retry read back
//! `status='completed', attempts=1` with a transient error still in
//! `last_error`, no `ScanCompleted`, no verdict and `last_scan_at` NULL — and
//! the job row is the system's only record that an artifact is still owed a
//! verdict, so the release sweep correctly declined those artifacts forever.
//! The terminal arm was clobbered the same way, which made "answered", "still
//! owes an answer" and "gave up" one word at the one place an operator looks.
//!
//! Convention already assumed the dispatcher owned the row, and convention
//! did not hold it. So:
//!
//! ## The property
//!
//! No production file under `crates/hort-app/src/**` except
//! [`ROW_WRITE_OWNER`] contains a method call to any of
//! [`ROW_WRITE_METHODS`]. **No allow-list** — a use case or task handler that
//! needs to move a row's result state is a review conversation about who owns
//! the row, not an exemption entry. A handler reports what the row should
//! become (for `kind='scan'`, a `ScanRowDisposition`) and the dispatcher
//! writes it.
//!
//! ## Why this is scoped to a layer and not to one file
//!
//! The row-write census is **three** production files, not two. Besides the
//! dispatcher and the scan path this guard removed, the Postgres adapter
//! resolves an unmappable *claimed* row terminally inside
//! `claim_pending_by_kinds` — and that call is deliberate. The claim UPDATE
//! has already moved the row to `running` by the time the row projection
//! fails, the claim predicate only selects `pending` rows, and an unmappable
//! row is unmappable on every later claim too, so re-queueing it would trade
//! silent loss for a hot loop that burns a batch slot every poll. A guard
//! phrased as "exactly one file in the workspace" would fail on correct code.
//! [`the_adapter_still_resolves_an_unmappable_claimed_row`] *pins* that call
//! instead, so this guard cannot be satisfied by deleting it.
//!
//! ## The other half of the handoff: one attempt budget
//!
//! [`the_attempt_budget_is_one_configured_number`] covers the number the two
//! sides meet on. The scan path spends its cap to decide the *artifact's*
//! terminal state and the dispatcher spends its cap to decide the *row's*;
//! while the dispatcher's was a compile-time `const u32 = 5` the two agreed
//! only at `HORT_SCANNER_MAX_ATTEMPTS`'s default. An operator who raised the
//! scan budget got rows failed at five with no artifact verdict behind them.
//!
//! ## What this cannot see
//!
//! The blind spot every source scan has: a call reached through a macro, or
//! one spelled through a differently-named local helper that itself calls the
//! port. The review check survives alongside it.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads` and
//! `db_tests_are_serialized`.

use std::fs;
use std::path::{Path, PathBuf};

/// The one application-layer file allowed to write a `jobs` row's result
/// state. `TaskDispatcher::record_outcome_for_row` is the single translation
/// of a `TaskOutcome` into a row transition, for every registered kind; its
/// `return_to_pending` is the fourth call and the same ownership.
const ROW_WRITE_OWNER: &str = "crates/hort-app/src/task_dispatcher.rs";

/// The three fenced result writes on the `JobsRepository` port, as they are
/// spelled at a call site.
const ROW_WRITE_METHODS: [&str; 3] = [".mark_completed(", ".reschedule(", ".mark_failed("];

/// The adapter whose claim path resolves an unmappable claimed row
/// terminally. Deliberate, and pinned rather than forbidden.
const CLAIM_PATH_ADAPTER: &str = "crates/hort-adapters-postgres/src/jobs_repository.rs";

/// The port that declares the three writes. Scanned so a rename of any of
/// them cannot make this guard vacuously green.
const JOBS_PORT: &str = "crates/hort-domain/src/ports/jobs_repository.rs";

/// The scan path, which decides what the row should become without writing
/// it.
const SCAN_ORCHESTRATION: &str = "crates/hort-app/src/use_cases/scan_orchestration.rs";

/// The handler that carries the scan path's disposition to the dispatcher.
const SCAN_HANDLER: &str = "crates/hort-app/src/task_handlers/scan.rs";

/// The worker composition root, which assigns the one configured attempt cap
/// to both sides of the scan boundary.
const WORKER_COMPOSITION: &str = "crates/hort-worker/src/composition.rs";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel} must be readable: {e}"))
}

/// Every `crates/hort-app/src/**/*.rs`, sorted so failures are stable.
fn app_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_rs(&root.join("crates/hort-app/src"), &mut out);
    out.sort();
    assert!(
        !out.is_empty(),
        "crates/hort-app/src must contain Rust sources"
    );
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

/// Drop everything an ownership rule must not police: the inline test module
/// (and anything after it), plus whole-line comments so prose naming a write
/// stays readable.
///
/// Test code legitimately calls the port — every mock `JobsRepository` in
/// this crate is exercised through it, and the dispatcher's own tests assert
/// on the calls. Blanking rather than deleting keeps byte offsets mapping
/// back to original line numbers.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for line in source.lines() {
        // A column-0 `#[cfg(test)]` starts the inline test module; the
        // workspace convention is that such modules come last.
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        let is_comment = line.trim_start().starts_with("//");
        if in_tests || is_comment {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Occurrences of `needle` in `text`, as 1-indexed line numbers.
fn hits(text: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(found) = text[search..].find(needle) {
        let at = search + found;
        out.push(line_of(text, at));
        search = at + needle.len();
    }
    out
}

#[test]
fn only_the_dispatcher_writes_a_jobs_rows_result_state() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();
    let mut owner_writes: Vec<(&str, usize)> = Vec::new();

    for path in app_sources(&root) {
        let rel = path
            .strip_prefix(&root)
            .expect("scanned path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");

        // Test-only harnesses: `test_support.rs` is compiled under
        // `cfg(any(test, feature = "test-support"))` and exists to give tests
        // mock repositories; a `*_tests.rs` sibling is a test module in its
        // own file (the workspace convention for long test modules).
        if rel.ends_with("_tests.rs") || rel.ends_with("test_support.rs") {
            continue;
        }

        let text = production_region(&read(&root, &rel));

        for method in ROW_WRITE_METHODS {
            for line in hits(&text, method) {
                if rel == ROW_WRITE_OWNER {
                    owner_writes.push((method, line));
                } else {
                    violations.push(format!(
                        "{rel}:{line} — `{method}` in the application layer outside \
                         {ROW_WRITE_OWNER}. The `jobs` row has one owner: the result-write \
                         fence is `AND attempts = $2` and nothing else, so a second writer on \
                         the same attempt silently overwrites the first — which is how a \
                         scheduled scan retry became `status='completed'` with no verdict \
                         behind it. Report what the row should become (for `kind='scan'`, a \
                         `ScanRowDisposition` that `ScanTaskHandler` turns into a \
                         `TaskOutcome`) and let the dispatcher write it"
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "application-layer `jobs` result writes outside {ROW_WRITE_OWNER} ({} found):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );

    // Counter-assertion: the scan has to be finding the owner's own writes,
    // or a rename of any of the three methods would make this test vacuously
    // green — the way a source-scan guard usually dies.
    //
    // Four calls, and the shape is part of the property:
    // `record_outcome_for_row` reaches all three (completed / reschedule /
    // terminal) and `return_to_pending` reverts a claimed-but-undispatchable
    // row through `reschedule`.
    let found: Vec<&str> = ROW_WRITE_METHODS
        .iter()
        .filter(|m| owner_writes.iter().any(|(w, _)| w == *m))
        .copied()
        .collect();
    assert_eq!(
        found.len(),
        ROW_WRITE_METHODS.len(),
        "the scan must still find all three writes in {ROW_WRITE_OWNER}; found {found:?} at \
         {owner_writes:?}. A missing one means either the dispatcher stopped writing the row \
         or the method was renamed and this guard is now checking nothing"
    );
    assert_eq!(
        owner_writes.len(),
        4,
        "expected exactly four result writes in {ROW_WRITE_OWNER} (three in \
         `record_outcome_for_row`, one in `return_to_pending`); found {owner_writes:?}. If a \
         write was legitimately added or removed there, update this count deliberately — a \
         drifting count means the scan stopped seeing them"
    );
}

#[test]
fn the_three_result_writes_are_still_the_ports_own() {
    let root = workspace_root();
    let port = read(&root, JOBS_PORT);
    for method in ROW_WRITE_METHODS {
        let decl = format!(
            "fn {}",
            method.trim_start_matches('.').trim_end_matches('(')
        );
        assert!(
            port.contains(&decl),
            "{JOBS_PORT} no longer declares `{decl}`. \
             `only_the_dispatcher_writes_a_jobs_rows_result_state` scans for `{method}` call \
             sites, so a renamed port method makes that scan vacuously green: rename the \
             entry in ROW_WRITE_METHODS in the same change"
        );
    }
}

#[test]
fn the_adapter_still_resolves_an_unmappable_claimed_row() {
    let root = workspace_root();
    let adapter = read(&root, CLAIM_PATH_ADAPTER);

    // The call is spelled in fully-qualified form (the inherent and trait
    // methods share a name on this type), which is also why the layer scan
    // above would not see it even if the adapter were in scope.
    assert!(
        adapter.contains("JobsRepository::mark_failed(self, id, attempt, &reason)"),
        "{CLAIM_PATH_ADAPTER} no longer resolves an unmappable claimed row terminally. That \
         call is deliberate and is the reason the ownership rule above is scoped to \
         `crates/hort-app/**` rather than to one file in the workspace: the claim UPDATE has \
         already moved the row to `running` when the projection fails, the claim predicate \
         only selects `pending` rows, and an unmappable row is unmappable on every later \
         claim — so re-queueing it trades silent loss for a hot loop that burns a batch slot \
         every poll. If this moved, pin it where it now lives"
    );
}

#[test]
fn the_scan_path_decides_the_rows_fate_without_writing_it() {
    let root = workspace_root();
    let orchestration = read(&root, SCAN_ORCHESTRATION);
    let handler = read(&root, SCAN_HANDLER);

    // The scan path still answers the question — it just answers it to the
    // handler instead of to the database. Without this, deleting
    // `record_outcome`'s row decision entirely would leave the guard above
    // green while a failing scan silently reported success.
    assert!(
        orchestration.contains("-> AppResult<ScanRowDisposition>"),
        "{SCAN_ORCHESTRATION}::record_outcome must still report what the row should become. \
         A scan path that reports nothing cannot distinguish a retry from a terminal failure, \
         which is the defect the single-owner change exists to fix"
    );
    for variant in [
        "ScanRowDisposition::Completed",
        "ScanRowDisposition::Failed(",
        "ScanRowDisposition::Retry(",
    ] {
        assert!(
            orchestration.contains(variant),
            "{SCAN_ORCHESTRATION} no longer produces `{variant}`. All three are reachable \
             outcomes of a scan: completed, terminal-failed, and retryable — collapsing any \
             of them is how the row stopped telling them apart"
        );
    }

    // And the handler still carries it to the dispatcher rather than
    // returning a blanket `Completed`, which was the other half of the
    // defect.
    assert!(
        handler.contains("fn outcome_for(disposition: ScanRowDisposition"),
        "{SCAN_HANDLER} must still translate the scan path's disposition into the \
         `TaskOutcome` the dispatcher writes"
    );
    for mapped in [
        "ScanRowDisposition::Completed => TaskOutcome::Completed",
        "ScanRowDisposition::Failed(reason) => TaskOutcome::fail(reason, false)",
        "ScanRowDisposition::Retry(reason) => TaskOutcome::fail(reason, true)",
    ] {
        assert!(
            handler.contains(mapped),
            "{SCAN_HANDLER} no longer maps `{mapped}`. Every scan outcome returning \
             `TaskOutcome::Completed` is the original defect: the dispatcher then writes \
             `status='completed'` over a row the scan had just asked to retry"
        );
    }
}

#[test]
fn the_attempt_budget_is_one_configured_number() {
    let root = workspace_root();
    let dispatcher = production_region(&read(&root, ROW_WRITE_OWNER));
    let composition = production_region(&read(&root, WORKER_COMPOSITION));

    // No compile-time cap on the dispatcher side. This is the shape that
    // made the two caps agree by comment: the scan path read
    // `HORT_SCANNER_MAX_ATTEMPTS` while the dispatcher carried
    // `const JOB_ATTEMPT_CAP: u32 = 5`, so they agreed at the default and
    // nowhere else.
    for line in dispatcher.lines() {
        let t = line.trim_start();
        let is_const = t.starts_with("const ") || t.starts_with("pub const ");
        assert!(
            !(is_const && (t.contains("ATTEMPT_CAP") || t.contains("MAX_ATTEMPTS"))),
            "{ROW_WRITE_OWNER} defines an attempt cap as a constant: {line:?}. The cap must \
             arrive as a `TaskDispatcher::new` argument, because it is the same number \
             `ScanOrchestrationConfig::max_attempts` carries: the scan path spends it on the \
             ARTIFACT's terminal state and the dispatcher on the ROW's. A `const` here means \
             an operator who moves `HORT_SCANNER_MAX_ATTEMPTS` moves only one of them"
        );
    }
    assert!(
        dispatcher.contains("self.attempt_cap"),
        "{ROW_WRITE_OWNER} must read its attempt cap from the value it was constructed with"
    );

    // And the composition root must give both sides the same one.
    assert!(
        composition.contains("orch_cfg.max_attempts = cfg.max_attempts;"),
        "{WORKER_COMPOSITION} must assign the scan orchestrator's cap from \
         `WorkerConfig::max_attempts`"
    );
    let ctor = composition
        .find("TaskDispatcher::new(")
        .map(|at| {
            let rest = &composition[at..];
            let end = rest.find(");").map_or(rest.len(), |e| e + 2);
            rest[..end].to_owned()
        })
        .unwrap_or_else(|| panic!("{WORKER_COMPOSITION} must construct the TaskDispatcher"));
    assert!(
        ctor.contains("cfg.max_attempts"),
        "{WORKER_COMPOSITION}'s `TaskDispatcher::new` call must pass `cfg.max_attempts` — the \
         same field it assigns to `orch_cfg.max_attempts`. Two separately-sourced numbers at \
         this boundary let one side fail the row while the other still considered the artifact \
         owed a verdict. Got:\n{ctor}"
    );
}
