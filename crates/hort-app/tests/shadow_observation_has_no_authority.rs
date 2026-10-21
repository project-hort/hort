//! Structural guard: **the shadow composite-scan observation is
//! unreachable from everything that decides delivery or release.**
//!
//! ADR 0064 D6 holds the composed verdict short of authority: it is an
//! observation an operator promotes on evidence, and until they do, no
//! artifact's downloadability, quarantine status or release may depend
//! on it. Before this guard that sentence was defended by reading the
//! code — and a new table holding verdicts is precisely the thing a
//! later change wires into a release predicate by accident, at which
//! point "we read it and it does not" stops being true and nothing says
//! so.
//!
//! The failure it prevents is silent and one-directional. The row
//! carries a `composite_findings_decision` whose whole purpose is to
//! say "this artifact would have been rejected"; a release path that
//! learned to read it would start rejecting artifacts on an analysis
//! that has never been promoted, and `Rejected` is terminal — the
//! periodic rescan never revisits it.
//!
//! ## The property
//!
//! Over production Rust under `crates/*/src`, with inline test modules
//! and whole-line comments removed:
//!
//! > No file that **decides delivery or release** names the observation
//! > port, its row type or the decision type it stores.
//!
//! Both sides are **derived**, not enumerated.
//!
//! - *Names the observation* is the port's own vocabulary:
//!   [`OBSERVATION_IDENTIFIERS`]. Type names rather than the module
//!   path, because the module path is how the module tree is declared
//!   (`pub mod composite_scan_observations;` in an adapter crate's
//!   `lib.rs`) and a declaration is not a reference. Every way of
//!   reaching the port — a `use`, a path-qualified call, an aliased
//!   import, a field type — spells one of these identifiers at the
//!   point it does so.
//! - *Decides delivery or release* is the domain's own vocabulary for
//!   the decisions themselves: [`RELEASE_DECISION_MARKERS`]. These are
//!   the names of the acts, not of the inputs — which is what lets the
//!   composite path call
//!   `hort_domain::policy::scan::evaluate_scan_result` for its
//!   counterfactual without being a decider. Reading the pure evaluator
//!   is how the row is *computed*; committing a `ScanCompleted`,
//!   transitioning an artifact or answering `is_downloadable` is how a
//!   decision is *made*, and only the second kind may not see this
//!   table.
//!
//! ## Blind spots
//!
//! The one every source scan has, in both directions. A file that
//! reaches the port through a helper in *another* file is invisible on
//! the first side — which is why the projection's only writer is a sink
//! whose `record` cannot return an error, so the handle has one holder
//! and one call site rather than being passed around. And a decision
//! site whose vocabulary is none of the markers is invisible on the
//! second: a new release predicate spelled in new words is a review
//! conversation this scan cannot have for you.
//!
//! A composition root appearing in the decider set would be a false
//! positive of a readable kind — it wires the sink, and it names no
//! decision today. If one ever does, that is worth reading rather than
//! exempting.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads`,
//! `cas_reads_are_verified` and `status_decode_fails_closed`.

use std::fs;
use std::path::{Path, PathBuf};

/// The observation port's vocabulary. A file naming any of these is
/// reaching the shadow projection.
///
/// `CompositeScanObservation` is a prefix of
/// `CompositeScanObservationRepository` and of the Postgres adapter's
/// `PgCompositeScanObservationRepository`, so the substring covers the
/// trait, the row type and every adapter that implements it.
/// `GateDecision` is the type the two verdict columns are stored as:
/// a release path computing one of those is the same hazard reached
/// from the other end.
const OBSERVATION_IDENTIFIERS: [&str; 3] = [
    "CompositeScanObservation",
    "CompositeAssessment",
    "GateDecision",
];

/// The domain's vocabulary for **deciding** delivery or release — the
/// acts, not their inputs.
///
/// - `is_downloadable` is the delivery predicate.
/// - `record_scan_result` / `record_scan_indeterminate` /
///   `commit_scan_result` are where a scan verdict becomes the
///   artifact's, atomically.
/// - `ArtifactReleased` / `ArtifactRejected` are the transitions
///   themselves, and `QuarantineStatus::Released` /
///   `QuarantineStatus::Rejected` the states they land in.
/// - `decide_rejected_transition` is the re-evaluation verdict function.
const RELEASE_DECISION_MARKERS: [&str; 9] = [
    "is_downloadable",
    "record_scan_result(",
    "record_scan_indeterminate(",
    "commit_scan_result",
    "ArtifactReleased",
    "ArtifactRejected",
    "QuarantineStatus::Released",
    "QuarantineStatus::Rejected",
    "decide_rejected_transition",
];

/// Files that must still be found naming the observation, so a rename
/// of the port cannot make this scan vacuously green. One per role the
/// port has: the definition, the adapter, the single producer and the
/// composition root that wires them.
const EXPECTED_OBSERVATION_SITES: [&str; 4] = [
    "crates/hort-domain/src/ports/composite_scan_observation.rs",
    "crates/hort-adapters-postgres/src/composite_scan_observations.rs",
    "crates/hort-app/src/use_cases/composite_scan.rs",
    "crates/hort-worker/src/composition.rs",
];

/// Files that must still be found deciding, so a rename of the decision
/// vocabulary cannot make this scan vacuously green either. The scan
/// axis, the domain's own predicate and the HTTP delivery gate.
const EXPECTED_DECISION_SITES: [&str; 4] = [
    "crates/hort-app/src/use_cases/quarantine_use_case.rs",
    "crates/hort-app/src/use_cases/scan_orchestration.rs",
    "crates/hort-domain/src/entities/artifact.rs",
    "crates/hort-http-core/src/artifact_gate.rs",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Every `crates/<crate>/src/**/*.rs` that is production code, sorted so
/// failures are stable. Test modules in their own files are dropped by
/// name; inline ones are dropped by [`production_region`].
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(crates) = fs::read_dir(root.join("crates")) else {
        panic!("crates/ must exist under the workspace root");
    };
    for crate_dir in crates.flatten() {
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            walk_rs(&src, &mut out);
        }
    }
    out.retain(|p| {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
        !matches!(name.as_deref(), Some("tests.rs") | Some("test_support.rs"))
            && !name.is_some_and(|n| n.ends_with("_tests.rs"))
    });
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

/// Drop the inline test module (and everything after it) plus whole-line
/// comments, so prose *about* a decision or about the projection is not
/// a reference to either. Dropped lines become empty ones, so line
/// numbers still map back.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_tests = false;
    for line in source.lines() {
        // The workspace convention is that an inline `#[cfg(test)]`
        // module at column 0 comes last in the file.
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

/// Does this production region reach the shadow observation projection?
fn names_the_observation(text: &str) -> bool {
    OBSERVATION_IDENTIFIERS.iter().any(|id| text.contains(id))
}

/// Does this production region decide delivery or release?
fn decides_delivery_or_release(text: &str) -> bool {
    RELEASE_DECISION_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
}

/// `(relative path, production region)` for every production source.
fn scanned(root: &Path) -> Vec<(String, String)> {
    production_sources(root)
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(root)
                .expect("scanned path is under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = fs::read_to_string(&path).expect("source file is readable UTF-8");
            let region = production_region(&source);
            (rel, region)
        })
        // This guard's own module docs quote both vocabularies.
        .filter(|(rel, _)| !rel.ends_with("tests/shadow_observation_has_no_authority.rs"))
        .collect()
}

#[test]
fn the_shadow_observation_is_unreachable_from_every_release_decision() {
    let root = workspace_root();
    let files = scanned(&root);

    let violations: Vec<String> = files
        .iter()
        .filter(|(_, text)| names_the_observation(text) && decides_delivery_or_release(text))
        .map(|(rel, text)| {
            let ids: Vec<&str> = OBSERVATION_IDENTIFIERS
                .iter()
                .copied()
                .filter(|id| text.contains(id))
                .collect();
            let markers: Vec<&str> = RELEASE_DECISION_MARKERS
                .iter()
                .copied()
                .filter(|m| text.contains(m))
                .collect();
            format!(
                "{rel} — names the shadow composite observation ({}) and decides delivery or \
                 release ({}). ADR 0064 D6 holds the composed verdict short of authority until \
                 an operator promotes it, and `Rejected` is terminal: a release path reading \
                 this table rejects artifacts on an analysis nobody promoted, irreversibly. \
                 Compute the counterfactual from `evaluate_scan_result` if that is what is \
                 wanted — reading the pure evaluator is not reading the shadow",
                ids.join(", "),
                markers.join(", "),
            )
        })
        .collect();

    assert!(
        violations.is_empty(),
        "the shadow composite observation is reachable from code that decides delivery or \
         release ({} file(s)):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );

    // Counter-assertions. Without them a rename of the port, of the row
    // type or of the decision vocabulary makes the scan vacuously green
    // — the way a source-scan guard usually dies.
    for expected in EXPECTED_OBSERVATION_SITES {
        assert!(
            files
                .iter()
                .any(|(rel, text)| rel == expected && names_the_observation(text)),
            "the scan no longer finds the observation port in {expected}. Either the port was \
             renamed (update {:?}) or that role moved — both are deliberate changes, and a \
             scan that finds nothing proves nothing",
            OBSERVATION_IDENTIFIERS,
        );
    }
    for expected in EXPECTED_DECISION_SITES {
        assert!(
            files
                .iter()
                .any(|(rel, text)| rel == expected && decides_delivery_or_release(text)),
            "the scan no longer recognises {expected} as deciding delivery or release. The \
             decision vocabulary ({:?}) has drifted, and with it the set this guard protects",
            RELEASE_DECISION_MARKERS,
        );
    }
    // Each identifier must be carrying its weight: one that matches
    // nothing is a renamed type the scan is silently no longer looking
    // for.
    for id in OBSERVATION_IDENTIFIERS {
        assert!(
            files.iter().any(|(_, text)| text.contains(id)),
            "no production file names `{id}`; the identifier list has drifted from the port"
        );
    }
}

/// The predicate reports what it exists to report. Asserted by
/// construction rather than by trusting the real scan's silence: a
/// guard that only ever says "nothing found" cannot be told apart from
/// one that looks at nothing.
#[test]
fn a_port_reference_inside_a_release_decision_is_reported() {
    // The shape the guard exists to catch: a release path that learned
    // to read the shadow row.
    let offending = "\
        use hort_domain::ports::composite_scan_observation::CompositeScanObservationRepository;\n\
        async fn release(&self, id: Uuid) {\n\
            let shadow = self.observations.find_by_artifact(id).await;\n\
            self.quarantine.record_scan_result(id, shadow).await;\n\
        }\n";
    let region = production_region(offending);
    assert!(names_the_observation(&region));
    assert!(decides_delivery_or_release(&region));

    // The producer's shape: it names the port and computes a
    // counterfactual through the pure evaluator, and that is not a
    // decision.
    let producer = "\
        use hort_domain::ports::composite_scan_observation::CompositeScanObservation;\n\
        use hort_domain::policy::scan::evaluate_scan_result;\n\
        fn gate(&self) -> GateDecision {\n\
            GateDecision::of(&evaluate_scan_result(c, f, p, e, now))\n\
        }\n";
    let region = production_region(producer);
    assert!(names_the_observation(&region));
    assert!(
        !decides_delivery_or_release(&region),
        "reading the pure evaluator must not count as deciding, or the counterfactual the \
         whole unit exists for could not be computed anywhere"
    );

    // A decision that does not touch the projection is not a finding.
    let decider = "fn gate(&self) -> bool { artifact.is_downloadable() }\n";
    let region = production_region(decider);
    assert!(!names_the_observation(&region));
    assert!(decides_delivery_or_release(&region));
}

/// Prose is not a reference. The composite path's module docs describe
/// what it does *not* reach, and a scan that read comments would make
/// that description a violation of itself.
#[test]
fn comments_and_inline_test_modules_are_not_references() {
    let source = "\
        //! Writes no ScanCompleted and never reaches ArtifactReleased.\n\
        fn produce() {}\n\
        #[cfg(test)]\n\
        mod tests {\n\
            use super::*;\n\
            fn fixture() -> CompositeScanObservation { record_scan_result() }\n\
        }\n";
    let region = production_region(source);
    assert!(!names_the_observation(&region));
    assert!(!decides_delivery_or_release(&region));
}
