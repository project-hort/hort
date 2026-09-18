use crate::error::DomainResult;
use crate::types::{ArtifactCoords, ArtifactKind, ContentHash, Finding, Sbom};

use super::BoxFuture;

/// Stable marker substring embedded in a scanner adapter's
/// [`DomainError::Invariant`](crate::error::DomainError::Invariant)
/// message when a scan is failed because the child's report drain hit
/// the `HORT_SCANNER_MAX_REPORT_SIZE` cap.
/// The orchestrator (`ScanOrchestrationUseCase::run_scan`)
/// matches this marker on a per-backend scan error to attribute the
/// `hort_scan_record_outcome_failures_total{result="report_too_large"}`
/// metric, then routes the backend failure through the normal
/// fail-closed `ScanIndeterminate` path. Centralised here (in the only
/// crate both the scanner adapters and `hort-app` depend on) so the
/// producer and the consumer cannot drift on the literal.
pub const SCAN_REPORT_TOO_LARGE_MARKER: &str = "scan report exceeded cap";

// ---------------------------------------------------------------------------
// ScanTarget
// ---------------------------------------------------------------------------

/// Everything a scanner adapter needs to know about *what* it is
/// scanning, beyond the bytes themselves.
///
/// A content scanner does not read bytes in the abstract. Trivy picks its
/// analyzers from file names, extensions and directory layout, so an
/// adapter has to materialise the CAS bytes under a name — or as a tree —
/// its analyzers recognise. The bare content hash cannot answer "under
/// what name?", which is why this struct carries the format identity and
/// the [`ArtifactKind`] alongside it.
///
/// A backend that adjudicates something other than the payload (the OSV
/// adapter scans the supplied SBOM) reads only the fields it needs and
/// ignores the rest; the struct is a description of the target, not a
/// contract that every field is consumed.
#[derive(Debug, Clone, Copy)]
pub struct ScanTarget<'a> {
    /// CAS address of the bytes to scan.
    pub content_hash: &'a ContentHash,
    /// Format-handler key the artifact's repository is configured with
    /// (`"oci"`, `"npm"`, `"cargo"`, `"pypi"`, `"maven"`). Used for
    /// diagnostics and for the format × backend attribution an operator
    /// needs when a pairing turns out to analyse nothing.
    pub format: &'a str,
    /// The artifact's coordinates. The adapter derives a natural file
    /// name from these when the kind is materialised as a single file
    /// (a `.jar` has to keep its extension, and `log4j-core-2.14.1.jar`
    /// is more use in a report than a bare digest).
    pub coords: &'a ArtifactCoords,
    /// What the bytes are, per the format handler
    /// ([`FormatHandler::scan_kind`](crate::ports::format_handler::FormatHandler::scan_kind)).
    pub kind: ArtifactKind,
}

// ---------------------------------------------------------------------------
// ScanAnalysis
// ---------------------------------------------------------------------------

/// Why a backend produced no verdict.
///
/// Each arm is a *different* operational story and they are kept apart
/// deliberately: the first two are properties of the artifact, the third
/// is a property of the pairing between that artifact and that backend.
/// All three are the absence of a verdict — but they do **not** all gate
/// the artifact, and the split is the whole reason the enum exists:
///
/// - [`Self::NotApplicable`] — **does not gate.** The artifact has no
///   package surface by construction, so no scanner could ever find a
///   threat level in it and there is nothing for a hold to be waiting
///   on. When it is the reason *every* configured backend abstained, the
///   orchestrator records a completed assessment of
///   [`ScanAssessment::NotApplicable`](crate::events::ScanAssessment::NotApplicable)
///   — scan authority exists, the release gate opens, and the trail says
///   "not applicable" rather than "analysed, clean". Holding here would
///   be a category error, not caution.
/// - [`Self::UnusableArchive`] and [`Self::NoAnalyzerMatched`] —
///   **gate.** A surface was expected and could not be assessed, which
///   is the same situation an absent verdict puts the scan axis in, so
///   they fail closed to
///   [`QuarantineStatus::ScanIndeterminate`](crate::entities::artifact::QuarantineStatus::ScanIndeterminate)
///   (ADR 0007). One of these among the abstentions is enough to hold
///   the artifact even when the rest are `NotApplicable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAnalysable {
    /// The artifact carries no package surface for this backend to look
    /// at — an OCI manifest or image config, or a payload no format
    /// handler claims. No scanner invocation was attempted. The same
    /// arm also covers a `rootfs`-mode invocation that *was* attempted
    /// and reported an empty result: Trivy's `rootfs` target runs every
    /// OS-package, language and binary analyzer over the whole
    /// materialised tree, so an empty report there is those analyzers
    /// agreeing the tree has no package surface at all — a completed
    /// fact about the artifact, not an unassessed pairing.
    ///
    /// Does not gate: see the type-level docs.
    NotApplicable,
    /// The payload is an archive the adapter refused to materialise: an
    /// extraction bound tripped, an entry tried to escape the workspace,
    /// or the container is one the adapter cannot open. Refusing is the
    /// point — a partially-extracted tree would be scanned as if it were
    /// the whole artifact.
    ///
    /// Gates (fail-closed): a surface was expected and went unassessed.
    UnusableArchive,
    /// The backend ran against a materialised target and reported no
    /// analysable target at all — not "analysed and clean", but "found
    /// nothing to analyse". For Trivy this is a report with no `Results`
    /// section: no analyzer claimed anything in the workspace.
    ///
    /// Gates (fail-closed): the pairing of this artifact with this
    /// backend is a policy mismatch, and the surface stays unassessed.
    NoAnalyzerMatched,
}

impl NotAnalysable {
    /// Whether this abstention holds the artifact.
    ///
    /// `false` only for [`Self::NotApplicable`] — the one arm that is
    /// *not* an unassessed surface but the absence of a surface. Kept as
    /// an exhaustive match so a future variant has to state its answer
    /// rather than inheriting one.
    #[must_use]
    pub fn gates_release(&self) -> bool {
        match self {
            Self::NotApplicable => false,
            Self::UnusableArchive | Self::NoAnalyzerMatched => true,
        }
    }
}

impl NotAnalysable {
    /// Stable lowercase identifier for logs and metric labels.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::UnusableArchive => "unusable_archive",
            Self::NoAnalyzerMatched => "no_analyzer_matched",
        }
    }
}

impl std::fmt::Display for NotAnalysable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one scanner backend produced for one [`ScanTarget`].
///
/// The distinction this type exists to make: **an empty finding list is
/// only a clean verdict when something was actually analysed.** A
/// `Vec<Finding>` return type cannot express that difference, so "the
/// scanner examined this artifact and found nothing wrong" and "the
/// scanner found nothing it could examine" both arrive as `vec![]` and
/// the second silently earns the release authority of the first. An enum
/// makes the second unrepresentable as a verdict: there is no finding
/// list to read off a [`Self::NothingAnalysable`].
///
/// The consumer (`ScanOrchestrationUseCase`) maps a target that no
/// backend could analyse to the existing fail-closed
/// [`QuarantineStatus::ScanIndeterminate`](crate::entities::artifact::QuarantineStatus::ScanIndeterminate)
/// (ADR 0007) — the same hold an absent verdict already receives — never
/// to a clean `ScanCompleted`. The one exception is an artifact whose
/// abstentions are all [`NotAnalysable::NotApplicable`]: there is no
/// surface to assess, so it records a completed
/// [`ScanAssessment::NotApplicable`](crate::events::ScanAssessment::NotApplicable)
/// instead of a hold — still never a clean verdict. See
/// [`NotAnalysable::gates_release`].
#[derive(Debug, Clone, PartialEq)]
pub enum ScanAnalysis {
    /// The backend analysed the target. An empty vector here **is** a
    /// clean verdict and carries release authority.
    Analysed(Vec<Finding>),
    /// The backend produced no verdict at all. Carries no findings by
    /// construction.
    NothingAnalysable(NotAnalysable),
}

impl ScanAnalysis {
    /// Convenience constructor for a clean verdict — an analysis that
    /// ran and found nothing.
    #[must_use]
    pub fn clean() -> Self {
        Self::Analysed(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// ScannerPort
// ---------------------------------------------------------------------------

/// Outbound port for vulnerability scanners (Trivy, OSV-scanner, etc.).
///
/// Scanner adapters live in their own per-backend crates
/// (`hort-adapters-scanner-<name>`) and depend only on `hort-domain`.
/// Implementations are responsible for any temporary workspace setup
/// and teardown — pulling content bytes from `StoragePort`, materialising
/// them into a temp dir under the names the backend's analyzers expect,
/// invoking the scanner, parsing output. The orchestrator
/// (`ScanOrchestrationUseCase`) treats scanners as opaque
/// target-in, analysis-out functions.
///
/// `sbom` is the format-handler-extracted component list. Many scanners
/// (OSV-scanner) consume it directly; others (Trivy fs) ignore it and
/// re-discover from the payload.
pub trait ScannerPort: Send + Sync {
    /// Stable identifier used in `ScanPolicy.scan_backends` (`"trivy"`,
    /// `"osv"`). Must match the registry name registered at startup.
    fn name(&self) -> &str;

    /// Run the scanner against the target and return what came of it.
    ///
    /// `Ok(ScanAnalysis::Analysed(_))` is a verdict — including an empty
    /// one. `Ok(ScanAnalysis::NothingAnalysable(_))` is the explicit
    /// absence of a verdict and must never be collapsed into an empty
    /// finding list by an implementation; `Err` is reserved for a backend
    /// that failed to run (missing binary, timeout, unparseable report).
    fn scan<'a>(
        &'a self,
        target: &'a ScanTarget<'a>,
        sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<ScanAnalysis>>;

    /// Health check invoked at worker startup. Failure means the backend
    /// is not deployable; the worker logs and exits non-zero.
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::entities::repository::RepositoryFormat;

    /// Compile-time assertion that `ScannerPort` is dyn-compatible.
    /// Runtime: `size_of` executes in the test body for coverage.
    #[test]
    fn scanner_port_is_dyn_compatible() {
        let _ = size_of::<&dyn ScannerPort>();
    }

    /// `Box<dyn ScannerPort>` resolves — proves the trait can be
    /// type-erased into an owned trait object the way adapter
    /// composition roots will store it.
    #[test]
    fn scanner_port_can_be_boxed() {
        let _: Option<Box<dyn ScannerPort>> = None;
    }

    fn coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "org.apache.logging.log4j:log4j-core".to_string(),
            name_as_published: "org.apache.logging.log4j:log4j-core".to_string(),
            version: Some("2.14.1".to_string()),
            path: "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar".to_string(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    /// The target is `Copy` so an adapter can pass it by value into a
    /// helper without the orchestrator having to clone coords.
    #[test]
    fn scan_target_carries_identity_and_kind_and_is_copy() {
        let h = hash();
        let c = coords();
        let target = ScanTarget {
            content_hash: &h,
            format: "maven",
            coords: &c,
            kind: ArtifactKind::MavenJar,
        };
        let copied = target;
        assert_eq!(copied.format, "maven");
        assert_eq!(copied.kind, ArtifactKind::MavenJar);
        assert_eq!(copied.content_hash, &h);
        assert!(copied.coords.path.ends_with(".jar"));
        // Both bindings remain usable — that is what `Copy` buys.
        assert_eq!(target.kind, copied.kind);
    }

    #[test]
    fn not_analysable_labels_are_distinct_and_snake_case() {
        let all = [
            NotAnalysable::NotApplicable,
            NotAnalysable::UnusableArchive,
            NotAnalysable::NoAnalyzerMatched,
        ];
        let mut labels: Vec<&str> = all.iter().map(NotAnalysable::as_str).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "labels must be distinct: {labels:?}");
        for label in labels {
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{label} must be lowercase snake_case"
            );
        }
    }

    /// The split the release gate rests on: only the absence of a
    /// surface is releasable; an unassessed surface still holds.
    #[test]
    fn only_not_applicable_does_not_gate_release() {
        assert!(!NotAnalysable::NotApplicable.gates_release());
        assert!(NotAnalysable::UnusableArchive.gates_release());
        assert!(NotAnalysable::NoAnalyzerMatched.gates_release());
    }

    #[test]
    fn not_analysable_display_matches_as_str() {
        assert_eq!(
            NotAnalysable::NoAnalyzerMatched.to_string(),
            "no_analyzer_matched"
        );
        assert_eq!(NotAnalysable::NotApplicable.to_string(), "not_applicable");
        assert_eq!(
            NotAnalysable::UnusableArchive.to_string(),
            "unusable_archive"
        );
    }

    /// The whole point of the enum: a clean verdict and an absent
    /// verdict are different values, not the same empty vector.
    #[test]
    fn clean_verdict_is_not_the_same_value_as_nothing_analysable() {
        let clean = ScanAnalysis::clean();
        assert_eq!(clean, ScanAnalysis::Analysed(Vec::new()));
        assert_ne!(
            clean,
            ScanAnalysis::NothingAnalysable(NotAnalysable::NoAnalyzerMatched)
        );
        // And there is no finding list to read off the absent verdict.
        match ScanAnalysis::NothingAnalysable(NotAnalysable::UnusableArchive) {
            ScanAnalysis::Analysed(f) => panic!("must not be a verdict: {f:?}"),
            ScanAnalysis::NothingAnalysable(reason) => {
                assert_eq!(reason, NotAnalysable::UnusableArchive);
            }
        }
    }

    #[test]
    fn analysis_debug_is_available_for_diagnostics() {
        let rendered = format!(
            "{:?}",
            ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable)
        );
        assert!(rendered.contains("NotApplicable"), "{rendered}");
    }
}
