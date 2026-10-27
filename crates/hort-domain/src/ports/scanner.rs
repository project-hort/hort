use crate::entities::scan_policy::CompositeVerdictMode;
use crate::error::DomainResult;
use crate::oci::{ImageLayout, ImageLayoutLayer};
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
// ComposedImage
// ---------------------------------------------------------------------------

/// A composed OCI image, resolved from an image manifest's own bytes and
/// handed to a backend as **one** scan unit (ADR 0064 D1).
///
/// The package set of a composed image is not a function of its layers'
/// individually assessed package sets — a later layer adds packages the
/// earlier one cannot be read for, and removes packages the earlier one
/// carries — so the composition has to be assembled and assessed as a
/// whole. This type is what the adapter needs in order to write that
/// composition out as an OCI image layout **without parsing anything**:
/// the manifest's own hash and declared media type, the config's hash,
/// and every layer's hash and container in the order they are applied.
///
/// Resolving the constituent set is the **application layer's** job, not
/// the adapter's: deciding what to scan reads the manifest bytes and the
/// config bytes and arbitrates between them, which is a decision, while
/// materialising a resolved description is mechanism.
///
/// **A malformed composite is unrepresentable**, which is the point of
/// the private fields: the only constructor is [`Self::new`], it takes an
/// [`ImageLayout`], and an `ImageLayout` is only ever produced by
/// completing a
/// [`ManifestNomination`](crate::oci::ManifestNomination) against its
/// config bytes — a nomination that only
/// [`strict_manifest_nomination`](crate::oci::strict_manifest_nomination)
/// produces, and which has no other producer. There is one door into a
/// composition and it is that pair. By the time
/// a layout exists, *every* declared descriptor has been accounted for, a
/// layer container the materialisation cannot describe has been refused,
/// an index has been refused, and a config that disagrees with the layer
/// list has been refused. There is therefore no composite with no layers,
/// no composite missing its config, and no composite carrying a layer
/// nobody vetted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedImage {
    /// CAS content hash of the image manifest — the composition's own
    /// identity and the artifact row that carries its verdict (D4).
    manifest: ContentHash,
    /// The config and ordered layers the manifest's bytes resolved to.
    layout: ImageLayout,
}

impl ComposedImage {
    /// Build the scan unit of the manifest at `manifest` from the
    /// `layout` its bytes resolved to.
    #[must_use]
    pub fn new(manifest: ContentHash, layout: ImageLayout) -> Self {
        Self { manifest, layout }
    }

    /// CAS content hash of the image manifest blob.
    #[must_use]
    pub fn manifest(&self) -> &ContentHash {
        &self.manifest
    }

    /// The manifest's `mediaType`, for the layout's `index.json`
    /// descriptor — see [`ImageLayout::manifest_media_type`].
    #[must_use]
    pub fn manifest_media_type(&self) -> &str {
        &self.layout.manifest_media_type
    }

    /// CAS content hash of the image config blob.
    #[must_use]
    pub fn config(&self) -> &ContentHash {
        &self.layout.config
    }

    /// Every layer, in the order they are applied. Never empty and never
    /// a subset of what the manifest declared.
    #[must_use]
    pub fn layers(&self) -> &[ImageLayoutLayer] {
        &self.layout.layers
    }

    /// How many CAS objects the composition is made of: the manifest, the
    /// config and every layer. What a whole-image budget counts, since
    /// each one costs a storage read, a file and an inode.
    #[must_use]
    pub fn constituent_count(&self) -> usize {
        2 + self.layout.layers.len()
    }
}

// ---------------------------------------------------------------------------
// ScanUnit
// ---------------------------------------------------------------------------

/// What a backend is pointed at: one stored object, or a composition of
/// several.
///
/// An enum rather than a hash plus an optional composition beside it,
/// because the two shapes have **different** identities and a target
/// carrying both could disagree with itself about which bytes the scan is
/// of. Here a blob target holds exactly one hash, a composed image holds
/// exactly one [`ComposedImage`], and the dispatch an adapter writes over
/// them is exhaustive — so a third shape has to state its own
/// materialisation rather than inheriting the blob one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanUnit<'a> {
    /// One CAS object: the artifact's own bytes, materialised by
    /// [`ScanTarget::kind`].
    Blob(&'a ContentHash),
    /// A composed OCI image — an image manifest together with the config
    /// and ordered layers its bytes name (ADR 0064 D1).
    Image(&'a ComposedImage),
}

impl ScanUnit<'_> {
    /// The CAS address of the artifact row this unit is **about**: the
    /// blob's own hash, or the composed image's manifest hash.
    ///
    /// For diagnostics and attribution, so a log or metric site does not
    /// have to match on the shape to say which artifact it is talking
    /// about. It is deliberately not "the bytes to materialise" — for a
    /// composition that is more than one object, and an adapter that
    /// treated this as the whole input would scan the manifest alone.
    #[must_use]
    pub fn subject_hash(&self) -> &ContentHash {
        match self {
            Self::Blob(hash) => hash,
            Self::Image(image) => image.manifest(),
        }
    }
}

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
/// contract that every field is consumed. That is what lets a composed
/// image reach every backend without each one having to understand it.
#[derive(Debug, Clone, Copy)]
pub struct ScanTarget<'a> {
    /// What is to be scanned: one stored object, or a composition of
    /// them.
    pub unit: ScanUnit<'a>,
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
    ///
    /// The kind of the artifact *row* — for a composed image that is the
    /// manifest, whose own bytes carry no package surface. The
    /// materialisation of a composition comes from
    /// [`ScanUnit::Image`], never from this field.
    pub kind: ArtifactKind,
}

impl ScanTarget<'_> {
    /// The CAS address of the artifact row this target is about — see
    /// [`ScanUnit::subject_hash`].
    #[must_use]
    pub fn subject_hash(&self) -> &ContentHash {
        self.unit.subject_hash()
    }
}

// ---------------------------------------------------------------------------
// ScanAnalysis
// ---------------------------------------------------------------------------

/// Why a backend produced no verdict.
///
/// Each arm is a *different* operational story and they are kept apart
/// deliberately. Every one of them is the absence of a verdict — but
/// they do **not** all gate the artifact, and they are not all
/// statements about the same thing, which is the whole reason the enum
/// exists:
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
/// - [`Self::UnusableArchive`], [`Self::NoAnalyzerMatched`] and
///   [`Self::IncompleteComposition`] — **gate.** A surface was expected
///   and could not be assessed, which is the same situation an absent
///   verdict puts the scan axis in, so they fail closed to
///   [`QuarantineStatus::ScanIndeterminate`](crate::entities::artifact::QuarantineStatus::ScanIndeterminate)
///   (ADR 0007). One of these among the abstentions is enough to hold
///   the artifact even when the rest are `NotApplicable`.
/// - [`Self::UnsupportedContainer`] — **gates, except for the one row
///   whose filesystem is not its own to assess.** See below.
///
/// # Two kinds of refusal, and only one of them is about the artifact
///
/// [`Self::UnusableArchive`] and [`Self::UnsupportedContainer`] are
/// separate values because they are statements about different things.
/// "This archive tripped an extraction bound" or "an entry tried to
/// escape the workspace" is about the payload's own bytes. "I have no
/// decoder for this container" is about this adapter's decoder
/// inventory — the bytes inside may be perfectly ordinary, and a
/// composition that *does* decode them reads them without difficulty
/// (ADR 0064 D2, whose measured case is `tar+zstd`).
///
/// Collapsing the two is what made a compression format and a zip bomb
/// the same log line and the same metric label. Keeping them apart is
/// what lets the second one stop gating a constituent whose filesystem
/// verdict belongs to its composition, while the first keeps gating
/// everywhere — the pair that [`Self::gates_release`] decides.
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
    /// The payload is an archive the adapter refused to materialise for
    /// a reason **about the payload's own bytes**: an extraction bound
    /// tripped, an entry tried to escape the workspace, an entry name
    /// could not be decoded well enough to put to the containment rule,
    /// or the archive could not be read at all. Refusing is the point —
    /// a partially-extracted tree would be scanned as if it were the
    /// whole artifact.
    ///
    /// "The archive could not be read" lands here rather than on
    /// [`Self::UnsupportedContainer`] deliberately: a reader that fails
    /// to open its input cannot tell a container it has no decoder for
    /// from a corrupt archive of a container it does decode, and
    /// fail-closed is which way an undecidable case goes.
    ///
    /// Gates (fail-closed): a surface was expected and went unassessed.
    UnusableArchive,
    /// The payload is a container this adapter has **no decoder for**,
    /// positively identified as such — not a broken archive, and not an
    /// absence of package surface. The bytes inside were never reached,
    /// so nothing here is a claim about them.
    ///
    /// Distinct from [`Self::UnusableArchive`] because the two are
    /// statements about different things, and only this one is a
    /// statement about hort rather than about the artifact. The measured
    /// case is an OCI `tar+zstd` layer: the per-blob materialiser
    /// decodes gzip and plain tar itself and has no zstd, xz or bzip2
    /// decoder, while the scanner composes `tar+zstd` identically to the
    /// other two — so the same bytes that are terminal standing alone
    /// are read without difficulty as part of a composition.
    ///
    /// **Gates, except on a constituent whose composition carries the
    /// filesystem verdict** (ADR 0064 D2) — the one arm whose answer
    /// [`Self::gates_release`] takes from its caller's context rather
    /// than from the variant alone. ADR 0064 D2 places this statement
    /// with the composition: it is not a statement that the layer's
    /// bytes are dangerous, so it must not gate the constituent once
    /// something above it is assessing the filesystem. The obligation
    /// **moves**, it is never dropped, which is why it moves only where
    /// an operator has promoted the composite verdict — before that, a
    /// constituent that stopped gating here would be a constituent
    /// nothing gates, trading a precise-but-wrong hold for no hold at
    /// all.
    UnsupportedContainer,
    /// The backend ran against a materialised target and reported no
    /// analysable target at all — not "analysed and clean", but "found
    /// nothing to analyse". For Trivy this is a report with no `Results`
    /// section: no analyzer claimed anything in the workspace.
    ///
    /// Two different situations reach it, and both are an expected
    /// surface left unassessed. For a **single artifact** it says the
    /// pairing of this artifact with this backend is a policy mismatch.
    /// For a **composed image** ([`ScanUnit::Image`]) it says the
    /// composition was assembled and the scanner found nothing in it to
    /// analyse — which cannot be "no package surface by construction",
    /// because a composition *is* the thing that was supposed to be
    /// assessed and its whole reason for existing is that the package
    /// surface belongs to it rather than to its layers (ADR 0064 D1).
    ///
    /// Gates (fail-closed): the surface stays unassessed either way.
    NoAnalyzerMatched,
    /// No report about a composed image exists. In every case this value
    /// reaches today, that is because the composition itself was not
    /// produced: a constituent was missing from storage, unreadable, the
    /// repository has no upstream to acquire it from, or the composition
    /// tripped the whole-image budget.
    ///
    /// Deliberately **not** the same value as [`Self::NoAnalyzerMatched`]:
    /// "I could not build the image" and "I built the image and nothing
    /// claimed anything in it" are facts about different things, and only
    /// the second says anything at all about the image. Collapsing them
    /// would make an incomplete composition indistinguishable from an
    /// assembled one — the partial-layout hazard the whole composition
    /// path exists to refuse, one level up (ADR 0064 D1: never a partial
    /// layout, never a clean verdict over a subset) — and it would put a
    /// false statement in the record of a manifest the gate is holding:
    /// a complete composition that every backend abstained on is none of
    /// the three causes above.
    ///
    /// One arm is not strictly either: a backend that **errored** on an
    /// assembled composition, with its retry request declined. No report
    /// exists, which is what this value says, but the composition was
    /// built — the composite path's own
    /// `CompositeScan::verdict_of` keeps it here because `NotAnalysable`
    /// has no word for "a backend malfunctioned on an assembled image",
    /// and inventing one is a decision about the vocabulary rather than
    /// about this artifact.
    ///
    /// Gates (fail-closed): the composition is the unit of filesystem
    /// assessment, so an image that was never assembled is an image whose
    /// filesystem went unassessed.
    IncompleteComposition,
}

impl NotAnalysable {
    /// Whether this abstention holds the artifact it is about.
    ///
    /// Two arms answer without consulting anything: [`Self::NotApplicable`]
    /// is not an unassessed surface but the absence of a surface, so there
    /// is nothing for a hold to wait on; [`Self::UnusableArchive`],
    /// [`Self::NoAnalyzerMatched`] and [`Self::IncompleteComposition`] are
    /// an expected surface that went unassessed, and the fail-closed
    /// reading of that is a hold (ADR 0007).
    ///
    /// [`Self::UnsupportedContainer`] is the one arm whose answer depends
    /// on the artifact rather than only on the refusal, and `kind` and
    /// `composite_verdict` are what that depends on (ADR 0064 D2). "I have
    /// no decoder for this container" is a statement about hort's decoder
    /// inventory, not about the bytes — so on a row that is a *constituent*
    /// of a composition hort assesses as one unit, and only where an
    /// operator has promoted that composite verdict, the statement belongs
    /// to the composition and must not hold the constituent. On every other
    /// row, and under every other posture, it holds exactly as it did
    /// before.
    ///
    /// Both inputs are required, and together: promotion alone would move
    /// the obligation for every format ADR 0064 explicitly leaves undecided,
    /// and the kind alone would move it before an operator had granted the
    /// composite verdict any authority — which is the "obligation dropped
    /// rather than moved" hazard D6's ordering exists to prevent.
    ///
    /// "Which rows are constituents?" is
    /// [`ArtifactKind::is_composition_constituent`]'s answer rather than a
    /// match here, so an absent assessment and a
    /// [`Finding`](crate::types::Finding) over the same surface cannot
    /// disagree about whether the row is a constituent.
    ///
    /// Exhaustive over the variants with no wildcard arm, so a future one
    /// has to state its answer rather than inheriting one.
    #[must_use]
    pub fn gates_release(
        &self,
        kind: ArtifactKind,
        composite_verdict: CompositeVerdictMode,
    ) -> bool {
        match self {
            Self::NotApplicable => false,
            Self::UnsupportedContainer => {
                !(kind.is_composition_constituent()
                    && composite_verdict.carries_release_authority())
            }
            Self::UnusableArchive | Self::NoAnalyzerMatched | Self::IncompleteComposition => true,
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
            Self::UnsupportedContainer => "unsupported_container",
            Self::NoAnalyzerMatched => "no_analyzer_matched",
            Self::IncompleteComposition => "incomplete_composition",
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
// EvidenceBasis
// ---------------------------------------------------------------------------

/// What a scanner backend looked at in order to produce its findings.
///
/// This is the backend's own, permanent property — not a per-scan outcome
/// — and the consumer needs it for one question it cannot answer any other
/// way: **what does it mean when a finding's `purl` matches nothing in the
/// artifact's SBOM?**
///
/// - [`Self::MaterialisedPayload`] — the backend pulled the artifact's
///   bytes out of storage and reported what it unpacked. A package it
///   names that the BOM never listed is a normal outcome, because the BOM
///   and the materialised tree are derived differently; the package was in
///   the artifact either way.
/// - [`Self::SuppliedSbom`] — the BOM *is* the backend's whole input. A
///   purl matching nothing in it cannot be a package discovered elsewhere,
///   so it is a join that failed, and the consumer records that it could
///   not establish the relation rather than inventing one.
///
/// Deriving the distinction from the backend's evidence, rather than from
/// a list of backend names held by the consumer, is what keeps it correct
/// when a backend is added: "did this come from the payload or from the
/// BOM?" has an answer for any scanner, while a name list silently omits
/// the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceBasis {
    /// The backend materialises the artifact's stored bytes and scans what
    /// it unpacked (Trivy).
    MaterialisedPayload,
    /// The backend consumes the supplied SBOM and never reads the payload
    /// (OSV-scanner). The same basis as the advisory-enrichment path,
    /// which the orchestrator feeds with the component list directly.
    SuppliedSbom,
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
///
/// A target names **one** scan unit, and that unit is either a stored
/// object or a composition of them ([`ScanUnit`]). An adapter that
/// materialises the payload has to answer for both: a backend that read
/// only the blob arm would scan a composed image's manifest document and
/// report a clean verdict about a document, which is the wrong subject.
/// A backend that adjudicates something else entirely (the OSV adapter
/// scans the supplied SBOM) ignores the unit, as it already ignores every
/// other payload fact.
pub trait ScannerPort: Send + Sync {
    /// Stable identifier used in `ScanPolicy.scan_backends` (`"trivy"`,
    /// `"osv"`). Must match the registry name registered at startup.
    fn name(&self) -> &str;

    /// Whether this backend can produce a verdict for at least one
    /// artifact kind of the given repository format (`trivy` → every
    /// format whose kinds it can materialise; `osv` → every format whose
    /// handler exposes an SBOM). The orchestrator does not invoke a
    /// backend on a format it does not apply to, because such an
    /// invocation can only ever return the absence of a verdict — an
    /// inert pairing that would look like coverage in a policy while
    /// analysing nothing at runtime.
    ///
    /// The mirror of
    /// [`ProvenancePort::applies_to`](crate::ports::provenance::ProvenancePort::applies_to)
    /// on the scan axis. The answer is the **adapter's own truth**: it
    /// derives from that backend's materialisation (or SBOM) capability
    /// and is mirrored — never duplicated by hand — by the static record
    /// the apply path reads, which has no adapters to ask.
    ///
    /// A backend answers `true` for a format only where a test proves a
    /// known-vulnerable fixture of that format yields at least one
    /// finding through this backend. No such test means `false`: a cell
    /// claimed without evidence is the false release authority the split
    /// between a verdict and an abstention exists to prevent.
    fn applies_to(&self, format: &str) -> bool;

    /// What this backend looked at to produce its findings — see
    /// [`EvidenceBasis`].
    ///
    /// Required, with no default, for the same reason
    /// [`applies_to`](Self::applies_to) is: a defaulted answer would let a
    /// new adapter inherit a claim about its own evidence that nobody
    /// checked. The two readings differ in what the consumer records for a
    /// finding the SBOM does not list, so an inherited wrong answer is
    /// silent — it produces a plausible relation on every such finding.
    fn evidence_basis(&self) -> EvidenceBasis;

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

    /// `applies_to` is a required method with no default, so a new
    /// adapter cannot inherit a blanket "yes" (or "no") for every
    /// format: it has to state its own capability. This stub proves the
    /// method is dispatchable through the trait object the orchestrator
    /// holds.
    #[test]
    fn applies_to_is_answered_per_format_through_the_trait_object() {
        struct OnlyMaven;
        impl ScannerPort for OnlyMaven {
            fn name(&self) -> &str {
                "only-maven"
            }
            fn applies_to(&self, format: &str) -> bool {
                format == "maven"
            }
            fn evidence_basis(&self) -> EvidenceBasis {
                EvidenceBasis::MaterialisedPayload
            }
            fn scan<'a>(
                &'a self,
                _target: &'a ScanTarget<'a>,
                _sbom: Option<&'a Sbom>,
            ) -> BoxFuture<'a, DomainResult<ScanAnalysis>> {
                Box::pin(async { Ok(ScanAnalysis::clean()) })
            }
            fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }
        let port: &dyn ScannerPort = &OnlyMaven;
        assert!(port.applies_to("maven"));
        assert!(!port.applies_to("oci"));
        assert!(!port.applies_to("gradle"));
        // Same shape, same reason: `evidence_basis` is required, so the
        // stub had to state it, and it is dispatchable through the trait
        // object the orchestrator holds.
        assert_eq!(port.evidence_basis(), EvidenceBasis::MaterialisedPayload);
    }

    /// The two bases are distinct values and both are constructible —
    /// the consumer branches on them and would read a collapsed enum as
    /// "every backend scanned the payload".
    #[test]
    fn evidence_basis_variants_are_distinct_and_debug_printable() {
        assert_ne!(
            EvidenceBasis::MaterialisedPayload,
            EvidenceBasis::SuppliedSbom
        );
        let copied = EvidenceBasis::SuppliedSbom;
        assert_eq!(copied, EvidenceBasis::SuppliedSbom);
        assert!(format!("{:?}", EvidenceBasis::MaterialisedPayload).contains("MaterialisedPayload"));
        assert!(format!("{:?}", EvidenceBasis::SuppliedSbom).contains("SuppliedSbom"));
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
            unit: ScanUnit::Blob(&h),
            format: "maven",
            coords: &c,
            kind: ArtifactKind::MavenJar,
        };
        let copied = target;
        assert_eq!(copied.format, "maven");
        assert_eq!(copied.kind, ArtifactKind::MavenJar);
        assert_eq!(copied.subject_hash(), &h);
        assert!(copied.coords.path.ends_with(".jar"));
        // Both bindings remain usable — that is what `Copy` buys.
        assert_eq!(target.kind, copied.kind);
    }

    /// The layer digests and media types the strict parse resolved, in
    /// manifest order, reach the adapter untouched — that list *is* what
    /// the layout writer walks, so an order or a container lost here is a
    /// different filesystem scanned.
    #[test]
    fn a_composed_image_carries_the_manifest_config_and_ordered_layers() {
        let manifest: ContentHash = "11".repeat(32).parse().unwrap();
        let config: ContentHash = "22".repeat(32).parse().unwrap();
        let lower: ContentHash = "33".repeat(32).parse().unwrap();
        let upper: ContentHash = "44".repeat(32).parse().unwrap();
        let image = ComposedImage::new(
            manifest.clone(),
            ImageLayout {
                config: config.clone(),
                layers: vec![
                    ImageLayoutLayer {
                        hash: lower.clone(),
                        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
                    },
                    ImageLayoutLayer {
                        hash: upper.clone(),
                        media_type: "application/vnd.oci.image.layer.v1.tar+zstd".to_string(),
                    },
                ],
                manifest_media_type: crate::oci::OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
            },
        );
        assert_eq!(image.manifest(), &manifest);
        assert_eq!(image.config(), &config);
        assert_eq!(
            image.manifest_media_type(),
            crate::oci::OCI_IMAGE_MANIFEST_MEDIA_TYPE
        );
        let hashes: Vec<&ContentHash> = image.layers().iter().map(|l| &l.hash).collect();
        assert_eq!(hashes, vec![&lower, &upper]);
        assert!(image.layers()[1].media_type.ends_with("tar+zstd"));
        // The manifest and the config count alongside the layers: each is
        // a storage read and a file in the layout.
        assert_eq!(image.constituent_count(), 4);

        // And the unit says which artifact row it is about without a
        // caller having to match on the shape.
        let unit = ScanUnit::Image(&image);
        assert_eq!(unit.subject_hash(), &manifest);
        let blob = ScanUnit::Blob(&config);
        assert_eq!(blob.subject_hash(), &config);
        assert_ne!(unit, blob);
    }

    /// Every arm, so a new one has to be added here before the
    /// assertions below can be read as covering the enum.
    const EVERY_ABSTENTION: [NotAnalysable; 5] = [
        NotAnalysable::NotApplicable,
        NotAnalysable::UnusableArchive,
        NotAnalysable::UnsupportedContainer,
        NotAnalysable::NoAnalyzerMatched,
        NotAnalysable::IncompleteComposition,
    ];

    #[test]
    fn not_analysable_labels_are_distinct_and_snake_case() {
        let all = EVERY_ABSTENTION;
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

    /// Every kind × posture pair in which nothing has moved — which is
    /// every one but a promoted constituent. Over all five variants, so
    /// "an unpromoted repository is byte-for-byte unchanged" is asserted
    /// rather than reasoned about.
    const UNMOVED: [(ArtifactKind, CompositeVerdictMode); 3] = [
        // A constituent, but no operator has promoted anything.
        (ArtifactKind::OciBlob, CompositeVerdictMode::Observed),
        // The composition itself, which carries its own verdict.
        (ArtifactKind::OciManifest, CompositeVerdictMode::Promoted),
        // A format ADR 0064 leaves undecided, under a policy whose
        // promotion is about OCI images.
        (ArtifactKind::NpmTarball, CompositeVerdictMode::Promoted),
    ];

    /// The split the release gate rests on: only the absence of a
    /// surface is releasable; an unassessed surface still holds.
    ///
    /// Asserted on every kind × posture pair in which nothing has moved,
    /// because the answers below are what an unpromoted repository — and
    /// every non-OCI repository under any posture — must keep getting.
    #[test]
    fn only_not_applicable_does_not_gate_release() {
        for (kind, mode) in UNMOVED {
            assert!(!NotAnalysable::NotApplicable.gates_release(kind, mode));
            assert!(NotAnalysable::UnusableArchive.gates_release(kind, mode));
            assert!(NotAnalysable::NoAnalyzerMatched.gates_release(kind, mode));
            // An image that was never assembled is an image whose
            // filesystem went unassessed — the one answer that must not
            // be the non-gating one.
            assert!(NotAnalysable::IncompleteComposition.gates_release(kind, mode));
            // Asserted again below as a pair with `UnusableArchive`,
            // which is the form that makes the day one of them stops a
            // deliberate edit rather than a line disappearing unnoticed.
            assert!(
                NotAnalysable::UnsupportedContainer.gates_release(kind, mode),
                "{kind} under {mode}: nothing has moved for this row"
            );
        }
    }

    /// **The pair ADR 0064 D2 splits, asserted together.** On a
    /// constituent under a promoted composite verdict, "I have no decoder
    /// for this container" stops holding the layer — the composition
    /// decodes it, and the measured case is `tar+zstd` — while "this
    /// archive tripped an extraction bound" keeps holding it, because
    /// that is a statement about the bytes.
    ///
    /// One test over the pair, because either assertion alone is
    /// satisfied by a wrong rule: dropping both would disarm the zip-bomb
    /// refusal, and dropping neither would leave the `tar+zstd` layer
    /// terminal with ADR 0062 withholding every image that binds it — the
    /// defect this moves.
    #[test]
    fn a_promoted_constituent_stops_gating_on_a_missing_decoder_but_not_on_a_hostile_archive() {
        let (kind, mode) = (ArtifactKind::OciBlob, CompositeVerdictMode::Promoted);
        assert!(
            !NotAnalysable::UnsupportedContainer.gates_release(kind, mode),
            "a missing decoder is a statement about hort, not about the layer; \
             the composition that reads these bytes carries the verdict"
        );
        assert!(
            NotAnalysable::UnusableArchive.gates_release(kind, mode),
            "an extraction bound tripped, or an entry that tried to escape the \
             workspace, is about these bytes and holds them wherever their \
             filesystem verdict lives"
        );
    }

    /// And the one cell that moved is the only one: every variant, over
    /// every kind, under both postures.
    ///
    /// The exhaustive form is what scopes the loosening. ADR 0064 decides
    /// the OCI image and says of every other format "not decided here";
    /// a kind drifting onto the moved side would hand an npm tarball a
    /// decision nobody took, and it would do so silently — the refusal
    /// would simply stop holding.
    #[test]
    fn exactly_one_cell_of_the_kind_posture_matrix_moved() {
        const EVERY_KIND: [ArtifactKind; 9] = [
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PyWheel,
            ArtifactKind::PySdist,
            ArtifactKind::OciBlob,
            ArtifactKind::OciManifest,
            ArtifactKind::Other,
        ];
        let mut moved = 0usize;
        for refusal in EVERY_ABSTENTION {
            for kind in EVERY_KIND {
                for mode in [
                    CompositeVerdictMode::Observed,
                    CompositeVerdictMode::Promoted,
                ] {
                    let gates = refusal.gates_release(kind, mode);
                    let is_moved_cell = refusal == NotAnalysable::UnsupportedContainer
                        && kind == ArtifactKind::OciBlob
                        && mode == CompositeVerdictMode::Promoted;
                    if is_moved_cell {
                        moved += 1;
                        assert!(!gates, "the moved cell must not gate");
                    } else if refusal == NotAnalysable::NotApplicable {
                        assert!(!gates, "{refusal} is the absence of a surface everywhere");
                    } else {
                        assert!(
                            gates,
                            "{refusal} on {kind} under {mode} must gate exactly as it did \
                             before ADR 0064 D2's loosening"
                        );
                    }
                }
            }
        }
        assert_eq!(moved, 1, "one cell moved, and it is the one above");
    }

    /// The two are **distinguishable by value**, which is what makes
    /// them distinguishable in the log line and in the metric label:
    /// both read their text off [`NotAnalysable::as_str`].
    ///
    /// "An archive tripped an extraction bound" and "I have no decoder
    /// for this container" were one value, so an operator could not tell
    /// a zip bomb from a compression format. The pair being unequal is
    /// the whole deliverable; `gates_release` agreeing on both is what
    /// says this unit changed no outcome.
    #[test]
    fn an_undecodable_container_is_not_the_same_value_as_an_unusable_archive() {
        assert_ne!(
            NotAnalysable::UnusableArchive,
            NotAnalysable::UnsupportedContainer
        );
        assert_ne!(
            NotAnalysable::UnusableArchive.as_str(),
            NotAnalysable::UnsupportedContainer.as_str()
        );
        assert_eq!(
            NotAnalysable::UnsupportedContainer.as_str(),
            "unsupported_container"
        );
        assert_eq!(
            NotAnalysable::UnsupportedContainer.to_string(),
            NotAnalysable::UnsupportedContainer.as_str(),
            "the log line and the metric label are the same string"
        );
        assert_eq!(
            NotAnalysable::UnusableArchive
                .gates_release(ArtifactKind::OciBlob, CompositeVerdictMode::Observed),
            NotAnalysable::UnsupportedContainer
                .gates_release(ArtifactKind::OciBlob, CompositeVerdictMode::Observed),
            "splitting the reason changed no outcome on its own; what separates \
             the two is the promoted constituent asserted above"
        );
    }

    /// Every arm answers `gates_release` and labels itself, with no arm
    /// silently inheriting either. Named separately from the two tests
    /// above because those are about one pair and this is about the
    /// enum: a sixth variant added without an answer fails here.
    #[test]
    fn every_abstention_answers_both_questions() {
        for refusal in EVERY_ABSTENTION {
            let label = refusal.as_str();
            assert!(!label.is_empty(), "{refusal:?} has no label");
            // `gates_release` is an exhaustive match, so this call is
            // what proves the arm was given an answer rather than
            // falling through a wildcard.
            let _ = refusal.gates_release(ArtifactKind::NpmTarball, CompositeVerdictMode::Observed);
        }
        assert_eq!(
            EVERY_ABSTENTION
                .iter()
                .filter(
                    |r| !r.gates_release(ArtifactKind::NpmTarball, CompositeVerdictMode::Observed)
                )
                .count(),
            1,
            "exactly one arm is the absence of a surface rather than an unassessed one"
        );
    }

    /// The two composite outcomes are distinct values. An assembled
    /// composition that reported nothing and a composition that could not
    /// be assembled are different facts, and a consumer that saw one
    /// value could not tell them apart.
    #[test]
    fn an_unassembled_composition_is_not_the_same_value_as_an_empty_one() {
        assert_ne!(
            NotAnalysable::IncompleteComposition,
            NotAnalysable::NoAnalyzerMatched
        );
        assert_ne!(
            NotAnalysable::IncompleteComposition,
            NotAnalysable::NotApplicable
        );
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
        assert_eq!(
            NotAnalysable::IncompleteComposition.to_string(),
            "incomplete_composition"
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
