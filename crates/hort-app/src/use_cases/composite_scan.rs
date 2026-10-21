//! Resolving an OCI image manifest's **composed** scan unit, and running
//! it as a shadow assessment.
//!
//! The unit of filesystem assessment for an OCI image is the image
//! manifest (ADR 0064 D1). A layer scanned on its own is evidence, not a
//! verdict: a layer carrying a complete package database and no
//! `/etc/os-release` reports *nothing* as a root filesystem, because
//! without an OS marker in those same bytes the scanner recognises no
//! operating system and never runs the package check — measured, on a
//! real image, at twenty-five packages and ninety-two advisories never
//! assessed. The composition is where that surface actually lives.
//!
//! # Who resolves what
//!
//! Deciding *what* to scan happens here, in the application layer:
//! reading the manifest bytes, acquiring and reading the config bytes, and
//! arbitrating between the two is a decision. Writing the resolved
//! description out as an OCI image layout is mechanism, and it belongs to
//! the scanner adapter. So this module produces a
//! [`ComposedImage`] and hands it over; the adapter parses nothing.
//!
//! **The constituent set comes from the manifest bytes in CAS, never from
//! the `content_references` edges** (ADR 0064 D1 — edges nominate and the
//! bytes decide, and the bytes additionally carry the *order*, which the
//! edges do not store at all). The parse is the strict one, not the
//! lenient `manifest_blob_refs`: a skipped descriptor would yield a strict
//! subset of the image that the scanner analyses and reports as the image
//! — a clean verdict about the wrong subject.
//!
//! # The order: nominate, acquire the config, then the layers
//!
//! A composition's **own description is a constituent too**. On a
//! pull-through manifest the config blob is as absent as the layers are —
//! its edges are registered by digest with no existence check — and the
//! client pull that would warm it begins with the manifest whose verdict
//! is being gated. So nothing may need the config's bytes before
//! acquisition has had a chance to fetch them:
//!
//! ```text
//! ┌─ one bounded span (CompositionSpan) ──────────────────────────────────┐
//! │ read the manifest bytes                                               │
//! │   → strict_manifest_nomination  (every manifest-side refusal, 0 I/O)  │
//! │   → acquire the config          (phase 1)                             │
//! │   → read the config bytes                                             │
//! │   → complete_with_config        (is this a runnable image?)           │
//! │   → acquire the layers          (phase 2)                             │
//! └───────────────────────────────────────────────────────────────────────┘
//!   → materialise and scan        (its own span, in the adapter)
//! ```
//!
//! The whole of that is **one** wall-clock span and not four, because what
//! the bound protects is the worker slot and the slot does not care how
//! the work was divided. The two CAS reads are inside it for a reason of
//! their own: the read ceiling bounds a document's *bytes*, so without the
//! span a store trickling a one-kilobyte manifest would hold a slot
//! indefinitely without a scanner ever being pointed at anything.
//!
//! The config is its own phase, and ahead of the layers, because its bytes
//! are what decide whether there is a composition: an **artifact**
//! manifest — a cosign signature, an SBOM attachment, a Helm chart — says
//! "no layered root filesystem" there, and acquiring the whole nominated
//! set up front would fetch every one of their layers before learning
//! there is nothing to compose.
//!
//! # Nothing here carries release authority
//!
//! The composite assessment is produced, mapped, logged and **recorded
//! as a shadow observation**. It transitions no artifact, writes no
//! `ScanCompleted`, and never reaches the release predicate — ADR 0064
//! D6: a new analysis path whose first production act can be
//! irreversible is the thing to avoid, because `Rejected` is terminal
//! and the periodic rescan never revisits it. The manifest row's own
//! assessment is exactly what it was before this module existed.
//!
//! The observation is a **projection**, deliberately not an event: the
//! artifact's event stream is where release authority is derived from,
//! so a shadow verdict written there is a verdict a future reader can
//! mistake for one that counts. It is written outside the transaction
//! that records the artifact's own scan result, through a sink whose
//! `record` cannot return an error, so a storage failure costs one stale
//! row and nothing else. Alongside the composite verdict it carries the
//! **counterfactual** — what the release gate would have decided had
//! that verdict carried authority — and what the same gate, under the
//! same policy, the same exclusion set and the same instant, decided
//! over the findings the manifest's own bytes produced. Those two
//! columns are what makes D6's promotion criterion a query.
//!
//! Three things it *does* reach, all deliberately short of authority.
//! [`constituent_acquisition`](crate::use_cases::constituent_acquisition)
//! writes digest-verified bytes into CAS — no row, no event, no job, no
//! quarantine window — so it can make nothing downloadable that was not
//! and withhold nothing that was. The observation projection is read by
//! nothing that decides delivery or release, which is held structurally
//! by `crates/hort-app/tests/shadow_observation_has_no_authority.rs`
//! rather than by inspection. And a composition that could not be
//! produced for a *transient* reason returns a
//! [`CompositeDisposition::Retry`] request, which the caller may decline;
//! the one thing it can cost when granted is a bounded delay of the
//! manifest's own `ScanCompleted`, never a different verdict.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::scan_policy::{
    CompositeVerdictMode, ExclusionProjection, ScanPolicyProjection,
};
use hort_domain::error::DomainError;
use hort_domain::oci::{strict_manifest_nomination, ConfigRefusal, ImageBudget, ManifestRefusal};
use hort_domain::policy::scan::{composite_verdict_mode_of, evaluate_scan_result};
use hort_domain::ports::composite_scan_observation::{
    bounded_reason, distinct_vulnerability_ids, AcquisitionCost, CompositeAssessment,
    CompositeScanObservation, CompositeScanObservationRepository, GateDecision,
};
use hort_domain::ports::scanner::{
    ComposedImage, EvidenceBasis, NotAnalysable, ScanAnalysis, ScanTarget, ScanUnit, ScannerPort,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::types::{
    severity_summary_from_findings, ArtifactCoords, ArtifactKind, ContentHash, Finding, Sbom,
};

use crate::error::AppError;
use crate::metrics::{
    emit_composite_assessment, emit_composite_comparison, CompositeAuthority,
    CompositeComparisonResult,
};
use crate::use_cases::cas_bounded_read::read_cas_bounded;
use crate::use_cases::constituent_acquisition::{
    Acquisition, AcquisitionStats, CompositionSpan, ConstituentAcquisition,
};
use crate::use_cases::scan_orchestration::merge_findings;

/// Ceiling on one CAS read while resolving a composition — the manifest
/// document and the image config document.
///
/// 16 MiB, the same ceiling the manifest closure walk uses, which in turn
/// matches the default upstream manifest-body cap
/// (`HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`). Sharing the number is the
/// point: a manifest hort accepted and can resolve for delivery is a
/// manifest hort can also resolve for a scan, so the composite path
/// cannot silently decline to assess something the serve path happily
/// answers for. Real manifests are kilobytes and real image configs tens
/// of kilobytes; the ceiling is a backstop, and it **refuses** rather
/// than truncating, because a prefix of a manifest parses into a shorter
/// layer list.
const MAX_COMPOSITION_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// What resolving *and* acquiring a manifest row's composed scan unit
/// produced.
///
/// Four arms, because they ask four different things of an operator and —
/// once the composite verdict carries authority (ADR 0064 D6) — of the
/// release gate:
///
/// - [`NothingToCompose`](Self::NothingToCompose) is the steady state for
///   a large share of OCI rows. An image index binds references rather
///   than a filesystem (D5), and a cosign signature, an SBOM attachment
///   or a Helm chart is an *artifact* manifest whose config describes no
///   root filesystem. There is no composition, so there is nothing for a
///   composite assessment to be about and nothing for a hold to wait on.
/// - [`Deterministic`](Self::Deterministic) is a composition that was
///   expected and could not be assembled, for a reason re-running
///   reproduces exactly. Completeness is a precondition of a verdict (D1):
///   never a partial layout, never a clean verdict over a subset.
/// - [`Transient`](Self::Transient) is the same absence of a composition
///   for a condition that may clear — a store that did not answer, an
///   upstream that was unreachable. ADR 0064 D1: collapsing it into the
///   arm above turns a momentary hiccup into a permanent-looking absence
///   of assessment, and an absence of assessment is what the release gate
///   reads.
#[derive(Debug)]
pub(crate) enum CompositeResolution {
    /// The manifest and its config agree about a composition, and every
    /// constituent of it is in CAS.
    Composed(ComposedImage),
    /// This row is not a composed image at all. Carries the reason, which
    /// is a fixed phrase because the set of ways a manifest can fail to
    /// be an image is closed and none of them quotes declarant data.
    NothingToCompose(&'static str),
    /// No composition, and re-running reads the same facts. Carries the
    /// reason, which may quote the parse's or the upstream's own
    /// complaint.
    Deterministic(String),
    /// No composition *yet*. Carries the reason, for the job's
    /// `last_error`.
    Transient(String),
}

/// Resolve the composed scan unit of the manifest row `acquisition` is
/// about, acquiring the constituents it does not already hold.
///
/// Resolving and acquiring are **one sequence** and cannot be two, because
/// a composition's own description is a constituent: the config bytes that
/// decide whether this manifest is a runnable image at all are themselves
/// something a pull-through repository may have to fetch first. The order
/// is the module doc's diagram, and each step exists where it does for a
/// reason:
///
/// 1. **the manifest's own bytes**, from CAS — the one document acquisition
///    cannot help with, since it is the artifact's own payload;
/// 2. **the manifest-only parse**, which settles every refusal that does
///    not depend on the config bytes, at zero I/O cost;
/// 3. **phase 1**, the config, under the whole acquisition's count and byte
///    bounds;
/// 4. **the config bytes**, now present, read from CAS;
/// 5. **the config-completion parse**, which is where an artifact manifest
///    ends — before a single layer has been asked for;
/// 6. **phase 2**, the layers.
///
/// All six run inside **one** [`CompositionSpan`], started here before the
/// first of them. Steps 1 and 4 are the reason it is created here rather
/// than inside the acquisition: a deadline that covered only the two
/// acquisition phases would leave the two document reads bounded by
/// nothing but their byte ceiling, and a trickling `StoragePort::get` of a
/// kilobyte-scale document would hold a worker slot for as long as it
/// liked.
///
/// Takes the acquisition rather than the handles it holds: it already
/// carries the store to read from, the upstream to acquire from, the
/// artifact whose manifest this is, and the whole-image budget, so passing
/// it is what keeps a second copy of that field list from existing — and
/// the span is started from that same budget, so the clock and the phases
/// inside it cannot be bounded by two different numbers.
pub(crate) async fn resolve_composition(
    acquisition: ConstituentAcquisition<'_>,
) -> (CompositeResolution, AcquisitionStats) {
    let mut stats = AcquisitionStats::default();
    let resolution = resolve_under(acquisition, &mut stats).await;
    (resolution, stats)
}

/// [`resolve_composition`]'s body, with the running cost threaded out
/// through `stats`.
///
/// The cost is an out-parameter rather than a payload on each arm
/// because **every** outcome has one and only one of them is a success:
/// a transient refusal that timed out after fetching three layers spent
/// exactly the egress an operator is being asked to pay for the shadow,
/// and an arm that could not carry it would report that run as free.
/// Updated once after each phase, so a refusal returned from the match
/// below cannot be the branch that forgot to.
async fn resolve_under(
    acquisition: ConstituentAcquisition<'_>,
    stats: &mut AcquisitionStats,
) -> CompositeResolution {
    let storage = &**acquisition.storage;
    let manifest_hash = acquisition.artifact.sha256_checksum.clone();
    let span = acquisition.start_span();

    let manifest_bytes =
        match read_document(storage, &span, "the manifest document", &manifest_hash).await {
            Ok(bytes) => bytes,
            Err(refusal) => return refusal,
        };

    let nomination = match strict_manifest_nomination(&manifest_bytes) {
        Ok(nomination) => nomination,
        Err(refusal) => return classify_manifest_refusal(refusal),
    };

    let mut run = match acquisition.begin(&nomination, span) {
        Ok(run) => run,
        Err(why) => return CompositeResolution::Deterministic(why),
    };

    // Phase 1. Until this has run, nothing in the system has established
    // that the config blob is here — a cold pull-through manifest's is
    // not, and reading it before acquiring it is how the composition came
    // to be refused as unresolvable for every such manifest.
    let config_acquired = run.acquire_config(&nomination).await;
    *stats = run.stats();
    match config_acquired {
        Acquisition::Complete => {}
        Acquisition::Deterministic(why) => return CompositeResolution::Deterministic(why),
        Acquisition::Transient(why) => return CompositeResolution::Transient(why),
    }

    let config_hash = nomination.config().clone();
    let config_bytes = match read_document(storage, &span, "the image config", &config_hash).await {
        Ok(bytes) => bytes,
        Err(refusal) => return refusal,
    };

    let layout = match nomination.complete_with_config(&config_bytes) {
        Ok(layout) => layout,
        Err(refusal) => return classify_config_refusal(&refusal),
    };
    let image = ComposedImage::new(manifest_hash, layout);

    // Phase 2, reached only because the config said there is a layered
    // filesystem to compose. An artifact manifest has already returned
    // above, having cost its config and not one layer.
    let layers_acquired = run.acquire_layers(&image).await;
    *stats = run.stats();
    match layers_acquired {
        Acquisition::Complete => CompositeResolution::Composed(image),
        Acquisition::Deterministic(why) => CompositeResolution::Deterministic(why),
        Acquisition::Transient(why) => CompositeResolution::Transient(why),
    }
}

/// Read one of the two composition documents out of CAS, inside the
/// composition phase's span.
///
/// Both reads are the same three-way answer — the bytes, a failure that is
/// or is not about the document, or a span that ran out — so they are one
/// function: a second copy is a place for the manifest read and the config
/// read to answer the same failure differently.
///
/// `Err` is the resolution to return, already classified.
async fn read_document(
    storage: &dyn StoragePort,
    span: &CompositionSpan,
    subject: &'static str,
    hash: &ContentHash,
) -> Result<Vec<u8>, CompositeResolution> {
    match span
        .bound(read_cas_bounded(
            storage,
            hash,
            MAX_COMPOSITION_DOCUMENT_BYTES,
        ))
        .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) => Err(document_read_refusal(subject, hash, &e)),
        // The span ran out while this document was still being read. A
        // store that is slow is availability — the same side the sibling
        // classifier gives it, and re-running may well succeed — which is
        // *not* the side absence or an over-ceiling document is on, and
        // those are exactly the two the read ceiling could otherwise be
        // mistaken for.
        Err(_elapsed) => Err(CompositeResolution::Transient(
            span.exhausted(&format!("reading {subject} (sha256:{hash})")),
        )),
    }
}

/// Which side of the retry decision a failure to read one of the two
/// composition documents falls on.
///
/// Read off [`read_cas_bounded`]'s **typed** answer and never off the
/// rendered message. That read states three shapes, and two of them are
/// statements about the document that re-reading reproduces exactly: it is
/// not there, or it is over the ceiling. Everything else — the store did
/// not answer, the stream failed partway — is availability, and asks for
/// the same other attempt a failed presence probe one layer down already
/// asks for.
///
/// Absence is deterministic for a different reason for each of the two
/// documents [`read_document`] reads, and both are ADR 0064 D1's:
///
/// - the **manifest** is the artifact's own payload. Acquisition cannot
///   fetch it — a manifest row with no bytes is a different problem, and
///   not one more attempts address.
/// - the **config** is read only after phase 1 reported it present, so a
///   config that is absent *there* is "a constituent still absent once
///   acquisition has run".
///
/// The two deterministic shapes are named and availability is the
/// catch-all, rather than the other way round, for the reason
/// [`classify_upstream_failure`](crate::use_cases::constituent_acquisition)
/// gives for its own unclassified arm: a failure whose shape this function
/// does not recognise is far more likely to be an infrastructure condition
/// than a statement about the document, and the cost of being wrong about
/// it is bounded by the scan job's attempt budget rather than open-ended.
fn document_read_refusal(subject: &str, hash: &ContentHash, err: &AppError) -> CompositeResolution {
    let why = format!("{subject} (sha256:{hash}) could not be read: {err}");
    match err {
        AppError::Domain(DomainError::NotFound { .. } | DomainError::Validation(_)) => {
            CompositeResolution::Deterministic(why)
        }
        _ => CompositeResolution::Transient(why),
    }
}

/// Turn a manifest-side refusal into a resolution.
///
/// The split between "not a composition" and "a composition that could
/// not be assembled" rests on one fact about the input: **the bytes were
/// verified on the way out of CAS** (ADR 0003), so a document that does not
/// parse is a document that was *stored* that way, not one that rotted.
/// That is why an unparseable manifest is a deterministic refusal: there is
/// no legitimate population of manifest-kind rows whose bytes are not
/// manifests — the PUT path parses one before accepting it and the
/// pull-through path parses one to register its edges.
///
/// Nothing on this side is transient: every arm is a statement the manifest
/// bytes make about themselves, and acquiring a blob cannot change one.
fn classify_manifest_refusal(refusal: ManifestRefusal) -> CompositeResolution {
    match refusal {
        // --- not a composition ---------------------------------------
        ManifestRefusal::NotAnImage => CompositeResolution::NothingToCompose(
            "an image index binds references, not a runnable filesystem; each platform \
             manifest is its own scan unit",
        ),
        ManifestRefusal::NoLayers => CompositeResolution::NothingToCompose(
            "the manifest declares no layers, so there is no composed filesystem",
        ),

        // --- a composition that could not be assembled ---------------
        ManifestRefusal::NotParseable(e) => CompositeResolution::Deterministic(format!(
            "the stored bytes of a manifest row are not a manifest document: {e}"
        )),
        ManifestRefusal::TooManyDescriptors { declared, max } => {
            CompositeResolution::Deterministic(format!(
                "the manifest declares {declared} config/layer descriptors; max is {max}"
            ))
        }
        ManifestRefusal::MalformedDescriptor { slot, problem } => {
            CompositeResolution::Deterministic(format!(
                "the manifest's {slot:?} descriptor does not name a blob ({problem:?})"
            ))
        }
        ManifestRefusal::UnsupportedLayer { index, media_type } => {
            CompositeResolution::Deterministic(format!(
                "layers[{index}] declares a container the composition cannot be described \
                 with: {media_type}"
            ))
        }
    }
}

/// Turn a config-side refusal into a resolution.
///
/// Two of the three arms are **not** refusals of an image at all: there is
/// a large, legitimate population of OCI artifact manifests — cosign
/// signatures, SBOM attachments, Helm charts — whose config is deliberately
/// not an image config, and an operator must not be warned once per such
/// row. The third is a config that describes a *different* image from the
/// one its manifest declares, which is a disagreement worth reporting.
///
/// Reached only once acquisition has made the config's bytes present, so
/// none of the three is about availability and none is transient.
///
/// By reference, unlike its manifest-side counterpart, because none of the
/// three arms carries anything into the resolution: two are fixed phrases
/// and the third quotes two numbers. The config parser's own complaint is
/// deliberately not quoted — an artifact manifest's config *not* parsing as
/// an image config is the expected shape of a large population, not a fault
/// to report in detail.
fn classify_config_refusal(refusal: &ConfigRefusal) -> CompositeResolution {
    match refusal {
        ConfigRefusal::RootfsNotLayers => CompositeResolution::NothingToCompose(
            "the config declares no layered root filesystem, so these bytes are an artifact \
             manifest rather than a runnable image",
        ),
        ConfigRefusal::NotParseable(_) => CompositeResolution::NothingToCompose(
            "the config blob is not an image config document, so these bytes are an artifact \
             manifest rather than a runnable image",
        ),
        ConfigRefusal::DiffIdArity { layers, diff_ids } => {
            CompositeResolution::Deterministic(format!(
                "the manifest declares {layers} layers and its config {diff_ids} diff_ids; \
                 one of the two is not about this image"
            ))
        }
    }
}

/// What the composite path leaves for the scan job to do.
///
/// Independent of whether the policy promoted the composite verdict
/// (ADR 0064 D6): a retry request is about whether the composition can be
/// *produced*, and that question has the same answer either way.
/// Acquisition is what makes it load-bearing — with an upstream in the
/// path, **transient failure is the routine case** (an upstream is down,
/// rate-limits, or is slow), and the alternative is reporting an image as
/// unassessed on the strength of a condition that was gone a minute later.
///
/// It is a request and not an action: the caller decides, and it declines
/// whenever the run has already earned something a retry would delay. The
/// job's own attempt budget is the bound, and exhausting it lands back on
/// the deterministic outcome — still no composite verdict, and now also no
/// more tries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositeDisposition {
    /// Nothing further. Either this row is not a composed image, or the
    /// composition reached an outcome — a verdict, or a deterministic
    /// no-verdict that re-running reproduces.
    Settled,
    /// The composition could not be produced for a condition that may
    /// clear. Carries the reason, for the job's `last_error`.
    Retry(String),
}

/// The contributor name a **promoted** composite verdict lands under on
/// `ScanCompleted.scanner`, and in the `backend=reason` breakdown of a
/// promoted composition's absence.
///
/// Names the **scan unit**, not the backend, because the unit is the new
/// information: a manifest whose `ScanCompleted` says `composite` is a
/// manifest whose verdict is its composed image's (ADR 0064 D1), which is
/// the one thing a reader of that event cannot otherwise tell. *Which*
/// backend answered is on the same run's `composite_scan_observations`
/// row (its `scanner` column) and on each finding's `source_scanner`, so
/// nothing is lost by not repeating it here.
pub(crate) const COMPOSITE_CONTRIBUTOR: &str = "composite";

/// What a composite assessment contributes to the **manifest row's own**
/// verdict (ADR 0064 D6).
///
/// The composition is assessed on every manifest scan; this is where the
/// resolved policy's `composite_verdict_mode` is spent. Under
/// `observed` every assessment reduces to [`Withheld`](Self::Withheld)
/// and the manifest's outcome is byte-for-byte what it would be with no
/// composite path at all. Under `promoted` the composition's answer takes
/// the path the manifest's own verdict already takes — the orchestrator's
/// per-unit bookkeeping — rather than a second release path of its own,
/// which is what keeps `composite_scan_observations` a measurement
/// surface and nothing more.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CompositeVerdict {
    /// Nothing reaches the manifest row. Either the policy has not
    /// promoted the composite verdict, or there is no composition for one
    /// to be about: an image index binds references rather than a
    /// filesystem (ADR 0064 D5), and a cosign signature, an SBOM
    /// attachment or a Helm chart is an *artifact* manifest whose config
    /// declares no layered root filesystem. Both are legitimate
    /// populations, not unassessed images, so promotion must not make
    /// either gate on a composition it does not have.
    Withheld,
    /// A backend assessed the composition. These findings are the
    /// manifest row's findings: they join the run's accumulator and reach
    /// the release gate under ADR 0007's existing predicate, exactly as a
    /// second backend's findings over the manifest's own bytes would. An
    /// empty list here **is** a clean verdict — the composition was
    /// assembled and examined.
    Assessed {
        /// What the answering backend looked at. Read off the composite
        /// loop's own filter, which admits only a backend whose evidence
        /// is a materialised payload, so the orchestrator's finding
        /// tagging restates nothing it has not been told.
        evidence: EvidenceBasis,
        /// The composite findings, already merged across backends with
        /// the run's own merge rule.
        findings: Vec<Finding>,
    },
    /// No composition could be produced, so the manifest's filesystem
    /// went unassessed — the absent verdict ADR 0007 fails closed on,
    /// reaching the artifact rather than a log line. Carries the
    /// fail-closed reason the manifest inherits.
    Absent(NotAnalysable),
}

/// Everything one composite run leaves behind, for a caller that owns the
/// manifest's verdict.
///
/// Two values and not one, because the two are independent: a transient
/// refusal both asks for another attempt **and**, if that request is
/// declined, is a promoted manifest's absent verdict. Collapsing them
/// would force the caller to re-derive one from the other.
#[derive(Debug)]
pub(crate) struct CompositeOutcome {
    /// What the composite path asks of the run.
    pub(crate) disposition: CompositeDisposition,
    /// What a promoted policy's manifest row receives.
    pub(crate) verdict: CompositeVerdict,
}

/// Where a shadow assessment's durable evidence goes, and the one place
/// a failure to write it is absorbed.
///
/// A newtype over the port rather than the port itself, for two reasons
/// that are the same reason twice:
///
/// - **The write cannot fail the scan.** [`Self::record`] returns `()`.
///   There is no `Result` for a caller to `?` into the scan's error path,
///   so "the artifact's outcome with this unit in place is byte-for-byte
///   the outcome without it" is a property of the type rather than of
///   every call site remembering it. Same posture as the ingest path's
///   best-effort refcount insert: warn and continue.
/// - **The port stays out of the orchestrator.** Nothing that decides
///   delivery or release may hold a handle on a table of shadow verdicts
///   (ADR 0064 D6), and the scan orchestrator — which commits the
///   artifact's own scan result — is exactly such a thing. It holds this
///   sink; the composite path holds the port.
pub struct ShadowObservationSink {
    repository: Arc<dyn CompositeScanObservationRepository>,
}

impl ShadowObservationSink {
    /// Wrap the projection's repository.
    #[must_use]
    pub fn new(repository: Arc<dyn CompositeScanObservationRepository>) -> Self {
        Self { repository }
    }

    /// Write one observation, replacing this artifact's previous row.
    ///
    /// Infallible by signature. A storage failure here means an operator
    /// reads one stale row while deciding whether to promote the
    /// composite verdict, which is a worse answer to a question nobody
    /// is forced to ask yet; failing the scan over it would be a shadow
    /// path with release authority, which is the one thing this unit may
    /// not be.
    async fn record(&self, observation: CompositeScanObservation) {
        if let Err(e) = self.repository.record(&observation).await {
            tracing::warn!(
                artifact_id = %observation.artifact_id,
                error = %e,
                "composite scan: the shadow observation could not be persisted; the \
                 artifact's own scan outcome is unaffected",
            );
        }
    }
}

/// What one shadow run produced, ready to be turned into a row.
///
/// Assembled at each of the four exits of [`ShadowCompositeScan::run`]
/// so that the row's shape is decided in one place and each exit only
/// states what it knows.
struct ShadowOutcome {
    /// Which of the four outcomes this run reached.
    assessment: CompositeAssessment,
    /// Why, for the three that are not
    /// [`CompositeAssessment::Assessed`].
    reason: Option<String>,
    /// The backend that answered, when one did.
    scanner: Option<String>,
    /// What acquiring the composition cost. Zero on the arms that never
    /// got as far as an acquisition.
    cost: AcquisitionCost,
    /// The composite findings, already merged across backends. Empty on
    /// every arm but [`CompositeAssessment::Assessed`].
    findings: Vec<Finding>,
    /// Which fail-closed absence a **promoted** manifest inherits from
    /// this run — [`CompositeScan::verdict_of`]'s answer for the two
    /// refusal assessments.
    ///
    /// Stated per exit rather than derived from `assessment`, because the
    /// assessment does not carry the fact it depends on. Both refusal
    /// assessments are reached from two different places: before the
    /// composition existed (a constituent missing, unreadable, over
    /// budget, no upstream to acquire from) and after it was assembled
    /// (every backend that ran abstained, or none materialises a payload
    /// for this format). Those are statements about different things, and
    /// only [`NotAnalysable::IncompleteComposition`] is true of the first
    /// — its own documentation names the three causes, and all three are
    /// false of a complete composition the scanners claimed nothing in.
    /// `NoAnalyzerMatched` already says that true thing.
    ///
    /// Both gate, so nothing is mis-decided either way; what the
    /// distinction fixes is the statement in the record of a manifest the
    /// release gate is holding.
    ///
    /// The two non-refusal arms carry [`NotAnalysable::NotApplicable`],
    /// which is not a dead value: an assessed composition has no
    /// unassessed surface, and a row with nothing to compose has no
    /// composed filesystem for an absence to be about. Neither is read —
    /// `verdict_of` answers those two from the assessment — and both are
    /// the honest value if it ever were.
    absence: NotAnalysable,
}

impl ShadowOutcome {
    /// A run that produced no verdict: the reason is the whole content,
    /// and nothing was acquired that the resolution did not already
    /// account for.
    ///
    /// `absence` is what a promoted manifest inherits — see the field. It
    /// is a parameter rather than a value this constructor picks, because
    /// only the call site knows whether the composition had been
    /// assembled by the time the refusal happened.
    fn refusal(assessment: CompositeAssessment, reason: &str, absence: NotAnalysable) -> Self {
        Self {
            assessment,
            reason: Some(bounded_reason(reason)),
            scanner: None,
            cost: AcquisitionCost::default(),
            findings: Vec::new(),
            absence,
        }
    }
}

/// Narrow [`AcquisitionStats`] to the row's bounded counts.
///
/// `usize` → `u32` is total for every reachable value: the whole-image
/// budget caps the constituent count far below `u32::MAX`, and the
/// saturating conversion is the fail-safe for a future budget that does
/// not — an inflated count is a wrong number in a column nobody gates
/// on, where a panic would be a shadow path aborting a scan.
fn cost_of(stats: AcquisitionStats) -> AcquisitionCost {
    AcquisitionCost {
        already_present: u32::try_from(stats.already_present).unwrap_or(u32::MAX),
        fetched: u32::try_from(stats.fetched).unwrap_or(u32::MAX),
        fetched_bytes: stats.fetched_bytes,
    }
}

/// One manifest's composed assessment — always recorded as an
/// observation, and gating the manifest only where the policy has
/// promoted it (ADR 0064 D6).
///
/// A struct rather than a free function with eight arguments: the caller
/// assembles it from values `run_scan` already holds, and naming them at
/// the call site is what keeps "which coords?" and "whose backends?"
/// answerable by reading it.
pub(crate) struct CompositeScan<'a> {
    /// CAS handle for the two resolution reads, the constituent presence
    /// survey and the acquisition's writes. The adapter reads the
    /// constituents itself through its own handle on the same store.
    pub(crate) storage: &'a Arc<dyn StoragePort>,
    /// Upstream blob fetch, for acquiring a proxy composition's absent
    /// constituents.
    pub(crate) upstream_proxy: &'a Arc<dyn UpstreamProxy>,
    /// Resolves whether this repository has an upstream at all — a hosted
    /// repository's absent constituent is a real refusal and stays one.
    pub(crate) upstream_resolver: &'a Arc<dyn UpstreamResolver>,
    /// The registered backends, by name.
    pub(crate) scanners: &'a HashMap<String, Arc<dyn ScannerPort>>,
    /// The manifest row being scanned.
    pub(crate) artifact: &'a Artifact,
    /// Format-handler key of the artifact's repository.
    pub(crate) format: &'a str,
    /// The artifact's coordinates, as the primary target carries them.
    pub(crate) coords: &'a ArtifactCoords,
    /// What the format handler says the row's bytes are. The composite
    /// path applies to an image manifest and to nothing else.
    pub(crate) kind: ArtifactKind,
    /// The backends the resolved policy named, in declared order — the
    /// same list the primary scan used, so the shadow cannot assess an
    /// image with a backend the operator did not configure.
    pub(crate) backends: &'a [String],
    /// The extracted SBOM, forwarded unchanged. A payload-materialising
    /// backend ignores it; it is passed so the shadow invocation differs
    /// from the primary one in exactly one respect — what is being
    /// scanned.
    pub(crate) sbom: Option<&'a Sbom>,
    /// Where the assessment's durable evidence goes (ADR 0064 D6).
    pub(crate) observations: &'a ShadowObservationSink,
    /// The policy the run resolved, forwarded rather than re-fetched.
    /// Both sides of the observation row are judged against it, so they
    /// cannot have been judged by different rules.
    pub(crate) policy: Option<&'a ScanPolicyProjection>,
    /// The exclusion set for that policy, resolved once by the caller.
    ///
    /// `None` is not "no exclusions" — it is "the set could not be
    /// resolved on this run". An empty slice in its place would judge
    /// the counterfactual more harshly than the primary axis was judged
    /// and report the difference as the composite's, so the row is
    /// skipped instead.
    pub(crate) exclusions: Option<&'a [ExclusionProjection]>,
    /// The findings the primary axis produced on this run, before the
    /// cross-backend merge. Merged here with the run's own rule so the
    /// recorded primary decision is the decision over the list the
    /// commit path evaluates.
    pub(crate) primary_findings: &'a [Finding],
    /// The run's `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE` setting,
    /// so the merge above is the run's merge and not a second one.
    pub(crate) allow_informed_downgrade: bool,
}

impl CompositeScan<'_> {
    /// Resolve, acquire, scan, record — and, where the policy has
    /// promoted it, hand the composition's answer back as the manifest
    /// row's own.
    ///
    /// Cannot fail: an assessment that could fail a scan run would be a
    /// release-authority change nobody granted, and under `observed`
    /// every arm leaves the run exactly as it found it. Both things the
    /// method returns are the caller's to act on — the
    /// [`CompositeDisposition`] request, which it is free to decline, and
    /// the [`CompositeVerdict`], which is
    /// [`CompositeVerdict::Withheld`] on every unpromoted run.
    pub(crate) async fn run(self) -> CompositeOutcome {
        // Only an image manifest has a composition. Returning without a
        // log line is deliberate: every artifact in every format reaches
        // this call, and a `debug!` here would say nothing about any of
        // them.
        if self.kind != ArtifactKind::OciManifest {
            return CompositeOutcome {
                disposition: CompositeDisposition::Settled,
                verdict: CompositeVerdict::Withheld,
            };
        }

        // One reading of the clock for the whole run: `observed_at`, and
        // the exclusion-expiry instant both sides of the comparison are
        // evaluated at. Two readings would let an exclusion expire
        // between the primary evaluation and the counterfactual, and the
        // row would report that difference as the composite's.
        let now = Utc::now();

        // Resolve and acquire are one sequence: the config blob whose bytes
        // decide whether this manifest is a runnable image is itself a
        // constituent a proxy may have to fetch first. For a hosted image,
        // and for a proxy image a client has already pulled, the
        // acquisition is a survey and nothing more; for a cold proxy image
        // it is what makes the composition exist at all.
        //
        // The cost comes back on every arm, not only the one that
        // composed something: a refusal that timed out after fetching
        // three layers spent the egress too, and a row reporting that
        // run as free would understate exactly the number an operator
        // weighing the shadow needs.
        let (resolution, stats) = resolve_composition(ConstituentAcquisition {
            storage: self.storage,
            upstream_proxy: self.upstream_proxy,
            upstream_resolver: self.upstream_resolver,
            artifact: self.artifact,
            budget: ImageBudget::default_for_composite_scan(),
        })
        .await;
        let cost = cost_of(stats);
        let image = match resolution {
            CompositeResolution::Composed(image) => image,
            CompositeResolution::NothingToCompose(why) => {
                // The expected steady state for an index, a signature
                // manifest or an OCI artifact — `debug!`, because
                // warning once per such row would bury the arms below.
                tracing::debug!(
                    artifact_id = %self.artifact.id,
                    format = self.format,
                    reason = why,
                    "composite scan: this manifest is not a composed image — nothing to assess",
                );
                return self
                    .finish(
                        ShadowOutcome {
                            cost,
                            ..ShadowOutcome::refusal(
                                CompositeAssessment::NothingToCompose,
                                why,
                                // Never read — `verdict_of` withholds this
                                // assessment. There is no composed
                                // filesystem here, so there is no absent
                                // assessment of one.
                                NotAnalysable::NotApplicable,
                            )
                        },
                        now,
                        CompositeDisposition::Settled,
                    )
                    .await;
            }
            CompositeResolution::Deterministic(why) => {
                tracing::warn!(
                    artifact_id = %self.artifact.id,
                    format = self.format,
                    reason = %why,
                    promoted = self.promoted(),
                    "composite scan: the composed image could not be produced and re-running \
                     reproduces it; no composite assessment",
                );
                return self
                    .finish(
                        ShadowOutcome {
                            cost,
                            ..ShadowOutcome::refusal(
                                CompositeAssessment::DeterministicRefusal,
                                &why,
                                // Reached before the composition existed:
                                // a constituent is missing, unreadable,
                                // over budget, or there is no upstream to
                                // acquire it from.
                                NotAnalysable::IncompleteComposition,
                            )
                        },
                        now,
                        CompositeDisposition::Settled,
                    )
                    .await;
            }
            CompositeResolution::Transient(why) => {
                tracing::warn!(
                    artifact_id = %self.artifact.id,
                    format = self.format,
                    reason = %why,
                    "composite scan: the composition is not complete yet for a transient \
                     reason; asking for another attempt",
                );
                return self
                    .finish(
                        ShadowOutcome {
                            cost,
                            ..ShadowOutcome::refusal(
                                CompositeAssessment::TransientRefusal,
                                &why,
                                // Also before the composition existed —
                                // the store or the upstream did not
                                // answer, or the phase ran out of clock.
                                NotAnalysable::IncompleteComposition,
                            )
                        },
                        now,
                        CompositeDisposition::Retry(why.clone()),
                    )
                    .await;
            }
        };

        // `info!` only when hort actually went to an upstream: that is
        // egress an operator did not ask for and should be able to see.
        // The all-local case is every hosted image and every warm proxy
        // image, so it stays at `debug!`.
        if stats.fetched > 0 {
            tracing::info!(
                artifact_id = %self.artifact.id,
                format = self.format,
                manifest = %image.manifest(),
                fetched = stats.fetched,
                fetched_bytes = stats.fetched_bytes,
                already_present = stats.already_present,
                "composite scan: acquired the composition's absent constituents \
                 from the repository's upstream",
            );
        } else {
            tracing::debug!(
                artifact_id = %self.artifact.id,
                manifest = %image.manifest(),
                already_present = stats.already_present,
                "composite scan: every constituent was already in storage",
            );
        }

        let target = ScanTarget {
            unit: ScanUnit::Image(&image),
            format: self.format,
            coords: self.coords,
            kind: self.kind,
        };

        // A backend `Err` on the composition is the adapter's transient
        // signal: a stalled storage stream, a failed read, a full scratch
        // disk — the machine, not the image. It only becomes a retry
        // request when *no* backend answered, because an answer means the
        // composition was assembled and a sibling's failure is then that
        // backend's problem rather than the composition's.
        let mut answered = false;
        let mut transient: Option<String> = None;
        // The observation's side of the same loop. `answered` cannot
        // stand in for it: an abstention is an answer for the purposes
        // of the retry request (the composition was assembled, so a
        // sibling backend's failure is that backend's problem) and is
        // emphatically *not* an assessment — recording one as a clean
        // composite verdict is the fail-open ADR 0007 exists to refuse.
        let mut composite_findings: Vec<Finding> = Vec::new();
        let mut analysed_by: Option<String> = None;
        let mut abstentions: Vec<String> = Vec::new();
        for backend in self.backends {
            let Some(scanner) = self.scanners.get(backend) else {
                continue;
            };
            if !scanner.applies_to(self.format) {
                continue;
            }
            // A backend whose evidence is the supplied BOM would be
            // handed the very BOM it was already handed for the manifest
            // row, so pointing it at the composition asks it the same
            // question twice and spends a second invocation on an answer
            // that cannot differ. Derived from the backend's own stated
            // evidence rather than from a list of backend names, which is
            // what keeps it right when a backend is added.
            if scanner.evidence_basis() != EvidenceBasis::MaterialisedPayload {
                continue;
            }

            match scanner.scan(&target, self.sbom).await {
                Ok(ScanAnalysis::Analysed(findings)) => {
                    answered = true;
                    tracing::info!(
                        artifact_id = %self.artifact.id,
                        scanner = backend,
                        manifest = %image.manifest(),
                        layers = image.layers().len(),
                        finding_count = findings.len(),
                        promoted = self.promoted(),
                        "composite scan: composed image assessed",
                    );
                    analysed_by = Some(backend.clone());
                    composite_findings.extend(findings);
                }
                Ok(ScanAnalysis::NothingAnalysable(why)) => {
                    answered = true;
                    tracing::warn!(
                        artifact_id = %self.artifact.id,
                        scanner = backend,
                        manifest = %image.manifest(),
                        layers = image.layers().len(),
                        reason = why.as_str(),
                        gates_release = why.gates_release(self.kind, self.composite_verdict()),
                        promoted = self.promoted(),
                        "composite scan: no composite verdict from this backend",
                    );
                    abstentions.push(format!("{backend}={}", why.as_str()));
                }
                Err(e) => {
                    tracing::warn!(
                        artifact_id = %self.artifact.id,
                        scanner = backend,
                        manifest = %image.manifest(),
                        error = %e,
                        promoted = self.promoted(),
                        "composite scan: backend failed on the composed image",
                    );
                    transient = Some(e.to_string());
                }
            }
        }

        // The row, from the same three facts the disposition is built
        // from. The partition mirrors the primary orchestrator's own: a
        // backend that errored may succeed on the next attempt, so that
        // is transient; a backend that ran cleanly and abstained has
        // fixed analyzers and a fixed image, so re-running reproduces
        // it. A composition nobody was configured to assess lands in the
        // same deterministic arm, because it is the same fact — the
        // composition exists and nothing looked at it.
        let outcome = match (analysed_by, transient.as_ref()) {
            (Some(scanner), _) => ShadowOutcome {
                assessment: CompositeAssessment::Assessed,
                reason: None,
                scanner: Some(scanner),
                cost,
                findings: merge_findings(composite_findings, self.allow_informed_downgrade),
                // Never read — this run produced a verdict, so there is
                // no absence for a promoted manifest to inherit.
                absence: NotAnalysable::NotApplicable,
            },
            (None, Some(why)) => ShadowOutcome {
                cost,
                ..ShadowOutcome::refusal(
                    CompositeAssessment::TransientRefusal,
                    why,
                    // The composition WAS assembled and a backend
                    // malfunctioned on it. `NotAnalysable` has no word
                    // for that, and neither available word is true of
                    // it: nothing claimed to have found no analysable
                    // target, and the image was built. This keeps the
                    // value the arm has always had rather than picking
                    // the other wrong one — see
                    // `NotAnalysable::IncompleteComposition`, which
                    // records the gap.
                    NotAnalysable::IncompleteComposition,
                )
            },
            (None, None) => ShadowOutcome {
                cost,
                ..ShadowOutcome::refusal(
                    CompositeAssessment::DeterministicRefusal,
                    &if abstentions.is_empty() {
                        "the composition was assembled and no configured backend \
                         materialises a payload for this format"
                            .to_string()
                    } else {
                        format!(
                            "the composition was assembled and every backend that ran \
                             abstained: {}",
                            abstentions.join(",")
                        )
                    },
                    // The composition was complete and nothing claimed
                    // anything in it. `IncompleteComposition` would say a
                    // constituent was missing, unreadable or over budget,
                    // and all three are false; `NoAnalyzerMatched` says
                    // the true thing, and its own documentation already
                    // names this exact case for a composed image.
                    NotAnalysable::NoAnalyzerMatched,
                )
            },
        };
        let disposition = match transient {
            Some(why) if !answered => CompositeDisposition::Retry(why),
            _ => CompositeDisposition::Settled,
        };
        self.finish(outcome, now, disposition).await
    }

    /// Whether this run's policy has promoted the composed-image verdict
    /// to release authority (ADR 0064 D6).
    ///
    /// `None` — no operator policy resolved for this repository, so the
    /// built-in default governs — is **not** promoted: the default policy
    /// has no operator behind it, and promotion is an operator act
    /// against named criteria. An out-of-the-box deployment therefore
    /// measures the composition and gates on nothing, which is the state
    /// every deployment starts in.
    fn promoted(&self) -> bool {
        self.composite_verdict().carries_release_authority()
    }

    /// This run's resolved composite-verdict posture.
    ///
    /// Through the domain's single resolver rather than off
    /// `self.policy` directly, so this path and the orchestrator's
    /// cannot disagree about what governs one repository — and so
    /// "`None` is not promoted" has one statement of why rather than
    /// two.
    fn composite_verdict(&self) -> CompositeVerdictMode {
        composite_verdict_mode_of(self.policy)
    }

    /// The single exit of [`Self::run`]: record the observation, then say
    /// what the manifest row receives.
    ///
    /// One place, because the mapping from "which of the four outcomes"
    /// to "what the release gate sees" is the whole of ADR 0064 D6's
    /// tightening and a second copy of it is a second answer. The
    /// observation is written **either way** — promoted or not — so an
    /// operator can confirm the promotion is behaving as the measurement
    /// predicted.
    async fn finish(
        &self,
        outcome: ShadowOutcome,
        now: DateTime<Utc>,
        disposition: CompositeDisposition,
    ) -> CompositeOutcome {
        self.observe(&outcome, now).await;
        CompositeOutcome {
            disposition,
            verdict: self.verdict_of(outcome),
        }
    }

    /// What a promoted policy's manifest row receives from `outcome`
    /// (ADR 0064 D6) — exhaustive over the four assessments, because
    /// each asks something different of the release gate and a
    /// wildcard would answer for a future one by accident.
    ///
    /// - **Assessed** → the composition's findings *are* the manifest's.
    ///   An empty list is a clean verdict and releases; a blocking one
    ///   rejects, under ADR 0007's existing predicate and the policy's
    ///   own `enforcement`.
    /// - **NothingToCompose** → withheld, and that is the answer under
    ///   promotion too. An image index binds references rather than a
    ///   filesystem (D5) and an artifact manifest declares no layered
    ///   root filesystem; neither is an unassessed image, so neither may
    ///   be made to gate on a composition it does not have.
    /// - **DeterministicRefusal / TransientRefusal** → no verdict, which
    ///   on a promoted policy is the fail-closed absence the run itself
    ///   named ([`ShadowOutcome::absence`]): the composition is the unit
    ///   of filesystem assessment (D1), so an image whose filesystem went
    ///   unassessed is held by ADR 0007 either way, and *which* absence
    ///   is the difference between a record that says a constituent was
    ///   missing and one that says the assembled image was never claimed
    ///   by an analyzer. The two refusal arms differ in whether another
    ///   attempt is worth making — which is the
    ///   [`CompositeDisposition`]'s question, not this one — and a
    ///   transient refusal reaches here only once the caller has
    ///   declined that request, which it does when the attempt budget is
    ///   spent or the run has an outcome of its own.
    fn verdict_of(&self, outcome: ShadowOutcome) -> CompositeVerdict {
        if !self.promoted() {
            return CompositeVerdict::Withheld;
        }
        match outcome.assessment {
            CompositeAssessment::Assessed => CompositeVerdict::Assessed {
                // The composite loop invokes a backend only when its
                // evidence is a materialised payload, so this is the
                // basis of whatever answered — stated here, where that
                // filter is, rather than in the orchestrator.
                evidence: EvidenceBasis::MaterialisedPayload,
                findings: outcome.findings,
            },
            CompositeAssessment::NothingToCompose => CompositeVerdict::Withheld,
            CompositeAssessment::DeterministicRefusal | CompositeAssessment::TransientRefusal => {
                CompositeVerdict::Absent(outcome.absence)
            }
        }
    }

    /// Record `outcome` as this artifact's current shadow observation,
    /// replacing whatever the last assessment left.
    ///
    /// This is where the **counterfactual** is computed: ADR 0064 D6's
    /// promotion criterion is "what would promoting the composite
    /// verdict have changed across this estate?", and that is a question
    /// about the release gate's decision, not about a finding list. So
    /// both sides of the row run through
    /// [`evaluate_scan_result`] — the pure composition of the per-rule
    /// evaluators, which reads `findings` and writes nothing — with the
    /// same coordinates, the same resolved policy, the same exclusion
    /// set and the same instant. Nothing here appends a
    /// `PolicyEvaluated`, caches a verdict or reaches
    /// `ScanEnforcement::Record`: an observation row and an enforcement
    /// switch are different things, and D6 rules the second one out by
    /// name.
    ///
    /// Written on a **promoted** run too. Once the composite verdict
    /// gates, `composite_findings_decision` is no longer a
    /// counterfactual but a record of what also happened, which is how
    /// an operator confirms the promotion is behaving as the measurement
    /// predicted. The two columns stay per-axis either way: the
    /// manifest's committed verdict is taken over the *union* of the two
    /// finding lists, and for an image manifest — whose own bytes carry
    /// no package surface — that union is the composite column.
    ///
    /// Takes `outcome` by reference so [`Self::finish`] can hand the
    /// same findings on as a promoted verdict without copying them; the
    /// two small owned fields the row needs are cloned.
    ///
    /// Infallible, by the whole unit's contract. The one way it declines
    /// to write is an unresolved exclusion set, which would make the two
    /// sides incomparable.
    async fn observe(&self, outcome: &ShadowOutcome, now: DateTime<Utc>) {
        // One increment per assessment, before the exclusion gate below.
        // The assessment happened whether or not the two sides could be
        // judged by the same rules, and a counter that skipped it would
        // understate coverage exactly when the exclusion read is
        // failing — which is the moment an operator most needs the
        // number to be honest.
        emit_composite_assessment(outcome.assessment.into(), self.authority());

        let Some(exclusions) = self.exclusions else {
            tracing::warn!(
                artifact_id = %self.artifact.id,
                assessment = outcome.assessment.as_str(),
                "composite scan: no exclusion set for this run, so the two sides of the \
                 shadow observation would be judged by different rules; not recording it",
            );
            return;
        };

        let (vulnerability_ids, distinct_vulnerability_count) =
            distinct_vulnerability_ids(&outcome.findings);
        // The primary axis's own findings, merged with the run's rule —
        // the list `record_scan_result` evaluates — so the two columns
        // differ in what was scanned and in nothing else.
        let primary = merge_findings(
            self.primary_findings.to_vec(),
            self.allow_informed_downgrade,
        );

        let observation = CompositeScanObservation {
            artifact_id: self.artifact.id,
            repository_id: self.artifact.repository_id,
            // The manifest row's own payload hash. The composition's
            // identity is the same value; taking it from the artifact
            // keeps every arm, including the ones that never built a
            // composition, carrying the same column.
            manifest_digest: self.artifact.sha256_checksum.clone(),
            scanner: outcome.scanner.clone(),
            observed_at: now,
            assessment: outcome.assessment,
            reason: outcome.reason.clone(),
            cost: outcome.cost,
            severity_summary: severity_summary_from_findings(&outcome.findings),
            finding_count: u32::try_from(outcome.findings.len()).unwrap_or(u32::MAX),
            distinct_vulnerability_count,
            vulnerability_ids,
            composite_findings_decision: match outcome.assessment {
                CompositeAssessment::Assessed => {
                    Some(self.gate(&outcome.findings, exclusions, now))
                }
                // Nothing was composed, so there is no verdict to have
                // carried authority. A `clean` here would read as "the
                // composite found nothing", which is a claim about an
                // image nobody assembled.
                CompositeAssessment::NothingToCompose
                | CompositeAssessment::DeterministicRefusal
                | CompositeAssessment::TransientRefusal => None,
            },
            primary_findings_decision: self.gate(&primary, exclusions, now),
        };

        // The promotion criterion as a rate, derived from the row's own
        // two columns so the counter and the table cannot disagree.
        // Only an assessed composition has a counterfactual, and
        // `composite_findings_decision` is `Some` exactly then — taking
        // the condition off the field rather than off the assessment is
        // what keeps the two from needing to be checked in step.
        //
        // Emitted here rather than after the write: the comparison was
        // computed either way, and a counter that depended on a
        // best-effort storage write succeeding would conflate two
        // different failures.
        if let Some(composite) = observation.composite_findings_decision {
            emit_composite_comparison(CompositeComparisonResult::of(
                composite,
                observation.primary_findings_decision,
            ));
        }

        self.observations.record(observation).await;
    }

    /// This run's posture, as the assessment counter's label.
    ///
    /// Derived from [`Self::promoted`] rather than read separately, so
    /// the metric and the verdict cannot disagree about whether this run
    /// gated anything.
    fn authority(&self) -> CompositeAuthority {
        if self.promoted() {
            CompositeAuthority::Promoted
        } else {
            CompositeAuthority::Observed
        }
    }

    /// The release gate's decision over one finding list, under this
    /// run's policy and exclusions. The single definition both sides of
    /// the row go through.
    fn gate(
        &self,
        findings: &[Finding],
        exclusions: &[ExclusionProjection],
        now: DateTime<Utc>,
    ) -> GateDecision {
        GateDecision::of(&evaluate_scan_result(
            self.coords,
            // The manifest row's own kind, for both sides of the
            // observation: the composite column is the verdict over the
            // composed image, which `ArtifactKind::OciManifest` is the
            // artifact *of* (ADR 0064 D4), and the primary column is that
            // same row's own findings. A manifest is not a constituent, so
            // neither column's filesystem claims have a composition above
            // them for the claim to move to.
            self.kind,
            findings,
            self.policy,
            exclusions,
            now,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metrics::capture_metrics;

    use std::sync::Mutex;
    use std::time::Duration;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::error::DomainResult;
    use hort_domain::events::PolicyScope;
    use hort_domain::oci::{DescriptorProblem, ImageDescriptorSlot};
    use hort_domain::ports::scanner::NotAnalysable;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ArtifactKind;

    use crate::use_cases::test_support::{
        oci_image_config_bytes, oci_image_manifest_bytes, MockCompositeScanObservationRepository,
        MockStoragePort, MockUpstreamProxy, MockUpstreamResolver, OCI_GZIP_LAYER_MEDIA_TYPE,
    };

    /// The real SHA-256 of `bytes`. `MockStoragePort::put` hashes what
    /// streams through it, so a fixture whose declared digest is not the
    /// real one exercises the verification refusal rather than the happy
    /// path — which is correct, and means an acquisition test that wants
    /// the happy path has to declare real digests.
    fn real_sha256(bytes: &[u8]) -> ContentHash {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
            .parse()
            .expect("a sha256 hex digest")
    }

    /// A catch-all upstream mapping for `repository_id` — the proxy shape.
    fn proxy_mapping(
        repository_id: Uuid,
    ) -> hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id,
            path_prefix: String::new(),
            upstream_url: "https://registry.example".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            allowed_realm_hosts: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// A repository with **no** configured upstream — the hosted shape.
    /// The resolver answers nothing, so the acquisition refuses an absent
    /// constituent without reaching the proxy; the proxy is handed over
    /// anyway because the struct needs one, and a test that cares seeds it.
    fn hosted() -> (Arc<dyn UpstreamProxy>, Arc<dyn UpstreamResolver>) {
        (
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockUpstreamResolver::new()),
        )
    }

    fn hash_of(seed: char) -> ContentHash {
        std::iter::repeat_n(seed, 64)
            .collect::<String>()
            .parse()
            .expect("synthetic sha256")
    }

    /// A two-layer image's three documents and their real digests, so a
    /// fixture can put any subset of them in CAS and leave the rest to an
    /// upstream.
    ///
    /// Real digests throughout, because `MockStoragePort::put` hashes what
    /// streams through it: a fixture whose declared digest is not the real
    /// one exercises the verification refusal rather than the happy path.
    /// The manifest's own hash is synthetic — nothing ever fetches or
    /// verifies the manifest, which is the artifact row's own payload.
    struct TwoLayerImage {
        manifest: ContentHash,
        manifest_bytes: Vec<u8>,
        config: ContentHash,
        config_bytes: Vec<u8>,
        layers: Vec<(ContentHash, Vec<u8>)>,
    }

    impl TwoLayerImage {
        fn new() -> Self {
            let config_bytes = oci_image_config_bytes(2);
            let config = real_sha256(&config_bytes);
            let layers: Vec<(ContentHash, Vec<u8>)> =
                [b"lower layer".to_vec(), b"upper layer".to_vec()]
                    .into_iter()
                    .map(|bytes| (real_sha256(&bytes), bytes))
                    .collect();
            let layer_refs: Vec<&ContentHash> = layers.iter().map(|(h, _)| h).collect();
            Self {
                manifest: hash_of('a'),
                manifest_bytes: oci_image_manifest_bytes(&config, &layer_refs),
                config,
                config_bytes,
                layers,
            }
        }

        /// **The genuinely cold state**: only the manifest row's own bytes
        /// are in CAS. This is the ordinary state of a pull-through
        /// manifest — its `oci_config` / `oci_layer` edges are registered
        /// by digest with no existence check, and the client pull that
        /// would warm them begins with this very manifest.
        fn cold_storage(&self) -> Arc<MockStoragePort> {
            let storage = MockStoragePort::new();
            storage.insert_content(self.manifest.clone(), self.manifest_bytes.clone());
            Arc::new(storage)
        }

        /// The **half-warm** window: the manifest and the config are here,
        /// the layers are not. Real — a client fetches the config first —
        /// but a narrow window rather than the state acquisition exists
        /// for.
        fn config_warm_storage(&self) -> Arc<MockStoragePort> {
            let storage = self.cold_storage();
            storage.insert_content(self.config.clone(), self.config_bytes.clone());
            storage
        }

        /// Everything local: every hosted image, and every proxy image a
        /// client has already pulled.
        fn warm_storage(&self) -> Arc<MockStoragePort> {
            let storage = self.config_warm_storage();
            for (hash, bytes) in &self.layers {
                storage.insert_content(hash.clone(), bytes.clone());
            }
            storage
        }

        /// Seed every blob the manifest names on `proxy`, under the
        /// catch-all mapping the fixtures use.
        fn seed_upstream(&self, proxy: &MockUpstreamProxy, upstream_name: &str) {
            for (hash, bytes) in std::iter::once((&self.config, &self.config_bytes))
                .chain(self.layers.iter().map(|(h, b)| (h, b)))
            {
                proxy.insert_blob(
                    "",
                    upstream_name,
                    &format!("sha256:{hash}"),
                    bytes.clone(),
                    None,
                );
            }
        }

        /// The digests the acquisition would fetch, in the order the two
        /// phases ask for them: the config, then the layers in manifest
        /// order.
        fn expected_fetch_log(&self) -> Vec<String> {
            std::iter::once(format!("sha256:{}", self.config))
                .chain(self.layers.iter().map(|(hash, _)| format!("sha256:{hash}")))
                .collect()
        }
    }

    fn coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "library/nginx".to_string(),
            name_as_published: "library/nginx".to_string(),
            version: Some("1.27".to_string()),
            path: "manifests/sha256:aaaa".to_string(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        }
    }

    fn manifest_artifact(hash: ContentHash) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            name: "library/nginx".to_string(),
            name_as_published: "library/nginx".to_string(),
            version: Some("1.27".to_string()),
            path: "manifests/sha256:aaaa".to_string(),
            size_bytes: 512,
            sha256_checksum: hash,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            provenance_hold_indefinite: false,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    /// Resolve and acquire the composition of `artifact`, through the same
    /// one-argument entry point the shadow run uses.
    async fn resolve(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        artifact: &Artifact,
    ) -> CompositeResolution {
        resolve_with_stats(storage, proxy, resolver, artifact)
            .await
            .0
    }

    /// The same, keeping what the acquisition cost — which comes back on
    /// every arm, not only the composed one.
    async fn resolve_with_stats(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        artifact: &Artifact,
    ) -> (CompositeResolution, AcquisitionStats) {
        resolve_with_budget(
            storage,
            proxy,
            resolver,
            artifact,
            ImageBudget::default_for_composite_scan(),
        )
        .await
    }

    /// The same, under a tightened budget — for the bounds, whose shipped
    /// numbers would need a 256-layer fixture to reach.
    async fn resolve_with_budget(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        artifact: &Artifact,
        budget: ImageBudget,
    ) -> (CompositeResolution, AcquisitionStats) {
        resolve_composition(ConstituentAcquisition {
            storage,
            upstream_proxy: proxy,
            upstream_resolver: resolver,
            artifact,
            budget,
        })
        .await
    }

    /// Resolve a manifest whose bytes are `manifest_bytes` and which needs
    /// no upstream — the shape every "this row is not a composed image"
    /// case takes, where what is under test is the parse rather than the
    /// acquisition.
    async fn resolve_hosted(
        manifest_bytes: Vec<u8>,
    ) -> (CompositeResolution, Arc<MockStoragePort>) {
        let hash = hash_of('a');
        let store = Arc::new(MockStoragePort::new());
        store.insert_content(hash.clone(), manifest_bytes);
        let storage: Arc<dyn StoragePort> = store.clone();
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(hash);
        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
        (resolution, store)
    }

    /// A backend that records every target it was handed, so a test can
    /// assert *what* reached it rather than only that something did.
    struct RecordingScanner {
        name_: String,
        evidence: EvidenceBasis,
        response: DomainResult<ScanAnalysis>,
        /// `(layer count, manifest hash)` per composed-image invocation,
        /// and `None` for a blob invocation.
        seen: Mutex<Vec<Option<(usize, String)>>>,
    }

    impl RecordingScanner {
        fn new(name: &str, response: DomainResult<ScanAnalysis>) -> Arc<Self> {
            Arc::new(Self {
                name_: name.to_string(),
                evidence: EvidenceBasis::MaterialisedPayload,
                response,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn sbom_driven(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name_: name.to_string(),
                evidence: EvidenceBasis::SuppliedSbom,
                response: Ok(ScanAnalysis::clean()),
                seen: Mutex::new(Vec::new()),
            })
        }
        fn seen(&self) -> Vec<Option<(usize, String)>> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ScannerPort for RecordingScanner {
        fn name(&self) -> &str {
            &self.name_
        }
        fn applies_to(&self, format: &str) -> bool {
            format == "oci"
        }
        fn evidence_basis(&self) -> EvidenceBasis {
            self.evidence
        }
        fn scan<'a>(
            &'a self,
            target: &'a ScanTarget<'a>,
            _sbom: Option<&'a Sbom>,
        ) -> BoxFuture<'a, DomainResult<ScanAnalysis>> {
            let observed = match target.unit {
                ScanUnit::Image(image) => {
                    Some((image.layers().len(), image.manifest().to_string()))
                }
                ScanUnit::Blob(_) => None,
            };
            self.seen.lock().unwrap().push(observed);
            let response = self.response.clone();
            Box::pin(async move { response })
        }
        fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn registry(scanners: Vec<Arc<dyn ScannerPort>>) -> HashMap<String, Arc<dyn ScannerPort>> {
        scanners
            .into_iter()
            .map(|s| (s.name().to_string(), s))
            .collect()
    }

    /// Everything the shadow run needs that is not a port handle: where
    /// the observation goes, and the inputs both sides of its comparison
    /// are judged by.
    ///
    /// Defaulted, so a test whose subject is the resolution or the
    /// disposition says nothing about the observation and still gets a
    /// readable row to assert on if it wants one.
    struct Fixture {
        observations: Arc<MockCompositeScanObservationRepository>,
        sink: ShadowObservationSink,
        policy: Option<ScanPolicyProjection>,
        /// `None` reproduces the "the exclusion set could not be
        /// resolved" case the caller signals with `None`.
        exclusions: Option<Vec<ExclusionProjection>>,
        primary_findings: Vec<Finding>,
    }

    impl Fixture {
        fn new() -> Self {
            let observations = Arc::new(MockCompositeScanObservationRepository::new());
            Self {
                sink: ShadowObservationSink::new(observations.clone()),
                observations,
                policy: None,
                exclusions: Some(Vec::new()),
                primary_findings: Vec::new(),
            }
        }

        fn with_policy(mut self, policy: ScanPolicyProjection) -> Self {
            self.policy = Some(policy);
            self
        }

        fn with_exclusions(mut self, exclusions: Vec<ExclusionProjection>) -> Self {
            self.exclusions = Some(exclusions);
            self
        }

        fn with_unresolved_exclusions(mut self) -> Self {
            self.exclusions = None;
            self
        }

        fn with_primary_findings(mut self, findings: Vec<Finding>) -> Self {
            self.primary_findings = findings;
            self
        }

        /// The single stored row, or a panic naming how many there are.
        fn row(&self) -> CompositeScanObservation {
            let rows = self.observations.rows();
            assert_eq!(rows.len(), 1, "expected exactly one observation row");
            rows.into_iter().next().expect("one row")
        }
    }

    /// Run the composite assessment of `artifact` against one backend
    /// list, returning the disposition only — the shape most run-level
    /// tests take, since most of them are about the retry request or the
    /// observation row rather than about the verdict.
    #[allow(clippy::too_many_arguments)]
    async fn shadow(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        scanners: &HashMap<String, Arc<dyn ScannerPort>>,
        artifact: &Artifact,
        format: &str,
        kind: ArtifactKind,
        backends: &[String],
        fixture: &Fixture,
    ) -> CompositeDisposition {
        outcome_of(
            storage, proxy, resolver, scanners, artifact, format, kind, backends, fixture,
        )
        .await
        .disposition
    }

    /// The same run, returning everything it produced — for the tests
    /// about ADR 0064 D6's promotion, where the verdict is the subject.
    #[allow(clippy::too_many_arguments)]
    async fn outcome_of(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        scanners: &HashMap<String, Arc<dyn ScannerPort>>,
        artifact: &Artifact,
        format: &str,
        kind: ArtifactKind,
        backends: &[String],
        fixture: &Fixture,
    ) -> CompositeOutcome {
        let coords = coords();
        CompositeScan {
            storage,
            upstream_proxy: proxy,
            upstream_resolver: resolver,
            scanners,
            artifact,
            format,
            coords: &coords,
            kind,
            backends,
            sbom: None,
            observations: &fixture.sink,
            policy: fixture.policy.as_ref(),
            exclusions: fixture.exclusions.as_deref(),
            primary_findings: &fixture.primary_findings,
            allow_informed_downgrade: true,
        }
        .run()
        .await
    }

    /// The shadow run of an OCI manifest against a single `trivy` backend
    /// — the shape all but a couple of the run-level tests take.
    async fn shadow_oci(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        scanner: &Arc<RecordingScanner>,
        artifact: &Artifact,
    ) -> CompositeDisposition {
        shadow_oci_with(storage, proxy, resolver, scanner, artifact, &Fixture::new()).await
    }

    /// The same, with the observation fixture the test wants to inspect
    /// or to bend.
    async fn shadow_oci_with(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        scanner: &Arc<RecordingScanner>,
        artifact: &Artifact,
        fixture: &Fixture,
    ) -> CompositeDisposition {
        shadow(
            storage,
            proxy,
            resolver,
            &registry(vec![scanner.clone() as Arc<dyn ScannerPort>]),
            artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            fixture,
        )
        .await
    }

    // -- resolution ------------------------------------------------------

    #[tokio::test]
    async fn a_well_formed_image_resolves_to_its_manifest_config_and_ordered_layers() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(img.manifest.clone());

        let (resolution, stats) = resolve_with_stats(&storage, &proxy, &resolver, &artifact).await;
        let CompositeResolution::Composed(image) = resolution else {
            panic!("a well-formed two-layer image must resolve, got {resolution:?}");
        };
        assert_eq!(image.manifest(), &img.manifest);
        assert_eq!(image.config(), &img.config);
        let layers: Vec<&ContentHash> = image.layers().iter().map(|l| &l.hash).collect();
        assert_eq!(
            layers,
            img.layers.iter().map(|(h, _)| h).collect::<Vec<_>>(),
            "the order is the manifest's, and a tree assembled in another order is another tree"
        );
        assert_eq!(image.constituent_count(), 4);
        assert_eq!(
            stats.already_present, 3,
            "the config and both layers were surveyed and found local"
        );
        assert_eq!(stats.fetched, 0);
    }

    /// An index is not a composition: it binds references, and each
    /// platform manifest is its own scan unit (D5).
    #[tokio::test]
    async fn an_index_has_nothing_to_compose() {
        let (resolution, store) = resolve_hosted(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", hash_of('b')),
                    "size": 100,
                }],
            }))
            .unwrap(),
        )
        .await;
        let CompositeResolution::NothingToCompose(why) = resolution else {
            panic!("an index binds references, not a filesystem: {resolution:?}");
        };
        assert!(why.contains("index"), "{why}");
        assert_eq!(
            store.size_of_call_count(),
            0,
            "an index is refused from its own bytes, so nothing is acquired for it"
        );
    }

    /// A cosign signature manifest, a Helm chart, an SBOM attachment: a
    /// config that describes no root filesystem means these bytes were
    /// never a runnable image, and an operator must not be warned about
    /// each one.
    #[tokio::test]
    async fn an_artifact_manifest_whose_config_is_not_an_image_config_has_nothing_to_compose() {
        for config_bytes in [
            serde_json::to_vec(&serde_json::json!({ "critical": {} })).unwrap(),
            b"not json at all".to_vec(),
        ] {
            let store = MockStoragePort::new();
            let (manifest, layer) = (hash_of('a'), hash_of('1'));
            let config = real_sha256(&config_bytes);
            store.insert_content(
                manifest.clone(),
                oci_image_manifest_bytes(&config, &[&layer]),
            );
            store.insert_content(config, config_bytes);
            let storage: Arc<dyn StoragePort> = Arc::new(store);
            let (proxy, resolver) = hosted();
            let artifact = manifest_artifact(manifest);
            let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
            assert!(
                matches!(resolution, CompositeResolution::NothingToCompose(_)),
                "an artifact manifest is not an incomplete image: {resolution:?}"
            );
        }
    }

    /// An absent manifest is a deterministic no-verdict naming the
    /// document: the manifest is the artifact row's own payload, so
    /// acquisition cannot fetch it and another attempt reads the same
    /// absence.
    #[tokio::test]
    async fn an_absent_manifest_is_deterministic_and_names_the_document() {
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let (proxy, resolver) = hosted();
        let manifest = hash_of('a');
        let artifact = manifest_artifact(manifest.clone());

        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("a manifest that is not there is not a composition: {resolution:?}");
        };
        assert!(why.contains("manifest document"), "{why}");
        assert!(why.contains(manifest.as_ref()), "{why}");
    }

    /// The other half of the manifest read's split: the store **failed**,
    /// which is not an absence. It asks for another attempt, exactly as a
    /// failed presence probe one layer down does — reporting an unassessed
    /// image on the strength of a storage hiccup is the direction that
    /// matters, because an absence of assessment is what the release gate
    /// reads.
    #[tokio::test]
    async fn a_storage_failure_reading_the_manifest_asks_for_another_attempt() {
        let img = TwoLayerImage::new();
        let store = img.warm_storage();
        // `get` resolves, then the stream fails partway: an infrastructure
        // failure rather than a missing object.
        store.fail_next_get_truncated(img.manifest.clone(), b"{\"schemaV".to_vec());
        let storage: Arc<dyn StoragePort> = store;
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(img.manifest.clone());

        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
        let CompositeResolution::Transient(why) = resolution else {
            panic!("a store that did not answer is retryable: {resolution:?}");
        };
        assert!(why.contains("manifest document"), "{why}");
    }

    /// The same split on the **config** read, which happens after phase 1
    /// has already made the blob present. A store that fails mid-stream
    /// there is still a store that did not answer.
    #[tokio::test]
    async fn a_storage_failure_reading_the_config_asks_for_another_attempt() {
        let img = TwoLayerImage::new();
        let store = img.warm_storage();
        store.fail_next_get_truncated(img.config.clone(), b"{\"rootf".to_vec());
        let storage: Arc<dyn StoragePort> = store;
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(img.manifest.clone());

        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
        let CompositeResolution::Transient(why) = resolution else {
            panic!("a store that did not answer is retryable: {resolution:?}");
        };
        assert!(why.contains("image config"), "{why}");
    }

    /// A config the presence probe found and the read then could not:
    /// deterministic, because by this point acquisition has run and ADR
    /// 0064 D1 puts "a constituent still absent once acquisition has run"
    /// on that side. Re-fetching it is the next attempt's job, not this
    /// resolution's.
    #[tokio::test]
    async fn a_config_absent_after_acquisition_has_run_is_deterministic() {
        let img = TwoLayerImage::new();
        let store = img.warm_storage();
        // `size_of` still answers from the stored bytes, so the survey
        // calls the config present; every `get` for it reports NotFound.
        store.fail_get_persistent(img.config.clone());
        let storage: Arc<dyn StoragePort> = store;
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(img.manifest.clone());

        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;
        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("a constituent still absent once acquisition ran is final: {resolution:?}");
        };
        assert!(why.contains("image config"), "{why}");
        assert!(why.contains(img.config.as_ref()), "{why}");
    }

    /// A manifest-kind row whose stored bytes are not a manifest
    /// document at all. There is no legitimate population of such rows —
    /// the PUT path parses a manifest before accepting it and the
    /// pull-through path parses one to register its edges — and the bytes
    /// were verified on the way out of CAS, so this is not corruption
    /// either. It fails closed.
    #[tokio::test]
    async fn a_manifest_row_whose_bytes_are_not_a_manifest_is_deterministic() {
        let (resolution, _) = resolve_hosted(b"not json at all".to_vec()).await;
        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("a manifest row that is not a manifest fails closed: {resolution:?}");
        };
        assert!(why.contains("not a manifest document"), "{why}");
    }

    /// **What the split bought.** A manifest whose `config` descriptor
    /// names nothing is refused from the manifest's own bytes — naming
    /// *that descriptor*, at zero I/O: no probe, no fetch. Before the
    /// parse was split, locating the config blob to read was the first
    /// thing resolution did, and a refusal about a descriptor had to be
    /// recovered from a complaint about bytes the caller had to invent.
    #[tokio::test]
    async fn a_manifest_with_no_config_descriptor_names_that_descriptor_with_no_io() {
        let (resolution, store) = resolve_hosted(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                // No `config` key at all.
                "layers": [{
                    "mediaType": OCI_GZIP_LAYER_MEDIA_TYPE,
                    "digest": format!("sha256:{}", hash_of('1')),
                    "size": 100,
                }],
            }))
            .unwrap(),
        )
        .await;
        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("a manifest with no config descriptor is not a composition: {resolution:?}");
        };
        assert!(why.contains("Config"), "{why}");
        assert!(
            !why.contains("image config"),
            "the refusal must be about the descriptor, not about config bytes nobody read: {why}"
        );
        assert_eq!(
            store.size_of_call_count(),
            0,
            "a manifest-side refusal costs no storage round-trip"
        );
    }

    /// A document over the read ceiling is refused, not truncated: a
    /// prefix of a manifest parses into a *shorter* layer list, which is
    /// the strict subset this whole path exists to refuse.
    #[tokio::test]
    async fn a_manifest_over_the_read_ceiling_is_deterministic() {
        let (resolution, _) = resolve_hosted(vec![b'x'; MAX_COMPOSITION_DOCUMENT_BYTES + 1]).await;
        assert!(matches!(resolution, CompositeResolution::Deterministic(_)));
    }

    /// **A hosted row whose config is absent.** The arm that could not be
    /// reached before the config became a constituent: resolution used to
    /// read the config blob itself, so an absent one was reported as an
    /// unresolvable composition and acquisition never ran. Now the refusal
    /// comes from the acquisition and names `config` — deterministically,
    /// because a repository with no upstream has nowhere to acquire it
    /// from, and with nothing fetched to discover that.
    #[tokio::test]
    async fn a_hosted_composition_with_an_absent_config_refuses_naming_the_config() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::new());
        let artifact = manifest_artifact(img.manifest.clone());

        let resolution = resolve(&storage, &proxy, &resolver, &artifact).await;

        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("a hosted repository has nowhere to acquire from: {resolution:?}");
        };
        assert!(why.contains("no configured upstream"), "{why}");
        assert!(
            why.contains("config") && !why.contains("layers["),
            "the refusal names the constituent that was needed first: {why}"
        );
        assert!(mock_proxy.blob_fetches().is_empty());
    }

    /// The constituent count is the one bound resolution itself reports: it
    /// is spent from the manifest bytes alone, before a phase runs, so the
    /// refusal reaches the caller without a probe or a fetch having been
    /// made. Deterministic — re-running counts the same descriptors.
    #[tokio::test]
    async fn an_over_count_manifest_is_deterministic_before_any_acquisition() {
        let config = hash_of('c');
        let layers: Vec<ContentHash> = (0..4).map(|i| hash_of((b'1' + i) as char)).collect();
        let layer_refs: Vec<&ContentHash> = layers.iter().collect();
        let manifest = hash_of('a');
        let store = Arc::new(MockStoragePort::new());
        store.insert_content(
            manifest.clone(),
            oci_image_manifest_bytes(&config, &layer_refs),
        );
        let storage: Arc<dyn StoragePort> = store.clone();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(manifest);
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));

        let resolution = resolve_with_budget(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget {
                max_blobs: 3,
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .0;

        let CompositeResolution::Deterministic(why) = resolution else {
            panic!("an over-count image is refused, not retried: {resolution:?}");
        };
        assert!(why.contains("declares 6 constituents"), "{why}");
        assert!(mock_proxy.blob_fetches().is_empty());
        assert_eq!(
            store.size_of_call_count(),
            0,
            "the count bound is spent from the manifest bytes alone, so it costs no \
             storage round-trip either"
        );
    }

    // -- the composition phase's one clock -------------------------------

    /// A CAS read that **trickles**: the stream parks for a delay before it
    /// yields the first byte, then serves the document whole.
    ///
    /// The hazard the span exists for, modelled where it actually lives.
    /// `get` has already answered `Ok` by the time this reader is handed
    /// over, and the read ceiling bounds a document's *bytes* — so nothing
    /// outside the span can interrupt it, and a kilobyte-scale document can
    /// hold a worker slot for as long as the store feels like taking.
    struct TricklingReader {
        inner: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        wait: std::pin::Pin<Box<tokio::time::Sleep>>,
        waited: bool,
    }

    impl tokio::io::AsyncRead for TricklingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if !me.waited {
                match std::future::Future::poll(me.wait.as_mut(), cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(()) => me.waited = true,
                }
            }
            std::pin::Pin::new(&mut me.inner).poll_read(cx, buf)
        }
    }

    /// A store that takes `delay` over the reads and probes a test names,
    /// and is otherwise the seeded `MockStoragePort` every other test here
    /// uses.
    ///
    /// A wrapper rather than a hand-rolled `StoragePort`, for the reason the
    /// acquisition's `SlowProxy` wraps its mock: what a slow store *serves*
    /// has to be the same fixture, or the test is about two things at once.
    struct SlowStorage {
        inner: Arc<MockStoragePort>,
        /// Digests whose `get` trickles. A read of anything else is
        /// immediate, which is what lets a test spend the span on exactly
        /// one of the two documents.
        slow_reads: Vec<ContentHash>,
        /// Whether a presence probe takes `delay` too — the way to spend the
        /// span *inside* an acquisition phase without a slow upstream.
        slow_probes: bool,
        delay: Duration,
    }

    impl StoragePort for SlowStorage {
        fn put(
            &self,
            stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>> {
            self.inner.put(stream)
        }
        fn get(
            &self,
            hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
            let hash = hash.clone();
            let trickles = self.slow_reads.contains(&hash);
            let delay = self.delay;
            Box::pin(async move {
                let inner = self.inner.get(&hash).await?;
                if !trickles {
                    return Ok(inner);
                }
                Ok(Box::new(TricklingReader {
                    inner,
                    wait: Box::pin(tokio::time::sleep(delay)),
                    waited: false,
                })
                    as Box<dyn tokio::io::AsyncRead + Send + Unpin>)
            })
        }
        fn get_range(
            &self,
            hash: &ContentHash,
            range: hort_domain::types::ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
            self.inner.get_range(hash, range)
        }
        fn exists(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            self.inner.exists(hash)
        }
        fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            let hash = hash.clone();
            let delay = self.delay;
            let slow = self.slow_probes;
            Box::pin(async move {
                if slow {
                    tokio::time::sleep(delay).await;
                }
                self.inner.size_of(&hash).await
            })
        }
    }

    /// Resolve `img`'s composition against a store that is slow in the way
    /// `storage` describes, under a tightened wall clock. Hosted, so nothing
    /// reaches an upstream and the only thing spending the span is the store.
    async fn resolve_against_slow_storage(
        img: &TwoLayerImage,
        storage: SlowStorage,
        max_duration: Duration,
    ) -> CompositeResolution {
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let (proxy, resolver) = hosted();
        let artifact = manifest_artifact(img.manifest.clone());
        resolve_with_budget(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget {
                max_duration,
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .0
    }

    /// **A trickling manifest read trips the composition phase's clock**, and
    /// is transient.
    ///
    /// This read happens before the acquisition exists, so until the span
    /// covered it nothing bounded it at all: `read_cas_bounded` refuses a
    /// document over 16 MiB and has nothing to say about one that arrives
    /// slowly, and `StoragePort::get` carries no deadline of its own.
    ///
    /// Transient because a store that is slow is availability — nothing about
    /// the image changed and re-running may well land — which is the side
    /// this module's other read failures and the acquisition's own stall
    /// already take.
    ///
    /// Virtual time, as the acquisition's clock test uses, so the deadline
    /// and the delay are exact rather than racing the test host.
    #[tokio::test(start_paused = true)]
    async fn a_trickling_manifest_read_trips_the_composition_clock() {
        let img = TwoLayerImage::new();
        let slow = |img: &TwoLayerImage| SlowStorage {
            inner: img.warm_storage(),
            slow_reads: vec![img.manifest.clone()],
            slow_probes: false,
            delay: Duration::from_millis(200),
        };

        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(100)).await;
        let CompositeResolution::Transient(why) = resolution else {
            panic!("a store that is slow is an availability condition: {resolution:?}");
        };
        assert!(why.contains("the manifest document"), "{why}");
        assert!(why.contains(img.manifest.as_ref()), "{why}");
        assert!(why.contains("wall-clock budget"), "{why}");

        // The same read and the same trickle, against a budget that covers
        // it: the composition is produced. So what trips above is the clock
        // rather than a fixture that cannot be read at all.
        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(400)).await;
        assert!(
            matches!(resolution, CompositeResolution::Composed(..)),
            "a slow read inside the budget still composes: {resolution:?}"
        );
    }

    /// **The same for the config read**, which sits between the two
    /// acquisition phases — the other place the budget did not reach. The
    /// manifest read and phase 1 both land; the clock runs out while the
    /// config document is still arriving.
    #[tokio::test(start_paused = true)]
    async fn a_trickling_config_read_trips_the_composition_clock() {
        let img = TwoLayerImage::new();
        let slow = |img: &TwoLayerImage| SlowStorage {
            inner: img.warm_storage(),
            slow_reads: vec![img.config.clone()],
            slow_probes: false,
            delay: Duration::from_millis(200),
        };

        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(100)).await;
        let CompositeResolution::Transient(why) = resolution else {
            panic!("a store that is slow is an availability condition: {resolution:?}");
        };
        assert!(why.contains("the image config"), "{why}");
        assert!(why.contains(img.config.as_ref()), "{why}");
        assert!(why.contains("wall-clock budget"), "{why}");

        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(400)).await;
        assert!(
            matches!(resolution, CompositeResolution::Composed(..)),
            "a slow read inside the budget still composes: {resolution:?}"
        );
    }

    /// **One span across the reads and the phases.** The budget here covers
    /// everything the two acquisition phases do and does *not* cover that
    /// plus the manifest read — so the composition completes if the phases
    /// get a clock of their own, and runs out if they are spending the one
    /// the read was already on. It runs out.
    ///
    /// That is the whole claim of this unit: a deadline created at the
    /// acquisition would give a composite scan the two document reads for
    /// free, on top of the occupancy `MAX_IMAGE_LAYOUT_DURATION` states.
    ///
    /// The arithmetic, at 60 ms per slow step: the manifest read ends at 60,
    /// phase 1's config probe at 120, phase 2's two layer probes at 180 and
    /// 240. The three probes alone are 180 — inside the 200 ms budget — and
    /// with the read ahead of them they are not.
    #[tokio::test(start_paused = true)]
    async fn the_composition_phase_is_one_span_across_its_reads_and_its_phases() {
        let img = TwoLayerImage::new();
        let slow = |img: &TwoLayerImage| SlowStorage {
            inner: img.warm_storage(),
            slow_reads: vec![img.manifest.clone()],
            slow_probes: true,
            delay: Duration::from_millis(60),
        };

        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(200)).await;
        let CompositeResolution::Transient(why) = resolution else {
            panic!(
                "the phases were spending a clock the manifest read had already started: \
                 {resolution:?}"
            );
        };
        assert!(
            why.contains("acquiring the composition's constituents"),
            "the step that ran out of clock is the phase, and it says so: {why}"
        );

        // The same four slow steps — one read and three probes — against a
        // budget that covers their sum, so what trips above is the sum and
        // not any one of them.
        let resolution =
            resolve_against_slow_storage(&img, slow(&img), Duration::from_millis(400)).await;
        assert!(
            matches!(resolution, CompositeResolution::Composed(..)),
            "every step fits and so does the sum: {resolution:?}"
        );
    }

    /// Every manifest-side refusal, classified — the half of the table
    /// that is decided before any constituent is acquired. Each arm
    /// decides whether an operator is warned and — once the verdict
    /// carries authority — whether the manifest holds.
    #[test]
    fn every_manifest_side_refusal_is_classified() {
        let nothing_to_compose = [ManifestRefusal::NotAnImage, ManifestRefusal::NoLayers];
        for refusal in nothing_to_compose {
            let rendered = format!("{refusal:?}");
            assert!(
                matches!(
                    classify_manifest_refusal(refusal),
                    CompositeResolution::NothingToCompose(_)
                ),
                "{rendered} is a row that is not an image"
            );
        }

        let deterministic = [
            ManifestRefusal::NotParseable("expected value".to_string()),
            ManifestRefusal::TooManyDescriptors {
                declared: 2000,
                max: 1024,
            },
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(3),
                problem: DescriptorProblem::MalformedSha256,
            },
            ManifestRefusal::UnsupportedLayer {
                index: 1,
                media_type: "application/vnd.oci.image.layer.v1.tar+brotli".to_string(),
            },
        ];
        for refusal in deterministic {
            let rendered = format!("{refusal:?}");
            let resolution = classify_manifest_refusal(refusal);
            assert!(
                matches!(resolution, CompositeResolution::Deterministic(_)),
                "{rendered} is a composition that could not be assembled"
            );
        }

        // And the refusals say enough to act on.
        let unsupported = classify_manifest_refusal(ManifestRefusal::UnsupportedLayer {
            index: 7,
            media_type: "application/x-nonsense".to_string(),
        });
        let CompositeResolution::Deterministic(why) = unsupported else {
            panic!("expected a deterministic refusal");
        };
        assert!(why.contains("layers[7]"), "{why}");
        assert!(why.contains("application/x-nonsense"), "{why}");

        let malformed = classify_manifest_refusal(ManifestRefusal::MalformedDescriptor {
            slot: ImageDescriptorSlot::Config,
            problem: DescriptorProblem::MissingDigest,
        });
        let CompositeResolution::Deterministic(why) = malformed else {
            panic!("expected a deterministic refusal");
        };
        assert!(why.contains("Config"), "{why}");
        assert!(why.contains("MissingDigest"), "{why}");

        let too_many = classify_manifest_refusal(ManifestRefusal::TooManyDescriptors {
            declared: 2000,
            max: 1024,
        });
        let CompositeResolution::Deterministic(why) = too_many else {
            panic!("expected a deterministic refusal");
        };
        assert!(why.contains("2000"), "{why}");

        let unparseable =
            classify_manifest_refusal(ManifestRefusal::NotParseable("trailing comma".to_string()));
        let CompositeResolution::Deterministic(why) = unparseable else {
            panic!("expected a deterministic refusal");
        };
        assert!(why.contains("trailing comma"), "{why}");
    }

    /// Every config-side refusal, classified — the half that is decided
    /// over bytes acquisition has already made present, which is why none
    /// of the three is transient.
    #[test]
    fn every_config_side_refusal_is_classified() {
        for refusal in [
            ConfigRefusal::RootfsNotLayers,
            ConfigRefusal::NotParseable("expected value".to_string()),
        ] {
            let rendered = format!("{refusal:?}");
            assert!(
                matches!(
                    classify_config_refusal(&refusal),
                    CompositeResolution::NothingToCompose(_)
                ),
                "{rendered} is an artifact manifest rather than a runnable image"
            );
        }

        let arity = classify_config_refusal(&ConfigRefusal::DiffIdArity {
            layers: 3,
            diff_ids: 2,
        });
        let CompositeResolution::Deterministic(why) = arity else {
            panic!("a config about another image is a refusal, not an artifact manifest");
        };
        assert!(why.contains('3') && why.contains('2'), "{why}");
    }

    // -- the shadow run --------------------------------------------------

    /// The composition reaches the backend as a composed image — the
    /// manifest it is of, and every layer in order.
    #[tokio::test]
    async fn the_shadow_run_hands_the_composition_to_a_payload_backend() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();

        shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert_eq!(
            scanner.seen(),
            vec![Some((2, img.manifest.to_string()))],
            "the backend must be handed the composition, not the manifest blob"
        );
    }

    /// Every arm of the backend's answer is logged and none of them
    /// escapes: the shadow has no release authority, so a finding, an
    /// abstention and a failure all leave the run untouched.
    #[tokio::test]
    async fn the_shadow_run_absorbs_every_backend_answer() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        for (response, expected) in [
            (
                Ok(ScanAnalysis::NothingAnalysable(
                    NotAnalysable::IncompleteComposition,
                )),
                CompositeDisposition::Settled,
            ),
            (
                Ok(ScanAnalysis::NothingAnalysable(
                    NotAnalysable::NoAnalyzerMatched,
                )),
                CompositeDisposition::Settled,
            ),
            // A backend `Err` is the adapter's transient signal — the
            // machine did not produce the composition — so it is the one
            // answer that asks for another attempt. It still reaches
            // nothing itself: the caller decides.
            (
                Err(DomainError::Invariant("trivy fell over".to_string())),
                CompositeDisposition::Retry("trivy fell over".to_string()),
            ),
        ] {
            let scanner = RecordingScanner::new("trivy", response);
            let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;
            assert_eq!(
                scanner.seen().len(),
                1,
                "the backend was asked exactly once"
            );
            assert_eq!(disposition, expected);
        }
    }

    /// A kind other than an image manifest never reaches a resolution —
    /// asserted with storage that panics on any read, so it is a property
    /// of the code rather than of an empty fixture.
    #[tokio::test]
    async fn a_non_manifest_kind_costs_no_read_and_no_invocation() {
        struct NoReads;
        impl StoragePort for NoReads {
            fn put(
                &self,
                _stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            ) -> BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(
                &self,
                _hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>>
            {
                panic!("a non-manifest kind must not cost a CAS read")
            }
            fn get_range(
                &self,
                _hash: &ContentHash,
                _range: hort_domain::types::ByteRange,
            ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>>
            {
                Box::pin(async { unreachable!() })
            }
            fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { unreachable!() })
            }
            fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
                panic!("a non-manifest kind must not cost a presence probe")
            }
            fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }
        let storage: Arc<dyn StoragePort> = Arc::new(NoReads);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(hash_of('a'));
        let (proxy, resolver) = hosted();
        for kind in [
            ArtifactKind::OciBlob,
            ArtifactKind::MavenJar,
            ArtifactKind::NpmTarball,
            ArtifactKind::Other,
        ] {
            shadow(
                &storage,
                &proxy,
                &resolver,
                &registry(vec![scanner.clone()]),
                &artifact,
                "oci",
                kind,
                &["trivy".to_string()],
                &Fixture::new(),
            )
            .await;
        }
        assert!(scanner.seen().is_empty());
    }

    /// A row with no composition to assess reaches no backend either,
    /// and — unlike the arm below — asks nothing of an operator. An
    /// index, a cosign signature and an OCI artifact are the ordinary
    /// shape of an OCI repository, so this is the quiet path.
    #[tokio::test]
    async fn a_row_with_nothing_to_compose_invokes_no_backend() {
        let manifest = hash_of('a');
        let store = MockStoragePort::new();
        store.insert_content(
            manifest.clone(),
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", hash_of('b')),
                    "size": 100,
                }],
            }))
            .unwrap(),
        );
        let storage: Arc<dyn StoragePort> = Arc::new(store);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(manifest);
        let (proxy, resolver) = hosted();

        shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert!(scanner.seen().is_empty());
    }

    /// An unresolved composition never reaches a backend: there is
    /// nothing assembled to point one at, and an invocation over a
    /// partial description is the clean-verdict-over-a-subset this path
    /// refuses.
    #[tokio::test]
    async fn an_unresolved_composition_invokes_no_backend() {
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(hash_of('a'));
        let (proxy, resolver) = hosted();

        shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert!(scanner.seen().is_empty());
    }

    /// Three reasons a configured backend is skipped, and all three are
    /// decided before an invocation is spent: it is not registered, it
    /// does not cover the format, or its evidence is the supplied BOM —
    /// which the composition does not change.
    #[tokio::test]
    async fn the_shadow_run_skips_backends_the_composition_cannot_inform() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();

        let sbom_backend = RecordingScanner::sbom_driven("osv");
        let payload_backend = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        shadow(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![sbom_backend.clone(), payload_backend.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            // `grype` is not registered; `osv` reads the BOM.
            &["grype".to_string(), "osv".to_string(), "trivy".to_string()],
            &Fixture::new(),
        )
        .await;
        assert!(
            sbom_backend.seen().is_empty(),
            "a BOM-driven backend would be asked the same question twice"
        );
        assert_eq!(payload_backend.seen().len(), 1);

        // And a backend that does not cover the format is not invoked
        // either: `RecordingScanner::applies_to` answers only for `oci`.
        let other_format = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        shadow(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![other_format.clone()]),
            &artifact,
            "npm",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            &Fixture::new(),
        )
        .await;
        assert!(other_format.seen().is_empty());
    }

    // -- acquisition, through the shadow ---------------------------------

    /// **The cold pull-through case, end to end.** Only the manifest is in
    /// CAS — the ordinary state of a proxy manifest, since its constituent
    /// edges are registered by digest with no existence check — so the
    /// config is acquired first, its bytes complete the composition, the
    /// layers follow, and the composition reaches the backend. Before the
    /// config became a constituent this manifest produced a
    /// `warn!`-per-row refusal and nothing was ever acquired for it.
    #[tokio::test]
    async fn a_cold_proxy_composition_is_acquired_and_then_assessed() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let artifact = manifest_artifact(img.manifest.clone());

        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        img.seed_upstream(&mock_proxy, &artifact.name);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert_eq!(
            mock_proxy.blob_fetches(),
            img.expected_fetch_log(),
            "the config is fetched first: nothing can ask for a layer until its bytes have \
             said there is a filesystem to compose"
        );
        assert_eq!(scanner.seen(), vec![Some((2, img.manifest.to_string()))]);
    }

    /// The **half-warm** window — a client has fetched the config, not the
    /// layers — acquires only what is still absent.
    #[tokio::test]
    async fn a_half_warm_proxy_composition_acquires_only_the_layers() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.config_warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());

        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        img.seed_upstream(&mock_proxy, &artifact.name);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert_eq!(
            mock_proxy.blob_fetches(),
            img.layers
                .iter()
                .map(|(hash, _)| format!("sha256:{hash}"))
                .collect::<Vec<_>>(),
            "the config was already local, so only the layers are fetched"
        );
        assert_eq!(scanner.seen(), vec![Some((2, img.manifest.to_string()))]);
    }

    /// **An artifact manifest costs its config and not one layer.** A
    /// cosign signature, an SBOM attachment or a Helm chart is a large,
    /// legitimate population on a proxy: its config says "no layered root
    /// filesystem", and until those bytes are read nothing knows that. So
    /// the config is acquired, the completion ends the composition, and
    /// the layers — which hort would never have assessed — are never
    /// fetched. Acquiring the whole nominated set up front would have
    /// pulled every one of them.
    #[tokio::test]
    async fn an_artifact_manifest_on_a_proxy_costs_its_config_and_not_one_layer() {
        let config_bytes = serde_json::to_vec(&serde_json::json!({
            "critical": { "type": "cosign container image signature" },
        }))
        .unwrap();
        let config = real_sha256(&config_bytes);
        let layer_bytes = b"the signature payload".to_vec();
        let layer = real_sha256(&layer_bytes);
        let manifest = hash_of('a');

        let store = MockStoragePort::new();
        store.insert_content(
            manifest.clone(),
            oci_image_manifest_bytes(&config, &[&layer]),
        );
        let storage: Arc<dyn StoragePort> = Arc::new(store);
        let artifact = manifest_artifact(manifest);

        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        for (hash, bytes) in [(&config, &config_bytes), (&layer, &layer_bytes)] {
            mock_proxy.insert_blob(
                "",
                &artifact.name,
                &format!("sha256:{hash}"),
                bytes.clone(),
                None,
            );
        }
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert_eq!(
            mock_proxy.blob_fetches(),
            vec![format!("sha256:{config}")],
            "the config says there is nothing to compose, so no layer is ever asked for"
        );
        assert!(
            scanner.seen().is_empty(),
            "and no backend is pointed at a composition that does not exist"
        );
    }

    /// The same cold composition in a **hosted** repository: no upstream,
    /// so the absence is a real refusal — and it is the *config* that is
    /// named, because that is the first constituent needed. No fetch, no
    /// backend, and the disposition asks for nothing: re-running
    /// reproduces it exactly.
    #[tokio::test]
    async fn a_cold_hosted_composition_settles_without_a_backend_or_a_fetch() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::new());
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(img.manifest.clone());

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert!(mock_proxy.blob_fetches().is_empty());
        assert!(scanner.seen().is_empty());
    }

    /// A transient acquisition failure asks for another attempt, and no
    /// backend is invoked: there is no composition to point one at, and a
    /// run over a partial description is the clean-verdict-over-a-subset
    /// this path refuses.
    #[tokio::test]
    async fn a_transient_acquisition_failure_asks_for_a_retry_and_invokes_no_backend() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.config_warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        mock_proxy.fail_blob_with(
            &format!("sha256:{}", img.layers[0].0),
            DomainError::Invariant("upstream:rate_limited:429 too many requests".to_string()),
        );
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        let CompositeDisposition::Retry(why) = disposition else {
            panic!("a rate-limited upstream is retryable; got {disposition:?}");
        };
        assert!(why.contains("rate_limited"), "{why}");
        assert!(scanner.seen().is_empty());
    }

    /// A transient failure acquiring the **config** reaches the same
    /// request, through the phase that did not exist before: the retry
    /// axis does not care which constituent was being acquired.
    #[tokio::test]
    async fn a_transient_failure_acquiring_the_config_asks_for_a_retry() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        img.seed_upstream(&mock_proxy, &artifact.name);
        mock_proxy.fail_blob_with(
            &format!("sha256:{}", img.config),
            DomainError::Invariant("upstream:upstream_5xx:503 from the registry".to_string()),
        );
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockUpstreamResolver::with_mappings(
            vec![proxy_mapping(artifact.repository_id)],
        ));
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));

        let disposition = shadow_oci(&storage, &proxy, &resolver, &scanner, &artifact).await;

        let CompositeDisposition::Retry(why) = disposition else {
            panic!("a 503 on the config is retryable; got {disposition:?}");
        };
        assert!(why.contains("config"), "{why}");
        assert!(
            !mock_proxy
                .blob_fetches()
                .iter()
                .any(|d| d.contains(img.layers[0].0.as_ref())),
            "no layer is fetched for a composition whose description could not be acquired"
        );
        assert!(scanner.seen().is_empty());
    }

    /// A backend that errored next to one that answered does **not** ask
    /// for a retry: an answer means the composition was assembled, so the
    /// sibling's failure is that backend's problem and not the
    /// composition's.
    #[tokio::test]
    async fn a_backend_error_beside_an_answer_does_not_ask_for_a_retry() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let (proxy, resolver) = hosted();
        let broken = RecordingScanner::new("trivy", Err(DomainError::Invariant("boom".into())));
        let working = RecordingScanner::new("grype", Ok(ScanAnalysis::clean()));
        let artifact = manifest_artifact(img.manifest.clone());

        let disposition = shadow(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![broken.clone(), working.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string(), "grype".to_string()],
            &Fixture::new(),
        )
        .await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert_eq!(broken.seen().len(), 1);
        assert_eq!(working.seen().len(), 1);
    }

    // -- the shadow observation -------------------------------------------

    /// A composite finding of `severity`, as a payload backend reports
    /// one over a composed image.
    fn composite_finding(vulnerability_id: &str, severity: SeverityThreshold) -> Finding {
        Finding {
            purl: "pkg:deb/debian/openssl@3.0.11".to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            severity,
            cvss_score: None,
            title: "openssl".to_string(),
            fixed_versions: Vec::new(),
            source_scanner: "trivy".to_string(),
            references: Vec::new(),
            aliases: Vec::new(),
            informational_class: None,
            severity_basis: hort_domain::types::SeverityBasis::Assessed,
            component_relation: hort_domain::types::ComponentRelation::Contained,
            statement: hort_domain::types::FindingStatement::Unstated,
        }
    }

    /// A policy that blocks at `threshold` and enforces the block.
    fn policy_blocking_at(threshold: SeverityThreshold) -> ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{
            CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement,
        };
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "composite-shadow-test".to_string(),
            scope: PolicyScope::Global,
            severity_threshold: threshold,
            quarantine_duration_secs: 24 * 3600,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// An exclusion of `cve_id` under `policy`, never expiring.
    fn exclusion(policy: &ScanPolicyProjection, cve_id: &str) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::new_v4(),
            policy_id: policy.policy_id,
            cve_id: cve_id.to_string(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "accepted".to_string(),
            added_by_actor_id: None,
            expires_at: None,
        }
    }

    /// The assessed arm writes one row carrying both sides of the
    /// comparison and the counterfactual, and a second assessment of the
    /// same artifact replaces it instead of adding one.
    #[tokio::test]
    async fn an_assessed_composition_writes_one_row_and_the_next_one_replaces_it() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new(
            "trivy",
            Ok(ScanAnalysis::Analysed(vec![composite_finding(
                "CVE-2024-7",
                SeverityThreshold::Critical,
            )])),
        );
        let fixture = Fixture::new().with_policy(policy_blocking_at(SeverityThreshold::Critical));

        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;
        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        assert_eq!(
            fixture.observations.writes().len(),
            2,
            "both assessments wrote"
        );
        let row = fixture.row();
        assert_eq!(row.artifact_id, artifact.id);
        assert_eq!(row.repository_id, artifact.repository_id);
        assert_eq!(row.manifest_digest, artifact.sha256_checksum);
        assert_eq!(row.assessment, CompositeAssessment::Assessed);
        assert_eq!(row.scanner.as_deref(), Some("trivy"));
        assert_eq!(row.reason, None);
        assert_eq!(row.finding_count, 1);
        assert_eq!(row.distinct_vulnerability_count, 1);
        assert_eq!(row.vulnerability_ids, vec!["CVE-2024-7".to_string()]);
        assert_eq!(row.severity_summary.critical, 1);
        // Both sides, in one row: the composite blocks, the manifest's
        // own bytes found nothing.
        assert_eq!(row.composite_findings_decision, Some(GateDecision::Reject));
        assert_eq!(row.primary_findings_decision, GateDecision::Clean);
    }

    /// The acquisition's cost rides with the verdict it bought — this is
    /// egress an operator did not ask for, and promoting the verdict
    /// means keeping it.
    #[tokio::test]
    async fn the_row_carries_what_acquiring_the_composition_cost() {
        let img = TwoLayerImage::new();
        // Cold: only the manifest is local, so the config and both
        // layers are fetched from the repository's upstream.
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let proxy_mock = MockUpstreamProxy::new();
        img.seed_upstream(&proxy_mock, &artifact.name);
        let resolver_mock = MockUpstreamResolver::new();
        resolver_mock.insert(proxy_mapping(artifact.repository_id));
        let proxy: Arc<dyn UpstreamProxy> = Arc::new(proxy_mock);
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(resolver_mock);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new();

        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::Assessed);
        assert_eq!(row.cost.fetched, 3, "the config and both layers");
        assert_eq!(row.cost.already_present, 0);
        assert!(row.cost.fetched_bytes > 0, "bytes crossed the wire");
    }

    /// A refusal that got part-way spent real egress, and the row says
    /// how much. The config was fetched from the upstream and the layers
    /// were not there, so the run bought nothing and still paid — which
    /// is precisely the number an operator weighing the shadow needs,
    /// and the one a cost carried only on the success arm would report
    /// as zero.
    #[tokio::test]
    async fn a_refusal_that_already_fetched_records_what_it_spent() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.cold_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let proxy_mock = MockUpstreamProxy::new();
        // Only the config is upstream; neither layer is.
        proxy_mock.insert_blob(
            "",
            &artifact.name,
            &format!("sha256:{}", img.config),
            img.config_bytes.clone(),
            None,
        );
        let resolver_mock = MockUpstreamResolver::new();
        resolver_mock.insert(proxy_mapping(artifact.repository_id));
        let proxy: Arc<dyn UpstreamProxy> = Arc::new(proxy_mock);
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(resolver_mock);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new();

        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        let row = fixture.row();
        assert_ne!(
            row.assessment,
            CompositeAssessment::Assessed,
            "no composition was assembled"
        );
        assert_eq!(row.cost.fetched, 1, "the config crossed the wire");
        assert_eq!(
            row.cost.fetched_bytes,
            img.config_bytes.len() as u64,
            "and the row says how many bytes it was"
        );
        assert!(scanner.seen().is_empty());
    }

    /// Each of the four outcomes reaches its own stored value, with the
    /// reason that makes it actionable — including the three that
    /// produce no findings at all, whose counterfactual is absent
    /// because there was no composition to decide on.
    #[tokio::test]
    async fn each_outcome_reaches_its_own_stored_value_with_its_reason() {
        let (proxy, resolver) = hosted();

        // 1. Nothing to compose: an index binds references, not a
        //    filesystem.
        let index = hash_of('a');
        let store = MockStoragePort::new();
        store.insert_content(
            index.clone(),
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", hash_of('b')),
                    "size": 100,
                }],
            }))
            .unwrap(),
        );
        let storage: Arc<dyn StoragePort> = Arc::new(store);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new();
        shadow_oci_with(
            &storage,
            &proxy,
            &resolver,
            &scanner,
            &manifest_artifact(index),
            &fixture,
        )
        .await;
        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::NothingToCompose);
        assert!(row.reason.is_some(), "the steady state still says why");
        assert_eq!(row.composite_findings_decision, None);
        assert_eq!(row.finding_count, 0);

        // 2. Deterministic refusal: the manifest's bytes do not parse,
        //    and re-reading them reproduces that exactly.
        let broken = hash_of('c');
        let store = MockStoragePort::new();
        store.insert_content(broken.clone(), b"not json".to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(store);
        let fixture = Fixture::new();
        shadow_oci_with(
            &storage,
            &proxy,
            &resolver,
            &scanner,
            &manifest_artifact(broken),
            &fixture,
        )
        .await;
        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::DeterministicRefusal);
        assert!(row.reason.is_some());
        assert_eq!(row.composite_findings_decision, None);

        // 3. Transient refusal: the store did not finish answering for
        //    the config document, which may clear. The run asks for
        //    another attempt, and the row says why it has no verdict.
        let img = TwoLayerImage::new();
        let store = img.warm_storage();
        store.fail_next_get_truncated(img.config.clone(), b"{\"rootf".to_vec());
        let storage: Arc<dyn StoragePort> = store;
        let fixture = Fixture::new();
        let disposition = shadow_oci_with(
            &storage,
            &proxy,
            &resolver,
            &scanner,
            &manifest_artifact(img.manifest.clone()),
            &fixture,
        )
        .await;
        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::TransientRefusal);
        assert!(
            row.reason
                .as_deref()
                .unwrap_or_default()
                .contains("image config"),
            "{:?}",
            row.reason
        );
        assert_eq!(row.composite_findings_decision, None);
        assert!(matches!(disposition, CompositeDisposition::Retry(_)));

        // 4. Assessed, with nothing found. A clean composite verdict is
        //    still a verdict: the row carries the counterfactual.
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let fixture = Fixture::new();
        shadow_oci_with(
            &storage,
            &proxy,
            &resolver,
            &scanner,
            &manifest_artifact(img.manifest.clone()),
            &fixture,
        )
        .await;
        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::Assessed);
        assert_eq!(row.reason, None);
        assert_eq!(row.composite_findings_decision, Some(GateDecision::Clean));
        assert_eq!(row.finding_count, 0);
    }

    // -- the counters ----------------------------------------------------

    /// Every series of one counter in a snapshot, as
    /// `(label values in `expected` order, increment)` pairs, so a test
    /// can assert both how many series fired and what each one counted.
    ///
    /// `expected` is the counter's **whole** label set, asserted rather
    /// than filtered: a label the emitter added and this call does not
    /// name is a cardinality change nobody reviewed, and that is the
    /// failure mode worth catching here — no decision, no artifact id,
    /// nothing unbounded.
    fn ticks(
        snap: metrics_util::debugging::Snapshot,
        metric: &str,
        expected: &[&str],
    ) -> Vec<(Vec<String>, u64)> {
        snap.into_vec()
            .into_iter()
            .filter(|(key, _, _, _)| key.key().name() == metric)
            .map(|(key, _, _, value)| {
                let labels: Vec<_> = key.key().labels().collect();
                assert_eq!(
                    labels.len(),
                    expected.len(),
                    "{metric} must carry exactly {expected:?}: {labels:?}"
                );
                let values = expected
                    .iter()
                    .map(|name| {
                        labels
                            .iter()
                            .find(|l| l.key() == *name)
                            .unwrap_or_else(|| panic!("{metric} must carry `{name}`: {labels:?}"))
                            .value()
                            .to_string()
                    })
                    .collect();
                let count = match value {
                    metrics_util::debugging::DebugValue::Counter(v) => v,
                    other => panic!("{metric} must be a counter, got {other:?}"),
                };
                (values, count)
            })
            .collect()
    }

    /// A current-thread runtime inside the metric recorder's sync
    /// closure — `metrics::with_local_recorder` cannot take an async
    /// one, and the recorder is thread-local.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
            .block_on(f)
    }

    /// `(storage, artifact)` for each of the four outcomes, reusing the
    /// same setups the stored-value test drives — so the counter and the
    /// row are asserted against one definition of how each outcome is
    /// reached.
    fn setup_for(assessment: CompositeAssessment) -> (Arc<dyn StoragePort>, Artifact) {
        match assessment {
            // An index binds references, not a filesystem.
            CompositeAssessment::NothingToCompose => {
                let index = hash_of('a');
                let store = MockStoragePort::new();
                store.insert_content(
                    index.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "schemaVersion": 2,
                        "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
                        "manifests": [{
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": format!("sha256:{}", hash_of('b')),
                            "size": 100,
                        }],
                    }))
                    .expect("index json"),
                );
                (Arc::new(store), manifest_artifact(index))
            }
            // Manifest bytes that do not parse; re-reading reproduces it.
            CompositeAssessment::DeterministicRefusal => {
                let broken = hash_of('c');
                let store = MockStoragePort::new();
                store.insert_content(broken.clone(), b"not json".to_vec());
                (Arc::new(store), manifest_artifact(broken))
            }
            // A store that did not finish answering for the config.
            CompositeAssessment::TransientRefusal => {
                let img = TwoLayerImage::new();
                let store = img.warm_storage();
                store.fail_next_get_truncated(img.config.clone(), b"{\"rootf".to_vec());
                (store, manifest_artifact(img.manifest.clone()))
            }
            CompositeAssessment::Assessed => {
                let img = TwoLayerImage::new();
                (img.warm_storage(), manifest_artifact(img.manifest.clone()))
            }
        }
    }

    /// **One assessment, one tick, under its own label** — on each of
    /// the four outcomes.
    ///
    /// The counter is what turns D6's promotion criteria (baseline
    /// completion, coverage, error rate) into something an operator can
    /// watch move; a one-row-per-manifest projection answers only
    /// today's snapshot. So it has to tick on the three arms that
    /// composed nothing as well as on the one that did — "how often is
    /// there nothing to assess?" is half of the coverage question.
    #[test]
    fn each_outcome_ticks_the_assessment_counter_exactly_once_under_its_own_label() {
        for assessment in [
            CompositeAssessment::Assessed,
            CompositeAssessment::NothingToCompose,
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            let (storage, artifact) = setup_for(assessment);
            let fixture = Fixture::new();
            let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
            let (proxy, resolver) = hosted();

            let snap = capture_metrics(|| {
                block_on(shadow_oci_with(
                    &storage, &proxy, &resolver, &scanner, &artifact, &fixture,
                ));
            });

            assert_eq!(
                ticks(
                    snap,
                    "hort_scan_composite_assessment_total",
                    &["result", "authority"],
                ),
                vec![(
                    vec![assessment.as_str().to_string(), "observed".to_string()],
                    1,
                )],
                "one tick for {}, under the label the row stores and this run's posture",
                assessment.as_str()
            );
            // And the counter's label is the row's column value, on the
            // same run rather than by inspection.
            assert_eq!(fixture.row().assessment, assessment);
        }
    }

    /// **The comparison counter ticks only for an assessed
    /// composition**, and its label is derived from the row's own two
    /// columns.
    ///
    /// Asserted together because they are one claim: a refusal has no
    /// counterfactual to compare, and an assessment's comparison must
    /// be the one a reader of the row would compute.
    #[test]
    fn the_comparison_counter_ticks_only_for_an_assessment_and_matches_the_row() {
        for assessment in [
            CompositeAssessment::NothingToCompose,
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            let (storage, artifact) = setup_for(assessment);
            let fixture = Fixture::new();
            let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
            let (proxy, resolver) = hosted();

            let snap = capture_metrics(|| {
                block_on(shadow_oci_with(
                    &storage, &proxy, &resolver, &scanner, &artifact, &fixture,
                ));
            });

            assert!(
                ticks(snap, "hort_scan_composite_comparison_total", &["result"]).is_empty(),
                "{} composed nothing, so there is no counterfactual to compare",
                assessment.as_str()
            );
            assert_eq!(fixture.row().composite_findings_decision, None);
        }

        // Three assessed runs, one per direction. The scanner's verdict
        // on the composition and the primary axis's own findings are
        // what set the two sides.
        let blocking = || composite_finding("CVE-2024-9", SeverityThreshold::Critical);
        let primary_blocking = || {
            let mut f = blocking();
            f.vulnerability_id = "CVE-2024-8".to_string();
            f
        };
        let cases = [
            // Composite blocks, primary clean: promoting adds a hold.
            (
                vec![blocking()],
                Vec::new(),
                "composite_stricter",
                Some(GateDecision::Reject),
                GateDecision::Clean,
            ),
            // Primary blocks, composite clean: promoting removes one.
            (
                Vec::new(),
                vec![primary_blocking()],
                "composite_permissive",
                Some(GateDecision::Clean),
                GateDecision::Reject,
            ),
            // Neither blocks: nothing would change.
            (
                Vec::new(),
                Vec::new(),
                "agree",
                Some(GateDecision::Clean),
                GateDecision::Clean,
            ),
        ];
        for (composite, primary, expected, composite_side, primary_side) in cases {
            let (storage, artifact) = setup_for(CompositeAssessment::Assessed);
            let fixture = Fixture::new()
                .with_policy(policy_blocking_at(SeverityThreshold::Critical))
                .with_primary_findings(primary);
            let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::Analysed(composite)));
            let (proxy, resolver) = hosted();

            let snap = capture_metrics(|| {
                block_on(shadow_oci_with(
                    &storage, &proxy, &resolver, &scanner, &artifact, &fixture,
                ));
            });

            assert_eq!(
                ticks(snap, "hort_scan_composite_comparison_total", &["result"]),
                vec![(vec![expected.to_string()], 1)],
            );
            // The label is the row's two columns compared — asserted
            // against the row from the same run, not against a
            // restatement of the rule.
            let row = fixture.row();
            assert_eq!(row.composite_findings_decision, composite_side);
            assert_eq!(row.primary_findings_decision, primary_side);
            assert_eq!(
                CompositeComparisonResult::of(
                    row.composite_findings_decision.expect("assessed"),
                    row.primary_findings_decision,
                )
                .as_str(),
                expected,
            );
        }
    }

    /// An unresolved exclusion set skips the **row** and the
    /// **comparison**, and still counts the assessment.
    ///
    /// The assessment happened; what could not be done is judging its
    /// two sides by the same rules. A counter that skipped it too would
    /// understate coverage exactly when the exclusion read is failing,
    /// which is the moment the number most needs to be honest — and the
    /// comparison must stay absent, because a comparison nobody could
    /// make is not an agreement.
    #[test]
    fn an_unresolved_exclusion_set_still_counts_the_assessment_but_not_the_comparison() {
        let (storage, artifact) = setup_for(CompositeAssessment::Assessed);
        let fixture = Fixture::new().with_unresolved_exclusions();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let (proxy, resolver) = hosted();

        let snap = capture_metrics(|| {
            block_on(shadow_oci_with(
                &storage, &proxy, &resolver, &scanner, &artifact, &fixture,
            ));
        });
        // Both counters are read off one snapshot, so "one fired and
        // the other did not" is asserted about the same run.
        let entries = snap.into_vec();
        let assessment_ticks: Vec<&str> = entries
            .iter()
            .filter(|(key, _, _, _)| key.key().name() == "hort_scan_composite_assessment_total")
            .map(|(key, _, _, _)| key.key().labels().next().expect("a result label").value())
            .collect();
        assert_eq!(assessment_ticks, vec!["assessed"]);
        assert!(
            !entries.iter().any(|(key, _, _, _)| {
                key.key().name() == "hort_scan_composite_comparison_total"
            }),
            "the two sides could not be judged by the same rules, so there is no comparison"
        );
        assert!(
            fixture.observations.writes().is_empty(),
            "and no row either — that is E5's behaviour, unchanged"
        );
    }

    /// A backend that errors leaves the composition unassessed for a
    /// condition that may clear — the transient arm, with the backend's
    /// own complaint as the reason.
    #[tokio::test]
    async fn a_backend_failure_stores_a_transient_refusal_with_its_reason() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new(
            "trivy",
            Err(DomainError::Invariant("scratch disk full".into())),
        );
        let fixture = Fixture::new();

        let disposition =
            shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        assert!(matches!(disposition, CompositeDisposition::Retry(_)));
        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::TransientRefusal);
        assert!(
            row.reason
                .as_deref()
                .unwrap_or_default()
                .contains("scratch disk full"),
            "{:?}",
            row.reason
        );
        assert_eq!(row.composite_findings_decision, None);
        assert_eq!(row.scanner, None, "no backend answered about the image");
    }

    /// A composition every backend abstained on is **not** a clean
    /// composite verdict — recording one would be the fail-open an
    /// absent verdict must never earn. It is the deterministic arm: the
    /// analyzers and the image are both fixed, so re-running reproduces
    /// it.
    #[tokio::test]
    async fn an_abstention_over_an_assembled_composition_is_a_deterministic_refusal() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NoAnalyzerMatched,
            )),
        );
        let fixture = Fixture::new();

        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::DeterministicRefusal);
        assert_eq!(row.composite_findings_decision, None);
        assert!(
            row.reason.as_deref().unwrap_or_default().contains("trivy="),
            "{:?}",
            row.reason
        );
        assert_eq!(row.cost.already_present, 3, "the composition was assembled");
    }

    /// A composition nobody is configured to assess is the same fact —
    /// assembled, and nothing looked at it — so it lands in the same
    /// deterministic arm and says so.
    #[tokio::test]
    async fn an_assembled_composition_no_backend_covers_is_a_deterministic_refusal() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let sbom_backend = RecordingScanner::sbom_driven("osv");
        let fixture = Fixture::new();

        shadow(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![sbom_backend.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["osv".to_string()],
            &fixture,
        )
        .await;

        let row = fixture.row();
        assert_eq!(row.assessment, CompositeAssessment::DeterministicRefusal);
        assert!(
            row.reason
                .as_deref()
                .unwrap_or_default()
                .contains("no configured backend materialises a payload"),
            "{:?}",
            row.reason
        );
    }

    /// The two rows a promotion decision is made of. The composite finds
    /// what the manifest's own bytes could not — so the counterfactual
    /// *differs* — and when the primary axis already found the same
    /// thing, the two *agree*.
    #[tokio::test]
    async fn the_counterfactual_differs_when_the_composition_finds_more_and_agrees_when_it_does_not(
    ) {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let blocking = composite_finding("CVE-2024-9", SeverityThreshold::Critical);
        let scanner =
            RecordingScanner::new("trivy", Ok(ScanAnalysis::Analysed(vec![blocking.clone()])));
        let policy = policy_blocking_at(SeverityThreshold::Critical);

        // Differs: the manifest's own bytes carry no package surface, so
        // the primary axis is clean while the composition rejects. This
        // is the row that makes promotion worth something.
        let differs = Fixture::new().with_policy(policy.clone());
        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &differs).await;
        let row = differs.row();
        assert_eq!(row.primary_findings_decision, GateDecision::Clean);
        assert_eq!(row.composite_findings_decision, Some(GateDecision::Reject));

        // Agrees: the primary axis already found the same advisory, so
        // promoting would change nothing for this artifact.
        let agrees = Fixture::new()
            .with_policy(policy)
            .with_primary_findings(vec![blocking]);
        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &agrees).await;
        let row = agrees.row();
        assert_eq!(row.primary_findings_decision, GateDecision::Reject);
        assert_eq!(row.composite_findings_decision, Some(GateDecision::Reject));
    }

    /// The counterfactual is judged by the run's own exclusions. An
    /// exclusion that suppresses a finding on the primary side
    /// suppresses it here too — otherwise the row would report an
    /// operator's own accepted risk as a difference the composition
    /// found.
    #[tokio::test]
    async fn an_exclusion_that_suppresses_the_primary_side_suppresses_the_counterfactual() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let blocking = composite_finding("CVE-2024-9", SeverityThreshold::Critical);
        let scanner =
            RecordingScanner::new("trivy", Ok(ScanAnalysis::Analysed(vec![blocking.clone()])));
        let policy = policy_blocking_at(SeverityThreshold::Critical);
        let excluded = exclusion(&policy, "CVE-2024-9");

        let fixture = Fixture::new()
            .with_policy(policy)
            .with_exclusions(vec![excluded])
            .with_primary_findings(vec![blocking]);
        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        let row = fixture.row();
        assert_eq!(row.primary_findings_decision, GateDecision::Clean);
        assert_eq!(
            row.composite_findings_decision,
            Some(GateDecision::Clean),
            "the same exclusion set governs both sides"
        );
        // The finding is still *recorded* — an exclusion suppresses the
        // verdict, not the evidence.
        assert_eq!(row.finding_count, 1);
        assert_eq!(row.vulnerability_ids, vec!["CVE-2024-9".to_string()]);
    }

    /// Without an exclusion set the two sides would be judged by
    /// different rules, so no row is written at all. An empty set in its
    /// place would judge the counterfactual more harshly than the
    /// primary axis was judged and report the difference as the
    /// composition's.
    #[tokio::test]
    async fn an_unresolved_exclusion_set_writes_no_row_and_changes_no_disposition() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new().with_unresolved_exclusions();

        let disposition =
            shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        assert_eq!(disposition, CompositeDisposition::Settled);
        assert!(fixture.observations.rows().is_empty());
        assert_eq!(scanner.seen().len(), 1, "the assessment still ran");
    }

    /// A failed observation write costs nothing: the backend was still
    /// asked, the disposition is what it would have been, and no row is
    /// left behind.
    #[tokio::test]
    async fn a_failing_observation_write_leaves_the_run_exactly_as_it_was() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new(
            "trivy",
            Err(DomainError::Invariant("trivy fell over".into())),
        );
        let fixture = Fixture::new();
        fixture
            .observations
            .fail_next_record(DomainError::Invariant("projection unavailable".into()));

        let disposition =
            shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        assert_eq!(
            disposition,
            CompositeDisposition::Retry("trivy fell over".to_string()),
            "the observation's failure did not become the run's"
        );
        assert!(fixture.observations.rows().is_empty());
    }

    /// A pathological image cannot write an unbounded column: the stored
    /// id list is capped while both counts stay exact.
    #[tokio::test]
    async fn the_stored_id_list_is_capped_while_the_counts_stay_exact() {
        use hort_domain::ports::composite_scan_observation::MAX_OBSERVED_VULNERABILITY_IDS;

        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let overflow = MAX_OBSERVED_VULNERABILITY_IDS + 11;
        let findings: Vec<Finding> = (0..overflow)
            .map(|i| composite_finding(&format!("CVE-2024-{i:05}"), SeverityThreshold::Low))
            .collect();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::Analysed(findings)));
        let fixture = Fixture::new();

        shadow_oci_with(&storage, &proxy, &resolver, &scanner, &artifact, &fixture).await;

        let row = fixture.row();
        assert_eq!(row.vulnerability_ids.len(), MAX_OBSERVED_VULNERABILITY_IDS);
        assert_eq!(row.distinct_vulnerability_count as usize, overflow);
        assert_eq!(row.finding_count as usize, overflow);
        assert_eq!(row.severity_summary.low as usize, overflow);
    }

    /// A row shape with no composition never reaches the projection
    /// either — the shadow is about image manifests and says nothing
    /// about anything else.
    #[tokio::test]
    async fn a_non_manifest_kind_writes_no_observation() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new();

        shadow(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![scanner.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciBlob,
            &["trivy".to_string()],
            &fixture,
        )
        .await;

        assert!(fixture.observations.rows().is_empty());
    }

    // -- promotion: what a manifest row receives (ADR 0064 D6) -----------

    /// [`policy_blocking_at`] with the composed-image verdict promoted to
    /// release authority.
    fn promoted_policy_blocking_at(threshold: SeverityThreshold) -> ScanPolicyProjection {
        ScanPolicyProjection {
            composite_verdict_mode: CompositeVerdictMode::Promoted,
            ..policy_blocking_at(threshold)
        }
    }

    /// Run a composite assessment of each of the four outcomes under
    /// both postures, returning the verdict.
    async fn verdict_for(
        assessment: CompositeAssessment,
        policy: ScanPolicyProjection,
    ) -> CompositeVerdict {
        let (storage, artifact) = setup_for(assessment);
        let fixture = Fixture::new().with_policy(policy);
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let (proxy, resolver) = hosted();
        outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![scanner]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            &fixture,
        )
        .await
        .verdict
    }

    /// **Unpromoted, every outcome is withheld.** The one assertion that
    /// makes "an unpromoted run is byte-for-byte today's behaviour" a
    /// property of the mapping rather than of each arm downstream: there
    /// is nothing for a caller to fold, whatever the composition said.
    #[tokio::test]
    async fn an_unpromoted_policy_withholds_every_outcome() {
        for assessment in [
            CompositeAssessment::Assessed,
            CompositeAssessment::NothingToCompose,
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            assert_eq!(
                verdict_for(assessment, policy_blocking_at(SeverityThreshold::Critical)).await,
                CompositeVerdict::Withheld,
                "{} must be withheld while the policy has not promoted the verdict",
                assessment.as_str()
            );
        }
    }

    /// **Promoted, each outcome maps to exactly one thing a manifest row
    /// can receive**, and the three refusal arms do not collapse into
    /// one answer: "nothing to compose" is not a refusal at all, while
    /// both ways of failing to assemble a composition are the same
    /// absent verdict as far as the release gate is concerned.
    #[tokio::test]
    async fn a_promoted_policy_maps_each_outcome_to_what_the_manifest_receives() {
        assert!(
            matches!(
                verdict_for(
                    CompositeAssessment::Assessed,
                    promoted_policy_blocking_at(SeverityThreshold::Critical),
                )
                .await,
                CompositeVerdict::Assessed {
                    evidence: EvidenceBasis::MaterialisedPayload,
                    ref findings,
                } if findings.is_empty()
            ),
            "an assembled, examined, clean composition is a clean verdict"
        );
        assert_eq!(
            verdict_for(
                CompositeAssessment::NothingToCompose,
                promoted_policy_blocking_at(SeverityThreshold::Critical),
            )
            .await,
            CompositeVerdict::Withheld,
            "an index binds references rather than a filesystem (ADR 0064 D5), so promotion \
             must not make it gate on a composition it does not have"
        );
        for refusal in [
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            assert_eq!(
                verdict_for(
                    refusal,
                    promoted_policy_blocking_at(SeverityThreshold::Critical)
                )
                .await,
                CompositeVerdict::Absent(NotAnalysable::IncompleteComposition),
                "{} is the absent verdict ADR 0007 fails closed on — and in both \
                 of `setup_for`'s refusals the composition was never built, which \
                 is what `incomplete_composition` says",
                refusal.as_str()
            );
        }
    }

    /// **The absence a promoted manifest inherits names what actually
    /// happened.** Both of these hold the manifest, so neither is
    /// mis-decided; what differs is the statement left in the record of an
    /// artifact the release gate is withholding.
    ///
    /// Asserted as a pair, because the correction is a distinction and a
    /// single assertion cannot show one: a composition that was never
    /// assembled is an `incomplete_composition` (a constituent missing,
    /// unreadable or over budget), and a composition that *was* assembled
    /// and that every backend abstained on is a `no_analyzer_matched` —
    /// all three of the first value's causes being false of it.
    #[tokio::test]
    async fn an_assembled_composition_nothing_claimed_is_not_an_incomplete_composition() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        // The composition is built and handed over; the backend runs and
        // claims nothing in it.
        let abstaining = RecordingScanner::new(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NoAnalyzerMatched,
            )),
        );
        let fixture =
            Fixture::new().with_policy(promoted_policy_blocking_at(SeverityThreshold::Critical));
        let assembled = outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![abstaining]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            &fixture,
        )
        .await;
        assert_eq!(
            assembled.verdict,
            CompositeVerdict::Absent(NotAnalysable::NoAnalyzerMatched),
            "the composition was complete and the scanners claimed nothing in it; \
             `incomplete_composition` would say a constituent was missing, \
             unreadable or over budget, and all three are false"
        );
        // The shadow row is unchanged by the correction: the assessment
        // it records is still the deterministic refusal, with the
        // per-backend abstentions named verbatim in its reason.
        let rows = fixture.observations.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].assessment,
            CompositeAssessment::DeterministicRefusal
        );
        assert!(
            rows[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("trivy=no_analyzer_matched")),
            "{:?}",
            rows[0].reason
        );

        // And the other half of the pair: the composition that was never
        // built keeps the value whose documentation describes it.
        assert_eq!(
            verdict_for(
                CompositeAssessment::DeterministicRefusal,
                promoted_policy_blocking_at(SeverityThreshold::Critical),
            )
            .await,
            CompositeVerdict::Absent(NotAnalysable::IncompleteComposition),
        );
    }

    /// A composition nobody was configured to assess reaches the same
    /// corrected value. The composition exists and nothing looked at it,
    /// which is `no_analyzer_matched`'s own meaning for a composed image —
    /// not an incomplete one.
    #[tokio::test]
    async fn a_composition_no_backend_materialises_a_payload_for_is_not_incomplete_either() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        // Its evidence is the supplied BOM, so the composite loop never
        // points it at the composition.
        let sbom_only = RecordingScanner::sbom_driven("osv");
        let fixture =
            Fixture::new().with_policy(promoted_policy_blocking_at(SeverityThreshold::Critical));
        let outcome = outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![sbom_only.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["osv".to_string()],
            &fixture,
        )
        .await;
        assert_eq!(
            outcome.verdict,
            CompositeVerdict::Absent(NotAnalysable::NoAnalyzerMatched),
        );
        assert!(
            sbom_only.seen().is_empty(),
            "an SBOM-driven backend is never pointed at the composition"
        );
    }

    /// **The composition's findings are what a promoted verdict carries**
    /// — merged with the run's own rule, not a second list and not the
    /// row's severity summary.
    #[tokio::test]
    async fn a_promoted_assessment_carries_the_compositions_merged_findings() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        // The same advisory twice, once per invocation of the merge's
        // key: a promoted verdict must carry the merged list the commit
        // path evaluates, never the raw union.
        let scanner = RecordingScanner::new(
            "trivy",
            Ok(ScanAnalysis::Analysed(vec![
                composite_finding("CVE-2022-0778", SeverityThreshold::Critical),
                composite_finding("CVE-2022-0778", SeverityThreshold::Critical),
            ])),
        );
        let fixture =
            Fixture::new().with_policy(promoted_policy_blocking_at(SeverityThreshold::Critical));

        let verdict = outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![scanner]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            &fixture,
        )
        .await
        .verdict;

        let CompositeVerdict::Assessed { ref findings, .. } = verdict else {
            panic!("got {verdict:?}");
        };
        assert_eq!(findings.len(), 1, "the merge deduplicates: {findings:?}");
        assert_eq!(findings[0].vulnerability_id, "CVE-2022-0778");
        // And the observation is written on the same run, with the same
        // decision the manifest's verdict now is.
        assert_eq!(
            fixture.row().composite_findings_decision,
            Some(GateDecision::Reject),
        );
    }

    /// **No policy resolved is not a promotion.** The built-in default
    /// governs a repository with no operator policy, and promotion is an
    /// operator act against named criteria — so an out-of-the-box
    /// deployment measures the composition and gates on nothing.
    #[tokio::test]
    async fn a_repository_with_no_policy_is_never_promoted() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture = Fixture::new();

        let verdict = outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![scanner]),
            &artifact,
            "oci",
            ArtifactKind::OciManifest,
            &["trivy".to_string()],
            &fixture,
        )
        .await
        .verdict;

        assert_eq!(verdict, CompositeVerdict::Withheld);
        assert_eq!(
            fixture.row().assessment,
            CompositeAssessment::Assessed,
            "and the assessment still happened and was still recorded"
        );
    }

    /// **The assessment counter separates the two postures.** The four
    /// `result` arms say what the assessment found and nothing about
    /// whether it decided anything; under `observed` a refusal is a
    /// coverage gap an operator is weighing, and under `promoted` the
    /// same arm is a manifest held fail-closed.
    #[test]
    fn the_assessment_counter_labels_the_runs_posture() {
        for (policy, expected) in [
            (policy_blocking_at(SeverityThreshold::Critical), "observed"),
            (
                promoted_policy_blocking_at(SeverityThreshold::Critical),
                "promoted",
            ),
        ] {
            let (storage, artifact) = setup_for(CompositeAssessment::Assessed);
            let fixture = Fixture::new().with_policy(policy);
            let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
            let (proxy, resolver) = hosted();
            let snap = capture_metrics(|| {
                block_on(shadow_oci_with(
                    &storage, &proxy, &resolver, &scanner, &artifact, &fixture,
                ));
            });
            assert_eq!(
                ticks(
                    snap,
                    "hort_scan_composite_assessment_total",
                    &["result", "authority"],
                ),
                vec![(vec!["assessed".to_string(), expected.to_string()], 1,)],
            );
        }
    }

    /// **A non-manifest row is withheld without the policy being
    /// consulted.** Every artifact in every format reaches this call,
    /// and only an image manifest has a composition — so a promoted
    /// policy governing an npm repository changes nothing about it.
    #[tokio::test]
    async fn a_non_manifest_kind_is_withheld_even_under_a_promoted_policy() {
        let img = TwoLayerImage::new();
        let storage: Arc<dyn StoragePort> = img.warm_storage();
        let artifact = manifest_artifact(img.manifest.clone());
        let (proxy, resolver) = hosted();
        let scanner = RecordingScanner::new("trivy", Ok(ScanAnalysis::clean()));
        let fixture =
            Fixture::new().with_policy(promoted_policy_blocking_at(SeverityThreshold::Critical));

        let outcome = outcome_of(
            &storage,
            &proxy,
            &resolver,
            &registry(vec![scanner.clone()]),
            &artifact,
            "oci",
            ArtifactKind::OciBlob,
            &["trivy".to_string()],
            &fixture,
        )
        .await;

        assert_eq!(outcome.verdict, CompositeVerdict::Withheld);
        assert_eq!(outcome.disposition, CompositeDisposition::Settled);
        assert!(fixture.observations.rows().is_empty());
        assert!(scanner.seen().is_empty(), "and nothing was scanned");
    }
}
