//! Per-finding vulnerability record — the unit of identity in the
//! `(purl, vulnerability_id)`-keyed `compute_added_findings` delta
//! function and the row shape in the `scan_findings`
//! projection.
//!
//! `Finding` is a pure value type with `validate()` enforcing
//! length caps. The caps
//! are byte-counted (`String::len()`), not char-counted — they exist
//! to prevent runaway scanner output from blowing up the
//! per-finding blob, and the storage cost is bytes-on-disk.
//!
//! `Deserialize` does NOT re-validate. Findings round-trip from the
//! event store JSONB column; events that were once written must still
//! parse, even if their shape would now be rejected by the
//! constructor / validator. This mirrors
//! [`UpstreamPublishedChecksum`](super::checksum::UpstreamPublishedChecksum) —
//! the constructor / `validate()` are the only enforcement points.
//! Tested in `finding_deserialises_without_revalidation`.
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::scan_policy::{CompositeVerdictMode, SeverityThreshold};
use crate::error::{DomainError, DomainResult};
use crate::events::SeveritySummary;
use crate::types::ArtifactKind;

/// Per-finding length caps. Bytes, not chars. Each is
/// validated in [`Finding::validate`]; violators surface as
/// [`DomainError::Validation`] naming the field and the offending
/// size.
const MAX_PURL_LEN: usize = 512;
const MAX_VULNERABILITY_ID_LEN: usize = 128;
const MAX_TITLE_LEN: usize = 1024;
const MAX_FIXED_VERSIONS: usize = 32;
const MAX_REFERENCES: usize = 32;
/// Cap on `Finding.aliases`. OSV vulnerabilities typically carry 1-3
/// aliases (one CVE id plus optional vendor advisory id); the cap
/// leaves headroom for vulnerabilities that span multiple advisory
/// databases without becoming a vector for unbounded scanner output.
/// Each alias is byte-capped via [`MAX_VULNERABILITY_ID_LEN`] (same
/// cap as the primary `vulnerability_id` field).
pub(crate) const MAX_ALIASES: usize = 16;

/// One vulnerability finding produced by a scanner backend, keyed on
/// `(purl, vulnerability_id)` for delta computation against a prior
/// scan. Severity reuses the
/// [`SeverityThreshold`](crate::entities::scan_policy::SeverityThreshold)
/// enum so the policy evaluator and the finding payload share one
/// taxonomy.
///
/// Construction is unchecked — `validate()` is the single enforcement
/// point. The application layer calls it after assembling a finding
/// from scanner output and rejects the entire scan run on failure.
/// `Deserialize` never re-runs validation: events round-tripped from
/// the event-store JSONB column must accept any shape that was once
/// written.
//
// SAFETY: `Deserialize` is required, not optional. `Finding` is
// reconstructed from JSON in two non-API code paths that both round-trip
// values *we ourselves wrote*:
//   1. `quarantine_use_case::hydrate_prior_findings` reads the CAS-stored
//      `findings_blob` written by a previous `ScanCompleted` and parses
//      `Vec<Finding>` out of it (the hash-referenced per-finding
//      blob).
//   2. `hort-adapters-advisory-osv` caches OSV query results as JSON-encoded
//      `Vec<Finding>` in Redis to absorb the daily-diff scan storm.
// Neither path crosses an HTTP boundary — both deserialise bytes the
// service produced. The usual no-`Deserialize`
// `assert_not_impl_any!` lock would be
// inappropriate here; the no-API-deser invariant is held by the absence
// of any `Finding` field on the per-format HTTP request types instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub purl: String,
    pub vulnerability_id: String,
    pub severity: SeverityThreshold,
    pub cvss_score: Option<f32>,
    pub title: String,
    pub fixed_versions: Vec<String>,
    pub source_scanner: String,
    pub references: Vec<String>,
    /// Alternate identifiers for the same vulnerability, e.g. the CVE
    /// id when `vulnerability_id` is a GHSA primary. OSV publishes
    /// these via `vulns[].aliases`; Trivy publishes them via
    /// `VendorIDs`. Used by
    /// [`crate::policy::exclusion::cve_matches`] so an operator
    /// exclusion keyed by CVE-id matches a finding whose primary id
    /// is the corresponding GHSA (and vice versa). The original
    /// design treated `vulnerability_id`
    /// as an opaque string, but the operator-facing exclusion
    /// surface needs cross-id resolution to honour the "exclude this
    /// CVE" promise against any scanner that primaries on GHSA /
    /// OSV id.
    ///
    /// `#[serde(default)]` for round-trip compatibility with
    /// in-flight events / cached blobs written before this field
    /// landed. The `Deserialize` impl never re-runs `validate()`, so
    /// a payload missing this field deserialises with the default
    /// empty vec — same posture as every other shape-evolution on
    /// this struct.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The raw OSV `database_specific.informational` class verbatim — the
    /// fact the advisory database published, not a derived interpretation.
    /// RustSec/OSV informational advisories carry `"unmaintained"`,
    /// `"unsound"`, or `"notice"` here (under `affected[].database_specific`
    /// for full records); these are maintenance signals published without a
    /// CVSS score by design, not exploitable defects. `None` means a scored
    /// vulnerability — no informational marker.
    ///
    /// Persisting the class string (the fact) rather than a derived boolean
    /// keeps the interpretation re-derivable: a future per-class policy
    /// (e.g. block `unsound`, ignore `unmaintained`) can re-evaluate from
    /// stored findings, which a baked-in boolean would have lost. The
    /// boolean is derived on demand via [`Finding::is_informational`].
    ///
    /// Informational findings are routed onto the non-enforcing
    /// **negligible** lane by [`severity_summary_from_findings`] and the
    /// post-exclusion block-decision summary, so they never trip a
    /// severity threshold. `severity` is cosmetic for these (the OSV
    /// adapters map it to `Low`); the negligible routing — keyed on
    /// [`Finding::is_informational`], not on `severity` — is what makes them
    /// non-blocking.
    ///
    /// `#[serde(default)]` for round-trip compatibility with events /
    /// cached blobs written before this field landed: a payload missing
    /// it deserialises as `None` (a scored vulnerability), the same
    /// no-re-validation posture as every other shape-evolution on this
    /// struct.
    #[serde(default)]
    pub informational_class: Option<String>,
    /// Whether the backend that produced this finding actually *read* a
    /// severity, or fell back to the unconditional `Critical` default
    /// because it could not determine one. See [`SeverityBasis`].
    ///
    /// `#[serde(default)]` yields [`SeverityBasis::Assessed`] — the
    /// fail-safe. A record written before this field existed cannot be
    /// proven to be a fail-closed default, so it keeps the pre-existing
    /// "a `Critical` always wins the merge" behaviour and is never talked
    /// down by a better-informed sibling. Defaulting to `Unassessed`
    /// instead would let a scored `Low` demote a legacy *genuine*
    /// `Critical`, which is a fail-open regression (ADR 0007). Same
    /// no-re-validation posture as every other shape-evolution on this
    /// struct.
    #[serde(default)]
    pub severity_basis: SeverityBasis,
    /// How the component this finding names relates to the artifact it was
    /// found on — the artifact's own subject component, a component the
    /// artifact carries, a component it does not carry, or not established.
    /// See [`ComponentRelation`].
    ///
    /// `#[serde(default)]` yields [`ComponentRelation::NotEstablished`], and
    /// [`Finding::may_condemn_artifact`] reads that as condemning. A record
    /// written before this field existed carries no evidence about its
    /// component at all, so it cannot be *proven* to name code the artifact
    /// does not contain; defaulting it to `NotContained` would strip release
    /// authority from every finding already in the event store and the
    /// findings blob in one step, which is a fail-open regression against
    /// ADR 0007. Same direction, and the same reasoning, as `severity_basis`
    /// defaulting to `Assessed`.
    ///
    /// The condemning default is only safe while `NotEstablished` stays rare
    /// and correctable. A scan whose SBOM has a subject always establishes
    /// the relation, and the subject is derived from the artifact's
    /// coordinates rather than its payload, so a persisted `NotEstablished`
    /// is a record awaiting a rescan, not a resting state of the design. A
    /// format that starts producing it on fresh scans is a defect in that
    /// format's SBOM builder, not something this default absorbs.
    ///
    /// Same no-re-validation posture as every other shape-evolution on this
    /// struct.
    #[serde(default)]
    pub component_relation: ComponentRelation,
    /// What this finding's statement is **about** — the bytes it was read
    /// out of, or the filesystem those bytes compose into. See
    /// [`FindingStatement`].
    ///
    /// **Persists**, and carries only the producer's half of ADR 0064
    /// D2's line. What the producer read is its own fact and is
    /// unrecoverable afterwards, so a verdict re-taken over stored
    /// findings has to be able to read it or it answers a different
    /// question from the one the fresh scan answered — which is what the
    /// tighten pass did while this field was transient: it read every
    /// stored finding as `Unstated`, condemned, and terminally rejected
    /// the same constituent a fresh scan under the same promoted policy
    /// had just let through. Whose filesystem the claim is about is
    /// **not** stored, because it is derivable from the row's
    /// [`ArtifactKind`] at any time; see [`FindingStatement`] on why the
    /// composition of the two is not a variant.
    ///
    /// `#[serde(default, skip_serializing_if = …)]` on the `Unstated`
    /// default, never a bare `#[serde(default)]`: a bare one re-serialises
    /// an older stored payload with a key it does not have, which breaks
    /// the event chain for every `ArtifactBecameVulnerable` written before
    /// this field persisted. With the skip, a finding whose statement is
    /// `Unstated` serialises to exactly the bytes it did before — the CAS
    /// findings blob and the event payload are unmoved, and so is the
    /// 64 KB serialised event cap's headroom for that population. A
    /// *stated* finding costs the key (`,"statement":"filesystem"`), which
    /// is the price of the field being readable at all.
    ///
    /// Same no-re-validation posture as every other shape-evolution on
    /// this struct: a payload missing the key deserialises as `Unstated`,
    /// which condemns.
    #[serde(default, skip_serializing_if = "FindingStatement::is_unstated")]
    pub statement: FindingStatement,
    /// When the advisory this finding names was **published** — the
    /// upstream fact about the vulnerability, not about any scan of ours.
    /// `None` when the producing backend carried no publication date.
    ///
    /// This is the primary anchor for the retention predicate
    /// `HasFindingDetectedFor`,
    /// whose question is *how long has this vulnerability been known* —
    /// the longer a vulnerability is public, the likelier it is
    /// exploited. Nothing about this artifact's own scan history answers
    /// that question, so the date has to travel with the finding from the
    /// backend that read it. The fallback when it is absent is our own
    /// earliest observation of the vulnerability, which is a strictly
    /// later and therefore non-deleting reading; see
    /// [`crate::retention::resolve_finding_age_anchor`].
    ///
    /// **Two wire forms, two meanings.** OSV publishes `published` —
    /// when the OSV *entry* was created in the advisory database. Trivy
    /// publishes `PublishedDate`, which trivy-db's own field comment
    /// takes *"from NVD or GHSA"*. The two therefore date related but
    /// distinct events, and the disagreement is not a rounding error: in
    /// a 10-advisory sample of GHSA-primary npm records, 7 agreed within
    /// a day while one GHSA entry postdated NVD by 325 days and another
    /// predated it by 15 — in **both** directions, so neither feed is
    /// systematically the earlier one.
    ///
    /// The anchor resolver takes the earliest across sources and records
    /// which source supplied it, because a feed that dates
    /// systematically early would otherwise drag every anchor forward
    /// undiagnosably. [`Self::source_scanner`] is that provenance — note
    /// that it names the **feed**, not the adapter: the osv-scanner
    /// backend and the OSV advisory-enrichment path both report
    /// `"osv"`.
    ///
    /// `#[serde(default, skip_serializing_if = …)]` rather than a bare
    /// `#[serde(default)]`, for the reason spelled out on
    /// [`Self::statement`]: a finding without a publication date must
    /// serialise to exactly the bytes it did before the field existed, or
    /// every `ArtifactBecameVulnerable` and CAS findings blob already
    /// written re-serialises with a key it never had. Same
    /// no-re-validation posture as every other shape-evolution here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_published_at: Option<DateTime<Utc>>,
}

/// Whether a finding's `severity` is a real reading or the fail-closed
/// default.
///
/// Two findings for the same advisory can be byte-identical
/// (`Critical` / no CVSS / no informational class) and yet mean opposite
/// things: one backend genuinely assessed the advisory as critical, another
/// simply could not parse a severity at all and fell back to the highest
/// tier (the fail-closed default that keeps an unreadable finding from
/// slipping under a block threshold). Persisting *which* of the two it is
/// lets the cross-backend merge keep the better-informed reading instead of
/// discarding it — see [`Finding::is_informed`] and ADR 0059.
///
/// Persist the fact, derive the interpretation: this records what the
/// backend did, not what the merge should conclude from it (the same shape
/// as [`Finding::informational_class`], ADR 0040).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBasis {
    /// The backend produced a real severity reading — a parsed CVSS score,
    /// a recognised severity label, or an informational classification.
    ///
    /// The `Default`, and therefore what `#[serde(default)]` yields for a
    /// record persisted before the field existed: the fail-safe reading
    /// that never talks a legacy finding down.
    #[default]
    Assessed,
    /// The backend could **not** determine a severity and fell back to the
    /// unconditional `Critical` default. The `Critical` carries no
    /// information about the advisory beyond "unreadable"; it is a floor,
    /// not an assessment.
    Unassessed,
}

/// How the component a finding names relates to the artifact under scan —
/// the fact a scan observed, never the verdict drawn from it.
///
/// A finding's `purl` names a component; the artifact's SBOM
/// ([`crate::types::Sbom`]) names a `subject` (the artifact itself) and the
/// `components` its payload resolved, joined to findings on
/// `Finding.purl == SbomComponent.purl`. Those resolved components are not
/// all in the artifact. A cargo `.crate` is a **source** distribution: it
/// carries the publishing maintainer's own `Cargo.lock` and none of the code
/// that lockfile pins, and a consumer's build ignores a dependency's
/// lockfile entirely — only the top-level package's resolve decides what is
/// built. So an advisory against a version read out of that embedded
/// lockfile is about code the artifact does not contain and nobody resolves.
/// A format whose payload carries its closure — an OCI image and its layers
/// — is the opposite case: the same non-subject component *is* in the
/// artifact. Keeping those apart is what this enum is for; the component
/// list itself stays useful either way (ADR 0056).
///
/// An enum, not a bool, for the reason ADR 0059 gives for [`SeverityBasis`]:
/// a bool fixes one question for ever, and there are already four distinct
/// observations here — two of which, "contained but not the subject" and
/// "not contained", a bool would have to collapse into one answer.
///
/// Persist the fact, derive the interpretation (ADR 0040): the variants name
/// what was observed about the component, and
/// [`Finding::may_condemn_artifact`] is the only place an observation
/// becomes release authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRelation {
    /// The finding names the artifact's **subject** component — the artifact
    /// itself. Its code is in the artifact by definition.
    Subject,
    /// The finding names a component other than the subject whose code the
    /// artifact nevertheless carries, because the format's payload contains
    /// its closure (an OCI image and its layers).
    Contained,
    /// The finding names a component whose code the artifact does **not**
    /// carry. The payload resolved the component's coordinates out of a
    /// manifest or lockfile it ships, but ships none of that component.
    NotContained,
    /// The relation was not determined — no subject was available to join
    /// the finding against, or the finding predates the field.
    ///
    /// The `Default`, and therefore what `#[serde(default)]` yields for a
    /// record persisted before the field existed. It is the fail-safe
    /// reading: an unestablished relation is an *absence* of evidence, and
    /// the finding keeps the release authority it has today rather than
    /// losing it on a fact nobody established.
    #[default]
    NotEstablished,
}

impl ComponentRelation {
    /// Resolve two relations for the **same** advisory on the same artifact
    /// to the one that withholds the least authority — the single
    /// definition of "which of these two is more condemning?", and the
    /// companion to [`Finding::may_condemn_artifact`] rather than a second
    /// answer to it.
    ///
    /// Two backends can report one `(purl, vulnerability_id)` and tag it
    /// differently: a purl the BOM does not list is a package a
    /// payload-scanning backend physically found
    /// ([`Self::Contained`]) and a failed join for a backend whose whole
    /// input was the BOM ([`Self::NotEstablished`]). The reconciliation
    /// that picks a survivor for such a collision ranks severity,
    /// information quality and CVSS (ADR 0059) and knows nothing about the
    /// relation, so without this the surviving row's release authority
    /// would be decided by which backend happened to win a severity
    /// comparison. The survivor keeps the stronger claim instead:
    /// authority is withheld only where non-containment was actually
    /// **established**, never as a side effect of a ranking on another
    /// axis (ADR 0007 fail-closed).
    ///
    /// Commutative, and idempotent, by construction: it is the maximum
    /// over [`Self::containment_claim_rank`], so the answer cannot depend
    /// on which backend reported first, and folding it across a run of
    /// collisions cannot move back down the order.
    pub fn more_condemning(self, other: Self) -> Self {
        if other.containment_claim_rank() > self.containment_claim_rank() {
            other
        } else {
            self
        }
    }

    /// How strongly this relation claims the artifact carries the named
    /// component's code: `Subject` (it *is* the artifact) > `Contained`
    /// (observed in the payload) > `NotEstablished` (nothing observed) >
    /// `NotContained` (observed absent).
    ///
    /// The bottom of the order is exactly the one relation
    /// [`Finding::may_condemn_artifact`] refuses, which is what makes the
    /// maximum above "the more condemning one" rather than a second,
    /// drifting opinion about authority —
    /// `the_bottom_of_the_order_is_exactly_the_relation_that_cannot_condemn`
    /// pins the two together. The order above the bottom is the evidential
    /// strength of the claim, so a future rule that withheld authority
    /// from a weaker claim would still find the strongest one surviving a
    /// merge.
    ///
    /// Exhaustive with no wildcard arm, for [`Finding::may_condemn_artifact`]'s
    /// reason: a new relation must be *placed* in the order, and getting a
    /// rank by omission is a compile error instead.
    const fn containment_claim_rank(self) -> u8 {
        match self {
            ComponentRelation::Subject => 3,
            ComponentRelation::Contained => 2,
            ComponentRelation::NotEstablished => 1,
            ComponentRelation::NotContained => 0,
        }
    }
}

/// What a finding's statement is **about**: the bytes it was read out of,
/// or the filesystem those bytes compose into (ADR 0064 D2).
///
/// The line this enum draws is whether the claim's truth depends on how
/// the bytes are composed. "This blob carries a leaked key" or "these
/// bytes are malware" is true of them however they are assembled, so such
/// a finding keeps gating the artifact it was found on. "This package is
/// installed and vulnerable" is true only of an assembled tree: a later
/// layer can delete the package, so the claim is not about any one
/// constituent's bytes — and for a constituent of a composition hort
/// assesses as a whole (ADR 0064 D1), the composition is where the claim
/// belongs.
///
/// **Set by the producer, from what it actually read, and by nobody
/// else.** A payload scanner knows which section of its report a finding
/// came out of and what it was pointed at; nothing downstream can recover
/// either, which is why the value persists (see [`Finding::statement`]).
/// Required of every producer for the reason
/// [`ScannerPort::evidence_basis`](crate::ports::scanner::ScannerPort::evidence_basis)
/// is required with no default: a value nobody stated is a claim about a
/// backend's own output that nobody checked.
///
/// Today every finding hort consumes is a package-vulnerability claim —
/// the Trivy report parser reads only `Vulnerabilities` — so D2 moves all
/// of them. The line is drawn now **because** that is true: a later
/// secrets or malware backend must not be silently disarmed by a decision
/// taken when no such backend existed.
///
/// # Three variants, and why there is no fourth
///
/// Persist the fact, derive the interpretation (ADR 0040). The three
/// variants are exactly what a producer can state about its own output,
/// and **"a claim about the filesystem one constituent of a composition
/// makes in isolation" is deliberately not among them** — that is the
/// composition of two facts, the producer's half and the
/// [`ArtifactKind`] of the row the finding was found on, and storing a
/// composition is storing a conclusion. The row's kind is derivable from
/// the artifact at any time; the producer's half is not. So only the
/// producer's half is a field, and
/// [`Finding::may_condemn_artifact`] composes the two where it decides,
/// the way
/// [`NotAnalysable::gates_release`](crate::ports::scanner::NotAnalysable::gates_release)
/// already does for an *absent* assessment of the same surface — which
/// also means a stored finding **cannot** carry the conclusion, as a
/// property of this type rather than of a convention about who writes it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatement {
    /// About **the bytes** the finding was read out of — true of them
    /// however they are composed. A leaked credential or a malware
    /// signature is in those bytes whatever tree they end up in, so such
    /// a finding keeps gating its own artifact under every posture.
    ///
    /// No backend hort ships produces one today (see the type docs); the
    /// variant exists so the first one that does has a side to state.
    Bytes,
    /// About **the filesystem those bytes compose into**.
    ///
    /// Whose filesystem that is, this variant does not say, because the
    /// producer cannot: for a composed OCI image (ADR 0064 D1) or any
    /// payload whose materialised tree is the whole artifact — an npm
    /// tarball installed under `node_modules`, a wheel, an sdist, a
    /// `.crate` — it is the artifact's own, and for a constituent of a
    /// composition hort assesses as one unit it is a tree nothing runs.
    /// [`Finding::may_condemn_artifact`] resolves that against the row's
    /// [`ArtifactKind`]; see the type docs.
    Filesystem,
    /// No producer stated a side. The `Default`, and what a record
    /// written before this field existed reads as.
    ///
    /// Two live populations reach it, and both are fail-closed: a
    /// producer that read no report section about a filesystem at all —
    /// the SBOM-driven backends and the advisory-enrichment path, whose
    /// whole input is a component list; and a finding reconstructed from
    /// a projection row, which has no column for the statement.
    ///
    /// Condemns, for [`ComponentRelation::NotEstablished`]'s reason: an
    /// unstated side is an absence of evidence, and the fail-closed
    /// reading of absent evidence is that the finding still counts
    /// (ADR 0007).
    #[default]
    Unstated,
}

impl FindingStatement {
    /// Whether no producer stated a side. Spent on the
    /// `skip_serializing_if` that keeps an `Unstated` statement out of
    /// the wire form entirely — see [`Finding::statement`].
    #[must_use]
    pub const fn is_unstated(&self) -> bool {
        matches!(self, Self::Unstated)
    }

    /// Stable lowercase identifier for logs — and the serialised form,
    /// which `#[serde(rename_all = "snake_case")]` derives to the same
    /// strings. Kept in step by
    /// `the_log_label_and_the_wire_form_are_the_same_string`, so a
    /// renamed label cannot silently become a second vocabulary.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Filesystem => "filesystem",
            Self::Unstated => "unstated",
        }
    }
}

impl std::fmt::Display for FindingStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Recognises the OSV `database_specific.informational` classes that mark a
/// finding as informational rather than a scored vulnerability:
/// `unmaintained` / `unsound` / `notice` (ASCII case-insensitive). This is
/// the canonical recognizer shared by the OSV adapters (which decide the
/// finding's severity from it) and the negligible-lane routing
/// ([`Finding::is_informational`]); a finding's raw informational class is
/// persisted, and this function re-derives the boolean interpretation from
/// it at decision time. Any other (or absent) value is not informational,
/// preserving the SUP-4 fail-closed Critical fallback for genuinely-unscored
/// vulnerabilities.
pub fn is_informational_class(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "unmaintained" | "unsound" | "notice"
    )
}

/// Parse an upstream advisory publication timestamp into
/// [`Finding::advisory_published_at`].
///
/// One definition, three producers. OSV spells the value `published`,
/// Trivy spells it `PublishedDate`, and both emit RFC 3339 — but a
/// per-adapter copy of this parse is a per-adapter opportunity to accept a
/// shape the others reject, and the field feeds a predicate that deletes.
/// The adapters call this; nothing else interprets the wire form.
///
/// An unparseable value yields `None` rather than an error. The field is
/// an optional refinement: without it the anchor falls back to our own
/// first observation of the vulnerability, which is strictly later and so
/// strictly less likely to expire anything. Failing the whole scan run
/// over a malformed date on one advisory would trade a harmless loss of
/// precision for a lost scan.
///
/// A future-dated value is returned verbatim, not clamped. The anchor it
/// becomes is then in the future, and the elapsed-time comparison in the
/// retention evaluator reads a future anchor as "not elapsed" — the
/// non-deleting answer. Clamping it to `now` would instead assert the
/// vulnerability became known this instant, which is a claim nothing
/// supports.
pub fn parse_advisory_published_at(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Bound a lowered finding's `title` to the byte cap
/// [`Finding::validate`] enforces, truncating on a character boundary.
///
/// One definition, two producers — the same shape as
/// [`parse_advisory_published_at`] above it and
/// [`collapse_alias_groups`](crate::types::collapse_alias_groups)
/// beside it. Both scanner adapters build `title` out of upstream prose
/// that carries no bound of its own — OSV from `summary`, falling back
/// to the long-form `details`; Trivy from `Title` — so both have to
/// apply the cap where the value is built. A per-adapter copy is
/// also a per-adapter copy of the cap *value*, which the copies cannot
/// see and so cannot be narrowed in step with: narrow the cap here and
/// an adapter holding a stale copy starts refusing titles it believes it
/// already bounded.
///
/// # Truncate the description, never the identity
///
/// A title is **descriptive** — nothing keys on it, and the cap is
/// routinely reached by real records, so losing the tail of a
/// description costs a reader some prose and nothing else. The identity
/// fields (`purl`, `vulnerability_id`, an alias element) are the
/// opposite case and deliberately have no counterpart here: truncating
/// one names a *different* package or a *different* advisory, and would
/// silently void an operator exclusion keyed on the real id. So a
/// finding that still fails `validate` after this cap has been applied
/// is holding an identity this system cannot represent, which is a
/// refusal of the whole report — never a finding to drop out of it,
/// because a report lowered to a shorter finding list is a verdict the
/// scanner did not reach, and a report lowered to an *empty* one is a
/// clean verdict carrying release authority.
///
/// A marker is appended so a reader can tell a truncated description
/// from one the publisher wrote that short, and the marker is counted
/// inside the cap rather than added past it.
pub fn cap_finding_title(title: String) -> String {
    if title.len() <= MAX_TITLE_LEN {
        return title;
    }
    const MARKER: &str = "…";
    let cut = title.floor_char_boundary(MAX_TITLE_LEN - MARKER.len());
    let mut out = String::with_capacity(cut + MARKER.len());
    out.push_str(&title[..cut]);
    out.push_str(MARKER);
    out
}

/// Per-tier count over `findings` — single source of truth
/// for the `ScanCompleted.severity_summary` aggregate. Lifted from
/// previously-duplicated copies in `hort-app::scan_orchestration` and
/// `hort-app::quarantine_use_case` so both
/// callers reuse one helper. A finding for which
/// [`Finding::is_informational`] holds is counted in `negligible` (the
/// non-enforcing lane) regardless of its cosmetic `severity`; the
/// `SeverityThreshold` enum has no Negligible variant — informational
/// is a property of the finding, not a severity tier.
pub fn severity_summary_from_findings(findings: &[Finding]) -> SeveritySummary {
    let mut s = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    for f in findings {
        if f.is_informational() {
            s.negligible += 1;
            continue;
        }
        match f.severity {
            SeverityThreshold::Critical => s.critical += 1,
            SeverityThreshold::High => s.high += 1,
            SeverityThreshold::Medium => s.medium += 1,
            SeverityThreshold::Low => s.low += 1,
        }
    }
    s
}

/// Lowercase wire string for the `severity` metric label.
/// Mirrors `SeverityThreshold`'s `Display` impl exactly so the catalog
/// stays the single source of truth. Lifted
/// from the previously-duplicated copies in
/// `hort-app::scan_orchestration` and `hort-app::quarantine_use_case`.
pub fn severity_label(s: SeverityThreshold) -> &'static str {
    match s {
        SeverityThreshold::Critical => "critical",
        SeverityThreshold::High => "high",
        SeverityThreshold::Medium => "medium",
        SeverityThreshold::Low => "low",
    }
}

/// Lowercase wire string for a [`ComponentRelation`] metric label.
/// Mirrors the `#[serde(rename_all = "snake_case")]` wire spelling
/// exactly — pinned by `component_relation_label_matches_the_serde_wire_spelling`
/// — so a stored finding and the counter that observed it name the same
/// relation with the same word.
///
/// Lives beside [`severity_label`], and for the same reason: the label
/// values of `hort_finding_component_relation_total{format, result}` are
/// this enum's variants and nothing else, so a parallel label enum in the
/// emitting layer would be a second taxonomy to keep in step rather than a
/// translation of anything. The match is exhaustive with no wildcard: a new
/// relation has to be given a wire word here, which is also what forces the
/// catalog row to move with it.
pub fn component_relation_label(relation: ComponentRelation) -> &'static str {
    match relation {
        ComponentRelation::Subject => "subject",
        ComponentRelation::Contained => "contained",
        ComponentRelation::NotContained => "not_contained",
        ComponentRelation::NotEstablished => "not_established",
    }
}

/// Pick the highest severity tier among `findings`.
/// `Critical > High > Medium > Low`. Returns `None` for an empty slice.
/// The
/// `hort_artifact_became_vulnerable_total.severity` label takes the top
/// tier of the post-delta `new_findings` set. Lifted into the domain
/// crate so the orchestrator and quarantine use
/// cases share one helper.
pub fn highest_severity(findings: &[Finding]) -> Option<SeverityThreshold> {
    let mut best: Option<SeverityThreshold> = None;
    for f in findings {
        let tier = severity_tier(f.severity);
        let best_tier = best.map(severity_tier);
        if best_tier.map(|bt| tier < bt).unwrap_or(true) {
            best = Some(f.severity);
        }
    }
    best
}

/// Numeric tier where `0 = Critical` and `3 = Low`. Lower number =
/// higher severity. Internal helper for [`highest_severity`], the
/// alias-group winner tie-break in
/// [`super::alias_group::collapse_alias_groups`], and the
/// `merge_findings` collision policy in `hort-app::scan_orchestration`.
pub(crate) fn severity_tier(s: SeverityThreshold) -> u8 {
    match s {
        SeverityThreshold::Critical => 0,
        SeverityThreshold::High => 1,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::Low => 3,
    }
}

impl Finding {
    /// Whether this finding is informational — derived at decision time
    /// from the persisted [`Finding::informational_class`] fact via the
    /// canonical [`is_informational_class`] recognizer. `None` (a scored
    /// vulnerability) or an unrecognised class is not informational.
    /// Routing onto the non-enforcing negligible lane keys on this, not on
    /// `severity`.
    ///
    /// A finding carrying any `cvss_score` is never informational, even
    /// with a recognised class: informational advisories carry no CVSS
    /// by design, so a scored finding stays on the enforced lane
    /// regardless of any class string. Gating on the absence of a CVSS
    /// score preserves the fail-closed posture — a genuinely-scored
    /// vulnerability cannot be demoted off the threshold gate.
    pub fn is_informational(&self) -> bool {
        self.cvss_score.is_none()
            && self
                .informational_class
                .as_deref()
                .is_some_and(is_informational_class)
    }

    /// Whether this finding carries a real severity reading, in any of the
    /// three forms that count as one: a parsed CVSS score, a recognised
    /// informational classification, or a [`SeverityBasis::Assessed`]
    /// marker from the producing backend.
    ///
    /// The complement — [`SeverityBasis::Unassessed`] with neither a score
    /// nor an informational class — is a finding whose `severity` is the
    /// fail-closed `Critical` floor rather than an assessment of the
    /// advisory. The cross-backend merge prefers an informed reading over
    /// an uninformed one for the same advisory, across severity tiers, so
    /// one backend's "I could not read this" does not discard another's
    /// correct reading (ADR 0059). Two *informed* findings still compare by
    /// severity tier, so a scored `Critical` is never talked down by a
    /// scored `Low` (ADR 0007).
    pub fn is_informed(&self) -> bool {
        matches!(self.severity_basis, SeverityBasis::Assessed)
            || self.cvss_score.is_some()
            || self.is_informational()
    }

    /// Whether this finding may condemn the artifact it was found on — the
    /// **single** place that question is answered. Every decision about
    /// whether a finding gates a release asks here; nothing re-derives the
    /// rule by matching on [`Finding::component_relation`] itself, and there
    /// is deliberately no second accessor phrasing the same question in
    /// other words.
    ///
    /// A finding condemns unless the artifact is known **not** to carry the
    /// named component's code. A source distribution lists the versions its
    /// maintainer resolved at publish time without shipping any of that
    /// code, and a consumer's build ignores those pins, so an advisory
    /// against one of them is not evidence about this artifact. Such a
    /// finding stays in the record — it is true information about the
    /// dependency, and a consumer may well want it — it simply carries no
    /// release authority.
    ///
    /// [`ComponentRelation::NotEstablished`] condemns. No relation having
    /// been established is an absence of evidence, and the fail-closed
    /// reading of absent evidence is that the finding still counts
    /// (ADR 0007).
    ///
    /// The match is exhaustive with no wildcard arm on purpose: a new
    /// relation must be given release authority, or denied it, here — and
    /// adding one without deciding is a compile error rather than a silent
    /// grant.
    ///
    /// [`ComponentRelation::more_condemning`] is the ordering companion,
    /// not a second answer: it says which of two relations reported for one
    /// advisory survives their reconciliation, and its bottom element is
    /// exactly the relation this predicate refuses.
    ///
    /// # The second question, and why it is the same question
    ///
    /// Two independent facts can take a finding's authority over *this*
    /// artifact away, and both are asked here because they are one
    /// question — "may this finding condemn the artifact it was found
    /// on?" — not two. A second predicate for the second fact would be a
    /// second voice answering it, which is what
    /// `hort-app/tests/condemning_rule_is_single_sourced.rs` exists to
    /// prevent.
    ///
    /// The second fact is **what the finding's statement is about**
    /// ([`FindingStatement`], ADR 0064 D2) — and it takes two inputs to
    /// spend, because the producer states only half of it. A claim about
    /// the filesystem one *constituent* of a composition makes in
    /// isolation is not a claim about the composition anything runs: a
    /// later layer adds packages an earlier one cannot be read for, and
    /// removes packages it carries, so no composition of per-constituent
    /// verdicts reconstructs the composed package set. Where an operator
    /// has promoted the composite verdict (`composite_verdict`), the
    /// composition is assessed as one unit and carries the filesystem
    /// verdict, so the constituent's own filesystem findings are evidence
    /// and nothing more. Under every other posture they gate exactly as
    /// they do today — which is what makes an unpromoted repository
    /// byte-for-byte unchanged a property of this one match.
    ///
    /// So the [`FindingStatement::Filesystem`] arm is where `kind` and
    /// `composite_verdict` are composed, and it is composed **here**
    /// rather than stored on the finding: the producer's half is a fact
    /// nothing downstream can recover, the row's half is derivable from
    /// the artifact whenever it is wanted, and a field holding the two
    /// already joined would be a stored conclusion (ADR 0040). The same
    /// two inputs, in the same conjunction, are what
    /// [`NotAnalysable::gates_release`](crate::ports::scanner::NotAnalysable::gates_release)
    /// composes for an *absent* assessment of that same surface — and
    /// "which rows are constituents?" is
    /// [`ArtifactKind::is_composition_constituent`]'s single answer in
    /// both, so a finding and an absence cannot disagree about one row.
    ///
    /// Both inputs are required, and together: promotion alone would move
    /// the obligation for every format ADR 0064 leaves undecided, and the
    /// kind alone would move it before an operator had granted the
    /// composite verdict any authority.
    ///
    /// The other two statements condemn, and each for its own reason:
    /// [`FindingStatement::Bytes`] is true of the bytes however they are
    /// composed, so no composition above it can take the claim; and
    /// [`FindingStatement::Unstated`] condemns for
    /// [`ComponentRelation::NotEstablished`]'s reason — an unstated side
    /// is an absence of evidence, and the fail-closed reading of absent
    /// evidence is that the finding still counts (ADR 0007).
    ///
    /// Exhaustive with no wildcard on either axis, for the same reason:
    /// a new relation, or a new kind of statement, is a compile error
    /// until it is given release authority or denied it here.
    ///
    /// `kind` is what the artifact's own format handler says its bytes
    /// are, and `composite_verdict` is a **resolved** posture — normally
    /// [`crate::policy::composite_verdict_mode_of`] over the policy that
    /// governs the artifact's repository, never a per-finding field,
    /// because promotion is a property of that policy and a finding
    /// carrying its own copy could disagree with it. One caller pins the
    /// posture to [`CompositeVerdictMode::Observed`] instead of resolving
    /// it, deliberately and for ADR 0064 D6's reason — see
    /// [`crate::policy::decide_rejected_transition`].
    pub fn may_condemn_artifact(
        &self,
        kind: ArtifactKind,
        composite_verdict: CompositeVerdictMode,
    ) -> bool {
        let carries_the_component = match self.component_relation {
            ComponentRelation::Subject => true,
            ComponentRelation::Contained => true,
            ComponentRelation::NotContained => false,
            ComponentRelation::NotEstablished => true,
        };
        let decides_this_artifact = match self.statement {
            FindingStatement::Bytes => true,
            FindingStatement::Unstated => true,
            FindingStatement::Filesystem => {
                !(kind.is_composition_constituent()
                    && composite_verdict.carries_release_authority())
            }
        };
        carries_the_component && decides_this_artifact
    }

    /// Validate the per-finding length caps.
    /// Returns `DomainError::Validation` naming the offending field
    /// and its observed size on failure. Lengths are byte-counted via
    /// `String::len()` and `Vec::len()`.
    pub fn validate(&self) -> DomainResult<()> {
        if self.purl.len() > MAX_PURL_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.purl is {} bytes, max is {}",
                self.purl.len(),
                MAX_PURL_LEN,
            )));
        }
        if self.vulnerability_id.len() > MAX_VULNERABILITY_ID_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.vulnerability_id is {} bytes, max is {}",
                self.vulnerability_id.len(),
                MAX_VULNERABILITY_ID_LEN,
            )));
        }
        if self.title.len() > MAX_TITLE_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.title is {} bytes, max is {}",
                self.title.len(),
                MAX_TITLE_LEN,
            )));
        }
        if self.fixed_versions.len() > MAX_FIXED_VERSIONS {
            return Err(DomainError::Validation(format!(
                "Finding.fixed_versions has {} entries, max is {}",
                self.fixed_versions.len(),
                MAX_FIXED_VERSIONS,
            )));
        }
        if self.references.len() > MAX_REFERENCES {
            return Err(DomainError::Validation(format!(
                "Finding.references has {} entries, max is {}",
                self.references.len(),
                MAX_REFERENCES,
            )));
        }
        if self.aliases.len() > MAX_ALIASES {
            return Err(DomainError::Validation(format!(
                "Finding.aliases has {} entries, max is {}",
                self.aliases.len(),
                MAX_ALIASES,
            )));
        }
        for (idx, alias) in self.aliases.iter().enumerate() {
            if alias.len() > MAX_VULNERABILITY_ID_LEN {
                return Err(DomainError::Validation(format!(
                    "Finding.aliases[{idx}] is {} bytes, max is {}",
                    alias.len(),
                    MAX_VULNERABILITY_ID_LEN,
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_finding() -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: "CVE-2021-23337".into(),
            severity: SeverityThreshold::High,
            cvss_score: Some(7.2),
            title: "Command Injection in lodash".into(),
            fixed_versions: vec!["4.17.21".into()],
            source_scanner: "trivy".into(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".into()],
            aliases: vec!["GHSA-35jh-r3h4-6jhm".into()],
            informational_class: None,
            severity_basis: SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    /// Every [`FindingStatement`], written out rather than iterated, so a
    /// new variant is a compile error in each matrix below instead of a
    /// silently unswept case. Mirrors `ALL_RELATIONS`.
    fn every_statement() -> [FindingStatement; 3] {
        [
            FindingStatement::Bytes,
            FindingStatement::Filesystem,
            FindingStatement::Unstated,
        ]
    }

    /// Every [`ArtifactKind`] — one constituent and every non-constituent
    /// — so the kind axis of the predicate's matrix is swept rather than
    /// sampled.
    fn every_kind() -> [ArtifactKind; 9] {
        [
            ArtifactKind::OciBlob,
            ArtifactKind::OciManifest,
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PyWheel,
            ArtifactKind::PySdist,
            ArtifactKind::Other,
        ]
    }

    // ----- Serde round-trips -----------------------------------------------

    #[test]
    fn finding_round_trips_through_serde_when_fully_populated() {
        let f = valid_finding();
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn finding_round_trips_with_empty_optional_and_collection_fields() {
        let f = Finding {
            purl: "pkg:cargo/anyhow@1.0.0".into(),
            vulnerability_id: "GHSA-aaaa-bbbb-cccc".into(),
            severity: SeverityThreshold::Low,
            cvss_score: None,
            title: "advisory".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
            severity_basis: SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: FindingStatement::Unstated,
            advisory_published_at: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn finding_deserialises_with_default_aliases_when_field_absent() {
        // `aliases` is `#[serde(default)]`
        // so an event / cached blob written before the field landed
        // round-trips with an empty alias list rather than failing to
        // deserialise. Mirrors the no-re-validation posture of every
        // other shape-evolution on this struct.
        let legacy_json = r#"{
            "purl": "pkg:npm/lodash@4.17.20",
            "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
            "severity": "High",
            "cvss_score": null,
            "title": "Command Injection in lodash",
            "fixed_versions": ["4.17.21"],
            "source_scanner": "osv",
            "references": []
        }"#;
        let back: Finding = serde_json::from_str(legacy_json).unwrap();
        assert!(back.aliases.is_empty());
        assert_eq!(back.vulnerability_id, "GHSA-35jh-r3h4-6jhm");
    }

    #[test]
    fn validate_accepts_aliases_at_cap() {
        let mut f = valid_finding();
        f.aliases = (0..MAX_ALIASES).map(|i| format!("CVE-2024-{i}")).collect();
        assert!(f.validate().is_ok());
    }

    #[test]
    fn validate_rejects_aliases_over_cap() {
        let mut f = valid_finding();
        f.aliases = (0..(MAX_ALIASES + 1))
            .map(|i| format!("CVE-2024-{i}"))
            .collect();
        let err = f.validate().unwrap_err();
        assert!(err.to_string().contains("aliases"), "{err}");
    }

    #[test]
    fn validate_rejects_overlong_alias_element() {
        let mut f = valid_finding();
        f.aliases = vec!["a".repeat(MAX_VULNERABILITY_ID_LEN + 1)];
        let err = f.validate().unwrap_err();
        assert!(err.to_string().contains("aliases[0]"), "{err}");
    }

    // ----- FindingStatement ------------------------------------------------

    /// **The one byte-compatibility assertion the field rests on.** A
    /// finding whose statement is the `Unstated` default serialises to
    /// exactly the bytes it did before the field persisted — no
    /// `statement` key at all.
    ///
    /// Two places serialise a `Finding`: the CAS findings blob and
    /// `ArtifactBecameVulnerable.new_findings`, the second an event
    /// payload under a 64 KB cap. A bare `#[serde(default)]` would
    /// re-serialise every record already written with a key it does not
    /// have, breaking the chain for every such event; the
    /// `skip_serializing_if` is what keeps that whole population's
    /// canonical bytes unmoved.
    #[test]
    fn an_unstated_statement_adds_no_key_to_the_wire_form() {
        let unstated = valid_finding();
        assert_eq!(unstated.statement, FindingStatement::Unstated);
        let json = serde_json::to_string(&unstated).unwrap();
        assert!(
            !json.contains("statement"),
            "an unstated statement must not appear in the wire form at all, \
             or every record already written changes shape: {json}"
        );
    }

    /// **A stored payload written before this field persisted
    /// re-serialises to itself, byte for byte.** This is the event-chain
    /// property, asserted on a literal rather than on a round trip of a
    /// value this code built: the string below is a `Finding` as the CAS
    /// findings blob and `ArtifactBecameVulnerable.new_findings` held it
    /// when `statement` was `#[serde(skip)]` — no `statement` key,
    /// because `skip` never wrote one.
    ///
    /// A bare `#[serde(default)]` would pass the deserialise half and
    /// fail this one, re-emitting the payload with a key it does not
    /// have and breaking the chain hash of every event that carries
    /// findings. `#[serde(default, skip_serializing_if = …)]` is what
    /// makes the two halves agree.
    #[test]
    fn a_pre_existing_stored_payload_reserialises_to_itself() {
        const STORED: &str = r#"{"purl":"pkg:npm/lodash@4.17.20","vulnerability_id":"CVE-2021-23337","severity":"High","cvss_score":7.2,"title":"Command Injection in lodash","fixed_versions":["4.17.21"],"source_scanner":"trivy","references":["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],"aliases":["GHSA-35jh-r3h4-6jhm"],"informational_class":null,"severity_basis":"assessed","component_relation":"not_established"}"#;

        let parsed: Finding = serde_json::from_str(STORED).expect("a stored payload still parses");
        assert_eq!(parsed.statement, FindingStatement::Unstated);
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            STORED,
            "a payload written before the field persisted must re-serialise \
             to the identical bytes, or the event chain breaks for every \
             `ArtifactBecameVulnerable` already stored"
        );
        assert_eq!(
            parsed,
            valid_finding(),
            "and the literal above really is this module's canonical \
             finding, so the assertion is about the shape and not about a \
             string nobody checked"
        );
    }

    /// And the other direction of the same compatibility: a payload with
    /// no `statement` key — every blob and event written before this
    /// field persisted — deserialises to the condemning default rather
    /// than failing.
    #[test]
    fn a_payload_without_the_key_deserialises_as_unstated() {
        let unstated = valid_finding();
        let json = serde_json::to_string(&unstated).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.statement, FindingStatement::Unstated);
        assert_eq!(back, unstated);
    }

    /// **What the field is for.** A statement a producer *did* make
    /// survives the round trip, so a verdict re-taken over stored
    /// findings reads the same fact the fresh scan read. Before this, the
    /// field was transient and every stored finding came back `Unstated`
    /// — which condemns, so the tighten pass terminally rejected the same
    /// constituent a promoted fresh scan had just let through.
    #[test]
    fn a_stated_statement_survives_the_round_trip() {
        for stated in [FindingStatement::Bytes, FindingStatement::Filesystem] {
            let mut f = valid_finding();
            f.statement = stated;
            let json = serde_json::to_string(&f).unwrap();
            assert!(
                json.contains(&format!("\"statement\":\"{stated}\"")),
                "{stated}: the producer's half must reach the wire: {json}"
            );
            let back: Finding = serde_json::from_str(&json).unwrap();
            assert_eq!(back.statement, stated);
            assert_eq!(back, f, "{stated}: and nothing else moves");
        }
    }

    /// The log label and the serialised token are the same string, by
    /// assertion rather than by two lists that happen to agree: the
    /// `rename_all = "snake_case"` derive and [`FindingStatement::as_str`]
    /// are independent definitions of one vocabulary, and an operator
    /// grepping a log line for what a stored finding says needs them to
    /// match.
    #[test]
    fn the_log_label_and_the_wire_form_are_the_same_string() {
        for statement in every_statement() {
            let json = serde_json::to_string(&statement).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", statement.as_str()),
                "{statement}: label and wire form must not be two vocabularies"
            );
        }
    }

    /// There is no variant for "a constituent's filesystem", and that is
    /// the design rather than an omission: it is the composition of the
    /// producer's half with the row's [`ArtifactKind`], and a composition
    /// is a conclusion (ADR 0040). So a *stored* finding cannot carry one
    /// — which this asserts the only way a wire form can be asserted, by
    /// refusing the token.
    #[test]
    fn the_wire_form_admits_no_composed_statement() {
        let err = serde_json::from_str::<FindingStatement>("\"constituent_filesystem\"")
            .expect_err("a composed statement is not a producer's fact");
        assert!(
            err.to_string().contains("unknown variant"),
            "the wire form must reject it outright: {err}"
        );
    }

    #[test]
    fn the_unstated_side_is_the_default() {
        assert_eq!(FindingStatement::default(), FindingStatement::Unstated);
    }

    #[test]
    fn every_statement_has_a_distinct_lowercase_label() {
        let all = every_statement();
        let mut seen: Vec<&str> = all.iter().map(FindingStatement::as_str).collect();
        let total = seen.len();
        for s in &seen {
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{s} must be lowercase snake_case"
            );
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "labels must be unique: {seen:?}");
        assert_eq!(FindingStatement::Bytes.to_string(), "bytes");
    }

    // ----- validate() — at-cap (passes) ------------------------------------

    #[test]
    fn validate_accepts_purl_at_exactly_512_bytes() {
        let mut f = valid_finding();
        f.purl = "a".repeat(MAX_PURL_LEN);
        assert_eq!(f.purl.len(), 512);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_vulnerability_id_at_exactly_128_bytes() {
        let mut f = valid_finding();
        f.vulnerability_id = "a".repeat(MAX_VULNERABILITY_ID_LEN);
        assert_eq!(f.vulnerability_id.len(), 128);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_title_at_exactly_1024_bytes() {
        let mut f = valid_finding();
        f.title = "a".repeat(MAX_TITLE_LEN);
        assert_eq!(f.title.len(), 1024);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_fixed_versions_at_exactly_32_entries() {
        let mut f = valid_finding();
        f.fixed_versions = (0..MAX_FIXED_VERSIONS).map(|i| i.to_string()).collect();
        assert_eq!(f.fixed_versions.len(), 32);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_references_at_exactly_32_entries() {
        let mut f = valid_finding();
        f.references = (0..MAX_REFERENCES).map(|i| i.to_string()).collect();
        assert_eq!(f.references.len(), 32);
        f.validate().unwrap();
    }

    // ----- validate() — at-cap-plus-one (rejects) --------------------------

    #[test]
    fn validate_rejects_purl_at_513_bytes() {
        let mut f = valid_finding();
        f.purl = "a".repeat(MAX_PURL_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("purl"), "{msg}");
        assert!(msg.contains("513"), "{msg}");
    }

    #[test]
    fn validate_rejects_vulnerability_id_at_129_bytes() {
        let mut f = valid_finding();
        f.vulnerability_id = "a".repeat(MAX_VULNERABILITY_ID_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("vulnerability_id"), "{msg}");
        assert!(msg.contains("129"), "{msg}");
    }

    #[test]
    fn validate_rejects_title_at_1025_bytes() {
        let mut f = valid_finding();
        f.title = "a".repeat(MAX_TITLE_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("title"), "{msg}");
        assert!(msg.contains("1025"), "{msg}");
    }

    // ----- cap_finding_title ------------------------------------------------

    /// A title the publisher wrote inside the cap — including one
    /// exactly at it — is returned untouched. Without this the cap
    /// could mark every title and a reader could no longer tell a
    /// truncated description from a short one.
    #[test]
    fn cap_finding_title_leaves_a_title_within_the_cap_alone() {
        for n in [0, 1, MAX_TITLE_LEN - 1, MAX_TITLE_LEN] {
            let title = "a".repeat(n);
            assert_eq!(cap_finding_title(title.clone()), title, "{n} bytes");
        }
    }

    /// Over the cap the value is truncated, marked, and — the point of
    /// the whole exercise — passes `validate`, so the finding carrying
    /// it survives instead of being refused or dropped.
    #[test]
    fn cap_finding_title_bounds_an_over_cap_title_and_marks_it() {
        let capped = cap_finding_title("x".repeat(MAX_TITLE_LEN * 5));
        assert!(capped.len() <= MAX_TITLE_LEN, "{} bytes", capped.len());
        assert!(capped.ends_with('…'), "a truncated title is marked");
        let mut f = valid_finding();
        f.title = capped;
        f.validate().expect("the bounded title is representable");
    }

    /// Truncation lands on a character boundary: a multi-byte character
    /// straddling the cap must not produce invalid UTF-8 — a naive byte
    /// slice panics here — and the kept prefix must still be a prefix of
    /// what the publisher wrote.
    #[test]
    fn cap_finding_title_truncates_on_a_character_boundary() {
        // 'é' is two bytes, so for one of these lengths the cut falls
        // mid-character whichever way the arithmetic rounds.
        for n in [600, 601] {
            let title = "é".repeat(n);
            let capped = cap_finding_title(title.clone());
            assert!(capped.len() <= MAX_TITLE_LEN, "{} bytes", capped.len());
            assert!(capped.ends_with('…'));
            assert!(
                title.starts_with(capped.trim_end_matches('…')),
                "the kept prefix is what the publisher wrote"
            );
        }
    }

    #[test]
    fn validate_rejects_fixed_versions_at_33_entries() {
        let mut f = valid_finding();
        f.fixed_versions = (0..=MAX_FIXED_VERSIONS).map(|i| i.to_string()).collect();
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("fixed_versions"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    #[test]
    fn validate_rejects_references_at_33_entries() {
        let mut f = valid_finding();
        f.references = (0..=MAX_REFERENCES).map(|i| i.to_string()).collect();
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("references"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    // ----- validate() — happy path -----------------------------------------

    #[test]
    fn validate_accepts_a_non_trivial_valid_finding() {
        let f = valid_finding();
        f.validate().unwrap();
    }

    // ----- Re-export reachability (mirrors the checksum precedent) ---------

    #[test]
    fn finding_is_re_exported_from_types_module() {
        // The mod.rs convention re-exports public types so callers can
        // write `crate::types::Finding` rather than
        // `crate::types::finding::Finding`. This test is a compile-time
        // assertion via a type alias — if the re-export disappears, the
        // alias fails to resolve and compilation breaks.
        // `unused_qualifications` would normally flag this because
        // `Finding` is in scope via `super::*`; here the explicit path
        // is the test, so allow it.
        #[allow(unused_qualifications)]
        type _Reexported = crate::types::Finding;
    }

    // ----- severity_summary_from_findings ----------------------------------

    #[test]
    fn severity_summary_from_findings_buckets_each_tier() {
        // Mixed input across all four `SeverityThreshold` tiers — the
        // helper must bucket each finding into the correct counter and
        // leave `negligible` at zero (the enum has no Negligible variant
        // today; the field stays for forward compatibility with the
        // event schema).
        let findings = vec![
            Finding {
                purl: "pkg:npm/a@1".into(),
                vulnerability_id: "CVE-A".into(),
                severity: SeverityThreshold::Critical,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/b@1".into(),
                vulnerability_id: "CVE-B".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/c@1".into(),
                vulnerability_id: "CVE-C".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/d@1".into(),
                vulnerability_id: "CVE-D".into(),
                severity: SeverityThreshold::Medium,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/e@1".into(),
                vulnerability_id: "CVE-E".into(),
                severity: SeverityThreshold::Low,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
        ];
        let s = severity_summary_from_findings(&findings);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 2,
                medium: 1,
                low: 1,
                negligible: 0,
            }
        );
    }

    #[test]
    fn severity_summary_from_findings_returns_zeros_for_empty_input() {
        let s = severity_summary_from_findings(&[]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            }
        );
    }

    #[test]
    fn severity_summary_routes_informational_to_negligible_regardless_of_severity() {
        // An informational finding is counted in `negligible` (the
        // non-enforcing lane) even though its cosmetic `severity` is a real
        // tier — the routing is keyed on `is_informational()` (derived from
        // the class), not on `severity`. A Critical-tier informational
        // finding must NOT land in the critical bucket, or it would block
        // under the default threshold. Informational advisories carry no
        // CVSS score by design, so the fixture has `cvss_score = None`.
        let mut critical_but_informational = valid_finding();
        critical_but_informational.severity = SeverityThreshold::Critical;
        critical_but_informational.cvss_score = None;
        critical_but_informational.informational_class = Some("unmaintained".to_string());

        let mut real_critical = valid_finding();
        real_critical.severity = SeverityThreshold::Critical;
        real_critical.informational_class = None;

        let s = severity_summary_from_findings(&[critical_but_informational, real_critical]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 1,
            }
        );
    }

    #[test]
    fn scored_finding_with_informational_class_stays_enforced() {
        // A finding carrying BOTH a real `cvss_score` AND a recognised
        // informational class must NOT route onto the negligible lane —
        // informational advisories carry no CVSS by design, so a scored
        // finding stays on the enforced lane (ADR 0040 §4). Demoting it
        // would let a scored Critical escape the threshold gate.
        let scored_but_classed = Finding {
            cvss_score: Some(9.0),
            informational_class: Some("unmaintained".to_string()),
            severity: SeverityThreshold::Critical,
            ..valid_finding()
        };
        assert!(
            !scored_but_classed.is_informational(),
            "a scored finding is never informational, regardless of class"
        );

        let s = severity_summary_from_findings(&[scored_but_classed]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            },
            "a scored Critical with a class counts as critical, not negligible"
        );
    }

    #[test]
    fn finding_deserialises_with_default_informational_class_none_when_field_absent() {
        // `informational_class` is `#[serde(default)]`: a legacy event /
        // cached blob written before the field landed must round-trip as
        // `None` (a scored vulnerability), preserving fail-closed behaviour
        // for old findings.
        let legacy_json = r#"{
            "purl": "pkg:cargo/proc-macro-error2@2.0.1",
            "vulnerability_id": "RUSTSEC-2026-0173",
            "severity": "Critical",
            "cvss_score": null,
            "title": "unmaintained",
            "fixed_versions": [],
            "source_scanner": "osv",
            "references": [],
            "aliases": []
        }"#;
        let back: Finding = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(back.informational_class, None);
        assert!(!back.is_informational());
    }

    /// `advisory_published_at` is `#[serde(default, skip_serializing_if)]`
    /// for the reason `statement` is: a finding with no publication date
    /// must serialise to exactly the bytes it did before the field
    /// existed, or every `ArtifactBecameVulnerable` and CAS findings
    /// blob already written re-serialises with a key it never carried.
    #[test]
    fn finding_without_a_publication_date_serialises_to_its_legacy_bytes() {
        let legacy_json = r#"{
            "purl": "pkg:cargo/proc-macro-error2@2.0.1",
            "vulnerability_id": "RUSTSEC-2026-0173",
            "severity": "Critical",
            "cvss_score": null,
            "title": "unmaintained",
            "fixed_versions": [],
            "source_scanner": "osv",
            "references": [],
            "aliases": []
        }"#;
        let back: Finding = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(back.advisory_published_at, None);
        let re_encoded = serde_json::to_value(&back).unwrap();
        assert!(
            re_encoded.get("advisory_published_at").is_none(),
            "an absent publication date must add no key: {re_encoded}"
        );
    }

    /// A present date round-trips, and costs the key — the price of the
    /// field being readable at all.
    #[test]
    fn finding_publication_date_round_trips() {
        let mut f = valid_finding();
        f.advisory_published_at = Some(
            DateTime::parse_from_rfc3339("2021-08-25T20:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let json = serde_json::to_value(&f).unwrap();
        assert!(json.get("advisory_published_at").is_some());
        let back: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(back.advisory_published_at, f.advisory_published_at);
    }

    // -- parse_advisory_published_at ----------------------------------------

    /// The RFC 3339 spellings the three producers actually emit: OSV's
    /// `published` (`Z`), and offset / fractional-second forms a feed is
    /// free to use.
    #[test]
    fn parse_advisory_published_at_accepts_the_rfc3339_forms() {
        let expected = DateTime::parse_from_rfc3339("2021-08-25T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            parse_advisory_published_at("2021-08-25T20:00:00Z"),
            Some(expected)
        );
        assert_eq!(
            parse_advisory_published_at("2021-08-25T22:00:00+02:00"),
            Some(expected)
        );
        assert_eq!(
            parse_advisory_published_at("2021-08-25T20:00:00.000Z"),
            Some(expected)
        );
        // Leading / trailing whitespace from a hand-edited feed.
        assert_eq!(
            parse_advisory_published_at("  2021-08-25T20:00:00Z  "),
            Some(expected)
        );
    }

    /// An unparseable value yields `None` — the field is an optional
    /// refinement, and the anchor falls back to our own later
    /// observation rather than the scan run failing.
    #[test]
    fn parse_advisory_published_at_rejects_what_it_cannot_read() {
        for raw in [
            "",
            "   ",
            "2021-08-25",
            "25/08/2021",
            "not a date",
            "2021-13-45T99:99:99Z",
        ] {
            assert_eq!(parse_advisory_published_at(raw), None, "raw: {raw:?}");
        }
    }

    /// A future-dated value is returned verbatim. The retention
    /// evaluator reads a future anchor as "not elapsed" — the
    /// non-deleting answer — whereas clamping to `now` would assert the
    /// vulnerability became known this instant.
    #[test]
    fn parse_advisory_published_at_does_not_clamp_a_future_date() {
        let parsed = parse_advisory_published_at("2999-01-01T00:00:00Z").expect("parsed");
        assert!(parsed > Utc::now());
    }

    #[test]
    fn is_informational_class_recognises_the_three_classes_and_rejects_others() {
        // The canonical recognizer: case-insensitive `unmaintained` /
        // `unsound` / `notice`; everything else (including a made-up class)
        // is not informational.
        assert!(is_informational_class("unmaintained"));
        assert!(is_informational_class("unsound"));
        assert!(is_informational_class("notice"));
        assert!(is_informational_class("UNMAINTAINED"));
        assert!(is_informational_class("  Unsound  "));
        assert!(!is_informational_class("some-future-class"));
        assert!(!is_informational_class(""));
        assert!(!is_informational_class("critical"));
    }

    #[test]
    fn is_informational_derives_the_boolean_from_the_persisted_class() {
        // A recognised class → informational; `None` or a made-up class → not.
        // The made-up string is stored verbatim (the fact) but does not flip
        // the derived boolean — the interpretation lives in the recognizer,
        // not in the stored value. Informational advisories carry no CVSS
        // score by design, so the fixture clears `cvss_score`.
        let mut f = valid_finding();
        f.cvss_score = None;
        f.informational_class = Some("unsound".to_string());
        assert!(f.is_informational());

        f.informational_class = Some("some-future-class".to_string());
        assert_eq!(
            f.informational_class.as_deref(),
            Some("some-future-class"),
            "the raw class is stored verbatim"
        );
        assert!(!f.is_informational());

        f.informational_class = None;
        assert!(!f.is_informational());
    }

    #[test]
    fn severity_label_maps_each_tier_to_its_lowercase_wire_string() {
        // Mirrors the metric-catalog label values exactly so the
        // catalog stays the single source of truth (the registry's
        // `severity` label is one of `critical|high|medium|low`).
        assert_eq!(severity_label(SeverityThreshold::Critical), "critical");
        assert_eq!(severity_label(SeverityThreshold::High), "high");
        assert_eq!(severity_label(SeverityThreshold::Medium), "medium");
        assert_eq!(severity_label(SeverityThreshold::Low), "low");
    }

    #[test]
    fn highest_severity_picks_the_top_tier() {
        let findings = vec![
            Finding {
                purl: "pkg:npm/a@1".into(),
                vulnerability_id: "CVE-A".into(),
                severity: SeverityThreshold::Low,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/b@1".into(),
                vulnerability_id: "CVE-B".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
            Finding {
                purl: "pkg:npm/c@1".into(),
                vulnerability_id: "CVE-C".into(),
                severity: SeverityThreshold::Medium,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: SeverityBasis::Assessed,
                component_relation: ComponentRelation::NotEstablished,
                statement: FindingStatement::Unstated,
                advisory_published_at: None,
            },
        ];
        assert_eq!(highest_severity(&findings), Some(SeverityThreshold::High));
    }

    #[test]
    fn highest_severity_returns_none_for_empty_input() {
        assert_eq!(highest_severity(&[]), None);
    }

    // ----- Deserialise without re-validation -------------------------------

    #[test]
    fn finding_deserialises_without_revalidation() {
        // Mirrors `published_checksum_deserializes_without_re_validating`.
        // A finding with a 600-byte purl exceeds MAX_PURL_LEN but the
        // event-store contract says serde must accept any shape that
        // was once written; only validate() rejects.
        let big_purl = "x".repeat(600);
        let raw = serde_json::json!({
            "purl": big_purl,
            "vulnerability_id": "CVE-2024-99999",
            "severity": "High",
            "cvss_score": null,
            "title": "title",
            "fixed_versions": [],
            "source_scanner": "trivy",
            "references": [],
        })
        .to_string();
        let parsed: Finding = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.purl.len(), 600);
        // ... and validate() rejects the same value.
        let err = parsed.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----- SeverityBasis ---------------------------------------------------

    /// Backward compatibility, and the fail-safe half of the merge rule. A
    /// finding persisted before `severity_basis` existed carries no such
    /// field; it MUST deserialise as `Assessed`. A legacy record cannot be
    /// proven to be a fail-closed default, so defaulting it to
    /// `Unassessed` would let a scored `Low` talk down a legacy *genuine*
    /// `Critical` — a fail-open regression against ADR 0007. The stranded
    /// legacy fail-closed records are un-stuck by re-emission with a
    /// correct basis, not by a permissive default.
    #[test]
    fn legacy_finding_without_severity_basis_deserialises_as_assessed() {
        let raw = serde_json::json!({
            "purl": "pkg:cargo/rsa@0.9.10",
            "vulnerability_id": "RUSTSEC-2023-0071",
            "severity": "Critical",
            "cvss_score": null,
            "title": "Marvin Attack",
            "fixed_versions": [],
            "source_scanner": "trivy",
            "references": [],
        })
        .to_string();
        let parsed: Finding = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.severity_basis, SeverityBasis::Assessed);
        assert!(
            parsed.is_informed(),
            "a legacy record is informed, so it is never demoted by the merge",
        );
    }

    #[test]
    fn severity_basis_round_trips_through_serde() {
        for basis in [SeverityBasis::Assessed, SeverityBasis::Unassessed] {
            let mut f = valid_finding();
            f.severity_basis = basis;
            let raw = serde_json::to_string(&f).unwrap();
            let parsed: Finding = serde_json::from_str(&raw).unwrap();
            assert_eq!(parsed.severity_basis, basis);
        }
    }

    #[test]
    fn severity_basis_wire_spelling_is_snake_case() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Unassessed;
        let raw = serde_json::to_string(&f).unwrap();
        assert!(raw.contains("\"severity_basis\":\"unassessed\""), "{raw}");
    }

    #[test]
    fn severity_basis_default_is_assessed() {
        assert_eq!(SeverityBasis::default(), SeverityBasis::Assessed);
    }

    #[test]
    fn severity_basis_debug_and_clone_are_available() {
        let basis = SeverityBasis::Unassessed;
        #[allow(clippy::clone_on_copy)]
        let cloned = basis.clone();
        assert_eq!(cloned, basis);
        assert!(format!("{basis:?}").contains("Unassessed"));
    }

    // ----- is_informed -----------------------------------------------------

    /// The only uninformed shape: `Unassessed`, no CVSS, no recognised
    /// informational class. This is what all three SUP-4 fail-closed sites
    /// emit when a backend cannot read a severity at all.
    #[test]
    fn unassessed_without_score_or_class_is_not_informed() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Unassessed;
        f.cvss_score = None;
        f.informational_class = None;
        assert!(!f.is_informed());
    }

    #[test]
    fn assessed_without_score_or_class_is_informed() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Assessed;
        f.cvss_score = None;
        f.informational_class = None;
        assert!(f.is_informed());
    }

    /// Defensive: a real CVSS is a severity reading whatever the basis
    /// marker says, so a mis-marked `Unassessed` scored finding is still
    /// informed and cannot be demoted by the merge.
    #[test]
    fn unassessed_with_a_cvss_score_is_still_informed() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Unassessed;
        f.cvss_score = Some(7.5);
        f.informational_class = None;
        assert!(f.is_informed());
    }

    /// An informational classification is itself a reading (ADR 0040), so
    /// it counts as informed even when the basis marker says otherwise.
    #[test]
    fn unassessed_with_a_recognised_informational_class_is_informed() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Unassessed;
        f.cvss_score = None;
        f.informational_class = Some("unmaintained".to_string());
        assert!(f.is_informational(), "fixture sanity");
        assert!(f.is_informed());
    }

    /// An *unrecognised* class string is not a classification, so it does
    /// not rescue an `Unassessed` finding from the uninformed lane — the
    /// same recogniser gate `is_informational()` applies.
    #[test]
    fn unassessed_with_an_unrecognised_class_is_not_informed() {
        let mut f = valid_finding();
        f.severity_basis = SeverityBasis::Unassessed;
        f.cvss_score = None;
        f.informational_class = Some("mystery".to_string());
        assert!(!f.is_informed());
    }

    // ----- ComponentRelation -----------------------------------------------

    /// Backward compatibility, and the half of the rule that protects the
    /// stored corpus. A finding persisted before `component_relation` existed
    /// carries no such field; it MUST deserialise as `NotEstablished` and it
    /// MUST still condemn. Defaulting the other way — or dropping
    /// `#[serde(default)]` so the field became required — would strip release
    /// authority from, or fail to parse, every finding already in the event
    /// store and the CAS findings blob.
    #[test]
    fn legacy_finding_without_component_relation_deserialises_as_not_established() {
        let raw = serde_json::json!({
            "purl": "pkg:cargo/hyper-util@0.1.21",
            "vulnerability_id": "RUSTSEC-2026-0004",
            "severity": "Critical",
            "cvss_score": null,
            "title": "advisory",
            "fixed_versions": [],
            "source_scanner": "osv",
            "references": [],
        })
        .to_string();
        let parsed: Finding = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.component_relation, ComponentRelation::NotEstablished);
        assert_eq!(
            parsed.statement,
            FindingStatement::Unstated,
            "and the statement key is absent from the same payload",
        );
        assert!(
            parsed.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed),
            "a record written before the fields existed keeps today's authority",
        );
    }

    #[test]
    fn component_relation_default_is_not_established() {
        assert_eq!(
            ComponentRelation::default(),
            ComponentRelation::NotEstablished
        );
    }

    #[test]
    fn component_relation_round_trips_through_serde() {
        for relation in [
            ComponentRelation::Subject,
            ComponentRelation::Contained,
            ComponentRelation::NotContained,
            ComponentRelation::NotEstablished,
        ] {
            let mut f = valid_finding();
            f.component_relation = relation;
            let raw = serde_json::to_string(&f).unwrap();
            let parsed: Finding = serde_json::from_str(&raw).unwrap();
            assert_eq!(parsed.component_relation, relation);
        }
    }

    /// The wire spelling is part of the compatibility surface: `Finding` is
    /// carried in event payloads and in the CAS findings blob, so a renamed
    /// variant string makes already-written records unreadable.
    #[test]
    fn component_relation_wire_spelling_is_snake_case() {
        for (relation, wire) in [
            (ComponentRelation::Subject, "subject"),
            (ComponentRelation::Contained, "contained"),
            (ComponentRelation::NotContained, "not_contained"),
            (ComponentRelation::NotEstablished, "not_established"),
        ] {
            let mut f = valid_finding();
            f.component_relation = relation;
            let raw = serde_json::to_string(&f).unwrap();
            assert!(
                raw.contains(&format!("\"component_relation\":\"{wire}\"")),
                "{raw}"
            );
        }
    }

    /// The metric label and the persisted wire spelling must be the same
    /// word. They are produced by two different mechanisms (a hand-written
    /// match and serde's rename rule), so nothing but this assertion stops
    /// a counter series from naming a relation differently than the record
    /// it counted — which would make a dashboard and a stored finding
    /// disagree about the same scan.
    #[test]
    fn component_relation_label_matches_the_serde_wire_spelling() {
        for relation in [
            ComponentRelation::Subject,
            ComponentRelation::Contained,
            ComponentRelation::NotContained,
            ComponentRelation::NotEstablished,
        ] {
            let serialised = serde_json::to_string(&relation).unwrap();
            assert_eq!(
                serialised,
                format!("\"{}\"", component_relation_label(relation)),
                "label and wire spelling diverged for {relation:?}"
            );
        }
    }

    /// Every arm of the label match is reached, and no two relations share
    /// a word — a label collision would merge two counter series and hide
    /// exactly the `not_established` rate the counter exists to show.
    #[test]
    fn component_relation_labels_are_distinct_per_variant() {
        let labels = [
            component_relation_label(ComponentRelation::Subject),
            component_relation_label(ComponentRelation::Contained),
            component_relation_label(ComponentRelation::NotContained),
            component_relation_label(ComponentRelation::NotEstablished),
        ];
        assert_eq!(
            labels,
            ["subject", "contained", "not_contained", "not_established"]
        );
        let distinct: std::collections::HashSet<&str> = labels.into_iter().collect();
        assert_eq!(distinct.len(), 4, "label values must be distinct");
    }

    #[test]
    fn component_relation_debug_and_clone_are_available() {
        let relation = ComponentRelation::NotContained;
        #[allow(clippy::clone_on_copy)]
        let cloned = relation.clone();
        assert_eq!(cloned, relation);
        assert!(format!("{relation:?}").contains("NotContained"));
    }

    // ----- may_condemn_artifact --------------------------------------------

    /// A kind that is never a constituent, for the relation-axis tests —
    /// they are about the component half and must not be answered by the
    /// role half.
    const NON_CONSTITUENT: ArtifactKind = ArtifactKind::NpmTarball;

    /// The case that must not regress. A finding about the artifact's own
    /// subject component keeps full release authority; an over-broad
    /// predicate here disarms the scanner silently.
    #[test]
    fn a_subject_finding_may_condemn() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::Subject;
        assert!(f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed));
    }

    /// A format whose payload carries its closure (an OCI image and its
    /// layers): a non-subject component is still in the artifact, so it
    /// condemns exactly as before.
    #[test]
    fn a_contained_component_finding_may_condemn() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::Contained;
        assert!(f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed));
    }

    /// The one relation that withholds authority: the artifact resolved the
    /// component's coordinates out of a manifest it ships but ships none of
    /// that component's code.
    #[test]
    fn a_not_contained_component_finding_may_not_condemn() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::NotContained;
        assert!(!f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed));
    }

    /// Absence of evidence is not evidence of non-containment: an
    /// unestablished relation keeps the authority the finding has today.
    #[test]
    fn a_not_established_relation_may_condemn() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::NotEstablished;
        assert!(f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed));
    }

    // -- the statement axis (ADR 0064 D2) ----------------------------------

    /// **The pair the loosening is.** Over the same artifact — an OCI
    /// layer — under the same promoted policy: a claim about the
    /// filesystem this constituent composes in isolation stops condemning
    /// it, and a claim about its bytes does not.
    ///
    /// Asserted together because either half alone is satisfied by a rule
    /// that is wrong. "Nothing moves" passes the second assertion; "every
    /// filesystem claim moves" passes the first. Only the pair says the
    /// line is where ADR 0064 D2 draws it — and the second half is the
    /// one that matters for a backend hort has not shipped yet: a secrets
    /// or malware finding must not be disarmed by a decision taken when
    /// no such backend existed.
    #[test]
    fn under_promotion_a_constituents_filesystem_claim_stops_condemning_and_its_bytes_do_not() {
        let mut filesystem = valid_finding();
        filesystem.statement = FindingStatement::Filesystem;
        let mut bytes = valid_finding();
        bytes.statement = FindingStatement::Bytes;

        assert!(
            !filesystem.may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Promoted),
            "a constituent's isolated package set is evidence; the composition \
             that binds it carries the verdict"
        );
        assert!(
            bytes.may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Promoted),
            "a leaked key or a malware signature is in those bytes however \
             they are composed, so it keeps gating its own artifact"
        );
    }

    /// And the whole matrix — every statement × every kind × both
    /// postures — so "an unpromoted repository is byte-for-byte
    /// unchanged" and "a non-constituent format is untouched" are both
    /// properties of this one predicate rather than of each caller:
    /// exactly one cell of the fifty-four differs from what it was before
    /// ADR 0064 D2.
    ///
    /// The expectation is spelled out from the two facts rather than read
    /// back off the predicate, so a change to the rule shows up here as a
    /// failure instead of moving both sides at once.
    #[test]
    fn exactly_one_statement_kind_and_posture_triple_withholds_authority() {
        for statement in every_statement() {
            for kind in every_kind() {
                for mode in [
                    CompositeVerdictMode::Observed,
                    CompositeVerdictMode::Promoted,
                ] {
                    let mut f = valid_finding();
                    f.statement = statement;
                    let moved = statement == FindingStatement::Filesystem
                        && kind == ArtifactKind::OciBlob
                        && mode == CompositeVerdictMode::Promoted;
                    assert_eq!(
                        f.may_condemn_artifact(kind, mode),
                        !moved,
                        "{statement} on a {kind} under {mode} must {} condemn",
                        if moved { "not" } else { "still" }
                    );
                }
            }
        }
    }

    /// **Both inputs are required, and together.** The kind alone would
    /// move the obligation before an operator granted the composite
    /// verdict any authority; the posture alone would move it for every
    /// format ADR 0064 leaves undecided. Stated as the two one-input
    /// slices of the cell above, because that is what a rule reading only
    /// one of them would pass.
    #[test]
    fn neither_the_kind_nor_the_posture_alone_moves_the_obligation() {
        let mut f = valid_finding();
        f.statement = FindingStatement::Filesystem;

        assert!(
            f.may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Observed),
            "a constituent that stopped gating before promotion would be a \
             constituent nothing gates — the obligation dropped, not moved"
        );
        assert!(
            f.may_condemn_artifact(ArtifactKind::NpmTarball, CompositeVerdictMode::Promoted),
            "a global `compositeVerdictMode: promoted` must not disarm an npm \
             estate: the tarball's materialised tree is the artifact's own"
        );
        assert!(
            f.may_condemn_artifact(ArtifactKind::OciManifest, CompositeVerdictMode::Promoted),
            "the composition is not a constituent of itself, so the row that \
             carries the composite verdict keeps its own filesystem findings"
        );
    }

    /// The two axes compose by conjunction, not by precedence: either one
    /// alone is enough to withhold authority, and neither can hand it
    /// back.
    #[test]
    fn both_axes_have_to_admit_a_finding() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::NotContained;
        f.statement = FindingStatement::Bytes;
        assert!(
            !f.may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Promoted),
            "a component the artifact does not carry never condemns, whatever \
             the statement is about"
        );

        f.component_relation = ComponentRelation::Subject;
        f.statement = FindingStatement::Filesystem;
        assert!(
            !f.may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Promoted),
            "a subject relation does not win back the authority the moved \
             obligation took away"
        );
    }

    /// **The trapdoor this field's persistence closed, as a property of
    /// the type.** A finding read back out of the stored blob answers the
    /// predicate exactly as the one the producer handed over did — so the
    /// verdict a fresh scan reached and the verdict re-taken over the
    /// stored findings cannot differ on what the finding is about.
    ///
    /// While the statement was transient this assertion ran the other
    /// way: the rehydrated finding read `Unstated`, which condemns, and
    /// the tighten pass therefore rejected the constituent a promoted
    /// fresh scan had just let through — terminally, since
    /// `ScanPolicyRetroactive → Rejected` is revisited by no rescan. What
    /// keeps promotion from un-rejecting the *already*-rejected estate
    /// (ADR 0064 D6) is now the posture the automatic loosening pass pins,
    /// not an absent value — see
    /// [`crate::policy::decide_rejected_transition`].
    #[test]
    fn a_finding_read_back_out_of_the_blob_answers_exactly_as_the_original() {
        for statement in every_statement() {
            let mut stored = valid_finding();
            stored.statement = statement;
            stored.component_relation = ComponentRelation::Contained;

            let raw = serde_json::to_string(&stored).unwrap();
            let rehydrated: Finding = serde_json::from_str(&raw).unwrap();
            assert_eq!(rehydrated.statement, statement);

            for kind in every_kind() {
                for mode in [
                    CompositeVerdictMode::Observed,
                    CompositeVerdictMode::Promoted,
                ] {
                    assert_eq!(
                        rehydrated.may_condemn_artifact(kind, mode),
                        stored.may_condemn_artifact(kind, mode),
                        "{statement} on a {kind} under {mode}: a stored finding \
                         must not answer differently from the one that was stored"
                    );
                }
            }
        }
    }

    /// The predicate answers one question and only that question. Folding in
    /// severity, the informational class or the severity basis would make a
    /// `NotContained` Critical condemn again — or, worse, silently remove
    /// authority from a subject finding whose severity could not be read.
    #[test]
    fn may_condemn_artifact_reads_only_the_component_relation_and_the_statement() {
        for severity in [
            SeverityThreshold::Critical,
            SeverityThreshold::High,
            SeverityThreshold::Medium,
            SeverityThreshold::Low,
        ] {
            for (cvss, class, basis) in [
                (Some(9.8), None, SeverityBasis::Assessed),
                (
                    None,
                    Some("unmaintained".to_string()),
                    SeverityBasis::Assessed,
                ),
                (None, None, SeverityBasis::Unassessed),
            ] {
                let mut f = valid_finding();
                f.severity = severity;
                f.cvss_score = cvss;
                f.informational_class = class;
                f.severity_basis = basis;

                f.component_relation = ComponentRelation::NotContained;
                assert!(
                    !f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed),
                    "a non-contained component never condemns: {f:?}"
                );

                f.component_relation = ComponentRelation::Subject;
                assert!(
                    f.may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed),
                    "a subject finding always condemns: {f:?}"
                );
            }
        }
    }

    /// A finding the artifact does not contain is removed from the
    /// *condemning* set, not from the record: it still validates, still
    /// round-trips, and is still counted into the severity summary exactly
    /// as before. Dropping it from the record would trade one wrong answer
    /// for another.
    #[test]
    fn a_not_contained_finding_is_still_recorded_and_still_counted() {
        let mut f = valid_finding();
        f.component_relation = ComponentRelation::NotContained;
        f.severity = SeverityThreshold::Critical;
        f.validate().unwrap();

        let raw = serde_json::to_string(&f).unwrap();
        let parsed: Finding = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, f);

        assert_eq!(
            severity_summary_from_findings(&[f]),
            SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            },
            "the aggregate still counts it; only its release authority changes",
        );
    }

    /// `component_relation` is outside `validate()`'s remit — it is a typed
    /// enum, not a length-capped string, so there is nothing to cap and no
    /// relation that makes a finding invalid.
    #[test]
    fn validate_accepts_every_component_relation() {
        for relation in [
            ComponentRelation::Subject,
            ComponentRelation::Contained,
            ComponentRelation::NotContained,
            ComponentRelation::NotEstablished,
        ] {
            let mut f = valid_finding();
            f.component_relation = relation;
            f.validate().unwrap();
        }
    }

    // ----- more_condemning -------------------------------------------------

    /// Every relation, so a pairwise sweep is exhaustive by construction
    /// rather than by a reviewer counting arms. A new variant that is not
    /// added here leaves the sweeps below quietly narrower, which is why
    /// `every_relation_is_covered_by_the_pairwise_sweep` asserts the
    /// length.
    const ALL_RELATIONS: [ComponentRelation; 4] = [
        ComponentRelation::Subject,
        ComponentRelation::Contained,
        ComponentRelation::NotContained,
        ComponentRelation::NotEstablished,
    ];

    fn with_relation(relation: ComponentRelation) -> Finding {
        let mut f = valid_finding();
        f.component_relation = relation;
        f
    }

    /// The sweep's own reach. `ComponentRelation` has no iterator, so a
    /// fifth variant would silently leave every pairwise assertion below
    /// testing a subset of the enum.
    #[test]
    fn every_relation_is_covered_by_the_pairwise_sweep() {
        for relation in ALL_RELATIONS {
            assert!(
                ALL_RELATIONS.contains(&relation),
                "{relation:?} missing from the sweep",
            );
        }
        let mut distinct = ALL_RELATIONS.to_vec();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            4,
            "the sweep must list each relation exactly once",
        );
    }

    /// The property the merge rests on: whichever row wins a severity
    /// comparison, the relation that survives is never less condemning
    /// than either input. Asserted over all sixteen pairs through
    /// [`Finding::may_condemn_artifact`] itself, so the order and the
    /// predicate cannot drift apart.
    #[test]
    fn more_condemning_never_returns_a_relation_less_condemning_than_an_input() {
        for a in ALL_RELATIONS {
            for b in ALL_RELATIONS {
                let winner = a.more_condemning(b);
                if with_relation(a)
                    .may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed)
                    || with_relation(b)
                        .may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed)
                {
                    assert!(
                        with_relation(winner)
                            .may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed),
                        "{a:?} + {b:?} resolved to {winner:?}, which cannot condemn \
                         although an input could",
                    );
                }
                assert!(
                    winner == a || winner == b,
                    "{a:?} + {b:?} resolved to {winner:?}, which is neither input",
                );
            }
        }
    }

    /// Order independence, stated as the test the merge needs: two
    /// backends reporting one advisory must reconcile to the same relation
    /// whichever arrived first, because nothing upstream fixes their
    /// order.
    #[test]
    fn more_condemning_is_commutative() {
        for a in ALL_RELATIONS {
            for b in ALL_RELATIONS {
                assert_eq!(a.more_condemning(b), b.more_condemning(a), "{a:?} + {b:?}",);
            }
        }
    }

    /// Folding across a run of collisions — three backends for one
    /// advisory — cannot walk back down the order. The merge applies the
    /// resolution pairwise as each duplicate arrives, so without this a
    /// third row could undo the second's.
    #[test]
    fn more_condemning_is_idempotent_and_monotone_under_folding() {
        for a in ALL_RELATIONS {
            assert_eq!(a.more_condemning(a), a, "{a:?}");
            for b in ALL_RELATIONS {
                for c in ALL_RELATIONS {
                    let folded = a.more_condemning(b).more_condemning(c);
                    assert_eq!(
                        folded,
                        a.more_condemning(b.more_condemning(c)),
                        "{a:?} + {b:?} + {c:?} must not depend on the grouping",
                    );
                    for input in [a, b, c] {
                        assert_eq!(
                            folded.more_condemning(input),
                            folded,
                            "{folded:?} dropped below {input:?} while folding",
                        );
                    }
                }
            }
        }
    }

    /// The tie the merge can actually reach today: a purl the BOM does not
    /// list, which a payload-scanning backend found in the artifact and an
    /// SBOM-driven one could not join at all. `Contained` is the stronger
    /// claim and survives.
    #[test]
    fn a_payload_observation_outranks_a_failed_join() {
        assert_eq!(
            ComponentRelation::NotEstablished.more_condemning(ComponentRelation::Contained),
            ComponentRelation::Contained,
        );
        assert_eq!(
            ComponentRelation::Contained.more_condemning(ComponentRelation::NotEstablished),
            ComponentRelation::Contained,
        );
    }

    /// The step that decides authority: `NotContained` loses to every
    /// other relation, and only to it does any other relation lose
    /// nothing. This is the assertion that makes "more condemning" mean
    /// what its name says.
    #[test]
    fn not_contained_loses_to_every_other_relation() {
        for other in ALL_RELATIONS {
            if other == ComponentRelation::NotContained {
                continue;
            }
            assert_eq!(
                ComponentRelation::NotContained.more_condemning(other),
                other,
                "{other:?} must outrank NotContained",
            );
        }
    }

    /// Ties the order to the predicate: the bottom of the containment
    /// order is exactly the relation that cannot condemn. If a future
    /// variant is ranked at the bottom while still condemning (or ranked
    /// above it while not condemning), the merge would resolve a
    /// disagreement away from the condemning relation and this fails.
    #[test]
    fn the_bottom_of_the_order_is_exactly_the_relation_that_cannot_condemn() {
        for relation in ALL_RELATIONS {
            let is_bottom = ALL_RELATIONS
                .iter()
                .all(|other| relation.more_condemning(*other) == *other || *other == relation);
            assert_eq!(
                is_bottom,
                !with_relation(relation)
                    .may_condemn_artifact(NON_CONSTITUENT, CompositeVerdictMode::Observed),
                "{relation:?}: sitting at the bottom of the containment order and \
                 being refused release authority must be the same thing",
            );
        }
    }
}
