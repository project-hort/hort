//! Outbound port for the **shadow** composite-scan observation
//! projection — the durable evidence behind ADR 0064 D6's promotion
//! decision.
//!
//! # Why a projection and not an event
//!
//! The composed assessment of an OCI image manifest carries **no release
//! authority** (ADR 0064 D6): it is produced, compared against what the
//! manifest's own bytes concluded, and recorded for an operator to read.
//! An artifact's event stream is where release authority is derived from
//! (ADR 0007's scan authority, ADR 0062's closure), so a shadow verdict
//! written there is a verdict a future reader can mistake for one that
//! counts — and `EventStore::read_stream`'s consumers are exactly the
//! code that must never see it. A projection keeps the two apart by
//! construction.
//!
//! # One row per manifest, replaced on each assessment
//!
//! The question this table exists to answer is about the estate's
//! *current* state: "if the composite verdict carried authority, how many
//! artifacts would change outcome, and in which direction?" That is a
//! `GROUP BY` over one row per artifact. An append-only per-scan history
//! would answer the same question only after a window filter, and it
//! would grow without bound on a population the rescan cadence re-visits
//! every day — so the row is keyed on the artifact and replaced.
//!
//! It is bounded by the artifact population and goes away with its
//! artifact (`ON DELETE CASCADE`), the way every other per-artifact
//! projection in the schema does.
//!
//! # What the row does not carry
//!
//! Not the full composite findings. A findings blob is a CAS object, a
//! CAS object needs a `content_references` claim to survive garbage
//! collection, and a claim written by a path that must carry no authority
//! is the beginning of the entanglement this whole unit exists to avoid.
//! The distinct vulnerability ids plus the exact counts answer the
//! promotion question; the full report is reproducible by re-running the
//! scan.
//!
//! The id list is **capped** at [`MAX_OBSERVED_VULNERABILITY_IDS`] so a
//! pathological image cannot write an unbounded column. The cap applies
//! to the stored list only — [`CompositeScanObservation::distinct_vulnerability_count`]
//! and [`CompositeScanObservation::finding_count`] are exact.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};
use crate::events::SeveritySummary;
use crate::policy::scan::ScanOutcome;
use crate::types::{ContentHash, Finding};

use super::BoxFuture;

/// Ceiling on how many distinct vulnerability ids one observation stores.
///
/// A real image's composite report runs to a few hundred advisories; a
/// deliberately-constructed one has no natural bound at all, and this
/// column is written by a path an operator did not ask to run. 256 keeps
/// the auditable core of "what would change" for every realistic image
/// (≈4 KB of text at the per-id cap below) while making the column's
/// worst case a number rather than a function of the upstream's
/// imagination.
pub const MAX_OBSERVED_VULNERABILITY_IDS: usize = 256;

/// Per-id length ceiling. Mirrors the `Finding::vulnerability_id` cap
/// enforced by [`Finding::validate`] — every id stored here came off a
/// `Finding`, so an id longer than that one is an id no producer in the
/// system can have made.
pub const MAX_OBSERVED_VULNERABILITY_ID_LEN: usize = 128;

/// Length ceiling on [`CompositeScanObservation::reason`]. Refusal
/// reasons may quote a parse's or an upstream's own complaint, which is
/// declarant data; it is kept because it is the one field that makes a
/// refusal actionable, and bounded because it is not ours.
pub const MAX_OBSERVED_REASON_LEN: usize = 1024;

/// Length ceiling on [`CompositeScanObservation::scanner`]. A backend
/// name is an operator-configured identifier (`"trivy"`), not free text.
pub const MAX_OBSERVED_SCANNER_LEN: usize = 128;

// ---------------------------------------------------------------------------
// CompositeAssessment
// ---------------------------------------------------------------------------

/// What one shadow composite assessment arrived at.
///
/// The four arms are the four arms of the composite resolution plus the
/// run's disposition, which is the whole outcome space a shadow run has:
/// it either assessed the composition, or it did not, for one of three
/// reasons that ask three different things of an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeAssessment {
    /// The composition was assembled and at least one backend answered
    /// about it. This is the only arm whose
    /// [`CompositeScanObservation::composite_findings_decision`] is
    /// populated.
    Assessed,
    /// This manifest is not a composed image at all — an index, a cosign
    /// signature, an SBOM attachment, a Helm chart. The steady state for
    /// a large share of OCI rows, and nothing for a promotion to change.
    NothingToCompose,
    /// A composition was expected and could not be assembled, for a
    /// reason re-running reproduces exactly.
    DeterministicRefusal,
    /// The same absence of a composition for a condition that may clear —
    /// a store that did not answer, an upstream that was unreachable.
    /// Distinct from the arm above because collapsing the two would make
    /// a momentary hiccup read as a permanent absence of assessment.
    TransientRefusal,
}

impl CompositeAssessment {
    /// The stored column value. Stable: it is operator-queryable SQL, so
    /// renaming one is a schema change.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Assessed => "assessed",
            Self::NothingToCompose => "nothing_to_compose",
            Self::DeterministicRefusal => "deterministic_refusal",
            Self::TransientRefusal => "transient_refusal",
        }
    }

    /// Inverse of [`Self::as_str`], for the adapter's read path.
    pub fn parse(value: &str) -> DomainResult<Self> {
        match value {
            "assessed" => Ok(Self::Assessed),
            "nothing_to_compose" => Ok(Self::NothingToCompose),
            "deterministic_refusal" => Ok(Self::DeterministicRefusal),
            "transient_refusal" => Ok(Self::TransientRefusal),
            other => Err(DomainError::Validation(format!(
                "composite_scan_observations.assessment: unknown value {other:?}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// What the release gate concludes over one finding list.
///
/// The persisted shape of [`ScanOutcome`], which is a domain outcome enum
/// and deliberately not serialisable. Both sides of an observation row
/// carry this same type, because "would promoting the composite verdict
/// have changed this artifact's outcome?" is only a question if the two
/// answers live in one value space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// No enforcement-worthy findings under the active policy.
    Clean,
    /// Blocking violations under a policy declaring
    /// `enforcement = record`: recorded, no transition.
    FindingsRecorded,
    /// Blocking violations under `enforcement = reject`.
    Reject,
}

impl GateDecision {
    /// Project a [`ScanOutcome`] onto the stored decision. The violations
    /// themselves are not stored: the promotion question is about the
    /// *direction* of a change across an estate, and a per-rule violation
    /// list is the full report this row deliberately does not duplicate.
    #[must_use]
    pub const fn of(outcome: &ScanOutcome) -> Self {
        match outcome {
            ScanOutcome::Clean => Self::Clean,
            ScanOutcome::FindingsRecorded(_) => Self::FindingsRecorded,
            ScanOutcome::Reject(_) => Self::Reject,
        }
    }

    /// The stored column value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::FindingsRecorded => "findings_recorded",
            Self::Reject => "reject",
        }
    }

    /// Inverse of [`Self::as_str`], for the adapter's read path.
    pub fn parse(value: &str) -> DomainResult<Self> {
        match value {
            "clean" => Ok(Self::Clean),
            "findings_recorded" => Ok(Self::FindingsRecorded),
            "reject" => Ok(Self::Reject),
            other => Err(DomainError::Validation(format!(
                "composite_scan_observations decision: unknown value {other:?}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// AcquisitionCost
// ---------------------------------------------------------------------------

/// What assembling the composition cost, in constituents and bytes.
///
/// Stored beside the verdict it bought because the fetches are **egress
/// an operator did not ask for**: the composite path acquires a proxy
/// image's absent layers in order to assess it, and an operator deciding
/// whether to promote the verdict is also deciding whether to keep paying
/// for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcquisitionCost {
    /// Constituents already in CAS when the survey ran.
    pub already_present: u32,
    /// Constituents fetched from the repository's upstream by this run.
    pub fetched: u32,
    /// Bytes written by those fetches.
    pub fetched_bytes: u64,
}

// ---------------------------------------------------------------------------
// CompositeScanObservation
// ---------------------------------------------------------------------------

/// One manifest artifact's current shadow composite assessment.
///
/// # The two decision columns are gate decisions, not dispositions
///
/// [`composite_findings_decision`](Self::composite_findings_decision)
/// and [`primary_findings_decision`](Self::primary_findings_decision)
/// are the **same gate's decision over two finding sets**, which is
/// exactly what makes them comparable: one resolved policy, one
/// exclusion set, one instant, so they differ in what was scanned and
/// in nothing else.
///
/// **The artifact's actual disposition is `artifacts.quarantine_status`,
/// joinable on `artifact_id`.** This row does not restate it, because a
/// second copy of a status is a second thing to drift. Reading either
/// column as the artifact's outcome is wrong in a way that reads as
/// reassuring: a run in which every backend abstained in a
/// release-gating way produces an empty primary finding list, so
/// `primary_findings_decision` is `Clean` while the artifact is held
/// `scan_indeterminate`. A column of `clean` is a column of gate
/// decisions over empty finding lists, not an estate that is fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeScanObservation {
    /// The manifest artifact row this is about. The table's primary key:
    /// one row per artifact, replaced on each assessment.
    pub artifact_id: Uuid,
    /// The artifact's repository, so the promotion question can be asked
    /// per repository without a join.
    pub repository_id: Uuid,
    /// The manifest's own content hash — the composition's identity
    /// (ADR 0064 D4). Present on every arm, including the refusals: the
    /// manifest row's payload is the one document the composite path
    /// always has.
    pub manifest_digest: ContentHash,
    /// The backend that answered about the composition, or `None` when
    /// none did. Several backends may be configured; the last one to
    /// produce an answer is the one named, matching the findings this row
    /// summarises.
    pub scanner: Option<String>,
    /// When the assessment ran.
    pub observed_at: DateTime<Utc>,
    /// Which of the four outcomes this run reached.
    pub assessment: CompositeAssessment,
    /// Why, for the three arms that are not [`CompositeAssessment::Assessed`].
    /// Bounded by [`MAX_OBSERVED_REASON_LEN`].
    pub reason: Option<String>,
    /// What acquiring the composition cost.
    pub cost: AcquisitionCost,
    /// Severity counts of the composite findings. Zero on every arm that
    /// produced no findings, including the two refusals and the
    /// nothing-to-compose steady state.
    pub severity_summary: SeveritySummary,
    /// Exact number of composite findings, before the id list is capped.
    pub finding_count: u32,
    /// Exact number of **distinct** vulnerability ids among them.
    /// `>= vulnerability_ids.len()`, and larger exactly when the cap bit.
    pub distinct_vulnerability_count: u32,
    /// Those distinct ids, sorted, truncated to
    /// [`MAX_OBSERVED_VULNERABILITY_IDS`].
    pub vulnerability_ids: Vec<String>,
    /// **The counterfactual**: what the release gate would have decided
    /// over the **composite** findings, had the composite verdict
    /// carried authority. `None` unless `assessment == Assessed` — there
    /// is no composition to decide on otherwise.
    pub composite_findings_decision: Option<GateDecision>,
    /// What the same gate, with the same policy and the same exclusion
    /// set, decided over the findings the **primary** axis produced on
    /// this run — the manifest's own bytes. The other half of the
    /// comparison, in the same row so the promotion question is one read.
    ///
    /// Both fields name a finding set because that is the only thing
    /// that differs between them, and **neither is this artifact's
    /// disposition** — see the type-level docs.
    pub primary_findings_decision: GateDecision,
}

impl CompositeScanObservation {
    /// Enforce the stored bounds. Called by the adapter before the write,
    /// the way `Finding::validate` is: the caps are the column's
    /// contract, not the producer's good manners.
    pub fn validate(&self) -> DomainResult<()> {
        self.severity_summary.validate()?;
        if self.vulnerability_ids.len() > MAX_OBSERVED_VULNERABILITY_IDS {
            return Err(DomainError::Validation(format!(
                "composite observation: vulnerability_ids has {} entries, cap is \
                 {MAX_OBSERVED_VULNERABILITY_IDS}",
                self.vulnerability_ids.len()
            )));
        }
        if let Some(long) = self
            .vulnerability_ids
            .iter()
            .find(|id| id.len() > MAX_OBSERVED_VULNERABILITY_ID_LEN)
        {
            return Err(DomainError::Validation(format!(
                "composite observation: vulnerability id of {} bytes exceeds \
                 {MAX_OBSERVED_VULNERABILITY_ID_LEN}",
                long.len()
            )));
        }
        if (self.distinct_vulnerability_count as usize) < self.vulnerability_ids.len() {
            return Err(DomainError::Validation(format!(
                "composite observation: distinct_vulnerability_count {} is below the {} ids \
                 stored; the counts are exact and the list is the truncation",
                self.distinct_vulnerability_count,
                self.vulnerability_ids.len()
            )));
        }
        if self.distinct_vulnerability_count > self.finding_count {
            return Err(DomainError::Validation(format!(
                "composite observation: {} distinct vulnerability ids among {} findings",
                self.distinct_vulnerability_count, self.finding_count
            )));
        }
        if let Some(reason) = self.reason.as_ref() {
            if reason.len() > MAX_OBSERVED_REASON_LEN {
                return Err(DomainError::Validation(format!(
                    "composite observation: reason of {} bytes exceeds {MAX_OBSERVED_REASON_LEN}",
                    reason.len()
                )));
            }
        }
        if let Some(scanner) = self.scanner.as_ref() {
            if scanner.len() > MAX_OBSERVED_SCANNER_LEN {
                return Err(DomainError::Validation(format!(
                    "composite observation: scanner name of {} bytes exceeds \
                     {MAX_OBSERVED_SCANNER_LEN}",
                    scanner.len()
                )));
            }
        }
        if i64::try_from(self.cost.fetched_bytes).is_err() {
            return Err(DomainError::Validation(format!(
                "composite observation: fetched_bytes {} exceeds what the column holds",
                self.cost.fetched_bytes
            )));
        }
        if self.assessment != CompositeAssessment::Assessed
            && self.composite_findings_decision.is_some()
        {
            return Err(DomainError::Validation(format!(
                "composite observation: a {} outcome composed nothing, so it cannot carry a \
                 counterfactual gate decision",
                self.assessment.as_str()
            )));
        }
        Ok(())
    }
}

/// The distinct vulnerability ids of `findings`, sorted and truncated to
/// [`MAX_OBSERVED_VULNERABILITY_IDS`], beside the **exact** distinct
/// count.
///
/// Sorted so two runs over the same image write the same column and a
/// diff of the table is a diff of the estate, not of the backend's
/// iteration order. Distinctness is case-insensitive on the way in and
/// keeps the first spelling seen, matching `merge_findings`' own
/// `(purl, vulnerability_id)` collision rule — one advisory reported by
/// two backends as `CVE-2024-1` and `cve-2024-1` is one id, not two.
///
/// Pure, so the truncation rule has one definition and the app layer
/// cannot re-derive a second one.
#[must_use]
pub fn distinct_vulnerability_ids(findings: &[Finding]) -> (Vec<String>, u32) {
    let mut seen: Vec<(String, String)> = Vec::new();
    for finding in findings {
        let key = finding.vulnerability_id.to_ascii_lowercase();
        if !seen.iter().any(|(k, _)| k == &key) {
            seen.push((key, finding.vulnerability_id.clone()));
        }
    }
    let total = u32::try_from(seen.len()).unwrap_or(u32::MAX);
    let mut ids: Vec<String> = seen.into_iter().map(|(_, id)| id).collect();
    ids.sort();
    ids.truncate(MAX_OBSERVED_VULNERABILITY_IDS);
    (ids, total)
}

/// Truncate `reason` to [`MAX_OBSERVED_REASON_LEN`] on a char boundary.
///
/// The producer's side of the cap [`CompositeScanObservation::validate`]
/// enforces: a refusal reason that quotes an upstream is data we did not
/// author, and losing the tail of one is better than losing the row.
#[must_use]
pub fn bounded_reason(reason: &str) -> String {
    if reason.len() <= MAX_OBSERVED_REASON_LEN {
        return reason.to_owned();
    }
    let mut end = MAX_OBSERVED_REASON_LEN;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// Outbound port for the `composite_scan_observations` projection.
///
/// **Nothing that decides delivery or release may hold this.** The row it
/// writes is a shadow verdict; a release predicate that read one would be
/// the authority ADR 0064 D6 withholds, arrived at by accident. The
/// property is held structurally by
/// `crates/hort-app/tests/shadow_observation_has_no_authority.rs`, not by
/// inspection.
pub trait CompositeScanObservationRepository: Send + Sync {
    /// Write `observation`, replacing any existing row for its artifact.
    ///
    /// Idempotent per artifact by construction: the artifact id is the
    /// primary key and the write is an upsert, so a rescan overwrites
    /// rather than accumulating.
    ///
    /// The caller treats a failure as **best-effort**: this write happens
    /// outside the transaction that records the artifact's own scan
    /// result and must never change it.
    fn record<'a>(
        &'a self,
        observation: &'a CompositeScanObservation,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// The current observation for `artifact_id`, if one has been
    /// written. Read-only: the promotion question is a `GROUP BY` over
    /// the table, and this is the single-artifact surface behind it.
    fn find_by_artifact(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<CompositeScanObservation>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::entities::scan_policy::SeverityThreshold;
    use crate::events::PolicyViolation;
    use crate::types::{ComponentRelation, SeverityBasis};

    fn finding(vulnerability_id: &str) -> Finding {
        Finding {
            purl: "pkg:oci/nginx@1.27".to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            severity: SeverityThreshold::High,
            cvss_score: None,
            title: "t".to_string(),
            fixed_versions: Vec::new(),
            source_scanner: "trivy".to_string(),
            references: Vec::new(),
            aliases: Vec::new(),
            informational_class: None,
            severity_basis: SeverityBasis::Assessed,
            component_relation: ComponentRelation::Contained,
            statement: crate::types::FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    fn hash() -> ContentHash {
        "a".repeat(64).parse().expect("synthetic sha256")
    }

    fn observation() -> CompositeScanObservation {
        CompositeScanObservation {
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            manifest_digest: hash(),
            scanner: Some("trivy".to_string()),
            observed_at: DateTime::<Utc>::from_timestamp(1, 0).expect("epoch + 1s"),
            assessment: CompositeAssessment::Assessed,
            reason: None,
            cost: AcquisitionCost {
                already_present: 2,
                fetched: 1,
                fetched_bytes: 4096,
            },
            severity_summary: SeveritySummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                negligible: 0,
            },
            finding_count: 1,
            distinct_vulnerability_count: 1,
            vulnerability_ids: vec!["CVE-2024-1".to_string()],
            composite_findings_decision: Some(GateDecision::Reject),
            primary_findings_decision: GateDecision::Clean,
        }
    }

    // -- the two closed sets ---------------------------------------------

    /// Every arm round-trips through the column value. The strings are
    /// operator-queryable SQL, so a silent rename is a schema break.
    #[test]
    fn every_assessment_round_trips_through_its_column_value() {
        for arm in [
            CompositeAssessment::Assessed,
            CompositeAssessment::NothingToCompose,
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            assert_eq!(
                CompositeAssessment::parse(arm.as_str()).expect("a known value"),
                arm
            );
        }
    }

    #[test]
    fn an_unknown_assessment_value_is_refused_and_named() {
        let err = CompositeAssessment::parse("composed").expect_err("not a known value");
        assert!(format!("{err}").contains("composed"), "{err}");
    }

    #[test]
    fn every_gate_decision_round_trips_through_its_column_value() {
        for arm in [
            GateDecision::Clean,
            GateDecision::FindingsRecorded,
            GateDecision::Reject,
        ] {
            assert_eq!(
                GateDecision::parse(arm.as_str()).expect("a known value"),
                arm
            );
        }
    }

    #[test]
    fn an_unknown_gate_decision_value_is_refused_and_named() {
        let err = GateDecision::parse("held").expect_err("not a known value");
        assert!(format!("{err}").contains("held"), "{err}");
    }

    /// The projection keeps the outcome and drops the violation list —
    /// the promotion question is about the direction of a change, and
    /// the per-rule detail is the full report this row does not
    /// duplicate.
    #[test]
    fn a_scan_outcome_projects_onto_its_decision() {
        let violation = PolicyViolation {
            rule: "cve-threshold".to_string(),
            severity: SeverityThreshold::Critical,
            message: "m".to_string(),
            details: serde_json::Value::Null,
        };
        assert_eq!(GateDecision::of(&ScanOutcome::Clean), GateDecision::Clean);
        assert_eq!(
            GateDecision::of(&ScanOutcome::FindingsRecorded(vec![violation.clone()])),
            GateDecision::FindingsRecorded
        );
        assert_eq!(
            GateDecision::of(&ScanOutcome::Reject(vec![violation])),
            GateDecision::Reject
        );
    }

    // -- the id digest ----------------------------------------------------

    #[test]
    fn no_findings_yield_no_ids_and_a_zero_count() {
        let (ids, total) = distinct_vulnerability_ids(&[]);
        assert!(ids.is_empty());
        assert_eq!(total, 0);
    }

    /// One advisory reported by two backends under two spellings is one
    /// id, and the first spelling seen is the one stored — the same
    /// `(purl, vulnerability_id)` collision rule the finding merge uses.
    #[test]
    fn ids_are_distinct_case_insensitively_and_sorted() {
        let (ids, total) = distinct_vulnerability_ids(&[
            finding("CVE-2024-2"),
            finding("cve-2024-2"),
            finding("CVE-2024-1"),
        ]);
        assert_eq!(
            ids,
            vec!["CVE-2024-1".to_string(), "CVE-2024-2".to_string()]
        );
        assert_eq!(total, 2);
    }

    /// The cap bounds the stored column and nothing else: the count
    /// still reports every distinct advisory the composition found.
    #[test]
    fn the_stored_list_is_capped_while_the_count_stays_exact() {
        let findings: Vec<Finding> = (0..MAX_OBSERVED_VULNERABILITY_IDS + 17)
            .map(|i| finding(&format!("CVE-2024-{i:05}")))
            .collect();
        let (ids, total) = distinct_vulnerability_ids(&findings);
        assert_eq!(ids.len(), MAX_OBSERVED_VULNERABILITY_IDS);
        assert_eq!(total as usize, MAX_OBSERVED_VULNERABILITY_IDS + 17);
        // Sorted, so the truncation is the same prefix on every run
        // rather than whichever order the backend happened to report.
        assert_eq!(ids.first().map(String::as_str), Some("CVE-2024-00000"));
    }

    // -- the reason bound --------------------------------------------------

    #[test]
    fn a_short_reason_is_kept_verbatim() {
        assert_eq!(bounded_reason("upstream said no"), "upstream said no");
    }

    #[test]
    fn a_long_reason_is_truncated_to_the_cap() {
        let long = "x".repeat(MAX_OBSERVED_REASON_LEN + 50);
        assert_eq!(bounded_reason(&long).len(), MAX_OBSERVED_REASON_LEN);
    }

    /// Truncation lands on a char boundary — an upstream's complaint is
    /// not guaranteed to be ASCII, and a split code point is not a
    /// `String`.
    #[test]
    fn a_long_reason_is_truncated_on_a_char_boundary() {
        // 'é' is two bytes; placing one across the cap means the naive
        // cut would split it.
        let long = format!(
            "{}é{}",
            "x".repeat(MAX_OBSERVED_REASON_LEN - 1),
            "y".repeat(10)
        );
        let cut = bounded_reason(&long);
        assert_eq!(cut.len(), MAX_OBSERVED_REASON_LEN - 1);
        assert!(cut.chars().all(|c| c == 'x'));
    }

    // -- validation --------------------------------------------------------

    #[test]
    fn a_well_formed_observation_validates() {
        observation()
            .validate()
            .expect("the fixture is well formed");
    }

    #[test]
    fn an_over_cap_id_list_is_refused() {
        let mut o = observation();
        o.vulnerability_ids = (0..MAX_OBSERVED_VULNERABILITY_IDS + 1)
            .map(|i| format!("CVE-{i}"))
            .collect();
        o.distinct_vulnerability_count = u32::try_from(o.vulnerability_ids.len()).expect("fits");
        o.finding_count = o.distinct_vulnerability_count;
        let err = o.validate().expect_err("over the cap");
        assert!(format!("{err}").contains("cap is"), "{err}");
    }

    #[test]
    fn an_over_long_id_is_refused() {
        let mut o = observation();
        o.vulnerability_ids = vec!["C".repeat(MAX_OBSERVED_VULNERABILITY_ID_LEN + 1)];
        let err = o.validate().expect_err("an id no producer can make");
        assert!(format!("{err}").contains("vulnerability id of"), "{err}");
    }

    /// The stored list is a truncation of the count, never the other way
    /// round — a count below the list means one of the two was computed
    /// from something else.
    #[test]
    fn a_count_below_the_stored_list_is_refused() {
        let mut o = observation();
        o.vulnerability_ids = vec!["CVE-1".to_string(), "CVE-2".to_string()];
        o.distinct_vulnerability_count = 1;
        o.finding_count = 2;
        let err = o.validate().expect_err("the counts disagree");
        assert!(format!("{err}").contains("is below the"), "{err}");
    }

    #[test]
    fn more_distinct_ids_than_findings_is_refused() {
        let mut o = observation();
        o.finding_count = 1;
        o.distinct_vulnerability_count = 2;
        o.vulnerability_ids = vec!["CVE-1".to_string(), "CVE-2".to_string()];
        let err = o
            .validate()
            .expect_err("distinct ids cannot exceed findings");
        assert!(
            format!("{err}").contains("distinct vulnerability ids among"),
            "{err}"
        );
    }

    #[test]
    fn an_over_long_reason_is_refused() {
        let mut o = observation();
        o.assessment = CompositeAssessment::DeterministicRefusal;
        o.composite_findings_decision = None;
        o.reason = Some("x".repeat(MAX_OBSERVED_REASON_LEN + 1));
        let err = o.validate().expect_err("over the reason cap");
        assert!(format!("{err}").contains("reason of"), "{err}");
    }

    #[test]
    fn an_over_long_scanner_name_is_refused() {
        let mut o = observation();
        o.scanner = Some("s".repeat(MAX_OBSERVED_SCANNER_LEN + 1));
        let err = o.validate().expect_err("over the scanner cap");
        assert!(format!("{err}").contains("scanner name of"), "{err}");
    }

    #[test]
    fn a_byte_count_the_column_cannot_hold_is_refused() {
        let mut o = observation();
        o.cost.fetched_bytes = u64::MAX;
        let err = o.validate().expect_err("beyond i64");
        assert!(format!("{err}").contains("fetched_bytes"), "{err}");
    }

    /// A refusal composed nothing, so a counterfactual on it would be a
    /// gate decision about findings nobody produced. Every non-assessed
    /// arm refuses one.
    #[test]
    fn a_counterfactual_without_an_assessment_is_refused() {
        for arm in [
            CompositeAssessment::NothingToCompose,
            CompositeAssessment::DeterministicRefusal,
            CompositeAssessment::TransientRefusal,
        ] {
            let mut o = observation();
            o.assessment = arm;
            o.composite_findings_decision = Some(GateDecision::Clean);
            let err = o.validate().expect_err("no composition, no counterfactual");
            assert!(format!("{err}").contains(arm.as_str()), "{err}");
        }
    }

    #[test]
    fn an_out_of_range_severity_summary_is_refused() {
        let mut o = observation();
        o.severity_summary.critical = u32::MAX;
        o.validate()
            .expect_err("the summary's own cap applies here too");
    }

    // -- the port ----------------------------------------------------------

    /// Compile-time assertion that the port is dyn-compatible. Mirrors
    /// the same probe on the sibling projection ports.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn CompositeScanObservationRepository>();
    }

    struct NoopRepo;
    impl CompositeScanObservationRepository for NoopRepo {
        fn record<'a>(
            &'a self,
            _observation: &'a CompositeScanObservation,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_artifact(
            &self,
            _artifact_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Option<CompositeScanObservation>>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[tokio::test]
    async fn both_port_methods_are_reachable_through_a_trait_object() {
        let repo: &dyn CompositeScanObservationRepository = &NoopRepo;
        repo.record(&observation()).await.expect("noop records");
        assert!(repo
            .find_by_artifact(Uuid::nil())
            .await
            .expect("noop reads")
            .is_none());
    }

    #[tokio::test]
    async fn err_round_trips_through_the_port_signature() {
        struct FailingRepo;
        impl CompositeScanObservationRepository for FailingRepo {
            fn record<'a>(
                &'a self,
                _observation: &'a CompositeScanObservation,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn find_by_artifact(
                &self,
                _artifact_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Option<CompositeScanObservation>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
        }
        let repo = FailingRepo;
        assert!(matches!(
            repo.record(&observation()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            repo.find_by_artifact(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
    }
}
