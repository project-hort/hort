//! Wire projection of the `retention-evaluate` job's `result_summary`.
//!
//! # Dep-graph invariant
//!
//! `hort-cli` imports nothing from `hort-domain` / `hort-app` /
//! `hort-adapters-*`. These types are therefore defined here verbatim
//! from the JSON the `retention-evaluate` task handler writes into
//! `jobs.result_summary`.
//!
//! **Sync-required**: mirrors the `result_summary` object built by
//! `hort_app::task_handlers::retention_evaluate::RetentionEvaluateHandler`
//! (`run` for the envelope, `build_preview` for the `preview` object).
//! The JSON field names are the contract.
//!
//! One server field is deliberately **not** projected here: `cursor`, the
//! keyset position the next run resumes from. It is the sweep's own
//! rotation state, not a figure an operator reads or acts on — its
//! operator-visible consequence is already carried by `coverage`. Serde
//! ignores it, which is the intended handling rather than an omission.
//!
//! # Deserialisation posture: tolerate, never invent
//!
//! Every numeric field is `#[serde(default)]` so a summary written by an
//! older or newer server still parses instead of failing the whole
//! command. The one field that is *not* allowed to degrade quietly is
//! the byte accounting: an unrecognised `freed_bytes.status` folds to
//! [`FreedBytes::Unrecognised`], which renders as "not measured" with an
//! explicit explanation. A missing or unparseable byte figure must never
//! surface as `0`, as a blank, or as a dash — each of those reads as
//! "nothing to free", which is a different and much more dangerous
//! claim than "hort did not measure this".
//!
//! [`ProposalDigest`] carries the same posture on the same grounds. It
//! is `Option`, and a digest missing either half counts as absent
//! ([`ProposalDigest::is_usable`]): an identity this client cannot use
//! must read as "which rows were not reported", never as "the same rows
//! as the other side". A blank comparing equal to another blank would
//! manufacture the one verdict — the same artifacts would be expired —
//! that lets the CLI skip a confirmation.

use serde::{Deserialize, Serialize};

/// A `freed_bytes.omitted.reason` in the shape the server actually sends
/// (`bound_omission_reason` in the `retention-evaluate` task handler):
/// which of the two simulation ceilings stopped the exact accounting,
/// what that ceiling is set to, and what this run presented to it.
///
/// Test fixtures across this module share it so a reader cannot mistake a
/// placeholder for the live contract. The CLI never matches on this text
/// — it carries the server's words through verbatim — so the value here
/// is illustrative, and the assertions below say so by checking shape
/// rather than wording.
#[cfg(test)]
pub(crate) const OMITTED_BYTES_REASON: &str =
    "exact byte accounting is bounded at 128000 reclaimable content targets; this run reached at least 128001. Narrow the sweep's scope — fewer repositories, or a predicate that matches fewer artifacts — to bring it under the bound.";

/// Top-level `result_summary` of a `retention-evaluate` job.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetentionRunSummary {
    /// `dry_run` or `execute`.
    #[serde(default)]
    pub mode: String,
    /// `complete` when this run examined the whole candidate set —
    /// it both started at the beginning and reached the end. `partial`
    /// when it stopped at its per-run batch cap, or resumed after an
    /// earlier run's position, leaving artifacts outside its window
    /// unexamined. Those artifacts are reached by later runs (the sweep
    /// persists where it stopped), so `partial` bounds the run's figures
    /// and not the sweep's reach.
    #[serde(default)]
    pub coverage: String,
    #[serde(default)]
    pub policies: u64,
    #[serde(default)]
    pub evaluated: u64,
    #[serde(default)]
    pub expired: u64,
    #[serde(default)]
    pub already_expired: u64,
    #[serde(default)]
    pub skipped_protected: u64,
    #[serde(default)]
    pub skipped_stale_scan: u64,
    #[serde(default)]
    pub errors: u64,
    /// Present only for a dry run; `null` for an execution.
    #[serde(default)]
    pub preview: Option<PreviewBody>,
}

impl RetentionRunSummary {
    /// `true` when the sweep stopped early and the totals therefore
    /// undercount. Anything other than the literal `complete` is treated
    /// as truncated — an unrecognised coverage word must not read as a
    /// reassurance.
    pub fn coverage_is_partial(&self) -> bool {
        coverage_is_partial(&self.coverage)
    }
}

/// The coverage rule in one place, so the delta — which holds only the
/// raw words — decides it exactly as the summary does.
pub fn coverage_is_partial(raw: &str) -> bool {
    raw != "complete"
}

/// The dry run's `preview` object.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreviewBody {
    /// Artifact **rows** that would be expired. Not a size.
    #[serde(default)]
    pub rows: u64,
    /// Distinct content hashes those rows point at. Not a size either.
    #[serde(default)]
    pub distinct_contents: u64,
    /// Measured bytes, or an explicit statement that hort did not
    /// measure them. Never an estimate.
    #[serde(default)]
    pub freed_bytes: FreedBytes,
    /// Which rows this run proposes to expire, as a bounded identity.
    /// `None` from a server that does not report one — see
    /// [`ProposalDigest`].
    #[serde(default)]
    pub proposal_digest: Option<ProposalDigest>,
    #[serde(default)]
    pub groups: Vec<PreviewGroup>,
    #[serde(default)]
    pub sample: Vec<PreviewSampleRow>,
    /// The server-side cap on how many sample rows were recorded.
    /// Absent on the no-active-policies short-circuit, which records an
    /// empty sample and no cap.
    #[serde(default)]
    pub sample_limit: Option<u64>,
}

/// Byte accounting for the content the purge would actually reclaim.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FreedBytes {
    /// Measured: every reclaimable target's size was read from storage.
    Exact {
        #[serde(default)]
        bytes: u64,
    },
    /// Deliberately not measured, with the server's reason.
    Omitted {
        #[serde(default)]
        reason: String,
    },
    /// A `status` this client does not know. Rendered exactly like
    /// `Omitted` — the one thing that must not happen is a number.
    #[serde(other)]
    Unrecognised,
}

impl Default for FreedBytes {
    /// A summary with no `freed_bytes` at all is *not* zero bytes.
    fn default() -> Self {
        Self::Unrecognised
    }
}

impl FreedBytes {
    /// The measured byte count, or `None` when hort did not measure one.
    pub fn measured(&self) -> Option<u64> {
        match self {
            Self::Exact { bytes } => Some(*bytes),
            Self::Omitted { .. } | Self::Unrecognised => None,
        }
    }

    /// Why no figure is available, for the two non-measured cases.
    pub fn omission_reason(&self) -> Option<&str> {
        match self {
            Self::Exact { .. } => None,
            Self::Omitted { reason } if !reason.is_empty() => Some(reason.as_str()),
            Self::Omitted { .. } => Some("the server gave no reason"),
            Self::Unrecognised => {
                Some("the server reported a byte-accounting status this CLI does not recognise")
            }
        }
    }
}

/// One `(policy, repository)` rollup.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreviewGroup {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub policy_name: String,
    /// The repository UUID — kept for machine consumers.
    #[serde(default)]
    pub repository_id: String,
    /// The repository key: the identifier an operator writes into a
    /// policy's `metadata.name`. This is what the human output shows.
    #[serde(default)]
    pub repository_key: String,
    #[serde(default)]
    pub rows: u64,
    #[serde(default)]
    pub distinct_contents: u64,
    /// This group's share of the proposal, as a bounded identity.
    #[serde(default)]
    pub proposal_digest: Option<ProposalDigest>,
}

impl PreviewGroup {
    /// Stable identity of a group across two sweeps.
    pub fn key(&self) -> (String, String) {
        (self.policy_id.clone(), self.repository_id.clone())
    }
}

/// Which rows a preview proposes to expire, stated as a fixed-width
/// digest over their identifiers.
///
/// # Why the wire carries this and not a list
///
/// `rows`, `distinct_contents` and the byte total are all *quantities*.
/// Two previews agreeing on every one of them can still name different
/// artifacts — one stopped matching and an equally sized one started —
/// and among artifacts of the same kind that is not a rare coincidence.
/// The sample cannot close the gap: it is capped server-side and may be
/// empty. A digest closes it exactly and costs the same on the wire for
/// a proposal of five rows as for one of fifty thousand.
///
/// # This is not a content hash
///
/// It digests `(policy, artifact)` identifiers, never artifact bytes. It
/// is not CAS identity, no storage path accepts it, and the server
/// domain-separates its input precisely so the two can never coincide.
/// Reading a value here as something to look up in storage is a
/// category error.
///
/// # Why `scheme` rides along
///
/// A single `apply --from-preview` can hold a baseline written before a
/// server upgrade and a fresh preview written after it. Comparing two
/// values produced by different constructions would report "the
/// proposal changed" when nothing had — and a warning that fires when
/// nothing moved is trained away, then missed on the run where
/// something did. Two digests are comparable only when their schemes
/// match; otherwise this CLI says it could not compare rather than
/// guessing.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProposalDigest {
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub value: String,
}

impl ProposalDigest {
    /// `true` when both halves are present. A digest missing either is
    /// treated exactly as an absent one: half a digest cannot decide
    /// anything, and letting one compare equal to another half-digest
    /// would manufacture a "same artifacts" verdict out of two blanks.
    pub fn is_usable(&self) -> bool {
        !self.scheme.is_empty() && !self.value.is_empty()
    }
}

/// What comparing two previews' proposal identities established.
///
/// Deliberately four answers and not a boolean: "these name different
/// artifacts" and "nobody told me which artifacts either names" demand
/// the same caution from an operator but are not the same statement,
/// and an output that collapses them teaches the reader to disbelieve
/// the one that is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalComparison {
    /// Both previews reported a comparable identity and the two agree:
    /// the same rows would be expired.
    Same,
    /// Both reported a comparable identity and the two differ: the
    /// proposed set is not the one the baseline showed.
    Different,
    /// At least one side reported no usable identity, so only totals
    /// were compared — and equal totals are not the same artifacts.
    Unreported,
    /// Both sides reported an identity, computed by different schemes.
    /// Not comparable, which is a different statement from "different".
    SchemeMismatch,
}

impl ProposalComparison {
    /// `true` only for the one answer that lets a reader conclude the
    /// same artifacts would be expired. Every other answer — including
    /// both flavours of "could not tell" — fails closed.
    pub fn is_same(self) -> bool {
        self == Self::Same
    }
}

/// Compare two proposal identities.
pub fn compare_proposals(
    baseline: Option<&ProposalDigest>,
    fresh: Option<&ProposalDigest>,
) -> ProposalComparison {
    match (
        baseline.filter(|d| d.is_usable()),
        fresh.filter(|d| d.is_usable()),
    ) {
        (Some(b), Some(f)) if b.scheme != f.scheme => ProposalComparison::SchemeMismatch,
        (Some(b), Some(f)) if b.value == f.value => ProposalComparison::Same,
        (Some(_), Some(_)) => ProposalComparison::Different,
        _ => ProposalComparison::Unreported,
    }
}

/// One sampled artifact, so the selection can be sanity-checked instead
/// of a total being believed.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreviewSampleRow {
    #[serde(default)]
    pub artifact_id: String,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub repository_id: String,
    #[serde(default)]
    pub repository_key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub age_seconds: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_summary_round_trips_from_the_handler_shape() {
        let raw = serde_json::json!({
            "mode": "dry_run",
            "coverage": "partial",
            "policies": 3,
            "evaluated": 1200,
            "expired": 812,
            "already_expired": 1,
            "skipped_protected": 2,
            "skipped_stale_scan": 3,
            "errors": 4,
            "preview": {
                "rows": 812,
                "distinct_contents": 634,
                "freed_bytes": { "status": "exact", "bytes": 12345 },
                "groups": [{
                    "policy_id": "p1", "policy_name": "npm-90d",
                    "repository_id": "r1", "repository_key": "npm-proxy",
                    "rows": 812, "distinct_contents": 634
                }],
                "sample": [{
                    "artifact_id": "a1", "policy_id": "p1",
                    "repository_id": "r1", "repository_key": "npm-proxy",
                    "name": "left-pad", "version": "1.3.0", "age_seconds": 98765
                }],
                "sample_limit": 500
            }
        });
        let parsed: RetentionRunSummary = serde_json::from_value(raw).expect("parses");
        assert!(parsed.coverage_is_partial());
        let preview = parsed.preview.expect("dry run carries a preview");
        assert_eq!(preview.rows, 812);
        assert_eq!(preview.freed_bytes.measured(), Some(12345));
        assert_eq!(preview.groups[0].repository_key, "npm-proxy");
        assert_eq!(preview.sample[0].repository_key, "npm-proxy");
        assert_eq!(preview.sample_limit, Some(500));
    }

    #[test]
    fn execute_summary_has_no_preview() {
        let parsed: RetentionRunSummary = serde_json::from_value(serde_json::json!({
            "mode": "execute", "coverage": "complete", "policies": 1,
            "evaluated": 10, "expired": 4, "already_expired": 0,
            "skipped_protected": 0, "skipped_stale_scan": 0, "errors": 0,
            "preview": null
        }))
        .expect("parses");
        assert!(parsed.preview.is_none());
        assert!(!parsed.coverage_is_partial());
    }

    #[test]
    fn omitted_bytes_never_become_a_number() {
        let omitted: FreedBytes = serde_json::from_value(serde_json::json!({
            "status": "omitted",
            "reason": OMITTED_BYTES_REASON
        }))
        .expect("parses");
        assert_eq!(omitted.measured(), None);
        assert_eq!(
            omitted.omission_reason().expect("a reason"),
            OMITTED_BYTES_REASON,
            "the server's reason is carried through verbatim, whatever it says",
        );
    }

    #[test]
    fn an_unknown_byte_status_degrades_to_not_measured_not_to_zero() {
        let unknown: FreedBytes =
            serde_json::from_value(serde_json::json!({ "status": "estimated", "bytes": 999 }))
                .expect("unknown status still parses");
        assert_eq!(unknown, FreedBytes::Unrecognised);
        assert_eq!(unknown.measured(), None, "an estimate is never reported");
        assert!(unknown.omission_reason().is_some());
    }

    #[test]
    fn a_missing_freed_bytes_object_is_not_zero_bytes() {
        let body: PreviewBody =
            serde_json::from_value(serde_json::json!({ "rows": 5 })).expect("parses");
        assert_eq!(body.freed_bytes.measured(), None);
        assert_eq!(body.sample_limit, None);
    }

    #[test]
    fn an_omitted_reason_is_never_empty_in_the_rendered_path() {
        let bare: FreedBytes =
            serde_json::from_value(serde_json::json!({ "status": "omitted" })).expect("parses");
        assert_eq!(bare.omission_reason(), Some("the server gave no reason"));
    }

    #[test]
    fn an_unrecognised_coverage_word_is_treated_as_truncated() {
        let summary = RetentionRunSummary {
            coverage: "who-knows".into(),
            ..RetentionRunSummary::default()
        };
        assert!(summary.coverage_is_partial());
    }

    /// The digest travels as an object, so a reader can tell a value it
    /// may compare from one it may not.
    #[test]
    fn a_proposal_digest_parses_from_the_handler_shape() {
        let body: PreviewBody = serde_json::from_value(serde_json::json!({
            "rows": 2,
            "proposal_digest": { "scheme": "policy-artifact-pairs-v1", "value": "abc123" },
            "groups": [{
                "policy_id": "p1", "repository_id": "r1", "rows": 2,
                "proposal_digest": { "scheme": "policy-artifact-pairs-v1", "value": "def456" }
            }]
        }))
        .expect("parses");
        let run = body.proposal_digest.expect("a run digest");
        assert_eq!(run.scheme, "policy-artifact-pairs-v1");
        assert_eq!(run.value, "abc123");
        assert!(run.is_usable());
        assert_eq!(
            body.groups[0]
                .proposal_digest
                .as_ref()
                .expect("a group digest")
                .value,
            "def456",
            "the per-group identity is what lets a reader say which group moved",
        );
    }

    /// A server that reports no identity must not be read as reporting
    /// the *same* identity.
    #[test]
    fn an_absent_or_half_present_digest_is_not_usable() {
        let body: PreviewBody =
            serde_json::from_value(serde_json::json!({ "rows": 1 })).expect("parses");
        assert!(body.proposal_digest.is_none());

        for half in [
            serde_json::json!({ "scheme": "policy-artifact-pairs-v1" }),
            serde_json::json!({ "value": "abc123" }),
            serde_json::json!({}),
        ] {
            let digest: ProposalDigest = serde_json::from_value(half.clone()).expect("parses");
            assert!(!digest.is_usable(), "{half}");
        }
    }

    #[test]
    fn comparing_two_identities_answers_same_different_or_not_at_all() {
        let d = |scheme: &str, value: &str| ProposalDigest {
            scheme: scheme.into(),
            value: value.into(),
        };
        let v1 = d("policy-artifact-pairs-v1", "aaaa");
        let v1_other = d("policy-artifact-pairs-v1", "bbbb");
        let v2 = d("policy-artifact-pairs-v2", "aaaa");
        let blank = ProposalDigest::default();

        assert_eq!(
            compare_proposals(Some(&v1), Some(&v1)),
            ProposalComparison::Same
        );
        assert_eq!(
            compare_proposals(Some(&v1), Some(&v1_other)),
            ProposalComparison::Different
        );
        assert_eq!(
            compare_proposals(Some(&v1), Some(&v2)),
            ProposalComparison::SchemeMismatch,
            "the same value under two constructions proves nothing",
        );
        assert_eq!(
            compare_proposals(None, Some(&v1)),
            ProposalComparison::Unreported
        );
        assert_eq!(
            compare_proposals(Some(&v1), None),
            ProposalComparison::Unreported
        );
        assert_eq!(
            compare_proposals(None, None),
            ProposalComparison::Unreported
        );
        assert_eq!(
            compare_proposals(Some(&blank), Some(&blank)),
            ProposalComparison::Unreported,
            "two blanks must not agree with each other",
        );
    }

    #[test]
    fn only_a_matching_identity_counts_as_the_same_proposal() {
        assert!(ProposalComparison::Same.is_same());
        for other in [
            ProposalComparison::Different,
            ProposalComparison::Unreported,
            ProposalComparison::SchemeMismatch,
        ] {
            assert!(!other.is_same(), "{other:?} must fail closed");
        }
    }

    #[test]
    fn the_coverage_rule_is_the_same_whether_read_from_a_summary_or_a_word() {
        assert!(!coverage_is_partial("complete"));
        assert!(coverage_is_partial("partial"));
        assert!(coverage_is_partial(""));
        assert!(coverage_is_partial("who-knows"));
    }

    #[test]
    fn group_key_pairs_policy_and_repository_ids() {
        let g = PreviewGroup {
            policy_id: "p".into(),
            repository_id: "r".into(),
            ..PreviewGroup::default()
        };
        assert_eq!(g.key(), ("p".to_string(), "r".to_string()));
    }
}
