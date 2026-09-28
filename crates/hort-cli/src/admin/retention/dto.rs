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
        self.coverage != "complete"
    }
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
}

impl PreviewGroup {
    /// Stable identity of a group across two sweeps.
    pub fn key(&self) -> (String, String) {
        (self.policy_id.clone(), self.repository_id.clone())
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
