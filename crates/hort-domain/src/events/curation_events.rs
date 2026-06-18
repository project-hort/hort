//! Curation-decision audit events.
//!
//! `CurationApplied` records a non-`Allow` curation decision — emitted at
//! ingest time for `Warn` matches and during the apply-pipeline retroactive
//! pass for both `Warn` and `Block` matches. `Allow` decisions are silent;
//! they would dominate the volume without carrying useful audit context.
//!
//! The event lives on a per-repository stream
//! ([`crate::events::StreamId::curation_per_repo`]), separate from the
//! per-artifact stream that carries the `ArtifactRejected` companion event
//! emitted on a retroactive `Block`. Splitting them keeps the curation
//! audit log queryable as a unit per repository while leaving each
//! artifact's lifecycle ordered within its own stream.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ArtifactCoords;

use super::validation::validate_string;

/// Cap on `CurationApplied.reason`. Mirrors the existing
/// `MAX_REASON_LEN` used by `ArtifactRejected` — operator-readable
/// context, 4 KiB is generous.
const MAX_REASON_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// CurationActionTag
// ---------------------------------------------------------------------------

/// Typed action carried by [`CurationApplied`].
///
/// Only `Warn` and `Block` exist — `Allow` decisions are not recorded
/// (too high-volume, no information value). The discriminant
/// is the audit query's primary filter ("show me every block in this
/// repo this week").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CurationActionTag {
    Warn,
    Block,
}

// ---------------------------------------------------------------------------
// CurationTrigger
// ---------------------------------------------------------------------------

/// What caused the [`CurationApplied`] event.
///
/// Distinguishes a fresh ingest hitting a curation rule
/// (`CurationTrigger::Ingest`) from the apply-pipeline retroactive
/// evaluation (`CurationTrigger::Retroactive`). Audit consumers use
/// this to separate "operator just added a rule that hit existing
/// artifacts" from "this incoming artifact tripped an existing rule."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CurationTrigger {
    Ingest,
    Retroactive,
}

// ---------------------------------------------------------------------------
// CurationApplied
// ---------------------------------------------------------------------------

/// Audit record for a non-`Allow` curation decision.
///
/// `repository_id` is also the entity id of the stream this event lands
/// on (one stream per repository — see
/// [`crate::events::StreamId::curation_per_repo`]); duplicating it on the
/// payload lets consumers project by repo without having to re-parse the
/// stream id.
///
/// `coords` carries the artifact's identifying name/version/format —
/// the same shape format handlers produce at ingest. Storing it here
/// avoids the audit consumer having to join against the `artifacts`
/// table for a metric or report.
///
/// `rule_id` and `rule_name` together resolve "which rule fired"
/// without an extra `curation_rules` lookup. The id is the stable
/// identity even if the rule's name later changes; the name is the
/// human-readable summary at the moment the decision was made.
///
/// `action` is the matched rule's action — only `Warn` or `Block` (an
/// `Allow` rule never produces a `CurationApplied` event).
///
/// `reason` is the rule's free-text explanation copied at decision
/// time. Capped at 4 KiB; the rule itself enforces the same cap at
/// gitops admission, so the runtime cap is defence-in-depth.
///
/// `trigger` indicates whether the decision happened at ingest or
/// during a retroactive apply-pipeline pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CurationApplied {
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: CurationActionTag,
    pub reason: String,
    pub trigger: CurationTrigger,
}

impl CurationApplied {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("rule_name", &self.rule_name, MAX_REASON_LEN)?;
        validate_string("reason", &self.reason, MAX_REASON_LEN)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;

    fn sample_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "xz-utils".into(),
            name_as_published: "xz-utils".into(),
            version: Some("1.0.0".into()),
            path: "dist/xz-utils-1.0.0.tar.gz".into(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    fn sample_event() -> CurationApplied {
        CurationApplied {
            repository_id: Uuid::new_v4(),
            coords: sample_coords(),
            rule_id: Uuid::new_v4(),
            rule_name: "block-xz".into(),
            action: CurationActionTag::Block,
            reason: "supply-chain risk".into(),
            trigger: CurationTrigger::Retroactive,
        }
    }

    // -- CurationActionTag --------------------------------------------------

    #[test]
    fn curation_action_tag_clone_eq_serde() {
        for tag in [CurationActionTag::Warn, CurationActionTag::Block] {
            let copied = tag; // Copy
            assert_eq!(tag, copied);
            let json = serde_json::to_string(&tag).unwrap();
            let back: CurationActionTag = serde_json::from_str(&json).unwrap();
            assert_eq!(tag, back);
        }
    }

    #[test]
    fn curation_action_tag_warn_block_distinct() {
        assert_ne!(CurationActionTag::Warn, CurationActionTag::Block);
    }

    // -- CurationTrigger ----------------------------------------------------

    #[test]
    fn curation_trigger_clone_eq_serde() {
        for trig in [CurationTrigger::Ingest, CurationTrigger::Retroactive] {
            let copied = trig; // Copy
            assert_eq!(trig, copied);
            let json = serde_json::to_string(&trig).unwrap();
            let back: CurationTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(trig, back);
        }
    }

    #[test]
    fn curation_trigger_ingest_retroactive_distinct() {
        assert_ne!(CurationTrigger::Ingest, CurationTrigger::Retroactive);
    }

    // -- CurationApplied: clone / eq / serde --------------------------------

    #[test]
    fn curation_applied_clone_eq() {
        let e = sample_event();
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn curation_applied_serde_round_trip() {
        let e = sample_event();
        let json = serde_json::to_string(&e).unwrap();
        let back: CurationApplied = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -- CurationApplied::validate ------------------------------------------

    #[test]
    fn validate_happy_path() {
        assert!(sample_event().validate().is_ok());
    }

    #[test]
    fn validate_empty_rule_name_fails() {
        let mut e = sample_event();
        e.rule_name = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("rule_name"));
    }

    #[test]
    fn validate_empty_reason_fails() {
        let mut e = sample_event();
        e.reason = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("reason"));
    }

    #[test]
    fn validate_reason_at_limit() {
        let mut e = sample_event();
        e.reason = "r".repeat(MAX_REASON_LEN);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn validate_reason_over_limit() {
        let mut e = sample_event();
        e.reason = "r".repeat(MAX_REASON_LEN + 1);
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_rule_name_over_limit() {
        let mut e = sample_event();
        e.rule_name = "n".repeat(MAX_REASON_LEN + 1);
        assert!(e.validate().is_err());
    }
}
