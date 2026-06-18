//! `CurationDecisionsRepository` port.
//!
//! Outbound port behind the curation-decisions read surface:
//! a paginated event-log scan over `events` filtered to curator
//! decisions (`ArtifactReleased{authority: CuratorWaiver}`,
//! `ArtifactRejected{rejected_by: Curator}`, `ExclusionAdded`,
//! `ExclusionRemoved`).
//!
//! The trait, [`CurationDecisionEntry`], [`CurationDecisionFilter`], and
//! [`CurationDecisionKind`] are defined here so the use-case struct
//! compiles; the SQL adapter and the use-case `list_decisions` method body
//! are supplied by the Postgres adapter.
//!
//! # Domain DTO discipline
//!
//! No serde on these types — HTTP DTO lives in the inbound-HTTP crate.
//! Mirrors the `PatchCandidateRepository` discipline.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Discriminator for the four curator decision shapes the listing
/// surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurationDecisionKind {
    /// Curator-driven release (`ArtifactReleased { authority:
    /// CuratorWaiver }`).
    Waive,
    /// Curator-driven rejection (`ArtifactRejected { rejected_by:
    /// Curator { .. } }`).
    Block,
    /// `ExclusionAdded` whose envelope `actor_kind = 'user'` and whose
    /// permission grant resolved to `Curate` (admin path coexists; the
    /// listing surfaces both for the curator surface).
    ExcludeFinding,
    /// `ExclusionRemoved` — symmetric to [`Self::ExcludeFinding`].
    UnexcludeFinding,
}

/// One row of the decisions listing — exactly one curator-attributable
/// event (events-first; correlation collapse is an
/// opt-in HTTP-layer `--by-correlation` parameter).
#[derive(Debug, Clone, PartialEq)]
pub struct CurationDecisionEntry {
    pub event_id: Uuid,
    pub kind: CurationDecisionKind,
    pub actor_id: Uuid,
    /// Populated for Waive / Block.
    pub artifact_id: Option<Uuid>,
    /// Populated for ExcludeFinding / UnexcludeFinding.
    pub policy_id: Option<Uuid>,
    /// Populated for ExcludeFinding / UnexcludeFinding.
    pub cve_id: Option<String>,
    pub justification: String,
    pub correlation_id: Uuid,
    pub occurred_at: DateTime<Utc>,
}

/// Query filter for [`CurationDecisionsRepository::list_decisions`].
///
/// `limit` defaults to 100; the use case caps at 500.
#[derive(Debug, Clone, PartialEq)]
pub struct CurationDecisionFilter {
    pub kind: Option<CurationDecisionKind>,
    pub actor_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
    pub package: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: u32,
}

impl Default for CurationDecisionFilter {
    fn default() -> Self {
        Self {
            kind: None,
            actor_id: None,
            repository_id: None,
            package: None,
            since: None,
            limit: 100,
        }
    }
}

/// Outbound port: paginated decisions log.
///
/// The trait exists here so `CurationUseCase` can hold `Arc<dyn _>`;
/// the Postgres adapter supplies the full implementation.
pub trait CurationDecisionsRepository: Send + Sync {
    fn list_decisions<'a>(
        &'a self,
        filter: CurationDecisionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn CurationDecisionsRepository>();
    }

    #[test]
    fn filter_default_uses_limit_100() {
        let f = CurationDecisionFilter::default();
        assert_eq!(f.limit, 100);
        assert!(f.kind.is_none());
        assert!(f.actor_id.is_none());
        assert!(f.repository_id.is_none());
        assert!(f.package.is_none());
        assert!(f.since.is_none());
    }
}
