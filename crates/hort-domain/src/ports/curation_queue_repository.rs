//! `CurationQueueRepository` port.
//!
//! Outbound port behind the curation-queue read surface: a paginated
//! read of curator-actionable
//! artifacts with per-row policy-deadline resolution + rejection-reason
//! discriminator via LATERAL JOIN.
//!
//! **Item 5 stub scope.** Item 5 (`CurationUseCase::waive` + `::block`)
//! wires `Arc<dyn CurationQueueRepository>` into `CurationUseCase`'s
//! port-only constructor so the full port can be threaded one-shot
//! when Item 6 lands. The trait, [`CurationQueueEntry`], and
//! [`CurationQueueFilter`] are defined here so the use-case
//! struct compiles; Item 6 supplies the SQL adapter + the use-case
//! `list_queue` method body.
//!
//! # Domain DTO discipline
//!
//! [`CurationQueueEntry`] and [`CurationQueueFilter`] do **NOT** derive
//! `Serialize` / `Deserialize`. The HTTP DTO lives in the inbound-HTTP
//! crate; mirrors `PatchCandidateRepository`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::QuarantineStatus;
use crate::entities::repository::RepositoryFormat;
use crate::entities::scan_policy::SeverityThreshold;
use crate::error::DomainResult;

use super::BoxFuture;

/// One row of the curation queue listing — an artifact currently in a
/// curator-actionable state. Design doc §2.5 + §3.
#[derive(Debug, Clone, PartialEq)]
pub struct CurationQueueEntry {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    /// Resolved by the adapter join — pass-through string the HTTP DTO
    /// renders for the operator. Use case never inspects it.
    pub repository_key: String,
    pub format: RepositoryFormat,
    pub package_name: String,
    pub version: Option<String>,
    pub quarantine_status: QuarantineStatus,
    pub quarantine_window_start: Option<DateTime<Utc>>,
    /// Computed by the adapter from `(window_start, policy.duration)`
    /// (ADR 0007). Non-persisted.
    pub quarantine_deadline: Option<DateTime<Utc>>,
    pub finding_count: u32,
    pub max_severity: Option<SeverityThreshold>,
    /// Design doc §2.5 — discriminator from the latest `ArtifactRejected`
    /// event's `rejected_by` payload (`"scanner" | "curator" |
    /// "curation_retroactive" | "corruption"`). `None` for non-rejected
    /// rows or when the event is missing (defensive).
    pub rejection_reason_kind: Option<String>,
}

/// Query filter for [`CurationQueueRepository::list_queue`].
///
/// `limit` defaults to 100; the use case caps at 500 (mirrors the
/// patch-candidate surface).
#[derive(Debug, Clone, PartialEq)]
pub struct CurationQueueFilter {
    pub repository_id: Option<Uuid>,
    pub status: Option<QuarantineStatus>,
    /// Filter on the LATERAL-joined rejection-reason kind. Applied
    /// post-join; meaningful only with `status = Rejected`.
    pub rejection_reason_kind: Option<String>,
    pub limit: u32,
}

impl Default for CurationQueueFilter {
    fn default() -> Self {
        Self {
            repository_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        }
    }
}

/// Outbound port: paginated listing of curator-actionable artifacts.
///
/// `CurationUseCase` holds this trait via `Arc<dyn _>` and exposes the
/// `list_queue` delegation; the Postgres adapter implements the body.
pub trait CurationQueueRepository: Send + Sync {
    fn list_queue<'a>(
        &'a self,
        filter: CurationQueueFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationQueueEntry>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn CurationQueueRepository>();
    }

    #[test]
    fn filter_default_uses_limit_100() {
        let f = CurationQueueFilter::default();
        assert_eq!(f.limit, 100);
        assert!(f.repository_id.is_none());
        assert!(f.status.is_none());
        assert!(f.rejection_reason_kind.is_none());
    }
}
