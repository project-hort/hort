//! `CurationExclusionsRepository` port.
//!
//! Outbound port behind the active-exclusions read surface.
//! Reads `exclusion_projections` (the same projection
//! `QuarantineUseCase::record_scan_result` consults). Distinct from
//! `CurationDecisionsRepository` because exclusions have *ongoing
//! state* — active until removed or expired. `CurationUseCase` holds
//! the trait via `Arc<dyn _>` and exposes `list_exclusions`; the
//! Postgres adapter supplies the SQL body.
//!
//! # Domain DTO discipline
//!
//! No serde on these types — the HTTP DTO lives in the inbound-HTTP
//! crate. Mirrors the `PatchCandidateRepository` discipline.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::events::PolicyScope;

use super::BoxFuture;

/// One row of the active-exclusions listing — a CVE waiver currently in
/// force on a policy.
#[derive(Debug, Clone, PartialEq)]
pub struct CurationExclusionEntry {
    pub exclusion_id: Uuid,
    pub policy_id: Uuid,
    pub cve_id: String,
    pub package_pattern: Option<String>,
    /// `None` when the projection row was authored by a system actor
    /// (rare — exclusions are operator-driven); use case surfaces the
    /// `Some` rows on the curator-actor filter when `Some(actor_id)`
    /// is supplied.
    pub added_by_actor_id: Option<Uuid>,
    pub reason: String,
    /// Pass-through from the projection — `Global` or `Repository(id)`.
    pub scope: PolicyScope,
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Query filter for [`CurationExclusionsRepository::list_exclusions`].
///
/// `limit` defaults to 100; the use case caps at 500.
#[derive(Debug, Clone, PartialEq)]
pub struct CurationExclusionFilter {
    pub policy_id: Option<Uuid>,
    pub cve_id: Option<String>,
    pub actor_id: Option<Uuid>,
    pub limit: u32,
}

impl Default for CurationExclusionFilter {
    fn default() -> Self {
        Self {
            policy_id: None,
            cve_id: None,
            actor_id: None,
            limit: 100,
        }
    }
}

/// Outbound port: paginated current-state of active exclusions.
///
/// **Item 5 stub.** Full body + Postgres adapter in Item 8. The trait
/// exists here so `CurationUseCase` can hold `Arc<dyn _>` one-shot.
pub trait CurationExclusionsRepository: Send + Sync {
    fn list_exclusions<'a>(
        &'a self,
        filter: CurationExclusionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationExclusionEntry>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn CurationExclusionsRepository>();
    }

    #[test]
    fn filter_default_uses_limit_100() {
        let f = CurationExclusionFilter::default();
        assert_eq!(f.limit, 100);
        assert!(f.policy_id.is_none());
        assert!(f.cve_id.is_none());
        assert!(f.actor_id.is_none());
    }
}
