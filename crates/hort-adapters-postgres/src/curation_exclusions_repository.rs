//! PostgreSQL adapter for [`CurationExclusionsRepository`].
//!
//! Reads the §2.9 + §3 active-exclusions listing from the
//! `exclusion_projections` table (the same projection
//! `QuarantineUseCase::record_scan_result` consults at
//! `quarantine_use_case.rs:343`). The table gains two new columns
//! in this initiative:
//!
//! - `added_by_actor_id uuid` — envelope-side author attribution
//!   sourced from the `ExclusionAdded` event's persisted
//!   `actor_type='api'` / `actor_id` pair. `NULL` for non-api
//!   envelopes (system / timer / gitops).
//! - `added_at timestamp with time zone NOT NULL DEFAULT now()` —
//!   first-write timestamp, populated by the DB DEFAULT at INSERT
//!   time so the projector remains envelope-naive about the moment
//!   of attribution.
//!
//! Both columns are edited in place into the original
//! `005_policy.sql` `CREATE TABLE` statement (pre-1.0 migration
//! edit-in-place rule). Existing DBs must be re-migrated when the
//! file's checksum changes.
//!
//! ## Filters (design §3)
//!
//! - `policy_id: Option<Uuid>` — equality
//! - `cve_id: Option<String>` — equality on the canonical CVE id
//! - `actor_id: Option<Uuid>` — equality on `added_by_actor_id`;
//!   surfaces only rows whose envelope was an `api` actor with the
//!   given user_id
//! - `limit: u32` — capped at 500 defensively; the use case validates
//!   `> 500` as `AppError::Validation` (mirrors Item 6 / Item 7)
//!
//! ## Ordering
//!
//! `ORDER BY added_at DESC, exclusion_id` — newest first, then a
//! deterministic tiebreak so re-runs produce stable orderings.
//!
//! ## DTO discipline (port docs)
//!
//! `CurationExclusionEntry` does NOT derive `Serialize` — DTO
//! crossing the HTTP boundary lives in `hort-http-admin-curation`
//! (Item 9), not the domain layer.
//!
//! See `docs/architecture/how-to/curator-workflow.md` for operator guidance.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::PolicyScope;
use hort_domain::ports::curation_exclusions_repository::{
    CurationExclusionEntry, CurationExclusionFilter, CurationExclusionsRepository,
};

use crate::BoxFuture;

/// `limit` hard cap — capped at 500 defensively. The use case validates
/// `> 500` as `AppError::Validation`; the adapter still clamps so a
/// bypass cannot drag the DB through a 10k-row scan.
const MAX_LIMIT: u32 = 500;

/// PostgreSQL adapter for the active-exclusions listing.
pub struct PgCurationExclusionsRepository {
    pool: PgPool,
}

impl PgCurationExclusionsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CurationExclusionsRepository for PgCurationExclusionsRepository {
    fn list_exclusions<'a>(
        &'a self,
        filter: CurationExclusionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationExclusionEntry>>> {
        Box::pin(async move {
            // Defensive clamp (use case already validates > 500 →
            // Validation). Same pattern as Item 6 / Item 7.
            let limit = filter.limit.min(MAX_LIMIT);

            // Parameters:
            //   $1 = Option<Uuid>  policy_id filter
            //   $2 = Option<&str>  cve_id filter
            //   $3 = Option<Uuid>  actor_id filter (matched against added_by_actor_id)
            //   $4 = i64           limit
            let rows = sqlx::query(
                r#"
                SELECT exclusion_id,
                       policy_id,
                       cve_id,
                       package_pattern,
                       added_by_actor_id,
                       reason,
                       scope,
                       added_at,
                       expires_at
                FROM exclusion_projections
                WHERE ($1::uuid IS NULL OR policy_id = $1)
                  AND ($2::text IS NULL OR cve_id = $2)
                  AND ($3::uuid IS NULL OR added_by_actor_id = $3)
                ORDER BY added_at DESC, exclusion_id
                LIMIT $4
                "#,
            )
            .bind(filter.policy_id)
            .bind(filter.cve_id.as_deref())
            .bind(filter.actor_id)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("curation_exclusions_repo list: {e}")))?;

            rows.iter().map(row_to_entry).collect()
        })
    }
}

/// Map one row of `exclusion_projections` to a domain entry. The
/// `scope` JSONB column decodes via serde — a corrupt row surfaces as
/// `DomainError::Invariant` (mirrors `policy_projection_repo`'s
/// `row_to_exclusion`).
fn row_to_entry(row: &sqlx::postgres::PgRow) -> DomainResult<CurationExclusionEntry> {
    let exclusion_id: Uuid = row.try_get("exclusion_id").map_err(|e| decode_err(&e))?;
    let policy_id: Uuid = row.try_get("policy_id").map_err(|e| decode_err(&e))?;
    let cve_id: String = row.try_get("cve_id").map_err(|e| decode_err(&e))?;
    let package_pattern: Option<String> =
        row.try_get("package_pattern").map_err(|e| decode_err(&e))?;
    let added_by_actor_id: Option<Uuid> = row
        .try_get("added_by_actor_id")
        .map_err(|e| decode_err(&e))?;
    let reason: String = row.try_get("reason").map_err(|e| decode_err(&e))?;
    let scope_json: serde_json::Value = row.try_get("scope").map_err(|e| decode_err(&e))?;
    let scope: PolicyScope = serde_json::from_value(scope_json).map_err(|e| {
        DomainError::Invariant(format!(
            "exclusion_projections.scope does not decode to PolicyScope: {e}"
        ))
    })?;
    let added_at: DateTime<Utc> = row.try_get("added_at").map_err(|e| decode_err(&e))?;
    let expires_at: Option<DateTime<Utc>> =
        row.try_get("expires_at").map_err(|e| decode_err(&e))?;

    Ok(CurationExclusionEntry {
        exclusion_id,
        policy_id,
        cve_id,
        package_pattern,
        added_by_actor_id,
        reason,
        scope,
        added_at,
        expires_at,
    })
}

fn decode_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(
        entity = "curation_exclusion",
        error = %e,
        "row decode failed"
    );
    DomainError::Invariant(format!("curation_exclusions_repo row decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    /// Mirrors the convention in Item 6 / Item 7.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: CurationExclusionsRepository>() {}
        assert_impl::<PgCurationExclusionsRepository>();
    }

    /// The adapter's hard cap matches the design's documented value
    /// (mirrors Items 6 / 7 — single canonical limit across the
    /// three §2.9 listings).
    #[test]
    fn max_limit_matches_design() {
        assert_eq!(MAX_LIMIT, 500);
    }
}
