//! PostgreSQL adapter for [`CompositeScanObservationRepository`] — the
//! `composite_scan_observations` projection from migration 032.
//!
//! One row per manifest artifact, replaced on each assessment: the write
//! is an `INSERT … ON CONFLICT (artifact_id) DO UPDATE`, so a rescan
//! overwrites rather than accumulating. See the port's module docs for
//! why this is a projection and not an event.
//!
//! The row is validated before it is bound. The column CHECKs in
//! migration 032 restate the domain's caps, and a write that would trip
//! one should fail with the domain's own message rather than a
//! constraint name.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::SeveritySummary;
use hort_domain::ports::composite_scan_observation::{
    AcquisitionCost, CompositeAssessment, CompositeScanObservation,
    CompositeScanObservationRepository, GateDecision,
};

use crate::{map_sqlx_error, BoxFuture};

/// The entity label on every mapped SQL error from this adapter.
const ENTITY: &str = "composite_scan_observation";

/// PostgreSQL adapter for the `composite_scan_observations` projection.
pub struct PgCompositeScanObservationRepository {
    pool: PgPool,
}

impl PgCompositeScanObservationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Bind a domain `u32` count as the `BIGINT` the column holds. Total:
/// every `u32` fits an `i64`, and the column's CHECK restates the same
/// ceiling.
fn count(v: u32) -> i64 {
    i64::from(v)
}

/// Decode one column, naming it in the error.
///
/// One helper rather than a `map_err` per column: twenty copies of a
/// message that differs only in a string literal is twenty chances for
/// the literal and the column it is about to drift apart, and the row
/// has twenty columns.
fn column<'r, T>(row: &'r PgRow, name: &'static str) -> DomainResult<T>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|e| DomainError::Invariant(format!("composite_scan_observations.{name}: {e}")))
}

/// Decode a `BIGINT` count column as the `u32` the domain carries.
///
/// The column's CHECK bounds it to `[0, u32::MAX]`, so a value outside
/// that range is a row no writer of this table produced — refused rather
/// than clamped, because a silently-clamped count is a wrong answer to
/// the promotion question that reads as a right one.
fn count_column(row: &PgRow, name: &'static str) -> DomainResult<u32> {
    let raw: i64 = column(row, name)?;
    u32::try_from(raw).map_err(|_| {
        DomainError::Invariant(format!(
            "composite_scan_observations.{name} holds {raw}, which is outside the u32 range the \
             column's CHECK permits"
        ))
    })
}

impl CompositeScanObservationRepository for PgCompositeScanObservationRepository {
    fn record<'a>(
        &'a self,
        observation: &'a CompositeScanObservation,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            observation.validate()?;
            let fetched_bytes = i64::try_from(observation.cost.fetched_bytes).map_err(|_| {
                DomainError::Invariant(format!(
                    "composite observation: fetched_bytes {} exceeds what the column holds",
                    observation.cost.fetched_bytes
                ))
            })?;
            sqlx::query(
                r#"
                INSERT INTO composite_scan_observations (
                    artifact_id, repository_id, manifest_digest, scanner, observed_at,
                    assessment, reason,
                    already_present, fetched, fetched_bytes,
                    severity_critical, severity_high, severity_medium,
                    severity_low, severity_negligible,
                    finding_count, distinct_vulnerability_count, vulnerability_ids,
                    composite_findings_decision, primary_findings_decision
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7,
                    $8, $9, $10,
                    $11, $12, $13,
                    $14, $15,
                    $16, $17, $18,
                    $19, $20
                )
                ON CONFLICT (artifact_id) DO UPDATE SET
                    repository_id   = EXCLUDED.repository_id,
                    manifest_digest = EXCLUDED.manifest_digest,
                    scanner         = EXCLUDED.scanner,
                    observed_at     = EXCLUDED.observed_at,
                    assessment      = EXCLUDED.assessment,
                    reason          = EXCLUDED.reason,
                    already_present = EXCLUDED.already_present,
                    fetched         = EXCLUDED.fetched,
                    fetched_bytes   = EXCLUDED.fetched_bytes,
                    severity_critical   = EXCLUDED.severity_critical,
                    severity_high       = EXCLUDED.severity_high,
                    severity_medium     = EXCLUDED.severity_medium,
                    severity_low        = EXCLUDED.severity_low,
                    severity_negligible = EXCLUDED.severity_negligible,
                    finding_count                = EXCLUDED.finding_count,
                    distinct_vulnerability_count = EXCLUDED.distinct_vulnerability_count,
                    vulnerability_ids            = EXCLUDED.vulnerability_ids,
                    composite_findings_decision = EXCLUDED.composite_findings_decision,
                    primary_findings_decision   = EXCLUDED.primary_findings_decision
                "#,
            )
            .bind(observation.artifact_id)
            .bind(observation.repository_id)
            .bind(observation.manifest_digest.to_string())
            .bind(observation.scanner.as_deref())
            .bind(observation.observed_at)
            .bind(observation.assessment.as_str())
            .bind(observation.reason.as_deref())
            .bind(count(observation.cost.already_present))
            .bind(count(observation.cost.fetched))
            .bind(fetched_bytes)
            .bind(count(observation.severity_summary.critical))
            .bind(count(observation.severity_summary.high))
            .bind(count(observation.severity_summary.medium))
            .bind(count(observation.severity_summary.low))
            .bind(count(observation.severity_summary.negligible))
            .bind(count(observation.finding_count))
            .bind(count(observation.distinct_vulnerability_count))
            .bind(&observation.vulnerability_ids)
            .bind(
                observation
                    .composite_findings_decision
                    .as_ref()
                    .map(GateDecision::as_str),
            )
            .bind(observation.primary_findings_decision.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, ENTITY, &observation.artifact_id.to_string()))?;
            Ok(())
        })
    }

    fn find_by_artifact(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<CompositeScanObservation>>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT artifact_id, repository_id, manifest_digest, scanner, observed_at,
                       assessment, reason,
                       already_present, fetched, fetched_bytes,
                       severity_critical, severity_high, severity_medium,
                       severity_low, severity_negligible,
                       finding_count, distinct_vulnerability_count, vulnerability_ids,
                       composite_findings_decision, primary_findings_decision
                  FROM composite_scan_observations
                 WHERE artifact_id = $1
                "#,
            )
            .bind(artifact_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, ENTITY, &artifact_id.to_string()))?;

            let Some(row) = row else {
                return Ok(None);
            };

            let digest: String = column(&row, "manifest_digest")?;
            let assessment: String = column(&row, "assessment")?;
            let composite_findings_decision: Option<String> =
                column(&row, "composite_findings_decision")?;
            let primary_findings_decision: String = column(&row, "primary_findings_decision")?;
            let fetched_bytes: i64 = column(&row, "fetched_bytes")?;

            Ok(Some(CompositeScanObservation {
                artifact_id,
                repository_id: column(&row, "repository_id")?,
                manifest_digest: digest.trim().parse().map_err(|e| {
                    DomainError::Invariant(format!(
                        "composite_scan_observations.manifest_digest is not a content hash: {e}"
                    ))
                })?,
                scanner: column(&row, "scanner")?,
                observed_at: column::<DateTime<Utc>>(&row, "observed_at")?,
                assessment: CompositeAssessment::parse(&assessment)?,
                reason: column(&row, "reason")?,
                cost: AcquisitionCost {
                    already_present: count_column(&row, "already_present")?,
                    fetched: count_column(&row, "fetched")?,
                    fetched_bytes: u64::try_from(fetched_bytes).map_err(|_| {
                        DomainError::Invariant(format!(
                            "composite_scan_observations.fetched_bytes holds {fetched_bytes}, \
                             which its non-negative CHECK does not permit"
                        ))
                    })?,
                },
                severity_summary: SeveritySummary {
                    critical: count_column(&row, "severity_critical")?,
                    high: count_column(&row, "severity_high")?,
                    medium: count_column(&row, "severity_medium")?,
                    low: count_column(&row, "severity_low")?,
                    negligible: count_column(&row, "severity_negligible")?,
                },
                finding_count: count_column(&row, "finding_count")?,
                distinct_vulnerability_count: count_column(&row, "distinct_vulnerability_count")?,
                vulnerability_ids: column(&row, "vulnerability_ids")?,
                composite_findings_decision: composite_findings_decision
                    .as_deref()
                    .map(GateDecision::parse)
                    .transpose()?,
                primary_findings_decision: GateDecision::parse(&primary_findings_decision)?,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The domain carries `u32` counts and the column is a `BIGINT`
    /// whose CHECK restates that range, so the widening is total.
    #[test]
    fn every_u32_count_widens_to_the_column() {
        for v in [0u32, 1, u32::MAX] {
            assert_eq!(count(v), i64::from(v));
        }
    }
}
