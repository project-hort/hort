//! PostgreSQL adapter for [`PatchCandidateRepository`].
//!
//! Executes the §3.2 query against the live `artifacts`, `repositories`,
//! and `scan_findings` tables and maps the row shape onto the domain
//! [`PatchCandidate`] DTO. The severity-rank `i16` produced by the
//! LATERAL subquery is adapter-private (§3.1 "Adapter responsibility
//! for severity-rank mapping") — the trait surface returns
//! `Option<SeverityThreshold>` and the integer never leaves this
//! module.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::patch_candidate_repository::{
    PatchCandidate, PatchCandidateFilter, PatchCandidateRepository,
};

use crate::BoxFuture;

/// PostgreSQL adapter for the patch-candidate surface.
pub struct PgPatchCandidateRepository {
    pool: PgPool,
}

impl PgPatchCandidateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl PatchCandidateRepository for PgPatchCandidateRepository {
    fn list_candidates<'a>(
        &'a self,
        filter: PatchCandidateFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<PatchCandidate>>> {
        Box::pin(async move {
            // The query in design-doc §3.2 — `repository_key` projected
            // per §3.4 ("adapter, not use case, resolves the
            // human-readable repository key"). `r.format::text` casts
            // the ENUM to TEXT so sqlx reads it as `String` (the
            // established pattern in `mappers.rs:35,67`). The cast on
            // `r.format::text <> 'oci'` mirrors the same idiom so the
            // outer filter compares against the ENUM's text form.
            //
            // `$1` is `Option<Uuid>` for the optional repo filter; sqlx
            // binds `None` to SQL NULL natively. `$2` is `i64` for the
            // LIMIT — the use case caps `filter.limit` at 500 so the
            // `i64::from(u32)` widening cannot overflow.
            let rows = sqlx::query_as::<_, PatchCandidateRow>(
                r#"
                SELECT
                    q.id                AS quarantined_artifact_id,
                    q.version           AS quarantined_version,
                    q.quarantine_status       AS quarantined_status,
                    q.quarantine_window_start AS quarantined_until,
                    q.repository_id     AS repository_id,
                    r.key               AS repository_key,
                    r.format::text      AS format,
                    q.name              AS package_name,
                    v.id                AS vulnerable_artifact_id,
                    v.version           AS vulnerable_version,
                    f.finding_count     AS vulnerable_finding_count,
                    f.max_severity_rank AS vulnerable_max_severity_rank
                FROM artifacts q
                JOIN repositories r ON r.id = q.repository_id
                JOIN artifacts v
                  ON v.repository_id = q.repository_id
                 AND v.name = q.name
                 AND v.id <> q.id
                 AND v.is_deleted = false
                 AND v.quarantine_status = 'released'
                 AND v.created_at < q.created_at
                JOIN LATERAL (
                    SELECT COUNT(*)::bigint AS finding_count,
                           MAX(CASE sf.severity
                                   WHEN 'critical' THEN 4
                                   WHEN 'high'     THEN 3
                                   WHEN 'medium'   THEN 2
                                   WHEN 'low'      THEN 1
                                   ELSE 0
                               END)::int2 AS max_severity_rank
                    FROM scan_findings sf
                    WHERE sf.artifact_id = v.id
                ) f ON f.finding_count > 0
                WHERE q.quarantine_status = 'quarantined'
                  AND q.is_deleted = false
                  AND r.format::text <> 'oci'
                  AND ($1::uuid IS NULL OR q.repository_id = $1)
                ORDER BY f.max_severity_rank DESC, q.created_at DESC
                LIMIT $2
                "#,
            )
            .bind(filter.repository_id)
            .bind(i64::from(filter.limit))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("patch_candidate_repo list: {e}")))?;

            rows.into_iter()
                .map(PatchCandidateRow::into_domain)
                .collect()
        })
    }
}

/// sqlx FromRow shape mirroring the §3.2 projection.
///
/// `quarantined_status` is read as `Option<String>` because the
/// underlying column is `varchar(20) NULL` per migration 003. The §3.2
/// outer filter pins it to the literal `'quarantined'`, but the
/// adapter still parses through [`QuarantineStatus::from_str`] to keep
/// the mapping semantically honest — a future migration that loosens
/// the outer filter would otherwise silently hardcode `Quarantined`
/// here.
#[derive(sqlx::FromRow)]
struct PatchCandidateRow {
    quarantined_artifact_id: Uuid,
    quarantined_version: Option<String>,
    quarantined_status: Option<String>,
    quarantined_until: Option<DateTime<Utc>>,
    repository_id: Uuid,
    repository_key: String,
    format: String,
    package_name: String,
    vulnerable_artifact_id: Uuid,
    vulnerable_version: Option<String>,
    vulnerable_finding_count: i64,
    vulnerable_max_severity_rank: i16,
}

impl PatchCandidateRow {
    fn into_domain(self) -> DomainResult<PatchCandidate> {
        // The §3.2 outer filter pins this to `'quarantined'`, but the
        // mapper parses through `from_str` so a future loosened filter
        // surfaces drift as `DomainError::Invariant` (mirrors the
        // strict mapper convention from `mappers.rs:UserRow`).
        //
        // The `None` arm is **defence-in-depth**, not currently
        // reachable: the §3.2 WHERE clause forces
        // `q.quarantine_status = 'quarantined'` (a non-NULL literal),
        // so a NULL value cannot land in this column today. The arm
        // exists because the schema permits NULL and a future relaxed
        // filter (e.g. `IN ('quarantined','pending')` or removing the
        // predicate entirely) would expose the column to NULL rows —
        // we want the mapper to fail loudly rather than silently
        // produce a misleading status. Do not remove this arm without
        // first making the SQL predicate enforce non-NULL another way.
        let quarantined_status = match self.quarantined_status.as_deref() {
            Some(s) => s.parse::<QuarantineStatus>().map_err(|_| {
                DomainError::Invariant(format!(
                    "unknown quarantine_status in patch_candidate_repo row: {s}"
                ))
            })?,
            None => {
                return Err(DomainError::Invariant(format!(
                    "patch_candidate_repo row {} has NULL quarantine_status",
                    self.quarantined_artifact_id
                )));
            }
        };

        // `RepositoryFormat::from_str` is infallible — unknown literals
        // round-trip as `Other(s)`. The §3.2 SQL filter excludes
        // `'oci'`, so the row mapper never sees `RepositoryFormat::Oci`
        // out of this query. Mirror `mappers.rs:67` for the fallback.
        let format: RepositoryFormat = self.format.parse().unwrap_or(RepositoryFormat::Generic);

        Ok(PatchCandidate {
            quarantined_artifact_id: self.quarantined_artifact_id,
            quarantined_version: self.quarantined_version,
            quarantined_status,
            quarantined_until: self.quarantined_until,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            format,
            package_name: self.package_name,
            vulnerable_artifact_id: self.vulnerable_artifact_id,
            vulnerable_version: self.vulnerable_version,
            vulnerable_finding_count: i64_finding_count_to_u32(self.vulnerable_finding_count),
            vulnerable_max_severity: severity_from_rank(self.vulnerable_max_severity_rank),
        })
    }
}

/// Anchors the round-trip test that guards the SQL `CASE` expression
/// against drift. **No production caller** — the SQL inlines the
/// equivalent computation. Deleting this helper means deleting
/// [`tests::severity_round_trip_all_variants`] as well, since the
/// round-trip is the contract that pins [`severity_from_rank`] to the
/// same mapping the query uses.
///
/// Renders a [`SeverityThreshold`] as the integer rank used by the §3.2
/// LATERAL subquery (`critical=4, high=3, medium=2, low=1`).
///
/// Adapter-private (not `pub`) per design §3.1 "Adapter responsibility
/// for severity-rank mapping" — the rank never leaves this module. A
/// future code path that needs to bind a rank as a query parameter has
/// the canonical mapping here as well.
#[allow(dead_code)] // SQL hard-codes the forward direction; helper anchors the round-trip test.
fn severity_rank(s: SeverityThreshold) -> i16 {
    match s {
        SeverityThreshold::Critical => 4,
        SeverityThreshold::High => 3,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::Low => 1,
    }
}

/// Inverse of [`severity_rank`]. `0` (the LATERAL `ELSE 0` branch when
/// no findings exist) and any value outside `1..=4` map to `None`
/// rather than panicking — defensive against migration drift in a
/// future rank computation.
///
/// In practice the §3.2 query's `f.finding_count > 0` LATERAL filter
/// prevents `0` from surfacing. The `None` arm exists at the type
/// level so a buggy rank in the future cannot crash the read path.
fn severity_from_rank(r: i16) -> Option<SeverityThreshold> {
    match r {
        4 => Some(SeverityThreshold::Critical),
        3 => Some(SeverityThreshold::High),
        2 => Some(SeverityThreshold::Medium),
        1 => Some(SeverityThreshold::Low),
        _ => None,
    }
}

/// Clamp a SQL `bigint COUNT(*)` to the domain's `u32` finding-count
/// field. Negative counts are SQL-impossible but the clamp lives here
/// for symmetry with [`crate::repo_security_score_repository`]'s
/// `i32_to_u32_clamp_zero`. Counts beyond `u32::MAX` saturate.
fn i64_finding_count_to_u32(v: i64) -> u32 {
    if v < 0 {
        0
    } else {
        u32::try_from(v).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    /// Mirrors the convention in
    /// `repo_security_score_repository::tests::pg_adapter_implements_port`.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: PatchCandidateRepository>() {}
        assert_impl::<PgPatchCandidateRepository>();
    }

    // -- severity_rank --------------------------------------------------------

    #[test]
    fn severity_rank_critical_is_four() {
        assert_eq!(severity_rank(SeverityThreshold::Critical), 4);
    }

    #[test]
    fn severity_rank_high_is_three() {
        assert_eq!(severity_rank(SeverityThreshold::High), 3);
    }

    #[test]
    fn severity_rank_medium_is_two() {
        assert_eq!(severity_rank(SeverityThreshold::Medium), 2);
    }

    #[test]
    fn severity_rank_low_is_one() {
        assert_eq!(severity_rank(SeverityThreshold::Low), 1);
    }

    // -- severity_from_rank ---------------------------------------------------

    #[test]
    fn severity_from_rank_zero_is_none() {
        // The §3.2 LATERAL `ELSE 0` branch. The `finding_count > 0`
        // filter should keep this out of the result set, but the
        // mapper is defensive — return `None` rather than panic.
        assert_eq!(severity_from_rank(0), None);
    }

    #[test]
    fn severity_from_rank_one_is_low() {
        assert_eq!(severity_from_rank(1), Some(SeverityThreshold::Low));
    }

    #[test]
    fn severity_from_rank_two_is_medium() {
        assert_eq!(severity_from_rank(2), Some(SeverityThreshold::Medium));
    }

    #[test]
    fn severity_from_rank_three_is_high() {
        assert_eq!(severity_from_rank(3), Some(SeverityThreshold::High));
    }

    #[test]
    fn severity_from_rank_four_is_critical() {
        assert_eq!(severity_from_rank(4), Some(SeverityThreshold::Critical));
    }

    #[test]
    fn severity_from_rank_negative_is_none() {
        assert_eq!(severity_from_rank(-1), None);
        assert_eq!(severity_from_rank(i16::MIN), None);
    }

    #[test]
    fn severity_from_rank_above_four_is_none() {
        assert_eq!(severity_from_rank(5), None);
        assert_eq!(severity_from_rank(99), None);
        assert_eq!(severity_from_rank(i16::MAX), None);
    }

    /// Round-trip: every variant survives rank-then-unrank.
    #[test]
    fn severity_round_trip_all_variants() {
        for v in [
            SeverityThreshold::Critical,
            SeverityThreshold::High,
            SeverityThreshold::Medium,
            SeverityThreshold::Low,
        ] {
            assert_eq!(severity_from_rank(severity_rank(v)), Some(v));
        }
    }

    // -- i64_finding_count_to_u32 -------------------------------------------

    #[test]
    fn finding_count_zero_round_trips() {
        assert_eq!(i64_finding_count_to_u32(0), 0);
    }

    #[test]
    fn finding_count_positive_round_trips() {
        assert_eq!(i64_finding_count_to_u32(1), 1);
        assert_eq!(i64_finding_count_to_u32(42), 42);
        assert_eq!(i64_finding_count_to_u32(i64::from(u32::MAX)), u32::MAX);
    }

    #[test]
    fn finding_count_negative_clamps_to_zero() {
        assert_eq!(i64_finding_count_to_u32(-1), 0);
        assert_eq!(i64_finding_count_to_u32(i64::MIN), 0);
    }

    #[test]
    fn finding_count_above_u32_max_saturates() {
        // u32::MAX is 4_294_967_295. i64::MAX is well above it.
        assert_eq!(i64_finding_count_to_u32(i64::from(u32::MAX) + 1), u32::MAX);
        assert_eq!(i64_finding_count_to_u32(i64::MAX), u32::MAX);
    }
}
