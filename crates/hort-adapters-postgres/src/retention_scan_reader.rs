//! PostgreSQL adapter for [`RetentionScanReader`] — the read surface
//! the retention evaluator uses against the `scan_findings` and
//! `repo_security_scores` projections from migration 009.
//!
//! Implements the dedicated retention read port against the scan
//! projections.
//!
//! ## Projection precision
//!
//! `scan_findings` carries `fixed_versions` from migration 029, so the
//! retention evaluator can observe fix availability on rescanned
//! findings. Rows written before migration 029 read as an empty array
//! until rescan. `references` and `aliases` remain in the per-finding
//! CAS blob (`ScanCompleted.findings_blob`) and are empty here.
//!
//! ## The read answers about the artifact's LAST scan
//!
//! `scan_findings` is per-scan history: every run writes its rows under a
//! fresh `scan_id` and nothing removes the previous run's. A read filtered
//! on `artifact_id` alone therefore hands the retention evaluator the
//! union of every scan the artifact ever had — and that evaluator's
//! predicate drives an `ArtifactExpired`, i.e. a deletion. A
//! vulnerability a later scan no longer reports must drive no retention
//! decision, so the read is scoped: `sf.detected_at = a.last_scan_at`
//! selects exactly one scan's rows, since every row of one scan shares the
//! one `detected_at` the run was committed with.
//!
//! **The anchor is `artifacts.last_scan_at`.**
//! `PgArtifactLifecycle::commit_scan_result_with_score` writes that column
//! and inserts the per-finding rows in the SAME transaction, from the same
//! `DateTime<Utc>` the rows' `detected_at` is bound from, so the anchor
//! cannot disagree with the rows it selects. An anchor taken from inside
//! `scan_findings` — the newest `scan_id` present, say — would hand back
//! the previous, dirty run for an artifact whose latest scan found
//! nothing, because a clean scan writes no row. `last_scan_at` advances on
//! that clean run and matches nothing, which is the honest answer.
//!
//! This is **not** the freshness gate. That gate asks *is there a recent
//! enough scan at all*, answers it from the artifact's own event stream
//! (`RetentionUseCase::scan_is_fresh` in
//! `crates/hort-app/src/use_cases/retention_use_case.rs`), and is
//! unchanged: scoping the findings to the last scan says nothing about how
//! old that scan is.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::repo_security_score_repository::RepoSecurityScore;
use hort_domain::ports::retention_scan_reader::RetentionScanReader;
use hort_domain::types::{ComponentRelation, Finding, FindingStatement, SeverityBasis};

use crate::BoxFuture;

/// PostgreSQL adapter for [`RetentionScanReader`].
pub struct PgRetentionScanReader {
    pool: PgPool,
}

impl PgRetentionScanReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// sqlx row shape for the `scan_findings` projection columns this
/// reader consumes.
#[derive(sqlx::FromRow)]
struct FindingRow {
    purl: String,
    vulnerability_id: String,
    severity: String,
    cvss_score: Option<f32>,
    source_scanner: String,
    title: String,
    fixed_versions: Vec<String>,
    informational_class: Option<String>,
}

impl FindingRow {
    /// Map a projection row to the shipped [`Finding`] value type.
    /// `fixed_versions` comes from the projection; `references` and
    /// `aliases` are empty because they have no projection columns.
    /// `informational_class` is read from the persisted column (migration
    /// 015) so an exclusion-triggered re-evaluation reconstructs the same
    /// negligible-lane routing the original scan produced. An
    /// unrecognised `severity` literal is a corruption signal (the
    /// migration 009 CHECK constrains it to the four-value set); surface
    /// it loudly rather than guessing.
    fn into_domain(self) -> DomainResult<Finding> {
        let severity = SeverityThreshold::from_str(&self.severity).map_err(|_| {
            DomainError::Invariant(format!(
                "scan_findings.severity '{}' is outside the migration-009 \
                 CHECK set (critical|high|medium|low) — projection corruption",
                self.severity
            ))
        })?;
        Ok(Finding {
            purl: self.purl,
            vulnerability_id: self.vulnerability_id,
            severity,
            cvss_score: self.cvss_score,
            title: self.title,
            fixed_versions: self.fixed_versions,
            source_scanner: self.source_scanner,
            references: Vec::new(),
            aliases: Vec::new(),
            informational_class: self.informational_class,
            // The projection has no `severity_basis` column and does not
            // need one: the cross-backend merge runs over in-flight
            // backend output and the CAS `findings_blob`, never over these
            // rows. `Assessed` is the fail-safe reconstruction — it is the
            // same value `#[serde(default)]` yields for a record written
            // before the field existed, so a projection-sourced finding
            // behaves identically to a legacy blob-sourced one and is
            // never talked down by a lower reading.
            severity_basis: SeverityBasis::Assessed,
            // The projection has no column for the component relation
            // either, so it cannot be reconstructed from these rows.
            // `NotEstablished` is the honest reading — nothing here
            // established one — and the fail-closed one: the finding
            // keeps the release authority it has today.
            component_relation: ComponentRelation::NotEstablished,
            // Nor does it have one for what the finding's statement was
            // about. The statement *does* persist in the CAS
            // `findings_blob` — which is where every verdict path reads
            // its findings from — but this projection predates it and has
            // no column, so `Unstated` is the honest reading here and the
            // fail-closed one: nothing in these rows recorded a side, and
            // an unstated side condemns. The retention evaluator is the
            // only consumer of this port and takes no release decision,
            // so the reading costs nothing beyond what it says.
            statement: FindingStatement::Unstated,
        })
    }
}

/// sqlx row shape for the `repo_security_scores` columns the freshness
/// gate needs. Counts are `int4` (signed) in the migration; clamped to
/// `u32` at the boundary, mirroring the existing
/// `repo_security_score_repository` adapter.
#[derive(sqlx::FromRow)]
struct ScoreRow {
    repository_id: Uuid,
    quarantined_count: i32,
    rejected_count: i32,
    released_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    last_scan_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

fn clamp(v: i32) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

impl ScoreRow {
    fn into_domain(self) -> RepoSecurityScore {
        RepoSecurityScore {
            repository_id: self.repository_id,
            quarantined_count: clamp(self.quarantined_count),
            rejected_count: clamp(self.rejected_count),
            released_count: clamp(self.released_count),
            critical_count: clamp(self.critical_count),
            high_count: clamp(self.high_count),
            medium_count: clamp(self.medium_count),
            low_count: clamp(self.low_count),
            last_scan_at: self.last_scan_at,
            updated_at: self.updated_at,
        }
    }
}

impl RetentionScanReader for PgRetentionScanReader {
    fn list_findings_for_artifact(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Finding>>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, FindingRow>(
                r#"
                SELECT sf.purl, sf.vulnerability_id, sf.severity, sf.cvss_score,
                       sf.source_scanner, sf.title, sf.fixed_versions,
                       sf.informational_class
                FROM scan_findings sf
                JOIN artifacts a ON a.id = sf.artifact_id
                WHERE sf.artifact_id = $1
                  -- The last scan's rows and nothing else. See the module
                  -- docs: a predicate that drives a DELETE must not fire on
                  -- a vulnerability a later scan no longer reports.
                  AND sf.detected_at = a.last_scan_at
                -- `detected_at` is constant across one scan's rows, so the
                -- tiebreakers are what make the order deterministic. The
                -- evaluator is order-independent (max / any / len); a stable
                -- order is for the tests and for anyone reading a log.
                ORDER BY sf.detected_at ASC, sf.vulnerability_id ASC,
                         sf.purl ASC, sf.source_scanner ASC
                "#,
            )
            .bind(artifact_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("scan_findings list_for_artifact: {e}")))?;
            rows.into_iter()
                .map(FindingRow::into_domain)
                .collect::<DomainResult<Vec<_>>>()
        })
    }

    fn repo_security_score(
        &self,
        repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, ScoreRow>(
                r#"
                SELECT
                    repository_id,
                    quarantined_count, rejected_count, released_count,
                    critical_count, high_count, medium_count, low_count,
                    last_scan_at, updated_at
                FROM repo_security_scores
                WHERE repository_id = $1
                "#,
            )
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("repo_security_scores find: {e}")))?;
            Ok(row.map(ScoreRow::into_domain))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Compile-time assertion that the adapter implements the port.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: RetentionScanReader>() {}
        assert_impl::<PgRetentionScanReader>();
    }

    #[test]
    fn clamp_negative_goes_to_zero() {
        assert_eq!(clamp(-5), 0);
        assert_eq!(clamp(0), 0);
        assert_eq!(clamp(42), 42);
    }

    #[test]
    fn finding_row_maps_severity_and_projected_fix_versions() {
        let r = FindingRow {
            purl: "pkg:npm/x@1".into(),
            vulnerability_id: "CVE-1".into(),
            severity: "high".into(),
            cvss_score: Some(7.0),
            source_scanner: "trivy".into(),
            title: "t".into(),
            fixed_versions: vec!["1.2.3".into()],
            informational_class: None,
        };
        let f = r.into_domain().unwrap();
        assert_eq!(f.severity, SeverityThreshold::High);
        assert_eq!(f.cvss_score, Some(7.0));
        assert_eq!(f.fixed_versions, ["1.2.3"]);
        assert!(f.references.is_empty());
        assert!(f.aliases.is_empty());
        assert_eq!(f.informational_class, None);
        assert!(!f.is_informational());
    }

    #[test]
    fn finding_row_preserves_informational_class() {
        // The persisted `scan_findings.informational_class` column must
        // reach the reconstructed Finding verbatim so the negligible-lane
        // routing stays stable under re-evaluation — not hardcoded to NULL.
        let r = FindingRow {
            purl: "pkg:cargo/proc-macro-error@1.0.4".into(),
            vulnerability_id: "RUSTSEC-2024-0370".into(),
            severity: "low".into(),
            cvss_score: None,
            source_scanner: "osv".into(),
            title: "unmaintained".into(),
            fixed_versions: vec![],
            informational_class: Some("unmaintained".to_string()),
        };
        let f = r.into_domain().unwrap();
        assert_eq!(f.informational_class.as_deref(), Some("unmaintained"));
        assert!(f.is_informational());
    }

    #[test]
    fn finding_row_rejects_corrupt_severity_literal() {
        let r = FindingRow {
            purl: "pkg:npm/x@1".into(),
            vulnerability_id: "CVE-1".into(),
            severity: "nuclear".into(),
            cvss_score: None,
            source_scanner: "trivy".into(),
            title: "t".into(),
            fixed_versions: vec![],
            informational_class: None,
        };
        let err = r.into_domain().unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("projection corruption"));
    }

    #[test]
    fn score_row_into_domain_clamps_and_preserves_last_scan() {
        let now = Utc::now();
        let r = ScoreRow {
            repository_id: Uuid::nil(),
            quarantined_count: -3,
            rejected_count: 1,
            released_count: 2,
            critical_count: 0,
            high_count: 4,
            medium_count: 0,
            low_count: 0,
            last_scan_at: Some(now),
            updated_at: now,
        };
        let s = r.into_domain();
        assert_eq!(s.quarantined_count, 0);
        assert_eq!(s.rejected_count, 1);
        assert_eq!(s.high_count, 4);
        assert_eq!(s.last_scan_at, Some(now));
    }

    /// DB-backed: empty + populated `scan_findings` round-trip. Gated
    /// on `DATABASE_URL` so unit-only runs skip cleanly (mirrors
    /// `scan_findings_repository`'s integration-test gating).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_findings_round_trip_db() {
        let Some(pool) = crate::test_support::shared_migrated_pool().await else {
            return;
        };

        // Seed repo + artifact (FK: scan_findings.artifact_id →
        // artifacts(id); repo_security_scores.repository_id →
        // repositories(id)).
        let repo_id = Uuid::new_v4();
        let rkey = format!("it-retread-{}", repo_id.simple());
        sqlx::query(
            r#"INSERT INTO public.repositories (
                   id, key, name, format, repo_type, storage_backend,
                   storage_path, replication_priority
               ) VALUES ($1,$2,$3,'pypi'::repository_format,
                   'hosted'::repository_type,'filesystem',$4,
                   'local_only'::replication_priority)"#,
        )
        .bind(repo_id)
        .bind(&rkey)
        .bind(&rkey)
        .bind(format!("/tmp/{rkey}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        let artifact_id = Uuid::new_v4();
        let akey = artifact_id.simple().to_string();
        let sha = format!("{akey}{akey}");
        sqlx::query(
            r#"INSERT INTO public.artifacts (
                   id, repository_id, name, name_as_published, version,
                   path, size_bytes, checksum_sha256, content_type,
                   storage_key
               ) VALUES ($1,$2,'rr','rr','0.0.0',$3,0,$4,
                   'application/octet-stream',$3)"#,
        )
        .bind(artifact_id)
        .bind(repo_id)
        .bind(format!("simple/rr/{akey}.tgz"))
        .bind(&sha)
        .execute(&pool)
        .await
        .expect("seed artifact");

        let reader = PgRetentionScanReader::new(pool.clone());

        // Empty before any findings.
        assert!(reader
            .list_findings_for_artifact(artifact_id)
            .await
            .unwrap()
            .is_empty());
        // No score row yet.
        assert!(reader.repo_security_score(repo_id).await.unwrap().is_none());

        // One scan's two rows: a scored finding (no `informational_class`
        // column → relies on the nullable column reading back NULL) and an
        // informational one (explicit class, which must read back verbatim).
        //
        // ONE `scan_id` and ONE `detected_at`, paired with an
        // `artifacts.last_scan_at` carrying the same timestamp — the shape
        // `PgArtifactLifecycle::commit_scan_result_with_score` writes in a
        // single transaction, and the shape this reader's last-scan anchor
        // selects. Two rows under different `detected_at` values would be
        // two scans, which no single run produces.
        let scan_id = Uuid::new_v4();
        let detected_at = Utc::now();
        sqlx::query(
            r#"INSERT INTO scan_findings
               (artifact_id, scan_id, purl, vulnerability_id, severity,
                cvss_score, source_scanner, title, detected_at)
               VALUES ($1,$2,$3,'CVE-RR-1','critical',9.8,'trivy','t',$4)"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:pypi/rr-{}@1", artifact_id.simple()))
        .bind(detected_at)
        .execute(&pool)
        .await
        .expect("insert finding");
        sqlx::query(
            r#"INSERT INTO scan_findings
               (artifact_id, scan_id, purl, vulnerability_id, severity,
                cvss_score, source_scanner, title, detected_at, informational_class)
               VALUES ($1,$2,$3,'RUSTSEC-RR-2','low',NULL,'osv','unmaintained',
                       $4, 'unmaintained')"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:cargo/rr-info-{}@1", artifact_id.simple()))
        .bind(detected_at)
        .execute(&pool)
        .await
        .expect("insert informational finding");
        sqlx::query("UPDATE artifacts SET last_scan_at = $1 WHERE id = $2")
            .bind(detected_at)
            .bind(artifact_id)
            .execute(&pool)
            .await
            .expect("pair the rows with the last-scan anchor");
        sqlx::query(
            r#"INSERT INTO repo_security_scores
               (repository_id, released_count, critical_count, last_scan_at)
               VALUES ($1, 1, 1, now())"#,
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("insert score");

        let fs = reader
            .list_findings_for_artifact(artifact_id)
            .await
            .unwrap();
        assert_eq!(fs.len(), 2);

        // The scored finding read back: severity preserved,
        // informational_class NULL (no marker — a scored vulnerability).
        let scored = fs
            .iter()
            .find(|f| f.vulnerability_id == "CVE-RR-1")
            .expect("scored finding present");
        assert_eq!(scored.severity, SeverityThreshold::Critical);
        assert_eq!(scored.cvss_score, Some(9.8));
        assert!(scored.fixed_versions.is_empty());
        assert_eq!(scored.informational_class, None);
        assert!(!scored.is_informational());

        // The informational finding read back: the persisted class survives
        // the projection round-trip verbatim rather than reverting to NULL.
        let info = fs
            .iter()
            .find(|f| f.vulnerability_id == "RUSTSEC-RR-2")
            .expect("informational finding present");
        assert_eq!(info.informational_class.as_deref(), Some("unmaintained"));
        assert!(info.is_informational());

        let sc = reader.repo_security_score(repo_id).await.unwrap();
        let sc = sc.expect("score row now present");
        assert!(sc.last_scan_at.is_some());
        assert_eq!(sc.critical_count, 1);

        // Cleanup (CASCADE handles findings + scores).
        sqlx::query("DELETE FROM public.repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
