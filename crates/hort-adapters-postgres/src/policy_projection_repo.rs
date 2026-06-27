//! PostgreSQL adapter for [`PolicyProjectionRepository`].
//!
//! Backed by `policy_projections` + `exclusion_projections` (migration
//! 095). Reads are covered by the active-name + policy-id partial
//! indexes; writes are `ON CONFLICT (...) DO UPDATE` upserts paired
//! with `ExpectedVersion::Exact` on the event-store side so a
//! concurrent imperative-API write between projection-read and
//! event-append surfaces as `ConcurrentModification`.
//!
//! `PolicyScope` round-trips through JSONB via serde — the column
//! shape is `"Global"` for the unit variant and
//! `{"Repository": "<uuid>"}` for the tuple variant. Decode failures
//! surface as [`DomainError::Invariant`] (the table is gitops-managed;
//! corrupt JSON is a bug, not a request error).
//!
//! Tracing per CLAUDE.md observability rules: every read logs at
//! `debug!` with `entity = "scan_policy"` and the lookup key (`name`
//! or `id`); unexpected sqlx errors log at `warn!`. We never log SQL
//! text or bind values.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::entities::scan_policy::{
    ExclusionProjection, NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    SignerIdentityPattern,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::PolicyScope;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;

use crate::BoxFuture;
use std::str::FromStr;

/// PostgreSQL implementation of [`PolicyProjectionRepository`].
///
/// Thin wrapper over a [`PgPool`]. Construction is cheap; the pool
/// itself governs connection lifecycle.
pub struct PgPolicyProjectionRepository {
    pool: PgPool,
}

impl PgPolicyProjectionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Row → domain mapping
// ---------------------------------------------------------------------------

fn row_to_projection(row: &sqlx::postgres::PgRow) -> DomainResult<ScanPolicyProjection> {
    let policy_id: Uuid = row.try_get("policy_id").map_err(|e| map_row_err(&e))?;
    let name: String = row.try_get("name").map_err(|e| map_row_err(&e))?;
    let scope_json: serde_json::Value = row.try_get("scope").map_err(|e| map_row_err(&e))?;
    let scope: PolicyScope = serde_json::from_value(scope_json).map_err(|e| {
        DomainError::Invariant(format!(
            "policy_projections.scope does not decode to PolicyScope: {e}"
        ))
    })?;
    let severity_str: String = row
        .try_get("severity_threshold")
        .map_err(|e| map_row_err(&e))?;
    let severity_threshold = SeverityThreshold::from_str(&severity_str)?;
    let quarantine_duration_secs: i64 = row
        .try_get("quarantine_duration_secs")
        .map_err(|e| map_row_err(&e))?;
    let require_approval: bool = row
        .try_get("require_approval")
        .map_err(|e| map_row_err(&e))?;
    // `provenance_mode` is a CHECK-constrained text column decoded via
    // the domain `FromStr` (a value outside the three variants is a
    // corrupt-row invariant violation, not a request error).
    let provenance_mode_str: String = row
        .try_get("provenance_mode")
        .map_err(|e| map_row_err(&e))?;
    let provenance_mode = ProvenanceMode::from_str(&provenance_mode_str).map_err(|e| {
        DomainError::Invariant(format!(
            "policy_projections.provenance_mode does not decode to ProvenanceMode: {e}"
        ))
    })?;
    // `provenance_backends` is `text[] NOT NULL DEFAULT {cosign}` — same
    // representation as `scan_backends`.
    let provenance_backends: Vec<String> = row
        .try_get("provenance_backends")
        .map_err(|e| map_row_err(&e))?;
    // `provenance_identities` is a JSONB array of `{issuer, san}` objects.
    let provenance_identities_json: serde_json::Value = row
        .try_get("provenance_identities")
        .map_err(|e| map_row_err(&e))?;
    let provenance_identities: Vec<SignerIdentityPattern> =
        serde_json::from_value(provenance_identities_json).map_err(|e| {
            DomainError::Invariant(format!(
                "policy_projections.provenance_identities does not decode to \
                 Vec<SignerIdentityPattern>: {e}"
            ))
        })?;
    let max_artifact_age_secs: Option<i64> = row
        .try_get("max_artifact_age_secs")
        .map_err(|e| map_row_err(&e))?;
    let license_policy: serde_json::Value =
        row.try_get("license_policy").map_err(|e| map_row_err(&e))?;
    let archived: bool = row.try_get("archived").map_err(|e| map_row_err(&e))?;
    // Read the scanner backend list. The column is `text[] NOT NULL`
    // with a `{trivy}` default so a row written before this column
    // existed would surface as Trivy-only after the migration upgrade —
    // matching `DefaultPolicy::block_on_critical_default_backends`.
    let scan_backends: Vec<String> = row.try_get("scan_backends").map_err(|e| map_row_err(&e))?;
    // Interval (hours) between bulk re-scans. The column is
    // `integer NOT NULL DEFAULT 24` so any row written before this
    // column existed surfaces as the documented default (matching
    // `DefaultPolicy::rescan_interval_hours`).
    let rescan_interval_hours: i32 = row
        .try_get("rescan_interval_hours")
        .map_err(|e| map_row_err(&e))?;
    // `negligible_action` is a CHECK-constrained text column decoded via
    // the domain `FromStr`. The column is `text NOT NULL DEFAULT
    // 'ignore'`, so any row written before this column existed surfaces
    // as Ignore (the non-blocking pre-knob behaviour). A value outside
    // the three variants is a corrupt-row invariant violation.
    let negligible_action_str: String = row
        .try_get("negligible_action")
        .map_err(|e| map_row_err(&e))?;
    let negligible_action = NegligibleAction::from_str(&negligible_action_str).map_err(|e| {
        DomainError::Invariant(format!(
            "policy_projections.negligible_action does not decode to NegligibleAction: {e}"
        ))
    })?;
    let stream_version_i64: i64 = row.try_get("stream_version").map_err(|e| map_row_err(&e))?;
    let stream_version = u64::try_from(stream_version_i64).map_err(|_| {
        DomainError::Invariant(format!(
            "policy_projections.stream_version is negative: {stream_version_i64}"
        ))
    })?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(|e| map_row_err(&e))?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(|e| map_row_err(&e))?;
    Ok(ScanPolicyProjection {
        policy_id,
        name,
        scope,
        severity_threshold,
        quarantine_duration_secs,
        require_approval,
        provenance_mode,
        provenance_backends,
        provenance_identities,
        max_artifact_age_secs,
        license_policy,
        archived,
        scan_backends,
        rescan_interval_hours,
        negligible_action,
        stream_version,
        created_at,
        updated_at,
    })
}

fn row_to_exclusion(row: &sqlx::postgres::PgRow) -> DomainResult<ExclusionProjection> {
    let exclusion_id: Uuid = row.try_get("exclusion_id").map_err(|e| map_row_err(&e))?;
    let policy_id: Uuid = row.try_get("policy_id").map_err(|e| map_row_err(&e))?;
    let cve_id: String = row.try_get("cve_id").map_err(|e| map_row_err(&e))?;
    let package_pattern: Option<String> = row
        .try_get("package_pattern")
        .map_err(|e| map_row_err(&e))?;
    let scope_json: serde_json::Value = row.try_get("scope").map_err(|e| map_row_err(&e))?;
    let scope: PolicyScope = serde_json::from_value(scope_json).map_err(|e| {
        DomainError::Invariant(format!(
            "exclusion_projections.scope does not decode to PolicyScope: {e}"
        ))
    })?;
    let reason: String = row.try_get("reason").map_err(|e| map_row_err(&e))?;
    // `added_by_actor_id` is nullable (system / gitops / timer
    // envelopes leave it NULL).
    let added_by_actor_id: Option<Uuid> = row
        .try_get("added_by_actor_id")
        .map_err(|e| map_row_err(&e))?;
    let expires_at: Option<DateTime<Utc>> =
        row.try_get("expires_at").map_err(|e| map_row_err(&e))?;
    Ok(ExclusionProjection {
        exclusion_id,
        policy_id,
        cve_id,
        package_pattern,
        scope,
        reason,
        added_by_actor_id,
        expires_at,
    })
}

fn map_row_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(entity = "scan_policy", error = %e, "row decode failed");
    DomainError::Invariant(format!("policy_projections row decode: {e}"))
}

fn map_query_err(e: &sqlx::Error, op: &'static str) -> DomainError {
    tracing::warn!(entity = "scan_policy", op, error = %e, "query failed");
    DomainError::Invariant(format!("policy_projections {op}: {e}"))
}

fn encode_scope(scope: &PolicyScope) -> DomainResult<serde_json::Value> {
    serde_json::to_value(scope)
        .map_err(|e| DomainError::Invariant(format!("PolicyScope serialise: {e}")))
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

impl PolicyProjectionRepository for PgPolicyProjectionRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        Box::pin(async move {
            tracing::debug!(entity = "scan_policy", lookup_key = %id, "find_by_id");
            let row = sqlx::query(
                r#"SELECT policy_id, name, scope, severity_threshold,
                          quarantine_duration_secs, require_approval,
                          provenance_mode, provenance_backends,
                          provenance_identities, max_artifact_age_secs,
                          license_policy, archived, scan_backends,
                          rescan_interval_hours, negligible_action,
                          stream_version, created_at, updated_at
                   FROM policy_projections
                   WHERE policy_id = $1"#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "find_by_id"))?;
            row.as_ref().map(row_to_projection).transpose()
        })
    }

    fn find_by_name(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        let name = name.to_owned();
        Box::pin(async move {
            tracing::debug!(entity = "scan_policy", lookup_key = %name, "find_by_name");
            let row = sqlx::query(
                r#"SELECT policy_id, name, scope, severity_threshold,
                          quarantine_duration_secs, require_approval,
                          provenance_mode, provenance_backends,
                          provenance_identities, max_artifact_age_secs,
                          license_policy, archived, scan_backends,
                          rescan_interval_hours, negligible_action,
                          stream_version, created_at, updated_at
                   FROM policy_projections
                   WHERE name = $1 AND archived = false"#,
            )
            .bind(&name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "find_by_name"))?;
            row.as_ref().map(row_to_projection).transpose()
        })
    }

    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        let name = name.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "scan_policy",
                lookup_key = %name,
                "find_by_name_including_archived"
            );
            let row = sqlx::query(
                r#"SELECT policy_id, name, scope, severity_threshold,
                          quarantine_duration_secs, require_approval,
                          provenance_mode, provenance_backends,
                          provenance_identities, max_artifact_age_secs,
                          license_policy, archived, scan_backends,
                          rescan_interval_hours, negligible_action,
                          stream_version, created_at, updated_at
                   FROM policy_projections
                   WHERE name = $1"#,
            )
            .bind(&name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "find_by_name_including_archived"))?;
            row.as_ref().map(row_to_projection).transpose()
        })
    }

    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<ScanPolicyProjection>>> {
        Box::pin(async move {
            tracing::debug!(entity = "scan_policy", "list_active");
            let rows = sqlx::query(
                r#"SELECT policy_id, name, scope, severity_threshold,
                          quarantine_duration_secs, require_approval,
                          provenance_mode, provenance_backends,
                          provenance_identities, max_artifact_age_secs,
                          license_policy, archived, scan_backends,
                          rescan_interval_hours, negligible_action,
                          stream_version, created_at, updated_at
                   FROM policy_projections
                   WHERE archived = false
                   ORDER BY name"#,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "list_active"))?;
            rows.iter().map(row_to_projection).collect()
        })
    }

    fn list_exclusions_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<ExclusionProjection>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "scan_policy",
                lookup_key = %policy_id,
                "list_exclusions_for_policy"
            );
            let rows = sqlx::query(
                r#"SELECT exclusion_id, policy_id, cve_id, package_pattern,
                          scope, reason, added_by_actor_id, expires_at
                   FROM exclusion_projections
                   WHERE policy_id = $1"#,
            )
            .bind(policy_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "list_exclusions_for_policy"))?;
            rows.iter().map(row_to_exclusion).collect()
        })
    }

    fn upsert(&self, projection: &ScanPolicyProjection) -> BoxFuture<'_, DomainResult<()>> {
        // Owned copies for the async block.
        let policy_id = projection.policy_id;
        let name = projection.name.clone();
        let scope = match encode_scope(&projection.scope) {
            Ok(v) => v,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        let severity = projection.severity_threshold.to_string();
        let quarantine = projection.quarantine_duration_secs;
        let require_approval = projection.require_approval;
        let provenance_mode = projection.provenance_mode.to_string();
        let provenance_backends = projection.provenance_backends.clone();
        let provenance_identities = match serde_json::to_value(&projection.provenance_identities) {
            Ok(v) => v,
            Err(e) => {
                return Box::pin(async move {
                    Err(DomainError::Invariant(format!(
                        "provenance_identities serialise: {e}"
                    )))
                })
            }
        };
        let max_age = projection.max_artifact_age_secs;
        let license = projection.license_policy.clone();
        let archived = projection.archived;
        let scan_backends = projection.scan_backends.clone();
        let rescan_interval_hours = projection.rescan_interval_hours;
        let negligible_action = projection.negligible_action.to_string();
        let raw_version = projection.stream_version;
        let Ok(stream_version) = i64::try_from(raw_version) else {
            return Box::pin(async move {
                Err(DomainError::Invariant(format!(
                    "stream_version exceeds i64::MAX: {raw_version}"
                )))
            });
        };
        let created_at = projection.created_at;
        let updated_at = projection.updated_at;

        Box::pin(async move {
            tracing::debug!(
                entity = "scan_policy",
                lookup_key = %policy_id,
                "upsert"
            );
            sqlx::query(
                r#"INSERT INTO policy_projections (
                       policy_id, name, scope, severity_threshold,
                       quarantine_duration_secs, require_approval,
                       provenance_mode, provenance_backends,
                       provenance_identities, max_artifact_age_secs,
                       license_policy, archived, scan_backends,
                       rescan_interval_hours, stream_version,
                       created_at, updated_at, negligible_action
                   ) VALUES (
                       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                       $16, $17, $18
                   )
                   ON CONFLICT (policy_id) DO UPDATE SET
                       name                     = EXCLUDED.name,
                       scope                    = EXCLUDED.scope,
                       severity_threshold       = EXCLUDED.severity_threshold,
                       quarantine_duration_secs = EXCLUDED.quarantine_duration_secs,
                       require_approval         = EXCLUDED.require_approval,
                       provenance_mode          = EXCLUDED.provenance_mode,
                       provenance_backends      = EXCLUDED.provenance_backends,
                       provenance_identities    = EXCLUDED.provenance_identities,
                       max_artifact_age_secs    = EXCLUDED.max_artifact_age_secs,
                       license_policy           = EXCLUDED.license_policy,
                       archived                 = EXCLUDED.archived,
                       scan_backends            = EXCLUDED.scan_backends,
                       rescan_interval_hours    = EXCLUDED.rescan_interval_hours,
                       negligible_action        = EXCLUDED.negligible_action,
                       stream_version           = EXCLUDED.stream_version,
                       updated_at               = EXCLUDED.updated_at"#,
            )
            .bind(policy_id)
            .bind(&name)
            .bind(&scope)
            .bind(&severity)
            .bind(quarantine)
            .bind(require_approval)
            .bind(&provenance_mode)
            .bind(&provenance_backends)
            .bind(&provenance_identities)
            .bind(max_age)
            .bind(&license)
            .bind(archived)
            .bind(&scan_backends)
            .bind(rescan_interval_hours)
            .bind(stream_version)
            .bind(created_at)
            .bind(updated_at)
            .bind(&negligible_action)
            .execute(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "upsert"))?;
            Ok(())
        })
    }

    fn upsert_exclusion(&self, exclusion: &ExclusionProjection) -> BoxFuture<'_, DomainResult<()>> {
        let exclusion_id = exclusion.exclusion_id;
        let policy_id = exclusion.policy_id;
        let cve_id = exclusion.cve_id.clone();
        let package_pattern = exclusion.package_pattern.clone();
        let scope = match encode_scope(&exclusion.scope) {
            Ok(v) => v,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        let reason = exclusion.reason.clone();
        // Envelope-side author attribution. The ExclusionAdded payload
        // carries NO actor field; the caller (`PolicyUseCase::add_exclusion`)
        // extracts `user_id` from `Actor::Api` and threads it via
        // `ExclusionProjection`. A non-`api` envelope (system / timer /
        // gitops) leaves the column NULL — the curator-decisions
        // listing's actor filter surfaces only the `Some` rows.
        // `added_at` is DB-default (`now()`); we deliberately do not
        // bind it so a re-upsert (ON CONFLICT path) keeps the original
        // first-write timestamp.
        let added_by_actor_id = exclusion.added_by_actor_id;
        let expires_at = exclusion.expires_at;

        Box::pin(async move {
            tracing::debug!(
                entity = "scan_policy",
                lookup_key = %exclusion_id,
                "upsert_exclusion"
            );
            // added_by_actor_id and added_at deliberately omitted: first-write
            // attribution wins; ON CONFLICT path is event replay only.
            sqlx::query(
                r#"INSERT INTO exclusion_projections (
                       exclusion_id, policy_id, cve_id, package_pattern,
                       scope, reason, added_by_actor_id, expires_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (exclusion_id) DO UPDATE SET
                       policy_id         = EXCLUDED.policy_id,
                       cve_id            = EXCLUDED.cve_id,
                       package_pattern   = EXCLUDED.package_pattern,
                       scope             = EXCLUDED.scope,
                       reason            = EXCLUDED.reason,
                       expires_at        = EXCLUDED.expires_at"#,
            )
            .bind(exclusion_id)
            .bind(policy_id)
            .bind(&cve_id)
            .bind(&package_pattern)
            .bind(&scope)
            .bind(&reason)
            .bind(added_by_actor_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "upsert_exclusion"))?;
            Ok(())
        })
    }

    fn delete_exclusion(&self, exclusion_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "scan_policy",
                lookup_key = %exclusion_id,
                "delete_exclusion"
            );
            sqlx::query("DELETE FROM exclusion_projections WHERE exclusion_id = $1")
                .bind(exclusion_id)
                .execute(&self.pool)
                .await
                .map_err(|e| map_query_err(&e, "delete_exclusion"))?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    // ---- Pure unit tests for the helpers (no DB required) ----

    #[test]
    fn encode_scope_global_round_trips() {
        let v = encode_scope(&PolicyScope::Global).expect("encode");
        let decoded: PolicyScope = serde_json::from_value(v).expect("decode");
        assert_eq!(decoded, PolicyScope::Global);
    }

    #[test]
    fn encode_scope_repository_round_trips() {
        let id = Uuid::from_u128(42);
        let v = encode_scope(&PolicyScope::Repository(id)).expect("encode");
        let decoded: PolicyScope = serde_json::from_value(v).expect("decode");
        assert_eq!(decoded, PolicyScope::Repository(id));
    }

    #[test]
    fn map_query_err_wraps_invariant() {
        let err = map_query_err(&sqlx::Error::PoolClosed, "find_by_id");
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("find_by_id"), "msg = {msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn map_row_err_wraps_invariant() {
        let err = map_row_err(&sqlx::Error::PoolClosed);
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // ---- DB-backed integration tests. Skipped when DATABASE_URL is unset.
    //
    // Mirrors the convention in `repository_upstream_mapping_repo.rs` /
    // `pg_content_reference_repo.rs`. CI runs these via the postgres
    // service in the Tier-2 job.

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    fn sample_projection(policy_id: Uuid, name: &str, version: u64) -> ScanPolicyProjection {
        let now = Utc::now();
        ScanPolicyProjection {
            policy_id,
            name: name.into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::json!({"allowed": ["MIT"]}),
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: version,
            created_at: now,
            updated_at: now,
        }
    }

    fn sample_exclusion(exclusion_id: Uuid, policy_id: Uuid, cve: &str) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: cve.into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            scope: PolicyScope::Global,
            reason: "patched in container layer".into(),
            added_by_actor_id: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_find_by_id_round_trip() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let id = Uuid::new_v4();
        let p = sample_projection(id, &format!("test-{}", id.simple()), 1);
        repo.upsert(&p).await.expect("upsert");

        let fetched = repo.find_by_id(id).await.expect("find_by_id");
        let fetched = fetched.expect("row exists");
        assert_eq!(fetched.policy_id, p.policy_id);
        assert_eq!(fetched.name, p.name);
        assert_eq!(fetched.severity_threshold, p.severity_threshold);
        assert_eq!(fetched.stream_version, p.stream_version);
        assert_eq!(fetched.scope, PolicyScope::Global);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_updates_existing_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, &format!("upd-{}", id.simple()), 1);
        repo.upsert(&p).await.expect("first upsert");

        p.severity_threshold = SeverityThreshold::Critical;
        p.stream_version = 5;
        p.scope = PolicyScope::Repository(Uuid::new_v4());
        repo.upsert(&p).await.expect("second upsert");

        let fetched = repo
            .find_by_id(id)
            .await
            .expect("find_by_id")
            .expect("exists");
        assert_eq!(fetched.severity_threshold, SeverityThreshold::Critical);
        assert_eq!(fetched.stream_version, 5);
        assert!(matches!(fetched.scope, PolicyScope::Repository(_)));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_name_skips_archived_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let id = Uuid::new_v4();
        let name = format!("arch-{}", id.simple());
        let mut p = sample_projection(id, &name, 1);
        repo.upsert(&p).await.expect("upsert");

        // Active find succeeds.
        assert!(repo
            .find_by_name(&name)
            .await
            .expect("find_by_name")
            .is_some());

        // Archive then re-check: name lookup must skip the row, but
        // id lookup still returns it.
        p.archived = true;
        p.stream_version = 2;
        repo.upsert(&p).await.expect("archive upsert");

        assert!(repo
            .find_by_name(&name)
            .await
            .expect("find_by_name post-archive")
            .is_none());
        assert!(repo
            .find_by_id(id)
            .await
            .expect("find_by_id post-archive")
            .is_some());
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_active_returns_only_unarchived() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let active_id = Uuid::new_v4();
        let archived_id = Uuid::new_v4();
        let active = sample_projection(active_id, &format!("act-{}", active_id.simple()), 1);
        let mut archived =
            sample_projection(archived_id, &format!("arc-{}", archived_id.simple()), 1);
        archived.archived = true;
        repo.upsert(&active).await.expect("active upsert");
        repo.upsert(&archived).await.expect("archived upsert");

        let listed = repo.list_active().await.expect("list_active");
        assert!(listed.iter().any(|p| p.policy_id == active_id));
        assert!(!listed.iter().any(|p| p.policy_id == archived_id));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_list_exclusions_round_trip() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let policy_id = Uuid::new_v4();
        let p = sample_projection(policy_id, &format!("exc-{}", policy_id.simple()), 1);
        repo.upsert(&p).await.expect("upsert policy");

        let e1 = sample_exclusion(Uuid::new_v4(), policy_id, "CVE-2024-3094");
        let e2 = sample_exclusion(Uuid::new_v4(), policy_id, "CVE-2025-0001");
        repo.upsert_exclusion(&e1).await.expect("upsert e1");
        repo.upsert_exclusion(&e2).await.expect("upsert e2");

        let listed = repo
            .list_exclusions_for_policy(policy_id)
            .await
            .expect("list");
        assert_eq!(listed.len(), 2);
        let cves: Vec<&str> = listed.iter().map(|e| e.cve_id.as_str()).collect();
        assert!(cves.contains(&"CVE-2024-3094"));
        assert!(cves.contains(&"CVE-2025-0001"));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_exclusion_updates_existing_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let policy_id = Uuid::new_v4();
        let p = sample_projection(policy_id, &format!("eup-{}", policy_id.simple()), 1);
        repo.upsert(&p).await.expect("upsert policy");

        let exclusion_id = Uuid::new_v4();
        let mut e = sample_exclusion(exclusion_id, policy_id, "CVE-2024-3094");
        repo.upsert_exclusion(&e).await.expect("first upsert");

        e.reason = "updated reason".into();
        e.package_pattern = None;
        repo.upsert_exclusion(&e).await.expect("second upsert");

        let listed = repo
            .list_exclusions_for_policy(policy_id)
            .await
            .expect("list");
        let updated = listed
            .iter()
            .find(|x| x.exclusion_id == exclusion_id)
            .expect("found");
        assert_eq!(updated.reason, "updated reason");
        assert!(updated.package_pattern.is_none());
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_exclusion_removes_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let policy_id = Uuid::new_v4();
        let p = sample_projection(policy_id, &format!("del-{}", policy_id.simple()), 1);
        repo.upsert(&p).await.expect("upsert policy");

        let exclusion_id = Uuid::new_v4();
        let e = sample_exclusion(exclusion_id, policy_id, "CVE-2024-3094");
        repo.upsert_exclusion(&e).await.expect("upsert exclusion");
        repo.delete_exclusion(exclusion_id)
            .await
            .expect("delete exclusion");

        let listed = repo
            .list_exclusions_for_policy(policy_id)
            .await
            .expect("list");
        assert!(listed.iter().all(|x| x.exclusion_id != exclusion_id));
    }

    // Round-trip the scan_backends array column.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_find_by_id_round_trip_scan_backends() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let id = Uuid::new_v4();
        let mut p = sample_projection(id, &format!("backends-{}", id.simple()), 1);
        // Use a non-default value so a regression in the read or write
        // path that silently used the column default (`{trivy}`) would
        // be caught.
        p.scan_backends = vec!["trivy".into(), "osv".into()];
        repo.upsert(&p).await.expect("upsert");

        let fetched = repo
            .find_by_id(id)
            .await
            .expect("find_by_id")
            .expect("row exists");
        assert_eq!(fetched.scan_backends, vec!["trivy", "osv"]);

        // Update to an empty list — operators may opt out of scanning.
        p.scan_backends = Vec::new();
        p.stream_version = 2;
        repo.upsert(&p).await.expect("second upsert");
        let fetched = repo.find_by_id(id).await.expect("find_by_id").expect("ok");
        assert!(fetched.scan_backends.is_empty());
    }

    // Round-trip the provenance trio (mode text column,
    // backends text[], identities JSONB) through the DB.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_find_by_id_round_trip_provenance_trio() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let id = Uuid::new_v4();
        let mut p = sample_projection(id, &format!("prov-{}", id.simple()), 1);
        // Non-default values exercise the read + write paths (a regression
        // that silently used the column default would be caught).
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = vec![SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
        )
        .expect("valid pattern")];
        repo.upsert(&p).await.expect("upsert");

        let fetched = repo
            .find_by_id(id)
            .await
            .expect("find_by_id")
            .expect("row exists");
        assert_eq!(fetched.provenance_mode, ProvenanceMode::Required);
        assert_eq!(fetched.provenance_backends, vec!["cosign".to_string()]);
        assert_eq!(fetched.provenance_identities.len(), 1);
        assert_eq!(
            fetched.provenance_identities[0].issuer,
            "https://token.actions.githubusercontent.com"
        );

        // Switch to Off with an empty backends array — the CHECK permits
        // empty backends only under Off.
        p.provenance_mode = ProvenanceMode::Off;
        p.provenance_backends = Vec::new();
        p.provenance_identities = Vec::new();
        p.stream_version = 2;
        repo.upsert(&p).await.expect("second upsert");
        let fetched = repo.find_by_id(id).await.expect("find_by_id").expect("ok");
        assert_eq!(fetched.provenance_mode, ProvenanceMode::Off);
        assert!(fetched.provenance_backends.is_empty());
        assert!(fetched.provenance_identities.is_empty());
    }

    // Round-trip `negligible_action` (text column, CHECK-constrained)
    // through the DB. A non-default value exercises the read + write
    // paths; the default makes a pre-knob row read back as Ignore.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_find_by_id_round_trip_negligible_action() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);

        let id = Uuid::new_v4();
        let mut p = sample_projection(id, &format!("negl-{}", id.simple()), 1);
        // sample_projection defaults to Ignore — confirm that reads back.
        assert_eq!(p.negligible_action, NegligibleAction::Ignore);
        repo.upsert(&p).await.expect("upsert ignore");
        let fetched = repo.find_by_id(id).await.expect("find").expect("row");
        assert_eq!(fetched.negligible_action, NegligibleAction::Ignore);

        // Flip to Block and confirm the non-default round-trips.
        p.negligible_action = NegligibleAction::Block;
        p.stream_version = 2;
        repo.upsert(&p).await.expect("upsert block");
        let fetched = repo.find_by_id(id).await.expect("find").expect("row");
        assert_eq!(fetched.negligible_action, NegligibleAction::Block);

        // And Warn.
        p.negligible_action = NegligibleAction::Warn;
        p.stream_version = 3;
        repo.upsert(&p).await.expect("upsert warn");
        let fetched = repo.find_by_id(id).await.expect("find").expect("row");
        assert_eq!(fetched.negligible_action, NegligibleAction::Warn);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_id_returns_none_for_missing_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let id = Uuid::new_v4();
        let result = repo.find_by_id(id).await.expect("find_by_id");
        assert!(result.is_none());
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_name_returns_none_for_missing_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPolicyProjectionRepository::new(pool);
        let result = repo
            .find_by_name("does-not-exist-name")
            .await
            .expect("find_by_name");
        assert!(result.is_none());
    }
}
