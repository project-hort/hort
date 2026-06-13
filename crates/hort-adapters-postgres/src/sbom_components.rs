//! PostgreSQL adapter for [`SbomComponentRepository`] — the per-artifact
//! `sbom_components` projection from migration 010.
//!
//! The projection lands atomically with the `ScanCompleted` append;
//! the transactional boundary is owned by
//! [`crate::artifact_lifecycle::PgArtifactLifecycle::commit_scan_result_with_score`]
//! (which calls into [`replace_for_artifact_in_tx`] inside the existing
//! scan tx); callers that exercise the trait outside that lifecycle
//! path get a self-contained transaction here.

use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::sbom_component_repository::SbomComponentRepository;
use hort_domain::types::sbom::{Ecosystem, SbomComponent};

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for [`SbomComponentRepository`].
pub struct PgSbomComponentRepository {
    pool: PgPool,
}

impl PgSbomComponentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Render an [`Ecosystem`] into the column literal stored in
/// `sbom_components.ecosystem`. The column is a free-form `TEXT`
/// (not an enum) per the migration 010 schema; we use lowercase
/// canonical PURL-style identifiers (`"npm"`, `"pypi"`, `"cargo"`,
/// …) so the advisory-watch query joining against OSV's per-
/// ecosystem identifiers works without a translation layer.
///
/// The mapping must stay symmetric with whatever the OSV adapter
/// emits for `AdvisoryEntry.ecosystem` so the
/// `list_artifacts_by_match(ecosystem, name, versions)` filter
/// matches the rows the projection wrote during the scan path.
pub(crate) fn ecosystem_to_sql(e: &Ecosystem) -> String {
    match e {
        Ecosystem::Npm => "npm".to_string(),
        Ecosystem::PyPI => "pypi".to_string(),
        Ecosystem::Cargo => "cargo".to_string(),
        Ecosystem::Maven => "maven".to_string(),
        Ecosystem::Go => "go".to_string(),
        Ecosystem::RubyGems => "rubygems".to_string(),
        Ecosystem::NuGet => "nuget".to_string(),
        Ecosystem::Composer => "composer".to_string(),
        Ecosystem::Hex => "hex".to_string(),
        Ecosystem::Pub => "pub".to_string(),
        Ecosystem::Conda => "conda".to_string(),
        Ecosystem::Helm => "helm".to_string(),
        Ecosystem::OciImage => "oci".to_string(),
        // The `Unknown(_)` escape hatch round-trips its inner string
        // verbatim. The projection table uses TEXT not an enum, so
        // arbitrary identifiers are accepted; the trade-off is that
        // an OSV query targeting a typed ecosystem won't match
        // rows that landed under `Unknown("…")`. That's the right
        // behaviour: an unknown ecosystem cannot be matched against
        // OSV's typed feeds anyway.
        Ecosystem::Unknown(s) => s.clone(),
    }
}

/// Replace every `(artifact_id, purl)` row for `artifact_id` with
/// the supplied components inside `tx`. DELETE-then-INSERT — not an
/// UPSERT — so a component dropped from the latest SBOM disappears
/// from the projection (the projection mirrors the latest scan exactly).
///
/// Empty `components` is a valid input (the manifest exists but
/// lists no dependencies); the DELETE still fires so stale rows
/// from a prior SBOM are removed.
pub(crate) async fn replace_for_artifact_in_tx(
    tx: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    components: &[SbomComponent],
) -> DomainResult<()> {
    sqlx::query("DELETE FROM sbom_components WHERE artifact_id = $1")
        .bind(artifact_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "sbom_components", &artifact_id.to_string()))?;

    if components.is_empty() {
        return Ok(());
    }

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO sbom_components (artifact_id, purl, ecosystem, name, version) ",
    );
    qb.push_values(components, |mut b, comp| {
        b.push_bind(artifact_id)
            .push_bind(&comp.purl)
            .push_bind(ecosystem_to_sql(&comp.ecosystem))
            .push_bind(&comp.name)
            .push_bind(&comp.version);
    });
    let query = qb.build();
    query
        .execute(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "sbom_components", &artifact_id.to_string()))?;
    Ok(())
}

impl SbomComponentRepository for PgSbomComponentRepository {
    fn replace_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
        components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(|e| {
                DomainError::Invariant(format!("sbom_components replace_for_artifact begin: {e}"))
            })?;
            replace_for_artifact_in_tx(&mut tx, artifact_id, components).await?;
            tx.commit().await.map_err(|e| {
                DomainError::Invariant(format!("sbom_components replace_for_artifact commit: {e}"))
            })?;
            Ok(())
        })
    }

    fn list_artifacts_by_match<'a>(
        &'a self,
        ecosystem: &'a Ecosystem,
        name: &'a str,
        versions: &'a [String],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            // Empty-versions short-circuit: a WHERE version = ANY('{}')
            // would return zero rows anyway, but the explicit shortcut
            // documents the invariant at the adapter boundary and saves
            // a round-trip.
            if versions.is_empty() {
                return Ok(Vec::new());
            }
            let eco = ecosystem_to_sql(ecosystem);
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT artifact_id FROM sbom_components \
                 WHERE ecosystem = $1 AND name = $2 AND version = ANY($3::text[])",
            )
            .bind(&eco)
            .bind(name)
            .bind(versions)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "sbom_components", name))?;
            Ok(rows.into_iter().map(|(id,)| id).collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Compile-time assertion that the adapter implements the port.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: SbomComponentRepository>() {}
        assert_impl::<PgSbomComponentRepository>();
    }

    /// Round-trip every named `Ecosystem` variant through the SQL
    /// literal mapping. The projection's `ecosystem` column is plain
    /// TEXT (not an enum), so any string is accepted, but we lock
    /// the canonical mapping in with a test so a future "rename
    /// pypi to py" change is a visible regression.
    #[test]
    fn ecosystem_to_sql_covers_all_named_variants() {
        assert_eq!(ecosystem_to_sql(&Ecosystem::Npm), "npm");
        assert_eq!(ecosystem_to_sql(&Ecosystem::PyPI), "pypi");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Cargo), "cargo");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Maven), "maven");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Go), "go");
        assert_eq!(ecosystem_to_sql(&Ecosystem::RubyGems), "rubygems");
        assert_eq!(ecosystem_to_sql(&Ecosystem::NuGet), "nuget");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Composer), "composer");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Hex), "hex");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Pub), "pub");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Conda), "conda");
        assert_eq!(ecosystem_to_sql(&Ecosystem::Helm), "helm");
        assert_eq!(ecosystem_to_sql(&Ecosystem::OciImage), "oci");
        assert_eq!(
            ecosystem_to_sql(&Ecosystem::Unknown("custom".into())),
            "custom"
        );
    }

    /// Pin: the `list_artifacts_by_match` empty-versions shortcut
    /// returns an empty Vec without issuing SQL — exercised through
    /// the public trait surface (no DB round-trip required).
    #[tokio::test]
    async fn list_artifacts_by_match_empty_versions_short_circuits() {
        // No connection — but `list_artifacts_by_match` short-circuits
        // before touching the pool when `versions.is_empty()`. We
        // still need a constructed adapter to call the method;
        // PgPool requires a URL, so gate on DATABASE_URL like the
        // rest of the suite.
        let Ok(url) = env::var("DATABASE_URL") else {
            return;
        };
        let Ok(pool) = PgPool::connect(&url).await else {
            return;
        };
        let repo = PgSbomComponentRepository::new(pool);
        let got = repo
            .list_artifacts_by_match(&Ecosystem::Npm, "anything", &[])
            .await
            .expect("empty-versions shortcut must not error");
        assert!(got.is_empty());
    }
}
