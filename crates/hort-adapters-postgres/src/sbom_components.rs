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

use crate::bulk_insert::ChunkedInsert;
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

/// The projection's columns, in the order [`components_statement`]
/// binds them.
///
/// This list is the single source of the insert's arity: the
/// `INSERT INTO … (…)` prefix is rendered from it and the number of rows
/// one statement may carry is derived from it, so adding a column here
/// moves both.
const COMPONENTS_COLUMNS: &[&str] = &["artifact_id", "purl", "ecosystem", "name", "version"];

/// The chunked `sbom_components` insert. At five bind parameters a row,
/// a large container image's component list is big enough to cross
/// PostgreSQL's per-statement parameter limit, and past it the statement
/// is refused outright — which, since these rows share the scan's
/// transaction, discards the scan's verdict with them.
const COMPONENTS_INSERT: ChunkedInsert = ChunkedInsert::new("sbom_components", COMPONENTS_COLUMNS);

/// The statement for one chunk of components. The production build,
/// shared with the arity test so a column whose `push_bind` nobody added
/// fails without a database.
///
/// `artifact_id` is captured rather than read off the row: every row of
/// a replace belongs to the same artifact, which is why the component
/// type does not carry it.
fn components_statement(artifact_id: Uuid, chunk: &[SbomComponent]) -> QueryBuilder<Postgres> {
    COMPONENTS_INSERT.statement(chunk, |mut b, comp: &SbomComponent| {
        b.push_bind(artifact_id)
            .push_bind(&comp.purl)
            .push_bind(ecosystem_to_sql(&comp.ecosystem))
            .push_bind(&comp.name)
            .push_bind(&comp.version);
    })
}

/// Replace every `(artifact_id, purl)` row for `artifact_id` with
/// the supplied components inside `tx`. DELETE-then-INSERT — not an
/// UPSERT — so a component dropped from the latest SBOM disappears
/// from the projection (the projection mirrors the latest scan exactly).
///
/// Empty `components` is a valid input (the manifest exists but
/// lists no dependencies); the DELETE still fires so stale rows
/// from a prior SBOM are removed.
///
/// A component list too large for one statement's bind-parameter budget
/// is split across several statements on `tx` — the caller's connection
/// — so the DELETE and every insert chunk stay in one transaction and
/// the replace is still all-or-nothing.
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

    COMPONENTS_INSERT
        .execute_chunked(tx, components, |chunk| {
            components_statement(artifact_id, chunk)
        })
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

    use serial_test::serial;

    use crate::bulk_insert::PG_MAX_BIND_PARAMS;

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
    ///
    /// `#[serial(hort_pg_db)]` (issue #94): the method itself issues no
    /// SQL, but the fixture still opens a real connection against the
    /// shared `DATABASE_URL` target — every test that acquires a real
    /// connection carries the crate-wide serial key, no exceptions,
    /// regardless of whether it queries.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_artifacts_by_match_empty_versions_short_circuits() {
        // No query issued — but `list_artifacts_by_match` short-circuits
        // before touching the pool when `versions.is_empty()`. We still
        // need a constructed adapter to call the method, hence the pool.
        let Some(pool) = crate::test_support::shared_migrated_pool().await else {
            return;
        };
        let repo = PgSbomComponentRepository::new(pool);
        let got = repo
            .list_artifacts_by_match(&Ecosystem::Npm, "anything", &[])
            .await
            .expect("empty-versions shortcut must not error");
        assert!(got.is_empty());
    }

    /// A per-test database, plus the FK parents a component row needs:
    /// `sbom_components.artifact_id` references `artifacts(id)`, which
    /// references `repositories(id)`. One statement for both, so the
    /// fixture stays beside the test it serves.
    async fn maybe_pool_with_artifact() -> Option<(PgPool, Uuid)> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;

        let key = format!("it-sbomlimit-{}", Uuid::new_v4().simple());
        let artifact_id: Uuid = sqlx::query_scalar(
            r#"WITH r AS (
                   INSERT INTO public.repositories (
                       key, name, format, repo_type, storage_backend,
                       storage_path, replication_priority
                   ) VALUES ($1, $1, 'oci', 'hosted', 'filesystem', $2, 'local_only')
                   RETURNING id
               )
               INSERT INTO public.artifacts (
                   repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               )
               SELECT r.id, 'sbom-limit', 'sbom-limit', '0.0.0', $3, 0, $4,
                      'application/octet-stream', $4
                 FROM r
               RETURNING id"#,
        )
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .bind(format!("oci/sbom-limit/{key}"))
        .bind("0".repeat(64))
        .fetch_one(&pool)
        .await
        .expect("seed the artifact the projection hangs off");
        Some((pool, artifact_id))
    }

    /// One component, distinguishable by `purl` — which is the
    /// projection's primary key beside `artifact_id`, so a list built
    /// from distinct `n` is one the table accepts whole.
    fn component(n: usize) -> SbomComponent {
        SbomComponent {
            purl: format!("pkg:npm/limit-{n}@1.0.0"),
            name: format!("limit-{n}"),
            version: Some("1.0.0".to_string()),
            ecosystem: Ecosystem::Npm,
            licenses: Vec::new(),
            direct_dependency: false,
        }
    }

    /// The statement binds exactly one placeholder per column per row,
    /// and names every column it declares.
    ///
    /// This is the check that survives a sixth column: add one to
    /// [`COMPONENTS_COLUMNS`] without a matching `push_bind` and the
    /// rendered placeholder count stops matching the declared column
    /// count — a statement Postgres would reject, and whose real arity
    /// the chunk size derived from the list no longer describes. No
    /// database needed.
    #[test]
    fn the_components_statement_binds_one_placeholder_per_column_per_row() {
        let artifact_id = Uuid::new_v4();
        let rows = [component(1), component(2)];
        let expected = rows.len() * COMPONENTS_COLUMNS.len();
        let sql = components_statement(artifact_id, &rows).into_string();

        assert_eq!(
            sql.matches('$').count(),
            expected,
            "{} rows x {} columns should bind {expected} parameters: {sql}",
            rows.len(),
            COMPONENTS_COLUMNS.len()
        );
        assert!(sql.contains(&format!("${expected}")), "{sql}");
        assert!(!sql.contains(&format!("${}", expected + 1)), "{sql}");
        for column in COMPONENTS_COLUMNS {
            assert!(sql.contains(column), "prefix omits {column}: {sql}");
        }
    }

    /// A full statement stays inside the bind-parameter limit, and one
    /// row more would not — so the chunk size is the largest one the
    /// wire protocol admits, derived rather than written down.
    #[test]
    fn the_components_chunk_is_the_largest_the_parameter_limit_admits() {
        let budget = COMPONENTS_INSERT.rows_per_statement();
        assert!(budget >= 1, "a statement must carry at least one row");
        assert!(budget * COMPONENTS_COLUMNS.len() <= PG_MAX_BIND_PARAMS);
        assert!((budget + 1) * COMPONENTS_COLUMNS.len() > PG_MAX_BIND_PARAMS);
    }

    /// One component more than a single statement can bind still lands
    /// in full, and the replace is still a replace.
    ///
    /// The `+ 1` is the whole test: a list of exactly the budget
    /// crosses no statement boundary and would pass against the
    /// unchunked insert too. Nothing has reached this limit in
    /// production yet — a large image's SBOM is what gets there — and
    /// the consequence would be the scan's own transaction failing, so
    /// the artifact would read as unscanned rather than as missing its
    /// components.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_component_list_past_one_statement_lands_in_full() {
        let Some((pool, artifact_id)) = maybe_pool_with_artifact().await else {
            return;
        };
        let repo = PgSbomComponentRepository::new(pool.clone());

        // A prior, smaller SBOM, so the oversized write below is also
        // exercising the DELETE half of the replace.
        repo.replace_for_artifact(artifact_id, &[component(0)])
            .await
            .expect("seed a prior SBOM");

        let wanted = COMPONENTS_INSERT.rows_per_statement() + 1;
        let components: Vec<SbomComponent> = (0..wanted).map(component).collect();
        repo.replace_for_artifact(artifact_id, &components)
            .await
            .expect("a list past one statement's bind budget must still insert");

        let stored: i64 =
            sqlx::query_scalar("SELECT count(*) FROM sbom_components WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&pool)
                .await
                .expect("count query");
        assert_eq!(
            usize::try_from(stored).expect("row count fits a usize"),
            wanted
        );

        // The last row specifically: a dropped tail chunk would still
        // leave a plausible-looking count if the list had been
        // truncated anywhere else.
        let tail: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sbom_components WHERE artifact_id = $1 AND purl = $2",
        )
        .bind(artifact_id)
        .bind(component(wanted - 1).purl)
        .fetch_one(&pool)
        .await
        .expect("tail query");
        assert_eq!(tail, 1, "the last chunk's final row is missing");
        // No cleanup: the database is this test's own and is swept.
    }
}
