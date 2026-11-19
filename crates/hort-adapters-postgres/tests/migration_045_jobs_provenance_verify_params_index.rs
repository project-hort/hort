//! The provenance-verify in-flight lookup must have an applicable partial index.

#![allow(clippy::expect_used)]

use std::env;

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

async fn migrated_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn provenance_verify_index_has_expression_and_partial_nonunique_predicate() {
    let Some(pool) = migrated_pool().await else {
        return;
    };

    let (indexdef, is_unique): (String, bool) = sqlx::query_as(
        "SELECT indexes.indexdef, index.indisunique \
         FROM pg_indexes AS indexes \
         JOIN pg_namespace AS namespace ON namespace.nspname = indexes.schemaname \
         JOIN pg_class AS relation ON relation.relnamespace = namespace.oid \
                                  AND relation.relname = indexes.indexname \
         JOIN pg_index AS index ON index.indexrelid = relation.oid \
         WHERE indexes.schemaname = 'public' AND indexes.tablename = 'jobs' \
           AND indexes.indexname = 'jobs_provenance_verify_artifact_idx'",
    )
    .fetch_one(&pool)
    .await
    .expect("provenance-verify index must exist on public.jobs");

    assert!(
        indexdef.contains("params ->> 'artifact_id'"),
        "index must use the artifact_id JSONB expression: {indexdef}"
    );
    assert!(
        indexdef.contains("WHERE")
            && indexdef.contains("kind = 'provenance-verify'")
            && indexdef.contains("status")
            && indexdef.contains("'pending'")
            && indexdef.contains("'running'"),
        "index must cover only in-flight provenance-verify rows: {indexdef}"
    );
    assert!(!is_unique, "the in-flight lookup index must not be unique");
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn provenance_verify_lookup_can_use_index_only_for_matching_expression() {
    let Some(pool) = migrated_pool().await else {
        return;
    };

    // Give the planner enough mixed rows to choose between the partial index
    // and a sequential scan on cost, then refresh its estimates.
    sqlx::query(
        "INSERT INTO public.jobs (kind, params, status) \
         SELECT CASE WHEN n % 2 = 0 THEN 'provenance-verify' ELSE 'noop' END, \
                jsonb_build_object('artifact_id', n::text, 'other_artifact_id', n::text), \
                CASE WHEN n % 3 = 0 THEN 'completed' ELSE 'pending' END \
         FROM generate_series(1, 4000) AS n",
    )
    .execute(&pool)
    .await
    .expect("seed mixed jobs");
    sqlx::query("ANALYZE public.jobs")
        .execute(&pool)
        .await
        .expect("analyze seeded jobs");

    let artifact_id = Uuid::new_v4().to_string();
    let matching: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (FORMAT TEXT) \
         SELECT id FROM public.jobs \
         WHERE kind = 'provenance-verify' \
           AND params->>'artifact_id' = $1 \
           AND status IN ('pending', 'running') \
         LIMIT 1",
    )
    .bind(&artifact_id)
    .fetch_all(&pool)
    .await
    .expect("explain provenance-verify lookup");
    let matching_plan = matching.join("\n");
    assert!(
        matching_plan.contains("Index Scan using jobs_provenance_verify_artifact_idx"),
        "provenance-verify lookup must be able to use its partial index:\n{matching_plan}"
    );
    assert!(
        !matching_plan.contains("Filter:"),
        "the partial predicate must absorb kind and status:\n{matching_plan}"
    );

    let different_key: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (FORMAT TEXT) \
         SELECT id FROM public.jobs \
         WHERE kind = 'provenance-verify' \
           AND params->>'other_artifact_id' = $1 \
           AND status IN ('pending', 'running') \
         LIMIT 1",
    )
    .bind(&artifact_id)
    .fetch_all(&pool)
    .await
    .expect("explain different JSONB key lookup");
    let different_key_plan = different_key.join("\n");
    assert!(
        different_key_plan.contains("Seq Scan")
            && !different_key_plan.contains("jobs_provenance_verify_artifact_idx"),
        "a different JSONB key must not use the provenance-verify index:\n{different_key_plan}"
    );
}
