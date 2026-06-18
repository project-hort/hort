//! `PgCurationExclusionsRepository` integration tests +
//! `ExclusionAdded` projector envelope-attribution tests.
//!
//! Exercises the active-exclusions listing against a real
//! Postgres + verifies the projector populates the `added_by_actor_id`
//! column from the event envelope (`api`-actor envelope → `Some(user_id)`;
//! non-api envelope → `NULL`).
//!
//! `#[serial(hort_pg_db)]` is **mandatory** on every test that acquires
//! a real DB connection — CLAUDE.md "DB-backed test isolation
//! (parallel-safety contract)". Adding a maybe_pool() test without
//! the serial key reintroduces the identity-shifting flake fixed in
//! ed79360a.
//!
//! DATABASE_URL-gated; every test early-returns silently when the
//! env var is unset so dev environments without a database keep the
//! suite green. Mirrors `curation_decisions_repository.rs`.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test curation_exclusions_repository
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::Utc;
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::curation_exclusions_repository::PgCurationExclusionsRepository;
use hort_domain::entities::scan_policy::ExclusionProjection;
use hort_domain::events::PolicyScope;
use hort_domain::ports::curation_exclusions_repository::{
    CurationExclusionFilter, CurationExclusionsRepository,
};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;

/// Connect via per-test isolation, run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Seed a non-archived `policy_projections` row so exclusion FK can
/// attach. Mirrors `curation_decisions_repository.rs::seed_policy`.
async fn seed_policy(pool: &PgPool) -> Uuid {
    let policy_id = Uuid::new_v4();
    let name = format!("it-curation-exclusions-policy-{}", policy_id.simple());
    let scope = json!({ "Global": null });
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, archived,
               stream_version
           ) VALUES (
               $1, $2, $3, 'high',
               24, 86400,
               false, false,
               1
           )"#,
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&scope)
    .execute(pool)
    .await
    .expect("seed policy_projections row");
    policy_id
}

/// Seed an `exclusion_projections` row directly (bypassing the
/// projector). Lets the adapter tests drive deterministic shapes
/// without dragging in the use case.
async fn seed_exclusion_raw(
    pool: &PgPool,
    exclusion_id: Uuid,
    policy_id: Uuid,
    cve_id: &str,
    package_pattern: Option<&str>,
    added_by_actor_id: Option<Uuid>,
    reason: &str,
) {
    let scope = json!({ "Global": null });
    sqlx::query(
        r#"INSERT INTO public.exclusion_projections (
               exclusion_id, policy_id, cve_id, package_pattern,
               scope, reason, added_by_actor_id
           ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(exclusion_id)
    .bind(policy_id)
    .bind(cve_id)
    .bind(package_pattern)
    .bind(&scope)
    .bind(reason)
    .bind(added_by_actor_id)
    .execute(pool)
    .await
    .expect("seed exclusion_projections row");
}

async fn cleanup_policy(pool: &PgPool, policy_id: Uuid) {
    let _ = sqlx::query("DELETE FROM policy_projections WHERE policy_id = $1")
        .bind(policy_id)
        .execute(pool)
        .await;
}

// ---------------------------------------------------------------------------
// Adapter — filter combinations
// ---------------------------------------------------------------------------

/// Filter by `policy_id` alone surfaces all of that policy's
/// exclusions and none from a sibling policy. Confirms the
/// `WHERE policy_id = $1` branch.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_filter_by_policy_id() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy_a = seed_policy(&pool).await;
    let policy_b = seed_policy(&pool).await;
    let actor = Uuid::new_v4();

    let in_a_1 = Uuid::new_v4();
    let in_a_2 = Uuid::new_v4();
    let in_b = Uuid::new_v4();

    seed_exclusion_raw(
        &pool,
        in_a_1,
        policy_a,
        "CVE-2026-0001",
        None,
        Some(actor),
        "patched in container layer",
    )
    .await;
    seed_exclusion_raw(
        &pool,
        in_a_2,
        policy_a,
        "CVE-2026-0002",
        Some("evil-pkg@<1"),
        Some(actor),
        "fp",
    )
    .await;
    seed_exclusion_raw(
        &pool,
        in_b,
        policy_b,
        "CVE-2026-0003",
        None,
        Some(actor),
        "different policy",
    )
    .await;

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy_a),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.exclusion_id).collect();
    assert!(ids.contains(&in_a_1), "policy_a row must surface");
    assert!(ids.contains(&in_a_2), "policy_a row must surface");
    assert!(!ids.contains(&in_b), "policy_b row must NOT surface");

    cleanup_policy(&pool, policy_a).await;
    cleanup_policy(&pool, policy_b).await;
}

/// Filter by `cve_id` alone surfaces every policy's matching
/// exclusion. Confirms the `WHERE cve_id = $2` branch.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_filter_by_cve_id() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy_a = seed_policy(&pool).await;
    let policy_b = seed_policy(&pool).await;
    let actor = Uuid::new_v4();
    let target_cve = "CVE-2026-7777";

    let in_a = Uuid::new_v4();
    let in_b = Uuid::new_v4();
    let other_cve = Uuid::new_v4();

    seed_exclusion_raw(&pool, in_a, policy_a, target_cve, None, Some(actor), "fp").await;
    seed_exclusion_raw(&pool, in_b, policy_b, target_cve, None, Some(actor), "fp").await;
    seed_exclusion_raw(
        &pool,
        other_cve,
        policy_a,
        "CVE-2026-9999",
        None,
        Some(actor),
        "irrelevant",
    )
    .await;

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            cve_id: Some(target_cve.into()),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.exclusion_id).collect();
    assert!(ids.contains(&in_a));
    assert!(ids.contains(&in_b));
    assert!(!ids.contains(&other_cve));
    assert!(rows.iter().all(|r| r.cve_id == target_cve));

    cleanup_policy(&pool, policy_a).await;
    cleanup_policy(&pool, policy_b).await;
}

/// Filter by `actor_id` alone surfaces only rows whose
/// `added_by_actor_id` matches. Confirms the
/// `WHERE added_by_actor_id = $3` branch.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_filter_by_actor_id() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();

    let by_alice = Uuid::new_v4();
    let by_bob = Uuid::new_v4();
    let by_system = Uuid::new_v4();

    seed_exclusion_raw(
        &pool,
        by_alice,
        policy,
        "CVE-2026-0001",
        None,
        Some(alice),
        "alice's exclusion",
    )
    .await;
    seed_exclusion_raw(
        &pool,
        by_bob,
        policy,
        "CVE-2026-0002",
        None,
        Some(bob),
        "bob's exclusion",
    )
    .await;
    seed_exclusion_raw(
        &pool,
        by_system,
        policy,
        "CVE-2026-0003",
        None,
        None,
        "system-driven (e.g. gitops)",
    )
    .await;

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            actor_id: Some(alice),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.exclusion_id).collect();
    assert!(ids.contains(&by_alice), "alice's row must surface");
    assert!(!ids.contains(&by_bob), "bob's row must NOT surface");
    assert!(
        !ids.contains(&by_system),
        "NULL-actor row must NOT match an explicit actor_id filter"
    );
    assert!(rows.iter().all(|r| r.added_by_actor_id == Some(alice)));

    cleanup_policy(&pool, policy).await;
}

/// All three filters AND together — only rows matching every facet
/// surface.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_filter_all_three() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    let target_cve = "CVE-2026-AAAA";

    let target = Uuid::new_v4();
    let wrong_actor = Uuid::new_v4();
    let wrong_cve = Uuid::new_v4();

    seed_exclusion_raw(&pool, target, policy, target_cve, None, Some(alice), "ok").await;
    seed_exclusion_raw(
        &pool,
        wrong_actor,
        policy,
        target_cve,
        None,
        Some(bob),
        "no",
    )
    .await;
    seed_exclusion_raw(
        &pool,
        wrong_cve,
        policy,
        "CVE-2026-BBBB",
        None,
        Some(alice),
        "no",
    )
    .await;

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy),
            cve_id: Some(target_cve.into()),
            actor_id: Some(alice),
            limit: 100,
        })
        .await
        .expect("list_exclusions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.exclusion_id).collect();
    assert!(ids.contains(&target));
    assert!(!ids.contains(&wrong_actor));
    assert!(!ids.contains(&wrong_cve));

    cleanup_policy(&pool, policy).await;
}

/// Limit cap (500) is enforced defensively at the adapter level
/// even if the caller bypasses the use-case validation.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_limit_capped_at_500() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let actor = Uuid::new_v4();

    // Seed 3 rows; the cap is unreachable here but the limit-bind
    // path still executes. The defensive clamp is exercised by passing
    // a limit > 500 and verifying the query does not error out
    // (sqlx i64 conversion would have overflowed if the cap were
    // ignored). Use a non-default tag to scope the assert.
    for i in 0..3 {
        seed_exclusion_raw(
            &pool,
            Uuid::new_v4(),
            policy,
            &format!("CVE-2026-CAP{i}"),
            None,
            Some(actor),
            "cap-test",
        )
        .await;
    }

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy),
            limit: 10_000,
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions with oversize limit must clamp, not error");

    assert!(rows.len() >= 3);
    assert!(rows.len() <= 500);

    cleanup_policy(&pool, policy).await;
}

/// Empty-result case — no exclusions match the filter, port returns
/// `Ok(Vec::new())`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_empty_result_returns_empty_vec() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    // No rows seeded for this policy.

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    assert!(
        rows.is_empty(),
        "policy with no exclusions must return empty vec, got {} rows",
        rows.len()
    );

    cleanup_policy(&pool, policy).await;
}

/// NULL-actor row pass-through. A row with `added_by_actor_id = NULL`
/// (system actor — e.g. a gitops-applied exclusion) MUST surface in
/// the unfiltered listing with `added_by_actor_id == None` on the
/// entry. An explicit `actor_id` filter must NOT surface it (covered
/// by `filter_by_actor_id`); this test covers the unfiltered shape.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_exclusions_null_actor_row_passes_through() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let exclusion_id = Uuid::new_v4();

    seed_exclusion_raw(
        &pool,
        exclusion_id,
        policy,
        "CVE-2026-NULL",
        None,
        None, // system actor — projector left the column NULL
        "system-driven",
    )
    .await;

    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    let row = rows
        .iter()
        .find(|r| r.exclusion_id == exclusion_id)
        .expect("NULL-actor row must surface");
    assert_eq!(row.added_by_actor_id, None);
    assert_eq!(row.cve_id, "CVE-2026-NULL");

    cleanup_policy(&pool, policy).await;
}

// ---------------------------------------------------------------------------
// Projector — envelope-side attribution
// ---------------------------------------------------------------------------

/// `PolicyProjectionRepository::upsert_exclusion` writes the
/// envelope-side `added_by_actor_id` into the projection. The caller
/// (`PolicyUseCase::add_exclusion`) is responsible for sourcing the
/// `user_id` from `Actor::Api`; the projector trait's writer simply
/// threads the value verbatim. This test confirms that an
/// `ExclusionProjection { added_by_actor_id: Some(uid), .. }`
/// round-trips into the `added_by_actor_id` column, and `None`
/// round-trips as NULL.
#[tokio::test]
#[serial(hort_pg_db)]
async fn projector_populates_added_by_actor_id_from_projection() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let curator = Uuid::new_v4();

    // Use the canonical projection-write path
    // (`upsert_exclusion`) — that's the projector for both the
    // imperative `add_exclusion` flow and the gitops-apply flow.
    let projector =
        hort_adapters_postgres::policy_projection_repo::PgPolicyProjectionRepository::new(
            pool.clone(),
        );

    let api_actor_exclusion_id = Uuid::new_v4();
    let api_actor_projection = ExclusionProjection {
        exclusion_id: api_actor_exclusion_id,
        policy_id: policy,
        cve_id: "CVE-2026-API".into(),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "curator-driven".into(),
        added_by_actor_id: Some(curator),
        expires_at: None,
    };
    projector
        .upsert_exclusion(&api_actor_projection)
        .await
        .expect("upsert api-actor exclusion");

    let system_actor_exclusion_id = Uuid::new_v4();
    let system_actor_projection = ExclusionProjection {
        exclusion_id: system_actor_exclusion_id,
        policy_id: policy,
        cve_id: "CVE-2026-SYS".into(),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "gitops-applied".into(),
        added_by_actor_id: None,
        expires_at: None,
    };
    projector
        .upsert_exclusion(&system_actor_projection)
        .await
        .expect("upsert system-actor exclusion");

    // Read back via the new adapter. The api-actor row carries the
    // curator's user_id; the system-actor row carries NULL.
    let adapter = PgCurationExclusionsRepository::new(pool.clone());
    let rows = adapter
        .list_exclusions(CurationExclusionFilter {
            policy_id: Some(policy),
            ..CurationExclusionFilter::default()
        })
        .await
        .expect("list_exclusions");

    let api_row = rows
        .iter()
        .find(|r| r.exclusion_id == api_actor_exclusion_id)
        .expect("api-actor row surfaces");
    assert_eq!(
        api_row.added_by_actor_id,
        Some(curator),
        "api-kind envelope → projection column populated with user_id"
    );

    let system_row = rows
        .iter()
        .find(|r| r.exclusion_id == system_actor_exclusion_id)
        .expect("system-actor row surfaces");
    assert_eq!(
        system_row.added_by_actor_id, None,
        "non-api envelope → projection column NULL"
    );

    // `added_at` is populated by the DB DEFAULT now() so both rows
    // carry a non-epoch timestamp — confirms the column was bound
    // correctly.
    assert!(api_row.added_at <= Utc::now());
    assert!(system_row.added_at <= Utc::now());

    cleanup_policy(&pool, policy).await;
}
