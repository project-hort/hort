//! DB-backed destructive-task idempotency adapter tests — part of the
//! Enforced-by set of ADR 0028 (`docs/adr/0028-destructive-task-idempotency.md`).
//!
//! Pins the four-case contract for `JobsRepository::enqueue_task`'s
//! `idempotency_key` parameter and the `jobs_idempotency_key_uq`
//! partial unique index:
//!
//! - **(a)** Two `None`-key enqueues both succeed (today's behaviour
//!   preserved — the partial-unique predicate is inert).
//! - **(b)** Two same-`Some(k)` enqueues — the second returns
//!   `EnqueueOutcome::Duplicate { existing_job_id }` matching the first.
//! - **(c)** Two different-`Some` keys — both succeed.
//! - **(d)** Schema CHECK rejects an invalid-charset key written via
//!   raw SQL (defence in depth — the SQL CHECK matches the Rust
//!   validator 1:1).
//!
//! Every test carries `#[serial(hort_pg_db)]` per CLAUDE.md →
//! *DB-backed test isolation* (mandatory; not optional). Tests connect
//! via the shared `isolated_db_from` helper, so per-test isolation is
//! both at the DB layer (fresh DB) and the serial-test layer (only one
//! DB-backed adapter test crate runs at a time).

#![allow(clippy::expect_used)]

use std::env;

use serial_test::serial;
use sqlx::{PgPool, Row};

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{EnqueueOutcome, JobsRepository};
use hort_domain::types::IdempotencyKey;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// Length boundary — the migration's length CHECK matches the Rust
/// validator at 1..=256. Confirms PG accepts a 256-byte key and rejects
/// a 257-byte key with `23514 check_violation` pointing at
/// `jobs_idempotency_key_length_chk`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn schema_length_check_admits_256_rejects_257() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    // 256 → accept.
    let key_256 = "a".repeat(256);
    let r = sqlx::query(
        "INSERT INTO public.jobs \
            (kind, params, priority, trigger_source, idempotency_key, status) \
         VALUES ($1, $2, $3, $4, $5, 'pending') \
         RETURNING id",
    )
    .bind("noop")
    .bind(sqlx::types::Json(serde_json::json!({})))
    .bind(0i16)
    .bind("manual")
    .bind(&key_256)
    .fetch_one(&pool)
    .await;
    assert!(
        r.is_ok(),
        "256-byte key must satisfy the length CHECK, got {:?}",
        r.err()
    );

    // 257 → reject with the length CHECK.
    let key_257 = "a".repeat(257);
    let err = sqlx::query(
        "INSERT INTO public.jobs \
            (kind, params, priority, trigger_source, idempotency_key, status) \
         VALUES ($1, $2, $3, $4, $5, 'pending') \
         RETURNING id",
    )
    .bind("noop")
    .bind(sqlx::types::Json(serde_json::json!({})))
    .bind(0i16)
    .bind("manual")
    .bind(&key_257)
    .fetch_one(&pool)
    .await
    .expect_err("257-byte key must violate the length CHECK");
    let db_err = err.as_database_error().expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("23514"));
    assert!(
        db_err.message().contains("jobs_idempotency_key_length_chk"),
        "length-CHECK constraint name must surface; got {}",
        db_err.message()
    );
}

/// Regression — the migration's charset regex must compile under
/// Postgres ERE. A prior draft used `{1,256}` for length, which
/// surfaces as `2201B invalid_regular_expression "invalid repetition
/// count(s)"` at INSERT time (Postgres ERE caps `{m,n}` quantifiers
/// at 255). The migration now splits into two CHECK predicates:
/// a charset regex with `+` and a separate `char_length BETWEEN
/// 1 AND 256` length predicate. This test exists so a future tightening
/// of the regex back to `{m,n}` is caught loudly the first time it lands.
#[tokio::test]
#[serial(hort_pg_db)]
async fn schema_charset_regex_compiles_under_pg_ere() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    // The exact regex baked into the migration's CHECK. If this
    // produces 2201B the migration is unusable — every destructive
    // enqueue 500s with the error rather than landing a row.
    let r: bool =
        sqlx::query_scalar("SELECT 'cron:retention-purge:2026-06-04' ~ '^[-A-Za-z0-9._:/]+$'")
            .fetch_one(&pool)
            .await
            .expect("charset regex must compile under PG ERE");
    assert!(r, "the destructive-cron key shape must satisfy the regex");
}

// -- (a) — two None-key enqueues both succeed -------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_task_with_no_idempotency_key_twice_both_succeed() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let params = serde_json::json!({});
    let first = repo
        .enqueue_task("noop", &params, None, 0, "manual", None)
        .await
        .expect("first None-key enqueue must succeed");
    let second = repo
        .enqueue_task("noop", &params, None, 0, "manual", None)
        .await
        .expect("second None-key enqueue must succeed");

    let first_id = match first {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("first call: expected Enqueued, got {other:?}"),
    };
    let second_id = match second {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("second call: expected Enqueued, got {other:?}"),
    };
    assert_ne!(
        first_id, second_id,
        "two None-key enqueues must yield two distinct rows"
    );
}

// -- (b) — same Some(k) enqueued twice, second is Duplicate -----------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_task_with_same_idempotency_key_returns_duplicate() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let key = IdempotencyKey::try_from(format!(
        "cron:retention-purge:{}",
        chrono::Utc::now().format("%Y-%m-%d")
    ))
    .expect("valid key");
    let params = serde_json::json!({});

    let first = repo
        .enqueue_task("noop", &params, None, 0, "manual", Some(&key))
        .await
        .expect("first Some-key enqueue must succeed");
    let second = repo
        .enqueue_task("noop", &params, None, 0, "manual", Some(&key))
        .await
        .expect("second Some-key enqueue must succeed (returns Duplicate)");

    let first_id = match first {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("first call: expected Enqueued, got {other:?}"),
    };
    let existing = match second {
        EnqueueOutcome::Duplicate { existing_job_id } => existing_job_id,
        other => panic!("second call: expected Duplicate, got {other:?}"),
    };
    assert_eq!(
        existing, first_id,
        "Duplicate.existing_job_id must point at the first row"
    );

    // Pin the schema invariant: only ONE row carries this key.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.jobs WHERE idempotency_key = $1")
            .bind(key.as_str())
            .fetch_one(&pool)
            .await
            .expect("count by idempotency_key");
    assert_eq!(count, 1, "partial-unique index must prevent a second row");
}

// -- (c) — two different Some keys both succeed -----------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_task_with_distinct_idempotency_keys_both_succeed() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let key_a = IdempotencyKey::try_from("cron:noop:2026-06-03").expect("valid");
    let key_b = IdempotencyKey::try_from("cron:noop:2026-06-04").expect("valid");
    let params = serde_json::json!({});

    let first = repo
        .enqueue_task("noop", &params, None, 0, "manual", Some(&key_a))
        .await
        .expect("first distinct-key enqueue must succeed");
    let second = repo
        .enqueue_task("noop", &params, None, 0, "manual", Some(&key_b))
        .await
        .expect("second distinct-key enqueue must succeed");

    let first_id = match first {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("first: expected Enqueued, got {other:?}"),
    };
    let second_id = match second {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("second: expected Enqueued, got {other:?}"),
    };
    assert_ne!(
        first_id, second_id,
        "distinct keys must yield distinct rows"
    );
}

// -- (d) — schema CHECK rejects invalid-charset key written via raw SQL ------

#[tokio::test]
#[serial(hort_pg_db)]
async fn schema_check_rejects_invalid_charset_key_via_raw_sql() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    // Bypass the domain validator and try to write a key with a space
    // (disallowed by the Rust regex AND the SQL CHECK). If the schema
    // CHECK is intact this insert fails with a 23514 check_violation;
    // we assert the error surfaces. If the CHECK ever drifts out of
    // sync with the Rust validator, this test fails first.
    let result = sqlx::query(
        "INSERT INTO public.jobs \
            (kind, params, priority, trigger_source, idempotency_key, status) \
         VALUES ($1, $2, $3, $4, $5, 'pending') \
         RETURNING id",
    )
    .bind("noop")
    .bind(sqlx::types::Json(serde_json::json!({})))
    .bind(0i16)
    .bind("manual")
    .bind("idem with space") // invalid: space is outside [A-Za-z0-9-_/:.]
    .fetch_one(&pool)
    .await;

    let err = result.expect_err("raw INSERT with invalid-charset key MUST fail the CHECK");
    let db_err = err
        .as_database_error()
        .expect("error must surface as a database error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "expected check_violation (SQLSTATE 23514), got code={:?} message={}",
        db_err.code(),
        db_err.message()
    );
    let msg = db_err.message();
    assert!(
        msg.contains("jobs_idempotency_key_charset_chk"),
        "constraint name must surface in the error message; got {msg}"
    );

    // Defence in depth: the row must not have leaked into the table.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.jobs WHERE idempotency_key = $1")
            .bind("idem with space")
            .fetch_one(&pool)
            .await
            .expect("post-failure count");
    assert_eq!(count, 0, "no row may exist after the CHECK rejection");
}

// -- supplementary: domain validator and SQL CHECK match 1:1 -----------------

/// Cross-validate that every byte rejected by `IdempotencyKey::try_from`
/// is also rejected by the SQL CHECK (i.e. the regex on the column).
/// Without this, a domain-bypass write path could smuggle a malformed
/// key past the schema and into the partial-unique index.
#[tokio::test]
#[serial(hort_pg_db)]
async fn schema_check_matches_domain_validator_on_sampled_byte_classes() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    for bad in ["", "with space", "tab\there", "plus+sign", "amp&sign"] {
        // Domain rejects:
        assert!(
            IdempotencyKey::try_from(bad).is_err(),
            "domain validator must reject {bad:?}"
        );

        // SQL CHECK rejects too (CHECK runs after a CHECK on NULL — we
        // skip empty because PG strips it to NULL only if the column
        // has NULL default *behaviour*; the explicit-bind path here
        // never triggers that, so the regex sees the literal empty
        // string and rejects). Empty input matches `^…{1,256}$` only if
        // length≥1 — the length-floor is part of the contract.
        let result = sqlx::query(
            "INSERT INTO public.jobs \
                (kind, params, priority, trigger_source, idempotency_key, status) \
             VALUES ($1, $2, $3, $4, $5, 'pending') \
             RETURNING id",
        )
        .bind("noop")
        .bind(sqlx::types::Json(serde_json::json!({})))
        .bind(0i16)
        .bind("manual")
        .bind(bad)
        .fetch_one(&pool)
        .await;

        let err = result.expect_err(&format!(
            "SQL CHECK must reject {bad:?} (matches domain validator)"
        ));
        let db_err = err
            .as_database_error()
            .expect("error must surface as a database error");
        assert_eq!(
            db_err.code().as_deref(),
            Some("23514"),
            "expected check_violation for {bad:?}, got code={:?}",
            db_err.code()
        );
    }
}

/// Pin the `priority` and `idempotency_key` columns round-trip through
/// the `Enqueued` outcome — a future column-name rename in the CTE that
/// silently drops the partial-unique projection would be caught here.
#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_task_persists_idempotency_key_for_some_path() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let key = IdempotencyKey::try_from("cron:eventstore-archive:2026-06-03").expect("valid");
    let outcome = repo
        .enqueue_task(
            "noop",
            &serde_json::json!({}),
            None,
            0,
            "manual",
            Some(&key),
        )
        .await
        .expect("enqueue");
    let job_id = match outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued, got {other:?}"),
    };

    let row = sqlx::query("SELECT idempotency_key FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read");
    let persisted: Option<String> = row.get("idempotency_key");
    assert_eq!(persisted.as_deref(), Some(key.as_str()));
}

/// `None` path leaves the column as SQL NULL — preserves today's
/// behaviour for non-destructive callers.
#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_task_leaves_idempotency_key_null_for_none_path() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let outcome = repo
        .enqueue_task("noop", &serde_json::json!({}), None, 0, "manual", None)
        .await
        .expect("enqueue");
    let job_id = match outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued, got {other:?}"),
    };

    let row = sqlx::query("SELECT idempotency_key FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read");
    let persisted: Option<String> = row.get("idempotency_key");
    assert!(
        persisted.is_none(),
        "None-key path must leave the column SQL NULL"
    );
}
