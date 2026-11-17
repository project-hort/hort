//! `PgApiTokenRepository` integration tests.
//!
//! Asserts the adapter contract:
//!
//! 1. `insert_then_find_by_id_round_trips` — a `pat` token round-trips
//!    through the adapter (insert → find_by_id) without losing fields.
//! 2. `find_by_prefix_returns_some_on_hit_none_on_miss` — the hot
//!    validator path. Miss is `Ok(None)`, NOT `Err(NotFound)` — the
//!    constant-time invariant lives in the use case, not the adapter.
//! 3. `list_for_user_orders_by_created_at_desc` — list paginates with
//!    descending `created_at`, total count matches.
//! 4. `update_last_used_buckets_ipv4_to_24` — write `203.0.113.42`,
//!    read back `203.0.113.0/24`. (Acceptance bullet 4 sub-bullet a.)
//! 5. `update_last_used_buckets_ipv6_to_48` — IPv6 input round-trips
//!    through `client_ip_bucket` exactly (the helper's wire form is
//!    the spec, not a hand-rolled string). (Sub-bullet b.)
//! 6. `update_last_used_truncates_user_agent_to_256_bytes` — 4 KB UA
//!    surfaces as 256 chars on read. (Sub-bullet c.)
//! 7. `update_last_used_respects_utf8_boundary_on_truncation` —
//!    multi-byte char straddling the 256-byte boundary does NOT crash
//!    the adapter; the persisted string is valid UTF-8. (Sub-bullet c
//!    second clause.)
//! 8. `update_last_used_passes_through_malformed_ip` — a non-parseable
//!    IP is stored verbatim, NOT crashed. (Sub-bullet d.)
//! 9. `revoke_sets_revoked_at_idempotently` — first revoke flips the
//!    column; double-revoke is a no-op (no error).
//! 10. `insert_round_trips_every_issued_via_value` — the provenance
//!     column survives the INSERT bind and the SELECT decode, which are
//!     two separate statements in the adapter.
//! 11. `operator_authority_query_separates_identities_from_exchange_rows`
//!     — the query the column exists for, over rows that `kind`,
//!     `revoked_at` and `created_by_user_id` cannot separate.
//! 12. The credential-store retention sweep's predicate, **one test per
//!     NULL case** rather than one sweep over a mixed fixture:
//!     `retention_sweep_deletes_a_row_expired_past_the_horizon`,
//!     `…_keeps_a_row_expired_inside_the_horizon`,
//!     `…_deletes_a_row_revoked_past_the_horizon`,
//!     `…_keeps_a_row_revoked_inside_the_horizon`,
//!     `…_keeps_a_row_with_both_marks_null`, and
//!     `…_keeps_a_row_whose_only_old_mark_is_a_future_expiry`. The
//!     both-NULL case is the one that matters most and is deliberately
//!     its own test rather than a corollary of another: that row is a
//!     durable identity that never expires, and a `COALESCE`-flattened
//!     or negated predicate reaches it. A mixed fixture asserting one
//!     deleted count would pass with the branches swapped.
//!
//! These tests follow the project convention (mirrored from
//! `api_tokens_migration.rs`): require `DATABASE_URL` to be set;
//! when unset, every test early-returns silently so dev environments
//! without a database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test api_token_repo
//! ```

#![allow(clippy::expect_used)]

use serial_test::serial;
use std::env;

use chrono::{Duration, Utc};
use hort_adapters_postgres::api_token_repo::PgApiTokenRepository;
use hort_domain::entities::api_token::{ApiToken, IssuedVia, TokenKind};
use hort_domain::entities::rbac::Permission;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::types::PageRequest;
use sqlx::PgPool;
use uuid::Uuid;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Insert a minimal-but-valid `users` row and return the id. Mirrors
/// `api_tokens_migration.rs::create_test_user`.
async fn create_test_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("apitoken_b4_{}", id.simple()))
    .bind(format!("apitoken_b4_{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

fn sample_token(user_id: Uuid, prefix: &str) -> ApiToken {
    ApiToken {
        id: Uuid::new_v4(),
        user_id,
        name: format!("ci-{}", &prefix[..4]),
        description: Some("api_token round-trip test".into()),
        kind: TokenKind::Pat,
        token_hash: "$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel".into(),
        token_prefix: prefix.to_string(),
        declared_permissions: vec![Permission::Read, Permission::Write],
        repository_ids: None,
        expires_at: Some(Utc::now() + Duration::days(90)),
        revoked_at: None,
        last_used_at: None,
        last_used_ip: None,
        last_used_user_agent: None,
        created_by_user_id: user_id,
        created_at: Utc::now(),
        issued_via: IssuedVia::HttpMint,
    }
}

// ---------------------------------------------------------------------------
// Acceptance — insert + find_by_id round-trip (bullet 1).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn insert_then_find_by_id_round_trips() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "abcd0001");

    repo.insert(&token).await.expect("insert succeeds");

    let fetched = repo
        .find_by_id(token.id)
        .await
        .expect("find_by_id succeeds");
    assert_eq!(fetched.id, token.id);
    assert_eq!(fetched.user_id, token.user_id);
    assert_eq!(fetched.kind, TokenKind::Pat);
    assert_eq!(fetched.token_prefix, "abcd0001");
    assert_eq!(
        fetched.declared_permissions,
        vec![Permission::Read, Permission::Write]
    );
    assert!(fetched.expires_at.is_some());
    assert!(fetched.revoked_at.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance — find_by_prefix returns Option<ApiToken> (bullet 3).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn find_by_prefix_returns_some_on_hit_none_on_miss() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "deadbeef");
    repo.insert(&token).await.expect("insert succeeds");

    // Hit.
    let hit = repo
        .find_by_prefix("deadbeef")
        .await
        .expect("find_by_prefix succeeds on hit");
    assert!(hit.is_some(), "prefix lookup must surface inserted token");
    assert_eq!(hit.unwrap().id, token.id);

    // Miss — the constant-time invariant lives in the use case;
    // the adapter MUST NOT raise NotFound here, just `Ok(None)`.
    let miss = repo
        .find_by_prefix("ffffffff")
        .await
        .expect("find_by_prefix succeeds on miss (Ok(None), not Err)");
    assert!(miss.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance — list_for_user paginates (bullet 1 supporting).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_for_user_orders_by_created_at_desc() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);

    // Insert three tokens in known order so the descending-by-created_at
    // contract is observable. Bump the timestamp explicitly so two
    // inserts in the same millisecond don't tie.
    let now = Utc::now();
    let mut t1 = sample_token(user_id, "11111111");
    t1.created_at = now - Duration::seconds(20);
    let mut t2 = sample_token(user_id, "22222222");
    t2.created_at = now - Duration::seconds(10);
    let mut t3 = sample_token(user_id, "33333333");
    t3.created_at = now;

    repo.insert(&t1).await.expect("insert t1");
    repo.insert(&t2).await.expect("insert t2");
    repo.insert(&t3).await.expect("insert t3");

    let page = repo
        .list_for_user(user_id, PageRequest::new(0, 10))
        .await
        .expect("list_for_user succeeds");
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 3);
    // Newest first.
    assert_eq!(page.items[0].id, t3.id);
    assert_eq!(page.items[1].id, t2.id);
    assert_eq!(page.items[2].id, t1.id);
}

// ---------------------------------------------------------------------------
// Acceptance bullet 4 — update_last_used buckets IPv4 to /24.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn update_last_used_buckets_ipv4_to_24() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "ip4bucke");
    repo.insert(&token).await.expect("insert");

    let when = Utc::now();
    repo.update_last_used(token.id, when, Some("203.0.113.42"), Some("curl/8.4"))
        .await
        .expect("update_last_used succeeds");

    let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
    assert_eq!(fetched.last_used_ip.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(fetched.last_used_user_agent.as_deref(), Some("curl/8.4"));
    assert!(fetched.last_used_at.is_some());
}

// ---------------------------------------------------------------------------
// Acceptance bullet 4 sub-bullet b — update_last_used buckets IPv6 to /48.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn update_last_used_buckets_ipv6_to_48() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "ip6bucke");
    repo.insert(&token).await.expect("insert");

    // Use the same input form the brute-force lockout consumer would
    // hand the adapter — verify against what `client_ip_bucket`
    // produces, NOT a hand-rolled expectation, so the test cannot
    // drift from the helper.
    let raw = "2001:db8:abcd:0012:0000:0000:0000:0001";
    let parsed: std::net::IpAddr = raw.parse().expect("test input parses");
    let expected = hort_app::metrics::client_ip_bucket(parsed);

    repo.update_last_used(token.id, Utc::now(), Some(raw), None)
        .await
        .expect("update_last_used succeeds");

    let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
    assert_eq!(fetched.last_used_ip.as_deref(), Some(expected.as_str()));
    // Sanity — the helper emits the /48 form.
    assert!(expected.ends_with("/48"));
}

// ---------------------------------------------------------------------------
// Acceptance bullet 4 sub-bullet c — UA truncation to 256 bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn update_last_used_truncates_user_agent_to_256_bytes() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "uatrunc8");
    repo.insert(&token).await.expect("insert");

    let huge_ua = "x".repeat(4096);
    repo.update_last_used(token.id, Utc::now(), None, Some(&huge_ua))
        .await
        .expect("update_last_used succeeds with huge UA");

    let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
    let stored = fetched.last_used_user_agent.expect("UA persisted");
    assert_eq!(stored.len(), 256, "UA must be truncated to 256 bytes");
    assert!(stored.chars().all(|c| c == 'x'));
}

// ---------------------------------------------------------------------------
// Acceptance bullet 4 sub-bullet c (UTF-8 boundary clause).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn update_last_used_respects_utf8_boundary_on_truncation() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "utf8boun");
    repo.insert(&token).await.expect("insert");

    // 254 bytes ASCII + a 3-byte EURO SIGN at bytes 254..257 + filler.
    // Naive byte truncation at 256 lands inside the multi-byte
    // sequence and would panic via `String::truncate`. The
    // boundary-aware truncator drops the EURO SIGN wholly.
    let mut ua = "x".repeat(254);
    ua.push('\u{20AC}');
    ua.extend(std::iter::repeat_n('y', 100));
    assert!(ua.len() > 256);

    repo.update_last_used(token.id, Utc::now(), None, Some(&ua))
        .await
        .expect("update_last_used must not panic on multi-byte boundary");

    let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
    let stored = fetched.last_used_user_agent.expect("UA persisted");
    // String::from_utf8 round-trip via as_bytes — torn UTF-8 would
    // fail this check.
    assert!(std::str::from_utf8(stored.as_bytes()).is_ok());
    // The 3-byte char straddled bytes 254..256; the adapter walked
    // back to 254, dropping it wholly.
    assert_eq!(stored.len(), 254);
    assert!(stored.chars().all(|c| c == 'x'));
}

// ---------------------------------------------------------------------------
// Acceptance bullet 4 sub-bullet d — malformed IP stored verbatim.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn update_last_used_passes_through_malformed_ip() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "malforip");
    repo.insert(&token).await.expect("insert");

    // The validation layer filters bad IP strings; the adapter MUST
    // NOT crash on one. The garbage round-trips verbatim — operators
    // can grep for it as a debug signal.
    let garbage = "not-an-ip-string";
    repo.update_last_used(token.id, Utc::now(), Some(garbage), None)
        .await
        .expect("update_last_used must not crash on a bad IP string");

    let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
    assert_eq!(fetched.last_used_ip.as_deref(), Some(garbage));
}

// ---------------------------------------------------------------------------
// Acceptance — revoke is idempotent.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn revoke_sets_revoked_at_idempotently() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);
    let token = sample_token(user_id, "revokeid");
    repo.insert(&token).await.expect("insert");

    // First revoke flips the column.
    repo.revoke(token.id).await.expect("first revoke succeeds");
    let after_first = repo.find_by_id(token.id).await.expect("find_by_id");
    let first_revoked_at = after_first
        .revoked_at
        .expect("revoked_at must be Some after first revoke");

    // Second revoke is a no-op — the row's `revoked_at` stays at the
    // first-revoke timestamp because the UPDATE is gated on
    // `revoked_at IS NULL`.
    repo.revoke(token.id)
        .await
        .expect("second revoke is idempotent");
    let after_second = repo.find_by_id(token.id).await.expect("find_by_id");
    assert_eq!(
        after_second.revoked_at,
        Some(first_revoked_at),
        "revoked_at must not advance on double-revoke"
    );
}

// ---------------------------------------------------------------------------
// Acceptance — find_by_id raises NotFound for an unknown id.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn find_by_id_raises_not_found_on_unknown_id() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgApiTokenRepository::new(pool);
    let err = repo
        .find_by_id(Uuid::new_v4())
        .await
        .expect_err("unknown id must surface as NotFound, not None");
    assert!(matches!(
        err,
        hort_domain::error::DomainError::NotFound {
            entity: "ApiToken",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// `issued_via` — the adapter writes and reads back the provenance, and the
// operator authority query separates identities from exchange rows.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn insert_round_trips_every_issued_via_value() {
    // The INSERT bind and the SELECT decode are two separate statements
    // in the adapter, so a value that writes but does not read back
    // (or the reverse) is a real failure mode: one column dropped from
    // `SELECT_COLS` and every read turns into a hard error, one missing
    // bind and every row lands on the column default.
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool);

    for (i, via) in [
        IssuedVia::Unknown,
        IssuedVia::AdminCli,
        IssuedVia::HttpMint,
        IssuedVia::FederationExchange,
        IssuedVia::Bootstrap,
        IssuedVia::ServiceAccountRotation,
    ]
    .into_iter()
    .enumerate()
    {
        let token = ApiToken {
            issued_via: via,
            ..sample_token(user_id, &format!("via{i:05}"))
        };
        repo.insert(&token).await.expect("insert succeeds");
        let fetched = repo.find_by_id(token.id).await.expect("find_by_id");
        assert_eq!(fetched.issued_via, via, "round trip failed for {via:?}");
    }
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn operator_authority_query_separates_identities_from_exchange_rows() {
    // The query this column exists for: the token cap lives in the row
    // rather than in an envelope (ADR 0012), so establishing an
    // identity's effective authority means reading `name`,
    // `declared_permissions` and `repository_ids` out of `api_tokens`.
    // Every row below is `kind = 'pat'` or `'service_account'` and
    // every one of them is live, so `kind`, `revoked_at` and
    // `created_by_user_id` cannot tell the identities from the
    // exchange residue — `issued_via` is what does.
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    let repo = PgApiTokenRepository::new(pool.clone());

    let mut expected_identities = Vec::new();
    for (i, (name, kind, via)) in [
        (
            "durable-ci-pusher",
            TokenKind::ServiceAccount,
            IssuedVia::AdminCli,
        ),
        (
            "durable-rotated",
            TokenKind::ServiceAccount,
            IssuedVia::ServiceAccountRotation,
        ),
        ("durable-human-pat", TokenKind::Pat, IssuedVia::HttpMint),
        ("durable-pre-column", TokenKind::Pat, IssuedVia::Unknown),
        ("durable-break-glass", TokenKind::Pat, IssuedVia::Bootstrap),
        (
            "exchange-ci-job-a",
            TokenKind::ServiceAccount,
            IssuedVia::FederationExchange,
        ),
        (
            "exchange-ci-job-b",
            TokenKind::ServiceAccount,
            IssuedVia::FederationExchange,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let token = ApiToken {
            name: name.to_string(),
            kind,
            issued_via: via,
            ..sample_token(user_id, &format!("opq{i:05}"))
        };
        if via != IssuedVia::FederationExchange {
            expected_identities.push(name.to_string());
        }
        repo.insert(&token).await.expect("insert succeeds");
    }
    // A revoked identity is out of scope either way — the query asks
    // about live authority.
    let revoked = ApiToken {
        name: "revoked-identity".into(),
        issued_via: IssuedVia::AdminCli,
        ..sample_token(user_id, "opqrevok")
    };
    repo.insert(&revoked).await.expect("insert succeeds");
    repo.revoke(revoked.id).await.expect("revoke succeeds");

    let rows: Vec<(String, Vec<String>, Option<Vec<Uuid>>)> = sqlx::query_as(
        "SELECT name, declared_permissions, repository_ids \
           FROM public.api_tokens \
          WHERE revoked_at IS NULL \
            AND issued_via <> 'federation_exchange' \
            AND user_id = $1 \
          ORDER BY name",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .expect("the operator authority query runs");

    expected_identities.sort();
    let names: Vec<String> = rows.iter().map(|(n, _, _)| n.clone()).collect();
    assert_eq!(
        names, expected_identities,
        "the query must answer with exactly the durable identities — \
         the exchange rows and the revoked row are out"
    );
    // And it answers with the cap, which is the point of asking.
    for (_, permissions, _) in &rows {
        assert_eq!(permissions, &vec!["read".to_string(), "write".to_string()]);
    }
}

// ---------------------------------------------------------------------------
// Acceptance — the credential-store retention sweep's predicate
// (bullet 12).
//
// `delete_expired_or_revoked_older_than` is the one statement in this
// adapter that removes a credential, and the table it removes it from is
// the one that decides who may do what. So the predicate is asserted
// **per branch**, against a real Postgres, rather than by one sweep over
// a mixed fixture whose single deleted count would be satisfied by the
// branches being swapped.
//
// Each test seeds exactly one row for a fresh user in an isolated
// database and asserts on that row's survival, so the two directions are
// never read off the same number.
// ---------------------------------------------------------------------------

/// The horizon every test below measures against — the handler's
/// `DEFAULT_HORIZON`, re-stated here as a `chrono::Duration` because the
/// fixtures place timestamps and the port takes a `std::time::Duration`.
const HORIZON_DAYS: i64 = 90;

fn horizon() -> std::time::Duration {
    std::time::Duration::from_secs((HORIZON_DAYS as u64) * 24 * 60 * 60)
}

/// Does a row with this id still exist?
async fn row_exists(pool: &PgPool, id: Uuid) -> bool {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM public.api_tokens WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count the row");
    n == 1
}

/// Seed one token for a fresh user, with the two marks set explicitly.
/// Written through SQL rather than `repo.insert` because `insert` has no
/// way to place `revoked_at` (the adapter's `revoke` sets it to `NOW()`),
/// and the whole point here is to place both marks at chosen times.
async fn seed_token_with_marks(
    pool: &PgPool,
    prefix: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let user_id = create_test_user(pool).await;
    let token = ApiToken {
        expires_at,
        revoked_at,
        ..sample_token(user_id, prefix)
    };
    sqlx::query(
        "INSERT INTO public.api_tokens \
           (id, user_id, name, description, kind, token_hash, token_prefix, \
            declared_permissions, repository_ids, expires_at, revoked_at, \
            created_by_user_id, created_at, issued_via) \
         VALUES ($1, $2, $3, $4, 'pat', $5, $6, ARRAY['read']::text[], NULL, $7, $8, $9, \
                 now(), 'http_mint')",
    )
    .bind(token.id)
    .bind(token.user_id)
    .bind(&token.name)
    .bind(&token.description)
    .bind(&token.token_hash)
    .bind(&token.token_prefix)
    .bind(token.expires_at)
    .bind(token.revoked_at)
    .bind(token.created_by_user_id)
    .execute(pool)
    .await
    .expect("seed api_tokens row with explicit marks");
    token.id
}

/// A row whose `expires_at` is older than the horizon is deleted.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_deletes_a_row_expired_past_the_horizon() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let id = seed_token_with_marks(
        &pool,
        "exppast1",
        Some(Utc::now() - Duration::days(HORIZON_DAYS + 1)),
        None,
    )
    .await;

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(deleted, 1, "the one eligible row is the one deleted");
    assert!(
        !row_exists(&pool, id).await,
        "a row expired longer than the horizon must be gone"
    );
}

/// A row whose `expires_at` is inside the horizon survives. The
/// credential is already dead; what the window is still holding is its
/// last-use trail.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_keeps_a_row_expired_inside_the_horizon() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let id = seed_token_with_marks(
        &pool,
        "expinsid",
        Some(Utc::now() - Duration::days(HORIZON_DAYS - 1)),
        None,
    )
    .await;

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(deleted, 0, "nothing in this database is eligible yet");
    assert!(
        row_exists(&pool, id).await,
        "a row expired inside the horizon must survive"
    );
}

/// A row whose `revoked_at` is older than the horizon is deleted — the
/// second disjunct, asserted on its own rather than inferred from the
/// first.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_deletes_a_row_revoked_past_the_horizon() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    // `expires_at` left NULL on purpose: this row is eligible *only*
    // through the revocation disjunct, so a predicate that lost that
    // disjunct fails here rather than passing on the other one.
    let id = seed_token_with_marks(
        &pool,
        "revpast1",
        None,
        Some(Utc::now() - Duration::days(HORIZON_DAYS + 1)),
    )
    .await;

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(deleted, 1, "the one eligible row is the one deleted");
    assert!(
        !row_exists(&pool, id).await,
        "a row revoked longer than the horizon must be gone"
    );
}

/// A row revoked inside the horizon survives.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_keeps_a_row_revoked_inside_the_horizon() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let id = seed_token_with_marks(
        &pool,
        "revinsid",
        None,
        Some(Utc::now() - Duration::days(HORIZON_DAYS - 1)),
    )
    .await;

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(deleted, 0, "nothing in this database is eligible yet");
    assert!(
        row_exists(&pool, id).await,
        "a row revoked inside the horizon must survive"
    );
}

/// **The one that matters.** A row with `expires_at IS NULL` and
/// `revoked_at IS NULL` is a durable identity that never expires, and the
/// sweep must never reach it — however old the row itself is.
///
/// Its own test rather than a corollary of the four above: it is the
/// failure a `COALESCE(expires_at, revoked_at) < now() - $horizon` or a
/// `NOT (…still live…)` predicate produces, and either of those would
/// pass every other test in this block. The `created_at` is placed well
/// past the horizon so that a predicate which quietly started measuring
/// from the wrong column fails here too.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_keeps_a_row_with_both_marks_null() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let id = seed_token_with_marks(&pool, "durable1", None, None).await;
    sqlx::query(
        "UPDATE public.api_tokens SET created_at = now() - interval '5 years' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("age the durable identity well past the horizon");

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(
        deleted, 0,
        "a credential with neither mark set is live; the sweep must delete nothing"
    );
    assert!(
        row_exists(&pool, id).await,
        "a row with both marks NULL is a durable identity and must survive any horizon"
    );
}

/// A row whose only non-NULL mark is a *future* `expires_at` survives.
///
/// The complement of the both-NULL case: here a mark IS present, so a
/// predicate that tested only `IS NOT NULL` without comparing the
/// timestamp would delete it. Together the two tests pin both halves of
/// each disjunct — the mark must be present AND older than the horizon.
#[tokio::test]
#[serial(hort_pg_db)]
async fn retention_sweep_keeps_a_row_whose_only_old_mark_is_a_future_expiry() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let id = seed_token_with_marks(
        &pool,
        "futureex",
        Some(Utc::now() + Duration::days(30)),
        None,
    )
    .await;

    let repo = PgApiTokenRepository::new(pool.clone());
    let deleted = repo
        .delete_expired_or_revoked_older_than(horizon())
        .await
        .expect("the sweep runs");

    assert_eq!(deleted, 0, "a credential that has not expired yet is live");
    assert!(
        row_exists(&pool, id).await,
        "a row with a future expiry must survive"
    );
}
