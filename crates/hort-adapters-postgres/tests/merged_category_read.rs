//! `EventStore::read_categories` against a live database: the Postgres
//! adapter's `UNION ALL`/`Merge Append` override must return the same
//! thing the port's default merge does — ONE `global_position`-ordered
//! page across the categories asked for.
//!
//! This is the correctness half. The cost half — why the statement is
//! shaped the way it is, and the two shapes it must never become — is
//! `tests/merged_category_read_plan_stability.rs` and the module docs of
//! `src/merged_category_read.rs`.
//!
//! The property under test is what makes a single persisted
//! `last_delivered_position` honest for a multi-category subscriber: the
//! page is a prefix of the merged stream, so a consumer that has passed
//! position P has read P in *every* subscribed category. A per-category
//! concatenation would satisfy "returns the right events" and still break
//! that, which is why the assertions are about order and truncation rather
//! than set membership.
//!
//! Needs a live PostgreSQL; without `DATABASE_URL` each test early-returns,
//! matching the convention in `event_store.rs`. Each takes a throwaway
//! database via `isolated_db_from` and carries the crate-wide
//! `#[serial(hort_pg_db)]` key: a per-test database is not isolation from
//! the cluster-global work the migration set and the stale-database
//! sweeper do.

use std::env;

use chrono::Utc;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::events::{
    system_actor, AuthenticationAttempted, DomainEvent, StreamCategory, StreamId,
};
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, SubscribeFrom,
};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Append one event to a fresh stream in `category` and return its
/// `global_position`.
///
/// The payload is always `AuthenticationAttempted`. The adapter is pure
/// persistence — it binds `stream_id` from the batch and the payload from
/// the event, and does not cross-check the two (ADR 0004) — so one payload
/// shape lets these tests place events in any category without dragging in
/// each category's own event vocabulary. What is under test is the read,
/// not the write.
async fn append_to(store: &PgEventStore, category: StreamCategory) -> u64 {
    let batch = AppendEvents {
        stream_id: StreamId {
            category,
            entity_id: Uuid::new_v4(),
        },
        expected_version: ExpectedVersion::NoStream,
        events: vec![EventToAppend::new(DomainEvent::AuthenticationAttempted(
            AuthenticationAttempted {
                client_ip: "127.0.0.1".parse().expect("literal ip"),
                result: "local_invalid_credentials".into(),
                external_id_if_decoded: None,
                at: Utc::now(),
            },
        ))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    };
    let result = store.append(batch).await.expect("append succeeds");
    result.global_positions[0]
}

fn positions(events: &[hort_domain::events::PersistedEvent]) -> Vec<u64> {
    events.iter().map(|e| e.global_position).collect()
}

/// Events interleaved across three categories come back in one
/// `global_position` order, not category by category.
///
/// The interleaving is the point: if the adapter concatenated per-category
/// pages, this returns the same six events in a different order, and a
/// caller that checkpointed the last one would have skipped the ones below
/// it belonging to the other categories.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_merged_read_returns_one_globally_ordered_page() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let mut expected = Vec::new();
    for category in [
        StreamCategory::Ref,
        StreamCategory::Artifact,
        StreamCategory::Policy,
        StreamCategory::Artifact,
        StreamCategory::Ref,
        StreamCategory::Policy,
    ] {
        expected.push(append_to(&store, category).await);
    }

    let page = store
        .read_categories(
            &[
                StreamCategory::Artifact,
                StreamCategory::Policy,
                StreamCategory::Ref,
            ],
            SubscribeFrom::Start,
            100,
        )
        .await
        .expect("merged read succeeds");

    assert_eq!(
        positions(&page),
        expected,
        "the page must be the merged stream in global order"
    );
}

/// The page is the merged stream's FIRST `max_count` events — not
/// `max_count` per category.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_merged_read_truncates_to_the_merged_streams_first_page() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let mut all = Vec::new();
    for category in [
        StreamCategory::Artifact,
        StreamCategory::Ref,
        StreamCategory::Artifact,
        StreamCategory::Ref,
        StreamCategory::Artifact,
        StreamCategory::Ref,
    ] {
        all.push(append_to(&store, category).await);
    }

    let page = store
        .read_categories(
            &[StreamCategory::Artifact, StreamCategory::Ref],
            SubscribeFrom::Start,
            3,
        )
        .await
        .expect("merged read succeeds");

    assert_eq!(
        positions(&page),
        all[..3].to_vec(),
        "a limit of 3 over two categories is 3 rows total, not 3 per arm"
    );
}

/// Paging forward from the last position of a page is contiguous: no
/// event is returned twice and none is skipped.
#[tokio::test]
#[serial(hort_pg_db)]
async fn paging_forward_from_the_page_end_is_contiguous() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let mut all = Vec::new();
    for i in 0..7 {
        let category = if i % 2 == 0 {
            StreamCategory::Artifact
        } else {
            StreamCategory::Ref
        };
        all.push(append_to(&store, category).await);
    }

    let categories = [StreamCategory::Artifact, StreamCategory::Ref];
    let mut walked = Vec::new();
    let mut from = SubscribeFrom::Start;
    loop {
        let page = store
            .read_categories(&categories, from, 2)
            .await
            .expect("merged read succeeds");
        if page.is_empty() {
            break;
        }
        let short = page.len() < 2;
        walked.extend(positions(&page));
        from = SubscribeFrom::AfterGlobal(page.last().expect("non-empty").global_position);
        if short {
            // A short page means every category is at its head — the
            // signal `catch_up` stops on.
            break;
        }
    }

    assert_eq!(
        walked, all,
        "walking page by page must visit every position exactly once, in order"
    );
}

/// `AfterGlobal` is exclusive, and it is exclusive across the whole merged
/// stream rather than per category.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_merged_read_starts_strictly_above_the_cursor() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let first = append_to(&store, StreamCategory::Artifact).await;
    let second = append_to(&store, StreamCategory::Ref).await;
    let third = append_to(&store, StreamCategory::Artifact).await;

    let page = store
        .read_categories(
            &[StreamCategory::Artifact, StreamCategory::Ref],
            SubscribeFrom::AfterGlobal(first),
            100,
        )
        .await
        .expect("merged read succeeds");
    assert_eq!(positions(&page), vec![second, third]);
}

/// Only the categories asked for. A subscriber must never be handed an
/// event from a category outside its filter — at delivery the filter walk
/// would drop it, but the cursor would already have moved over it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_merged_read_excludes_categories_that_were_not_asked_for() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let artifact = append_to(&store, StreamCategory::Artifact).await;
    let _policy = append_to(&store, StreamCategory::Policy).await;
    let artifact2 = append_to(&store, StreamCategory::Artifact).await;

    let page = store
        .read_categories(&[StreamCategory::Artifact], SubscribeFrom::Start, 100)
        .await
        .expect("merged read succeeds");
    assert_eq!(positions(&page), vec![artifact, artifact2]);
}

/// A repeated category is read once. The statement carries one arm per
/// distinct category, so a duplicate would otherwise return every one of
/// its events twice — and the caller would deliver them twice.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repeated_category_is_read_once() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let first = append_to(&store, StreamCategory::Artifact).await;
    let second = append_to(&store, StreamCategory::Artifact).await;

    let page = store
        .read_categories(
            &[
                StreamCategory::Artifact,
                StreamCategory::Artifact,
                StreamCategory::Artifact,
            ],
            SubscribeFrom::Start,
            100,
        )
        .await
        .expect("merged read succeeds");
    assert_eq!(positions(&page), vec![first, second]);
}

/// An empty category list is an empty page, not an error and not a query.
/// A zero-arm `UNION ALL` is not valid SQL, so the adapter has to answer
/// this one itself.
#[tokio::test]
#[serial(hort_pg_db)]
async fn no_categories_is_an_empty_page() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    append_to(&store, StreamCategory::Artifact).await;

    let page = store
        .read_categories(&[], SubscribeFrom::Start, 100)
        .await
        .expect("an empty filter is not an error");
    assert!(page.is_empty());
}

/// The order the caller lists its categories in must not change the
/// result — nor, since the statement text is built from that list, the
/// prepared statement the connection caches.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_caller_s_category_order_does_not_change_the_page() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    for category in [
        StreamCategory::Ref,
        StreamCategory::Artifact,
        StreamCategory::Policy,
    ] {
        append_to(&store, category).await;
    }

    let forward = store
        .read_categories(
            &[
                StreamCategory::Artifact,
                StreamCategory::Policy,
                StreamCategory::Ref,
            ],
            SubscribeFrom::Start,
            100,
        )
        .await
        .expect("merged read succeeds");
    let reverse = store
        .read_categories(
            &[
                StreamCategory::Ref,
                StreamCategory::Policy,
                StreamCategory::Artifact,
            ],
            SubscribeFrom::Start,
            100,
        )
        .await
        .expect("merged read succeeds");
    assert_eq!(positions(&forward), positions(&reverse));
}

/// Every filterable category at once, which is also the widest statement
/// the builder produces (one arm each). Pins that the arity does not break
/// the statement and that the merge still holds at full width.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_merge_holds_across_every_category() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool).await.expect("event store");
    let all = [
        StreamCategory::Artifact,
        StreamCategory::Policy,
        StreamCategory::Admin,
        StreamCategory::Ref,
        StreamCategory::ArtifactGroup,
        StreamCategory::Curation,
        StreamCategory::Repository,
        StreamCategory::AuthAttempts,
        StreamCategory::Authorization,
        StreamCategory::User,
        StreamCategory::DownloadAudit,
        StreamCategory::TokenUse,
        StreamCategory::RetentionPolicy,
    ];
    let mut expected = Vec::new();
    for category in all {
        expected.push(append_to(&store, category).await);
    }

    let page = store
        .read_categories(&all, SubscribeFrom::Start, 100)
        .await
        .expect("merged read succeeds at full width");
    assert_eq!(positions(&page), expected);
}
