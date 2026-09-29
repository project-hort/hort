//! The statement behind `EventStore::read_categories` on Postgres: one
//! `global_position`-ordered page across several stream categories.
//!
//! Lives in its own module because the *shape* of this statement is the
//! contract, not an implementation detail — the notification dispatcher
//! runs it once every `STORE_POLL_INTERVAL` (5s) per subscription, and
//! two semantically identical spellings of it differ by four orders of
//! magnitude in what they read.
//! `tests/merged_category_read_plan_stability.rs` scans this file to keep
//! the shape from drifting.
//!
//! # The shape, and the two shapes it is not
//!
//! Measured against 200 000 seeded events with a realistic skew — a
//! `repository` category holding 16% of the rows but none above position
//! 39 999, under `artifact` / `auth` / `download_audit` neighbours that
//! churn to the head — with `EXPLAIN (ANALYZE, BUFFERS)` of real
//! server-side prepared statements, on the 7th execution of each, under
//! `plan_cache_mode` forced to `force_generic_plan` as well as left on
//! `auto`:
//!
//! | shape | quiet 3-category read, 160k rows above the mark | caught-up read |
//! |---|---|---|
//! | `stream_category = ANY($1) … ORDER BY global_position` | 160 641 buffers, 33.9 ms, 160 001 rows discarded | 3 buffers |
//! | row-value keyset `(stream_category, global_position) > (cat, $n)` per category | 247 buffers, 0.61 ms | 919 buffers, 2.5 ms |
//! | **this one** — `UNION ALL` of per-category keyset arms, merged | **9 buffers, 0.011 ms** | **3 buffers** |
//!
//! **Not `stream_category = ANY($1)`.** With an array predicate the
//! composite `(stream_category, global_position)` index cannot deliver
//! `ORDER BY global_position` without sorting every matching row, so the
//! planner takes `events_global_position_key` plus a filter and the read
//! costs O(rows of every *other* category above the mark) — it scans and
//! discards 160 001 rows to return nothing, every tick, and it does so
//! identically under a custom and a generic plan. This is also the
//! array-membership shape that already cost this project once elsewhere
//! (see `tests/retention_preview_plan_stability.rs`).
//!
//! **Not a row-value keyset.** `(stream_category, global_position) >
//! (cat, $n)` is a valid index qual, but it gives the scan no upper
//! bound: once past the category's own entries the scan keeps walking
//! the rest of the index rather than stopping, so a *caught-up* read
//! pays for the tail of the whole index (919 buffers / 2.5 ms for the
//! alphabetically-first category).
//!
//! **This one.** One arm per category, each anchored by an equality on
//! `stream_category` — which is what bounds the index scan at both ends
//! — and each ordered by `stream_category, global_position`. Spelling
//! the full composite key is load-bearing even though the equality makes
//! it equivalent to ordering by `global_position` alone: the
//! single-column `events_global_position_key` index cannot produce that
//! order, so an arm cannot regress into the scan-and-discard plan if an
//! estimate shifts. The outer `ORDER BY global_position` over the
//! `UNION ALL` is served by a `Merge Append` across the arms, so the
//! statement reads `max_count` rows in total rather than `max_count` per
//! category.
//!
//! # Cost of the shape
//!
//! The statement text carries one arm per category, so the prepared
//! statement is per-arity rather than per-call: at most one cached plan
//! for each distinct filter width (1..=13 today). The category *values*
//! stay bound parameters — nothing is interpolated but the arm count.

/// `SELECT` list shared with the other event reads.
use crate::event_store::EVENT_COLS;

/// Build the merged-read statement for `category_count` categories.
///
/// Parameter layout: `$1..$category_count` are the category wire labels
/// (`text`), `$category_count + 1` is the exclusive `global_position`
/// floor (`bigint`), `$category_count + 2` is the row limit (`bigint`).
///
/// Panics on `category_count == 0`; the caller returns an empty page
/// without a round trip instead (a zero-arm `UNION ALL` is not valid
/// SQL).
pub(crate) fn merged_category_read_sql(category_count: usize) -> String {
    assert!(
        category_count > 0,
        "merged_category_read_sql needs at least one category arm"
    );
    let after = category_count + 1;
    let limit = category_count + 2;
    let arms: Vec<String> = (1..=category_count)
        .map(|n| {
            format!(
                "(SELECT {EVENT_COLS}
                   FROM events
                   WHERE stream_category = ${n}
                     AND global_position > ${after}
                   ORDER BY stream_category, global_position
                   LIMIT ${limit})"
            )
        })
        .collect();
    format!(
        "SELECT * FROM (
             {}
         ) merged
         ORDER BY global_position ASC
         LIMIT ${limit}",
        arms.join("\n             UNION ALL\n             ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_category_yields_one_arm_and_three_parameters() {
        let sql = merged_category_read_sql(1);
        assert_eq!(sql.matches("FROM events").count(), 1);
        assert!(sql.contains("stream_category = $1"));
        assert!(sql.contains("global_position > $2"));
        assert!(sql.contains("LIMIT $3"));
        assert!(!sql.contains("UNION ALL"));
    }

    #[test]
    fn three_categories_yield_three_arms_sharing_the_floor_and_limit() {
        let sql = merged_category_read_sql(3);
        assert_eq!(sql.matches("FROM events").count(), 3);
        assert_eq!(sql.matches("UNION ALL").count(), 2);
        for n in 1..=3 {
            assert!(sql.contains(&format!("stream_category = ${n}")));
        }
        assert_eq!(sql.matches("global_position > $4").count(), 3);
        // One LIMIT per arm plus the outer one.
        assert_eq!(sql.matches("LIMIT $5").count(), 4);
    }

    #[test]
    fn every_arm_orders_by_the_full_composite_key() {
        let sql = merged_category_read_sql(4);
        assert_eq!(
            sql.matches("ORDER BY stream_category, global_position")
                .count(),
            4,
            "an arm ordered by global_position alone can be served by the \
             single-column index plus a filter, which is the scan-and-discard plan"
        );
        assert!(sql.contains("ORDER BY global_position ASC"));
    }

    #[test]
    #[should_panic(expected = "at least one category arm")]
    fn zero_categories_is_a_caller_error() {
        let _ = merged_category_read_sql(0);
    }
}
