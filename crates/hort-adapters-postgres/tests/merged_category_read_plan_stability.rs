//! Structural guard on the merged category-read statement: it must stay a
//! `UNION ALL` of per-category keyset arms, each anchored by an equality
//! on `stream_category` and each ordered by the full composite key. It
//! must never become an array-membership filter, and it must never become
//! a row-value keyset range.
//!
//! # Why a source scan rather than a timing test
//!
//! All three spellings return byte-for-byte the same page, so no assertion
//! about the *result* can tell them apart. They differ only in what the
//! planner does with them, and demonstrating that needs a six-figure
//! corpus with a specific skew plus server-side `PREPARE`/`EXECUTE` (bound
//! parameters passed through `EXPLAIN` are re-planned as constants every
//! time, so they cannot show a generic plan at all). That is not a cost
//! the standard suite should pay on every run. The shape of the statement,
//! on the other hand, is free to check and is exactly what a well-meaning
//! simplification would undo — "why thirteen near-identical arms when
//! `= ANY($1)` says the same thing?" is a reasonable-sounding review
//! comment, and the answer is a number.
//!
//! Measured on 200 000 events with a quiet category holding 16% of rows
//! but none above position 39 999, `EXPLAIN (ANALYZE, BUFFERS)` of the 7th
//! execution of a prepared statement, under both `plan_cache_mode = auto`
//! and `force_generic_plan`:
//!
//! | shape | quiet 3-category read | caught-up read |
//! |---|---|---|
//! | `= ANY($1)` | 160 641 buffers, 33.9 ms, 160 001 rows discarded | 3 buffers |
//! | row-value keyset | 247 buffers, 0.61 ms | 919 buffers, 2.5 ms |
//! | UNION ALL arms (this one) | 9 buffers, 0.011 ms | 3 buffers |
//!
//! The `= ANY` row is the same class of failure as
//! `retention_preview_plan_stability.rs` guards against: an array
//! predicate the planner cannot use to satisfy the `ORDER BY`, so it takes
//! the single-column `events_global_position_key` index plus a filter and
//! scans every row of every *other* category above the mark. It is plan-
//! mode independent — forcing a custom plan does not rescue it.
//!
//! The row-value row fails differently: `(stream_category,
//! global_position) > (cat, $n)` is a usable index qual but gives the scan
//! no upper bound, so a caught-up read walks the remainder of the index
//! instead of stopping at the category boundary.

use std::fs;

/// The statement builder lives in its own module, so the guard reads that
/// module's source rather than a fixture that could drift away from it.
fn builder_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/merged_category_read.rs");
    fs::read_to_string(path).expect("merged_category_read.rs is readable")
}

/// The `format!` literal that builds one arm, i.e. the predicate whose
/// plan stability is at stake. Scoping the assertions here keeps the
/// module docs — which name the rejected forms on purpose — out of scope,
/// and keeps an unrelated future statement elsewhere in the file from
/// tripping the guard.
fn arm_template(src: &str) -> String {
    let start = src
        .find("(SELECT {EVENT_COLS}")
        .expect("the per-category arm is still built from a format! literal");
    let end = src[start..]
        .find("LIMIT ${limit})")
        .expect("the arm still ends in its own row limit")
        + start;
    src[start..end].to_string()
}

#[test]
fn each_arm_is_anchored_by_an_equality_on_the_category() {
    let arm = arm_template(&builder_source());
    assert!(
        arm.contains("stream_category = ${n}"),
        "the equality is what bounds the index scan at BOTH ends; without it the scan \
         runs past the category into the rest of the index. Found:\n{arm}"
    );
    assert!(
        arm.contains("global_position > ${after}"),
        "the arm still has to be a keyset range above the cursor; found:\n{arm}"
    );
}

#[test]
fn each_arm_orders_by_the_full_composite_key() {
    let arm = arm_template(&builder_source());
    assert!(
        arm.contains("ORDER BY stream_category, global_position"),
        "an arm ordered by global_position alone can also be served by \
         events_global_position_key plus a filter, which is the scan-and-discard plan \
         (160 641 buffers / 33.9 ms at a 160k gap). Naming the full composite key means \
         the single-column index cannot supply the order at all, so the arm cannot \
         regress into it when an estimate shifts. Found:\n{arm}"
    );
}

#[test]
fn the_statement_never_filters_on_a_bound_category_array() {
    let arm = arm_template(&builder_source());
    assert!(
        !arm.contains("= ANY("),
        "an array-membership predicate cannot satisfy ORDER BY global_position from the \
         (stream_category, global_position) index, so the planner falls back to the \
         single-column index plus a filter and the read costs O(rows of every other \
         category above the mark) — measured at 160 001 rows discarded to return zero, \
         under a custom plan as much as a generic one. Found:\n{arm}"
    );
}

#[test]
fn the_statement_never_uses_a_row_value_keyset() {
    let arm = arm_template(&builder_source());
    assert!(
        !arm.contains("(stream_category, global_position) >"),
        "a row-value comparison is a usable index qual but bounds the scan only from \
         below, so a caught-up read walks the rest of the index rather than stopping at \
         the category boundary — 919 buffers / 2.5 ms to return nothing. Found:\n{arm}"
    );
}

#[test]
fn the_arms_are_merged_by_a_single_ordered_limit() {
    let src = builder_source();
    assert!(
        src.contains("UNION ALL"),
        "one arm per category, unioned, is what lets Postgres merge them with a Merge \
         Append and read max_count rows in total rather than max_count per category"
    );
    assert!(
        src.contains("ORDER BY global_position ASC"),
        "the outer ordering is the whole contract of the method: one page of the merged \
         stream, so the caller can hold one cursor over it"
    );
}
