//! Structural guard on the retention-preview simulation statement: the
//! "still referenced from outside the candidate set" test must stay an
//! anti-join against the `candidate_ids` CTE and must never go back to an
//! array-membership filter on the bound parameter.
//!
//! # Why a source scan rather than a timing test
//!
//! The two forms are semantically identical and return byte-for-byte the same
//! target set, so no assertion about the *result* can tell them apart. They
//! differ only in cost, and only under a condition a test cannot cheaply
//! reproduce: Postgres substitutes bound parameters into constants while it
//! builds custom plans, so `NOT (source_artifact_id = ANY($1::uuid[]))` is
//! hashed and fast for the first five executions of a prepared statement and
//! then — once the statement flips to a generic plan, which it does from the
//! sixth execution on a connection that a worker pool keeps open for days —
//! degrades to a linear scan of the candidate array for every row of
//! `content_references`. Measured with 40 000 candidate artifacts over a
//! 660 000-edge table: 1.7 s as an anti-join, 64.2 s as an array filter.
//!
//! Demonstrating that needs a five-figure corpus and minutes of wall time,
//! which is not a cost the standard suite should pay on every run. The shape
//! of the statement, on the other hand, is free to check and is the thing a
//! well-meaning simplification would undo.

use std::fs;

/// The statement text lives inline in the adapter, so the guard reads the
/// adapter source rather than a fixture that could drift away from it.
fn adapter_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/retention_preview.rs");
    fs::read_to_string(path).expect("retention_preview.rs is readable")
}

/// Everything from the start of the survivor sub-select to the `LIMIT`, i.e.
/// the predicate whose plan stability is at stake. Scoping the assertions
/// here keeps an unrelated future `= ANY(...)` elsewhere in the file from
/// tripping the guard, and keeps the module docs — which name the rejected
/// form on purpose — out of scope.
fn survivor_probe(src: &str) -> String {
    let start = src
        .find("FROM content_references survivor")
        .expect("the survivor sub-select is still there");
    let end = src[start..]
        .find("LIMIT $2")
        .expect("the statement still ends in its result limit")
        + start;
    src[start..end].to_string()
}

#[test]
fn the_survivor_probe_is_an_anti_join_against_the_candidate_cte() {
    let probe = survivor_probe(&adapter_source());
    assert!(
        probe.contains("LEFT JOIN candidate_ids ci"),
        "the survivor probe must join the candidate CTE so the plan is a hash \
         anti-join under both custom and generic plans; found:\n{probe}"
    );
    assert!(
        probe.contains("ci.artifact_id IS NULL"),
        "the anti-join needs its IS NULL arm to mean \"not a candidate\"; found:\n{probe}"
    );
}

#[test]
fn the_survivor_probe_never_filters_on_the_bound_array() {
    let probe = survivor_probe(&adapter_source());
    assert!(
        !probe.contains("= ANY($1"),
        "an array-membership filter on the bound parameter cannot be hashed once \
         the prepared statement flips to a generic plan, and the simulation then \
         costs O(edges x candidates) instead of O(edges); found:\n{probe}"
    );
}
