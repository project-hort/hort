//! Structural guard on the list-surface census statement: the statuses
//! it treats as terminal must stay **derived** from
//! `QuarantineStatus::is_terminal`, the edge kinds it descends must stay
//! the domain's, and it must stay **one** statement.
//!
//! # What goes wrong without the status half
//!
//! `is_terminal` is the single definition of "this artifact's lifecycle
//! has concluded against delivery" (ADR 0062's enforcement anchor). Two
//! surfaces now ask it of two different layers — the manifest route from
//! the bytes, the list surfaces from the membership projection — and the
//! obvious way to write either query,
//! `AND a.quarantine_status IN ('rejected','scan_indeterminate')`, is a
//! second definition. A sixth `QuarantineStatus` variant that is
//! terminal would then be terminal for the pull and not for the list,
//! with nothing in the build failing: `tags/list` would advertise a tag
//! whose manifest the next request refuses. That is the "a list names
//! what the pull denies" contradiction this unit exists to close,
//! reintroduced one variant later.
//!
//! # What goes wrong without the kind half
//!
//! The descent is over `content_references`, which carries edges of
//! several unrelated relations under one table. Two of them would be
//! actively wrong to descend, and both fail silently:
//!
//! - `oci_subject` points from a referrer manifest at the **subject** it
//!   describes. Descending it would make an attestation vanish from the
//!   referrers index whenever the image it talks about is withdrawn —
//!   the relation run backwards against the one surface that exists to
//!   report it.
//! - `primary_content` targets the source artifact's **own** hash, so
//!   descending it would make every artifact its own constituent.
//!
//! Neither mistake breaks a build or a type. A spelled-out
//! `kind IN (…)` in the statement is where one would land, so the kinds
//! are bound from `CLOSURE_EDGE_KINDS` and asserted here against it.
//!
//! # Why a source scan as well as the DB-backed tests
//!
//! The adapter's own DB-backed tests drive `QuarantineStatus::ALL`
//! through the live statement and pin the `oci_subject` exclusion
//! behaviourally, which is the stronger check — but they only run with a
//! `DATABASE_URL`, and they would stay green if a future edit replaced a
//! bound array with a literal list that happens to name today's values.
//! The property at stake is not "the answer is right today", it is "the
//! answer cannot diverge from the domain", and that is a property of the
//! statement's *shape*.
//!
//! # Counter-assertions
//!
//! Every assertion below is paired with one that fails if the scan stops
//! finding the real thing: the statement must still be in the file, it
//! must still join each unnested CTE, and the binding helpers must still
//! be what the query binds. A rename that moved the statement elsewhere
//! would otherwise leave this guard vacuously green.

use std::fs;

use hort_adapters_postgres::list_deliverability::PgListDeliverabilityCensus;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::ports::constituent_status::terminal_statuses_by_refusal_precedence;
use hort_domain::ports::list_deliverability::CLOSURE_EDGE_KINDS;

/// The adapter source. Read from disk rather than `include_str!`-ed into
/// a fixture so the guard cannot drift away from the file it guards.
fn adapter_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/list_deliverability.rs");
    fs::read_to_string(path).expect("list_deliverability.rs is readable")
}

/// The statement itself — from the `const`'s raw-string opener to its
/// terminator. Scoping the assertions here keeps this file's own prose,
/// and the module doc's, which name the rejected forms on purpose, out
/// of scope.
fn statement(src: &str) -> String {
    let start = src
        .find("const NON_DELIVERABLE_IN_SQL: &str = r#\"")
        .expect("the statement is still a hoisted const in this file");
    let body = &src[start..];
    let end = body
        .find("\"#;")
        .expect("the statement is still a terminated raw string");
    body[..end].to_string()
}

/// The stored spelling of every status, so the scan can look for *any*
/// of them rather than only the two that are terminal today. A literal
/// `'released'` in this statement would be just as wrong as a literal
/// `'rejected'`: both decide, in SQL, a question the domain owns.
fn every_stored_status_spelling() -> Vec<String> {
    QuarantineStatus::ALL
        .into_iter()
        .filter(|status| *status != QuarantineStatus::None)
        .map(|status| status.to_string())
        .collect()
}

#[test]
fn the_statement_spells_out_no_quarantine_status() {
    let sql = statement(&adapter_source());
    // Counter-assertion: the scan is looking at the real statement.
    assert!(
        sql.contains("FROM artifacts a"),
        "the scan must still be reading the census statement; found:\n{sql}"
    );
    assert!(
        every_stored_status_spelling().len() >= 4,
        "the corpus of stored spellings must be real, or the loop below is vacuous"
    );
    for spelling in every_stored_status_spelling() {
        assert!(
            !sql.contains(&spelling),
            "the statement names the status {spelling:?}; the terminal set must be bound \
             from QuarantineStatus::is_terminal, never written into SQL, or a sixth \
             variant leaves the list surfaces advertising what the pull refuses with \
             nothing failing:\n{sql}"
        );
    }
}

#[test]
fn the_statement_spells_out_no_reference_kind() {
    let sql = statement(&adapter_source());
    // Counter-assertion: the scan is looking at the real statement, and
    // at the part of it that reads the edge table.
    assert!(
        sql.contains("JOIN content_references e"),
        "the scan must still be reading the descent; found:\n{sql}"
    );
    // Every kind in scope — the three the census descends and the three
    // it must not. A literal naming of an excluded kind is as wrong as a
    // literal naming of an included one: both move the definition of
    // "closure" out of the domain.
    let kinds = [
        "oci_config",
        "oci_layer",
        "oci_index_member",
        "oci_subject",
        "primary_content",
        "metadata_blob",
    ];
    for kind in kinds {
        assert!(
            !sql.contains(kind),
            "the statement names the reference kind {kind:?}; the descent set must be \
             bound from CLOSURE_EDGE_KINDS so the definition of a document's closure \
             stays in the domain:\n{sql}"
        );
    }
}

#[test]
fn the_bound_terminal_set_is_exactly_what_the_predicate_calls_terminal() {
    let bound = PgListDeliverabilityCensus::terminal_status_binding();
    for status in QuarantineStatus::ALL {
        // `None` is stored as SQL NULL and has no spelling in the column;
        // it is also not terminal, so it must simply be absent.
        assert_eq!(
            bound.contains(&status.to_string()),
            status.is_terminal(),
            "{status} is in the bound terminal set iff is_terminal() holds for it; bound: \
             {bound:?}"
        );
    }
    // Counter-assertion: the binding is not empty, and it is the same
    // derivation the by-the-bytes sibling binds — the two surfaces must
    // not be able to disagree about what terminal means.
    assert_eq!(
        bound,
        terminal_statuses_by_refusal_precedence()
            .into_iter()
            .map(|status| status.to_string())
            .collect::<Vec<_>>(),
        "the census must bind the crate's one terminal-status derivation, not its own"
    );
}

#[test]
fn the_bound_closure_kinds_are_exactly_the_domains() {
    let bound = PgListDeliverabilityCensus::closure_kind_binding();
    assert_eq!(
        bound,
        CLOSURE_EDGE_KINDS
            .iter()
            .map(|kind| (*kind).to_string())
            .collect::<Vec<_>>(),
        "the descent must bind the domain's closure-edge set verbatim"
    );
    // Counter-assertion: the set is real and does not contain the two
    // relations that would be wrong to descend. This is the assertion
    // that fails if someone widens `CLOSURE_EDGE_KINDS` itself rather
    // than the statement.
    assert_eq!(
        bound.len(),
        3,
        "the closure set must not be empty: {bound:?}"
    );
    for excluded in ["oci_subject", "primary_content"] {
        assert!(
            !bound.contains(&excluded.to_string()),
            "{excluded} is not a closure edge — see CLOSURE_EDGE_KINDS' doc for which \
             relation it is and why descending it is wrong"
        );
    }
}

#[test]
fn every_bound_set_is_joined_not_tested_as_an_array() {
    let sql = statement(&adapter_source());
    for (what, join) in [
        ("the candidate-hash set", "FROM candidates c"),
        ("the terminal-status set", "JOIN terminal t ON t.status ="),
        ("the closure-kind set", "JOIN closure_kinds k ON k.kind ="),
    ] {
        assert!(
            sql.contains(join),
            "{what} must enter the statement through its unnested CTE so the plan is \
             stable under a generic plan; found:\n{sql}"
        );
    }
    assert!(
        !sql.contains("= ANY"),
        "an array-membership filter on a bound parameter cannot be hashed once the \
         prepared statement flips to a generic plan (1.7 s against 64.2 s, measured on \
         this project's corpus); found:\n{sql}"
    );
}

/// The verdict is a **semi-join** over the closure, not a join that
/// drags the closure's whole row set through the repository's artifacts.
/// Measured on a 22,001-artifact corpus at 2.3–3.0 ms against 10–11 ms
/// for the join form; the module doc carries the numbers. Pinned because
/// the join form is the one a reader would write first and nothing but
/// latency tells them apart.
#[test]
fn the_verdict_is_a_semi_join_over_the_closure() {
    let sql = statement(&adapter_source());
    assert!(
        sql.contains("WHERE EXISTS ("),
        "the verdict must be an EXISTS over each closure member's own row; found:\n{sql}"
    );
    // Counter-assertion: the EXISTS is the one that reads the catalog,
    // correlated on the closure member.
    assert!(
        sql.contains("FROM artifacts a") && sql.contains("a.checksum_sha256 = cl.member"),
        "the semi-join must be correlated on the closure member's hash; found:\n{sql}"
    );
}

#[test]
fn the_walk_is_recursive_and_distinct() {
    let sql = statement(&adapter_source());
    assert!(
        sql.contains("WITH RECURSIVE"),
        "one hop is an arbitrary cut: an index over a child whose layers are terminal \
         would be listed and then fail at the grandchild; found:\n{sql}"
    );
    assert!(
        !sql.contains("UNION ALL"),
        "the recursive term must be a distinct UNION: it is what terminates the walk over \
         a cyclic or self-referential edge set, which content addressing cannot express \
         but the relational projection does not forbid; found:\n{sql}"
    );
    // Counter-assertion: there is a `UNION` to have been made `ALL`.
    assert!(
        sql.contains("UNION"),
        "the scan must still be reading a recursive union; found:\n{sql}"
    );
}

#[test]
fn the_statement_is_repository_scoped_and_live_only() {
    let sql = statement(&adapter_source());
    assert_eq!(
        sql.matches("repository_id = $1").count(),
        3,
        "every table reference — the descent's parent row, the descent's edge row, and \
         the verdict's row — must be repository-scoped: the same bytes held in another \
         repository must not withdraw this one's entry; found:\n{sql}"
    );
    assert_eq!(
        sql.matches("deleted_at IS NULL").count(),
        2,
        "both the descent and the verdict must filter retirement, matching every live \
         ArtifactRepository read: a row no read path can see must not withhold anything; \
         found:\n{sql}"
    );
}

/// The census costs **one** statement per list call, which is the
/// criterion the whole resolution was shaped around: a per-entry
/// fan-out would put a round trip on every name a client resolves
/// against. The port method is the only thing that talks to the pool,
/// so the check is that the file issues exactly one query.
#[test]
fn the_census_issues_exactly_one_statement() {
    let src = adapter_source();
    // Scope to production code: the `#[cfg(test)]` module below seeds
    // rows with queries of its own.
    let production = src
        .split("#[cfg(test)]")
        .next()
        .expect("the file has production code ahead of its test module");
    let issued = production.matches("sqlx::query").count();
    assert_eq!(
        issued, 1,
        "the census must issue exactly one statement per list call, not one per entry; \
         found {issued} sqlx::query call sites"
    );
    // Counter-assertion: that one call site is the statement this guard
    // has been asserting about.
    assert!(
        production.contains("sqlx::query(NON_DELIVERABLE_IN_SQL)"),
        "the one statement must be the hoisted const this guard reads"
    );
}
