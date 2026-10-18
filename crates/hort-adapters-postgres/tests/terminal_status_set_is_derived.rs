//! Structural guard on the constituent-deliverability statement: the set
//! of statuses it treats as terminal must stay **derived** from
//! `QuarantineStatus::is_terminal`, and must never be written out in SQL.
//!
//! # What goes wrong without it
//!
//! `is_terminal` is the single definition of "this artifact's lifecycle
//! has concluded against delivery" (ADR 0062's enforcement anchor), and
//! the manifest write path already derives its refusal from it. The read
//! path's constituent query asks the same question of a different layer,
//! and the obvious way to write it —
//! `AND a.quarantine_status IN ('rejected','scan_indeterminate')` — is a
//! second definition. A sixth `QuarantineStatus` variant that is terminal
//! would then be terminal for the push and not for the pull, with nothing
//! in the build failing: the manifest would be refused at PUT and served
//! at GET over a constituent nobody can download. That is precisely the
//! "a push reports success and a pull answers not found" contradiction
//! this whole unit exists to close, reintroduced one variant later.
//!
//! # Why a source scan as well as a behavioural test
//!
//! The adapter's own DB-backed tests drive every `QuarantineStatus::ALL`
//! member through the live statement, which is the stronger check — but
//! it only runs with a `DATABASE_URL`, and it would stay green if a
//! future edit replaced the bound array with a literal list that happens
//! to name today's two statuses. The property at stake is not "the
//! answer is right today", it is "the answer cannot go narrower than the
//! predicate", and that is a property of the statement's *shape*.
//!
//! # Counter-assertions
//!
//! Every assertion below is paired with one that fails if the scan stops
//! finding the real thing: the statement must still be in the file, it
//! must still join both unnested CTEs, and the binding helper must still
//! be the thing the query binds. A rename that moved the statement
//! elsewhere would otherwise leave this guard vacuously green.

use std::fs;

use hort_adapters_postgres::constituent_status::PgConstituentStatusReader;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::ports::constituent_status::terminal_statuses_by_refusal_precedence;

/// The adapter source. Read from disk rather than `include_str!`-ed into
/// a fixture so the guard cannot drift away from the file it guards.
fn adapter_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/constituent_status.rs");
    fs::read_to_string(path).expect("constituent_status.rs is readable")
}

/// The statement itself — from the `const`'s raw-string opener to its
/// terminator. Scoping the assertions here keeps this file's own prose,
/// which names the rejected forms on purpose, out of scope.
fn statement(src: &str) -> String {
    let start = src
        .find("const STRONGEST_TERMINAL_CONSTITUENT_SQL: &str = r#\"")
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
        "the scan must still be reading the constituent statement; found:\n{sql}"
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
             variant leaves the pull narrower than the push with nothing failing:\n{sql}"
        );
    }
}

#[test]
fn the_bound_terminal_set_is_exactly_what_the_predicate_calls_terminal() {
    let bound = PgConstituentStatusReader::terminal_status_binding();
    for status in QuarantineStatus::ALL {
        // `None` is stored as SQL NULL and has no spelling in the column;
        // it is also not terminal, so it must simply be absent.
        let expected = status.is_terminal();
        assert_eq!(
            bound.contains(&status.to_string()),
            expected,
            "{status} is in the bound terminal set iff is_terminal() holds for it; bound: \
             {bound:?}"
        );
    }
    // Counter-assertion: the binding is not empty and is in refusal
    // precedence order, which is what the statement's ORDER BY reads.
    assert_eq!(
        bound,
        terminal_statuses_by_refusal_precedence()
            .into_iter()
            .map(|status| status.to_string())
            .collect::<Vec<_>>(),
        "the binding must preserve the domain's refusal precedence — the statement orders \
         by the array's ordinality and nothing else tells it which verdict is stronger"
    );
}

#[test]
fn the_membership_tests_are_joins_not_array_predicates() {
    let sql = statement(&adapter_source());
    assert!(
        sql.contains("JOIN wanted w ON w.content_hash = a.checksum_sha256"),
        "the constituent-hash membership test must be a join against the unnested CTE so \
         the plan is stable under a generic plan; found:\n{sql}"
    );
    assert!(
        sql.contains("JOIN terminal t ON t.status = a.quarantine_status"),
        "the terminal-status membership test must be a join against the unnested bound \
         array; found:\n{sql}"
    );
    assert!(
        !sql.contains("= ANY"),
        "an array-membership filter on a bound parameter cannot be hashed once the \
         prepared statement flips to a generic plan (1.7 s against 64.2 s, measured on \
         this project's corpus); found:\n{sql}"
    );
}

#[test]
fn the_statement_is_repository_scoped_and_live_only() {
    let sql = statement(&adapter_source());
    assert!(
        sql.contains("a.repository_id = $1"),
        "the question is per repository: the same bytes held in another repository must \
         not withdraw this one's manifest; found:\n{sql}"
    );
    assert!(
        sql.contains("a.deleted_at IS NULL"),
        "every live ArtifactRepository read filters deleted_at, and deliverability is \
         their question — a retired row must be as absent here as it is there; found:\n{sql}"
    );
}

/// The deliverability answer costs **one** statement per manifest read,
/// which is the criterion the whole resolution was shaped around: a
/// per-constituent fan-out would put one round trip on every layer of
/// every pull. The port method is the only thing that talks to the pool,
/// so the check is that the file issues exactly one query.
#[test]
fn the_resolution_issues_exactly_one_statement() {
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
        "the constituent resolution must issue exactly one statement, not one per \
         constituent; found {issued} sqlx::query call sites"
    );
    // Counter-assertion: that one call site is the statement this guard
    // has been asserting about.
    assert!(
        production.contains("sqlx::query(STRONGEST_TERMINAL_CONSTITUENT_SQL)"),
        "the one statement must be the hoisted const this guard reads"
    );
}
