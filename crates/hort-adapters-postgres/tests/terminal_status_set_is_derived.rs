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
//! # Every statement in the file, not a named one
//!
//! The module holds **two** statements — the `LIMIT 1` one a manifest
//! read asks, and the per-hash one admission asks so it can record each
//! declared reference — and what must not become two is the derivation
//! behind them. So the scan is a **census**: it finds every
//! `const …_SQL` in the file and holds each one to the same shape, with
//! no list of names to fall out of. A third statement added beside them
//! is scanned by virtue of being there.
//!
//! # Counter-assertions
//!
//! Every assertion below is paired with one that fails if the scan stops
//! finding the real thing: the census must still find more than one
//! statement, each must still join both unnested CTEs, and the binding
//! helper must still be the thing every query binds. A rename that moved
//! a statement elsewhere would otherwise leave this guard vacuously
//! green.

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

/// Every statement in the file, as `(const name, text)` — each from its
/// `const`'s raw-string opener to that string's terminator.
///
/// Derived from the source rather than listed here, so a statement added
/// beside the two is held to the same shape without anyone remembering
/// to add it. Scoping the assertions to the statement texts keeps this
/// file's own prose, which names the rejected forms on purpose, out of
/// scope.
fn statements(src: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("_SQL: &str = r#\"") {
        let name_start = rest[..at]
            .rfind("const ")
            .expect("a statement const is introduced by `const`")
            + "const ".len();
        let name = rest[name_start..at].to_string() + "_SQL";
        let body = &rest[at..];
        let end = body
            .find("\"#;")
            .expect("every statement is a terminated raw string");
        found.push((name, body[..end].to_string()));
        rest = &body[end..];
    }
    found
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

/// The census itself, with the counter-assertions every other test
/// leans on: more than one statement is found, and each is the real
/// thing rather than a comment the extractor wandered into.
#[test]
fn the_census_finds_every_statement_in_the_file() {
    let found = statements(&adapter_source());
    assert!(
        found.len() >= 2,
        "the file holds the read path's statement and admission's per-hash one; the census \
         found {}: {:?}",
        found.len(),
        found.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );
    for (name, sql) in &found {
        assert!(
            sql.contains("FROM artifacts a"),
            "{name} must be a statement over the artifact catalog; found:\n{sql}"
        );
    }
}

#[test]
fn no_statement_spells_out_a_quarantine_status() {
    assert!(
        every_stored_status_spelling().len() >= 4,
        "the corpus of stored spellings must be real, or the loop below is vacuous"
    );
    for (name, sql) in statements(&adapter_source()) {
        for spelling in every_stored_status_spelling() {
            assert!(
                !sql.contains(&spelling),
                "{name} names the status {spelling:?}; the terminal set must be bound \
                 from QuarantineStatus::is_terminal, never written into SQL, or a sixth \
                 variant leaves the pull narrower than the push with nothing failing:\n{sql}"
            );
        }
    }
}

/// Both halves of the binding are the same for every statement: the
/// vocabulary **and** the order. A statement that unnested the array
/// without ordering by its ordinality would be ranking verdicts by
/// something the domain does not own, and a statement ranking by its own
/// expression would be a second precedence — which is the drift two
/// statements make possible and this is what forbids.
#[test]
fn every_statement_ranks_by_the_bound_arrays_own_ordinality() {
    for (name, sql) in statements(&adapter_source()) {
        assert!(
            sql.contains("unnest($3::text[]) WITH ORDINALITY AS t(status, precedence)"),
            "{name} must take its precedence from the bound array's ordinality; found:\n{sql}"
        );
        assert!(
            sql.contains("ORDER BY t.precedence, w.position"),
            "{name} must rank by the bound precedence first and the caller's own position \
             second — the one order the domain defines; found:\n{sql}"
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
    for (name, sql) in statements(&adapter_source()) {
        assert!(
            sql.contains("JOIN wanted w ON w.content_hash = a.checksum_sha256"),
            "{name}'s constituent-hash membership test must be a join against the unnested \
             CTE so the plan is stable under a generic plan; found:\n{sql}"
        );
        assert!(
            sql.contains("JOIN terminal t ON t.status = a.quarantine_status"),
            "{name}'s terminal-status membership test must be a join against the unnested \
             bound array; found:\n{sql}"
        );
        assert!(
            !sql.contains("= ANY"),
            "an array-membership filter on a bound parameter cannot be hashed once the \
             prepared statement flips to a generic plan (1.7 s against 64.2 s, measured on \
             this project's corpus); found in {name}:\n{sql}"
        );
    }
}

#[test]
fn every_statement_is_repository_scoped_and_live_only() {
    for (name, sql) in statements(&adapter_source()) {
        assert!(
            sql.contains("a.repository_id = $1"),
            "{name}: the question is per repository: the same bytes held in another \
             repository must not withdraw this one's manifest; found:\n{sql}"
        );
        assert!(
            sql.contains("a.deleted_at IS NULL"),
            "{name}: every live ArtifactRepository read filters deleted_at, and \
             deliverability is their question — a retired row must be as absent here as it \
             is there; found:\n{sql}"
        );
    }
}

/// Each resolution costs **one** statement, which is the criterion the
/// whole module was shaped around: a per-constituent fan-out would put
/// one round trip on every layer of every pull and on every reference of
/// every push. So the file issues exactly as many queries as it holds
/// statements, each of them a hoisted const this guard has read — a query
/// built inline, or one issued inside a loop, breaks the count.
#[test]
fn each_resolution_issues_exactly_one_statement() {
    let src = adapter_source();
    // Scope to production code: the `#[cfg(test)]` module below seeds
    // rows with queries of its own.
    let production = src
        .split("#[cfg(test)]")
        .next()
        .expect("the file has production code ahead of its test module");
    let held = statements(production);
    let issued = production.matches("sqlx::query").count();
    assert_eq!(
        issued,
        held.len(),
        "the module must issue one statement per resolution, not one per constituent and \
         none it did not hoist; found {issued} sqlx::query call sites against {} statements",
        held.len()
    );
    // Counter-assertion: every call site is one of the statements this
    // guard has been asserting about, named rather than built.
    for (name, _) in &held {
        assert!(
            production.contains(&format!("sqlx::query({name})")),
            "{name} must be issued by name, so what runs is what this guard read"
        );
    }
    // And every statement binds the one derivation of the terminal
    // vocabulary and its order — same helper, same call, at each site.
    assert_eq!(
        production
            .matches(".bind(Self::terminal_status_binding())")
            .count(),
        held.len(),
        "each statement must bind the derived terminal set; a statement binding something \
         else is a second definition of what terminal means"
    );
}
