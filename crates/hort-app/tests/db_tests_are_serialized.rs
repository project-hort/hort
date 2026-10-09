//! Source guard over every `.rs` file under `crates/`: a test that
//! acquires a real Postgres connection carries `#[serial(hort_pg_db)]`.
//!
//! ## The invariant
//!
//! Every DB-backed test in the workspace runs against **one** Postgres
//! server, and libtest runs the tests inside one binary on many threads
//! at once. A per-test database is not isolation from that: the
//! migration set issues cluster-global `CREATE ROLE`, the stale-database
//! sweeper walks shared catalogs, `CREATE`/`DROP DATABASE` take
//! server-wide locks, and several adapters probe `pg_stat_activity`. On
//! the shared-target path (`shared_migrated_pool`) there is no isolation
//! at all — no rollback, no schema-per-test, no truncation — so a
//! concurrent sibling reads and deletes another test's rows. One
//! workspace-wide key, `hort_pg_db`, is what orders all of that.
//!
//! ## Why one key rather than a file-local mutex
//!
//! A file-local `Mutex` serialises exactly the same set of tests the key
//! does — this is a `serial_test` build **without** `file_locks` (no
//! `fslock` in `Cargo.lock`), so `#[serial(key)]` is process-local too,
//! and cargo runs test binaries one after another anyway. The reason to
//! keep one mechanism is not reach, it is composition: two independent
//! serialisations do not compose into one order. A test holding only the
//! mutex and a test holding only the key run concurrently, and a
//! reviewer cannot rule that out by reading either test alone. This
//! guard is what makes the key the single mechanism.
//!
//! ## What this guard cannot see
//!
//! It is a source scan, so it is regex-shaped: a helper in **another
//! file** — a `mod common;` pool fixture, say — hides the connect from
//! it, as does a connection opened through a type alias or a macro. The
//! sibling guard `db_gate_not_silent` already accepts that limit for the
//! same family of checks. The job here is to make the **common** shape
//! impossible to land silently, not to be a type system.
//!
//! ## What counts as a hit
//!
//! A function carrying a test attribute (`#[test]`, `#[tokio::test]`,
//! anything whose attribute path ends in `::test`) whose body reaches
//! one of the three entry points that open a real connection —
//! `hort_adapters_postgres::test_support::{isolated_db_from,
//! shared_migrated_pool, connect_or_panic}` — either directly or through
//! a helper defined in the same file (the module-local `maybe_pool()` /
//! `admin_pool()` shape, transitively), and which carries no
//! `#[serial(hort_pg_db)]` attribute.
//!
//! A raw `PgPool::connect` / `PgConnection::connect_with` counts as
//! well, because a fixture that hand-rolls its own throwaway database
//! never touches `test_support` and would otherwise be the one shape the
//! guard is blind to — which is exactly what it was for the single test
//! in `api_tokens_migration.rs` that creates its own database to run a
//! destructive `DROP TABLE … CASCADE` in. `connect_lazy` is not a hit:
//! it opens no socket, and the DB-free unit tests across
//! `hort-adapters-postgres/src` use it for that reason.
//!
//! Comments and string/char literals are blanked before anything
//! structural is read, so prose describing the banned shape stays
//! readable and the snippets planted in this file's own self-tests are
//! not findings.
//!
//! ## Where the lexer lives
//!
//! The comment/literal blanker and the `fn`-item parser are shared with
//! the sibling `cas_reads_are_verified` target via `tests/rust_scan/mod.rs`
//! — one implementation of the lexical discipline, so the two guards
//! cannot drift into differing notions of what a comment or a function
//! body is. What stays HERE is what encodes this guard's policy: the
//! connect entry points, the serialization key, the transitive
//! helper-chain matcher, and the self-checks that pin them.

use std::collections::BTreeSet;
use std::fs;

mod rust_scan;

use rust_scan::{
    attr_path, blank_noncode, is_ident_byte, parse_fns, walk_rust, workspace_root, FnItem,
};

/// The three entry points in `hort-adapters-postgres::test_support` that
/// open a real connection. Almost everything in the workspace reaches a
/// database through one of them.
const CONNECT_ENTRY_POINTS: [&str; 3] = [
    "isolated_db_from",
    "shared_migrated_pool",
    "connect_or_panic",
];

/// The sqlx constructors a fixture that bypasses `test_support` reaches
/// for. `connect_lazy` is excluded below — it opens no socket.
const SQLX_CONNECT_PATHS: [&str; 2] = ["PgPool::connect", "PgConnection::connect"];

/// The workspace-wide serialization key for DB-backed tests.
const SERIAL_KEY: &str = "hort_pg_db";

/// True when the attribute run marks the item as a libtest test —
/// `#[test]`, `#[tokio::test]`, `#[sqlx::test]`, …
fn carries_test_attr(attrs: &[String]) -> bool {
    attrs
        .iter()
        .map(|attr| attr_path(attr))
        .any(|path| path == "test" || path.ends_with("::test"))
}

/// True when the attribute run carries `#[serial(hort_pg_db)]` — under
/// any import path, since `serial_test::serial` may be used qualified.
fn carries_serial_key(attrs: &[String]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr_path(attr);
        (path == "serial" || path.ends_with("::serial")) && attr.contains(SERIAL_KEY)
    })
}

/// True when `body` calls `name`: the identifier on a token boundary,
/// followed by `(`. Matching the call rather than the bare name keeps a
/// same-named struct field or local binding out of the result.
fn calls(body: &str, name: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0usize;
    while let Some(offset) = body[from..].find(name) {
        let at = from + offset;
        from = at + name.len();
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        let mut after = at + name.len();
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if after < bytes.len() && bytes[after] == b'(' {
            return true;
        }
    }
    false
}

/// True when `body` opens a Postgres connection through sqlx directly
/// rather than through `test_support` — `PgPool::connect`,
/// `PgConnection::connect_with`, and the rest of that family.
///
/// `connect_lazy` is deliberately not one: it performs no I/O, and the
/// DB-free unit tests across `hort-adapters-postgres/src` use it
/// precisely because it never reaches a server.
fn opens_a_connection_directly(body: &str) -> bool {
    let bytes = body.as_bytes();
    for path in SQLX_CONNECT_PATHS {
        let mut from = 0usize;
        while let Some(offset) = body[from..].find(path) {
            let at = from + offset;
            from = at + path.len();
            if at > 0 && is_ident_byte(bytes[at - 1]) {
                continue;
            }
            let mut end = at + path.len();
            while end < bytes.len() && is_ident_byte(bytes[end]) {
                end += 1;
            }
            if &body[at + path.len()..end] == "_lazy" {
                continue;
            }
            let mut after = end;
            while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                after += 1;
            }
            if after < bytes.len() && bytes[after] == b'(' {
                return true;
            }
        }
    }
    false
}

/// True when `body` reaches a real connection: an entry point, a raw
/// sqlx connect, or one of the file's `helpers`.
fn reaches_a_connection(body: &str, helpers: &BTreeSet<String>) -> bool {
    CONNECT_ENTRY_POINTS.iter().any(|entry| calls(body, entry))
        || opens_a_connection_directly(body)
        || helpers.iter().any(|helper| calls(body, helper))
}

/// The names of the file's functions that reach a real connection, to a
/// fixed point: a helper that calls an entry point, a helper that calls
/// such a helper, and so on.
fn connecting_helpers(items: &[FnItem]) -> BTreeSet<String> {
    let mut reaching: BTreeSet<String> = BTreeSet::new();
    loop {
        let mut grew = false;
        for item in items {
            if !reaching.contains(&item.name) && reaches_a_connection(&item.body, &reaching) {
                reaching.insert(item.name.clone());
                grew = true;
            }
        }
        if !grew {
            return reaching;
        }
    }
}

/// Every test in `source` that reaches a real connection without the
/// serialization key, as `(line, function)` pairs.
fn unserialized_db_tests(source: &str) -> Vec<(usize, String)> {
    let items = parse_fns(&blank_noncode(source));
    let helpers = connecting_helpers(&items);
    items
        .iter()
        .filter(|item| carries_test_attr(&item.attrs) && !carries_serial_key(&item.attrs))
        .filter(|item| reaches_a_connection(&item.body, &helpers))
        .map(|item| (item.line, item.name.clone()))
        .collect()
}

#[test]
fn every_db_backed_test_carries_the_serialization_key() {
    let root = workspace_root();
    let mut hits = Vec::new();
    walk_rust(&root.join("crates"), &mut |path| {
        let Ok(source) = fs::read_to_string(path) else {
            return;
        };
        let shown = path.strip_prefix(&root).unwrap_or(path);
        for (line, name) in unserialized_db_tests(&source) {
            hits.push(format!("{}:{line}: {name}", shown.display()));
        }
    });
    hits.sort();
    assert!(
        hits.is_empty(),
        "every test in the workspace that acquires a real Postgres \
         connection must carry `#[serial(hort_pg_db)]`. The whole suite \
         shares one server and libtest runs a binary's tests on many \
         threads at once: a per-test database is no protection from the \
         cluster-global work a migration set does (`CREATE ROLE`, \
         `CREATE`/`DROP DATABASE`, the stale-database sweeper's catalog \
         reads, `pg_stat_activity` probes), and on the shared-target path \
         there is no per-test isolation at all. One key orders all of it; \
         a file-local mutex beside it is a second, non-composing order. \
         Add `#[serial(hort_pg_db)]` (`use serial_test::serial;`) to each \
         of the {} test(s) below — there is no allow-list, and a site \
         that genuinely must not carry the key is a review conversation, \
         not an exemption:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

#[test]
fn the_scanner_trips_on_a_planted_unserialized_db_test() {
    let planted = "async fn maybe_pool() -> Option<PgPool> {\n    \
                   let url = env::var(\"DATABASE_URL\").ok()?;\n    \
                   crate::test_support::isolated_db_from(&url).await\n}\n\n\
                   #[tokio::test]\nasync fn reads_a_row() {\n    \
                   let Some(pool) = maybe_pool().await else { return };\n}";
    assert_eq!(
        unserialized_db_tests(planted),
        vec![(7, "reads_a_row".to_string())],
        "a test reaching a connection through a module-local helper is a hit"
    );
}

#[test]
fn the_scanner_accepts_a_keyed_db_test() {
    let keyed = "async fn maybe_pool() -> Option<PgPool> {\n    \
                 hort_adapters_postgres::test_support::shared_migrated_pool().await\n}\n\n\
                 #[tokio::test]\n#[serial(hort_pg_db)]\nasync fn reads_a_row() {\n    \
                 let Some(pool) = maybe_pool().await else { return };\n}";
    assert!(
        unserialized_db_tests(keyed).is_empty(),
        "the key is exactly what the guard asks for"
    );
}

#[test]
fn the_scanner_follows_a_helper_chain() {
    // `pool()` → `maybe_pool()` → `connect_or_panic`. A scan that only
    // looked one hop deep would miss the test.
    let chained = "async fn maybe_pool() -> Option<PgPool> {\n    \
                   Some(test_support::connect_or_panic(&url).await)\n}\n\
                   async fn pool() -> PgPool { maybe_pool().await.unwrap() }\n\n\
                   #[tokio::test]\nasync fn reads_a_row() { let p = pool().await; }";
    assert_eq!(
        unserialized_db_tests(chained),
        vec![(7, "reads_a_row".to_string())]
    );
}

#[test]
fn the_scanner_ignores_a_test_that_touches_no_database() {
    let db_free = "#[test]\nfn parses_a_header() {\n    assert_eq!(1, 1);\n}";
    assert!(unserialized_db_tests(db_free).is_empty());
}

#[test]
fn the_scanner_ignores_an_unkeyed_helper_that_is_not_a_test() {
    // Only test functions are reported: the key belongs on the unit
    // libtest schedules, and a helper is not one.
    let helper_only = "async fn maybe_pool() -> Option<PgPool> {\n    \
                       test_support::isolated_db_from(&url).await\n}";
    assert!(unserialized_db_tests(helper_only).is_empty());
}

#[test]
fn the_scanner_reads_no_entry_point_out_of_a_comment_or_a_string() {
    // Prose and planted snippets name the entry points constantly —
    // including in this file. Blanking is what keeps them from reading
    // as calls.
    let quoted = "#[test]\nfn documents_the_shape() {\n    \
                  // isolated_db_from(&url) is the isolated path.\n    \
                  let sql = \"select connect_or_panic(1)\";\n}";
    assert!(unserialized_db_tests(quoted).is_empty());
}

#[test]
fn the_scanner_survives_braces_inside_strings_and_comments() {
    // A brace in a SQL literal or a doc comment must not open a block:
    // if it did, the body of the test that follows would be swallowed
    // and the hit lost.
    let braced = "const Q: &str = \"jsonb_build_object('a', '{')\";\n\
                  /// A doc comment with an unbalanced } in it.\n\
                  #[tokio::test]\nasync fn reads_a_row() {\n    \
                  let p = test_support::shared_migrated_pool().await;\n}";
    assert_eq!(
        unserialized_db_tests(braced),
        vec![(4, "reads_a_row".to_string())]
    );
}

#[test]
fn the_scanner_survives_a_brace_inside_a_raw_string() {
    let raw = "const Q: &str = r#\"{\"a\": 1}\"#;\n\
               #[tokio::test]\nasync fn reads_a_row() {\n    \
               let p = test_support::shared_migrated_pool().await;\n}";
    assert_eq!(
        unserialized_db_tests(raw),
        vec![(3, "reads_a_row".to_string())]
    );
}

#[test]
fn the_scanner_reads_the_key_through_a_qualified_attribute_path() {
    let qualified = "#[tokio::test]\n#[serial_test::serial(hort_pg_db)]\n\
                     async fn reads_a_row() { test_support::connect_or_panic(&url).await; }";
    assert!(unserialized_db_tests(qualified).is_empty());
}

#[test]
fn the_scanner_rejects_a_serial_attribute_carrying_a_different_key() {
    // A different key is a different lock: it orders the test against
    // its own group and not against the DB suite at all.
    let other_key = "#[tokio::test]\n#[serial(some_other_key)]\n\
                     async fn reads_a_row() { test_support::connect_or_panic(&url).await; }";
    assert_eq!(
        unserialized_db_tests(other_key),
        vec![(3, "reads_a_row".to_string())]
    );
}

#[test]
fn the_scanner_looks_past_item_modifiers_to_the_attributes() {
    // `pub(crate) async fn` sits between the attribute run and the `fn`
    // keyword; a backwards walk that stopped at the first modifier would
    // report a keyed test.
    let modifiers = "#[tokio::test]\n#[serial(hort_pg_db)]\n\
                     pub(crate) async fn reads_a_row() { \
                     test_support::connect_or_panic(&url).await; }";
    assert!(unserialized_db_tests(modifiers).is_empty());
}

#[test]
fn the_scanner_does_not_read_a_fn_pointer_type_as_an_item() {
    let pointer_type = "type Check = fn(&str) -> bool;\n\
                        #[tokio::test]\nasync fn reads_a_row() { \
                        test_support::connect_or_panic(&url).await; }";
    assert_eq!(
        unserialized_db_tests(pointer_type),
        vec![(3, "reads_a_row".to_string())]
    );
}

#[test]
fn the_scanner_sees_a_hand_rolled_sqlx_connect() {
    let hand_rolled = "#[tokio::test]\nasync fn rewinds_a_migration() {\n    \
                       let mut admin = sqlx::PgConnection::connect_with(&opts)\n        \
                       .await\n        .expect(\"connect\");\n}";
    assert_eq!(
        unserialized_db_tests(hand_rolled),
        vec![(2, "rewinds_a_migration".to_string())]
    );
}

#[test]
fn the_scanner_ignores_connect_lazy() {
    // `connect_lazy` opens no socket — it is how the DB-free unit tests
    // in `hort-adapters-postgres/src` build a pool they never use.
    let lazy = "#[tokio::test]\nasync fn maps_an_error() {\n    \
                let pool = PgPool::connect_lazy(\"postgres://localhost/nonexistent\")\n        \
                .expect(\"lazy pool\");\n}";
    assert!(unserialized_db_tests(lazy).is_empty());
}

#[test]
fn the_scanner_does_not_carry_an_earlier_items_attributes_onto_a_test() {
    // The attribute run stops at the previous item's closing brace, so a
    // key on one test never covers the next.
    let neighbours = "#[tokio::test]\n#[serial(hort_pg_db)]\n\
                      async fn keyed() { test_support::connect_or_panic(&url).await; }\n\
                      #[tokio::test]\n\
                      async fn unkeyed() { test_support::connect_or_panic(&url).await; }";
    assert_eq!(
        unserialized_db_tests(neighbours),
        vec![(5, "unkeyed".to_string())]
    );
}
