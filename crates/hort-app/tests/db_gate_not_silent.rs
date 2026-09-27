//! Source guard over every `.rs` file under `crates/`: a Postgres
//! **connect** failure is never flattened into a test skip.
//!
//! ## The invariant
//!
//! A DB-gated test skips on exactly one condition — `DATABASE_URL`
//! unset. Every DB-gated fixture in the workspace reads the variable
//! first (`let url = env::var("DATABASE_URL").ok()?;`) and only then
//! asks for a connection, so by the time a connect is attempted the
//! operator has declared that a database exists. A connect that fails
//! from there is a configured database that did not work — a hard
//! failure, never a skip.
//!
//! Turning it into a skip does not make the result uncertain, it makes
//! it false: libtest reports `ok`, not `ignored`, for a test whose
//! fixture returned `None` and whose body early-returned. Measured on
//! the code this guard was written against, `cargo test --workspace
//! --tests --no-fail-fast` with `DATABASE_URL` pointed at a closed port
//! reported 12,350 passed / 1 failed / 7 ignored — 488 of the 489 tests
//! that touch the database claiming to have passed without opening a
//! connection, and not one of them in the `ignored` column. The gate inverted in precisely
//! the state that makes a green gate worth having.
//!
//! ## Why a source scan
//!
//! The swallow was spread across three independent shapes:
//! `hort_adapters_postgres::test_support::isolated_db_from` (reached by
//! 60 call sites), `shared_migrated_pool` (4 files), and five
//! hand-rolled `admin_pool()` fixtures that never touched `test_support`
//! at all. Fixing the helpers cannot reach the third shape, and nothing
//! in the type system distinguishes "no database configured" from "the
//! configured database refused a connection" — both are `None`. A
//! token scan is what closes it: a sixth hand-rolled copy trips this
//! test before review, and reverting the helpers trips it too.
//!
//! ## What counts as a hit
//!
//! Any call whose path ends in `…::connect…` — `PgPool::connect`,
//! `PgConnection::connect_with`, and anything else shaped like them —
//! whose result is immediately discarded with `.ok()`: i.e.
//! `…connect(x).await.ok()`, with or without a trailing `?`, and
//! regardless of how rustfmt wrapped the expression across lines. The
//! predicate is deliberately wider than "sqlx": erring wide costs a
//! false alarm that a reviewer resolves in a minute, erring narrow costs
//! the next hand-rolled copy. The scanner matches the call's closing
//! parenthesis back to its opener and checks the identifier in front of
//! it, so an unrelated `.await.ok()` elsewhere in the same statement
//! (`admin.close().await.ok();` after a connect, for instance) is not a
//! hit.
//!
//! `connect_lazy` performs no I/O and has no error to swallow; it is not
//! `async`, so it can never be followed by `.await.ok()` and needs no
//! explicit exemption.
//!
//! Rust line comments (`//`, `///`, `//!`) are stripped first — prose
//! describing the fixed pattern must stay readable, and the compiler
//! does not read comments.
//!
//! The second check narrows the same invariant inside the isolation
//! harness itself: in `hort-adapters-postgres/src/test_support.rs` the
//! only `?`-shaped `Option` conversion allowed is the `DATABASE_URL`
//! read. Every other `.ok()?` there would be a failure of the declared
//! database being handed back as if no database had been declared.

use std::fs;
use std::path::{Path, PathBuf};

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-app`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Walk `dir` recursively, calling `visit` on every `.rs` file.
fn walk_rust(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            walk_rust(&path, visit);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}

/// Drop Rust line comments, then all whitespace, so a call split across
/// lines by rustfmt reads as one token sequence.
fn code_tokens(source: &str) -> String {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Every `…::connect*(…).await.ok()` in `source`, named by the callee.
fn discarded_connects(source: &str) -> Vec<String> {
    const TOKEN: &str = ".await.ok()";
    let squashed = code_tokens(source);
    let bytes = squashed.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = squashed[from..].find(TOKEN) {
        let at = from + offset;
        from = at + TOKEN.len();
        // The discarded value must be a call: `…)` immediately before.
        if at == 0 || bytes[at - 1] != b')' {
            continue;
        }
        // Match that `)` back to its `(`.
        let mut depth = 0usize;
        let mut cursor = at - 1;
        let open = loop {
            match bytes[cursor] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        break Some(cursor);
                    }
                }
                _ => {}
            }
            if cursor == 0 {
                break None;
            }
            cursor -= 1;
        };
        let Some(open) = open else { continue };
        // The identifier in front of the `(` is the callee. Stepping back
        // by `len_utf8` rather than by one byte keeps the slice on a char
        // boundary: `is_alphanumeric` accepts non-ASCII, so the character
        // that ends the identifier can be multi-byte.
        let head = &squashed[..open];
        let start = head
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_alphanumeric() || *c == '_' || *c == ':'))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let callee = &head[start..];
        if callee.contains("::connect") {
            found.push(callee.to_string());
        }
    }
    found
}

#[test]
fn a_postgres_connect_error_is_never_discarded() {
    let crates_dir = workspace_root().join("crates");
    let mut hits = Vec::new();
    walk_rust(&crates_dir, &mut |path| {
        // Self-exclude: this file spells the banned shape out as prose
        // and plants it in the scanner self-test below.
        if path.ends_with("tests/db_gate_not_silent.rs") {
            return;
        }
        let Ok(source) = fs::read_to_string(path) else {
            return;
        };
        for callee in discarded_connects(&source) {
            hits.push(format!("{}: {callee}(…).await.ok()", path.display()));
        }
    });
    assert!(
        hits.is_empty(),
        "a Postgres connect error must never be discarded with `.ok()`: a \
         DB-gated fixture only reaches a connect because DATABASE_URL was \
         set, so the failure is a configured database that did not work, and \
         the caller cannot tell the resulting `None` apart from \"no database \
         configured\" — libtest then reports the test `ok` without it having \
         run. Use `hort_adapters_postgres::test_support::connect_or_panic` \
         (or `isolated_db_from`), which panic instead. Found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

#[test]
fn the_isolation_harness_skips_only_on_the_env_var() {
    let harness = workspace_root()
        .join("crates/hort-adapters-postgres/src/test_support.rs")
        .canonicalize()
        .expect("the isolation harness exists at the path this guard pins");
    let source = fs::read_to_string(&harness).expect("read the isolation harness");
    let offenders: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| line.contains(".ok()?"))
        .filter(|(_, line)| !line.contains("env::var("))
        .map(|(i, line)| format!("{}:{}: {}", harness.display(), i + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "inside the isolation harness the only `?`-shaped skip may be the \
         DATABASE_URL read — every other early return hands a failure of the \
         declared database back as if no database had been declared. Found \
         {} offending line(s):\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

#[test]
fn the_scanner_trips_on_a_planted_silent_connect() {
    let planted = "async fn admin_pool() -> Option<PgPool> {\n    \
                   let url = env::var(\"DATABASE_URL\").ok()?;\n    \
                   PgPool::connect(&url)\n        .await\n        .ok()\n}";
    assert_eq!(
        discarded_connects(planted),
        vec!["PgPool::connect".to_string()],
        "the scanner must see a connect whose error is discarded, including \
         one rustfmt split across lines"
    );
}

#[test]
fn the_scanner_ignores_an_unrelated_ok_after_a_connect() {
    // `admin.close().await.ok()` follows a connect in the same block but
    // discards the *close*, not the connect. A scanner that looked for
    // `.await.ok()` near a connect would call this a hit.
    let benign = "let mut admin = PgConnection::connect_with(&opts).await.expect(\"connect\");\n\
                  admin.close().await.ok();";
    assert!(
        discarded_connects(benign).is_empty(),
        "closing a connection is not connecting to one"
    );
}

#[test]
fn the_scanner_ignores_a_connect_whose_error_is_handled() {
    let handled = "let pool = match PgPool::connect_with(opts).await {\n    \
                   Ok(pool) => pool,\n    Err(err) => panic!(\"{err}\"),\n};";
    assert!(
        discarded_connects(handled).is_empty(),
        "a handled connect error is the shape this guard is asking for"
    );
}

#[test]
fn the_scanner_stays_on_char_boundaries_around_non_ascii() {
    // `is_alphanumeric` accepts non-ASCII, so the character that ends the
    // callee identifier can be multi-byte. Byte-stepping off it would
    // slice mid-character and panic — in a guard, a panic is a false
    // alarm that looks like a finding.
    let with_multibyte = "let s = \"—\"; PgPool::connect(&url).await.ok()";
    assert_eq!(
        discarded_connects(with_multibyte),
        vec!["PgPool::connect".to_string()]
    );
}
