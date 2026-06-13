//! Build script: track `migrations` so an in-place migration
//! edit recompiles this crate (incl. its `--lib` and `tests/` targets).
//!
//! `sqlx::migrate!("../../migrations")` embeds the migration
//! SQL at **compile time**. It is a proc-macro and therefore cannot
//! itself emit `cargo:rerun-if-changed`. Without this build script,
//! cargo has no dependency edge from the compiled artifact to the
//! `.sql` files: editing a migration in place (the sanctioned pre-v1.0
//! practice) does NOT change any `.rs`, so a cached/incremental build
//! keeps a **stale embedded schema**. A stale migrator then silently
//! applies an outdated schema and records the version in
//! `_sqlx_migrations`; later (fresh-embed) migrators skip it by
//! version number, so a later-added DDL (e.g. migration 013's
//! `subscriptions.created_by_token_id` FK) is never applied.
//!
//! Pointing `rerun-if-changed` at the migrations directory makes cargo
//! recompile this crate whenever any migration file changes — locally
//! and in CI (even with a warm `target/` cache). Path is relative to
//! this package's manifest dir (`crates/hort-adapters-postgres/`).
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
