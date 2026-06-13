//! Build script: track `migrations` so an in-place migration
//! edit recompiles this crate.
//!
//! `hort-worker` embeds the migration SQL at **compile time** via
//! `sqlx::migrate!("../../migrations")` (see
//! `src/composition.rs`). `sqlx::migrate!` is a proc-macro and cannot
//! itself emit `cargo:rerun-if-changed`. Without this build script,
//! cargo has no dependency edge from the compiled artifact to the
//! `.sql` files: an in-place migration edit (the sanctioned pre-v1.0
//! practice) does NOT change any `.rs`, so a cached/incremental build
//! keeps a **stale embedded schema** and a stale migrator can silently
//! apply an outdated schema. Pointing `rerun-if-changed` at the
//! migrations directory makes cargo recompile this crate whenever any
//! migration file changes. Path is relative to this package's manifest
//! dir (`crates/hort-worker/`).
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
