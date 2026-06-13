//! Test-only utilities shared across adapter modules.
//!
//! Tests in this crate cannot use `#[tokio::test]` because some test paths
//! must run inside `temp_env::with_var(...)` (sync) which captures the
//! whole future. A standalone `block_on` keeps the env-var harness sync
//! while still letting the adapter return a `BoxFuture`.

use std::future::Future;

/// Run an async block on a fresh current-thread runtime.
/// Used so individual test bodies stay synchronous (necessary for
/// `temp_env::with_var`, which is sync).
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
        .block_on(f)
}
