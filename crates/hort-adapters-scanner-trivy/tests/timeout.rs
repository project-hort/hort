//! Regression test — `TrivyAdapter::scan` must
//! enforce its configured `timeout` by wrapping the spawned `trivy`
//! child in `tokio::time::timeout` and `child.kill()`-ing it on
//! expiry. Trivy's own `--timeout` flag is defence-in-depth; this is
//! the Rust-side backstop for "trivy hangs before honouring it".
//! Without the wrapper a hung child pegs the worker until something
//! else terminates it.
//!
//! Strategy mirrors the OSV adapter's `tests/timeout.rs`: write a tiny
//! `#!/bin/sh\nsleep 30` script to a `tempfile::TempPath`, mark it
//! executable, and point `trivy_bin` at it. The adapter appends its
//! argv (`fs --format json …`); the script ignores it and just
//! sleeps. With a 100ms configured timeout the only path back is the
//! Rust timeout branch firing.
//!
//! On non-Unix the shebang trick does not apply; the test
//! short-circuits via `#![cfg(unix)]`. CI runs Linux so the
//! regression guard is in force where it matters.
//!
//! Manual-run path:
//! `cargo test -p hort-adapters-scanner-trivy --test timeout
//!  trivy_scan_timeout_kills_hung_child_within_configured_window`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hort_adapters_scanner_trivy::{TrivyAdapter, TrivyConfig};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::ports::storage::{PutResult, StoragePort};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};
use tokio::io::AsyncRead;

fn placeholder_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .unwrap()
}

/// Storage stub returning a tiny payload so `prepare_workspace`
/// succeeds and the scan proceeds into the (hung) CLI invocation.
struct TinyStorage;
impl StoragePort for TinyStorage {
    fn put(&self, _s: Box<dyn AsyncRead + Send + Unpin>) -> BoxFuture<'_, DomainResult<PutResult>> {
        Box::pin(async { unreachable!() })
    }
    fn get(
        &self,
        _h: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async {
            let r: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(std::io::Cursor::new(b"scan target".to_vec()));
            Ok(r)
        })
    }
    fn get_range(
        &self,
        _h: &ContentHash,
        _r: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!() })
    }
    fn exists(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        Box::pin(async { unreachable!() })
    }
    fn size_of(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        Box::pin(async { unreachable!() })
    }
}

/// Materialise an executable shell script that sleeps for `secs`
/// seconds then exits 0. `TempPath` (not `NamedTempFile`) so the
/// writable handle is closed before the child execs it — Linux
/// returns `ETXTBSY` against a path with an open writable handle.
fn hung_child_script(secs: u64) -> tempfile::TempPath {
    let f = tempfile::Builder::new()
        .prefix("hort-trivy-fake-bin-")
        .suffix(".sh")
        .tempfile()
        .expect("temp file create");
    let body = format!("#!/bin/sh\nsleep {secs}\n");
    fs::write(f.path(), body).expect("write script body");
    let mut perms = fs::metadata(f.path()).expect("stat").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(f.path(), perms).expect("chmod +x");
    f.into_temp_path()
}

#[tokio::test]
async fn trivy_scan_timeout_kills_hung_child_within_configured_window() {
    let script = hung_child_script(30);
    let cfg = TrivyConfig {
        trivy_bin: script.to_path_buf(),
        timeout: Duration::from_millis(100),
        ..TrivyConfig::default()
    };
    let adapter = TrivyAdapter::new(cfg, Arc::new(TinyStorage));
    let hash = placeholder_hash();

    let started = Instant::now();
    let result = adapter.scan(&hash, None).await;
    let elapsed = started.elapsed();

    // 100ms timeout + kill/cleanup overhead must land well under 2s.
    // Without the Rust-side wrapper this future never resolves and the
    // harness hangs — the wall-clock assertion makes the regression
    // observable rather than a runtime hang.
    assert!(
        elapsed < Duration::from_secs(2),
        "scan with hung child must return within ~2s once timeout fires; \
         elapsed = {elapsed:?}"
    );

    match result {
        Err(DomainError::Invariant(msg)) => {
            assert!(
                msg.contains("timeout"),
                "timeout error must mention 'timeout'; got: {msg}"
            );
            assert!(
                msg.contains("trivy adapter"),
                "timeout error must mention 'trivy adapter' for operator clarity; got: {msg}"
            );
            // Uniform cross-backend wording contract (matches OSV):
            // "trivy adapter: scan exceeded timeout (Ns)".
            assert!(
                msg.contains("scan exceeded timeout"),
                "wording must match the uniform cross-backend contract; got: {msg}"
            );
        }
        Ok(findings) => panic!(
            "timeout regression: scan must NOT return Ok when the child hangs; \
             got findings={findings:?}"
        ),
        Err(other) => panic!(
            "timeout regression: scan must surface DomainError::Invariant on timeout; \
             got {other:?}"
        ),
    }

    drop(script);
}
