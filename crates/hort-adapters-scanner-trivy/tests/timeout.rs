//! Regression test — `TrivyAdapter::scan` must
//! enforce its configured `timeout` by wrapping the spawned `trivy`
//! child in `tokio::time::timeout` and `child.kill()`-ing it on
//! expiry. Trivy's own `--timeout` flag is defence-in-depth; this is
//! the Rust-side backstop for "trivy hangs before honouring it".
//! Without the wrapper a hung child pegs the worker until something
//! else terminates it.
//!
//! A symlink in a private tempdir points at the checked-in fake Trivy.
//! Its invoked name selects a 30-second sleep; the adapter's argv is
//! ignored. With a 100ms configured timeout the only path back is the
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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hort_adapters_scanner_trivy::{TrivyAdapter, TrivyConfig};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{ScanTarget, ScanUnit, ScannerPort};
use hort_domain::ports::storage::{PutResult, StoragePort};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ArtifactCoords, ArtifactKind, ByteRange, ContentHash};
use tokio::io::AsyncRead;

fn placeholder_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .unwrap()
}

/// A Maven-JAR target: its materialisation is a single named file, so the
/// workspace step is trivial and the test lands squarely in the CLI
/// invocation the hung child is standing in for.
fn jar_coords() -> ArtifactCoords {
    ArtifactCoords {
        name: "com.example:app".to_string(),
        name_as_published: "com.example:app".to_string(),
        version: Some("1.0.0".to_string()),
        path: "com/example/app/1.0.0/app-1.0.0.jar".to_string(),
        format: RepositoryFormat::Maven,
        metadata: serde_json::Value::Null,
    }
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

fn hung_child_script(dir: &tempfile::TempDir) -> PathBuf {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-trivy.sh");
    let link = dir.path().join("fake-trivy-hang");
    std::os::unix::fs::symlink(&fixture, &link).expect("symlink fake Trivy fixture");
    link
}

#[tokio::test]
async fn trivy_scan_timeout_kills_hung_child_within_configured_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = hung_child_script(&dir);
    let cfg = TrivyConfig {
        trivy_bin: script,
        timeout: Duration::from_millis(100),
        ..TrivyConfig::default()
    };
    let adapter = TrivyAdapter::new(cfg, Arc::new(TinyStorage));
    let hash = placeholder_hash();
    let coords = jar_coords();
    let target = ScanTarget {
        unit: ScanUnit::Blob(&hash),
        format: "maven",
        coords: &coords,
        kind: ArtifactKind::MavenJar,
    };

    let started = Instant::now();
    let result = adapter.scan(&target, None).await;
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
        Ok(analysis) => panic!(
            "timeout regression: scan must NOT return Ok when the child hangs; \
             got {analysis:?}"
        ),
        Err(other) => panic!(
            "timeout regression: scan must surface DomainError::Invariant on timeout; \
             got {other:?}"
        ),
    }
}
