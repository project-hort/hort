//! Regression test — `OsvScannerAdapter::scan`
//! must enforce its configured `timeout` by wrapping the child process
//! in `tokio::time::timeout` and `child.kill()`-ing the process on
//! expiry. Without the wrapper a hung osv-scanner pegs the worker
//! until something else terminates it.
//!
//! Strategy: write a tiny shell script (`#!/bin/sh\nsleep 30`) to a
//! `tempfile::NamedTempFile`, mark it executable, and point
//! `osv_scanner_bin` at it. The adapter's argv (`--format json
//! --sbom <path>`) is appended but the script ignores it and just
//! sleeps. With a 100ms configured timeout the only path back is
//! the timeout branch firing.
//!
//! On Windows the shebang trick does not apply; the test
//! short-circuits on non-Unix targets. CI runs Linux so the
//! regression guard is in force where it matters.
//!
//! Manual-run path:
//! `cargo test -p hort-adapters-scanner-osv --test timeout
//!  osv_scan_timeout_kills_hung_child_within_configured_window`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use hort_adapters_scanner_osv::{OsvScannerAdapter, OsvScannerConfig};
use hort_domain::error::DomainError;
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::types::{ContentHash, Sbom};

fn placeholder_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .unwrap()
}

fn empty_sbom() -> Sbom {
    Sbom {
        subject: None,
        components: vec![],
    }
}

/// Materialise an executable shell script that sleeps for `secs`
/// seconds and then exits 0. Returns the temp path handle (must
/// outlive the adapter call so the script is not unlinked mid-spawn).
/// We use `tempfile::TempPath` rather than `NamedTempFile` so the
/// underlying file is closed before the child execs it — Linux
/// returns `ETXTBSY` when execve runs against a path with an open
/// writable handle.
fn hung_child_script(secs: u64) -> tempfile::TempPath {
    let f = tempfile::Builder::new()
        .prefix("hort-osv-fake-bin-")
        .suffix(".sh")
        .tempfile()
        .expect("temp file create");
    let body = format!("#!/bin/sh\nsleep {secs}\n");
    fs::write(f.path(), body).expect("write script body");
    let mut perms = fs::metadata(f.path()).expect("stat").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(f.path(), perms).expect("chmod +x");
    // Convert `NamedTempFile` to `TempPath`; the writable file handle
    // is dropped here, satisfying `execve`'s ETXTBSY constraint.
    f.into_temp_path()
}

#[tokio::test]
async fn osv_scan_timeout_kills_hung_child_within_configured_window() {
    let script = hung_child_script(30);
    let cfg = OsvScannerConfig {
        // Substitute the hung-child script for the osv-scanner binary.
        // The adapter passes `--format json --sbom <path>` as argv;
        // the script ignores them and just sleeps. That holds
        // stdout/stderr pipes open and forces `run_scan` down the
        // timeout branch.
        osv_scanner_bin: script.to_path_buf(),
        timeout: Duration::from_millis(100),
        max_report_size: 256 * 1024 * 1024,
        subprocess_ca_bundle: None,
    };
    let adapter = OsvScannerAdapter::new(cfg);
    let hash = placeholder_hash();
    let sbom = empty_sbom();

    let started = Instant::now();
    let result = adapter.scan(&hash, Some(&sbom)).await;
    let elapsed = started.elapsed();

    // The timeout (100ms) plus kill + cleanup overhead should land
    // well under 2s. Without the timeout wrapper this future never
    // resolves and the test harness eventually hangs / hits its own
    // outer timeout — the wall-clock assertion makes the regression
    // observable rather than a test-runtime hang.
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
                msg.contains("osv adapter"),
                "timeout error must mention 'osv adapter' for operator clarity; got: {msg}"
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

    // Keep `script` alive until after the adapter call returns so
    // the temp file is not unlinked while the spawned child still
    // holds the path open.
    drop(script);
}
