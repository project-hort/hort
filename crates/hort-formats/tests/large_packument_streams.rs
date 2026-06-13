//! Supplementary functional proof that the npm packument streaming
//! projector handles a multi-megabyte body through the `FormatHandler`
//! streaming-reader port without materialising a whole-body
//! `serde_json::Value` tree (see ADR 0026).
//!
//! The structural proof lives in
//! `crates/hort-domain/tests/streaming_metadata_port.rs` (the port
//! signatures + the no-`metadata_body_bytes` call-site guard). This
//! test is the optional functional companion: it feeds a synthetic
//! ~4 MiB packument (thousands of versions) through
//! `NpmFormatHandler::extract_upstream_versions(&mut reader)` and
//! asserts every version streams out.
//!
//! ## Size calibration (why ~4 MiB)
//!
//! `NpmFormatHandler::extract_upstream_versions` STREAMS the body, so
//! its *input body* ceiling is the streaming plausibility bound
//! `STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES` = **64 MiB** (aligned
//! with the `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE` fetch backstop), NOT
//! the small in-memory `metadata_expected_max_bytes()`. An over-cap body
//! surfaces a `Validation` error — load-bearing fail-closed behaviour
//! verified by `extract_upstream_versions_npm_over_cap_returns_validation_error`
//! in `npm.rs`. This test uses ~4 MiB to keep the fixture cheap to
//! build while still being far larger than any single per-version
//! object: the point is the orthogonal one — a multi-MiB document
//! (thousands of entries) streams through the incremental projector
//! successfully, the projector bounding memory by projected shape (the
//! small version-string list), not by buffering the whole document into
//! a `serde_json::Value`. No exact peak-RSS probe (env-dependent); the
//! streaming success on a multi-MiB body is the observable signal.

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::npm::NpmFormatHandler;

/// Build a syntactically-valid npm packument JSON with `count` versions,
/// targeting roughly `min_bytes` total size by padding each per-version
/// object with a benign description string. Each per-version object
/// stays small (well under the projector's 2 MiB per-version cap).
fn synthetic_packument(count: usize, min_bytes: usize) -> Vec<u8> {
    // Per-version padding so the whole document reaches the target size
    // while every individual version object remains KiB-scale.
    let pad_per_version = (min_bytes / count.max(1)).max(64);
    let pad = "x".repeat(pad_per_version);

    let mut s = String::with_capacity(min_bytes + 4096);
    s.push_str("{\"name\":\"big-pkg\",\"dist-tags\":{\"latest\":\"1.0.0\"},\"versions\":{");
    for i in 0..count {
        if i > 0 {
            s.push(',');
        }
        // Distinct, ordered version strings: 0.0.0, 0.0.1, ...
        let version = format!("0.0.{i}");
        s.push_str(&format!(
            "\"{version}\":{{\"name\":\"big-pkg\",\"version\":\"{version}\",\
             \"dist\":{{\"integrity\":\"sha512-{i}\",\"tarball\":\"https://r/big-pkg-{version}.tgz\"}},\
             \"description\":\"{pad}\"}}"
        ));
    }
    s.push_str("}}");
    s.into_bytes()
}

#[test]
fn large_multi_mib_packument_streams_through_extract_upstream_versions() {
    // ~4 MiB target — comfortably under the streaming plausibility input
    // cap (64 MiB) so the body is accepted, yet far larger than any
    // single per-version object, exercising the incremental streaming
    // projector over a multi-megabyte document.
    const TARGET_BYTES: usize = 4 * 1024 * 1024;
    const VERSION_COUNT: usize = 5_000;

    let body = synthetic_packument(VERSION_COUNT, TARGET_BYTES);
    assert!(
        body.len() >= TARGET_BYTES,
        "synthetic packument is {} bytes, expected >= {} — fixture calibration drifted",
        body.len(),
        TARGET_BYTES
    );
    // Sanity: stay under the 64 MiB streaming plausibility input cap so
    // this is a SUCCESS path, not the over-cap rejection path (covered
    // elsewhere).
    assert!(
        body.len() < 64 * 1024 * 1024,
        "synthetic packument {} bytes exceeds the 64 MiB streaming input cap — \
         recalibrate VERSION_COUNT/TARGET_BYTES so the success path is exercised",
        body.len()
    );

    // Stream it through the port's streaming reader. A `Cursor` is the
    // reader; the projector consumes it incrementally.
    let mut reader = std::io::Cursor::new(&body);
    let versions = NpmFormatHandler
        .extract_upstream_versions(&mut reader)
        .expect("multi-MiB packument streams through the projector successfully");

    assert_eq!(
        versions.len(),
        VERSION_COUNT,
        "every version in the multi-MiB packument should stream out"
    );
    // Spot-check first / last to confirm ordered, complete extraction.
    assert_eq!(versions.first().map(String::as_str), Some("0.0.0"));
    assert_eq!(
        versions.last().map(String::as_str),
        Some(format!("0.0.{}", VERSION_COUNT - 1).as_str())
    );
}
