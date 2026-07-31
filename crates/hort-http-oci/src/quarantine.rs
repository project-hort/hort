//! Shared quarantine / scan-indeterminate response helpers for OCI pull
//! handlers.
//!
//! Both the blob and manifest handlers check `Artifact.quarantine_status`
//! directly — see `blobs.rs` module doc for why handler-side check + 503
//! is the shape required for OCI clients behind transparent proxies
//! (Artifactory). Extracting the shared logic here keeps the 503
//! response shape consistent across every OCI read path. Each handler
//! restructures its own gate into an exhaustive `match` on
//! `QuarantineStatus` (issue #92) and calls the matching helper below
//! ONLY from the arm that already knows the state — these functions are
//! therefore infallible builders, not `Option`-returning short-circuit
//! checks; the exhaustiveness lives at the call site, not here.
//!
//! ## What these helpers do NOT do
//!
//! - Neither handles the `Rejected` case. Rejected artifacts are
//!   mapped to format-specific hidden-404 envelopes (`BLOB_UNKNOWN` /
//!   `MANIFEST_UNKNOWN`); the caller decides which one to emit.
//! - Neither handles `None` / `Released`. Those arms fall through to
//!   the happy path in the caller's own match; there is nothing for
//!   this module to build.

use axum::response::{IntoResponse, Response};
use chrono::Utc;

use hort_domain::entities::artifact::Artifact;

use super::error::OciError;

/// Default `Retry-After` when the computed `quarantine_deadline` is
/// absent — 1 hour, matching the pre-refactor open-coded value in
/// `blobs.rs` / `manifests.rs`.
const DEFAULT_QUARANTINE_RETRY_AFTER_SECS: i64 = 3600;

/// Build the `Quarantined` 503 + `Retry-After` response and emit the
/// `hort_download_total{format="oci", repository=<repo_key>,
/// result="quarantined"}` counter. Callers invoke this ONLY from a
/// `QuarantineStatus::Quarantined` match arm — see the module doc.
///
/// `repo_key` goes into the counter's `repository` label. It is NOT
/// echoed in the response body, so quarantine state stays opaque to
/// the client — only "try again later" is exposed.
pub(super) fn check_quarantine(artifact: &Artifact, repo_key: &str) -> Response {
    // Retry-After computation: seconds until the computed quarantine
    // deadline (`quarantine_deadline` is hydrated by the use-case layer;
    // the format crate never computes it), clamped to >= 1 so clients
    // don't get `Retry-After: 0` (spec-legal but easy to misparse),
    // falling back to 1 hour when no deadline is set.
    let retry_after_seconds = artifact
        .quarantine_deadline
        .map(|deadline| (deadline - Utc::now()).num_seconds().max(1))
        .unwrap_or(DEFAULT_QUARANTINE_RETRY_AFTER_SECS);

    // Emit the download-outcome counter from the short-circuit path.
    // `ArtifactUseCase::download` never runs for quarantined pulls (we
    // never opened the CAS stream), so without this counter here the
    // `hort_download_total{result="quarantined"}` signal would drop to
    // zero the moment the handler-side short-circuit kicked in.
    // `repository` is the client-supplied repo key (not yet resolved
    // to an id here — the download path uses the key label too).
    metrics::counter!(
        "hort_download_total",
        "format" => "oci",
        "repository" => repo_key.to_string(),
        "result" => "quarantined",
    )
    .increment(1);

    OciError::Quarantined {
        retry_after_seconds,
    }
    .into_response()
}

/// Build the `ScanIndeterminate` 503 response — no `Retry-After` (no
/// self-resolving deadline; ADR 0007's fail-closed terminal state,
/// issue #6) and no ADR 0039 hold-read / probe extension for any
/// caller, including write-granted (issue #92). Callers invoke this
/// ONLY from a `QuarantineStatus::ScanIndeterminate` match arm — see
/// the module doc.
///
/// Deliberately does NOT emit `hort_download_total` — no new metric
/// label value for this state (existing `hort_http_*` request-level
/// metrics already cover the 503 status code). Takes no arguments: the
/// response is fixed, independent of which artifact or repo triggered
/// it (quarantine state stays opaque to the client).
pub(super) fn check_scan_indeterminate() -> Response {
    OciError::ScanIndeterminate.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use chrono::Duration;
    use hort_app::use_cases::test_support::sample_artifact;
    use hort_domain::entities::artifact::QuarantineStatus;

    // `check_quarantine` no longer self-guards on `quarantine_status` —
    // callers invoke it only from an already-matched `Quarantined` arm
    // (issue #92 restructure), so there is no "wrong state → None" case
    // left to test here; that invariant is pinned by the handler-level
    // exhaustive-match tests in `manifests.rs` / `blobs.rs` instead.

    #[tokio::test]
    async fn quarantined_with_future_deadline_uses_computed_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let secs: i64 = response
            .headers()
            .get("Retry-After")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&secs), "retry-after out of range: {secs}");
    }

    #[tokio::test]
    async fn quarantined_with_past_deadline_clamps_to_one() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        // Deadline in the past — the raw num_seconds would be negative;
        // the helper clamps to 1 so the client doesn't retry immediately.
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo");
        let secs: i64 = response
            .headers()
            .get("Retry-After")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(secs, 1);
    }

    #[tokio::test]
    async fn quarantined_without_deadline_uses_default_hour() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = None;
        let response = check_quarantine(&artifact, "myrepo");
        let secs: i64 = response
            .headers()
            .get("Retry-After")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(secs, DEFAULT_QUARANTINE_RETRY_AFTER_SECS);
    }

    #[tokio::test]
    async fn body_is_oci_envelope_with_unavailable_code() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo");
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        // `detail.retry_after_seconds` echoes the computed delta so
        // the client can cross-check against the header.
        assert!(parsed["errors"][0]["detail"]["retry_after_seconds"].is_i64());
    }

    #[tokio::test]
    async fn scan_indeterminate_response_is_503_with_no_retry_after() {
        let response = check_scan_indeterminate();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers().get("Retry-After").is_none(),
            "ScanIndeterminate must never carry Retry-After — no self-resolving deadline"
        );
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        assert_eq!(
            parsed["errors"][0]["message"],
            "artifact scan result is indeterminate"
        );
        assert!(parsed["errors"][0]["detail"].is_null());
    }
}
