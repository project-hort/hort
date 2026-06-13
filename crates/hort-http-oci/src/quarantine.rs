//! Shared quarantine-response helper for OCI pull handlers.
//!
//! Both the blob (Item 6) and manifest (Item 7) handlers must check
//! `Artifact.quarantine_status` directly — see `blobs.rs` module doc
//! for why handler-side check + 503 + `Retry-After` is the shape
//! required for OCI clients behind transparent proxies (Artifactory).
//! The two handlers previously open-coded the same 23-line block with
//! only the hidden-404 code string differing; Item 19 (proxy-fetch)
//! will make it a third call site. Extracting the shared logic here
//! keeps the 503 response shape and the `hort_download_total{result=
//! "quarantined"}` counter consistent across every OCI read path.
//!
//! ## What this helper does NOT do
//!
//! - It does NOT handle the `Rejected` case. Rejected artifacts are
//!   mapped to format-specific hidden-404 envelopes (`BLOB_UNKNOWN` /
//!   `MANIFEST_UNKNOWN`); the caller decides which one to emit.
//! - It does NOT fall through to the happy path. Callers use the
//!   `Option<Response>` return: `Some` short-circuits the handler;
//!   `None` lets it continue.

use axum::response::{IntoResponse, Response};
use chrono::Utc;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};

use super::error::OciError;

/// Default `Retry-After` when the computed `quarantine_deadline` is
/// absent — 1 hour, matching the pre-refactor open-coded value in
/// `blobs.rs` / `manifests.rs`.
const DEFAULT_QUARANTINE_RETRY_AFTER_SECS: i64 = 3600;

/// If `artifact` is quarantined, build a 503 + `Retry-After` response
/// and emit the `hort_download_total{format="oci", repository=<repo_key>,
/// result="quarantined"}` counter. Return `Some(response)` — the
/// caller returns it straight to the client. Return `None` for every
/// other state (None / Released / Rejected); the caller handles
/// Rejected itself because the hidden-404 envelope differs between
/// blob and manifest handlers.
///
/// `repo_key` goes into the counter's `repository` label. It is NOT
/// echoed in the response body, so quarantine state stays opaque to
/// the client — only "try again later" is exposed.
pub(super) fn check_quarantine(artifact: &Artifact, repo_key: &str) -> Option<Response> {
    if !matches!(artifact.quarantine_status, QuarantineStatus::Quarantined) {
        return None;
    }
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

    Some(
        OciError::Quarantined {
            retry_after_seconds,
        }
        .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use chrono::Duration;
    use hort_app::use_cases::test_support::sample_artifact;

    #[tokio::test]
    async fn not_quarantined_returns_none() {
        let artifact = sample_artifact(QuarantineStatus::None);
        assert!(check_quarantine(&artifact, "myrepo").is_none());
    }

    #[tokio::test]
    async fn released_returns_none() {
        let artifact = sample_artifact(QuarantineStatus::Released);
        assert!(check_quarantine(&artifact, "myrepo").is_none());
    }

    #[tokio::test]
    async fn rejected_returns_none() {
        // Rejected is caller's responsibility — the hidden-404 envelope
        // differs between blob / manifest handlers.
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        assert!(check_quarantine(&artifact, "myrepo").is_none());
    }

    #[tokio::test]
    async fn quarantined_with_future_deadline_uses_computed_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo").expect("expected response");
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
        let response = check_quarantine(&artifact, "myrepo").expect("expected response");
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
        let response = check_quarantine(&artifact, "myrepo").expect("expected response");
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
        let response = check_quarantine(&artifact, "myrepo").expect("expected response");
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        // `detail.retry_after_seconds` echoes the computed delta so
        // the client can cross-check against the header.
        assert!(parsed["errors"][0]["detail"]["retry_after_seconds"].is_i64());
    }
}
