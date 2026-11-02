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
//! - Neither handles the `Rejected` case. That arm answers `403`
//!   `DENIED` naming the rejection axis, and the subject it names is
//!   route-specific (a blob digest, a manifest reference), so each
//!   caller builds its own `OciError::ArtifactRejected`.
//! - Neither handles `None` / `Released`. Those arms fall through to
//!   the happy path in the caller's own match; there is nothing for
//!   this module to build.

use std::num::NonZeroU32;

use axum::response::{IntoResponse, Response};

use hort_domain::entities::artifact::Artifact;
use hort_http_core::artifact_gate::quarantine_retry_after_seconds;

use super::error::OciError;

/// Build the `Quarantined` 503 response and emit the
/// `hort_download_total{format="oci", repository=<repo_key>,
/// result="quarantined"}` counter. Callers invoke this ONLY from a
/// `QuarantineStatus::Quarantined` match arm — see the module doc.
///
/// ## The seconds are not computed here
///
/// How many seconds a held artifact advertises is a property of the
/// hold, not of the protocol carrying the refusal, so it comes from
/// [`quarantine_retry_after_seconds`] — the one definition, shared with
/// the four hosted/proxy content routes' own gate
/// (`hort_http_core::artifact_gate::non_servable_response`). This
/// function owns only the OCI **envelope**, which is a different
/// protocol's document and stays separate on purpose.
///
/// It was not always shared, and the cost of that was measured: a
/// container pull is an OCI request, so the copy answering real pulls
/// was this one, and a correction applied to the core gate alone left it
/// advertising `Retry-After: 1` on a hold that took a minute to clear.
///
/// `retry_after_floor_secs` is the operator-configured floor
/// (`AppContext::quarantine_retry_after_floor_secs`,
/// `HORT_QUARANTINE_RETRY_AFTER_FLOOR_SECS`), threaded from the handler
/// rather than read from anywhere process-global.
///
/// ## Which states reach which answer
///
/// Both inputs to the computation are hydrated by the use-case layer
/// (`ArtifactUseCase::hydrate_quarantine_deadline`); the format crate
/// computes neither, and cannot — resolving a `ScanPolicy` or reading
/// the artifact's event stream from here would reach past the use case
/// (ADR 0008).
///
/// - An **in-window** hold answers its own remaining delta.
/// - A hold whose window has **already elapsed** answers the floor. What
///   it waits on is the artifact's own scan verdict, which does arrive,
///   so a number is the honest answer — just not the one second the
///   negative subtraction used to clamp to.
/// - A hold with **no** `quarantine_window_start` answers
///   `hort_http_core::artifact_gate::DEFAULT_QUARANTINE_RETRY_AFTER_SECS`
///   (1 hour, "the deadline is genuinely unknown"). **Every** path that
///   resolves an artifact for a read hydrates the deadline — the three
///   visibility-checked loaders (`ArtifactUseCase::find_visible_by_path`
///   / `find_visible_by_id` / `find_in_repo_by_hash`) and `get_by_id`,
///   which `blobs.rs`'s bounded-await poll loop re-reads through and
///   whose row it returns when the bound is exhausted — and both
///   `IngestUseCase` mint paths stamp it from the window they just
///   derived. So the only state left is a row the schema permits (the
///   column is nullable and no CHECK ties it to the status) but no
///   current code path produces; such a row also sits outside the
///   release sweep's candidacy filter
///   (`quarantine_window_start IS NOT NULL`).
/// - A hold waiting on an **external** event
///   (`provenance_hold_indefinite`) answers `503` with **no** header at
///   all, mirroring [`check_scan_indeterminate`] (ADR 0039's 2026-09-12
///   amendment, D5). No floor rescues that case: a signature arriving is
///   not an event any delta-seconds value describes, so the floor would
///   only move the lie from one second to the floor.
///
/// On the OCI blob route that last clause is narrower than it sounds,
/// and worth not over-reading. The population it describes — an elapsed
/// window under `provenance_mode: Required` with the gate still
/// `Pending` — is exactly what
/// `blobs.rs::maybe_bounded_await_release`'s provenance-blocked guard
/// detects via `QuarantineUseCase::release_blocked_on_provenance`, and
/// that guard returns **before** the poll loop. So for that population
/// the row the refusal answers from is `find_visible_by_path`'s,
/// hydrated on the way in, and the loop never runs. What `get_by_id`'s
/// hydration closes is the guard's **fail-safe** path: the guard treats
/// a clearance-read error as "not blocked" so it can never introduce a
/// new hold, the wait then runs against an artifact that will not be
/// released inside the bound, and the row it hands back at exhaustion is
/// the one that has to carry the flag. The manifest route has no such
/// loop at all.
///
/// `repo_key` goes into the counter's `repository` label. It is NOT
/// echoed in the response body, and the two holds are indistinguishable
/// on the wire beyond the presence of the header, so quarantine state
/// stays opaque to the client — only "try again later", or nothing at
/// all, is exposed.
pub(super) fn check_quarantine(
    artifact: &Artifact,
    repo_key: &str,
    retry_after_floor_secs: NonZeroU32,
) -> Response {
    let retry_after_seconds = quarantine_retry_after_seconds(artifact, retry_after_floor_secs);

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
    use chrono::{Duration, Utc};
    use hort_app::use_cases::test_support::sample_artifact;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_http_core::artifact_gate::{
        DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS, DEFAULT_QUARANTINE_RETRY_AFTER_SECS,
    };

    // `check_quarantine` no longer self-guards on `quarantine_status` —
    // callers invoke it only from an already-matched `Quarantined` arm
    // (issue #92 restructure), so there is no "wrong state → None" case
    // left to test here; that invariant is pinned by the handler-level
    // exhaustive-match tests in `manifests.rs` / `blobs.rs` instead.

    /// A floor deliberately **not** equal to
    /// [`DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS`]: an expectation
    /// derived from the default cannot tell "the configured value
    /// reaches the computation" from "the default is baked in".
    const TEST_FLOOR: NonZeroU32 = NonZeroU32::new(45).expect("45 is non-zero");

    /// Parse the `Retry-After` of a response that must carry one.
    fn retry_after_secs(response: &Response) -> i64 {
        response
            .headers()
            .get("Retry-After")
            .expect("this hold must advertise a Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn quarantined_with_future_deadline_uses_computed_retry_after() {
        const WINDOW_SECS: i64 = 600;
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(WINDOW_SECS));
        let response = check_quarantine(&artifact, "myrepo", TEST_FLOOR);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let secs = retry_after_secs(&response);
        // The window is an order of magnitude above the floor, so a
        // regression answering the floor unconditionally fails here.
        assert!(
            (WINDOW_SECS - 5..=WINDOW_SECS).contains(&secs),
            "retry-after out of range: {secs}"
        );
        assert!(
            secs > i64::from(TEST_FLOOR.get()),
            "a long window answers its own delta, not the floor: {secs}"
        );
    }

    /// A deadline already in the past answers the **configured floor**,
    /// not the one second the negative subtraction used to clamp to.
    ///
    /// This is the state a container pull of a just-ingested image hits:
    /// the window is over, the scan verdict is not in, and `1` told a
    /// `Retry-After`-honouring client to poll once a second for the whole
    /// of a minute-long scan.
    #[tokio::test]
    async fn quarantined_with_past_deadline_answers_the_configured_floor() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo", TEST_FLOOR);
        assert_eq!(retry_after_secs(&response), i64::from(TEST_FLOOR.get()));
    }

    /// The default an operator gets without setting the env var is the
    /// shared constant, and it is not `1`.
    #[tokio::test]
    async fn the_default_floor_reaches_the_oci_envelope() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let response = check_quarantine(
            &artifact,
            "myrepo",
            DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS,
        );
        assert_eq!(
            retry_after_secs(&response),
            i64::from(DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS.get())
        );
        assert_ne!(
            retry_after_secs(&response),
            1,
            "the one-second clamp is what the floor replaced"
        );
    }

    /// The no-deadline hour is a different answer to a different
    /// question, so the floor does not reach it — asserted under a floor
    /// above the hour, the only configuration in which the two branches
    /// are distinguishable at all.
    #[tokio::test]
    async fn quarantined_without_deadline_uses_default_hour_unfloored() {
        const ABSURD_FLOOR: NonZeroU32 = NonZeroU32::new(2 * 3600).expect("two hours is non-zero");
        assert!(
            i64::from(ABSURD_FLOOR.get()) > DEFAULT_QUARANTINE_RETRY_AFTER_SECS,
            "the premise of this test is a floor above the fallback"
        );
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = None;
        let response = check_quarantine(&artifact, "myrepo", ABSURD_FLOOR);
        assert_eq!(
            retry_after_secs(&response),
            DEFAULT_QUARANTINE_RETRY_AFTER_SECS
        );
    }

    #[tokio::test]
    async fn body_is_oci_envelope_with_unavailable_code() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        let response = check_quarantine(&artifact, "myrepo", TEST_FLOOR);
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        // `detail.retry_after_seconds` echoes the computed delta so
        // the client can cross-check against the header.
        assert!(parsed["errors"][0]["detail"]["retry_after_seconds"].is_i64());
    }

    /// ADR 0039 D5 — the hold whose window has elapsed and which is
    /// still waiting on a signature keeps the 503 and drops the header.
    /// Without this the response advertises the floor on every pull,
    /// forever: the floor is a better number than `1` for a hold that
    /// does resolve itself, and no number at all is right for one that
    /// does not.
    #[tokio::test]
    async fn provenance_held_past_window_is_503_with_no_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        artifact.provenance_hold_indefinite = true;
        let response = check_quarantine(&artifact, "myrepo", TEST_FLOOR);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers().get("Retry-After").is_none(),
            "an unsigned hold past its window has no self-resolving deadline — no Retry-After"
        );
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        // Same message as the time-bounded hold: which hold this is
        // stays opaque to the client.
        assert_eq!(parsed["errors"][0]["message"], "artifact is quarantined");
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    /// The converse: a hold still inside its window has a real deadline,
    /// so its `Retry-After` is correct and useful and must survive.
    #[tokio::test]
    async fn hold_inside_its_window_keeps_its_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(600));
        // The hydration never sets this inside the window; pinned here so
        // the two inputs cannot be conflated into one.
        artifact.provenance_hold_indefinite = false;
        let response = check_quarantine(&artifact, "myrepo", TEST_FLOOR);
        let secs = retry_after_secs(&response);
        assert!(
            (595..=600).contains(&secs),
            "retry-after out of range: {secs}"
        );
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
