//! The per-artifact status gate every non-OCI content route shares.
//!
//! A download handler that has already resolved an [`Artifact`] still has
//! to decide whether the bytes may be served, and what to answer when
//! they may not. That decision is a property of the artifact's
//! [`QuarantineStatus`], not of the format, and
//! [`non_servable_response`] is its single definition for the
//! cargo / npm / PyPI / Maven content routes — each of which previously
//! carried its own transcription of it.
//!
//! One definition matters here for a reason the duplicates demonstrated:
//! ADR 0039 D5 (a hold with no self-resolving deadline advertises no
//! deadline) was implemented once, at one call site, and the four copies
//! kept on promising a `Retry-After` to a client that could never
//! usefully use it. A rule that has to be re-typed per format is a rule
//! that will be re-typed wrong.
//!
//! ## What this module does NOT do
//!
//! - It never consults the caller. The gate is a function of the
//!   artifact's state alone, so a held artifact is withheld from every
//!   principal identically — the read-gate decision (who may see this
//!   repository at all) has already been made upstream, and a
//!   write-granted publisher is no more entitled to held bytes than an
//!   anonymous puller.
//! - It computes neither the quarantine deadline nor the indefinite-hold
//!   flag. Both are transient fields the use-case layer hydrates on every
//!   read path; resolving a `ScanPolicy` or reading the artifact's event
//!   stream from an inbound-HTTP crate would reach past the use case
//!   (ADR 0008).
//! - It builds no response for `None` / `Released`. Those return
//!   [`None`] and the caller continues to its own happy path.

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use chrono::Utc;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::events::RejectionReason;

/// `Retry-After` for a `Quarantined` artifact whose computed
/// `quarantine_deadline` is absent — 1 hour, the value every one of the
/// four routes open-coded before this module existed.
///
/// This is a "the deadline is genuinely unknown" constant rather than a
/// guess at the window, and it is unrelated to any configured
/// `quarantineDuration`. Every read path that resolves an artifact
/// hydrates the deadline, so the one state that reaches it is a
/// `Quarantined` row carrying no `quarantine_window_start`: the schema
/// permits it (the column is nullable and no CHECK ties it to the status)
/// and such a row is outside the release sweep's candidacy filter
/// (`quarantine_window_start IS NOT NULL`) as well, so "unknown" is the
/// honest answer rather than a computed one.
const DEFAULT_QUARANTINE_RETRY_AFTER_SECS: i64 = 3600;

/// Seconds to advertise in `Retry-After` for a quarantined artifact, or
/// [`None`] when the hold has no deadline to advertise.
///
/// A hold that resolves itself with the passage of time — the artifact's
/// own scan verdict is what is outstanding — answers from its own window,
/// clamped to `>= 1` so a client never gets `Retry-After: 0` (spec-legal
/// but easy to misparse). A hold waiting on an **external** event, which
/// is what `provenance_hold_indefinite` records, has no such deadline and
/// therefore advertises none: the clamp would otherwise tell a
/// well-behaved client to come back one second later, forever (ADR 0039
/// D5).
fn quarantine_retry_after_seconds(artifact: &Artifact) -> Option<i64> {
    if artifact.provenance_hold_indefinite {
        return None;
    }
    Some(
        artifact
            .quarantine_deadline
            .map(|deadline| (deadline - Utc::now()).num_seconds().max(1))
            .unwrap_or(DEFAULT_QUARANTINE_RETRY_AFTER_SECS),
    )
}

/// Build the `403` body for a `Rejected` artifact, naming the axis it was
/// condemned on.
///
/// The axis token comes from [`RejectionReason::wire_kind`] and from
/// nowhere else — no second mapping and no string literal here — so an
/// eighth variant is a compile error at `wire_kind`'s exhaustive match
/// rather than a stale answer on the wire.
///
/// What the body deliberately does NOT carry: no `curator_id` and no
/// `rule_id` (an actor and a rule are not a diagnosis of an artifact), no
/// policy, no findings and no CVE identifiers. Axis is what ends the
/// consumer's search; the next action — ask the operator — is the same
/// either way.
///
/// An absent axis emits **no** `axis` field, and never an `unknown`
/// token: a token would dress an inconsistency up as a verdict and
/// clients would key on it. The operator is told instead, because a
/// `Rejected` projection with no `ArtifactRejected` behind it on the
/// stream is the illegal state ADR 0039 D6 names. That line is a correct
/// detector only because every read path hydrates the axis before the
/// artifact reaches here: an un-hydrated `None` would say nothing about
/// the stream and would fire on every healthy rejection.
fn rejected_response(artifact: &Artifact) -> Response {
    let axis = artifact
        .rejection_reason
        .as_ref()
        .map(RejectionReason::wire_kind);
    let body = match axis {
        Some(axis) => serde_json::json!({"error": "artifact is rejected", "axis": axis}),
        None => {
            tracing::error!(
                artifact_id = %artifact.id,
                "refusing a Rejected artifact with no rejection axis to report"
            );
            serde_json::json!({"error": "artifact is rejected"})
        }
    };
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(body.to_string()))
        .expect("static-shape rejected response always builds")
}

/// Surface the per-artifact status gate as the HTTP response a content
/// route owes a caller, or [`None`] when the artifact is servable.
///
/// - `Quarantined` → `503` plus `Retry-After`, except for a hold with no
///   self-resolving deadline (see [`quarantine_retry_after_seconds`]).
///   The body is identical either way: which of the two holds this is
///   stays opaque to the client, and the absence of the header is the
///   only difference on the wire.
/// - `Rejected` → `403` naming the rejection axis (see
///   [`rejected_response`]).
/// - `ScanIndeterminate` → `403`. The scanner could not decide, so this
///   is fail-closed and terminal like `Rejected` rather than a timed
///   hold: no window applies and therefore no `Retry-After`.
/// - `None` / `Released` → [`None`]; the caller serves the bytes.
///
/// The `match` is exhaustive with **no wildcard arm**, so a future
/// [`QuarantineStatus`] variant is a compile error here rather than a
/// fall-through that serves withheld bytes.
pub fn non_servable_response(artifact: &Artifact) -> Option<Response> {
    match artifact.quarantine_status {
        QuarantineStatus::Quarantined => {
            let mut builder = Response::builder().status(StatusCode::SERVICE_UNAVAILABLE);
            if let Some(secs) = quarantine_retry_after_seconds(artifact) {
                builder = builder.header("Retry-After", secs.to_string());
            }
            Some(
                builder
                    .body(Body::from(
                        serde_json::json!({"error": "artifact is quarantined"}).to_string(),
                    ))
                    .expect("static-shape quarantined response always builds"),
            )
        }
        QuarantineStatus::Rejected => Some(rejected_response(artifact)),
        QuarantineStatus::ScanIndeterminate => Some(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    serde_json::json!({"error": "artifact scan is indeterminate"}).to_string(),
                ))
                .expect("static-shape scan-indeterminate response always builds"),
        ),
        QuarantineStatus::None | QuarantineStatus::Released => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use chrono::Duration;
    use hort_app::use_cases::test_support::sample_artifact;
    use tracing_test::traced_test;

    /// Drain a gate response into `(status, retry_after, parsed body)`.
    fn parts(response: Response) -> (StatusCode, Option<String>, serde_json::Value) {
        let status = response.status();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .map(|v| v.to_str().unwrap().to_string());
        let body = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { to_bytes(response.into_body(), 4 * 1024).await.unwrap() });
        (status, retry_after, serde_json::from_slice(&body).unwrap())
    }

    /// A `Rejected` artifact whose axis has already been hydrated, as
    /// every production read path hands it to the gate.
    fn rejected_with(axis: Option<RejectionReason>) -> Artifact {
        let mut artifact = sample_artifact(QuarantineStatus::Rejected);
        artifact.rejection_reason = axis;
        artifact
    }

    // -- Quarantined: the Retry-After rule --------------------------------

    #[test]
    fn in_window_hold_keeps_its_computed_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        // The hydration never sets this inside the window; pinned here so
        // the two inputs cannot be conflated into one.
        artifact.provenance_hold_indefinite = false;
        let (status, retry_after, body) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let secs: i64 = retry_after
            .expect("an in-window hold keeps its computed Retry-After")
            .parse()
            .unwrap();
        assert!((1..=60).contains(&secs), "retry-after out of range: {secs}");
        assert_eq!(body["error"], "artifact is quarantined");
    }

    #[test]
    fn elapsed_window_clamps_to_one_second() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let (_, retry_after, _) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(retry_after.as_deref(), Some("1"));
    }

    #[test]
    fn a_hold_with_no_deadline_falls_back_to_the_unknown_hour() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = None;
        let (_, retry_after, _) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(
            retry_after.as_deref(),
            Some(DEFAULT_QUARANTINE_RETRY_AFTER_SECS.to_string().as_str())
        );
    }

    /// ADR 0039 D5 — the hold whose window has elapsed and which is still
    /// waiting on a signature keeps the 503 and drops the header. Without
    /// this the answer is `Retry-After: 1` on every pull, forever (the
    /// clamp above).
    #[test]
    fn a_hold_with_no_self_resolving_deadline_advertises_none() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        artifact.provenance_hold_indefinite = true;
        let (status, retry_after, body) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            retry_after, None,
            "an unsigned hold past its window has no self-resolving deadline"
        );
        // Same body as the time-bounded hold: which hold this is stays
        // opaque to the client.
        assert_eq!(body["error"], "artifact is quarantined");
    }

    /// The flag suppresses the header even when the deadline still reads
    /// as future — the two inputs are independent, and the hydration
    /// owns which of them is set.
    #[test]
    fn the_flag_suppresses_the_header_regardless_of_the_deadline() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(60));
        artifact.provenance_hold_indefinite = true;
        let (_, retry_after, _) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(retry_after, None);
    }

    // -- Rejected: the axis ------------------------------------------------

    /// **Every** [`RejectionReason`] variant reaches the wire as its own
    /// `wire_kind()` token, iterated off
    /// [`RejectionReason::ALL_KIND_SAMPLES`] rather than a hand-written
    /// list — so a variant added tomorrow is covered the moment it joins
    /// that constant, and cannot reach a client undecided.
    #[test]
    fn every_rejection_reason_variant_reaches_the_wire_as_its_wire_kind() {
        assert_eq!(
            RejectionReason::ALL_KIND_SAMPLES.len(),
            7,
            "the corpus is the vocabulary; a drop to zero would make this loop vacuous"
        );
        for sample in RejectionReason::ALL_KIND_SAMPLES {
            let artifact = rejected_with(Some(sample.clone()));
            let (status, retry_after, body) = parts(non_servable_response(&artifact).unwrap());
            assert_eq!(status, StatusCode::FORBIDDEN, "{sample:?}");
            assert_eq!(retry_after, None, "a rejection is terminal: {sample:?}");
            assert_eq!(body["error"], "artifact is rejected");
            assert_eq!(
                body["axis"],
                sample.wire_kind(),
                "axis for {sample:?} must be its wire_kind()"
            );
        }
    }

    /// The refusal is a diagnosis of an artifact, not a disclosure about
    /// a person, a rule, or a weakness. Asserted over every variant,
    /// which is what makes it meaningful: `Curator { curator_id }` and
    /// `CurationRetroactive { rule_id }` are the two that carry a uuid,
    /// so a body built from the payload rather than the discriminator
    /// would leak here and nowhere else.
    #[tokio::test]
    async fn no_refusal_body_carries_a_uuid_or_a_cve_identifier() {
        crate::test_support::assert_refusal_leaks_no_uuid_or_cve(|axis| async move {
            let response = non_servable_response(&rejected_with(axis)).unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        })
        .await;
    }

    /// ADR 0039 D6's illegal state: the projection says `Rejected` and no
    /// `ArtifactRejected` stands behind it on the stream. The caller is
    /// still refused — but no axis field is emitted and no `unknown`
    /// token is invented, because a token would make an inconsistency
    /// read as a verdict. The operator is told instead, at `error` level;
    /// this is the one place that line is asserted, because it is the one
    /// place it is written.
    #[traced_test]
    #[test]
    fn an_unrecoverable_axis_emits_no_field_and_tells_the_operator() {
        let artifact = rejected_with(None);
        let (status, _, body) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "artifact is rejected");
        assert!(
            body.get("axis").is_none(),
            "an unrecoverable axis emits no axis field: {body}"
        );
        logs_assert(|lines: &[&str]| {
            let hits = lines
                .iter()
                .filter(|l| {
                    l.contains("ERROR")
                        && l.contains("refusing a Rejected artifact with no rejection axis")
                })
                .count();
            if hits == 1 {
                Ok(())
            } else {
                Err(format!(
                    "expected exactly one ERROR line, got {hits}: {lines:?}"
                ))
            }
        });
    }

    /// The converse of the line above: a recoverable axis is not an
    /// incident, so nothing is logged at `error`. Without this the
    /// detector could be made green by logging unconditionally.
    #[traced_test]
    #[test]
    fn a_recoverable_axis_raises_no_alarm() {
        let artifact = rejected_with(Some(RejectionReason::Scanner));
        let (status, _, body) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["axis"], "scanner");
        logs_assert(
            |lines: &[&str]| match lines.iter().filter(|l| l.contains("ERROR")).count() {
                0 => Ok(()),
                n => Err(format!(
                    "a healthy rejection logged {n} ERROR lines: {lines:?}"
                )),
            },
        );
    }

    // -- the remaining statuses -------------------------------------------

    #[test]
    fn scan_indeterminate_is_terminal_and_carries_no_retry_after() {
        let artifact = sample_artifact(QuarantineStatus::ScanIndeterminate);
        let (status, retry_after, body) = parts(non_servable_response(&artifact).unwrap());
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(retry_after, None);
        assert_eq!(body["error"], "artifact scan is indeterminate");
    }

    #[test]
    fn a_servable_artifact_yields_no_response() {
        for status in [QuarantineStatus::None, QuarantineStatus::Released] {
            assert!(
                non_servable_response(&sample_artifact(status)).is_none(),
                "{status:?} is servable; the caller owns the happy path"
            );
        }
    }
}
