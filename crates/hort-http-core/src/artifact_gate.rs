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
//!
//! ## The seconds and the envelope are scoped differently
//!
//! [`non_servable_response`] is the refusal envelope for the four
//! hosted/proxy content routes above. OCI deliberately does not share
//! it: an OCI refusal is an `{"errors":[{"code":…}]}` document defined
//! by another protocol, built in `hort_http_oci::error`.
//!
//! What the two **do** share is [`quarantine_retry_after_seconds`].
//! How long a held artifact tells a client to wait is a property of the
//! hold, not of the protocol carrying the refusal, and the cost of
//! transcribing it twice was measured: a container pull is an OCI
//! request, so the copy that answered the pull was the OCI one, and a
//! correction applied to this file alone would have left it untouched.

use std::num::NonZeroU32;

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
///
/// Deliberately **not** subject to the floor below: the floor corrects a
/// window-derived number that has gone too small, and an hour is never
/// too small. The two branches answer different questions and keep
/// their own reasoning.
pub const DEFAULT_QUARANTINE_RETRY_AFTER_SECS: i64 = 3600;

/// Default floor for the window-derived `Retry-After`, in seconds — what
/// `HORT_QUARANTINE_RETRY_AFTER_FLOOR_SECS` carries when the operator
/// sets nothing.
///
/// **The only definition of this number.** `hort_server::config` parses
/// the env var with `.get()` of this constant as the default, and the
/// mock-context builder seeds the same constant, so a test expectation
/// and a production answer cannot drift apart.
///
/// 20 s is scan-interval-shaped: long enough that a client polling a
/// held artifact costs one request per scan turnaround rather than one
/// per second, short enough that a release landing early is not waited
/// out. An operator whose scanners are slower raises it.
///
/// [`NonZeroU32`] rather than `u32` so "never advertise
/// `Retry-After: 0`" (spec-legal, easy to misparse) is a property of the
/// type instead of a `.max(1)` every consumer has to remember — the same
/// carry as [`crate::middleware::load_shed::ConcurrencyLimitConfig`]'s
/// caps, which hold their non-zero invariant from the env parse to the
/// middleware constructor. The parse rejects `0` with
/// `ConfigError::ValueNotPositive`, and it has to: a zero floor restores
/// exactly the behaviour this constant exists to remove.
pub const DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS: NonZeroU32 =
    NonZeroU32::new(20).expect("20 is non-zero");

/// Seconds to advertise in `Retry-After` for a quarantined artifact, or
/// [`None`] when the hold has no deadline to advertise.
///
/// **The one definition of this computation.** The OCI pull path calls
/// it too (`hort_http_oci::quarantine::check_quarantine`) and wraps only
/// its own protocol envelope around the answer.
///
/// A hold that resolves itself with the passage of time — the artifact's
/// own scan verdict is what is outstanding — answers from its own
/// window, floored at `floor_secs`.
///
/// The floor is the correction for what the subtraction cannot know.
/// `(deadline - now)` measures when the observation **window** ends, and
/// the window ending is not the event the caller is waiting for:
/// `ArtifactReleased` follows the scan verdict. Once the deadline is in
/// the past the subtraction is negative, and the honest answer there is
/// not "immediately" but "about as long as a scan takes" — which is why
/// the floor is an operator knob rather than a constant. A floor only
/// bites when the computed value is below it, so a genuine long window
/// is unaffected.
///
/// A hold waiting on an **external** event, which is what
/// `provenance_hold_indefinite` records, has no deadline at all and
/// therefore advertises none: a floor there would tell a well-behaved
/// client to come back in `floor_secs` seconds, forever (ADR 0039 D5).
/// A floored lie is cheaper than a one-second lie and still a lie, so
/// [`None`] stays [`None`].
pub fn quarantine_retry_after_seconds(artifact: &Artifact, floor_secs: NonZeroU32) -> Option<i64> {
    if artifact.provenance_hold_indefinite {
        return None;
    }
    Some(
        artifact
            .quarantine_deadline
            .map(|deadline| {
                (deadline - Utc::now())
                    .num_seconds()
                    .max(i64::from(floor_secs.get()))
            })
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
///
/// `retry_after_floor_secs` is the operator-configured floor
/// (`AppContext::quarantine_retry_after_floor_secs`,
/// `HORT_QUARANTINE_RETRY_AFTER_FLOOR_SECS`). It arrives as an argument
/// rather than through the context so this function — and the
/// arithmetic behind it — stays a pure function of its inputs, unit
/// testable without a composed application, and so the value a request
/// answers with is the one the composition root wired rather than
/// anything process-global.
pub fn non_servable_response(
    artifact: &Artifact,
    retry_after_floor_secs: NonZeroU32,
) -> Option<Response> {
    match artifact.quarantine_status {
        QuarantineStatus::Quarantined => {
            let mut builder = Response::builder().status(StatusCode::SERVICE_UNAVAILABLE);
            if let Some(secs) = quarantine_retry_after_seconds(artifact, retry_after_floor_secs) {
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

    /// A floor deliberately **not** equal to
    /// [`DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS`]. An expectation
    /// derived from the default cannot tell "the argument is wired" from
    /// "the number is baked into the arithmetic"; this one can.
    const TEST_FLOOR: NonZeroU32 = NonZeroU32::new(45).expect("45 is non-zero");

    /// A `Rejected` artifact whose axis has already been hydrated, as
    /// every production read path hands it to the gate.
    fn rejected_with(axis: Option<RejectionReason>) -> Artifact {
        let mut artifact = sample_artifact(QuarantineStatus::Rejected);
        artifact.rejection_reason = axis;
        artifact
    }

    // -- Quarantined: the Retry-After rule --------------------------------

    /// A window with real time left on it answers its own remaining
    /// delta, and the floor is inert. The window is chosen an order of
    /// magnitude above [`TEST_FLOOR`] so the two answers cannot be
    /// confused: a regression that returned the floor unconditionally
    /// fails the lower bound here.
    #[test]
    fn in_window_hold_keeps_its_computed_retry_after() {
        const WINDOW_SECS: i64 = 600;
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(WINDOW_SECS));
        // The hydration never sets this inside the window; pinned here so
        // the two inputs cannot be conflated into one.
        artifact.provenance_hold_indefinite = false;
        let (status, retry_after, body) =
            parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let secs: i64 = retry_after
            .expect("an in-window hold keeps its computed Retry-After")
            .parse()
            .unwrap();
        // A few seconds of slack for the clock between seeding and the
        // response; the floor is far below the bottom of this range.
        assert!(
            (WINDOW_SECS - 5..=WINDOW_SECS).contains(&secs),
            "retry-after out of range: {secs}"
        );
        assert!(
            secs > i64::from(TEST_FLOOR.get()),
            "a long window must answer its own delta, not the floor: {secs}"
        );
        assert_eq!(body["error"], "artifact is quarantined");
    }

    /// A deadline already in the past answers the **configured floor**.
    ///
    /// What it used to answer was `1`: the subtraction is negative there
    /// and the old clamp lifted it to one second, which a client
    /// honouring `Retry-After` turns into one poll per second for as long
    /// as the artifact's scan verdict takes to land. The window ending is
    /// not what that client is waiting for.
    #[test]
    fn an_elapsed_window_answers_the_configured_floor() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let (_, retry_after, _) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
        let expected = TEST_FLOOR.get().to_string();
        assert_eq!(retry_after.as_deref(), Some(expected.as_str()));
    }

    /// The floor bites inside the window too, whenever what is left of it
    /// is smaller than the floor — the state a zero-duration policy puts
    /// every freshly-ingested artifact in. Nothing about "the window has
    /// elapsed" is load-bearing; "the computed value is below the floor"
    /// is.
    #[test]
    fn a_window_shorter_than_the_floor_answers_the_floor() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() + Duration::seconds(2));
        let (_, retry_after, _) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
        let expected = TEST_FLOOR.get().to_string();
        assert_eq!(retry_after.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn a_hold_with_no_deadline_falls_back_to_the_unknown_hour() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = None;
        let (_, retry_after, _) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
        assert_eq!(
            retry_after.as_deref(),
            Some(DEFAULT_QUARANTINE_RETRY_AFTER_SECS.to_string().as_str())
        );
    }

    /// The floor is not a substitute for the deadline-unknown fallback:
    /// the two answer different questions, so an absent deadline keeps
    /// its hour even under a floor that exceeds it. Asserted with an
    /// absurd floor precisely because that is the only configuration in
    /// which the two branches are distinguishable at all — under any
    /// sane floor the hour is already above it.
    #[test]
    fn an_absent_deadline_is_not_floored() {
        const ABSURD_FLOOR: NonZeroU32 = NonZeroU32::new(2 * 3600).expect("two hours is non-zero");
        assert!(
            i64::from(ABSURD_FLOOR.get()) > DEFAULT_QUARANTINE_RETRY_AFTER_SECS,
            "the premise of this test is a floor above the fallback"
        );
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = None;
        let (_, retry_after, _) = parts(non_servable_response(&artifact, ABSURD_FLOOR).unwrap());
        assert_eq!(
            retry_after.as_deref(),
            Some(DEFAULT_QUARANTINE_RETRY_AFTER_SECS.to_string().as_str()),
            "an unknown deadline answers the hour, floored or not"
        );
    }

    /// The default the operator gets when they set nothing is this
    /// crate's constant and not a second copy of `20` somewhere in the
    /// arithmetic.
    #[test]
    fn the_default_floor_is_what_an_elapsed_window_answers() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        let secs =
            quarantine_retry_after_seconds(&artifact, DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS)
                .expect("a timed hold advertises a deadline");
        assert_eq!(
            secs,
            i64::from(DEFAULT_QUARANTINE_RETRY_AFTER_FLOOR_SECS.get())
        );
        assert_ne!(secs, 1, "the one-second clamp is what this replaced");
    }

    /// ADR 0039 D5 — the hold whose window has elapsed and which is still
    /// waiting on a signature keeps the 503 and drops the header. Without
    /// this the answer is the floor above on every pull, forever: an
    /// external signature is not an event a delta-seconds number can
    /// describe at any value.
    #[test]
    fn a_hold_with_no_self_resolving_deadline_advertises_none() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_deadline = Some(Utc::now() - Duration::seconds(60));
        artifact.provenance_hold_indefinite = true;
        let (status, retry_after, body) =
            parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
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
        let (_, retry_after, _) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
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
            let (status, retry_after, body) =
                parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
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
            let response = non_servable_response(&rejected_with(axis), TEST_FLOOR).unwrap();
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
        let (status, _, body) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
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
        let (status, _, body) = parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
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
        let (status, retry_after, body) =
            parts(non_servable_response(&artifact, TEST_FLOOR).unwrap());
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(retry_after, None);
        assert_eq!(body["error"], "artifact scan is indeterminate");
    }

    #[test]
    fn a_servable_artifact_yields_no_response() {
        for status in [QuarantineStatus::None, QuarantineStatus::Released] {
            assert!(
                non_servable_response(&sample_artifact(status), TEST_FLOOR).is_none(),
                "{status:?} is servable; the caller owns the happy path"
            );
        }
    }
}
