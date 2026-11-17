//! What an OCI read answers when the **download** refuses after the
//! handler's own gate admitted it.
//!
//! Both pull handlers resolve an artifact, run an exhaustive
//! `QuarantineStatus` gate over it, and then hand the id to
//! `ArtifactUseCase::{download, download_range, download_hold_read}`,
//! each of which re-reads the row and re-applies its own gate. So there
//! is a window: a concurrent rescan can flip the row to a terminal state
//! between the handler's read and the use case's, and the use case then
//! refuses with [`DomainError::Forbidden`].
//!
//! The bytes stay withheld either way — the fail-closed half was never in
//! question. What was wrong is everything else about the answer. Every
//! error from those three calls mapped to `500 UNAVAILABLE`, so a caller
//! whose pull hort deliberately withheld was told the server broke; and
//! no [`log_refused_read`] line was emitted, so the module whose whole
//! purpose is the record a refused read leaves had nothing for the one
//! refusal an operator is least able to reconstruct. A rescan reaches
//! this path in normal operation.
//!
//! # The discrimination is on the error, never on a guess
//!
//! Only [`DomainError::Forbidden`] is a refusal. That variant is what
//! both download gates return for a non-servable row and nothing else on
//! these paths produces it; a storage fault arrives as
//! [`AppError::Storage`], a vanished row as
//! [`DomainError::NotFound`], an event-store or policy failure as its
//! own variant. Each of those stays a logged `500`, because answering a
//! real infrastructure failure with a refusal envelope would be a worse
//! bug than the one this closes: it would tell a client "this artifact is
//! withheld" about an artifact hort simply failed to read, and it would
//! bury the failure under an `info!`/`warn!` nobody pages on.
//!
//! # Which envelope, and where it comes from
//!
//! The status the download refused on is not on the error — it is on the
//! row — so the row is **re-read** ([`ArtifactUseCase::get_by_id`]) and
//! the answer comes from its current status. That is a read and not a
//! guess, which is the whole requirement: the alternative shapes are
//! inferring the status from the error's message text, or assuming the
//! likely one, and both state as fact something hort did not look up.
//! `get_by_id` is the right loader for it — it checks no repository
//! visibility because its callers re-read a row they already resolved
//! through a visibility-checked path, which is exactly this situation,
//! and it hydrates the rejection axis the `Rejected` envelope needs.
//! `blobs.rs`'s bounded-await poll loop already re-reads through it into
//! the same handler gate, so this is that established shape and not a
//! new one.
//!
//! The envelope per status is the one **this same route** already sends
//! for that status, and nothing is disclosed beyond it: the `Rejected`
//! `403 DENIED` with its axis, the `Quarantined` `503` with its
//! `Retry-After` (or without, for a hold with no self-resolving
//! deadline), the `ScanIndeterminate` `503` with none. A client meets no
//! shape it does not already know, and learns nothing it would not have
//! learned by arriving one moment later.
//!
//! A re-read that comes back **servable** — a second flip, or a refusal
//! from a gate whose predicate the status alone does not decide — yields
//! no refusal: there is nothing to withhold and the download still
//! failed, so it stays the logged `500`. Same for a re-read that itself
//! fails. Neither invents an answer out of a question hort could not
//! settle.
//!
//! # No download counter here
//!
//! `hort_download_total` for these states belongs to the use case on this
//! path: `ArtifactUseCase::download` already counted the pull before
//! returning the `Forbidden`. The handler-side counter in
//! [`crate::quarantine::check_quarantine`] exists for the *short-circuit*
//! gate, which refuses before the download runs — hence
//! [`crate::quarantine::quarantined_response`], the same envelope without
//! it.

use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::DomainError;
use hort_domain::events::RejectionReason;
use hort_http_core::context::AppContext;

use crate::error::OciError;
use crate::quarantine;
use crate::refusal::{log_refused_read, ReadRoute, RefusalReason, RefusedRead};

/// One failed `download` / `download_range` / `download_hold_read` call,
/// as [`response_for`] needs to see it.
pub(crate) struct FailedDownload<'a> {
    /// What the use case returned.
    pub(crate) error: &'a AppError,
    /// The artifact the handler had already resolved and admitted.
    pub(crate) artifact_id: Uuid,
    /// Which call failed, as a log field — the three are distinguishable
    /// in an operator's log without three message strings.
    pub(crate) operation: &'static str,
    /// The read in hand, for the refusal record.
    pub(crate) refused: &'a RefusedRead<'a>,
}

/// The response an OCI read owes its caller when the download failed.
///
/// A refusal is answered in the status's own envelope and recorded
/// through [`log_refused_read`]; anything else is an `error!` and
/// `500`. See the module doc for why the two are told apart on the
/// error and not on the row.
pub(crate) async fn response_for(ctx: &Arc<AppContext>, failed: &FailedDownload<'_>) -> Response {
    if matches!(failed.error, AppError::Domain(DomainError::Forbidden(_))) {
        if let Some(response) = refusal_response(ctx, failed).await {
            return response;
        }
    }
    tracing::error!(
        artifact_id = %failed.artifact_id,
        operation = failed.operation,
        error = %failed.error,
        "OCI read: the CAS download failed after the artifact was resolved and admitted"
    );
    OciError::Internal.into_response()
}

/// Re-read the row and build the refusal its current status owes, or
/// [`None`] when there is no refusal to answer.
async fn refusal_response(ctx: &Arc<AppContext>, failed: &FailedDownload<'_>) -> Option<Response> {
    let artifact = match ctx.artifact_use_case.get_by_id(failed.artifact_id).await {
        Ok(a) => a,
        Err(e) => {
            // Reported here rather than swallowed, because the caller's
            // own `error!` names the download failure and not this one.
            tracing::warn!(
                artifact_id = %failed.artifact_id,
                operation = failed.operation,
                error = %e,
                "OCI read: the download refused this artifact, but re-reading its status \
                 failed, so the refusal cannot be answered in that status's own envelope"
            );
            return None;
        }
    };

    // Exhaustive with no wildcard arm, so a sixth `QuarantineStatus`
    // variant is a compile error here rather than a refusal silently
    // reported as a server fault.
    let (response, reason) = match artifact.quarantine_status {
        QuarantineStatus::Quarantined => (
            quarantine::quarantined_response(&artifact, ctx.quarantine_retry_after_floor_secs),
            RefusalReason::hold(&artifact),
        ),
        QuarantineStatus::Rejected => {
            // The axis is a plain field: `ArtifactUseCase` derives it
            // from the artifact's own `ArtifactRejected` event during the
            // load, because the `artifacts` projection carries no such
            // column and a format crate must not read a stream
            // (ADR 0008).
            let axis = artifact
                .rejection_reason
                .as_ref()
                .map(RejectionReason::wire_kind);
            if axis.is_none() {
                // Never an `unknown` token, which would make an
                // inconsistency look like a verdict. `Rejected` with no
                // rejection on the record is the illegal state ADR 0039
                // D6 names, and the use-case layer tells its two causes
                // apart in its own log.
                tracing::error!(
                    artifact_id = %artifact.id,
                    operation = failed.operation,
                    "refusing a Rejected artifact with no rejection axis to report"
                );
            }
            (
                OciError::ArtifactRejected {
                    subject: refusal_subject(failed.refused),
                    axis,
                }
                .into_response(),
                RefusalReason::Rejected,
            )
        }
        QuarantineStatus::ScanIndeterminate => (
            quarantine::check_scan_indeterminate(),
            RefusalReason::ScanIndeterminate,
        ),
        // Servable now: a second flip, or a download gate that refused on
        // something the status does not decide. Nothing is being
        // withheld, so there is no refusal to answer or to record.
        QuarantineStatus::None | QuarantineStatus::Released => return None,
    };
    log_refused_read(&response, failed.refused, &reason);
    Some(response)
}

/// What the `Rejected` envelope names as its `subject`, per route — the
/// same value that route's own `Rejected` gate arm names, so one state
/// has one answer however it was reached.
///
/// The manifest route names the client's reference: a tag is what the
/// caller asked for and what their own report will quote. The blob route
/// re-renders the resolved digest rather than echoing, which is also
/// what its gate arm does.
fn refusal_subject(read: &RefusedRead<'_>) -> String {
    match read.route {
        ReadRoute::Manifest => read.reference.to_string(),
        ReadRoute::Blob => format!("sha256:{}", read.digest.as_ref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use chrono::{Duration, Utc};
    use hort_app::use_cases::test_support::{persisted_artifact_rejected, sample_artifact};
    use hort_domain::entities::artifact::Artifact;
    use hort_domain::error::DomainError;
    use hort_domain::events::StreamId;
    use hort_domain::types::ContentHash;
    use hort_http_core::test_support::{build_mock_ctx, MockPorts};
    use metrics_exporter_prometheus::PrometheusBuilder;

    use crate::refusal::{assert_no_refusal_line, assert_refusal_line, ExpectedRefusal};
    use crate::test_tracing::{capture_tracing, CapturedEvent};

    const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// What one [`response_for`] call produced, drained so the assertions
    /// read as statements about the answer rather than about a `Response`.
    struct Answered {
        status: StatusCode,
        advertises_a_deadline: bool,
        envelope: serde_json::Value,
        events: Vec<CapturedEvent>,
    }

    impl Answered {
        /// Whether any captured event carries `needle`.
        fn mentions(&self, needle: &str) -> bool {
            self.events.iter().any(|e| e.fields.contains(needle))
        }
    }

    /// Seed one row at [`DIGEST_HEX`] carrying `status` — the state a
    /// concurrent rescan left behind for the download's own re-read to
    /// find — and return it.
    fn seed_row(mocks: &MockPorts, status: QuarantineStatus) -> Artifact {
        let mut artifact = sample_artifact(status);
        artifact.sha256_checksum = DIGEST_HEX.parse().expect("valid sha256");
        if status == QuarantineStatus::Quarantined {
            // A hold only has a deadline to advertise once its window is
            // anchored; the hydration computes the rest.
            artifact.quarantine_window_start = Some(Utc::now() - Duration::seconds(30));
        }
        mocks.artifacts.insert(artifact.clone());
        artifact
    }

    /// Put an `ArtifactRejected` on the row's own stream, so the axis the
    /// refusal reports is hydrated from the record rather than stamped on
    /// a fixture. An empty stream is the ADR 0039 D6 illegal state.
    fn seed_axis(mocks: &MockPorts, artifact_id: Uuid, axis: Option<RejectionReason>) {
        mocks.events.set_stream(
            &StreamId::artifact(artifact_id),
            axis.map(|reason| vec![persisted_artifact_rejected(artifact_id, reason, 1)])
                .unwrap_or_default(),
        );
    }

    /// Drive [`response_for`] on `route` for `error`, with `seed`
    /// populating the harness and naming the artifact the download
    /// failed on.
    ///
    /// Everything runs inside one runtime and one tracing capture: the
    /// mock context needs a reactor to build, and the response body has
    /// to be drained before the runtime goes away.
    fn answer<S>(route: ReadRoute, error: &AppError, seed: S) -> Answered
    where
        S: FnOnce(&MockPorts) -> Uuid,
    {
        let digest: ContentHash = DIGEST_HEX.parse().expect("valid sha256");
        let reference = match route {
            ReadRoute::Manifest => "1.21".to_string(),
            ReadRoute::Blob => format!("sha256:{DIGEST_HEX}"),
        };
        let (status, advertises_a_deadline, envelope, events) = {
            let mut captured = Vec::new();
            let (parts, events) = capture_tracing(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime")
                    .block_on(async {
                        let (base, mocks) =
                            build_mock_ctx(PrometheusBuilder::new().build_recorder().handle());
                        // The hydrating context, so a `Rejected` row's
                        // axis is recovered from its own stream rather
                        // than read off a field a harness stamped — the
                        // same wiring the handler suites opt into.
                        let ctx =
                            hort_http_core::test_support::with_provenance_hold_hydration(&base);
                        let artifact_id = seed(&mocks);
                        let response = response_for(
                            &ctx,
                            &FailedDownload {
                                error,
                                artifact_id,
                                operation: "test_download",
                                refused: &RefusedRead {
                                    route,
                                    repo_key: "myrepo",
                                    name: "library/nginx",
                                    reference: &reference,
                                    digest: &digest,
                                },
                            },
                        )
                        .await;
                        let status = response.status();
                        let advertises_a_deadline = response
                            .headers()
                            .contains_key(axum::http::header::RETRY_AFTER);
                        let bytes = to_bytes(response.into_body(), 4 * 1024)
                            .await
                            .expect("a bounded error body");
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&bytes).expect("an OCI error envelope");
                        (status, advertises_a_deadline, parsed["errors"][0].clone())
                    })
            });
            captured.extend(events);
            (parts.0, parts.1, parts.2, captured)
        };
        Answered {
            status,
            advertises_a_deadline,
            envelope,
            events,
        }
    }

    fn forbidden() -> AppError {
        AppError::Domain(DomainError::Forbidden("not downloadable".into()))
    }

    const DOWNLOAD_FAILED: &str = "the CAS download failed after the artifact was resolved";
    const RE_READ_FAILED: &str = "re-reading its status failed";

    // -- the discrimination ----------------------------------------------

    /// **Acceptance: a real infrastructure failure is still a `500` and
    /// still an `error!`.** `AppError::Storage` is what the download
    /// returns when the CAS read itself failed — nothing about the
    /// artifact was decided, so answering a refusal envelope would tell
    /// the client "this artifact is withheld" about one hort merely
    /// failed to read, and would bury the failure under a line nobody
    /// pages on.
    ///
    /// The absence of the re-read `warn!` is the load-bearing half: the
    /// row is seeded `Rejected`, which is exactly the state that WOULD
    /// produce a refusal, so a discrimination made on the row rather
    /// than on the error fails here.
    #[test]
    fn a_storage_failure_answers_500_and_logs_an_error_without_re_reading_the_row() {
        let out = answer(
            ReadRoute::Blob,
            &AppError::Storage("backend unreachable".into()),
            |mocks| seed_row(mocks, QuarantineStatus::Rejected).id,
        );
        assert_eq!(out.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            out.mentions(DOWNLOAD_FAILED),
            "the failure is reported at error level: {:?}",
            out.events
        );
        assert!(
            !out.mentions(RE_READ_FAILED),
            "a non-refusal must not reach the re-read at all: {:?}",
            out.events
        );
        assert_no_refusal_line(&out.events);
    }

    /// And the other non-`Forbidden` shapes, so the rule is not satisfied
    /// by "anything that is not a storage error".
    #[test]
    fn other_errors_are_not_refusals_either() {
        for error in [
            AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                id: "gone".into(),
            }),
            AppError::Domain(DomainError::Invariant("broken".into())),
            AppError::Repository("pool exhausted".into()),
        ] {
            let label = error.to_string();
            let out = answer(ReadRoute::Blob, &error, |mocks| {
                seed_row(mocks, QuarantineStatus::Rejected).id
            });
            assert_eq!(
                out.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{label} must stay a 500"
            );
            assert_no_refusal_line(&out.events);
        }
    }

    // -- the envelopes ---------------------------------------------------

    /// **Acceptance: a mid-read flip to `Rejected` answers that status's
    /// own envelope and is recorded.** `403 DENIED`, the axis recovered
    /// from the row's own stream, one `rejected` refusal line.
    #[test]
    fn a_forbidden_on_a_rejected_row_answers_403_with_its_axis_and_records_it() {
        let out = answer(ReadRoute::Manifest, &forbidden(), |mocks| {
            let artifact = seed_row(mocks, QuarantineStatus::Rejected);
            seed_axis(mocks, artifact.id, Some(RejectionReason::Scanner));
            artifact.id
        });
        assert_eq!(out.status, StatusCode::FORBIDDEN);
        assert_refusal_line(
            &out.events,
            &ExpectedRefusal {
                level: tracing::Level::WARN,
                route: "manifest",
                repository: "myrepo",
                name: "library/nginx",
                reference: "1.21",
                digest: DIGEST_HEX,
                status: 403,
                reason: "rejected",
            },
        );
        assert_eq!(out.envelope["code"], "DENIED");
        assert_eq!(
            out.envelope["detail"]["subject"], "1.21",
            "the manifest route names the client's own reference"
        );
        assert_eq!(
            out.envelope["detail"]["axis"], "scanner",
            "and the axis comes from the stream this test seeded"
        );
    }

    /// The blob route names the resolved digest instead — the same value
    /// its own `Rejected` gate arm names, so one state has one answer
    /// however it was reached.
    #[test]
    fn the_blob_route_names_the_resolved_digest_as_the_subject() {
        let out = answer(ReadRoute::Blob, &forbidden(), |mocks| {
            let artifact = seed_row(mocks, QuarantineStatus::Rejected);
            seed_axis(mocks, artifact.id, Some(RejectionReason::Scanner));
            artifact.id
        });
        assert_eq!(
            out.envelope["detail"]["subject"],
            format!("sha256:{DIGEST_HEX}")
        );
    }

    /// A `Rejected` row with no `ArtifactRejected` behind it is the
    /// illegal state ADR 0039 D6 names. The refusal stands and names the
    /// subject; the axis field is **absent** rather than an `unknown`
    /// token, and the operator is told.
    #[test]
    fn a_rejected_row_with_no_axis_still_refuses_and_emits_no_axis_token() {
        let out = answer(ReadRoute::Blob, &forbidden(), |mocks| {
            let artifact = seed_row(mocks, QuarantineStatus::Rejected);
            seed_axis(mocks, artifact.id, None);
            artifact.id
        });
        assert_eq!(out.status, StatusCode::FORBIDDEN);
        assert!(
            out.mentions("no rejection axis to report"),
            "the illegal state is reported: {:?}",
            out.events
        );
        assert!(
            out.envelope["detail"]["axis"].is_null(),
            "no axis field at all, and never an `unknown` token: {}",
            out.envelope
        );
        assert_eq!(
            out.envelope["detail"]["subject"],
            format!("sha256:{DIGEST_HEX}")
        );
    }

    /// A flip to a **hold** answers the hold's envelope with its
    /// `Retry-After`, at `info!` — the level criterion is the refusal
    /// module's and is not re-decided here.
    #[test]
    fn a_forbidden_on_a_quarantined_row_answers_503_with_a_retry_after() {
        let out = answer(ReadRoute::Blob, &forbidden(), |mocks| {
            seed_row(mocks, QuarantineStatus::Quarantined).id
        });
        assert_eq!(out.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            out.advertises_a_deadline,
            "a timed hold advertises its deadline"
        );
        assert_refusal_line(
            &out.events,
            &ExpectedRefusal {
                level: tracing::Level::INFO,
                route: "blob",
                repository: "myrepo",
                name: "library/nginx",
                reference: &format!("sha256:{DIGEST_HEX}"),
                digest: DIGEST_HEX,
                status: 503,
                reason: "quarantined",
            },
        );
    }

    /// A flip to `ScanIndeterminate` answers `503` with **no**
    /// `Retry-After`: that hold has no self-resolving deadline.
    #[test]
    fn a_forbidden_on_an_indeterminate_row_answers_503_without_a_retry_after() {
        let out = answer(ReadRoute::Blob, &forbidden(), |mocks| {
            seed_row(mocks, QuarantineStatus::ScanIndeterminate).id
        });
        assert_eq!(out.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !out.advertises_a_deadline,
            "an indeterminate verdict has no deadline to advertise"
        );
        assert_refusal_line(
            &out.events,
            &ExpectedRefusal {
                level: tracing::Level::WARN,
                route: "blob",
                repository: "myrepo",
                name: "library/nginx",
                reference: &format!("sha256:{DIGEST_HEX}"),
                digest: DIGEST_HEX,
                status: 503,
                reason: "scan_indeterminate",
            },
        );
    }

    // -- the two no-answer cases -----------------------------------------

    /// A `Forbidden` over a row that is servable again: nothing is being
    /// withheld, so there is no refusal to answer or to record — and the
    /// download still failed, so the logged `500` stands.
    #[test]
    fn a_forbidden_on_a_servable_row_stays_a_logged_500_and_records_nothing() {
        for status in [QuarantineStatus::None, QuarantineStatus::Released] {
            let out = answer(ReadRoute::Blob, &forbidden(), |mocks| {
                seed_row(mocks, status).id
            });
            assert_eq!(
                out.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{status}: nothing is withheld, so no refusal is invented"
            );
            assert!(out.mentions(DOWNLOAD_FAILED), "{status}");
            assert_no_refusal_line(&out.events);
        }
    }

    /// A re-read that itself fails yields no envelope either: the status
    /// a refusal would answer in is exactly what could not be
    /// established. Reported at `warn!` in its own right, because the
    /// caller's `error!` names a different failure.
    #[test]
    fn a_forbidden_whose_re_read_fails_stays_a_logged_500() {
        // No row seeded at all, so the re-read answers `NotFound`.
        let out = answer(ReadRoute::Blob, &forbidden(), |_| Uuid::new_v4());
        assert_eq!(out.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            out.mentions(RE_READ_FAILED),
            "the failed re-read is reported in its own right: {:?}",
            out.events
        );
        assert!(out.mentions(DOWNLOAD_FAILED));
        assert_no_refusal_line(&out.events);
    }

    /// The subject mapping, pinned per route against the gate arms it
    /// mirrors. A regression that collapsed the two would make one route
    /// name the other's value.
    #[test]
    fn the_refusal_subject_is_the_routes_own() {
        let digest: ContentHash = DIGEST_HEX.parse().expect("valid sha256");
        let read = |route| RefusedRead {
            route,
            repo_key: "myrepo",
            name: "library/nginx",
            reference: "1.21",
            digest: &digest,
        };
        assert_eq!(refusal_subject(&read(ReadRoute::Manifest)), "1.21");
        assert_eq!(
            refusal_subject(&read(ReadRoute::Blob)),
            format!("sha256:{DIGEST_HEX}")
        );
    }
}
