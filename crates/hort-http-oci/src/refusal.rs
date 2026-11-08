//! The record a refused hosted OCI read leaves.
//!
//! A **served** read is already durably audited: both pull handlers reach
//! [`hort_app::use_cases::artifact_use_case::ArtifactUseCase::download`] on
//! their happy path, which appends an `ArtifactDownloaded` event to the
//! artifact's download-audit stream. A **refused** read reaches neither —
//! the withholding gate runs before the download, so the `503`, the `403`
//! and the indefinite hold used to leave nothing behind at all. Success was
//! reconstructable and refusal was not, and refusal is the case an operator
//! is asked to explain (the incident behind this was one deploy tool
//! retrying a withheld pull 21 times in two minutes, with nothing in the
//! registry's own record to show it).
//!
//! ## A log line and not an event — decided, with the reason
//!
//! The volume on this path is set by **someone else**: a served download is
//! bounded by how many artifacts exist, a refusal by whoever is retrying. A
//! volume another party controls does not belong in the event store, which
//! is durable, replicated and retention-governed. Secondarily, a refused
//! read changes no artifact state, and the event vocabulary is the artifact
//! lifecycle. So there is no `DomainEvent` variant for this and nothing is
//! added to the download-audit stream.
//!
//! ## One level decision, over one criterion: does waiting fix it?
//!
//! - A hold with a deadline is the registry working as designed. Every cold
//!   pull of a freshly-ingested artifact answers one while the scan runs,
//!   the response carries a `Retry-After`, and a well-behaved client comes
//!   back and succeeds. At `warn!` that would make the warn stream
//!   routinely non-empty, which makes it a stream nobody reads. → `info!`.
//! - A rejection, an indeterminate verdict, and a hold waiting on an
//!   external signature are refusals no amount of retrying resolves. They
//!   carry no `Retry-After` because there is no deadline to advertise, and
//!   they end only when an operator waives, re-scans, signs or replaces the
//!   artifact — until then the client is stuck. → `warn!`.
//!
//! That criterion is visible on the wire, because a refusal that advertises
//! a `Retry-After` is exactly one that resolves itself, and
//! `refusal_level_agrees_with_retry_after` holds the two together. So a
//! further reason cannot be given a level that disagrees with what the
//! client was told, and the level stays one decision made in one place
//! rather than a choice re-made at each exit.
//!
//! ## Scope
//!
//! The exits that call this are the ones where hort holds the bytes and
//! withholds them. Two gates refuse that way, and both record it: the
//! exhaustive `QuarantineStatus` gate in `manifests::serve` and
//! `blobs::serve`, which withholds on the artifact's **own** state, and
//! `manifests::terminal_constituent_response`, which withholds a
//! perfectly good manifest because something in its closure carries a
//! terminal verdict (ADR 0062).
//!
//! That second one is recorded twice over, deliberately, and the two
//! records are not one incident counted twice — they have disjoint field
//! sets because they are about different things. The **decision** is
//! logged by `hort_app::use_cases::manifest_deliverability`, at the
//! single place it is made, naming the manifest hash, the offending
//! constituent, its verdict and the size of the closure; it is given a
//! repository id and a manifest hash and nothing else, so it cannot name
//! the image the client asked for. This line records **what the client
//! was told**: the repository key, the OCI name, the client's reference
//! and the status. And of every refusal on these routes it is the one
//! whose cause is least obvious — the image named in the request is
//! fine, and an artifact the client never named is what withheld it —
//! which is exactly why the line that names the image is worth more
//! here, not less.
//!
//! Two neighbouring refusal classes deliberately get no line, because
//! neither is a withheld read:
//!
//! - A malformed digest, tag, name or `Range` is a request hort could not
//!   parse; the response is the whole diagnosis, and these paths refuse to
//!   echo the offending bytes on purpose (log-injection defence, see
//!   `name::validate_oci_name`). Nothing was withheld.
//! - An internal failure, a failed upstream fetch and a negotiation `406`
//!   each already log at the point of failure, with the error in hand.
//!   This covers both `500`s beside the constituent refusal above — a
//!   closure that could not be resolved, and a constituent the port
//!   reported as terminal that is not one. Each fails closed on a
//!   question it could not answer rather than withholding a decided
//!   artifact, and each already `error!`s with what it could not resolve.

use axum::response::Response;

use hort_domain::entities::artifact::Artifact;
use hort_domain::types::ContentHash;

/// Which hosted read route refused.
///
/// A field on the line rather than the event target: one module serves
/// both routes, so `module_path!()` would say `refusal` for every line and
/// an operator could not filter a manifest refusal from a blob refusal.
pub(crate) enum ReadRoute {
    Manifest,
    Blob,
}

impl ReadRoute {
    fn token(&self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Blob => "blob",
        }
    }
}

/// Which read was refused.
///
/// `reference` is what the client asked for and `digest` what it resolved
/// to. Both are carried because they are the join between two records: a
/// client's report names the reference it used (a tag, on the manifest
/// route), while hort's own adjacent refusal line — the
/// `manifest_deliverability` one above — names the bare content hash. On
/// the blob route and on a digest-addressed manifest pull the two coincide,
/// which costs one repeated field and keeps the field set uniform across
/// every exit.
///
/// `digest` is not optional: every exit that logs here sits **after**
/// reference resolution and artifact lookup, so the resolved hash is always
/// in hand.
pub(crate) struct RefusedRead<'a> {
    pub(crate) route: ReadRoute,
    /// The client-supplied repository key, the same label the
    /// `hort_download_total{result="quarantined"}` counter carries.
    pub(crate) repo_key: &'a str,
    /// The OCI name within that key. Without it the line names no image:
    /// the request is `/v2/<repo_key>/<name>/...`, and `<name>` is the half
    /// a client reports.
    pub(crate) name: &'a str,
    /// A tag or a `sha256:` digest, exactly as the client sent it — and
    /// already validated by then (the tag grammar on the tag branch,
    /// `parse_digest` on the digest branch), so this never puts unchecked
    /// request bytes in the log.
    pub(crate) reference: &'a str,
    /// The resolved content hash, rendered bare (no `sha256:` prefix) to
    /// match the `manifest_deliverability` refusal line, so one grep finds
    /// an artifact across both.
    pub(crate) digest: &'a ContentHash,
}

/// Why the read was refused.
///
/// One token per withholding state, because the status alone does not
/// distinguish them: a hold that clears itself and a hold that never will
/// are both `503`, and so is an indeterminate verdict.
pub(crate) enum RefusalReason {
    /// A hold with a deadline — the artifact's own scan verdict is
    /// outstanding and does arrive.
    Quarantined,
    /// A hold waiting on an external event: a signature that has not
    /// arrived under `provenance_mode: Required`.
    ProvenanceHold,
    /// A terminal verdict against the artifact.
    Rejected,
    /// A scan that reached no verdict — terminal too, and fail-closed.
    ScanIndeterminate,
    /// Nothing is wrong with the manifest the client asked for: an
    /// artifact in its closure carries a terminal verdict, so the
    /// manifest is not deliverable (ADR 0062).
    ///
    /// One reason across both envelopes that refusal answers in — the
    /// constituent's own verdict picks the status, `403` for a rejected
    /// one and `503` for an indeterminate one — because the state being
    /// recorded is the same one either way: this image is withheld for
    /// something it binds. Which constituent, and which verdict, is the
    /// `manifest_deliverability` decision line's half of the record.
    TerminalConstituent,
}

impl RefusalReason {
    /// Which hold a `Quarantined` refusal is.
    ///
    /// The flag read here decides, in
    /// `hort_http_core::artifact_gate::quarantine_retry_after_seconds` and
    /// only there, whether the refusal advertises a `Retry-After`; this
    /// read only names the hold. So the token and the header cannot
    /// disagree about the response — they are the same fact reported once
    /// each.
    pub(crate) fn hold(artifact: &Artifact) -> Self {
        if artifact.provenance_hold_indefinite {
            Self::ProvenanceHold
        } else {
            Self::Quarantined
        }
    }

    fn token(&self) -> &'static str {
        match self {
            Self::Quarantined => "quarantined",
            Self::ProvenanceHold => "provenance_hold",
            Self::Rejected => "rejected",
            Self::ScanIndeterminate => "scan_indeterminate",
            Self::TerminalConstituent => "terminal_constituent",
        }
    }

    /// Whether waiting resolves this refusal — the whole of the level
    /// decision stated in the module doc.
    ///
    /// The constituent refusal is decided by this same criterion and not
    /// beside it: `ConstituentStatusReader` can only name a status
    /// `QuarantineStatus::is_terminal` holds for, so the only states
    /// that reach it are `Rejected` and `ScanIndeterminate` — neither has
    /// a deadline to advertise, both answer in the no-`Retry-After`
    /// envelope the manifest's own arms for those states answer in, and
    /// the refusal ends only when an operator acts on the constituent.
    fn self_resolving(&self) -> bool {
        match self {
            Self::Quarantined => true,
            Self::ProvenanceHold
            | Self::Rejected
            | Self::ScanIndeterminate
            | Self::TerminalConstituent => false,
        }
    }
}

/// Record one refused hosted OCI read.
///
/// Called at the exit, with the response the exit is about to return, so
/// the **status is read off that response and never passed in**: the
/// `OciError` → response mapping is the one thing that decides it, and a
/// line carrying its own copy could report a status the client never
/// received.
pub(crate) fn log_refused_read(
    response: &Response,
    read: &RefusedRead<'_>,
    reason: &RefusalReason,
) {
    let status = response.status().as_u16();
    // Two macro calls and not one: `tracing` bakes the level into static
    // callsite metadata, so it cannot be a runtime value. The level is
    // still decided once, by `self_resolving`.
    if reason.self_resolving() {
        tracing::info!(
            route = read.route.token(),
            repository = %read.repo_key,
            name = %read.name,
            reference = %read.reference,
            digest = %read.digest,
            status,
            reason = reason.token(),
            "OCI read refused"
        );
    } else {
        tracing::warn!(
            route = read.route.token(),
            repository = %read.repo_key,
            name = %read.name,
            reference = %read.reference,
            digest = %read.digest,
            status,
            reason = reason.token(),
            "OCI read refused"
        );
    }
}

/// The `target` every refusal line carries — this module's path. Tests
/// select by it rather than indexing into the capture buffer.
#[cfg(test)]
pub(crate) const REFUSAL_TARGET: &str = "hort_http_oci::refusal";

/// Field-by-field expectation for one refusal line, shared by the
/// `manifests` and `blobs` handler suites.
///
/// One implementation, because the rendered-field matching is subtle in the
/// same way for every caller: the capture flattens fields to `name=value `
/// pairs, so an expectation has to include the trailing space or
/// `reason=quarantined` would also be satisfied by a hypothetical
/// `reason=quarantined_something`.
#[cfg(test)]
pub(crate) struct ExpectedRefusal<'a> {
    pub(crate) level: tracing::Level,
    pub(crate) route: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) name: &'a str,
    pub(crate) reference: &'a str,
    pub(crate) digest: &'a str,
    pub(crate) status: u16,
    pub(crate) reason: &'a str,
}

/// Assert that `events` holds exactly one refusal line and that every field
/// on it is the expected value.
///
/// Exactly one, because two lines for one refusal is the noise this module
/// exists not to produce, and zero is the regression it exists to catch.
#[cfg(test)]
pub(crate) fn assert_refusal_line(
    events: &[crate::test_tracing::CapturedEvent],
    expected: &ExpectedRefusal<'_>,
) {
    let lines: Vec<_> = events
        .iter()
        .filter(|e| e.target == REFUSAL_TARGET)
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one refusal line, got: {lines:?}"
    );
    let line = lines[0];
    assert_eq!(
        line.level, expected.level,
        "refusal level disagrees with the one level decision: {line:?}"
    );
    for pair in [
        format!("route={} ", expected.route),
        format!("repository={} ", expected.repository),
        format!("name={} ", expected.name),
        format!("reference={} ", expected.reference),
        format!("digest={} ", expected.digest),
        format!("status={} ", expected.status),
        format!("reason={} ", expected.reason),
        "message=OCI read refused ".to_string(),
    ] {
        assert!(
            line.fields.contains(&pair),
            "refusal line is missing `{pair}`: {line:?}"
        );
    }
}

/// Assert that nothing in `events` is a refusal line.
///
/// The converse half of every assertion above: without it, a line emitted
/// unconditionally — on a served read, or on an exemption that lifted the
/// refusal — would satisfy all of them.
#[cfg(test)]
pub(crate) fn assert_no_refusal_line(events: &[crate::test_tracing::CapturedEvent]) {
    let lines: Vec<_> = events
        .iter()
        .filter(|e| e.target == REFUSAL_TARGET)
        .collect();
    assert!(
        lines.is_empty(),
        "nothing was refused, so nothing may be recorded as refused: {lines:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::response::IntoResponse;

    use crate::error::OciError;
    use crate::test_tracing::{capture_tracing, CapturedEvent};
    use hort_app::use_cases::test_support::sample_artifact;
    use hort_domain::entities::artifact::QuarantineStatus;

    const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Emit one line against a response built from `error`, for a fixed
    /// blob-route subject, and return what the subscriber saw.
    fn emit(error: OciError, reason: &RefusalReason) -> Vec<CapturedEvent> {
        let digest: ContentHash = DIGEST_HEX.parse().unwrap();
        let response = error.into_response();
        let (_, events) = capture_tracing(|| {
            log_refused_read(
                &response,
                &RefusedRead {
                    route: ReadRoute::Blob,
                    repo_key: "myrepo",
                    name: "nginx",
                    reference: "sha256:deadbeef",
                    digest: &digest,
                },
                reason,
            );
        });
        events
    }

    /// Assert the line [`emit`] produced. That helper fixes the subject,
    /// so only the level, the status and the reason vary per case — which
    /// is exactly what each case below is about.
    fn assert_emitted(events: &[CapturedEvent], level: tracing::Level, status: u16, reason: &str) {
        assert_refusal_line(
            events,
            &ExpectedRefusal {
                level,
                route: "blob",
                repository: "myrepo",
                name: "nginx",
                reference: "sha256:deadbeef",
                digest: DIGEST_HEX,
                status,
                reason,
            },
        );
    }

    /// The status is the response's and not the caller's: there is no
    /// parameter to pass one, so the line reports what the client got.
    #[test]
    fn the_line_reports_the_responses_own_status() {
        let events = emit(
            OciError::ArtifactRejected {
                subject: "sha256:deadbeef".to_string(),
                axis: None,
            },
            &RefusalReason::Rejected,
        );
        assert_emitted(&events, tracing::Level::WARN, 403, "rejected");
    }

    /// A hold that resolves itself is the registry working as designed.
    #[test]
    fn a_time_bounded_hold_is_info() {
        let events = emit(
            OciError::Quarantined {
                retry_after_seconds: Some(600),
            },
            &RefusalReason::Quarantined,
        );
        assert_emitted(&events, tracing::Level::INFO, 503, "quarantined");
    }

    /// Same status, same envelope, different answer: a hold waiting on a
    /// signature has no deadline, so no retry ends it.
    #[test]
    fn an_indefinite_hold_is_warn_on_the_same_status() {
        let events = emit(
            OciError::Quarantined {
                retry_after_seconds: None,
            },
            &RefusalReason::ProvenanceHold,
        );
        assert_emitted(&events, tracing::Level::WARN, 503, "provenance_hold");
    }

    #[test]
    fn an_indeterminate_verdict_is_warn() {
        let events = emit(
            OciError::ScanIndeterminate,
            &RefusalReason::ScanIndeterminate,
        );
        assert_emitted(&events, tracing::Level::WARN, 503, "scan_indeterminate");
    }

    /// The route reaches the line, so a manifest refusal is filterable
    /// from a blob one — which `target` cannot do, since one module emits
    /// both. Asserted on a tag reference too: that is the shape in which
    /// `reference` and `digest` differ at all.
    #[test]
    fn the_route_and_the_tag_reference_both_reach_the_line() {
        let digest: ContentHash = DIGEST_HEX.parse().unwrap();
        let response = OciError::ScanIndeterminate.into_response();
        let (_, events) = capture_tracing(|| {
            log_refused_read(
                &response,
                &RefusedRead {
                    route: ReadRoute::Manifest,
                    repo_key: "myrepo",
                    name: "nginx",
                    reference: "1.21",
                    digest: &digest,
                },
                &RefusalReason::ScanIndeterminate,
            );
        });
        assert_refusal_line(
            &events,
            &ExpectedRefusal {
                level: tracing::Level::WARN,
                route: "manifest",
                repository: "myrepo",
                name: "nginx",
                reference: "1.21",
                digest: DIGEST_HEX,
                status: 503,
                reason: "scan_indeterminate",
            },
        );
    }

    /// The level criterion stated in the module doc, held against the
    /// wire: `info!` exactly when the refusal advertises a `Retry-After`.
    ///
    /// This is what stops the level and the response drifting apart. A
    /// reason added without a `Retry-After` and left `self_resolving`
    /// fails here, and here is the only place the two facts meet. Every
    /// reason is listed, and a reason that answers in more than one
    /// envelope is listed once per envelope — the criterion is a claim
    /// about responses, so a reason covered on one of its responses is
    /// covered on none of the others.
    #[test]
    fn refusal_level_agrees_with_retry_after() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        let timed = RefusalReason::hold(&artifact);
        artifact.provenance_hold_indefinite = true;
        let indefinite = RefusalReason::hold(&artifact);

        for (reason, error) in [
            (
                timed,
                OciError::Quarantined {
                    retry_after_seconds: Some(600),
                },
            ),
            (
                indefinite,
                OciError::Quarantined {
                    retry_after_seconds: None,
                },
            ),
            (
                RefusalReason::Rejected,
                OciError::ArtifactRejected {
                    subject: "sha256:deadbeef".to_string(),
                    axis: None,
                },
            ),
            (
                RefusalReason::ScanIndeterminate,
                OciError::ScanIndeterminate,
            ),
            // Both envelopes the constituent refusal answers in, because
            // one reason spans two of them and the criterion has to hold
            // on each. `ConstituentStatusReader` can only name a status
            // `is_terminal` holds for, so these two are the only states
            // that reach it — which is what makes the existing criterion
            // decide this reason rather than a special case deciding it.
            (
                RefusalReason::TerminalConstituent,
                OciError::ArtifactRejected {
                    subject: "sha256:deadbeef".to_string(),
                    axis: None,
                },
            ),
            (
                RefusalReason::TerminalConstituent,
                OciError::ScanIndeterminate,
            ),
        ] {
            let response = error.into_response();
            let advertises_a_deadline = response
                .headers()
                .contains_key(axum::http::header::RETRY_AFTER);
            assert_eq!(
                reason.self_resolving(),
                advertises_a_deadline,
                "the level decision and the advertised Retry-After disagree on `{}`",
                reason.token()
            );
        }
    }

    /// `hold` reads the flag the response builder reads, so the token and
    /// the header report one fact rather than two.
    #[test]
    fn the_hold_token_follows_the_indefinite_flag() {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        assert_eq!(RefusalReason::hold(&artifact).token(), "quarantined");
        artifact.provenance_hold_indefinite = true;
        assert_eq!(RefusalReason::hold(&artifact).token(), "provenance_hold");
    }

    /// Every reason has its own token: a collision would merge two
    /// operator-distinguishable states into one log value.
    #[test]
    fn every_reason_has_a_distinct_token() {
        let tokens = [
            RefusalReason::Quarantined.token(),
            RefusalReason::ProvenanceHold.token(),
            RefusalReason::Rejected.token(),
            RefusalReason::ScanIndeterminate.token(),
            RefusalReason::TerminalConstituent.token(),
        ];
        let mut unique = tokens.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            tokens.len(),
            "duplicate reason token: {tokens:?}"
        );
    }

    /// The helper both handler suites lean on can still fail — without
    /// this, a capture that silently stopped seeing the line would make
    /// every assertion above vacuous.
    #[test]
    #[should_panic(expected = "expected exactly one refusal line")]
    fn the_assertion_fails_when_no_line_was_emitted() {
        assert_emitted(&[], tracing::Level::WARN, 403, "rejected");
    }

    /// And the converse helper too, for the same reason.
    #[test]
    #[should_panic(expected = "nothing was refused")]
    fn the_converse_assertion_fails_when_a_line_was_emitted() {
        assert_no_refusal_line(&emit(OciError::ScanIndeterminate, &RefusalReason::Rejected));
    }
}
