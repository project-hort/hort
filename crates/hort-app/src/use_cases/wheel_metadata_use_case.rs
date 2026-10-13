//! PEP 658 `.metadata` read-path use case. See PEP 658 and
//! `docs/architecture/how-to/pypi-pull-through.md`.
//!
//! Serves the raw `<dist-info>/METADATA` bytes of a wheel artifact via
//! `GET /{repo_key}/files/{filename}.metadata` (PEP 658). The use case
//! itself is HTTP-shape-free: the handler turns the
//! [`WheelMetadataServeOutcome`] back into wire bytes + headers
//! (`Content-Type`, `Content-Digest`, `Retry-After`).
//!
//! # Gates (in order)
//!
//! 1. **Per-resource visibility** via
//!    [`ArtifactUseCase::find_visible_by_path`]. Anonymous on a private
//!    repo collapses to `NotFound { entity: "Repository" }`, missing repo
//!    collapses to `NotFound { entity: "Repository" }`, and a visible
//!    repo with a missing path collapses to `NotFound { entity:
//!    "Artifact" }`. **Anti-enumeration** — denied/missing/invisible
//!    must be wire-indistinguishable from the actor's perspective.
//! 2. **Per-artifact status filter.** The universal
//!    `NonServableStatusFilter` shape — but applied at per-artifact
//!    granularity here, not index-build granularity. Every status that
//!    withholds the wheel — [`QuarantineStatus::Quarantined`],
//!    [`QuarantineStatus::Rejected`],
//!    [`QuarantineStatus::ScanIndeterminate`] — yields
//!    [`WheelMetadataServeOutcome::NonServable`] carrying the loaded
//!    artifact, and the HTTP layer answers it through the same gate the
//!    wheel-download route answers through. A `.metadata` request is a
//!    request about the same artifact, so it gets the same answer: a
//!    caller told `403 rejected` by the wheel and `404` by its metadata
//!    learns only that the two routes were written on different days.
//! 3. **ContentReference lookup** for the
//!    `(repo_id, wheel_artifact_id, "wheel_metadata")` PK. Missing row
//!    (legacy un-backfilled wheel, format-handler returned `None` at
//!    ingest, or the metadata backfill not yet run) → `Err(NotFound)`.
//!    The simple-index layer gates its
//!    `data-dist-info-metadata` emission on the SAME row's presence, so
//!    pip clients normally never reach this 404; this is the
//!    operator-visible safety net for direct-URL probes.
//! 4. **CAS fetch** — stream the bytes back via
//!    [`StoragePort::get`]. The handler builds `Content-Digest` from
//!    [`MetadataBlob::content_hash`]; no use-case-side hash recomputation.
//!
//! # Caller threading
//!
//! Per the architect skill's anti-pattern checklist, the
//! use case threads `Option<&CallerPrincipal>` through to the
//! visibility hop itself — the handler delegates entirely; there is no
//! HTTP-layer authz gate. The single-gate property is what makes the
//! review-checklist anti-pattern hold.
//!
//! # Observability
//!
//! `#[tracing::instrument(skip(self), fields(endpoint_kind = "wheel_metadata"))]`
//! operators dashboard the metadata-vs-wheel-download breakdown from
//! the tracing field (no new metric). The download metric
//! `hort_download_total{format="pypi", result=...}` is *not* incremented
//! here — this surface is per-source-attribute serve, not a primary
//! artifact download. (Re-using the metric would conflate cardinality
//! and dirty the wheel-download dashboards.)

use std::sync::Arc;

use tokio::io::AsyncRead;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use crate::error::{AppError, AppResult};
use crate::use_cases::artifact_use_case::ArtifactUseCase;

/// Wheel-metadata content streamed back from CAS.
///
/// Carries the bytes stream plus the hash (so the HTTP layer can
/// emit `Content-Digest: sha256=:<base64>:` per RFC 9530) and the
/// size in bytes (for `Content-Length`).
pub struct MetadataBlob {
    /// Asynchronous reader yielding the raw METADATA bytes. Mirrors the
    /// `ArtifactUseCase::download` return shape so the HTTP layer wraps
    /// it in `ReaderStream::new(_)` identically.
    pub bytes: Box<dyn AsyncRead + Send + Unpin>,
    /// SHA-256 of the bytes stream. The HTTP layer formats this into the
    /// RFC 9530 `Content-Digest: sha256=:<base64>:` header so a
    /// tampering proxy on the wire is detectable.
    pub content_hash: ContentHash,
    /// Byte length — emitted as `Content-Length` so a mid-stream truncation
    /// of the response is client-detectable. Mirrors the wheel-download
    /// handler's `Content-Length` discipline (anti-truncation: a known
    /// `Content-Length` beats bare chunked encoding).
    pub size: u64,
}

/// Outcome of a `.metadata` serve.
///
/// Two states, because there are only two answers a caller who reached
/// this far can be owed:
///
/// - [`Self::Available`] — 200 + bytes + headers.
/// - [`Self::NonServable`] — the parent wheel's own
///   [`QuarantineStatus`] withholds it. The loaded [`Artifact`] rides
///   along so the HTTP layer answers through the one gate the
///   wheel-download route answers through
///   (`hort_http_core::artifact_gate::non_servable_response`): a
///   `.metadata` request is a request about that same artifact, and it
///   is owed that same answer.
///
/// **Carrying the artifact rather than a variant per status is what
/// makes that structural.** The gate's match over [`QuarantineStatus`]
/// has no wildcard arm, so the per-status shape of a refusal — which
/// code, which headers, which body — has exactly one definition and a
/// status added tomorrow is a compile error there. A variant per status
/// here would be a second place to forget, and it would hand the HTTP
/// layer strictly less than the artifact already carries: the hydrated
/// `quarantine_deadline`, the `provenance_hold_indefinite` flag
/// (ADR 0039 D5) and the rejection axis (ADR 0039 D6) are all on it by
/// the time [`ArtifactUseCase::find_visible_by_path`] hands it over.
///
/// What is still an `Err(AppError::Domain(DomainError::NotFound { … }))`
/// from [`WheelMetadataUseCase::serve`]: an invisible or missing
/// repository (ADR 0021 / 0045 — that challenge fires before any status
/// is read, and this outcome does not weaken it), a path that resolves
/// to no artifact at all, and a wheel with no `wheel_metadata`
/// ContentReference row. The last of those is genuinely "no such
/// metadata" rather than a verdict, which is why it keeps the 404 the
/// terminal verdicts no longer borrow.
pub enum WheelMetadataServeOutcome {
    /// The CAS-resident `wheel_metadata` blob is available.
    Available(MetadataBlob),
    /// The parent wheel's status withholds it — `Quarantined`,
    /// `Rejected` or `ScanIndeterminate`. Carries the hydrated artifact
    /// so the HTTP layer can put the shared status gate's question to it.
    ///
    /// Boxed because an `Artifact` is several hundred bytes against the
    /// blob arm's handful, mirroring
    /// `hort_http_pypi::VirtualMemberDownload::Found`.
    NonServable(Box<Artifact>),
}

impl std::fmt::Debug for WheelMetadataServeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available(blob) => f
                .debug_struct("Available")
                .field("content_hash", &blob.content_hash)
                .field("size", &blob.size)
                .finish_non_exhaustive(),
            Self::NonServable(artifact) => f
                .debug_struct("NonServable")
                .field("artifact_id", &artifact.id)
                .field("quarantine_status", &artifact.quarantine_status)
                .finish_non_exhaustive(),
        }
    }
}

/// Composition over [`ArtifactUseCase`] + [`ContentReferenceIndex`] +
/// [`StoragePort`].
///
/// Hosted-only: the
/// proxy dispatcher composes this use case as the "cache-hit" path and
/// adds the strategy-1/strategy-2 fallbacks around it.
pub struct WheelMetadataUseCase {
    /// Threaded for the visibility-gated `find_visible_by_path` hop +
    /// the `Artifact` hydration. Shared `Arc` with the rest of the
    /// composition root.
    artifacts: Arc<ArtifactUseCase>,
    /// `ContentReferenceIndex` for the
    /// `(repo, source, "wheel_metadata")` PK lookup. Direct port access
    /// is fine in `hort-app` (the `pub(crate)`-on-`AppContext`
    /// rule (ADR 0008) applies only to format crates — the use-case
    /// layer is allowed to hold ports).
    content_references: Arc<dyn ContentReferenceIndex>,
    /// CAS reader for the `wheel_metadata` blob. Same `Arc<dyn
    /// StoragePort>` the artifact use case holds.
    storage: Arc<dyn StoragePort>,
}

impl WheelMetadataUseCase {
    /// Construct a new use case from the wired dependencies. Mirrors
    /// the shape of every other `*UseCase::new(...)` constructor.
    pub fn new(
        artifacts: Arc<ArtifactUseCase>,
        content_references: Arc<dyn ContentReferenceIndex>,
        storage: Arc<dyn StoragePort>,
    ) -> Self {
        Self {
            artifacts,
            content_references,
            storage,
        }
    }

    /// Serve the PEP 658 `.metadata` bytes for the wheel at
    /// `(repo_key, wheel_filename)`. The `wheel_filename` is the wheel's
    /// **filename only** (`example-1.0.0-py3-none-any.whl`); the
    /// `.metadata` suffix has already been stripped by the HTTP handler.
    /// The path looked up against `ArtifactRepository::find_by_path` is
    /// built as `simple/{project}/{wheel_filename}` to mirror the
    /// wheel-download handler exactly (the project segment is derived
    /// from the wheel filename's distribution-name prefix via the
    /// caller).
    ///
    /// **Wheels only.** The HTTP handler short-circuits sdists on the
    /// `.whl` suffix BEFORE reaching this use case (PEP 658 applies
    /// only to wheels — sdists have no `<dist-info>/METADATA`). This use
    /// case therefore does not re-validate the suffix; an `artifact_path`
    /// that doesn't end in `.whl` is a callsite bug, not a runtime
    /// reject path.
    #[tracing::instrument(skip(self), fields(endpoint_kind = "wheel_metadata"))]
    pub async fn serve(
        &self,
        repo_key: &str,
        artifact_path: &str,
        caller: Option<&CallerPrincipal>,
    ) -> AppResult<WheelMetadataServeOutcome> {
        // ---- (1) Visibility-gated artifact resolution ---------------
        // Anti-enumeration — denied / missing / invisible all
        // collapse to a `NotFound` envelope inside this hop. It is also
        // the one hop that hydrates the transient fields no `row ->
        // Artifact` load can carry — the quarantine deadline, the
        // indefinite-hold flag and the rejection axis — which is what
        // lets the refusal below be built from the artifact alone,
        // without this use case resolving a `ScanPolicy` or the format
        // crate reading an event stream it may not reach (ADR 0008).
        let (repo, artifact) = self
            .artifacts
            .find_visible_by_path(repo_key, artifact_path, caller)
            .await?;

        // ---- (2) Per-artifact status filter -------------------------
        // One arm for every status that withholds the wheel: the
        // artifact goes back to the HTTP layer and the shared status gate
        // decides what the caller is told, so this route cannot answer a
        // status differently from the wheel-download route beside it.
        // The match carries no wildcard arm, so a new `QuarantineStatus`
        // is a compile error here rather than a silent withholding — or
        // a silent serve — of a state nobody classified.
        match artifact.quarantine_status {
            QuarantineStatus::None | QuarantineStatus::Released => {}
            QuarantineStatus::Quarantined
            | QuarantineStatus::Rejected
            | QuarantineStatus::ScanIndeterminate => {
                tracing::info!(
                    artifact_id = %artifact.id,
                    repository = %repo_key,
                    status = %artifact.quarantine_status,
                    "wheel_metadata serve withheld — the parent wheel is not servable"
                );
                return Ok(WheelMetadataServeOutcome::NonServable(Box::new(artifact)));
            }
        }

        // ---- (3) ContentReference lookup ----------------------------
        let row = self
            .content_references
            .find_by_source_and_kind(repo.id, artifact.id, "wheel_metadata")
            .await?;
        let Some(row) = row else {
            // Legacy un-backfilled wheel, or `extract_wheel_metadata_bytes`
            // returned `None` (corrupt wheel, no METADATA member), or
            // the metadata backfill hasn't run yet. Collapse to
            // 404 — the simple-index gates the
            // advertisement on the SAME row's presence, so a normal
            // PEP 658 client never reaches here for this wheel.
            tracing::debug!(
                artifact_id = %artifact.id,
                repository = %repo_key,
                "wheel_metadata serve — no ContentReference row; serving 404"
            );
            return Err(AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                id: format!("{repo_key}:{artifact_path}.metadata"),
            }));
        };

        // ---- (4) CAS fetch ------------------------------------------
        let stream = self
            .storage
            .get(&row.target_content_hash)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let size = self
            .storage
            .size_of(&row.target_content_hash)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(WheelMetadataServeOutcome::Available(MetadataBlob {
            bytes: stream,
            content_hash: row.target_content_hash,
            size,
        }))
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use serde_json::json;
    use tokio::io::AsyncReadExt;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};

    use super::*;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use crate::use_cases::test_support::{
        persisted_artifact_rejected, sample_artifact, sample_repository,
        MockArtifactMetadataRepository, MockArtifactRepository, MockContentReferenceIndex,
        MockEventStore, MockRepositoryRepository, MockStoragePort,
    };

    /// SHA-256 of the constant test METADATA payload below; used as the
    /// row's `target_content_hash` and seeded into the mock storage.
    const METADATA_BYTES: &[u8] = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";

    fn metadata_hash() -> ContentHash {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(METADATA_BYTES);
        let hex = hex::encode(h.finalize());
        hex.parse().unwrap()
    }

    fn private_pypi_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.to_string();
        r.format = RepositoryFormat::Pypi;
        r.is_public = false;
        r
    }

    fn public_pypi_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.to_string();
        r.format = RepositoryFormat::Pypi;
        r.is_public = true;
        r
    }

    struct Harness {
        uc: WheelMetadataUseCase,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        content_references: Arc<MockContentReferenceIndex>,
        /// The artifact's own event stream. Only wired by
        /// [`build_harness_with_axis_hydration`]; the rejection axis is
        /// derived from an `ArtifactRejected` event, so a test that wants
        /// it seeds this handle.
        events: Arc<MockEventStore>,
    }

    fn build_harness(access: RbacAccess) -> Harness {
        build(access, false)
    }

    /// [`build_harness`] plus the artifact-stream port, so
    /// `find_visible_by_path` can hydrate `Artifact::rejection_reason`
    /// from the stream the way production does.
    ///
    /// Opt-in rather than default for the reason the unwired arm exists
    /// at all: a harness that leaves the port out gets a `warn!` and a
    /// `None` axis, and a test asserting on the axis has to be unable to
    /// pass for that reason.
    fn build_harness_with_axis_hydration(access: RbacAccess) -> Harness {
        build(access, true)
    }

    fn build(access: RbacAccess, hydrate_axis: bool) -> Harness {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let repositories = Arc::new(MockRepositoryRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let events = Arc::new(MockEventStore::new());

        let access_uc = Arc::new(RepositoryAccessUseCase::new(
            repositories.clone(),
            access,
            true,
        ));
        let mut artifact_uc = ArtifactUseCase::new(
            artifacts.clone(),
            storage.clone(),
            repositories.clone(),
            true,
        )
        .with_repository_access(access_uc)
        .with_artifact_metadata(metadata);
        if hydrate_axis {
            artifact_uc = artifact_uc.with_artifact_stream_events(events.clone());
        }
        let uc = WheelMetadataUseCase::new(
            Arc::new(artifact_uc),
            content_references.clone() as Arc<dyn ContentReferenceIndex>,
            storage.clone(),
        );
        Harness {
            uc,
            artifacts,
            repositories,
            storage,
            content_references,
            events,
        }
    }

    /// Seed a public hosted PyPI wheel + its `wheel_metadata`
    /// ContentReference row + the CAS bytes. Returns the (repo,
    /// artifact_path) tuple the use case will be called with.
    fn seed_wheel_with_metadata(
        h: &Harness,
        repo_key: &str,
        project: &str,
        filename: &str,
        status: QuarantineStatus,
    ) -> (Repository, String) {
        let repo = public_pypi_repo(repo_key);
        h.repositories.insert(repo.clone());
        let mut artifact = sample_artifact(status);
        artifact.repository_id = repo.id;
        artifact.name = project.to_string();
        artifact.path = format!("simple/{project}/{filename}");
        h.artifacts.insert(artifact.clone());
        let hash = metadata_hash();
        h.storage
            .insert_content(hash.clone(), METADATA_BYTES.to_vec());
        // Insert the wheel_metadata ContentReference row.
        let row = ContentReference {
            source_artifact_id: artifact.id,
            target_content_hash: hash,
            kind: "wheel_metadata".to_string(),
            metadata: json!({}),
            repository_id: repo.id,
            recorded_at: Utc::now(),
        };
        futures::executor::block_on(h.content_references.insert(row)).unwrap();
        (repo, format!("simple/{project}/{filename}"))
    }

    // -- happy path ----------------------------------------------------

    #[tokio::test]
    async fn serve_returns_available_with_bytes_and_hash_on_happy_path() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
        );

        let outcome = h.uc.serve("pypi-test", &path, None).await.unwrap();
        let blob = match outcome {
            WheelMetadataServeOutcome::Available(b) => b,
            other => panic!("expected Available, got {other:?}"),
        };
        // Hash matches the seeded payload's SHA-256.
        assert_eq!(blob.content_hash, metadata_hash());
        assert_eq!(blob.size, METADATA_BYTES.len() as u64);
        // Body bytes round-trip.
        let mut buf = Vec::new();
        let mut reader = blob.bytes;
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, METADATA_BYTES);
    }

    /// The `Debug` shape each arm renders: enough to identify the
    /// outcome in a failing assertion or a log line, and deliberately
    /// less than it carries. `finish_non_exhaustive` is doing work in
    /// both arms — the blob's bytes and the artifact's every field
    /// (path, name, checksums) have no business being formatted into a
    /// log by an accidental `{outcome:?}`.
    #[tokio::test]
    async fn debug_identifies_each_outcome_without_dumping_what_it_carries() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
        );
        let available = format!("{:?}", h.uc.serve("pypi-test", &path, None).await.unwrap());
        assert!(
            available.starts_with("Available") && available.contains("content_hash"),
            "unexpected Available debug: {available}"
        );

        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Rejected,
        );
        let withheld = format!("{:?}", h.uc.serve("pypi-test", &path, None).await.unwrap());
        assert!(
            withheld.starts_with("NonServable")
                && withheld.contains("quarantine_status")
                && withheld.contains(".."),
            "unexpected NonServable debug: {withheld}"
        );
        assert!(
            !withheld.contains("example-1.0.0-py3-none-any.whl"),
            "the artifact's path has no business in a log line: {withheld}"
        );
    }

    // -- Anti-enumeration on private repo -------------------------

    #[tokio::test]
    async fn serve_anonymous_on_private_repo_returns_notfound() {
        // Build with enabled-RBAC (empty evaluator) so the private repo
        // is invisible to anonymous callers; with `Disabled` the access
        // use case would admit-all and a `private`-flagged repo would
        // be visible (the test would assert the wrong axis).
        let h = build_harness(RbacAccess::Enabled(Arc::new(
            arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())),
        )));
        let repo = private_pypi_repo("private-pypi");
        h.repositories.insert(repo);
        let path = "simple/secret/secret-1.0.0-py3-none-any.whl".to_string();

        let err =
            h.uc.serve("private-pypi", &path, None)
                .await
                .expect_err("anonymous on private MUST be denied");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "Repository",
                    ..
                })
            ),
            "expected Repository NotFound (anti-enumeration), got {err:?}"
        );
    }

    // -- a non-servable parent wheel reaches the HTTP layer ------------

    /// Unwrap a `NonServable` outcome, or fail naming what came instead.
    fn expect_non_servable(outcome: WheelMetadataServeOutcome) -> Artifact {
        match outcome {
            WheelMetadataServeOutcome::NonServable(artifact) => *artifact,
            other => panic!("expected NonServable, got {other:?}"),
        }
    }

    /// A quarantined parent wheel reaches the HTTP layer as the artifact
    /// itself, carrying the hydrated deadline the `503`'s `Retry-After`
    /// is computed from.
    ///
    /// The deadline is what the retired `Quarantined { quarantine_deadline }`
    /// variant carried, and it is the smaller half of what the artifact
    /// carries: `provenance_hold_indefinite` rides on the same value and
    /// decides whether that `Retry-After` is emitted at all (ADR 0039
    /// D5), which the variant had no room for. The hydration of both
    /// fields on this load path is pinned by `ArtifactUseCase`'s own
    /// `find_visible_by_path` tests.
    #[tokio::test]
    async fn serve_quarantined_wheel_hands_back_the_artifact_with_its_deadline() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Quarantined,
        );

        let artifact = expect_non_servable(h.uc.serve("pypi-test", &path, None).await.unwrap());
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
        assert!(
            artifact.quarantine_deadline.is_some(),
            "deadline should be hydrated for quarantined artifact"
        );
    }

    /// **The reversal.** A rejected wheel's `.metadata` no longer
    /// disappears into an `Artifact NotFound`: the artifact goes back to
    /// the HTTP layer, which refuses it through the same gate the wheel
    /// download refuses it through — a `403` naming the axis.
    ///
    /// Its predecessor, `serve_rejected_wheel_returns_notfound_not_forbidden`,
    /// asserted the opposite and was right for the caller it had in
    /// mind: a `404` here hid the wheel's existence from someone who
    /// could not otherwise learn it. That caller does not arrive at this
    /// arm. The repository challenge fires first (ADR 0021 / 0045, and
    /// `serve_anonymous_on_private_repo_returns_notfound` still pins
    /// it), so whoever reaches here was already admitted by the read
    /// gate — and the simple index they came through listed the wheel.
    /// The 404 therefore concealed nothing but the verdict, which is the
    /// one fact that ends their search (ADR 0055, read-gate audience).
    #[tokio::test]
    async fn serve_rejected_wheel_hands_back_the_artifact_with_its_axis() {
        let h = build_harness_with_axis_hydration(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Rejected,
        );
        // The axis lives on the artifact's stream, not in a column: the
        // repository mock clears `rejection_reason` on read exactly as
        // the one `row -> Artifact` mapper does, so seeding the fixture
        // entity would prove nothing. Only the hydration can put it back.
        let seeded = h.artifacts.snapshot_all().pop().expect("the seeded wheel");
        h.events.set_stream(
            &hort_domain::events::StreamId::artifact(seeded.id),
            vec![persisted_artifact_rejected(
                seeded.id,
                hort_domain::events::RejectionReason::Scanner,
                1,
            )],
        );

        let artifact = expect_non_servable(h.uc.serve("pypi-test", &path, None).await.unwrap());
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(
            artifact.rejection_reason,
            Some(hort_domain::events::RejectionReason::Scanner),
            "the axis must reach the HTTP layer; a refusal that cannot name it \
             is the ADR 0039 D6 illegal state, not a healthy rejection"
        );
    }

    /// The same reversal for the other terminal verdict, and for the same
    /// reason. Its predecessor, `serve_scan_indeterminate_wheel_returns_notfound`,
    /// pinned the `404` and was right for the same caller the rejected
    /// test's predecessor was right for.
    ///
    /// Note what this test does **not** assert: a status code. Whether
    /// `ScanIndeterminate` answers `403` or `503` is an open cross-format
    /// question with a recorded divergence, and answering through the
    /// shared gate is what lets this route hold no position on it — now,
    /// or after it is settled.
    #[tokio::test]
    async fn serve_scan_indeterminate_wheel_hands_back_the_artifact() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::ScanIndeterminate,
        );

        let artifact = expect_non_servable(h.uc.serve("pypi-test", &path, None).await.unwrap());
        assert_eq!(
            artifact.quarantine_status,
            QuarantineStatus::ScanIndeterminate
        );
    }

    // -- wheel ingested but no ContentReference row (un-backfilled) ----

    #[tokio::test]
    async fn serve_wheel_without_contentreference_row_returns_notfound() {
        let h = build_harness(RbacAccess::Disabled);
        // Seed the wheel + storage WITHOUT the wheel_metadata row.
        let repo = public_pypi_repo("pypi-test");
        h.repositories.insert(repo.clone());
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "example".into();
        artifact.path = "simple/example/example-1.0.0-py3-none-any.whl".into();
        h.artifacts.insert(artifact);

        let err =
            h.uc.serve(
                "pypi-test",
                "simple/example/example-1.0.0-py3-none-any.whl",
                None,
            )
            .await
            .expect_err("missing ContentReference row must collapse to NotFound");
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                ..
            })
        ));
    }

    // -- artifact missing entirely ------------------------------------

    #[tokio::test]
    async fn serve_missing_artifact_returns_notfound() {
        let h = build_harness(RbacAccess::Disabled);
        let repo = public_pypi_repo("pypi-test");
        h.repositories.insert(repo);

        let err =
            h.uc.serve(
                "pypi-test",
                "simple/missing/missing-1.0.0-py3-none-any.whl",
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                ..
            })
        ));
    }
}
