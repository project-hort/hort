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
//!    granularity here, not index-build granularity:
//!    - [`QuarantineStatus::Quarantined`] →
//!      [`WheelMetadataServeOutcome::Quarantined`] carrying the
//!      hydrated `quarantine_deadline` so the HTTP layer can build a
//!      503 + `Retry-After` matching the wheel download's shape.
//!    - [`QuarantineStatus::Rejected`] /
//!      [`QuarantineStatus::ScanIndeterminate`] →
//!      `Err(NotFound { entity: "Artifact" })`. **Diverges from the
//!      wheel-download handler's 403 mapping** — for `.metadata`, even
//!      the existence of the rejected wheel must stay hidden (a 403
//!      would leak: "the wheel exists but is blocked"; the metadata
//!      contains declared deps + signature surface that an attacker
//!      without download rights could otherwise enumerate).
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
//! per design doc §4 — operators dashboard the metadata-vs-wheel-download
//! breakdown from the tracing field (no new metric). The download metric
//! `hort_download_total{format="pypi", result=...}` is *not* incremented
//! here — this surface is per-source-attribute serve, not a primary
//! artifact download. (Re-using the metric would conflate cardinality
//! and dirty the wheel-download dashboards.)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::io::AsyncRead;

use hort_domain::entities::artifact::QuarantineStatus;
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
/// Three states the HTTP layer must distinguish to produce the correct
/// wire shape:
///
/// - [`Self::Available`] — 200 + bytes + headers.
/// - [`Self::Quarantined`] — 503 + `Retry-After` (computed from the
///   carried deadline). The use case does NOT compute the seconds string —
///   that's HTTP-layer concern (the same shape the wheel-download handler
///   uses today).
///
/// The fourth state — `Rejected` / `ScanIndeterminate` / missing
/// ContentReference / invisible repo — is signalled by
/// `Err(AppError::Domain(DomainError::NotFound { … }))` from
/// [`WheelMetadataUseCase::serve`], NOT by an additional outcome
/// variant. Collapsing those onto one `NotFound` envelope is the
/// anti-enumeration property the test matrix pins.
pub enum WheelMetadataServeOutcome {
    /// The CAS-resident `wheel_metadata` blob is available.
    Available(MetadataBlob),
    /// The parent wheel is in [`QuarantineStatus::Quarantined`].
    /// `quarantine_deadline` is the hydrated transient deadline; the
    /// HTTP layer turns it into a `Retry-After` seconds value
    /// matching the wheel-download handler's shape.
    Quarantined {
        quarantine_deadline: Option<DateTime<Utc>>,
    },
}

impl std::fmt::Debug for WheelMetadataServeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available(blob) => f
                .debug_struct("Available")
                .field("content_hash", &blob.content_hash)
                .field("size", &blob.size)
                .finish_non_exhaustive(),
            Self::Quarantined {
                quarantine_deadline,
            } => f
                .debug_struct("Quarantined")
                .field("quarantine_deadline", quarantine_deadline)
                .finish(),
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
        // collapse to a `NotFound` envelope inside this hop. The
        // `find_visible_by_path` use case hydrates the transient
        // `quarantine_deadline` so we can build the
        // `Retry-After` below without resolving a `ScanPolicy`
        // ourselves.
        let (repo, artifact) = self
            .artifacts
            .find_visible_by_path(repo_key, artifact_path, caller)
            .await?;

        // ---- (2) Per-artifact status filter -------------------------
        match artifact.quarantine_status {
            QuarantineStatus::None | QuarantineStatus::Released => {}
            QuarantineStatus::Quarantined => {
                // 503-shaped — HTTP layer builds the Retry-After.
                tracing::info!(
                    artifact_id = %artifact.id,
                    repository = %repo_key,
                    "wheel_metadata serve rejected — parent wheel quarantined"
                );
                return Ok(WheelMetadataServeOutcome::Quarantined {
                    quarantine_deadline: artifact.quarantine_deadline,
                });
            }
            QuarantineStatus::Rejected | QuarantineStatus::ScanIndeterminate => {
                // **404, not 403** — see module doc §2 — anti-enumeration
                // for the metadata surface; the wheel's existence stays
                // hidden. Anti-enumeration log envelope on the use-case
                // side; the handler emits no additional log.
                tracing::info!(
                    artifact_id = %artifact.id,
                    repository = %repo_key,
                    status = %artifact.quarantine_status,
                    "wheel_metadata serve denied — non-servable parent wheel collapses to NotFound"
                );
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    id: format!("{repo_key}:{artifact_path}"),
                }));
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
        sample_artifact, sample_repository, MockArtifactMetadataRepository, MockArtifactRepository,
        MockContentReferenceIndex, MockRepositoryRepository, MockStoragePort,
    };

    /// SHA-256 of the constant test METADATA payload below; used as the
    /// row's `target_content_hash` and seeded into the mock storage.
    const METADATA_BYTES: &[u8] = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";

    fn metadata_hash() -> ContentHash {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(METADATA_BYTES);
        let hex = format!("{:x}", h.finalize());
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
    }

    fn build_harness(access: RbacAccess) -> Harness {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let repositories = Arc::new(MockRepositoryRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());

        let access_uc = Arc::new(RepositoryAccessUseCase::new(
            repositories.clone(),
            access,
            true,
        ));
        let artifact_uc = Arc::new(
            ArtifactUseCase::new(
                artifacts.clone(),
                storage.clone(),
                repositories.clone(),
                true,
            )
            .with_repository_access(access_uc)
            .with_artifact_metadata(metadata),
        );
        let uc = WheelMetadataUseCase::new(
            artifact_uc,
            content_references.clone() as Arc<dyn ContentReferenceIndex>,
            storage.clone(),
        );
        Harness {
            uc,
            artifacts,
            repositories,
            storage,
            content_references,
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

    // -- F-25 anti-enumeration on private repo -------------------------

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

    // -- Quarantined parent wheel → 503-shaped outcome -----------------

    #[tokio::test]
    async fn serve_quarantined_wheel_returns_quarantined_outcome_with_deadline() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Quarantined,
        );

        let outcome = h.uc.serve("pypi-test", &path, None).await.unwrap();
        match outcome {
            WheelMetadataServeOutcome::Quarantined {
                quarantine_deadline,
            } => {
                // Hydration filled in the deadline from
                // `quarantine_window_start` (deadline hydration).
                assert!(
                    quarantine_deadline.is_some(),
                    "deadline should be hydrated for quarantined artifact"
                );
            }
            WheelMetadataServeOutcome::Available(_) => {
                panic!("quarantined wheel must NOT yield Available outcome")
            }
        }
    }

    // -- Rejected wheel → 404 (NOT 403) --------------------------------

    #[tokio::test]
    async fn serve_rejected_wheel_returns_notfound_not_forbidden() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Rejected,
        );

        let err =
            h.uc.serve("pypi-test", &path, None)
                .await
                .expect_err("rejected wheel must deny");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    ..
                })
            ),
            "rejected wheel `.metadata` must return Artifact NotFound for anti-enumeration, got {err:?}"
        );
    }

    // -- ScanIndeterminate wheel → 404 (NOT 403) -----------------------

    #[tokio::test]
    async fn serve_scan_indeterminate_wheel_returns_notfound() {
        let h = build_harness(RbacAccess::Disabled);
        let (_repo, path) = seed_wheel_with_metadata(
            &h,
            "pypi-test",
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::ScanIndeterminate,
        );

        let err =
            h.uc.serve("pypi-test", &path, None)
                .await
                .expect_err("scan-indeterminate wheel must deny");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    ..
                })
            ),
            "scan-indeterminate `.metadata` must return NotFound, got {err:?}"
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
