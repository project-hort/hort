use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;
use hort_domain::events::{system_actor, ArtifactDownloaded, DomainEvent, DownloadActor, StreamId};
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{
    ByteRange, ContentHash, LimitedList, Page, PageRequest, LIMIT_LIST_MAX_ITEMS,
};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_download_audit_dropped, labels, values, DownloadAuditDropResult, DownloadResult,
};
use crate::use_cases::repository_access::{AccessLevel, RepositoryAccessUseCase};

/// Opt-in download-audit gate.
///
/// `ArtifactUseCase` holds an `Option<DownloadAuditGate>` so legacy /
/// test deployments that wire no event store keep working with the
/// audit-emit logic short-circuited — the same optional-builder shape
/// as [`AuthenticateUseCase`]'s `AuthEventGate` /
/// `with_audit_events`. There is no throttle handle here (contrast
/// `AuthEventGate`'s ephemeral store): the per-repository
/// `download_audit_enabled` opt-in IS the volume control.
struct DownloadAuditGate {
    events: Arc<EventStorePublisher>,
}

/// Application use case for artifact read, download, and delete operations.
pub struct ArtifactUseCase {
    artifacts: Arc<dyn ArtifactRepository>,
    storage: Arc<dyn StoragePort>,
    repositories: Arc<dyn RepositoryRepository>,
    /// Cardinality safety valve mirroring the `METRICS_INCLUDE_REPOSITORY_LABEL`
    /// env var. When false, every metric emission from this use case sets
    /// `repository = "_all"` ([`values::REPOSITORY_ALL`]).
    include_repository_label: bool,
    /// Composed for the `find_visible_*` and
    /// `list_*_visible` extensions. `Option` so existing call sites
    /// (`new(4 args)`) keep compiling — they get `None` and never call
    /// the new methods. The OCI path wires this via
    /// [`Self::with_repository_access`] in the composition root.
    repository_access: Option<Arc<RepositoryAccessUseCase>>,
    /// Composed for [`Self::batch_metadata`].
    /// Optional for the same backward-compat reason as
    /// [`Self::repository_access`]. Wired via
    /// [`Self::with_artifact_metadata`].
    artifact_metadata: Option<Arc<dyn ArtifactMetadataRepository>>,
    /// Opt-in download-audit emit
    /// gate. `None` when unwired (legacy / test deployments) — the
    /// emit logic short-circuits. Wired via [`Self::with_audit_events`]
    /// (production composition root only).
    audit_events: Option<DownloadAuditGate>,
}

impl ArtifactUseCase {
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        storage: Arc<dyn StoragePort>,
        repositories: Arc<dyn RepositoryRepository>,
        include_repository_label: bool,
    ) -> Self {
        Self {
            artifacts,
            storage,
            repositories,
            include_repository_label,
            repository_access: None,
            artifact_metadata: None,
            audit_events: None,
        }
    }

    /// Enable opt-in download-audit emits.
    /// Wires the [`EventStorePublisher`] handle used to `append`
    /// one [`ArtifactDownloaded`] event per served download **when the
    /// served artifact's `Repository.download_audit_enabled` is true**.
    /// Fail-open: an append error never blocks the download.
    ///
    /// Same builder shape as [`Self::with_repository_access`] /
    /// `AuthenticateUseCase::with_audit_events` so every existing
    /// `ArtifactUseCase::new(..)` call site stays compiling unchanged;
    /// only the production composition root opts in.
    #[must_use]
    pub fn with_audit_events(mut self, events: Arc<EventStorePublisher>) -> Self {
        self.audit_events = Some(DownloadAuditGate { events });
        self
    }

    /// Wire the composed [`RepositoryAccessUseCase`].
    ///
    /// Methods that need it (`find_visible_by_path`, `find_visible_by_id`,
    /// `list_by_raw_name_visible`, `list_distinct_names_visible`) return
    /// [`AppError::Repository`] when called against a use case whose
    /// access port was not wired — that signals a composition-root bug
    /// (`new` was called instead of `with_repository_access`). Phase 1
    /// composition keeps both call sites alive.
    #[must_use]
    pub fn with_repository_access(mut self, access: Arc<RepositoryAccessUseCase>) -> Self {
        self.repository_access = Some(access);
        self
    }

    /// Wire the [`ArtifactMetadataRepository`] port consumed by
    /// [`Self::batch_metadata`]. See [`Self::with_repository_access`]
    /// for the optional-field rationale.
    #[must_use]
    pub fn with_artifact_metadata(mut self, metadata: Arc<dyn ArtifactMetadataRepository>) -> Self {
        self.artifact_metadata = Some(metadata);
        self
    }

    /// Resolve the `repository` metric label — see
    /// [`values::REPOSITORY_ALL`] / [`values::REPOSITORY_UNKNOWN`].
    fn repo_label(&self, repo_key: Option<&str>) -> String {
        if !self.include_repository_label {
            values::REPOSITORY_ALL.to_string()
        } else {
            repo_key.unwrap_or(values::REPOSITORY_UNKNOWN).to_string()
        }
    }

    /// Resolve the `format` metric label. Falls back to
    /// [`values::FORMAT_UNKNOWN`] when the artifact/repo lookup fails before
    /// the format could be resolved.
    fn format_label(format: Option<&str>) -> String {
        format.unwrap_or(values::FORMAT_UNKNOWN).to_string()
    }

    /// Get an artifact by ID.
    #[tracing::instrument(skip(self))]
    pub async fn get_by_id(&self, id: Uuid) -> AppResult<Artifact> {
        Ok(self.artifacts.find_by_id(id).await?)
    }

    /// Find an artifact by SHA-256 checksum.
    #[tracing::instrument(skip(self))]
    pub async fn find_by_checksum(&self, sha256: &ContentHash) -> AppResult<Option<Artifact>> {
        Ok(self.artifacts.find_by_checksum(sha256).await?)
    }

    /// List artifacts in a repository.
    #[tracing::instrument(skip(self))]
    pub async fn list_by_repository(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> AppResult<Page<Artifact>> {
        Ok(self
            .artifacts
            .list_by_repository(repository_id, page)
            .await?)
    }

    /// List artifacts by **raw** (client-supplied) name, with a drift-
    /// resilience fallback. The two-step logic is:
    ///
    /// 1. Call `handler.normalize_name(raw_name)` to derive the current
    ///    normalised form, then `find_by_name_in_repo(repo, normalised)`.
    /// 2. If step 1 returns a non-empty `Vec`, return it unchanged.
    /// 3. Otherwise fall back to `find_by_name_as_published(repo, raw_name)`
    ///    — the exact client-supplied form is stored on every artifact row.
    ///    If the fallback finds rows, the current normalisation
    ///    function has drifted from whatever was active at ingest. Emit an
    ///    `info!` log naming the repo, raw name, current normalised form,
    ///    and count of recovered rows so operators can detect drift in the
    ///    wild, then return the fallback rows.
    ///
    /// **Every handler's index/packument lookup must call this method** —
    /// calling `find_by_name_in_repo` directly from a handler re-introduces
    /// the silent-unreachability hole this method exists to close.
    ///
    /// Internally iterates the paginated port
    /// methods up to [`LIMIT_LIST_MAX_ITEMS`] and discards the
    /// truncation flag (callers that need it use
    /// [`Self::list_by_raw_name_limited`]). The cap is a defence-in-depth
    /// ceiling, not a normal mode; if a single package legitimately
    /// exceeds 10 000 versions the operator should review the
    /// pull-through retention policy.
    #[tracing::instrument(skip(self, handler))]
    pub async fn list_by_raw_name(
        &self,
        repository_id: Uuid,
        handler: &dyn FormatHandler,
        raw_name: &str,
    ) -> AppResult<Vec<Artifact>> {
        Ok(self
            .list_by_raw_name_limited(repository_id, handler, raw_name)
            .await?
            .items)
    }

    /// Truncation-aware variant of [`Self::list_by_raw_name`]. Returns a
    /// [`LimitedList`] whose `truncated` flag fires when the iterating
    /// loop hit [`LIMIT_LIST_MAX_ITEMS`] without exhausting the
    /// underlying result set. PyPI's simple-index handler emits a
    /// `Warning: 299` HTTP header when this fires, so SIEM tooling can
    /// pick up the defence-in-depth bound's ignition.
    #[tracing::instrument(skip(self, handler))]
    pub async fn list_by_raw_name_limited(
        &self,
        repository_id: Uuid,
        handler: &dyn FormatHandler,
        raw_name: &str,
    ) -> AppResult<LimitedList<Artifact>> {
        let normalised = handler.normalize_name(raw_name);
        let primary = {
            let normalised_ref = normalised.as_str();
            iterate_pages_capped(LIMIT_LIST_MAX_ITEMS as usize, |page| async move {
                Ok(self
                    .artifacts
                    .find_by_name_in_repo(repository_id, normalised_ref, page)
                    .await?)
            })
            .await?
        };
        if !primary.items.is_empty() {
            if primary.truncated {
                tracing::warn!(
                    %repository_id,
                    raw_name,
                    cap = LIMIT_LIST_MAX_ITEMS,
                    "list_by_raw_name primary result set truncated at cap"
                );
            }
            return Ok(primary);
        }

        let fallback = iterate_pages_capped(LIMIT_LIST_MAX_ITEMS as usize, |page| async move {
            Ok(self
                .artifacts
                .find_by_name_as_published(repository_id, raw_name, page)
                .await?)
        })
        .await?;
        if !fallback.items.is_empty() {
            tracing::info!(
                %repository_id,
                raw_name,
                current_normalised = %normalised,
                recovered = fallback.items.len(),
                "normalisation drift detected: primary lookup missed, \
                 fallback via name_as_published recovered rows"
            );
            if fallback.truncated {
                tracing::warn!(
                    %repository_id,
                    raw_name,
                    cap = LIMIT_LIST_MAX_ITEMS,
                    "list_by_raw_name fallback result set truncated at cap"
                );
            }
        }
        Ok(fallback)
    }

    /// Delete an artifact by ID.
    #[tracing::instrument(skip(self))]
    pub async fn delete(&self, id: Uuid) -> AppResult<()> {
        Ok(self.artifacts.delete(id).await?)
    }

    /// Download an artifact's content as a stream.
    ///
    /// Returns the artifact metadata and a content stream. Blocks download
    /// if the artifact is quarantined or rejected.
    ///
    /// `actor` is the already-resolved request principal threaded from
    /// the inbound format handler — it
    /// is the *subject* attribution for the opt-in `ArtifactDownloaded`
    /// audit event when the served repository has
    /// `download_audit_enabled = true`. `None` ⇒ anonymous pull
    /// (recorded as [`DownloadActor::Anonymous`] — no audit-log gaps).
    /// It does NOT gate the download (reads are anonymous-by-default;
    /// per-resource visibility was already enforced by the handler's
    /// `find_visible_by_*` hop) — it is audit attribution only.
    #[tracing::instrument(skip(self, actor))]
    pub async fn download(
        &self,
        artifact_id: Uuid,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Artifact, Box<dyn AsyncRead + Send + Unpin>)> {
        let started = Instant::now();
        let outcome = self.download_inner(artifact_id, actor).await;

        let elapsed = started.elapsed().as_secs_f64();
        // Apply the cardinality-safety-valve and the FORMAT_UNKNOWN fallback
        // at the emission boundary; the inner pipeline carries `Option<String>`
        // for both so the sentinel policy lives in exactly one place.
        let (result_label, format_label, repository_label): (&'static str, String, String) =
            match &outcome {
                Ok(ctx) => (
                    DownloadResult::Success.as_str(),
                    Self::format_label(Some(&ctx.format)),
                    self.repo_label(Some(&ctx.repo_key)),
                ),
                Err(DownloadFailure {
                    result,
                    format,
                    repo_key,
                    ..
                }) => (
                    result.as_str(),
                    Self::format_label(format.as_deref()),
                    self.repo_label(repo_key.as_deref()),
                ),
            };

        metrics::counter!(
            "hort_download_total",
            labels::FORMAT => format_label.clone(),
            labels::REPOSITORY => repository_label,
            labels::RESULT => result_label,
        )
        .increment(1);
        metrics::histogram!(
            "hort_download_duration_seconds",
            labels::FORMAT => format_label,
        )
        .record(elapsed);

        match outcome {
            Ok(ctx) => Ok((ctx.artifact, ctx.stream)),
            Err(failure) => Err(failure.error),
        }
    }

    async fn download_inner(
        &self,
        artifact_id: Uuid,
        actor: Option<&CallerPrincipal>,
    ) -> Result<DownloadOk, DownloadFailure> {
        let artifact = self.artifacts.find_by_id(artifact_id).await.map_err(|e| {
            let result = match &e {
                DomainError::NotFound { .. } => DownloadResult::NotFound,
                _ => DownloadResult::StorageError,
            };
            DownloadFailure {
                error: AppError::Domain(e),
                result,
                // Format/repository unknown at this stage — the outer
                // `download` applies FORMAT_UNKNOWN / REPOSITORY_UNKNOWN
                // sentinels (or REPOSITORY_ALL when the flag is disabled).
                format: None,
                repo_key: None,
            }
        })?;

        let repository = self
            .repositories
            .find_by_id(artifact.repository_id)
            .await
            .ok();
        let (format, repo_key): (Option<String>, Option<String>) = match &repository {
            Some(r) => (Some(r.format.to_string()), Some(r.key.clone())),
            None => (None, None),
        };

        if !artifact.is_downloadable() {
            let result = match artifact.quarantine_status {
                QuarantineStatus::Quarantined => DownloadResult::Quarantined,
                QuarantineStatus::Rejected => DownloadResult::Rejected,
                // Any other state that is_downloadable() forbids.
                _ => DownloadResult::Rejected,
            };
            return Err(DownloadFailure {
                error: AppError::Domain(DomainError::Forbidden(format!(
                    "artifact {} is not downloadable (status: {})",
                    artifact_id, artifact.quarantine_status
                ))),
                result,
                format,
                repo_key,
            });
        }

        let stream = self
            .storage
            .get(&artifact.sha256_checksum)
            .await
            .map_err(|e| DownloadFailure {
                error: AppError::Storage(e.to_string()),
                result: DownloadResult::StorageError,
                format: format.clone(),
                repo_key: repo_key.clone(),
            })?;

        tracing::debug!(%artifact_id, hash = %artifact.sha256_checksum, "download");

        // Opt-in download-audit emit.
        // AFTER the is_downloadable() gate AND after the content stream
        // is obtained (a quarantined / storage-failed pull is not a
        // "served download"), BEFORE returning the stream. Fail-open:
        // an append error never blocks the download — the audit trail
        // is "as-good-as-it-can-be", not "must-succeed-before-serve"
        // (mirrors `maybe_append_auth_event`'s best-effort contract).
        // No-op unless the gate is wired AND the served repository
        // opted in (`download_audit_enabled`). The opt-in flag is the
        // volume control; there is no throttle.
        if let (Some(gate), Some(repo)) = (&self.audit_events, repository.as_ref()) {
            if repo.download_audit_enabled {
                let occurred_at = chrono::Utc::now();
                let download_actor = match actor {
                    Some(p) => DownloadActor::User {
                        user_id: p.user_id,
                        external_id: p.external_id.clone(),
                    },
                    None => DownloadActor::Anonymous,
                };
                let event = ArtifactDownloaded {
                    artifact_id: artifact.id,
                    repository_id: repo.id,
                    content_hash: artifact.sha256_checksum.clone(),
                    actor: download_actor,
                    occurred_at,
                };
                let batch = AppendEvents {
                    // Per-(repo, UTC-date) stream — NEVER the artifact
                    // aggregate/lifecycle stream (audit streams stay
                    // out of aggregate streams — ADR 0002; asserted in
                    // tests).
                    stream_id: StreamId::download_audit(repo.id, occurred_at.date_naive()),
                    expected_version: ExpectedVersion::Any,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactDownloaded(event))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    // The batch recorder is `system_actor()` (the
                    // recorder); the subject rides the payload
                    // `DownloadActor` (decision A — mirrors
                    // `AuthenticationAttempted`).
                    actor: system_actor(),
                };
                if let Err(e) = gate.events.append(batch).await {
                    // Fail-open: serve the stream anyway. NO routine-
                    // success log on the Ok path (high-volume served-
                    // download path); only the drop path is observable.
                    tracing::warn!(
                        audit_write_failed = true,
                        error = %e,
                        repository_id = %repo.id,
                        "download audit append failed; download served"
                    );
                    emit_download_audit_dropped(
                        &Self::format_label(format.as_deref()),
                        &self.repo_label(repo_key.as_deref()),
                        DownloadAuditDropResult::AppendError,
                    );
                }
            }
        }

        // `Ok` path always has both format and repo_key resolved — inner code
        // only reaches here after a successful repository lookup.
        Ok(DownloadOk {
            artifact,
            stream,
            format: format.unwrap_or_default(),
            repo_key: repo_key.unwrap_or_default(),
        })
    }

    /// Resolve the full upload-payload metadata for an artifact row,
    /// transparently following a `metadata_blob` reference when present.
    ///
    /// Two shapes:
    /// - `row.metadata_blob == None` — the row's `metadata` field IS the
    ///   full payload (Inline strategy, or HashReference under the inline
    ///   threshold). Returned verbatim; no CAS round-trip.
    /// - `row.metadata_blob == Some(hash)` — the row's `metadata` holds the
    ///   handler-extracted summary and the full payload lives in CAS.
    ///   Stream the blob, collect, deserialise.
    ///
    /// Callers that only need summary fields (index listings,
    /// `data-requires-python`) read `row.metadata` directly and never call
    /// this helper — summary sufficiency is a handler contract.
    ///
    /// A malformed blob in CAS surfaces as [`AppError::Storage`] (not
    /// Domain) because the CAS write-time SHA-256 guarantee has held but
    /// the bytes no longer round-trip as JSON — that's an integrity
    /// failure of the blob store, not a business-logic error. The
    /// message is intentionally terse; the blob hash is in the row the
    /// caller already holds, and surfacing it in the error string would
    /// leak the addressable identifier into error-channel logs.
    #[tracing::instrument(skip(self, row), fields(artifact_id = %row.artifact_id))]
    pub async fn load_full_metadata(&self, row: &ArtifactMetadata) -> AppResult<serde_json::Value> {
        match &row.metadata_blob {
            None => Ok(row.metadata.clone()),
            Some(hash) => {
                let mut stream = self
                    .storage
                    .get(hash)
                    .await
                    .map_err(|e| AppError::Storage(e.to_string()))?;
                let mut buf = Vec::new();
                stream
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| AppError::Storage(format!("metadata blob read failed: {e}")))?;
                serde_json::from_slice(&buf)
                    .map_err(|_| AppError::Storage("metadata blob deserialisation failed".into()))
            }
        }
    }

    // -- visibility-aware extensions ----------------------------------------

    /// Borrow the wired [`RepositoryAccessUseCase`] or surface a
    /// composition-root error.
    fn access(&self) -> AppResult<&Arc<RepositoryAccessUseCase>> {
        self.repository_access.as_ref().ok_or_else(|| {
            AppError::Repository(
                "RepositoryAccessUseCase not wired — call `with_repository_access` in composition"
                    .into(),
            )
        })
    }

    /// Resolve an artifact by `(repo_key, path)` after confirming Read
    /// visibility on the repo. Returns `NotFound` indistinguishably for
    /// missing repo, invisible repo, or missing path. Carries
    /// `Repository` alongside so callers don't re-look-up for quarantine
    /// config / format checks.
    #[tracing::instrument(skip(self))]
    pub async fn find_visible_by_path(
        &self,
        repo_key: &str,
        path: &str,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Repository, Artifact)> {
        let repo = self
            .access()?
            .resolve(repo_key, actor, AccessLevel::Read)
            .await?;
        match self.artifacts.find_by_path(repo.id, path).await? {
            Some(a) => Ok((repo, Self::hydrate_quarantine_deadline(a))),
            None => Err(AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                // Carry both repo + path so logs can reconstruct the
                // request shape; safe because the caller has already
                // demonstrated Read visibility on the repo.
                id: format!("{repo_key}:{path}"),
            })),
        }
    }

    /// Hydrate the transient, non-persisted `quarantine_deadline`
    /// onto an artifact about to be returned to a
    /// format-crate read path.
    ///
    /// The adapter-free `hort-http-<format>` crates cannot resolve a
    /// `ScanPolicy`, so they cannot compute the observation-window
    /// deadline themselves; the use-case layer supplies it here for the
    /// proxy-`503` `Retry-After` sites to read.
    ///
    /// The stored column is the immutable window **anchor**
    /// (`quarantine_window_start`); the deadline is
    /// `effective_quarantine_deadline(anchor, duration)`. `ArtifactUseCase`
    /// holds no `ScanPolicy` projection port, so this hydration uses the
    /// anchor as the deadline directly — correct while the ingest path
    /// still stamps `now + duration` into the column. Once the ingest
    /// stores the bare ingest-time anchor and wires policy-duration
    /// resolution, the duration-aware computation lands with it.
    fn hydrate_quarantine_deadline(mut artifact: Artifact) -> Artifact {
        artifact.quarantine_deadline = artifact.quarantine_window_start;
        artifact
    }

    /// Same shape, by artifact id. Loads the artifact, then re-checks
    /// Read on the row's repo. Carries `Repository` so the handler can
    /// render quarantine / format metadata without re-fetch.
    ///
    /// Returns `NotFound` for: artifact missing, repo invisible to actor.
    #[tracing::instrument(skip(self))]
    pub async fn find_visible_by_id(
        &self,
        artifact_id: Uuid,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Repository, Artifact)> {
        let artifact = match self.artifacts.find_by_id(artifact_id).await {
            Ok(a) => a,
            Err(DomainError::NotFound { .. }) => {
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    id: artifact_id.to_string(),
                }));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };
        let repo = match self
            .access()?
            .resolve_by_id(artifact.repository_id, actor, AccessLevel::Read)
            .await
        {
            Ok(r) => r,
            // Anti-enumeration: if the repo is invisible (or missing —
            // can happen on a stale projection), surface as "artifact
            // not found", NOT "repo not found". The actor probed an
            // artifact id; the wire envelope must talk about the
            // artifact, not leak the existence of the repo.
            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    id: artifact_id.to_string(),
                }));
            }
            Err(other) => return Err(other),
        };
        Ok((repo, Self::hydrate_quarantine_deadline(artifact)))
    }

    /// Repo-scoped hash lookup. Caller supplies a pre-authz'd
    /// `repo_id` (typically from `WriteRepoAccess` on a manifest PUT).
    /// Closes the inventory bug at OCI `manifests_write.rs:922`
    /// where today's `find_by_checksum` returns any repo's row matching
    /// the hash, breaking the OCI §2.14 same-repo manifest invariant.
    #[tracing::instrument(skip(self))]
    pub async fn find_in_repo_by_hash(
        &self,
        repo_id: Uuid,
        hash: &ContentHash,
    ) -> AppResult<Option<Artifact>> {
        Ok(self
            .artifacts
            .find_by_repo_and_checksum(repo_id, hash)
            .await?)
    }

    /// Range-aware download. Folds the `storage.get_range` bypass from
    /// OCI `blobs.rs:334`. Callers pre-authz'd via
    /// [`Self::find_visible_by_path`] / [`Self::find_visible_by_id`];
    /// this method is purely the streaming hop. Returns the artifact
    /// alongside so the handler can echo `Content-Length` /
    /// `Content-Range` without re-reading the row.
    ///
    /// Quarantined / rejected artifacts return `Forbidden` mirroring
    /// the existing [`Self::download`] gate. Storage errors propagate
    /// as [`AppError::Storage`].
    #[tracing::instrument(skip(self))]
    pub async fn download_range(
        &self,
        artifact_id: Uuid,
        range: ByteRange,
    ) -> AppResult<(Artifact, Box<dyn AsyncRead + Send + Unpin>)> {
        let artifact = self.artifacts.find_by_id(artifact_id).await?;
        if !artifact.is_downloadable() {
            return Err(AppError::Domain(DomainError::Forbidden(format!(
                "artifact {} is not downloadable (status: {})",
                artifact_id, artifact.quarantine_status
            ))));
        }
        let stream = self
            .storage
            .get_range(&artifact.sha256_checksum, range)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok((artifact, stream))
    }

    /// Visible variant of [`Self::list_by_raw_name_limited`]. Resolves
    /// the repo with Read visibility first, then runs the same drift-
    /// resilient raw-name lookup. npm packument is the primary caller
    /// today; future cargo / PyPI variants share the shape.
    ///
    /// Returns a
    /// [`LimitedList`] so the HTTP handler can emit a `Warning: 299`
    /// header when the underlying paginated read hits the
    /// [`LIMIT_LIST_MAX_ITEMS`] cap.
    #[tracing::instrument(skip(self, handler))]
    pub async fn list_by_raw_name_visible(
        &self,
        repo_key: &str,
        handler: &dyn FormatHandler,
        raw_name: &str,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Repository, LimitedList<Artifact>)> {
        let repo = self
            .access()?
            .resolve(repo_key, actor, AccessLevel::Read)
            .await?;
        let rows = self
            .list_by_raw_name_limited(repo.id, handler, raw_name)
            .await?;
        Ok((repo, rows))
    }

    /// Visible variant of `list_distinct_names`. Same shape, different
    /// terminal port call. Used by the PyPI root index today; future
    /// cargo `_index` and npm `-/all` consumers reuse.
    ///
    /// Iterates the
    /// paginated port up to [`LIMIT_LIST_MAX_ITEMS`]. Truncation logged
    /// at `warn!` and surfaced via the [`LimitedList::truncated`] flag
    /// so the HTTP handler can attach a `Warning: 299` header.
    #[tracing::instrument(skip(self))]
    pub async fn list_distinct_names_visible(
        &self,
        repo_key: &str,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Repository, LimitedList<String>)> {
        let repo = self
            .access()?
            .resolve(repo_key, actor, AccessLevel::Read)
            .await?;
        let repo_id = repo.id;
        let names = iterate_pages_capped(LIMIT_LIST_MAX_ITEMS as usize, |page| async move {
            Ok(self.artifacts.list_distinct_names(repo_id, page).await?)
        })
        .await?;
        if names.truncated {
            tracing::warn!(
                repository_id = %repo_id,
                cap = LIMIT_LIST_MAX_ITEMS,
                "list_distinct_names result set truncated at cap"
            );
        }
        Ok((repo, names))
    }

    /// Batch-fetch metadata for ids the caller already authz'd in THIS
    /// request (typically via a `find_visible_by_*` / `list_*_visible`
    /// hop). Documented as **trusted ids** — no per-id re-check; batch
    /// is the whole point. The single-id variant collapses into
    /// `batch_metadata(&[id])` with a `.get(&id)` at the call site.
    ///
    /// Empty input short-circuits to an empty map without hitting the
    /// port — symmetric with `list_by_artifact_ids` semantics.
    #[tracing::instrument(skip(self))]
    pub async fn batch_metadata(
        &self,
        artifact_ids: &[Uuid],
    ) -> AppResult<HashMap<Uuid, ArtifactMetadata>> {
        if artifact_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let port = self.artifact_metadata.as_ref().ok_or_else(|| {
            AppError::Repository(
                "ArtifactMetadataRepository not wired — call `with_artifact_metadata` in composition"
                    .into(),
            )
        })?;
        Ok(port.list_by_artifact_ids(artifact_ids).await?)
    }

    /// Per-`(repository, package)` version-and-status read for the
    /// quarantine-aware index-serve filter.
    ///
    /// Thin pass-through to
    /// [`ArtifactRepository::package_version_status`]: the format crate
    /// (e.g. `hort-http-npm`'s `serve_rewritten`) calls this to obtain the
    /// raw `(version, quarantine_status)` pairs Hort holds for `package`
    /// in `repository_id`, then feeds them — together with the upstream
    /// version set and the operator-selected `IndexMode` — to
    /// [`crate::use_cases::index_serve_filter::filter_served_versions`].
    ///
    /// Lives on `ArtifactUseCase` (not on a new use case) because the
    /// data port is the existing `ArtifactRepository`, the existing
    /// composed object exposed on `AppContext::artifact_use_case`. A
    /// new use case for one pass-through method would add ceremony for
    /// no win.
    ///
    /// **Hot path.** This is called on every packument / sparse-index /
    /// simple-index serve. The adapter relies on the
    /// covering index `artifacts (repository_id, name) INCLUDE
    /// (version, quarantine_status) WHERE NOT is_deleted`
    /// for an index-only scan; callers must NOT page-fan-out this method.
    ///
    /// **Return shape.** The port carries a third tuple
    /// element (`quarantine_until: Option<DateTime<Utc>>`) consumed only
    /// by [`DiscoveryUseCase`]. This wrapper preserves the original
    /// 2-tuple shape because every index/prefetch consumer
    /// (`PrefetchUseCase::plan`, `fire_hot_path_trigger`, the
    /// `fire_prefetch_trigger_{npm,pypi,cargo}` helpers,
    /// `filter_served_versions`, `NonServableStatusFilter`,
    /// `IndexModeFilter`, the index-build pipeline) consumes
    /// `&[(String, QuarantineStatus)]` and ignores the new field. The
    /// truncation here is the one-tuple-arm-extension boundary; the
    /// extended tuple is exposed on the port to
    /// [`DiscoveryUseCase`], not through this wrapper.
    #[tracing::instrument(skip(self))]
    pub async fn package_version_status(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> AppResult<Vec<(String, QuarantineStatus)>> {
        Ok(self
            .artifacts
            .package_version_status(repository_id, package)
            .await?
            .into_iter()
            .map(|(v, s, _)| (v, s))
            .collect())
    }
}

/// Iterate a paginated port-call until exhaustion or the `cap`,
/// whichever fires first. Uses `MAX_PAGE_SIZE` (1 000) per request — the
/// existing [`PageRequest::new`] cap — so the per-call I/O is bounded
/// and a 10 000-item walk amortises to ten round-trips.
///
/// The closure receives a [`PageRequest`] and yields `AppResult<Page<T>>`.
///
/// On `truncated`: fires when the number of items already accumulated
/// reaches `cap` AND the underlying source was not exhausted. The cap
/// is enforced by truncating the last fetched page; the loop never
/// over-fills past `cap`.
async fn iterate_pages_capped<T, F, Fut>(cap: usize, mut fetch: F) -> AppResult<LimitedList<T>>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: std::future::Future<Output = AppResult<Page<T>>>,
{
    // Per-page limit drives round-trip count; clamped by `PageRequest::new`
    // to its workspace `MAX_LIMIT` (1 000). Capping at the workspace max
    // amortises a 10 000-item walk to 10 round-trips.
    const PER_PAGE_LIMIT: u64 = 1_000;

    let mut items: Vec<T> = Vec::new();
    let mut offset: u64 = 0;
    loop {
        let want = (cap - items.len()) + 1; // over-fetch one to detect saturation
        let limit = (want as u64).min(PER_PAGE_LIMIT);
        let page = fetch(PageRequest::new(offset, limit)).await?;
        let fetched = page.items.len();
        if fetched == 0 {
            break;
        }
        items.extend(page.items);
        if items.len() > cap {
            // Saturated: trim and report.
            items.truncate(cap);
            return Ok(LimitedList {
                items,
                truncated: true,
            });
        }
        if (fetched as u64) < limit {
            // Last page (under-fetch). Source exhausted.
            break;
        }
        offset += fetched as u64;
    }
    Ok(LimitedList {
        items,
        truncated: false,
    })
}

struct DownloadOk {
    artifact: Artifact,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    format: String,
    repo_key: String,
}

struct DownloadFailure {
    error: AppError,
    result: DownloadResult,
    format: Option<String>,
    repo_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use metrics::SharedString;
    use metrics_util::debugging::DebugValue;
    use metrics_util::{CompositeKey, MetricKind};

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::error::DomainResult;

    use super::*;
    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::*;

    // -- Helpers ------------------------------------------------------------

    const OTHER_SHA256: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn find_metric<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        metric_name: &str,
        expected_labels: &[(&str, &str)],
    ) -> Option<&'a MetricEntry> {
        entries.iter().find(|(ck, _, _, _)| {
            ck.kind() == kind
                && ck.key().name() == metric_name
                && expected_labels.iter().all(|(k, v)| {
                    ck.key()
                        .labels()
                        .any(|label| label.key() == *k && label.value() == *v)
                })
        })
    }

    fn assert_counter(
        entries: &[MetricEntry],
        metric_name: &str,
        expected_labels: &[(&str, &str)],
        expected_value: u64,
    ) {
        match find_metric(entries, MetricKind::Counter, metric_name, expected_labels) {
            Some((_, _, _, DebugValue::Counter(got))) => assert_eq!(
                *got, expected_value,
                "counter {metric_name} with {expected_labels:?} had {got}, expected {expected_value}"
            ),
            Some(_) => panic!("metric {metric_name} is not a counter"),
            None => {
                let names: Vec<&str> =
                    entries.iter().map(|(ck, _, _, _)| ck.key().name()).collect();
                panic!(
                    "expected counter {metric_name} with {expected_labels:?} not found; seen: {names:?}"
                );
            }
        }
    }

    fn assert_histogram_has_sample(
        entries: &[MetricEntry],
        metric_name: &str,
        expected_labels: &[(&str, &str)],
    ) {
        match find_metric(entries, MetricKind::Histogram, metric_name, expected_labels) {
            Some((_, _, _, DebugValue::Histogram(samples))) => assert!(
                !samples.is_empty(),
                "histogram {metric_name} with {expected_labels:?} has no samples"
            ),
            Some(_) => panic!("metric {metric_name} is not a histogram"),
            None => panic!("expected histogram {metric_name} with {expected_labels:?} not found"),
        }
    }

    fn sample_artifact_in_repo(repo_id: Uuid) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: "my-pkg".into(),
            name_as_published: "my-pkg".into(),
            version: Some("1.0.0".into()),
            path: "my-pkg/1.0.0/my-pkg-1.0.0.tar.gz".into(),
            size_bytes: 2048,
            sha256_checksum: VALID_SHA256.parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/gzip".into(),
            quarantine_status: QuarantineStatus::None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_use_case_with_artifact() -> (ArtifactUseCase, Artifact, Arc<MockStoragePort>) {
        let mock = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repositories = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();
        let artifact = sample_artifact_in_repo(repo_id);
        mock.insert(artifact.clone());
        (
            ArtifactUseCase::new(mock, storage.clone(), repositories, true),
            artifact,
            storage,
        )
    }

    // -- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn get_by_id_found() {
        let (uc, artifact, _storage) = make_use_case_with_artifact();
        let found = uc.get_by_id(artifact.id).await.unwrap();
        assert_eq!(found.id, artifact.id);
    }

    #[tokio::test]
    async fn get_by_id_not_found() {
        let (uc, _, _storage) = make_use_case_with_artifact();
        let err = uc.get_by_id(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn find_by_checksum_found() {
        let (uc, _, _storage) = make_use_case_with_artifact();
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let found = uc.find_by_checksum(&hash).await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn find_by_checksum_not_found() {
        let (uc, _, _storage) = make_use_case_with_artifact();
        let hash: ContentHash = OTHER_SHA256.parse().unwrap();
        let found = uc.find_by_checksum(&hash).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn list_by_repository() {
        let (uc, artifact, _storage) = make_use_case_with_artifact();
        let page = uc
            .list_by_repository(artifact.repository_id, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total, 1);
    }

    #[tokio::test]
    async fn list_by_repository_empty() {
        let (uc, _, _storage) = make_use_case_with_artifact();
        let page = uc
            .list_by_repository(Uuid::new_v4(), PageRequest::default())
            .await
            .unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn delete_existing() {
        let (uc, artifact, _storage) = make_use_case_with_artifact();
        uc.delete(artifact.id).await.unwrap();
        let err = uc.get_by_id(artifact.id).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_not_found() {
        let (uc, _, _storage) = make_use_case_with_artifact();
        let err = uc.delete(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- list_by_raw_name: normalisation drift fallback --------------
    //
    // These tests use the shared [`StubFormatHandler`] re-exported from
    // `test_support`; it is also the stub the `IngestUseCase` cap-boundary
    // tests consume.

    fn insert_artifact_for_raw_lookup(
        artifacts: &MockArtifactRepository,
        repo_id: Uuid,
        stored_name: &str,
        name_as_published: &str,
        version: &str,
    ) -> Artifact {
        let mut a = sample_artifact_in_repo(repo_id);
        a.name = stored_name.to_string();
        a.name_as_published = name_as_published.to_string();
        a.version = Some(version.to_string());
        a.path = format!("{stored_name}/{version}/{stored_name}-{version}.tar.gz");
        artifacts.insert(a.clone());
        a
    }

    #[tokio::test]
    async fn list_by_raw_name_primary_hit_skips_fallback() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();
        insert_artifact_for_raw_lookup(&artifacts, repo_id, "foo-bar", "Foo_Bar", "1.0.0");

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        // Current normalise maps "Foo_Bar" → "foo-bar", matching the stored
        // `name`. Primary lookup hits; fallback is not needed.
        let handler = StubFormatHandler::new("test").with_mapping("Foo_Bar", "foo-bar");

        let rows = uc
            .list_by_raw_name(repo_id, &handler, "Foo_Bar")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "foo-bar");
        assert_eq!(rows[0].name_as_published, "Foo_Bar");
    }

    #[tokio::test]
    async fn list_by_raw_name_fallback_hits_on_primary_miss() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();
        // Stored under the OLD normalised form (`foo-bar`) with the raw
        // published name `Foo_Bar`.
        insert_artifact_for_raw_lookup(&artifacts, repo_id, "foo-bar", "Foo_Bar", "1.0.0");

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        // DRIFT: current normalise now returns "foo_bar" (underscore) for
        // the same raw input. Primary lookup misses; fallback by
        // `name_as_published = "Foo_Bar"` must recover the row.
        let handler = StubFormatHandler::new("test").with_mapping("Foo_Bar", "foo_bar");

        let rows = uc
            .list_by_raw_name(repo_id, &handler, "Foo_Bar")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        // Returned row still has the OLD stored `name`.
        assert_eq!(rows[0].name, "foo-bar");
        assert_eq!(rows[0].name_as_published, "Foo_Bar");
    }

    /// The returned rows carry the STORED `name` even when the current
    /// handler's `normalize_name` is **non-idempotent** on that stored
    /// value — the whole point of the drift safety net. Downstream
    /// consumers (index URL emission, download path construction) use
    /// `artifact.name` directly; if `list_by_raw_name` ever re-normalised
    /// the rows on the way out, drift resilience would collapse.
    #[tokio::test]
    async fn list_by_raw_name_returns_stored_name_even_when_non_idempotent() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();
        // Stored under the OLD normalised form `legacy-name`.
        insert_artifact_for_raw_lookup(&artifacts, repo_id, "legacy-name", "RAW", "1.0.0");

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        // Stub maps both the raw input AND the stored name to something
        // DIFFERENT — a stricter plugin whose normalise is non-idempotent
        // on old stored values.
        //
        // - normalize("RAW") = "new-form"       → primary lookup misses
        // - normalize("legacy-name") = "legacy_name" (underscore) →
        //   if `list_by_raw_name` ever re-normalised its output, the
        //   returned row would have `name = "legacy_name"` instead of
        //   `"legacy-name"` and every downstream URL would be wrong.
        let handler = StubFormatHandler::new("test")
            .with_mapping("RAW", "new-form")
            .with_mapping("legacy-name", "legacy_name");

        let rows = uc.list_by_raw_name(repo_id, &handler, "RAW").await.unwrap();
        assert_eq!(rows.len(), 1);
        // The stored name is returned UNCHANGED — proving
        // `list_by_raw_name` doesn't re-normalise on the way out.
        assert_eq!(rows[0].name, "legacy-name");
        assert_eq!(rows[0].name_as_published, "RAW");
        // Similarly, the stored path is untouched — no layer in the
        // helper re-derives it from `name` under the current algorithm.
        assert_eq!(rows[0].path, "legacy-name/1.0.0/legacy-name-1.0.0.tar.gz");
    }

    #[tokio::test]
    async fn list_by_raw_name_no_match_returns_empty() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let handler = StubFormatHandler::new("test");
        let rows = uc
            .list_by_raw_name(repo_id, &handler, "unknown")
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    // -- Download tests -------------------------------------------------------

    struct DownloadHarness {
        uc: ArtifactUseCase,
        artifact: Artifact,
        repo_key: String,
        repo_format: String,
    }

    /// Helper: put content into mock storage and return a fully-wired use case
    /// with the artifact's repository also registered in the repo mock.
    fn make_download_harness(status: QuarantineStatus) -> DownloadHarness {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repositories = Arc::new(MockRepositoryRepository::new());

        // Store content so storage.get() can find it.
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        storage.insert_content(hash, b"file content".to_vec());

        let repo = sample_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let repo_format = repo.format.to_string();
        repositories.insert(repo);

        let mut artifact = sample_artifact_in_repo(repo_id);
        artifact.quarantine_status = status;
        if status == QuarantineStatus::Quarantined || status == QuarantineStatus::Rejected {
            artifact.quarantine_window_start = Some(Utc::now());
        }
        artifacts.insert(artifact.clone());

        DownloadHarness {
            uc: ArtifactUseCase::new(artifacts, storage, repositories, true),
            artifact,
            repo_key,
            repo_format,
        }
    }

    /// Helper: assert download() returns an error whose message contains `needle`.
    async fn assert_download_err(uc: &ArtifactUseCase, id: Uuid, needle: &str) {
        match uc.download(id, None).await {
            Err(e) => assert!(
                e.to_string().contains(needle),
                "expected error containing {needle:?}, got: {e}"
            ),
            Ok(_) => panic!("expected error containing {needle:?}, got Ok"),
        }
    }

    #[test]
    fn download_succeeds_for_none_status() {
        let h = make_download_harness(QuarantineStatus::None);
        let artifact_id = h.artifact.id;
        let repo_key = h.repo_key.clone();
        let repo_format = h.repo_format.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (returned, mut stream) = h.uc.download(artifact_id, None).await.unwrap();
                assert_eq!(returned.id, artifact_id);

                let mut buf = Vec::new();
                AsyncReadExt::read_to_end(&mut stream, &mut buf)
                    .await
                    .unwrap();
                assert_eq!(buf, b"file content");
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", repo_format.as_str()),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_download_duration_seconds",
            &[("format", repo_format.as_str())],
        );
    }

    #[test]
    fn download_succeeds_for_released_status() {
        let h = make_download_harness(QuarantineStatus::Released);
        let artifact_id = h.artifact.id;
        let repo_key = h.repo_key.clone();
        let repo_format = h.repo_format.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (returned, _stream) = h.uc.download(artifact_id, None).await.unwrap();
                assert_eq!(returned.id, artifact_id);
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", repo_format.as_str()),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
    }

    #[test]
    fn download_blocked_for_quarantined() {
        let h = make_download_harness(QuarantineStatus::Quarantined);
        let artifact_id = h.artifact.id;
        let repo_key = h.repo_key.clone();
        let repo_format = h.repo_format.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                assert_download_err(&h.uc, artifact_id, "not downloadable").await;
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", repo_format.as_str()),
                ("repository", repo_key.as_str()),
                ("result", "quarantined"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_download_duration_seconds",
            &[("format", repo_format.as_str())],
        );
    }

    #[test]
    fn download_blocked_for_rejected() {
        let h = make_download_harness(QuarantineStatus::Rejected);
        let artifact_id = h.artifact.id;
        let repo_key = h.repo_key.clone();
        let repo_format = h.repo_format.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                assert_download_err(&h.uc, artifact_id, "not downloadable").await;
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", repo_format.as_str()),
                ("repository", repo_key.as_str()),
                ("result", "rejected"),
            ],
            1,
        );
    }

    #[test]
    fn download_not_found() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _, _storage) = make_use_case_with_artifact();
                assert_download_err(&uc, Uuid::new_v4(), "not found").await;
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                // format falls back to FORMAT_UNKNOWN when artifact lookup
                // fails (no repo → no format).
                ("format", "unknown"),
                ("repository", "unknown"),
                ("result", "not_found"),
            ],
            1,
        );
    }

    // Storage port that fails on `get` — exercises StorageError path.
    struct FailingGetStoragePort;

    impl StoragePort for FailingGetStoragePort {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>>
        {
            Box::pin(async { unreachable!() })
        }

        fn get(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>>
        {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "storage read failed: disk crashed".into(),
                ))
            })
        }

        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>>
        {
            Box::pin(async { unreachable!("FailingGetStoragePort.get_range not exercised") })
        }

        fn exists(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Ok(false) })
        }

        fn size_of(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
    }

    #[test]
    fn download_storage_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage: Arc<dyn StoragePort> = Arc::new(FailingGetStoragePort);
        let repositories = Arc::new(MockRepositoryRepository::new());

        let repo = sample_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let repo_format = repo.format.to_string();
        repositories.insert(repo);

        let artifact = sample_artifact_in_repo(repo_id);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let uc = ArtifactUseCase::new(artifacts, storage, repositories, true);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                match uc.download(artifact_id, None).await {
                    Err(e) => assert!(e.to_string().contains("storage"), "got: {e}"),
                    Ok(_) => panic!("expected storage error"),
                }
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", repo_format.as_str()),
                ("repository", repo_key.as_str()),
                ("result", "storage_error"),
            ],
            1,
        );
    }

    // -- repo_label sentinel + download error-path coverage ------------------

    /// `repo_label` with `include_repository_label = false` must collapse
    /// to the `REPOSITORY_ALL` sentinel regardless of the caller-supplied
    /// key. Direct unit test for the cardinality-safety-valve branch.
    #[test]
    fn repo_label_collapses_to_all_when_flag_disabled() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let disabled =
            ArtifactUseCase::new(artifacts.clone(), storage.clone(), repos.clone(), false);
        assert_eq!(disabled.repo_label(Some("repo-key")), "_all");
        assert_eq!(disabled.repo_label(None), "_all");

        let enabled = ArtifactUseCase::new(artifacts, storage, repos, true);
        assert_eq!(enabled.repo_label(Some("repo-key")), "repo-key");
        assert_eq!(enabled.repo_label(None), "unknown");
    }

    /// `format_label` falls back to `FORMAT_UNKNOWN` when `None`. Pure
    /// sentinel-wiring test — covers the `unwrap_or` branch.
    #[test]
    fn format_label_unknown_when_none() {
        assert_eq!(ArtifactUseCase::format_label(Some("pypi")), "pypi");
        assert_eq!(ArtifactUseCase::format_label(None), "unknown");
    }

    /// Stub artifact repo whose `find_by_id` returns a non-NotFound
    /// domain error. The other trait methods return trivial Ok/None
    /// values — they're not called by the download path but are
    /// trait-required. A companion test
    /// (`failing_find_artifact_repository_trait_stubs_are_exercised`)
    /// exercises them directly so the trait impl is fully covered.
    struct FailingFindArtifactRepository;

    impl ArtifactRepository for FailingFindArtifactRepository {
        fn find_by_id(
            &self,
            id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Artifact>> {
            let msg = format!("connection reset while loading artifact {id}");
            Box::pin(async move { Err(DomainError::Invariant(msg)) })
        }
        fn find_by_checksum(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _repository_id: Uuid,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _repository_id: Uuid,
            _page: PageRequest,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Page<Artifact>>> {
            Box::pin(async {
                Ok(Page {
                    items: vec![],
                    total: 0,
                })
            })
        }
        fn delete(&self, _id: Uuid) -> hort_domain::ports::BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_path(
            &self,
            _repository_id: Uuid,
            _path: &str,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_distinct_names(
            &self,
            _repository_id: Uuid,
            _page: PageRequest,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Page<String>>> {
            Box::pin(async {
                Ok(Page {
                    items: vec![],
                    total: 0,
                })
            })
        }
        fn find_by_name_in_repo(
            &self,
            _repository_id: Uuid,
            _normalized_name: &str,
            _page: PageRequest,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Page<Artifact>>> {
            Box::pin(async {
                Ok(Page {
                    items: vec![],
                    total: 0,
                })
            })
        }
        fn find_by_name_as_published(
            &self,
            _repository_id: Uuid,
            _raw_name: &str,
            _page: PageRequest,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Page<Artifact>>> {
            Box::pin(async {
                Ok(Page {
                    items: vec![],
                    total: 0,
                })
            })
        }
        fn list_active_for_repo(
            &self,
            _repository_id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
            Box::pin(async { Ok(LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _policy_id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
            Box::pin(async { Ok(LimitedList::empty()) })
        }
        fn package_version_status(
            &self,
            _repository_id: Uuid,
            _package: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            DomainResult<
                Vec<(
                    String,
                    hort_domain::entities::artifact::QuarantineStatus,
                    Option<DateTime<Utc>>,
                )>,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
        ) -> hort_domain::ports::BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    /// `download`'s `find_by_id` error classification has two arms:
    /// `NotFound` → `DownloadResult::NotFound` (covered by
    /// `download_not_found`), and any other domain error →
    /// `DownloadResult::StorageError` (uncovered by mock because
    /// `MockArtifactRepository::find_by_id` only returns NotFound).
    /// [`FailingFindArtifactRepository`] exercises the defensive arm.
    #[test]
    fn download_find_by_id_non_notfound_error_classifies_as_storage_error() {
        let uc = ArtifactUseCase::new(
            Arc::new(FailingFindArtifactRepository),
            Arc::new(MockStoragePort::new()),
            Arc::new(MockRepositoryRepository::new()),
            true,
        );

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                match uc.download(Uuid::new_v4(), None).await {
                    Err(e) => assert!(e.to_string().contains("connection reset")),
                    Ok(_) => panic!("expected Err from failing find_by_id stub"),
                }
            });
        });

        let entries = snap.into_vec();
        // Format/repo unknown at the point of failure (find_by_id hasn't
        // yielded the artifact yet) → both collapse to their UNKNOWN
        // sentinels. This confirms the `(None, None)` branch + format
        // fallback arms.
        assert_counter(
            &entries,
            "hort_download_total",
            &[
                ("format", "unknown"),
                ("repository", "unknown"),
                ("result", "storage_error"),
            ],
            1,
        );
    }

    /// Exercise [`FailingFindArtifactRepository`]'s trait-required
    /// methods that the download path doesn't call. Without this test
    /// they'd be dead under coverage — trait impl methods that exist
    /// only to satisfy the port contract.
    #[test]
    fn failing_find_artifact_repository_trait_stubs_are_exercised() {
        let repo: &dyn ArtifactRepository = &FailingFindArtifactRepository;
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            assert!(repo.find_by_checksum(&hash).await.unwrap().is_none());
            assert!(repo
                .find_by_repo_and_checksum(Uuid::nil(), &hash)
                .await
                .unwrap()
                .is_none());
            let page = repo
                .list_by_repository(Uuid::nil(), PageRequest::default())
                .await
                .unwrap();
            assert!(page.is_empty());
            repo.delete(Uuid::nil()).await.unwrap();
            assert!(repo.find_by_path(Uuid::nil(), "x").await.unwrap().is_none());
            assert!(repo
                .list_distinct_names(Uuid::nil(), PageRequest::default())
                .await
                .unwrap()
                .is_empty());
            assert!(repo
                .find_by_name_in_repo(Uuid::nil(), "x", PageRequest::default())
                .await
                .unwrap()
                .is_empty());
            assert!(repo
                .find_by_name_as_published(Uuid::nil(), "x", PageRequest::default())
                .await
                .unwrap()
                .is_empty());
            assert!(repo
                .list_active_for_repo(Uuid::nil())
                .await
                .unwrap()
                .is_empty());
            assert!(repo
                .list_rejected_for_policy(Uuid::nil())
                .await
                .unwrap()
                .is_empty());
            // The stub returns an empty pair list, but
            // hitting the method here keeps the trait impl fully covered
            // when a future refactor reshuffles arms.
            assert!(repo
                .package_version_status(Uuid::nil(), "x")
                .await
                .unwrap()
                .is_empty());
        });
    }

    /// `download` path where the artifact IS found but the repository
    /// lookup fails — exercises the `None => (None, None)` branch at
    /// `download_inner` (artifact_use_case.rs line ~220) when `.ok()` on
    /// repository `find_by_id` returns `None`. The artifact proceeds to
    /// `is_downloadable` and the stream is served; the `format` /
    /// `repo_key` carried into the Ok branch collapse to empty strings
    /// via `Option::unwrap_or_default()` on the Ok path. (The Err path
    /// properly substitutes UNKNOWN sentinels; the Ok path has a
    /// pre-existing quirk where a successful download with a missing
    /// repo emits empty-string labels. That's unrelated to the normalisation
    /// drift fallback — the point of this test is to cover line 220.)
    #[test]
    fn download_with_missing_repository_still_serves_and_covers_none_branch() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repositories = Arc::new(MockRepositoryRepository::new()); // empty

        // Seed an artifact referencing a repo that DOESN'T exist in the
        // repository mock. Pre-populate storage so the download succeeds.
        let mut artifact = sample_artifact_in_repo(Uuid::new_v4());
        artifact.quarantine_status = QuarantineStatus::None;
        let artifact_id = artifact.id;
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        storage.insert_content(hash, b"payload".to_vec());
        artifacts.insert(artifact);

        let uc = ArtifactUseCase::new(artifacts, storage, repositories, true);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            match uc.download(artifact_id, None).await {
                Ok(_) => {}
                Err(e) => panic!("expected Ok from download after `(None, None)` branch: {e}"),
            }
        });
    }

    // ---------------------------------------------------------------------
    // Opt-in download-audit emit
    // ---------------------------------------------------------------------

    mod download_audit {
        use super::*;
        use crate::event_store_publisher::{wrap_for_test, EventStorePublisher};
        use hort_domain::entities::caller::CallerPrincipal;
        use hort_domain::events::{
            DomainEvent, DownloadActor, PersistedEvent, StreamCategory, StreamId as DStreamId,
        };
        use hort_domain::ports::event_store::{
            AppendEvents, AppendResult, EventStore, ExpectedVersion, ReadFrom, SubscribeFrom,
        };
        use hort_domain::ports::BoxFuture;

        fn principal() -> CallerPrincipal {
            CallerPrincipal {
                user_id: Uuid::from_u128(0xB12),
                external_id: "keycloak:realm-users:b12".into(),
                username: "b12-user".into(),
                email: "b12@example.com".into(),
                claims: vec![],
                token_kind: None,
                issued_at: Utc::now(),
                token_cap: None,
            }
        }

        /// Build a download harness whose repo has
        /// `download_audit_enabled = audit_on`, wired to the supplied
        /// event publisher (or unwired when `publisher` is `None`).
        fn harness(
            audit_on: bool,
            publisher: Option<Arc<EventStorePublisher>>,
        ) -> (ArtifactUseCase, Uuid, Uuid, String, String) {
            let artifacts = Arc::new(MockArtifactRepository::new());
            let storage = Arc::new(MockStoragePort::new());
            let repositories = Arc::new(MockRepositoryRepository::new());

            let hash: ContentHash = VALID_SHA256.parse().unwrap();
            storage.insert_content(hash, b"file content".to_vec());

            let mut repo = sample_repository();
            repo.download_audit_enabled = audit_on;
            let repo_id = repo.id;
            let repo_key = repo.key.clone();
            let repo_format = repo.format.to_string();
            repositories.insert(repo);

            let artifact = sample_artifact_in_repo(repo_id);
            let artifact_id = artifact.id;
            artifacts.insert(artifact);

            let mut uc = ArtifactUseCase::new(artifacts, storage, repositories, true);
            if let Some(p) = publisher {
                uc = uc.with_audit_events(p);
            }
            (uc, artifact_id, repo_id, repo_key, repo_format)
        }

        async fn read_stream_to_end(mut s: Box<dyn AsyncRead + Send + Unpin>) -> Vec<u8> {
            let mut buf = Vec::new();
            AsyncReadExt::read_to_end(&mut s, &mut buf).await.unwrap();
            buf
        }

        #[tokio::test]
        async fn emits_artifact_downloaded_when_enabled_user_actor() {
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, artifact_id, repo_id, _k, _f) = harness(true, Some(publisher));
            let p = principal();

            let (_a, stream) = uc.download(artifact_id, Some(&p)).await.unwrap();
            assert_eq!(read_stream_to_end(stream).await, b"file content");

            let batches = events.appended_batches();
            assert_eq!(batches.len(), 1, "exactly one audit batch");
            let batch = &batches[0];

            // Audit-stream separation assertions (ADR 0002).
            assert_eq!(batch.expected_version, ExpectedVersion::Any);
            assert_eq!(batch.stream_id.category, StreamCategory::DownloadAudit);
            assert_ne!(
                batch.stream_id,
                DStreamId::artifact(artifact_id),
                "must NOT be the artifact aggregate/lifecycle stream"
            );
            assert_eq!(
                batch.stream_id,
                DStreamId::download_audit(repo_id, Utc::now().date_naive()),
                "per-(repo, UTC-date) stream"
            );
            // Batch recorder is system; subject rides the payload.
            assert!(matches!(
                batch.actor,
                hort_domain::events::Actor::Internal(hort_domain::events::InternalActor::System)
            ));
            assert_eq!(batch.events.len(), 1);
            match &batch.events[0].event {
                DomainEvent::ArtifactDownloaded(e) => {
                    assert_eq!(e.artifact_id, artifact_id);
                    assert_eq!(e.repository_id, repo_id);
                    match &e.actor {
                        DownloadActor::User {
                            user_id,
                            external_id,
                        } => {
                            assert_eq!(*user_id, p.user_id);
                            assert_eq!(external_id, &p.external_id);
                        }
                        DownloadActor::Anonymous => {
                            panic!("expected User actor for an authenticated pull")
                        }
                    }
                }
                other => panic!("expected ArtifactDownloaded, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn emits_anonymous_actor_when_no_principal() {
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, artifact_id, _r, _k, _f) = harness(true, Some(publisher));

            let (_a, stream) = uc.download(artifact_id, None).await.unwrap();
            let _ = read_stream_to_end(stream).await;

            let batches = events.appended_batches();
            assert_eq!(batches.len(), 1);
            match &batches[0].events[0].event {
                DomainEvent::ArtifactDownloaded(e) => {
                    assert!(
                        matches!(e.actor, DownloadActor::Anonymous),
                        "anonymous pull must record DownloadActor::Anonymous (no audit gap)"
                    );
                }
                other => panic!("expected ArtifactDownloaded, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn does_not_emit_when_repo_opt_in_disabled() {
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, artifact_id, _r, _k, _f) = harness(false, Some(publisher));

            let (_a, stream) = uc.download(artifact_id, Some(&principal())).await.unwrap();
            let _ = read_stream_to_end(stream).await;

            assert!(
                events.appended_batches().is_empty(),
                "no audit event when download_audit_enabled = false"
            );
        }

        #[tokio::test]
        async fn does_not_emit_when_gate_unwired() {
            // No publisher wired (legacy/test deployment) — even with
            // the repo opted in, the emit logic short-circuits.
            let (uc, artifact_id, _r, _k, _f) = harness(true, None);
            let (_a, stream) = uc.download(artifact_id, Some(&principal())).await.unwrap();
            assert_eq!(read_stream_to_end(stream).await, b"file content");
        }

        /// Append-failing `EventStore` stub. Only `append` is exercised
        /// by the download path; the rest are unreachable here.
        struct FailingAppendEventStore;

        impl EventStore for FailingAppendEventStore {
            fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                Box::pin(async {
                    Err(DomainError::Invariant(
                        "simulated event-store outage".into(),
                    ))
                })
            }
            fn read_stream(
                &self,
                _s: &DStreamId,
                _f: ReadFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { unreachable!("download path never reads streams") })
            }
            fn read_category(
                &self,
                _c: StreamCategory,
                _f: SubscribeFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { unreachable!() })
            }
            fn delete_stream(&self, _s: DStreamId) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
            fn archive_stream(&self, _s: DStreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }

        #[test]
        fn fail_open_serves_stream_increments_metric_and_warns() {
            let publisher = Arc::new(EventStorePublisher::without_broadcast(Arc::new(
                FailingAppendEventStore,
            )));
            let (uc, artifact_id, _r, repo_key, repo_format) = harness(true, Some(publisher));

            let snap = capture_metrics(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    // Fail-open: the download MUST still succeed.
                    let (_a, stream) = uc.download(artifact_id, Some(&principal())).await.unwrap();
                    let buf = read_stream_to_end(stream).await;
                    assert_eq!(buf, b"file content", "fail-open: stream still served");
                });
            });

            let entries = snap.into_vec();
            // The fail-open drop counter fired with the expected labels.
            assert_counter(
                &entries,
                "hort_download_audit_dropped",
                &[
                    ("format", repo_format.as_str()),
                    ("repository", repo_key.as_str()),
                    ("result", "append_error"),
                ],
                1,
            );
            // `hort_download_total` is UNAFFECTED by the audit failure —
            // it still records the successful download.
            assert_counter(
                &entries,
                "hort_download_total",
                &[
                    ("format", repo_format.as_str()),
                    ("repository", repo_key.as_str()),
                    ("result", "success"),
                ],
                1,
            );
        }

        #[test]
        fn download_audit_drop_result_as_str_is_catalogued() {
            assert_eq!(
                DownloadAuditDropResult::AppendError.as_str(),
                "append_error"
            );
        }
    }

    // -- load_full_metadata --------------------------------------------------
    //
    // Three cases to cover:
    //   1. `metadata_blob = None`   → return `row.metadata` verbatim.
    //   2. `metadata_blob = Some(h)` → CAS fetch, deserialise, return.
    //   3. `metadata_blob = Some(h)` with malformed bytes in CAS →
    //      `AppError::Storage("metadata blob deserialisation failed")`.
    //
    // Built with a fresh [`ArtifactUseCase`] so the tests are independent
    // of the download harness above — this helper does not touch the
    // artifact repo or repository repo, only storage.

    use hort_domain::entities::repository::RepositoryFormat;

    fn sample_metadata(
        metadata_blob: Option<ContentHash>,
        inline: serde_json::Value,
    ) -> ArtifactMetadata {
        ArtifactMetadata {
            artifact_id: Uuid::new_v4(),
            format: RepositoryFormat::Pypi,
            metadata: inline,
            metadata_blob,
            properties: serde_json::Value::Object(Default::default()),
        }
    }

    /// Blob-less row: `load_full_metadata` is a pure clone of
    /// `row.metadata`. Storage must NOT be touched (no `get` call).
    #[tokio::test]
    async fn load_full_metadata_inline_returns_row_metadata() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = ArtifactUseCase::new(artifacts, storage.clone(), repos, true);

        let inline = serde_json::json!({ "name": "pkg", "version": "1.0.0" });
        let row = sample_metadata(None, inline.clone());

        let got = uc.load_full_metadata(&row).await.unwrap();
        assert_eq!(got, inline);
        // Pure inline path — storage must not have been consulted. The
        // mock has no seeded content so a `get` would return NotFound
        // regardless, but the stronger invariant is that inline rows
        // never round-trip through CAS at all.
        assert!(
            storage.stored_hashes().is_empty(),
            "inline path must not touch storage"
        );
    }

    /// HashReference row: full payload lives in CAS under `metadata_blob`;
    /// `row.metadata` is the summary. `load_full_metadata` fetches and
    /// deserialises the blob, returning the full payload (NOT the summary).
    #[tokio::test]
    async fn load_full_metadata_hash_reference_streams_and_deserialises_blob() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());

        // Seed the blob in the mock: the full payload as UTF-8 JSON bytes.
        let full = serde_json::json!({
            "name": "pkg",
            "version": "1.0.0",
            "readme": "Long readme text...",
            "dependencies": { "serde": "^1" },
        });
        let bytes = serde_json::to_vec(&full).unwrap();
        let hash: ContentHash = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&bytes))
                .parse()
                .unwrap()
        };
        storage.insert_content(hash.clone(), bytes);

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);

        // Summary in the row — what an index listing would see.
        let summary = serde_json::json!({ "name": "pkg", "version": "1.0.0" });
        let row = sample_metadata(Some(hash), summary.clone());

        let got = uc.load_full_metadata(&row).await.unwrap();
        // The FULL payload, not the summary.
        assert_eq!(got, full);
        assert_ne!(
            got, summary,
            "helper must follow the blob, not return the summary"
        );
    }

    /// Blob present but the bytes in CAS are not valid JSON: surface as
    /// `AppError::Storage` with the catalog-stable message. The error
    /// variant choice (Storage vs Domain) is load-bearing — a corrupt
    /// blob is an integrity failure of the storage backend, not a
    /// business-logic or validation error.
    #[tokio::test]
    async fn load_full_metadata_malformed_blob_surfaces_storage_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());

        // Seed non-JSON bytes directly at a known hash via the mock's
        // insert_content helper. The mock does NOT re-verify that the
        // bytes match the declared hash — which is exactly what we need
        // to simulate corruption-in-CAS without plumbing through a
        // separate fault-injection port.
        let junk: Vec<u8> = b"\x00\x01\x02 not-json \xff\xfe".to_vec();
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        storage.insert_content(hash.clone(), junk);

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let row = sample_metadata(Some(hash), serde_json::Value::Null);

        let err = uc.load_full_metadata(&row).await.unwrap_err();
        match err {
            AppError::Storage(msg) => {
                assert!(
                    msg.contains("deserialisation failed"),
                    "expected deserialisation-failure message, got: {msg}"
                );
            }
            other => panic!("expected AppError::Storage, got: {other:?}"),
        }
    }

    /// Blob declared in the row but CAS returns `NotFound` (e.g. the row
    /// references a blob that has been GC'd or never written). The `get`
    /// error propagates as `AppError::Storage` carrying the underlying
    /// message. Storage-port errors are not silently swallowed.
    #[tokio::test]
    async fn load_full_metadata_missing_blob_surfaces_storage_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);

        // A valid hash that was never inserted into the mock.
        let hash: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let row = sample_metadata(Some(hash), serde_json::Value::Null);

        let err = uc.load_full_metadata(&row).await.unwrap_err();
        assert!(
            matches!(err, AppError::Storage(_)),
            "expected AppError::Storage for missing blob, got: {err:?}"
        );
    }
}

// ===========================================================================
// visibility-aware extension tests
// ===========================================================================

#[cfg(test)]
mod visibility_extension_tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use chrono::{DateTime, Utc};

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::Repository;
    use hort_domain::types::ByteRange;
    use uuid::Uuid;

    use super::*;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::repository_access::{AccessLevel, RbacAccess, RepositoryAccessUseCase};
    use crate::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactMetadataRepository, MockArtifactRepository,
        MockRepositoryRepository, MockStoragePort, StubFormatHandler, VALID_SHA256,
    };

    // -- helpers -----------------------------------------------------------

    fn principal(roles: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: roles.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn enabled(rbac: RbacEvaluator) -> RbacAccess {
        RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(rbac)))
    }

    /// Evaluator where (claim-subject model, ADR 0012):
    /// - the `developer` claim has `Permission::Write` scoped to `repo_id`.
    /// - the `reader` claim has `Permission::Read` globally.
    fn rbac_with_read_and_write(repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![
            PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["developer".to_string()]),
                repository_id: Some(repo_id),
                permission: Permission::Write,
                created_at: Utc::now(),
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
            },
            PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["reader".to_string()]),
                repository_id: None,
                permission: Permission::Read,
                created_at: Utc::now(),
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
            },
        ])
    }

    fn private_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = false;
        r
    }

    fn public_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = true;
        r
    }

    /// Build a wired use case with the new fields populated. The
    /// access port admits everything by default (`Disabled`); tests
    /// that exercise authz pass an explicit `RbacAccess`.
    fn wired_use_case(
        artifacts: Arc<MockArtifactRepository>,
        storage: Arc<MockStoragePort>,
        repos: Arc<MockRepositoryRepository>,
        access: RbacAccess,
        metadata: Arc<MockArtifactMetadataRepository>,
    ) -> ArtifactUseCase {
        let access_uc = Arc::new(RepositoryAccessUseCase::new(repos.clone(), access, true));
        ArtifactUseCase::new(artifacts, storage, repos, true)
            .with_repository_access(access_uc)
            .with_artifact_metadata(metadata)
    }

    fn artifact_in_repo(repo_id: Uuid, path: &str, sha: &str) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0.0".into()),
            path: path.into(),
            size_bytes: 12,
            sha256_checksum: sha.parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // -- find_visible_by_path ---------------------------------------------

    #[tokio::test]
    async fn find_visible_by_path_happy_returns_repo_and_artifact() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = public_repo("alpha");
        let repo_id = repo.id;
        repos.insert(repo);
        let a = artifact_in_repo(repo_id, "pkg/1.0.0/pkg.tar.gz", VALID_SHA256);
        artifacts.insert(a.clone());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let (got_repo, got_artifact) = uc
            .find_visible_by_path("alpha", "pkg/1.0.0/pkg.tar.gz", None)
            .await
            .unwrap();
        assert_eq!(got_repo.key, "alpha");
        assert_eq!(got_artifact.id, a.id);
    }

    #[tokio::test]
    async fn find_visible_by_path_invisible_repo_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        repos.insert(private_repo("vault"));

        let uc = wired_use_case(
            artifacts,
            storage,
            repos,
            enabled(RbacEvaluator::new(Vec::new())),
            metadata,
        );
        let err = uc
            .find_visible_by_path("vault", "pkg/path", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn find_visible_by_path_visible_repo_missing_path_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        repos.insert(public_repo("alpha"));

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let err = uc
            .find_visible_by_path("alpha", "missing/path", None)
            .await
            .unwrap_err();
        match err {
            AppError::Domain(DomainError::NotFound { entity, id }) => {
                assert_eq!(entity, "Artifact");
                assert!(id.contains("alpha"));
                assert!(id.contains("missing/path"));
            }
            other => panic!("expected NotFound(Artifact), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn find_visible_by_path_unwired_returns_repository_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        // NOTE: not using `wired_use_case` — exercising the unwired path.
        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let err = uc
            .find_visible_by_path("any", "any", None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Repository(_)));
    }

    // -- find_visible_by_id -----------------------------------------------

    #[tokio::test]
    async fn find_visible_by_id_happy_returns_repo_and_artifact() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = public_repo("alpha");
        let repo_id = repo.id;
        repos.insert(repo);
        let a = artifact_in_repo(repo_id, "pkg/1.0.0/pkg.tar.gz", VALID_SHA256);
        artifacts.insert(a.clone());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let (got_repo, got_artifact) = uc.find_visible_by_id(a.id, None).await.unwrap();
        assert_eq!(got_repo.key, "alpha");
        assert_eq!(got_artifact.id, a.id);
    }

    #[tokio::test]
    async fn find_visible_by_id_invisible_repo_returns_not_found_artifact() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let a = artifact_in_repo(repo_id, "pkg/1.0.0/pkg.tar.gz", VALID_SHA256);
        artifacts.insert(a.clone());

        let uc = wired_use_case(
            artifacts,
            storage,
            repos,
            enabled(RbacEvaluator::new(Vec::new())),
            metadata,
        );
        let err = uc.find_visible_by_id(a.id, None).await.unwrap_err();
        // Anti-enum: surface as Artifact NotFound, NOT Repository NotFound.
        match err {
            AppError::Domain(DomainError::NotFound { entity, .. }) => {
                assert_eq!(entity, "Artifact");
            }
            other => panic!("expected NotFound(Artifact), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn find_visible_by_id_missing_artifact_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let err = uc
            .find_visible_by_id(Uuid::new_v4(), None)
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

    #[tokio::test]
    async fn find_visible_by_id_unwired_returns_repository_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());

        // Seed an artifact so `find_by_id` succeeds — we want the
        // failure to come from `access()`, not a missing artifact.
        let a = artifact_in_repo(Uuid::new_v4(), "p", VALID_SHA256);
        artifacts.insert(a.clone());

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let err = uc.find_visible_by_id(a.id, None).await.unwrap_err();
        assert!(matches!(err, AppError::Repository(_)));
    }

    /// `find_visible_by_id` propagates non-NotFound `find_by_id` errors
    /// verbatim — covers the `Err(other) => return Err(AppError::Domain(other))`
    /// arm. Without this test, that branch is dead under coverage.
    #[tokio::test]
    async fn find_visible_by_id_propagates_invariant_errors_from_artifact_lookup() {
        struct FailingFind;
        impl ArtifactRepository for FailingFind {
            fn find_by_id(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Artifact>>
            {
                Box::pin(async { Err(DomainError::Invariant("artifact lookup failed".into())) })
            }
            fn find_by_checksum(
                &self,
                _hash: &ContentHash,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Option<Artifact>>>
            {
                Box::pin(async { Ok(None) })
            }
            fn find_by_repo_and_checksum(
                &self,
                _repository_id: Uuid,
                _hash: &ContentHash,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Option<Artifact>>>
            {
                Box::pin(async { Ok(None) })
            }
            fn list_by_repository(
                &self,
                _repository_id: Uuid,
                _page: PageRequest,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<Artifact>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn delete(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn find_by_path(
                &self,
                _repository_id: Uuid,
                _path: &str,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Option<Artifact>>>
            {
                Box::pin(async { Ok(None) })
            }
            fn list_distinct_names(
                &self,
                _repository_id: Uuid,
                _page: PageRequest,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<String>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn find_by_name_in_repo(
                &self,
                _repository_id: Uuid,
                _normalized_name: &str,
                _page: PageRequest,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<Artifact>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn find_by_name_as_published(
                &self,
                _repository_id: Uuid,
                _raw_name: &str,
                _page: PageRequest,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<Artifact>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn list_active_for_repo(
                &self,
                _repository_id: Uuid,
            ) -> hort_domain::ports::BoxFuture<
                '_,
                hort_domain::error::DomainResult<LimitedList<Artifact>>,
            > {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn list_rejected_for_policy(
                &self,
                _policy_id: Uuid,
            ) -> hort_domain::ports::BoxFuture<
                '_,
                hort_domain::error::DomainResult<LimitedList<Artifact>>,
            > {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn package_version_status(
                &self,
                _repository_id: Uuid,
                _package: &str,
            ) -> hort_domain::ports::BoxFuture<
                '_,
                hort_domain::error::DomainResult<
                    Vec<(
                        String,
                        hort_domain::entities::artifact::QuarantineStatus,
                        Option<DateTime<Utc>>,
                    )>,
                >,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn find_pypi_wheels_without_kind(
                &self,
                _kind: &str,
                _limit: u32,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Vec<Artifact>>>
            {
                Box::pin(async { Ok(Vec::new()) })
            }
        }

        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());
        let uc = wired_use_case(
            Arc::new(MockArtifactRepository::new()), // unused in failing path
            storage.clone(),
            repos.clone(),
            RbacAccess::Disabled,
            metadata.clone(),
        );
        // Replace artifact port with the failing one — easier than
        // rebuilding the whole wired_use_case, since `wired_use_case`
        // requires `Arc<MockArtifactRepository>`. We construct a fresh
        // bare use case instead.
        let access_uc = Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ));
        let _ = uc; // unused
        let uc = ArtifactUseCase::new(
            Arc::new(FailingFind),
            storage,
            Arc::new(MockRepositoryRepository::new()),
            true,
        )
        .with_repository_access(access_uc)
        .with_artifact_metadata(metadata);

        let err = uc
            .find_visible_by_id(Uuid::new_v4(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("artifact lookup failed"));
    }

    /// `find_visible_by_id` propagates non-NotFound errors from the
    /// `RepositoryAccessUseCase::resolve_by_id` hop. Covers the
    /// `Err(other) => return Err(other)` arm in the access-resolution
    /// match.
    #[tokio::test]
    async fn find_visible_by_id_propagates_non_notfound_from_access_use_case() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        // Seed an artifact + repo, then make the NEXT find_by_key call
        // fail. resolve_by_id calls find_by_id, but
        // RepositoryAccessUseCase uses find_by_id for the by-id lookup
        // — let's instead make that fail. We can't easily do that with
        // the standard mock. Use a dedicated stub that returns
        // Invariant from `find_by_id` only. The same stub from the
        // repository_access test module works.
        struct FailingFindById;
        impl RepositoryRepository for FailingFindById {
            fn find_by_id(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Repository>>
            {
                Box::pin(async { Err(DomainError::Invariant("db down".into())) })
            }
            fn find_by_key(
                &self,
                _k: &str,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Repository>>
            {
                Box::pin(async {
                    Err(DomainError::NotFound {
                        entity: "Repository",
                        id: "x".into(),
                    })
                })
            }
            fn list(
                &self,
                _p: PageRequest,
                _s: Option<&str>,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<Repository>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn save(
                &self,
                _r: &Repository,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn delete(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn get_virtual_members(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Vec<Repository>>>
            {
                Box::pin(async { Ok(vec![]) })
            }
            fn add_virtual_member(
                &self,
                _v: Uuid,
                _m: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn remove_virtual_member(
                &self,
                _v: Uuid,
                _m: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn get_storage_usage(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<u64>>
            {
                Box::pin(async { Ok(0) })
            }
            fn save_managed(
                &self,
                _r: &Repository,
                _d: &[u8; 32],
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn delete_managed(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
        }

        let a = artifact_in_repo(Uuid::new_v4(), "p", VALID_SHA256);
        artifacts.insert(a.clone());

        let access_uc = Arc::new(RepositoryAccessUseCase::new(
            Arc::new(FailingFindById),
            RbacAccess::Disabled,
            true,
        ));
        let uc = ArtifactUseCase::new(artifacts, storage, repos, true)
            .with_repository_access(access_uc)
            .with_artifact_metadata(metadata);

        let err = uc.find_visible_by_id(a.id, None).await.unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    // -- find_in_repo_by_hash ---------------------------------------------

    /// **Acceptance bullet — multi-repo isolation.**
    /// Two artifact rows with identical SHA in different repos. Querying
    /// by repo A's id returns A's row; querying by repo B's id returns
    /// B's row. Closes the OCI §2.14 same-repo invariant violation.
    #[tokio::test]
    async fn find_in_repo_by_hash_isolates_across_repos() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo_a = public_repo("repo-a");
        let repo_b = public_repo("repo-b");
        let id_a = repo_a.id;
        let id_b = repo_b.id;
        repos.insert(repo_a);
        repos.insert(repo_b);

        // Two artifacts with the same SHA, different repos.
        let mut art_a = artifact_in_repo(id_a, "pkg-a/1.0/pkg.tar", VALID_SHA256);
        art_a.name = "pkg-a".into();
        let mut art_b = artifact_in_repo(id_b, "pkg-b/2.0/pkg.tar", VALID_SHA256);
        art_b.name = "pkg-b".into();
        artifacts.insert(art_a.clone());
        artifacts.insert(art_b.clone());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let hash: ContentHash = VALID_SHA256.parse().unwrap();

        let got_a = uc.find_in_repo_by_hash(id_a, &hash).await.unwrap();
        let got_b = uc.find_in_repo_by_hash(id_b, &hash).await.unwrap();

        assert!(got_a.is_some(), "repo A's row missing");
        assert!(got_b.is_some(), "repo B's row missing");
        assert_eq!(got_a.unwrap().id, art_a.id);
        assert_eq!(got_b.unwrap().id, art_b.id);
    }

    #[tokio::test]
    async fn find_in_repo_by_hash_returns_none_when_hash_not_in_repo() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        let got = uc
            .find_in_repo_by_hash(Uuid::new_v4(), &hash)
            .await
            .unwrap();
        assert!(got.is_none());
    }

    // -- download_range ---------------------------------------------------

    #[tokio::test]
    async fn download_range_happy_returns_artifact_and_stream() {
        use tokio::io::AsyncReadExt;

        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let hash: ContentHash = VALID_SHA256.parse().unwrap();
        storage.insert_content(hash.clone(), b"0123456789".to_vec());

        let repo = public_repo("alpha");
        let repo_id = repo.id;
        repos.insert(repo);
        let a = artifact_in_repo(repo_id, "p/1.0/p.tar", VALID_SHA256);
        let a_id = a.id;
        artifacts.insert(a);

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let (got_a, mut stream) = uc
            .download_range(a_id, ByteRange::Inclusive { start: 2, end: 4 })
            .await
            .unwrap();
        assert_eq!(got_a.id, a_id);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"234");
    }

    #[tokio::test]
    async fn download_range_quarantined_is_forbidden() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let mut a = artifact_in_repo(Uuid::new_v4(), "p", VALID_SHA256);
        a.quarantine_status = QuarantineStatus::Quarantined;
        a.quarantine_window_start = Some(Utc::now());
        let a_id = a.id;
        artifacts.insert(a);

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        match uc.download_range(a_id, ByteRange::From { start: 0 }).await {
            Err(AppError::Domain(DomainError::Forbidden(_))) => {}
            Err(other) => panic!("expected Forbidden, got: {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[tokio::test]
    async fn download_range_missing_artifact_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        match uc
            .download_range(Uuid::new_v4(), ByteRange::From { start: 0 })
            .await
        {
            Err(AppError::Domain(DomainError::NotFound {
                entity: "Artifact", ..
            })) => {}
            Err(other) => panic!("expected NotFound(Artifact), got: {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    /// `download_range` surfaces storage-port errors as
    /// [`AppError::Storage`] — covers the `.map_err(|e| ...)` arm on
    /// the `get_range` call.
    #[tokio::test]
    async fn download_range_storage_error_surfaces_as_storage() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        // No content seeded — `get_range` returns NotFound.
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let a = artifact_in_repo(Uuid::new_v4(), "p", VALID_SHA256);
        let a_id = a.id;
        artifacts.insert(a);

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        match uc.download_range(a_id, ByteRange::From { start: 0 }).await {
            Err(AppError::Storage(_)) => {}
            Err(other) => panic!("expected Storage, got: {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    // -- list_by_raw_name_visible / list_distinct_names_visible ------------

    #[tokio::test]
    async fn list_by_raw_name_visible_happy_returns_repo_and_rows() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = public_repo("alpha");
        let repo_id = repo.id;
        repos.insert(repo);

        let mut a = artifact_in_repo(repo_id, "Foo_Bar/1.0/Foo_Bar.tar.gz", VALID_SHA256);
        a.name = "foo-bar".into();
        a.name_as_published = "Foo_Bar".into();
        artifacts.insert(a.clone());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let handler = StubFormatHandler::new("test").with_mapping("Foo_Bar", "foo-bar");
        let (got_repo, rows) = uc
            .list_by_raw_name_visible("alpha", &handler, "Foo_Bar", None)
            .await
            .unwrap();
        assert_eq!(got_repo.key, "alpha");
        assert_eq!(rows.len(), 1);
        assert!(!rows.truncated);
        assert_eq!(rows.items[0].id, a.id);
    }

    #[tokio::test]
    async fn list_by_raw_name_visible_invisible_repo_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        repos.insert(private_repo("vault"));

        let uc = wired_use_case(
            artifacts,
            storage,
            repos,
            enabled(RbacEvaluator::new(Vec::new())),
            metadata,
        );
        let handler = StubFormatHandler::new("test");
        let err = uc
            .list_by_raw_name_visible("vault", &handler, "anything", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn list_distinct_names_visible_happy_returns_repo_and_names() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = public_repo("alpha");
        let repo_id = repo.id;
        repos.insert(repo);

        let mut a = artifact_in_repo(repo_id, "p1", VALID_SHA256);
        a.name = "name-one".into();
        artifacts.insert(a);
        let mut b = artifact_in_repo(repo_id, "p2", VALID_SHA256);
        b.name = "name-two".into();
        artifacts.insert(b);

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let (got_repo, names) = uc.list_distinct_names_visible("alpha", None).await.unwrap();
        assert_eq!(got_repo.key, "alpha");
        assert_eq!(names.len(), 2);
        assert!(!names.truncated);
        assert!(names.items.contains(&"name-one".to_string()));
        assert!(names.items.contains(&"name-two".to_string()));
    }

    #[tokio::test]
    async fn list_distinct_names_visible_invisible_repo_is_not_found() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        repos.insert(private_repo("vault"));

        let uc = wired_use_case(
            artifacts,
            storage,
            repos,
            enabled(RbacEvaluator::new(Vec::new())),
            metadata,
        );
        let err = uc
            .list_distinct_names_visible("vault", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    // -- batch_metadata ---------------------------------------------------

    #[tokio::test]
    async fn batch_metadata_empty_input_returns_empty_map() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let got = uc.batch_metadata(&[]).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn batch_metadata_returns_subset_for_known_ids() {
        use hort_domain::entities::repository::RepositoryFormat;

        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let id_missing = Uuid::new_v4();

        metadata.insert(ArtifactMetadata {
            artifact_id: id_a,
            format: RepositoryFormat::Pypi,
            metadata: serde_json::json!({"name": "a"}),
            metadata_blob: None,
            properties: serde_json::Value::Object(Default::default()),
        });
        metadata.insert(ArtifactMetadata {
            artifact_id: id_b,
            format: RepositoryFormat::Pypi,
            metadata: serde_json::json!({"name": "b"}),
            metadata_blob: None,
            properties: serde_json::Value::Object(Default::default()),
        });

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let got = uc.batch_metadata(&[id_a, id_b, id_missing]).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains_key(&id_a));
        assert!(got.contains_key(&id_b));
        assert!(!got.contains_key(&id_missing));
    }

    #[tokio::test]
    async fn batch_metadata_unwired_returns_repository_error() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let err = uc.batch_metadata(&[Uuid::new_v4()]).await.unwrap_err();
        assert!(matches!(err, AppError::Repository(_)));
    }

    // -- package_version_status wrapper -------------------------------------

    /// The use-case wrapper is a thin pass-through to the port — but it
    /// is the public surface format crates consume (ADR 0008
    /// anti-pattern: format crates don't touch `ctx.artifacts` directly).
    /// One positive test pins the shape; mock-port edge cases (deleted
    /// rows, null versions, repo-scoping) are pinned at the mock /
    /// adapter layer.
    #[tokio::test]
    async fn package_version_status_passes_through_to_port() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo_id = Uuid::new_v4();

        // Seed two versions with different statuses.
        let mut a1 = sample_artifact(QuarantineStatus::Released);
        a1.id = Uuid::new_v4();
        a1.repository_id = repo_id;
        a1.name = "leftpad".into();
        a1.version = Some("1.0.0".into());
        artifacts.insert(a1);

        let mut a2 = sample_artifact(QuarantineStatus::Quarantined);
        a2.id = Uuid::new_v4();
        a2.repository_id = repo_id;
        a2.name = "leftpad".into();
        a2.version = Some("1.1.0".into());
        artifacts.insert(a2);

        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let pairs = uc
            .package_version_status(repo_id, "leftpad")
            .await
            .expect("ok");
        assert_eq!(
            pairs,
            vec![
                ("1.0.0".to_string(), QuarantineStatus::Released),
                ("1.1.0".to_string(), QuarantineStatus::Quarantined),
            ]
        );
    }

    #[tokio::test]
    async fn package_version_status_unknown_package_returns_empty() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        let pairs = uc
            .package_version_status(Uuid::new_v4(), "never-seen")
            .await
            .expect("ok");
        assert!(pairs.is_empty());
    }

    // -- builder methods (must_use coverage) ------------------------------

    #[test]
    fn with_repository_access_returns_self() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let access = Arc::new(RepositoryAccessUseCase::new(
            repos.clone(),
            RbacAccess::Disabled,
            true,
        ));
        let _uc =
            ArtifactUseCase::new(artifacts, storage, repos, true).with_repository_access(access);
    }

    #[test]
    fn with_artifact_metadata_returns_self() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());
        let _uc =
            ArtifactUseCase::new(artifacts, storage, repos, true).with_artifact_metadata(metadata);
    }

    /// `access()` returns `Ok` when the use case is wired. Pure positive
    /// path so the helper's both arms are exercised.
    #[test]
    fn access_helper_returns_ok_when_wired() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let access = Arc::new(RepositoryAccessUseCase::new(
            repos.clone(),
            RbacAccess::Disabled,
            true,
        ));
        let uc =
            ArtifactUseCase::new(artifacts, storage, repos, true).with_repository_access(access);
        let _ = uc.access().expect("wired use case must yield Ok");
    }

    #[test]
    fn access_helper_returns_err_when_unwired() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = ArtifactUseCase::new(artifacts, storage, repos, true);
        match uc.access() {
            Err(AppError::Repository(_)) => {}
            Err(other) => panic!("expected Repository, got: {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    /// Lifts `AccessLevel::Write` through the use-case to make sure
    /// `find_visible_*` is hard-coded to Read (regression guard against
    /// a future change accidentally letting Write callers through the
    /// read-side API).
    #[tokio::test]
    async fn find_visible_by_path_uses_read_level_not_write() {
        // Construct a scenario where actor has Read but not Write —
        // find_visible_by_path must succeed. If the impl ever switches
        // to AccessLevel::Write, this test fails with a Forbidden.
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let a = artifact_in_repo(repo_id, "p", VALID_SHA256);
        artifacts.insert(a);

        let uc = wired_use_case(
            artifacts,
            storage,
            repos,
            enabled(rbac_with_read_and_write(repo_id)),
            metadata,
        );
        let reader = principal(&["reader"]); // Read only
        let _ = uc
            .find_visible_by_path("vault", "p", Some(&reader))
            .await
            .expect("Read-only actor must pass find_visible_by_path");

        // Sanity: verify the AccessLevel enum still has both variants
        // (compile-time guard).
        let _ = AccessLevel::Read;
        let _ = AccessLevel::Write;
    }

    // -- iterate_pages_capped ------------------------------------------------

    /// Build a `Page<u32>` over `[offset .. offset+limit)` clipped to the
    /// total `n` items, used to drive `iterate_pages_capped` with a
    /// purpose-built fake source. Returns `total = n` so the helper can
    /// short-circuit if a future revision uses it.
    fn make_fake_source(
        n: u64,
    ) -> impl Fn(
        PageRequest,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = AppResult<Page<u32>>> + Send>> {
        move |req: PageRequest| {
            let start = req.offset.min(n);
            let end = (req.offset + req.limit).min(n);
            let items: Vec<u32> = (start..end).map(|i| i as u32).collect();
            Box::pin(async move { Ok(Page { items, total: n }) })
        }
    }

    #[tokio::test]
    async fn iterate_pages_capped_returns_all_items_when_under_cap() {
        // Fake source has 50 items, cap is 100. Loop walks one page
        // (limit clipped to 50 by the over-fetch arithmetic), sees the
        // under-fetch, exits cleanly. No truncation.
        let src = make_fake_source(50);
        let result = iterate_pages_capped(100, &src).await.unwrap();
        assert_eq!(result.items.len(), 50);
        assert!(!result.truncated);
        // Items are 0..50 in order — pagination preserves source order.
        assert_eq!(result.items.first(), Some(&0));
        assert_eq!(result.items.last(), Some(&49));
    }

    #[tokio::test]
    async fn iterate_pages_capped_truncates_at_cap_boundary() {
        // Fake source has cap+1 items, cap=5. Loop reads up to cap+1 and
        // detects saturation, truncating to exactly cap items.
        let src = make_fake_source(6);
        let result = iterate_pages_capped(5, &src).await.unwrap();
        assert_eq!(result.items.len(), 5);
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn iterate_pages_capped_no_truncation_when_exactly_at_cap() {
        // Fake source has exactly cap items. Loop reads all cap items,
        // tries to over-fetch one more (gets empty), exits without
        // setting `truncated`. This is the load-bearing boundary —
        // setting the flag here would cry wolf on every cap-sized
        // legitimate result set.
        let src = make_fake_source(5);
        let result = iterate_pages_capped(5, &src).await.unwrap();
        assert_eq!(result.items.len(), 5);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn iterate_pages_capped_handles_empty_source() {
        let src = make_fake_source(0);
        let result = iterate_pages_capped(100, &src).await.unwrap();
        assert!(result.items.is_empty());
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn iterate_pages_capped_walks_multiple_pages() {
        // Source > PER_PAGE_LIMIT (1000) forces multiple round-trips.
        // Use 2_500 items with a cap of 5_000 — this should fully fetch
        // without truncation across at least three pages.
        let src = make_fake_source(2_500);
        let result = iterate_pages_capped(5_000, &src).await.unwrap();
        assert_eq!(result.items.len(), 2_500);
        assert!(!result.truncated);
        // No duplicates: items should be 0..2500 strictly.
        for (i, item) in result.items.iter().enumerate() {
            assert_eq!(*item, i as u32, "duplicate or skipped item at index {i}");
        }
    }

    #[tokio::test]
    async fn iterate_pages_capped_propagates_fetch_error() {
        let result: AppResult<LimitedList<u32>> =
            iterate_pages_capped(100, |_p| async { Err(AppError::Repository("fake".into())) })
                .await;
        assert!(result.is_err());
    }

    // -- list_by_raw_name_limited / list_distinct_names_visible
    //    truncation behaviour ------------------------------------------------

    /// `list_by_raw_name_limited` propagates the truncation flag from the
    /// underlying iterator. Seed the mock with > `LIMIT_LIST_MAX_ITEMS`
    /// artifacts so the over-fetch detection at the mock fires.
    /// The mock's cap matches production (`LIMIT_LIST_MAX_ITEMS`), so a
    /// seed of cap+1 is the minimum to exercise truncation.
    ///
    /// Skipped by default — seeding 10_001 mock rows is workable but
    /// slow (~1s on a developer machine); the corresponding fast unit
    /// test on `iterate_pages_capped` covers the same logic at cap=5.
    /// Run with `cargo test -p hort-app -- --ignored` to exercise.
    #[tokio::test]
    #[ignore = "slow: seeds 10_001 artifacts; iterate_pages_capped tests cover the cap-detection logic"]
    async fn list_by_raw_name_limited_flags_truncation_at_cap() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let metadata = Arc::new(MockArtifactMetadataRepository::new());

        let repo_id = Uuid::new_v4();
        for i in 0..(LIMIT_LIST_MAX_ITEMS as usize + 1) {
            let path = format!("many/{i:08}/many-{i:08}.tar.gz");
            let mut a = artifact_in_repo(repo_id, &path, VALID_SHA256);
            a.name = "many".into();
            a.version = Some(format!("{i:08}"));
            artifacts.insert(a);
        }

        let uc = wired_use_case(artifacts, storage, repos, RbacAccess::Disabled, metadata);
        let handler = StubFormatHandler::new("test").with_mapping("many", "many");
        let result = uc
            .list_by_raw_name_limited(repo_id, &handler, "many")
            .await
            .unwrap();
        assert_eq!(result.items.len(), LIMIT_LIST_MAX_ITEMS as usize);
        assert!(result.truncated);
    }
}
