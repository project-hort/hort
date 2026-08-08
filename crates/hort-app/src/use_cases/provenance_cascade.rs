//! Provenance-clearance cascade machinery (ADR 0039 §11).
//!
//! Extracted from `ProvenanceOrchestrationUseCase` so the **two trigger
//! ends** of the subject⇄constituent clearance dependency share one
//! implementation:
//!
//! - **Subject end** — the verify-time cascade. A `Verified` verdict on a
//!   signed subject under `Required` walks the subject's signed CAS bytes
//!   and appends a cascaded `ProvenanceVerified` to every constituent that
//!   is already ingested and held.
//! - **Constituent end** — the late-joiner self-clear. A constituent that
//!   arrives *after* its subject was verified walks the same authority in
//!   the opposite direction at its own quarantine-commit time and clears
//!   itself.
//!
//! Both ends resolve membership from the **signed bytes** and never from
//! DB edges: `content_references` rows are mutable projections, so they
//! may point at the right parent but they are not clearance authority.
//! An edge only ever *nominates* a candidate subject; the digest walk
//! decides.
//!
//! Everything here is best-effort by construction. The subject's own
//! clearance is already committed when the verify-time cascade runs, and
//! the late-joiner end runs after the constituent's quarantine has
//! committed — so no failure in this module may retract or block either.
//! Every error is `warn!` + continue, which leaves exactly the hold the
//! caller would have had without the attempt (fail-closed).

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::events::{system_actor, DomainEvent};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, ReadFrom,
};
use hort_domain::ports::provenance::SignerIdentity;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use tokio::io::AsyncReadExt;

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;

/// Upper bound on bytes read from CAS for a subject preimage / a single
/// attestation bundle. For OCI cosign the subject is the manifest (small);
/// the bundle is a Sigstore JSON blob. A generous backstop that keeps a
/// pathological CAS object from buffering unbounded into memory on the
/// verify path. 16 MiB.
pub(crate) const MAX_PROVENANCE_READ_BYTES: u64 = 16 * 1024 * 1024;

/// Cap on the number of events read when scanning an artifact stream for an
/// existing `ProvenanceVerified` (the already-cleared no-op skip and the
/// cascade's idempotency check). Mirrors `STREAM_READ_LIMIT` in
/// `release_clearance` (the release gate's own clearance read); every
/// artifact stream begins well within this bound.
pub(crate) const STREAM_READ_LIMIT: u64 = 200;

/// A late-joiner clearance that was committed: which subject's signature
/// cleared the constituent, and under which verifier backend. Returned so
/// the caller emits the metric + log once, at one site.
pub(crate) struct LateJoinerClearance {
    /// CAS hash of the **directly-verified** subject whose signed bytes
    /// bind the constituent's digest.
    pub(crate) subject: ContentHash,
    /// The verifier backend recorded on the subject's clearance — the
    /// metric's only label.
    pub(crate) backend: String,
}

/// Shared cascade machinery over the four ports both trigger ends need.
///
/// Port-only (`Arc<dyn _Port>`), mirroring the use cases that own it; it
/// holds no use-case handles and makes no policy decisions — the callers
/// decide *whether* a cascade applies (`Required` mode, committed
/// verdict / committed quarantine), this decides *what* the signature
/// covers.
pub(crate) struct ProvenanceCascade {
    artifacts: Arc<dyn ArtifactRepository>,
    storage: Arc<dyn StoragePort>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    events: Arc<EventStorePublisher>,
    content_references: Arc<dyn ContentReferenceIndex>,
}

impl ProvenanceCascade {
    pub(crate) fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        storage: Arc<dyn StoragePort>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        events: Arc<EventStorePublisher>,
        content_references: Arc<dyn ContentReferenceIndex>,
    ) -> Self {
        Self {
            artifacts,
            storage,
            lifecycle,
            events,
            content_references,
        }
    }

    // -----------------------------------------------------------------
    // Constituent end — late-joiner self-clear
    // -----------------------------------------------------------------

    /// Clear a **late-joining constituent** against an already-verified
    /// subject, at the constituent's own quarantine-commit time.
    ///
    /// The verify-time cascade clears the constituents that exist *when
    /// the subject verifies*. A constituent ingested afterwards has no
    /// clearance path of its own: cosign signs only the top-level digest,
    /// so its own verify finds no bundle, and under `Required` the
    /// referenced-tree-descendant hold keeps it `Pending` forever. This
    /// is the symmetric second trigger: the constituent looks *up* for a
    /// verified subject the moment it lands.
    ///
    /// Returns `Some(..)` iff a cascaded `ProvenanceVerified` was
    /// committed. Never returns an error — every failure warns and leaves
    /// the constituent exactly as held as it already was.
    ///
    /// # Authority
    ///
    /// The inbound `content_references` rows only *nominate* candidate
    /// subjects. Clearance requires, per candidate:
    ///
    /// - a **direct** `ProvenanceVerified` on the candidate
    ///   (`cascaded_from == None`) — or, for a candidate that was itself
    ///   cascade-cleared, the directly-verified **root** its clearance
    ///   names (see [`Self::clearance_root`]); a cascaded clearance never
    ///   re-walks its own bytes, so it can never widen the covered set;
    /// - the constituent's digest present in that root's **signed CAS
    ///   bytes**, via the same [`Self::constituent_digests`] walk the
    ///   verify-time cascade uses — identical authority, identical
    ///   one-level bound.
    ///
    /// Everything else (`Quarantined`-only, same-repository-only,
    /// idempotency, the version-conflict retry) is inherited unchanged
    /// from [`Self::cascade_one`].
    pub(crate) async fn resolve_late_joiner_clearance(
        &self,
        artifact: &Artifact,
    ) -> Option<LateJoinerClearance> {
        // Fail-closed on a read error: no edges resolved ⇒ no clearance
        // attempt ⇒ exactly the hold this artifact already has.
        let refs = match self
            .content_references
            .find_by_target(
                artifact.repository_id,
                &artifact.sha256_checksum,
                None, // UNFILTERED: kind is not authority; the digest walk decides.
            )
            .await
        {
            Ok(refs) => refs,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "late-joiner clearance: inbound content_references read failed — \
                     no clearance attempted (artifact stays held)",
                );
                return None;
            }
        };

        let mut visited: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        for reference in &refs {
            // An artifact's own `primary_content` / `metadata_blob`
            // refcount rows target its own hash; a self-clear would be
            // circular authority.
            if reference.source_artifact_id == artifact.id {
                continue;
            }
            if !visited.insert(reference.source_artifact_id) {
                continue;
            }
            match self
                .try_clear_from_source(artifact, reference.source_artifact_id)
                .await
            {
                Ok(Some(cleared)) => {
                    tracing::info!(
                        artifact_id = %artifact.id,
                        constituent = %artifact.sha256_checksum,
                        subject = %cleared.subject,
                        backend = %cleared.backend,
                        "provenance: late-joining constituent self-cleared from a verified subject",
                    );
                    return Some(cleared);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    artifact_id = %artifact.id,
                    source_artifact_id = %reference.source_artifact_id,
                    error = %e,
                    "late-joiner clearance: candidate subject could not be resolved — skipped",
                ),
            }
        }
        None
    }

    /// Attempt the late-joiner clearance of `artifact` against ONE
    /// candidate subject. `Ok(None)` is a deliberate skip (no clearance
    /// on the candidate, membership miss, candidate is the artifact
    /// itself); `Err` is an infra failure the caller warns on. Both leave
    /// the artifact held.
    async fn try_clear_from_source(
        &self,
        artifact: &Artifact,
        source_artifact_id: Uuid,
    ) -> AppResult<Option<LateJoinerClearance>> {
        let source = self.artifacts.find_by_id(source_artifact_id).await?;

        // Same-repository only, mirroring `cascade_one`'s repo-scoped
        // constituent lookup: a clearance never crosses a repo boundary.
        // `find_by_target` is already repo-scoped, so this is a
        // belt-and-braces guard against a future widening of the port.
        if source.repository_id != artifact.repository_id {
            return Ok(None);
        }

        let Some((subject_hash, clearance)) = self.clearance_root(&source).await? else {
            return Ok(None);
        };

        // A subject cannot be its own constituent; guard before the CAS
        // read so a self-referential edge can never re-append to this
        // artifact's stream through the cascade.
        if subject_hash == artifact.sha256_checksum {
            return Ok(None);
        }

        // MEMBERSHIP AUTHORITY: the subject's signed bytes, never the DB
        // edge that nominated it. An edge can be stale, hand-written, or
        // point at a subject whose signature does not cover this digest.
        let subject_bytes = self.read_bounded(&subject_hash).await?;
        let digests = self.constituent_digests(&subject_bytes).await?;
        if !digests.iter().any(|d| d == &artifact.sha256_checksum) {
            tracing::debug!(
                artifact_id = %artifact.id,
                subject = %subject_hash,
                "late-joiner clearance: digest not bound by the subject's signed bytes — \
                 no clearance",
            );
            return Ok(None);
        }

        let committed = self
            .cascade_one(
                artifact.repository_id,
                &subject_hash,
                &artifact.sha256_checksum,
                &clearance.signer,
                clearance.predicate_type.as_deref(),
                &clearance.backend,
            )
            .await?;

        Ok(committed.then_some(LateJoinerClearance {
            subject: subject_hash,
            backend: clearance.backend,
        }))
    }

    /// Resolve the **directly-verified root** behind a candidate
    /// subject's clearance, as `(root content hash, the root's clearance
    /// event)`.
    ///
    /// - A candidate holding a DIRECT clearance (`cascaded_from == None`)
    ///   is its own root.
    /// - A candidate holding a CASCADED clearance is *not* authority for
    ///   anything — its own bytes are covered by someone else's
    ///   signature, and re-walking them is exactly how an
    ///   index-of-indexes would leak clearance to grandchildren the
    ///   signature never covered. So the walk continues to the root its
    ///   `cascaded_from` names and reads THAT subject's signed bytes
    ///   instead. Exactly one hop, and the root must itself be directly
    ///   verified — so the covered set is byte-for-byte the set the
    ///   verify-time cascade derives from the same root, no wider.
    ///
    /// This is what lets a late-joining config/layer blob clear: its only
    /// inbound edge is its parent manifest, which under a signed
    /// multi-arch index is itself only cascade-cleared. The blob's digest
    /// is nonetheless inside the index's one-level walk, so the index
    /// clears it — the same digest the verify-time cascade would have
    /// cleared had the blob been present then.
    ///
    /// `Ok(None)` when the candidate carries no clearance, when its
    /// `cascaded_from` root has no artifact row in the repository, or
    /// when that root's own clearance is missing / not direct.
    async fn clearance_root(
        &self,
        source: &Artifact,
    ) -> AppResult<Option<(ContentHash, hort_domain::events::ProvenanceVerified)>> {
        let (Some(clearance), _) = self.read_clearance_state(source.id).await? else {
            return Ok(None);
        };
        let Some(root_hash) = clearance.cascaded_from.clone() else {
            return Ok(Some((source.sha256_checksum.clone(), clearance)));
        };

        let Some(root) = self
            .artifacts
            .find_by_repo_and_checksum(source.repository_id, &root_hash)
            .await?
        else {
            return Ok(None);
        };
        let (Some(root_clearance), _) = self.read_clearance_state(root.id).await? else {
            return Ok(None);
        };
        // Terminate the walk here unconditionally: a root whose own
        // clearance is itself cascaded is not a signature anchor, and
        // following further would be the unbounded recursion the
        // one-level bound forbids.
        if root_clearance.cascaded_from.is_some() {
            return Ok(None);
        }
        Ok(Some((root_hash, root_clearance)))
    }

    // -----------------------------------------------------------------
    // Subject end — verify-time cascade (ADR 0039 §11)
    // -----------------------------------------------------------------

    /// Cascade the verified subject's provenance clearance to the
    /// constituents its signed bytes bind (ADR 0039 cascade).
    ///
    /// The constituent set derives from the subject's **verified CAS
    /// bytes** — never from DB edges (`content_references` /
    /// `oci_index_member` rows are mutable projections; the signed bytes
    /// are the cryptographic authority). An image index yields its
    /// `manifests[]` children plus, per child manifest read back from CAS,
    /// that manifest's `config`/`layers` digests; a single-image manifest
    /// yields its own `config`/`layers`. Each digest sits inside its signed
    /// parent's bytes (a Merkle-like chain), so the signature over the
    /// subject digest covers exactly these constituents — and nothing else.
    ///
    /// Best-effort end to end: the subject's own clearance is already
    /// committed when this runs, and no failure here may retract or block
    /// it — every error is `warn!` + continue. Only the provenance
    /// authority cascades; the scan gate and observation window stay
    /// per-artifact (ADR 0007 / ADR 0043).
    pub(crate) async fn cascade_clearance(
        &self,
        repository_id: Uuid,
        subject_hash: &ContentHash,
        subject_bytes: &[u8],
        signer: &SignerIdentity,
        predicate_type: Option<&str>,
        backend: &str,
    ) {
        let digests = match self.constituent_digests(subject_bytes).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    subject = %subject_hash,
                    error = %e,
                    "provenance cascade: subject bytes did not parse as an OCI \
                     index/manifest — cascading to nothing",
                );
                return;
            }
        };

        let mut cascaded = 0usize;
        for digest in &digests {
            // Defensive self-reference guard: a subject cannot reference its
            // own hash in real content (self-referential digest), but the
            // cascade must never re-append to the subject's stream.
            if digest == subject_hash {
                continue;
            }
            match self
                .cascade_one(
                    repository_id,
                    subject_hash,
                    digest,
                    signer,
                    predicate_type,
                    backend,
                )
                .await
            {
                Ok(true) => cascaded += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    subject = %subject_hash,
                    constituent = %digest,
                    error = %e,
                    "provenance cascade: constituent clearance failed — skipped",
                ),
            }
        }
        if cascaded > 0 {
            tracing::info!(
                subject = %subject_hash,
                constituents = cascaded,
                backend = %backend,
                "provenance: cascaded clearance to signed constituents",
            );
        }
    }

    /// Derive the constituent digest set from the verified subject bytes.
    ///
    /// Index → `manifests[]` children (capped by the domain's
    /// `MAX_INDEX_CHILDREN`) plus each child manifest's `config`/`layers`
    /// digests read back from the child's own CAS bytes (capped per
    /// manifest by `MAX_MANIFEST_BLOBS`); single-image manifest → its own
    /// `config`/`layers`. A child whose CAS bytes cannot be read or parsed
    /// contributes the child digest itself (it is bound into the signed
    /// index bytes regardless) but no blobs — `warn!` + continue.
    /// Deduplicated (a blob shared across children appears once),
    /// order-preserving.
    pub(crate) async fn constituent_digests(
        &self,
        subject_bytes: &[u8],
    ) -> AppResult<Vec<ContentHash>> {
        let mut out: Vec<ContentHash> = Vec::new();
        if hort_domain::oci::is_image_index(subject_bytes) {
            for child in hort_domain::oci::index_child_digests(subject_bytes)? {
                out.push(child.clone());
                let child_bytes = match self.read_bounded(&child).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            child = %child,
                            error = %e,
                            "provenance cascade: child manifest CAS read failed — \
                             its config/layer blobs are not cascaded",
                        );
                        continue;
                    }
                };
                match hort_domain::oci::manifest_blob_digests(&child_bytes) {
                    Ok(blobs) => out.extend(blobs),
                    Err(e) => tracing::warn!(
                        child = %child,
                        error = %e,
                        "provenance cascade: child manifest did not parse — \
                         its config/layer blobs are not cascaded",
                    ),
                }
            }
        } else {
            out.extend(hort_domain::oci::manifest_blob_digests(subject_bytes)?);
        }
        let mut seen = std::collections::HashSet::new();
        out.retain(|h| seen.insert(h.clone()));
        Ok(out)
    }

    /// Cascade the clearance to ONE constituent digest. Returns `Ok(true)`
    /// when a cascaded `ProvenanceVerified` was committed, `Ok(false)` on
    /// the deliberate skips:
    ///
    /// - no artifact row for the digest **in the subject's repository**
    ///   (the lookup is repo-scoped — a same-digest artifact in another
    ///   repo is never touched);
    /// - a constituent that is not currently held (the domain guard in
    ///   [`Artifact::cascade_provenance_clearance`] refuses every
    ///   non-`Quarantined` state — terminally rejected stays rejected,
    ///   `Released`/status-`None` need no clearance);
    /// - a constituent already carrying a `ProvenanceVerified` (its own
    ///   verification or an earlier cascade) — idempotent re-runs append
    ///   no duplicate.
    pub(crate) async fn cascade_one(
        &self,
        repository_id: Uuid,
        subject_hash: &ContentHash,
        digest: &ContentHash,
        signer: &SignerIdentity,
        predicate_type: Option<&str>,
        backend: &str,
    ) -> AppResult<bool> {
        let Some(constituent) = self
            .artifacts
            .find_by_repo_and_checksum(repository_id, digest)
            .await?
        else {
            return Ok(false);
        };

        // The domain guard: only a held (`Quarantined`) constituent takes
        // a cascaded clearance. The `Err` is the guard refusing a
        // non-held state — a deliberate skip, not an infra failure.
        let Ok(event) = constituent.cascade_provenance_clearance(
            subject_hash.clone(),
            signer.clone(),
            predicate_type.map(str::to_string),
            backend,
        ) else {
            tracing::debug!(
                artifact_id = %constituent.id,
                status = %constituent.quarantine_status,
                "provenance cascade: constituent not held — skipped",
            );
            return Ok(false);
        };

        let (cleared, expected_version) = self.read_clearance_state(constituent.id).await?;
        if cleared.is_some() {
            return Ok(false);
        }

        // Append at the just-read version. A version conflict means a
        // concurrent append bumped the stream between the read and this
        // append (the constituent's own `ScanCompleted` is the realistic
        // race — scan and sign both land seconds after push): re-read
        // once, re-check idempotency (the concurrent event may itself
        // have been a `ProvenanceVerified`), and re-append at the fresh
        // version. ONE retry only — a second conflict, or any
        // non-conflict error, propagates to the caller's warn+skip.
        if let Err(err) = self
            .commit_cascade_event(&constituent, event.clone(), expected_version)
            .await
        {
            if !matches!(err, hort_domain::error::DomainError::Conflict(_)) {
                return Err(err.into());
            }
            tracing::debug!(
                artifact_id = %constituent.id,
                "provenance cascade: version conflict — retrying once with a fresh read",
            );
            let (cleared, fresh_version) = self.read_clearance_state(constituent.id).await?;
            if cleared.is_some() {
                return Ok(false);
            }
            self.commit_cascade_event(&constituent, event, fresh_version)
                .await?;
        }

        tracing::info!(
            artifact_id = %constituent.id,
            constituent = %digest,
            subject = %subject_hash,
            backend = %backend,
            "provenance: clearance cascaded from verified subject",
        );
        Ok(true)
    }

    /// Append one cascaded `ProvenanceVerified` to `constituent`'s stream
    /// at `expected_version`. Split out of [`Self::cascade_one`] so the
    /// version-conflict retry re-appends through the identical path;
    /// returns the raw [`DomainResult`](hort_domain::error::DomainResult)
    /// so the caller can match the event store's `Conflict` shape before
    /// converting to `AppError`.
    ///
    /// Routed through the verdict-scoped conditional write
    /// (`commit_provenance_verdict`), NOT `commit_transition`: a full-row
    /// `save_in_tx` write-back could clobber any column a concurrent
    /// writer changed on `constituent`'s stale in-memory snapshot.
    /// `prior_status` is `constituent.quarantine_status` as loaded by
    /// `cascade_one` — the SAME status the artifact is still in here,
    /// since `Artifact::cascade_provenance_clearance` takes `&self` and
    /// never mutates it (only the domain GUARD reads it, requiring
    /// `Quarantined`). So `artifact.quarantine_status == prior_status`
    /// always on this path, and the skip-unchanged rule always fires: the
    /// cascade's `ProvenanceVerified` event still appends, but NO
    /// status-column write happens at all — the full-row clobber vector
    /// is gone.
    pub(crate) async fn commit_cascade_event(
        &self,
        constituent: &Artifact,
        event: hort_domain::events::ProvenanceVerified,
        expected_version: ExpectedVersion,
    ) -> hort_domain::error::DomainResult<()> {
        self.lifecycle
            .commit_provenance_verdict(
                constituent,
                AppendEvents {
                    stream_id: hort_domain::events::StreamId::artifact(constituent.id),
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ProvenanceVerified(event))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: system_actor(),
                },
                constituent.quarantine_status,
            )
            .await
            .map(|_| ())
    }

    /// Read the artifact's event stream once, reporting the existing
    /// `ProvenanceVerified` (if any) plus the expected version for a
    /// subsequent append — a single read serving the already-cleared
    /// verify skip (which inspects the event's `cascaded_from` / signer
    /// for the cascade re-drive), the cascade's idempotency check +
    /// append, and the late-joiner end's subject-authority check.
    pub(crate) async fn read_clearance_state(
        &self,
        artifact_id: Uuid,
    ) -> AppResult<(
        Option<hort_domain::events::ProvenanceVerified>,
        ExpectedVersion,
    )> {
        let stream_id = hort_domain::events::StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await?;
        let cleared = persisted.iter().find_map(|e| match &e.event {
            DomainEvent::ProvenanceVerified(ev) => Some(ev.clone()),
            _ => None,
        });
        let expected = match persisted.last() {
            Some(last) => ExpectedVersion::Exact(last.stream_position),
            None => ExpectedVersion::NoStream,
        };
        Ok((cleared, expected))
    }

    /// Read up to [`MAX_PROVENANCE_READ_BYTES`] from the CAS object at
    /// `hash`. A read error surfaces as `Err`. Over-cap content is
    /// truncated at the cap (the verify path does not need the full blob
    /// for the manifest-shaped subjects Tier-1 covers; a larger artifact
    /// simply hashes wrong and is rejected by the verifier, never a panic).
    pub(crate) async fn read_bounded(&self, hash: &ContentHash) -> AppResult<Vec<u8>> {
        let reader = self.storage.get(hash).await?;
        let mut limited = reader.take(MAX_PROVENANCE_READ_BYTES);
        let mut buf = Vec::new();
        limited.read_to_end(&mut buf).await.map_err(|e| {
            hort_domain::error::DomainError::Invariant(format!(
                "provenance: CAS read failed for {hash}: {e}"
            ))
        })?;
        Ok(buf)
    }
}

#[cfg(test)]
#[path = "provenance_cascade_tests.rs"]
mod tests;
