//! OCI manifest write path — `PUT` + `DELETE /v2/:repo_key/*name/manifests/:ref`.
//!
//! Deliberately split from [`super::manifests`] (the read path) for
//! review cohesion — the PUT handler composes four use cases
//! ([`IngestUseCase`](hort_app::use_cases::ingest_use_case::IngestUseCase),
//! [`ArtifactGroupUseCase`](hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase),
//! [`RefUseCase`](hort_app::use_cases::ref_use_case::RefUseCase), and
//! [`ContentReferenceIndex`](hort_domain::ports::content_reference_index::ContentReferenceIndex))
//! behind a causation-chain contract that the read path doesn't touch,
//! so keeping them in one file would bloat both. The read/write split
//! mirrors the separation in the OCI Distribution Spec read/write surface.
//!
//! # Workflow summary (PUT)
//!
//! 1. Parse `<name>/manifests/<ref>` from the `*tail` capture; reject
//!    malformed shapes as `NAME_UNKNOWN`.
//! 2. Validate `Content-Type` against
//!    [`SUPPORTED_MANIFEST_MEDIA_TYPES`]. Reject outside the allowlist
//!    as `MANIFEST_INVALID`. Single-image manifests and image indexes /
//!    manifest lists are both accepted; the blob/child parse (step 4)
//!    branches on the media type.
//! 3. Pre-compute the manifest body's SHA-256 **before** calling
//!    [`IngestUseCase::ingest`]. On a digest-reference PUT the declared
//!    digest is compared against the computed hash via
//!    `declared_sha256`; a mismatch surfaces as
//!    [`AppError::Domain`](hort_app::error::AppError::Domain) with
//!    [`DomainError::Conflict`](hort_domain::error::DomainError::Conflict)
//!    and rolls back the CAS blob — the handler maps it to 400
//!    `MANIFEST_INVALID`. On a tag PUT
//!    the computed hash is used to mint the response's `Location`
//!    header and `Docker-Content-Digest`.
//! 4. Parse the manifest JSON by media-type shape. A single-image
//!    manifest yields `config.digest` + `layers[*].digest`; an image
//!    index / manifest list yields `manifests[*].digest` (child
//!    **manifest** references). Resolve each referenced blob / child
//!    through
//!    [`ArtifactRepository::find_by_checksum`]; enforce
//!    `artifact.repository_id == repo` (cross-repo isolation). Any
//!    missing blob / child returns 400 `MANIFEST_BLOB_UNKNOWN` with a
//!    `detail.blobs` array. The manifest artifact stays committed so
//!    the client's retry-after-pushing-blobs path is idempotent; the
//!    group is NOT created.
//! 5. Attach the primary `manifest` member to the group, plus (single-
//!    image only) config + layers, via
//!    [`ArtifactGroupUseCase::add_member`]. Shared per-request
//!    `correlation_id`; every call threads `causation_id =
//!    Some(manifest_event_id)` — the audit-trail contract.
//! 6. Tag-reference PUTs call
//!    [`RefUseCase::set`](hort_app::use_cases::ref_use_case::RefUseCase::set)
//!    with `RefTarget::ContentHash(manifest_digest)`. Digest-reference
//!    PUTs skip this step (digest is self-naming).
//! 7. If the manifest carries `subject.digest`, insert a
//!    [`ContentReference`] row with `kind = "oci_subject"`.
//!
//! Response: 201 + `Location: /v2/<repo_key>/<name>/manifests/<ref>` +
//! `Docker-Content-Digest: sha256:<hex>`. Empty body.
//!
//! # DELETE
//!
//! Tag references route through [`RefUseCase::retire`]; digest
//! references look up the manifest artifact via `find_by_path`, call
//! [`ContentReferenceIndex::delete_by_source`], then remove the
//! artifact via [`ArtifactUseCase::delete`]. CAS blob lifetime is GC's
//! concern — the DELETE handler never touches storage directly.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::Router;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::ingest_use_case::VerifiedIngestRequest;
use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::mutable_ref::RefTarget;
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor};
use hort_domain::ports::content_reference_index::ContentReference;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;

use hort_http_core::authz::{DeleteRepoAccess, WriteRepoAccess};
use hort_http_core::context::AppContext;
use hort_http_core::limits::BoundedPath;

use super::coords::{oci_group_coords, oci_manifest_coords};
use super::digest::{parse_digest, DigestParse, UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE};
use super::error::OciError;
use super::name::validate_oci_name;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Manifest media-types accepted on `PUT`. Anything outside the
/// allowlist is rejected as `MANIFEST_INVALID`.
///
/// Both single-image manifests and multi-arch indexes / manifest lists
/// are accepted. The blob/child parse branches on the media type: an
/// index / list media type routes to [`index_child_digests`] (child
/// **manifest** resolution); every other media type routes to the
/// single-image [`parse_manifest_blobs`] (`config` + `layers[]`).
const SUPPORTED_MANIFEST_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v1+json",
];

/// Returns `true` iff `media_type` is an image-index / manifest-list
/// media type — the shape that carries `manifests[]` (child descriptors)
/// instead of `config` + `layers[]`. The write path dispatches the
/// blob/child parse on this predicate: an index resolves its child
/// manifests; every other media type runs the single-image parse.
pub(crate) fn is_index_media_type(media_type: &str) -> bool {
    media_type == hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE
        || media_type == hort_domain::oci::DOCKER_MANIFEST_LIST_MEDIA_TYPE
}

/// Upper bound on the manifest body read into memory before parsing.
/// OCI manifests are typically a few KB; a 1 MiB ceiling accommodates
/// every real-world manifest while capping the memory cost of a
/// pathological client sending megabytes of junk. Exceeding this is a
/// `MANIFEST_INVALID` (not `SIZE_INVALID` — size applies to blobs).
const MANIFEST_BODY_MAX_BYTES: usize = 1024 * 1024;

/// Upper bound on the number of distinct blob references (`config`
/// digest plus `layers[*].digest`) a single manifest may carry.
///
/// The 1 MiB body cap above stops gross OOM, but a packed JSON body
/// can fit ~10k pathologically dense `{"digest":"sha256:..."}` entries
/// within 1 MiB — and every referenced blob triggers a
/// `find_in_repo_by_hash` lookup against
/// the artifact repository in [`resolve_referenced_blobs`]. A real-
/// world OCI image carries tens of layers; 1024 is two orders of
/// magnitude past observed maxima. Exceeding it lands as
/// `MANIFEST_INVALID` per [`parse_manifest_blobs`]'s error envelope.
///
/// The cap is enforced **at parse time** so the resolution loop is
/// never entered for an over-cap manifest. Do NOT move this gate
/// into `resolve_referenced_blobs` — that would defeat the purpose
/// of the cap (the cost the cap protects against is N database
/// lookups, one per referenced blob).
pub(crate) const MAX_BLOB_REFERENCES: usize = 1024;

/// `Retry-After` for a manifest write that lost to persistent storage
/// contention, in seconds.
///
/// Short on purpose. A contention abort is over by the time the client hears
/// about it — the writer that won committed before the storage engine raised
/// the error — so the only thing left to wait out is a co-writer queue that
/// drains in milliseconds. This is a "come straight back" hint, not the
/// quarantine-hold timescale [`OciError::Quarantined`] advertises, and an OCI
/// client that honours it re-pushes the same manifest and succeeds.
const MANIFEST_CONTENTION_RETRY_AFTER_SECS: i64 = 1;

/// Classify a failed write on the manifest-PUT path.
///
/// `Some(response)` when the failure is storage write contention that
/// outlived the adapter's own bounded retry ([`DomainError::Contended`]).
/// That case is emphatically not a 500: the manifest was valid, the
/// transaction rolled back whole so nothing was half-applied, and re-pushing
/// it is expected to work. A concurrent multi-architecture push is the
/// ordinary producer — sibling manifests share content-reference targets (an
/// image index's attestation manifests all reference the same empty-config
/// blob), so their edge writes contend on one row by construction. Answering
/// that with `INTERNAL` reports a healthy registry as broken, sends whoever
/// debugs the intermittent failure hunting a bug that is not there, and
/// withholds from the client the one instruction that would resolve it.
///
/// `None` for every other failure, so each caller keeps its own
/// rich-context `error!` and its `Internal` response untouched. The `warn`
/// here rather than at the call sites is deliberate: their logging is
/// `error!`, which is the right level for a genuine fault and the wrong one
/// for a registry that is merely busy.
fn manifest_write_contention(err: &AppError, stage: &'static str) -> Option<OciError> {
    matches!(err, AppError::Domain(DomainError::Contended(_))).then(|| {
        tracing::warn!(
            stage,
            error = %err,
            "manifest write lost to persistent storage contention; answering 503 + Retry-After"
        );
        OciError::Unavailable {
            retry_after_seconds: MANIFEST_CONTENTION_RETRY_AFTER_SECS,
        }
    })
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build a manifest write router for use INSIDE THIS CRATE'S TESTS.
///
/// Production routing flows through [`super::oci_routes_with_config`] →
/// the top-level `/v2/:repo_key/*tail` PUT dispatcher in `lib.rs`, which
/// peeks at the tail shape and forwards to either
/// [`put_manifest_dispatch`] (manifest PUT) or
/// [`super::uploads::put_upload_dispatch`] (blob PUT-finalize). DELETE
/// goes through [`delete_manifest_dispatch`] unconditionally because
/// the only DELETE on the OCI surface is on manifests. Production code
/// never invokes this builder — the test harness uses it to exercise
/// the manifest router in isolation.
#[cfg(test)]
fn router() -> Router<Arc<AppContext>> {
    Router::new().route(
        "/v2/{repo_key}/{*tail}",
        axum::routing::put(put_manifest_dispatch).delete(delete_manifest_dispatch),
    )
}

// ---------------------------------------------------------------------------
// Tail parsing
// ---------------------------------------------------------------------------

/// Parsed `<name>/manifests/<reference>` tail for PUT/DELETE.
///
/// Separate from [`super::tail::TailKind`] because the manifest write
/// path is method-specific — adding a write-only variant to the shared
/// pull tail parser would pollute the GET dispatcher with an
/// unreachable arm.
struct ManifestTail<'a> {
    name: &'a str,
    reference: &'a str,
}

/// Extract `(name, reference)` from the `*tail` capture. The shape is
/// `<name>/manifests/<reference>`; `name` may be multi-segment
/// (`library/nginx`) and `reference` is either a tag (no `:`) or a
/// digest (`sha256:<hex>`). `rsplit_once` matches on the rightmost
/// `/manifests/` — OCI's name grammar reserves the word and forbids it
/// inside a legitimate image name, so the rightmost rule is unambiguous
/// (matches the pull-tail parser's behaviour).
fn parse_manifest_tail(tail: &str) -> Option<ManifestTail<'_>> {
    let (name, reference) = tail.rsplit_once("/manifests/")?;
    if name.is_empty() || reference.is_empty() {
        return None;
    }
    Some(ManifestTail { name, reference })
}

// ---------------------------------------------------------------------------
// PUT dispatch
// ---------------------------------------------------------------------------

/// Entry point for `PUT /v2/:repo_key/*tail`.
///
/// `WriteRepoAccess` runs as a `FromRequestParts` extractor before the
/// body is touched — resolving the repo and running the RBAC check up
/// front means an unauthorised caller never hits the manifest parser
/// (cheap-fail principle). The handler itself is a straight-line
/// composition of the workflow documented at the module head.
pub(crate) async fn put_manifest_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    request: Request<Body>,
) -> Response {
    let Some(ManifestTail { name, reference }) = parse_manifest_tail(&tail) else {
        return OciError::NameUnknown {
            repository: format!("{repo_key}/{tail}"),
        }
        .into_response();
    };
    // Validate the parsed `<name>` segment against the OCI Distribution
    // Spec name grammar BEFORE any storage, manifest, or upload action.
    // Rejecting on the pre-storage path keeps malformed names out of
    // `Artifact.name`, metric labels, log lines, and the manifest blob
    // CAS commit.
    if let Err(e) = validate_oci_name(name) {
        return super::name_invalid_response(e);
    }
    let name = name.to_string();
    let reference = reference.to_string();

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };

    // Shared per-request correlation_id threaded through every call the
    // handler issues downstream (ingest, add_member × N, ref set,
    // content_references insert). Load-bearing audit contract — see
    // audit-trail contract.
    let correlation_id = Uuid::new_v4();

    // Pull headers + body up front. Body reading is the one
    // unavoidable point of no return; subsequent failures must treat
    // the body as consumed. The 1 MiB cap applies here; axum's
    // `to_bytes` returns an `Err` if the body exceeds the limit — we
    // classify that as `MANIFEST_INVALID` (not `SIZE_INVALID`, which
    // is reserved for blob-upload limits).
    let headers = request.headers().clone();
    let body_bytes = match to_bytes(request.into_body(), MANIFEST_BODY_MAX_BYTES).await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest body too large or unreadable",
                    "max_bytes": MANIFEST_BODY_MAX_BYTES,
                })),
            }
            .into_response();
        }
    };

    // Content-Type allowlist.
    let media_type = match extract_media_type(&headers) {
        Ok(mt) => mt,
        Err(resp) => return *resp,
    };
    if !SUPPORTED_MANIFEST_MEDIA_TYPES.contains(&media_type.as_str()) {
        return OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "unsupported manifest media type",
                "media_type": media_type,
            })),
        }
        .into_response();
    }

    // Pre-parse the manifest JSON for `subject.digest` (used in
    // `payload_metadata`) and, later, `config.digest` + `layers[*].digest`.
    // Invalid JSON at this step → 400 `MANIFEST_INVALID` per OCI spec
    // (unparseable JSON is an envelope-shape violation, not
    // UNSUPPORTED).
    let parsed_manifest: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest body is not valid JSON",
                    "error": e.to_string(),
                })),
            }
            .into_response();
        }
    };

    // Cross-check the client-declared media type against the manifest's
    // actual shape BEFORE any state change. The blob/child parse
    // dispatches on the declared `Content-Type` (`is_index_media_type`);
    // `is_image_index` is the structural shape probe (non-empty
    // `manifests[]`). If the two disagree the push is mislabeled and is
    // rejected as `MANIFEST_INVALID`:
    //   * declared index / manifest-list, but the bytes carry no
    //     `manifests[]` (a single-image manifest sent under an index
    //     Content-Type) — the index parse would find zero children; and
    //   * declared single-image, but the bytes ARE an index — the
    //     single-image parse would look for a `config` the index lacks,
    //     silently mis-handling the children.
    // Dispatching by declared type is preserved for the matching case;
    // a well-formed push whose declared type matches its shape is
    // unaffected.
    let media_type_is_index = is_index_media_type(&media_type);
    let bytes_are_index = hort_domain::oci::is_image_index(&body_bytes);
    if media_type_is_index != bytes_are_index {
        return OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "declared media type does not match manifest shape",
                "media_type": media_type,
                "declared_index": media_type_is_index,
                "shape_is_index": bytes_are_index,
            })),
        }
        .into_response();
    }

    // `subject.digest` may be absent — serde_json returns Null for a
    // missing key path, which we coerce to `None`.
    let subject_digest_str: Option<String> = parsed_manifest
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let artifact_type_opt: Option<String> = parsed_manifest
        .get("artifactType")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // N-5: pre-validate `subject.digest` BEFORE the manifest ingest commits.
    // The previous flow re-parsed the digest just before the
    // ContentReferenceIndex insert at the tail of the handler — by then
    // the manifest artifact + group + ref had already been committed, so
    // a malformed `subject.digest` produced a 500 with the manifest left
    // half-attached. Validating up front keeps the failure on the same
    // pre-commit path as config/layer digest validation: 400
    // MANIFEST_INVALID, no state change.
    let subject_digest_parsed: Option<ContentHash> = match subject_digest_str.as_deref() {
        None => None,
        Some(raw) => match parse_digest(raw) {
            DigestParse::Ok(h) => Some(h),
            DigestParse::Unsupported => {
                // Neither `algorithm` nor `message` is included in the
                // detail — both are attacker-controlled manifest-JSON
                // content (mirrors `parse_blob_digest`'s contract); the
                // raw value is already logged inside `parse_digest`.
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "subject digest uses unsupported algorithm",
                        "field": "subject.digest",
                    })),
                }
                .into_response();
            }
            DigestParse::Invalid { .. } => {
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "subject digest malformed",
                        "field": "subject.digest",
                    })),
                }
                .into_response();
            }
        },
    };

    // Pre-compute the SHA-256 of the manifest body. Doing this before
    // calling `ingest` means (a) `declared_sha256` can be set on both
    // digest-ref AND tag-ref PUTs so mismatches are caught consistently,
    // (b) coords carry the real hash up front (no placeholder rewrite),
    // and (c) the response headers (`Location`,
    // `Docker-Content-Digest`) can be formatted before `ingest` runs
    // so their construction never participates in a partial-failure
    // rollback. Pre-compute is the recommended option in the Item
    // brief's workflow step 5 (a); the cost of a second SHA over a
    // manifest body is negligible (sub-millisecond for typical KB
    // manifests).
    let computed_hash = compute_sha256(&body_bytes);
    let reference_is_digest = reference.contains(':');

    // On a digest-ref PUT, compare the declared digest against the
    // computed one. Mismatch → 400 `MANIFEST_INVALID` BEFORE any state
    // change. A successful parse of the declared digest feeds into
    // `declared_sha256` below so `IngestUseCase::ingest` cannot commit
    // a manifest whose bytes disagree with the client's claim.
    let declared_hash: Option<ContentHash> = if reference_is_digest {
        match parse_digest(&reference) {
            DigestParse::Ok(h) => {
                if h != computed_hash {
                    return OciError::ManifestInvalid {
                        detail: Some(serde_json::json!({
                            "reason": "declared digest does not match manifest content",
                            "declared": format!("sha256:{}", h.as_ref()),
                            "computed": format!("sha256:{}", computed_hash.as_ref()),
                        })),
                    }
                    .into_response();
                }
                Some(h)
            }
            DigestParse::Unsupported => {
                // Well-formed but non-sha256 algorithm. The OCI
                // The spec pins `UNSUPPORTED` for a digest whose
                // algorithm is recognised but can't be processed.
                // This is the ONE path where UNSUPPORTED is correct
                // (vs DIGEST_INVALID).
                return OciError::Unsupported {
                    message: UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE.to_string(),
                }
                .into_response();
            }
            DigestParse::Invalid { message } => {
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "malformed digest reference",
                        "error": message,
                    })),
                }
                .into_response();
            }
        }
    } else {
        // Tag-ref PUT: validate the tag against the OCI grammar (INJ-4 — the
        // same `validate_oci_tag` the GET/serve path uses) BEFORE it becomes
        // a stored ref, via the shared `tag_invalid_response` mapping (400
        // `MANIFEST_INVALID`, non-echoing reason). Mirrors the digest
        // branch's malformed-digest rejection above; rejects before any
        // ingest/state change.
        if let Err(e) = super::tag::validate_oci_tag(&reference) {
            return super::tag_invalid_response(e);
        }
        // Declare the computed hash so the ingest path has a consistent
        // post-storage check. `IngestUseCase::ingest` treats
        // `declared_sha256 = Some(computed)` as a tautology here, but
        // asserting it closes a latent window where a concurrent mutation
        // between compute and commit would slip through.
        Some(computed_hash.clone())
    };

    // Build the ingest request + stream. The body is an in-memory
    // `Vec<u8>` by the time we're here (the 1 MiB cap keeps this
    // cheap); wrap in a `Cursor` to get an `AsyncRead`.
    let manifest_coords = oci_manifest_coords(&name, &computed_hash);
    let payload_metadata = serde_json::json!({
        "oci_media_type": media_type,
        "oci_subject_digest": subject_digest_str,
    });
    // Manifest write: digest from request body (when reference is a
    // digest) or computed from bytes. Either way ProtocolNative is
    // correct because OCI's protocol embeds the digest in the request
    // itself (ADR 0006).
    let upstream_digest = declared_hash.unwrap_or_else(|| computed_hash.clone());
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(body_bytes.clone()));

    // Route a pushed cosign **signature** manifest (a *pure* Sigstore-bundle
    // referrer) to the narrow `ingest_signature_manifest` path instead of
    // the generic `ingest_verified` pipeline. Quarantine is an observation
    // window for time-deferred safety uncertainty; a Sigstore signature's
    // validity is deterministic and immediate, so quarantining / scanning /
    // provenance-verifying it is a category error.
    //
    // The exemption is gated on the manifest's declared media types, which a
    // write-authed pusher fully controls — so it is deliberately AIRTIGHT:
    // it fires **only** when the manifest carries a `subject.digest` AND
    // EVERY layer is signature material — either a Sigstore v0.3 bundle
    // (`is_pure_sigstore_bundle`, keyless) OR a cosign `simplesigning` layer
    // (`is_pure_simplesigning`, the keyed `cosign sign --key` shape, ADR 0039
    // §8). A mixed manifest (a signature layer plus a runnable `tar+gzip` layer)
    // does NOT match → it stays on `ingest_verified` and IS scanned. "Exempted"
    // ⟺ "carries no runnable content" — the anti-scan-evasion guard.
    //
    // Both predicates parse the manifest JSON; the body already parsed cleanly
    // above (`parsed_manifest`), so a parse error here is not expected. On the
    // off chance one errors, fail safe → generic path (`unwrap_or(false)`),
    // so the generic path scans/quarantines it — never a wrongful exemption.
    let is_pure_signature = subject_digest_parsed.is_some()
        && (hort_domain::oci::is_pure_sigstore_bundle(&body_bytes).unwrap_or(false)
            || hort_domain::oci::is_pure_simplesigning(&body_bytes).unwrap_or(false));

    // Ingest the manifest bytes. A `Conflict` here is the
    // declared-hash mismatch. The wire mapping
    // (Conflict -> ManifestInvalid) is preserved. The signature path
    // surfaces the same `Conflict` shape on a put-vs-declared mismatch.
    let ingest_result = if is_pure_signature {
        ctx.ingest_use_case
            .ingest_signature_manifest(
                repo_id,
                manifest_coords,
                media_type.clone(),
                actor.clone(),
                payload_metadata,
                upstream_digest,
                // S3 (design §2 S3): the subject image's content hash, so
                // the ingest use case can resolve the subject artifact and
                // enqueue a best-effort provenance-verify for it — clearing
                // a held image within seconds of `cosign sign`. Always
                // `Some` here (an `is_pure_signature` manifest carries a
                // `subject.digest`, gated at `is_pure_signature` above).
                subject_digest_parsed.clone(),
                stream,
            )
            .await
    } else {
        let ingest_req = VerifiedIngestRequest::ProtocolNative {
            repository_id: repo_id,
            coords: manifest_coords,
            content_type: media_type.clone(),
            actor: actor.clone(),
            payload_metadata,
            upstream_digest,
            upstream_published_at: None,
            // Manifest write is OCI-direct (`PUT /v2/<name>/manifests/<reference>`):
            // no serving `RepositoryUpstreamMapping`, opt-in cannot apply (ADR 0007).
            trust_upstream_publish_time: false,
        };
        ctx.ingest_use_case
            .ingest_verified(ingest_req, stream, &OciFormatHandler)
            .await
    };
    let ingest_outcome = match ingest_result {
        Ok(o) => o,
        Err(AppError::Domain(DomainError::Conflict(_))) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest ingest rejected declared digest",
                })),
            }
            .into_response();
        }
        Err(err) => {
            if let Some(busy) = manifest_write_contention(&err, "manifest_ingest") {
                return busy.into_response();
            }
            tracing::error!(error = %err, "OCI manifest ingest failed");
            return OciError::Internal.into_response();
        }
    };

    let manifest_artifact = ingest_outcome.artifact;
    let manifest_event_id = ingest_outcome.ingested_event_id;
    let manifest_digest = computed_hash.clone();

    // Parse the referenced blobs / children by media-type shape.
    //
    // - Image index / manifest list: `manifests[*].digest` child
    //   **manifest** references (no `config`, no `layers`). An over-cap
    //   index is `MANIFEST_INVALID`, mirroring the single-image
    //   reference-count rejection.
    // - Single-image manifest: the unchanged `config` + `layers[]` parse.
    //
    // On either path a parse failure lands as `MANIFEST_INVALID`; the
    // manifest artifact is already committed, so the client can retry
    // with a corrected manifest (or push the blobs/children and retry).
    // The partially-attached state is permitted to persist.
    // `media_type_is_index` was computed up front (declared-vs-shape
    // cross-check); reuse it here to dispatch the blob/child parse.
    let referenced = match if media_type_is_index {
        parse_index_children(&body_bytes)
    } else {
        parse_manifest_blobs(&parsed_manifest)
    } {
        Ok(r) => r,
        Err(detail) => {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact.id,
                "manifest parse failed post-ingest; artifact stays committed for client retry"
            );
            return OciError::ManifestInvalid {
                detail: Some(detail),
            }
            .into_response();
        }
    };

    // Resolve each referenced blob / child manifest. Cross-repo
    // isolation: a hash that exists in a foreign repo counts as missing —
    // the blob must live in the same repo as the manifest (mount it
    // across explicitly via
    // `POST /v2/.../blobs/uploads/?mount=...&from=...`). For an index the
    // children are resolved for **existence only** — a missing child is
    // `MANIFEST_BLOB_UNKNOWN`, exactly like a missing layer (clients push
    // the platform manifests before the index).
    let (config_artifact, layer_artifacts, missing) =
        match resolve_referenced_blobs(&ctx, repo_id, &referenced).await {
            Ok(t) => t,
            Err(resp) => {
                tracing::error!("infrastructure error during blob resolution");
                return resp;
            }
        };
    if !missing.is_empty() {
        // The manifest artifact stays committed so a client retry after
        // pushing the missing blobs reconciles cleanly.
        // We do NOT create the group on this path.
        //
        // Group-attachment retry path: the manifest stays committed so
        // the client can push missing blobs and retry idempotently.
        tracing::info!(
            manifest_artifact_id = %manifest_artifact.id,
            missing = ?missing,
            "manifest referenced unknown blobs; group attachment deferred until client retry"
        );
        return OciError::ManifestBlobUnknown { blobs: missing }.into_response();
    }
    // A single-image manifest has a resolved `config`; an index carries
    // none. Only require the config on the single-image path — an index
    // that resolved its children with no config is the correct shape.
    if !media_type_is_index && config_artifact.is_none() {
        // Defensive: reachable only if `parse_manifest_blobs` accepted
        // a single-image manifest with no config AND
        // `resolve_referenced_blobs` didn't mark it missing. The current
        // parser rejects missing config, so this branch is an assertion.
        tracing::error!(
            manifest_artifact_id = %manifest_artifact.id,
            "resolve_referenced_blobs returned None config with empty missing list"
        );
        return OciError::Internal.into_response();
    }

    // Attach members to the group. Order: manifest (primary) first, then
    // (single-image only) config, then every layer. An index attaches
    // only the primary `manifest` member — it has no config/layers and
    // its child manifests are NOT group members (the index→child linkage
    // is a content-reference edge, Item 3). The shared `correlation_id` +
    // `causation_id = Some(manifest_event_id)` is the load-bearing audit
    // contract — the causation-integrity test reads the recorded batches
    // and asserts this on every member event.
    let group_coords = oci_group_coords(&name, &manifest_digest);
    let actor_any = Actor::Api(actor.clone());

    // ADR 0060 contract (`hort_app::append_conflict`): a same-member
    // replay (same artifact_id + same role re-add) is an idempotent
    // non-error — the adapter's `ON CONFLICT DO NOTHING` absorbs it on
    // the first attempt, or `add_member`'s own retry cycle absorbs it
    // after a conflict. A different-member (or different-role) append
    // that loses a real version race is retried inside `add_member`,
    // bounded; exhaustion surfaces `DomainError::Contended`, mapped to
    // 503 + `Retry-After` below — never swallowed, never a bare 500.
    // Any OTHER error reaching this site is a genuine infrastructure
    // failure and stays a logged 500.
    if let Err(e) = ctx
        .artifact_group_use_case
        .add_member(
            repo_id,
            group_coords.clone(),
            "manifest".into(),
            manifest_artifact.id,
            /* is_primary = */ true,
            actor_any.clone(),
            correlation_id,
            Some(manifest_event_id),
            Some(&repo_key),
            "oci",
        )
        .await
    {
        if let Some(busy) = manifest_write_contention(&e, "group_attach_manifest") {
            return busy.into_response();
        }
        tracing::error!(
            manifest_artifact_id = %manifest_artifact.id,
            manifest_digest = %manifest_digest,
            repo_key = %repo_key,
            stage = "group_attach_manifest",
            error = ?e,
            "manifest group-attach failed; not idempotent-shaped (see commit_member_added \
             contract) — this is a genuine error"
        );
        return OciError::Internal.into_response();
    }

    if let Some(config_artifact) = &config_artifact {
        if let Err(e) = ctx
            .artifact_group_use_case
            .add_member(
                repo_id,
                group_coords.clone(),
                "config".into(),
                config_artifact.id,
                /* is_primary = */ false,
                actor_any.clone(),
                correlation_id,
                Some(manifest_event_id),
                Some(&repo_key),
                "oci",
            )
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "group_attach_config") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                config_digest = %config_artifact.sha256_checksum,
                repo_key = %repo_key,
                stage = "group_attach_config",
                error = ?e,
                "config group-attach failed; not idempotent-shaped (see commit_member_added \
                 contract) — this is a genuine error"
            );
            return OciError::Internal.into_response();
        }
    }

    for layer in &layer_artifacts {
        if let Err(e) = ctx
            .artifact_group_use_case
            .add_member(
                repo_id,
                group_coords.clone(),
                "layer".into(),
                layer.id,
                /* is_primary = */ false,
                actor_any.clone(),
                correlation_id,
                Some(manifest_event_id),
                Some(&repo_key),
                "oci",
            )
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "group_attach_layer") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                layer_id = %layer.id,
                layer_digest = %layer.sha256_checksum,
                repo_key = %repo_key,
                stage = "group_attach_layer",
                error = ?e,
                "layer group-attach failed; not idempotent-shaped (see commit_member_added \
                 contract) — this is a genuine error"
            );
            return OciError::Internal.into_response();
        }
    }

    // Tag-ref PUT: set the ref. Digest-ref PUT: skip — the digest is
    // self-naming; creating a ref would be redundant.
    //
    // ADR 0060 contract: `RefUseCase::set` short-circuits to `Ok` when
    // the target is unchanged, retries `RefCommitOutcome::RefAlreadyExists`
    // internally (never surfaced as `Err`), and now also retries a
    // losing append `Conflict` against the refreshed ref state, bounded;
    // exhaustion surfaces `DomainError::Contended`, mapped to 503 +
    // `Retry-After` below. Any OTHER error reaching here is a genuine
    // infrastructure failure, not an idempotency case to collapse.
    if !reference_is_digest {
        if let Err(e) = ctx
            .ref_use_case
            .set(
                repo_id,
                /* namespace */ &name,
                /* ref_name */ &reference,
                RefTarget::ContentHash(manifest_digest.clone()),
                actor.clone(),
                Some(&repo_key),
            )
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "ref_set") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                repo_key = %repo_key,
                reference = %reference,
                stage = "ref_set",
                error = ?e,
                "ref set failed; not idempotent-shaped (see RefUseCase::set contract) — \
                 this is a genuine error"
            );
            return OciError::Internal.into_response();
        }
    }

    // Insert the content-reference row if the manifest carries
    // `subject.digest`. `ContentReferenceIndex::insert` is upsert-on-
    // PK (see the port docstring) so a client retry with the same
    // manifest simply refreshes the row — no find_by_target
    // pre-check needed here. The digest itself was validated up
    // front via `subject_digest_parsed` (N-5 fix); a None here means
    // the manifest had no `subject` field at all.
    //
    // #73 step 1: this INSERT is a genuine SQL `ON CONFLICT ... DO
    // UPDATE` upsert (see `pg_content_reference_repo.rs::insert`) — a
    // duplicate can NEVER surface as `DomainError::Conflict` here; the
    // database absorbs it silently as a metadata refresh. Any `Err`
    // reaching this call site is therefore a genuine infrastructure
    // failure (e.g. FK violation, connection loss), not an idempotency
    // case — never swallow it.
    if let Some(subject_hash) = subject_digest_parsed.clone() {
        let reference_row = ContentReference {
            source_artifact_id: manifest_artifact.id,
            target_content_hash: subject_hash,
            kind: "oci_subject".into(),
            metadata: serde_json::json!({
                "artifact_type": artifact_type_opt,
                "media_type": media_type,
            }),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        // Write goes through the use case (ADR 0008). The method is
        // no-authz by contract (caller has already extracted
        // `WriteRepoAccess` for `repo_id`); the use case carries the
        // explicit `repo_id` argument so future audits can grep for
        // cross-repo write confusion at the use-case boundary. The
        // port's idempotent-upsert shape is preserved verbatim.
        if let Err(e) = ctx
            .content_reference_use_case
            .insert_for_repo(repo_id, reference_row)
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "content_references_insert") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                repo_key = %repo_key,
                error = ?e,
                stage = "content_references_insert",
                "content_references (oci_subject) insert failed; upsert cannot Conflict — \
                 this is a genuine error, referrers index is eventual — operator rebuild is \
                 future work"
            );
            return OciError::Internal.into_response();
        }
    }

    // Manifest→blob membership edges (#46 Item 1). For a single-image
    // manifest, record one content-reference row per referenced blob:
    // `source =` the manifest artifact, `target =` the blob's own content
    // hash, `kind = "oci_config"` (the config blob) / `"oci_layer"` (each
    // layer blob). An image index has no config/layers — `referenced`
    // contains only `ChildManifest` entries there, so this loop is a
    // no-op on that path (its children are covered by the
    // `oci_index_member` loop below).
    //
    // These are GC-ACTIVE keepalive edges, exactly like `oci_subject` /
    // `oci_index_member` below: the purge refcount counts rows of every
    // kind against a target hash, so a live manifest keeps its
    // config/layer blobs alive here too. This does not double-count
    // against the `ArtifactGroupUseCase::add_member` calls above — group
    // membership is an orthogonal, GC-invisible axis (the purge/refcount
    // sweep never reads `artifact_group_members`); see issue #46 comment
    // "Item 1 GC-interaction — RESOLVED". Manifest DELETE's
    // `delete_by_source` removes every kind for the source, so these
    // edges are cleaned up exactly like `oci_index_member`.
    for blob in referenced
        .iter()
        .filter(|r| r.role == BlobRole::Config || r.role == BlobRole::Layer)
    {
        let kind = if blob.role == BlobRole::Config {
            "oci_config"
        } else {
            "oci_layer"
        };
        let blob_reference = ContentReference {
            source_artifact_id: manifest_artifact.id,
            target_content_hash: blob.hash.clone(),
            kind: kind.into(),
            metadata: serde_json::json!({
                "digest": blob.digest_raw,
                "media_type": media_type,
            }),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        if let Err(e) = ctx
            .content_reference_use_case
            .insert_for_repo(repo_id, blob_reference)
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "oci_blob_reference_insert") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                blob_digest = %blob.digest_raw,
                kind,
                repo_key = %repo_key,
                error = ?e,
                stage = "oci_blob_reference_insert",
                "blob content_references insert failed; upsert cannot Conflict — this is a \
                 genuine error, GC alive-keep for this blob is eventual — operator rebuild is \
                 future work"
            );
            return OciError::Internal.into_response();
        }
    }

    // Image-index membership edges (D3). For an image index / manifest
    // list, record one `oci_index_member` content-reference row per child
    // manifest: `source =` the index artifact, `target =` the child's own
    // content hash, `kind =` the fixed literal `"oci_index_member"`. This
    // both records the index→child membership and keeps every child
    // manifest's blob alive under GC — the purge refcount counts rows of
    // *every* kind against a target hash (`purge_use_case`), so a live
    // index keeps its children exactly as a live `oci_subject` referrer
    // keeps its subject.
    //
    // The widened PK `(repository_id, source_artifact_id,
    // target_content_hash, kind)` (migration 013) lets N children share
    // one `(source = index_id, kind = "oci_index_member")` — each row is
    // distinguished by its `target_content_hash`, so the `insert` upsert
    // no longer collapses them (the old narrow PK forced a hash-in-`kind`
    // workaround; that is gone). `source = index` is pinned — the
    // direction the GC-alive-keep and the index-DELETE sweep both key on.
    // Written through the use case (ADR 0008), mirroring the `oci_subject`
    // write. The `ChildManifest` entries come from `parse_index_children`
    // (`hort_domain::oci::index_child_digests`); a single-image manifest
    // has none, so this loop is a no-op there.
    for child in referenced
        .iter()
        .filter(|r| r.role == BlobRole::ChildManifest)
    {
        let member_reference = ContentReference {
            source_artifact_id: manifest_artifact.id,
            target_content_hash: child.hash.clone(),
            kind: "oci_index_member".into(),
            metadata: serde_json::json!({
                "child_digest": child.digest_raw,
                "media_type": media_type,
            }),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        if let Err(e) = ctx
            .content_reference_use_case
            .insert_for_repo(repo_id, member_reference)
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "oci_index_member_insert") {
                return busy.into_response();
            }
            tracing::error!(
                manifest_artifact_id = %manifest_artifact.id,
                manifest_digest = %manifest_digest,
                child_digest = %child.digest_raw,
                repo_key = %repo_key,
                error = ?e,
                stage = "oci_index_member_insert",
                "index-member content_references insert failed; upsert cannot Conflict — \
                 this is a genuine error, GC alive-keep for this child is eventual — operator \
                 rebuild is future work"
            );
            return OciError::Internal.into_response();
        }
    }

    created_manifest_response(&repo_key, &name, &reference, &manifest_digest)
}

// ---------------------------------------------------------------------------
// DELETE dispatch
// ---------------------------------------------------------------------------

/// Entry point for `DELETE /v2/:repo_key/*tail`.
///
/// Tag references route through [`RefUseCase::retire`]; digest
/// references delete the artifact + its content-reference rows. The
/// response is 202 (not 200) — OCI clients treat 200 and 202
/// identically here, but the spec prefers 202 for asynchronous cleanup
/// semantics.
///
/// Authorisation runs against [`DeleteRepoAccess`] rather than
/// `WriteRepoAccess`. Destroying a published manifest is the canonical
/// "I'm removing landed content visible to other readers" operation,
/// distinct from publishing (`PUT`-finalize) or cancelling an own-incomplete
/// upload. Operators who declared `permissions: [write]` grants in gitops
/// `PermissionGrant` manifests for OCI repositories must add a parallel
/// `permissions: [delete]` entry (or extend the existing array to
/// `permissions: [write, delete]`) if those roles should be able to delete
/// published manifests; the `admin` role bypasses per-permission
/// grants via the role-name short-circuit in
/// `hort_app::rbac::RbacEvaluator::authorize` (rbac.rs:104) and is
/// therefore unaffected.
pub(crate) async fn delete_manifest_dispatch(
    access: DeleteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
) -> Response {
    let Some(ManifestTail { name, reference }) = parse_manifest_tail(&tail) else {
        return OciError::NameUnknown {
            repository: format!("{repo_key}/{tail}"),
        }
        .into_response();
    };
    // Same name-grammar gate as the PUT path — validate the parsed
    // `<name>` against the OCI grammar before any ref retire,
    // content-reference delete, or artifact removal.
    // Closes the audit's "names with control bytes / mixed case
    // flow into find_in_repo_by_hash" finding for the DELETE side.
    if let Err(e) = validate_oci_name(name) {
        return super::name_invalid_response(e);
    }
    let name = name.to_string();
    let reference = reference.to_string();

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };

    if reference.contains(':') {
        delete_by_digest(
            &ctx,
            repo_id,
            &repo_key,
            &name,
            &reference,
            &access.principal,
            actor,
        )
        .await
    } else {
        // Tag-ref DELETE: validate the tag against the OCI grammar (INJ-4 —
        // same `validate_oci_tag` as the GET/serve and PUT paths) before the
        // `RefUseCase::retire`, via the shared `tag_invalid_response` mapping
        // (400 `MANIFEST_INVALID`, non-echoing reason).
        if let Err(e) = super::tag::validate_oci_tag(&reference) {
            return super::tag_invalid_response(e);
        }
        delete_by_tag(&ctx, repo_id, &repo_key, &name, &reference, actor).await
    }
}

async fn delete_by_tag(
    ctx: &AppContext,
    repo_id: Uuid,
    repo_key: &str,
    name: &str,
    tag: &str,
    actor: ApiActor,
) -> Response {
    match ctx
        .ref_use_case
        .retire(repo_id, name, tag, actor, Some(repo_key))
        .await
    {
        Ok(()) => (StatusCode::ACCEPTED, Body::empty()).into_response(),
        Err(AppError::Domain(DomainError::NotFound { .. })) => OciError::ManifestUnknown {
            reference: tag.to_string(),
        }
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "OCI manifest DELETE tag failed");
            OciError::Internal.into_response()
        }
    }
}

/// `principal` is the visibility subject for the path lookup; `actor` is
/// the same authenticated identity in event-attribution form, threaded
/// through to `ArtifactUseCase::delete` so the `ArtifactDeleted` event
/// names who removed the manifest.
#[allow(clippy::too_many_arguments)] // repo/name/digest coordinates + both actor forms.
async fn delete_by_digest(
    ctx: &AppContext,
    repo_id: Uuid,
    repo_key: &str,
    name: &str,
    digest_str: &str,
    principal: &hort_domain::entities::caller::CallerPrincipal,
    actor: ApiActor,
) -> Response {
    let hash = match parse_digest(digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported => {
            return OciError::Unsupported {
                message: UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE.to_string(),
            }
            .into_response();
        }
        DigestParse::Invalid { .. } => {
            // A malformed digest on DELETE surfaces as 404
            // `MANIFEST_UNKNOWN` — the reference-shape is unusable for
            // a lookup and the spec pins the not-found envelope here.
            return OciError::ManifestUnknown {
                reference: digest_str.to_string(),
            }
            .into_response();
        }
    };
    let coords = oci_manifest_coords(name, &hash);
    // Visibility-aware path lookup (ADR 0008). `WriteRepoAccess`
    // already authorised the caller for Write on this repo (Write
    // implies Read in `RepositoryAccessUseCase::resolve` semantics),
    // so the use case's Read check is redundant for this principal —
    // but routing through it keeps the call shape uniform across the
    // crate and matches the enforcement guarantee.
    let artifact = match ctx
        .artifact_use_case
        .find_visible_by_path(repo_key, &coords.path, Some(principal))
        .await
    {
        Ok((_repo, a)) => a,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            return OciError::ManifestUnknown {
                reference: digest_str.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OCI manifest DELETE find_visible_by_path failed");
            return OciError::Internal.into_response();
        }
    };

    // content_references cleanup. Idempotent — missing entries are
    // `Ok(())` per the port contract. A failure here is logged but
    // does NOT short-circuit the artifact delete: an orphaned
    // reference is less harmful than a half-deleted manifest.
    //
    // Cleanup goes through the use case (ADR 0008). Same no-authz
    // trust contract as `insert_for_repo` above (caller has
    // `WriteRepoAccess`). The explicit `repo_id` keeps the call site
    // semantically scoped even though the underlying port keys delete
    // by `source` alone.
    if let Err(e) = ctx
        .content_reference_use_case
        .delete_by_source_for_repo(repo_id, artifact.id)
        .await
    {
        tracing::warn!(
            manifest_artifact_id = %artifact.id,
            error = %e,
            "content_references delete_by_source failed; proceeding with artifact delete"
        );
    }

    // Artifact lifecycle delete. `ArtifactUseCase::delete` is an
    // event-sourced soft delete: the row survives with `deleted_at` set
    // and an `ArtifactDeleted` event lands on the artifact's stream,
    // attributed to this caller. The CAS blob is NOT removed (GC
    // concern; multiple artifacts may share CAS bytes) — the
    // `content_references` cleanup above is what lets refcount GC
    // reclaim it later if nothing else references it.
    if let Err(e) = ctx
        .artifact_use_case
        .delete(artifact.id, Actor::Api(actor))
        .await
    {
        tracing::error!(
            manifest_artifact_id = %artifact.id,
            error = %e,
            "OCI manifest DELETE artifact.delete failed"
        );
        return OciError::Internal.into_response();
    }

    (StatusCode::ACCEPTED, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Small representation of a referenced blob extracted from manifest
/// JSON. Digest strings are kept raw (with the `sha256:` prefix) so
/// `MANIFEST_BLOB_UNKNOWN.detail.blobs` can echo them back verbatim —
/// clients match on the same form they sent.
#[derive(Debug, Clone)]
pub(crate) struct ReferencedBlob {
    pub(crate) digest_raw: String,
    pub(crate) hash: ContentHash,
    pub(crate) role: BlobRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobRole {
    Config,
    Layer,
    /// A child manifest referenced by an image index / manifest list via
    /// `manifests[*].digest`. Resolved by the same same-repo existence
    /// path a layer uses (a missing child → `MANIFEST_BLOB_UNKNOWN`), but
    /// not attached as a group member — the index lands as a plain
    /// primary `manifest` member; the index→child linkage is an
    /// `oci_index_member` content-reference edge, not a group role.
    ChildManifest,
}

/// Parse the single-image manifest shape:
///
/// ```json
/// {
///   "schemaVersion": 2,
///   "config": { "digest": "sha256:...", ... },
///   "layers": [ { "digest": "sha256:...", ... }, ... ]
/// }
/// ```
///
/// Returns the config blob (required) followed by the layer blobs
/// (possibly empty) in manifest order. Order matters only for the
/// `add_member` call sequence — the event stream records it as the
/// audit trail; consumers of the group read unordered.
///
/// Error shape: returns an `Err(serde_json::Value)` carrying the
/// `detail` object for a 400 `MANIFEST_INVALID` so the caller can
/// surface it verbatim. This keeps all manifest-shape validation in
/// one place and avoids leaking parser internals into the handler.
pub(crate) fn parse_manifest_blobs(
    manifest: &serde_json::Value,
) -> Result<Vec<ReferencedBlob>, serde_json::Value> {
    let mut out: Vec<ReferencedBlob> = Vec::new();

    // config.digest — REQUIRED by the single-image shape.
    let config_digest = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            serde_json::json!({
                "reason": "manifest missing required `config.digest`",
            })
        })?;
    let config_hash = parse_blob_digest(config_digest)?;
    out.push(ReferencedBlob {
        digest_raw: config_digest.to_string(),
        hash: config_hash,
        role: BlobRole::Config,
    });

    // layers[*].digest — OPTIONAL (some manifests are config-only).
    // Each entry must have a well-formed sha256 digest.
    if let Some(layers) = manifest.get("layers").and_then(|v| v.as_array()) {
        for (idx, layer) in layers.iter().enumerate() {
            let layer_digest = layer
                .get("digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "reason": format!("layer[{idx}] missing `digest` field"),
                    })
                })?;
            let layer_hash = parse_blob_digest(layer_digest)?;
            out.push(ReferencedBlob {
                digest_raw: layer_digest.to_string(),
                hash: layer_hash,
                role: BlobRole::Layer,
            });
        }
    }

    // Bound the referenced-blob count at parse time so the per-blob
    // lookup loop in `resolve_referenced_blobs` is never entered for
    // an over-cap manifest. Surfaces as `MANIFEST_INVALID` at the
    // call site.
    if out.len() > MAX_BLOB_REFERENCES {
        return Err(serde_json::json!({
            "reason": format!(
                "manifest references {} blobs; max is {}",
                out.len(),
                MAX_BLOB_REFERENCES,
            ),
        }));
    }

    Ok(out)
}

/// Parse an image-index / manifest-list shape into the child **manifest**
/// references it declares via `manifests[*].digest`:
///
/// ```json
/// {
///   "schemaVersion": 2,
///   "mediaType": "application/vnd.oci.image.index.v1+json",
///   "manifests": [ { "digest": "sha256:...", "platform": {...} }, ... ]
/// }
/// ```
///
/// Delegates the JSON parse + bound + sha256-only filtering to the domain
/// helper [`index_child_digests`](hort_domain::oci::index_child_digests):
/// a non-sha256 / malformed child digest is skipped, and an index
/// declaring more than the domain cap is a
/// [`DomainError::Validation`](hort_domain::error::DomainError::Validation).
///
/// Each resolved child becomes a [`ReferencedBlob`] with role
/// [`BlobRole::ChildManifest`], so the shared [`resolve_referenced_blobs`]
/// same-repo existence check treats a missing child exactly like a missing
/// layer — a `MANIFEST_BLOB_UNKNOWN`. Clients push the platform child
/// manifests before the index, so an unresolved child is the expected
/// out-of-order case, not a hard error.
///
/// Error shape mirrors [`parse_manifest_blobs`]: an `Err(serde_json::Value)`
/// carrying the `detail` object for a 400 `MANIFEST_INVALID`. An over-cap
/// index (the domain `Validation`) maps here to the same envelope the
/// single-image over-cap rejection produces.
pub(crate) fn parse_index_children(body: &[u8]) -> Result<Vec<ReferencedBlob>, serde_json::Value> {
    let children = hort_domain::oci::index_child_digests(body).map_err(|e| {
        serde_json::json!({
            "reason": format!("invalid image index: {e}"),
        })
    })?;

    Ok(children
        .into_iter()
        .map(|hash| ReferencedBlob {
            digest_raw: format!("sha256:{}", hash.as_ref()),
            hash,
            role: BlobRole::ChildManifest,
        })
        .collect())
}

/// Parse a `sha256:<hex>` digest into a `ContentHash`, returning the
/// `serde_json::Value` `detail` payload on failure. Separate from
/// [`parse_digest`] because this one produces the manifest-invalid
/// envelope shape rather than the blob-pull one — the handler-level
/// error codes differ.
///
/// Neither error arm echoes `raw` (the client-supplied manifest
/// `config.digest` / `layers[*].digest` field) or the inner
/// `message`/`algorithm` text into the `detail` payload — both are
/// attacker-controlled manifest-JSON content and reflecting them is a
/// response-reflection vector (mirrors [`parse_digest`]'s own
/// never-echo contract). The raw value stays available server-side via
/// `tracing::debug!`.
fn parse_blob_digest(raw: &str) -> Result<ContentHash, serde_json::Value> {
    match parse_digest(raw) {
        DigestParse::Ok(h) => Ok(h),
        DigestParse::Unsupported => {
            tracing::debug!(digest = %raw, "OCI manifest referenced an unsupported digest algorithm");
            Err(serde_json::json!({
                "reason": "unsupported digest algorithm in manifest",
            }))
        }
        DigestParse::Invalid { .. } => {
            tracing::debug!(digest = %raw, "OCI manifest referenced a malformed digest");
            Err(serde_json::json!({
                "reason": "malformed digest in manifest",
            }))
        }
    }
}

/// Resolve every referenced blob by SHA-256 against the artifact
/// repository, enforcing cross-repo isolation. Returns
/// `(config_opt, layers, missing_digests)` — `missing_digests` carries
/// the raw `sha256:<hex>` strings so the response body can echo the
/// client's form.
///
/// Resolve every referenced blob by SHA-256 against the artifact
/// repository, enforcing cross-repo isolation (ADR 0008). The call
/// uses `find_in_repo_by_hash` which scopes the SQL query to the
/// target repo at the port boundary — the right row is the only
/// candidate and there is no ordering hazard from cross-repo rows
/// sharing the same SHA-256.
async fn resolve_referenced_blobs(
    ctx: &AppContext,
    repo: Uuid,
    refs: &[ReferencedBlob],
) -> Result<(Option<Artifact>, Vec<Artifact>, Vec<String>), Response> {
    let mut config: Option<Artifact> = None;
    let mut layers: Vec<Artifact> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for r in refs {
        let hit = match ctx
            .artifact_use_case
            .find_in_repo_by_hash(repo, &r.hash)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = %e, "find_in_repo_by_hash failed");
                return Err(OciError::Internal.into_response());
            }
        };
        match hit {
            // The use case already enforces `repository_id == repo`
            // at the port boundary; no post-filter needed. Clients
            // cross-mount explicitly via
            // `POST …/blobs/uploads/?mount=<digest>&from=<src_repo>`
            // before pushing the manifest.
            Some(a) => match r.role {
                BlobRole::Config => {
                    if config.is_some() {
                        // Defensive — `parse_manifest_blobs` emits at
                        // most one config; two configs would be a
                        // parser regression.
                        tracing::warn!(
                            "multiple config blobs resolved; keeping first and ignoring extras"
                        );
                    } else {
                        config = Some(a);
                    }
                }
                BlobRole::Layer => layers.push(a),
                // A child manifest of an image index is resolved for
                // existence only — it is NOT attached as a group member
                // (the index lands as a plain primary `manifest`; the
                // index→child linkage is a content-reference edge, Item
                // 3). A present child is simply confirmed and dropped.
                BlobRole::ChildManifest => {}
            },
            None => {
                if r.role == BlobRole::ChildManifest {
                    // Mirror the layer-missing path: a child pushed
                    // out-of-order (index before its platform manifests)
                    // is the expected retry case, surfaced as
                    // `MANIFEST_BLOB_UNKNOWN` at the call site.
                    tracing::warn!(
                        child_digest = %r.digest_raw,
                        "image index references an unknown child manifest; deferring until client retry"
                    );
                }
                missing.push(r.digest_raw.clone());
            }
        }
    }

    Ok((config, layers, missing))
}

/// Register-only `content_references` membership-edge write for the
/// **pull-through** ingest path (#46 Item 4 — the pull-through re-fix).
/// Parses the just-ingested manifest bytes by media type and writes the
/// SAME edges the hosted PUT path writes above — `oci_index_member` per
/// child for an image index, `oci_config` + `oci_layer` per referenced
/// blob for a single-image manifest — **without fetching** the
/// referenced children/blobs (register by digest only; #46 Item 1/D3
/// scope). `source = manifest_artifact_id` (the artifact the pull-through
/// path just ingested), `target =` each declared child/blob digest.
///
/// Item 2's `IngestUseCase::is_referenced_descendant` target-check reads
/// exactly these kinds; before this function existed, a proxy pull-through
/// never wrote them, so every proxy descendant's target-check always
/// missed and got the full quarantine window (the bug this closes).
///
/// **Non-fatal by design.** The manifest is already committed
/// (`ArtifactIngested` has landed) by the time this runs — a parse or
/// insert failure here must not fail the pull-through response or undo
/// the ingest. Mirrors the existing warn-and-continue posture of the
/// pull-through path's other post-ingest side effects (the leader-side
/// tag→digest ref write and prefetch trigger in `manifests.rs`) and the
/// "content_references is eventually authoritative" invariant the
/// `RefcountReconcileUseCase` sweep already backstops. Idempotent — a
/// re-pull of the same manifest re-registers the same rows via the
/// upsert-on-PK `insert_for_repo` contract.
pub(crate) async fn register_membership_edges_from_pull(
    ctx: &AppContext,
    repo_id: Uuid,
    manifest_artifact_id: Uuid,
    media_type: &str,
    body: &[u8],
) {
    let referenced = if is_index_media_type(media_type) {
        match parse_index_children(body) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(
                    manifest_artifact_id = %manifest_artifact_id,
                    %repo_id,
                    media_type,
                    ?detail,
                    "OCI pull-through: image-index child parse failed; membership edges \
                     not registered (non-fatal, register-only best-effort)"
                );
                return;
            }
        }
    } else {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    manifest_artifact_id = %manifest_artifact_id,
                    %repo_id,
                    media_type,
                    error = %e,
                    "OCI pull-through: manifest body did not parse as JSON; membership \
                     edges not registered (non-fatal, register-only best-effort)"
                );
                return;
            }
        };
        match parse_manifest_blobs(&parsed) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(
                    manifest_artifact_id = %manifest_artifact_id,
                    %repo_id,
                    media_type,
                    ?detail,
                    "OCI pull-through: manifest blob parse failed; membership edges not \
                     registered (non-fatal, register-only best-effort)"
                );
                return;
            }
        }
    };

    for blob in &referenced {
        let (kind, metadata) = match blob.role {
            BlobRole::ChildManifest => (
                "oci_index_member",
                serde_json::json!({
                    "child_digest": blob.digest_raw,
                    "media_type": media_type,
                }),
            ),
            BlobRole::Config | BlobRole::Layer => (
                if blob.role == BlobRole::Config {
                    "oci_config"
                } else {
                    "oci_layer"
                },
                serde_json::json!({
                    "digest": blob.digest_raw,
                    "media_type": media_type,
                }),
            ),
        };
        let reference_row = ContentReference {
            source_artifact_id: manifest_artifact_id,
            target_content_hash: blob.hash.clone(),
            kind: kind.into(),
            metadata,
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        if let Err(e) = ctx
            .content_reference_use_case
            .insert_for_repo(repo_id, reference_row)
            .await
        {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact_id,
                %repo_id,
                blob_digest = %blob.digest_raw,
                kind,
                error = %e,
                "OCI pull-through: content_references insert failed; membership edge not \
                 registered (non-fatal, eventual — operator reconcile is future work)"
            );
        }
    }
}

/// Extract the `Content-Type` header as an owned `String`. Missing or
/// non-ASCII values land as `MANIFEST_INVALID` — the manifest push
/// path requires a valid media-type from the supported allowlist.
fn extract_media_type(headers: &HeaderMap) -> Result<String, Box<Response>> {
    let Some(value) = headers.get(CONTENT_TYPE) else {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "missing required Content-Type header",
                })),
            }
            .into_response(),
        ));
    };
    let Ok(s) = value.to_str() else {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "Content-Type header is not valid ASCII",
                })),
            }
            .into_response(),
        ));
    };
    // Strip any `;params` suffix. The allowlist keys on the type/subtype
    // only; `application/vnd.oci.image.manifest.v1+json; charset=utf-8`
    // must round-trip to the same allowlist hit.
    let trimmed = s.split(';').next().unwrap_or("").trim().to_string();
    Ok(trimmed)
}

/// Compute the SHA-256 of the manifest body. The returned
/// [`ContentHash`] parses the lowercase hex — this matches the `ingest`
/// path's `declared_sha256` column, which is also `ContentHash`-typed.
fn compute_sha256(bytes: &[u8]) -> ContentHash {
    let digest = Sha256::digest(bytes);
    let hex = format!("{digest:x}");
    hex.parse()
        .expect("sha2::Sha256::digest produces valid 64-char lowercase hex")
}

/// Build the 201 response for a successful manifest PUT. `Location`
/// echoes the request URL with the client's reference form (tag or
/// digest); `Docker-Content-Digest` carries the computed hash
/// regardless of reference form.
fn created_manifest_response(
    repo_key: &str,
    name: &str,
    reference: &str,
    hash: &ContentHash,
) -> Response {
    let location = format!("/v2/{repo_key}/{name}/manifests/{reference}");
    // `repo_key` / `name` / `reference` come from the request URL
    // captures; CRLF or other non-ASCII bytes in any segment produce
    // an `InvalidHeaderValue` from `from_str`. Routing through the
    // shared helper returns the canonical `NAME_UNKNOWN` 404 envelope
    // instead of panicking (which would degrade to 500 — a DoS
    // primitive).
    let location_header = match super::header_value_or_bad_request(&location) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_header);
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    (StatusCode::CREATED, headers, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, GroupCommitInjection, MockArtifactGroupLifecyclePort,
        MockArtifactGroupRepository, MockArtifactLifecycle, MockArtifactRepository,
        MockContentReferenceIndex, MockEventStore, MockRefLifecyclePort, MockRefRegistryPort,
        MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::artifact_group::ArtifactGroup;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::events::DomainEvent;
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_domain::ports::content_reference_index::ContentReferenceIndex;
    use hort_domain::ports::ref_registry::RefRegistryPort;

    use hort_http_core::test_support::build_mock_ctx;

    // -------------------- Harness --------------------

    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        refs: Arc<MockRefRegistryPort>,
        #[allow(dead_code)]
        ref_lifecycle: Arc<MockRefLifecyclePort>,
        #[allow(dead_code)]
        artifact_groups: Arc<MockArtifactGroupRepository>,
        group_lifecycle: Arc<MockArtifactGroupLifecyclePort>,
        content_references: Arc<MockContentReferenceIndex>,
        // Observe which ingest path ran via `lifecycle.scan_enqueues()`:
        // a normal / mixed / non-bundle manifest routes via `ingest_verified`,
        // which enqueues a scan ATOMICALLY with the transition (the seeded
        // HTTP-test policy carries `scan_backends: ["trivy"]`); a pure
        // Sigstore-bundle referrer routes via `ingest_signature_manifest` →
        // NO scan enqueued.
        lifecycle: Arc<MockArtifactLifecycle>,
        #[allow(dead_code)]
        events: Arc<MockEventStore>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
            refs: mocks.refs,
            ref_lifecycle: mocks.ref_lifecycle,
            artifact_groups: mocks.artifact_groups,
            group_lifecycle: mocks.artifact_group_lifecycle,
            content_references: mocks.content_references,
            lifecycle: mocks.lifecycle,
            events: mocks.events,
        }
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
    }

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn test_principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            // `claims` is the resolved set from the token (ADR 0012);
            // an empty set is the under-privileged shape these tests
            // start from and override per-case via
            // [`principal_with_claims`].
            claims: Vec::new(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn with_principal(mut req: axum::http::Request<Body>) -> axum::http::Request<Body> {
        // Wrap in `AuthenticatedPrincipal` via the test-support helper.
        hort_http_core::middleware::auth::test_support::inject_principal(
            &mut req,
            test_principal(),
        );
        req
    }

    /// Seed a blob artifact at `blobs/sha256:<hex>` with CAS content.
    /// Returns the hash for wiring into manifest JSON.
    fn seed_blob(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        content: &[u8],
    ) -> ContentHash {
        let hex = format!("{:x}", Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        artifacts.insert(a);
        storage.insert_content(hash.clone(), content.to_vec());
        hash
    }

    /// Build a minimal single-image manifest JSON pointing at the
    /// supplied config + layer digests. Returns the raw bytes (the
    /// handler computes the SHA of these).
    fn build_manifest_json(config_hash: &ContentHash, layer_hashes: &[ContentHash]) -> Vec<u8> {
        let layers: Vec<serde_json::Value> = layer_hashes
            .iter()
            .map(|h| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layers,
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// Build a manifest with a `subject.digest` reference. Used for
    /// the content_references insert test.
    fn build_manifest_with_subject(
        config_hash: &ContentHash,
        layer_hashes: &[ContentHash],
        subject_hash: &ContentHash,
    ) -> Vec<u8> {
        let layers: Vec<serde_json::Value> = layer_hashes
            .iter()
            .map(|h| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.example.test",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layers,
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{}", subject_hash.as_ref()),
                "size": 0,
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// Construct a PUT request with the right media-type + body.
    fn put_request(uri: &str, body: Vec<u8>) -> axum::http::Request<Body> {
        let req = HttpRequest::put(uri)
            .header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(body))
            .unwrap();
        with_principal(req)
    }

    // -------------------- parse_manifest_tail --------------------

    #[test]
    fn parse_tail_accepts_tag_reference() {
        let t = parse_manifest_tail("library/nginx/manifests/v1").unwrap();
        assert_eq!(t.name, "library/nginx");
        assert_eq!(t.reference, "v1");
    }

    #[test]
    fn parse_tail_accepts_digest_reference() {
        let t = parse_manifest_tail("nginx/manifests/sha256:abc").unwrap();
        assert_eq!(t.name, "nginx");
        assert_eq!(t.reference, "sha256:abc");
    }

    #[test]
    fn parse_tail_rejects_missing_manifests_literal() {
        assert!(parse_manifest_tail("nginx/blobs/sha256:abc").is_none());
    }

    #[test]
    fn parse_tail_rejects_empty_name_or_reference() {
        assert!(parse_manifest_tail("/manifests/v1").is_none());
        assert!(parse_manifest_tail("nginx/manifests/").is_none());
    }

    // -------------------- PUT — happy path --------------------

    #[test]
    fn put_by_tag_commits_ingested_group_and_ref() {
        let (status, headers, group_count, ref_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            // Gather assertions from mocks after dispatch.
            let group_count = h.group_lifecycle.commit_call_count();
            let ref_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
            // Also prove the manifest artifact got committed.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let got = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap();
            assert!(got.is_some(), "manifest artifact must be committed");
            (status, headers, group_count, ref_count)
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(loc, "/v2/myrepo/library/nginx/manifests/v1");
        let dcd = headers
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            dcd.starts_with("sha256:") && dcd.len() == "sha256:".len() + 64,
            "Docker-Content-Digest shape: {dcd}"
        );
        // Three add_member calls (manifest + config + 1 layer).
        assert_eq!(group_count, 3);
        assert_eq!(ref_count, 1, "ref count for library/nginx namespace");
    }

    /// INJ-4: a PUT to an out-of-grammar tag is rejected 400 `MANIFEST_INVALID`
    /// BEFORE any ingest / ref write — the tag validator runs before the state
    /// change, so a malformed tag can never become a stored ref. The body is a
    /// well-formed manifest over unseeded blobs (never resolved, because the
    /// tag check rejects first); the 400 with an `oci.tag:` reason proves the
    /// validator fired pre-ingest, and `group_count`/`ref_count` staying 0
    /// proves no state change. The response never echoes the offending bytes.
    #[test]
    fn put_manifest_out_of_grammar_tag_rejected_400_before_ingest() {
        let over_cap = "a".repeat(129);
        let cases: [(&str, &str); 4] = [
            ("..", "double-dot path traversal"),
            (".leadingdot", "leading dot"),
            ("-leadinghyphen", "leading hyphen"),
            (&over_cap, "129-byte over-cap tag"),
        ];
        for (uri_tag, label) in cases {
            let (status, body, group_count, ref_count) = run(async {
                let h = harness();
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                h.repositories.insert(repo);
                // Well-formed manifest body over UNSEEDED blobs — never
                // resolved, because the tag check rejects before blob
                // resolution / ingest.
                let config_hash: ContentHash =
                    format!("{:x}", Sha256::digest(b"cfg")).parse().unwrap();
                let layer_hash: ContentHash =
                    format!("{:x}", Sha256::digest(b"layer")).parse().unwrap();
                let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

                let router = router().with_state(h.ctx.clone());
                let uri = format!("/v2/myrepo/library/nginx/manifests/{uri_tag}");
                let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
                let status = resp.status();
                let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                let group_count = h.group_lifecycle.commit_call_count();
                let ref_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
                (status, rbody, group_count, ref_count)
            });
            assert_eq!(status, StatusCode::BAD_REQUEST, "case: {label}");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["errors"][0]["code"], "MANIFEST_INVALID",
                "case: {label}"
            );
            let reason = parsed["errors"][0]["detail"]["reason"]
                .as_str()
                .unwrap_or("");
            assert!(
                reason.starts_with("oci.tag: "),
                "case {label}: reason must be tagged `oci.tag:` ({reason})"
            );
            assert_eq!(
                group_count, 0,
                "case {label}: no ingest before tag rejection"
            );
            assert_eq!(
                ref_count, 0,
                "case {label}: no ref written before tag rejection"
            );
        }
    }

    // -------------------- PUT — causation integrity --------------------

    #[test]
    fn put_causation_integrity() {
        // Post-ingest events (group member × 3) MUST all:
        //   (a) carry causation_id = Some(manifest_event_id) —
        //       the event_id minted by the `ArtifactIngested` commit,
        //   (b) share a SINGLE correlation_id (the handler's per-
        //       request UUID).
        //
        // This is the load-bearing audit-trail contract (C1). The
        // ingest use case has its own internal correlation_id (a
        // separate scope — ingest orchestrates its own set of
        // transitions); post-ingest events use the handler's
        // correlation_id, a common ancestor the handler generated
        // up front.
        let (ok, cross_check) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();

            // 1. Find the ArtifactIngested event_id via the lifecycle commits.
            let transitions = h.lifecycle.committed_transitions();
            let manifest_event_id = transitions
                .iter()
                .find_map(|(_, batch, _)| {
                    batch
                        .events
                        .iter()
                        .find(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
                        .map(|e| e.event_id)
                })
                .expect("ArtifactIngested must have been committed");

            // 2. Walk every group-commit batch. All must share the
            //    SAME correlation_id (proves the handler threaded
            //    one UUID through every call). All must have
            //    causation_id = Some(manifest_event_id).
            let group_commits = h.group_lifecycle.recorded_commits();
            assert!(
                group_commits.len() >= 3,
                "expected at least 3 add_member calls (manifest + config + layer), got {}",
                group_commits.len()
            );
            let handler_correlation_id = group_commits[0].batch.correlation_id;
            let mut violations: Vec<String> = Vec::new();
            for c in &group_commits {
                if c.batch.correlation_id != handler_correlation_id {
                    violations.push(format!(
                        "group batch role={} correlation_id {} != first {}",
                        c.member_role, c.batch.correlation_id, handler_correlation_id
                    ));
                }
                if c.batch.causation_id != Some(manifest_event_id) {
                    violations.push(format!(
                        "group batch role={} causation_id {:?} != Some({})",
                        c.member_role, c.batch.causation_id, manifest_event_id
                    ));
                }
            }

            // Also cross-check: the handler's correlation_id is
            // DIFFERENT from the ingest batch's internal correlation_id
            // (separate orchestration scopes). Not a correctness
            // invariant, but asserting it documents the split.
            let ingest_correlation_id = transitions
                .iter()
                .find_map(|(_, batch, _)| {
                    batch
                        .events
                        .iter()
                        .any(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
                        .then_some(batch.correlation_id)
                })
                .unwrap();

            (
                violations,
                (
                    handler_correlation_id,
                    ingest_correlation_id,
                    manifest_event_id,
                ),
            )
        });
        assert!(ok.is_empty(), "causation/correlation violations: {ok:?}");
        // Handler + ingest correlation_ids are distinct scopes.
        assert_ne!(
            cross_check.0, cross_check.1,
            "handler and ingest correlation_ids are independent"
        );
    }

    // -------------------- PUT — idempotence --------------------

    #[test]
    fn put_idempotence_second_put_emits_zero_new_events() {
        // First PUT commits a known set of events; an identical second
        // PUT must NOT emit new domain events. The invariant covers
        // three event families:
        //
        // 1. ArtifactIngested — `IngestUseCase::ingest` dedups on
        //    `(repo, path, hash)` via `find_by_path`. The mock
        //    `MockArtifactLifecycle.committed_transitions()` ticks once
        //    per accepted commit, so a stable count proves the dedup
        //    happened.
        //
        // 2. RefMoved — `RefUseCase::set` short-circuits at the use
        //    case layer when the new target equals the existing
        //    target (see `ref_use_case.rs` "no-op short-circuit").
        //    `MockRefLifecyclePort.recorded_moves()` grows ONLY on
        //    accepted commits, so a stable count proves the
        //    short-circuit fired.
        //
        // 3. ArtifactGroupMemberAdded — adapter-level invariant via
        //    `INSERT ON CONFLICT DO NOTHING` in the postgres adapter
        //    The use case ALWAYS delegates to `commit_member_added`
        //    and the mock's outcome path is
        //    Committed-by-default (it does not model ON CONFLICT). At
        //    the mock-router-test layer we therefore CANNOT assert
        //    "member event count stable" — that's an integration-test
        //    invariant. We DO assert `commit_call_count` grew by
        //    exactly the per-PUT delta (3: manifest + config + layer)
        //    so a regression that drops the delegation entirely would
        //    fail. The "zero new events" property for member-added
        //    must be re-asserted at the postgres adapter level.
        let (
            first_lifecycle,
            second_lifecycle,
            first_moves,
            second_moves,
            first_group_calls,
            second_group_calls,
        ) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";

            let resp1 = router
                .clone()
                .oneshot(put_request(uri, body.clone()))
                .await
                .unwrap();
            assert_eq!(resp1.status(), StatusCode::CREATED);
            let first_lifecycle = h.lifecycle.committed_transitions().len();
            let first_moves = h.ref_lifecycle.recorded_moves().len();
            let first_group_calls = h.group_lifecycle.commit_call_count();

            let resp2 = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp2.status(), StatusCode::CREATED);
            let second_lifecycle = h.lifecycle.committed_transitions().len();
            let second_moves = h.ref_lifecycle.recorded_moves().len();
            let second_group_calls = h.group_lifecycle.commit_call_count();
            (
                first_lifecycle,
                second_lifecycle,
                first_moves,
                second_moves,
                first_group_calls,
                second_group_calls,
            )
        });
        // 1. ArtifactIngested dedup — count unchanged.
        assert_eq!(
            first_lifecycle, second_lifecycle,
            "manifest ArtifactIngested must dedup; lifecycle commits grew from {first_lifecycle} to {second_lifecycle}"
        );
        // 2. RefMoved short-circuit — count unchanged. First PUT
        //    creates the tag (1 move); second PUT with same target
        //    must short-circuit (still 1).
        assert_eq!(
            first_moves, 1,
            "first tag-PUT must create exactly one ref move, got {first_moves}"
        );
        assert_eq!(
            first_moves, second_moves,
            "RefMoved must short-circuit on same-target PUT; recorded_moves grew from {first_moves} to {second_moves}"
        );
        // 3. ArtifactGroupMemberAdded delegation — adapter contract.
        //    Use case always delegates; mock cannot witness ON CONFLICT
        //    DO NOTHING. Assert the per-PUT delegation delta so a
        //    regression that breaks the delegation entirely is caught.
        let group_delta_per_put = 3; // manifest + config + layer
        assert_eq!(
            first_group_calls, group_delta_per_put,
            "first PUT must delegate add_member 3× (manifest + config + layer), got {first_group_calls}"
        );
        assert_eq!(
            second_group_calls,
            2 * group_delta_per_put,
            "second PUT must also delegate 3× (adapter-level ON CONFLICT DO NOTHING is the no-op guard); commit_call_count={second_group_calls}"
        );
    }

    // -------------------- #73 step 1: diagnosability --------------------
    //
    // `put_idempotence_second_put_emits_zero_new_events` above (and the
    // `*_idempotent_on_repush` / `oci_manifest_put_idempotent_*` tests
    // elsewhere in this module) already exercise the idempotent-success
    // path end to end and continue to pass unchanged — confirming no
    // behaviour change on the success path. The tests below cover the
    // NEW diagnosability behaviour: a genuine (non-idempotent) Conflict
    // from `add_member` is logged at `error!` with rich context, not
    // silently folded into an unlogged 500.

    /// Custom tracing layer that captures emitted events into a shared
    /// vector. Mirrors the identical pattern in
    /// `crates/hort-http-pypi/src/upstream_pull.rs` (and the cargo / npm
    /// siblings) — see that module for the detailed rationale on
    /// `Interest::sometimes()`, per-callsite caching, and the
    /// global-passthrough seeding.
    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    /// Serialises tests that install per-thread tracing subscribers.
    /// `tracing` caches per-callsite `Interest` globally; installing one
    /// subscriber on thread A while thread B fires the same callsite
    /// races. The mutex eliminates the race without touching global state.
    static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Install a global passthrough subscriber (once per process) so the
    /// per-callsite cache is seeded with `Interest::sometimes()` rather
    /// than `Never`. Without this, a no-op subscriber installed by any
    /// earlier test can cache `Never` for our callsites and prevent the
    /// per-thread `set_default` subscriber from ever seeing those events.
    fn install_global_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = CapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    /// #73 step 1 acceptance: a genuine (non-idempotent) `Conflict` from
    /// `add_member`'s manifest-attach call is logged at `error!` with
    /// the manifest digest, repo key, stage, and the full `DomainError`
    /// (variant + message) — not folded into a silent `warn!` the way
    /// it used to be. The response stays a 500 (no wire-behaviour
    /// change, per the directive's diagnosability-first scope); what
    /// changed is that the failure is now legible from the logs.
    #[test]
    fn divergent_add_member_conflict_is_logged_at_error_not_swallowed() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let status = rt.block_on(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            // Force the FIRST add_member call (the "manifest" primary
            // attach) to observe a genuine divergence — mirrors the
            // real `commit_member_added` "primary role mismatch" /
            // "already belongs with a different role" Conflict shapes,
            // neither of which is idempotent-collapsible (see the
            // `group_attach_manifest` call site's own comment).
            h.group_lifecycle.inject(GroupCommitInjection::Conflict {
                reason: "primary role mismatch: existing `config`, requested `manifest`".into(),
            });

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            resp.status()
        });

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "no wire-behaviour change: a genuine Conflict is still a 500"
        );

        let records = captured.lock().unwrap();
        let error_event = records
            .iter()
            .find(|(lvl, msg)| {
                *lvl == tracing::Level::ERROR
                    && msg.contains("group-attach failed")
                    && msg.contains("genuine error")
            })
            .map(|(_, msg)| msg.clone());
        assert!(
            error_event.is_some(),
            "expected an ERROR-level log naming the group-attach failure as genuine; \
             captured records: {:?}",
            records
                .iter()
                .map(|(l, m)| format!("{l:?}: {m}"))
                .collect::<Vec<_>>()
        );
        let msg = error_event.unwrap();
        assert!(
            msg.contains("stage=group_attach_manifest"),
            "expected the stage field in the log line, got: {msg}"
        );
        assert!(
            msg.contains("error=Domain(Conflict"),
            "expected the full DomainError (variant + message) via Debug formatting, got: {msg}"
        );
        // No pre-existing WARN-level "partial attachment" line for this
        // failure — confirms the old silent-warn path is gone, not just
        // supplemented.
        assert!(
            !records.iter().any(
                |(lvl, msg)| *lvl == tracing::Level::WARN && msg.contains("partial attachment")
            ),
            "the old warn!-level 'partial attachment' message must be fully replaced, not \
             merely supplemented"
        );
    }

    // -------------------- PUT — digest ref --------------------

    #[test]
    fn put_by_digest_does_not_emit_ref_moved() {
        // A digest-reference PUT must NOT create a tag ref. Two
        // independent witnesses for the same invariant:
        //
        // - Projection level (`refs.list().len() == 0`) — proves no
        //   ref row landed.
        // - Lifecycle level (`recorded_moves().len() == 0`) — proves
        //   the use case never even called `move_ref`. This is the
        //   tighter assertion: a future bug that emits a RefMoved
        //   event but rolls back the projection write would slip past
        //   the projection check, but `recorded_moves` would still
        //   tick. Both checks together guard the audit-trail integrity
        //   the OCI spec mandates for digest-self-naming PUTs.
        let (ref_count, recorded_moves_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{manifest_hex}");
            let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            (
                h.refs.list(repo_id, "library/nginx").await.unwrap().len(),
                h.ref_lifecycle.recorded_moves().len(),
            )
        });
        assert_eq!(
            ref_count, 0,
            "digest-reference PUT must not create a ref row"
        );
        assert_eq!(
            recorded_moves_count, 0,
            "digest-reference PUT must not invoke move_ref (no RefMoved event)"
        );
    }

    // -------------------- PUT — mismatched declared digest --------------------

    #[test]
    fn put_by_digest_with_mismatched_declared_returns_400_manifest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let body = build_manifest_json(&config_hash, &[]);
            // Use the WRONG digest in the URL — any 64-char hex that
            // isn't the real body's SHA.
            let wrong_hex = "a".repeat(64);
            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{wrong_hex}");
            let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Must be MANIFEST_INVALID (NOT UNSUPPORTED).
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
    }

    // -------------------- PUT — subject --------------------

    #[test]
    fn put_with_subject_inserts_content_reference() {
        // Every ArtifactIngested also writes a `kind = "primary_content"`
        // refcount row (ADR 0020). So a PUT-with-subject now produces TWO
        // content_references rows: one `oci_subject` (from the OCI write
        // path, asserted here) and one `primary_content` (from the ingest
        // path, covered by dedicated tests in `hort-app::ingest_use_case`).
        // This test counts only `oci_subject` rows so the OCI Referrers
        // contract stays load-bearing without coupling to the ingest-path
        // refcount surface.
        let (status, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            // Count `oci_subject` rows specifically — the row pointing
            // at `subject_hash` from the manifest source artifact.
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            (status, oci_subject_rows)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            oci_subject_rows, 1,
            "content_references must carry one oci_subject row after PUT with subject"
        );
    }

    #[test]
    fn put_with_subject_reference_carries_expected_metadata() {
        // Sanity-check the metadata shape stored — the Referrers API
        // depends on `artifact_type` + `media_type` being present on
        // the row so the response body can rebuild the descriptor.
        let (kind, artifact_type_ok, media_type_ok) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);
            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            router.oneshot(put_request(uri, body)).await.unwrap();

            let rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap();
            assert_eq!(rows.len(), 1, "one row per subject");
            let r = &rows[0];
            (
                r.kind.clone(),
                r.metadata.get("artifact_type").is_some(),
                r.metadata.get("media_type").is_some(),
            )
        });
        assert_eq!(kind, "oci_subject");
        assert!(artifact_type_ok, "metadata.artifact_type must be present");
        assert!(media_type_ok, "metadata.media_type must be present");
    }

    // ----------------------------------------------------------------
    // Signature manifest routing: signatures are NOT quarantined —
    // route a pure Sigstore-bundle referrer to the narrow
    // `ingest_signature_manifest` path; everything else stays on
    // `ingest_verified`. The distinguishing observable is the scan-job
    // enqueue: `ingest_verified` enqueues a scan (the seeded HTTP-test
    // policy carries `scan_backends: ["trivy"]`); the narrow path does
    // NOT. The `oci_subject` content-reference write is unchanged on
    // both paths.
    // ----------------------------------------------------------------

    const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /// Build a referrer manifest whose layers all carry `layer_media_types`
    /// (in order), with a `subject.digest` pointing at `subject_hash` and a
    /// declared `artifactType`. The config + every layer digest are seeded
    /// blobs so the OCI write path's blob resolution succeeds.
    fn build_referrer_manifest(
        config_hash: &ContentHash,
        layers: &[(&str, &ContentHash)],
        subject_hash: &ContentHash,
        artifact_type: &str,
    ) -> Vec<u8> {
        let layer_values: Vec<serde_json::Value> = layers
            .iter()
            .map(|(mt, h)| {
                serde_json::json!({
                    "mediaType": mt,
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": artifact_type,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layer_values,
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{}", subject_hash.as_ref()),
                "size": 0,
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// (a) A PUT of a PURE Sigstore-bundle referrer (subject.digest set,
    /// single bundle layer) routes to `ingest_signature_manifest`:
    /// the artifact is status `None`, NO scan job is enqueued, and the
    /// `oci_subject` content-reference row is still written.
    #[test]
    fn put_pure_sigstore_bundle_referrer_is_not_quarantined_or_scanned() {
        let (status, scan_calls, oci_subject_rows, artifact_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
            let bundle_hash =
                seed_blob(&h.artifacts, &h.storage, repo_id, b"the-cosign-bundle-json");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-signed-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[(SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash)],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sig";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();

            let scan_calls = h.lifecycle.scan_enqueues().len();
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            // The committed manifest artifact must be status None.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let artifact_status = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .map(|a| a.quarantine_status);
            (status, scan_calls, oci_subject_rows, artifact_status)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            scan_calls, 0,
            "a pure Sigstore-bundle referrer must NOT enqueue a scan job (narrow path)"
        );
        assert_eq!(
            oci_subject_rows, 1,
            "the oci_subject content-reference row must still be written"
        );
        assert_eq!(
            artifact_status,
            Some(QuarantineStatus::None),
            "the signature manifest artifact must be status None (not quarantined)"
        );
    }

    /// (b) THE SECURITY GUARD — a MIXED manifest (one bundle layer + one
    /// runnable `tar+gzip` layer, subject.digest set) is NOT exempted: it
    /// stays on `ingest_verified` and IS scanned. A pusher cannot smuggle a
    /// runnable layer past the scanner by labelling one layer a bundle.
    #[test]
    fn put_mixed_bundle_plus_tar_gzip_referrer_is_still_scanned() {
        let scan_calls = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"mixed-config-bytes");
            let bundle_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"a-real-bundle");
            let malware_hash =
                seed_blob(&h.artifacts, &h.storage, repo_id, b"runnable-malware-layer");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"victim-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[
                    (SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash),
                    ("application/vnd.oci.image.layer.v1.tar+gzip", &malware_hash),
                ],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sig";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            h.lifecycle.scan_enqueues().len()
        });
        assert_eq!(
            scan_calls, 1,
            "a MIXED manifest carrying a runnable tar+gzip layer must NOT be exempted — it stays scanned (anti-scan-evasion guard)"
        );
    }

    /// (c) A normal image manifest (NO subject, tar+gzip layers) is
    /// unchanged: it routes via `ingest_verified` and IS scanned.
    #[test]
    fn put_normal_image_manifest_is_scanned_unchanged() {
        let scan_calls = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            h.lifecycle.scan_enqueues().len()
        });
        assert_eq!(
            scan_calls, 1,
            "a normal image manifest must stay on ingest_verified and be scanned"
        );
    }

    /// (d) A non-Sigstore referrer (subject.digest set, single SBOM-typed
    /// layer) is NOT exempted — only PURE Sigstore-bundle referrers are.
    /// It stays on `ingest_verified` and IS scanned.
    #[test]
    fn put_non_sigstore_sbom_referrer_is_still_scanned() {
        let (scan_calls, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sbom-config-bytes");
            let sbom_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-spdx-sbom");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"described-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[("application/spdx+json", &sbom_hash)],
                &subject_hash,
                "application/spdx+json",
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sbom";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let scan_calls = h.lifecycle.scan_enqueues().len();
            // The oci_subject row is still written (the referrer machinery
            // is unchanged) — only the lifecycle treatment differs.
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            (scan_calls, oci_subject_rows)
        });
        assert_eq!(
            scan_calls, 1,
            "a non-Sigstore (SBOM) referrer must stay on ingest_verified and be scanned"
        );
        assert_eq!(
            oci_subject_rows, 1,
            "oci_subject row still written for the SBOM referrer"
        );
    }

    /// Idempotency regression guard: pushing the same manifest with the same
    /// `subject.digest` twice must produce exactly ONE `oci_subject`
    /// row. Pins the `(repo, source, kind)` upsert shape against
    /// future PK drift — a regression that flipped the conflict target
    /// to `(repo, source)` (without `kind`) would silently start
    /// replacing the `primary_content` row with the `oci_subject` row
    /// on the second PUT, breaking the refcount projection (ADR 0020).
    #[test]
    fn oci_manifest_put_idempotent_single_oci_subject_row() {
        let (status_first, status_second, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes-idem");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes-idem");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);

            let uri = "/v2/myrepo/library/nginx/manifests/v1";

            // First PUT — establishes both rows (oci_subject + primary_content).
            let r1 = router().with_state(h.ctx.clone());
            let resp1 = r1.oneshot(put_request(uri, body.clone())).await.unwrap();
            let status_first = resp1.status();

            // Second PUT, same manifest body — must upsert the
            // existing `oci_subject` row, not append a new one.
            // Build a fresh router because Service<Request> is consumed
            // by `oneshot`.
            let r2 = router().with_state(h.ctx.clone());
            let resp2 = r2.oneshot(put_request(uri, body)).await.unwrap();
            let status_second = resp2.status();

            // Count `oci_subject` rows pointing at the subject from
            // the manifest source — should be exactly one regardless
            // of how many PUTs landed.
            let rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap();
            (status_first, status_second, rows.len())
        });
        assert_eq!(status_first, StatusCode::CREATED);
        assert_eq!(status_second, StatusCode::CREATED);
        assert_eq!(
            oci_subject_rows, 1,
            "idempotent re-push must upsert the oci_subject row, not append"
        );
    }

    // -------------------- PUT — malformed subject digest (N-5) --------

    #[test]
    fn put_with_malformed_subject_digest_returns_400_manifest_invalid_pre_ingest() {
        // Subject digest pre-validation runs BEFORE manifest ingest.
        // A malformed `subject.digest` must surface as 400
        // MANIFEST_INVALID with no state change — no manifest artifact
        // committed, no group attached, no content_references row
        // inserted. (Previously this was a 500 returned at the tail of
        // the handler, after the manifest had already been committed,
        // leaving a half-attached state.)
        let (status, body, manifest_present, content_ref_count, lifecycle_commits) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");

            // Construct a manifest body whose subject.digest is a
            // syntactically broken string (no algorithm prefix).
            let body = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.example.test",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": format!("sha256:{}", config_hash.as_ref()),
                    "size": 0,
                },
                "layers": [],
                "subject": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "this-is-not-a-valid-digest",
                    "size": 0,
                },
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            let manifest_hex = format!("{:x}", Sha256::digest(&body_bytes));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body_bytes)).await.unwrap();
            let status = resp.status();
            let resp_body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();

            // The manifest artifact must NOT be committed — pre-ingest
            // validation rejected the request.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let manifest_present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            let content_ref_count = h.content_references.entry_count();
            let lifecycle_commits = h.lifecycle.committed_transitions().len();
            (
                status,
                resp_body,
                manifest_present,
                content_ref_count,
                lifecycle_commits,
            )
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        let detail = &parsed["errors"][0]["detail"];
        assert_eq!(detail["field"], "subject.digest");
        assert!(
            !manifest_present,
            "malformed subject.digest must reject pre-ingest; manifest artifact must NOT land"
        );
        assert_eq!(
            content_ref_count, 0,
            "no content_references row may be inserted on the rejection path"
        );
        assert_eq!(
            lifecycle_commits, 0,
            "no ArtifactIngested event must be committed on the rejection path"
        );
    }

    #[test]
    fn put_with_unsupported_subject_digest_algo_returns_400_manifest_invalid() {
        // sha512 (or any non-sha256) on subject.digest is treated the
        // same as a malformed digest at this layer — rejected pre-
        // ingest with MANIFEST_INVALID. The detail must NOT echo the
        // requested algorithm string — it's attacker-controlled
        // manifest-JSON content (never-echo-rejected-input rule).
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");

            let body = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": format!("sha256:{}", config_hash.as_ref()),
                    "size": 0,
                },
                "layers": [],
                "subject": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha512:{}", "f".repeat(128)),
                    "size": 0,
                },
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body_bytes,
                ))
                .await
                .unwrap();
            (
                resp.status(),
                to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec(),
            )
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(parsed["errors"][0]["detail"]["field"], "subject.digest");
        assert!(parsed["errors"][0]["detail"]["algorithm"].is_null());
        assert!(
            !String::from_utf8_lossy(&body).contains("sha512"),
            "response body must not echo the rejected subject.digest algorithm"
        );
    }

    // -------------------- PUT — missing blob --------------------

    #[test]
    fn put_with_missing_blob_returns_400_manifest_blob_unknown() {
        let (status, body, group_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed config but NOT the layer.
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            // Build a "missing" layer hash — never seeded.
            let missing_content = b"never-pushed-layer";
            let missing_hex = format!("{:x}", Sha256::digest(missing_content));
            let missing_hash: ContentHash = missing_hex.parse().unwrap();
            let body = build_manifest_json(&config_hash, &[missing_hash]);
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            // Assert the manifest artifact IS committed — the client
            // retries after pushing the blob.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let found = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap();
            assert!(
                found.is_some(),
                "manifest artifact must persist so client retry reconciles"
            );
            // Group must NOT have been created.
            let group_count = h.group_lifecycle.commit_call_count();
            (status, body, group_count)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        let blobs = parsed["errors"][0]["detail"]["blobs"].as_array().unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(
            blobs[0].as_str().unwrap().starts_with("sha256:"),
            "blobs detail must echo raw sha256:<hex> shape"
        );
        assert_eq!(
            group_count, 0,
            "group must NOT be created on missing-blob path"
        );
    }

    #[test]
    fn put_with_foreign_repo_blob_digest_returns_400_manifest_blob_unknown() {
        // Cross-repo isolation: a blob that exists in repo_B is
        // invisible to repo_A's manifest push. The handler must
        // treat the hit as missing and surface MANIFEST_BLOB_UNKNOWN.
        let status = run(async {
            let h = harness();
            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            let repo_b_id = repo_b.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);
            // Seed the config in repo_A.
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"config-bytes");
            // Seed the layer ONLY in repo_B.
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_b_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            // PUT to repo_A — layer lives in repo_B and must count
            // as missing.
            let uri = "/v2/repo-a/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Blob resolution cross-repo isolation regression guard (ADR 0008).
    ///
    /// When the same SHA-256 lives in two repos, a cross-repo
    /// `find_by_checksum` followed by `repository_id == repo` post-filter
    /// returns rows in adapter-defined order — if the foreign-repo row
    /// comes first, the filter spuriously rejects a same-repo-present blob
    /// as `MANIFEST_BLOB_UNKNOWN`. The correct path routes through
    /// `ArtifactUseCase::find_in_repo_by_hash` which scopes the SQL
    /// query to the target repo at the port boundary.
    ///
    /// Test shape: seed identical SHA in repo_a (config + layer) AND
    /// repo_b (layer only — different artifact rows, same hash).
    /// Push the manifest to repo_a. Pre-fix outcome was probabilistic
    /// (depends on adapter ordering); post-fix outcome is always 201.
    #[test]
    fn put_with_same_sha_in_two_repos_resolves_to_target_repo_blob() {
        let (status, body) = run(async {
            let h = harness();

            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            let repo_b_id = repo_b.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);

            // Seed the config + layer in repo_a (legitimate blobs the
            // manifest references).
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"layer-bytes");

            // Seed an additional row with the SAME layer SHA in
            // repo_b — different artifact id, identical content hash.
            // This is the scenario where pre-fix `find_by_checksum`
            // could return repo_b's row first and incorrectly reject
            // the manifest push to repo_a.
            let mut foreign = sample_artifact(QuarantineStatus::None);
            foreign.repository_id = repo_b_id;
            foreign.path = format!("blobs/sha256:{}", layer_hash.as_ref());
            foreign.sha256_checksum = layer_hash.clone();
            foreign.size_bytes = b"layer-bytes".len() as i64;
            h.artifacts.insert(foreign);

            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/repo-a/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        // Post-fix: the use case scopes the SHA lookup to repo_a's id
        // at the port boundary, returns the right row, manifest is
        // accepted with 201 Created.
        assert_eq!(
            status,
            StatusCode::CREATED,
            "manifest PUT must succeed when its blobs are present in the target repo, \
             regardless of foreign-repo rows sharing the same SHA-256: body = {}",
            String::from_utf8_lossy(&body)
        );
    }

    // -------------------- PUT — unsupported content-type --------------------

    #[test]
    fn put_unsupported_content_type_returns_400_manifest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            h.repositories.insert(repo);
            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::put("/v2/myrepo/library/nginx/manifests/v1")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(b"{}".to_vec()))
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
    }

    // -------------------- PUT — image index / manifest list --------------------
    //
    // An image index / manifest list is accepted on PUT (issue #15, Item
    // 2). Its `manifests[*].digest` children are resolved as **manifests**
    // via the same same-repo existence path a layer uses; a missing child
    // → `MANIFEST_BLOB_UNKNOWN` (clients push children before the index).
    // The index lands as a plain primary `manifest` group member (no
    // config, no layers). Single-image PUTs are byte-for-byte unchanged.

    /// Build a minimal image-index JSON referencing the supplied child
    /// **manifest** digests via `manifests[*]`. `media_type` selects the
    /// OCI-index or Docker-manifest-list shape.
    fn build_index_json(child_hashes: &[ContentHash], media_type: &str) -> Vec<u8> {
        let manifests: Vec<serde_json::Value> = child_hashes
            .iter()
            .map(|h| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                    "platform": { "architecture": "amd64", "os": "linux" },
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media_type,
            "manifests": manifests,
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// Build a PUT request with an image-index Content-Type + body.
    fn put_index_request(uri: &str, body: Vec<u8>, media_type: &str) -> axum::http::Request<Body> {
        let req = HttpRequest::put(uri)
            .header(CONTENT_TYPE, media_type)
            .body(Body::from(body))
            .unwrap();
        with_principal(req)
    }

    /// A PUT of an image index whose children are all present in-repo is
    /// accepted (201) and lands as a committed `manifest` artifact with a
    /// single primary group member (no config / layer members).
    #[test]
    fn put_image_index_with_present_children_is_committed_as_manifest() {
        let (status, headers, group_calls, manifest_present, manifest_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed the two platform child manifests as artifacts in-repo.
            let child_a = seed_blob(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let child_b = seed_blob(&h.artifacts, &h.storage, repo_id, b"arm64-child-manifest");
            let body = build_index_json(
                &[child_a, child_b],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            // ONE add_member call — the primary manifest. No config /
            // layer members for an index.
            let group_calls = h.group_lifecycle.commit_call_count();
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let a = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap();
            let manifest_status = a.as_ref().map(|a| a.quarantine_status);
            (status, headers, group_calls, a.is_some(), manifest_status)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert!(manifest_present, "index must commit as a manifest artifact");
        // The index rides the generic `ingest_verified` manifest lifecycle
        // (NOT the narrow signature path). Under this crate's permissive
        // HTTP-test policy (`quarantine_duration_secs = 0`) ingest does not
        // auto-quarantine, so the committed status is `None` — the same
        // result a single-image manifest gets here. (The generic
        // quarantine-on-ingest posture of Design §2 D4 is asserted at
        // Item 4 with a quarantine-fired policy.)
        assert_eq!(
            manifest_status,
            Some(QuarantineStatus::None),
            "the index rides the generic ingest_verified path (permissive fixture → None)"
        );
        let dcd = headers
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            dcd.starts_with("sha256:") && dcd.len() == "sha256:".len() + 64,
            "Docker-Content-Digest shape: {dcd}"
        );
        assert_eq!(
            group_calls, 1,
            "an index attaches ONLY the primary manifest member (no config / layers)"
        );
    }

    /// A PUT of an image index records exactly one `oci_index_member`
    /// content-reference row per parsed child manifest: `source =` the
    /// index artifact, `target =` the child's own content hash,
    /// `kind = "oci_index_member"` — no more, no fewer. This pins the D3
    /// membership-write loop at the handler layer: a regression that
    /// writes the wrong `kind`/`target`, skips a child, or writes a member
    /// row for a hash the index did not name fails here. Inspection is via
    /// the mock's `find_by_target` (keyed by target hash + kind), the same
    /// accessor the `oci_subject` test uses — each child hash is a
    /// distinct target, so the widened-PK mock keeps all N rows.
    #[test]
    fn put_image_index_records_oci_index_member_rows_for_each_child() {
        let (
            status,
            member_rows_a,
            member_rows_b,
            source_a,
            source_b,
            index_artifact_id,
            spurious_member_rows,
        ) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child_a = seed_blob(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let child_b = seed_blob(&h.artifacts, &h.storage, repo_id, b"arm64-child-manifest");
            let body = build_index_json(
                &[child_a.clone(), child_b.clone()],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();

            // The index artifact is the source of every member row.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let index_artifact_id = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .expect("index committed as artifact")
                .id;

            // One `oci_index_member` row per child, keyed by the child's
            // own content hash as the target.
            let rows_a = h
                .content_references
                .find_by_target(repo_id, &child_a, Some("oci_index_member"))
                .await
                .unwrap();
            let rows_b = h
                .content_references
                .find_by_target(repo_id, &child_b, Some("oci_index_member"))
                .await
                .unwrap();
            let source_a = rows_a.first().map(|r| r.source_artifact_id);
            let source_b = rows_b.first().map(|r| r.source_artifact_id);

            // No `oci_index_member` row for a hash the index never named —
            // proves the loop wrote members for exactly the parsed children
            // (a spurious/mis-targeted write would surface here). We probe a
            // hash that IS present in-repo (the index's own manifest digest)
            // but is not one of the two child descriptors.
            let index_own_hash: ContentHash = manifest_hex.parse().unwrap();
            let spurious = h
                .content_references
                .find_by_target(repo_id, &index_own_hash, Some("oci_index_member"))
                .await
                .unwrap();
            (
                status,
                rows_a.len(),
                rows_b.len(),
                source_a,
                source_b,
                index_artifact_id,
                spurious.len(),
            )
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(member_rows_a, 1, "one oci_index_member row for child A");
        assert_eq!(member_rows_b, 1, "one oci_index_member row for child B");
        assert_eq!(
            source_a,
            Some(index_artifact_id),
            "child A member row's source is the index artifact"
        );
        assert_eq!(
            source_b,
            Some(index_artifact_id),
            "child B member row's source is the index artifact"
        );
        assert_eq!(
            spurious_member_rows, 0,
            "no oci_index_member row is written for a hash the index did not name as a child"
        );
    }

    /// #46 Item 1: a single-image manifest PUT with N layers + 1 config
    /// writes N+1 `content_references` blob edges — one `oci_config` row
    /// (`target = config hash`) and one `oci_layer` row per layer
    /// (`target = layer hash`), all `source = manifest artifact`. Mirrors
    /// `put_image_index_records_oci_index_member_rows_for_each_child`.
    #[test]
    fn put_single_image_manifest_records_oci_config_and_oci_layer_rows() {
        let (
            status,
            config_rows,
            layer_a_rows,
            layer_b_rows,
            source_config,
            source_layer_a,
            source_layer_b,
            manifest_artifact_id,
        ) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_a = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-a-bytes");
            let layer_b = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-b-bytes");
            let body = build_manifest_json(&config_hash, &[layer_a.clone(), layer_b.clone()]);
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();

            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let manifest_artifact_id = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .expect("manifest committed as artifact")
                .id;

            let config_rows = h
                .content_references
                .find_by_target(repo_id, &config_hash, Some("oci_config"))
                .await
                .unwrap();
            let layer_a_rows = h
                .content_references
                .find_by_target(repo_id, &layer_a, Some("oci_layer"))
                .await
                .unwrap();
            let layer_b_rows = h
                .content_references
                .find_by_target(repo_id, &layer_b, Some("oci_layer"))
                .await
                .unwrap();
            let source_config = config_rows.first().map(|r| r.source_artifact_id);
            let source_layer_a = layer_a_rows.first().map(|r| r.source_artifact_id);
            let source_layer_b = layer_b_rows.first().map(|r| r.source_artifact_id);
            (
                status,
                config_rows.len(),
                layer_a_rows.len(),
                layer_b_rows.len(),
                source_config,
                source_layer_a,
                source_layer_b,
                manifest_artifact_id,
            )
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(config_rows, 1, "one oci_config row for the config blob");
        assert_eq!(layer_a_rows, 1, "one oci_layer row for layer A");
        assert_eq!(layer_b_rows, 1, "one oci_layer row for layer B");
        assert_eq!(
            source_config,
            Some(manifest_artifact_id),
            "oci_config row's source is the manifest artifact"
        );
        assert_eq!(
            source_layer_a,
            Some(manifest_artifact_id),
            "oci_layer row (layer A)'s source is the manifest artifact"
        );
        assert_eq!(
            source_layer_b,
            Some(manifest_artifact_id),
            "oci_layer row (layer B)'s source is the manifest artifact"
        );
    }

    // -----------------------------------------------------------------
    // Write contention on the manifest-PUT path.
    //
    // The reported symptom was an intermittent 500 on concurrent hosted
    // manifest PUTs. The storage adapter now classifies a Postgres
    // concurrency abort as `DomainError::Contended` and retries the write
    // itself, bounded; these two cases pin what the OCI edge does with the
    // classification once that budget is spent, and — just as importantly —
    // what it does NOT do to everything else.
    // -----------------------------------------------------------------

    /// Persistent write contention on a content-reference edge answers
    /// **503 + `Retry-After`**, not 500.
    ///
    /// The client's manifest was valid and nothing was half-applied, so the
    /// correct instruction is "ask again shortly". A 500 tells it, and the
    /// operator's alerting, that the registry is broken — which is how this
    /// class of failure came to be reported as an intermittent server bug in
    /// the first place.
    #[test]
    fn edge_write_contention_returns_503_with_retry_after_not_500() {
        let (status, retry_after) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer]);

            // The config edge is the one sibling manifests of a single push
            // share by construction (every attestation manifest in a
            // buildkit index references the same empty-config blob), so it
            // is the realistic contention point.
            h.content_references.fail_next_insert_for_kind(
                "oci_config",
                DomainError::Contended(
                    "content-reference upsert aborted by concurrent write contention \
                     (SQLSTATE 40P01)"
                        .into(),
                ),
            );

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            (status, retry_after)
        });
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "persistent write contention is a busy registry, not a broken one"
        );
        assert_eq!(
            retry_after.as_deref(),
            Some(MANIFEST_CONTENTION_RETRY_AFTER_SECS.to_string().as_str()),
            "a contention 503 must tell the client when to come back — without it \
             the client has no instruction it can act on"
        );
    }

    /// The complement, and the reason the retry classification has to be
    /// narrow: a genuine adapter failure on the same edge still answers
    /// **500**. Widening the contention arm to any error would silently
    /// convert real faults into "retry shortly" and hide them behind
    /// clients that dutifully do.
    #[test]
    fn edge_write_genuine_failure_still_returns_500() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer]);

            h.content_references.fail_next_insert_for_kind(
                "oci_config",
                DomainError::Invariant("database error: connection reset".into()),
            );

            let router = router().with_state(h.ctx.clone());
            router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap()
                .status()
        });
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "only a contention abort is retryable; a real fault must stay a 500"
        );
    }

    /// ADR 0060 adoption: a member-append `Conflict` that survives
    /// every retry attempt inside `ArtifactGroupUseCase::add_member`
    /// surfaces as `DomainError::Contended`, which the
    /// `group_attach_manifest` site must map to 503 + `Retry-After` —
    /// never a bare 500. Pre-seeding the group with the SAME primary
    /// role the manifest attach claims means `decide_primary_role`
    /// resolves to `None` (already primary, no assignment), so the
    /// injected `Conflict`s land on the retry-eligible member-append
    /// path rather than the unretried primary-role-claim path.
    #[test]
    fn group_attach_exhausted_contention_returns_503_not_500() {
        let (status, retry_after) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let manifest_digest = compute_sha256(&body);

            h.artifact_groups.insert(ArtifactGroup {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                coords: oci_group_coords("library/nginx", &manifest_digest),
                primary_role: "manifest".into(),
                members: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
            // Comfortably more than hort-app's retry bound (5) so
            // exhaustion is reached regardless of the exact count.
            for _ in 0..10 {
                h.group_lifecycle.inject(GroupCommitInjection::Conflict {
                    reason: "persistent member-append contention".into(),
                });
            }

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            (status, retry_after)
        });
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "exhausted member-append contention is a busy registry, not a broken one"
        );
        assert_eq!(
            retry_after.as_deref(),
            Some(MANIFEST_CONTENTION_RETRY_AFTER_SECS.to_string().as_str()),
            "a contention 503 must tell the client when to come back"
        );
    }

    /// ADR 0060 adoption: an append `Conflict` that survives every
    /// retry attempt inside `RefUseCase::set` surfaces as
    /// `DomainError::Contended`, which the `ref_set` site must map to
    /// 503 + `Retry-After` — never a bare 500.
    #[test]
    fn ref_set_exhausted_contention_returns_503_not_500() {
        let (status, retry_after) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            // Seed the tag at a target the PUT's digest will differ
            // from, so `RefUseCase::set` actually dispatches a move
            // (not a same-target no-op) and reaches `move_ref`.
            h.refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                namespace: "library/nginx".into(),
                ref_name: "v1".into(),
                target: RefTarget::Version("stale".into()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
            // Comfortably more than hort-app's retry bound (5).
            for _ in 0..10 {
                h.ref_lifecycle
                    .inject_move_conflict("persistent ref-append contention");
            }

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            (status, retry_after)
        });
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "exhausted ref-append contention is a busy registry, not a broken one"
        );
        assert_eq!(
            retry_after.as_deref(),
            Some(MANIFEST_CONTENTION_RETRY_AFTER_SECS.to_string().as_str()),
            "a contention 503 must tell the client when to come back"
        );
    }

    /// The classifier itself, over the whole error surface it has to
    /// discriminate. The router cases above prove the two ends are wired;
    /// this pins the middle so a future variant cannot quietly join the
    /// retryable side.
    #[test]
    fn manifest_write_contention_classifies_only_contended() {
        assert!(
            manifest_write_contention(
                &AppError::Domain(DomainError::Contended("x".into())),
                "test"
            )
            .is_some(),
            "Contended is the retryable class"
        );
        for other in [
            DomainError::Conflict("duplicate".into()),
            DomainError::Invariant("boom".into()),
            DomainError::Validation("bad".into()),
            DomainError::NotFound {
                entity: "Artifact",
                id: "x".into(),
            },
            DomainError::InvalidState("held".into()),
        ] {
            assert!(
                manifest_write_contention(&AppError::Domain(other.clone()), "test").is_none(),
                "{other:?} must not be answered as retryable contention"
            );
        }
    }

    /// An image **index** PUT writes **zero** `oci_config`/`oci_layer`
    /// blob edges — an index has no config/layers (only child manifests,
    /// covered by `oci_index_member` above). Pins the "index unchanged"
    /// half of the #46 Item 1 acceptance.
    #[test]
    fn put_image_index_records_zero_oci_config_or_oci_layer_rows() {
        let (status, config_rows, layer_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_blob(&h.artifacts, &h.storage, repo_id, b"child-manifest-bytes");
            let body = build_index_json(
                std::slice::from_ref(&child),
                "application/vnd.oci.image.index.v1+json",
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();

            // No `oci_config`/`oci_layer` row for the child hash, nor for
            // any other kind our test can probe — the loop is a no-op on
            // the index path (the `referenced` list carries only
            // `ChildManifest` entries there).
            let config_rows = h
                .content_references
                .find_by_target(repo_id, &child, Some("oci_config"))
                .await
                .unwrap();
            let layer_rows = h
                .content_references
                .find_by_target(repo_id, &child, Some("oci_layer"))
                .await
                .unwrap();
            (status, config_rows.len(), layer_rows.len())
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(config_rows, 0, "an index PUT writes no oci_config rows");
        assert_eq!(layer_rows, 0, "an index PUT writes no oci_layer rows");
    }

    /// Re-PUTting the identical single-image manifest is idempotent: the
    /// `oci_config`/`oci_layer` rows are upserted (refreshed), not
    /// duplicated — same idempotency contract as `oci_index_member` /
    /// `oci_subject`, backed by the widened PK `(repository_id,
    /// source_artifact_id, target_content_hash, kind)`.
    #[test]
    fn put_single_image_manifest_blob_edges_idempotent_on_repush() {
        let (status_first, status_second, config_rows, layer_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let status_first = router
                .clone()
                .oneshot(put_request(uri, body.clone()))
                .await
                .unwrap()
                .status();
            // Second PUT of the identical bytes — same digest, same tag.
            let status_second = router
                .oneshot(put_request(uri, body))
                .await
                .unwrap()
                .status();

            let config_rows = h
                .content_references
                .find_by_target(repo_id, &config_hash, Some("oci_config"))
                .await
                .unwrap();
            let layer_rows = h
                .content_references
                .find_by_target(repo_id, &layer_hash, Some("oci_layer"))
                .await
                .unwrap();
            (
                status_first,
                status_second,
                config_rows.len(),
                layer_rows.len(),
            )
        });
        assert_eq!(status_first, StatusCode::CREATED);
        assert_eq!(status_second, StatusCode::CREATED);
        assert_eq!(
            config_rows, 1,
            "idempotent re-push must upsert, not duplicate, oci_config"
        );
        assert_eq!(
            layer_rows, 1,
            "idempotent re-push must upsert, not duplicate, oci_layer"
        );
    }

    // ---------------------------------------------------------------------
    // #46 Item 4 — `register_membership_edges_from_pull` direct unit tests.
    // The pull-through call sites (`manifests.rs`) are exercised at the
    // HTTP level in that module's own test suite; these tests pin the
    // shared function's own contract (idempotency, fail-safe on a
    // malformed body) directly, against the lighter-weight `harness()`
    // used throughout this module.
    // ---------------------------------------------------------------------

    /// Calling `register_membership_edges_from_pull` twice with the
    /// identical inputs (simulating a re-pull of the same manifest)
    /// upserts, not duplicates — same widened-PK idempotency contract
    /// the PUT path relies on (`put_single_image_manifest_blob_edges_idempotent_on_repush`
    /// above).
    #[test]
    fn register_membership_edges_from_pull_idempotent_on_repeat_call() {
        let (config_rows, layer_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash: ContentHash = format!("{:x}", Sha256::digest(b"pull-config"))
                .parse()
                .unwrap();
            let layer_hash: ContentHash = format!("{:x}", Sha256::digest(b"pull-layer"))
                .parse()
                .unwrap();
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_artifact_id = Uuid::new_v4();
            let media_type = "application/vnd.oci.image.manifest.v1+json";

            register_membership_edges_from_pull(
                &h.ctx,
                repo_id,
                manifest_artifact_id,
                media_type,
                &body,
            )
            .await;
            // Second call — identical inputs, simulating a re-pull.
            register_membership_edges_from_pull(
                &h.ctx,
                repo_id,
                manifest_artifact_id,
                media_type,
                &body,
            )
            .await;

            let config_rows = h
                .content_references
                .find_by_target(repo_id, &config_hash, Some("oci_config"))
                .await
                .unwrap()
                .len();
            let layer_rows = h
                .content_references
                .find_by_target(repo_id, &layer_hash, Some("oci_layer"))
                .await
                .unwrap()
                .len();
            (config_rows, layer_rows)
        });
        assert_eq!(
            config_rows, 1,
            "repeat call must upsert, not duplicate, oci_config"
        );
        assert_eq!(
            layer_rows, 1,
            "repeat call must upsert, not duplicate, oci_layer"
        );
    }

    /// A body that fails to parse (malformed JSON, or a well-formed
    /// index whose declared media type is single-image so the wrong
    /// parser runs — either way `parse_manifest_blobs`/
    /// `parse_index_children` returns `Err`) is a non-fatal, silent skip:
    /// no `content_references` rows are written, and the function
    /// returns normally (no panic). Register-only is best-effort by
    /// design — the manifest is already committed by the time this runs.
    #[test]
    fn register_membership_edges_from_pull_malformed_body_is_skipped_non_fatal() {
        let entry_count = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let manifest_artifact_id = Uuid::new_v4();

            register_membership_edges_from_pull(
                &h.ctx,
                repo_id,
                manifest_artifact_id,
                "application/vnd.oci.image.manifest.v1+json",
                b"this is not json",
            )
            .await;

            h.content_references.entry_count()
        });
        assert_eq!(
            entry_count, 0,
            "a malformed body must write zero edges, not panic or partially write"
        );
    }

    /// A Docker manifest-list media type routes down the same index path.
    #[test]
    fn put_docker_manifest_list_with_present_children_is_committed() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_blob(&h.artifacts, &h.storage, repo_id, b"child-manifest-bytes");
            let media = "application/vnd.docker.distribution.manifest.list.v2+json";
            let body = build_index_json(std::slice::from_ref(&child), media);

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            router
                .oneshot(put_index_request(uri, body, media))
                .await
                .unwrap()
                .status()
        });
        assert_eq!(status, StatusCode::CREATED);
    }

    /// A push whose Content-Type declares an image index / manifest list
    /// but whose bytes are a SINGLE-image manifest (no `manifests[]`) is a
    /// declared-vs-shape mismatch → 400 `MANIFEST_INVALID`, rejected
    /// pre-ingest (no artifact committed). This is the production consumer
    /// of `hort_domain::oci::is_image_index` as a cross-check on the
    /// client-declared media type.
    #[test]
    fn put_index_content_type_with_single_image_bytes_returns_400_manifest_invalid() {
        let (status, body, manifest_present) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            // Single-image manifest bytes (config + layers, NO manifests[]).
            let single_image_body = build_manifest_json(&config, &[]);
            let manifest_hex = format!("{:x}", Sha256::digest(&single_image_body));
            // ...but declared under an index Content-Type.
            let media = "application/vnd.oci.image.index.v1+json";

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(uri, single_image_body, media))
                .await
                .unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            (status, rbody, present)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert!(
            !manifest_present,
            "a declared/shape mismatch must reject pre-ingest; no artifact may land"
        );
    }

    /// The mirror case: a push whose Content-Type declares a SINGLE-image
    /// manifest but whose bytes ARE an image index (non-empty
    /// `manifests[]`) is a declared-vs-shape mismatch → 400
    /// `MANIFEST_INVALID`, rejected pre-ingest.
    #[test]
    fn put_single_image_content_type_with_index_bytes_returns_400_manifest_invalid() {
        let (status, body, manifest_present) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_blob(&h.artifacts, &h.storage, repo_id, b"a-child-manifest");
            // Index bytes (non-empty manifests[]) ...
            let index_body = build_index_json(
                std::slice::from_ref(&child),
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&index_body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            // ...but declared under the single-image Content-Type
            // (`put_request` sets `application/vnd.oci.image.manifest.v1+json`).
            let resp = router.oneshot(put_request(uri, index_body)).await.unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            (status, rbody, present)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert!(
            !manifest_present,
            "an index sent under a single-image Content-Type must reject pre-ingest"
        );
    }

    /// The matching cases are unaffected by the cross-check: a
    /// single-image manifest under the single-image Content-Type, and an
    /// index under an index Content-Type, both still commit (201). This
    /// pins that the mismatch guard fires ONLY on a genuine
    /// declared-vs-shape disagreement.
    #[test]
    fn put_matching_declared_type_and_shape_are_unaffected_by_cross_check() {
        let (single_status, index_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            // Single-image bytes under the single-image Content-Type.
            let config = seed_blob(&h.artifacts, &h.storage, repo_id, b"cfg-match");
            let single_body = build_manifest_json(&config, &[]);
            let single_router = router().with_state(h.ctx.clone());
            let single_status = single_router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/single",
                    single_body,
                ))
                .await
                .unwrap()
                .status();

            // Index bytes under the index Content-Type.
            let child = seed_blob(&h.artifacts, &h.storage, repo_id, b"child-match");
            let media = "application/vnd.oci.image.index.v1+json";
            let index_body = build_index_json(std::slice::from_ref(&child), media);
            let index_router = router().with_state(h.ctx.clone());
            let index_status = index_router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/idx",
                    index_body,
                    media,
                ))
                .await
                .unwrap()
                .status();
            (single_status, index_status)
        });
        assert_eq!(
            single_status,
            StatusCode::CREATED,
            "matching single-image push is unaffected"
        );
        assert_eq!(
            index_status,
            StatusCode::CREATED,
            "matching index push is unaffected"
        );
    }

    /// An index referencing a child manifest that is NOT present in-repo
    /// → 400 `MANIFEST_BLOB_UNKNOWN` (mirroring a missing layer). The
    /// index artifact stays committed for client retry; the group is not
    /// created.
    #[test]
    fn put_image_index_with_missing_child_returns_400_manifest_blob_unknown() {
        let (status, body, group_calls, manifest_present) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // A present child + a NEVER-seeded child.
            let present = seed_blob(&h.artifacts, &h.storage, repo_id, b"present-child");
            let missing_hex = format!("{:x}", Sha256::digest(b"never-pushed-child"));
            let missing: ContentHash = missing_hex.parse().unwrap();
            let body = build_index_json(
                &[present, missing],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let group_calls = h.group_lifecycle.commit_call_count();
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            (status, rbody, group_calls, present)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        let blobs = parsed["errors"][0]["detail"]["blobs"].as_array().unwrap();
        assert_eq!(blobs.len(), 1, "exactly the one missing child echoed");
        assert!(
            blobs[0].as_str().unwrap().starts_with("sha256:"),
            "blobs detail must echo raw sha256:<hex> shape"
        );
        assert!(
            manifest_present,
            "index artifact must persist so client retry (after pushing the child) reconciles"
        );
        assert_eq!(
            group_calls, 0,
            "group must NOT be created on the missing-child path"
        );
    }

    /// A cross-repo child manifest counts as missing (same-repo isolation,
    /// via `find_in_repo_by_hash`) → `MANIFEST_BLOB_UNKNOWN`.
    #[test]
    fn put_image_index_with_foreign_repo_child_returns_400_manifest_blob_unknown() {
        let status = run(async {
            let h = harness();
            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_b_id = repo_b.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);
            // Seed the child ONLY in repo_b.
            let child = seed_blob(&h.artifacts, &h.storage, repo_b_id, b"child-in-other-repo");
            let body = build_index_json(
                std::slice::from_ref(&child),
                "application/vnd.oci.image.index.v1+json",
            );

            let router = router().with_state(h.ctx.clone());
            // PUT to repo-a — the child lives in repo-b, so it's missing.
            let uri = "/v2/repo-a/library/nginx/manifests/v1";
            router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap()
                .status()
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// An index declaring MORE than the domain cap of children →
    /// `MANIFEST_INVALID` (the domain `index_child_digests` returns
    /// `Validation`; the handler maps it to the same shape the
    /// single-image over-cap rejection produces). The manifest artifact
    /// still commits (parse runs post-ingest) but no group is created.
    #[test]
    fn put_image_index_over_child_cap_returns_400_manifest_invalid() {
        // MAX_INDEX_CHILDREN in hort-domain is 1024; declare 1025 children
        // (synthetic sha256 digests — never resolved, the cap rejects
        // before resolution).
        let over_cap = 1025usize;
        let (status, body, group_calls) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            h.repositories.insert(repo);
            let manifests: Vec<serde_json::Value> = (0..over_cap)
                .map(|i| {
                    serde_json::json!({
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": format!("sha256:{i:064x}"),
                        "size": 0,
                    })
                })
                .collect();
            let index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": manifests,
            });
            let body = serde_json::to_vec(&index).unwrap();

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let group_calls = h.group_lifecycle.commit_call_count();
            (status, rbody, group_calls)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "MANIFEST_INVALID",
            "an over-cap index must map to MANIFEST_INVALID"
        );
        assert_eq!(
            group_calls, 0,
            "no group created for an over-cap index (rejected pre-attach)"
        );
    }

    /// §3.5 red test: an image index — even one carrying a `subject`
    /// (defensively) — is NOT routed to `ingest_signature_manifest`.
    /// The `is_pure_*` predicates key on layer media types, and an index
    /// has no layers, so `is_pure_signature` is `false`. Observable: the
    /// index routes via `ingest_verified`, which enqueues a scan (the
    /// seeded HTTP-test policy carries `scan_backends: ["trivy"]`); the
    /// narrow signature path enqueues none.
    #[test]
    fn put_image_index_with_subject_is_not_routed_to_signature_ingest() {
        let (status, scan_calls) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_blob(&h.artifacts, &h.storage, repo_id, b"index-child-manifest");
            let subject = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-subject-image");
            // An index shape WITH a defensive `subject` and NO layers.
            let index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": format!("sha256:{}", child.as_ref()),
                        "size": 0,
                        "platform": { "architecture": "amd64", "os": "linux" },
                    }
                ],
                "subject": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", subject.as_ref()),
                    "size": 0,
                },
            });
            let body = serde_json::to_vec(&index).unwrap();

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(
                    uri,
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            (status, h.lifecycle.scan_enqueues().len())
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            scan_calls, 1,
            "an index (no layers) is NOT is_pure_signature — it stays on \
             ingest_verified and IS scanned, even with a defensive subject"
        );
    }

    // -------------------- DELETE --------------------

    #[test]
    fn delete_tag_emits_ref_retired_and_returns_202() {
        let (status, post_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed a tag ref pointing at some content hash.
            let hash: ContentHash =
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .parse()
                    .unwrap();
            h.refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                namespace: "library/nginx".into(),
                ref_name: "v1".into(),
                target: RefTarget::ContentHash(hash),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });

            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::delete("/v2/myrepo/library/nginx/manifests/v1")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            // The ref should have been retired (removed from the
            // registry mock).
            let post_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
            (status, post_count)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(post_count, 0, "ref must be retired after DELETE");
    }

    /// INJ-4: a DELETE to an out-of-grammar tag is rejected 400
    /// `MANIFEST_INVALID` before the `RefUseCase::retire`. No ref is seeded,
    /// so an unvalidated path would 404 (`ManifestUnknown`) on the retire
    /// miss; the 400 with an `oci.tag:` reason proves the validator fired
    /// first. The response never echoes the offending bytes.
    #[test]
    fn delete_manifest_out_of_grammar_tag_rejected_400() {
        let over_cap = "a".repeat(129);
        let cases: [(&str, &str); 4] = [
            ("..", "double-dot path traversal"),
            (".leadingdot", "leading dot"),
            ("-leadinghyphen", "leading hyphen"),
            (&over_cap, "129-byte over-cap tag"),
        ];
        for (uri_tag, label) in cases {
            let (status, body) = run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = router().with_state(h.ctx.clone());
                let uri = format!("/v2/myrepo/library/nginx/manifests/{uri_tag}");
                let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                (status, rbody)
            });
            assert_eq!(status, StatusCode::BAD_REQUEST, "case: {label}");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["errors"][0]["code"], "MANIFEST_INVALID",
                "case: {label}"
            );
            let reason = parsed["errors"][0]["detail"]["reason"]
                .as_str()
                .unwrap_or("");
            assert!(
                reason.starts_with("oci.tag: "),
                "case {label}: reason must be tagged `oci.tag:` ({reason})"
            );
        }
    }

    #[test]
    fn delete_digest_removes_artifact_and_content_references() {
        let (status, post_artifact, post_refs) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed a manifest artifact at manifests/sha256:<hex>.
            let content = b"manifest-body-bytes";
            let hex = format!("{:x}", Sha256::digest(content));
            let hash: ContentHash = hex.parse().unwrap();
            let mut a = sample_artifact(QuarantineStatus::None);
            let artifact_id = a.id;
            a.repository_id = repo_id;
            a.path = format!("manifests/sha256:{hex}");
            a.sha256_checksum = hash.clone();
            a.size_bytes = content.len() as i64;
            h.artifacts.insert(a);
            h.storage.insert_content(hash.clone(), content.to_vec());

            // Seed two content_references rows with this artifact as source.
            h.content_references
                .insert(ContentReference {
                    source_artifact_id: artifact_id,
                    target_content_hash: "a".repeat(64).parse().unwrap(),
                    kind: "oci_subject".into(),
                    metadata: serde_json::Value::Null,
                    repository_id: repo_id,
                    recorded_at: Utc::now(),
                })
                .await
                .unwrap();

            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();

            // After DELETE: artifact gone, content_references gone.
            let post_artifact = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{hex}"))
                .await
                .unwrap();
            let post_refs = h.content_references.entry_count();
            (status, post_artifact, post_refs)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            post_artifact.is_none(),
            "artifact row must be deleted after digest DELETE"
        );
        assert_eq!(
            post_refs, 0,
            "content_references rows with this source must be swept"
        );
    }

    /// The digest-DELETE path must attribute the deletion to the
    /// authenticated caller. The `ArtifactDeleted` event's actor comes
    /// straight from this argument, so a dropped actor here produces an
    /// unattributable terminal transition in the audit trail.
    #[test]
    fn delete_digest_attributes_the_deletion_to_the_authenticated_caller() {
        let caller_id = Uuid::new_v4();
        let deletions = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let content = b"attributed-manifest-body";
            let hex = format!("{:x}", Sha256::digest(content));
            let hash: ContentHash = hex.parse().unwrap();
            let mut a = sample_artifact(QuarantineStatus::None);
            a.repository_id = repo_id;
            a.path = format!("manifests/sha256:{hex}");
            a.sha256_checksum = hash.clone();
            a.size_bytes = content.len() as i64;
            h.artifacts.insert(a);
            h.storage.insert_content(hash, content.to_vec());

            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let mut req = HttpRequest::delete(&uri).body(Body::empty()).unwrap();
            let mut principal = test_principal();
            principal.user_id = caller_id;
            hort_http_core::middleware::auth::test_support::inject_principal(&mut req, principal);
            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            h.artifacts.deletions()
        });

        assert_eq!(deletions.len(), 1, "exactly one artifact deleted");
        assert!(
            matches!(&deletions[0].1, Actor::Api(a) if a.user_id == caller_id),
            "deletion must be attributed to the authenticated caller, got {:?}",
            deletions[0].1
        );
    }

    #[test]
    fn delete_unknown_tag_returns_404_manifest_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::delete("/v2/myrepo/library/nginx/manifests/never-existed")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    #[test]
    fn delete_unknown_digest_returns_404_manifest_unknown() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{valid_hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    // ---------------- Header-injection guard: created_manifest_response ----
    //
    // `created_manifest_response` used to call
    // `HeaderValue::from_str(&location).expect("ASCII by construction")`
    // on a string interpolating `repo_key` / `name` / `reference` from
    // URL captures. CRLF in any of the three would panic, axum would
    // catch the panic and emit a 500 — a DoS primitive. The fix
    // funnels the call through the shared helper that emits 404
    // NAME_UNKNOWN on the failure path.

    fn manifest_sample_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    #[test]
    fn created_manifest_response_with_crlf_in_repo_key_returns_400_not_500() {
        let repo_key_with_crlf = "myrepo\r\nX-Injected: pwn";
        let resp = created_manifest_response(
            repo_key_with_crlf,
            "library/nginx",
            "v1",
            &manifest_sample_hash(),
        );
        assert_ne!(
            resp.status(),
            StatusCode::CREATED,
            "must NOT return 201 with a smuggled header"
        );
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "must NOT degrade to 500 on URL-capture-induced HeaderValue failure"
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn created_manifest_response_with_clean_ascii_returns_201_with_location() {
        let resp =
            created_manifest_response("myrepo", "library/nginx", "v1", &manifest_sample_hash());
        assert_eq!(resp.status(), StatusCode::CREATED);
        let location = resp
            .headers()
            .get(LOCATION)
            .expect("Location header missing on happy path")
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(location, "/v2/myrepo/library/nginx/manifests/v1");
    }

    // -------------------- parse_manifest_blobs blob-count cap --------------------
    //
    // The 1 MiB body cap stops gross OOM but a manifest body can pack
    // ~10k pathologically dense entries within 1 MiB — each entry
    // triggers a `find_in_repo_by_hash` lookup in
    // `resolve_referenced_blobs`. Cap the blob-reference count at 1024
    // at parse time, before the lookup loop is entered.

    /// Build a manifest JSON with `n` distinct synthetic layer digests
    /// plus one config digest. Total referenced blobs = n + 1.
    /// Digests are unique-by-construction (the index is encoded into
    /// the hex), so the cap counts distinct entries, not deduplicated
    /// hashes.
    fn build_manifest_with_n_layers(n: usize) -> serde_json::Value {
        // Use a stable config hash and unique-per-index layer hashes.
        // 64 hex chars per digest; index encoded as 16-hex prefix.
        let config_digest = format!("sha256:{}", "c".repeat(64));
        let layers: Vec<serde_json::Value> = (0..n)
            .map(|i| {
                let hex = format!("{i:016x}{}", "0".repeat(48));
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{hex}"),
                    "size": 0,
                })
            })
            .collect();
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 0,
            },
            "layers": layers,
        })
    }

    #[test]
    fn parse_manifest_blobs_accepts_1023_layers_plus_config() {
        // 1023 layers + 1 config = 1024 referenced blobs, exactly at
        // the cap. Must succeed.
        let manifest = build_manifest_with_n_layers(1023);
        let result = parse_manifest_blobs(&manifest);
        assert!(
            result.is_ok(),
            "1024 referenced blobs (1023 layers + 1 config) must be accepted; got {result:?}"
        );
        let blobs = result.unwrap();
        assert_eq!(blobs.len(), 1024, "must include config + 1023 layers");
    }

    #[test]
    fn parse_manifest_blobs_accepts_1024_layers_when_total_is_1025_fails() {
        // Sanity: 1024 layers + 1 config = 1025 referenced blobs,
        // exactly one over the cap. Must fail.
        let manifest = build_manifest_with_n_layers(1024);
        let result = parse_manifest_blobs(&manifest);
        assert!(
            result.is_err(),
            "1025 referenced blobs (1024 layers + 1 config) must be rejected; got {result:?}"
        );
        let detail = result.unwrap_err();
        let reason = detail
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("error detail must carry `reason`");
        assert!(
            reason.contains("1025") && reason.contains("1024"),
            "reason must surface both the count and the cap; got {reason:?}"
        );
    }

    #[test]
    fn parse_manifest_blobs_rejects_2048_layers() {
        // Far over the cap — proves the check fires regardless of how
        // far over the manifest is.
        let manifest = build_manifest_with_n_layers(2048);
        let result = parse_manifest_blobs(&manifest);
        assert!(result.is_err(), "2049 referenced blobs must be rejected");
        let detail = result.unwrap_err();
        let reason = detail
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("error detail must carry `reason`");
        assert!(
            reason.contains("2049") && reason.contains("1024"),
            "reason must report actual count 2049 and cap 1024; got {reason:?}"
        );
    }

    #[test]
    fn parse_manifest_blobs_small_manifest_unchanged() {
        // Existing happy path — small single-layer manifest stays
        // green. Regression guard: the cap must not interfere with
        // legitimate manifests.
        let manifest = build_manifest_with_n_layers(1);
        let blobs =
            parse_manifest_blobs(&manifest).expect("a single-layer manifest must parse cleanly");
        assert_eq!(blobs.len(), 2, "config + 1 layer = 2 referenced blobs");
    }

    /// `config.digest` is fully attacker-controlled manifest-JSON
    /// content. A malformed value must reject without the raw digest
    /// (or the inner parse-failure text) reaching the `detail` payload.
    #[test]
    fn parse_manifest_blobs_malformed_config_digest_does_not_echo_raw_value() {
        let manifest = serde_json::json!({
            "config": {"digest": "xsentinel-not-a-digest-at-all"},
            "layers": [],
        });
        let detail = parse_manifest_blobs(&manifest).unwrap_err();
        assert_eq!(detail["reason"], "malformed digest in manifest");
        assert!(
            detail.get("digest").is_none(),
            "detail must not carry a `digest` field echoing the raw value: {detail:?}"
        );
        let serialized = detail.to_string();
        assert!(
            !serialized.contains("xsentinel"),
            "detail must not echo the rejected digest: {serialized}"
        );
    }

    /// A well-formed-but-unsupported `config.digest` algorithm (e.g.
    /// `sha512:`) must reject without the requested algorithm reaching
    /// the `detail` payload.
    #[test]
    fn parse_manifest_blobs_unsupported_config_digest_algo_does_not_echo_algorithm() {
        let manifest = serde_json::json!({
            "config": {"digest": format!("xsentinelalgo:{}", "a".repeat(64))},
            "layers": [],
        });
        let detail = parse_manifest_blobs(&manifest).unwrap_err();
        assert_eq!(detail["reason"], "unsupported digest algorithm in manifest");
        assert!(
            detail.get("digest").is_none(),
            "detail must not carry a `digest` field echoing the raw value: {detail:?}"
        );
        let serialized = detail.to_string();
        assert!(
            !serialized.contains("xsentinelalgo"),
            "detail must not echo the rejected algorithm: {serialized}"
        );
    }

    // -------------------------------------------------------------
    // DeleteRepoAccess reclassification regression guard
    // -------------------------------------------------------------
    //
    // Each test drives a real handler under `AuthContext::Enabled`
    // with a tightly-scoped RBAC evaluator and asserts which
    // permission was consulted.
    //
    // Layout:
    //
    //   delete_manifest_dispatch + [read, write] (no delete) → 403
    //   delete_manifest_dispatch + [read, write, delete]     → 202
    //   delete_manifest_dispatch + [admin] (no grants)       → 202
    //   post_upload_dispatch     + [write]                   → 202
    //   put_upload_dispatch      + [write]                   → success
    //
    // The last two are the "stays Write" lock: they prove the upload
    // lifecycle endpoints did NOT get switched to DeleteRepoAccess
    // alongside the manifest-delete endpoint. (The OCI surface has no
    // dedicated cancel-upload handler today — DELETE on a
    // `/blobs/uploads/<uuid>` tail falls through `delete_manifest_dispatch`
    // and 404s at parse time. `post_upload_dispatch` substitutes for
    // cancel as the simplest upload-lifecycle WriteRepoAccess call site.)

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_http_core::context::AuthContext;
    use hort_http_core::test_support::{with_auth, with_repository_access};

    /// Build an RBAC evaluator with explicit `(claim_name, permissions)`
    /// pairs scoped to `repo_id`. Uses the `GrantSubject::Claims` grant
    /// set (ADR 0012): a principal whose resolved `claims` contain
    /// `claim_name` matches. A claim with no permissions contributes no
    /// grants (the admin-shortcut test relies on this empty-evaluator
    /// shape).
    fn rbac_with_grants(
        repo_id: Uuid,
        claim_perms: &[(&str, &[Permission])],
    ) -> (RbacEvaluator, Arc<arc_swap::ArcSwap<RbacEvaluator>>) {
        let mut grants: Vec<PermissionGrant> = Vec::new();
        for (name, perms) in claim_perms {
            for p in *perms {
                grants.push(PermissionGrant {
                    id: Uuid::new_v4(),
                    subject: GrantSubject::Claims(vec![(*name).to_string()]),
                    repository_id: Some(repo_id),
                    permission: *p,
                    created_at: Utc::now(),
                    managed_by: ManagedBy::Local,
                    managed_by_digest: None,
                });
            }
        }
        let eval = RbacEvaluator::new(grants);
        let swap = Arc::new(arc_swap::ArcSwap::from_pointee(eval.clone()));
        (eval, swap)
    }

    /// Flip `h.ctx` to `AuthContext::Enabled` carrying the supplied
    /// RBAC evaluator and rebuild the matching `RepositoryAccessUseCase`
    /// so visibility checks downstream observe the same state.
    fn enable_auth_with_rbac(
        h: &Harness,
        rbac_swap: Arc<arc_swap::ArcSwap<RbacEvaluator>>,
    ) -> Arc<AppContext> {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let ctx = with_auth(
            &h.ctx,
            AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap.clone(),
                // Tests in this module do not exercise the WWW-Authenticate selector.
                issuer_url: None,
            },
        );
        let access = Arc::new(RepositoryAccessUseCase::new(
            h.repositories.clone(),
            RbacAccess::Enabled(rbac_swap),
            true,
        ));
        with_repository_access(&ctx, access)
    }

    /// Inject a principal carrying the resolved claim set `claims`
    /// into the request (ADR 0012). Mirrors what the
    /// `oci_bearer_auth` middleware does after JIT-resolving a token,
    /// minus the network bits.
    fn with_principal_claims(
        mut req: axum::http::Request<Body>,
        claims: &[&str],
    ) -> axum::http::Request<Body> {
        let mut p = test_principal();
        p.claims = claims.iter().map(|s| (*s).to_string()).collect();
        hort_http_core::middleware::auth::test_support::inject_principal(&mut req, p);
        req
    }

    /// Seed a manifest artifact at `manifests/sha256:<hex>`. Returns
    /// the digest string clients embed in the DELETE URL.
    fn seed_manifest_artifact(h: &Harness, repo_id: Uuid) -> String {
        let content = b"manifest-body-bytes";
        let hex = format!("{:x}", Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("manifests/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        h.artifacts.insert(a);
        h.storage.insert_content(hash, content.to_vec());
        hex
    }

    // ---- delete_manifest_dispatch reclassification ----

    /// Reclassification row: `DELETE /v2/<name>/manifests/<ref>` with
    /// `[read, write]` (no `delete`) MUST 403. Previously the same
    /// principal would have authorised because the handler keyed off
    /// `Permission::Write`. The 403 is the lock that the switch to
    /// `DeleteRepoAccess` actually happened in production code.
    #[test]
    fn reclassify_delete_manifest_with_write_only_returns_403() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            let (_eval, swap) =
                rbac_with_grants(repo_id, &[("dev", &[Permission::Read, Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "principal with [read, write] but no `delete` grant must be denied"
        );
    }

    /// Reclassification row: `DELETE /v2/<name>/manifests/<ref>` with
    /// `[read, write, delete]` MUST succeed. Pairs with the 403 test
    /// above to lock the boundary at exactly `Permission::Delete`
    /// rather than at any of the broader permissions.
    #[test]
    fn reclassify_delete_manifest_with_delete_grant_returns_202() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            let (_eval, swap) = rbac_with_grants(
                repo_id,
                &[(
                    "deleter",
                    &[Permission::Read, Permission::Write, Permission::Delete],
                )],
            );
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["deleter"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "principal with explicit `delete` grant must succeed at manifest delete"
        );
    }

    /// Reclassification row + admin-shortcut lock: an `admin` role
    /// without any explicit `permission_grants` rows succeeds at the
    /// manifest-delete endpoint via the role-name short-circuit in
    /// `RbacEvaluator::authorize` (rbac.rs:104). This pins the
    /// admin role short-circuits without an explicit `delete` grant —
    /// operators do NOT need to add a parallel `delete` grant for
    /// admin roles.
    #[test]
    fn reclassify_delete_manifest_admin_role_short_circuits_without_explicit_grant() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            // EMPTY evaluator — no grants. The admin short-circuit
            // (`claims.contains("admin")`, ADR 0012) ignores it.
            let swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new(),
            )));
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["admin"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "admin role bypasses per-permission grants — no explicit delete grant needed"
        );
        // Also assert there's no implicit `_repo_id` warning; the
        // path consumes its own repo_id parameter.
    }

    // ---- "stays Write" reclassification rows ----
    //
    // Drive the upload-lifecycle handlers with a `[write]`-only
    // principal to prove they did NOT get switched to
    // `DeleteRepoAccess` alongside the manifest-delete endpoint.
    // Both paths route through the upload router defined in
    // `super::uploads::router`.

    /// Reclassification row: `POST /v2/<name>/blobs/uploads/`
    /// (initiate) MUST stay `WriteRepoAccess`. A write-only
    /// principal succeeds. Substitute for the cancel-upload row in
    /// the design-doc table — the OCI surface has no dedicated
    /// cancel handler today, so the simplest upload-lifecycle write
    /// op locks the same "stays Write" decision.
    #[test]
    fn reclassify_post_upload_initiate_with_write_only_stays_write_and_succeeds() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let (_eval, swap) = rbac_with_grants(repo_id, &[("dev", &[Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = super::super::uploads::router().with_state(ctx);
            let req = with_principal_claims(
                HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "write-only principal must initiate uploads — POST stays WriteRepoAccess"
        );
    }

    /// Reclassification row: `PUT /v2/<name>/blobs/uploads/<uuid>?digest=…`
    /// (finalize) MUST stay `WriteRepoAccess`. A write-only principal
    /// satisfies the extractor; the request fails downstream at the
    /// missing-session lookup with a 404 `BLOB_UPLOAD_UNKNOWN`, NOT a
    /// 403 — proving the authz step admitted the caller.
    ///
    /// We don't seed a real session because the goal is to assert
    /// the extractor decision, not the finalize semantics. A 403
    /// here would mean the wrong extractor wired in.
    #[test]
    fn reclassify_put_upload_finalize_with_write_only_stays_write_and_passes_authz() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let (_eval, swap) = rbac_with_grants(repo_id, &[("dev", &[Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = super::super::uploads::router().with_state(ctx);
            // A random session UUID — no session exists, the finalize
            // path will reject downstream. The extractor decision
            // happens FIRST; if it returned 403 we'd see 403 here.
            let session_id = Uuid::new_v4();
            let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let uri = format!(
                "/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{valid_hex}"
            );
            let req = with_principal_claims(
                HttpRequest::put(&uri)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(Body::empty())
                    .unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        // Anything OTHER than 403 means the WriteRepoAccess
        // extractor admitted the principal — that's the "stays
        // Write" lock. The downstream finalize logic is free to
        // reject for any other reason (404 BLOB_UPLOAD_UNKNOWN is
        // the most likely).
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "PUT-finalize must stay WriteRepoAccess — write-only principal must NOT be denied"
        );
    }
}
