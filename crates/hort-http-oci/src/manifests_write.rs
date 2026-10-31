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
//! 4. **Before** the ingest of step 6: parse the manifest JSON by
//!    media-type shape. A single-image manifest yields `config.digest` +
//!    `layers[*].digest`; an image index / manifest list yields
//!    `manifests[*].digest` (child **manifest** references). Resolve
//!    each referenced blob / child through
//!    [`ArtifactRepository::find_by_checksum`]; enforce
//!    `artifact.repository_id == repo` (cross-repo isolation) and that
//!    the resolved row's quarantine status is not terminal (a row the
//!    blob read would refuse is not a satisfied reference).
//!
//!    **Then the door** ([`refuse_misdeclared_signature_layers`]): when
//!    the manifest declares EVERY layer to be signature material hort
//!    recognises — the condition the scan/quarantine exemption of step 6
//!    fires on — each declared layer's blob is read back from CAS and
//!    must parse as the shape it was declared as. Unparseable ⇒ 400
//!    `MANIFEST_INVALID` naming the offending layer digest, **before**
//!    the mint, so a refused push leaves no artifact behind. Bytes that
//!    cannot be read are accepted and logged instead, and an
//!    unrecognised media type never reaches the door at all — see that
//!    function for why each of those is deliberate.
//! 5. Build the manifest's content-reference claim set from the resolved
//!    references — one [`ContentReferenceClaim`] per `oci_config` /
//!    `oci_layer` / `oci_index_member` edge, plus the `oci_subject`
//!    claim of step 2 — and hand the set to step 6's ingest so every
//!    edge commits in the manifest artifact's own transaction.
//!    Membership claims are built **only** when every reference
//!    resolved, so an edge can never name a blob this repository does
//!    not hold.
//! 6. Ingest the manifest bytes, carrying the claim set.
//! 7. Any blob / child that does not resolve to a **deliverable**
//!    same-repo row — absent, foreign-repo, or present but in a terminal
//!    quarantine state — returns 400 `MANIFEST_BLOB_UNKNOWN` with a
//!    `detail.blobs` array. Deliberately answered **after** the mint: the
//!    manifest artifact stays committed so the client's
//!    retry-after-pushing-blobs path is idempotent (a terminal reference
//!    is the case no retry fixes); the group is NOT created, and the
//!    manifest carries no membership claims.
//! 8. Attach the primary `manifest` member to the group, plus (single-
//!    image only) config + layers, via
//!    [`ArtifactGroupUseCase::add_member`]. Shared per-request
//!    `correlation_id`; every call threads `causation_id =
//!    Some(manifest_event_id)` — the audit-trail contract.
//! 9. Tag-reference PUTs call
//!    [`RefUseCase::set`](hort_app::use_cases::ref_use_case::RefUseCase::set)
//!    with `RefTarget::ContentHash(manifest_digest)`. Digest-reference
//!    PUTs skip this step (digest is self-naming).
//!
//! **No step records a [`ContentReference`] row after the ingest
//! returned, and that order is the contract.** A `content_references` row
//! is a claim on bytes — the storage GC deletes a CAS blob exactly when no
//! row targets its hash — so an edge written beside its referrer's
//! transaction rather than inside it is a window in which the manifest is
//! live and the bytes it claims carry one fewer claim. For `oci_subject`,
//! `oci_config`, `oci_layer` and `oci_index_member` the target is
//! *another* artifact's content and nothing repairs the gap afterwards: the
//! refcount-reconcile sweep derives `primary_content` / `metadata_blob`
//! from the artifact row, and no relational row records what a manifest
//! references. The parse and the resolve therefore run ahead of the mint
//! (both are reads, and both only ever used the manifest's id as a log
//! field), which is what makes every claim derivable before the
//! transaction that has to carry it.
//!
//! Response: 201 + `Location: /v2/<repo_key>/<name>/manifests/<ref>` +
//! `Docker-Content-Digest: sha256:<hex>`. Empty body.
//!
//! # DELETE
//!
//! Tag references route through [`RefUseCase::retire`]; digest
//! references look up the manifest artifact via `find_by_path`, remove
//! the artifact via [`ArtifactUseCase::delete`], and only then sweep its
//! `content_references` rows via
//! [`ContentReferenceIndex::delete_by_source`]. That order is an
//! invariant, not a detail: the sweep drops keepalive edges no reconcile
//! sweep re-creates, so running it first left a failed delete with a
//! live manifest whose blobs were collectable. CAS blob lifetime is GC's
//! concern — the DELETE handler never touches storage directly.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::Router;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::ingest_use_case::{IngestOutcome, VerifiedIngestRequest};
use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::mutable_ref::RefTarget;
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor};
use hort_domain::ports::content_reference_index::ContentReferenceClaim;
use hort_domain::types::{ArtifactCoords, ContentHash};
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
/// index / list media type routes to
/// [`parse_index_children_for_admission`] (child **manifest**
/// resolution); every other media type routes to the
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

/// `<name>/manifests/<reference>` tail parse + OCI name-grammar validation,
/// BEFORE any storage, manifest, or upload action. Rejecting on the
/// pre-storage path keeps malformed names out of `Artifact.name`, metric
/// labels, log lines, and the manifest blob CAS commit.
fn parse_and_validate_manifest_tail(
    repo_key: &str,
    tail: &str,
) -> Result<(String, String), Box<Response>> {
    let Some(ManifestTail { name, reference }) = parse_manifest_tail(tail) else {
        return Err(Box::new(
            OciError::NameUnknown {
                repository: format!("{repo_key}/{tail}"),
            }
            .into_response(),
        ));
    };
    if let Err(e) = validate_oci_name(name) {
        return Err(Box::new(super::name_invalid_response(e)));
    }
    Ok((name.to_string(), reference.to_string()))
}

/// Pull headers + body up front. Body reading is the one unavoidable point
/// of no return; subsequent failures must treat the body as consumed. The 1
/// MiB cap applies here; axum's `to_bytes` returns an `Err` if the body
/// exceeds the limit — classified as `MANIFEST_INVALID` (not `SIZE_INVALID`,
/// which is reserved for blob-upload limits).
async fn read_manifest_body(request: Request<Body>) -> Result<(HeaderMap, Vec<u8>), Response> {
    let headers = request.headers().clone();
    match to_bytes(request.into_body(), MANIFEST_BODY_MAX_BYTES).await {
        Ok(b) => Ok((headers, b.to_vec())),
        Err(_) => Err(OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "manifest body too large or unreadable",
                "max_bytes": MANIFEST_BODY_MAX_BYTES,
            })),
        }
        .into_response()),
    }
}

/// Content-Type allowlist.
fn validate_manifest_media_type(headers: &HeaderMap) -> Result<String, Box<Response>> {
    let media_type = extract_media_type(headers)?;
    if !SUPPORTED_MANIFEST_MEDIA_TYPES.contains(&media_type.as_str()) {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "unsupported manifest media type",
                    "media_type": media_type,
                })),
            }
            .into_response(),
        ));
    }
    Ok(media_type)
}

/// Pre-parse the manifest JSON for `subject.digest` (used in
/// `payload_metadata`) and, later, `config.digest` + `layers[*].digest`.
/// Invalid JSON at this step → 400 `MANIFEST_INVALID` per OCI spec
/// (unparseable JSON is an envelope-shape violation, not UNSUPPORTED).
fn parse_manifest_json(body_bytes: &[u8]) -> Result<serde_json::Value, Box<Response>> {
    serde_json::from_slice(body_bytes).map_err(|e| {
        Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest body is not valid JSON",
                    "error": e.to_string(),
                })),
            }
            .into_response(),
        )
    })
}

/// Cross-check the client-declared media type against the manifest's actual
/// shape BEFORE any state change. The blob/child parse dispatches on the
/// declared `Content-Type` (`is_index_media_type`); `is_image_index` is the
/// structural shape probe (non-empty `manifests[]`). If the two disagree the
/// push is mislabeled and is rejected as `MANIFEST_INVALID`:
///
///   * declared index / manifest-list, but the bytes carry no `manifests[]`
///     (a single-image manifest sent under an index Content-Type) — the
///     index parse would find zero children; and
///   * declared single-image, but the bytes ARE an index — the single-image
///     parse would look for a `config` the index lacks, silently
///     mis-handling the children.
///
/// Returns whether the declared type is an index/manifest-list, for reuse
/// by the blob/child parse dispatch.
fn check_declared_media_type_matches_shape(
    media_type: &str,
    body_bytes: &[u8],
) -> Result<bool, Box<Response>> {
    let media_type_is_index = is_index_media_type(media_type);
    let bytes_are_index = hort_domain::oci::is_image_index(body_bytes);
    if media_type_is_index != bytes_are_index {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "declared media type does not match manifest shape",
                    "media_type": media_type,
                    "declared_index": media_type_is_index,
                    "shape_is_index": bytes_are_index,
                })),
            }
            .into_response(),
        ));
    }
    Ok(media_type_is_index)
}

/// `subject.digest` / `artifactType`, when present. `serde_json` returns
/// `Null` for a missing key path, which is coerced to `None`.
fn extract_subject_and_artifact_type(
    parsed_manifest: &serde_json::Value,
) -> (Option<String>, Option<String>) {
    let subject_digest_str = parsed_manifest
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let artifact_type_opt = parsed_manifest
        .get("artifactType")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    (subject_digest_str, artifact_type_opt)
}

/// N-5: pre-validate `subject.digest` BEFORE the manifest ingest commits.
/// The previous flow re-parsed the digest just before the
/// ContentReferenceIndex insert at the tail of the handler — by then the
/// manifest artifact + group + ref had already been committed, so a
/// malformed `subject.digest` produced a 500 with the manifest left
/// half-attached. Validating up front keeps the failure on the same
/// pre-commit path as config/layer digest validation: 400 MANIFEST_INVALID,
/// no state change.
fn validate_subject_digest(
    subject_digest_str: Option<&str>,
) -> Result<Option<ContentHash>, Box<Response>> {
    let Some(raw) = subject_digest_str else {
        return Ok(None);
    };
    match parse_digest(raw) {
        DigestParse::Ok(h) => Ok(Some(h)),
        DigestParse::Unsupported => {
            // Neither `algorithm` nor `message` is included in the detail —
            // both are attacker-controlled manifest-JSON content (mirrors
            // `parse_blob_digest`'s contract); the raw value is already
            // logged inside `parse_digest`.
            Err(Box::new(
                OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "subject digest uses unsupported algorithm",
                        "field": "subject.digest",
                    })),
                }
                .into_response(),
            ))
        }
        DigestParse::Invalid { .. } => Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "subject digest malformed",
                    "field": "subject.digest",
                })),
            }
            .into_response(),
        )),
    }
}

/// The manifest body's computed content hash, whether the reference is
/// digest- or tag-shaped, and (for a digest reference) the client's
/// declared hash once cross-checked against the computed one.
struct ManifestHashDecision {
    computed_hash: ContentHash,
    declared_hash: Option<ContentHash>,
    reference_is_digest: bool,
}

/// Pre-compute the SHA-256 of the manifest body. Doing this before calling
/// `ingest` means (a) `declared_sha256` can be set on both digest-ref AND
/// tag-ref PUTs so mismatches are caught consistently, (b) coords carry the
/// real hash up front (no placeholder rewrite), and (c) the response
/// headers (`Location`, `Docker-Content-Digest`) can be formatted before
/// `ingest` runs so their construction never participates in a
/// partial-failure rollback.
///
/// On a digest-ref PUT, the declared digest is compared against the
/// computed one — mismatch is 400 `MANIFEST_INVALID` BEFORE any state
/// change. On a tag-ref PUT the tag is validated against the OCI grammar
/// (INJ-4) before it becomes a stored ref, mirroring the digest branch's
/// malformed-digest rejection.
fn resolve_manifest_hash(
    body_bytes: &[u8],
    reference: &str,
) -> Result<ManifestHashDecision, Box<Response>> {
    let computed_hash = compute_sha256(body_bytes);
    let reference_is_digest = reference.contains(':');

    let declared_hash = if reference_is_digest {
        match parse_digest(reference) {
            DigestParse::Ok(h) => {
                if h != computed_hash {
                    return Err(Box::new(
                        OciError::ManifestInvalid {
                            detail: Some(serde_json::json!({
                                "reason": "declared digest does not match manifest content",
                                "declared": format!("sha256:{}", h.as_ref()),
                                "computed": format!("sha256:{}", computed_hash.as_ref()),
                            })),
                        }
                        .into_response(),
                    ));
                }
                Some(h)
            }
            DigestParse::Unsupported => {
                // Well-formed but non-sha256 algorithm. The OCI spec pins
                // `UNSUPPORTED` for a digest whose algorithm is recognised
                // but can't be processed. This is the ONE path where
                // UNSUPPORTED is correct (vs DIGEST_INVALID).
                return Err(Box::new(
                    OciError::Unsupported {
                        message: UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE.to_string(),
                    }
                    .into_response(),
                ));
            }
            DigestParse::Invalid { message } => {
                return Err(Box::new(
                    OciError::ManifestInvalid {
                        detail: Some(serde_json::json!({
                            "reason": "malformed digest reference",
                            "error": message,
                        })),
                    }
                    .into_response(),
                ));
            }
        }
    } else {
        if let Err(e) = super::tag::validate_oci_tag(reference) {
            return Err(Box::new(super::tag_invalid_response(e)));
        }
        // Declare the computed hash so the ingest path has a consistent
        // post-storage check. `IngestUseCase::ingest` treats
        // `declared_sha256 = Some(computed)` as a tautology here, but
        // asserting it closes a latent window where a concurrent mutation
        // between compute and commit would slip through.
        Some(computed_hash.clone())
    };

    Ok(ManifestHashDecision {
        computed_hash,
        declared_hash,
        reference_is_digest,
    })
}

/// Route a pushed cosign **signature** manifest (a *pure* Sigstore-bundle
/// referrer) to the narrow `ingest_signature_manifest` path instead of the
/// generic `ingest_verified` pipeline. Quarantine is an observation window
/// for time-deferred safety uncertainty; a Sigstore signature's validity is
/// deterministic and immediate, so quarantining / scanning /
/// provenance-verifying it is a category error.
///
/// The exemption is gated on the manifest's declared media types, which a
/// write-authed pusher fully controls — so it is deliberately AIRTIGHT: it
/// fires **only** when the manifest carries a `subject.digest` AND EVERY
/// layer is signature material — either a Sigstore v0.3 bundle
/// (`is_pure_sigstore_bundle`, keyless) OR a cosign `simplesigning` layer
/// (`is_pure_simplesigning`, the keyed `cosign sign --key` shape, ADR 0039
/// §8). A mixed manifest (a signature layer plus a runnable `tar+gzip`
/// layer) does NOT match → it stays on `ingest_verified` and IS scanned.
/// "Exempted" ⟺ "carries no runnable content" — the anti-scan-evasion guard.
///
/// Both predicates parse the manifest JSON; a parse error is not expected
/// since the body already parsed cleanly upstream. On the off chance one
/// errors, fail safe → generic path (`unwrap_or(false)`), so the generic
/// path scans/quarantines it — never a wrongful exemption.
///
/// A manifest that matches then has to clear
/// [`refuse_misdeclared_signature_layers`] before it is minted: declaring a
/// layer to be signature material is one thing, the bytes behind it being
/// that thing is another, and only the second earns the exemption.
fn is_pure_signature_manifest(
    subject_digest_parsed: &Option<ContentHash>,
    body_bytes: &[u8],
) -> bool {
    subject_digest_parsed.is_some()
        && (hort_domain::oci::is_pure_sigstore_bundle(body_bytes).unwrap_or(false)
            || hort_domain::oci::is_pure_simplesigning(body_bytes).unwrap_or(false))
}

/// Upper bound on the bytes read back from CAS for one signature-layer shape
/// check. A Sigstore v0.3 bundle is a few KB of JSON (the checked-in real
/// cosign fixture is 11 KB) and a `simplesigning` payload is a few hundred
/// bytes, so 1 MiB is three orders of magnitude past real signature material
/// — the same generosity [`MANIFEST_BODY_MAX_BYTES`] applies to the manifest
/// itself.
///
/// **The direction of the cap is what matters, not its value.** A layer over
/// the cap reads as unreadable, which this door accepts and logs — so
/// lowering the cap can only ever move a layer from *refused* to *accepted*,
/// never the reverse, which keeps the door the narrowing-only check it claims
/// to be. Raising it past the verify path's own 16 MiB CAS ceiling would buy
/// nothing either: beyond that ceiling every verifier reads a truncated
/// prefix, so there is no material up there any of them could use.
const MAX_SIGNATURE_LAYER_READ_BYTES: usize = 1024 * 1024;

/// **The door.** When a manifest declares EVERY layer to be signature
/// material hort recognises — the condition
/// [`is_pure_signature_manifest`] grants the scan/quarantine exemption on —
/// the blob behind each declared layer must actually parse as the shape it was
/// declared as. Unparseable ⇒ the push is refused, before the mint, with 400
/// `MANIFEST_INVALID` naming the offending layer digest.
///
/// This narrows the exemption; it never widens it. The "every layer must be
/// signature material" rule above is the anti-scan-evasion guard and is
/// untouched: a mixed manifest (a signature layer plus a runnable `tar+gzip`
/// layer) still fails `is_pure_*`, still never reaches this function, and
/// still takes the generic scanned path.
///
/// # Shape, never validity
///
/// Whether a signature is *valid* needs the trust root and the subject's
/// bytes and stays in the verifiers (`hort-adapters-provenance-*`, which this
/// crate must not depend on — ADR 0008). The door answers one question: is
/// this the kind of thing it claims to be? A door that started verifying
/// would be both wrong — a signature can be well-formed and untrusted, which
/// is a verdict for the verify path to record against the subject — and a
/// denial-of-service surface on the write path.
///
/// # It is not total, and must not pretend to be
///
/// Two gaps, both deliberate, both covered by the complementary rule that
/// unreadable material contributes nothing to a verdict (ADR 0039 D4):
///
/// - **Unreadable bytes are accepted.** The resolution ahead of this call
///   establishes a same-repo, non-terminal **row** per referenced blob; a row
///   can exist while CAS does not hold the object, and a read can fail for
///   reasons that are nothing to do with the push. Refusing there would turn
///   a storage fault into a client error the client cannot act on, so the
///   read failure is logged and the push proceeds.
/// - **Referrers hort lands itself from an upstream proxy never come through
///   here.** The pull-through path mints them without a client PUT, so this
///   door has no say over them at all.
///
/// # Forward compatibility
///
/// An **unrecognised** layer media type fails both purity predicates, so such
/// a manifest is not a signature manifest at all and takes the generic ingest
/// path — scanned and quarantined like any other content. A future bundle
/// version carrying a new media type is therefore **not** refused here; it
/// simply is not treated as a signature, and an artifact relying on it holds
/// as unsigned. Only *recognised media type declared* **and** *bytes
/// unparseable as that shape* is refused.
async fn refuse_misdeclared_signature_layers(
    ctx: &AppContext,
    body_bytes: &[u8],
    manifest_digest: &ContentHash,
) -> Result<(), Box<Response>> {
    let layers = match hort_domain::oci::declared_signature_layers(body_bytes) {
        Ok(l) => l,
        Err(e) => {
            // Unreachable in practice: the body parsed as JSON upstream and
            // both purity predicates parsed it again to get here. Fail safe
            // the same way they do — no refusal out of a parse this code
            // could not perform.
            tracing::warn!(
                manifest_digest = %manifest_digest,
                error = %e,
                "signature-layer enumeration failed on a manifest the purity predicates \
                 accepted; the shape check is skipped for this push"
            );
            return Ok(());
        }
    };

    for layer in layers {
        // The echoed digest is rebuilt from the PARSED hash, never from the
        // manifest's raw string: `ContentHash` is 64 lowercase hex, so this
        // is byte-identical to what a client sent for any digest that got
        // this far, while carrying none of the client's bytes into the
        // response (the never-echo contract `parse_blob_digest` states).
        let layer_digest = format!("sha256:{}", layer.hash);
        let bytes = match ctx
            .artifact_use_case
            .read_content_for_projection(&layer.hash, MAX_SIGNATURE_LAYER_READ_BYTES)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    manifest_digest = %manifest_digest,
                    layer_digest = %layer_digest,
                    media_type = layer.carriage.media_type(),
                    error = %e,
                    "declared signature layer could not be read at push time; the push is \
                     accepted and the shape is not asserted — material a verifier cannot \
                     read contributes nothing to a verdict either"
                );
                continue;
            }
        };
        if !layer.carriage.accepts(&bytes) {
            tracing::warn!(
                manifest_digest = %manifest_digest,
                layer_digest = %layer_digest,
                media_type = layer.carriage.media_type(),
                "declared signature layer is not the shape its media type declares; \
                 refusing the push"
            );
            return Err(Box::new(
                OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "layer is not well-formed as the signature media type it declares",
                        "layer_digest": layer_digest,
                        "media_type": layer.carriage.media_type(),
                    })),
                }
                .into_response(),
            ));
        }
    }

    Ok(())
}

/// Ingest the manifest bytes. A `Conflict` here is the declared-hash
/// mismatch. The wire mapping (Conflict -> ManifestInvalid) is preserved.
/// The signature path surfaces the same `Conflict` shape on a
/// put-vs-declared mismatch.
///
/// `claimed_edges` are the content-reference edges the manifest claims on
/// bytes it does not own: its `subject.digest`, and — when every declared
/// reference resolved in this repository — its `oci_config` / `oci_layer` /
/// `oci_index_member` membership edges. They are handed to the ingest
/// rather than written after it so they commit in the manifest artifact's
/// own transaction: a `content_references` row is what keeps the target's
/// bytes out of the storage GC, and an edge written afterwards is a window
/// in which the referrer is live and its target collectable. Both ingest
/// arms take them, so a pure-signature referrer is covered exactly like any
/// other manifest.
///
/// `is_pure_signature` is [`is_pure_signature_manifest`]'s answer, taken as a
/// parameter rather than re-derived here: the same decision selects the ingest
/// arm AND gates [`refuse_misdeclared_signature_layers`] ahead of the mint,
/// and two independently-computed copies of it could disagree — a manifest
/// whose layers were never shape-checked taking the exempt arm is exactly the
/// state the door exists to prevent.
#[allow(clippy::too_many_arguments)]
async fn run_manifest_ingest(
    ctx: &AppContext,
    repo_id: Uuid,
    name: &str,
    actor: &ApiActor,
    media_type: &str,
    subject_digest_str: Option<String>,
    subject_digest_parsed: &Option<ContentHash>,
    is_pure_signature: bool,
    claimed_edges: &[ContentReferenceClaim],
    hashes: &ManifestHashDecision,
    body_bytes: &[u8],
) -> Result<IngestOutcome, Response> {
    // Build the ingest request + stream. The body is an in-memory `Vec<u8>`
    // by the time we're here (the 1 MiB cap keeps this cheap); wrap in a
    // `Cursor` to get an `AsyncRead`.
    let manifest_coords = oci_manifest_coords(name, &hashes.computed_hash);
    let payload_metadata = serde_json::json!({
        "oci_media_type": media_type,
        "oci_subject_digest": subject_digest_str,
    });
    // Manifest write: digest from request body (when reference is a
    // digest) or computed from bytes. Either way ProtocolNative is correct
    // because OCI's protocol embeds the digest in the request itself (ADR
    // 0006).
    let upstream_digest = hashes
        .declared_hash
        .clone()
        .unwrap_or_else(|| hashes.computed_hash.clone());
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(body_bytes.to_vec()));

    let ingest_result = if is_pure_signature {
        ctx.ingest_use_case
            .ingest_signature_manifest(
                repo_id,
                manifest_coords,
                media_type.to_string(),
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
                claimed_edges,
                stream,
            )
            .await
    } else {
        let ingest_req = VerifiedIngestRequest::ProtocolNative {
            repository_id: repo_id,
            coords: manifest_coords,
            content_type: media_type.to_string(),
            actor: actor.clone(),
            payload_metadata,
            upstream_digest,
            upstream_published_at: None,
            // Manifest write is OCI-direct (`PUT /v2/<name>/manifests/<reference>`):
            // no serving `RepositoryUpstreamMapping`, opt-in cannot apply (ADR 0007).
            trust_upstream_publish_time: false,
        };
        ctx.ingest_use_case
            .ingest_verified(ingest_req, claimed_edges, stream, &OciFormatHandler)
            .await
    };

    match ingest_result {
        Ok(o) => Ok(o),
        Err(AppError::Domain(DomainError::Conflict(_))) => Err(OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "manifest ingest rejected declared digest",
            })),
        }
        .into_response()),
        Err(err) => {
            if let Some(busy) = manifest_write_contention(&err, "manifest_ingest") {
                return Err(busy.into_response());
            }
            tracing::error!(error = %err, "OCI manifest ingest failed");
            Err(OciError::Internal.into_response())
        }
    }
}

/// Parse the referenced blobs / children by media-type shape.
///
/// - Image index / manifest list: `manifests[*].digest` child **manifest**
///   references (no `config`, no `layers`). An over-cap index is
///   `MANIFEST_INVALID`, mirroring the single-image reference-count
///   rejection.
/// - Single-image manifest: the unchanged `config` + `layers[]` parse.
///
/// A single-image parse failure lands as `MANIFEST_INVALID`. The index path
/// picks its own code: an index child whose digest matches the descriptor
/// grammar but names an algorithm hort cannot address is a valid index this
/// registry cannot store, so it answers `UNSUPPORTED` rather than
/// `MANIFEST_INVALID` — see [`parse_index_children_for_admission`]. That is
/// why this function forwards the index branch's error instead of wrapping
/// every failure in one envelope: wrapping is how the two answers used to
/// collapse into one.
/// `media_type_is_index` was computed up front (declared-vs-shape
/// cross-check); reused here to dispatch the blob/child parse.
///
/// **Runs before the mint**, which is why the diagnostic names the body's
/// computed digest rather than an artifact id: the manifest this body
/// describes does not exist yet, and a body this parse rejects never
/// becomes an artifact at all. That is a change from the ordering this
/// handler used to have — the parse ran after the ingest and a structurally
/// invalid manifest stayed committed — and it is the price of having the
/// membership claims in hand before the transaction that must carry them.
/// The client sees the same 400 `MANIFEST_INVALID` either way; what it no
/// longer leaves behind is an artifact row for a body hort refused.
fn parse_referenced_blobs(
    media_type_is_index: bool,
    body_bytes: &[u8],
    parsed_manifest: &serde_json::Value,
    manifest_digest: &ContentHash,
) -> Result<Vec<ReferencedBlob>, Box<Response>> {
    let result = if media_type_is_index {
        parse_index_children_for_admission(body_bytes)
    } else {
        parse_manifest_blobs(parsed_manifest).map_err(|detail| OciError::ManifestInvalid {
            detail: Some(detail),
        })
    };
    result.map_err(|err| {
        tracing::warn!(
            manifest_digest = %manifest_digest,
            "manifest parse failed pre-ingest; nothing minted"
        );
        Box::new(err.into_response())
    })
}

/// The outcome of resolving a manifest's declared references against the
/// repository, as it stands **before** the manifest is minted.
///
/// Two outcomes, because the mint happens between them and the claim set
/// depends on which one it is. [`Self::Complete`] means every declared
/// reference resolved to an artifact in this repository, so the membership
/// edges are safe to claim: no claim can name bytes the repository does not
/// hold. [`Self::Missing`] carries the raw `sha256:<hex>` strings for the
/// 400 `MANIFEST_BLOB_UNKNOWN` the caller answers **after** the mint — the
/// manifest still commits (unchanged contract: the client's
/// retry-after-pushing-the-blobs path is idempotent) and simply carries no
/// membership claims, which is exactly what the post-ingest insert loop
/// this replaced also left behind on that path.
enum ResolvedReferences {
    /// Boxed because an `Option<Artifact>` dwarfs a `Vec<String>` and
    /// `clippy::large_enum_variant` is right to object: the
    /// unknown-blob arm is the one every missing-blob PUT returns, and it
    /// should not carry an artifact-sized hole. Same reflex as this
    /// module's `Box<Response>` returns.
    Complete(Box<ResolvedReferenceSet>),
    Missing(Vec<String>),
}

/// The artifacts behind a [`ResolvedReferences::Complete`] resolution: the
/// config blob (single-image manifests only — an index has none) and the
/// layer blobs, in manifest order, as `attach_group_members` consumes them.
/// An index's children are resolved for existence only and so appear in
/// neither field.
struct ResolvedReferenceSet {
    config_artifact: Option<Artifact>,
    layer_artifacts: Vec<Artifact>,
}

/// Resolve each referenced blob / child manifest. Cross-repo isolation: a
/// hash that exists in a foreign repo counts as missing — the blob must
/// live in the same repo as the manifest (mount it across explicitly via
/// `POST /v2/.../blobs/uploads/?mount=...&from=...`). A hash whose
/// same-repo row is in a terminal state counts as missing too — see
/// [`resolve_referenced_blobs`]. For an index the children are resolved
/// for **existence only** — a missing child is `MANIFEST_BLOB_UNKNOWN`,
/// exactly like a missing layer (clients push the platform manifests
/// before the index). A single-image manifest has a resolved `config`; an
/// index carries none — the config is required only on the single-image
/// path.
///
/// `Err` is reserved for the two failures that must abort before anything
/// is minted: an infrastructure error from the lookup, and the defensive
/// no-config assertion. A *missing* reference is not an error here — it is
/// the [`ResolvedReferences::Missing`] outcome, answered after the mint so
/// the committed-manifest contract is preserved.
///
/// This is a pure read — `find_in_repo_by_hash` and nothing else — which is
/// what makes it runnable ahead of the mint. It used to take the minted
/// manifest's id and used it only as a log field; the pre-mint diagnostics
/// name the body's computed digest instead.
async fn resolve_and_check_referenced_blobs(
    ctx: &AppContext,
    repo_id: Uuid,
    referenced: &[ReferencedBlob],
    media_type_is_index: bool,
    manifest_digest: &ContentHash,
) -> Result<ResolvedReferences, Response> {
    let (config_artifact, layer_artifacts, missing) =
        resolve_referenced_blobs(ctx, repo_id, referenced)
            .await
            .inspect_err(|_| {
                tracing::error!("infrastructure error during blob resolution");
            })?;

    if !missing.is_empty() {
        // The manifest artifact stays committed, and what that buys the
        // client depends on WHY the reference did not resolve — the two
        // cases this list folds together:
        //
        // - **No row for the digest.** A retry after pushing the blob
        //   reconciles cleanly; that is the case this path was built for
        //   and the common one (a client pushing out of order, or an
        //   index landing ahead of its platform children).
        // - **A row in a terminal state** (`Rejected` /
        //   `ScanIndeterminate`). No retry can help: the row already
        //   exists, so re-pushing those bytes deduplicates onto it and
        //   leaves the status untouched. Leaving the hold needs a
        //   deliberate act on the blob — admin override, curator waiver,
        //   a re-scan — or different content.
        //
        // Both answer the same envelope on purpose. It is not an opaque
        // one — `detail.blobs` names every unresolvable digest, so the
        // publisher knows exactly which references to act on; what it
        // does not say is which of the two causes applied, and that
        // costs them nothing because their next move is the same for
        // both (upload or cross-mount the blob, at which point a
        // terminal row surfaces on its own). The cause is in the log
        // line in `resolve_referenced_blobs`, which names the digest and
        // the status. Either way we do NOT create the group on this path, and
        // the mint carries no membership claims — an edge must never name
        // a blob the repository cannot deliver.
        tracing::info!(
            manifest_digest = %manifest_digest,
            missing = ?missing,
            "manifest referenced unresolvable blobs; group attachment and membership claims \
             withheld (absent blobs reconcile on client retry; a terminal blob does not)"
        );
        return Ok(ResolvedReferences::Missing(missing));
    }

    if !media_type_is_index && config_artifact.is_none() {
        // Defensive: reachable only if `parse_manifest_blobs` accepted a
        // single-image manifest with no config AND this resolution didn't
        // mark it missing. The current parser rejects missing config, so
        // this branch is an assertion.
        tracing::error!(
            manifest_digest = %manifest_digest,
            "resolve_referenced_blobs returned None config with empty missing list"
        );
        return Err(OciError::Internal.into_response());
    }

    Ok(ResolvedReferences::Complete(Box::new(
        ResolvedReferenceSet {
            config_artifact,
            layer_artifacts,
        },
    )))
}

/// Identifiers shared by the post-ingest writes left in the manifest-PUT
/// pipeline — the group attach and the tag-ref set — bundled to avoid
/// repeating the same argument list across both stages.
///
/// The content-reference inserts used to be in that list and are no longer:
/// every edge now rides the ingest transition as a
/// [`ContentReferenceClaim`], which is why nothing here carries a media
/// type any more (the claim metadata is built before the mint).
struct ManifestPostIngest<'a> {
    repo_id: Uuid,
    repo_key: &'a str,
    manifest_artifact: &'a Artifact,
    manifest_digest: &'a ContentHash,
    manifest_event_id: Uuid,
    correlation_id: Uuid,
    actor_any: Actor,
    group_coords: ArtifactCoords,
}

/// Attach members to the group. Order: manifest (primary) first, then
/// (single-image only) config, then every layer. An index attaches only
/// the primary `manifest` member — it has no config/layers and its child
/// manifests are NOT group members (the index→child linkage is a
/// content-reference edge, Item 3). The shared `correlation_id` +
/// `causation_id = Some(manifest_event_id)` is the load-bearing audit
/// contract — the causation-integrity test reads the recorded batches and
/// asserts this on every member event.
///
/// ADR 0060 contract (`hort_app::append_conflict`): a same-member replay
/// (same artifact_id + same role re-add) is an idempotent non-error — the
/// adapter's `ON CONFLICT DO NOTHING` absorbs it on the first attempt, or
/// `add_member`'s own retry cycle absorbs it after a conflict. A
/// different-member (or different-role) append that loses a real version
/// race is retried inside `add_member`, bounded; exhaustion surfaces
/// `DomainError::Contended`, mapped to 503 + `Retry-After` below — never
/// swallowed, never a bare 500. Any OTHER error reaching this site is a
/// genuine infrastructure failure and stays a logged 500.
async fn attach_group_members(
    ctx: &AppContext,
    m: &ManifestPostIngest<'_>,
    config_artifact: &Option<Artifact>,
    layer_artifacts: &[Artifact],
) -> Result<(), Response> {
    if let Err(e) = ctx
        .artifact_group_use_case
        .add_member(
            m.repo_id,
            m.group_coords.clone(),
            "manifest".into(),
            m.manifest_artifact.id,
            /* is_primary = */ true,
            m.actor_any.clone(),
            m.correlation_id,
            Some(m.manifest_event_id),
            Some(m.repo_key),
            "oci",
        )
        .await
    {
        if let Some(busy) = manifest_write_contention(&e, "group_attach_manifest") {
            return Err(busy.into_response());
        }
        tracing::error!(
            manifest_artifact_id = %m.manifest_artifact.id,
            manifest_digest = %m.manifest_digest,
            repo_key = %m.repo_key,
            stage = "group_attach_manifest",
            error = ?e,
            "manifest group-attach failed; not idempotent-shaped (see commit_member_added \
             contract) — this is a genuine error"
        );
        return Err(OciError::Internal.into_response());
    }

    if let Some(config_artifact) = config_artifact {
        if let Err(e) = ctx
            .artifact_group_use_case
            .add_member(
                m.repo_id,
                m.group_coords.clone(),
                "config".into(),
                config_artifact.id,
                /* is_primary = */ false,
                m.actor_any.clone(),
                m.correlation_id,
                Some(m.manifest_event_id),
                Some(m.repo_key),
                "oci",
            )
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "group_attach_config") {
                return Err(busy.into_response());
            }
            tracing::error!(
                manifest_artifact_id = %m.manifest_artifact.id,
                manifest_digest = %m.manifest_digest,
                config_digest = %config_artifact.sha256_checksum,
                repo_key = %m.repo_key,
                stage = "group_attach_config",
                error = ?e,
                "config group-attach failed; not idempotent-shaped (see commit_member_added \
                 contract) — this is a genuine error"
            );
            return Err(OciError::Internal.into_response());
        }
    }

    for layer in layer_artifacts {
        if let Err(e) = ctx
            .artifact_group_use_case
            .add_member(
                m.repo_id,
                m.group_coords.clone(),
                "layer".into(),
                layer.id,
                /* is_primary = */ false,
                m.actor_any.clone(),
                m.correlation_id,
                Some(m.manifest_event_id),
                Some(m.repo_key),
                "oci",
            )
            .await
        {
            if let Some(busy) = manifest_write_contention(&e, "group_attach_layer") {
                return Err(busy.into_response());
            }
            tracing::error!(
                manifest_artifact_id = %m.manifest_artifact.id,
                manifest_digest = %m.manifest_digest,
                layer_id = %layer.id,
                layer_digest = %layer.sha256_checksum,
                repo_key = %m.repo_key,
                stage = "group_attach_layer",
                error = ?e,
                "layer group-attach failed; not idempotent-shaped (see commit_member_added \
                 contract) — this is a genuine error"
            );
            return Err(OciError::Internal.into_response());
        }
    }

    Ok(())
}

/// Tag-ref PUT: set the ref. Digest-ref PUT: skip — the digest is
/// self-naming; creating a ref would be redundant.
///
/// ADR 0060 contract: `RefUseCase::set` short-circuits to `Ok` when the
/// target is unchanged, retries `RefCommitOutcome::RefAlreadyExists`
/// internally (never surfaced as `Err`), and now also retries a losing
/// append `Conflict` against the refreshed ref state, bounded; exhaustion
/// surfaces `DomainError::Contended`, mapped to 503 + `Retry-After` below.
/// Any OTHER error reaching here is a genuine infrastructure failure, not
/// an idempotency case to collapse.
async fn set_tag_ref(
    ctx: &AppContext,
    m: &ManifestPostIngest<'_>,
    name: &str,
    reference: &str,
    actor: &ApiActor,
) -> Result<(), Response> {
    if let Err(e) = ctx
        .ref_use_case
        .set(
            m.repo_id,
            /* namespace */ name,
            /* ref_name */ reference,
            RefTarget::ContentHash(m.manifest_digest.clone()),
            actor.clone(),
            Some(m.repo_key),
        )
        .await
    {
        if let Some(busy) = manifest_write_contention(&e, "ref_set") {
            return Err(busy.into_response());
        }
        tracing::error!(
            manifest_artifact_id = %m.manifest_artifact.id,
            manifest_digest = %m.manifest_digest,
            repo_key = %m.repo_key,
            reference = %reference,
            stage = "ref_set",
            error = ?e,
            "ref set failed; not idempotent-shaped (see RefUseCase::set contract) — \
             this is a genuine error"
        );
        return Err(OciError::Internal.into_response());
    }
    Ok(())
}

/// The content-reference claim the manifest carries when it declares a
/// `subject.digest`: `kind = "oci_subject"`, target the subject image's
/// content hash. `None` when the manifest had no `subject` field at all;
/// the digest itself was validated up front by `validate_subject_digest`.
///
/// **A claim, not a row.** The claim rides the manifest's own ingest
/// transition (see [`run_manifest_ingest`]), so the referrer and the row
/// that keeps its subject's bytes alive commit together or not at all. It
/// used to be an `insert_for_repo` issued after the ingest had returned,
/// which is a window in which the manifest is live, servable through the
/// Referrers API, and its subject has one fewer claim against the storage
/// GC — the GC deletes a CAS blob exactly when no `content_references` row
/// targets its hash. Nothing repairs that afterwards: the refcount-reconcile
/// sweep derives `primary_content` and `metadata_blob` from the artifact row
/// and mints no tree edge, because no artifact row records one. The subject
/// is another artifact's content, so the failure mode is somebody else's
/// bytes going away.
///
/// Idempotency is unchanged and now belongs to the transition: the upsert is
/// on `(repository_id, source_artifact_id, target_content_hash, kind)`, so a
/// client retry of the same manifest refreshes the row.
fn subject_content_reference_claim(
    subject_digest_parsed: &Option<ContentHash>,
    media_type: &str,
    artifact_type_opt: &Option<String>,
) -> Option<ContentReferenceClaim> {
    subject_digest_parsed
        .clone()
        .map(|subject_hash| ContentReferenceClaim {
            target_content_hash: subject_hash,
            kind: "oci_subject".into(),
            metadata: serde_json::json!({
                "artifact_type": artifact_type_opt,
                "media_type": media_type,
            }),
        })
}

/// The manifest→blob / index→child membership claims a manifest body
/// declares: one [`ContentReferenceClaim`] per referenced blob, with
/// `kind = "oci_config"` (the config blob), `"oci_layer"` (each layer
/// blob) or `"oci_index_member"` (each child manifest of an image index /
/// manifest list). A single-image manifest declares the first two and no
/// third; an index declares only the third.
///
/// These are GC-ACTIVE keepalive claims, exactly like `oci_subject`: the
/// purge refcount counts rows of every kind against a target hash, so a
/// live manifest keeps its config / layer blobs and an index keeps every
/// child manifest's bytes. This does not double-count against the
/// [`ArtifactGroupUseCase::add_member`] calls in [`attach_group_members`] —
/// group membership is an orthogonal, GC-invisible axis (the
/// purge/refcount sweep never reads `artifact_group_members`). Manifest
/// DELETE's `delete_by_source` removes every kind for the source, so these
/// rows are cleaned up together; the manifest's own primary-content edge is
/// then re-derived by the storage-GC sweep from `artifacts.checksum_sha256`
/// when it collects the manifest bytes.
///
/// **A claim set, not a row set.** These used to be two post-ingest
/// `insert_for_repo` loops, which meant a failure left the manifest live
/// with its constituents holding one fewer claim against the storage GC and
/// no sweep able to re-derive a tree edge. They now ride the manifest's own
/// ingest transition. The ordering worry that kept them outside it — that a
/// claim made before the blob-existence gate could name a blob the
/// repository does not hold, and so hand the blob's own later ingest a
/// zero-window quarantine carve-out it did not earn — is answered by
/// *resolving first and claiming second*: the caller builds this set only
/// from a [`ResolvedReferences::Complete`] resolution, and the
/// unknown-blob 400 still answers after the mint, so the committed-manifest
/// retry contract is untouched. Neither side of that trade-off had to be
/// paid.
///
/// The widened PK `(repository_id, source_artifact_id,
/// target_content_hash, kind)` (migration 013) lets N targets share one
/// `(source, kind)` — an index with N children, a manifest with N layers.
/// A manifest may legally repeat a layer digest, so the set may carry the
/// same `(target, kind)` twice; the adapter issues one upsert per claim, so
/// the repeat refreshes rather than tripping the primary key.
///
/// [`ArtifactGroupUseCase::add_member`]:
///     hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase::add_member
pub(crate) fn membership_claims(
    referenced: &[ReferencedBlob],
    media_type: &str,
) -> Vec<ContentReferenceClaim> {
    referenced
        .iter()
        .map(|blob| match blob.role {
            BlobRole::ChildManifest { .. } => ContentReferenceClaim {
                target_content_hash: blob.hash.clone(),
                kind: "oci_index_member".into(),
                metadata: serde_json::json!({
                    "child_digest": blob.digest_raw,
                    "media_type": media_type,
                }),
            },
            BlobRole::Config | BlobRole::Layer => ContentReferenceClaim {
                target_content_hash: blob.hash.clone(),
                kind: if blob.role == BlobRole::Config {
                    "oci_config"
                } else {
                    "oci_layer"
                }
                .into(),
                metadata: serde_json::json!({
                    "digest": blob.digest_raw,
                    "media_type": media_type,
                }),
            },
        })
        .collect()
}

/// The complete content-reference claim set the manifest PUT hands to its
/// ingest: the `oci_subject` claim (when the body declares one) followed by
/// the membership claims.
///
/// The membership claims are gated on the resolution being
/// [`ResolvedReferences::Complete`], and that gate is the whole reason this
/// function exists rather than a bare `extend`. An `oci_config` /
/// `oci_layer` / `oci_index_member` row is a tree edge that
/// `hort_app`'s referenced-tree-descendant predicate counts, so a row
/// naming a blob the repository does not hold would let that blob's own
/// later ingest see itself already referenced and take the zero-window
/// quarantine carve-out — an observation window shortened on the strength
/// of an edge written for content that did not exist. Resolving before the
/// mint removes the possibility rather than mitigating it: on the
/// unknown-blob path there is no membership claim to be wrong about.
///
/// `oci_subject` is NOT gated the same way, and deliberately: the OCI
/// Referrers flow lets a referrer be pushed for a subject this repository
/// has not got, and the handler has always minted that referrer — gating
/// it would refuse a legitimate push.
///
/// What that costs is worth stating, because it is not nothing and the
/// opposite is easy to assume. `oci_subject` **is** a tree edge on the
/// descendant predicate: `is_referenced_tree_descendant` counts every
/// kind outside `{primary_content, metadata_blob}`, `oci_subject`
/// included. So a referrer for an absent subject does set the zero-window
/// carve-out for that subject's own later ingest. That is the pre-existing
/// shape of the Referrers flow and resolving the membership claims before
/// the mint neither introduces nor repairs it; the two are gated
/// differently because the push each one refuses is different, not
/// because one of them is harmless.
fn manifest_ingest_claims(
    subject_claim: Option<ContentReferenceClaim>,
    resolved: &ResolvedReferences,
    referenced: &[ReferencedBlob],
    media_type: &str,
) -> Vec<ContentReferenceClaim> {
    let mut claims: Vec<ContentReferenceClaim> = subject_claim.into_iter().collect();
    if matches!(resolved, ResolvedReferences::Complete(_)) {
        claims.extend(membership_claims(referenced, media_type));
    }
    claims
}

/// Entry point for `PUT /v2/:repo_key/*tail`.
///
/// `WriteRepoAccess` runs as a `FromRequestParts` extractor before the
/// body is touched — resolving the repo and running the RBAC check up
/// front means an unauthorised caller never hits the manifest parser
/// (cheap-fail principle). The handler itself is a straight-line
/// composition of the workflow documented at the module head; each stage
/// below owns one pre-commit or post-ingest gate, and
/// [`put_manifest_dispatch_inner`]'s call order is the load-bearing
/// contract.
pub(crate) async fn put_manifest_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    request: Request<Body>,
) -> Response {
    match put_manifest_dispatch_inner(access, &ctx, repo_key, tail, request).await {
        Ok(resp) => resp,
        Err(resp) => *resp,
    }
}

// `Box<Response>` per `clippy::result_large_err` (`http::Response<Body>` is
// > 128 bytes) — mirrors `extract_media_type` / `resolve_digest_reference`'s
// established boxing convention in this crate.
async fn put_manifest_dispatch_inner(
    access: WriteRepoAccess,
    ctx: &AppContext,
    repo_key: String,
    tail: String,
    request: Request<Body>,
) -> Result<Response, Box<Response>> {
    let (name, reference) = parse_and_validate_manifest_tail(&repo_key, &tail)?;

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };
    // Shared per-request correlation_id threaded through every call the
    // handler issues downstream (ingest, add_member × N, ref set,
    // content_references insert). Load-bearing audit contract — see
    // audit-trail contract.
    let correlation_id = Uuid::new_v4();

    let (headers, body_bytes) = read_manifest_body(request).await.map_err(Box::new)?;
    let media_type = validate_manifest_media_type(&headers)?;
    let parsed_manifest = parse_manifest_json(&body_bytes)?;
    let media_type_is_index = check_declared_media_type_matches_shape(&media_type, &body_bytes)?;

    let (subject_digest_str, artifact_type_opt) =
        extract_subject_and_artifact_type(&parsed_manifest);
    let subject_digest_parsed = validate_subject_digest(subject_digest_str.as_deref())?;

    let hashes = resolve_manifest_hash(&body_bytes, &reference)?;

    // The subject claim is built from the parsed body, ahead of the mint,
    // and handed to the ingest: it is a claim on the SUBJECT image's bytes,
    // and the transaction that makes the referrer live is the only place it
    // can be recorded without leaving a window in which the subject has one
    // fewer claim against the storage GC.
    let subject_claim =
        subject_content_reference_claim(&subject_digest_parsed, &media_type, &artifact_type_opt);

    // Parse and resolve the declared references BEFORE the mint. Both are
    // reads over data already in hand (the body, and `find_in_repo_by_hash`)
    // and both only ever used the manifest's id as a log field, so neither
    // needs the artifact to exist. Running them here is what puts the
    // membership claims in the ingest's hands: a `content_references` row is
    // the claim that keeps bytes alive, and the manifest's own transaction is
    // the only place to record a claim on somebody else's bytes without
    // leaving a window in which the manifest is live and those bytes are
    // collectable.
    let referenced = parse_referenced_blobs(
        media_type_is_index,
        &body_bytes,
        &parsed_manifest,
        &hashes.computed_hash,
    )?;
    let resolved = resolve_and_check_referenced_blobs(
        ctx,
        repo_id,
        &referenced,
        media_type_is_index,
        &hashes.computed_hash,
    )
    .await
    .map_err(Box::new)?;

    // ONE decision, two consumers: it selects the ingest arm below and it
    // gates the door immediately after. See `run_manifest_ingest`.
    let is_pure_signature = is_pure_signature_manifest(&subject_digest_parsed, &body_bytes);

    // The door, before the mint. Gated on a COMPLETE resolution so the bytes
    // it parses are bytes this repository holds: on the `Missing` path there
    // is nothing of ours to read behind at least one declared layer, and that
    // push keeps its established answer (the post-mint 400
    // `MANIFEST_BLOB_UNKNOWN` below) rather than acquiring a second one.
    if is_pure_signature && matches!(resolved, ResolvedReferences::Complete(_)) {
        refuse_misdeclared_signature_layers(ctx, &body_bytes, &hashes.computed_hash).await?;
    }

    let claims = manifest_ingest_claims(subject_claim, &resolved, &referenced, &media_type);

    let ingest_outcome = run_manifest_ingest(
        ctx,
        repo_id,
        &name,
        &actor,
        &media_type,
        subject_digest_str,
        &subject_digest_parsed,
        is_pure_signature,
        &claims,
        &hashes,
        &body_bytes,
    )
    .await
    .map_err(Box::new)?;

    let manifest_artifact = ingest_outcome.artifact;
    let manifest_event_id = ingest_outcome.ingested_event_id;
    let manifest_digest = hashes.computed_hash.clone();

    // The unresolvable-reference answer lands HERE — after the mint — and
    // that is the unchanged contract, not an oversight: a manifest
    // referencing blobs the client has not pushed yet stays committed so the
    // retry-after-pushing path is idempotent. For a reference that resolved
    // to a TERMINAL row the mint is still committed but buys the client
    // nothing — that blob's row already exists, so no re-push changes the
    // answer (see `resolve_and_check_referenced_blobs` for both cases). What
    // the reorder above changed is only that such a manifest now also
    // carries no membership claims, which is what the post-ingest insert
    // loop this replaced already left behind on this path (its gate returned
    // before the first insert).
    let (config_artifact, layer_artifacts) = match resolved {
        ResolvedReferences::Complete(set) => (set.config_artifact, set.layer_artifacts),
        ResolvedReferences::Missing(blobs) => {
            return Err(Box::new(
                OciError::ManifestBlobUnknown { blobs }.into_response(),
            ));
        }
    };

    let post_ingest = ManifestPostIngest {
        repo_id,
        repo_key: &repo_key,
        manifest_artifact: &manifest_artifact,
        manifest_digest: &manifest_digest,
        manifest_event_id,
        correlation_id,
        actor_any: Actor::Api(actor.clone()),
        group_coords: oci_group_coords(&name, &manifest_digest),
    };
    attach_group_members(ctx, &post_ingest, &config_artifact, &layer_artifacts)
        .await
        .map_err(Box::new)?;

    if !hashes.reference_is_digest {
        set_tag_ref(ctx, &post_ingest, &name, &reference, &actor)
            .await
            .map_err(Box::new)?;
    }

    Ok(created_manifest_response(
        &repo_key,
        &name,
        &reference,
        &manifest_digest,
    ))
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

    // Artifact lifecycle delete FIRST, keepalive-edge sweep second. The
    // ORDER is the invariant here, not an incidental sequence.
    //
    // The sweep below drops every `content_references` row sourced from
    // this manifest — including the keepalive edges `oci_config`,
    // `oci_layer` and `oci_index_member`, which are what hold the
    // manifest's config/layer blobs and child manifests against storage
    // GC. `RefcountReconcileUseCase` re-creates only the single-target
    // `primary_content` / `metadata_blob` kinds, so nothing repairs the
    // keepalive kinds once they are gone. Sweeping BEFORE the state
    // change therefore left a failed delete with a live, servable
    // manifest whose blobs were collectable: at the next purge the bytes
    // vanish under an artifact every read path considers healthy.
    // Sweeping after the transition has committed makes that state
    // unreachable — a failed delete returns 500 with every edge intact,
    // and the client's retry is idempotent.
    //
    // `ArtifactUseCase::delete` is an event-sourced soft delete: the row
    // survives with `deleted_at` set and an `ArtifactDeleted` event lands
    // on the artifact's stream, attributed to this caller. The CAS blob is
    // NOT removed here (GC concern; multiple artifacts may share CAS
    // bytes) — the manifest's OWN bytes are released by the storage-GC
    // sweep, for which the `ArtifactDeleted` appended here is the work
    // item.
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

    // content_references cleanup, on the committed-transition side of the
    // ordering above. Idempotent — missing entries are `Ok(())` per the
    // port contract — and unaffected by the soft delete, since
    // `delete_by_source` keys on the source artifact id alone.
    //
    // This sweep is NOT redundant with the one `purge_artifact_refs`
    // performs inside the purge transaction, for two independent reasons:
    //
    // - Reachability. The purge is only ever offered an artifact whose
    //   `quarantine_status` lies outside the GC-protected set, so a
    //   manifest deleted while `quarantined` or `scan_indeterminate` is
    //   never purged and its edges would otherwise stand forever.
    // - Promptness. These edges feed live decisions — the OCI referrers
    //   projection, the referenced-tree-descendant quarantine anchor in
    //   `IngestUseCase`, and the release sweep's parent-gated-blob skip —
    //   each of which must stop seeing a tombstoned source now, not at
    //   the next purge interval. The parent-gated skip in particular
    //   relies on this sweep to resume the expiry backstop for a blob
    //   whose parent manifest has gone away.
    //
    // A failure here is logged and does NOT fail the request: the
    // transition is already durable, the projection is eventually
    // authoritative, and answering 500 after a committed delete would
    // invite a retry of something that has already happened. The
    // residual state — a tombstoned source with edges still standing —
    // is the same one the purge sweep is there to clear.
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
            "content_references delete_by_source failed after the manifest delete \
             committed; the edges stand until the purge sweep clears them"
        );
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
    ///
    /// **Existence is not identity**, which is why this variant carries
    /// data and the other two do not: a present row is also held against
    /// what the index's descriptor said about it. The declared `size` lives
    /// on the variant rather than beside `role` so there is no field that
    /// is meaningful for one role and inert for the others — the check site
    /// gets the value by destructuring the only role that has one.
    ChildManifest {
        /// Zero-based slot in the index's `manifests[]`. Carried so a refusal
        /// over this child names `manifests[N]` — the same thing the parse
        /// refusals name, and for the same reason: it is the only name for a
        /// descriptor that is not a reflection of what the declarant wrote.
        position: usize,
        /// The descriptor's declared `size` in bytes, when it declared one
        /// readable as an `i64`. `None` is a descriptor that stated nothing
        /// to compare (`size` is REQUIRED by the image spec, so this is a
        /// non-conformant child), never "the sizes agree".
        declared_size: Option<i64>,
    },
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
/// Delegates the JSON parse + bound + descriptor classification to the
/// domain helper
/// [`index_child_descriptors`](hort_domain::oci::index_child_descriptors).
/// An index declaring more than the domain cap is a
/// [`DomainError::Validation`](hort_domain::error::DomainError::Validation).
///
/// Each child becomes a [`ReferencedBlob`] with role
/// [`BlobRole::ChildManifest`], so the shared [`resolve_referenced_blobs`]
/// same-repo existence check treats a missing child exactly like a missing
/// layer — a `MANIFEST_BLOB_UNKNOWN`. Clients push the platform child
/// manifests before the index, so an unresolved child is the expected
/// out-of-order case, not a hard error. The descriptor's declared `size`
/// rides along on the role, because existence alone is not identity — see
/// [`resolve_referenced_blobs`].
///
/// # A child with no usable digest is a refusal, not a skip
///
/// This parse used to hand the domain's bare-hash projection straight
/// through, which meant a child descriptor with **no `digest`**, a
/// **non-`sha256` algorithm** or **malformed hex** simply was not in the
/// list: the index was admitted with a `201` and one graph edge fewer than
/// it claimed. `digest` is a REQUIRED property of an OCI Content
/// Descriptor, so such an entry does not describe a child this registry
/// failed to resolve — it is an index that does not say what it claims to
/// say, and the admission gate refuses it.
///
/// Which refusal depends on the descriptor, and the spec draws the line:
/// an unrecognised **algorithm** "SHOULD pass validation" if it matches the
/// digest grammar, so `sha512:<hex>` is a *valid* index naming content
/// hort's CAS keyspace cannot address — [`OciError::Unsupported`]
/// (`UNSUPPORTED`). A digest matching no grammar, or an absent one, is a
/// malformed manifest — [`OciError::ManifestInvalid`] (`MANIFEST_INVALID`).
/// This is the same three-way split [`parse_digest`] applies to a
/// request-line digest in this crate; the classification itself is the
/// domain's ([`DescriptorProblem`]), because the projection that reads the
/// field lives there and `hort-app`'s readers of stored indexes need the
/// same vocabulary (ADR 0008 — nothing in `hort-domain` or `hort-app` can
/// reach into this crate for it).
///
/// # Never-echo
///
/// Neither refusal reflects any part of the declaration — not the digest,
/// not the algorithm, not an inner message. All three are
/// attacker-controlled manifest-JSON content and reflecting them in a
/// response body is a response-reflection vector (the contract
/// [`parse_blob_digest`] and [`parse_digest`] record). What the client gets
/// is a constant reason plus `manifests[N]`, hort's own zero-based slot
/// number, so a publisher is not left searching for which child was
/// refused. The declaration itself goes to `tracing` server-side.
pub(crate) fn parse_index_children_for_admission(
    body: &[u8],
) -> Result<Vec<ReferencedBlob>, OciError> {
    let declared =
        hort_domain::oci::index_child_descriptors(body).map_err(|e| OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": format!("invalid image index: {e}"),
            })),
        })?;

    let children = declared.into_all_declared().map_err(|fault| {
        tracing::debug!(
            child = %fault,
            "OCI image index declares a child whose descriptor names no addressable content"
        );
        let descriptor = format!("manifests[{}]", fault.position);
        if fault.problem.is_well_formed_but_unsupported() {
            // A valid index this registry cannot store: the descriptor's
            // digest complies with the spec grammar and names an algorithm
            // outside hort's CAS keyspace. `UNSUPPORTED` carries no
            // `detail`, so the slot rides in the message — which stays a
            // constant plus hort's own integer.
            OciError::Unsupported {
                message: format!("{UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE} in {descriptor}"),
            }
        } else {
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "image index child descriptor does not name addressable content",
                    "descriptor": descriptor,
                })),
            }
        }
    })?;

    Ok(children
        .into_iter()
        .map(|child| ReferencedBlob {
            digest_raw: format!("sha256:{}", child.hash.as_ref()),
            hash: child.hash,
            role: BlobRole::ChildManifest {
                position: child.position,
                declared_size: child.declared_size,
            },
        })
        .collect())
}

/// The same projection for the **pull-through membership** derivation, which
/// skips what it cannot address instead of refusing.
///
/// Separate from [`parse_index_children_for_admission`] rather than a flag on
/// it, because the two answers are not configuration — they are two different
/// questions, and a reader of either call site can see which one is being
/// asked. The hosted `PUT` is an admission gate: hort decides whether these
/// bytes enter the registry at all. This path runs over bytes that are already
/// stored, fetched from an upstream and verified against the digest the
/// upstream declared, and its only job is to derive the `content_references`
/// edges those bytes imply. Refusing here would not un-store the manifest —
/// it would mint it with **no** membership edges at all, which is the
/// un-keepalived state `oci_membership_edge_backfill` exists to repair, and it
/// would do so over a child the index's siblings have nothing to do with.
///
/// The claim set is therefore exactly what this path produced before — the
/// addressable children, no more and no fewer — with each skipped descriptor
/// now named in the log instead of vanishing. The existence check this path
/// deliberately does not perform is unchanged; see
/// [`pull_membership_claims`].
fn parse_index_children_for_membership(
    body: &[u8],
) -> Result<Vec<ReferencedBlob>, serde_json::Value> {
    let declared = hort_domain::oci::index_child_descriptors(body).map_err(|e| {
        serde_json::json!({
            "reason": format!("invalid image index: {e}"),
        })
    })?;

    let children = declared.into_resolvable(|fault| {
        tracing::warn!(
            child = %fault,
            "OCI pull-through: an image-index child declares no addressable content; no \
             membership edge for it (its siblings are unaffected)"
        );
    });

    Ok(children
        .into_iter()
        .map(|child| ReferencedBlob {
            digest_raw: format!("sha256:{}", child.hash.as_ref()),
            hash: child.hash,
            role: BlobRole::ChildManifest {
                position: child.position,
                declared_size: child.declared_size,
            },
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
///
/// **A row is not enough: the row's status decides too.** A reference
/// resolving to an artifact in a terminal state
/// ([`QuarantineStatus::is_terminal`](hort_domain::entities::artifact::QuarantineStatus::is_terminal)
/// — `Rejected` / `ScanIndeterminate`) counts as **not present** and joins
/// `missing`, because the blob GET refuses that very row (404
/// `BLOB_UNKNOWN` for `Rejected`, 503 for `ScanIndeterminate` —
/// `blobs.rs`, the exhaustive status match). Accepting the manifest over
/// it is how a push reports success and the subsequent pull answers `not
/// found` on a layer. The status arrives with the row
/// `find_in_repo_by_hash` already returns, so this costs no extra port
/// call and no extra I/O.
///
/// `Quarantined` still resolves as present — including a hold with no
/// self-resolving deadline. Hort quarantines at ingest and the manifest
/// PUT follows seconds later, so a hold-sensitive check would refuse
/// essentially every push; and under `provenance_mode: required` the
/// subject is held until its signature arrives, which ADR 0039 §10
/// exists to let the signer read and sign. Hence the status-only
/// predicate: see its rustdoc for why widening it to the hydrated
/// `provenance_hold_indefinite` flag would break sign-after-push.
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
            // A row in a terminal state is not a satisfied reference:
            // the blob GET refuses this exact row, so admitting it here
            // mints a manifest the registry cannot deliver. It joins the
            // same `missing` list as an absent row — one code path, one
            // `MANIFEST_BLOB_UNKNOWN` envelope, and the client is not
            // told which of the two the reference was.
            //
            // Folding the two together is sound here on its own terms,
            // and does not depend on how the blob GET answers. The caller
            // on this path is a **publisher**, and
            // `MANIFEST_BLOB_UNKNOWN`'s `detail.blobs` already names the
            // offending digest — so nobody is left searching, which is
            // the harm a collapsed answer would otherwise do. Their next
            // action is the same for both causes: upload or cross-mount
            // that blob, and if it is terminally blocked the upload is
            // what surfaces that. The diagnosis of WHICH cause is this
            // log line, which is why it carries the digest AND the
            // status: without the status an operator has to compare
            // event timestamps to learn why the push was refused.
            Some(a) if a.quarantine_status.is_terminal() => {
                tracing::warn!(
                    digest = %r.digest_raw,
                    status = %a.quarantine_status,
                    role = ?r.role,
                    "manifest references a terminally-blocked artifact; counted as missing \
                     (the blob read would refuse this row)"
                );
                missing.push(r.digest_raw.clone());
            }
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
                // A child manifest of an image index is not attached as a
                // group member (the index lands as a plain primary
                // `manifest`; the index→child linkage is a
                // content-reference edge, Item 3) — but it IS held against
                // the descriptor that named it before being dropped.
                BlobRole::ChildManifest {
                    position,
                    declared_size,
                } => {
                    check_child_against_descriptor(r, position, declared_size, &a)
                        .map_err(|e| *e)?;
                }
            },
            None => {
                if matches!(r.role, BlobRole::ChildManifest { .. }) {
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

/// Hold a **present** index child against the descriptor that named it.
///
/// Existence used to be the whole check: a row under the child's digest was
/// confirmed and dropped, so the descriptor's own statements about that
/// content were never read. The descriptor spec says they must be: "Before
/// consuming content targeted by a descriptor from untrusted sources, the byte
/// content SHOULD be verified against the digest string. Before calculating
/// the digest, the size of the content SHOULD be verified to reduce hash
/// collision space." — and of `size` itself, "If the length of the retrieved
/// content does not match the specified length, the content SHOULD NOT be
/// trusted."
///
/// Hort already has the digest half for free, and more strongly than the spec
/// asks: a stored row's `sha256_checksum` IS the lookup key, and CAS reads are
/// hash-verified on the way out (ADR 0003). What it did not have is the size
/// half — so that is what this adds, and it is cheap: `size_bytes` arrives on
/// the row `find_in_repo_by_hash` already returned, so the check costs no port
/// call and no I/O.
///
/// # What is compared, and what is not
///
/// **`size`**: compared when the descriptor declared one. A disagreement is a
/// `MANIFEST_INVALID` refusal of the index, before anything is minted — the
/// index is making a false statement about content this registry would then
/// serve under it. A descriptor that declared no readable `size` is
/// non-conformant (`size` is REQUIRED) but states nothing to disagree with, so
/// it is logged and admitted; tightening that into a refusal is a decision
/// about rejecting indexes hort accepts today, not a consequence of this one.
///
/// **`mediaType`**: deliberately NOT compared. The apparent counterpart is
/// `Artifact::content_type`, and it is not the descriptor's `mediaType` — it
/// is the `Content-Type` header whoever wrote that row supplied: a pusher's
/// manifest `PUT`, an upstream's response, or `application/octet-stream` when
/// the same bytes entered through a blob upload. `artifacts` is unique on
/// `(repository_id, path)` and not on the checksum, so one repository can hold
/// several rows for one hash, and the repo-scoped checksum lookup behind
/// `find_in_repo_by_hash` is a `LIMIT 1` with no `ORDER BY`. Comparing against
/// it would make the admission verdict depend on which duplicate row the
/// database happened to return. `size_bytes` has no such exposure: it is a
/// property of the bytes, so every row for one hash agrees on it.
///
/// The one sound `mediaType` check would be against the child's **own stored
/// bytes** (`is_image_index` over them) rather than against a header — the
/// same "the body decides, never the declared media type" rule
/// [`pull_membership_claims`] records. It is not done here because it would
/// put one CAS read per child on the manifest `PUT` path, and this resolution
/// being a pure catalog read is what lets it run ahead of the mint at all.
///
/// Returns the refusal `Box`ed, the same reflex as this module's other
/// `Box<Response>` returns: an `axum` `Response` dwarfs the `()` success here.
fn check_child_against_descriptor(
    r: &ReferencedBlob,
    position: usize,
    declared_size: Option<i64>,
    stored: &Artifact,
) -> Result<(), Box<Response>> {
    let Some(declared) = declared_size else {
        tracing::warn!(
            child_digest = %r.digest_raw,
            descriptor = %format_args!("manifests[{position}]"),
            "image index child descriptor declares no readable `size`, which the image \
             spec requires; nothing to hold the stored child against"
        );
        return Ok(());
    };
    if declared == stored.size_bytes {
        return Ok(());
    }
    tracing::warn!(
        child_digest = %r.digest_raw,
        descriptor = %format_args!("manifests[{position}]"),
        declared_size = declared,
        stored_size = stored.size_bytes,
        "image index child descriptor disagrees with the stored child's size; refusing \
         the index"
    );
    // Never-echo: both sizes are a declaration and a stored fact about the
    // client's own content, so they stay in the log line above and out of the
    // response. What the client gets is a constant reason plus hort's own slot
    // number — the publisher of the index is the publisher of the child, so it
    // can compare the two itself once it knows which child.
    Err(Box::new(
        OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "image index child descriptor disagrees with the stored child's size",
                "descriptor": format!("manifests[{position}]"),
            })),
        }
        .into_response(),
    ))
}

/// The `content_references` membership claims a **pull-through** manifest
/// declares, derived from its body: `oci_index_member` per child for an
/// image index, `oci_config` + `oci_layer` per referenced blob for a
/// single-image manifest. `target =` each declared child/blob digest.
///
/// **Register by digest, no existence check — and that is the mechanism,
/// not an omission.** A proxy descendant's edge is what gives it the
/// zero-window quarantine carve-out on its own later ingest (ADR 0007,
/// `referenced_descendant.rs`): the target-check reads exactly these kinds,
/// and before these edges were written at all, every proxy descendant's
/// check missed and took the full observation window. The hosted PUT path
/// gates its claims on in-repo resolution because ADR 0043 makes it
/// reject an unknown-blob manifest in the same breath; a pull-through
/// manifest's constituents legitimately are not here yet — the worker
/// fetches an index's children off the request path — so gating here would
/// mean never claiming them.
///
/// **The body decides whether this is an index, never the declared media
/// type.** `media_type` is the upstream's `Content-Type`, which an upstream
/// can get wrong; the body is the bytes that were hashed, verified against
/// the digest and stored, and it is what every other consumer of a pulled
/// manifest dispatches on. Deciding here on the header instead would mean a
/// structurally-index body served under an image-manifest `Content-Type`
/// gets its children ingested while its `oci_index_member` rows are never
/// written — the incomplete-membership defect the membership-edge backfill
/// exists to repair, and one digest verification cannot catch because the
/// bytes match their digest and only the header lies. A disagreement is
/// still worth knowing about, so it is logged; it just does not decide.
///
/// # Derivation failure is warn-and-continue; an insert failure is not
///
/// A parse failure yields **no** claims and does not fail the pull: the
/// bytes match the digest the upstream declared and the manifest is
/// legitimately servable, so it is minted with its own `primary_content`
/// edge and without membership edges — the state
/// `oci_membership_edge_backfill` exists to repair. The warn is the report
/// of it. (Mirrors `oci_index_child_ingest::derive_claims`.)
///
/// An **insert** failure is a different animal and no longer reachable
/// here: there is no insert left in this function. The claims this returns
/// ride the referrer's own ingest transition, so a failed edge fails the
/// mint and the client's retry of the GET re-runs the whole pull. This was
/// an `insert_for_repo` loop with a `warn!`-and-continue arm per edge,
/// which left the manifest committed and servable while a blob it
/// references carried one fewer claim against the storage GC — and nothing
/// repairs a tree edge afterwards, because the refcount-reconcile sweep
/// derives `primary_content` / `metadata_blob` from the artifact row and no
/// relational row records what a manifest references. A committed manifest
/// with no claim was not retriable; a failed GET is.
///
/// Idempotency is unchanged and now belongs to the transition: the upsert is
/// on `(repository_id, source_artifact_id, target_content_hash, kind)`, so a
/// re-pull of the same manifest refreshes the same rows.
pub(crate) fn pull_membership_claims(
    repo_id: Uuid,
    manifest_digest: &ContentHash,
    media_type: &str,
    body: &[u8],
) -> Vec<ContentReferenceClaim> {
    let body_is_index = hort_domain::oci::is_image_index(body);
    if is_index_media_type(media_type) != body_is_index {
        tracing::warn!(
            %repo_id,
            manifest_digest = %manifest_digest,
            media_type,
            body_is_index,
            "OCI pull-through: upstream media type disagrees with the manifest body's \
             shape; membership edges follow the body"
        );
    }
    let referenced = if body_is_index {
        match parse_index_children_for_membership(body) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(
                    %repo_id,
                    manifest_digest = %manifest_digest,
                    media_type,
                    ?detail,
                    "OCI pull-through: image-index child parse failed; manifest minted \
                     without membership edges"
                );
                return Vec::new();
            }
        }
    } else {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    %repo_id,
                    manifest_digest = %manifest_digest,
                    media_type,
                    error = %e,
                    "OCI pull-through: manifest body did not parse as JSON; manifest \
                     minted without membership edges"
                );
                return Vec::new();
            }
        };
        match parse_manifest_blobs(&parsed) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(
                    %repo_id,
                    manifest_digest = %manifest_digest,
                    media_type,
                    ?detail,
                    "OCI pull-through: manifest blob parse failed; manifest minted \
                     without membership edges"
                );
                return Vec::new();
            }
        }
    };

    membership_claims(&referenced, media_type)
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
    let hex = hex::encode(Sha256::digest(bytes));
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

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use crate::test_tracing::{capture_tracing, events_at};

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, GroupCommitInjection, MockArtifactGroupLifecyclePort,
        MockArtifactGroupRepository, MockArtifactLifecycle, MockArtifactRepository,
        MockContentReferenceIndex, MockEventStore, MockPolicyProjectionRepository,
        MockRefLifecyclePort, MockRefRegistryPort, MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::artifact_group::ArtifactGroup;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::events::DomainEvent;
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
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
        // Only the provenance-hold fixture seeds a policy; every other
        // test runs on the harness's permissive global seed.
        policy_projections: Arc<MockPolicyProjectionRepository>,
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
            policy_projections: mocks.policy_projections,
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
        seed_blob_with_status(artifacts, storage, repo_id, content, QuarantineStatus::None)
    }

    /// [`seed_blob`] with an explicit quarantine status, for the
    /// reference-resolution cases that turn on the row's state rather
    /// than its existence.
    fn seed_blob_with_status(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        content: &[u8],
        status: QuarantineStatus,
    ) -> ContentHash {
        let hash = seed_blob_row_without_content(artifacts, repo_id, content, status);
        storage.insert_content(hash.clone(), content.to_vec());
        hash
    }

    /// A seeded child manifest as an index fixture needs to declare it: the
    /// row's hash **and** the byte count that row carries.
    ///
    /// The two travel together from the seeding site rather than being
    /// re-derived where the index JSON is built, because the admission gate
    /// holds the descriptor's `size` against the stored row's. A fixture that
    /// builds the two independently can declare a size the child does not
    /// have — which is a refusal test, and must be written as one on purpose
    /// rather than reached by accident. (The fixture declared `"size": 0` for
    /// every child before that check existed, so every index in this corpus
    /// was non-conformant and nothing noticed.)
    #[derive(Clone, Debug)]
    struct SeededIndexChild {
        hash: ContentHash,
        size: i64,
    }

    /// [`seed_blob`] for a child manifest, carrying the stored byte count out
    /// alongside the hash so the index declaring it can be conformant.
    fn seed_index_child(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        content: &[u8],
    ) -> SeededIndexChild {
        SeededIndexChild {
            hash: seed_blob(artifacts, storage, repo_id, content),
            size: content.len() as i64,
        }
    }

    /// An artifact **row** for `content`'s hash with **no CAS object behind
    /// it**. Reference resolution finds a same-repo, non-terminal row, and a
    /// read of the bytes behind it then fails — the state a storage fault
    /// leaves, and the branch the signature-layer door accepts rather than
    /// refuses.
    fn seed_blob_row_without_content(
        artifacts: &MockArtifactRepository,
        repo_id: Uuid,
        content: &[u8],
        status: QuarantineStatus,
    ) -> ContentHash {
        let hex = hex::encode(Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(status);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        artifacts.insert(a);
        hash
    }

    /// Seed a blob in the `provenance_mode: required` hold-until-signed
    /// shape (ADR 0039 D4): `Quarantined`, with the observation-window
    /// **anchor** aged well past any window the caller's policy sets.
    ///
    /// The transient pair is NOT stamped here, deliberately: the schema
    /// stores only the anchor and
    /// `ArtifactUseCase::hydrate_quarantine_deadline` recomputes
    /// `quarantine_deadline` / `provenance_hold_indefinite` on every
    /// read, so a stamped value would be overwritten and reading it back
    /// would prove nothing. What makes the hold indefinite is this aged
    /// anchor plus a `Required` policy plus no `ProvenanceVerified` on
    /// the artifact's stream — see
    /// `put_with_indefinitely_held_layer_still_succeeds`.
    fn seed_indefinitely_held_blob(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        content: &[u8],
    ) -> ContentHash {
        let hex = hex::encode(Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        a.quarantine_window_start = Some(Utc::now() - chrono::Duration::seconds(3600));
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
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
                let config_hash: ContentHash = hex::encode(Sha256::digest(b"cfg")).parse().unwrap();
                let layer_hash: ContentHash =
                    hex::encode(Sha256::digest(b"layer")).parse().unwrap();
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

    /// #73 step 1 acceptance: a genuine (non-idempotent) `Conflict` from
    /// `add_member`'s manifest-attach call is logged at `error!` with
    /// the manifest digest, repo key, stage, and the full `DomainError`
    /// (variant + message) — not folded into a silent `warn!` the way
    /// it used to be. The response stays a 500 (no wire-behaviour
    /// change, per the directive's diagnosability-first scope); what
    /// changed is that the failure is now legible from the logs.
    #[test]
    fn divergent_add_member_conflict_is_logged_at_error_not_swallowed() {
        let (status, records) = capture_tracing(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
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
            })
        });

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "no wire-behaviour change: a genuine Conflict is still a 500"
        );

        let errors = events_at(
            &records,
            tracing::Level::ERROR,
            "hort_http_oci::manifests_write",
        );
        let error_event = errors
            .iter()
            .find(|e| {
                e.fields.contains("group-attach failed") && e.fields.contains("genuine error")
            })
            .map(|e| e.fields.clone());
        assert!(
            error_event.is_some(),
            "expected an ERROR-level log naming the group-attach failure as genuine; \
             captured records: {records:?}"
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
            !events_at(
                &records,
                tracing::Level::WARN,
                "hort_http_oci::manifests_write"
            )
            .iter()
            .any(|e| e.fields.contains("partial attachment")),
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
            let manifest_hex = hex::encode(Sha256::digest(&body));

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

    /// **The acceptance for the `oci_subject` edge.** A failed subject edge
    /// takes the whole manifest PUT with it: no manifest artifact, no event
    /// on its stream, no edge — and a 500, not a 201 over a referrer that
    /// never recorded its claim.
    ///
    /// `oci_subject` targets the SUBJECT image's bytes, so this is not the
    /// referrer's own bookkeeping going missing — it is somebody else's
    /// bytes losing a claim. The storage GC deletes a CAS blob exactly when
    /// no `content_references` row targets its hash, and no sweep
    /// re-derives a tree edge (the refcount reconcile converges
    /// `primary_content` / `metadata_blob` from the artifact row, which
    /// records nothing about what a manifest references). A failed PUT is
    /// retriable; a committed referrer with no subject row was not
    /// repairable from the request path at all.
    #[test]
    fn put_with_failing_subject_edge_rolls_back_the_manifest() {
        let (status, subject_rows, manifest_present, event_batches) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);
            let manifest_hex = hex::encode(Sha256::digest(&body));

            // Baseline: the two seeded blobs each committed their own
            // `primary_content` edge through the ingest, so count the
            // batches already recorded rather than assuming zero.
            let batches_before = h.events.appended_batches().len();

            h.content_references.fail_next_insert_for_kind(
                "oci_subject",
                DomainError::Invariant("simulated oci_subject insert failure".into()),
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();

            let subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let manifest_present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            let event_batches = h.events.appended_batches().len() - batches_before;
            (status, subject_rows, manifest_present, event_batches)
        });
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed claim on the subject's bytes must fail the PUT"
        );
        assert_eq!(subject_rows, 0, "no oci_subject row landed");
        assert!(
            !manifest_present,
            "no manifest artifact may survive the rolled-back PUT"
        );
        assert_eq!(
            event_batches, 0,
            "no event may survive the rolled-back PUT — not even ArtifactIngested"
        );
    }

    /// The counter-assertion: on the happy path ONE lifecycle call carries
    /// the manifest artifact AND its whole claim set — its own content, its
    /// `oci_subject`, and its `oci_config` membership claim. Without it the
    /// rollback test above would pass equally against a PUT that recorded no
    /// edge at all.
    ///
    /// The `oci_config` claim riding the same call is the point of the
    /// membership-edge conversion: this used to be a second write issued
    /// after the transition returned.
    #[test]
    fn put_with_subject_commits_the_edge_with_the_manifest_transition() {
        run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);

            let manifest = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .expect("manifest minted");

            // The manifest's own transition — the last recorded one, after
            // the two seeded blobs' mints — carries its own content claim,
            // the subject claim and the config membership claim.
            let manifest_edges: Vec<(String, String)> = h
                .lifecycle
                .ingest_edge_kinds()
                .into_iter()
                .filter(|(id, _, _)| *id == manifest.id)
                .map(|(_, kind, target)| (kind, target))
                .collect();
            assert_eq!(
                manifest_edges,
                vec![
                    (
                        "primary_content".to_string(),
                        manifest.sha256_checksum.as_ref().to_owned()
                    ),
                    ("oci_subject".to_string(), subject_hash.as_ref().to_owned()),
                    ("oci_config".to_string(), config_hash.as_ref().to_owned()),
                ],
                "the manifest's claim on its own bytes, on its subject's and on its \
                 config blob's, in one call"
            );
            let carrying: Vec<_> = h
                .lifecycle
                .ingest_edges()
                .into_iter()
                .filter(|(id, _)| *id == manifest.id)
                .collect();
            assert_eq!(
                carrying.len(),
                1,
                "one transition carries the manifest's whole edge set"
            );
        });
    }

    /// **The acceptance for the single-image membership edges.** A failed
    /// `oci_layer` claim takes the whole manifest PUT with it: no manifest
    /// artifact, no event on its stream, and the `oci_config` claim the
    /// transition had already applied rolled back with it.
    ///
    /// These claim the CONFIG and LAYER blobs' bytes — other artifacts'
    /// content. The storage GC deletes a CAS blob exactly when no
    /// `content_references` row targets its hash, and no sweep re-derives a
    /// tree edge (the refcount reconcile converges `primary_content` /
    /// `metadata_blob` from the artifact row, which records nothing about
    /// what a manifest references). Before the conversion this was two
    /// post-ingest insert loops: a failure left a live, servable manifest
    /// whose layers were collectable and nothing in the request path could
    /// repair it. A failed PUT is retriable.
    #[test]
    fn put_with_failing_layer_edge_rolls_back_the_manifest() {
        let (status, config_rows, layer_rows, manifest_present, event_batches) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_hex = hex::encode(Sha256::digest(&body));

            // The two seeded blobs each committed their own
            // `primary_content` edge through the ingest, so count the
            // batches already recorded rather than assuming zero.
            let batches_before = h.events.appended_batches().len();

            // Target the LAYER claim, which the transition applies AFTER
            // the config claim — so this is about the rollback of an
            // earlier edge, not about a single-edge failure.
            h.content_references.fail_next_insert_for_kind(
                "oci_layer",
                DomainError::Invariant("simulated oci_layer insert failure".into()),
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();

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
            let manifest_present = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .is_some();
            let event_batches = h.events.appended_batches().len() - batches_before;
            (
                status,
                config_rows,
                layer_rows,
                manifest_present,
                event_batches,
            )
        });
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed claim on a layer's bytes must fail the PUT"
        );
        assert_eq!(layer_rows, 0, "no oci_layer row landed");
        assert_eq!(
            config_rows, 0,
            "the oci_config claim the transition applied first rolled back with it"
        );
        assert!(
            !manifest_present,
            "no manifest artifact may survive the rolled-back PUT"
        );
        assert_eq!(
            event_batches, 0,
            "no event may survive the rolled-back PUT — not even ArtifactIngested"
        );
    }

    /// **The acceptance for the image-index membership edges.** A failed
    /// `oci_index_member` claim takes the whole index PUT with it: no index
    /// artifact, no event on its stream, no row.
    ///
    /// An index's claim is on its CHILDREN's bytes, and a live index is the
    /// only thing keeping them out of the storage GC — the refcount query
    /// counts rows of every kind against a target hash.
    #[test]
    fn put_image_index_with_failing_member_edge_rolls_back_the_index() {
        let (status, member_rows, index_present, event_batches) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let media = "application/vnd.oci.image.index.v1+json";
            let body = build_index_json(std::slice::from_ref(&child), media);
            let index_hex = hex::encode(Sha256::digest(&body));

            let batches_before = h.events.appended_batches().len();
            h.content_references.fail_next_insert_for_kind(
                "oci_index_member",
                DomainError::Invariant("simulated oci_index_member insert failure".into()),
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(uri, body, media))
                .await
                .unwrap();
            let status = resp.status();

            let member_rows = h
                .content_references
                .find_by_target(repo_id, &child.hash, Some("oci_index_member"))
                .await
                .unwrap()
                .len();
            let index_present = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .is_some();
            let event_batches = h.events.appended_batches().len() - batches_before;
            (status, member_rows, index_present, event_batches)
        });
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed claim on a child manifest's bytes must fail the PUT"
        );
        assert_eq!(member_rows, 0, "no oci_index_member row landed");
        assert!(
            !index_present,
            "no index artifact may survive the rolled-back PUT"
        );
        assert_eq!(event_batches, 0, "no event may survive the rolled-back PUT");
    }

    /// The counter-assertion for the index case: ONE lifecycle call carries
    /// the index artifact AND an `oci_index_member` claim per declared
    /// child. Without it the rollback test above would pass equally against
    /// a PUT that claimed nothing.
    #[test]
    fn put_image_index_commits_member_claims_with_the_index_transition() {
        run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child_a =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let child_b =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"arm64-child-manifest");
            let media = "application/vnd.oci.image.index.v1+json";
            let body = build_index_json(&[child_a.clone(), child_b.clone()], media);
            let index_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(uri, body, media))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);

            let index = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .expect("index minted");

            let index_edges: Vec<(String, String)> = h
                .lifecycle
                .ingest_edge_kinds()
                .into_iter()
                .filter(|(id, _, _)| *id == index.id)
                .map(|(_, kind, target)| (kind, target))
                .collect();
            assert_eq!(
                index_edges,
                vec![
                    (
                        "primary_content".to_string(),
                        index.sha256_checksum.as_ref().to_owned()
                    ),
                    (
                        "oci_index_member".to_string(),
                        child_a.hash.as_ref().to_owned()
                    ),
                    (
                        "oci_index_member".to_string(),
                        child_b.hash.as_ref().to_owned()
                    ),
                ],
                "the index's claim on its own bytes and on both children's, in one call"
            );
            let carrying: Vec<_> = h
                .lifecycle
                .ingest_edges()
                .into_iter()
                .filter(|(id, _)| *id == index.id)
                .collect();
            assert_eq!(
                carrying.len(),
                1,
                "one transition carries the index's whole edge set"
            );
        });
    }

    /// The gate that makes claiming-before-resolving safe: a manifest whose
    /// layer the client has not pushed yet is still minted — unchanged
    /// contract, the retry-after-pushing path stays idempotent — and it
    /// carries NO membership claim.
    ///
    /// This is the pin on the ordering worry that previously kept these
    /// edges outside the transition. `oci_config` / `oci_layer` /
    /// `oci_index_member` are tree-edge kinds that the
    /// referenced-tree-descendant predicate counts, so a claim naming a
    /// blob the repository does not hold would hand that blob's own later
    /// ingest the zero-window quarantine carve-out on the strength of an
    /// edge written for content that did not exist. Resolving before the
    /// mint removes the possibility instead of mitigating it: there is no
    /// membership claim on this path to be wrong about. The `oci_subject`
    /// claim is deliberately NOT gated this way — a referrer for a subject
    /// this repository lacks is legitimate OCI Referrers usage and
    /// `oci_subject` is not on the descendant predicate.
    #[test]
    fn put_with_missing_blob_mints_the_manifest_with_no_membership_claims() {
        run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            // Never pushed — the layer the client still owes.
            let missing_hash: ContentHash = hex::encode(Sha256::digest(b"never-pushed-layer"))
                .parse()
                .unwrap();
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&missing_hash));
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            let manifest = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .expect("manifest must persist so client retry reconciles");

            let manifest_edges: Vec<(String, String)> = h
                .lifecycle
                .ingest_edge_kinds()
                .into_iter()
                .filter(|(id, _, _)| *id == manifest.id)
                .map(|(_, kind, target)| (kind, target))
                .collect();
            assert_eq!(
                manifest_edges,
                vec![(
                    "primary_content".to_string(),
                    manifest.sha256_checksum.as_ref().to_owned()
                )],
                "an unknown-blob manifest claims its own bytes and nothing else — no \
                 oci_config for the blob that DID resolve either, because the resolution \
                 as a whole was incomplete"
            );
            assert_eq!(
                h.content_references.entry_count(),
                // The manifest's own `primary_content` row and nothing
                // else. `seed_blob` inserts the config blob's artifact row
                // directly, so that blob never ran an ingest and has no row
                // of its own here.
                1,
                "no membership row exists anywhere for an unknown-blob manifest"
            );
        });
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
    ///
    /// **The readable-and-well-formed branch of the door.** The layer blob
    /// carries a genuine Sigstore-bundle shape, so the shape check passes and
    /// the narrow signature path still fires — the exemption is narrowed by
    /// the door, not broken by it. The bytes used to be an opaque
    /// `b"the-cosign-bundle-json"` placeholder, which is material no verifier
    /// in the system could read; a fixture standing on it was asserting an
    /// exemption for a push hort now refuses.
    #[test]
    fn put_pure_sigstore_bundle_referrer_is_not_quarantined_or_scanned() {
        let (status, scan_calls, oci_subject_rows, artifact_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
            let bundle_hash = seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &well_formed_bundle_bytes("the-signing-key"),
            );
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-signed-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[(SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash)],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
    ///
    /// Also pins that the signature-layer door runs strictly INSIDE the
    /// exemption and never widens it: this manifest's bundle layer carries
    /// `b"a-real-bundle"`, which is not a well-formed bundle, and the push is
    /// still accepted — because a mixed manifest is not a signature manifest
    /// at all, so the door never sees it and the generic scanned path owns
    /// the outcome.
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

    // ----------------------------------------------------------------
    // The door: a layer declared as signature material must BE that
    // material. Four branches, named explicitly on each test — bytes
    // readable and unparseable (refuse), bytes readable and well-formed
    // (accept, narrow path still fires), bytes unreadable from CAS
    // (accept, logged), and an unrecognised media type (never reaches
    // the door at all — the generic scanned path).
    // ----------------------------------------------------------------

    const COSIGN_SIMPLESIGNING_MEDIA_TYPE: &str =
        "application/vnd.dev.cosign.simplesigning.v1+json";

    /// Bytes that are **well-formed** as a Sigstore v0.3 bundle: the
    /// structural members the door requires, and nothing more.
    ///
    /// Deliberately not a *valid* signature. The door checks shape, never
    /// validity — a test that wired a real signature in here would be
    /// asserting the verify path's job on the push path, which is precisely
    /// the thing the door must not start doing. `hint` varies the bytes so
    /// two layers of one manifest get two different CAS hashes.
    fn well_formed_bundle_bytes(hint: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": { "publicKey": { "hint": hint } },
            "dsseEnvelope": {
                "payload": "e30=",
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": "AA==" } ],
            },
        }))
        .unwrap()
    }

    /// Bytes that are **well-formed** as a cosign `simplesigning` payload:
    /// the one field the keyed verifier binds. Same shape-not-validity rule
    /// as [`well_formed_bundle_bytes`] — the digest is not even required to
    /// name this push's subject, because a payload binding the wrong digest
    /// is readable material whose binding fails, which is a finding for the
    /// verify path and not a reason to refuse a push.
    fn well_formed_simplesigning_bytes(digest_hex: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": { "docker-reference": "example.com/app" },
                "image": { "docker-manifest-digest": format!("sha256:{digest_hex}") },
                "type": "cosign container image signature",
            },
            "optional": serde_json::Value::Null,
        }))
        .unwrap()
    }

    /// Read the `errors[0]` object out of an OCI error response body.
    async fn error_envelope(resp: Response) -> serde_json::Value {
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        parsed["errors"][0].clone()
    }

    /// **Bytes readable and unparseable → REFUSE** (keyless carriage).
    ///
    /// A manifest declaring two Sigstore-bundle layers, the first a genuine
    /// bundle and the second unparseable rubbish. The push is refused with
    /// 400 `MANIFEST_INVALID` naming the SECOND layer — so the check runs
    /// over every declared layer, not just the first — and nothing is
    /// committed: no manifest artifact, no scan, no `oci_subject` row.
    ///
    /// `MANIFEST_INVALID` rather than the neighbouring
    /// `MANIFEST_BLOB_UNKNOWN`: the blob is present and merely is not what
    /// it claims, which is the manifest being invalid rather than a
    /// reference being unsatisfiable. It is also the code this path already
    /// answers for "declared media type does not match manifest shape" one
    /// level up, in `check_declared_media_type_matches_shape`.
    #[test]
    fn put_signature_referrer_with_an_unparseable_bundle_layer_is_refused() {
        let (status, envelope, scan_calls, minted, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
            let good_hash = seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &well_formed_bundle_bytes("key-a"),
            );
            let junk_hash = seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                b"not a sigstore bundle at all",
            );
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-victim-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[
                    (SIGSTORE_BUNDLE_MEDIA_TYPE, &good_hash),
                    (SIGSTORE_BUNDLE_MEDIA_TYPE, &junk_hash),
                ],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/sha256.sig",
                    body,
                ))
                .await
                .unwrap();
            let status = resp.status();
            let envelope = error_envelope(resp).await;
            let minted = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .is_some();
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            (
                status,
                envelope,
                h.lifecycle.scan_enqueues().len(),
                minted,
                oci_subject_rows,
            )
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(envelope["code"], "MANIFEST_INVALID");
        assert_eq!(
            envelope["detail"]["layer_digest"],
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(b"not a sigstore bundle at all"))
            ),
            "the detail must name the offending layer digest — and it is the SECOND \
             layer, so the check covers every declared layer"
        );
        assert_eq!(envelope["detail"]["media_type"], SIGSTORE_BUNDLE_MEDIA_TYPE);
        assert!(
            !minted,
            "a refused push must leave no manifest artifact behind — the door runs \
             before the mint"
        );
        assert_eq!(
            scan_calls, 0,
            "nothing was ingested, so nothing was scanned"
        );
        assert_eq!(
            oci_subject_rows, 0,
            "no content-reference edge may survive a refused push"
        );
    }

    /// **Bytes readable and unparseable → REFUSE** (keyed carriage): the
    /// same rule for a `simplesigning` layer whose blob is not a
    /// simplesigning payload. The door's predicate here IS the keyed
    /// verifier's readability test (`simplesigning_subject_digest`), so it
    /// cannot refuse a payload that verifier could have read.
    #[test]
    fn put_signature_referrer_with_an_unparseable_simplesigning_layer_is_refused() {
        let (status, envelope, minted) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"keyed-config-bytes");
            let junk_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"{\"critical\":{}}");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"keyed-victim-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[(COSIGN_SIMPLESIGNING_MEDIA_TYPE, &junk_hash)],
                &subject_hash,
                COSIGN_SIMPLESIGNING_MEDIA_TYPE,
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/sha256.sig",
                    body,
                ))
                .await
                .unwrap();
            let status = resp.status();
            let envelope = error_envelope(resp).await;
            let minted = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .is_some();
            (status, envelope, minted)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(envelope["code"], "MANIFEST_INVALID");
        assert_eq!(
            envelope["detail"]["media_type"],
            COSIGN_SIMPLESIGNING_MEDIA_TYPE
        );
        assert!(!minted, "a refused push leaves no manifest artifact behind");
    }

    /// **Bytes readable and well-formed → ACCEPT, and the narrow signature
    /// path still fires** (keyed carriage): the keyed counterpart of test
    /// (a). A genuine `simplesigning` payload is exempted exactly as before
    /// the door existed — no scan enqueued, status `None`.
    #[test]
    fn put_pure_simplesigning_referrer_with_a_real_payload_is_still_exempted() {
        let (status, scan_calls, artifact_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"keyed-config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-keyed-image");
            let payload_hash = seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &well_formed_simplesigning_bytes(subject_hash.as_ref()),
            );
            let body = build_referrer_manifest(
                &config_hash,
                &[(COSIGN_SIMPLESIGNING_MEDIA_TYPE, &payload_hash)],
                &subject_hash,
                COSIGN_SIMPLESIGNING_MEDIA_TYPE,
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/sha256.sig",
                    body,
                ))
                .await
                .unwrap();
            let status = resp.status();
            let artifact_status = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .map(|a| a.quarantine_status);
            (status, h.lifecycle.scan_enqueues().len(), artifact_status)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            scan_calls, 0,
            "a pure keyed simplesigning referrer whose payload IS a simplesigning payload \
             keeps the narrow path"
        );
        assert_eq!(artifact_status, Some(QuarantineStatus::None));
    }

    /// **Bytes unreadable from CAS → ACCEPT, logged.** Reference resolution
    /// establishes a same-repo, non-terminal **row** per layer; it does not
    /// establish that CAS holds the object. When the read behind a declared
    /// layer fails, the push is accepted and the reason is logged — refusing
    /// there would turn a storage fault into a client error the client cannot
    /// act on, and the complementary rule (unreadable material contributes
    /// nothing to a verdict) already covers the material itself.
    #[test]
    fn put_signature_referrer_with_unreadable_layer_bytes_is_accepted_and_logged() {
        let ((status, scan_calls), records) = capture_tracing(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let h = harness();
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                h.repositories.insert(repo);
                let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
                // A row, but no CAS object behind it.
                let bundle_hash = seed_blob_row_without_content(
                    &h.artifacts,
                    repo_id,
                    b"bundle-bytes-that-storage-lost",
                    QuarantineStatus::None,
                );
                let subject_hash =
                    seed_blob(&h.artifacts, &h.storage, repo_id, b"the-signed-image");
                let body = build_referrer_manifest(
                    &config_hash,
                    &[(SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash)],
                    &subject_hash,
                    SIGSTORE_BUNDLE_MEDIA_TYPE,
                );

                let router = router().with_state(h.ctx.clone());
                let resp = router
                    .oneshot(put_request(
                        "/v2/myrepo/library/nginx/manifests/sha256.sig",
                        body,
                    ))
                    .await
                    .unwrap();
                (resp.status(), h.lifecycle.scan_enqueues().len())
            })
        });
        assert_eq!(
            status,
            StatusCode::CREATED,
            "an unreadable layer must NOT refuse the push"
        );
        assert_eq!(
            scan_calls, 0,
            "the exemption still applies — the door asserts nothing about material it \
             could not read"
        );
        let warned = events_at(
            &records,
            tracing::Level::WARN,
            "hort_http_oci::manifests_write",
        )
        .iter()
        .any(|e| {
            e.fields.contains("could not be read at push time")
                && e.fields.contains("the push is accepted")
        });
        assert!(
            warned,
            "the accepted-unreadable branch must say so in the log; captured: {records:?}"
        );
    }

    /// **An unrecognised layer media type is NOT refused** — the forward
    /// compatibility the whole shape rests on. A future bundle version
    /// carrying a new media type fails both purity predicates, so such a
    /// manifest is not a signature manifest at all: it takes the generic
    /// ingest path and IS scanned. Its layer bytes are rubbish here and that
    /// changes nothing, because the door is never consulted for a media type
    /// it does not recognise.
    #[test]
    fn put_referrer_with_a_future_bundle_media_type_is_not_refused() {
        let (status, scan_calls) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"future-config");
            let blob_hash = seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                b"a v0.4 bundle this build cannot parse",
            );
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"future-image");
            let future_media_type = "application/vnd.dev.sigstore.bundle.v0.4+json";
            let body = build_referrer_manifest(
                &config_hash,
                &[(future_media_type, &blob_hash)],
                &subject_hash,
                future_media_type,
            );

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/sha256.sig",
                    body,
                ))
                .await
                .unwrap();
            (resp.status(), h.lifecycle.scan_enqueues().len())
        });
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a future bundle media type must not be refused — it is simply not treated \
             as a signature"
        );
        assert_eq!(
            scan_calls, 1,
            "and because it is not treated as a signature it takes the generic scanned path"
        );
    }

    /// The door is gated on a COMPLETE reference resolution, so a signature
    /// manifest with a layer this repository does not hold keeps its
    /// established answer — the post-mint 400 `MANIFEST_BLOB_UNKNOWN` — and
    /// does not acquire a second one. There are no bytes of ours behind that
    /// layer to parse, so there is nothing for the door to say.
    #[test]
    fn put_signature_referrer_with_an_unresolvable_layer_keeps_the_blob_unknown_answer() {
        let (status, envelope) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-signed-image");
            // Never seeded at all: no row, no CAS object.
            let absent_hash: ContentHash = hex::encode(Sha256::digest(b"never-pushed-bundle"))
                .parse()
                .unwrap();
            let body = build_referrer_manifest(
                &config_hash,
                &[(SIGSTORE_BUNDLE_MEDIA_TYPE, &absent_hash)],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/sha256.sig",
                    body,
                ))
                .await
                .unwrap();
            let status = resp.status();
            (status, error_envelope(resp).await)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            envelope["code"], "MANIFEST_BLOB_UNKNOWN",
            "an unresolvable layer is still answered as an unsatisfiable reference, not \
             as a misdeclared shape"
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
            let manifest_hex = hex::encode(Sha256::digest(&body_bytes));

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
            let missing_hex = hex::encode(Sha256::digest(missing_content));
            let missing_hash: ContentHash = missing_hex.parse().unwrap();
            let body = build_manifest_json(&config_hash, &[missing_hash]);
            let manifest_hex = hex::encode(Sha256::digest(&body));

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

    // -------------------- PUT — terminal reference --------------------
    //
    // A referenced blob / child whose same-repo row exists but is in a
    // terminal quarantine state (`Rejected` / `ScanIndeterminate`) is not
    // a satisfied reference: the blob GET refuses that exact row (404
    // `BLOB_UNKNOWN` / 503), so accepting the manifest is how a push
    // reports success and the pull then answers `not found` on a layer.
    // Such a reference joins the same `missing` list an absent row does —
    // one envelope, same opacity, same post-mint answer.

    /// Which reference of the pushed document carries the seeded status.
    #[derive(Clone, Copy, Debug)]
    enum SeededRole {
        Config,
        Layer,
        IndexChild,
    }

    /// Outcome of a push whose `role` reference resolves to a row in the
    /// seeded status: the response status + body, the number of group
    /// commits, and whether the pushed document itself was committed.
    struct PushOutcome {
        status: StatusCode,
        body: Vec<u8>,
        group_calls: usize,
        document_committed: bool,
    }

    /// Push a document one of whose references resolves to an existing
    /// same-repo row in `status`. Every other reference is seeded
    /// `QuarantineStatus::None` (plainly deliverable), so the only thing
    /// under test is the seeded row's state.
    fn push_with_referenced_status(role: SeededRole, status: QuarantineStatus) -> PushOutcome {
        run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let (body, content_type) = match role {
                SeededRole::Config => {
                    let config = seed_blob_with_status(
                        &h.artifacts,
                        &h.storage,
                        repo_id,
                        b"config-bytes",
                        status,
                    );
                    let layer = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
                    (
                        build_manifest_json(&config, &[layer]),
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                }
                SeededRole::Layer => {
                    let config = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
                    let layer = seed_blob_with_status(
                        &h.artifacts,
                        &h.storage,
                        repo_id,
                        b"layer-bytes",
                        status,
                    );
                    (
                        build_manifest_json(&config, &[layer]),
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                }
                SeededRole::IndexChild => {
                    let present =
                        seed_index_child(&h.artifacts, &h.storage, repo_id, b"present-child");
                    let seeded = SeededIndexChild {
                        hash: seed_blob_with_status(
                            &h.artifacts,
                            &h.storage,
                            repo_id,
                            b"seeded-child",
                            status,
                        ),
                        size: b"seeded-child".len() as i64,
                    };
                    (
                        build_index_json(
                            &[present, seeded],
                            "application/vnd.oci.image.index.v1+json",
                        ),
                        "application/vnd.oci.image.index.v1+json",
                    )
                }
            };
            let document_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(put_index_request(uri, body, content_type))
                .await
                .unwrap();
            let status_code = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let document_committed = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{document_hex}"))
                .await
                .unwrap()
                .is_some();
            PushOutcome {
                status: status_code,
                body,
                group_calls: h.group_lifecycle.commit_call_count(),
                document_committed,
            }
        })
    }

    /// The whole refusal shape for a terminal reference: 400
    /// `MANIFEST_BLOB_UNKNOWN`, exactly one digest echoed in
    /// `detail.blobs`, no "why" anywhere in the envelope (the client is
    /// never told the reference was terminal — the diagnosis is the
    /// server-side log line), the document still committed, and no group.
    fn assert_terminal_reference_refusal(out: &PushOutcome, case: &str) {
        assert_eq!(
            out.status,
            StatusCode::BAD_REQUEST,
            "{case}: a terminal reference must refuse the push: body = {}",
            String::from_utf8_lossy(&out.body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN",
            "{case}: must reuse the existing missing-reference envelope"
        );
        let blobs = parsed["errors"][0]["detail"]["blobs"].as_array().unwrap();
        assert_eq!(
            blobs.len(),
            1,
            "{case}: exactly the one unresolvable reference is echoed"
        );
        assert!(
            blobs[0].as_str().unwrap().starts_with("sha256:"),
            "{case}: blobs detail must echo the raw sha256:<hex> shape"
        );
        let wire = String::from_utf8_lossy(&out.body).to_lowercase();
        for leak in ["reject", "indeterminate", "quarantin", "terminal"] {
            assert!(
                !wire.contains(leak),
                "{case}: the envelope must not disclose WHY the reference failed \
                 (found {leak:?} in {wire})"
            );
        }
        assert!(
            out.document_committed,
            "{case}: the post-mint answer is unchanged — the document stays committed"
        );
        assert_eq!(
            out.group_calls, 0,
            "{case}: no group attachment on the unresolvable-reference path"
        );
    }

    #[test]
    fn put_with_rejected_layer_returns_400_manifest_blob_unknown() {
        let out = push_with_referenced_status(SeededRole::Layer, QuarantineStatus::Rejected);
        assert_terminal_reference_refusal(&out, "rejected layer");
    }

    #[test]
    fn put_with_scan_indeterminate_layer_returns_400_manifest_blob_unknown() {
        let out =
            push_with_referenced_status(SeededRole::Layer, QuarantineStatus::ScanIndeterminate);
        assert_terminal_reference_refusal(&out, "scan-indeterminate layer");
    }

    /// The config blob is caught too, not only a layer — it is resolved
    /// through the same loop and the pull reads it through the same blob
    /// handler.
    #[test]
    fn put_with_rejected_config_returns_400_manifest_blob_unknown() {
        let out = push_with_referenced_status(SeededRole::Config, QuarantineStatus::Rejected);
        assert_terminal_reference_refusal(&out, "rejected config");
    }

    #[test]
    fn put_with_scan_indeterminate_config_returns_400_manifest_blob_unknown() {
        let out =
            push_with_referenced_status(SeededRole::Config, QuarantineStatus::ScanIndeterminate);
        assert_terminal_reference_refusal(&out, "scan-indeterminate config");
    }

    /// An index child is caught too. It is resolved for existence only
    /// (never attached as a group member), which is exactly why the
    /// status read has to happen in the resolution loop rather than in
    /// the attachment step.
    #[test]
    fn put_image_index_with_rejected_child_returns_400_manifest_blob_unknown() {
        let out = push_with_referenced_status(SeededRole::IndexChild, QuarantineStatus::Rejected);
        assert_terminal_reference_refusal(&out, "rejected index child");
    }

    #[test]
    fn put_image_index_with_scan_indeterminate_child_returns_400_manifest_blob_unknown() {
        let out = push_with_referenced_status(
            SeededRole::IndexChild,
            QuarantineStatus::ScanIndeterminate,
        );
        assert_terminal_reference_refusal(&out, "scan-indeterminate index child");
    }

    /// `Quarantined` is NOT terminal and must keep resolving as present.
    /// Hort quarantines at ingest and the manifest PUT follows seconds
    /// later, so a hold-sensitive reference check would refuse
    /// essentially every push.
    #[test]
    fn put_with_quarantined_layer_still_succeeds() {
        for role in [SeededRole::Layer, SeededRole::Config] {
            let out = push_with_referenced_status(role, QuarantineStatus::Quarantined);
            assert_eq!(
                out.status,
                StatusCode::CREATED,
                "a held ({role:?}) reference is an outstanding evaluation, not a verdict: \
                 body = {}",
                String::from_utf8_lossy(&out.body)
            );
        }
    }

    /// Item 7's named case: **absence is not a hold.** A referenced blob
    /// with no catalog row at all is "not local yet" — the ordinary state
    /// of a cold pull-through reference — and must keep answering exactly
    /// as it did before the status read existed: 400
    /// `MANIFEST_BLOB_UNKNOWN`, the document committed so the retry after
    /// pushing the blob reconciles, no group. This is the one place where
    /// the fail-closed reflex gives the wrong answer; folding absence into
    /// the terminal arm would break every cold pull-through.
    #[test]
    fn a_referenced_blob_with_no_row_is_not_local_yet_not_terminal() {
        let (status, body, group_calls, manifest_committed, row_absent) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            // Never seeded in ANY state — no row, so there is no status
            // for the terminality predicate to read.
            let absent_hex = hex::encode(Sha256::digest(b"never-pushed-layer"));
            let absent: ContentHash = absent_hex.parse().unwrap();
            let body = build_manifest_json(&config, std::slice::from_ref(&absent));
            let manifest_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let manifest_committed = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{manifest_hex}"))
                .await
                .unwrap()
                .is_some();
            let row_absent = h
                .artifacts
                .find_by_repo_and_checksum(repo_id, &absent)
                .await
                .unwrap()
                .is_none();
            (
                status,
                rbody,
                h.group_lifecycle.commit_call_count(),
                manifest_committed,
                row_absent,
            )
        });
        assert!(
            row_absent,
            "fixture integrity: the reference under test must have no catalog row"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["blobs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            manifest_committed,
            "an absent reference is the retry case: the manifest must stay committed so the \
             client's push-the-blob-then-retry path reconciles"
        );
        assert_eq!(group_calls, 0);
    }

    /// A layer held with **no self-resolving deadline** — the
    /// `provenance_mode: required` hold-until-signed state (ADR 0039 D4)
    /// — still pushes.
    ///
    /// This is the regression the status-only predicate exists to
    /// prevent. ADR 0039 §10 exists so a held subject can be read and
    /// signed; a client re-pushing that manifest after the observation
    /// window elapsed would be refused if the reference check keyed on
    /// `provenance_hold_indefinite`, which breaks sign-after-push. Widen
    /// `QuarantineStatus::is_terminal`'s call site to consult that
    /// hydrated flag and this test goes red — that inversion is what it
    /// is here to catch.
    ///
    /// The hold is built through the real read path, not stamped on the
    /// row: `hydrate_quarantine_deadline` recomputes the transient pair
    /// on every read, so the fixture needs a `Required` policy, an anchor
    /// already past the window, no `ProvenanceVerified` on the stream,
    /// and the opt-in hydration wiring.
    #[test]
    fn put_with_indefinitely_held_layer_still_succeeds() {
        let (status, body, hold_indefinite) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            crate::test_authz::seed_required_provenance_policy(
                &h.policy_projections,
                repo_id,
                /* window */ 1,
            );

            let config = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer = seed_indefinitely_held_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                b"held-until-signed-layer",
            );
            let body = build_manifest_json(&config, std::slice::from_ref(&layer));

            // Opt the read-path hydration into the real policy +
            // clearance resolution, so the layer the handler resolves
            // genuinely carries `provenance_hold_indefinite = true`
            // rather than the mapper's `false` default.
            let ctx = hort_http_core::test_support::with_provenance_hold_hydration(&h.ctx);
            // Fixture integrity: assert the flag the predicate must NOT
            // consult is actually set on the row the handler will see. A
            // harness that quietly hydrates `false` would make this test
            // pass for the wrong reason.
            let hold_indefinite = ctx
                .artifact_use_case
                .find_in_repo_by_hash(repo_id, &layer)
                .await
                .unwrap()
                .expect("seeded layer")
                .provenance_hold_indefinite;

            let router = router().with_state(ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, rbody, hold_indefinite)
        });
        assert!(
            hold_indefinite,
            "fixture integrity: the layer must hydrate as an indefinite provenance hold, \
             otherwise this test cannot catch a predicate that consults the flag"
        );
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a hold with no self-resolving deadline is still an outstanding evaluation; \
             refusing it here breaks ADR 0039 §10 sign-after-push: body = {}",
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
    fn build_index_json(children: &[SeededIndexChild], media_type: &str) -> Vec<u8> {
        let manifests: Vec<serde_json::Value> = children
            .iter()
            .map(|c| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", c.hash.as_ref()),
                    "size": c.size,
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

    /// Build an index declaring exactly `manifests`, verbatim — for the cases
    /// whose subject IS a descriptor [`build_index_json`] cannot express: a
    /// child with no `digest`, a digest hort cannot address, a `size` that
    /// disagrees with the stored child.
    fn build_index_json_from_descriptors(
        manifests: &[serde_json::Value],
        media_type: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media_type,
            "manifests": manifests,
        }))
        .unwrap()
    }

    /// A child descriptor in [`build_index_json_from_descriptors`] form whose
    /// `digest` and `size` both agree with a seeded row — the conformant
    /// baseline a one-bad-descriptor fixture puts its good siblings in.
    fn good_child_descriptor(child: &SeededIndexChild) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", child.hash.as_ref()),
            "size": child.size,
            "platform": { "architecture": "amd64", "os": "linux" },
        })
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
            let child_a =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let child_b =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"arm64-child-manifest");
            let body = build_index_json(
                &[child_a, child_b],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
            let child_a =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"amd64-child-manifest");
            let child_b =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"arm64-child-manifest");
            let body = build_index_json(
                &[child_a.clone(), child_b.clone()],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
                .find_by_target(repo_id, &child_a.hash, Some("oci_index_member"))
                .await
                .unwrap();
            let rows_b = h
                .content_references
                .find_by_target(repo_id, &child_b.hash, Some("oci_index_member"))
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
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
            let child =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"child-manifest-bytes");
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
                .find_by_target(repo_id, &child.hash, Some("oci_config"))
                .await
                .unwrap();
            let layer_rows = h
                .content_references
                .find_by_target(repo_id, &child.hash, Some("oci_layer"))
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
    // `pull_membership_claims` direct unit tests. The pull-through call
    // sites (`manifests.rs`) are exercised at the HTTP level in that
    // module's own test suite; these tests pin the shared derivation's own
    // contract (what it derives, the fail-safe on a malformed body, and
    // that the BODY decides index-versus-image) directly.
    //
    // The function this replaced wrote the rows itself, and these tests
    // read them back out of the mock index. There is nothing to read back
    // now: the derivation takes no port, no `AppContext` and no artifact
    // id, so it CANNOT write — the claims it returns are carried into the
    // referrer's own ingest transition by the caller. "No edge is written
    // beside the transition here" is therefore a property of the
    // signature, not an assertion a future change could quietly falsify.
    // ---------------------------------------------------------------------

    /// Flattened `(kind, target_hex)` for a claim set, in derivation
    /// order — the shape these assertions want, since the per-claim
    /// `metadata` is pinned separately below.
    fn claim_kinds(claims: &[ContentReferenceClaim]) -> Vec<(String, String)> {
        claims
            .iter()
            .map(|c| (c.kind.clone(), c.target_content_hash.as_ref().to_owned()))
            .collect()
    }

    /// A single-image body yields exactly one `oci_config` claim and one
    /// `oci_layer` claim per layer, in manifest order, each targeting the
    /// blob's own content hash.
    #[test]
    fn pull_membership_claims_derives_config_and_layer_claims() {
        let config_hash: ContentHash = hex::encode(Sha256::digest(b"pull-config")).parse().unwrap();
        let layer_hash: ContentHash = hex::encode(Sha256::digest(b"pull-layer")).parse().unwrap();
        let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
        let media_type = "application/vnd.oci.image.manifest.v1+json";

        let claims =
            pull_membership_claims(Uuid::new_v4(), &compute_sha256(&body), media_type, &body);

        assert_eq!(
            claim_kinds(&claims),
            vec![
                ("oci_config".to_string(), config_hash.as_ref().to_owned()),
                ("oci_layer".to_string(), layer_hash.as_ref().to_owned()),
            ],
            "config first, then layers in manifest order"
        );
        assert_eq!(
            claims[0].metadata["digest"],
            format!("sha256:{}", config_hash.as_ref()),
            "the claim metadata echoes the raw digest form the body declared"
        );
        assert_eq!(claims[0].metadata["media_type"], media_type);
        assert_eq!(
            claims[1].metadata["digest"],
            format!("sha256:{}", layer_hash.as_ref())
        );
    }

    /// A body that fails to parse — malformed JSON, or a body neither
    /// `parse_manifest_blobs` nor `parse_index_children_for_admission` can
    /// enumerate —
    /// yields an EMPTY claim set rather than an error. The bytes matched
    /// the digest the upstream declared, so the manifest is legitimately
    /// servable and is minted with its own `primary_content` edge and no
    /// membership edges; refusing the pull over a projection hort cannot
    /// derive would be the wrong trade. Mirrors
    /// `oci_index_child_ingest::derive_claims`.
    #[test]
    fn pull_membership_claims_malformed_body_yields_no_claims() {
        let body = b"this is not json";
        let claims = pull_membership_claims(
            Uuid::new_v4(),
            &compute_sha256(body),
            "application/vnd.oci.image.manifest.v1+json",
            body,
        );
        assert!(
            claims.is_empty(),
            "a malformed body derives nothing, and derives it without failing"
        );
    }

    /// An upstream serving a structurally-index body under a SINGLE-IMAGE
    /// `Content-Type` still yields `oci_index_member` claims: the claim
    /// derivation, the eager child-ingest enqueue and the child-ingest
    /// handler all decide on the body, so the feature has exactly one answer
    /// to index-versus-image. Deciding on the header here would ingest the
    /// children while never claiming the index's membership, and digest
    /// verification cannot catch that — the bytes match, the header lies.
    #[test]
    fn pull_membership_claims_index_body_under_image_media_type_yields_member_claims() {
        // Nothing is seeded on the pull-through path: it registers edges by
        // digest with no existence check, so the declared size has nothing to
        // be held against here. It still states the truth about the bytes.
        let child = SeededIndexChild {
            hash: hex::encode(Sha256::digest(b"pull-child")).parse().unwrap(),
            size: b"pull-child".len() as i64,
        };
        let body = build_index_json(
            std::slice::from_ref(&child),
            "application/vnd.oci.image.index.v1+json",
        );

        let claims = pull_membership_claims(
            Uuid::new_v4(),
            &compute_sha256(&body),
            // The lie: an index body announced as a single-image manifest.
            "application/vnd.oci.image.manifest.v1+json",
            &body,
        );

        assert_eq!(
            claim_kinds(&claims),
            vec![(
                "oci_index_member".to_string(),
                child.hash.as_ref().to_owned()
            )],
            "the body's shape decides: an index body yields oci_index_member claims \
             whatever Content-Type the upstream declared, and nothing else — the \
             single-image parse must not have run"
        );
        assert_eq!(
            claims[0].metadata["child_digest"],
            format!("sha256:{}", child.hash.as_ref()),
            "an index member's metadata key is `child_digest`, not `digest`"
        );
    }

    /// The mirror case: a single-image body announced as an index yields the
    /// `oci_config`/`oci_layer` claims the bytes actually call for, not the
    /// zero child claims the declared type would have produced.
    #[test]
    fn pull_membership_claims_image_body_under_index_media_type_yields_blob_claims() {
        let config_hash: ContentHash = hex::encode(Sha256::digest(b"pull-config")).parse().unwrap();
        let layer_hash: ContentHash = hex::encode(Sha256::digest(b"pull-layer")).parse().unwrap();
        let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

        let claims = pull_membership_claims(
            Uuid::new_v4(),
            &compute_sha256(&body),
            "application/vnd.oci.image.index.v1+json",
            &body,
        );

        assert_eq!(
            claim_kinds(&claims),
            vec![
                ("oci_config".to_string(), config_hash.as_ref().to_owned()),
                ("oci_layer".to_string(), layer_hash.as_ref().to_owned()),
            ]
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
            let child =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"child-manifest-bytes");
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
            let manifest_hex = hex::encode(Sha256::digest(&single_image_body));
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
            let child = seed_index_child(&h.artifacts, &h.storage, repo_id, b"a-child-manifest");
            // Index bytes (non-empty manifests[]) ...
            let index_body = build_index_json(
                std::slice::from_ref(&child),
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = hex::encode(Sha256::digest(&index_body));

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
            let child = seed_index_child(&h.artifacts, &h.storage, repo_id, b"child-match");
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
            let present = seed_index_child(&h.artifacts, &h.storage, repo_id, b"present-child");
            let missing_hex = hex::encode(Sha256::digest(b"never-pushed-child"));
            let missing = SeededIndexChild {
                hash: missing_hex.parse().unwrap(),
                size: b"never-pushed-child".len() as i64,
            };
            let body = build_index_json(
                &[present, missing],
                "application/vnd.oci.image.index.v1+json",
            );
            let manifest_hex = hex::encode(Sha256::digest(&body));

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
            let child =
                seed_index_child(&h.artifacts, &h.storage, repo_b_id, b"child-in-other-repo");
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
    /// `MANIFEST_INVALID` (the domain `index_child_descriptors` returns
    /// `Validation`; the handler maps it to the same shape the
    /// single-image over-cap rejection produces). No group is created.
    ///
    /// **And nothing is minted.** The reference parse moved ahead of the
    /// ingest — it has to, because the membership claims it produces must
    /// ride the mint's transaction — so a body this parse rejects no longer
    /// leaves an artifact row behind. That is a deliberate change from the
    /// previous ordering, in which the parse ran post-ingest and the
    /// docstring here recorded the manifest as still committed; the client
    /// sees the same 400 either way. It does not touch the *unknown-blob*
    /// contract, which is a resolution outcome rather than a parse failure
    /// and still mints (see
    /// `put_with_missing_blob_mints_the_manifest_with_no_membership_claims`).
    #[test]
    fn put_image_index_over_child_cap_returns_400_manifest_invalid() {
        // MAX_INDEX_CHILDREN in hort-domain is 1024; declare 1025 children
        // (synthetic sha256 digests — never resolved, the cap rejects
        // before resolution).
        let over_cap = 1025usize;
        let (status, body, group_calls, index_present) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
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
            let index_hex = hex::encode(Sha256::digest(&body));

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
            let index_present = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .is_some();
            (status, rbody, group_calls, index_present)
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
        assert!(
            !index_present,
            "a body the reference parse rejects is not minted: the parse runs ahead of \
             the ingest so its claims can ride the transition"
        );
    }

    // -------------------- PUT — an index child is a descriptor --------------
    //
    // `digest` is a REQUIRED property of an OCI Content Descriptor, so a
    // `manifests[]` entry with no usable digest is not a child the registry
    // failed to resolve — it is an index that does not say what it claims to
    // say. Admission refuses it. Which refusal depends on the descriptor, and
    // the image spec draws the line: a digest complying with the digest
    // grammar but naming an unrecognised algorithm "SHOULD pass validation",
    // so `sha512:<hex>` is a VALID index hort cannot store (`UNSUPPORTED`),
    // while a digest matching no grammar, or an absent one, is a malformed
    // manifest (`MANIFEST_INVALID`).
    //
    // Before this, all three were dropped inside the domain projection's
    // `filter_map`: the index was admitted `201` carrying one `oci_index_member`
    // edge fewer than it declared, and nothing said so.

    /// Outcome of a PUT of an index carrying `manifests`, verbatim.
    struct IndexRefusal {
        status: StatusCode,
        body: Vec<u8>,
        index_minted: bool,
        member_edges: usize,
    }

    /// PUT an index declaring exactly `manifests` alongside one good child,
    /// and report what came back and what it left behind.
    ///
    /// The good sibling is the point: a refusal has to be the refusal of the
    /// *index*, not an empty enumeration. Before the correction the sibling's
    /// edge was written and the index was `201` — the bad descriptor simply
    /// was not there.
    fn put_index_with_descriptors(
        extra: impl Fn(&SeededIndexChild) -> Vec<serde_json::Value>,
    ) -> IndexRefusal {
        run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let good = seed_index_child(&h.artifacts, &h.storage, repo_id, b"good-child-manifest");
            let mut manifests = vec![good_child_descriptor(&good)];
            manifests.extend(extra(&good));
            let body = build_index_json_from_descriptors(
                &manifests,
                "application/vnd.oci.image.index.v1+json",
            );
            let index_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let index_minted = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .is_some();
            let member_edges = h
                .content_references
                .find_by_target(repo_id, &good.hash, Some("oci_index_member"))
                .await
                .unwrap()
                .len();
            IndexRefusal {
                status,
                body,
                index_minted,
                member_edges,
            }
        })
    }

    /// The wire envelope's `code`, for an assertion that names the spec code
    /// rather than a message.
    fn envelope_code(body: &[u8]) -> String {
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        parsed["errors"][0]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn a_body_that_cannot_project_as_an_index_never_reaches_the_child_parse() {
        // `parse_index_children_for_admission` interpolates the domain error
        // into `detail.reason` for a `Validation`, and one of the two
        // `Validation` shapes carries a serde message ABOUT the body — which
        // would be declarant content in a response body if it could get here.
        // It cannot, and this test is why: the index branch is only entered
        // when the declared media type agrees with `is_image_index(body)`, and
        // `is_image_index` is the same `from_slice::<OciImageIndex>` over the
        // same bytes. A body whose projection fails makes that probe `false`,
        // so `check_declared_media_type_matches_shape` refuses first with its
        // own envelope, which names only the media type the client sent in a
        // header and hort's own `shape_is_index` verdict.
        //
        // That leaves exactly one reachable `Validation` behind the
        // interpolation — the over-cap refusal, whose message is hort's own
        // counts (asserted below). Reorder these two checks and the serde
        // message becomes reflectable; that is what this pins.
        for body in [
            br#"{"schemaVersion":2,"manifests":"CANARY-abc123"}"#.to_vec(),
            br#"{"schemaVersion":2,"manifests":[{"digest":"CANARY-abc123"}],"#.to_vec(),
            br#"{"schemaVersion":2,"manifests":[{"digest":42}]}"#.to_vec(),
        ] {
            let (status, rbody) = run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = router().with_state(h.ctx.clone());
                let resp = router
                    .oneshot(put_index_request(
                        "/v2/myrepo/library/nginx/manifests/v1",
                        body.clone(),
                        "application/vnd.oci.image.index.v1+json",
                    ))
                    .await
                    .unwrap();
                let st = resp.status();
                let b = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                (st, b)
            });
            let text = String::from_utf8_lossy(&rbody);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
            assert!(
                !text.contains("CANARY"),
                "a response reflected declarant manifest content: {text}"
            );
        }

        // The counter-half: the one `Validation` that IS reachable behind the
        // interpolation, carrying hort's own numbers and nothing of the body's.
        let over_cap = 1025usize;
        let (status, rbody) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let manifests: Vec<serde_json::Value> = (0..over_cap)
                .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}"), "size": 1 }))
                .collect();
            let body = build_index_json_from_descriptors(
                &manifests,
                "application/vnd.oci.image.index.v1+json",
            );
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let st = resp.status();
            let b = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (st, b)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
        let reason = parsed["errors"][0]["detail"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains("invalid image index") && reason.contains(&over_cap.to_string()),
            "the over-cap refusal reaches the interpolation and states hort's own \
             counts: {reason}"
        );
    }

    #[test]
    fn put_index_with_a_child_carrying_no_digest_is_refused_not_swept_up() {
        let out = put_index_with_descriptors(|_| {
            vec![serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 7,
                "platform": { "architecture": "arm64", "os": "linux" },
            })]
        });
        assert_eq!(out.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            envelope_code(&out.body),
            "MANIFEST_INVALID",
            "`digest` is a REQUIRED descriptor property, so its absence is a malformed \
             manifest"
        );
        assert!(
            !out.index_minted,
            "the parse runs ahead of the ingest: a refused index leaves no artifact row"
        );
        assert_eq!(
            out.member_edges, 0,
            "and no edge for the sibling either — this used to be a 201 carrying exactly \
             this one edge and claiming two children"
        );
    }

    #[test]
    fn put_index_with_a_malformed_child_digest_is_refused() {
        for bad in [
            "sha256:not-valid-hex",
            "sha256:dead",
            &format!("sha256:{}", "A".repeat(64)),
        ] {
            let out = put_index_with_descriptors(|_| {
                vec![serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": bad,
                    "size": 7,
                })]
            });
            assert_eq!(out.status, StatusCode::BAD_REQUEST, "digest {bad}");
            assert_eq!(
                envelope_code(&out.body),
                "MANIFEST_INVALID",
                "a `sha256:` body that is not 64 lowercase hex matches no digest hort can \
                 read: digest {bad}"
            );
            assert!(!out.index_minted, "digest {bad}");
            assert_eq!(out.member_edges, 0, "digest {bad}");
        }
    }

    #[test]
    fn put_index_with_an_unprefixed_child_digest_is_refused_as_manifest_invalid() {
        // No `<algorithm>:` at all — ungrammatical, so malformed rather than
        // unsupported. This is the half of the old `NotSha256` collapse that
        // must NOT answer `UNSUPPORTED`.
        let out = put_index_with_descriptors(|_| {
            vec![serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "a".repeat(64),
                "size": 7,
            })]
        });
        assert_eq!(out.status, StatusCode::BAD_REQUEST);
        assert_eq!(envelope_code(&out.body), "MANIFEST_INVALID");
        assert!(!out.index_minted);
    }

    #[test]
    fn put_index_with_a_sha512_child_is_refused_as_unsupported() {
        let out = put_index_with_descriptors(|_| {
            vec![serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha512:{}", "a".repeat(128)),
                "size": 7,
            })]
        });
        assert_eq!(out.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            envelope_code(&out.body),
            "UNSUPPORTED",
            "a `sha512:` child digest complies with the descriptor digest grammar, which \
             the image spec says SHOULD pass validation — the index is valid and hort \
             cannot store it, which is not the same answer as a malformed manifest"
        );
        assert!(!out.index_minted);
        assert_eq!(out.member_edges, 0);
    }

    #[test]
    fn the_unsupported_and_invalid_index_child_codes_are_not_the_same_value() {
        // Counter-assertion to the pair above: the whole point of the split is
        // that a client can tell "invalid index" from "valid index this
        // registry cannot store". A later refactor that routed both through
        // one envelope would leave both tests above green if they only
        // asserted 400, and green against each other if the two codes were
        // ever made equal.
        let unsupported = put_index_with_descriptors(|_| {
            vec![serde_json::json!({
                "digest": format!("sha512:{}", "a".repeat(128)),
                "size": 7,
            })]
        });
        let invalid = put_index_with_descriptors(|_| vec![serde_json::json!({ "size": 7 })]);
        let (a, b) = (
            envelope_code(&unsupported.body),
            envelope_code(&invalid.body),
        );
        assert_ne!(
            a, b,
            "the two refusals must stay distinguishable on the wire; both were {a}"
        );
        assert_eq!(
            (a.as_str(), b.as_str()),
            ("UNSUPPORTED", "MANIFEST_INVALID")
        );
    }

    #[test]
    fn an_index_child_refusal_never_echoes_the_declaration() {
        // Every refusal above is driven by declarant-controlled manifest JSON,
        // and the `detail` payload is the one place it could be reflected
        // back. The marker strings here are unique enough that a substring
        // search over the whole body is a real test of the contract.
        let algorithm = "sha512";
        let hex = "ab7dfa".repeat(10);
        for descriptor in [
            serde_json::json!({ "digest": format!("{algorithm}:{hex}"), "size": 7 }),
            serde_json::json!({ "digest": format!("sha256:{hex}"), "size": 7 }),
            serde_json::json!({ "digest": hex.clone(), "size": 7 }),
            serde_json::json!({ "mediaType": format!("application/{hex}"), "size": 7 }),
        ] {
            let out = put_index_with_descriptors(|_| vec![descriptor.clone()]);
            let body = String::from_utf8_lossy(&out.body);
            assert_eq!(out.status, StatusCode::BAD_REQUEST, "{descriptor}");
            assert!(
                !body.contains(&hex),
                "the refusal reflected the client-supplied digest body: {body}"
            );
            assert!(
                !body.contains(algorithm),
                "the refusal reflected the client-supplied algorithm: {body}"
            );
            // It still names WHICH child, by hort's own slot number, so a
            // publisher is not left searching a 50-platform index.
            assert!(
                body.contains("manifests[1]"),
                "the refusal must name the offending descriptor's slot: {body}"
            );
        }
    }

    // -------------------- PUT — existence is not identity -------------------
    //
    // A present child was confirmed and dropped, so the descriptor's own
    // statements about that content were never read. The descriptor spec:
    // "Before calculating the digest, the size of the content SHOULD be
    // verified to reduce hash collision space", and of `size`, "If the length
    // of the retrieved content does not match the specified length, the
    // content SHOULD NOT be trusted."

    #[test]
    fn put_index_whose_child_descriptor_lies_about_the_size_is_refused() {
        let out = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_index_child(&h.artifacts, &h.storage, repo_id, b"the-child-manifest");
            // Present, same repo, non-terminal — everything the existence
            // check asks. The descriptor declares a size the row does not have.
            let mut descriptor = good_child_descriptor(&child);
            descriptor["size"] = serde_json::json!(child.size + 1);
            let body = build_index_json_from_descriptors(
                &[descriptor],
                "application/vnd.oci.image.index.v1+json",
            );
            let index_hex = hex::encode(Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let index_minted = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .is_some();
            (status, rbody, index_minted, child.size)
        });
        let (status, body, index_minted, stored_size) = out;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a present child is not a satisfied reference if the descriptor disagrees \
             with it: body = {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(envelope_code(&body), "MANIFEST_INVALID");
        assert!(
            !index_minted,
            "the descriptor check runs in the pre-mint resolution, so nothing is left behind"
        );
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains(&(stored_size + 1).to_string()),
            "the declared size is declarant-supplied and must not be reflected: {text}"
        );
    }

    #[test]
    fn the_descriptor_check_is_not_gated_on_every_other_child_resolving() {
        // ORDER, which is what this issue is about. A missing reference is NOT
        // an error on this path — it is the `Missing` outcome, answered with
        // `MANIFEST_BLOB_UNKNOWN` AFTER the mint, because the client's
        // retry-after-pushing-the-blob has to be idempotent. A descriptor that
        // disagrees with a child the repository DOES hold is a different thing:
        // it is an invalid document, and it must be refused before the mint
        // even when a sibling has not arrived yet. Putting the size check
        // behind "did everything resolve" would let one un-pushed child carry
        // a lying descriptor past the gate on the same request.
        let (status, body, index_minted) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let present = seed_index_child(&h.artifacts, &h.storage, repo_id, b"present-child");
            let absent_hex = hex::encode(Sha256::digest(b"never-pushed-child"));
            let mut liar = good_child_descriptor(&present);
            liar["size"] = serde_json::json!(present.size + 1);
            let body = build_index_json_from_descriptors(
                &[
                    serde_json::json!({
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": format!("sha256:{absent_hex}"),
                        "size": 7,
                    }),
                    liar,
                ],
                "application/vnd.oci.image.index.v1+json",
            );
            let index_hex = hex::encode(Sha256::digest(&body));
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            let status = resp.status();
            let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let minted = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{index_hex}"))
                .await
                .unwrap()
                .is_some();
            (status, rbody, minted)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            envelope_code(&body),
            "MANIFEST_INVALID",
            "the invalid descriptor answers, not the unknown blob: body = {}",
            String::from_utf8_lossy(&body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["detail"]["descriptor"], "manifests[1]",
            "and it names the offending slot, not the absent sibling's"
        );
        assert!(
            !index_minted,
            "a MANIFEST_BLOB_UNKNOWN commits the manifest; this refusal must not — the \
             document is invalid, which is decided before the mint"
        );
    }

    #[test]
    fn put_index_whose_child_descriptor_agrees_on_the_size_is_admitted() {
        // The counterpart: the check refuses a disagreement and nothing else.
        // Without this, making the comparison always-fail would pass the test
        // above.
        let (status, child_size) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_index_child(&h.artifacts, &h.storage, repo_id, b"the-child-manifest");
            let body = build_index_json_from_descriptors(
                &[good_child_descriptor(&child)],
                "application/vnd.oci.image.index.v1+json",
            );
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap();
            (resp.status(), child.size)
        });
        assert!(child_size > 0, "the fixture must declare a real byte count");
        assert_eq!(status, StatusCode::CREATED);
    }

    #[test]
    fn put_index_whose_child_descriptor_omits_the_size_is_admitted() {
        // `size` is REQUIRED by the spec, so such an index is non-conformant —
        // but it declares nothing to disagree with, and refusing it would
        // reject indexes hort accepts today over a field this change does not
        // decide. Admitted, with the non-conformance logged.
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let child = seed_index_child(&h.artifacts, &h.storage, repo_id, b"the-child-manifest");
            let body = build_index_json_from_descriptors(
                &[serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", child.hash.as_ref()),
                })],
                "application/vnd.oci.image.index.v1+json",
            );
            let router = router().with_state(h.ctx.clone());
            router
                .oneshot(put_index_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body,
                    "application/vnd.oci.image.index.v1+json",
                ))
                .await
                .unwrap()
                .status()
        });
        assert_eq!(status, StatusCode::CREATED);
    }

    #[test]
    fn pull_membership_claims_skips_an_unaddressable_child_and_keeps_the_rest() {
        // The pull-through membership derivation is the other side of the
        // split: these bytes are already stored and digest-verified, so a
        // descriptor hort cannot address costs that child its edge and
        // nothing else. Refusing here would mint the manifest with NO
        // membership edges at all — the un-keepalived state the backfill
        // handler exists to repair.
        let good = SeededIndexChild {
            hash: hex::encode(Sha256::digest(b"upstream-child"))
                .parse()
                .unwrap(),
            size: b"upstream-child".len() as i64,
        };
        let media = "application/vnd.oci.image.index.v1+json";
        let body = build_index_json_from_descriptors(
            &[
                good_child_descriptor(&good),
                serde_json::json!({ "digest": format!("sha512:{}", "a".repeat(128)), "size": 7 }),
                serde_json::json!({ "size": 7 }),
            ],
            media,
        );

        let claims = pull_membership_claims(Uuid::new_v4(), &compute_sha256(&body), media, &body);

        assert_eq!(
            claim_kinds(&claims),
            vec![(
                "oci_index_member".to_string(),
                good.hash.as_ref().to_owned()
            )],
            "the addressable child keeps its edge; the two that name no CAS object get \
             none, and the pull is unaffected"
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
            let child =
                seed_index_child(&h.artifacts, &h.storage, repo_id, b"index-child-manifest");
            let subject = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-subject-image");
            // An index shape WITH a defensive `subject` and NO layers. The
            // child descriptor declares the stored child's real size: this
            // test is about ingest routing, and a descriptor disagreeing with
            // its child is refused before routing is reached.
            let index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [ good_child_descriptor(&child) ],
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
            let hex = hex::encode(Sha256::digest(content));
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

    /// The ORDERING invariant of the digest-DELETE path, driven from the
    /// failure side: when `ArtifactUseCase::delete` fails, the manifest is
    /// still live and servable, so every keepalive edge it owns must still
    /// be standing. Those edges (`oci_config` / `oci_layer`) are what hold
    /// the config and layer blobs against storage GC, and the
    /// refcount-reconcile sweep re-creates only the single-target
    /// `primary_content` / `metadata_blob` kinds — so an edge dropped here
    /// is dropped for good, and the blobs of a manifest every read path
    /// considers healthy become collectable.
    ///
    /// A success-path test cannot distinguish this: both orderings end with
    /// the artifact gone and the edges gone. Only the forced failure does.
    #[test]
    fn failed_digest_delete_leaves_every_keepalive_edge_standing() {
        let (status, manifest_still_live, config_rows, layer_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_hex = hex::encode(Sha256::digest(&body));
            let manifest_path = format!("manifests/sha256:{manifest_hex}");

            let router = router().with_state(h.ctx.clone());
            let put = router
                .clone()
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            assert_eq!(put.status(), StatusCode::CREATED, "PUT must seed the edges");

            // Force the lifecycle delete to fail. The mock leaves the row
            // in place, matching the adapter: the `deleted_at` write and
            // the `ArtifactDeleted` append commit together, so a failure
            // means the manifest never left service.
            h.artifacts.fail_next_delete(DomainError::Invariant(
                "injected artifact-delete failure".into(),
            ));

            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{manifest_hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();

            let manifest_still_live = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
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
            (status, manifest_still_live, config_rows, layer_rows)
        });

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed lifecycle delete must surface as 500, not a false 202"
        );
        assert!(
            manifest_still_live,
            "the failed delete must leave the manifest live — otherwise this test \
             is not exercising the state the ordering protects"
        );
        assert_eq!(
            config_rows, 1,
            "a live manifest must keep its oci_config keepalive edge; without it \
             the config blob is collectable while the manifest is still served"
        );
        assert_eq!(
            layer_rows, 1,
            "a live manifest must keep its oci_layer keepalive edge"
        );
    }

    /// The other half of the ordering: on the success path the edges ARE
    /// swept, per keepalive kind rather than by a bare row count. Pins that
    /// moving the sweep behind the lifecycle delete did not turn it into a
    /// no-op.
    #[test]
    fn successful_digest_delete_sweeps_the_keepalive_edges() {
        let (status, manifest_still_live, config_rows, layer_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_hex = hex::encode(Sha256::digest(&body));
            let manifest_path = format!("manifests/sha256:{manifest_hex}");

            let router = router().with_state(h.ctx.clone());
            let put = router
                .clone()
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            assert_eq!(put.status(), StatusCode::CREATED, "PUT must seed the edges");

            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{manifest_hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();

            let manifest_still_live = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
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
            (status, manifest_still_live, config_rows, layer_rows)
        });

        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            !manifest_still_live,
            "the manifest artifact must be deleted"
        );
        assert_eq!(config_rows, 0, "the oci_config edge must be swept");
        assert_eq!(layer_rows, 0, "the oci_layer edge must be swept");
    }

    /// The residual state the ordering deliberately accepts: the sweep runs
    /// on the committed-transition side, so a projection-write failure can
    /// no longer roll the delete back. The request still succeeds and the
    /// edges stand until the purge sweep clears them — answering 500 here
    /// would invite a retry of a delete that already happened.
    #[test]
    fn digest_delete_succeeds_when_the_edge_sweep_fails_after_the_commit() {
        let (status, manifest_still_live, config_rows, deletions) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let manifest_hex = hex::encode(Sha256::digest(&body));
            let manifest_path = format!("manifests/sha256:{manifest_hex}");

            let router = router().with_state(h.ctx.clone());
            let put = router
                .clone()
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();
            assert_eq!(put.status(), StatusCode::CREATED, "PUT must seed the edges");

            h.content_references
                .fail_next_delete(DomainError::Invariant("injected sweep failure".into()));

            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{manifest_hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();

            let manifest_still_live = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            let config_rows = h
                .content_references
                .find_by_target(repo_id, &config_hash, Some("oci_config"))
                .await
                .unwrap()
                .len();
            (
                status,
                manifest_still_live,
                config_rows,
                h.artifacts.deletions(),
            )
        });

        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "a failed projection write must not undo a committed delete"
        );
        assert!(
            !manifest_still_live,
            "the lifecycle delete ran first and committed"
        );
        assert_eq!(
            deletions.len(),
            1,
            "exactly one artifact delete reached the port"
        );
        assert_eq!(
            config_rows, 1,
            "the edge stands after a failed sweep — the purge transaction is \
             what clears it"
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
            let hex = hex::encode(Sha256::digest(content));
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
        let hex = hex::encode(Sha256::digest(content));
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
