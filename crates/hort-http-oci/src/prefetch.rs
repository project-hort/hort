//! OCI `OnDistTagMove` prefetch wiring (see `explanation/prefetch-pipeline.md` + ADR 0016).
//!
//! Joins npm + pypi + cargo on the Phase-1 prefetch surface — when a
//! tag manifest pull resolves a new upstream digest that differs from
//! hort's previously-held digest for that tag, fire the
//! [`PrefetchUseCase::plan`] with [`PrefetchTrigger::OnDistTagMove`] and
//! spawn background pull-throughs for the manifest's referenced blobs
//! (`config.digest` + `layers[*].digest`). The intent is to age the new
//! image's blobs through the quarantine window in parallel with the
//! ongoing client interactions, so by the time a client actually pulls
//! the new layer bytes the window has already closed (or is close to).
//!
//! # Load-bearing design constraints
//!
//! Two constraints shape this module and MUST NOT be relaxed without
//! revisiting the architecture decision:
//!
//! 1. **No silent substitution.** A quarantined-new OCI manifest is
//!    NEVER served as a stand-in for the previous tag target. The
//!    `503`-with-`Retry-After` response shape in
//!    [`crate::quarantine::check_quarantine`] is the contract. Prefetch
//!    here only shrinks the *exposure window* by warming the new image
//!    in the background; it does NOT defer the tag move. Deferred-move /
//!    `pending_target` designs are rejected — silent substitution on OCI
//!    tags breaks the exact-pointer semantics of OCI tags.
//!
//! 2. **`IndexMode::ReleasedOnly` does NOT apply to OCI.**
//!    An OCI tag is an exact pointer, not a range. Substituting a
//!    different (e.g. older) manifest for a tag pull is precisely the
//!    rejected behaviour from constraint #1. The
//!    [`tests::oci_manifest_serve_path_must_not_consult_index_mode`]
//!    test enforces this structurally: a grep over the OCI crate's
//!    sources MUST find zero `IndexMode` / `index_mode` references
//!    outside `prefetch_policy` / `RepositoryFormat`-shaped fixtures.
//!    See the inline guardrail comment at the bottom of this file.
//!
//! # Planner inputs for OCI
//!
//! The shared [`PrefetchUseCase::plan`] API takes
//! `(upstream_versions, held_status, ordering)` where
//! `VersionOrdering::compare` sorts version strings per format
//! (semver / PEP 440 / Maven). OCI tag targets are content digests —
//! NOT ordered. The design intent is "if the upstream digest differs
//! from hort's held digest for this tag, that IS a tag move; queue the
//! new manifest's blob set for prefetch."
//!
//! - **`upstream_versions = &[upstream_digest_str]`** — a single-element
//!   slice carrying the freshly-resolved `sha256:<hex>` digest. With
//!   one upstream entry there is at most one candidate; the planner's
//!   sort+truncate path is a no-op regardless of the ordering.
//! - **`held_status = &[]`** — the call site has already gated on
//!   "this is a tag move" (prior held digest differs from upstream).
//!   Passing an empty held set bypasses the planner's `already_held`
//!   and `not_newer` filters, which are version-range semantics that
//!   don't apply to OCI tags. The dedup of "we already have THIS
//!   manifest in CAS" is handled downstream by `PullDedup`
//!   inside the blob pull-through.
//! - **`ordering = &OciDigestOrdering`** — a degenerate "everything is
//!   equal" comparator. The planner never calls it in a load-bearing
//!   way under the single-upstream / empty-held shape — but a future
//!   refactor that supplies a populated `held_status` would activate
//!   the comparator, and the `Ordering::Equal`-always semantic
//!   documents that digest content-addressability has no natural
//!   ordering.

use std::cmp::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use hort_app::use_cases::index_serve_filter::VersionOrdering;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};
use hort_domain::types::ContentHash;
use hort_http_core::context::AppContext;

/// Degenerate [`VersionOrdering`] for OCI manifest digests.
///
/// OCI tags carry content-addressable digests (`sha256:<hex>`) which
/// have no natural total order — a "newer" digest is determined by
/// upstream's tag-pointer movement, not by any property of the digest
/// bytes. The planner's [`Ordering::Equal`]-always semantic is safe
/// for the single-upstream / empty-held call shape this module uses
/// (the comparator is never load-bearing in the planner's sort /
/// truncate / not_newer arms) and documents that any future refactor
/// supplying a populated held set MUST reconsider the call shape
/// rather than relying on a synthetic order over digest strings.
///
/// Lexical ordering would be actively wrong here — it would gate the
/// new upstream digest as `not_newer` whenever it sorted lexically
/// before the prior held digest. That is the bug `Ordering::Equal`
/// exists to prevent.
pub(crate) struct OciDigestOrdering;

impl VersionOrdering for OciDigestOrdering {
    fn compare(&self, _a: &str, _b: &str) -> Ordering {
        Ordering::Equal
    }
}

/// Best-effort `OnDistTagMove` prefetch trigger fired from the OCI
/// manifest tag-pull-through hot path.
///
/// Called by [`crate::manifests::try_upstream_manifest_pull_by_tag`]
/// AFTER a successful upstream manifest fetch, with:
///
/// - `upstream_digest` — the `sha256:<hex>` digest the upstream just
///   resolved for the tag.
/// - `prior_held_digest` — `Some(hash)` if hort already had a
///   `MutableRef` entry for `(repo, name, tag)` pointing at a
///   (potentially different) digest, `None` for first-time pulls.
/// - `manifest_bytes` — the bytes of the manifest the leader ingested.
///   Walked here to extract `config.digest` + `layers[*].digest` for
///   the spawned blob prefetches.
///
/// The trigger:
///
/// 1. Returns immediately if `repo.prefetch_policy.enabled` is false
///    (zero-cost for the steady-state opt-out repository).
/// 2. Returns immediately if `prior_held_digest == Some(upstream)` —
///    no tag move, nothing to prefetch.
/// 3. Calls [`crate::hort_app_prefetch::plan`] with `OnDistTagMove`.
///    The planner emits the `hort_prefetch_enqueued_total{trigger=
///    "on_dist_tag_move", repository=<key>}` counter when the plan is
///    non-empty (i.e. the operator has subscribed to the trigger).
/// 4. Parses the manifest body for blob digests and spawns one
///    [`crate::blobs::try_upstream_blob_pull`] task per blob. Each
///    spawn rides through [`hort_app::pull_dedup::PullDedup`]
///    in the existing blob-pull path, so a racing client pull for
///    the same blob collapses to a single upstream fetch.
///
/// The trigger NEVER blocks the manifest serve — the spawned tasks
/// run in the background. A trigger failure (planner disabled, blob
/// parse failure, pull error) is invisible to the client.
pub(crate) fn fire_prefetch_trigger_oci(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    tag: &str,
    upstream_digest: &ContentHash,
    prior_held_digest: Option<&ContentHash>,
    manifest_bytes: &Bytes,
) {
    // Cheap escape hatch — most repositories don't opt in. Mirrors
    // the cargo / npm / pypi trigger shape; the planner would emit
    // `skipped{reason=disabled}` regardless, but skipping the
    // upstream-digest comparison + manifest parse here is the
    // steady-state-cost optimisation those triggers also do.
    if !repo.prefetch_policy.enabled {
        return;
    }

    // Tag-move detection: if hort's prior held digest for this tag
    // matches the upstream digest, the tag did NOT move — no prefetch
    // is warranted (the blobs would be `already_held` anyway, and a
    // first-pull cascade has already happened). When `prior_held` is
    // `None`, treat this as a tag move (first ingest of the tag is
    // the analogue of "tag moved from no-digest to a-digest").
    if let Some(prior) = prior_held_digest {
        if prior.as_ref() == upstream_digest.as_ref() {
            return;
        }
    }

    // Build the single-element upstream version slice. Per the module
    // doc, the planner's call shape for OCI is one upstream + empty
    // held; the comparator (`OciDigestOrdering`) is never load-bearing.
    let upstream_digest_str = format!("sha256:{}", upstream_digest.as_ref());
    let upstream_refs: [&str; 1] = [&upstream_digest_str];

    let plan = ctx.prefetch_use_case.plan(
        repo,
        name,
        PrefetchTrigger::OnDistTagMove,
        &upstream_refs,
        // Empty held — the call-site gate above has already established
        // the "tag move" precondition. `PullDedup` is the canonical
        // de-duplication mechanism for the blob fetches the spawn loop
        // below kicks off; the planner's `already_held` is a
        // version-range optimisation that doesn't apply to OCI.
        &[],
        &OciDigestOrdering,
    );

    if plan.is_empty() {
        // Planner short-circuited (trigger not subscribed → the
        // planner already emitted `skipped{reason=trigger_not_enabled}`;
        // nothing further to do here).
        return;
    }

    // Parse the manifest body for blob references. A malformed or
    // unparseable manifest is non-fatal — log + skip the spawn. The
    // manifest has already been ingested at this call site, so a
    // parse failure here means the manifest is structurally unusual
    // (an OCI index without standard `config.digest`, a Helm chart
    // manifest, etc.) and prefetch is not the right tool for it.
    let blob_hashes = match parse_manifest_blob_digests(manifest_bytes) {
        Some(h) if !h.is_empty() => h,
        Some(_) => {
            tracing::debug!(
                repo_key = %repo.key,
                name = %name,
                tag = %tag,
                "OCI prefetch: manifest references no blobs (config-only or index); nothing to prefetch"
            );
            return;
        }
        None => {
            tracing::warn!(
                repo_key = %repo.key,
                name = %name,
                tag = %tag,
                "OCI prefetch: manifest body did not parse as a blob-referencing OCI manifest; skipping prefetch (non-fatal)"
            );
            return;
        }
    };

    tracing::info!(
        format = "oci",
        repository_key = %repo.key,
        name = %name,
        tag = %tag,
        upstream_digest = %upstream_digest_str,
        prior_digest_present = prior_held_digest.is_some(),
        blob_count = blob_hashes.len(),
        "OCI prefetch on_dist_tag_move: spawning background blob pull-throughs"
    );

    for blob_hash in blob_hashes {
        let ctx = ctx.clone();
        let repo = repo.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            // The blob pull-through rides `PullDedup` inside
            // `try_upstream_blob_pull`'s `coalesce_blob`, so a racing
            // client pull collapses to a single upstream fetch. The
            // result is logged but not surfaced — prefetch is
            // best-effort.
            let outcome =
                crate::blobs::try_upstream_blob_pull(&ctx, &repo, &name, &blob_hash).await;
            match outcome {
                crate::blobs::UpstreamPullOutcome::Ingested(_) => {
                    tracing::info!(
                        format = "oci",
                        repository_key = %repo.key,
                        name = %name,
                        blob_digest = %blob_hash,
                        trigger = "on_dist_tag_move",
                        "OCI prefetch pull-through succeeded"
                    );
                }
                other => {
                    // Non-Ingested outcomes are not failures of the
                    // serve path — they're operational signals (no
                    // upstream mapping, upstream miss, etc.). Logged
                    // at `warn!` to surface persistent prefetch
                    // problems but without affecting the live pull.
                    tracing::warn!(
                        format = "oci",
                        repository_key = %repo.key,
                        name = %name,
                        blob_digest = %blob_hash,
                        outcome = ?other,
                        trigger = "on_dist_tag_move",
                        "OCI prefetch pull-through did not complete (non-fatal)"
                    );
                }
            }
        });
    }
}

/// Parse a manifest body for `config.digest` + `layers[*].digest`,
/// returning a `Vec<ContentHash>` of the parsed SHA-256 digests.
///
/// Returns `None` on a JSON parse failure, `Some(empty)` when the
/// document parsed but referenced no blobs (e.g. an OCI image index
/// — whose `manifests[*].digest` entries reference *other manifests*,
/// not blobs, and are handled by the standard manifest-pull flow if a
/// client pulls them).
///
/// Deliberately a simple walker — does NOT enforce the
/// `MAX_BLOB_REFERENCES` cap or 400-shape errors that
/// [`crate::manifests_write::parse_manifest_blobs`] enforces. Those
/// are validation rules for *pushes*; for prefetch we only care about
/// "what blobs to optimistically warm" and treat unparseable entries
/// as nothing-to-prefetch.
fn parse_manifest_blob_digests(body: &Bytes) -> Option<Vec<ContentHash>> {
    // Stream-project via `OciManifestProjector` (ADR 0026). Memory bound
    // is `sizeof(OciManifestProjection)` (a handful of descriptors),
    // not the full `serde_json::Value` tree. The None-on-parse-fail
    // policy stays — prefetch is best-effort.
    use hort_domain::ports::upstream_proxy::MetadataProjector;
    let projection = hort_formats::oci::projection::OciManifestProjector::new()
        .project(std::io::Cursor::new(body.as_ref()))
        .ok()?;
    let mut out: Vec<ContentHash> = Vec::new();

    // config.digest — present in single-image manifests. Missing /
    // malformed → skip silently (an image index won't have it).
    if let Some(d) = projection.config.as_ref().and_then(|c| c.digest.as_deref()) {
        if let Some(h) = parse_sha256_digest(d) {
            out.push(h);
        }
    }

    // layers[*].digest — single-image manifests carry one entry per
    // layer; absent in indexes. Malformed entries skipped.
    for layer in &projection.layers {
        if let Some(d) = layer.digest.as_deref() {
            if let Some(h) = parse_sha256_digest(d) {
                out.push(h);
            }
        }
    }

    Some(out)
}

/// Parse a `sha256:<hex>` string into a [`ContentHash`]. Returns
/// `None` for any other shape — a non-SHA256 algorithm, missing
/// prefix, or hex parse failure. Used by [`parse_manifest_blob_digests`]
/// for prefetch-time best-effort digest extraction; the strict
/// manifest-push validator lives in [`crate::manifests_write`].
fn parse_sha256_digest(s: &str) -> Option<ContentHash> {
    s.strip_prefix("sha256:")?.parse::<ContentHash>().ok()
}

// ---------------------------------------------------------------------------
// GUARDRAIL — `IndexMode::ReleasedOnly` does NOT apply to OCI.
// ---------------------------------------------------------------------------
//
// An OCI tag is an exact pointer, not a version range. The `ReleasedOnly`
// index mode filters a served version *catalog* down to hort-held released
// versions — meaningless for OCI's pull-by-tag semantics, and equivalent
// to the rejected silent-substitution (deferred-move) design.
//
// The OCI manifest serve path (`crate::manifests::serve`) MUST NOT consult
// `Repository::index_mode`. The structural guard is:
//
// 1. No `use hort_domain::entities::repository::IndexMode` import anywhere in
//    `crate::manifests`, `crate::blobs`, `crate::tags`, or `crate::quarantine`.
// 2. No field access `repo.index_mode` outside the prefetch-policy
//    surface (which lives on `repo.prefetch_policy`, not `repo.index_mode`).
//
// The [`tests::oci_manifest_serve_path_must_not_consult_index_mode`] test
// below enforces (1) + (2) via a source-file scan. A regression that
// adds a filter here is caught at test time, NOT after a moved-tag pull
// has already returned the wrong manifest in production.
//
// Do NOT remove this comment or the test without updating the architecture
// docs first.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, RepositoryFormat, RepositoryType,
    };
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use uuid::Uuid;

    use hort_http_core::test_support::build_mock_ctx;

    // ---------- Fixtures ----------

    fn oci_repo_with_policy(key: &str, policy: PrefetchPolicy) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: "Test OCI".into(),
            description: None,
            format: RepositoryFormat::Oci,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/test".into(),
            upstream_url: Some("https://registry.example.com".into()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            // `ReleasedOnly` does not apply to OCI but the field is on
            // every Repository for schema uniformity. The guardrail test
            // below verifies the OCI serve path never *consults* this
            // field.
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: policy,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn enabled_dist_tag_move_policy() -> PrefetchPolicy {
        PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::OnDistTagMove],
            depth: 5,
            transitive_depth: 5,
            max_age_days: None,
            // Inherit the production default.
            max_descendants: PrefetchPolicy::default().max_descendants,
        }
    }

    /// Build a synthetic single-image manifest body referencing one
    /// config blob + N layer blobs. The digest hex values are
    /// deterministic per layer index so tests can assert on them
    /// without computing live hashes.
    fn synthetic_manifest_bytes(config_hex: &str, layer_hexes: &[&str]) -> Bytes {
        let layers: Vec<serde_json::Value> = layer_hexes
            .iter()
            .map(|hex| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{hex}"),
                    "size": 1024,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_hex}"),
                "size": 512,
            },
            "layers": layers,
        });
        Bytes::from(serde_json::to_vec(&body).unwrap())
    }

    fn hash(hex: &str) -> ContentHash {
        hex.parse().unwrap()
    }

    // ---------- OciDigestOrdering ----------

    /// The degenerate ordering is always `Equal`. Pins the
    /// documented-by-design behaviour so a refactor that swaps it for
    /// a lexical comparator is caught — lexical would cause
    /// not_newer false-positives if the planner ever ran with a
    /// populated held set.
    #[test]
    fn oci_digest_ordering_always_returns_equal() {
        let cmp = OciDigestOrdering;
        let a = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let b = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(cmp.compare(a, b), Ordering::Equal);
        assert_eq!(cmp.compare(b, a), Ordering::Equal);
        assert_eq!(cmp.compare(a, a), Ordering::Equal);
    }

    // ---------- parse_manifest_blob_digests ----------

    #[test]
    fn parse_manifest_blob_digests_extracts_config_plus_layers() {
        let body = synthetic_manifest_bytes(
            "1111111111111111111111111111111111111111111111111111111111111111",
            &[
                "2222222222222222222222222222222222222222222222222222222222222222",
                "3333333333333333333333333333333333333333333333333333333333333333",
            ],
        );
        let digests = parse_manifest_blob_digests(&body).expect("parse succeeds");
        assert_eq!(digests.len(), 3, "1 config + 2 layers");
        // Order is config first, then layers in encounter order.
        assert_eq!(
            digests[0].as_ref(),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            digests[1].as_ref(),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        assert_eq!(
            digests[2].as_ref(),
            "3333333333333333333333333333333333333333333333333333333333333333"
        );
    }

    #[test]
    fn parse_manifest_blob_digests_ignores_non_sha256_algorithms() {
        // An sha512 digest (or any non-sha256 algorithm) is silently
        // skipped — prefetch is best-effort and a non-SHA256 entry
        // signals a manifest we don't know how to handle here.
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "config": { "digest": "sha512:abc" },
                "layers": [{ "digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444" }],
            }))
            .unwrap(),
        );
        let digests = parse_manifest_blob_digests(&body).expect("parse succeeds");
        assert_eq!(digests.len(), 1, "sha512 config skipped; sha256 layer kept");
    }

    #[test]
    fn parse_manifest_blob_digests_returns_none_on_invalid_json() {
        let body = Bytes::from(b"this is not JSON".to_vec());
        assert!(parse_manifest_blob_digests(&body).is_none());
    }

    #[test]
    fn parse_manifest_blob_digests_returns_empty_for_index_without_blobs() {
        // An OCI image index has `manifests[*]` not `layers[*]` and no
        // `config`. The walker returns `Some(empty)` — there is
        // nothing to blob-prefetch (the per-platform manifests are
        // pulled separately by the client and trigger their own
        // pull-through cascade).
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                }],
            }))
            .unwrap(),
        );
        let digests = parse_manifest_blob_digests(&body).expect("parse succeeds");
        assert!(
            digests.is_empty(),
            "image index has no blob refs to prefetch"
        );
    }

    // ---------- fire_prefetch_trigger_oci ----------

    /// Build the in-test tokio runtime needed by `build_mock_ctx`
    /// (the `EphemeralStore` adapter registers a reactor-bound timer
    /// at construction time) and run the supplied closure inside it.
    fn in_runtime<F: FnOnce()>(f: F) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { f() });
    }

    /// Disabled prefetch policy → no enqueued metric tick, no spawn.
    #[test]
    fn disabled_policy_emits_no_enqueued_counter() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let handle = PrometheusBuilder::new().build_recorder().handle();

        metrics::with_local_recorder(&recorder, || {
            in_runtime(|| {
                let (ctx, _mocks) = build_mock_ctx(handle);
                // PrefetchPolicy::default() → enabled = false.
                let repo = oci_repo_with_policy("oci-mirror", PrefetchPolicy::default());
                let upstream =
                    hash("6666666666666666666666666666666666666666666666666666666666666666");
                let manifest_bytes = synthetic_manifest_bytes(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    &["2222222222222222222222222222222222222222222222222222222222222222"],
                );

                fire_prefetch_trigger_oci(
                    &ctx,
                    &repo,
                    "library/nginx",
                    "latest",
                    &upstream,
                    None,
                    &manifest_bytes,
                );
            });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            snapshot.iter().all(|(ck, _, _, _)| {
                !(ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total")
            }),
            "hort_prefetch_enqueued_total must NOT fire when prefetch_policy.enabled = false"
        );
    }

    /// No-op test: held digest equals upstream digest → no trigger
    /// fires (this is NOT a tag move).
    #[test]
    fn held_equal_to_upstream_does_not_fire_trigger() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let handle = PrometheusBuilder::new().build_recorder().handle();

        metrics::with_local_recorder(&recorder, || {
            in_runtime(|| {
                let (ctx, _mocks) = build_mock_ctx(handle);
                let repo = oci_repo_with_policy("oci-mirror", enabled_dist_tag_move_policy());
                let upstream =
                    hash("7777777777777777777777777777777777777777777777777777777777777777");
                let prior = upstream.clone(); // identical → not a move.
                let manifest_bytes = synthetic_manifest_bytes(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    &["2222222222222222222222222222222222222222222222222222222222222222"],
                );

                fire_prefetch_trigger_oci(
                    &ctx,
                    &repo,
                    "library/nginx",
                    "latest",
                    &upstream,
                    Some(&prior),
                    &manifest_bytes,
                );
            });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            snapshot.iter().all(|(ck, _, _, _)| {
                !(ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total")
            }),
            "hort_prefetch_enqueued_total must NOT fire when held digest == upstream digest"
        );
    }

    /// Divergence between held and upstream digests → counter ticks
    /// with `trigger=on_dist_tag_move` and the repository key.
    /// Divergence between held and upstream digests → counter ticks.
    #[test]
    fn divergent_upstream_digest_emits_on_dist_tag_move_counter() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let handle = PrometheusBuilder::new().build_recorder().handle();

        metrics::with_local_recorder(&recorder, || {
            in_runtime(|| {
                let (ctx, _mocks) = build_mock_ctx(handle);
                let repo = oci_repo_with_policy("oci-mirror", enabled_dist_tag_move_policy());
                let prior =
                    hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                let upstream =
                    hash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
                assert_ne!(prior.as_ref(), upstream.as_ref(), "fixture sanity");
                let manifest_bytes = synthetic_manifest_bytes(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    &[
                        "2222222222222222222222222222222222222222222222222222222222222222",
                        "3333333333333333333333333333333333333333333333333333333333333333",
                    ],
                );

                fire_prefetch_trigger_oci(
                    &ctx,
                    &repo,
                    "library/nginx",
                    "latest",
                    &upstream,
                    Some(&prior),
                    &manifest_bytes,
                );
            });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        let entry = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "trigger" && l.value() == "on_dist_tag_move")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "repository" && l.value() == "oci-mirror")
            })
            .expect(
                "hort_prefetch_enqueued_total{trigger=on_dist_tag_move,repository=oci-mirror} \
                 must fire on a digest-divergence pull",
            );
        match &entry.3 {
            DebugValue::Counter(c) => assert_eq!(
                *c, 1,
                "single-upstream / empty-held planner shape → exactly one enqueue tick"
            ),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    /// No prior held digest (first tag pull) → trigger fires. A
    /// first-time tag pull is the analogue of "moved from
    /// no-digest to a-digest" and warms the new image's blobs.
    #[test]
    fn no_prior_held_digest_still_fires_trigger() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let handle = PrometheusBuilder::new().build_recorder().handle();

        metrics::with_local_recorder(&recorder, || {
            in_runtime(|| {
                let (ctx, _mocks) = build_mock_ctx(handle);
                let repo = oci_repo_with_policy("oci-mirror", enabled_dist_tag_move_policy());
                let upstream =
                    hash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
                let manifest_bytes = synthetic_manifest_bytes(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    &["2222222222222222222222222222222222222222222222222222222222222222"],
                );

                fire_prefetch_trigger_oci(
                    &ctx,
                    &repo,
                    "library/nginx",
                    "latest",
                    &upstream,
                    None, // no prior — first pull.
                    &manifest_bytes,
                );
            });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            snapshot.iter().any(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "trigger" && l.value() == "on_dist_tag_move")
            }),
            "first-tag-pull (no prior held) must fire the on_dist_tag_move trigger"
        );
    }

    /// Trigger not subscribed in policy → planner emits skipped, no
    /// enqueued counter ticks. Pins the operator-opt-in shape:
    /// enabling `prefetch_policy.enabled` is necessary but not
    /// sufficient — the trigger must also be in `policy.triggers`.
    #[test]
    fn trigger_not_subscribed_emits_no_enqueued_counter() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let handle = PrometheusBuilder::new().build_recorder().handle();

        metrics::with_local_recorder(&recorder, || {
            in_runtime(|| {
                let (ctx, _mocks) = build_mock_ctx(handle);
                // Enabled but only `Scheduled` is subscribed —
                // `OnDistTagMove` is NOT, so the planner emits
                // skipped{reason=trigger_not_enabled} and no
                // enqueued counter ticks.
                let policy = PrefetchPolicy {
                    enabled: true,
                    triggers: vec![PrefetchTrigger::Scheduled],
                    depth: 5,
                    transitive_depth: 5,
                    max_age_days: None,
                    // Inherit the production default.
                    max_descendants: PrefetchPolicy::default().max_descendants,
                };
                let repo = oci_repo_with_policy("oci-mirror", policy);
                let upstream =
                    hash("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
                let manifest_bytes = synthetic_manifest_bytes(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    &["2222222222222222222222222222222222222222222222222222222222222222"],
                );

                fire_prefetch_trigger_oci(
                    &ctx,
                    &repo,
                    "library/nginx",
                    "latest",
                    &upstream,
                    None,
                    &manifest_bytes,
                );
            });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            snapshot.iter().all(|(ck, _, _, _)| {
                !(ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total")
            }),
            "hort_prefetch_enqueued_total must NOT fire when OnDistTagMove is not subscribed"
        );
    }

    // ---------- IndexMode guardrail ----------

    /// Guardrail: the OCI manifest serve path MUST NOT consult
    /// [`IndexMode::ReleasedOnly`]. Source-file scan over
    /// `manifests.rs`, `blobs.rs`, `tags.rs`, and `quarantine.rs` —
    /// the four files that constitute the OCI READ path.
    ///
    /// A regression that adds an `IndexMode` import / `repo.index_mode`
    /// field read in these files is a structural error caught here,
    /// NOT after a moved-tag pull has already returned a stand-in
    /// manifest in production. Silent substitution on OCI tags is
    /// rejected unconditionally; this test makes that an enforceable
    /// invariant rather than a code-review convention.
    ///
    /// **DO NOT** silence this test by adding an `#[ignore]` or by
    /// relaxing the scan — if the design ever permits `IndexMode` on
    /// OCI, the architecture docs must be amended FIRST and this test
    /// retired in the SAME change.
    ///
    /// The scan ignores `//` line comments and `/* … */` doc-comment
    /// content so the explainer comments in this very crate (which
    /// DESCRIBE the rule) do not trip the guard against CODE that
    /// USES the rule's banned types.
    #[test]
    fn oci_manifest_serve_path_must_not_consult_index_mode() {
        // The four read-path source files. The write paths
        // (`manifests_write.rs`, `uploads.rs`) are out of scope —
        // index-mode is a *serve* concept and a write-path mention
        // would be just as wrong but is out of scope for this guard.
        let read_path_files: &[(&str, &str)] = &[
            ("manifests.rs", include_str!("manifests.rs")),
            ("blobs.rs", include_str!("blobs.rs")),
            ("tags.rs", include_str!("tags.rs")),
            ("quarantine.rs", include_str!("quarantine.rs")),
        ];
        for (filename, src) in read_path_files {
            let code = strip_rust_comments(src);
            // `IndexMode` as a type / variant reference in CODE.
            assert!(
                !code.contains("IndexMode"),
                "OCI read-path file `{filename}` references the `IndexMode` type in CODE \
                 — `ReleasedOnly` index-filtering is forbidden on the OCI tag-pull \
                 surface; silent substitution on OCI tags is rejected unconditionally"
            );
            // `.index_mode` field access in CODE (the field exists on
            // every `Repository` row; OCI must not READ it).
            assert!(
                !code.contains(".index_mode"),
                "OCI read-path file `{filename}` reads the `.index_mode` field in CODE — \
                 the OCI tag-pull surface must not gate on this field (see IndexMode guardrail)"
            );
        }
    }

    /// Strip Rust `//`-line and `/* … */`-block comments from `src`
    /// for the purposes of the index-mode guardrail scan. NOT a complete
    /// Rust lexer — does not handle string literals, raw strings, or
    /// nested block comments correctly. For the constrained
    /// keyword-presence scan here those edge cases don't matter:
    /// the read-path files don't contain the banned tokens inside
    /// any string literal.
    fn strip_rust_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let bytes = src.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Block comment: skip until terminator `*/`.
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
            // Line comment: skip until newline.
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }
}
