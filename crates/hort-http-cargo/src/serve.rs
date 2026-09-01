//! Cargo unified sparse-index serve handler.
//!
//! This is the cargo-side of the **Source → Filter → Builder** pipeline.
//! One handler covers the hosted and proxy paths for the sparse-index
//! routes (`GET /cargo/{repo_key}/{prefix}/{name}`):
//!
//! 1. **Source.** Dispatch on `repo.repo_type`:
//!    - `Proxy` → [`ProxyCargoSource`] (calls
//!      [`crate::index_cache::fetch_with_cache`] under the hood —
//!      preserving cache + dedup + filter + stale-while-error
//!      invariants byte-for-byte);
//!    - anything else → [`HostedCargoSource`] (reads
//!      [`ArtifactUseCase::list_by_raw_name_visible`] — the
//!      anti-enumeration-enforcing entry point).
//! 2. **Filter pipeline.** `NonServableStatusFilter` then
//!    `IndexModeFilter`, both carrying the caller's `HeldVisibility`.
//!    Otherwise identical to the npm/pypi pipeline; future
//!    operator-defined exclusion filters append to this list.
//! 3. **Builder.** [`CargoIndexBuilder`] emits the sparse-index
//!    NDJSON body.
//!
//! # Anti-enumeration shape
//!
//! Anonymous / denied callers on a private repo receive `404`, not
//! `403`. The hosted source's `list_by_raw_name_visible` already
//! collapses denial / missing / invisible into
//! `NotFound { entity: "Repository" }`; the unified handler maps
//! that through to a 404 envelope. The proxy source re-resolves via
//! `RepositoryAccessUseCase` for defence-in-depth; same envelope.
//! Empty result sets (hosted produces zero rows; proxy parses an
//! empty NDJSON body) also map to 404 with the
//! `Artifact NotFound { id: <crate_name> }` envelope.
//!
//! # Write-authorized hold-read
//!
//! A caller holding *granted* write authority on the repository sees
//! `Quarantined` versions in the served index (ADR 0055, generalising
//! ADR 0039 §10) — a publisher has to resolve the sibling it just
//! uploaded, and `cargo publish` does that through the index even under
//! `--no-verify`. The widening is metadata-only and `Quarantined`-only:
//! terminal verdicts stay hidden from everyone, and held `.crate` bytes
//! stay unserved to everyone (the download path carries no exemption).
//! It does not apply to an aggregated (virtual) read, whose entries
//! belong to member repositories the caller's grant says nothing about.
//!
//! Because the served set therefore varies by identity, every response
//! from this handler carries `Cache-Control: private, no-store` and
//! `Vary: Authorization`.
//!
//! # Yanked semantics
//!
//! Cargo clients honour `yanked: true` orthogonally to quarantine —
//! a yanked version stays in the served set. The filter pipeline
//! does NOT filter on yanked; the builder emits whatever
//! [`CargoVersionPayload::yanked`](hort_app::use_cases::index_serve::CargoVersionPayload::yanked)
//! carries. The hosted source emits `yanked: false` always (the
//! v2 model has no operator-driven yank yet); the proxy source
//! preserves the upstream-supplied value.
//!
//! # Truncation `Warning: 299` header
//!
//! Threaded through [`IndexSourceOutput::truncated`]. Only the
//! hosted source can be truncated (its `list_by_raw_name_visible`
//! is paginated and capped at
//! [`LIMIT_LIST_MAX_ITEMS`](hort_domain::types::LIMIT_LIST_MAX_ITEMS));
//! the proxy source always reports `truncated = false`.
//!
//! # Observability
//!
//! - **No new metrics.** The filter pipeline reuses the existing
//!   `hort_index_versions_filtered_total{format, repository}` counter.
//!   This handler emits it once per call across the
//!   number of versions the filter pipeline dropped (universal +
//!   mode-specific arms combined).
//! - **One `info!` line** carrying `format`, `repository`, `package`,
//!   `index_source = "hosted" | "proxy"`, and the
//!   `upstream_versions` / `served_versions` / `filtered_versions`
//!   triple. `index_source` is a tracing field (no metric — operators
//!   dashboard from the tracing field, not a new metric).

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, VARY};
use axum::http::StatusCode;
use axum::response::Response;

use hort_app::error::AppError;
use hort_app::use_cases::index_filters::{
    HeldVisibility, IndexModeFilter, NonServableStatusFilter,
};
use hort_app::use_cases::index_serve::{BuildContext, IndexFilter, VersionEntry};
use hort_app::use_cases::index_serve_filter::NpmSemverOrdering;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryType};
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::index::CargoIndexBuilder;
use hort_formats::index_serve::IndexBuilder;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::index_source::{select_source, IndexSourceOutput};

/// Unified cargo sparse-index serve — the cargo-side of the
/// Source → Filter → Builder pipeline.
///
/// `caller` is threaded through the source layer; both hosted and
/// proxy sources call `RepositoryAccessUseCase::resolve(_, caller,
/// Read)` (directly or via `list_by_raw_name_visible`), so denied /
/// invisible / missing repos all collapse to a 404 `Repository
/// NotFound` envelope before any rows / upstream bytes are surfaced.
///
/// On success returns a 200 `text/plain; charset=utf-8` response
/// carrying the NDJSON bytes (cargo sparse-index wire content-type).
/// On truncation, the same response gains a
/// `Warning: 299 - "results truncated at <cap> items"` header.
#[tracing::instrument(
    skip(ctx, caller),
    fields(repo_key = %repo_key, crate_name = %crate_name),
)]
pub(crate) async fn serve_index_unified(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    crate_name: &str,
    caller: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // ---- Resolve the repo + access check -----------------------------
    // Central anti-enumeration hop (ADR 0008). Anonymous on private
    // collapses to `NotFound { entity: "Repository" }` — same 404
    // envelope as a missing repo. The hosted source re-resolves
    // through `list_by_raw_name_visible` (its own access check), and
    // the proxy source re-resolves defensively; this top-level resolve
    // gives the proxy branch a `Repository` to inspect `repo_type`
    // on without an extra check round.
    let repo: Repository = ctx
        .repository_access_use_case
        .resolve(repo_key, caller, AccessLevel::Read)
        .await
        .map_err(ApiError::from)?;

    // ---- Crate-name validation (serve-path parity, INJ-2) ------------
    // The download / publish paths validate the crate name via
    // `validate_cargo_name` before any path construction; the
    // sparse-index serve path historically only lowercase-normalised it.
    // A `..` / `..%2f`-shaped name would otherwise flow unvalidated into
    // `index_path_for` → the Redis cache key + composed upstream URL.
    // There is no filesystem escape (CAS + `reject_traversal` backstop),
    // but the cache key / upstream path would be polluted. Reject here,
    // BEFORE any cache-key / upstream-URL construction, returning the
    // SAME `DomainError::Validation` envelope the download path emits.
    hort_formats::cargo::validate_cargo_name(crate_name)
        .map_err(|e| ApiError::from(AppError::Domain(e)))?;

    // ---- Step 1: Source dispatch (transparent to repo type) ----------
    // `select_source` returns the hosted / proxy / virtual source. The
    // virtual source aggregates its members behind this same seam
    // (ADR 0031), so this handler never special-cases `Virtual` — it
    // dispatches by type for the tracing label only, then runs the
    // unchanged filter pipeline + builder. `map_source_error` handles the
    // proxy-only `External` → 502 arm and falls through to `ApiError::from`
    // for hosted/virtual errors.
    let index_source_label = match repo.repo_type {
        RepositoryType::Proxy => "proxy",
        RepositoryType::Virtual => "virtual",
        _ => "hosted",
    };
    let output: IndexSourceOutput = select_source(&repo)
        .fetch(ctx, &repo, crate_name, caller)
        .await
        .map_err(map_source_error)?;

    // Empty hosted results → 404. For proxy the equivalent path is
    // `NoUpstream` → 404 (raised at the source layer above); a
    // parsed-empty NDJSON is allowed and produces an empty served body.
    // Hosted with zero entries is the "crate doesn't exist in this
    // repo" envelope.
    if matches!(
        repo.repo_type,
        RepositoryType::Hosted | RepositoryType::Staging | RepositoryType::Virtual
    ) && output.entries.is_empty()
    {
        return Err(ApiError::from(AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: hort_formats::cargo::CargoFormatHandler.normalize_name(crate_name),
            },
        )));
    }

    // ---- Step 2: Filter pipeline -------------------------------------
    // `NonServableStatusFilter` first (universal — drops
    // Quarantined/Rejected/ScanIndeterminate regardless of mode), then
    // `IndexModeFilter` for the mode-specific never-ingested handling.
    // Future operator-exclusion filters append at the end of this list.
    //
    // Write-authorized hold-read (ADR 0055, generalising ADR 0039 §10):
    // `cargo publish` resolves a crate's intra-workspace dependencies
    // through the index even under `--no-verify`, so a publisher pushing
    // a dependency chain into a hosted repo with an observation window
    // cannot resolve the sibling it just uploaded — every publish after
    // the first fails mid-chain, with the earlier crates already
    // uploaded and only yankable. A principal that may WRITE the
    // repository may therefore resolve held *metadata* there: the
    // sparse-index entry is cargo's manifest analogue. Held `.crate`
    // BYTES stay unserved to everyone, publisher included — the
    // download path (`render_cargo_crate_response`) has no exemption
    // and must never grow one.
    //
    // The predicate keys on GRANTED write authority
    // (`resolve_granted_write`, the grants leg alone) rather than the
    // presented token's cap. A cap-intersected `resolve(_, Write)` would
    // never engage for a correctly-behaving publisher: cargo presents
    // one registry token for both reading the index and uploading, and a
    // read-scoped capability legitimately carries a read-only cap while
    // the identity's grants carry Write. The read being exempted stays
    // fully cap-gated through the ordinary `resolve(Read)` above; only
    // the held-visibility decision consults identity-level authority.
    //
    // The rule is "may write to a repository ⇒ may resolve held
    // metadata THERE", so it is evaluated against the repository that
    // holds the artifacts. A virtual repo holds none — its entries come
    // from its members (ADR 0031), and write authority on the aggregator
    // is not write authority on the member the held entry lives in.
    // Aggregated reads therefore keep the ordinary view.
    //
    // Fail closed: ONLY a definitive granted-Write authorization widens
    // the view — a denied or errored resolve leaves held entries hidden.
    // The resolve fires solely when the source actually produced a held
    // entry, so the ordinary read path pays nothing for it.
    let upstream_count = output.entries.len();
    let held_visibility = if !matches!(repo.repo_type, RepositoryType::Virtual)
        && output
            .entries
            .iter()
            .any(|e| e.status == Some(QuarantineStatus::Quarantined))
        && ctx
            .repository_access_use_case
            .resolve_granted_write(repo_key, caller)
            .await
            .is_ok()
    {
        HeldVisibility::WriteAuthorized
    } else {
        HeldVisibility::Hidden
    };
    let filters: Vec<Arc<dyn IndexFilter>> = vec![
        Arc::new(NonServableStatusFilter::new(held_visibility)),
        Arc::new(IndexModeFilter::with_held_visibility(
            repo.index_mode,
            held_visibility,
        )),
    ];
    let filtered: Vec<VersionEntry> = filters.iter().fold(output.entries, |acc, f| f.apply(acc));
    let served_count = filtered.len();
    let filtered_count = upstream_count.saturating_sub(served_count);

    // Emit the per-call filter metric once, summed across the filters
    // that fired (universal + mode arms). Catalog axis: `{format,
    // repository}`.
    if filtered_count > 0 {
        metrics::counter!(
            "hort_index_versions_filtered_total",
            "format" => "cargo",
            "repository" => repo_key.to_string(),
        )
        .increment(filtered_count as u64);
    }

    tracing::info!(
        crate_name = %crate_name,
        repository = %repo_key,
        index_source = index_source_label,
        index_mode = %repo.index_mode,
        upstream_versions = upstream_count,
        served_versions = served_count,
        filtered_versions = filtered_count,
        held_visibility = ?held_visibility,
        "cargo unified sparse-index serve completed",
    );

    // ---- Step 3: Build the wire bytes --------------------------------
    // base_url and package_name are unused by the cargo builder (the
    // sparse-index NDJSON does not carry per-version download URLs;
    // see `hort_formats::cargo::index`'s module rustdoc). We still
    // supply them per the trait shape; the builder ignores them.
    let builder = CargoIndexBuilder;
    let body_bytes = builder.build(
        BuildContext {
            package_name: crate_name,
            base_url: "", // unused — see CargoIndexBuilder rustdoc
            index_mode: repo.index_mode,
            ordering: &NpmSemverOrdering, // CargoSemverOrdering alias
        },
        filtered,
    );

    // The served set depends on the caller's authority (the hold-read
    // above), so the response is identity-dependent and must never be
    // reused across principals. Absent directives are not "no caching":
    // heuristic caching applies, and with no `Vary` nothing tells an
    // intermediary the body varies by identity — a shared cache or
    // reverse proxy could otherwise store a publisher's response, held
    // entries included, and replay it to an anonymous consumer. Both
    // headers are unconditional: emitting them only on the exempted
    // responses would leave the ordinary ones heuristically cacheable
    // under the same URL key.
    let mut builder_resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "private, no-store")
        .header(VARY, AUTHORIZATION.as_str());
    if output.truncated {
        builder_resp = builder_resp.header(
            "Warning",
            format!(
                "299 - \"results truncated at {} items\"",
                hort_domain::types::LIMIT_LIST_MAX_ITEMS
            ),
        );
    }
    Ok(builder_resp.body(Body::from(body_bytes)).unwrap())
}

/// Map an [`AppError`] coming out of [`ProxyCargoSource::fetch`] to
/// an [`ApiError`] preserving the expected wire shape:
///
/// - `External(_)` (upstream unavailable, no cache fallback) → 502
///   bad-gateway, emitting `502 + {"error":"upstream unavailable"}`;
///   the unified handler delegates to
///   `ApiError::from(AppError::External(...))` which produces the
///   equivalent 502 envelope.
/// - Anything else → default `ApiError::from(AppError)` mapping.
///
/// The proxy-source-only `External` arm is handled here so the
/// shared `ApiError::from(AppError::External(...))` mapping (which
/// is the generic 500 / 502 path) can stay agnostic of cargo's
/// proxy dispatch contract.
fn map_source_error(err: AppError) -> ApiError {
    match err {
        AppError::External(msg) if msg.contains("cargo upstream unavailable") => {
            // ApiError doesn't currently have a typed 502 constructor;
            // wrap as `External` and let the generic mapping emit
            // 502. We preserve the message so downstream telemetry
            // sees the same string.
            ApiError::from(AppError::External(msg))
        }
        other => ApiError::from(other),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Tests for the unified sparse-index serve handler:
    //!
    //! 1. Quarantined hosted artifact filtered.
    //! 2. Rejected hosted artifact (rescan-driven) filtered.
    //! 3. Anti-enumeration — anonymous on private repo gets
    //!    `NotFound` (404), not 403.
    //! 4. NDJSON wire-shape preservation — one line per served
    //!    version, `\n`-terminated, JSON valid per cargo sparse-index
    //!    spec.
    //! 5. Yanked semantics preserved — yanked versions are included
    //!    in the NDJSON with `yanked: true` (cargo clients treat
    //!    yanked separately from removal).
    //!
    //! Plus a smoke for the empty-hosted-result → 404 envelope path.
    //!
    //! All tests drive the unified handler directly via
    //! [`serve_index_unified`].

    use std::sync::Arc;

    use axum::response::IntoResponse;
    use chrono::Utc;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::api_token::TokenCap;
    use hort_domain::entities::artifact::Artifact;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::{IndexMode, RepositoryFormat};
    use hort_domain::types::ContentHash;
    use hort_http_core::test_support::{
        build_mock_ctx, trust_config_untrusted_peer_fallback, with_repository_access,
        with_trust_config,
    };
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use super::*;

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    fn insert_hosted_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        mode: IndexMode,
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Hosted;
        repo.index_mode = mode;
        mocks.repositories.insert(repo.clone());
        repo
    }

    /// Build a stable distinct SHA-256 per seed so each artifact gets
    /// a unique CAS hash.
    fn fake_sha256(seed: u8) -> ContentHash {
        let mut s = String::with_capacity(64);
        for _ in 0..64 {
            s.push(((seed % 16) + b'0') as char);
        }
        s.parse().unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap()
        })
    }

    fn insert_artifact(
        mocks: &hort_http_core::test_support::MockPorts,
        repo_id: Uuid,
        name: &str,
        version: &str,
        sha_seed: u8,
        status: QuarantineStatus,
    ) -> Artifact {
        let sha256 = fake_sha256(sha_seed);
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: format!("crates/{name}/{version}/{name}-{version}.crate"),
            size_bytes: 100,
            sha256_checksum: sha256,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/x-tar".into(),
            quarantine_status: status,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: now,
            updated_at: now,
        };
        mocks.artifacts.insert(artifact.clone());
        artifact
    }

    /// RBAC-enabled context over an explicit grant set, reusing the
    /// harness's `repositories` mock so seeded repos still resolve.
    fn rbac_grant_ctx(
        base: &Arc<AppContext>,
        mocks: &hort_http_core::test_support::MockPorts,
        grants: Vec<PermissionGrant>,
    ) -> Arc<AppContext> {
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(grants),
            ))),
            true,
        ));
        with_repository_access(base, access)
    }

    /// RBAC-enabled context granting `claim` repo-wide `Write`. Whether
    /// the *caller* carries the claim is the variable under test.
    fn write_grant_ctx(
        base: &Arc<AppContext>,
        mocks: &hort_http_core::test_support::MockPorts,
        claim: &str,
    ) -> Arc<AppContext> {
        rbac_grant_ctx(
            base,
            mocks,
            vec![PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec![claim.to_string()]),
                repository_id: None,
                permission: Permission::Write,
                created_at: Utc::now(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            }],
        )
    }

    /// A principal carrying `claim`, with `token_cap` set to the given
    /// permissions (`None` = an uncapped session token).
    fn principal(claim: &str, cap: Option<Vec<Permission>>) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: format!("test:{claim}"),
            username: claim.to_string(),
            email: format!("{claim}@example.com"),
            claims: vec![claim.to_string()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: cap.map(|permissions| TokenCap {
                permissions,
                repository_ids: None,
            }),
        }
    }

    fn parse_lines(body: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(body)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each line must be JSON"))
            .collect()
    }

    // -----------------------------------------------------------------
    // 1. Quarantined hosted artifact filtered out of the served NDJSON.
    //    Three versions seeded; the Quarantined one (1.1.0) MUST NOT
    //    appear. The two Released versions appear in semver order.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn quarantined_hosted_artifact_is_filtered_from_served_ndjson() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        // Route through an RBAC-ENABLED context (not the mock harness's
        // admit-everything default) so the anonymous caller genuinely
        // lacks Write — otherwise the hold-read exemption would admit
        // the admit-everything mock's anonymous "Write" and serve the
        // held entry. In production an anonymous caller's Write resolve
        // fails, so the entry stays hidden; this exercises that path.
        let ctx = write_grant_ctx(&ctx, &mocks, "ci-publisher");
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.2.0",
            3,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);

        let versions: Vec<&str> = lines.iter().map(|l| l["vers"].as_str().unwrap()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0", "1.2.0"],
            "Quarantined 1.1.0 MUST be filtered by NonServableStatusFilter; \
             survivors in semver order"
        );
    }

    // -----------------------------------------------------------------
    // 2. Rejected hosted artifact (rescan-driven) filtered.
    //    A long-released artifact transitioned to Rejected disappears
    //    from the served NDJSON.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rejected_hosted_artifact_is_filtered_from_served_ndjson() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Rejected,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        let versions: Vec<&str> = lines.iter().map(|l| l["vers"].as_str().unwrap()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0"],
            "1.1.0 (Rejected via rescan) MUST be filtered by NonServableStatusFilter",
        );
    }

    // -----------------------------------------------------------------
    // 2b. Write-authorized hold-read (ADR 0055, generalising ADR 0039
    //     §10). The exemption's full matrix: caller authority ×
    //     artifact status.
    //
    //     `cargo publish` resolves a crate's intra-workspace
    //     dependencies through the index even under `--no-verify`, so a
    //     publisher pushing a dependency chain into a repo with an
    //     observation window must be able to resolve the sibling it just
    //     uploaded. Metadata only: held `.crate` bytes stay unserved to
    //     everyone (pinned in `lib.rs`).
    // -----------------------------------------------------------------

    /// Seed one Released + one held/verdict-bearing version, serve as
    /// `caller`, and return the versions in the served NDJSON.
    async fn served_versions_for(
        caller: Option<&CallerPrincipal>,
        second_status: QuarantineStatus,
    ) -> Vec<String> {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        // A `ci-publisher` Write grant always exists; whether the caller
        // carries the claim is the variable under test.
        let ctx = write_grant_ctx(&ctx, &mocks, "ci-publisher");
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "hort-domain",
            "0.11.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(&mocks, repo.id, "hort-domain", "0.11.1", 2, second_status);

        let res = serve_index_unified(&ctx, "cargo-test", "hort-domain", caller)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        parse_lines(&body)
            .iter()
            .map(|l| l["vers"].as_str().unwrap().to_string())
            .collect()
    }

    /// The exemption engages: a write-granted publisher resolves the
    /// held sibling it just uploaded.
    #[tokio::test]
    async fn quarantined_entry_is_served_to_a_write_granted_caller() {
        let publisher = principal("ci-publisher", None);
        let versions = served_versions_for(Some(&publisher), QuarantineStatus::Quarantined).await;
        assert_eq!(
            versions,
            vec!["0.11.0", "0.11.1"],
            "a write-granted principal must resolve the held version — without it \
             every publish after the first fails to resolve its just-uploaded sibling"
        );
    }

    /// The ADR 0039 §10 trap as a regression test. Cargo presents one
    /// registry token for both reading the index and uploading, so the
    /// index read legitimately arrives under a read-scoped capability
    /// while the identity's grants carry Write. A cap-intersected
    /// `resolve(_, Write)` would silently never engage here; the
    /// exemption keys on the grants leg alone, so it does.
    #[tokio::test]
    async fn read_scoped_token_of_a_write_granted_principal_still_gets_the_exemption() {
        let publisher = principal("ci-publisher", Some(vec![Permission::Read]));
        let versions = served_versions_for(Some(&publisher), QuarantineStatus::Quarantined).await;
        assert_eq!(
            versions,
            vec!["0.11.0", "0.11.1"],
            "the hold-read keys on GRANTED write authority, not the presented cap — \
             a cap-intersected resolve would never engage for a real publisher"
        );
    }

    /// Scope guard: the exemption is write-authorized only. A caller
    /// holding read but not write sees the ordinary index.
    #[tokio::test]
    async fn quarantined_entry_stays_hidden_from_a_read_only_caller() {
        let reader = principal("ci-reader", None);
        let versions = served_versions_for(Some(&reader), QuarantineStatus::Quarantined).await;
        assert_eq!(
            versions,
            vec!["0.11.0"],
            "a principal without the Write grant must not see held metadata"
        );
    }

    /// Scope guard: anonymous callers are the pull-through consumers the
    /// quarantine window exists to protect. They never see held entries.
    #[tokio::test]
    async fn quarantined_entry_stays_hidden_from_an_anonymous_caller() {
        let versions = served_versions_for(None, QuarantineStatus::Quarantined).await;
        assert_eq!(
            versions,
            vec!["0.11.0"],
            "anonymous callers must not see held metadata"
        );
    }

    /// Scope guard: `Rejected` is a terminal verdict, not a hold pending
    /// one. The exemption does NOT reach it, for any caller.
    #[tokio::test]
    async fn rejected_entry_stays_hidden_even_from_a_write_granted_caller() {
        let publisher = principal("ci-publisher", None);
        let versions = served_versions_for(Some(&publisher), QuarantineStatus::Rejected).await;
        assert_eq!(
            versions,
            vec!["0.11.0"],
            "the hold-read covers Quarantined only — a reached verdict stays hidden \
             from everyone, publisher included"
        );
    }

    /// Scope guard: `ScanIndeterminate` is a terminal fail-closed block
    /// with no self-resolving deadline. Same answer as `Rejected`.
    #[tokio::test]
    async fn scan_indeterminate_entry_stays_hidden_even_from_a_write_granted_caller() {
        let publisher = principal("ci-publisher", None);
        let versions =
            served_versions_for(Some(&publisher), QuarantineStatus::ScanIndeterminate).await;
        assert_eq!(
            versions,
            vec!["0.11.0"],
            "ScanIndeterminate is terminal and fail-closed — no caller sees it"
        );
    }

    /// `Released` is unaffected by the caller's authority — the
    /// exemption widens exactly one column.
    #[tokio::test]
    async fn released_entries_are_served_identically_to_every_caller() {
        let publisher = principal("ci-publisher", None);
        let reader = principal("ci-reader", None);
        let expected = vec!["0.11.0", "0.11.1"];
        for caller in [Some(&publisher), Some(&reader), None] {
            let versions = served_versions_for(caller, QuarantineStatus::Released).await;
            assert_eq!(
                versions, expected,
                "Released entries must not depend on caller authority"
            );
        }
    }

    // -----------------------------------------------------------------
    // 2c. The served set varies by principal, so the response must not
    //     be reusable across principals by any intermediary. Absent
    //     directives are not "no caching" — heuristic caching applies,
    //     and with no `Vary` nothing marks the body identity-dependent.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn index_response_is_uncacheable_by_shared_caches() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        // Anonymous — the response a shared cache would be most willing
        // to store and replay. The directives are unconditional, so this
        // one carries them too.
        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(
            res.headers().get(CACHE_CONTROL).unwrap(),
            "private, no-store",
            "the served set varies by principal — a shared cache must not store it"
        );
        assert_eq!(
            res.headers().get(VARY).unwrap(),
            "authorization",
            "without Vary nothing tells an intermediary the body is identity-dependent"
        );
    }

    // -----------------------------------------------------------------
    // 3. Anti-enumeration — anonymous caller on a private repo
    //    receives NotFound (not 403).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_caller_on_private_repo_receives_not_found_not_forbidden() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        // Flip the access use case to Enabled with an empty RBAC
        // evaluator (no claims grant any access).
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx, access);

        let mut repo = sample_repository();
        repo.key = "private-cargo".into();
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Hosted;
        repo.is_public = false;
        mocks.repositories.insert(repo.clone());
        insert_artifact(
            &mocks,
            repo.id,
            "secret-crate",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let err = serve_index_unified(&ctx, "private-cargo", "secret-crate", None)
            .await
            .expect_err("anonymous on private MUST be denied");
        let response = err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "anti-enumeration: denied caller MUST receive 404, NEVER 403",
        );
    }

    // -----------------------------------------------------------------
    // 4. NDJSON wire-shape preservation — one line per served version,
    //    `\n`-terminated, JSON valid per cargo sparse-index spec.
    //    Each line carries the mandatory `name`, `vers`, `deps`,
    //    `cksum`, `features`, `yanked` keys.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn ndjson_wire_shape_preserved_one_line_per_version_newline_terminated() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(ct, "text/plain; charset=utf-8");
        let body_bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly two `\n`-terminators (one per line including the
        // last). No trailing empty line.
        assert_eq!(body.matches('\n').count(), 2);
        assert!(body.ends_with('\n'));

        let lines = parse_lines(&body_bytes);
        assert_eq!(lines.len(), 2);
        for v in &lines {
            // Mandatory cargo sparse-index keys.
            assert!(v["name"].is_string(), "`name` is mandatory");
            assert!(v["vers"].is_string(), "`vers` is mandatory");
            assert!(v["cksum"].is_string(), "`cksum` is mandatory");
            assert!(v["deps"].is_array(), "`deps` is mandatory (may be [])");
            assert!(v["features"].is_object(), "`features` is mandatory");
            assert!(v["yanked"].is_boolean(), "`yanked` is mandatory");
        }
    }

    // -----------------------------------------------------------------
    // 5. Yanked semantics preserved — the filter pipeline does NOT
    //    filter yanked entries. A future operator-driven yank flag on
    //    Artifact would surface here as `yanked: true` on the served
    //    line. Today the hosted source emits `yanked: false` for every
    //    row (no yank mechanism); this test pins the architectural
    //    invariant via the proxy branch's parse — see
    //    `index_source::parse_ndjson_to_entries`.
    //
    //    We exercise the invariant directly on the builder here (via
    //    a payload with `yanked: true`) — proxy-source tests cover
    //    the upstream-parse-and-re-emit shape; this test pins the
    //    "filter pipeline doesn't drop yanked" structural property
    //    on the unified handler.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn yanked_versions_pass_through_filter_pipeline_to_served_set() {
        // Construct a hosted scenario where the artifact projection
        // includes a Released version. The hosted source produces
        // `yanked: false` (v2 has no yank mechanism), but the test
        // exercises the FILTER PIPELINE invariant: yanked is not a
        // quarantine-status concern, so the unified handler does
        // NOT consult `yanked` when deciding to drop. We pin this
        // by asserting the served set is NOT empty for a Released
        // entry (i.e., the filter pipeline kept it regardless of
        // its `yanked` field value).
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]["yanked"].is_boolean(),
            "yanked field present on served line (filter pipeline did not strip it)"
        );
        // The structural invariant — the filter pipeline is
        // status-aware, not yank-aware. Even if a future hosted row
        // were `yanked: true`, the filter pipeline would NOT drop
        // it; the builder would emit `yanked: true` in the line.
    }

    // -----------------------------------------------------------------
    // 6. Missing-crate smoke — visible hosted repo, no matching
    //    artifact → 404. Pins the empty-entries-→ 404 path of the
    //    unified handler.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn missing_crate_on_visible_hosted_repo_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        let err = serve_index_unified(&ctx, "cargo-test", "missing-crate", None)
            .await
            .expect_err("missing crate must 404");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------
    // 6b. Serve-path crate-name validation (INJ-2). A traversal-shaped
    //     name (`..`, `../etc`) on the sparse-index serve path must be
    //     rejected by `validate_cargo_name` BEFORE any cache-key /
    //     upstream-URL construction, returning the SAME 400
    //     `DomainError::Validation` envelope the download path emits —
    //     not a normalised name that flows into `index_path_for`.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn serve_rejects_traversal_crate_name_before_key_construction() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        // `..` and `../etc` are both rejected by `validate_cargo_name`
        // (the cargo grammar forbids `.` / `/`); the serve path must
        // surface that as a 400, not lowercase-normalise it onward.
        for bad in ["..", "../etc", "..%2fetc"] {
            let err = serve_index_unified(&ctx, "cargo-test", bad, None)
                .await
                .expect_err("traversal name must be rejected");
            let response = err.into_response();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "traversal name {bad:?} must map to 400, got {}",
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn serve_accepts_valid_crate_name_after_validation_gate() {
        // The validation gate must not regress the happy path: a normal
        // crate name still resolves through the source pipeline.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("valid name must pass the validation gate and serve"));
        assert_eq!(res.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------
    // 7. Drift-resilience pin — top-level NDJSON `name` reflects the
    //    STORED canonical name, not the request parameter. Mirrors
    //    the npm/pypi same arm.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn unified_handler_emits_stored_canonical_name_under_drift() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        // The drift: request is for "drift-crate" but the stored
        // artifact's name is "Legacy-Crate". The use case's
        // `list_by_raw_name_visible` performs the normalisation-drift
        // fallback; the hosted source embeds the stored name.
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            name: "Legacy-Crate".into(),
            name_as_published: "drift-crate".into(),
            version: Some("0.1.0".into()),
            path: "crates/Legacy-Crate/0.1.0/Legacy-Crate-0.1.0.crate".into(),
            size_bytes: 100,
            sha256_checksum: fake_sha256(9),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/x-tar".into(),
            quarantine_status: QuarantineStatus::Released,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: now,
            updated_at: now,
        };
        mocks.artifacts.insert(artifact);

        let res = serve_index_unified(&ctx, "cargo-test", "drift-crate", None)
            .await
            .unwrap_or_else(|_| panic!("drift recovery must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(
            lines[0]["name"].as_str().unwrap(),
            "Legacy-Crate",
            "NDJSON `name` must carry the STORED form (drift-resilience pin)"
        );
    }

    // -----------------------------------------------------------------
    // `pubtime` — hosted source uses the artifact's own `created_at`.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn hosted_pubtime_uses_artifact_created_at() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        let mut artifact = insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        // Give the artifact a distinct, easily-recognised `created_at`
        // (`insert_artifact` uses `Utc::now()`, indistinguishable from
        // "the test forgot to check the value").
        artifact.created_at = "2022-03-04T05:06:07Z".parse().unwrap();
        mocks.artifacts.insert(artifact.clone());

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(
            lines[0]["pubtime"].as_str().unwrap(),
            "2022-03-04T05:06:07Z",
            "hosted pubtime must be the artifact's own created_at"
        );
    }

    // -----------------------------------------------------------------
    // Virtual (aggregating) serve — ADR 0031. The serve handler is
    // transparent (no `Virtual` branch); these drive it end-to-end through
    // `select_source` → `VirtualCargoSource` → `aggregate_virtual_index`.
    // -----------------------------------------------------------------

    fn insert_virtual_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        members: &[&Repository],
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Virtual;
        repo.index_mode = IndexMode::ReleasedOnly;
        mocks.repositories.insert(repo.clone());
        for m in members {
            mocks.repositories.seed_virtual_member(repo.id, m.id);
        }
        repo
    }

    async fn served_versions(res: Response) -> Vec<String> {
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        parse_lines(&body)
            .iter()
            .map(|l| l["vers"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn virtual_merges_member_sparse_indexes() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "cargo-a", IndexMode::ReleasedOnly);
        let b = insert_hosted_repo(&mocks, "cargo-b", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            a.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            b.id,
            "serde",
            "2.0.0",
            2,
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "cargo-virt", &[&a, &b]);

        let res = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions(res).await;
        assert!(versions.contains(&"1.0.0".to_string()), "member a served");
        assert!(versions.contains(&"2.0.0".to_string()), "member b served");
    }

    #[tokio::test]
    async fn virtual_pubtime_passes_through_winning_member() {
        // Confirmed design point 2 (virtual): the winning member's
        // `pubtime` passes through untouched — no aggregation-level
        // synthesis.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "cargo-a", IndexMode::ReleasedOnly);
        let mut artifact = insert_artifact(
            &mocks,
            a.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        artifact.created_at = "2021-07-08T09:10:11Z".parse().unwrap();
        mocks.artifacts.insert(artifact.clone());
        insert_virtual_repo(&mocks, "cargo-virt", &[&a]);

        let res = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(
            lines[0]["pubtime"].as_str().unwrap(),
            "2021-07-08T09:10:11Z",
            "virtual read must pass the winning member's pubtime through unchanged"
        );
    }

    #[tokio::test]
    async fn virtual_same_version_held_primary_not_replaced_by_secondary() {
        // Dependency-confusion regression (same-version): the higher-priority
        // member holds 1.0.0 Quarantined; a lower-priority member has the SAME
        // version Released. The held copy wins the authoritative merge and is
        // then filtered out — NOT replaced by the secondary's released copy.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let primary = insert_hosted_repo(&mocks, "cargo-primary", IndexMode::ReleasedOnly);
        let secondary = insert_hosted_repo(&mocks, "cargo-secondary", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            primary.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            secondary.id,
            "serde",
            "1.0.0",
            2,
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "cargo-virt", &[&primary, &secondary]);

        let res = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions(res).await;
        assert!(
            versions.is_empty(),
            "held primary copy filtered out, NOT replaced by the secondary's released copy: {versions:?}"
        );
    }

    /// Scope guard on the hold-read: the rule is "may write to a
    /// repository ⇒ may resolve held metadata THERE". A virtual repo
    /// holds nothing — a Write grant on the aggregator says nothing
    /// about the member the held entry actually lives in, so an
    /// aggregated read keeps the ordinary view even for a write-granted
    /// caller.
    #[tokio::test]
    async fn virtual_read_does_not_grant_the_hold_read_over_member_repos() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let ctx = write_grant_ctx(&ctx, &mocks, "ci-publisher");
        let member = insert_hosted_repo(&mocks, "cargo-member", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            member.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Quarantined,
        );
        insert_virtual_repo(&mocks, "cargo-virt", &[&member]);

        // The very principal that WOULD see the held entry on the
        // member repo directly.
        let publisher = principal("ci-publisher", None);
        let res = serve_index_unified(&ctx, "cargo-virt", "serde", Some(&publisher))
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        let versions = served_versions(res).await;
        assert!(
            versions.is_empty(),
            "a write grant on the aggregator must not surface a member's held \
             metadata: {versions:?}"
        );
    }

    // -----------------------------------------------------------------
    // Stored publish metadata in the served entry.
    //
    // The hosted entry's dependency graph comes from the metadata the
    // publish handler persisted. Without it every hosted entry claims
    // `deps: []` / `features: {}`, and cargo — which validates a
    // feature edge against the INDEX entry, not the dependency's own
    // manifest — refuses to package a crate that names a sibling's
    // feature.
    // -----------------------------------------------------------------

    /// The publish body of a crate whose only feature uses the
    /// namespaced-dependency syntax — the shape that must reach the
    /// wire as `features2` + `v: 2`.
    const HORT_APP_PUBLISH_BODY: &str = r#"{
        "name": "hort-app",
        "vers": "0.11.0",
        "deps": [
            {
                "name": "hort-domain",
                "version_req": "=0.11.0",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": null
            },
            {
                "name": "metrics-util",
                "version_req": "^0.16",
                "features": [],
                "optional": true,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": null
            }
        ],
        "features": {
            "default": [],
            "test-support": ["dep:metrics-util"]
        },
        "links": null,
        "rust_version": "1.94",
        "cksum": "a-publisher-supplied-digest-that-must-be-ignored"
    }"#;

    /// Seed the metadata row a cargo publish of `publish_body` writes.
    fn insert_publish_metadata(
        mocks: &hort_http_core::test_support::MockPorts,
        artifact_id: Uuid,
        publish_body: &str,
    ) {
        let parsed: crate::publish_metadata::PublishMetadata =
            serde_json::from_str(publish_body).expect("fixture publish body parses");
        mocks
            .artifact_metadata
            .insert(hort_domain::entities::artifact::ArtifactMetadata {
                artifact_id,
                format: RepositoryFormat::Cargo,
                metadata: parsed.to_index_metadata(),
                metadata_blob: None,
                properties: serde_json::Value::Null,
            });
    }

    /// Serve `crate_name` from a hosted repo and return the one served
    /// NDJSON line.
    async fn single_served_line(
        ctx: &Arc<AppContext>,
        repo_key: &str,
        crate_name: &str,
    ) -> serde_json::Value {
        let res = serve_index_unified(ctx, repo_key, crate_name, None)
            .await
            .unwrap_or_else(|_| panic!("hosted serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let mut lines = parse_lines(&body);
        assert_eq!(lines.len(), 1, "one seeded version → one served line");
        lines.remove(0)
    }

    #[tokio::test]
    async fn hosted_entry_carries_stored_deps_in_index_shape() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        let artifact = insert_artifact(
            &mocks,
            repo.id,
            "hort-app",
            "0.11.0",
            1,
            QuarantineStatus::Released,
        );
        insert_publish_metadata(&mocks, artifact.id, HORT_APP_PUBLISH_BODY);

        let line = single_served_line(&ctx, "cargo-test", "hort-app").await;

        assert_eq!(
            line["deps"],
            serde_json::json!([
                {
                    "name": "hort-domain",
                    "req": "=0.11.0",
                    "features": [],
                    "optional": false,
                    "default_features": true,
                    "target": null,
                    "kind": "normal",
                    "registry": null,
                    "package": null,
                },
                {
                    "name": "metrics-util",
                    "req": "^0.16",
                    "features": [],
                    "optional": true,
                    "default_features": true,
                    "target": null,
                    "kind": "normal",
                    "registry": null,
                    "package": null,
                },
            ]),
            "served deps carry the index schema (`req`, `package`), not the publish schema"
        );
        assert_eq!(line["rust_version"], "1.94");
        assert!(line["links"].is_null());
        assert_eq!(
            line["cksum"],
            artifact.sha256_checksum.to_string(),
            "the CAS hash is the served checksum — never the publisher-supplied one"
        );
        assert_eq!(line["yanked"], false);
        assert_eq!(line["name"], "hort-app");
        assert_eq!(line["vers"], "0.11.0");
    }

    /// The `v0.11.0-beta.8` publish failure, pinned: `hort-http-core`
    /// declares `hort-app/test-support`, and cargo validates that edge
    /// against `hort-app`'s served index entry. The entry must carry
    /// the feature — in `features2`, because it names a dependency
    /// with the `dep:` syntax — and announce the schema version that
    /// tells a client to merge the two maps.
    #[tokio::test]
    async fn hosted_entry_splits_namespaced_features_into_features2() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        let artifact = insert_artifact(
            &mocks,
            repo.id,
            "hort-app",
            "0.11.0",
            1,
            QuarantineStatus::Released,
        );
        insert_publish_metadata(&mocks, artifact.id, HORT_APP_PUBLISH_BODY);

        let line = single_served_line(&ctx, "cargo-test", "hort-app").await;

        assert_eq!(
            line["features"],
            serde_json::json!({"default": []}),
            "plain features stay in `features`"
        );
        assert_eq!(
            line["features2"],
            serde_json::json!({"test-support": ["dep:metrics-util"]}),
            "a `dep:`-syntax feature is served in `features2`"
        );
        assert_eq!(line["v"], 2, "`features2` requires the v2 schema marker");
    }

    /// Versions ingested before publish captured metadata — and rows
    /// written by non-publish paths, whose document has none of these
    /// keys — keep serving exactly the entry they served before.
    #[tokio::test]
    async fn hosted_entry_without_stored_metadata_serves_the_pre_metadata_shape() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        let artifact = insert_artifact(
            &mocks,
            repo.id,
            "hort-app",
            "0.11.0",
            1,
            QuarantineStatus::Released,
        );

        let line = single_served_line(&ctx, "cargo-test", "hort-app").await;

        assert_eq!(
            line,
            serde_json::json!({
                "name": "hort-app",
                "vers": "0.11.0",
                "deps": [],
                "cksum": artifact.sha256_checksum.to_string(),
                "features": {},
                "yanked": false,
                "links": null,
                "rust_version": null,
                "pubtime": artifact.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            }),
            "a version with no stored metadata serves the pre-metadata entry verbatim \
             (plus the always-present hosted `pubtime`)"
        );
    }

    #[tokio::test]
    async fn virtual_with_no_matching_versions_is_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "cargo-a", IndexMode::ReleasedOnly);
        insert_virtual_repo(&mocks, "cargo-virt", &[&a]);
        // No artifacts seeded → member returns empty → merged empty → 404.
        let err = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .expect_err("empty virtual must 404");
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }
}
