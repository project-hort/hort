//! Caching upstream-mapping resolver.
//!
//! Implements [`UpstreamResolver`] over an in-memory snapshot of the
//! `repository_upstream_mappings` table. The snapshot is held in an
//! [`ArcSwap`]; the request path reads through `.load()` (lock-free,
//! microsecond-fast) and a background task in `hort-server`
//! (and `hort-worker`) swaps the snapshot atomically every
//! `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` (default 60s).
//!
//! # Algorithm
//!
//! For each `resolve(repo_id, requested_name)` call:
//!
//! 1. Look up the repository's mappings in the snapshot.
//! 2. Sort candidates by `path_prefix.len()` desc — longest match
//!    wins. Empty-prefix mappings act as the catch-all and only
//!    match when no more-specific prefix does.
//! 3. The first candidate whose `path_prefix` is a prefix of
//!    `requested_name` is selected.
//! 4. Strip the prefix from the requested name to produce the
//!    upstream-facing name.
//! 5. Apply Docker Hub single-name normalization
//!    (`nginx` → `library/nginx`) iff the matched mapping's
//!    `upstream_url` host is Docker Hub
//!    (`registry-1.docker.io` / `index.docker.io` / `docker.io`).
//!
//! # Cache shape
//!
//! `Arc<ArcSwap<HashMap<Uuid, Vec<RepositoryUpstreamMapping>>>>`.
//! Pre-grouped by `repository_id` so the request path's HashMap
//! lookup is O(1) and the per-repo scan is over a small Vec
//! (deployments expect O(1–5) mappings per repo).
//!
//! # No I/O at construction
//!
//! `CachingResolver::new` takes a pre-built map; no DB access. The
//! caller (composition root) is responsible for priming the cache
//! via [`CachingResolver::reload`] before serving requests.
//! Construction-time DB access would force the constructor to be
//! `async-fallible`, fragmenting `AppContext` build paths in tests.
//!
//! See `docs/architecture/how-to/oci-pull-through.md`.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::upstream_resolver::UpstreamResolver;

/// Snapshot-backed [`UpstreamResolver`].
///
/// Construct with [`CachingResolver::new`] (empty map) or
/// [`CachingResolver::with_snapshot`] (pre-populated). Callers
/// repopulate via [`CachingResolver::reload`] from the background
/// refresh task.
pub struct CachingResolver {
    snapshot: Arc<ArcSwap<HashMap<Uuid, Vec<RepositoryUpstreamMapping>>>>,
}

impl CachingResolver {
    /// Build a resolver with an empty snapshot. The composition root
    /// typically calls [`Self::reload`] before publishing the
    /// resolver onto `AppContext`.
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    /// Build a resolver pre-populated from an explicit list of
    /// mappings. Used by tests to skip the DB-backed prime path.
    pub fn with_snapshot(mappings: Vec<RepositoryUpstreamMapping>) -> Self {
        let resolver = Self::new();
        resolver.swap(group_by_repo(mappings));
        resolver
    }

    /// Atomically replace the snapshot. Lock-free — readers in flight
    /// continue to see the old map until they re-`load()`.
    pub fn swap(&self, new_snapshot: HashMap<Uuid, Vec<RepositoryUpstreamMapping>>) {
        self.snapshot.store(Arc::new(new_snapshot));
    }

    /// Re-prime the snapshot from the persistence layer. Returns the
    /// number of mappings loaded so the background task can include
    /// it in its `tracing::info!` line.
    pub fn reload(&self, mappings: Vec<RepositoryUpstreamMapping>) -> usize {
        let n = mappings.len();
        self.swap(group_by_repo(mappings));
        n
    }

    /// Return the current `(repository_count,
    /// total_mapping_count)`. Public so the composition root can log
    /// the cache size after the refresh task primes it; tests use
    /// the same surface to assert reload semantics.
    pub fn snapshot_size(&self) -> (usize, usize) {
        let snap = self.snapshot.load();
        let mappings = snap.values().map(Vec::len).sum();
        (snap.len(), mappings)
    }
}

impl Default for CachingResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Group mappings by `repository_id` for O(1) per-request lookup.
fn group_by_repo(
    mappings: Vec<RepositoryUpstreamMapping>,
) -> HashMap<Uuid, Vec<RepositoryUpstreamMapping>> {
    let mut grouped: HashMap<Uuid, Vec<RepositoryUpstreamMapping>> = HashMap::new();
    for m in mappings {
        grouped.entry(m.repository_id).or_default().push(m);
    }
    grouped
}

impl UpstreamResolver for CachingResolver {
    fn resolve(
        &self,
        repo_id: Uuid,
        requested_name: &str,
    ) -> Option<(RepositoryUpstreamMapping, String)> {
        let snap = self.snapshot.load();
        let mappings = snap.get(&repo_id)?;

        // Sort by prefix length desc. The Vec is small (1–5 entries
        // typical) so an O(n log n) per-request sort is cheaper than
        // maintaining a sorted invariant on every cache swap.
        let mut sorted: Vec<&RepositoryUpstreamMapping> = mappings.iter().collect();
        sorted.sort_by_key(|m| std::cmp::Reverse(m.path_prefix.len()));

        for m in sorted {
            if requested_name.starts_with(&m.path_prefix) {
                let stripped = requested_name[m.path_prefix.len()..].to_string();
                let normalised = normalize_for_upstream(&m.upstream_url, &stripped);
                return Some((m.clone(), normalised));
            }
        }
        None
    }
}

/// Apply upstream-specific name normalization.
///
/// Docker Hub single-name images are conventionally written without
/// a namespace (e.g. `nginx`), but the registry API requires the
/// `library/` namespace (e.g. `library/nginx`). The rewrite gate is
/// the upstream URL host — Docker Hub gets the rewrite, every other
/// registry passes the name through unchanged. The auth strategy
/// (`UpstreamAuth::BearerChallenge`) is no longer 1:1 with Docker
/// Hub: GHCR / Quay / GitLab CR / Harbor / Nexus all use bearer
/// challenge too, and they must NOT receive a `library/` infix.
fn normalize_for_upstream(upstream_url: &str, name: &str) -> String {
    if is_docker_hub(upstream_url) && !name.contains('/') && !name.is_empty() {
        return format!("library/{name}");
    }
    name.to_string()
}

/// Returns `true` when `url`'s host is one of Docker Hub's canonical
/// hostnames. Comparison is case-insensitive on the host (URL host
/// matching is case-insensitive per RFC 3986). Malformed URLs and
/// URLs with no host return `false` — only well-formed Docker Hub
/// URLs trigger the rewrite.
fn is_docker_hub(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
        .map(|h| {
            matches!(
                h.as_str(),
                "registry-1.docker.io" | "index.docker.io" | "docker.io"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use hort_domain::ports::repository_upstream_mapping_repository::UpstreamAuth;

    fn mapping(
        repo: Uuid,
        prefix: &str,
        url: &str,
        auth: UpstreamAuth,
    ) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo,
            path_prefix: prefix.into(),
            upstream_url: url.into(),
            upstream_name_prefix: None,
            upstream_auth: auth,
            secret_ref: None,
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    // -- Compile-time port-impl assertion -------------------------------

    #[test]
    fn resolver_implements_port() {
        fn _assert_port<T: UpstreamResolver>() {}
        _assert_port::<CachingResolver>();
    }

    // -- Empty snapshot --------------------------------------------------

    #[test]
    fn empty_snapshot_yields_none() {
        let resolver = CachingResolver::new();
        assert!(resolver.resolve(Uuid::new_v4(), "any").is_none());
    }

    #[test]
    fn unknown_repo_yields_none() {
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            Uuid::new_v4(),
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::Anonymous,
        )]);
        // Different repo_id — no match.
        assert!(resolver.resolve(Uuid::new_v4(), "ghcr/foo").is_none());
    }

    // -- Longest-prefix-match -------------------------------------------

    /// Two mappings, `dockerhub/` and `dockerhub/library/`. Request
    /// `dockerhub/library/nginx` matches the longer prefix.
    #[test]
    fn longest_prefix_wins_when_multiple_match() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![
            mapping(
                repo,
                "dockerhub/",
                "https://registry-1.docker.io",
                UpstreamAuth::BearerChallenge,
            ),
            mapping(
                repo,
                "dockerhub/library/",
                "https://library-mirror.example.com",
                UpstreamAuth::Anonymous,
            ),
        ]);

        let (m, stripped) = resolver
            .resolve(repo, "dockerhub/library/nginx")
            .expect("longest prefix matches");
        assert_eq!(m.upstream_url, "https://library-mirror.example.com");
        assert_eq!(stripped, "nginx");
    }

    /// Empty-prefix mapping is the catch-all — it only matches when
    /// no more-specific prefix does.
    #[test]
    fn empty_prefix_acts_as_catch_all() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![
            mapping(
                repo,
                "",
                "https://default.example.com",
                UpstreamAuth::Anonymous,
            ),
            mapping(repo, "ghcr/", "https://ghcr.io", UpstreamAuth::Anonymous),
        ]);

        // ghcr/ matches; not the catch-all.
        let (m, _) = resolver.resolve(repo, "ghcr/foo/bar").unwrap();
        assert_eq!(m.upstream_url, "https://ghcr.io");

        // No more-specific prefix — falls through to catch-all.
        let (m, stripped) = resolver.resolve(repo, "alpine/3.19").unwrap();
        assert_eq!(m.upstream_url, "https://default.example.com");
        assert_eq!(stripped, "alpine/3.19");
    }

    /// Single-upstream (only an empty-prefix mapping) returns the
    /// requested name unchanged.
    #[test]
    fn single_upstream_passes_name_through() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo,
            "",
            "https://upstream.example.com",
            UpstreamAuth::Anonymous,
        )]);
        let (_, stripped) = resolver.resolve(repo, "any/path/here").unwrap();
        assert_eq!(stripped, "any/path/here");
    }

    // -- Docker Hub library/ rewrite ------------------------------------

    /// `BearerChallenge` + single-name image → `library/<name>`.
    #[test]
    fn docker_hub_bearer_challenge_rewrites_single_name_images() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo,
            "dockerhub/",
            "https://registry-1.docker.io",
            UpstreamAuth::BearerChallenge,
        )]);
        let (_, stripped) = resolver.resolve(repo, "dockerhub/nginx").unwrap();
        assert_eq!(stripped, "library/nginx");
    }

    /// `BearerChallenge` + already-namespaced image → pass-through.
    #[test]
    fn docker_hub_bearer_challenge_leaves_namespaced_images_alone() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo,
            "dockerhub/",
            "https://registry-1.docker.io",
            UpstreamAuth::BearerChallenge,
        )]);
        let (_, stripped) = resolver.resolve(repo, "dockerhub/myorg/myimg").unwrap();
        assert_eq!(stripped, "myorg/myimg");
    }

    /// Non-DockerHub upstream + single-name image → no rewrite.
    /// Generic mirrors don't get the namespace prefix.
    #[test]
    fn anonymous_upstream_does_not_rewrite_single_name() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo,
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::Anonymous,
        )]);
        let (_, stripped) = resolver.resolve(repo, "ghcr/nginx").unwrap();
        assert_eq!(stripped, "nginx");
    }

    /// `BearerChallenge` against a non-Docker-Hub upstream (e.g.
    /// GHCR) does NOT trigger the `library/` rewrite. The gate is
    /// upstream-URL host, not auth variant.
    #[test]
    fn non_docker_hub_bearer_challenge_does_not_rewrite_single_name() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo,
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::BearerChallenge,
        )]);
        let (_, stripped) = resolver.resolve(repo, "ghcr/nginx").unwrap();
        assert_eq!(stripped, "nginx");
    }

    // -- is_docker_hub helper -------------------------------------------

    /// All three canonical Docker Hub hostnames count as Docker Hub.
    #[test]
    fn is_docker_hub_recognises_canonical_hostnames() {
        assert!(is_docker_hub("https://registry-1.docker.io"));
        assert!(is_docker_hub("https://index.docker.io"));
        assert!(is_docker_hub("https://docker.io"));
    }

    /// Host comparison is case-insensitive (RFC 3986).
    #[test]
    fn is_docker_hub_is_case_insensitive_on_host() {
        assert!(is_docker_hub("https://Registry-1.Docker.io"));
        assert!(is_docker_hub("HTTPS://INDEX.DOCKER.IO"));
        assert!(is_docker_hub("http://Docker.IO/"));
    }

    /// Other registries are not Docker Hub.
    #[test]
    fn is_docker_hub_rejects_other_registries() {
        assert!(!is_docker_hub("https://ghcr.io"));
        assert!(!is_docker_hub("https://quay.io"));
        assert!(!is_docker_hub("https://harbor.example.com"));
    }

    /// Lookalike hostnames that are NOT Docker Hub do not match.
    /// Belt-and-braces against typo-confusion attacks.
    #[test]
    fn is_docker_hub_rejects_lookalike_hostnames() {
        assert!(!is_docker_hub("https://docker.io.evil.example"));
        assert!(!is_docker_hub("https://notdocker.io"));
        assert!(!is_docker_hub("https://docker-io"));
    }

    /// Malformed URLs return `false` rather than panicking.
    #[test]
    fn is_docker_hub_rejects_malformed_urls() {
        assert!(!is_docker_hub("not a url"));
        assert!(!is_docker_hub(""));
        assert!(!is_docker_hub("://broken"));
    }

    /// URLs with no host (e.g. `data:` URIs, `file:///path` on
    /// some platforms) return `false`.
    #[test]
    fn is_docker_hub_rejects_urls_with_no_host() {
        // `data:` URIs parse but carry no host.
        assert!(!is_docker_hub("data:text/plain,hello"));
    }

    // -- Cache reload ---------------------------------------------------

    /// `reload` swaps the snapshot atomically. After reload, queries
    /// hit the new mapping.
    #[test]
    fn reload_replaces_snapshot_atomically() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let resolver = CachingResolver::with_snapshot(vec![mapping(
            repo_a,
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::Anonymous,
        )]);
        // Pre-reload: repo_a hits, repo_b misses.
        assert!(resolver.resolve(repo_a, "ghcr/foo").is_some());
        assert!(resolver.resolve(repo_b, "ghcr/foo").is_none());

        // Reload with a different mapping.
        let n = resolver.reload(vec![mapping(
            repo_b,
            "quay/",
            "https://quay.io",
            UpstreamAuth::Anonymous,
        )]);
        assert_eq!(n, 1);

        // Post-reload: repo_a no longer hits; repo_b hits.
        assert!(resolver.resolve(repo_a, "ghcr/foo").is_none());
        let (m, _) = resolver.resolve(repo_b, "quay/foo").unwrap();
        assert_eq!(m.upstream_url, "https://quay.io");
    }

    /// Reload from empty to non-empty primes the cache (the prod
    /// composition-root pattern).
    #[test]
    fn reload_from_empty_primes_cache() {
        let repo = Uuid::new_v4();
        let resolver = CachingResolver::new();
        assert_eq!(resolver.snapshot_size(), (0, 0));

        resolver.reload(vec![
            mapping(repo, "ghcr/", "https://ghcr.io", UpstreamAuth::Anonymous),
            mapping(repo, "quay/", "https://quay.io", UpstreamAuth::Anonymous),
        ]);
        assert_eq!(resolver.snapshot_size(), (1, 2));
    }

    // -- Trait-object plumbing ------------------------------------------

    /// Compile-time check that the resolver wires through a trait
    /// object on `AppContext`-shaped state.
    #[test]
    fn resolver_works_through_trait_object() {
        let repo = Uuid::new_v4();
        let resolver: Arc<dyn UpstreamResolver> =
            Arc::new(CachingResolver::with_snapshot(vec![mapping(
                repo,
                "ghcr/",
                "https://ghcr.io",
                UpstreamAuth::Anonymous,
            )]));
        let (m, stripped) = resolver.resolve(repo, "ghcr/foo").unwrap();
        assert_eq!(m.upstream_url, "https://ghcr.io");
        assert_eq!(stripped, "foo");
    }
}
