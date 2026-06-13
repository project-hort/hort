//! Per-crate configuration for the OCI HTTP handlers.
//!
//! Owned by the OCI handler surface; never lives on `AppContext` and
//! never reaches the use case layer. When hort extracts per-format HTTP
//! crates (see design discussion), this struct travels with
//! `hort-http-oci` unchanged.
//!
//! # Scope
//!
//! Every knob here is purely about HTTP routing / response shape. If
//! a flag would affect a use case's behaviour, it belongs in
//! `AppContext` (workspace-wide) or a format-specific use case
//! constructor — not here. Use cases must stay format-agnostic.

/// OCI HTTP-layer configuration.
///
/// Threaded from `hort-server::Config` into [`super::oci_routes`] at
/// router-build time. The struct stays intentionally small; additional
/// OCI-specific flags (future: upload session GC age envelope, chunk
/// upload max bytes) will join it here.
#[derive(Debug, Clone)]
pub struct OciHttpConfig {
    /// When `true`, mounts the Docker-legacy global catalog endpoint
    /// `GET /v2/_catalog` that aggregates qualified image names
    /// (`<repo_key>/<name>`) across visible repositories. Default
    /// `false` (strict-modern).
    ///
    /// # Why default-off
    ///
    /// The global catalog is a registry-wide enumeration surface —
    /// a known reconnaissance target. Default-off means operators opt
    /// in consciously, usually because they need Docker Hub client
    /// compatibility. Reversing the default later is painful (clients
    /// start depending on it); starting strict and relaxing is easy.
    ///
    /// The modern per-repo catalog `GET /v2/:repo_key/_catalog`
    /// remains available regardless of this flag.
    ///
    /// Configured via `HORT_OCI_LEGACY_CATALOG_ENABLED=true`.
    pub legacy_catalog_enabled: bool,
    /// Per-`(repo, principal)` outstanding-session cap on the OCI
    /// three-phase blob upload. New `POST /v2/<name>/blobs/uploads/`
    /// requests are rejected with `429 Too Many Requests` once the
    /// caller already holds this many open sessions against the same
    /// repository. Configured via `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL`.
    /// Default `32`: enough headroom for legit parallel pushes (multi-arch
    /// image, multi-layer pipeline) while bounding the storage state a
    /// malicious or runaway client can pin until TTL expiry.
    pub max_sessions_per_principal: u32,
}

impl Default for OciHttpConfig {
    fn default() -> Self {
        Self {
            legacy_catalog_enabled: false,
            // Default 32 per audit guidance (DoS session-cap).
            max_sessions_per_principal: 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_legacy_catalog_disabled() {
        // Load-bearing: the default MUST be strict. Flipping this to
        // `true` silently opens the global enumeration endpoint on
        // every deployment that doesn't set the env var — that's the
        // opposite of what an operator expects when leaving config
        // unset.
        let c = OciHttpConfig::default();
        assert!(!c.legacy_catalog_enabled);
    }

    #[test]
    fn default_max_sessions_per_principal_is_32() {
        // The default cap MUST match the audit guidance — flipping it
        // changes the DoS posture across every deployment that doesn't
        // set the env var. A test here pins the catalogued default.
        let c = OciHttpConfig::default();
        assert_eq!(c.max_sessions_per_principal, 32);
    }
}
