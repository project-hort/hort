//! Canonical outbound HTTP `User-Agent` identity for hort.
//!
//! [`DEFAULT_USER_AGENT`] is the single source of truth for the
//! `User-Agent` every hort process sends on outbound HTTP — upstream
//! package-registry pull-through, OSV advisory fetches, the Sigstore
//! trusted-root refresh, OIDC/JWKS, webhooks. A non-empty UA is required by
//! some registries (crates.io returns `403` without one) and the `(+url)`
//! contact pointer lets upstream operators reach the project.
//!
//! It lives here — next to [`crate::extra_ca`], the other cross-adapter HTTP
//! primitive — so every reqwest-building adapter shares one version-stamped
//! identity instead of drifting into per-adapter hardcoded strings. The
//! version is this workspace's shared `CARGO_PKG_VERSION` (every crate
//! carries `version.workspace = true`), so the string is identical no matter
//! which crate references it. A bare `&'static str` honours this crate's
//! no-`reqwest` charter.
//!
//! `hort-adapters-upstream-http` layers an operator override
//! (`HORT_UPSTREAM_USER_AGENT`) on top of this default for the
//! registry-pull-through path specifically; the default identity itself is
//! uniform across every outbound path.

/// The process-wide default outbound `User-Agent`:
/// `hort/<workspace-version> (+<project-url>)`.
pub const DEFAULT_USER_AGENT: &str = concat!(
    "hort/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/project-hort/hort)"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_user_agent_identifies_hort_with_version_and_contact() {
        assert!(
            DEFAULT_USER_AGENT.starts_with("hort/"),
            "must identify hort: {DEFAULT_USER_AGENT:?}"
        );
        // A version segment follows the slash (crates.io rejects an empty UA;
        // upstream operators key rate limits off a stable, versioned token).
        let after = DEFAULT_USER_AGENT
            .strip_prefix("hort/")
            .expect("checked starts_with above");
        assert!(
            after.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "expected a version after 'hort/', got {DEFAULT_USER_AGENT:?}"
        );
        // A contact pointer for upstream operators.
        assert!(
            DEFAULT_USER_AGENT.contains("(+https://"),
            "expected a (+url) contact pointer: {DEFAULT_USER_AGENT:?}"
        );
    }
}
