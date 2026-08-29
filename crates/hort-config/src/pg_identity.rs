//! Version-stamped Postgres `application_name` identity, shared by
//! `hort-server` and `hort-worker` connection pools.
//!
//! Every hort Postgres connection sets `application_name =
//! "hort-{role}/<workspace-version>"` so `pg_stat_activity` can answer
//! "which release is this client running" without an out-of-band
//! inventory. The runtime fleet fence in `hort-server migrate` (backlog
//! 145, ADR 0030 amendment (c)) reads exactly this string back to decide
//! whether an older fleet member is still connected before a scheduled
//! contraction applies.
//!
//! Lives next to [`crate::user_agent`] for the same reason: a single,
//! version-stamped identity shared across every connecting crate instead
//! of drifting into per-adapter hardcoded strings. Zero I/O — the
//! workspace version comes from `CARGO_PKG_VERSION`, identical across
//! every crate here (`version.workspace = true`).

/// `hort-server`'s role segment.
pub const SERVER_ROLE: &str = "server";
/// `hort-worker`'s role segment.
pub const WORKER_ROLE: &str = "worker";

/// Build `hort-{role}/<workspace-version>`, e.g. `hort-server/0.12.2-dev`.
pub fn pg_application_name(role: &str) -> String {
    format!("hort-{role}/{}", env!("CARGO_PKG_VERSION"))
}

/// One `pg_stat_activity.application_name` value, decomposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedApplicationName {
    pub role: String,
    /// `None` for a hort-shaped name with no `/version` segment — a
    /// client that predates this identity scheme. Fail-closed callers
    /// must treat this the same as an older version.
    pub version: Option<String>,
}

/// Parse a `pg_stat_activity.application_name` value. Returns `None`
/// when `name` is not hort-shaped (`hort-*`) at all — such clients are
/// unrelated to the hort fleet and out of scope for the fence.
pub fn parse_pg_application_name(name: &str) -> Option<ParsedApplicationName> {
    let rest = name.strip_prefix("hort-")?;
    match rest.split_once('/') {
        Some((role, version)) if !version.is_empty() => Some(ParsedApplicationName {
            role: role.to_string(),
            version: Some(version.to_string()),
        }),
        Some((role, _empty_version)) => Some(ParsedApplicationName {
            role: role.to_string(),
            version: None,
        }),
        None => Some(ParsedApplicationName {
            role: rest.to_string(),
            version: None,
        }),
    }
}

/// The `major.minor.patch` core of a version string, with any
/// pre-release/build suffix dropped — mirrors the expand/contract
/// guard's `VersionCore` ordering rule (`crates/hort-app/tests/expand_contract_guard.rs`):
/// a `X.Y.Z-dev` tree is working towards `X.Y.Z`, so its core sorts as
/// `X.Y.Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionCore {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

/// Parse the `X.Y.Z` core of a version string, ignoring any `-pre` /
/// `+build` suffix. Returns `None` on any non-numeric or missing
/// component — fail-closed callers treat an unparseable version as
/// unknown/older.
pub fn parse_version_core(raw: &str) -> Option<VersionCore> {
    let core = raw.split(['-', '+']).next().unwrap_or(raw);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(VersionCore {
        major,
        minor,
        patch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_application_name_is_role_prefixed_and_versioned() {
        let name = pg_application_name(SERVER_ROLE);
        assert!(
            name.starts_with("hort-server/"),
            "unexpected shape: {name:?}"
        );
        let version = name.strip_prefix("hort-server/").expect("checked above");
        assert!(
            parse_version_core(version).is_some(),
            "version segment must parse: {version:?}"
        );
    }

    #[test]
    fn worker_role_is_distinct_from_server() {
        assert_ne!(
            pg_application_name(SERVER_ROLE),
            pg_application_name(WORKER_ROLE)
        );
        assert!(pg_application_name(WORKER_ROLE).starts_with("hort-worker/"));
    }

    #[test]
    fn parse_round_trips_a_built_name() {
        let name = pg_application_name(SERVER_ROLE);
        let parsed = parse_pg_application_name(&name).expect("hort-shaped");
        assert_eq!(parsed.role, "server");
        assert_eq!(parsed.version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn parse_treats_unversioned_hort_shaped_name_as_no_version() {
        let parsed = parse_pg_application_name("hort-server").expect("hort-shaped");
        assert_eq!(parsed.role, "server");
        assert_eq!(parsed.version, None);

        // A trailing empty version segment (`hort-server/`) is the same
        // fail-closed "unversioned" case, not a parse error.
        let parsed = parse_pg_application_name("hort-server/").expect("hort-shaped");
        assert_eq!(parsed.role, "server");
        assert_eq!(parsed.version, None);
    }

    #[test]
    fn parse_rejects_non_hort_names() {
        assert_eq!(parse_pg_application_name("psql"), None);
        assert_eq!(parse_pg_application_name(""), None);
        assert_eq!(parse_pg_application_name("hortonworks/1.0"), None);
    }

    #[test]
    fn version_core_drops_prerelease_and_build_suffix() {
        assert_eq!(
            parse_version_core("0.12.2-dev"),
            parse_version_core("0.12.2")
        );
        assert_eq!(
            parse_version_core("1.2.3+build.7"),
            Some(VersionCore {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
    }

    #[test]
    fn version_core_orders_by_tuple() {
        let older = parse_version_core("0.11.0").expect("parses");
        let newer = parse_version_core("0.12.2-dev").expect("parses");
        assert!(older < newer);
    }

    #[test]
    fn version_core_rejects_malformed_input() {
        assert_eq!(parse_version_core("not-a-version"), None);
        assert_eq!(parse_version_core("1.2"), None);
        assert_eq!(parse_version_core("1.2.3.4"), None);
    }
}
