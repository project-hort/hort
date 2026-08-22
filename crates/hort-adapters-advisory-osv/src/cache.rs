//! Cache-key construction for the OSV advisory cache.
//!
//! The advisory cache is per-(ecosystem, name, version) — the same
//! granularity as an OSV `querybatch` query input. We hash the three
//! inputs together and prefix with `advisory:osv:` so the key:
//!
//! 1. routes to the **evictable** Redis (losing the cache forces a
//!    re-fetch from `api.osv.dev`, which is the correct fallback);
//! 2. cannot collide across ecosystems (`(npm, foo, 1.0)` and
//!    `(PyPI, foo, 1.0)` produce different SHA-256 inputs).
//!
//! The hash is content-derived only — we do not need a cryptographic
//! trust boundary here. SHA-256 is used because it is already in the
//! workspace; `blake3` would also be fine.

use sha2::{Digest, Sha256};

#[cfg(test)]
use hort_domain::types::Ecosystem;

/// Keyspace prefix for OSV advisory cache entries.
///
/// Registered as evictable in `hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY`.
pub(crate) const ADVISORY_OSV_PREFIX: &str = "advisory:osv:";

/// SHA-256 (hex) of the (ecosystem, name, version) triple — i.e. the
/// suffix that follows [`ADVISORY_OSV_PREFIX`] in the full cache key.
///
/// The hash inputs are concatenated with a single 0x1F (Unit Separator)
/// byte between fields so two distinct triples cannot accidentally hash
/// to the same digest via boundary ambiguity (e.g. `(npm, "foo|bar",
/// "1")` vs `(npm, "foo", "bar|1")`).
///
/// The full key is constructed at the `EphemeralStore::put` / `get`
/// call sites in `lib.rs` via `format!("advisory:osv:{}", ...)` —
/// the literal prefix at the call site lets the `ephemeral_keyspace_exhaustive`
/// guard (`crates/hort-server/tests/ephemeral_keyspace_exhaustive.rs`)
/// statically resolve which keyspace this adapter writes to. If you
/// move the prefix back into this function you must add
/// `"advisory:osv:"` to `FORWARD_REGISTERED_PREFIXES` (or extend the
/// walker to follow cross-file `fn` definitions).
pub(crate) fn cache_key_hash(eco: &str, name: &str, version: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(eco.as_bytes());
    hasher.update([0x1F]);
    hasher.update(name.as_bytes());
    hasher.update([0x1F]);
    // Distinguish "version absent" from "version present and empty".
    match version {
        Some(v) => {
            hasher.update(b"v=");
            hasher.update(v.as_bytes());
        }
        None => hasher.update(b"v=*"),
    }
    hex_of(hasher.finalize().as_slice())
}

/// Full cache key: [`ADVISORY_OSV_PREFIX`] + [`cache_key_hash`].
///
/// Wire shape: `advisory:osv:<hex-sha256-of-eco|name|version>`.
///
/// Production code in `lib.rs` calls [`cache_key_hash`] directly and
/// applies the prefix at the call site (keyspace-walker requirement —
/// see [`cache_key_hash`]'s rustdoc). `build_cache_key` survives for
/// tests that pin the full-key shape and for the `cache_lookup` path
/// which is read-only (the walker doesn't scan reads).
pub(crate) fn build_cache_key(eco: &str, name: &str, version: Option<&str>) -> String {
    format!(
        "{}{}",
        ADVISORY_OSV_PREFIX,
        cache_key_hash(eco, name, version)
    )
}

/// Keyspace prefix for hydrated full-record entries.
///
/// A sub-namespace of [`ADVISORY_OSV_PREFIX`], so it inherits the same
/// evictable registry entry — the registry matches on prefix and
/// `advisory:osv:vuln:` starts with `advisory:osv:`.
pub(crate) const ADVISORY_OSV_VULN_PREFIX: &str = "advisory:osv:vuln:";

/// SHA-256 (hex) of the `(id, modified)` pair — the suffix that
/// follows [`ADVISORY_OSV_VULN_PREFIX`] in a hydrated-record cache key.
///
/// **`modified` is part of the key on purpose.** It is the exact
/// invalidation signal `querybatch` hands back with every id: when OSV
/// edits a record it moves `modified`, which shifts the key and forces
/// a re-fetch; when OSV has not touched the record the key is stable
/// and the cached copy stays valid for its full TTL. Keying on `id`
/// alone would serve a stale severity for up to the TTL after OSV
/// rescored an advisory.
///
/// Same 0x1F (Unit Separator) field separator as
/// [`cache_key_hash`] so `("A-1", "2026-01")` and `("A", "1-2026-01")`
/// cannot collide.
///
/// As with [`cache_key_hash`], the literal prefix is applied at the
/// `EphemeralStore::put` call site (in `hydrate.rs`) so the
/// `ephemeral_keyspace_exhaustive` guard can statically resolve it.
pub(crate) fn vuln_cache_key_hash(id: &str, modified: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update([0x1F]);
    match modified {
        Some(m) => {
            hasher.update(b"m=");
            hasher.update(m.as_bytes());
        }
        None => hasher.update(b"m=*"),
    }
    hex_of(hasher.finalize().as_slice())
}

/// Full hydrated-record cache key: [`ADVISORY_OSV_VULN_PREFIX`] +
/// [`vuln_cache_key_hash`].
///
/// Read side and tests only — the write site applies the prefix
/// inline (see [`vuln_cache_key_hash`]).
pub(crate) fn build_vuln_cache_key(id: &str, modified: Option<&str>) -> String {
    format!(
        "{}{}",
        ADVISORY_OSV_VULN_PREFIX,
        vuln_cache_key_hash(id, modified)
    )
}

/// Lowercase hex encoding of a digest. `std` has no one-liner for this
/// without an extra dependency.
fn hex_of(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0F));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!("nibble out of range"),
    }
}

/// Convenience wrapper: build the cache key from an `Ecosystem` enum
/// directly. Returns `None` for ecosystems OSV does not cover (the
/// caller is expected to filter these before lookup).
///
/// Currently only consumed by tests, but kept on the crate-private
/// surface so the cache-key boundary check is exercised against the
/// real `Ecosystem` enum (not just hand-rolled OSV strings) — protects
/// future contributors who plumb a new `Ecosystem` variant from
/// silently dropping it on the cache path.
#[cfg(test)]
pub(crate) fn build_cache_key_for_component(
    eco: &Ecosystem,
    name: &str,
    version: Option<&str>,
) -> Option<String> {
    let osv_eco = crate::ecosystem::osv_ecosystem_for(eco)?;
    Some(build_cache_key(osv_eco, name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_starts_with_advisory_osv_prefix() {
        let key = build_cache_key("npm", "lodash", Some("4.17.20"));
        assert!(
            key.starts_with(ADVISORY_OSV_PREFIX),
            "key must carry advisory:osv: prefix: {key}"
        );
    }

    #[test]
    fn cache_key_is_deterministic_for_same_input() {
        let a = build_cache_key("npm", "lodash", Some("4.17.20"));
        let b = build_cache_key("npm", "lodash", Some("4.17.20"));
        assert_eq!(a, b, "same input must produce same key");
    }

    #[test]
    fn cache_key_differs_when_ecosystem_differs() {
        let a = build_cache_key("npm", "foo", Some("1.0.0"));
        let b = build_cache_key("PyPI", "foo", Some("1.0.0"));
        assert_ne!(
            a, b,
            "ecosystems must produce distinct keys to prevent collisions"
        );
    }

    #[test]
    fn cache_key_differs_when_name_differs() {
        let a = build_cache_key("npm", "foo", Some("1.0.0"));
        let b = build_cache_key("npm", "bar", Some("1.0.0"));
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_differs_when_version_differs() {
        let a = build_cache_key("npm", "foo", Some("1.0.0"));
        let b = build_cache_key("npm", "foo", Some("1.0.1"));
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_distinguishes_present_empty_version_from_absent_version() {
        let absent = build_cache_key("npm", "foo", None);
        let empty = build_cache_key("npm", "foo", Some(""));
        assert_ne!(
            absent, empty,
            "None vs Some(\"\") must produce distinct keys"
        );
    }

    #[test]
    fn cache_key_avoids_separator_collision() {
        // Both inputs reduce to "npm" + "foo" + "bar" + "1" if the
        // separator weren't in place. Confirm they differ.
        let a = build_cache_key("npm", "foo|bar", Some("1"));
        let b = build_cache_key("npm", "foo", Some("bar|1"));
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_hex_is_64_chars_after_prefix() {
        let key = build_cache_key("npm", "lodash", Some("4.17.20"));
        let suffix = key.strip_prefix(ADVISORY_OSV_PREFIX).expect("prefix");
        assert_eq!(
            suffix.len(),
            64,
            "SHA-256 hex must be 64 lowercase chars: got {suffix}"
        );
        assert!(
            suffix.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "hex must be lowercase: {suffix}"
        );
    }

    #[test]
    fn cache_key_for_component_returns_none_for_unsupported_ecosystem() {
        let key = build_cache_key_for_component(
            &Ecosystem::Unknown("rare-format".into()),
            "foo",
            Some("1"),
        );
        assert!(key.is_none(), "Unknown ecosystem must return None");
    }

    #[test]
    fn cache_key_for_component_yields_npm_label_for_npm_variant() {
        let from_enum = build_cache_key_for_component(&Ecosystem::Npm, "lodash", Some("4.17.20"))
            .expect("npm is supported");
        let direct = build_cache_key("npm", "lodash", Some("4.17.20"));
        assert_eq!(
            from_enum, direct,
            "Ecosystem::Npm must map to the same string the direct path uses"
        );
    }

    // -----------------------------------------------------------------------
    // Hydrated-record cache key — keyed on (id, modified)
    // -----------------------------------------------------------------------

    #[test]
    fn vuln_cache_key_starts_with_advisory_osv_vuln_prefix() {
        let key = build_vuln_cache_key("RUSTSEC-2023-0071", Some("2026-04-25T06:45:06.122559Z"));
        assert!(
            key.starts_with(ADVISORY_OSV_VULN_PREFIX),
            "key must carry the advisory:osv:vuln: prefix: {key}"
        );
        // Sub-namespace of the registered evictable keyspace.
        assert!(key.starts_with(ADVISORY_OSV_PREFIX));
    }

    #[test]
    fn vuln_cache_key_changes_when_modified_changes() {
        // The whole point of the (id, modified) key: OSV rescoring a
        // record moves `modified`, which must shift the key so the
        // stale severity cannot be served for the rest of the TTL.
        let before = build_vuln_cache_key("RUSTSEC-2023-0071", Some("2026-04-25T06:45:06Z"));
        let after = build_vuln_cache_key("RUSTSEC-2023-0071", Some("2026-05-01T00:00:00Z"));
        assert_ne!(
            before, after,
            "a changed `modified` must invalidate the hydrated record"
        );
    }

    #[test]
    fn vuln_cache_key_is_stable_for_same_id_and_modified() {
        let a = build_vuln_cache_key("GHSA-xxxx", Some("2026-01-01T00:00:00Z"));
        let b = build_vuln_cache_key("GHSA-xxxx", Some("2026-01-01T00:00:00Z"));
        assert_eq!(a, b);
    }

    #[test]
    fn vuln_cache_key_differs_when_id_differs() {
        let a = build_vuln_cache_key("GHSA-aaaa", Some("2026-01-01T00:00:00Z"));
        let b = build_vuln_cache_key("GHSA-bbbb", Some("2026-01-01T00:00:00Z"));
        assert_ne!(a, b);
    }

    #[test]
    fn vuln_cache_key_distinguishes_absent_modified_from_present() {
        let absent = build_vuln_cache_key("GHSA-xxxx", None);
        let empty = build_vuln_cache_key("GHSA-xxxx", Some(""));
        assert_ne!(absent, empty, "None vs Some(\"\") must be distinct keys");
    }

    #[test]
    fn vuln_cache_key_avoids_separator_collision() {
        let a = build_vuln_cache_key("A-1", Some("2026-01"));
        let b = build_vuln_cache_key("A", Some("1-2026-01"));
        assert_ne!(a, b);
    }

    #[test]
    fn vuln_cache_key_hex_is_64_chars_after_prefix() {
        let key = build_vuln_cache_key("GHSA-xxxx", Some("2026-01-01T00:00:00Z"));
        let suffix = key.strip_prefix(ADVISORY_OSV_VULN_PREFIX).expect("prefix");
        assert_eq!(suffix.len(), 64, "SHA-256 hex must be 64 chars: {suffix}");
        assert!(suffix.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn hex_nibble_round_trip_covers_full_range() {
        for n in 0u8..=15 {
            let c = hex_nibble(n);
            let back = c.to_digit(16).expect("hex digit");
            assert_eq!(back as u8, n);
        }
    }
}
