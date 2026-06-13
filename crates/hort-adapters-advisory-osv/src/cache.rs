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
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        // Lowercase hex; std doesn't have a one-liner for this without
        // an extra dep, so do it inline.
        let hi = byte >> 4;
        let lo = byte & 0x0F;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
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

    #[test]
    fn hex_nibble_round_trip_covers_full_range() {
        for n in 0u8..=15 {
            let c = hex_nibble(n);
            let back = c.to_digit(16).expect("hex digit");
            assert_eq!(back as u8, n);
        }
    }
}
