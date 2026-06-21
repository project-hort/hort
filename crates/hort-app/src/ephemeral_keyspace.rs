//! # Ephemeral keyspace classification
//!
//! The routing-primitive data types and the
//! single-source-of-truth registry that maps every `EphemeralStore`
//! key prefix to one of two operational classes:
//!
//! - **Evictable** — caches whose loss is recoverable by re-fetching
//!   from upstream or re-computing. Routed (in production) to a Redis
//!   instance configured with `maxmemory-policy=allkeys-lru`.
//! - **Durable** — stateful records and security counters whose loss
//!   has user-visible consequences (failed upload, defense-in-depth
//!   tier degradation). Routed to a Redis instance configured with
//!   `maxmemory-policy=noeviction`.
//!
//! ## Purity
//!
//! This module imports nothing from `tokio`, `tracing`, `sqlx`,
//! `redis`, or any adapter crate. It is pure data and pure functions,
//! so it can be embedded in tests, the metric wrapper, and the
//! composition root without dragging async runtimes or I/O along.

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum EphemeralKeyspaceClass {
    /// Caches whose loss is recoverable by re-fetching from upstream
    /// or re-computing. Routed to the evictable Redis (recommended
    /// `maxmemory-policy=allkeys-lru`).
    Evictable,
    /// Stateful records and security counters whose loss has user-
    /// visible consequences (failed upload, defense-in-depth tier
    /// degradation). Routed to the durable Redis (recommended
    /// `maxmemory-policy=noeviction`).
    Durable,
}

impl EphemeralKeyspaceClass {
    /// Lowercase-snake label for `class={...}` metric series.
    ///
    /// `docs/metrics-catalog.md` locks the closed taxonomy
    /// — the two return values here are the only legal values of the
    /// `class` Prometheus label.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Evictable => "evictable",
            Self::Durable => "durable",
        }
    }
}

/// Single source of truth for prefix → class mapping.
///
/// Every entry is reachable from at least
/// one `EphemeralStore::put*` / `compare_and_swap` / `extend_ttl` /
/// `try_increment_counter` call site in the workspace; the
/// keyspace-exhaustiveness integration test
/// (`ephemeral_keyspace_exhaustive`) is the CI gate that keeps this
/// true.
///
/// **Do not deduplicate `pat-attempt:` and `pat-attempt-counter:`** —
/// the two prefixes are siblings, NOT one-prefixes-the-other. Position
/// 11 differs: `:` versus `-`. The boundary test in this module's
/// `tests` block exists precisely to prevent a future contributor from
/// "simplifying" the registry by collapsing them.
pub const KEYSPACE_REGISTRY: &[(&str, EphemeralKeyspaceClass)] = &[
    // Format-specific upstream caches.
    // Cargo upstream sparse-index PROJECTION cache (ADR 0026).
    // Replaced `cargo_index:` — the entry now holds the small serialized
    // `Vec<CargoVersionLine>` projection (versions + cksum/yanked/deps/…),
    // NOT the raw NDJSON body. The raw body moved to the logical-keyed
    // `MetadataMirrorStore` (`meta-mirror/...`, a storage keyspace, not
    // Redis). Evictable: cache loss just re-projects from the mirror or
    // re-fetches upstream. The `_proj` prefix bump means a rolling deploy
    // never reads a pre-amendment `cargo_index:` base64-JSON raw-body
    // envelope. Source: `crates/hort-http-cargo/src/index_cache.rs`.
    ("cargo_index_proj:", EphemeralKeyspaceClass::Evictable),
    // Sibling of `cargo_index_proj:` — Cargo registry `config.json`
    // cache, separate keyspace from the per-crate index entries because
    // the sparse-registry `config.json` has different cache semantics
    // (one record per upstream mapping rather than one per crate).
    // Source: `crates/hort-http-cargo/src/upstream_pull.rs`.
    // **NOT prefix-matched by `cargo_index_proj:`** — position 11 differs
    // (`:` vs `_`), same gotcha as `pat-attempt-counter:` below.
    ("cargo_index_config:", EphemeralKeyspaceClass::Evictable),
    // PyPI upstream simple-index PROJECTION cache (ADR 0026).
    // Replaced `pypi_simple:` — the entry now holds the small
    // serialized `PypiSimpleIndexProjection` (files + sha256/url/
    // requires-python/metadata-sha256), NOT the raw HTML/JSON body, and is
    // FORMAT-INDEPENDENT (the pre-amendment cache held per-format `:html`
    // and `:json` rows; both arms now project to the SAME representation-
    // independent projection under ONE key). The raw body moved to the
    // logical-keyed `MetadataMirrorStore` (`meta-mirror/...`, a storage
    // keyspace, not Redis) under a format-DISTINCT mirror key. Evictable:
    // cache loss just re-projects from the mirror or re-fetches upstream.
    // The `_proj` prefix bump means a rolling deploy never reads a
    // pre-amendment `pypi_simple:` base64-JSON raw-body envelope. Source:
    // `crates/hort-http-pypi/src/simple_index.rs`.
    ("pypi_simple_proj:", EphemeralKeyspaceClass::Evictable),
    // Maven on-demand checksum-sidecar digest cache (ADR 0032 / §6).
    // Memoises the hex digest of a STORED Maven artifact computed on a
    // sidecar GET (`<file>.{sha1,sha512,md5}`). Key shape:
    // `mavensum:{content_hash}:{algorithm}` where `content_hash` is the
    // artifact's CAS SHA-256 (the immutable identity of the bytes) and
    // `algorithm` is the lowercase sidecar token (`sha1`/`sha512`/`md5` —
    // `sha256` is the CAS hash itself, served free without a hash or a
    // cache entry). Evictable: the digest of immutable content is itself
    // immutable, so cache loss costs at most one re-hash, never
    // correctness — exactly the `cargo_index_proj:` recomputable-cache
    // rationale. The cache also bounds a re-hash CPU-amplification vector
    // (repeated `.sha1` GETs of a large blob hash it at most once until
    // eviction). Source: `crates/hort-http-maven/src/sidecar.rs`.
    ("mavensum:", EphemeralKeyspaceClass::Evictable),
    // npm upstream-packument PROJECTION cache (ADR 0026).
    // Replaced `npm_packument_raw:` — the entry now holds the small
    // serialized `NpmProjection` (versions + dist.tarball/integrity/time,
    // dist-tags.latest), NOT the raw body. The raw body moved to the
    // logical-keyed `MetadataMirrorStore` (`meta-mirror/...`, a storage
    // keyspace, not Redis). Evictable: cache loss just re-projects from
    // the mirror or re-fetches upstream. The `_proj` prefix bump means a
    // rolling deploy never reads a pre-amendment `npm_packument_raw:`
    // raw-body entry. Source: `crates/hort-http-npm/src/packument.rs` +
    // `.../upstream_pull.rs`.
    ("npm_packument_proj:", EphemeralKeyspaceClass::Evictable),
    // OSV advisory feed cache. Evictable: cache loss
    // forces a re-fetch from `api.osv.dev`, which is the correct
    // fallback. Source: `crates/hort-adapters-advisory-osv/src/cache.rs`
    // (`build_cache_key` prefixes every entry with `advisory:osv:`).
    ("advisory:osv:", EphemeralKeyspaceClass::Evictable),
    // Pull-through dedup locks + status records (`PullDedup` Layer B).
    ("pulldedup:", EphemeralKeyspaceClass::Evictable),
    // OCI three-phase upload session metadata (~80 B per session).
    // Bytes live on StatefulUploadStagingPort (filesystem); only the
    // record header lands here. Sub-keys observed today:
    // `stateful_upload:oci_v2:{sid}`, `stateful_upload:oci:{sid}`
    // (legacy), `stateful_upload:maven:{sid}`.
    // Source: `crates/hort-http-oci/src/upload_session.rs:117`.
    ("stateful_upload:", EphemeralKeyspaceClass::Durable),
    // Auth event-store throttle keys. The literal
    // key shape today is `auth:event:throttle:{result}:{ip_bucket}`
    // (`crates/hort-app/src/use_cases/authenticate_use_case.rs:269-273`).
    // Registering the head prefix `auth:event:` keeps room for
    // future auth-event sub-keyspaces. Loss is benign (more audit
    // events emitted), but they share the lockout family's Redis
    // so route them with the family.
    ("auth:event:", EphemeralKeyspaceClass::Durable),
    // PAT brute-force lockout. Two SIBLING prefixes —
    // `pat-attempt-counter:` does NOT prefix-match `pat-attempt:`
    // (position 11: `-` vs `:`), so both must be registered.
    // Literals: `crates/hort-app/src/use_cases/pat_validation_use_case.rs:100-106`.
    ("pat-attempt:", EphemeralKeyspaceClass::Durable),
    ("pat-attempt-counter:", EphemeralKeyspaceClass::Durable),
    // OCI per-(repo, principal) upload-session cap counter. Literal from
    // `crates/hort-http-oci/src/upload_session.rs:150-152`.
    ("oci:session_count:", EphemeralKeyspaceClass::Durable),
    // Admin-task invoke idempotency tokens. Written by
    // `hort-http-admin-tasks::handlers::invoke` when the caller supplies an
    // `Idempotency-Key` header; read on the next request with the same key
    // to short-circuit re-enqueue. Durable: loss causes a duplicate job
    // row for the same operator intent within the 5-minute window — an
    // operational nuisance rather than a correctness failure, but still
    // a user-visible consequence (the dedup window the RFC implies is
    // broken). Source:
    // `crates/hort-http-admin-tasks/src/handlers/invoke.rs:IDEM_TASK_PREFIX`.
    ("idem-task:", EphemeralKeyspaceClass::Durable),
    // Per-token `ApiTokenUsed` audit-emit throttle.
    // `put_if_absent` on `token_use:audit:throttle:{token_id}`
    // with a 1h TTL dedups the high-volume per-use audit event to one
    // emit per token per window. Loss is benign (an extra `ApiTokenUsed`
    // audit event is emitted — fail-open, never blocks the auth hot
    // path), exactly the `auth:event:` audit-throttle rationale; routed
    // Durable to share that family's Redis. Source:
    // `crates/hort-app/src/use_cases/pat_validation_use_case.rs:128`
    // (`TOKEN_USE_AUDIT_THROTTLE_PREFIX`).
    ("token_use:audit:throttle:", EphemeralKeyspaceClass::Durable),
    // CliSession access-token `jti` emergency-revocation
    // denylist. `put` on `cli-session-revoked:{jti}` with TTL =
    // remaining-until-`exp`; the validate path consults it with `get`
    // and rejects (401) any revoked `jti` before its `exp`. **Durable**:
    // loss re-permits a revoked-but-not-yet-expired CliSession token —
    // a security regression (the whole reason the denylist exists is to
    // restore AK-side immediate revocation the opaque→JWT cutover would
    // otherwise lose), so it must NOT be on an LRU-evictable backend.
    // Self-expiring (TTL = token `exp`) so the set stays bounded.
    // Source: `crates/hort-app/src/use_cases/api_token_use_case.rs`
    // (`revoke_cli_session`) + `.../authenticate_use_case.rs` (check).
    ("cli-session-revoked:", EphemeralKeyspaceClass::Durable),
];

/// Look up the class of the keyspace a key belongs to. Returns
/// `None` if the key matches no registered prefix — callers treat
/// this as a programming error (a write to an unregistered keyspace).
///
/// The match is the **first** registered prefix that `key` starts
/// with. The registry order is therefore semantically meaningful for
/// any keyspace pair where one prefix prefixes the other; today no
/// such pair exists (`pat-attempt:` and `pat-attempt-counter:` look
/// adjacent but are siblings — see the registry comment block).
pub fn keyspace_class(key: &str) -> Option<EphemeralKeyspaceClass> {
    KEYSPACE_REGISTRY
        .iter()
        .find(|(prefix, _)| key.starts_with(prefix))
        .map(|(_, class)| *class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_metric_label_round_trips_both_variants() {
        assert_eq!(
            EphemeralKeyspaceClass::Evictable.as_metric_label(),
            "evictable"
        );
        assert_eq!(EphemeralKeyspaceClass::Durable.as_metric_label(), "durable");
    }

    #[test]
    fn cargo_index_proj_resolves_to_evictable() {
        // The cargo per-crate index cache holds
        // the projection under `cargo_index_proj:` (was `cargo_index:`).
        assert_eq!(
            keyspace_class("cargo_index_proj:mapping-uuid:se/rd/serde"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    /// Boundary test (load-bearing). `cargo_index_config:` is a
    /// SIBLING of `cargo_index_proj:`, not a sub-prefix: position 11 is
    /// `_` here, `:` in the registry entry above, so `starts_with`
    /// would return `false` if only `cargo_index_proj:` were registered.
    /// This test exists to prevent a future contributor from
    /// "simplifying" the registry by deleting the
    /// `cargo_index_config:` entry. Same gotcha as
    /// `pat_attempt_counter_resolves_via_its_own_entry_not_pat_attempt`.
    #[test]
    fn cargo_index_config_resolves_via_its_own_entry_not_cargo_index() {
        assert_eq!(
            keyspace_class("cargo_index_config:mapping-uuid"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
        // Sanity check — confirm `starts_with` would in fact NOT match
        // `cargo_index_proj:` for `cargo_index_config:...`. If this
        // assertion ever fires, Rust changed its `str::starts_with`
        // semantics and the entire registry approach needs revisiting.
        assert!(
            !"cargo_index_config:mapping-uuid".starts_with("cargo_index_proj:"),
            "regression: cargo_index_config: prefix-matches cargo_index_proj:",
        );
    }

    #[test]
    fn pypi_simple_proj_resolves_to_evictable() {
        // The PyPI simple-index cache
        // holds the projection under the unified, format-independent
        // `pypi_simple_proj:` key (was per-format `pypi_simple:{...}:{html|json}`).
        assert_eq!(
            keyspace_class("pypi_simple_proj:mapping-uuid:requests"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    #[test]
    fn npm_packument_proj_resolves_to_evictable() {
        assert_eq!(
            keyspace_class("npm_packument_proj:mapping-uuid:lodash"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    #[test]
    fn mavensum_resolves_to_evictable() {
        // The Maven on-demand sidecar-digest cache holds the recomputable
        // hex of a stored artifact under
        // `mavensum:{content_hash}:{algorithm}`. Evictable: cache loss
        // costs a re-hash, never correctness.
        assert_eq!(
            keyspace_class(&format!(
                "mavensum:{}:sha1",
                "a".repeat(64) // a 64-hex content hash placeholder
            )),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    #[test]
    fn pulldedup_resolves_to_evictable() {
        assert_eq!(
            keyspace_class("pulldedup:abc123"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    #[test]
    fn advisory_osv_resolves_to_evictable() {
        // Losing the OSV advisory cache forces a
        // re-fetch from api.osv.dev, which is the correct fallback.
        assert_eq!(
            keyspace_class("advisory:osv:abcdef0123456789"),
            Some(EphemeralKeyspaceClass::Evictable),
        );
    }

    #[test]
    fn stateful_upload_resolves_to_durable() {
        // All three production sub-prefixes (oci_v2, oci, maven) are
        // subsumed by the single `stateful_upload:` registry entry.
        assert_eq!(
            keyspace_class("stateful_upload:oci_v2:0123-uuid"),
            Some(EphemeralKeyspaceClass::Durable),
        );
        assert_eq!(
            keyspace_class("stateful_upload:oci:legacy-uuid"),
            Some(EphemeralKeyspaceClass::Durable),
        );
        assert_eq!(
            keyspace_class("stateful_upload:maven:mvn-uuid"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    #[test]
    fn token_use_audit_throttle_resolves_to_durable() {
        // Per-token audit-emit throttle.
        assert_eq!(
            keyspace_class("token_use:audit:throttle:00000000-0000-0000-0000-000000000000"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    #[test]
    fn auth_event_resolves_to_durable() {
        assert_eq!(
            keyspace_class("auth:event:throttle:failed:10.0.0.1"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    #[test]
    fn pat_attempt_resolves_to_durable() {
        assert_eq!(
            keyspace_class("pat-attempt:10.0.0.1"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    /// **Boundary test — load-bearing.**
    ///
    /// `pat-attempt-counter:` is a SIBLING of `pat-attempt:`, NOT a
    /// sub-keyspace. They diverge at position 11 (`-` vs `:`):
    ///
    /// ```text
    ///   pat-attempt:        (12 chars; ':' at index 11)
    ///   pat-attempt-counter:(20 chars; '-' at index 11)
    /// ```
    ///
    /// `"pat-attempt-counter:bucket".starts_with("pat-attempt:")` is
    /// `false`, so the registry MUST contain both prefixes
    /// independently. This test exists to prevent a future
    /// contributor from "simplifying" the registry by deleting one
    /// of the two entries — if either entry is removed, this test
    /// fails loudly.
    #[test]
    fn pat_attempt_counter_resolves_via_its_own_entry_not_pat_attempt() {
        let result = keyspace_class("pat-attempt-counter:bucket");
        assert_eq!(result, Some(EphemeralKeyspaceClass::Durable));

        // Sanity: the two prefixes really are siblings — neither is
        // a prefix of the other. If this ever flips (e.g. someone
        // renames `pat-attempt-counter:` to `pat-attempt:counter:`),
        // the registry has to be re-reviewed.
        assert!(!"pat-attempt-counter:bucket".starts_with("pat-attempt:"));
        assert!(!"pat-attempt:bucket".starts_with("pat-attempt-counter:"));
    }

    #[test]
    fn oci_session_count_resolves_to_durable() {
        assert_eq!(
            keyspace_class("oci:session_count:42:7"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    #[test]
    fn unregistered_prefix_returns_none() {
        assert_eq!(keyspace_class("completely_unrelated:foo"), None);
    }

    #[test]
    fn empty_string_returns_none() {
        // The first registered prefix is `cargo_index_proj:` (non-empty),
        // so `"".starts_with(<any non-empty prefix>) == false` for
        // every entry.
        assert_eq!(keyspace_class(""), None);
    }

    #[test]
    fn key_shorter_than_any_registered_prefix_returns_none() {
        // The shortest prefix is `auth:event:` (11 chars). A 3-char
        // input cannot start with any prefix.
        assert_eq!(keyspace_class("abc"), None);
    }

    #[test]
    fn idem_task_resolves_to_durable() {
        // Admin-task idempotency tokens must land on
        // the durable Redis so the 5-minute dedup window survives a
        // Redis pod restart. Key shape:
        // `idem-task:<operator-supplied-Idempotency-Key>`.
        assert_eq!(
            keyspace_class("idem-task:my-deploy-run-001"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }

    #[test]
    fn registry_has_expected_entry_count_and_classes() {
        // Guards against accidental additions / deletions; if the
        // count changes, this assertion must be updated together with
        // the registry edit (and the change reviewed deliberately).
        // Current shape: 15 entries — 8 durable, 7 evictable (the
        // Maven on-demand sidecar-digest cache `mavensum:` added the
        // 7th evictable entry).
        assert_eq!(KEYSPACE_REGISTRY.len(), 15);

        let evictable = KEYSPACE_REGISTRY
            .iter()
            .filter(|(_, c)| *c == EphemeralKeyspaceClass::Evictable)
            .count();
        let durable = KEYSPACE_REGISTRY
            .iter()
            .filter(|(_, c)| *c == EphemeralKeyspaceClass::Durable)
            .count();
        assert_eq!(evictable, 7, "expected 7 evictable entries");
        assert_eq!(durable, 8, "expected 8 durable entries");
    }

    #[test]
    fn cli_session_revoked_resolves_to_durable() {
        // The CliSession `jti` denylist must be Durable:
        // an evicted entry would re-permit a revoked token before its
        // `exp`, the exact AK-side-revocation regression the denylist
        // exists to prevent.
        assert_eq!(
            keyspace_class("cli-session-revoked:00000000-0000-0000-0000-000000000000"),
            Some(EphemeralKeyspaceClass::Durable),
        );
    }
}
