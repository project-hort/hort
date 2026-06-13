//! Repository upstream-mapping repository port.
//!
//! Format-agnostic CRUD over the `repository_upstream_mappings` table.
//! The first consumer is the OCI pull-through-mirror flow, but the
//! port deliberately does NOT name OCI: single-upstream
//! formats (npm, PyPI, Cargo) reuse the same table with empty
//! `path_prefix` to surface their pre-existing single-upstream
//! configuration through the same admin surface.
//!
//! # Design
//!
//! - One row per `(repository_id, path_prefix)` — uniqueness enforced
//!   at the schema layer.
//! - `path_prefix = ""` doubles as the single-upstream catch-all.
//! - `UpstreamAuth` discriminates how the upstream-proxy adapter
//!   builds outbound credentials. The variant set is closed at the
//!   port level (`Anonymous`, `BearerChallenge`, `Basic`); new
//!   variants land in the same change as their consumer.
//!
//! # Provenance + write contract
//!
//! There are no admin REST writers; the gitops apply pipeline is the
//! sole writer. `managed_by` mirrors `Repository` / `GroupMapping` /
//! `CurationRule`; `list_managed_by_gitops` is the diff query
//! `ApplyConfigUseCase` runs every boot. `save_managed` is INSERT-or-
//! UPDATE keyed on the schema-level `(repository_id, path_prefix)`
//! UNIQUE; `delete_managed_by_id` removes a gitops row by primary
//! key (the diff layer surfaces ids, not the composite identity, to
//! mirror `RoleRepository::delete_managed_grant`).
//!
//! # Caching
//!
//! Reads are NOT cached at this layer. The upstream resolver
//! (`crate::ports::upstream_resolver`) holds an `ArcSwap`-backed cache
//! refreshed via [`RepositoryUpstreamMappingRepository::list_all`] on
//! a `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` cadence. Per-request reads
//! against this port go through the resolver's cache, not the DB.
//!
//! See `docs/architecture/how-to/oci-pull-through.md` and
//! `docs/architecture/how-to/declare-gitops-config.md`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::managed_by::ManagedBy;
use crate::error::{DomainError, DomainResult};
use crate::ports::secret_port::SecretRef;

use super::BoxFuture;

/// How the upstream proxy adapter authenticates outbound requests.
///
/// Variants are closed at the port level. Adding a new auth strategy
/// requires:
/// 1. A new variant here.
/// 2. A new `UPSTREAM_AUTH_*` constant + parser in the Postgres
///    adapter.
/// 3. Handling in the upstream-proxy adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAuth {
    /// No credentials sent. Plain HTTP/S registries, public mirrors,
    /// and Docker Hub for the simple anonymous-pull case (the
    /// `BearerChallenge` variant is reserved for registries that
    /// mandate the RFC 7235 + Docker token-spec challenge handshake).
    Anonymous,
    /// Generalised bearer-challenge flow (RFC 7235 §4.1 + Docker
    /// token spec): on a 401 response the proxy adapter parses the
    /// `WWW-Authenticate: Bearer realm=…,service=…,scope=…` header,
    /// fetches a token from the realm endpoint advertised by the
    /// upstream, and retries the original request with
    /// `Authorization: Bearer <token>`. Tokens are cached in-process
    /// keyed by `(realm, service, scope, cred_identity)` so
    /// subsequent requests skip the 401 round-trip. Covers Docker
    /// Hub, GHCR, Quay, GitLab CR, Harbor, Nexus, ECR Public, and
    /// every other registry that follows the Docker token spec.
    /// When `secret_ref` is set on the mapping, the realm exchange
    /// carries `Authorization: Basic <user:secret>` (cache-key
    /// semantics: distinct `SecretRef`
    /// values key distinctly; identical `(source, location)` pairs
    /// collapse to a single cache entry).
    BearerChallenge,
    /// HTTP Basic auth with credentials drawn from the encrypted
    /// secrets table. `username` is plaintext (low value to attackers,
    /// safe to log at debug); the password is referenced by the row's
    /// `secret_ref`; `SecretPort::resolve` reads the
    /// bytes from the configured env var or mounted file at fetch
    /// time.
    Basic { username: String },
}

/// One pull-through upstream attached to a repository.
///
/// `path_prefix` is empty for single-upstream formats and non-empty
/// for OCI multi-upstream mirrors (e.g. `dockerhub/`, `ghcr/`). The
/// resolver matches by longest-prefix; an empty-prefix row is the
/// catch-all and must not shadow a more-specific one.
///
/// `managed_by` + `managed_by_digest` carry gitops provenance.
/// `managed_by_digest` is `Some(_)` exactly when `managed_by` is
/// `GitOps` — the schema CHECK constraint enforces this in lockstep
/// with the in-memory invariant; adapters constructing the struct from
/// rows MUST preserve the pairing.
#[derive(Debug, Clone)]
pub struct RepositoryUpstreamMapping {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path_prefix: String,
    pub upstream_url: String,
    /// Optional outbound path segment(s) inserted
    /// between `/v2/` and `<name>` in OCI requests. `None` matches
    /// today's behaviour byte-for-byte; `Some("docker.io")` produces
    /// `<base>/v2/docker.io/<name>/<kind>/<value>`. **Format-effective
    /// for OCI only**: non-OCI adapters accept the field but must NOT
    /// consume it in URL composition (the operator can achieve the
    /// same shape by including the prefix in `upstream_url` because
    /// their format-native paths don't pin a fixed root).
    ///
    /// Validation in [`RepositoryUpstreamMapping::new`] mirrors the
    /// schema CHECK constraint
    /// `chk_repository_upstream_mappings_name_prefix` so a row inserted
    /// via raw SQL cannot escape the guard.
    pub upstream_name_prefix: Option<String>,
    pub upstream_auth: UpstreamAuth,
    /// Reference to a secret used to authenticate the upstream pull.
    /// Resolved at fetch time via [`SecretPort`].
    /// `None` for the `Anonymous` variant; for `BearerChallenge` /
    /// `Basic` the `SecretPort` adapter resolves the bytes on each
    /// fetch (file source) or once at process startup (env-var
    /// source). Operators wire whatever sync mechanism they prefer —
    /// the `SecretPort` only reads from env vars and mounted files.
    ///
    /// [`SecretPort`]: crate::ports::secret_port::SecretPort
    pub secret_ref: Option<SecretRef>,
    /// Provenance discriminator. `GitOps` rows are
    /// produced by `ApplyConfigUseCase`; `Local` is reserved for any
    /// future non-gitops bootstrap path.
    pub managed_by: ManagedBy,
    /// SHA-256 over the canonicalised YAML spec that produced this
    /// row, set in lockstep with `save_managed`. `Some(_)` exactly
    /// when `managed_by == ManagedBy::GitOps`; the schema's
    /// `chk_repository_upstream_mappings_managed_digest` mirrors that
    /// invariant.
    pub managed_by_digest: Option<[u8; 32]>,
    /// Operator-explicit opt-in to a
    /// plaintext (`http://`) upstream. Default `false`: the constructor
    /// rejects non-`https://` upstreams. When set to `true` the
    /// constructor accepts an `http://` upstream and the proxy adapter
    /// emits a `WARN` log line plus
    /// `hort_upstream_insecure_total{format,reason}` on every fetch.
    /// Per-mapping rather than process-wide so an operator with one
    /// legitimate internal plaintext mirror among many `https`
    /// upstreams cannot silently widen the posture for the rest.
    pub insecure_upstream_url: bool,
    /// Per-upstream opt-in: when `true`, ingests
    /// served by this mapping use `upstream_published_at` (clamped to
    /// `ingested_at` to defeat future-skew) as the quarantine anchor;
    /// when `false` (default), the anchor is `ingested_at`, unchanged
    /// from Phase 1. Mirrors the `insecure_upstream_url` per-upstream
    /// opt-in shape — per-mapping rather than process-wide so a
    /// publish-time trust decision for one upstream cannot silently
    /// widen the posture for the rest. The `IngestUseCase` anchor
    /// computation is the consumer (ADR 0007).
    pub trust_upstream_publish_time: bool,
    /// Reference to the PEM-encoded mTLS
    /// client certificate the proxy adapter presents on the outbound
    /// TLS handshake. Resolved at fetch time via [`SecretPort`] and
    /// cached per-mapping. **Pairing invariant:** must be `Some(_)` iff
    /// [`Self::mtls_key_ref`] is `Some(_)` — supplying a cert without
    /// a key (or vice versa) is rejected at construction. Any TLS
    /// field set requires `upstream_url` to be `https://`. Behaviour
    /// (cert load, rustls integration, metric emission) lives in the
    /// upstream-http adapter's TLS config module.
    ///
    /// [`SecretPort`]: crate::ports::secret_port::SecretPort
    pub mtls_cert_ref: Option<SecretRef>,
    /// Reference to the PEM-encoded mTLS
    /// client private key paired with [`Self::mtls_cert_ref`]. The
    /// key bytes never leave the SecretPort adapter; they are loaded
    /// into the rustls config and dropped (zeroized) on cache eviction.
    /// **Pairing invariant:** see [`Self::mtls_cert_ref`].
    pub mtls_key_ref: Option<SecretRef>,
    /// Reference to a PEM-encoded
    /// custom CA bundle that augments (not replaces) the system trust
    /// roots when this mapping's upstream is reached. `None` keeps
    /// the system CA store unmodified. Independent of mTLS — operators
    /// with a private CA but no client-cert requirement set only this.
    pub ca_bundle_ref: Option<SecretRef>,
    /// Pinned SHA-256 thumbprint of the
    /// upstream's leaf certificate (DER bytes), as a 64-character
    /// lowercase hex string. When `Some(_)`, the adapter's rustls
    /// `ServerCertVerifier` rejects any handshake
    /// whose leaf cert thumbprint does not match — this is operator-
    /// explicit pinning, defence-in-depth on top of CA-trust validation.
    /// Validation: exactly 64 chars, charset `[0-9a-f]`. Schema CHECK
    /// mirrors the same regex.
    pub pinned_cert_sha256: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Constructor argument bundle for [`RepositoryUpstreamMapping::new`].
///
/// The struct exists so the constructor is keyword-arg-shaped at the
/// call site without taking 11 positional parameters. Validation is
/// performed inside `new`; bypassing the constructor by struct-literal
/// is only safe in test-scaffolding and adapter row-decoding paths
/// where the upstream URL came from a previously-validated source.
#[derive(Debug, Clone)]
pub struct RepositoryUpstreamMappingArgs {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path_prefix: String,
    pub upstream_url: String,
    /// See [`RepositoryUpstreamMapping::upstream_name_prefix`].
    pub upstream_name_prefix: Option<String>,
    pub upstream_auth: UpstreamAuth,
    pub secret_ref: Option<SecretRef>,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
    pub insecure_upstream_url: bool,
    /// See [`RepositoryUpstreamMapping::trust_upstream_publish_time`].
    pub trust_upstream_publish_time: bool,
    /// See [`RepositoryUpstreamMapping::mtls_cert_ref`].
    pub mtls_cert_ref: Option<SecretRef>,
    /// See [`RepositoryUpstreamMapping::mtls_key_ref`].
    pub mtls_key_ref: Option<SecretRef>,
    /// See [`RepositoryUpstreamMapping::ca_bundle_ref`].
    pub ca_bundle_ref: Option<SecretRef>,
    /// See [`RepositoryUpstreamMapping::pinned_cert_sha256`].
    pub pinned_cert_sha256: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Outbound-path-prefix validation, mirrored 1:1 in
/// the schema CHECK constraint `chk_repository_upstream_mappings_name_prefix`.
///
/// Equivalent to the regex
/// `^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$` plus two extra guards
/// (`..` substring forbidden; segments of one-or-more dots forbidden).
/// Hand-rolled to avoid pulling `regex` into `hort-domain`.
fn validate_upstream_name_prefix(prefix: &str) -> DomainResult<()> {
    if prefix.is_empty() {
        return Err(DomainError::Validation(
            "RepositoryUpstreamMapping.upstream_name_prefix must not be empty; \
             use None instead of Some(\"\")"
                .into(),
        ));
    }
    if prefix.starts_with('/') || prefix.ends_with('/') {
        return Err(DomainError::Validation(format!(
            "RepositoryUpstreamMapping.upstream_name_prefix must not start or \
             end with `/`; got `{prefix}`"
        )));
    }
    if prefix.contains("..") {
        return Err(DomainError::Validation(format!(
            "RepositoryUpstreamMapping.upstream_name_prefix must not contain \
             `..` (path traversal); got `{prefix}`"
        )));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() {
            return Err(DomainError::Validation(format!(
                "RepositoryUpstreamMapping.upstream_name_prefix must not \
                 contain empty segments (consecutive `/`); got `{prefix}`"
            )));
        }
        if segment.chars().all(|c| c == '.') {
            return Err(DomainError::Validation(format!(
                "RepositoryUpstreamMapping.upstream_name_prefix must not \
                 contain a segment of only dots; got `{prefix}`"
            )));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(DomainError::Validation(format!(
                "RepositoryUpstreamMapping.upstream_name_prefix segments must \
                 match [A-Za-z0-9_.-]; got `{prefix}`"
            )));
        }
    }
    Ok(())
}

impl RepositoryUpstreamMapping {
    /// Construct a [`RepositoryUpstreamMapping`] enforcing the
    /// transport-scheme invariant.
    /// Returns [`DomainError::Validation`] when the URL is
    /// unparseable, the scheme is something other than `http`/`https`,
    /// or the scheme is `http` and `insecure_upstream_url` is `false`.
    ///
    /// This is the production-side construction path. Test scaffolding
    /// across the workspace continues to use struct-literal
    /// construction for brevity; the security guarantee is that every
    /// row that originates from operator input — gitops apply
    /// (`ApplyConfigUseCase`), Postgres row decode, and any future REST
    /// writer — flows through `new`.
    pub fn new(args: RepositoryUpstreamMappingArgs) -> DomainResult<Self> {
        let parsed = url::Url::parse(&args.upstream_url).map_err(|e| {
            DomainError::Validation(format!(
                "RepositoryUpstreamMapping.upstream_url is not a valid URL: {e}"
            ))
        })?;
        match parsed.scheme() {
            "https" => {}
            "http" => {
                if !args.insecure_upstream_url {
                    return Err(DomainError::Validation(format!(
                        "RepositoryUpstreamMapping.upstream_url scheme must be \
                         https; got `{}`. Set insecure_upstream_url=true on the \
                         mapping to opt in to a plaintext upstream.",
                        parsed.scheme()
                    )));
                }
            }
            other => {
                return Err(DomainError::Validation(format!(
                    "RepositoryUpstreamMapping.upstream_url scheme must be \
                     https (or http with insecure_upstream_url=true); got `{other}`"
                )));
            }
        }

        // TLS-field invariants:
        //
        //   1. mtls_cert_ref.is_some() ⇔ mtls_key_ref.is_some()
        //      Supplying half the pair is an operator error; the proxy
        //      adapter cannot construct a usable rustls client config
        //      from an asymmetric pairing.
        //
        //   2. Any TLS field set ⇒ scheme is "https". TLS material on
        //      a plaintext upstream is incoherent — pinning a cert
        //      that will never be presented, or trusting a private CA
        //      for an http:// connection that does no TLS handshake.
        //
        //   3. pinned_cert_sha256, when Some(_), is exactly 64
        //      lowercase hex chars (raw SHA-256 thumbprint of the
        //      leaf certificate's DER bytes). Schema CHECK mirrors
        //      the same regex as defence-in-depth.
        match (args.mtls_cert_ref.is_some(), args.mtls_key_ref.is_some()) {
            (true, true) | (false, false) => {}
            (true, false) | (false, true) => {
                return Err(DomainError::Validation(
                    "RepositoryUpstreamMapping.mtls_cert_ref and \
                     mtls_key_ref must be set together: supply both PEM \
                     references for outbound mTLS, or neither."
                        .into(),
                ));
            }
        }

        let any_tls_field = args.mtls_cert_ref.is_some()
            || args.mtls_key_ref.is_some()
            || args.ca_bundle_ref.is_some()
            || args.pinned_cert_sha256.is_some();
        if any_tls_field && parsed.scheme() != "https" {
            return Err(DomainError::Validation(format!(
                "RepositoryUpstreamMapping carries mTLS / CA-bundle / \
                 cert-pinning material but upstream_url scheme is `{}`; \
                 these fields require https.",
                parsed.scheme()
            )));
        }

        if let Some(pin) = args.pinned_cert_sha256.as_deref() {
            if pin.len() != 64 || !pin.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
                return Err(DomainError::Validation(format!(
                    "RepositoryUpstreamMapping.pinned_cert_sha256 must be \
                     exactly 64 lowercase hex characters (SHA-256 of the \
                     leaf certificate's DER bytes); got `{pin}` ({} chars)",
                    pin.len()
                )));
            }
        }

        if let Some(prefix) = args.upstream_name_prefix.as_deref() {
            validate_upstream_name_prefix(prefix)?;
        }

        Ok(Self {
            id: args.id,
            repository_id: args.repository_id,
            path_prefix: args.path_prefix,
            upstream_url: args.upstream_url,
            upstream_name_prefix: args.upstream_name_prefix,
            upstream_auth: args.upstream_auth,
            secret_ref: args.secret_ref,
            managed_by: args.managed_by,
            managed_by_digest: args.managed_by_digest,
            insecure_upstream_url: args.insecure_upstream_url,
            trust_upstream_publish_time: args.trust_upstream_publish_time,
            mtls_cert_ref: args.mtls_cert_ref,
            mtls_key_ref: args.mtls_key_ref,
            ca_bundle_ref: args.ca_bundle_ref,
            pinned_cert_sha256: args.pinned_cert_sha256,
            created_at: args.created_at,
            updated_at: args.updated_at,
        })
    }
}

/// Outbound port: CRUD on `repository_upstream_mappings`.
///
/// All four methods are async-fallible via [`BoxFuture`] +
/// [`DomainResult`]. Callers serialize through a single instance
/// (Postgres pool's connection management); concurrency is the
/// adapter's problem, not this port's.
pub trait RepositoryUpstreamMappingRepository: Send + Sync {
    /// All mappings for a single repository, in insertion order. The
    /// resolver's longest-prefix-match algorithm sorts them by
    /// `path_prefix.len()` desc on the read side — the adapter does
    /// NOT pre-sort.
    fn list_for_repository(
        &self,
        repository_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>>;

    /// Every mapping across every repository, in arbitrary order.
    /// Used by the resolver's cache-refresh task
    /// (`HORT_UPSTREAM_RESOLVER_REFRESH_SECS`).
    /// At scale this is bounded by the operator's repository count
    /// times average mappings-per-repo — typical deployments have
    /// O(10s) repositories with O(1–5) upstream mappings each.
    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>>;

    /// Upsert by `(repository_id, path_prefix)` — re-running with the
    /// same key updates the existing row in place rather than
    /// failing on the unique constraint. `created_at` is preserved on
    /// update; `updated_at` is bumped to NOW(). The supplied `id` is
    /// honoured on insert and ignored on update (the existing row's
    /// id stays stable so cache invalidation by id keeps working).
    fn upsert(&self, mapping: RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>>;

    /// Remove the mapping at `(repository_id, path_prefix)`.
    /// No-op when the row does not exist — admins re-issuing DELETE
    /// after a cache refresh window must not see spurious failures.
    fn delete(&self, repository_id: Uuid, path_prefix: &str) -> BoxFuture<'_, DomainResult<()>>;

    // ---- Gitops-managed write surface ----

    /// Every `managed_by = 'gitops'` mapping plus its digest. Bounded
    /// by the partial index `idx_repository_upstream_mappings_managed_by`
    /// (`007_upstream_mappings.sql`). This is the diff query
    /// [`ApplyConfigUseCase`] runs on every boot.
    ///
    /// [`ApplyConfigUseCase`]: hort-app::use_cases::apply_config_use_case::ApplyConfigUseCase
    fn list_managed_by_gitops(&self)
        -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>>;

    /// INSERT-or-UPDATE a `managed_by = 'gitops'` row. Sets the
    /// digest in the same statement so a partial write cannot leave
    /// `managed_by = 'gitops'` with `managed_by_digest = NULL`. The
    /// schema CHECK enforces this on the DB side; the port surfaces
    /// the pairing through `RepositoryUpstreamMapping`.
    /// [`ApplyConfigUseCase`] is the only caller.
    ///
    /// `mapping.managed_by` must be `GitOps` and `mapping.managed_by_digest`
    /// must be `Some(_)` — adapters return [`DomainError::Invariant`]
    /// otherwise rather than silently widening the invariant.
    ///
    /// [`ApplyConfigUseCase`]: hort-app::use_cases::apply_config_use_case::ApplyConfigUseCase
    /// [`DomainError::Invariant`]: crate::error::DomainError::Invariant
    fn save_managed(&self, mapping: &RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>>;

    /// DELETE a `managed_by = 'gitops'` row by primary key. Refuses
    /// non-gitops rows defensively (the diff layer never schedules a
    /// delete on a `managed_by = 'local'` row, but the port enforces
    /// the invariant in case of out-of-band SQL or future bugs). Pairs
    /// with `RoleRepository::delete_managed_grant` shape — the diff
    /// emits ids, not the composite identity, because the partial
    /// index keeps id lookup cheap.
    fn delete_managed_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    /// Compile-time assertion that the port is dyn-compatible —
    /// held as `Arc<dyn RepositoryUpstreamMappingRepository>` on
    /// `AppContext`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RepositoryUpstreamMappingRepository>();
    }

    #[test]
    fn upstream_auth_variants_are_pattern_exhaustive() {
        // Encodes the closed-variant invariant — adding a variant
        // forces this test to fail until the new arm is documented.
        let cases = [
            UpstreamAuth::Anonymous,
            UpstreamAuth::BearerChallenge,
            UpstreamAuth::Basic {
                username: "alice".into(),
            },
        ];
        for c in cases {
            match c {
                UpstreamAuth::Anonymous
                | UpstreamAuth::BearerChallenge
                | UpstreamAuth::Basic { .. } => {}
            }
        }
    }

    // -- Transport-scheme posture ------------------------------------------
    //
    // Transport-scheme posture rules:
    //   - `upstream_url.scheme() == "https"` is a value-object invariant.
    //   - Operators may opt in to plaintext per-mapping via
    //     `insecure_upstream_url: true`; constructor accepts http://
    //     only when that flag is set, and the proxy adapter then emits
    //     WARN + `hort_upstream_insecure_total{format,reason}` on every
    //     fetch through the mapping.
    //
    // These tests pin the constructor-time enforcement; the proxy-side
    // emission is covered by the `hort-adapters-upstream-http` test suite.

    fn make_args(upstream_url: &str, insecure: bool) -> RepositoryUpstreamMappingArgs {
        RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: upstream_url.to_string(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: insecure,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn secret(name: &str) -> SecretRef {
        use crate::ports::secret_port::SecretSource;
        SecretRef {
            source: SecretSource::EnvVar,
            location: name.to_string(),
        }
    }

    #[test]
    fn constructor_accepts_https_upstream() {
        let args = make_args("https://registry.example.com", false);
        let m = RepositoryUpstreamMapping::new(args).expect("https must be accepted");
        assert_eq!(m.upstream_url, "https://registry.example.com");
        assert!(!m.insecure_upstream_url);
    }

    #[test]
    fn constructor_rejects_http_upstream_without_opt_in() {
        let args = make_args("http://internal.example.com", false);
        let err = RepositoryUpstreamMapping::new(args)
            .expect_err("http:// must be rejected without insecure_upstream_url");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("https") || msg.contains("scheme") || msg.contains("insecure"),
            "error message must reference the scheme rule, got `{msg}`"
        );
    }

    #[test]
    fn constructor_accepts_http_upstream_when_insecure_opt_in_set() {
        let args = make_args("http://internal-mirror.example.com", true);
        let m = RepositoryUpstreamMapping::new(args)
            .expect("http:// must be accepted when insecure_upstream_url=true");
        assert!(m.insecure_upstream_url);
        assert_eq!(m.upstream_url, "http://internal-mirror.example.com");
    }

    #[test]
    fn constructor_rejects_unparseable_upstream_url() {
        let args = make_args("not a url", false);
        let err = RepositoryUpstreamMapping::new(args).expect_err("malformed URL must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_rejects_non_http_scheme_even_with_insecure_opt_in() {
        // The insecure opt-in widens the scheme set from
        // {https} to {https, http} only — `file://`, `ftp://`, etc.
        // remain unconditionally rejected.
        let args = make_args("ftp://example.com", true);
        let err = RepositoryUpstreamMapping::new(args)
            .expect_err("ftp:// must be rejected even with insecure opt-in");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    // -- `trust_upstream_publish_time` opt-in ------------------------------
    //
    // Per-upstream opt-in flag (default `false`) that gates the
    // publish-anchored quarantine window (ADR 0007).
    // The field is a plain bool — no validation, no cross-field rules
    // — so the value-object surface is just the constructor default
    // and the round-trip from `Args`. The `IngestUseCase` anchor
    // computation is the consumer.

    #[test]
    fn constructor_defaults_trust_upstream_publish_time_to_false() {
        // make_args constructs the Args with trust_upstream_publish_time
        // unset (the test-helper default mirrors the operator default).
        // The constructor must round-trip `false` without surprises.
        let args = make_args("https://registry.example.com", false);
        assert!(
            !args.trust_upstream_publish_time,
            "test fixture pre-condition: default Args carries false"
        );
        let m = RepositoryUpstreamMapping::new(args).expect("https must construct");
        assert!(
            !m.trust_upstream_publish_time,
            "default constructor must leave trust_upstream_publish_time = false"
        );
    }

    #[test]
    fn constructor_round_trips_trust_upstream_publish_time_true() {
        let mut args = make_args("https://registry.example.com", false);
        args.trust_upstream_publish_time = true;
        let m = RepositoryUpstreamMapping::new(args).expect("https + opt-in must construct");
        assert!(
            m.trust_upstream_publish_time,
            "opt-in `true` must survive the constructor"
        );
    }

    // -- mTLS / cert-pinning value-object plumbing --------------------------
    //
    // The four optional fields land here at the value-object layer;
    // behaviour (cert load, rustls verifier, metric emission) lives in
    // the upstream-http adapter's TLS config module.
    //
    // Invariants enforced by `RepositoryUpstreamMapping::new`:
    //   - `mtls_cert_ref.is_some() ⇔ mtls_key_ref.is_some()` (both or neither)
    //   - Any of {mtls_cert_ref, mtls_key_ref, ca_bundle_ref,
    //     pinned_cert_sha256} set ⇒ upstream URL scheme is `https`
    //     (plaintext + cert-pinning is an operator error)
    //   - `pinned_cert_sha256`, when `Some(_)`, is a 64-char lowercase
    //     hex string (raw SHA-256 of the leaf certificate's DER bytes)

    fn make_args_with_tls(
        upstream_url: &str,
        insecure: bool,
        mtls_cert_ref: Option<SecretRef>,
        mtls_key_ref: Option<SecretRef>,
        ca_bundle_ref: Option<SecretRef>,
        pinned_cert_sha256: Option<String>,
    ) -> RepositoryUpstreamMappingArgs {
        RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: upstream_url.to_string(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: insecure,
            trust_upstream_publish_time: false,
            mtls_cert_ref,
            mtls_key_ref,
            ca_bundle_ref,
            pinned_cert_sha256,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn valid_pin() -> String {
        // 64 lowercase hex chars — a syntactically valid SHA-256 thumbprint.
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string()
    }

    #[test]
    fn constructor_accepts_all_tls_fields_unset() {
        // Default posture: no operator-supplied TLS material; any
        // `https://` upstream constructs cleanly.
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            None,
        );
        let m = RepositoryUpstreamMapping::new(args).expect("default posture must accept");
        assert!(m.mtls_cert_ref.is_none());
        assert!(m.mtls_key_ref.is_none());
        assert!(m.ca_bundle_ref.is_none());
        assert!(m.pinned_cert_sha256.is_none());
    }

    #[test]
    fn constructor_accepts_mtls_cert_and_key_paired() {
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            Some(secret("HORT_MTLS_CERT")),
            Some(secret("HORT_MTLS_KEY")),
            None,
            None,
        );
        let m = RepositoryUpstreamMapping::new(args).expect("paired mTLS refs must accept");
        assert!(m.mtls_cert_ref.is_some());
        assert!(m.mtls_key_ref.is_some());
    }

    #[test]
    fn constructor_rejects_mtls_cert_without_key() {
        // `mtls_cert_ref.is_some() ⇔ mtls_key_ref.is_some()` — supplying
        // a cert without a key (or vice versa) is an operator error.
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            Some(secret("HORT_MTLS_CERT")),
            None,
            None,
            None,
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("cert without key must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("mtls_cert_ref") && msg.contains("mtls_key_ref"),
            "error must reference both ref names; got `{msg}`"
        );
    }

    #[test]
    fn constructor_rejects_mtls_key_without_cert() {
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            Some(secret("HORT_MTLS_KEY")),
            None,
            None,
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("key without cert must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_accepts_ca_bundle_alone() {
        // `ca_bundle_ref` is independent of mTLS — operators with a
        // private CA but no client-cert requirement set only this.
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            Some(secret("HORT_CA_BUNDLE")),
            None,
        );
        let m = RepositoryUpstreamMapping::new(args).expect("CA-only must accept");
        assert!(m.ca_bundle_ref.is_some());
    }

    #[test]
    fn constructor_accepts_pinned_cert_alone() {
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            Some(valid_pin()),
        );
        let m = RepositoryUpstreamMapping::new(args).expect("pin-only must accept");
        assert_eq!(m.pinned_cert_sha256.as_deref(), Some(valid_pin().as_str()));
    }

    #[test]
    fn constructor_rejects_mtls_with_plaintext_upstream() {
        // Operator error: TLS fields require https. With http+insecure
        // opt-in, the scheme is plaintext and any TLS field is incoherent.
        let args = make_args_with_tls(
            "http://internal-mirror.example.com",
            true,
            Some(secret("HORT_MTLS_CERT")),
            Some(secret("HORT_MTLS_KEY")),
            None,
            None,
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("mTLS + http:// must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("https"),
            "error must reference the https requirement; got `{msg}`"
        );
    }

    #[test]
    fn constructor_rejects_ca_bundle_with_plaintext_upstream() {
        let args = make_args_with_tls(
            "http://internal-mirror.example.com",
            true,
            None,
            None,
            Some(secret("HORT_CA_BUNDLE")),
            None,
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("CA bundle + http:// must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_rejects_pinned_cert_with_plaintext_upstream() {
        let args = make_args_with_tls(
            "http://internal-mirror.example.com",
            true,
            None,
            None,
            None,
            Some(valid_pin()),
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("pinning + http:// must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_rejects_pin_too_short() {
        let mut short = valid_pin();
        short.pop();
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            Some(short),
        );
        let err = RepositoryUpstreamMapping::new(args)
            .expect_err("pin shorter than 64 chars must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("pinned_cert_sha256"),
            "error must reference the field; got `{msg}`"
        );
    }

    #[test]
    fn constructor_rejects_pin_too_long() {
        let long = format!("{}f", valid_pin());
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            Some(long),
        );
        let err = RepositoryUpstreamMapping::new(args)
            .expect_err("pin longer than 64 chars must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_rejects_pin_with_uppercase_hex() {
        // Schema-level CHECK enforces lowercase via the regex
        // `^[0-9a-f]+$`; mirror that at the value-object boundary.
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            Some(valid_pin().to_uppercase()),
        );
        let err =
            RepositoryUpstreamMapping::new(args).expect_err("uppercase hex pin must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_rejects_pin_with_non_hex_chars() {
        let mut bad = valid_pin();
        bad.replace_range(0..1, "z");
        let args = make_args_with_tls(
            "https://registry.example.com",
            false,
            None,
            None,
            None,
            Some(bad),
        );
        let err = RepositoryUpstreamMapping::new(args).expect_err("non-hex pin must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn constructor_accepts_full_tls_combination() {
        // mTLS + custom CA + pinning all set together — this is the
        // most-locked-down operator posture and must compose cleanly.
        let args = make_args_with_tls(
            "https://registry.internal.example.com",
            false,
            Some(secret("HORT_MTLS_CERT")),
            Some(secret("HORT_MTLS_KEY")),
            Some(secret("HORT_CA_BUNDLE")),
            Some(valid_pin()),
        );
        let m = RepositoryUpstreamMapping::new(args)
            .expect("full TLS combination on https must accept");
        assert!(m.mtls_cert_ref.is_some());
        assert!(m.mtls_key_ref.is_some());
        assert!(m.ca_bundle_ref.is_some());
        assert!(m.pinned_cert_sha256.is_some());
    }

    // -- `upstream_name_prefix` validation ----------------------------------
    //
    // Outbound OCI path-prefix injection. The field is optional; when
    // present it gets spliced between `/v2/` and `<name>` in the
    // outbound URL by the proxy adapter. Validation rules:
    //
    //   * Regex: `^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`
    //   * Reject `..` substring anywhere (path traversal — defence in
    //     depth on top of the segment-of-dots guard, which catches
    //     standalone `..` segments but not embedded `foo..bar`).
    //   * Reject any segment that is one-or-more dots (`.`, `..`,
    //     `...`) — standalone or between slashes.
    //   * Reject `Some("")` — operators use `None`, not an empty string.
    //
    // CHECK constraint in `007_upstream_mappings.sql` mirrors the
    // constructor 1:1 so raw SQL cannot bypass the guard.

    fn args_with_prefix(prefix: Option<&str>) -> RepositoryUpstreamMappingArgs {
        let mut args = make_args("https://registry.example.com", false);
        args.upstream_name_prefix = prefix.map(str::to_string);
        args
    }

    fn assert_prefix_rejected_with_field_named(prefix: &str) {
        let args = args_with_prefix(Some(prefix));
        let err = RepositoryUpstreamMapping::new(args)
            .expect_err(&format!("prefix `{prefix}` must be rejected"));
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("upstream_name_prefix"),
            "error message must name the field; got `{msg}` for input `{prefix}`"
        );
    }

    #[test]
    fn constructor_rejects_empty_upstream_name_prefix() {
        // Some("") is operator confusion — they should use None.
        assert_prefix_rejected_with_field_named("");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_leading_slash() {
        assert_prefix_rejected_with_field_named("/foo");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_trailing_slash() {
        assert_prefix_rejected_with_field_named("foo/");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_consecutive_slashes() {
        // Empty segment between slashes — defence against accidental
        // double-slash in operator config.
        assert_prefix_rejected_with_field_named("foo//bar");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_dotdot_substring() {
        // Path-traversal defence. Every other `..`-bearing shape
        // (`foo/../bar`, `..`, `foo/..`) hits the same `contains("..")`
        // guard first, so one input pins this branch.
        assert_prefix_rejected_with_field_named("foo..bar");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_standalone_single_dot() {
        // Segment-of-dots guard, single-segment case. The `..`-substring
        // guard above fires first on `..` / `foo/..` / `foo/../bar`, so
        // `.` is the input that actually pins this branch.
        assert_prefix_rejected_with_field_named(".");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_middle_dot_segment() {
        // Segment-of-dots guard, mid-loop case — verifies the
        // `for segment in prefix.split('/')` iteration reaches
        // non-first segments.
        assert_prefix_rejected_with_field_named("foo/./bar");
    }

    #[test]
    fn constructor_rejects_upstream_name_prefix_with_disallowed_character() {
        // Char-class guard. Every disallowed char (`?`, `#`, whitespace,
        // ASCII control, …) lands in the same single branch — one
        // input pins it. Whitespace is the most common operator typo.
        assert_prefix_rejected_with_field_named("foo bar");
    }

    // -- Accept paths -----------------------------------------------------

    #[test]
    fn constructor_accepts_upstream_name_prefix_none() {
        let m = RepositoryUpstreamMapping::new(args_with_prefix(None))
            .expect("None must be accepted (default)");
        assert!(m.upstream_name_prefix.is_none());
    }

    #[test]
    fn constructor_accepts_upstream_name_prefix_single_segment() {
        let m = RepositoryUpstreamMapping::new(args_with_prefix(Some("dockerhub")))
            .expect("single segment must be accepted");
        assert_eq!(m.upstream_name_prefix.as_deref(), Some("dockerhub"));
    }

    #[test]
    fn constructor_accepts_upstream_name_prefix_dots_inside_segment() {
        // `docker.io` is the canonical Zot-rewriter case — dots inside
        // a segment must NOT be confused with the segment-of-dots reject.
        let m = RepositoryUpstreamMapping::new(args_with_prefix(Some("docker.io")))
            .expect("dots inside a segment must be accepted");
        assert_eq!(m.upstream_name_prefix.as_deref(), Some("docker.io"));
    }

    #[test]
    fn constructor_accepts_upstream_name_prefix_multi_segment() {
        let m = RepositoryUpstreamMapping::new(args_with_prefix(Some("acme/internal/proxy")))
            .expect("multi-segment prefix must be accepted");
        assert_eq!(
            m.upstream_name_prefix.as_deref(),
            Some("acme/internal/proxy")
        );
    }

    #[test]
    fn constructor_accepts_upstream_name_prefix_with_hyphens_and_underscores() {
        // Allowed character class includes `_`, `.`, `-` and ASCII
        // alphanumerics.
        let m = RepositoryUpstreamMapping::new(args_with_prefix(Some("acme-internal_v2.0")))
            .expect("hyphens and underscores must be accepted");
        assert_eq!(
            m.upstream_name_prefix.as_deref(),
            Some("acme-internal_v2.0")
        );
    }
}
