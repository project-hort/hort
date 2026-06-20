//! `kind: ArtifactRepository` schema, parser, and per-spec validation.
//!
//! The YAML shape mirrors `hort_domain::entities::repository::Repository`
//! verbatim — there is no parallel enum surface to maintain. Domain
//! enums reach this crate via `hort_domain` (a zero-I/O dep), so importing
//! them here doesn't break the runtime-free invariant on `hort-config`.
//!
//! Parsing and validation are layered:
//! - This module — parse + per-spec validate (one envelope at a time).
//! - `crate::desired` — cross-spec validate (duplicate names, dangling
//!   virtual members, HORT_AUTH_PROVIDER consistency) and diff.
//! - `hort-app::ApplyConfigUseCase` — execute the diff.
//!
//! The `to_create_repository` converter lives in the apply use case
//! (cycle: `hort-app` already depends on `hort-config`, so `hort-config`
//! cannot depend on `hort-app`). Putting it there also keeps the
//! validator-inlining note in one place.

use std::path::Path;
use std::str::FromStr;

use hort_domain::entities::repository::{
    IndexMode, PrefetchPolicy, PromotionConfig, ReplicationPriority, RepositoryFormat,
    RepositoryType,
};
use hort_domain::ports::secret_port::{SecretRef, SecretSource};
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};
use crate::interpolate::interpolate;

/// Shape of a `kind: ArtifactRepository` YAML body.
///
/// Field names use camelCase to match the Kubernetes-style operator
/// surface. `deny_unknown_fields` makes typos surface immediately —
/// silent default coercion is a footgun ruled out explicitly via
/// `deny_unknown_fields`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositorySpec {
    /// Human-readable display name. Maps to `Repository.name`.
    pub name: String,
    pub description: Option<String>,
    /// Lowercase format identifier. Maps to `RepositoryFormat`. Unknown
    /// values become `RepositoryFormat::Other(_)` (the same fall-through
    /// the admin handler uses), which surfaces in cross-spec validation
    /// because it's never a useful production state for a managed repo.
    pub format: String,
    /// `hosted | proxy | virtual | staging`. The
    /// `type` Rust keyword forces a serde rename.
    #[serde(rename = "type")]
    pub repo_type: String,
    /// Per-repository storage placement hint — **optional**. Omitting
    /// the `storage:` block means "inherit the deployment's effective
    /// global backend": the documented honest path, since per-repo
    /// storage is not routing-effective in v2 (see the [`StorageSpec`]
    /// honesty note). `#[serde(default)]` ⇒ absent deserialises to
    /// `None`; the apply layer (`build_repository_from_spec`) resolves
    /// `None` to the effective global backend.
    #[serde(default)]
    pub storage: Option<StorageSpec>,
    /// Required iff `type == proxy`; forbidden otherwise (cross-spec
    /// rule). Reserved fields `credentials` / `secretRef` inside this
    /// block are caught at parse-time, NOT here — see
    /// `parse_repository`.
    pub proxy: Option<ProxySpec>,
    /// Required iff `type == virtual`; forbidden otherwise. Each entry
    /// is the `metadata.name` of another `ArtifactRepository`. The
    /// The cross-spec validator resolves these to UUIDs.
    pub virtual_members: Option<Vec<String>>,
    pub is_public: bool,
    /// Opt-in per-repository download auditing (`downloadAuditEnabled`
    /// in YAML). When `true`, every served download from this
    /// repository appends one `ArtifactDownloaded` event to a dedicated
    /// per-`(repo, UTC-date)` audit stream (fail-open). Defaults to
    /// `false` when absent so existing gitops configs are non-breaking
    /// (additive field under the `deny_unknown_fields` schema). The
    /// opt-in flag is the volume control; the per-format download
    /// *count* stays Prometheus-only.
    #[serde(default)]
    pub download_audit_enabled: bool,
    /// Quarantine-aware index-serve mode (`indexMode` in YAML). When
    /// absent (`#[serde(default)]`), defaults to
    /// `IndexMode::ReleasedOnly` — the build-safe-by-construction
    /// posture: the served index lists only versions hort holds in a
    /// servable status, so a range never resolves to a version that
    /// would `503` on download. Operators who want maximal upstream
    /// discoverability set `indexMode: include_pending`. Additive field
    /// under the `deny_unknown_fields` schema — existing gitops configs
    /// are non-breaking. See `explanation/index-construction.md`.
    #[serde(default)]
    pub index_mode: IndexMode,
    /// Per-repository prefetch policy (`prefetchPolicy` in YAML). When
    /// absent (`#[serde(default)]`), defaults to
    /// `PrefetchPolicy::default()` — disabled, no triggers, default
    /// depths: upgrading the binary does not silently turn a repository
    /// into a mirror. The `on_dist_tag_move` consumer fires on index
    /// events; `scheduled` via `PrefetchTickHandler`; the transitive
    /// cascade handles deeper dependency resolution. Additive field
    /// under the `deny_unknown_fields` schema — existing gitops configs
    /// are non-breaking. See `explanation/prefetch-pipeline.md`.
    #[serde(default)]
    pub prefetch_policy: PrefetchPolicy,
    pub quota_bytes: Option<i64>,
    /// `immediate | scheduled | on_demand | local_only`.
    pub replication_priority: String,
    pub promotion: Option<PromotionConfig>,
    /// Names of `CurationRule` objects (referenced by `metadata.name`)
    /// attached to this repository. The embedded `curation:` config has
    /// been replaced — operators declare `CurationRule` objects
    /// separately and list them here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curation_rules: Option<Vec<String>>,
}

/// Per-repository storage placement hint.
///
/// **Honesty note.** Both fields are parsed and DB-persisted
/// (`repository.storage_backend` / `storage_path`,
/// mapper-round-tripped) but they do **not** route blob placement in
/// v2: the actual CAS is the single global storage adapter wired once
/// at serve start from the deployment-level `HORT_STORAGE_BACKEND`.
/// `backend` is enum-validated at parse to `{filesystem, s3}` (the
/// global value-domain) so it can no longer be a silent free-string
/// no-op, and an apply against a deployment whose effective global
/// backend differs is intended to be rejected loud + fail-closed rather
/// than silently ignored. Full per-repository multi-backend storage
/// routing is a planned future feature. Until that lands, the per-repo
/// `storage.backend` is parsed + persisted but does NOT route
/// placement; the apply-time mismatch reject keeps this honest.
///
/// `RepositorySpec.storage` is `Option<StorageSpec>`: omitting the
/// whole block is the documented honest path (inherit the deployment's
/// effective global backend). The apply-time mismatch reject and the
/// suggested remedy "omit the per-repo `storage:` block" are therefore
/// actually reachable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageSpec {
    /// `filesystem | s3` — enum-validated at parse, case-sensitive,
    /// matching the global `HORT_STORAGE_BACKEND` value-domain.
    /// Persisted but placement-inert in v2 (see the `StorageSpec`
    /// honesty note above).
    pub backend: String,
    pub path: String,
}

/// The closed value-domain for [`StorageSpec::backend`]. Mirrors the
/// global `HORT_STORAGE_BACKEND` enum (`hort-server`/`hort-worker`
/// config: `filesystem | s3`). Case-sensitive on purpose — the global
/// parser lowercases its input, but the per-repo gitops surface is
/// operator-authored YAML where a silent case-coercion would mask a
/// typo (the same posture `deny_unknown_fields` takes elsewhere).
///
/// `pub` so `hort-app`'s pure `EffectiveStorageBackend` enum can
/// assert it emits *exactly* these strings — the apply-time
/// per-repo-vs-global cross-check compares like for like.
pub const VALID_STORAGE_BACKENDS: &[&str] = &["filesystem", "s3"];

/// Enum-validate `storage.backend` at parse.
///
/// `hort-config` deliberately has no `regex`/enum-derive deps; a slice
/// `contains` check matches the established hand-rolled-validator
/// pattern in this module (`name_regex_matches`,
/// `is_posix_env_var_name`). Returns the distinct named
/// [`ParseError::InvalidStorageBackend`] so the operator learns
/// per-repo routing is unsupported in v2 (not that they typo'd a key).
fn validate_storage_backend(backend: &str) -> Result<(), ParseError> {
    if VALID_STORAGE_BACKENDS.contains(&backend) {
        Ok(())
    } else {
        Err(ParseError::InvalidStorageBackend {
            got: backend.to_string(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxySpec {
    pub upstream_url: String,
    /// Optional override for the index/metadata host on split-host
    /// registries. When set, Cargo metadata fetches (config.json +
    /// per-crate NDJSON) target this URL instead of `upstream_url`;
    /// the download leg always follows the resolved `RegistryConfig.dl`.
    /// The cross-spec validator rejects `Some(_)` on non-cargo formats
    /// and non-proxy repo types so this stays a narrow-surface escape
    /// hatch (`indexUpstreamUrl` in YAML, under the existing
    /// `deny_unknown_fields` schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_upstream_url: Option<String>,
}

/// Operator-visible name regex: DNS-safe, 1-63 chars, lowercase letter
/// first. Same constraint the DB enforces on `Repository.key`.
fn name_regex_matches(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Parse one `ArtifactRepository` envelope from a YAML file's bytes.
///
/// `path` is purely diagnostic — it appears in error messages so the
/// boot caller can render `path: <error>` lines from a `ParseErrors`
/// vec without re-tracking the source.
///
/// Steps:
/// 1. Pre-scan the raw YAML for the forbidden `proxy.credentials`
///    field. Without this, `deny_unknown_fields` on `ProxySpec` would
///    still fire — but with a generic "unknown field" message that
///    doesn't tell the operator the field is rejected as a
///    plaintext-credentials anti-pattern. The custom error points
///    toward the `UpstreamMappingSpec` kind for authenticated upstreams.
/// 2. Strict-deserialize into `Envelope<RepositorySpec>`. The inline
///    `proxy.secretRef` field was removed (it was parsed but never
///    wired to an upstream-auth writer); `ProxySpec`'s
///    `deny_unknown_fields` now rejects `proxy: { secretRef: ... }`
///    here. Authenticated upstreams use the standalone
///    `UpstreamMappingSpec` kind (`crate::upstream_mapping`).
/// 4. Enum-validate `storage.backend` against `{filesystem, s3}` —
///    case-sensitive, matching the global `HORT_STORAGE_BACKEND`
///    value-domain. Runs before interpolation: `backend` is not an
///    interpolated field, so a `${VAR}` there is itself an
///    out-of-domain value.
/// 5. Run `interpolate()` on every string-typed field that supports
///    `${VAR}` substitution. Enum-mapped strings (`format`, `type`,
///    `replicationPriority`) are NOT interpolated — operators don't
///    need substitution there, and silently expanding a typo'd
///    `${repo_type}` into nothing would break the cross-spec rules
///    in surprising ways.
pub fn parse_repository(path: &Path, bytes: &[u8]) -> Result<Envelope<RepositorySpec>, ParseError> {
    // Step 1: forbidden-field scan. Only `credentials:` is rejected;
    // the `secretRef` inline field was removed (see Step 3 note below).
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_slice(bytes)?;
    if let Some(spec) = raw.get("spec").and_then(|v| v.as_mapping()) {
        if let Some(proxy) = spec.get(serde_yaml_ng::Value::String("proxy".into())) {
            if let Some(map) = proxy.as_mapping() {
                if map
                    .get(serde_yaml_ng::Value::String("credentials".into()))
                    .is_some()
                {
                    return Err(ParseError::CredentialsFieldForbidden {
                        field: "credentials",
                    });
                }
            }
        }
    }

    // Step 2: strict deserialize into the typed envelope.
    let mut env: Envelope<RepositorySpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::ArtifactRepository {
        // The dispatch in `DesiredState::parse_files` routes by `kind`
        // first, so this branch only fires when a single-
        // file caller hands us the wrong envelope. Fail loudly rather
        // than silently coercing.
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["ArtifactRepository"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    let _ = path; // currently only used in cross-file error rendering

    // Step 3 (removed): the inline `proxy.secretRef` field was removed —
    // it was parsed and location-validated here but never wired to a
    // `RepositoryUpstreamMapping` writer (accepted-at-apply, inert-at-
    // runtime anti-pattern). With the field gone, `ProxySpec`'s
    // `deny_unknown_fields` now rejects any `proxy: { secretRef: ... }`
    // loud + fail-closed. Authenticated upstreams use the standalone
    // `UpstreamMappingSpec` gitops kind, which carries its own
    // `secret_ref` and IS wired to a writer (see `crate::upstream_mapping`
    // + `apply_upstream_mappings`). The shared `validate_secret_ref`
    // location-format check now runs only on that path.

    // Step 4: enum-validate `storage.backend`. The struct-level
    // `deny_unknown_fields` only catches stray keys; the *value* of
    // `backend` must be explicitly validated. Validate before
    // interpolation — `backend` is intentionally NOT interpolated (Step
    // 5 only interpolates `storage.path`), so a `${VAR}` here is not
    // expanded and is itself rejected as an out-of-domain literal.
    // `storage` is optional — an omitted block inherits the deployment's
    // effective global backend (resolved in the apply layer). Only
    // validate/interpolate when the operator actually supplied one.
    if let Some(storage) = env.spec.storage.as_ref() {
        validate_storage_backend(&storage.backend)?;
    }

    // Step 5: interpolation on the supported fields.
    if let Some(desc) = env.spec.description.as_mut() {
        *desc = interpolate(desc)?;
    }
    if let Some(storage) = env.spec.storage.as_mut() {
        storage.path = interpolate(&storage.path)?;
    }
    if let Some(p) = env.spec.proxy.as_mut() {
        p.upstream_url = interpolate(&p.upstream_url)?;
    }

    Ok(env)
}

/// Validate the location format of a `SecretRef`.
///
/// `source: file` → `location` must be an absolute path (`starts_with('/')`).
/// `source: env_var` → `location` must match `^[A-Z_][A-Z0-9_]*$`
/// (POSIX-portable identifier).
///
/// Existence of the referenced file or env var is NOT checked here —
/// the operator may populate it after gitops apply.
pub(crate) fn validate_secret_ref(secret_ref: &SecretRef) -> Result<(), ParseError> {
    match secret_ref.source {
        SecretSource::File => {
            if !secret_ref.location.starts_with('/') {
                return Err(ParseError::SecretRefLocationInvalid {
                    detail: format!(
                        "with `source: file` must be an absolute path, got `{}`",
                        secret_ref.location
                    ),
                });
            }
        }
        SecretSource::EnvVar => {
            if !is_posix_env_var_name(&secret_ref.location) {
                return Err(ParseError::SecretRefLocationInvalid {
                    detail: format!(
                        "with `source: env_var` must match `^[A-Z_][A-Z0-9_]*$` \
                         (uppercase letters, digits, underscores; no leading digit), \
                         got `{}`",
                        secret_ref.location
                    ),
                });
            }
        }
    }
    Ok(())
}

/// POSIX-portable env-var name check: `^[A-Z_][A-Z0-9_]*$`. Hand-rolled
/// byte-check matches the established crate pattern (`name_regex_matches`)
/// — `hort-config` deliberately has no `regex` dep. Distinct rules from
/// `name_regex_matches` (uppercase + underscores vs. lowercase + dashes);
/// do NOT consolidate.
fn is_posix_env_var_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    if !(bytes[0] == b'_' || bytes[0].is_ascii_uppercase()) {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Formats whose `type: virtual` **serve-time** member resolution has
/// shipped. A `type: virtual` repo whose `format` is **not** in this set
/// is rejected at gitops apply (see [`validate_repository`]).
///
/// This is the structural close for the ADR 0015 "apply-accepted,
/// runtime-inert field" anti-pattern that `virtualMembers` was the
/// canonical instance of: until a format's serve path consults the
/// members, accepting + persisting the membership edges while serving
/// nothing is exactly the inert-field violation. Rejecting at apply makes
/// the operator surface honest until resolution lands.
///
/// **Grows per format as serve-time resolution ships** (ADR 0031). Phase 1
/// added `Npm`, Phase 2 `Pypi`, Phase 3 `Cargo` — the three formats on the
/// shared Source → Filter → Builder `VersionEntry` pipeline. The steady
/// state rejects only the not-yet-specced formats (OCI/Maven/etc.), which is
/// correct — not an inert field. A future format joins this list when its
/// serve-time member resolution ships.
///
/// `pub` so later-phase serve code and tests can assert against the
/// single source of truth rather than re-listing the supported formats.
pub const VIRTUAL_SERVE_SUPPORTED_FORMATS: &[RepositoryFormat] = &[
    RepositoryFormat::Npm,
    RepositoryFormat::Pypi,
    RepositoryFormat::Cargo,
];

/// Per-spec validation: applies only to one envelope's content.
///
/// Cross-spec rules (duplicate names, dangling members across files,
/// managed conflicts against the snapshot) live in `crate::desired`.
/// Splitting the surface keeps unit tests local — the cross-spec
/// rules need a `DesiredState` fixture, the per-spec ones don't.
///
/// Returns *every* violation rather than first-error-wins, so an
/// operator gets the full list in one boot pass.
pub fn validate_repository(env: &Envelope<RepositorySpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = &env.metadata.name;
    let kind = Kind::ArtifactRepository;

    if !name_regex_matches(name) {
        errors.push(ValidationError::Invalid {
            kind,
            name: name.clone(),
            detail: format!("metadata.name `{name}` must match ^[a-z][a-z0-9-]{{0,62}}$"),
        });
    }

    // Format must parse and not be `Other(_)`. The admin handler
    // applies the same rule (handlers/admin.rs:251) — managed repos
    // get the same guarantee that they reach a real format dispatch.
    let format: RepositoryFormat = env.spec.format.parse().unwrap_or(RepositoryFormat::Generic);
    if matches!(format, RepositoryFormat::Other(_)) {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.format",
            got: env.spec.format.clone(),
            // Bounded subset for the error message; the full ~40-name
            // list would be noise. Operators referencing an unknown
            // format know what they meant — the message orients them.
            expected: vec!["npm", "pypi", "cargo", "maven", "docker", "..."],
        });
    }

    // type ∈ {hosted, proxy, virtual, staging}.
    let repo_type = match RepositoryType::from_str(&env.spec.repo_type) {
        Ok(t) => Some(t),
        Err(_) => {
            errors.push(ValidationError::UnknownEnumValue {
                field: "spec.type",
                got: env.spec.repo_type.clone(),
                expected: vec!["hosted", "proxy", "virtual", "staging"],
            });
            None
        }
    };

    if ReplicationPriority::from_str(&env.spec.replication_priority).is_err() {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.replicationPriority",
            got: env.spec.replication_priority.clone(),
            expected: vec!["immediate", "scheduled", "on_demand", "local_only"],
        });
    }

    // Prefetch-policy upper-bound caps (architect review).
    //
    // Migration `002_repositories.sql` stores `prefetch_depth` /
    // `prefetch_transitive_depth` / `prefetch_max_age_days` as `int`
    // (PostgreSQL `int4`, i.e. signed 32-bit). The bind path narrows
    // the domain `u32` to `i32` via `as i32`, so a value above
    // `i32::MAX` silently wraps to a negative on write; the mapper's
    // defensive `u32::try_from(i32).ok().unwrap_or(default)` then
    // rejects the negative and falls back to the in-code default on
    // read. Net effect without this gate: the operator wrote one
    // value, the system stored / served another, with no diagnostic.
    //
    // Cap at parse-time so the operator sees the typo at apply rather
    // than discovering the silent fallback by reading metrics later.
    // The cap is generous (`10_000`) — practical operator values are
    // 1-100 for depth, 1-3650 for `maxAgeDays` (a decade); the cap is
    // a wrap-prevention bound, not a tuning suggestion. Mirrors the
    // existing hand-rolled-validator pattern in this module
    // (`validate_storage_backend`, `name_regex_matches`).
    const MAX_REASONABLE_PREFETCH_BOUND: u32 = 10_000;
    if env.spec.prefetch_policy.depth > MAX_REASONABLE_PREFETCH_BOUND {
        errors.push(ValidationError::Invalid {
            kind,
            name: name.clone(),
            detail: format!(
                "spec.prefetchPolicy.depth = {} exceeds the configured cap of {}. \
                 Practical operator values are 1-100; the cap exists to catch \
                 i32 wrap-on-write that would silently fall back to the in-code \
                 default on read (architect review).",
                env.spec.prefetch_policy.depth, MAX_REASONABLE_PREFETCH_BOUND,
            ),
        });
    }
    if env.spec.prefetch_policy.transitive_depth > MAX_REASONABLE_PREFETCH_BOUND {
        errors.push(ValidationError::Invalid {
            kind,
            name: name.clone(),
            detail: format!(
                "spec.prefetchPolicy.transitiveDepth = {} exceeds the configured cap of {}. \
                 Cap mirrors `spec.prefetchPolicy.depth` — architect review.",
                env.spec.prefetch_policy.transitive_depth, MAX_REASONABLE_PREFETCH_BOUND,
            ),
        });
    }
    if let Some(days) = env.spec.prefetch_policy.max_age_days {
        if days > MAX_REASONABLE_PREFETCH_BOUND {
            errors.push(ValidationError::Invalid {
                kind,
                name: name.clone(),
                detail: format!(
                    "spec.prefetchPolicy.maxAgeDays = {days} exceeds the configured cap of \
                     {MAX_REASONABLE_PREFETCH_BOUND}. A decade is ~3650 days; values above \
                     the cap exist only as the u32-near-MAX wrap footgun architect review \
                     the cap caught."
                ),
            });
        }
    }

    // `maxDescendants` upper bound — distinct from
    // `MAX_REASONABLE_PREFETCH_BOUND` (10_000) because this knob's
    // operator-set values are usually larger (100-10_000 transitive
    // closures are plausible); the cap exists specifically to keep an
    // operator typo (`4_000_000_000`) from effectively disabling the
    // cascade ceiling. `0` is a deliberate operator value (collapse the
    // feature to leaf-prefetch-only) and is accepted.
    const MAX_DESCENDANTS_BOUND: u32 = 100_000;
    if env.spec.prefetch_policy.max_descendants > MAX_DESCENDANTS_BOUND {
        errors.push(ValidationError::Invalid {
            kind,
            name: name.clone(),
            detail: format!(
                "spec.prefetchPolicy.maxDescendants = {} exceeds the configured cap of {}. \
                 The cap exists so an operator typo cannot effectively disable the cumulative \
                 cascade ceiling. 0 collapses the feature to \
                 leaf-prefetch-only.",
                env.spec.prefetch_policy.max_descendants, MAX_DESCENDANTS_BOUND,
            ),
        });
    }

    // Cross-field shape rules — only run when the type parsed; an
    // unknown type already failed loudly above and chaining the rules
    // on top would produce noise.
    if let Some(t) = repo_type {
        match t {
            RepositoryType::Proxy => {
                let proxy_present = env.spec.proxy.is_some();
                let members_present = env.spec.virtual_members.is_some();
                if !proxy_present {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: "type=proxy requires a `proxy:` block".into(),
                    });
                }
                if members_present {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: "type=proxy must not declare virtualMembers".into(),
                    });
                }
            }
            RepositoryType::Virtual => {
                // ADR 0015 / ADR 0031 inert-field stopgap: reject a
                // `type: virtual` repo whose format has no serve-time
                // member resolution yet. `VIRTUAL_SERVE_SUPPORTED_FORMATS`
                // is the single source of truth (npm/pypi/cargo today); the
                // set grows per format as resolution ships (see the const's
                // doc + ADR 0031).
                // Skip when the format itself is unknown — the
                // `Other(_)` check above already reported that and adding
                // this on top is noise.
                if !matches!(format, RepositoryFormat::Other(_))
                    && !VIRTUAL_SERVE_SUPPORTED_FORMATS.contains(&format)
                {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: format!(
                            "type=virtual is not yet serve-supported for format \
                             `{}` — virtualMembers would be accepted but never \
                             served (ADR 0015 inert-field). Serve-time aggregation \
                             ships per format (npm/pypi/cargo today); see ADR 0031 \
                             and docs/architecture/how-to/declare-gitops-config.md",
                            env.spec.format
                        ),
                    });
                }

                let proxy_present = env.spec.proxy.is_some();
                let members = env.spec.virtual_members.as_deref().unwrap_or(&[]);
                if proxy_present {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: "type=virtual must not declare a proxy block".into(),
                    });
                }
                if members.is_empty() {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: "type=virtual requires non-empty virtualMembers".into(),
                    });
                }
                // Per-entry: regex, no dupes, no self-reference.
                let mut seen = std::collections::HashSet::new();
                for member in members {
                    if !name_regex_matches(member) {
                        errors.push(ValidationError::Invalid {
                            kind,
                            name: name.clone(),
                            detail: format!(
                                "virtualMembers entry `{member}` must match \
                                 ^[a-z][a-z0-9-]{{0,62}}$"
                            ),
                        });
                    }
                    if member == name {
                        errors.push(ValidationError::Invalid {
                            kind,
                            name: name.clone(),
                            detail: "virtualMembers must not reference \
                                     metadata.name (self-reference)"
                                .into(),
                        });
                    }
                    if !seen.insert(member.clone()) {
                        errors.push(ValidationError::Invalid {
                            kind,
                            name: name.clone(),
                            detail: format!("duplicate virtualMembers entry `{member}`"),
                        });
                    }
                }
            }
            RepositoryType::Hosted | RepositoryType::Staging => {
                if env.spec.proxy.is_some() {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: format!(
                            "type={t} must not declare a proxy block (only type=proxy may)"
                        ),
                    });
                }
                if env.spec.virtual_members.is_some() {
                    errors.push(ValidationError::Invalid {
                        kind,
                        name: name.clone(),
                        detail: format!(
                            "type={t} must not declare virtualMembers (only type=virtual may)"
                        ),
                    });
                }
            }
        }
    }

    if let Some(qb) = env.spec.quota_bytes {
        if qb <= 0 {
            errors.push(ValidationError::Invalid {
                kind,
                name: name.clone(),
                detail: format!("quotaBytes must be > 0, got {qb}"),
            });
        }
    }

    if let Some(p) = env.spec.proxy.as_ref() {
        if !is_http_url_with_host(&p.upstream_url) {
            errors.push(ValidationError::Invalid {
                kind,
                name: name.clone(),
                detail: format!(
                    "proxy.upstreamUrl `{}` must be an http or https URL with a host",
                    p.upstream_url
                ),
            });
        }

        // `indexUpstreamUrl` override: per-spec rule mirrors
        // `upstream_url`: must be an http(s) URL with a host. The
        // format / repo-type narrowness is enforced separately below.
        if let Some(idx) = p.index_upstream_url.as_deref() {
            if !is_http_url_with_host(idx) {
                errors.push(ValidationError::Invalid {
                    kind,
                    name: name.clone(),
                    detail: format!(
                        "proxy.indexUpstreamUrl `{idx}` must be an http or https URL with a host"
                    ),
                });
            }

            // Cross-spec narrowing: `indexUpstreamUrl` is only meaningful
            // for cargo proxy repositories. The `repo_type != proxy`
            // arm is structurally unreachable today because the
            // `Hosted | Staging` arm above already rejects the entire
            // `proxy:` block on non-proxy types — we restate the rule
            // explicitly so a future refactor that loosens that guard
            // does not silently expose an `index_upstream_url` write
            // path on hosted repos.
            if env.spec.format != "cargo" {
                errors.push(ValidationError::Invalid {
                    kind,
                    name: name.clone(),
                    detail: "proxy.indexUpstreamUrl is only valid for cargo proxy repositories"
                        .into(),
                });
            }
            if env.spec.repo_type != "proxy" {
                errors.push(ValidationError::Invalid {
                    kind,
                    name: name.clone(),
                    detail: "proxy.indexUpstreamUrl is only valid for cargo proxy repositories"
                        .into(),
                });
            }
        }
    }

    errors
}

/// Cheap http/https + host check without pulling in a URL parser.
///
/// `hort-config` has zero deps on `url`/`reqwest` — the only consumer
/// is one validator. Inlining the parse keeps the dep graph small.
fn is_http_url_with_host(s: &str) -> bool {
    let rest = if let Some(r) = s.strip_prefix("https://") {
        r
    } else if let Some(r) = s.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    /// Build a complete YAML doc by interpolating `spec_body` into the
    /// envelope. `spec_body` must already be 2-space indented (one
    /// level under `spec:`). The literal raw newline at the start
    /// prevents Rust's `\` line-continuation from stripping leading
    /// whitespace and corrupting indentation.
    fn yaml(spec_body: &str) -> String {
        format!(
            "apiVersion: project-hort.de/v1beta1\nkind: ArtifactRepository\nmetadata:\n  name: npm-public\nspec:{spec_body}"
        )
    }

    #[test]
    fn parse_complete_envelope_round_trip() {
        let body = "
  name: \"npm Public Mirror\"
  description: \"npmjs.org pull-through cache\"
  format: npm
  type: proxy
  storage:
    backend: filesystem
    path: /var/lib/hort/npm-public
  proxy:
    upstreamUrl: https://registry.npmjs.org
  isPublic: true
  quotaBytes: 1073741824
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(env.metadata.name, "npm-public");
        assert_eq!(env.spec.name, "npm Public Mirror");
        assert_eq!(env.spec.format, "npm");
        assert_eq!(env.spec.repo_type, "proxy");
        assert_eq!(
            env.spec.proxy.as_ref().unwrap().upstream_url,
            "https://registry.npmjs.org"
        );
        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    #[test]
    fn interpolation_in_storage_path_and_upstream_url() {
        // The lookup hits real env via the public `interpolate`. Use a
        // var that almost certainly isn't set so we observe failure;
        // success-path interpolation is covered by interpolate's own
        // unit tests, which don't have to fight cargo's parallel env.
        let body = "
  name: x
  format: npm
  type: proxy
  storage:
    backend: filesystem
    path: \"/var/lib/${HORT_TEST_VAR_THAT_DOES_NOT_EXIST_zzz}\"
  proxy:
    upstreamUrl: https://example.com
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::InterpolationVarNotFound { .. }));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
  bogus_field: 42
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        // serde_yaml_ng's deny_unknown_fields surfaces under Yaml, not
        // a custom variant. The message must name the offending field
        // so the operator can locate it.
        let rendered = err.to_string();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(
            rendered.contains("bogus_field"),
            "yaml error must name the unknown field: {rendered}"
        );
    }

    #[test]
    fn proxy_credentials_field_is_forbidden() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://example.com
    credentials: { username: u, password: p }
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        match err {
            ParseError::CredentialsFieldForbidden { field } => assert_eq!(field, "credentials"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The inline `proxy.secretRef` field was removed because it was
    /// parsed + location-validated but never wired to an upstream-auth
    /// writer (accepted-at-apply, inert-at-runtime anti-pattern). With
    /// the field gone, `ProxySpec`'s `deny_unknown_fields` rejects any
    /// `proxy: { secretRef: ... }` loud + fail-closed. This test
    /// replaces the former `proxy_secret_ref_*_round_trips` tests.
    /// Authenticated upstreams use the standalone `UpstreamMappingSpec`
    /// kind (its own `secret_ref` IS wired); the shared
    /// `validate_secret_ref` location-format coverage now lives in the
    /// direct `validate_secret_ref_*` unit tests below and in
    /// `upstream_mapping::tests::parse_rejects_invalid_secret_ref_location`.
    #[test]
    fn proxy_with_secret_ref_is_rejected_as_unknown_field() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://example.com
    secretRef:
      source: file
      location: /run/secrets/ghcr-token
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        // `deny_unknown_fields` on `ProxySpec` surfaces under Yaml, not a
        // custom variant. The message must name the offending field so the
        // operator can locate it (and learn it is no longer a `ProxySpec`
        // key).
        let rendered = err.to_string();
        assert!(
            matches!(err, ParseError::Yaml(_)),
            "expected yaml parse error: {rendered}"
        );
        assert!(
            rendered.contains("secretRef"),
            "yaml error must name the unknown field: {rendered}"
        );
    }

    #[test]
    fn proxy_without_secret_ref_still_parses() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://example.com
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let proxy = env.spec.proxy.expect("proxy block parsed");
        assert_eq!(proxy.upstream_url, "https://example.com");
    }

    #[test]
    fn validate_secret_ref_file_source_rules() {
        // (location, expect_ok)
        let cases: &[(&str, bool)] = &[
            ("/run/secrets/x", true),
            ("/etc/hort/token", true),
            ("relative/path", false),
            ("./bad", false),
            ("", false),
        ];

        for &(location, expect_ok) in cases {
            let r = SecretRef {
                source: SecretSource::File,
                location: location.into(),
            };
            let result = validate_secret_ref(&r);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "expected file source location `{location}` to be ok={expect_ok}"
            );
        }
    }

    #[test]
    fn validate_secret_ref_env_var_source_rules() {
        let cases: &[(&str, bool)] = &[
            ("GHCR_TOKEN", true),
            ("_LEADING", true),
            ("MY_VAR_2", true),
            ("lowercase", false),
            ("WITH-DASH", false),
            ("WITH SPACE", false),
            ("2LEADING_DIGIT", false),
            ("", false),
        ];

        for &(location, expect_ok) in cases {
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: location.into(),
            };
            let result = validate_secret_ref(&r);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "expected env_var source location `{location}` to be ok={expect_ok}"
            );
        }
    }

    #[test]
    fn type_proxy_without_proxy_block_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("type=proxy requires")));
    }

    #[test]
    fn type_hosted_with_proxy_block_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: https://example.com }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("must not declare a proxy block")));
    }

    #[test]
    fn type_virtual_without_members_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: virtual
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("non-empty virtualMembers")));
    }

    #[test]
    fn type_virtual_with_self_reference_is_validation_error() {
        // metadata.name == "x" and virtualMembers contains "x" — the
        // self-reference rule must fire.
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: x
spec:
  name: x
  format: npm
  type: virtual
  storage: { backend: filesystem, path: /x }
  virtualMembers: [npm-public, x]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("self-reference")));
    }

    #[test]
    fn type_virtual_with_duplicate_members_is_validation_error() {
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: a
spec:
  name: a
  format: npm
  type: virtual
  storage: { backend: filesystem, path: /x }
  virtualMembers: [b, b, c]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("duplicate virtualMembers entry `b`")));
    }

    #[test]
    fn type_hosted_with_virtual_members_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  virtualMembers: [a]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("must not declare virtualMembers")));
    }

    #[test]
    fn type_virtual_unsupported_format_is_validation_error() {
        // ADR 0015 inert-field stopgap (spec §9 part A): a format absent from
        // `VIRTUAL_SERVE_SUPPORTED_FORMATS` is rejected at apply rather than
        // accepted with an inert `virtualMembers`. npm/pypi/cargo are lifted
        // (Phases 1-3); `maven` is a known, still-unsupported format — the
        // correct steady state. The repo below is otherwise valid (members
        // present, no dup, no self-reference), so the unsupported-format
        // rejection is the operative error.
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: vroot
spec:
  name: vroot
  format: maven
  type: virtual
  storage: { backend: filesystem, path: /x }
  virtualMembers: [a, b]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("not yet serve-supported")));
    }

    #[test]
    fn type_virtual_npm_is_serve_supported() {
        // Phase 1 lifted npm into `VIRTUAL_SERVE_SUPPORTED_FORMATS`, so a
        // valid `type: virtual` npm repo no longer trips the inert-field
        // stopgap — `virtualMembers` is now genuinely served (ADR 0031).
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: vroot
spec:
  name: vroot
  format: npm
  type: virtual
  storage: { backend: filesystem, path: /x }
  virtualMembers: [a, b]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            !errors
                .iter()
                .any(|e| e.to_string().contains("not yet serve-supported")),
            "npm virtual is serve-supported and must not trip the stopgap: {errors:?}"
        );
    }

    #[test]
    fn type_virtual_unknown_format_skips_serve_support_error() {
        // The unsupported-format check is suppressed when the format itself is
        // unknown (`Other(_)`) — that is reported by the format check, and
        // stacking "not yet serve-supported" on top would be noise. Exercises
        // the `!matches!(format, Other(_))` short-circuit (cond-false arm).
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: vroot
spec:
  name: vroot
  format: madeupformat
  type: virtual
  storage: { backend: filesystem, path: /x }
  virtualMembers: [a, b]
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            !errors
                .iter()
                .any(|e| e.to_string().contains("not yet serve-supported")),
            "unknown format must not also raise the serve-support error"
        );
    }

    #[test]
    fn metadata_name_uppercase_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: ArtifactRepository\nmetadata:\n  name: NPM-Public\nspec:\n{body}"
        );
        let env = parse_repository(&p(), yaml_doc.as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("must match")));
    }

    #[test]
    fn quota_bytes_zero_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  quotaBytes: 0
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("quotaBytes must be > 0")));
    }

    #[test]
    fn quota_bytes_negative_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  quotaBytes: -100
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("quotaBytes must be > 0")));
    }

    #[test]
    fn proxy_upstream_url_must_be_http_or_https() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: \"ftp://example.com\" }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("must be an http or https URL")));
    }

    #[test]
    fn proxy_upstream_url_without_host_is_invalid() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: \"https:///path\" }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("must be an http or https URL")));
    }

    // -- Typed `proxy.indexUpstreamUrl` override --------

    /// Happy path: a cargo proxy repo with a valid https
    /// `indexUpstreamUrl` parses cleanly and produces no validation
    /// errors. Exercises the field's serde mapping (camelCase
    /// `indexUpstreamUrl` ↔ `index_upstream_url`) and confirms the
    /// per-spec validator accepts an http(s) URL with a host.
    #[test]
    fn proxy_index_upstream_url_parses_when_https() {
        let body = "
  name: x
  format: cargo
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://crates.io
    indexUpstreamUrl: https://internal-index.example.com
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let proxy = env.spec.proxy.as_ref().expect("proxy block");
        assert_eq!(
            proxy.index_upstream_url.as_deref(),
            Some("https://internal-index.example.com")
        );
        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    /// `downloadAuditEnabled` is an additive, `#[serde(default)]`
    /// opt-in. Absent ⇒ `false` (non-breaking for existing gitops
    /// configs); `true` parses and round-trips through
    /// serialize/deserialize.
    #[test]
    fn download_audit_enabled_defaults_false_when_absent() {
        let body = "
  name: x
  format: pypi
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert!(
            !env.spec.download_audit_enabled,
            "absent downloadAuditEnabled must default to false (additive/non-breaking)"
        );
        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    // -- `indexMode` is optional + snake_case enum ---------

    /// `indexMode` is `#[serde(default)]`; an absent field deserialises
    /// to `IndexMode::ReleasedOnly`, the build-safe posture. Existing
    /// gitops configs are non-breaking under `deny_unknown_fields`.
    #[test]
    fn index_mode_defaults_released_only_when_absent() {
        let body = "
  name: x
  format: pypi
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.index_mode,
            IndexMode::ReleasedOnly,
            "absent indexMode must default to ReleasedOnly (additive/non-breaking)"
        );
        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    /// `indexMode: include_pending` parses to the typed enum. The
    /// on-wire literal uses snake_case so it matches the migration
    /// column value-domain (`'released_only','include_pending'`) 1:1;
    /// the cross-layer contract is locked by the round-trip below.
    /// (Renamed from `filter_quarantined` pre-v1.0, in-place.)
    #[test]
    fn index_mode_parses_include_pending_and_serde_round_trips() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: https://registry.npmjs.org }
  isPublic: true
  indexMode: include_pending
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(env.spec.index_mode, IndexMode::IncludePending);
        // serde round-trip preserves the variant; this pins the on-wire
        // literal so a rename without a migration breaks the test.
        let json = serde_json::to_string(&env.spec).unwrap();
        assert!(
            json.contains("\"include_pending\""),
            "expected snake_case on-wire literal in JSON: {json}"
        );
        let decoded: RepositorySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.index_mode, IndexMode::IncludePending);
    }

    /// An out-of-domain `indexMode` literal is rejected at parse with
    /// serde's deny-unknown-variant message. Belt-and-braces with the
    /// DB CHECK constraint added in migration 002.
    #[test]
    fn index_mode_unknown_value_is_rejected_at_parse() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  indexMode: permissive
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        let rendered = err.to_string();
        assert!(matches!(err, ParseError::Yaml(_)), "got {rendered}");
        assert!(
            rendered.contains("permissive"),
            "error must name the bad value: {rendered}"
        );
    }

    // -- `prefetchPolicy` is optional + nested camelCase ---

    /// `prefetchPolicy` is `#[serde(default)]`; an absent field
    /// deserialises to `PrefetchPolicy::default()` (the
    /// disabled-with-no-triggers posture). Existing gitops configs are
    /// non-breaking under `deny_unknown_fields`.
    #[test]
    fn prefetch_policy_defaults_disabled_when_absent() {
        let body = "
  name: x
  format: pypi
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.prefetch_policy,
            PrefetchPolicy::default(),
            "absent prefetchPolicy must default to PrefetchPolicy::default() (additive/non-breaking)"
        );
        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    /// A populated `prefetchPolicy` block parses through the typed
    /// `PrefetchPolicy` struct. YAML keys are camelCase
    /// (`transitiveDepth`, `maxAgeDays`) to match the surrounding
    /// `RepositorySpec` convention; trigger values are the
    /// migration-CHECK snake_case literals.
    #[test]
    fn prefetch_policy_parses_populated_block_and_serde_round_trips() {
        use hort_domain::entities::repository::PrefetchTrigger;
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: https://registry.npmjs.org }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move, scheduled]
    depth: 10
    transitiveDepth: 7
    maxAgeDays: 180
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert!(env.spec.prefetch_policy.enabled);
        assert_eq!(
            env.spec.prefetch_policy.triggers,
            vec![PrefetchTrigger::OnDistTagMove, PrefetchTrigger::Scheduled]
        );
        assert_eq!(env.spec.prefetch_policy.depth, 10);
        assert_eq!(env.spec.prefetch_policy.transitive_depth, 7);
        assert_eq!(env.spec.prefetch_policy.max_age_days, Some(180));

        // serde round-trip preserves the typed value and the camelCase
        // wire form. Pins the cross-layer naming contract — a stray
        // rename on `PrefetchPolicy` lights this test up.
        let json = serde_json::to_string(&env.spec).unwrap();
        assert!(
            json.contains("\"transitiveDepth\"")
                && json.contains("\"maxAgeDays\"")
                && json.contains("\"on_dist_tag_move\""),
            "expected camelCase fields + snake_case trigger literals: {json}"
        );
        let decoded: RepositorySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.prefetch_policy, env.spec.prefetch_policy);
    }

    /// A *minimal* `prefetchPolicy` block (`enabled` + `triggers` only)
    /// parses with the documented numeric defaults applied (`depth = 3`,
    /// `transitiveDepth = 5`, `maxAgeDays = None`, `maxDescendants =
    /// 200`). Before the field-level serde defaults landed on
    /// `PrefetchPolicy`, `depth` / `transitiveDepth` / `maxAgeDays` were
    /// required, so this block failed one missing-field error per restart
    /// — the alpha-reported three-crashloop authoring loop. `enabled` +
    /// `triggers` stay required (no struct-level `#[serde(default)]`),
    /// so `prefetchPolicy: {}` still cannot silently disable prefetch.
    #[test]
    fn prefetch_policy_minimal_block_applies_documented_defaults() {
        use hort_domain::entities::repository::PrefetchTrigger;
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: https://registry.npmjs.org }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [transitive_deps]
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let pp = &env.spec.prefetch_policy;
        assert!(pp.enabled);
        assert_eq!(pp.triggers, vec![PrefetchTrigger::TransitiveDeps]);
        assert_eq!(pp.depth, 3, "depth must default to 3");
        assert_eq!(pp.transitive_depth, 5, "transitiveDepth must default to 5");
        assert_eq!(pp.max_age_days, None, "maxAgeDays must default to None");
        assert_eq!(
            pp.max_descendants, 200,
            "maxDescendants must default to 200"
        );

        let errors = validate_repository(&env);
        assert!(errors.is_empty(), "should be valid: {errors:?}");
    }

    /// An out-of-domain `triggers` literal is rejected at parse with
    /// serde's deny-unknown-variant message (belt-and-braces with the
    /// migration CHECK).
    #[test]
    fn prefetch_policy_unknown_trigger_is_rejected_at_parse() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [eager]
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        let rendered = err.to_string();
        assert!(matches!(err, ParseError::Yaml(_)), "got {rendered}");
        assert!(
            rendered.contains("eager"),
            "error must name the bad trigger: {rendered}"
        );
    }

    #[test]
    fn download_audit_enabled_parses_true_and_serde_round_trips() {
        let body = "
  name: x
  format: pypi
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  downloadAuditEnabled: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert!(env.spec.download_audit_enabled);
        // serde round-trip preserves the explicit value.
        let json = serde_json::to_string(&env.spec).unwrap();
        let decoded: RepositorySpec = serde_json::from_str(&json).unwrap();
        assert!(decoded.download_audit_enabled);
        assert_eq!(decoded, env.spec);
    }

    /// Per-spec rule mirrors `upstream_url`: a non-http(s) scheme on
    /// `indexUpstreamUrl` is rejected with the standard URL-shape
    /// message. Distinct from the cross-spec narrowing checked below;
    /// this is the URL-form check.
    #[test]
    fn proxy_index_upstream_url_rejected_when_not_https() {
        let body = "
  name: x
  format: cargo
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://crates.io
    indexUpstreamUrl: \"ftp://internal-index.example.com\"
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors
                .iter()
                .any(|e| e.to_string().contains("indexUpstreamUrl")
                    && e.to_string().contains("must be an http or https URL")),
            "expected indexUpstreamUrl URL-shape rejection: {errors:?}"
        );
    }

    /// Regression for `deny_unknown_fields` on `ProxySpec`: the new
    /// field landing in this item must NOT widen the schema. A typo
    /// (`indexUpstream` without the `Url` suffix) is still rejected
    /// at parse time — keeps the surface area honest.
    #[test]
    fn proxy_unknown_field_still_rejected_under_deny_unknown_fields() {
        let body = "
  name: x
  format: cargo
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://crates.io
    indexUpstream: https://internal-index.example.com
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        let rendered = err.to_string();
        assert!(
            matches!(err, ParseError::Yaml(_)),
            "expected yaml parse error: {rendered}"
        );
        assert!(
            rendered.contains("indexUpstream"),
            "yaml error must name the unknown field: {rendered}"
        );
    }

    /// Cross-spec narrowing: `indexUpstreamUrl` is meaningful only for
    /// cargo proxies. A `format != cargo` proxy with the override set
    /// is rejected with the canonical message.
    #[test]
    fn proxy_index_upstream_url_rejected_for_non_cargo_format() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy:
    upstreamUrl: https://registry.npmjs.org
    indexUpstreamUrl: https://internal-index.example.com
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| e
                .to_string()
                .contains("indexUpstreamUrl is only valid for cargo proxy repositories")),
            "expected non-cargo cross-spec rejection: {errors:?}"
        );
    }

    /// Cross-spec narrowing: `indexUpstreamUrl` requires `type: proxy`.
    /// In practice the `repo_type != proxy` arm is structurally
    /// unreachable because the broader "no `proxy:` block on hosted /
    /// staging" rule catches it first — but the validator restates the
    /// rule explicitly so a future loosening of that broader rule does
    /// not silently expose the override on hosted repos.
    ///
    /// We hand-craft an `Envelope<RepositorySpec>` rather than parse
    /// YAML for this test: the parser would reject the `proxy:` block
    /// on a hosted repo before the cross-spec rule fires. Going through
    /// `validate_repository` directly is the only way to observe the
    /// guard we want to lock down.
    #[test]
    fn proxy_index_upstream_url_rejected_for_non_proxy_type() {
        use crate::envelope::{Envelope, Kind, Metadata};
        use crate::ApiVersion;

        let env = Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: "x".into() },
            spec: RepositorySpec {
                name: "x".into(),
                description: None,
                format: "cargo".into(),
                repo_type: "hosted".into(),
                storage: Some(StorageSpec {
                    backend: "filesystem".into(),
                    path: "/x".into(),
                }),
                proxy: Some(ProxySpec {
                    upstream_url: "https://crates.io".into(),
                    index_upstream_url: Some("https://internal-index.example.com".into()),
                }),
                virtual_members: None,
                is_public: true,
                download_audit_enabled: false,
                index_mode: IndexMode::default(),
                prefetch_policy: PrefetchPolicy::default(),
                quota_bytes: None,
                replication_priority: "immediate".into(),
                promotion: None,
                curation_rules: None,
            },
        };

        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| e
                .to_string()
                .contains("indexUpstreamUrl is only valid for cargo proxy repositories")),
            "expected non-proxy cross-spec rejection: {errors:?}"
        );
    }

    // -- StorageSpec.backend enum-validation --

    /// A `storage.backend` value outside `{filesystem, s3}` is rejected
    /// at parse with the distinct named
    /// [`ParseError::InvalidStorageBackend`] variant — not the generic
    /// `deny_unknown_fields` Yaml error (the *key* is known; only its
    /// *value* is out of the enum domain). The message must name the
    /// offending value and explain that per-repo storage routing is not
    /// yet implemented.
    #[test]
    fn storage_backend_invalid_value_is_rejected_at_parse() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: glacier, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml(body).as_bytes()).unwrap_err();
        match err {
            ParseError::InvalidStorageBackend { got } => {
                assert_eq!(got, "glacier");
                let rendered = ParseError::InvalidStorageBackend {
                    got: "glacier".into(),
                }
                .to_string();
                assert!(
                    rendered.contains("glacier"),
                    "message must name the bad value: {rendered}"
                );
                assert!(
                    rendered.contains("filesystem") && rendered.contains("s3"),
                    "message must enumerate the allowed set: {rendered}"
                );
                assert!(
                    rendered.contains("not yet implemented"),
                    "message must note routing is unimplemented: {rendered}"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// `backend: filesystem` is accepted (the value the
    /// shipped docs/fixtures use — must stay green unchanged).
    #[test]
    fn storage_backend_filesystem_is_accepted_at_parse() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(env.spec.storage.as_ref().unwrap().backend, "filesystem");
    }

    /// A `RepositorySpec` with **no** `storage:` block parses cleanly
    /// to `None` (regression pin: it used to fail serde with
    /// `missing field 'storage'` — the exact crash that bricked a
    /// config-swapped pod). Omission is the documented honest path:
    /// inherit the deployment's effective global backend (resolved in
    /// the apply layer, covered by `hort-app` tests).
    #[test]
    fn storage_omitted_parses_to_none() {
        let body = "
  name: x
  format: npm
  type: hosted
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes())
            .expect("a storage-omitted RepositorySpec must parse");
        assert!(
            env.spec.storage.is_none(),
            "omitted storage must deserialise to None, not a default"
        );
    }

    /// `backend: s3` is accepted at parse (matches the global
    /// `HORT_STORAGE_BACKEND` value-domain; case-sensitive). Acceptance
    /// at parse does NOT imply per-repo routing — placement is still the
    /// single global adapter; the apply-time mismatch reject and the
    /// honesty doc-comment carry that contract.
    #[test]
    fn storage_backend_s3_is_accepted_at_parse() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: s3, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(env.spec.storage.as_ref().unwrap().backend, "s3");
    }

    /// The enum check is case-sensitive — it must match the
    /// global `HORT_STORAGE_BACKEND` value-domain exactly. `Filesystem`
    /// / `S3` (wrong case) are rejected, never silently coerced.
    #[test]
    fn storage_backend_enum_is_case_sensitive() {
        for bad in ["Filesystem", "S3", "FILESYSTEM", " s3"] {
            let body = format!(
                "
  name: x
  format: npm
  type: hosted
  storage: {{ backend: \"{bad}\", path: /x }}
  isPublic: true
  replicationPriority: immediate
"
            );
            let err = parse_repository(&p(), yaml(&body).as_bytes()).unwrap_err();
            assert!(
                matches!(err, ParseError::InvalidStorageBackend { ref got } if got == bad),
                "case-variant `{bad}` must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn unknown_format_surfaces_as_validation_error() {
        let body = "
  name: x
  format: madeupformat
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("madeupformat")));
    }

    #[test]
    fn unknown_repo_type_surfaces_as_validation_error_and_skips_shape_rules() {
        let body = "
  name: x
  format: npm
  type: weird
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        // Only the type error should fire — shape rules are skipped to
        // avoid spurious "must not declare ..." chains on top of the
        // primary error.
        assert!(errors.iter().any(|e| e.to_string().contains("weird")));
        assert!(!errors
            .iter()
            .any(|e| e.to_string().contains("requires a `proxy:` block")));
    }

    #[test]
    fn unknown_replication_priority_is_validation_error() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: never
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("never")));
    }

    // -----------------------------------------------------------------
    // Prefetch-policy upper-bound caps
    // -----------------------------------------------------------------

    /// Practical operator values pass — Cap is a wrap-prevention bound
    /// (`10_000`), not a tuning suggestion. 100 is well-inside it.
    #[test]
    fn prefetch_policy_practical_values_accepted_at_parse_time() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 100
    transitiveDepth: 50
    maxAgeDays: 365
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            !errors
                .iter()
                .any(|e| e.to_string().contains("prefetchPolicy")),
            "100/50/365 must all be inside the 10_000 cap; got: {errors:?}",
        );
    }

    /// `depth = u32::MAX` is the textbook wrap footgun — the bind path
    /// would coerce it to `-1` and the mapper would fall back to the
    /// in-code default on read. The parse-time validator catches it.
    #[test]
    fn prefetch_policy_depth_above_cap_rejected_at_parse_time() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 4294967295
    transitiveDepth: 5
    maxAgeDays: 365
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| {
                let s = e.to_string();
                s.contains("prefetchPolicy.depth") && s.contains("4294967295")
            }),
            "depth=u32::MAX must be rejected; got: {errors:?}",
        );
    }

    /// `transitiveDepth` carries the same exposure as `depth` — same
    /// cap, same rejection. (Pinned independently of `depth` so a
    /// future refactor doesn't accidentally drop the gate on one.)
    #[test]
    fn prefetch_policy_transitive_depth_above_cap_rejected_at_parse_time() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 3
    transitiveDepth: 4000000000
    maxAgeDays: 365
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| {
                let s = e.to_string();
                s.contains("prefetchPolicy.transitiveDepth") && s.contains("4000000000")
            }),
            "transitiveDepth above cap must be rejected; got: {errors:?}",
        );
    }

    /// `maxAgeDays` is `Option<u32>` — only checked when `Some`.
    /// `u32::MAX` days (~11.7 million years) is the wrap surface.
    #[test]
    fn prefetch_policy_max_age_days_above_cap_rejected_at_parse_time() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 3
    transitiveDepth: 5
    maxAgeDays: 4294967295
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| {
                let s = e.to_string();
                s.contains("prefetchPolicy.maxAgeDays") && s.contains("4294967295")
            }),
            "maxAgeDays above cap must be rejected; got: {errors:?}",
        );
    }

    /// `prefetchPolicy:` block absent entirely — the struct-level
    /// `#[serde(default)]` on `RepositorySpec.prefetch_policy` lands a
    /// `PrefetchPolicy::default()` (disabled, depth=3, max_age_days=
    /// None), so the prefetch-cap gate sees only in-cap defaults and must
    /// NOT push any error. Pins the no-false-positive property for the
    /// default-disabled prefetch posture every existing repo carries.
    #[test]
    fn prefetch_policy_absent_block_passes_the_f6_1_gate() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            !errors
                .iter()
                .any(|e| e.to_string().contains("prefetchPolicy")),
            "absent prefetchPolicy must not trigger the prefetch-cap gate; got: {errors:?}",
        );
    }

    /// `maxDescendants` over its dedicated cap (100_000) is rejected at
    /// parse-time validation. The cap protects against an operator typo
    /// (e.g. `4_000_000_000`) silently disabling the cumulative cascade
    /// ceiling.
    #[test]
    fn prefetch_policy_max_descendants_above_cap_rejected_at_parse_time() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [transitive_deps]
    depth: 3
    transitiveDepth: 5
    maxDescendants: 4000000000
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            errors.iter().any(|e| {
                let s = e.to_string();
                s.contains("prefetchPolicy.maxDescendants") && s.contains("4000000000")
            }),
            "maxDescendants above cap must be rejected; got: {errors:?}",
        );
    }

    /// `maxDescendants` exactly at its upper bound (100_000) is accepted
    /// (strict `>` gate). 0 is also accepted as a deliberate "collapse
    /// transitive enqueue" knob. Pins the boundary against a future
    /// `>=` refactor.
    #[test]
    fn prefetch_policy_max_descendants_at_bound_or_zero_is_accepted() {
        for descendants in [0u32, 100_000] {
            let body = format!(
                "
  name: x
  format: npm
  type: hosted
  storage: {{ backend: filesystem, path: /x }}
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [transitive_deps]
    depth: 3
    transitiveDepth: 5
    maxDescendants: {descendants}
  replicationPriority: immediate
"
            );
            let env = parse_repository(&p(), yaml(&body).as_bytes()).unwrap();
            let errors = validate_repository(&env);
            assert!(
                !errors
                    .iter()
                    .any(|e| e.to_string().contains("maxDescendants")),
                "maxDescendants={descendants} must be accepted; got: {errors:?}",
            );
        }
    }

    /// The `maxDescendants` YAML key is camelCase (matching the
    /// surrounding `PrefetchPolicy` serde convention) and parses through
    /// to the typed `u32` on the domain entity. Round-trip locks the
    /// cross-layer wire form.
    #[test]
    fn prefetch_policy_parses_max_descendants_camelcase_yaml() {
        let body = "
  name: x
  format: npm
  type: proxy
  storage: { backend: filesystem, path: /x }
  proxy: { upstreamUrl: https://registry.npmjs.org }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [transitive_deps]
    depth: 3
    transitiveDepth: 5
    maxDescendants: 500
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        assert_eq!(env.spec.prefetch_policy.max_descendants, 500);
        let json = serde_json::to_string(&env.spec).unwrap();
        assert!(
            json.contains("\"maxDescendants\":500"),
            "expected camelCase maxDescendants wire form: {json}"
        );
    }

    /// Exactly-at-cap (`10_000`) is accepted (the gate is strict `>`,
    /// not `>=`). Pins the boundary so a future refactor that flips
    /// the comparator is caught.
    #[test]
    fn prefetch_policy_exactly_at_cap_is_accepted() {
        let body = "
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 10000
    transitiveDepth: 10000
    maxAgeDays: 10000
  replicationPriority: immediate
";
        let env = parse_repository(&p(), yaml(body).as_bytes()).unwrap();
        let errors = validate_repository(&env);
        assert!(
            !errors
                .iter()
                .any(|e| e.to_string().contains("prefetchPolicy")),
            "exactly-at-cap (10_000) must be accepted (gate is strict `>`, not `>=`); got: {errors:?}",
        );
    }

    #[test]
    fn empty_metadata_name_at_parse_time() {
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: ''
spec:
  name: x
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /x }
  isPublic: true
  replicationPriority: immediate
";
        let err = parse_repository(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    #[test]
    fn name_regex_accepts_dash_and_digits() {
        assert!(name_regex_matches("a"));
        assert!(name_regex_matches("npm-public-1"));
        assert!(name_regex_matches("a23456789"));
    }

    #[test]
    fn name_regex_rejects_uppercase_dot_underscore_leading_digit_or_dash() {
        assert!(!name_regex_matches(""));
        assert!(!name_regex_matches("Foo"));
        assert!(!name_regex_matches("foo.bar"));
        assert!(!name_regex_matches("foo_bar"));
        assert!(!name_regex_matches("1foo"));
        assert!(!name_regex_matches("-foo"));
        let too_long = "a".repeat(64);
        assert!(!name_regex_matches(&too_long));
    }
}
