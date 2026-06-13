//! `kind: UpstreamMapping` schema and parser.
//!
//! The `repository_upstream_mappings` table's admin REST writers were
//! removed; this kind is the gitops surface that replaced them. See
//! `docs/architecture/how-to/declare-gitops-config.md`.
//!
//! YAML shape:
//!
//! ```yaml
//! apiVersion: project-hort.de/v1beta1
//! kind: UpstreamMapping
//! metadata:
//!   name: oci-mirror-dockerhub        # operator-cosmetic handle
//! spec:
//!   repository: oci-mirror-e2e        # → resolves to repository_id
//!   pathPrefix: dockerhub/            # "" for single-upstream formats
//!   upstreamUrl: https://registry-1.docker.io
//!   auth:
//!     type: bearer_challenge          # anonymous | bearer_challenge | basic
//!     # username: foo                 # required for type=basic
//!   # secretRef:                      # required for type=basic; optional otherwise
//!   #   source: env_var
//!   #   location: DOCKERHUB_TOKEN
//!   # insecureUpstreamUrl: true       # opt-in to a plaintext (http://)
//!                                     # upstream; default false. Set per
//!                                     # mapping so a single internal
//!                                     # plaintext mirror does not silently
//!                                     # widen posture for other upstreams.
//! ```
//!
//! # Identity
//!
//! The DB diff identity is composite `(repository_id, path_prefix)` —
//! same as the schema-level UNIQUE constraint. `metadata.name` is
//! operator-cosmetic; two envelopes carrying different `metadata.name`
//! but the same `(repository, pathPrefix)` collide. The cross-spec
//! validator in `desired::validate` enforces this.

use std::path::Path;

use hort_domain::ports::secret_port::SecretRef;
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};
use crate::repository::validate_secret_ref;

/// Shape of a `kind: UpstreamMapping` YAML body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamMappingSpec {
    /// Local repository name. Resolves to `repository_id` at apply
    /// time — must reference a declared `ArtifactRepository` envelope
    /// (cross-spec rule in `desired::validate`).
    pub repository: String,
    /// Empty string for single-upstream formats; non-empty (e.g.
    /// `dockerhub/`, `ghcr/`) for multi-upstream OCI mirrors.
    #[serde(default)]
    pub path_prefix: String,
    /// Base URL the proxy adapter reaches when this mapping matches.
    pub upstream_url: String,
    /// Optional outbound OCI path segment(s) spliced between `/v2/`
    /// and `<name>` in upstream requests (e.g. `docker.io` for a Zot
    /// multi-storage path; `library/proxy` for a GitLab Container
    /// Registry per-project URL). Format-effective for OCI only: the
    /// cross-spec validator in `desired::validate` rejects this field
    /// on non-OCI repositories. Validation regex mirrors the domain
    /// constructor's `validate_upstream_name_prefix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_name_prefix: Option<String>,
    /// How the proxy adapter authenticates outbound requests.
    pub auth: UpstreamAuthSpec,
    /// Reference to a secret used to authenticate the upstream pull.
    /// `Some(_)` is required when `auth.type = basic`; `None` is the
    /// default for the anonymous and bearer-challenge variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,
    /// Operator-explicit opt-in to a plaintext (`http://`) upstream
    /// URL. Default `false`. When `false`, a non-`https://`
    /// `upstreamUrl` is rejected at apply time by the value-object
    /// constructor; when `true`, an `http://` upstream is accepted and
    /// the proxy adapter emits a `WARN` log line plus
    /// `hort_upstream_insecure_total{format,reason}` on every fetch.
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure_upstream_url: bool,
    /// Per-upstream opt-in to publish-time anchoring of the quarantine
    /// window. Default `false`. When `true`, ingests served by this
    /// mapping use `upstream_published_at` (clamped to `ingested_at`
    /// to defeat future-skew) as the quarantine anchor; when `false`
    /// (default), the anchor is `ingested_at`. Mirrors
    /// `insecureUpstreamUrl`'s per-mapping shape so a publish-time
    /// trust decision for one upstream cannot silently widen the
    /// posture for the rest. See ADR 0007.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trust_upstream_publish_time: bool,
    /// Reference to a SecretPort-resolved PEM-encoded mTLS client
    /// certificate the proxy adapter presents on the outbound TLS
    /// handshake. Pairs with [`Self::mtls_key_ref`]: both must be set
    /// together or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_cert_ref: Option<SecretRef>,
    /// Reference to a SecretPort-resolved PEM-encoded mTLS client
    /// private key. Pairs with [`Self::mtls_cert_ref`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_key_ref: Option<SecretRef>,
    /// Reference to a SecretPort-resolved PEM-encoded CA bundle that
    /// augments (does not replace) the system trust roots when reaching
    /// this mapping's upstream. Independent of mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_ref: Option<SecretRef>,
    /// Pinned SHA-256 thumbprint of the upstream's leaf certificate
    /// (DER bytes), as a 64-character lowercase hex string. Validated
    /// at value-object construction time; schema CHECK mirrors the same
    /// regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_cert_sha256: Option<String>,
}

/// `serde(skip_serializing_if)` predicate for the default-`false`
/// `insecure_upstream_url` flag — keeps gitops round-trips of safe
/// (https-only) mappings byte-for-byte identical to the pre-Item-6
/// shape so the canonicalised-spec digest does not flip.
fn is_false(b: &bool) -> bool {
    !*b
}

/// YAML-side encoding of `UpstreamAuth`.
///
/// Mirrors the domain enum but with the strings the YAML surface uses
/// (lowercase, snake_case via serde `rename_all`). `username` is required
/// when `r#type = basic`, ignored otherwise — validation enforces both
/// halves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamAuthSpec {
    /// `anonymous` | `bearer_challenge` | `basic`. Closed enum; unknown
    /// values surface as `ValidationError::UnknownEnumValue`.
    pub r#type: String,
    /// Plaintext username for HTTP Basic auth. Required iff `r#type
    /// = basic`. Ignored on the wire for the other variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

const AUTH_ANONYMOUS: &str = "anonymous";
const AUTH_BEARER_CHALLENGE: &str = "bearer_challenge";
const AUTH_BASIC: &str = "basic";

const AUTH_VARIANTS: &[&str] = &[AUTH_ANONYMOUS, AUTH_BEARER_CHALLENGE, AUTH_BASIC];

/// Parse one `UpstreamMapping` envelope.
pub fn parse_upstream_mapping(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<UpstreamMappingSpec>, ParseError> {
    let env: Envelope<UpstreamMappingSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::UpstreamMapping {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["UpstreamMapping"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    // Same shape rules as repository.rs: validate the SecretRef
    // location format if one was supplied, regardless of auth type.
    // Cross-field rules (auth=basic ⇒ secret_ref required, etc.) live
    // in `validate_upstream_mapping`.
    if let Some(secret) = env.spec.secret_ref.as_ref() {
        validate_secret_ref(secret)?;
    }
    Ok(env)
}

/// Gitops-side mirror of the domain constructor's
/// `validate_upstream_name_prefix`. Returns `None` on accept,
/// `Some(detail)` on reject. The two implementations must stay in sync
/// (same regex, same extra guards) — a divergence shows up as a YAML
/// that parses cleanly but blows up at apply-time inside the
/// constructor. Verified by the round-trip tests below.
fn validate_upstream_name_prefix(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return Some(
            "spec.upstreamNamePrefix must not be empty; omit the field instead of setting it to \"\""
                .into(),
        );
    }
    if prefix.starts_with('/') || prefix.ends_with('/') {
        return Some(format!(
            "spec.upstreamNamePrefix must not start or end with `/`; got `{prefix}`"
        ));
    }
    if prefix.contains("..") {
        return Some(format!(
            "spec.upstreamNamePrefix must not contain `..` (path traversal); got `{prefix}`"
        ));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() {
            return Some(format!(
                "spec.upstreamNamePrefix must not contain empty segments (consecutive `/`); got `{prefix}`"
            ));
        }
        if segment.chars().all(|c| c == '.') {
            return Some(format!(
                "spec.upstreamNamePrefix must not contain a segment of only dots; got `{prefix}`"
            ));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Some(format!(
                "spec.upstreamNamePrefix segments must match [A-Za-z0-9_.-]; got `{prefix}`"
            ));
        }
    }
    None
}

/// Per-spec validation. Returns every violation rather than first-wins.
pub fn validate_upstream_mapping(env: &Envelope<UpstreamMappingSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = env.metadata.name.clone();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::UpstreamMapping,
            name: name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    if env.spec.repository.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::UpstreamMapping,
            name: name.clone(),
            detail: "spec.repository must not be blank".into(),
        });
    }

    // Empty path_prefix is intentional (single-upstream catch-all);
    // only reject explicit whitespace-only values, which would compare
    // unequal to "" and confuse longest-prefix-match.
    if !env.spec.path_prefix.is_empty() && env.spec.path_prefix.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::UpstreamMapping,
            name: name.clone(),
            detail: "spec.pathPrefix must be either empty or a non-whitespace value".into(),
        });
    }

    if env.spec.upstream_url.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::UpstreamMapping,
            name: name.clone(),
            detail: "spec.upstreamUrl must not be blank".into(),
        });
    } else if env.spec.upstream_url.starts_with("https://") {
        // Allowed unconditionally.
    } else if env.spec.upstream_url.starts_with("http://") {
        // Plaintext upstream is a credential-leak surface. Operator
        // must opt in per-mapping via `insecureUpstreamUrl: true`.
        // The value-object constructor (`RepositoryUpstreamMapping::new`)
        // re-checks the same invariant — this validator-side message is
        // the operator-facing surface where it's caught at apply time
        // before the diff layer rolls anything forward.
        if !env.spec.insecure_upstream_url {
            errors.push(ValidationError::Invalid {
                kind: Kind::UpstreamMapping,
                name: name.clone(),
                detail: "spec.upstreamUrl is plaintext (http://) without the \
                         spec.insecureUpstreamUrl opt-in. Set insecureUpstreamUrl: true \
                         on this mapping to acknowledge the credential-leak \
                         surface, or switch to https://."
                    .into(),
            });
        }
    } else {
        errors.push(ValidationError::Invalid {
            kind: Kind::UpstreamMapping,
            name: name.clone(),
            detail: "spec.upstreamUrl must start with http:// or https://".into(),
        });
    }

    // `upstreamNamePrefix` per-spec validation. Mirrors the domain
    // constructor's `validate_upstream_name_prefix`
    // (`crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs`)
    // 1:1, so YAML typos surface at apply-config parse time rather than
    // at fetch time. The cross-format reject (this field set on a
    // non-OCI repository) lives in `desired::validate` because it
    // needs the parent repository's `format` in scope.
    if let Some(prefix) = env.spec.upstream_name_prefix.as_deref() {
        if let Some(detail) = validate_upstream_name_prefix(prefix) {
            errors.push(ValidationError::Invalid {
                kind: Kind::UpstreamMapping,
                name: name.clone(),
                detail,
            });
        }
    }

    let auth_type = env.spec.auth.r#type.as_str();
    if !AUTH_VARIANTS.contains(&auth_type) {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.auth.type",
            got: env.spec.auth.r#type.clone(),
            expected: AUTH_VARIANTS.to_vec(),
        });
    } else {
        // Cross-field rules — only meaningful once we know the variant
        // is one of the closed set.
        match auth_type {
            AUTH_BASIC => {
                if env
                    .spec
                    .auth
                    .username
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::UpstreamMapping,
                        name: name.clone(),
                        detail: "spec.auth.username is required when spec.auth.type = basic".into(),
                    });
                }
                if env.spec.secret_ref.is_none() {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::UpstreamMapping,
                        name: name.clone(),
                        detail: "spec.secretRef is required when spec.auth.type = basic".into(),
                    });
                }
            }
            AUTH_ANONYMOUS => {
                if env.spec.secret_ref.is_some() {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::UpstreamMapping,
                        name: name.clone(),
                        detail: "spec.secretRef must not be set when spec.auth.type = anonymous"
                            .into(),
                    });
                }
                if env.spec.auth.username.is_some() {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::UpstreamMapping,
                        name: name.clone(),
                        detail: "spec.auth.username is only valid when spec.auth.type = basic"
                            .into(),
                    });
                }
            }
            AUTH_BEARER_CHALLENGE => {
                // bearer_challenge accepts `secret_ref` (carries a
                // long-lived API token used in the realm-token
                // exchange's Basic auth) but not `username` — the
                // realm-token exchange does not surface a username.
                if env.spec.auth.username.is_some() {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::UpstreamMapping,
                        name: name.clone(),
                        detail: "spec.auth.username is only valid when spec.auth.type = basic"
                            .into(),
                    });
                }
            }
            _ => unreachable!("auth_type validated against AUTH_VARIANTS above"),
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    fn yaml(name: &str, body: &str) -> String {
        format!(
            "apiVersion: project-hort.de/v1beta1\nkind: UpstreamMapping\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    #[test]
    fn parse_anonymous_round_trip() {
        let body = "
  repository: oci-mirror-e2e
  pathPrefix: dockerhub/
  upstreamUrl: https://registry-1.docker.io
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("dockerhub", body).as_bytes()).unwrap();
        assert_eq!(env.spec.repository, "oci-mirror-e2e");
        assert_eq!(env.spec.path_prefix, "dockerhub/");
        assert_eq!(env.spec.upstream_url, "https://registry-1.docker.io");
        assert_eq!(env.spec.auth.r#type, "anonymous");
        assert!(validate_upstream_mapping(&env).is_empty());
    }

    #[test]
    fn parse_bearer_challenge_round_trip() {
        let body = "
  repository: oci-mirror-e2e
  pathPrefix: ghcr/
  upstreamUrl: https://ghcr.io
  auth:
    type: bearer_challenge
";
        let env = parse_upstream_mapping(&p(), yaml("ghcr", body).as_bytes()).unwrap();
        assert!(validate_upstream_mapping(&env).is_empty());
    }

    #[test]
    fn parse_basic_with_secret_ref_round_trip() {
        let body = "
  repository: oci-mirror-e2e
  pathPrefix: priv/
  upstreamUrl: https://private.example.com
  auth:
    type: basic
    username: alice
  secretRef:
    source: env_var
    location: PRIV_TOKEN
";
        let env = parse_upstream_mapping(&p(), yaml("priv", body).as_bytes()).unwrap();
        assert_eq!(env.spec.auth.username.as_deref(), Some("alice"));
        assert!(env.spec.secret_ref.is_some());
        assert!(validate_upstream_mapping(&env).is_empty());
    }

    #[test]
    fn empty_path_prefix_is_accepted_as_single_upstream_catch_all() {
        // path_prefix `""` is the schema-level single-upstream
        // catch-all — must validate successfully.
        let body = "
  repository: pypi-proxy
  pathPrefix: ''
  upstreamUrl: https://pypi.org
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("pypi", body).as_bytes()).unwrap();
        assert_eq!(env.spec.path_prefix, "");
        assert!(validate_upstream_mapping(&env).is_empty());
    }

    #[test]
    fn missing_path_prefix_defaults_to_empty() {
        // `path_prefix` carries `#[serde(default)]`. Operators omitting
        // the field for single-upstream formats must succeed.
        let body = "
  repository: pypi-proxy
  upstreamUrl: https://pypi.org
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("pypi", body).as_bytes()).unwrap();
        assert_eq!(env.spec.path_prefix, "");
        assert!(validate_upstream_mapping(&env).is_empty());
    }

    #[test]
    fn validate_rejects_unknown_auth_type() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: oauth2
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.auth.type" && got == "oauth2"
        )));
    }

    #[test]
    fn validate_rejects_basic_without_username() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: basic
  secretRef:
    source: env_var
    location: TOKEN
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("username")));
    }

    #[test]
    fn validate_rejects_basic_without_secret_ref() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: basic
    username: alice
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("secretRef")));
    }

    #[test]
    fn validate_rejects_anonymous_with_secret_ref() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
  secretRef:
    source: env_var
    location: TOKEN
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("secretRef")));
    }

    #[test]
    fn validate_rejects_anonymous_with_username() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
    username: alice
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("username")));
    }

    #[test]
    fn validate_rejects_bearer_challenge_with_username() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: bearer_challenge
    username: alice
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("username")));
    }

    #[test]
    fn validate_rejects_blank_repository() {
        let body = "
  repository: ''
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("repository")));
    }

    #[test]
    fn validate_rejects_unschemed_upstream_url() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("http:// or https://")));
    }

    // -- `insecureUpstreamUrl` opt-in ----------------------------------------
    // The `insecureUpstreamUrl` opt-in is the operator surface for the
    // value-object scheme invariant. Without it, http:// is rejected at
    // apply time; with it, http:// is accepted and a downstream WARN +
    // metric fires on every fetch (covered by the proxy-adapter tests).

    #[test]
    fn validate_rejects_http_upstream_without_insecure_opt_in() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: http://internal-mirror.example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("insecureUpstreamUrl")),
            "expected an error mentioning the insecureUpstreamUrl opt-in; got {errs:?}"
        );
    }

    #[test]
    fn parse_and_validate_accept_http_upstream_with_insecure_opt_in() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: http://internal-mirror.example.com
  auth:
    type: anonymous
  insecureUpstreamUrl: true
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        assert!(env.spec.insecure_upstream_url);
        assert!(
            validate_upstream_mapping(&env).is_empty(),
            "http:// upstream with insecureUpstreamUrl: true must validate clean"
        );
    }

    #[test]
    fn insecure_upstream_url_defaults_to_false_when_field_omitted() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        assert!(!env.spec.insecure_upstream_url);
    }

    // -- `trustUpstreamPublishTime` opt-in --------------------------------
    // The `trustUpstreamPublishTime` opt-in is the gitops surface for
    // the per-upstream publish-time-anchor opt-in flag. It mirrors the
    // `insecureUpstreamUrl` shape (camelCase, default `false`,
    // skip-serialize when default so the canonical-spec digest does
    // not flip for unaffected envelopes). The validator does NOT need
    // a dedicated check — a plain bool with no cross-field rules.

    #[test]
    fn trust_upstream_publish_time_defaults_to_false_when_field_omitted() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        assert!(
            !env.spec.trust_upstream_publish_time,
            "missing field must default to false"
        );
        assert!(
            validate_upstream_mapping(&env).is_empty(),
            "omitting the field must validate clean"
        );
    }

    #[test]
    fn trust_upstream_publish_time_parses_and_validates_when_set() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
  trustUpstreamPublishTime: true
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        assert!(env.spec.trust_upstream_publish_time);
        assert!(
            validate_upstream_mapping(&env).is_empty(),
            "trustUpstreamPublishTime: true must validate clean (plain bool, no cross-field rules)"
        );
    }

    #[test]
    fn trust_upstream_publish_time_skip_serialize_when_default() {
        // Mirrors the `insecureUpstreamUrl` digest-stability invariant:
        // round-tripping a default-`false` envelope must not emit the
        // field so existing operator YAML keeps producing the same
        // canonicalised-spec digest.
        let spec = UpstreamMappingSpec {
            repository: "r".into(),
            path_prefix: "x/".into(),
            upstream_url: "https://x.example.com".into(),
            upstream_name_prefix: None,
            auth: UpstreamAuthSpec {
                r#type: "anonymous".into(),
                username: None,
            },
            secret_ref: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
        };
        let yaml_out =
            serde_yaml_ng::to_string(&spec).expect("default spec must serialise to YAML");
        assert!(
            !yaml_out.contains("trustUpstreamPublishTime"),
            "default `false` must skip-serialize; got:\n{yaml_out}"
        );

        // And the `true` variant DOES round-trip through the serialiser.
        let spec_true = UpstreamMappingSpec {
            trust_upstream_publish_time: true,
            ..spec
        };
        let yaml_out_true =
            serde_yaml_ng::to_string(&spec_true).expect("opted-in spec must serialise to YAML");
        assert!(
            yaml_out_true.contains("trustUpstreamPublishTime"),
            "opt-in `true` must serialise; got:\n{yaml_out_true}"
        );
    }

    #[test]
    fn validate_rejects_blank_upstream_url() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: ''
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("upstreamUrl")));
    }

    #[test]
    fn validate_rejects_whitespace_only_path_prefix() {
        let body = "
  repository: r
  pathPrefix: '   '
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("pathPrefix")));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
  bogus: 1
";
        let err = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: anonymous
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: UpstreamMapping\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_upstream_mapping(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    #[test]
    fn parse_rejects_invalid_secret_ref_location() {
        // `source: file` with a non-absolute path must fail at parse
        // time (same secret-ref rule applied to repositories).
        let body = "
  repository: r
  pathPrefix: x/
  upstreamUrl: https://x.example.com
  auth:
    type: basic
    username: alice
  secretRef:
    source: file
    location: relative/path
";
        let err = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::SecretRefLocationInvalid { .. }));
    }

    // -- `upstreamNamePrefix` ------------------------------------------
    //
    // Optional outbound OCI path-prefix injection. The field is
    // OCI-effective only; cross-format rejection (non-OCI repository
    // with the field set) lives in `desired::validate()` because it
    // needs the parent repository's `format` in scope.

    #[test]
    fn parse_round_trips_upstream_name_prefix_some() {
        let body = "
  repository: oci-mirror-e2e
  pathPrefix: ''
  upstreamUrl: https://zot.example.com
  upstreamNamePrefix: docker.io
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("zot", body).as_bytes()).unwrap();
        assert_eq!(env.spec.upstream_name_prefix.as_deref(), Some("docker.io"));
        assert!(
            validate_upstream_mapping(&env).is_empty(),
            "valid prefix must pass per-spec validation"
        );
    }

    #[test]
    fn parse_round_trips_upstream_name_prefix_absent_defaults_to_none() {
        let body = "
  repository: oci-mirror-e2e
  pathPrefix: ''
  upstreamUrl: https://registry-1.docker.io
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("dh", body).as_bytes()).unwrap();
        assert!(env.spec.upstream_name_prefix.is_none());
    }

    #[test]
    fn validate_rejects_upstream_name_prefix_with_path_traversal() {
        let body = "
  repository: r
  pathPrefix: ''
  upstreamUrl: https://zot.example.com
  upstreamNamePrefix: foo/../bar
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("upstreamNamePrefix")),
            "expected an error naming upstreamNamePrefix; got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_upstream_name_prefix_with_leading_slash() {
        let body = "
  repository: r
  pathPrefix: ''
  upstreamUrl: https://zot.example.com
  upstreamNamePrefix: /foo
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("upstreamNamePrefix")),
            "expected an error naming upstreamNamePrefix; got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_upstream_name_prefix_string() {
        // YAML `upstreamNamePrefix: ''` deserialises to `Some("")` —
        // the validator rejects it the same way the domain constructor
        // does (operators use field-absent / None, not empty string).
        let body = "
  repository: r
  pathPrefix: ''
  upstreamUrl: https://zot.example.com
  upstreamNamePrefix: ''
  auth:
    type: anonymous
";
        let env = parse_upstream_mapping(&p(), yaml("u", body).as_bytes()).unwrap();
        let errs = validate_upstream_mapping(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("upstreamNamePrefix")),
            "expected an error naming upstreamNamePrefix; got {errs:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_kind_envelope() {
        // The dispatch in DesiredState::parse_files routes by kind, but
        // a single-file caller handing the wrong envelope here must
        // surface a typed error rather than silently coercing.
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: GroupMapping
metadata:
  name: u
spec:
  group: g
  role: r
";
        let err = parse_upstream_mapping(&p(), yaml_doc.as_bytes()).unwrap_err();
        // Wrong kind fails at deserialize because the spec shape doesn't
        // fit. The exact variant is not pinned; what matters is rejection.
        assert!(matches!(err, ParseError::Yaml(_)));
    }
}
