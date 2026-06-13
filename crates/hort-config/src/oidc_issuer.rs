//! `kind: OidcIssuer` schema, parser, and per-spec validation.
//!
//! Declares an external OIDC issuer that hort-server federates with for
//! workload identity (see ADR 0018). One envelope per trusted issuer;
//! envelope identity is `metadata.name`.
//!
//! See `docs/architecture/how-to/declare-gitops-config.md` for the
//! canonical YAML.
//!
//! # Apply-time invariants
//!
//! - `issuerUrl` must be HTTPS. Plaintext (`http://`) is rejected
//!   outright — JWKS over HTTP is a credential-leak surface, and
//!   `HORT_EXTRA_CA_BUNDLE` is the supported way to trust internal
//!   CAs.
//! - `audiences` non-empty (each entry must be non-blank).
//! - `allowedAlgorithms`: every entry must be one of the supported
//!   asymmetric variants (`RS256/384/512`, `ES256/384/512`).
//!   Symmetric (`HS*`) is excluded by the domain enum
//!   ([`JwtAlg`](hort_domain::entities::oidc_issuer::JwtAlg)).
//! - `jwksRefreshInterval` between 1 minute and 24 hours. The lower
//!   bound prevents a misconfigured short interval from hammering the
//!   issuer's JWKS endpoint; the upper bound caps key-rotation lag.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use hort_domain::entities::oidc_issuer::JwtAlg;
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// Minimum allowed `jwksRefreshInterval`. Below this the apply
/// validator rejects — a 1-minute lower bound is generous (real-world
/// JWKS rotation cadence is hours to days) and prevents accidental
/// hot-loops against an upstream's `.well-known` endpoint.
const MIN_JWKS_REFRESH: Duration = Duration::from_secs(60);

/// Maximum allowed `jwksRefreshInterval`. 24h caps key-rotation
/// propagation latency at one day; longer intervals leave revoked keys
/// usable on this server for too long.
const MAX_JWKS_REFRESH: Duration = Duration::from_secs(24 * 3600);

/// Shape of a `kind: OidcIssuer` YAML body.
///
/// All fields use camelCase wire form (`#[serde(rename_all = "camelCase")]`)
/// matching the rest of the gitops vocabulary. `deny_unknown_fields`
/// rejects typos at parse time rather than silently dropping data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcIssuerSpec {
    /// Canonical `iss` claim value the federation handler matches on.
    /// Must start with `https://` (validated apply-time).
    pub issuer_url: String,
    /// Accepted `aud` claim values. Non-empty, entries non-blank.
    pub audiences: Vec<String>,
    /// Humantime string (e.g. `"1h"`, `"30m"`). Validated against the
    /// `[1m, 24h]` window at apply time. Defaults to `"1h"` when
    /// omitted.
    #[serde(default = "default_jwks_refresh_interval")]
    pub jwks_refresh_interval: String,
    /// JWT signature algorithms accepted on the federation branch.
    /// Each entry must parse through `JwtAlg::from_str` (uppercase
    /// RFC 7518 wire form: `RS256`, `ES256`, etc.). Defaults to
    /// `["RS256"]` when omitted.
    #[serde(default = "default_allowed_algorithms")]
    pub allowed_algorithms: Vec<String>,
    /// When `true` a federated JWT from this issuer that lacks a `jti`
    /// claim is rejected (`jti_required`) before any replay check or
    /// mint. When `false` the issuer is opted into the weaker
    /// `(iss,sub,iat,exp)` composite anti-replay fallback (a
    /// documented false-positive risk if the IdP mints two tokens for
    /// the same `sub` within the same `iat` second and `exp`).
    ///
    /// **Defaults to `true`** (secure-by-default, CRA Annex I (1)).
    /// **Silent-apply upgrade note:** an existing `OidcIssuer` envelope
    /// written before this field existed has no `requireJti:` key;
    /// `#[serde(default)]` then resolves it to `true`, so on the next
    /// `apply` such an issuer starts rejecting jti-less JWTs. This is
    /// an intentional security tightening — an operator that relies on
    /// jti-less workload JWTs must explicitly set `requireJti: false`
    /// on that issuer before upgrading.
    #[serde(default = "default_require_jti")]
    pub require_jti: bool,
}

/// Default for `jwksRefreshInterval` — 1 hour.
fn default_jwks_refresh_interval() -> String {
    "1h".to_string()
}

/// Default for `allowedAlgorithms` — single-element `["RS256"]`.
fn default_allowed_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

/// Default for `requireJti` — `true`. Secure-by-default: a JWT without
/// `jti` is rejected unless the operator explicitly opts the issuer
/// down to the weaker composite anti-replay key. See the `require_jti`
/// field docstring for the silent-apply upgrade implication.
fn default_require_jti() -> bool {
    true
}

/// Parse one `OidcIssuer` envelope.
pub fn parse_oidc_issuer(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<OidcIssuerSpec>, ParseError> {
    let env: Envelope<OidcIssuerSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::OidcIssuer {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["OidcIssuer"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation. Returns every violation rather than
/// first-error-wins so the operator gets the full list per boot pass.
///
/// Cross-spec rules (`ServiceAccount.federatedIdentities[].issuer`
/// references a declared `OidcIssuer.name`) live in the apply use case's
/// `validate_against` step — they need the desired-state's union of
/// other kinds. This validator only looks at the envelope in isolation.
pub fn validate_oidc_issuer(env: &Envelope<OidcIssuerSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = env.metadata.name.clone();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    // -- issuerUrl ----------------------------------------------------------
    if env.spec.issuer_url.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "spec.issuerUrl must not be blank".into(),
        });
    } else if env.spec.issuer_url.starts_with("http://") {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "spec.issuerUrl must start with https:// — plaintext OIDC \
                     issuer URLs are forbidden (JWKS over HTTP is a credential-leak surface). \
                     Use HORT_EXTRA_CA_BUNDLE to trust internal CAs."
                .into(),
        });
    } else if !env.spec.issuer_url.starts_with("https://") {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "spec.issuerUrl must start with https://".into(),
        });
    }

    // -- audiences ----------------------------------------------------------
    if env.spec.audiences.is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "spec.audiences must contain at least one entry".into(),
        });
    }
    for aud in &env.spec.audiences {
        if aud.trim().is_empty() {
            errors.push(ValidationError::Invalid {
                kind: Kind::OidcIssuer,
                name: name.clone(),
                detail: "spec.audiences[*] must not be blank".into(),
            });
        }
    }

    // -- allowedAlgorithms --------------------------------------------------
    if env.spec.allowed_algorithms.is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::OidcIssuer,
            name: name.clone(),
            detail: "spec.allowedAlgorithms must contain at least one entry".into(),
        });
    }
    for alg in &env.spec.allowed_algorithms {
        if JwtAlg::from_str(alg).is_err() {
            errors.push(ValidationError::UnknownEnumValue {
                field: "spec.allowedAlgorithms[*]",
                got: alg.clone(),
                expected: vec!["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            });
        }
    }

    // -- jwksRefreshInterval ------------------------------------------------
    match humantime::parse_duration(&env.spec.jwks_refresh_interval) {
        Err(err) => {
            errors.push(ValidationError::Invalid {
                kind: Kind::OidcIssuer,
                name: name.clone(),
                detail: format!(
                    "spec.jwksRefreshInterval `{}` is not a valid humantime duration: {err}",
                    env.spec.jwks_refresh_interval
                ),
            });
        }
        Ok(d) if d < MIN_JWKS_REFRESH => {
            errors.push(ValidationError::Invalid {
                kind: Kind::OidcIssuer,
                name: name.clone(),
                detail: format!(
                    "spec.jwksRefreshInterval `{}` is below the minimum of 1m — \
                     short intervals risk hot-looping against the issuer's JWKS endpoint",
                    env.spec.jwks_refresh_interval
                ),
            });
        }
        Ok(d) if d > MAX_JWKS_REFRESH => {
            errors.push(ValidationError::Invalid {
                kind: Kind::OidcIssuer,
                name: name.clone(),
                detail: format!(
                    "spec.jwksRefreshInterval `{}` is above the maximum of 24h — \
                     longer intervals leave revoked keys usable on this server for too long",
                    env.spec.jwks_refresh_interval
                ),
            });
        }
        Ok(_) => {}
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
            "apiVersion: project-hort.de/v1beta1\nkind: OidcIssuer\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    // -- Happy paths --------------------------------------------------------

    #[test]
    fn parse_minimal_round_trip_uses_defaults() {
        let body = "
  issuerUrl: https://token.actions.githubusercontent.com
  audiences: [hort-server]
";
        let env = parse_oidc_issuer(&p(), yaml("github-actions", body).as_bytes()).unwrap();
        assert_eq!(env.metadata.name, "github-actions");
        assert_eq!(
            env.spec.issuer_url,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(env.spec.audiences, vec!["hort-server"]);
        // Defaults — jwksRefreshInterval `"1h"` + allowedAlgorithms `["RS256"]`.
        assert_eq!(env.spec.jwks_refresh_interval, "1h");
        assert_eq!(env.spec.allowed_algorithms, vec!["RS256"]);
        // `requireJti` defaults to `true` (secure-by-default): an
        // envelope written before the field existed parses with
        // `require_jti = true`.
        assert!(
            env.spec.require_jti,
            "requireJti must default to true (secure-by-default)"
        );
        assert!(validate_oidc_issuer(&env).is_empty());
    }

    #[test]
    fn parse_explicit_require_jti_false_opts_issuer_down() {
        // An operator may explicitly opt an issuer into the weaker
        // composite fallback. Only an explicit `requireJti: false`
        // does so; the default never silently weakens.
        let body = "
  issuerUrl: https://gitlab.com
  audiences: [hort-server]
  requireJti: false
";
        let env = parse_oidc_issuer(&p(), yaml("gitlab", body).as_bytes()).unwrap();
        assert!(!env.spec.require_jti);
        assert!(validate_oidc_issuer(&env).is_empty());
    }

    #[test]
    fn parse_explicit_require_jti_true_round_trips() {
        let body = "
  issuerUrl: https://gitlab.com
  audiences: [hort-server]
  requireJti: true
";
        let env = parse_oidc_issuer(&p(), yaml("gitlab", body).as_bytes()).unwrap();
        assert!(env.spec.require_jti);
    }

    #[test]
    fn parse_full_round_trip() {
        let body = "
  issuerUrl: https://gitlab.com
  audiences: [hort-server, hort-cli]
  jwksRefreshInterval: 30m
  allowedAlgorithms: [RS256, ES256]
";
        let env = parse_oidc_issuer(&p(), yaml("gitlab", body).as_bytes()).unwrap();
        assert_eq!(env.spec.audiences.len(), 2);
        assert_eq!(env.spec.allowed_algorithms.len(), 2);
        assert!(validate_oidc_issuer(&env).is_empty());
    }

    // -- Parse rejects ------------------------------------------------------

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  bogus: 1
";
        let err = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_missing_issuer_url() {
        let body = "
  audiences: [a]
";
        let err = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_missing_audiences() {
        let body = "
  issuerUrl: https://example.com
";
        let err = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_wrong_kind_envelope() {
        let yaml_doc = "apiVersion: project-hort.de/v1beta1
kind: Role
metadata:
  name: x
spec:
  isSystem: false
";
        let err = parse_oidc_issuer(&p(), yaml_doc.as_bytes()).unwrap_err();
        // serde may fail at deserialize-time on the wrong spec shape;
        // either path is acceptable so long as the envelope is refused.
        assert!(matches!(
            err,
            ParseError::Yaml(_) | ParseError::UnknownKind { .. }
        ));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: OidcIssuer\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_oidc_issuer(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    // -- Validate rejects ---------------------------------------------------

    #[test]
    fn validate_rejects_http_issuer_url() {
        let body = "
  issuerUrl: http://insecure.example.com
  audiences: [a]
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(
            errs.iter().any(|e| e.to_string().contains("https://")),
            "expected https-required error, got: {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_unschemed_issuer_url() {
        let body = "
  issuerUrl: example.com
  audiences: [a]
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("https://")));
    }

    #[test]
    fn validate_rejects_blank_issuer_url() {
        let body = "
  issuerUrl: ''
  audiences: [a]
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("issuerUrl")));
    }

    #[test]
    fn validate_rejects_empty_audiences() {
        let body = "
  issuerUrl: https://example.com
  audiences: []
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("audiences")));
    }

    #[test]
    fn validate_rejects_blank_audience() {
        let body = "
  issuerUrl: https://example.com
  audiences: ['   ']
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("audiences[*]")));
    }

    #[test]
    fn validate_rejects_hmac_algorithm() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  allowedAlgorithms: [HS256]
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.allowedAlgorithms[*]" && got == "HS256"
        )));
    }

    #[test]
    fn validate_rejects_lowercase_algorithm() {
        // RFC 7518 wire form is uppercase. Mixed-case typos must surface.
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  allowedAlgorithms: [rs256]
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { got, .. } if got == "rs256"
        )));
    }

    #[test]
    fn validate_rejects_empty_allowed_algorithms_when_explicit() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  allowedAlgorithms: []
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("allowedAlgorithms")));
    }

    #[test]
    fn validate_accepts_every_supported_algorithm() {
        for alg in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"] {
            let body = format!(
                "
  issuerUrl: https://example.com
  audiences: [a]
  allowedAlgorithms: [{alg}]
"
            );
            let env = parse_oidc_issuer(&p(), yaml("x", &body).as_bytes()).unwrap();
            let errs = validate_oidc_issuer(&env);
            assert!(
                errs.is_empty(),
                "algorithm `{alg}` must validate cleanly: {errs:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_unparseable_jwks_refresh_interval() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  jwksRefreshInterval: not-a-duration
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("jwksRefreshInterval")));
    }

    #[test]
    fn validate_rejects_jwks_refresh_below_one_minute() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  jwksRefreshInterval: 30s
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("below the minimum")),
            "expected min-bound error, got: {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_jwks_refresh_above_24_hours() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  jwksRefreshInterval: 48h
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_oidc_issuer(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("above the maximum")),
            "expected max-bound error, got: {errs:?}"
        );
    }

    #[test]
    fn validate_accepts_jwks_refresh_at_one_minute_boundary() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  jwksRefreshInterval: 1m
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        assert!(validate_oidc_issuer(&env).is_empty());
    }

    #[test]
    fn validate_accepts_jwks_refresh_at_24h_boundary() {
        let body = "
  issuerUrl: https://example.com
  audiences: [a]
  jwksRefreshInterval: 24h
";
        let env = parse_oidc_issuer(&p(), yaml("x", body).as_bytes()).unwrap();
        assert!(validate_oidc_issuer(&env).is_empty());
    }

    #[test]
    fn validate_rejects_blank_metadata_name() {
        let env = Envelope {
            api_version: crate::envelope::ApiVersion::V1Beta1,
            kind: Kind::OidcIssuer,
            metadata: crate::envelope::Metadata { name: "   ".into() },
            spec: OidcIssuerSpec {
                issuer_url: "https://example.com".into(),
                audiences: vec!["a".into()],
                jwks_refresh_interval: "1h".into(),
                allowed_algorithms: vec!["RS256".into()],
                require_jti: true,
            },
        };
        let errs = validate_oidc_issuer(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("blank")));
    }
}
