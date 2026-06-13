//! `WWW-Authenticate: Bearer ...` challenge parser per
//! RFC 7235 §4.1 + the Docker token spec.
//!
//! Pure, dependency-free, single-pass. The OCI upstream adapter
//! (Item 3) calls [`parse_www_authenticate`] when an upstream
//! returns 401 to discover the realm/service/scope triple it must
//! exchange a token against.
//!
//! No I/O. No `tracing` calls — failures are surfaced via the typed
//! [`ChallengeParseError`] variants and the caller is responsible
//! for logging, per the project's observability rules.

use thiserror::Error;

/// Parsed `WWW-Authenticate: Bearer ...` challenge per RFC 7235 §4.1
/// + Docker token spec.
///
/// `realm` is mandatory. `service` and `scope` are absent on
/// some registries' discovery probes (`GET /v2/`) but present on
/// every real resource fetch the proxy actually issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Realm endpoint URL (mandatory). Any URL string the upstream
    /// served — caller is responsible for verifying it parses as a
    /// URL when fetching a token.
    pub realm: String,
    /// `service` parameter; absent on some registries' discovery
    /// challenges, present on every real resource fetch.
    pub service: Option<String>,
    /// `scope` parameter; same caveat — present on every real
    /// resource fetch the proxy issues.
    pub scope: Option<String>,
}

/// Parse failure modes the adapter (Item 3) needs to distinguish.
///
/// `NotBearer` and `Malformed` map to different runtime decisions:
/// non-Bearer schemes surface the original 401 verbatim (no
/// exchange attempt — we don't speak Basic/Digest/NTLM); Bearer
/// challenges with parse errors are logged and surfaced as
/// `Unauthorized` so an operator sees the malformed challenge.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChallengeParseError {
    /// Header value is empty / whitespace-only.
    #[error("WWW-Authenticate header is empty")]
    Empty,
    /// Scheme is something other than Bearer (Basic, Digest, NTLM,
    /// vendor schemes). Item 3 surfaces the original 401 verbatim
    /// in this case — no exchange attempt.
    #[error("non-Bearer auth scheme: {0}")]
    NotBearer(String),
    /// Bearer scheme present but the parameter list is malformed
    /// (e.g. unterminated quote, missing `=`, no `realm`).
    #[error("malformed Bearer challenge: {0}")]
    Malformed(String),
}

/// Parse a `WWW-Authenticate` header value into a [`Challenge`].
///
/// Single-pass, hand-rolled. The header is small (typically <500
/// chars); a full parser-combinator pull is unjustified weight.
pub fn parse_www_authenticate(header_value: &str) -> Result<Challenge, ChallengeParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(ChallengeParseError::Empty);
    }

    // Split off the auth-scheme: first whitespace-delimited token.
    let (scheme, rest) = match trimmed.find(char::is_whitespace) {
        Some(idx) => (&trimmed[..idx], trimmed[idx..].trim_start()),
        // Scheme with no parameters (e.g. `"Bearer"` or `"Basic"`
        // by itself). Treat `rest` as empty.
        None => (trimmed, ""),
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(ChallengeParseError::NotBearer(scheme.to_string()));
    }

    let params = parse_params(rest)?;

    let mut realm: Option<String> = None;
    let mut service: Option<String> = None;
    let mut scope: Option<String> = None;
    for (key, value) in params {
        match key.as_str() {
            "realm" => realm = Some(value),
            "service" => service = if value.is_empty() { None } else { Some(value) },
            "scope" => scope = if value.is_empty() { None } else { Some(value) },
            _ => { /* advisory / vendor extension — drop */ }
        }
    }

    let realm = match realm {
        Some(r) if !r.is_empty() => r,
        _ => return Err(ChallengeParseError::Malformed("missing realm".to_string())),
    };

    Ok(Challenge {
        realm,
        service,
        scope,
    })
}

/// Parse a comma-separated `key=value [, key=value]*` list into a
/// vector of `(lowercased_key, unescaped_value)` pairs preserving
/// input order. Tolerates whitespace around `=` and `,`. Values may
/// be RFC 7230 tokens (unquoted) or quoted-strings (with `\"` /
/// `\\` escapes per RFC 7230 §3.2.6).
fn parse_params(input: &str) -> Result<Vec<(String, String)>, ChallengeParseError> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut chars = input.char_indices().peekable();

    loop {
        // Skip leading whitespace and commas between params.
        while let Some(&(_, c)) = chars.peek() {
            if c.is_whitespace() || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        if chars.peek().is_none() {
            break;
        }

        // Read the key (RFC 7230 token: ASCII letters/digits + a few
        // specials). Stop at `=`, whitespace, or `,`.
        let key_start = chars.peek().map(|&(i, _)| i).unwrap();
        let mut key_end = key_start;
        while let Some(&(i, c)) = chars.peek() {
            if c == '=' || c.is_whitespace() || c == ',' {
                break;
            }
            key_end = i + c.len_utf8();
            chars.next();
        }
        if key_end == key_start {
            return Err(ChallengeParseError::Malformed(
                "empty parameter key".to_string(),
            ));
        }
        let key = input[key_start..key_end].to_ascii_lowercase();

        // Skip whitespace before `=`.
        while let Some(&(_, c)) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }
        // Require `=`.
        match chars.peek() {
            Some(&(_, '=')) => {
                chars.next();
            }
            _ => {
                return Err(ChallengeParseError::Malformed(format!(
                    "parameter `{key}` missing `=`"
                )));
            }
        }
        // Skip whitespace after `=`.
        while let Some(&(_, c)) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        // Value: quoted-string or token.
        let value = match chars.peek() {
            Some(&(_, '"')) => {
                chars.next(); // consume opening quote
                let mut buf = String::new();
                let mut closed = false;
                while let Some((_, c)) = chars.next() {
                    if c == '\\' {
                        match chars.next() {
                            Some((_, esc)) => buf.push(esc),
                            None => {
                                return Err(ChallengeParseError::Malformed(
                                    "trailing backslash in quoted value".to_string(),
                                ));
                            }
                        }
                    } else if c == '"' {
                        closed = true;
                        break;
                    } else {
                        buf.push(c);
                    }
                }
                if !closed {
                    return Err(ChallengeParseError::Malformed(
                        "unterminated quoted value".to_string(),
                    ));
                }
                buf
            }
            Some(&(start, _)) => {
                let mut end = start;
                while let Some(&(i, c)) = chars.peek() {
                    if c == ',' || c.is_whitespace() {
                        break;
                    }
                    end = i + c.len_utf8();
                    chars.next();
                }
                input[start..end].to_string()
            }
            None => String::new(),
        };

        // Insert; duplicate keys overwrite (defensive — last wins).
        if let Some(existing) = out.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = value;
        } else {
            out.push((key, value));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Batch A: scheme dispatch ---------------------------------------

    #[test]
    fn parses_minimal_bearer_with_realm_only() {
        let c = parse_www_authenticate(r#"Bearer realm="https://x""#).unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://x".to_string(),
                service: None,
                scope: None,
            }
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse_www_authenticate(""), Err(ChallengeParseError::Empty));
        assert_eq!(
            parse_www_authenticate("   "),
            Err(ChallengeParseError::Empty)
        );
    }

    #[test]
    fn rejects_basic_scheme() {
        assert_eq!(
            parse_www_authenticate(r#"Basic realm="x""#),
            Err(ChallengeParseError::NotBearer("Basic".to_string()))
        );
    }

    #[test]
    fn rejects_digest_scheme() {
        assert_eq!(
            parse_www_authenticate(r#"Digest realm="x", nonce="abc""#),
            Err(ChallengeParseError::NotBearer("Digest".to_string()))
        );
    }

    // ----- Batch B: real-registry challenge shapes ------------------------

    #[test]
    fn parses_docker_hub_challenge() {
        let c = parse_www_authenticate(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://auth.docker.io/token".to_string(),
                service: Some("registry.docker.io".to_string()),
                scope: Some("repository:library/alpine:pull".to_string()),
            }
        );
    }

    #[test]
    fn parses_ghcr_challenge() {
        let c = parse_www_authenticate(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:oci-playground/hello-world:pull""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://ghcr.io/token".to_string(),
                service: Some("ghcr.io".to_string()),
                scope: Some("repository:oci-playground/hello-world:pull".to_string()),
            }
        );
    }

    #[test]
    fn parses_quay_challenge() {
        let c = parse_www_authenticate(
            r#"Bearer realm="https://quay.io/v2/auth",service="quay.io",scope="repository:redhat/ubi8:pull""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://quay.io/v2/auth".to_string(),
                service: Some("quay.io".to_string()),
                scope: Some("repository:redhat/ubi8:pull".to_string()),
            }
        );
    }

    #[test]
    fn parses_gitlab_cr_challenge() {
        let c = parse_www_authenticate(
            r#"Bearer realm="https://gitlab.example.com/jwt/auth",service="container_registry",scope="repository:group/project:pull""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://gitlab.example.com/jwt/auth".to_string(),
                service: Some("container_registry".to_string()),
                scope: Some("repository:group/project:pull".to_string()),
            }
        );
    }

    #[test]
    fn parses_harbor_challenge() {
        let c = parse_www_authenticate(
            r#"Bearer realm="https://harbor.example.com/service/token",service="harbor-registry",scope="repository:project/image:pull""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge {
                realm: "https://harbor.example.com/service/token".to_string(),
                service: Some("harbor-registry".to_string()),
                scope: Some("repository:project/image:pull".to_string()),
            }
        );
    }

    // ----- Batch C: tolerance ---------------------------------------------

    #[test]
    fn tolerates_parameter_order() {
        let c = parse_www_authenticate(
            r#"Bearer scope="repository:x:pull",realm="https://r",service="s""#,
        )
        .unwrap();
        assert_eq!(c.realm, "https://r");
        assert_eq!(c.service.as_deref(), Some("s"));
        assert_eq!(c.scope.as_deref(), Some("repository:x:pull"));
    }

    #[test]
    fn tolerates_whitespace() {
        let c = parse_www_authenticate(r#"Bearer realm = "x" , service = "y""#).unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.service.as_deref(), Some("y"));
    }

    #[test]
    fn tolerates_unquoted_token_values() {
        let c = parse_www_authenticate("Bearer realm=x").unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.service, None);
        assert_eq!(c.scope, None);
    }

    #[test]
    fn case_insensitive_scheme() {
        let c = parse_www_authenticate(r#"BEARER realm="x""#).unwrap();
        assert_eq!(c.realm, "x");
        let c = parse_www_authenticate(r#"bearer realm="x""#).unwrap();
        assert_eq!(c.realm, "x");
    }

    #[test]
    fn case_insensitive_param_keys() {
        let c = parse_www_authenticate(r#"Bearer Realm="x""#).unwrap();
        assert_eq!(c.realm, "x");
        let c = parse_www_authenticate(r#"Bearer REALM="y", Service="z", SCOPE="w""#).unwrap();
        assert_eq!(c.realm, "y");
        assert_eq!(c.service.as_deref(), Some("z"));
        assert_eq!(c.scope.as_deref(), Some("w"));
    }

    // ----- Batch D: advisory parameters dropped ---------------------------

    #[test]
    fn ignores_error_parameter() {
        let c = parse_www_authenticate(r#"Bearer realm="x", error="insufficient_scope""#).unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.service, None);
        assert_eq!(c.scope, None);
    }

    #[test]
    fn ignores_error_description() {
        let c = parse_www_authenticate(
            r#"Bearer realm="x", error_description="The access token is invalid""#,
        )
        .unwrap();
        assert_eq!(c.realm, "x");
    }

    #[test]
    fn ignores_vendor_extensions() {
        let c =
            parse_www_authenticate(r#"Bearer realm="x", x-vendor-thing="foo", weird=bar"#).unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.service, None);
        assert_eq!(c.scope, None);
    }

    // ----- Batch E: quoted-string escape semantics ------------------------

    #[test]
    fn unescapes_quoted_string_quotes() {
        let c =
            parse_www_authenticate(r#"Bearer realm="https://example.com/path/with/\"quotes\"""#)
                .unwrap();
        assert_eq!(c.realm, r#"https://example.com/path/with/"quotes""#);
    }

    #[test]
    fn unescapes_backslash() {
        // Header value as it would appear on the wire:
        //   realm="path\\to\\thing"
        // RFC 7230 quoted-pair unescapes each `\X` to `X`, so the
        // four backslashes yield two literal backslashes.
        let c = parse_www_authenticate(r#"Bearer realm="path\\to\\thing""#).unwrap();
        assert_eq!(c.realm, r"path\to\thing");
    }

    #[test]
    fn quoted_value_with_comma() {
        let c = parse_www_authenticate(r#"Bearer realm="a,b", service="x""#).unwrap();
        assert_eq!(c.realm, "a,b");
        assert_eq!(c.service.as_deref(), Some("x"));
    }

    // ----- Batch F: malformed inputs --------------------------------------

    #[test]
    fn rejects_missing_realm() {
        let err = parse_www_authenticate(r#"Bearer service="x", scope="y""#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => assert!(msg.contains("missing realm")),
            other => panic!("expected Malformed(missing realm), got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_realm() {
        let err = parse_www_authenticate(r#"Bearer realm="""#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => assert!(msg.contains("missing realm")),
            other => panic!("expected Malformed(missing realm), got {other:?}"),
        }
    }

    #[test]
    fn rejects_unterminated_quote() {
        let err = parse_www_authenticate(r#"Bearer realm="https://x"#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_param_without_equals() {
        let err = parse_www_authenticate(r#"Bearer realm="x", justakey"#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // ----- Batch G: multi-challenge stance --------------------------------
    //
    // RFC 7235 allows comma-separated multiple challenges in one
    // header, but the syntax is genuinely ambiguous (the same `,`
    // separates parameters within a challenge AND challenges from
    // each other; disambiguation requires recognising scheme tokens
    // that have no `=`). Real OCI registries do NOT multi-challenge,
    // so we pin to single-Bearer parsing: a stray scheme keyword
    // appearing in the parameter section is treated as a key-without-
    // `=` malformed parameter. This is the simplest correct stance.

    #[test]
    fn bearer_with_trailing_basic_scheme_keyword_is_malformed() {
        let err = parse_www_authenticate(r#"Bearer realm="x", Basic"#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn bearer_first_in_comma_split_with_quoted_realm() {
        let err = parse_www_authenticate(r#"Bearer realm="https://x", Negotiate"#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // ----- Batch H: coverage edge cases -----------------------------------

    #[test]
    fn empty_service_treated_as_none() {
        let c = parse_www_authenticate(r#"Bearer realm="x", service="""#).unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.service, None);
    }

    #[test]
    fn empty_scope_treated_as_none() {
        let c = parse_www_authenticate(r#"Bearer realm="x", scope="""#).unwrap();
        assert_eq!(c.realm, "x");
        assert_eq!(c.scope, None);
    }

    #[test]
    fn realm_only_no_service_no_scope() {
        let c = parse_www_authenticate(r#"Bearer realm="https://quay.io/v2/auth""#).unwrap();
        assert_eq!(c.realm, "https://quay.io/v2/auth");
        assert_eq!(c.service, None);
        assert_eq!(c.scope, None);
    }

    #[test]
    fn duplicate_realm_last_wins() {
        let c = parse_www_authenticate(r#"Bearer realm="a", realm="b""#).unwrap();
        assert_eq!(c.realm, "b");
    }

    // ----- Coverage-fill: branches not exercised by the batches above ------

    #[test]
    fn bare_bearer_with_no_params_is_missing_realm() {
        // Exercises the "scheme has no whitespace at all" branch in
        // the scheme-split: `find(char::is_whitespace) == None`.
        let err = parse_www_authenticate("Bearer").unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => assert!(msg.contains("missing realm")),
            other => panic!("expected Malformed(missing realm), got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_parameter_key() {
        // Exercises the empty-key branch: `=value` with no preceding
        // identifier.
        let err = parse_www_authenticate(r#"Bearer ="x""#).unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => assert!(msg.contains("empty parameter key")),
            other => panic!("expected Malformed(empty parameter key), got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_backslash_in_quoted_value() {
        // Exercises the trailing-backslash branch in the quoted-string
        // escape arm. Header ends mid-escape: `realm="x\`.
        let err = parse_www_authenticate("Bearer realm=\"x\\").unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => {
                assert!(msg.contains("trailing backslash"));
            }
            other => panic!("expected Malformed(trailing backslash), got {other:?}"),
        }
    }

    #[test]
    fn unquoted_value_terminates_at_comma() {
        // Exercises the `c == ','` break in the unquoted-value loop.
        let c = parse_www_authenticate("Bearer realm=foo,service=bar").unwrap();
        assert_eq!(c.realm, "foo");
        assert_eq!(c.service.as_deref(), Some("bar"));
    }

    #[test]
    fn empty_unquoted_value_after_equals_treated_as_missing_realm() {
        // Exercises the `None => String::new()` branch (input ends
        // immediately after `=`). With realm=<empty>, the malformed-
        // realm check fires.
        let err = parse_www_authenticate("Bearer realm=").unwrap_err();
        match err {
            ChallengeParseError::Malformed(msg) => assert!(msg.contains("missing realm")),
            other => panic!("expected Malformed(missing realm), got {other:?}"),
        }
    }
}
