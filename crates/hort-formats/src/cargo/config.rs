use hort_domain::error::{DomainError, DomainResult};

use crate::cargo::prefix_for;

/// Parsed representation of a Cargo registry `config.json`.
///
/// See: <https://doc.rust-lang.org/cargo/reference/registry-index.html#index-configuration>
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RegistryConfig {
    /// Download URL template. May contain any of the five spec-defined
    /// placeholders: `{crate}`, `{version}`, `{prefix}`, `{lowerprefix}`,
    /// `{sha256-checksum}`. If none are present the registry serves downloads
    /// at `<dl>/{crate}/{version}/download`.
    pub dl: String,
    /// REST API endpoint (optional; unused by pull-through but parsed for
    /// completeness).
    pub api: Option<String>,
}

/// Parse a `config.json` body into a [`RegistryConfig`].
///
/// Unknown JSON fields are silently ignored (forward compatibility).
/// Returns [`DomainError::Validation`] when the body is not valid JSON or
/// when the mandatory `dl` field is absent.
pub fn parse_registry_config(body: &[u8]) -> DomainResult<RegistryConfig> {
    serde_json::from_slice(body)
        .map_err(|e| DomainError::Validation(format!("invalid Cargo registry config: {e}")))
}

/// Compose the download URL for a crate release from a registry config.
///
/// Substitutes the five spec-defined placeholders in `config.dl`:
///
/// | Placeholder          | Substitution                                     |
/// |----------------------|--------------------------------------------------|
/// | `{crate}`            | `name`                                           |
/// | `{version}`          | `version`                                        |
/// | `{prefix}`           | Cargo index prefix (see [`prefix_for`])          |
/// | `{lowerprefix}`      | Lowercase variant of `{prefix}` (ASCII-identical)|
/// | `{sha256-checksum}`  | Hex-encoded SHA-256 from `cksum` when `Some`     |
///
/// If the template contains **none** of the five placeholders, the spec
/// mandates appending `/{crate}/{version}/download` to `dl`.
///
/// If the template contains `{sha256-checksum}` and `cksum` is `None`, the
/// placeholder is left unsubstituted so the upstream HTTP request fails
/// naturally with a 404 rather than panicking or returning an error here.
pub fn compose_download_url(
    config: &RegistryConfig,
    name: &str,
    version: &str,
    cksum: Option<&str>,
) -> String {
    let template = &config.dl;

    // Check whether any placeholder is present before substituting.
    let has_placeholders = template.contains("{crate}")
        || template.contains("{version}")
        || template.contains("{prefix}")
        || template.contains("{lowerprefix}")
        || template.contains("{sha256-checksum}");

    if !has_placeholders {
        // Spec default: append /{crate}/{version}/download.
        return format!("{template}/{name}/{version}/download");
    }

    let prefix = prefix_for(name);
    // For ASCII crate names (the only valid Cargo names), lowercase and
    // uppercase prefix are byte-identical, but the placeholder exists for
    // mixed-case registry URLs.
    let lower_prefix = prefix.to_lowercase();

    // Substitute {lowerprefix} BEFORE {prefix} to avoid treating {prefix} as
    // a substring of {lowerprefix} and double-substituting.
    let mut url = template.replace("{lowerprefix}", &lower_prefix);
    url = url.replace("{prefix}", &prefix);
    url = url.replace("{crate}", name);
    url = url.replace("{version}", version);
    // If cksum is None the placeholder is left unsubstituted; the upstream
    // request will receive a malformed URL and fail with 404 naturally.
    if let Some(cksum) = cksum {
        url = url.replace("{sha256-checksum}", cksum);
    }

    url
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_registry_config ─────────────────────────────────────────────────

    #[test]
    fn parse_crates_io_config_happy_path() {
        let body = include_bytes!("../../tests/fixtures/cargo/crates_io_config.json");
        let cfg = parse_registry_config(body).unwrap();
        assert_eq!(cfg.dl, "https://static.crates.io/crates");
        assert_eq!(cfg.api.as_deref(), Some("https://crates.io"));
    }

    #[test]
    fn parse_accepts_unknown_fields() {
        let body = br#"{"dl": "https://example.com/dl", "future_field": 42}"#;
        let cfg = parse_registry_config(body).unwrap();
        assert_eq!(cfg.dl, "https://example.com/dl");
    }

    #[test]
    fn parse_missing_dl_returns_validation_error() {
        let body = br#"{"api": "https://example.com/api"}"#;
        let err = parse_registry_config(body).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation error, got: {err:?}"
        );
        assert!(
            err.to_string().contains("invalid Cargo registry config"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_invalid_json_returns_validation_error() {
        let body = b"not json at all";
        let err = parse_registry_config(body).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation error, got: {err:?}"
        );
        assert!(
            err.to_string().contains("invalid Cargo registry config"),
            "unexpected message: {err}"
        );
    }

    // ── compose_download_url ──────────────────────────────────────────────────

    #[test]
    fn compose_crates_io_serde_1_0_214() {
        // crates.io's dl has no placeholders → spec default suffix is appended.
        let body = include_bytes!("../../tests/fixtures/cargo/crates_io_config.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "serde", "1.0.214", None);
        assert_eq!(
            url,
            "https://static.crates.io/crates/serde/1.0.214/download"
        );
    }

    /// Private-registry template: `{prefix}/{lowerprefix}/{crate}-{version}.crate`
    /// Tests all four Cargo name-length cases (1 / 2 / 3 / 4+ chars).
    #[test]
    fn compose_private_registry_one_char_name() {
        let body = include_bytes!("../../tests/fixtures/cargo/private_registry_config.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "a", "1.0.0", None);
        // prefix("a") = "1", lowerprefix = "1"
        assert_eq!(url, "https://artifacts.example.com/1/1/a-1.0.0.crate");
    }

    #[test]
    fn compose_private_registry_two_char_name() {
        let body = include_bytes!("../../tests/fixtures/cargo/private_registry_config.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "ab", "2.0.0", None);
        // prefix("ab") = "2", lowerprefix = "2"
        assert_eq!(url, "https://artifacts.example.com/2/2/ab-2.0.0.crate");
    }

    #[test]
    fn compose_private_registry_three_char_name() {
        let body = include_bytes!("../../tests/fixtures/cargo/private_registry_config.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "abc", "3.0.0", None);
        // prefix("abc") = "3/a", lowerprefix = "3/a"
        assert_eq!(url, "https://artifacts.example.com/3/a/3/a/abc-3.0.0.crate");
    }

    #[test]
    fn compose_private_registry_four_plus_char_name() {
        let body = include_bytes!("../../tests/fixtures/cargo/private_registry_config.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "serde", "1.0.214", None);
        // prefix("serde") = "se/rd", lowerprefix = "se/rd"
        assert_eq!(
            url,
            "https://artifacts.example.com/se/rd/se/rd/serde-1.0.214.crate"
        );
    }

    #[test]
    fn compose_checksum_template_with_cksum_some() {
        let body = include_bytes!("../../tests/fixtures/cargo/template_with_checksum.json");
        let cfg = parse_registry_config(body).unwrap();
        let cksum = "f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b5";
        let url = compose_download_url(&cfg, "serde", "1.0.214", Some(cksum));
        assert_eq!(
            url,
            format!("https://artifacts.example.com/crates/serde/1.0.214/{cksum}.crate")
        );
    }

    #[test]
    fn compose_checksum_template_with_cksum_none_leaves_placeholder() {
        let body = include_bytes!("../../tests/fixtures/cargo/template_with_checksum.json");
        let cfg = parse_registry_config(body).unwrap();
        let url = compose_download_url(&cfg, "serde", "1.0.214", None);
        // Placeholder must be present in result so the HTTP request fails
        // naturally (404) rather than silently routing to a wrong URL.
        assert!(
            url.contains("{sha256-checksum}"),
            "expected unsubstituted placeholder in: {url}"
        );
    }
}
