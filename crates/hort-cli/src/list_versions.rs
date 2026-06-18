//! `hort-cli list-versions` subcommand.
//!
//! Calls `GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`
//! and renders the [`DiscoveryListing`] JSON envelope as a two-column
//! status-annotated table (version + status). The six status values mirror
//! `hort_domain::entities::discovery::DiscoveryVersionStatus`:
//!
//! - `released` — installable.
//! - `quarantined (until <RFC3339>)` — active future-dated deadline.
//! - `quarantined-awaiting-release` — deadline elapsed, no release
//!   authority has fired yet (see ADR 0007).
//! - `rejected` — terminally rejected by scan or curator-block.
//! - `scan-indeterminate` — scanner could not produce a verdict;
//!   treated as terminal for the auto-release path.
//! - `unknown` — upstream-advertised, HORT has never ingested.
//!
//! The endpoint requires `Permission::Read` on the repo **and** a CLI
//! session JWT (`TokenKind::CliSession`); both gates are enforced
//! server-side — this client does not perform its own pre-flight check
//! (the server is the source of truth and a redundant client check would
//! drift).
//!
//! # Dep-graph invariant
//!
//! Mirrors the `get` subcommand discipline: zero imports from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The response wire DTOs
//! (`DiscoveryListingDto`, `DiscoveryVersionEntryDto`,
//! `DiscoveryVersionStatusDto`) are mirrored verbatim from
//! `hort_domain::entities::discovery` — the architect-doc anti-pattern
//! *"Domain type deserialization in API layer"* forbids `Deserialize`
//! on the domain types themselves (`static_assertions` at
//! `crates/hort-domain/src/entities/discovery.rs:279` pin the rule), so
//! the CLI declares Deserialize-side wire shapes locally. Field
//! names + serde tags + variant rename rules are part of the response
//! contract.

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (sync-required with hort_domain::entities::discovery)
// ---------------------------------------------------------------------------

/// JSON envelope for
/// `GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`.
///
/// **Sync-required**: mirrors `hort_domain::entities::discovery::DiscoveryListing`
/// (Serialize-only on the server side; this is the Deserialize-side
/// counterpart on the CLI). `Serialize` is implemented locally so the
/// `--output json` path can re-emit the parsed envelope verbatim — the
/// architect-doc anti-pattern *"Domain type deserialization in API
/// layer"* is asymmetric (forbids `Deserialize` on the domain type,
/// not `Serialize`), and this DTO is in the CLI / inbound-shape layer,
/// not the domain.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DiscoveryListingDto {
    /// Package name in the format-native spelling.
    pub package: String,
    /// Format identifier (`"npm"`, `"pypi"`, `"cargo"`, ...).
    pub format: String,
    /// One entry per known version (AK-held ∪ upstream-advertised).
    pub versions: Vec<DiscoveryVersionEntryDto>,
}

/// One version row inside [`DiscoveryListingDto::versions`].
///
/// **Sync-required**: mirrors
/// `hort_domain::entities::discovery::DiscoveryVersionEntry`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DiscoveryVersionEntryDto {
    /// Version string in the format-native spelling.
    pub version: String,
    /// Current status of this version in this repository.
    pub status: DiscoveryVersionStatusDto,
}

/// Per-version status, surfaced by discovery.
///
/// **Sync-required**: mirrors
/// `hort_domain::entities::discovery::DiscoveryVersionStatus` — the
/// `#[serde(tag = "kind", rename_all = "snake_case")]` representation
/// is the wire contract.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiscoveryVersionStatusDto {
    /// Released — installable.
    Released,
    /// Quarantined with an active future-dated deadline.
    Quarantined {
        /// Future-dated UTC instant at which the quarantine window
        /// ends.
        quarantine_until: DateTime<Utc>,
    },
    /// Quarantine deadline elapsed; no release authority has fired
    /// (see ADR 0007 — release-predicate invariant).
    QuarantinedAwaitingRelease,
    /// Terminally rejected by scan or curator-block.
    Rejected,
    /// Scan result was indeterminate; treated as terminal.
    ScanIndeterminate,
    /// Upstream-advertised but HORT has never ingested.
    Unknown,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli list-versions <repo> <package>`.
///
/// Positional `repo` is the operator-facing stable repository key (e.g.
/// `npm-proxy`) — NOT a UUID; the server resolves it via
/// `RepositoryUseCase::get_by_key` (404 on unknown key). Positional
/// `package` is the format-native spelling (the server preserves case;
/// it does NOT canonicalise — design echo-back).
#[derive(Args, Debug)]
pub struct ListVersionsArgs {
    /// Repository stable key (e.g. `npm-proxy`).
    #[arg(add = crate::completions::repo_arg_candidates())]
    pub repo: String,
    /// Package name in the format-native spelling (e.g. `left-pad`,
    /// `Django`, `serde`). Path-encoded transparently.
    pub package: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Top-level dispatch for `hort-cli list-versions`.
///
/// Loads `EffectiveConfig` (so CLI flags and env vars are honoured),
/// builds the `AkClient`, calls
/// `GET /api/v1/repositories/{repo}/discovery/versions/{package}`, and
/// prints the result to stdout. Mirrors the `get::run` dispatch shape.
pub async fn run(
    args: ListVersionsArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> Result<std::process::ExitCode> {
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    run_with_client(&client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Testable inner — takes a pre-built client so tests can point it at a
/// mockito `Server::new_async()` URL.
pub async fn run_with_client(
    client: &AkClient,
    args: ListVersionsArgs,
    output: OutputFormat,
) -> Result<()> {
    let path = build_path(&args.repo, &args.package);
    let listing: DiscoveryListingDto = client.get(&path).await?;
    println!("{}", render(&listing, output));
    Ok(())
}

// ---------------------------------------------------------------------------
// Path builder
// ---------------------------------------------------------------------------

/// Build `/api/v1/repositories/{repo}/discovery/versions/{package}` with
/// percent-encoded segments.
///
/// Repository keys and package names may contain non-unreserved bytes
/// (PyPI canonical names use `-`, npm scopes use `@org/name`, OCI uses
/// `library/alpine`). Encoding is conservative: only RFC 3986 unreserved
/// bytes pass through; everything else is `%HH`-escaped. `.` is
/// intentionally excluded so `..` cannot survive encoding (defense-in-
/// depth against path-traversal in operator input; mirrors
/// `curation::encode_path_segment`).
pub(crate) fn build_path(repo: &str, package: &str) -> String {
    format!(
        "/api/v1/repositories/{}/discovery/versions/{}",
        encode_path_segment(repo),
        encode_path_segment(package),
    )
}

/// Percent-encode a single URL path segment.
///
/// Mirrors `curation::encode_path_segment` byte-for-byte (defensive,
/// dot-excluded). Not shared because the curation copy may diverge as
/// validation rules evolve.
fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            b => {
                encoded.push('%');
                encoded.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                encoded.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render the listing for the given output format.
fn render(listing: &DiscoveryListingDto, output: OutputFormat) -> String {
    match output {
        OutputFormat::Json => format_json(listing),
        OutputFormat::Table => render_table(listing),
    }
}

/// Render as a two-column table: `VERSION` + `STATUS`.
///
/// Status column text:
/// - `released`
/// - `quarantined (until YYYY-MM-DDTHH:MM:SSZ)` with the deadline in
///   RFC 3339 UTC
/// - `quarantined-awaiting-release`
/// - `rejected`
/// - `scan-indeterminate`
/// - `unknown`
fn render_table(listing: &DiscoveryListingDto) -> String {
    let headers = &["VERSION", "STATUS"];
    let rows: Vec<Vec<String>> = listing
        .versions
        .iter()
        .map(|entry| vec![entry.version.clone(), format_status(&entry.status)])
        .collect();
    format_table_rows(headers, &rows)
}

/// Format a single status arm as its operator-facing string.
fn format_status(status: &DiscoveryVersionStatusDto) -> String {
    match status {
        DiscoveryVersionStatusDto::Released => "released".to_string(),
        DiscoveryVersionStatusDto::Quarantined { quarantine_until } => {
            // RFC 3339 with the trailing `Z` is the established UTC
            // serialisation across the codebase (`to_rfc3339()` on a
            // `DateTime<Utc>` already produces that suffix).
            format!("quarantined (until {})", quarantine_until.to_rfc3339())
        }
        DiscoveryVersionStatusDto::QuarantinedAwaitingRelease => {
            "quarantined-awaiting-release".to_string()
        }
        DiscoveryVersionStatusDto::Rejected => "rejected".to_string(),
        DiscoveryVersionStatusDto::ScanIndeterminate => "scan-indeterminate".to_string(),
        DiscoveryVersionStatusDto::Unknown => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EffectiveConfig;
    use clap::Parser;
    use mockito::Server;
    use url::Url;

    // ----- Args parsing -----------------------------------------------------

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestCmd {
        ListVersions(ListVersionsArgs),
    }

    #[test]
    fn args_parse_two_positionals() {
        let cli = TestCli::try_parse_from(["x", "list-versions", "npm-proxy", "left-pad"])
            .expect("parses");
        let TestCmd::ListVersions(args) = cli.cmd;
        assert_eq!(args.repo, "npm-proxy");
        assert_eq!(args.package, "left-pad");
    }

    #[test]
    fn args_missing_package_is_a_clap_error() {
        let err = TestCli::try_parse_from(["x", "list-versions", "npm-proxy"]).unwrap_err();
        // clap reports "required" for the missing positional.
        let msg = err.to_string();
        assert!(
            msg.contains("required") || msg.contains("PACKAGE") || msg.contains("package"),
            "clap surfaces missing positional: {msg}"
        );
    }

    #[test]
    fn args_missing_repo_is_a_clap_error() {
        let err = TestCli::try_parse_from(["x", "list-versions"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("required") || msg.contains("REPO") || msg.contains("repo"),
            "clap surfaces missing positional: {msg}"
        );
    }

    // ----- Path builder + URL encoding -------------------------------------

    #[test]
    fn build_path_uses_long_form_url_not_short_form() {
        // The long form `/repositories/` was chosen over the short form
        // `/repos/`; matches the shipped admin-security route at
        // `crates/hort-http-admin-security/src/router.rs:32`.
        let path = build_path("npm-proxy", "left-pad");
        assert_eq!(
            path,
            "/api/v1/repositories/npm-proxy/discovery/versions/left-pad"
        );
        assert!(!path.contains("/repos/"), "must NOT use short form: {path}");
    }

    #[test]
    fn build_path_percent_encodes_npm_scoped_package() {
        // npm scoped names contain `/` and `@`. `@` and `/` are NOT in the
        // unreserved set, so both must be percent-encoded.
        let path = build_path("npm-proxy", "@types/node");
        assert!(path.contains("%40types"), "@ must be %40-encoded: {path}");
        assert!(path.contains("%2Fnode"), "/ must be %2F-encoded: {path}");
    }

    #[test]
    fn build_path_blocks_traversal_in_package_segment() {
        // Defensive — `.` is intentionally excluded from the unreserved
        // pass-through set so `..` cannot survive encoding.
        let path = build_path("r", "..");
        assert!(path.contains("%2E%2E"), "dots must be %2E-encoded: {path}");
    }

    // ----- Status formatter — every arm ------------------------------------

    #[test]
    fn format_status_released_arm() {
        assert_eq!(
            format_status(&DiscoveryVersionStatusDto::Released),
            "released"
        );
    }

    #[test]
    fn format_status_quarantined_arm_includes_deadline() {
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let s = format_status(&DiscoveryVersionStatusDto::Quarantined {
            quarantine_until: when,
        });
        assert!(s.starts_with("quarantined (until "));
        // RFC 3339 with the trailing `Z` for UTC.
        assert!(s.contains("2023-11-14T22:13:20"));
        assert!(s.ends_with(")"));
    }

    #[test]
    fn format_status_quarantined_awaiting_release_arm() {
        assert_eq!(
            format_status(&DiscoveryVersionStatusDto::QuarantinedAwaitingRelease),
            "quarantined-awaiting-release"
        );
    }

    #[test]
    fn format_status_rejected_arm() {
        assert_eq!(
            format_status(&DiscoveryVersionStatusDto::Rejected),
            "rejected"
        );
    }

    #[test]
    fn format_status_scan_indeterminate_arm() {
        assert_eq!(
            format_status(&DiscoveryVersionStatusDto::ScanIndeterminate),
            "scan-indeterminate"
        );
    }

    #[test]
    fn format_status_unknown_arm() {
        assert_eq!(
            format_status(&DiscoveryVersionStatusDto::Unknown),
            "unknown"
        );
    }

    // ----- Wire DTO deserialisation ----------------------------------------

    #[test]
    fn dto_decodes_quarantined_arm_with_deadline() {
        let body = r#"{
            "package": "left-pad",
            "format": "npm",
            "versions": [
                {
                    "version": "1.3.0",
                    "status": { "kind": "quarantined", "quarantine_until": "2026-05-27T08:00:00Z" }
                }
            ]
        }"#;
        let listing: DiscoveryListingDto = serde_json::from_str(body).expect("decodes");
        assert_eq!(listing.package, "left-pad");
        assert_eq!(listing.format, "npm");
        assert_eq!(listing.versions.len(), 1);
        match &listing.versions[0].status {
            DiscoveryVersionStatusDto::Quarantined { quarantine_until } => {
                assert_eq!(quarantine_until.to_rfc3339(), "2026-05-27T08:00:00+00:00");
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn dto_decodes_quarantined_awaiting_release_without_payload() {
        let body = r#"{
            "package": "p", "format": "npm",
            "versions": [
                { "version": "9.9.9", "status": { "kind": "quarantined_awaiting_release" } }
            ]
        }"#;
        let listing: DiscoveryListingDto = serde_json::from_str(body).expect("decodes");
        assert!(matches!(
            listing.versions[0].status,
            DiscoveryVersionStatusDto::QuarantinedAwaitingRelease
        ));
    }

    #[test]
    fn dto_decodes_all_six_arms() {
        // Exhaustive arm-coverage on the Deserialize path — sibling of the
        // domain-side `discovery_version_status_six_arms_are_pairwise_distinct`
        // test. Catches a future variant-rename collapse.
        let body = r#"{
            "package": "p", "format": "npm",
            "versions": [
                { "version": "1", "status": { "kind": "released" } },
                { "version": "2", "status": { "kind": "quarantined", "quarantine_until": "2026-05-27T08:00:00Z" } },
                { "version": "3", "status": { "kind": "quarantined_awaiting_release" } },
                { "version": "4", "status": { "kind": "rejected" } },
                { "version": "5", "status": { "kind": "scan_indeterminate" } },
                { "version": "6", "status": { "kind": "unknown" } }
            ]
        }"#;
        let listing: DiscoveryListingDto = serde_json::from_str(body).expect("decodes");
        assert_eq!(listing.versions.len(), 6);
        // Spot-check each arm landed on the right variant.
        assert!(matches!(
            listing.versions[0].status,
            DiscoveryVersionStatusDto::Released
        ));
        assert!(matches!(
            listing.versions[1].status,
            DiscoveryVersionStatusDto::Quarantined { .. }
        ));
        assert!(matches!(
            listing.versions[2].status,
            DiscoveryVersionStatusDto::QuarantinedAwaitingRelease
        ));
        assert!(matches!(
            listing.versions[3].status,
            DiscoveryVersionStatusDto::Rejected
        ));
        assert!(matches!(
            listing.versions[4].status,
            DiscoveryVersionStatusDto::ScanIndeterminate
        ));
        assert!(matches!(
            listing.versions[5].status,
            DiscoveryVersionStatusDto::Unknown
        ));
    }

    // ----- Table rendering --------------------------------------------------

    #[test]
    fn render_table_two_columns_and_header() {
        let listing = DiscoveryListingDto {
            package: "left-pad".into(),
            format: "npm".into(),
            versions: vec![
                DiscoveryVersionEntryDto {
                    version: "1.3.0".into(),
                    status: DiscoveryVersionStatusDto::Released,
                },
                DiscoveryVersionEntryDto {
                    version: "1.4.0".into(),
                    status: DiscoveryVersionStatusDto::Unknown,
                },
            ],
        };
        let out = render_table(&listing);
        assert!(out.contains("VERSION"));
        assert!(out.contains("STATUS"));
        assert!(out.contains("1.3.0"));
        assert!(out.contains("released"));
        assert!(out.contains("1.4.0"));
        assert!(out.contains("unknown"));
    }

    #[test]
    fn render_table_empty_versions_renders_header_only() {
        let listing = DiscoveryListingDto {
            package: "p".into(),
            format: "npm".into(),
            versions: vec![],
        };
        let out = render_table(&listing);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "header only");
        assert!(lines[0].starts_with("VERSION"));
    }

    #[test]
    fn render_table_quarantined_row_shows_deadline() {
        // Operator-UX guard: the deadline must be visible on the table
        // row so the operator can answer "when does this auto-release?"
        // without a second lookup.
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let listing = DiscoveryListingDto {
            package: "p".into(),
            format: "npm".into(),
            versions: vec![DiscoveryVersionEntryDto {
                version: "4.19.0".into(),
                status: DiscoveryVersionStatusDto::Quarantined {
                    quarantine_until: when,
                },
            }],
        };
        let out = render_table(&listing);
        assert!(out.contains("4.19.0"));
        assert!(out.contains("quarantined (until "));
        assert!(out.contains("2023-11-14T22:13:20"));
    }

    // ----- JSON rendering ---------------------------------------------------

    #[test]
    fn render_json_emits_envelope_with_all_fields() {
        let listing = DiscoveryListingDto {
            package: "p".into(),
            format: "npm".into(),
            versions: vec![DiscoveryVersionEntryDto {
                version: "1.0.0".into(),
                status: DiscoveryVersionStatusDto::Released,
            }],
        };
        let out = render(&listing, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(parsed["package"], "p");
        assert_eq!(parsed["format"], "npm");
        assert_eq!(parsed["versions"][0]["version"], "1.0.0");
        // serde-json's tagged-union encoding: kind=released.
        assert_eq!(parsed["versions"][0]["status"]["kind"], "released");
    }

    // ----- Network error path -----------------------------------------------

    fn test_client(server_url: &str) -> AkClient {
        let cfg = EffectiveConfig {
            server: Url::parse(server_url).expect("valid url"),
            token: "test-token".to_string(),
            default_format: OutputFormat::Table,
        };
        AkClient::new(&cfg).expect("client builds")
    }

    #[tokio::test]
    async fn http_500_surfaces_as_anyhow_error() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("GET", "/api/v1/repositories/r/discovery/versions/p")
            .with_status(500)
            .with_body(r#"{"error":{"code":"internal","message":"boom"}}"#)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let err = run_with_client(
            &client,
            ListVersionsArgs {
                repo: "r".into(),
                package: "p".into(),
            },
            OutputFormat::Table,
        )
        .await
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("500"), "error carries HTTP status: {msg}");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn http_403_token_kind_denied_surfaces_as_error() {
        // The use case returns Forbidden with the message
        // "this endpoint requires a CLI session token" when the caller's
        // `token_kind != Some(CliSession)`. The CLI surfaces the upstream
        // body verbatim via `response_to_error`.
        let mut server = Server::new_async().await;
        let m = server
            .mock("GET", "/api/v1/repositories/r/discovery/versions/p")
            .with_status(403)
            .with_body(r#"{"error":{"code":"forbidden","message":"this endpoint requires a CLI session token"}}"#)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let err = run_with_client(
            &client,
            ListVersionsArgs {
                repo: "r".into(),
                package: "p".into(),
            },
            OutputFormat::Json,
        )
        .await
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("403"), "403 status surfaced: {msg}");
        assert!(
            msg.contains("CLI session token"),
            "server message surfaced: {msg}"
        );
        m.assert_async().await;
    }

    #[tokio::test]
    async fn unreachable_host_surfaces_as_anyhow_error() {
        // Network-error path — point the client at a routable-but-
        // unbound port to exercise `client::AkClient::get`'s error
        // wrapping (`.context("HTTP GET")`). RFC 5737 reserves
        // 192.0.2.0/24 for documentation/never-routed; combined with a
        // short connect timeout this surfaces as a transport error
        // without depending on OS-specific "connection refused"
        // wording.
        let bad_url = "http://192.0.2.1:1/";
        let client = test_client(bad_url);

        let err = run_with_client(
            &client,
            ListVersionsArgs {
                repo: "r".into(),
                package: "p".into(),
            },
            OutputFormat::Table,
        )
        .await
        .unwrap_err();

        let msg = format!("{err:#}").to_lowercase();
        // Assert the anyhow chain carries the context wrapper from
        // client.rs (`.context("HTTP GET")`); the underlying transport
        // wording is OS-dependent so we only require the context tag.
        assert!(
            msg.contains("http get"),
            "context-wrap from AkClient::get present: {msg}"
        );
    }
}
