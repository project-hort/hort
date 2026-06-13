//! `hort-cli prefetch` subcommand.
//!
//! Calls `POST /api/v1/repositories/{repo_key}/prefetch` with a
//! **single-item** `items` array (the CLI exposes single-package
//! ergonomics; the server-side envelope is batch-shaped and this client
//! renders the full continue-on-error envelope so a future bulk-mode
//! extension does not need to reshape the printer).
//!
//! The four `PrefetchOutcome` partitions:
//!
//! - `enqueued_job_ids` — fresh `jobs` row IDs (successful enqueue).
//! - `skipped_already_held` — HORT already holds this `(package, version)`
//!   at `Released` ∨ `Quarantined` ∨ `QuarantinedAwaitingRelease`; the
//!   ingest is a no-op.
//! - `rejected_packages` — terminal HORT status (`ScanRejected` ∨
//!   `ScanIndeterminate`) for the requested version; re-prefetch refused —
//!   operator uses curator-waive (see
//!   `docs/architecture/how-to/curator-workflow.md`) or admin override.
//! - `failed` — per-item upstream-fetch / parse / network failure
//!   (per `PrefetchItemError` taxonomy).
//!
//! The endpoint requires `Permission::Read ∧ Permission::Prefetch` on
//! the repo **and** `TokenKind::CliSession`; both gates are enforced
//! server-side.
//!
//! # `BlockOutcome` mirror
//!
//! Output rendering mirrors `curation::block::render_outcome` exactly:
//! a five-column count summary table, then per-partition detail
//! sections (one per non-empty bucket). ANSI red highlight on the two
//! "operator should notice" counts (`REJECTED` + `FAILED`) is gated on
//! `std::io::stdout().is_terminal()` so pipes / file redirects /
//! CI log aggregators get plain text (mirrors
//! `crates/hort-cli/src/curation/block.rs:222-227`).
//!
//! # Dep-graph invariant
//!
//! Mirrors `get` and `list_versions`: zero imports from `hort-domain`,
//! `hort-app`, or `hort-adapters-*`. Wire DTOs (`PrefetchOutcomeDto`,
//! `PackageCoordsDto`, `RejectedItemDto`, `RejectionReasonDto`,
//! `FailedItemDto`, `PrefetchItemErrorDto`) mirror
//! `hort_domain::entities::discovery` verbatim — the domain types are
//! Serialize-only on the server side (per `static_assertions` at
//! `crates/hort-domain/src/entities/discovery.rs:283`); the CLI declares
//! Deserialize-side counterparts locally.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ANSI escape for red text — used in table output to highlight the
// `REJECTED` and `FAILED` counts when non-zero (mirrors
// `curation::block`'s ANSI handling; inline literals avoid pulling in
// the `colored` crate per the architect-doc no-extra-deps stance).
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Wire DTOs (sync-required with hort_domain::entities::discovery)
// ---------------------------------------------------------------------------

/// Request body envelope sent to
/// `POST /api/v1/repositories/{repo_key}/prefetch`.
///
/// **Sync-required**: mirrors
/// `hort_http_discovery::dto::SelfServicePrefetchRequestDto`. The
/// `Serialize` derive is the CLI side of that contract (the handler
/// `Deserialize`s the same shape from the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SelfServicePrefetchRequestBody {
    items: Vec<PrefetchRequestItemBody>,
}

/// One item in the request batch.
///
/// **Sync-required**: mirrors
/// `hort_http_discovery::dto::PrefetchRequestItemDto`. `version: None`
/// means *latest upstream-advertised* — the server resolves at enqueue
/// time (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PrefetchRequestItemBody {
    package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

/// Response envelope for `POST .../prefetch`.
///
/// **Sync-required**: mirrors
/// `hort_domain::entities::discovery::PrefetchOutcome`. Both
/// `Deserialize` (CLI parses the response) and `Serialize` (we re-emit
/// the parsed envelope for `--output json`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PrefetchOutcomeDto {
    pub enqueued_job_ids: Vec<Uuid>,
    pub skipped_already_held: Vec<PackageCoordsDto>,
    pub rejected_packages: Vec<RejectedItemDto>,
    pub failed: Vec<FailedItemDto>,
}

/// Mirror of `hort_domain::entities::discovery::PackageCoords`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PackageCoordsDto {
    pub package: String,
    pub version: Option<String>,
}

/// Mirror of `hort_domain::entities::discovery::RejectedItem`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RejectedItemDto {
    pub coords: PackageCoordsDto,
    pub reason: RejectionReasonDto,
}

/// Mirror of `hort_domain::entities::discovery::RejectionReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReasonDto {
    ScanRejected,
    ScanIndeterminate,
}

/// Mirror of `hort_domain::entities::discovery::FailedItem`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FailedItemDto {
    pub coords: PackageCoordsDto,
    pub error: PrefetchItemErrorDto,
}

/// Mirror of `hort_domain::entities::discovery::PrefetchItemError` — the
/// eight-arm closed enum aligned with `UpstreamErrorKind` (§3.2).
///
/// `Upstream4xx` / `Upstream5xx` carry the explicit `serde(rename)` per
/// the domain definition so the wire labels are exactly `upstream_4xx`
/// / `upstream_5xx` (snake_case default would not insert the underscore
/// between letters and digits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchItemErrorDto {
    UpstreamNotFound,
    Unauthorized,
    RateLimited,
    #[serde(rename = "upstream_4xx")]
    Upstream4xx,
    #[serde(rename = "upstream_5xx")]
    Upstream5xx,
    NetworkError,
    Timeout,
    ParseError,
    /// AK-side infrastructure failure (H7) — server-side fault, not an
    /// upstream/egress problem. Mirrors `PrefetchItemError::Internal`.
    Internal,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli prefetch <repo> <package> [--version <v>]`.
///
/// Positional `repo` is the operator-facing stable repository key (not
/// a UUID); `package` is the format-native spelling. `--version` is
/// optional — omitted means "latest upstream-advertised", which the
/// server resolves at enqueue time via
/// `UpstreamMetadataPort::list_versions` (design §3.1).
#[derive(Args, Debug)]
pub struct PrefetchArgs {
    /// Repository stable key (e.g. `npm-proxy`).
    pub repo: String,
    /// Package name in the format-native spelling (e.g. `left-pad`,
    /// `Django`, `serde`).
    pub package: String,
    /// Pin to a specific version. Omit for "latest upstream-advertised".
    #[arg(long)]
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Top-level dispatch for `hort-cli prefetch`.
///
/// Resolves `EffectiveConfig`, builds the `AkClient`, calls
/// `POST /api/v1/repositories/{repo}/prefetch`, and prints the
/// outcome envelope to stdout. Mirrors `list_versions::run`.
pub async fn run(
    args: PrefetchArgs,
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
    run_with_client_to(&client, args, output, &mut std::io::stdout()).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Testable inner — pre-built client, pre-built writer.
///
/// Splits out so tests can write into a `Vec<u8>` buffer and assert on
/// the rendered output without driving `stdout()` (mirrors
/// `curation::block::run_artifact_with_output`'s shape).
pub async fn run_with_client_to(
    client: &AkClient,
    args: PrefetchArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let path = build_path(&args.repo);
    let body = SelfServicePrefetchRequestBody {
        items: vec![PrefetchRequestItemBody {
            package: args.package,
            version: args.version,
        }],
    };
    let outcome: PrefetchOutcomeDto = client.post(&path, &body).await?;
    // TTY-gate ANSI colors on the program's *stdout* rather than the
    // test-injected `out` buffer (mirrors `curation::block`'s pattern at
    // `crates/hort-cli/src/curation/block.rs:225-227`).
    let use_ansi = std::io::stdout().is_terminal();
    render_outcome(&outcome, output, out, use_ansi)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Path builder
// ---------------------------------------------------------------------------

/// Build `/api/v1/repositories/{repo}/prefetch` with the repo segment
/// percent-encoded.
///
/// Same encoding policy as `list_versions::build_path` — unreserved
/// bytes only, `.` excluded to defang `..` traversal in operator input.
pub(crate) fn build_path(repo: &str) -> String {
    format!(
        "/api/v1/repositories/{}/prefetch",
        encode_path_segment(repo)
    )
}

/// Percent-encode a single URL path segment.
///
/// Sibling of `list_versions::encode_path_segment` /
/// `curation::encode_path_segment`. Not shared because the three may
/// diverge as per-surface validation rules evolve.
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

/// Render a `PrefetchOutcomeDto` envelope.
///
/// Table mode: a four-column summary (counts per partition) then
/// per-partition detail sections for the non-empty buckets. JSON mode:
/// emit the envelope verbatim via `serde_json::to_string_pretty`. ANSI
/// red highlights are gated on `use_ansi`:
///
/// - `REJECTED` column → red when non-zero (operator should know
///   curator-waive / admin-override is required for these versions).
/// - `FAILED` column → red when non-zero (operator should retry).
/// - The detail-section banners (`REJECTED (N)`, `FAILED (N)`) mirror
///   the column highlight.
///
/// `ENQUEUED` and `SKIPPED` are routine partitions — no highlight even
/// when non-zero.
fn render_outcome(
    outcome: &PrefetchOutcomeDto,
    output: OutputFormat,
    out: &mut impl Write,
    use_ansi: bool,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(outcome))?;
        }
        OutputFormat::Table => {
            let headers = &["ENQUEUED", "SKIPPED", "REJECTED", "FAILED"];
            let enqueued = outcome.enqueued_job_ids.len().to_string();
            let skipped = outcome.skipped_already_held.len().to_string();
            let rejected = highlight_if_nonzero(outcome.rejected_packages.len(), use_ansi);
            let failed = highlight_if_nonzero(outcome.failed.len(), use_ansi);
            let rows = vec![vec![enqueued, skipped, rejected, failed]];
            write!(out, "{}", format_table_rows(headers, &rows))?;

            // Per-partition detail sections. Only emit when non-empty so
            // the happy path stays compact (mirrors `curation::block`'s
            // pattern). ANSI escapes wrap the red sections; gated on
            // `use_ansi` so pipes / file redirects / CI log aggregators
            // get plain text.
            let (red, reset) = if use_ansi {
                (ANSI_RED, ANSI_RESET)
            } else {
                ("", "")
            };

            if !outcome.enqueued_job_ids.is_empty() {
                writeln!(out, "\nENQUEUED ({}):", outcome.enqueued_job_ids.len())?;
                let hdr = &["JOB_ID"];
                let rows: Vec<Vec<String>> = outcome
                    .enqueued_job_ids
                    .iter()
                    .map(|id| vec![id.to_string()])
                    .collect();
                write!(out, "{}", format_table_rows(hdr, &rows))?;
            }

            if !outcome.skipped_already_held.is_empty() {
                writeln!(
                    out,
                    "\nSKIPPED_ALREADY_HELD ({}) — hort already holds these versions:",
                    outcome.skipped_already_held.len(),
                )?;
                let hdr = &["PACKAGE", "VERSION"];
                let rows: Vec<Vec<String>> = outcome
                    .skipped_already_held
                    .iter()
                    .map(|c| {
                        vec![
                            c.package.clone(),
                            c.version.clone().unwrap_or_else(|| "<latest>".into()),
                        ]
                    })
                    .collect();
                write!(out, "{}", format_table_rows(hdr, &rows))?;
            }

            if !outcome.rejected_packages.is_empty() {
                writeln!(
                    out,
                    "\n{red}REJECTED ({}) — terminal hort status; use `hort-cli curation waive` or admin override:{reset}",
                    outcome.rejected_packages.len(),
                )?;
                let hdr = &["PACKAGE", "VERSION", "REASON"];
                let rows: Vec<Vec<String>> = outcome
                    .rejected_packages
                    .iter()
                    .map(|r| {
                        vec![
                            r.coords.package.clone(),
                            r.coords
                                .version
                                .clone()
                                .unwrap_or_else(|| "<latest>".into()),
                            format_rejection_reason(r.reason),
                        ]
                    })
                    .collect();
                write!(out, "{}", format_table_rows(hdr, &rows))?;
            }

            if !outcome.failed.is_empty() {
                writeln!(
                    out,
                    "\n{red}FAILED ({}) — upstream-side fetch / parse errors; retry recommended:{reset}",
                    outcome.failed.len(),
                )?;
                let hdr = &["PACKAGE", "VERSION", "ERROR"];
                let rows: Vec<Vec<String>> = outcome
                    .failed
                    .iter()
                    .map(|f| {
                        vec![
                            f.coords.package.clone(),
                            f.coords
                                .version
                                .clone()
                                .unwrap_or_else(|| "<latest>".into()),
                            format_prefetch_item_error(f.error),
                        ]
                    })
                    .collect();
                write!(out, "{}", format_table_rows(hdr, &rows))?;
            }
        }
    }
    Ok(())
}

/// Wrap `n` in ANSI red when `n > 0` AND `use_ansi` is true.
///
/// Mirrors `curation::block::highlight_if_nonzero` verbatim — the
/// TTY-gating contract is the same (interactive eye-draw; suppress on
/// pipe/redirect so `grep`/`awk`/log-aggregators see plain digits).
fn highlight_if_nonzero(n: usize, use_ansi: bool) -> String {
    if n > 0 && use_ansi {
        format!("{ANSI_RED}{n}{ANSI_RESET}")
    } else {
        n.to_string()
    }
}

/// Format a `RejectionReasonDto` as its operator-facing label.
fn format_rejection_reason(r: RejectionReasonDto) -> String {
    match r {
        RejectionReasonDto::ScanRejected => "scan-rejected".to_string(),
        RejectionReasonDto::ScanIndeterminate => "scan-indeterminate".to_string(),
    }
}

/// Format a `PrefetchItemErrorDto` as its operator-facing label.
///
/// Labels are kebab-cased forms of the snake_case wire labels — easier
/// on the eye in a table row. The wire labels remain accessible via
/// `--output json`.
fn format_prefetch_item_error(e: PrefetchItemErrorDto) -> String {
    match e {
        PrefetchItemErrorDto::UpstreamNotFound => "upstream-not-found".to_string(),
        PrefetchItemErrorDto::Unauthorized => "unauthorized".to_string(),
        PrefetchItemErrorDto::RateLimited => "rate-limited".to_string(),
        PrefetchItemErrorDto::Upstream4xx => "upstream-4xx".to_string(),
        PrefetchItemErrorDto::Upstream5xx => "upstream-5xx".to_string(),
        PrefetchItemErrorDto::NetworkError => "network-error".to_string(),
        PrefetchItemErrorDto::Timeout => "timeout".to_string(),
        PrefetchItemErrorDto::ParseError => "parse-error".to_string(),
        PrefetchItemErrorDto::Internal => "internal".to_string(),
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
        Prefetch(PrefetchArgs),
    }

    #[test]
    fn args_parse_two_positionals_no_version() {
        let cli =
            TestCli::try_parse_from(["x", "prefetch", "npm-proxy", "left-pad"]).expect("parses");
        let TestCmd::Prefetch(args) = cli.cmd;
        assert_eq!(args.repo, "npm-proxy");
        assert_eq!(args.package, "left-pad");
        assert!(
            args.version.is_none(),
            "no --version flag → None (= latest)"
        );
    }

    #[test]
    fn args_parse_with_version_flag() {
        let cli = TestCli::try_parse_from([
            "x",
            "prefetch",
            "npm-proxy",
            "left-pad",
            "--version",
            "1.3.0",
        ])
        .expect("parses");
        let TestCmd::Prefetch(args) = cli.cmd;
        assert_eq!(args.version.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn args_missing_package_is_a_clap_error() {
        let err = TestCli::try_parse_from(["x", "prefetch", "npm-proxy"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("required") || msg.contains("PACKAGE") || msg.contains("package"),
            "clap surfaces missing positional: {msg}"
        );
    }

    // ----- Path builder + URL encoding -------------------------------------

    #[test]
    fn build_path_uses_long_form_url() {
        // URL-2 (design §2.2) — `/repositories/` not `/repos/`.
        let path = build_path("npm-proxy");
        assert_eq!(path, "/api/v1/repositories/npm-proxy/prefetch");
        assert!(!path.contains("/repos/"));
    }

    #[test]
    fn build_path_percent_encodes_repo_key() {
        // Non-unreserved bytes in the repo segment get %HH-encoded.
        let path = build_path("ns/repo");
        assert!(path.contains("ns%2Frepo"), "{path}");
    }

    // ----- Request body shape ----------------------------------------------

    #[test]
    fn request_body_with_version_serializes_items_array() {
        let body = SelfServicePrefetchRequestBody {
            items: vec![PrefetchRequestItemBody {
                package: "left-pad".into(),
                version: Some("1.3.0".into()),
            }],
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["items"][0]["package"], "left-pad");
        assert_eq!(v["items"][0]["version"], "1.3.0");
    }

    #[test]
    fn request_body_without_version_omits_field() {
        // `serde(skip_serializing_if = "Option::is_none")` keeps the wire
        // shape tight — the server treats absent and `null` identically
        // (`Option::deserialize` accepts both), but absent is the
        // canonical "I do not have a value" encoding.
        let body = SelfServicePrefetchRequestBody {
            items: vec![PrefetchRequestItemBody {
                package: "left-pad".into(),
                version: None,
            }],
        };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v["items"][0].get("version").is_none(), "{v}");
    }

    // ----- Outcome DTO deserialisation -------------------------------------

    #[test]
    fn outcome_dto_decodes_all_four_partitions() {
        let body = r#"{
            "enqueued_job_ids": ["00000000-0000-0000-0000-000000000001"],
            "skipped_already_held": [
                { "package": "a", "version": "1.0.0" }
            ],
            "rejected_packages": [
                { "coords": { "package": "b", "version": "2.0.0" },
                  "reason": "scan_rejected" }
            ],
            "failed": [
                { "coords": { "package": "c", "version": null },
                  "error": "timeout" }
            ]
        }"#;
        let dto: PrefetchOutcomeDto = serde_json::from_str(body).expect("decodes");
        assert_eq!(dto.enqueued_job_ids.len(), 1);
        assert_eq!(dto.skipped_already_held.len(), 1);
        assert_eq!(dto.rejected_packages.len(), 1);
        assert_eq!(dto.failed.len(), 1);
        assert_eq!(
            dto.rejected_packages[0].reason,
            RejectionReasonDto::ScanRejected
        );
        assert_eq!(dto.failed[0].error, PrefetchItemErrorDto::Timeout);
        assert!(dto.failed[0].coords.version.is_none());
    }

    #[test]
    fn outcome_dto_decodes_eight_arm_error_taxonomy() {
        // Eight-arm closed enum guard — flips a future variant-rename
        // collapse into a loud test failure. The `upstream_4xx` /
        // `upstream_5xx` wire labels carry the explicit `serde(rename)`
        // (snake_case default would not insert the underscore between
        // letters and digits).
        for (label, expected) in &[
            ("upstream_not_found", PrefetchItemErrorDto::UpstreamNotFound),
            ("unauthorized", PrefetchItemErrorDto::Unauthorized),
            ("rate_limited", PrefetchItemErrorDto::RateLimited),
            ("upstream_4xx", PrefetchItemErrorDto::Upstream4xx),
            ("upstream_5xx", PrefetchItemErrorDto::Upstream5xx),
            ("network_error", PrefetchItemErrorDto::NetworkError),
            ("timeout", PrefetchItemErrorDto::Timeout),
            ("parse_error", PrefetchItemErrorDto::ParseError),
        ] {
            let body = format!(
                r#"{{
                    "enqueued_job_ids": [], "skipped_already_held": [],
                    "rejected_packages": [],
                    "failed": [{{ "coords": {{ "package": "p", "version": null }}, "error": "{label}" }}]
                }}"#
            );
            let dto: PrefetchOutcomeDto = serde_json::from_str(&body).expect("decodes");
            assert_eq!(dto.failed[0].error, *expected, "label {label}");
        }
    }

    // ----- Highlight helper -------------------------------------------------

    #[test]
    fn highlight_zero_no_ansi() {
        assert_eq!(highlight_if_nonzero(0, true), "0");
        assert_eq!(highlight_if_nonzero(0, false), "0");
    }

    #[test]
    fn highlight_positive_with_ansi_wraps_red() {
        let s = highlight_if_nonzero(2, true);
        assert!(s.contains("2"));
        assert!(s.contains(ANSI_RED));
        assert!(s.contains(ANSI_RESET));
    }

    #[test]
    fn highlight_positive_without_ansi_is_plain() {
        let s = highlight_if_nonzero(2, false);
        assert_eq!(s, "2");
        assert!(!s.contains('\x1b'));
    }

    // ----- Label formatters — every arm ------------------------------------

    #[test]
    fn format_rejection_reason_both_arms() {
        assert_eq!(
            format_rejection_reason(RejectionReasonDto::ScanRejected),
            "scan-rejected"
        );
        assert_eq!(
            format_rejection_reason(RejectionReasonDto::ScanIndeterminate),
            "scan-indeterminate"
        );
    }

    #[test]
    fn format_prefetch_item_error_all_eight_arms() {
        // Exhaustive — one assertion per arm so a future variant-rename
        // surfaces a specific failing test, not a generic one.
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::UpstreamNotFound),
            "upstream-not-found"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::Unauthorized),
            "unauthorized"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::RateLimited),
            "rate-limited"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::Upstream4xx),
            "upstream-4xx"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::Upstream5xx),
            "upstream-5xx"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::NetworkError),
            "network-error"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::Timeout),
            "timeout"
        );
        assert_eq!(
            format_prefetch_item_error(PrefetchItemErrorDto::ParseError),
            "parse-error"
        );
    }

    // ----- Envelope rendering ----------------------------------------------

    fn empty_outcome() -> PrefetchOutcomeDto {
        PrefetchOutcomeDto {
            enqueued_job_ids: vec![],
            skipped_already_held: vec![],
            rejected_packages: vec![],
            failed: vec![],
        }
    }

    #[test]
    fn render_table_empty_outcome_has_no_detail_sections() {
        // Compact happy path — header + four-column zero row, nothing
        // else (mirrors `curation::block`'s empty-detail behaviour).
        let outcome = empty_outcome();
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("ENQUEUED"));
        assert!(out.contains("SKIPPED"));
        assert!(out.contains("REJECTED"));
        assert!(out.contains("FAILED"));
        // No detail-section banners on an all-empty outcome.
        assert!(!out.contains("ENQUEUED ("));
        assert!(!out.contains("FAILED ("));
        assert!(!out.contains("REJECTED ("));
    }

    #[test]
    fn render_table_enqueued_section_emits_job_id_rows() {
        let mut outcome = empty_outcome();
        outcome
            .enqueued_job_ids
            .push(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap());
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("ENQUEUED (1)"));
        assert!(out.contains("11111111-1111-1111-1111-111111111111"));
    }

    #[test]
    fn render_table_skipped_section_shows_latest_marker() {
        // `version: None` renders as `<latest>` — the same encoding the
        // server returns for a request that omitted the field; keeps the
        // table column non-empty for operator readability.
        let mut outcome = empty_outcome();
        outcome.skipped_already_held.push(PackageCoordsDto {
            package: "left-pad".into(),
            version: None,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("SKIPPED_ALREADY_HELD (1)"));
        assert!(out.contains("left-pad"));
        assert!(out.contains("<latest>"));
    }

    #[test]
    fn render_table_rejected_section_uses_red_when_ansi() {
        let mut outcome = empty_outcome();
        outcome.rejected_packages.push(RejectedItemDto {
            coords: PackageCoordsDto {
                package: "p".into(),
                version: Some("1.0.0".into()),
            },
            reason: RejectionReasonDto::ScanRejected,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("REJECTED (1)"));
        assert!(out.contains("scan-rejected"));
        assert!(out.contains(ANSI_RED));
    }

    #[test]
    fn render_table_rejected_section_no_ansi_when_piped() {
        // Pipe/redirect path — `use_ansi=false`. The section banner +
        // row stay; only ANSI escapes vanish (downstream `grep`/`awk`
        // safety).
        let mut outcome = empty_outcome();
        outcome.rejected_packages.push(RejectedItemDto {
            coords: PackageCoordsDto {
                package: "p".into(),
                version: Some("1.0.0".into()),
            },
            reason: RejectionReasonDto::ScanIndeterminate,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("REJECTED (1)"));
        assert!(out.contains("scan-indeterminate"));
        assert!(!out.contains('\x1b'), "no ANSI bytes when piped: {out:?}");
    }

    #[test]
    fn render_table_failed_section_uses_red_when_ansi() {
        let mut outcome = empty_outcome();
        outcome.failed.push(FailedItemDto {
            coords: PackageCoordsDto {
                package: "p".into(),
                version: Some("1.0.0".into()),
            },
            error: PrefetchItemErrorDto::Timeout,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("FAILED (1)"));
        assert!(out.contains("timeout"));
        assert!(out.contains(ANSI_RED));
    }

    #[test]
    fn render_table_failed_section_no_ansi_when_piped() {
        let mut outcome = empty_outcome();
        outcome.failed.push(FailedItemDto {
            coords: PackageCoordsDto {
                package: "p".into(),
                version: None,
            },
            error: PrefetchItemErrorDto::NetworkError,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("FAILED (1)"));
        assert!(out.contains("network-error"));
        assert!(!out.contains('\x1b'), "no ANSI bytes when piped: {out:?}");
    }

    #[test]
    fn render_table_all_four_partitions_populated() {
        // Batch-shape rehearsal — even though the CLI sends a single item,
        // the printer mirrors the server's response shape so a future
        // bulk-mode CLI extension does not need to reshape the printer.
        let mut outcome = empty_outcome();
        outcome.enqueued_job_ids.push(Uuid::nil());
        outcome.skipped_already_held.push(PackageCoordsDto {
            package: "a".into(),
            version: Some("1".into()),
        });
        outcome.rejected_packages.push(RejectedItemDto {
            coords: PackageCoordsDto {
                package: "b".into(),
                version: Some("2".into()),
            },
            reason: RejectionReasonDto::ScanRejected,
        });
        outcome.failed.push(FailedItemDto {
            coords: PackageCoordsDto {
                package: "c".into(),
                version: Some("3".into()),
            },
            error: PrefetchItemErrorDto::Upstream5xx,
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        // All four detail sections present.
        assert!(out.contains("ENQUEUED (1)"));
        assert!(out.contains("SKIPPED_ALREADY_HELD (1)"));
        assert!(out.contains("REJECTED (1)"));
        assert!(out.contains("FAILED (1)"));
        // And the per-row content lands.
        assert!(out.contains("scan-rejected"));
        assert!(out.contains("upstream-5xx"));
    }

    #[test]
    fn render_json_emits_valid_envelope() {
        // JSON output bypasses ANSI entirely — `use_ansi` is a no-op
        // for serde rendering.
        for use_ansi in [true, false] {
            let outcome = empty_outcome();
            let mut buf = Vec::new();
            render_outcome(&outcome, OutputFormat::Json, &mut buf, use_ansi).expect("renders");
            let out = String::from_utf8(buf).expect("utf8");
            assert!(
                !out.contains('\x1b'),
                "JSON never carries ANSI (use_ansi={use_ansi})"
            );
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            assert!(parsed.get("enqueued_job_ids").is_some());
            assert!(parsed.get("skipped_already_held").is_some());
            assert!(parsed.get("rejected_packages").is_some());
            assert!(parsed.get("failed").is_some());
        }
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
    async fn http_post_happy_path_renders_outcome() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/repositories/npm-proxy/prefetch")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "enqueued_job_ids": ["00000000-0000-0000-0000-000000000001"],
                "skipped_already_held": [],
                "rejected_packages": [],
                "failed": []
            }"#,
            )
            .create_async()
            .await;

        let client = test_client(&server.url());
        let mut buf = Vec::new();
        run_with_client_to(
            &client,
            PrefetchArgs {
                repo: "npm-proxy".into(),
                package: "left-pad".into(),
                version: Some("1.3.0".into()),
            },
            OutputFormat::Table,
            &mut buf,
        )
        .await
        .expect("succeeds");

        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("ENQUEUED"));
        assert!(out.contains("ENQUEUED (1)"));
        assert!(out.contains("00000000-0000-0000-0000-000000000001"));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn http_500_surfaces_as_anyhow_error() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/repositories/r/prefetch")
            .with_status(500)
            .with_body(r#"{"error":{"code":"internal","message":"boom"}}"#)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let mut buf = Vec::new();
        let err = run_with_client_to(
            &client,
            PrefetchArgs {
                repo: "r".into(),
                package: "p".into(),
                version: None,
            },
            OutputFormat::Table,
            &mut buf,
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("500"), "error carries HTTP status: {msg}");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn http_403_token_kind_denied_surfaces_as_error() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/repositories/r/prefetch")
            .with_status(403)
            .with_body(r#"{"error":{"code":"forbidden","message":"this endpoint requires a CLI session token"}}"#)
            .create_async()
            .await;

        let client = test_client(&server.url());
        let mut buf = Vec::new();
        let err = run_with_client_to(
            &client,
            PrefetchArgs {
                repo: "r".into(),
                package: "p".into(),
                version: None,
            },
            OutputFormat::Json,
            &mut buf,
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("403"));
        assert!(msg.contains("CLI session token"));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn unreachable_host_surfaces_as_anyhow_error() {
        // Network-error path — RFC 5737 documentation IP
        // (192.0.2.0/24, "never routed") on a port nobody binds to.
        // Surfaces as a transport error without depending on the
        // OS-specific "connection refused" wording.
        let bad_url = "http://192.0.2.1:1/";
        let client = test_client(bad_url);

        let mut buf = Vec::new();
        let err = run_with_client_to(
            &client,
            PrefetchArgs {
                repo: "r".into(),
                package: "p".into(),
                version: None,
            },
            OutputFormat::Table,
            &mut buf,
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}").to_lowercase();
        assert!(
            msg.contains("http post"),
            "context-wrap from AkClient::post present: {msg}"
        );
    }
}
