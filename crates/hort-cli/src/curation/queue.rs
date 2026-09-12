//! `hort-cli curation queue` — GET `/api/v1/admin/curation/queue`.
//!
//! Wire contract: `GET /api/v1/admin/curation/queue`
//! (`hort-http-core::handlers::admin::curation::queue`).
//! Paginated read-only listing of every artifact in a curator-actionable
//! state (`Quarantined` / `Rejected` / `ScanIndeterminate`) with per-row
//! quarantine deadlines and a `rejection_reason_kind` discriminator for
//! rejected rows.
//!
//! # Query parameters
//!
//! - `--repo <key>` → `?repository=<key>`. Server resolves the stable key
//!   to a UUID; unknown key → 404.
//! - `--status <quarantined|rejected|scan_indeterminate>` → `?status=`.
//!   Closed-set validation CLIENT-side (fail-fast with a clear "valid:"
//!   hint).
//! - `--reason <kind>` → `?reason=`. **No client-side validation** — the
//!   CLI passes through and lets the server's 400 surface, exactly as
//!   `--limit` does. The accepted set is the server's `RejectionReason`
//!   vocabulary, which grows when the domain gains a rejection axis; this
//!   crate deliberately carries no `hort-domain` dependency, so any list
//!   here would be a hand-maintained copy and would go stale the moment
//!   that vocabulary widened. It did: the copy that stood here still
//!   refused `admin`, `scan_policy_retroactive` and `provenance` after the
//!   server had begun serving rows carrying exactly those — a fast hint
//!   turned into a fast wrong answer.
//! - `--limit <n>` → `?limit=`. Server caps at 500. No client-side
//!   validation — the CLI passes through and lets the server's 400
//!   surface naturally.
//!
//! # Output
//!
//! `--output json` (pass-through): the server's
//! `CurationQueueResponseDto` pretty-printed.
//!
//! `--output table` (default): one row per entry with columns
//! `ARTIFACT_ID  REPO  FORMAT  PACKAGE  VERSION  STATUS  DEADLINE
//! FINDINGS  SEVERITY  REJECT_REASON`. `DEADLINE` renders as ISO-8601
//! UTC (rather than relative duration — operators viewing the curation
//! queue care about the exact wall-clock the artifact becomes eligible
//! for auto-release, not a `in 6h` hand-wave). `REJECT_REASON` is the
//! `rejection_reason_kind` discriminator for rejected rows; `-` when
//! absent (only rejected rows carry one).
//!
//! Empty result prints the header row AND a `No curation queue entries`
//! line (tests pin this).
//!
//! # Implementation note — no ANSI here
//!
//! The `queue` rows are read-only summary data with no "operator must
//! notice" highlights. Skipping ANSI keeps the surface simple.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Closed-set client-side validation
// ---------------------------------------------------------------------------

/// Accepted values for `--status`. Mirrors `QuarantineStatus::FromStr` on
/// the server side: lower-case `quarantined | rejected |
/// scan_indeterminate`. The CLI validates client-side for a fast hint;
/// the server re-validates (defence in depth).
const ACCEPTED_STATUSES: &[&str] = &["quarantined", "rejected", "scan_indeterminate"];

fn validate_status(s: &str) -> Result<()> {
    if ACCEPTED_STATUSES.contains(&s) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "invalid --status {s:?} (valid: {})",
            ACCEPTED_STATUSES.join(" | "),
        ))
    }
}

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::curation::queue)
// ---------------------------------------------------------------------------

/// Wire-format row.
///
/// **Sync-required**: mirrors `CurationQueueEntryDto` in
/// `hort-http-core::handlers::admin::curation::queue`. Enum fields are
/// already projected to lowercase strings server-side; the CLI does NOT
/// re-parse them.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CurationQueueEntryDto {
    pub artifact_id: String,
    pub repository_id: String,
    pub repository_key: String,
    pub format: String,
    pub package_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub quarantine_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_window_start: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_deadline: Option<DateTime<Utc>>,
    pub finding_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason_kind: Option<String>,
}

/// Response envelope.
///
/// **Sync-required**: mirrors `CurationQueueResponseDto` in
/// `hort-http-core::handlers::admin::curation::queue`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CurationQueueResponseDto {
    pub entries: Vec<CurationQueueEntryDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation queue`.
#[derive(clap::Args, Debug)]
pub struct QueueArgs {
    /// Filter by repository stable key (e.g. `npm-proxy`). Unknown key
    /// returns 404.
    #[arg(long = "repo", add = crate::completions::repo_arg_candidates())]
    pub repository: Option<String>,

    /// Filter by quarantine status. Valid: `quarantined`, `rejected`,
    /// `scan_indeterminate`. Validated client-side.
    #[arg(long)]
    pub status: Option<String>,

    /// Filter by rejection-reason kind (`rejected` rows only), e.g.
    /// `scanner`, `curator`, `curation_retroactive`,
    /// `scan_policy_retroactive`, `admin`, `provenance`, `corruption`.
    /// Validated server-side (400 lists the accepted set) — the server's
    /// vocabulary is the only authority on it.
    #[arg(long)]
    pub reason: Option<String>,

    /// Maximum rows to return (server caps at 500 — 400 on overflow).
    #[arg(long)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: QueueArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: QueueArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — closed-set client-side validation (fail-fast hints).
    // `--status` only: `QuarantineStatus` is a fixed three-value lifecycle
    // enum, whereas `--reason` tracks the server's `RejectionReason`
    // vocabulary and is validated there (see the module doc).
    if let Some(ref s) = args.status {
        validate_status(s)?;
    }

    let resp: CurationQueueResponseDto = client.get(&build_path(&args)).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            render_table(&resp.entries, out)?;
        }
    }
    Ok(())
}

/// Build the request path + query string. Manual assembly keeps the dep
/// set tight (mirrors `task_list.rs:74-93` and
/// `list_patch_candidates.rs:113-127`).
///
/// Factored out of [`run_with_output`] so the pass-through behaviour of
/// each filter is testable without an HTTP round trip — `--reason` in
/// particular, which this CLI must forward verbatim rather than judge.
fn build_path(args: &QueueArgs) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref r) = args.repository {
        parts.push(format!("repository={}", urlencoded(r)));
    }
    if let Some(ref s) = args.status {
        parts.push(format!("status={}", urlencoded(s)));
    }
    if let Some(ref r) = args.reason {
        parts.push(format!("reason={}", urlencoded(r)));
    }
    if let Some(l) = args.limit {
        parts.push(format!("limit={l}"));
    }
    if parts.is_empty() {
        "/api/v1/admin/curation/queue".to_string()
    } else {
        format!("/api/v1/admin/curation/queue?{}", parts.join("&"))
    }
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the queue listing as an aligned table. ALWAYS emits the header
/// row; appends a `No curation queue entries` line when `rows` is empty.
/// The convention is applied uniformly across all three read subcommands
/// so the operator surface is predictable.
fn render_table(rows: &[CurationQueueEntryDto], out: &mut impl Write) -> std::io::Result<()> {
    let headers = &[
        "ARTIFACT_ID",
        "REPO",
        "FORMAT",
        "PACKAGE",
        "VERSION",
        "STATUS",
        "DEADLINE",
        "FINDINGS",
        "SEVERITY",
        "REJECT_REASON",
    ];

    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.artifact_id.clone(),
                r.repository_key.clone(),
                r.format.clone(),
                r.package_name.clone(),
                r.version.clone().unwrap_or_else(|| "-".to_string()),
                r.quarantine_status.clone(),
                r.quarantine_deadline
                    .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".to_string()),
                r.finding_count.to_string(),
                r.max_severity.clone().unwrap_or_else(|| "-".to_string()),
                r.rejection_reason_kind
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();

    write!(out, "{}", format_table_rows(headers, &data))?;
    if rows.is_empty() {
        writeln!(out, "No curation queue entries")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode a query-string value (RFC 3986 unreserved set passes
/// through; everything else → `%HH`). Inlined rather than shared with
/// `list_patch_candidates.rs::urlencoded` so the two callers can diverge
/// as their validation rules evolve.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_status_accepts_closed_set() {
        for s in ACCEPTED_STATUSES {
            assert!(validate_status(s).is_ok(), "{s} should be accepted");
        }
    }

    #[test]
    fn validate_status_rejects_unknown() {
        let err = validate_status("bogus").unwrap_err().to_string();
        assert!(err.contains("valid:"), "hint present: {err}");
        assert!(err.contains("quarantined"), "lists accepted: {err}");
    }

    fn queue_args(reason: Option<&str>) -> QueueArgs {
        QueueArgs {
            repository: None,
            status: None,
            reason: reason.map(str::to_string),
            limit: None,
        }
    }

    /// **Every reason the server's vocabulary can hold reaches it.** The
    /// CLI once carried its own `["scanner", "curator",
    /// "curation_retroactive"]` copy and refused the rest client-side, so
    /// an operator asking for the rows that existed got a confident local
    /// "invalid" instead. This crate has no `hort-domain` dependency by
    /// design, so it cannot derive the set — it forwards instead, and the
    /// server (which does derive it) answers.
    #[test]
    fn reason_is_forwarded_verbatim_for_every_server_side_discriminator() {
        for reason in [
            "scanner",
            "admin",
            "curation_retroactive",
            "scan_policy_retroactive",
            "curator",
            "provenance",
            "corruption",
        ] {
            assert_eq!(
                build_path(&queue_args(Some(reason))),
                format!("/api/v1/admin/curation/queue?reason={reason}")
            );
        }
    }

    /// Even an unknown value is forwarded: the server's 400 names the
    /// accepted set, which is a better answer than a stale local list.
    #[test]
    fn reason_unknown_is_forwarded_rather_than_refused_locally() {
        assert_eq!(
            build_path(&queue_args(Some("bogus"))),
            "/api/v1/admin/curation/queue?reason=bogus"
        );
    }

    #[test]
    fn build_path_without_filters_has_no_query_string() {
        assert_eq!(
            build_path(&queue_args(None)),
            "/api/v1/admin/curation/queue"
        );
    }

    #[test]
    fn build_path_joins_every_filter() {
        let args = QueueArgs {
            repository: Some("npm main".into()),
            status: Some("rejected".into()),
            reason: Some("corruption".into()),
            limit: Some(42),
        };
        assert_eq!(
            build_path(&args),
            "/api/v1/admin/curation/queue?repository=npm%20main&status=rejected\
             &reason=corruption&limit=42"
        );
    }

    #[test]
    fn urlencoded_passes_through_basic() {
        assert_eq!(urlencoded("npm-main"), "npm-main");
        assert_eq!(urlencoded("CVE-2026-0001"), "CVE-2026-0001");
    }

    #[test]
    fn urlencoded_encodes_specials() {
        assert_eq!(urlencoded("a b"), "a%20b");
        assert_eq!(urlencoded("k=v"), "k%3Dv");
    }

    fn sample_entry() -> CurationQueueEntryDto {
        CurationQueueEntryDto {
            artifact_id: "11111111-1111-1111-1111-111111111111".into(),
            repository_id: "22222222-2222-2222-2222-222222222222".into(),
            repository_key: "npm-main".into(),
            format: "npm".into(),
            package_name: "evil-pkg".into(),
            version: Some("1.0.0".into()),
            quarantine_status: "quarantined".into(),
            quarantine_window_start: None,
            quarantine_deadline: None,
            finding_count: 3,
            max_severity: Some("high".into()),
            rejection_reason_kind: None,
        }
    }

    #[test]
    fn render_table_emits_header_and_row() {
        let rows = vec![sample_entry()];
        let mut buf = Vec::new();
        render_table(&rows, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("ARTIFACT_ID"));
        assert!(out.contains("REJECT_REASON"));
        assert!(out.contains("npm-main"));
        assert!(out.contains("evil-pkg"));
        assert!(out.contains("high"));
        assert!(!out.contains("No curation queue entries"));
    }

    #[test]
    fn render_table_empty_emits_header_and_message() {
        let mut buf = Vec::new();
        render_table(&[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Header still present.
        assert!(out.contains("ARTIFACT_ID"));
        // Plus the empty-result message.
        assert!(out.contains("No curation queue entries"));
    }

    #[test]
    fn render_table_renders_rejection_reason_kind_when_present() {
        let mut e = sample_entry();
        e.quarantine_status = "rejected".into();
        e.rejection_reason_kind = Some("curator".into());
        let mut buf = Vec::new();
        render_table(&[e], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("rejected"));
        assert!(out.contains("curator"));
    }

    #[test]
    fn render_table_dashes_for_missing_optional_fields() {
        let mut e = sample_entry();
        e.version = None;
        e.max_severity = None;
        e.rejection_reason_kind = None;
        let mut buf = Vec::new();
        render_table(&[e], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // At least three '-' columns (version, severity, reject_reason).
        assert!(out.matches(" -").count() >= 3, "dashes in output: {out}");
    }
}
