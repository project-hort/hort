//! `hort-cli admin quarantine list-patch-candidates`.
//!
//! Wire contract: GET `/api/v1/admin/quarantine/patch-candidates`
//! (`hort-http-core::handlers::admin`). The CLI mirrors the response DTO
//! verbatim and renders a table or pretty-printed JSON.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::PatchCandidate{Dto,ResponseDto})
// ---------------------------------------------------------------------------

/// One row of the patch-candidate listing.
///
/// **Sync-required**: mirrors `PatchCandidateDto` in
/// `hort-http-core::handlers::admin`. Field names form the wire contract;
/// any rename on the server side must land here in the same PR. Enum
/// fields (`quarantined_status`, `format`, `vulnerable_max_severity`)
/// are projected as the server's `Display` strings — the CLI does not
/// re-parse them.
///
/// Field `quarantined_until` mirrors the server-side projection of the
/// quarantined artifact's `quarantine_window_start` column (the
/// observation-window anchor); the `quarantined_` prefix groups it with
/// the other quarantined-side fields (parallel to the `vulnerable_*`
/// cluster) without restating the column name.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PatchCandidateRowDto {
    pub quarantined_artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_version: Option<String>,
    pub quarantined_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_until: Option<DateTime<Utc>>,
    pub repository_id: String,
    pub repository_key: String,
    pub format: String,
    pub package_name: String,
    pub vulnerable_artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerable_version: Option<String>,
    pub vulnerable_finding_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerable_max_severity: Option<String>,
}

/// Response envelope from `GET /admin/quarantine/patch-candidates`.
///
/// **Sync-required**: mirrors `PatchCandidateResponseDto` in
/// `hort-http-core::handlers::admin`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct PatchCandidateListResponseDto {
    pub candidates: Vec<PatchCandidateRowDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin quarantine list-patch-candidates`.
///
/// `--repo` is a free-form **repository key** (e.g. `npm-proxy`) —
/// the server-side handler resolves it through
/// `RepositoryRepository::find_by_key` and returns 404
/// with `{"error":"repository_not_found","key":...}` for unknown
/// keys. The CLI does NOT pre-validate so the wire-level error is
/// the canonical message operators see (one error path, not two);
/// the value is passed through verbatim, URL-encoded only for
/// transport-safety.
#[derive(clap::Args, Debug)]
pub struct ListPatchCandidatesArgs {
    /// Filter by repository key (e.g. `npm-proxy`). When absent:
    /// admin-wide scope. Unknown keys return 404.
    #[arg(long = "repo", add = crate::completions::repo_arg_candidates())]
    pub repository: Option<String>,

    /// Maximum rows to return (server caps at 500 — 400 on overflow).
    #[arg(long)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(
    client: AkClient,
    args: ListPatchCandidatesArgs,
    output: OutputFormat,
) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl so integration
/// tests can capture output into a `Vec<u8>` buffer.
pub async fn run_with_output(
    client: AkClient,
    args: ListPatchCandidatesArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Build the path with query parameters. Mirror `task_list.rs:74-93`
    // — manual assembly keeps the CLI dep set minimal (no `url` query
    // builder dance, no `urlencoding` crate).
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref r) = args.repository {
        parts.push(format!("repository={}", urlencoded(r)));
    }
    if let Some(l) = args.limit {
        parts.push(format!("limit={l}"));
    }
    let path = if parts.is_empty() {
        "/api/v1/admin/quarantine/patch-candidates".to_string()
    } else {
        format!(
            "/api/v1/admin/quarantine/patch-candidates?{}",
            parts.join("&")
        )
    };

    let resp: PatchCandidateListResponseDto = client.get(&path).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            if resp.candidates.is_empty() {
                writeln!(out, "No patch candidates")?;
            } else {
                let table = render_table(&resp.candidates, Utc::now());
                write!(out, "{table}")?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the candidate listing as an aligned table.
///
/// Columns:
/// `PACKAGE  FORMAT  VULN_VERSION → QUARANTINED  SEVERITY  FINDINGS  QUARANTINE_UNTIL`.
/// `QUARANTINE_UNTIL` is rendered as a relative duration (`in 6h 14m`)
/// against `now` so the operator sees "how long until auto-evaluation"
/// rather than a wall-clock timestamp.
fn render_table(rows: &[PatchCandidateRowDto], now: DateTime<Utc>) -> String {
    let headers = &[
        "PACKAGE",
        "FORMAT",
        "VERSION_TRANSITION",
        "SEVERITY",
        "FINDINGS",
        "QUARANTINE_UNTIL",
    ];

    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let vuln = r.vulnerable_version.as_deref().unwrap_or("?");
            let quar = r.quarantined_version.as_deref().unwrap_or("?");
            let transition = format!("{vuln} -> {quar}");
            let severity = r
                .vulnerable_max_severity
                .as_deref()
                .unwrap_or("-")
                .to_string();
            let findings = r.vulnerable_finding_count.to_string();
            let until = match r.quarantined_until {
                Some(ts) => format_relative_until(now, ts),
                None => "-".to_string(),
            };
            vec![
                r.package_name.clone(),
                r.format.clone(),
                transition,
                severity,
                findings,
                until,
            ]
        })
        .collect();

    format_table_rows(headers, &data)
}

/// Render `until - now` as `in <h>h <m>m`, or `<h>h <m>m ago` if the
/// timer has already elapsed (the row is past-due — usually means a
/// sweep is pending). Sub-hour ranges drop the hour segment; sub-minute
/// ranges read `< 1m`.
///
/// Implemented inline so the CLI keeps its dep set tight (no
/// `humantime`, which would add a dep purely for this two-segment
/// formatter).
fn format_relative_until(now: DateTime<Utc>, until: DateTime<Utc>) -> String {
    let delta = until.signed_duration_since(now);
    let past = delta < chrono::Duration::zero();
    let secs = delta.num_seconds().abs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;

    let core = if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        "< 1m".to_string()
    };

    if past {
        format!("{core} ago")
    } else {
        format!("in {core}")
    }
}

/// Percent-encode a query-string value (RFC 3986 unreserved set
/// passes through; everything else → `%HH`). Inlined rather than
/// shared with `task_list.rs` so the two callers can diverge as their
/// validation rules evolve.
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

    fn make_row(pkg: &str, vuln: Option<&str>, quar: Option<&str>) -> PatchCandidateRowDto {
        PatchCandidateRowDto {
            quarantined_artifact_id: "11111111-1111-1111-1111-111111111111".into(),
            quarantined_version: quar.map(str::to_string),
            quarantined_status: "quarantined".into(),
            quarantined_until: None,
            repository_id: "22222222-2222-2222-2222-222222222222".into(),
            repository_key: "npm-main".into(),
            format: "npm".into(),
            package_name: pkg.into(),
            vulnerable_artifact_id: "33333333-3333-3333-3333-333333333333".into(),
            vulnerable_version: vuln.map(str::to_string),
            vulnerable_finding_count: 3,
            vulnerable_max_severity: Some("high".into()),
        }
    }

    #[test]
    fn render_table_includes_headers_and_transition() {
        let rows = vec![make_row("lodash", Some("4.17.20"), Some("4.17.21"))];
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let out = render_table(&rows, now);
        assert!(out.contains("PACKAGE"));
        assert!(out.contains("FORMAT"));
        assert!(out.contains("VERSION_TRANSITION"));
        assert!(out.contains("SEVERITY"));
        assert!(out.contains("lodash"));
        assert!(out.contains("4.17.20 -> 4.17.21"));
        assert!(out.contains("high"));
    }

    #[test]
    fn render_table_renders_dash_for_missing_versions() {
        let rows = vec![make_row("ghost", None, None)];
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let out = render_table(&rows, now);
        assert!(out.contains("? -> ?"));
    }

    #[test]
    fn format_relative_until_future_renders_in_prefix() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let future = now + chrono::Duration::hours(6) + chrono::Duration::minutes(14);
        assert_eq!(format_relative_until(now, future), "in 6h 14m");
    }

    #[test]
    fn format_relative_until_past_renders_ago_suffix() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let past = now - chrono::Duration::hours(2);
        assert_eq!(format_relative_until(now, past), "2h 0m ago");
    }

    #[test]
    fn format_relative_until_sub_hour_drops_hours() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let future = now + chrono::Duration::minutes(30);
        assert_eq!(format_relative_until(now, future), "in 30m");
    }

    #[test]
    fn format_relative_until_sub_minute_renders_lt_one_min() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let future = now + chrono::Duration::seconds(30);
        assert_eq!(format_relative_until(now, future), "in < 1m");
    }

    #[test]
    fn urlencoded_passes_through_uuid() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        assert_eq!(urlencoded(uuid), uuid);
    }

    #[test]
    fn urlencoded_encodes_specials() {
        assert_eq!(urlencoded("a=b"), "a%3Db");
        assert_eq!(urlencoded(" "), "%20");
    }
}
