//! `hort-cli curation decisions` — GET `/api/v1/admin/curation/decisions`.
//!
//! Wire contract: `GET /api/v1/admin/curation/decisions`
//! (`hort-http-core::handlers::admin::curation::decisions`).
//! Paginated event-log scan of curator decisions. Default is uncollapsed
//! (one row per event); `--by-correlation` is an opt-in flag that
//! collapses bulk operations into the curator's intent (one row per
//! shared `correlation_id`).
//!
//! **The rollup is performed SERVER-SIDE.** The CLI passes
//! `?by_correlation=true` and renders whichever populated field
//! (`events` xor `groups`) the response carries.
//!
//! # Query parameters
//!
//! - `--type <waive|block|exclude_finding|unexclude_finding>` → `?type=`.
//!   Closed-set validation client-side.
//! - `--actor <uuid>` → `?actor=`. No UUID validation client-side; the
//!   server's `Uuid::from_str` is the canonical validator (mirror
//!   `list_patch_candidates.rs:71-80` precedent).
//! - `--repo <key>` → `?repository=`. Server resolves key → UUID;
//!   unknown → 404.
//! - `--package <name>` → `?package=`. Substring / exact-match
//!   semantics applied server-side.
//! - `--since <iso-8601>` → `?since=`. CLIENT-side parse for fail-fast
//!   (operator gets a clear error before the round-trip); server
//!   re-validates.
//! - `--limit <n>` → `?limit=`. Server caps at 500.
//! - `--by-correlation` → `?by_correlation=true`. When set, the server
//!   collapses correlated events into one group per `correlation_id`.
//!
//! # Output
//!
//! `--output json` (pass-through): the server's
//! `CurationDecisionsResponseDto` pretty-printed verbatim — same
//! tagged shape as the wire, so operator tooling can read either arm
//! by inspecting `by_correlation`.
//!
//! `--output table` (default): when `by_correlation=false`, columns
//! `EVENT_ID  KIND  ACTOR  ARTIFACT  POLICY  CVE  CORRELATION
//! OCCURRED_AT  JUSTIFICATION`. When `by_correlation=true`, columns
//! `CORRELATION  KIND  ACTOR  EVENT_COUNT  FIRST_OCCURRED  LAST_OCCURRED
//! JUSTIFICATION`. Empty result prints header + a `No curation
//! decisions` line.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Closed-set client-side validation
// ---------------------------------------------------------------------------

/// Accepted values for `--type`. Mirrors the server's
/// `parse_kind` in `hort-http-core::handlers::admin::curation::decisions`.
const ACCEPTED_TYPES: &[&str] = &["waive", "block", "exclude_finding", "unexclude_finding"];

fn validate_type(t: &str) -> Result<()> {
    if ACCEPTED_TYPES.contains(&t) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "invalid --type {t:?} (valid: {})",
            ACCEPTED_TYPES.join(" | "),
        ))
    }
}

/// Parse `--since` as RFC 3339 / ISO-8601. Returns the canonical string
/// (RFC 3339 with offset) — sending the canonical form on the wire
/// rather than the operator's raw input keeps server-side parsing
/// trivial and the audit log readable.
///
/// CLIENT-side parsing is fail-fast — burning a 400 on a typo
/// (`2026-05-32`) is wasteful when chrono can reject it in microseconds.
/// The server still re-validates (defence in depth).
fn parse_since(s: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(s).map_err(|e| {
        anyhow::anyhow!("invalid --since {s:?}: {e} (expected RFC 3339 / ISO-8601)")
    })?;
    Ok(parsed.to_rfc3339())
}

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::curation::decisions)
// ---------------------------------------------------------------------------

/// Wire-format per-event row.
///
/// **Sync-required**: mirrors `CurationDecisionRowDto` in
/// `hort-http-core::handlers::admin::curation::decisions`. `kind` is
/// already the wire-stable lowercase string (`waive`, `block`,
/// `exclude_finding`, `unexclude_finding`) on the server side.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CurationDecisionRowDto {
    pub event_id: Uuid,
    pub kind: String,
    pub actor_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub justification: String,
    pub correlation_id: Uuid,
    pub occurred_at: DateTime<Utc>,
}

/// Wire-format per-correlation-group rollup row.
///
/// **Sync-required**: mirrors `CurationDecisionGroupDto` in
/// `hort-http-core::handlers::admin::curation::decisions`. The server
/// constructs groups via the documented BTreeMap-by-correlation_id
/// rollup — the CLI just renders.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CurationDecisionGroupDto {
    pub correlation_id: Uuid,
    pub kind: String,
    pub actor_id: Uuid,
    pub event_count: u32,
    pub first_occurred_at: DateTime<Utc>,
    pub last_occurred_at: DateTime<Utc>,
    pub justification: String,
}

/// Response envelope.
///
/// **Sync-required**: mirrors `CurationDecisionsResponseDto`. The
/// `by_correlation` discriminator tags which of `events` / `groups` is
/// populated. The server's contract is "only one populated per
/// response"; the CLI renders based on the flag, NOT field emptiness
/// (an empty events list with `by_correlation=false` is the empty-result
/// case, NOT a request to render groups).
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CurationDecisionsResponseDto {
    pub by_correlation: bool,
    pub events: Vec<CurationDecisionRowDto>,
    pub groups: Vec<CurationDecisionGroupDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation decisions`.
#[derive(clap::Args, Debug)]
pub struct DecisionsArgs {
    /// Filter by decision kind. Valid: `waive`, `block`,
    /// `exclude_finding`, `unexclude_finding`. Validated client-side.
    #[arg(long = "type")]
    pub type_: Option<String>,

    /// Filter by actor user_id (UUID). No client-side UUID validation —
    /// the server re-validates.
    #[arg(long)]
    pub actor: Option<String>,

    /// Filter by repository stable key (e.g. `npm-proxy`). Unknown key
    /// → 404 from the server.
    #[arg(long = "repo", add = crate::completions::repo_arg_candidates())]
    pub repository: Option<String>,

    /// Filter by package name substring (server-side semantics).
    #[arg(long)]
    pub package: Option<String>,

    /// Filter by `occurred_at >= <iso-8601>`. RFC 3339 / ISO-8601
    /// validated client-side for fail-fast (server re-validates).
    #[arg(long)]
    pub since: Option<String>,

    /// Maximum rows to return (server caps at 500).
    #[arg(long)]
    pub limit: Option<u32>,

    /// Collapse correlated events into one row per `correlation_id`
    /// (server-side rollup). When set, the response carries `groups`
    /// instead of `events`.
    #[arg(long = "by-correlation")]
    pub by_correlation: bool,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: DecisionsArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: DecisionsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — closed-set client-side validation (fail-fast).
    if let Some(ref t) = args.type_ {
        validate_type(t)?;
    }
    let since_canonical = match args.since {
        Some(ref s) => Some(parse_since(s)?),
        None => None,
    };

    // Step 2 — build query string.
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref t) = args.type_ {
        parts.push(format!("type={}", urlencoded(t)));
    }
    if let Some(ref a) = args.actor {
        parts.push(format!("actor={}", urlencoded(a)));
    }
    if let Some(ref r) = args.repository {
        parts.push(format!("repository={}", urlencoded(r)));
    }
    if let Some(ref p) = args.package {
        parts.push(format!("package={}", urlencoded(p)));
    }
    if let Some(ref s) = since_canonical {
        parts.push(format!("since={}", urlencoded(s)));
    }
    if let Some(l) = args.limit {
        parts.push(format!("limit={l}"));
    }
    if args.by_correlation {
        parts.push("by_correlation=true".to_string());
    }
    let path = if parts.is_empty() {
        "/api/v1/admin/curation/decisions".to_string()
    } else {
        format!("/api/v1/admin/curation/decisions?{}", parts.join("&"))
    };

    let resp: CurationDecisionsResponseDto = client.get(&path).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            // The tagged `by_correlation` flag is the canonical
            // discriminator (NOT field-emptiness): an empty events list
            // with `by_correlation=false` is the empty-result case, not
            // a request to render the groups list.
            if resp.by_correlation {
                render_groups_table(&resp.groups, out)?;
            } else {
                render_events_table(&resp.events, out)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the events list (uncollapsed, default). Always emits the
/// header; appends `No curation decisions` when empty.
fn render_events_table(
    rows: &[CurationDecisionRowDto],
    out: &mut impl Write,
) -> std::io::Result<()> {
    let headers = &[
        "EVENT_ID",
        "KIND",
        "ACTOR",
        "ARTIFACT",
        "POLICY",
        "CVE",
        "CORRELATION",
        "OCCURRED_AT",
        "JUSTIFICATION",
    ];
    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.event_id.to_string(),
                r.kind.clone(),
                r.actor_id.to_string(),
                r.artifact_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.policy_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.cve_id.clone().unwrap_or_else(|| "-".to_string()),
                r.correlation_id.to_string(),
                r.occurred_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                truncate_for_table(&r.justification),
            ]
        })
        .collect();
    write!(out, "{}", format_table_rows(headers, &data))?;
    if rows.is_empty() {
        writeln!(out, "No curation decisions")?;
    }
    Ok(())
}

/// Render the groups list (server-side collapsed). Always emits the
/// header; appends `No curation decisions` when empty.
fn render_groups_table(
    rows: &[CurationDecisionGroupDto],
    out: &mut impl Write,
) -> std::io::Result<()> {
    let headers = &[
        "CORRELATION",
        "KIND",
        "ACTOR",
        "EVENT_COUNT",
        "FIRST_OCCURRED",
        "LAST_OCCURRED",
        "JUSTIFICATION",
    ];
    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|g| {
            vec![
                g.correlation_id.to_string(),
                g.kind.clone(),
                g.actor_id.to_string(),
                g.event_count.to_string(),
                g.first_occurred_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                g.last_occurred_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                truncate_for_table(&g.justification),
            ]
        })
        .collect();
    write!(out, "{}", format_table_rows(headers, &data))?;
    if rows.is_empty() {
        writeln!(out, "No curation decisions")?;
    }
    Ok(())
}

/// Justifications can be up to 512 bytes. Long
/// justifications wreck table column alignment. Truncate to 60 chars
/// with an ellipsis for the table view; JSON output carries the full
/// text.
fn truncate_for_table(s: &str) -> String {
    const MAX: usize = 60;
    if s.len() <= MAX {
        s.to_string()
    } else {
        // Find a char boundary at or before MAX-3 so we don't split a
        // multibyte char.
        let mut cut = MAX.saturating_sub(3);
        while !s.is_char_boundary(cut) && cut > 0 {
            cut -= 1;
        }
        format!("{}...", &s[..cut])
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode a query-string value.
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
    fn validate_type_accepts_closed_set() {
        for t in ACCEPTED_TYPES {
            assert!(validate_type(t).is_ok());
        }
    }

    #[test]
    fn validate_type_rejects_unknown() {
        let err = validate_type("bogus").unwrap_err().to_string();
        assert!(err.contains("valid:"));
        assert!(err.contains("waive"));
    }

    #[test]
    fn parse_since_accepts_rfc3339() {
        let s = parse_since("2026-05-01T00:00:00Z").unwrap();
        // Canonical form parseable by chrono.
        assert!(DateTime::parse_from_rfc3339(&s).is_ok());
    }

    #[test]
    fn parse_since_accepts_offset() {
        // RFC 3339 with offset — chrono accepts.
        let s = parse_since("2026-05-01T12:00:00+02:00").unwrap();
        assert!(DateTime::parse_from_rfc3339(&s).is_ok());
    }

    #[test]
    fn parse_since_rejects_garbage() {
        let err = parse_since("not-a-timestamp").unwrap_err().to_string();
        assert!(err.contains("invalid --since"));
    }

    #[test]
    fn parse_since_rejects_date_only() {
        // chrono's RFC 3339 parser requires time + offset.
        let err = parse_since("2026-05-01").unwrap_err().to_string();
        assert!(err.contains("invalid --since"));
    }

    #[test]
    fn urlencoded_passes_through_basic() {
        assert_eq!(urlencoded("npm-main"), "npm-main");
    }

    #[test]
    fn truncate_for_table_short_unchanged() {
        assert_eq!(truncate_for_table("short text"), "short text");
    }

    #[test]
    fn truncate_for_table_long_gets_ellipsis() {
        let long = "a".repeat(100);
        let t = truncate_for_table(&long);
        assert!(t.ends_with("..."));
        assert!(t.len() <= 60);
    }

    #[test]
    fn truncate_for_table_multibyte_safe() {
        // Mostly-ASCII with a single multibyte char near the boundary —
        // truncation must not split it.
        let s = format!("{}{}", "a".repeat(58), "é"); // 58 + 2 bytes = 60
        let t = truncate_for_table(&s);
        // Must be valid UTF-8 (this is a tautology since `t` is a
        // String, but the truncation path itself slices bytes — the
        // is_char_boundary loop is what we're really pinning here).
        let _: &str = &t;
    }

    fn sample_event() -> CurationDecisionRowDto {
        CurationDecisionRowDto {
            event_id: Uuid::new_v4(),
            kind: "waive".into(),
            actor_id: Uuid::new_v4(),
            artifact_id: Some(Uuid::new_v4()),
            policy_id: None,
            cve_id: None,
            justification: "shared justification".into(),
            correlation_id: Uuid::new_v4(),
            occurred_at: Utc::now(),
        }
    }

    fn sample_group() -> CurationDecisionGroupDto {
        CurationDecisionGroupDto {
            correlation_id: Uuid::new_v4(),
            kind: "block".into(),
            actor_id: Uuid::new_v4(),
            event_count: 3,
            first_occurred_at: Utc::now(),
            last_occurred_at: Utc::now(),
            justification: "bulk-block justification".into(),
        }
    }

    #[test]
    fn render_events_table_emits_header_and_row() {
        let mut buf = Vec::new();
        render_events_table(&[sample_event()], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("EVENT_ID"));
        assert!(out.contains("JUSTIFICATION"));
        assert!(out.contains("waive"));
        assert!(out.contains("shared justification"));
        assert!(!out.contains("No curation decisions"));
    }

    #[test]
    fn render_events_table_empty_emits_header_and_message() {
        let mut buf = Vec::new();
        render_events_table(&[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("EVENT_ID"));
        assert!(out.contains("No curation decisions"));
    }

    #[test]
    fn render_groups_table_emits_header_and_row() {
        let mut buf = Vec::new();
        render_groups_table(&[sample_group()], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("EVENT_COUNT"));
        assert!(out.contains("FIRST_OCCURRED"));
        assert!(out.contains("block"));
        assert!(out.contains("3"));
        assert!(!out.contains("No curation decisions"));
    }

    #[test]
    fn render_groups_table_empty_emits_header_and_message() {
        let mut buf = Vec::new();
        render_groups_table(&[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("CORRELATION"));
        assert!(out.contains("No curation decisions"));
    }
}
