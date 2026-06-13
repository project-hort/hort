//! `hort-cli curation exclusions` — GET `/api/v1/admin/curation/exclusions`.
//!
//! Wire contract: `GET /api/v1/admin/curation/exclusions`
//! (`hort-http-core::handlers::admin::curation::exclusions`).
//! Paginated current-state listing of active CVE exclusions. Distinct
//! from `decisions` because exclusions have **ongoing state** (active
//! until removed or expired); decisions are point-in-time.
//!
//! # Query parameters
//!
//! - `--policy <uuid>` → `?policy=`. No CLI-side UUID validation; the
//!   server is the canonical validator (mirrors the
//!   `list_patch_candidates.rs` precedent).
//! - `--cve <id>` → `?cve=`. Pass-through; server forwards to the use
//!   case verbatim.
//! - `--actor <uuid>` → `?actor=`. Same pass-through.
//! - `--limit <n>` → `?limit=`. Server caps at 500.
//!
//! # Output
//!
//! `--output json` (pass-through): the server's
//! `CurationExclusionsResponseDto` pretty-printed verbatim. The `scope`
//! field is already a tagged-union JSON object (`{"kind":"global"}` or
//! `{"kind":"repository","repository_id":"<uuid>"}`); CLI passes it
//! through unchanged.
//!
//! `--output table` (default): columns `EXCLUSION_ID  POLICY  CVE
//! PACKAGE_PATTERN  ACTOR  SCOPE  ADDED_AT  EXPIRES_AT  REASON`.
//! `SCOPE` renders as `global` or `repo:<uuid>` for at-a-glance
//! readability (the tagged-union JSON shape is too noisy for table
//! mode). Empty result prints header + `No exclusions`.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::curation::exclusions)
// ---------------------------------------------------------------------------

/// Wire-format row.
///
/// **Sync-required**: mirrors `CurationExclusionEntryDto` in
/// `hort-http-core::handlers::admin::curation::exclusions`. The `scope`
/// field is a tagged-union JSON value (`{"kind":"global"}` or
/// `{"kind":"repository","repository_id":"<uuid>"}`); the CLI does
/// NOT model it as a Rust enum — `serde_json::Value` passes the shape
/// through unchanged, and table-mode formatting reads the `kind` tag
/// directly. This avoids a third-party `untagged` enum that would
/// silently swallow unknown future arms.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CurationExclusionEntryDto {
    pub exclusion_id: Uuid,
    pub policy_id: Uuid,
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_by_actor_id: Option<Uuid>,
    pub reason: String,
    pub scope: serde_json::Value,
    pub added_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response envelope.
///
/// **Sync-required**: mirrors `CurationExclusionsResponseDto`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CurationExclusionsResponseDto {
    pub entries: Vec<CurationExclusionEntryDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation exclusions`.
#[derive(clap::Args, Debug)]
pub struct ExclusionsArgs {
    /// Filter by scan policy UUID. Server validates the UUID shape.
    #[arg(long)]
    pub policy: Option<String>,

    /// Filter by CVE identifier (e.g. `CVE-2026-0001`, `GHSA-xxxx-yyyy-zzzz`).
    #[arg(long)]
    pub cve: Option<String>,

    /// Filter by actor user_id (UUID).
    #[arg(long)]
    pub actor: Option<String>,

    /// Maximum rows to return (server caps at 500).
    #[arg(long)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: ExclusionsArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: ExclusionsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Build query string.
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref p) = args.policy {
        parts.push(format!("policy={}", urlencoded(p)));
    }
    if let Some(ref c) = args.cve {
        parts.push(format!("cve={}", urlencoded(c)));
    }
    if let Some(ref a) = args.actor {
        parts.push(format!("actor={}", urlencoded(a)));
    }
    if let Some(l) = args.limit {
        parts.push(format!("limit={l}"));
    }
    let path = if parts.is_empty() {
        "/api/v1/admin/curation/exclusions".to_string()
    } else {
        format!("/api/v1/admin/curation/exclusions?{}", parts.join("&"))
    };

    let resp: CurationExclusionsResponseDto = client.get(&path).await?;

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

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the exclusions listing as an aligned table.
fn render_table(rows: &[CurationExclusionEntryDto], out: &mut impl Write) -> std::io::Result<()> {
    let headers = &[
        "EXCLUSION_ID",
        "POLICY",
        "CVE",
        "PACKAGE_PATTERN",
        "ACTOR",
        "SCOPE",
        "ADDED_AT",
        "EXPIRES_AT",
        "REASON",
    ];
    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|e| {
            vec![
                e.exclusion_id.to_string(),
                e.policy_id.to_string(),
                e.cve_id.clone(),
                e.package_pattern.clone().unwrap_or_else(|| "-".to_string()),
                e.added_by_actor_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                render_scope(&e.scope),
                e.added_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                e.expires_at
                    .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".to_string()),
                truncate_for_table(&e.reason),
            ]
        })
        .collect();
    write!(out, "{}", format_table_rows(headers, &data))?;
    if rows.is_empty() {
        writeln!(out, "No exclusions")?;
    }
    Ok(())
}

/// Render the tagged-union `scope` for the table.
///
/// `{"kind":"global"}` → `"global"`.
/// `{"kind":"repository","repository_id":"<uuid>"}` → `"repo:<uuid>"`.
/// Anything else (forward-compatibility — a future arm the CLI does
/// not know) renders as the JSON `kind` string verbatim (or `?` if
/// even that is missing).
fn render_scope(scope: &serde_json::Value) -> String {
    let kind = scope.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
    match kind {
        "global" => "global".to_string(),
        "repository" => {
            let id = scope
                .get("repository_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("repo:{id}")
        }
        other => other.to_string(),
    }
}

/// Reasons can be up to 512 bytes; truncate for table view (JSON keeps
/// full text). Mirrors `decisions.rs::truncate_for_table` — kept
/// per-file so the two callers can diverge as their column budgets do.
fn truncate_for_table(s: &str) -> String {
    const MAX: usize = 60;
    if s.len() <= MAX {
        s.to_string()
    } else {
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
    use serde_json::json;

    fn sample_entry() -> CurationExclusionEntryDto {
        CurationExclusionEntryDto {
            exclusion_id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            cve_id: "CVE-2026-1234".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            added_by_actor_id: Some(Uuid::new_v4()),
            reason: "false positive in container layer".into(),
            scope: json!({ "kind": "global" }),
            added_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn render_scope_global() {
        assert_eq!(render_scope(&json!({ "kind": "global" })), "global");
    }

    #[test]
    fn render_scope_repository() {
        let id = "11111111-1111-1111-1111-111111111111";
        let s = render_scope(&json!({ "kind": "repository", "repository_id": id }));
        assert_eq!(s, format!("repo:{id}"));
    }

    #[test]
    fn render_scope_repository_missing_id() {
        // Forward-compat: server bug or schema drift → render `?` rather
        // than panic.
        let s = render_scope(&json!({ "kind": "repository" }));
        assert_eq!(s, "repo:?");
    }

    #[test]
    fn render_scope_unknown_kind_forward_compatible() {
        // A future arm the CLI does not know — render the kind verbatim
        // so operators see the wire shape rather than a crash.
        let s = render_scope(&json!({ "kind": "future-arm" }));
        assert_eq!(s, "future-arm");
    }

    #[test]
    fn render_scope_no_kind() {
        let s = render_scope(&json!({}));
        assert_eq!(s, "?");
    }

    #[test]
    fn render_table_emits_header_and_row() {
        let mut buf = Vec::new();
        render_table(&[sample_entry()], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("EXCLUSION_ID"));
        assert!(out.contains("CVE-2026-1234"));
        assert!(out.contains("global"));
        assert!(out.contains("xz-utils@<5.6.2"));
        assert!(!out.contains("No exclusions"));
    }

    #[test]
    fn render_table_empty_emits_header_and_message() {
        let mut buf = Vec::new();
        render_table(&[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("EXCLUSION_ID"));
        assert!(out.contains("No exclusions"));
    }

    #[test]
    fn render_table_repository_scope_renders_repo_prefix() {
        let mut e = sample_entry();
        let rid = "22222222-2222-2222-2222-222222222222";
        e.scope = json!({ "kind": "repository", "repository_id": rid });
        let mut buf = Vec::new();
        render_table(&[e], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains(&format!("repo:{rid}")));
    }

    #[test]
    fn render_table_missing_optionals_show_dashes() {
        let mut e = sample_entry();
        e.package_pattern = None;
        e.added_by_actor_id = None;
        e.expires_at = None;
        let mut buf = Vec::new();
        render_table(&[e], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Three '-' columns minimum.
        assert!(out.matches(" -").count() >= 3, "dashes in row: {out}");
    }

    #[test]
    fn truncate_for_table_long_gets_ellipsis() {
        let long = "z".repeat(120);
        let t = truncate_for_table(&long);
        assert!(t.ends_with("..."));
        assert!(t.len() <= 60);
    }

    #[test]
    fn truncate_for_table_short_unchanged() {
        assert_eq!(truncate_for_table("ok"), "ok");
    }

    #[test]
    fn urlencoded_passes_through_basic() {
        assert_eq!(urlencoded("CVE-2026-0001"), "CVE-2026-0001");
    }

    #[test]
    fn urlencoded_encodes_specials() {
        assert_eq!(urlencoded("a@b"), "a%40b");
    }
}
