//! `hort-cli admin rbac resolve --group <g> [--group <g>...]` — POST `/api/v1/admin/rbac/resolve`.
//!
//! Wire contract: `POST /api/v1/admin/rbac/resolve`
//! (`hort-http-core::handlers::admin`). The admin supplies the user's IdP
//! groups (from their own IdP / user-management); HORT resolves the
//! `groups → claims → effective (repo, permission) grants` half it owns
//! (no IdP query, no cache). The CLI mirrors the request + response DTOs
//! verbatim and renders a table or pretty-printed JSON.
//!
//! This is the claim-based-authority companion to
//! `hort-cli admin users effective-permissions`: the per-user surface cannot
//! resolve a user's claims without that user's session, so the admin feeds
//! the groups in here for the what-if view
//! (see `docs/architecture/how-to/operate/claim-based-rbac.md`).

use std::io::Write;

use anyhow::Result;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin Rbac* DTOs)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/rbac/resolve`.
///
/// **Sync-required**: mirrors `RbacResolveRequest` in
/// `hort-http-core::handlers::admin`. The JSON field name (`groups`) is the
/// contract.
#[derive(Debug, serde::Serialize)]
struct RbacResolveRequestBody {
    groups: Vec<String>,
}

/// One resolved effective grant.
///
/// **Sync-required**: mirrors `ResolvedGrantDto` in
/// `hort-http-core::handlers::admin`. `repository = null` ⇒ global grant.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ResolvedGrantDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub permission: String,
}

/// Response envelope from `POST /admin/rbac/resolve`.
///
/// **Sync-required**: mirrors `RbacResolveResponseDto` in
/// `hort-http-core::handlers::admin`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RbacResolveResponseDto {
    pub resolved_claims: Vec<String>,
    pub effective_grants: Vec<ResolvedGrantDto>,
    pub global_admin: bool,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin rbac resolve`.
///
/// `--group` is repeatable (`--group a --group b`) and required at least
/// once. An empty group set is a valid server request (resolves to the
/// empty footprint), but the CLI requires ≥1 group so an operator who
/// forgot to pass any gets a fast clap error rather than a silently-empty
/// resolution.
#[derive(clap::Args, Debug)]
pub struct ResolveArgs {
    /// An IdP group to resolve. Repeat for multiple groups
    /// (`--group developers --group team-alpha`).
    #[arg(long = "group", required = true)]
    pub group: Vec<String>,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: ResolveArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: ResolveArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let body = RbacResolveRequestBody { groups: args.group };
    let resp: RbacResolveResponseDto = client.post("/api/v1/admin/rbac/resolve", &body).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            render_table_block(&resp, out)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the full table-format block (header + grant table) for a
/// resolution response. Extracted from the `Table` arm so it is
/// unit-testable without an HTTP client.
fn render_table_block(resp: &RbacResolveResponseDto, out: &mut impl Write) -> std::io::Result<()> {
    let claims = if resp.resolved_claims.is_empty() {
        "(none)".to_string()
    } else {
        resp.resolved_claims.join(", ")
    };
    writeln!(
        out,
        "global_admin:     {}\n\
         resolved_claims:  {}",
        resp.global_admin, claims,
    )?;

    if resp.global_admin {
        // The marker stands in for the full authority — there is no cell
        // No cell enumeration to render when global_admin is set —
        // the global-admin marker stands in for the full authority.
        writeln!(
            out,
            "\nGlobal admin — holds every permission on every repository"
        )?;
    } else if resp.effective_grants.is_empty() {
        writeln!(out, "\nNo effective grants")?;
    } else {
        writeln!(out)?;
        let table = render_table(&resp.effective_grants);
        write!(out, "{table}")?;
    }
    Ok(())
}

/// Render the effective-grant listing as an aligned table:
/// `PERMISSION  REPOSITORY`. `REPOSITORY` is `*` for a global grant.
fn render_table(rows: &[ResolvedGrantDto]) -> String {
    let headers = &["PERMISSION", "REPOSITORY"];
    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|g| {
            let repo = g.repository.as_deref().unwrap_or("*").to_string();
            vec![g.permission.clone(), repo]
        })
        .collect();
    format_table_rows(headers, &data)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(perm: &str, repo: Option<&str>) -> ResolvedGrantDto {
        ResolvedGrantDto {
            repository: repo.map(str::to_string),
            permission: perm.into(),
        }
    }

    #[test]
    fn render_table_headers_and_global_marker() {
        let rows = vec![grant("write", None)];
        let out = render_table(&rows);
        assert!(out.contains("PERMISSION"));
        assert!(out.contains("REPOSITORY"));
        assert!(out.contains("write"));
        assert!(out.contains('*'), "null repository renders as *");
    }

    #[test]
    fn render_table_scoped_row() {
        let rows = vec![grant("read", Some("11111111-1111-1111-1111-111111111111"))];
        let out = render_table(&rows);
        assert!(out.contains("11111111-1111-1111-1111-111111111111"));
        assert!(out.contains("read"));
    }

    #[test]
    fn table_block_renders_claims_and_grants() {
        let resp = RbacResolveResponseDto {
            resolved_claims: vec!["developer".into(), "team-alpha".into()],
            effective_grants: vec![grant("read", None)],
            global_admin: false,
        };
        let mut buf: Vec<u8> = Vec::new();
        render_table_block(&resp, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("global_admin:     false"));
        assert!(out.contains("resolved_claims:  developer, team-alpha"));
        assert!(out.contains("read"));
    }

    #[test]
    fn table_block_renders_global_admin_marker_no_cells() {
        let resp = RbacResolveResponseDto {
            resolved_claims: vec!["admin".into()],
            effective_grants: Vec::new(),
            global_admin: true,
        };
        let mut buf: Vec<u8> = Vec::new();
        render_table_block(&resp, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("global_admin:     true"));
        assert!(out.contains("Global admin"));
        assert!(
            !out.contains("PERMISSION"),
            "no cell table when global_admin — the marker stands in"
        );
    }

    #[test]
    fn table_block_renders_empty_resolution() {
        let resp = RbacResolveResponseDto {
            resolved_claims: Vec::new(),
            effective_grants: Vec::new(),
            global_admin: false,
        };
        let mut buf: Vec<u8> = Vec::new();
        render_table_block(&resp, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("resolved_claims:  (none)"));
        assert!(out.contains("No effective grants"));
    }

    #[test]
    fn response_dto_roundtrips() {
        let json = r#"{
            "resolved_claims":["developer","ci-pusher"],
            "effective_grants":[
                {"repository":null,"permission":"read"},
                {"repository":"11111111-1111-1111-1111-111111111111","permission":"write"}
            ],
            "global_admin":false
        }"#;
        let r: RbacResolveResponseDto = serde_json::from_str(json).unwrap();
        assert_eq!(r.resolved_claims, vec!["developer", "ci-pusher"]);
        assert_eq!(r.effective_grants.len(), 2);
        assert!(r.effective_grants[0].repository.is_none());
        assert_eq!(
            r.effective_grants[1].repository.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(!r.global_admin);
    }

    #[test]
    fn request_body_serializes_groups() {
        let body = RbacResolveRequestBody {
            groups: vec!["a".into(), "b".into()],
        };
        let s = serde_json::to_string(&body).unwrap();
        assert_eq!(s, r#"{"groups":["a","b"]}"#);
    }
}
