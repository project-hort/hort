//! `hort-cli admin users effective-permissions <user_id>` — GET `/api/v1/admin/users/<user_id>/effective-permissions`.
//!
//! Wire contract: GET
//! `/api/v1/admin/users/<user_id>/effective-permissions`
//! (`hort-http-core::handlers::admin`). The CLI mirrors the response DTO
//! verbatim and renders a table or pretty-printed JSON.
//!
//! This is the operator/auditor surface for what HORT knows about a user
//! *without their token* — the `is_admin` bit and the matching grant rows
//! (`User`-subject grants + synthetic-`admin`-derived grants). The user's
//! claim-based authority is **not** resolvable here (OIDC resolves claims
//! live at login), so the response carries an honest
//! `claim_based_authority` marker plus a hint pointing at the
//! `POST /api/v1/admin/rbac/resolve` what-if resolver instead of an
//! always-`[]` `claims` field. See
//! `docs/architecture/how-to/operate/claim-based-rbac.md`.

use std::io::Write;

use anyhow::Result;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::Effective* DTOs)
// ---------------------------------------------------------------------------

/// A grant's subject. `kind` is the discriminator;
/// `required` is present only for `claims`.
///
/// **Sync-required**: mirrors `GrantSourceDto` in
/// `hort-http-core::handlers::admin`. The `#[serde(tag = "kind")]`
/// adjacently-internally-tagged shape is the wire contract.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantSourceDto {
    Claims { required: Vec<String> },
    User,
}

/// One effective grant row.
///
/// **Sync-required**: mirrors `EffectiveGrantDto` in
/// `hort-http-core::handlers::admin`. `repository_id = null` ⇒ global.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EffectiveGrantDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub permission: String,
    pub source: GrantSourceDto,
}

/// Response envelope from
/// `GET /admin/users/:user_id/effective-permissions`.
///
/// **Sync-required**: mirrors `EffectivePermissionsResponseDto` in
/// `hort-http-core::handlers::admin`. The always-`[]` `claims`/`claims_source`
/// fields are gone; `claim_based_authority` + `claim_based_authority_hint`
/// take their place.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EffectivePermissionsResponseDto {
    pub user_id: String,
    pub is_admin: bool,
    pub claim_based_authority: String,
    pub claim_based_authority_hint: String,
    pub grants: Vec<EffectiveGrantDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin users effective-permissions`.
///
/// `<user_id>` is the inspected user's UUID. The CLI does NOT
/// pre-validate it so the server's 404 is the canonical error operators
/// see (one error path, not two); the value is passed through verbatim
/// in the path.
#[derive(clap::Args, Debug)]
pub struct EffectivePermissionsArgs {
    /// UUID of the user to inspect.
    pub user_id: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(
    client: AkClient,
    args: EffectivePermissionsArgs,
    output: OutputFormat,
) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: EffectivePermissionsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let path = format!(
        "/api/v1/admin/users/{}/effective-permissions",
        urlencoded(&args.user_id)
    );
    let resp: EffectivePermissionsResponseDto = client.get(&path).await?;

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

/// Render the full table-format block (header + grant table) for an
/// effective-permissions response. Extracted from the `Table` arm so it
/// is unit-testable without an HTTP client.
fn render_table_block(
    resp: &EffectivePermissionsResponseDto,
    out: &mut impl Write,
) -> std::io::Result<()> {
    writeln!(
        out,
        "user_id:                {}\n\
         is_admin:               {}\n\
         claim_based_authority:  {}",
        resp.user_id, resp.is_admin, resp.claim_based_authority,
    )?;
    writeln!(out, "  ({})", resp.claim_based_authority_hint)?;
    if resp.grants.is_empty() {
        writeln!(out, "\nNo direct grants")?;
    } else {
        writeln!(out)?;
        let table = render_table(&resp.grants);
        write!(out, "{table}")?;
    }
    Ok(())
}

/// Render the grant listing as an aligned table:
/// `PERMISSION  REPOSITORY  SOURCE`. `REPOSITORY` is `*` for a global
/// grant. `SOURCE` is `user` or `claims:[a, b]`.
fn render_table(rows: &[EffectiveGrantDto]) -> String {
    let headers = &["PERMISSION", "REPOSITORY", "SOURCE"];
    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|g| {
            let repo = g.repository_id.as_deref().unwrap_or("*").to_string();
            let source = match &g.source {
                GrantSourceDto::User => "user".to_string(),
                GrantSourceDto::Claims { required } => {
                    format!("claims:[{}]", required.join(", "))
                }
            };
            vec![g.permission.clone(), repo, source]
        })
        .collect();
    format_table_rows(headers, &data)
}

/// Percent-encode a path-segment value. Inlined (same rationale as
/// `quarantine/list_patch_candidates.rs::urlencoded`) so the CLI keeps
/// its dep set tight.
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

    fn user_grant(perm: &str, repo: Option<&str>) -> EffectiveGrantDto {
        EffectiveGrantDto {
            repository_id: repo.map(str::to_string),
            permission: perm.into(),
            source: GrantSourceDto::User,
        }
    }

    fn claims_grant(perm: &str, required: &[&str]) -> EffectiveGrantDto {
        EffectiveGrantDto {
            repository_id: None,
            permission: perm.into(),
            source: GrantSourceDto::Claims {
                required: required.iter().map(|s| (*s).to_string()).collect(),
            },
        }
    }

    #[test]
    fn render_table_headers_and_global_marker() {
        let rows = vec![user_grant("write", None)];
        let out = render_table(&rows);
        assert!(out.contains("PERMISSION"));
        assert!(out.contains("REPOSITORY"));
        assert!(out.contains("SOURCE"));
        assert!(out.contains("write"));
        assert!(out.contains('*'), "null repository renders as *");
        assert!(out.contains("user"));
    }

    #[test]
    fn render_table_scoped_and_claims_source_row() {
        let rows = vec![
            user_grant("read", Some("11111111-1111-1111-1111-111111111111")),
            claims_grant("admin", &["admin"]),
        ];
        let out = render_table(&rows);
        assert!(out.contains("11111111-1111-1111-1111-111111111111"));
        assert!(out.contains("claims:[admin]"));
    }

    #[test]
    fn source_dto_deserializes_tagged_shape() {
        let claims: GrantSourceDto =
            serde_json::from_str(r#"{"kind":"claims","required":["developer","team-alpha"]}"#)
                .unwrap();
        match claims {
            GrantSourceDto::Claims { required } => {
                assert_eq!(required, vec!["developer", "team-alpha"]);
            }
            GrantSourceDto::User => panic!("expected claims"),
        }
        let user: GrantSourceDto = serde_json::from_str(r#"{"kind":"user"}"#).unwrap();
        assert!(matches!(user, GrantSourceDto::User));
    }

    #[test]
    fn response_dto_roundtrips() {
        // Response shape: no `claims`/`claims_source`; honest marker +
        // hint instead.
        let json = r#"{
            "user_id":"abc",
            "is_admin":false,
            "claim_based_authority":"not_resolvable_without_session",
            "claim_based_authority_hint":"use POST /api/v1/admin/rbac/resolve",
            "grants":[{"repository_id":null,"permission":"read","source":{"kind":"user"}}]
        }"#;
        let r: EffectivePermissionsResponseDto = serde_json::from_str(json).unwrap();
        assert_eq!(r.claim_based_authority, "not_resolvable_without_session");
        assert!(r
            .claim_based_authority_hint
            .contains("/api/v1/admin/rbac/resolve"));
        assert!(!r.is_admin);
        assert_eq!(r.grants.len(), 1);
        assert!(matches!(r.grants[0].source, GrantSourceDto::User));
    }

    /// Table output carries the honest marker + the resolver hint and no
    /// longer renders a `claims:` line.
    #[test]
    fn table_output_shows_marker_and_hint_no_claims_line() {
        let resp = EffectivePermissionsResponseDto {
            user_id: "abc".into(),
            is_admin: false,
            claim_based_authority: "not_resolvable_without_session".into(),
            claim_based_authority_hint:
                "use POST /api/v1/admin/rbac/resolve with the user's groups".into(),
            grants: vec![user_grant("read", None)],
        };
        let mut buf: Vec<u8> = Vec::new();
        render_table_block(&resp, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("claim_based_authority:"));
        assert!(out.contains("not_resolvable_without_session"));
        assert!(out.contains("/api/v1/admin/rbac/resolve"));
        assert!(
            !out.contains("claims:") && !out.contains("claims_source:"),
            "the dropped claims fields must not render"
        );
        // The grant row still renders.
        assert!(out.contains("read"));
    }

    #[test]
    fn urlencoded_passes_through_uuid() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        assert_eq!(urlencoded(uuid), uuid);
    }

    #[test]
    fn urlencoded_encodes_specials() {
        assert_eq!(urlencoded("a/b"), "a%2Fb");
    }
}
