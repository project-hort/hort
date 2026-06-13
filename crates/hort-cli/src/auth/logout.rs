//! `hort-cli auth logout` — clear the locally stored token.
//!
//! # Behaviour
//!
//! 1. Read `~/.hort/config.toml` (or `$HORT_CONFIG_PATH`).
//! 2. Remove the `token` key from the file (the `server` key is preserved
//!    so the next `auth login` does not need `--server`).
//! 3. Re-save the file with 0600 permissions.
//! 4. Print a warning that the server-side token remains valid.
//!
//! If no config file exists, the command succeeds silently (nothing to
//! clear).

use std::process::ExitCode;

use anyhow::{Context, Result};

use crate::config::config_file_path;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> Result<ExitCode> {
    let Some(path) = config_file_path() else {
        eprintln!("hort-cli: cannot determine config file path (HOME not set)");
        return Ok(ExitCode::from(1));
    };

    // Read existing content. If the file is absent, there's nothing to do.
    let existing = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No config file found — nothing to clear.");
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("reading config file {path:?}: {e}"));
        }
    };

    // Parse and strip the `token` key.
    let cleared = clear_token_from_toml(&existing);

    // Re-write the file.
    std::fs::write(&path, &cleared).with_context(|| format!("writing config file {path:?}"))?;

    // Unix: enforce 0600 permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 permissions on {path:?}"))?;
    }

    println!(
        "Local token cleared. Server-side, the token remains valid until you \
         revoke it via DELETE /api/v1/users/me/tokens/:id."
    );

    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// TOML token removal
// ---------------------------------------------------------------------------

/// Remove the `token = "..."` line from a TOML config string.
///
/// Lines matching `^token\s*=` (with optional leading whitespace) are
/// dropped. All other lines, including comments and the `server` key, are
/// preserved verbatim. This keeps the file human-readable without a full
/// TOML round-trip.
///
/// Design choice: *remove the key entirely* rather than setting it to `""`
/// — an absent key forces a visible "not logged in" error on the next
/// command, which is the desired UX (the user must re-run `login`). An
/// empty-string token would produce a confusing 401 instead.
pub fn clear_token_from_toml(content: &str) -> String {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("token") || {
                // Only strip lines where the next non-whitespace after "token"
                // is `=` (avoids accidentally stripping a `token_foo = ...`
                // key if one is ever added).
                let rest = trimmed.strip_prefix("token").unwrap_or("");
                !rest.trim_start().starts_with('=')
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        // Re-add a trailing newline if the original had one.
        + if content.ends_with('\n') { "\n" } else { "" }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_token_removes_token_line() {
        let input = "server = \"https://example.com\"\ntoken  = \"hort_cli_abc123\"\n";
        let out = clear_token_from_toml(input);
        assert!(
            !out.contains("hort_cli_abc123"),
            "token value must be removed"
        );
        assert!(out.contains("server"), "server line must be preserved");
    }

    #[test]
    fn clear_token_preserves_server_and_comments() {
        let input =
            "# managed by hort-cli\nserver = \"https://a.example.com\"\ntoken = \"secret\"\n";
        let out = clear_token_from_toml(input);
        assert!(out.contains("# managed by hort-cli"));
        assert!(out.contains("server = \"https://a.example.com\""));
        assert!(!out.contains("secret"));
    }

    #[test]
    fn clear_token_no_token_line_is_idempotent() {
        let input = "server = \"https://example.com\"\n";
        let out = clear_token_from_toml(input);
        assert_eq!(out, input);
    }

    #[test]
    fn clear_token_preserves_trailing_newline() {
        let input = "server = \"s\"\ntoken = \"t\"\n";
        let out = clear_token_from_toml(input);
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn clear_token_without_trailing_newline() {
        let input = "server = \"s\"\ntoken = \"t\"";
        let out = clear_token_from_toml(input);
        // Trailing newline NOT added when original didn't have one.
        assert!(!out.ends_with('\n') || out == "server = \"s\"\n");
    }
}
