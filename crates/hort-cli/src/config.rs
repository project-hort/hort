//! `hort-cli` configuration resolution.
//!
//! Precedence: CLI flag → env var → `~/.hort/config.toml` → error.
//! Supports `$HORT_CONFIG_PATH` to override the default config file
//! location (useful in tests and CI).
//!
//! The config file is **optional** for v1: if both `server` and `token`
//! arrive via CLI flags or environment variables, the file is not read.
//! A missing file is silently ignored; a present-but-malformed file is
//! a hard [`ConfigError::Toml`].

use std::path::PathBuf;

use clap::ValueEnum;
use directories::BaseDirs;
use serde::Deserialize;
use url::Url;

// -----------------------------------------------------------------
// Public types
// -----------------------------------------------------------------

/// CLI + config-file output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable aligned-column table (default).
    Table,
    /// Machine-readable pretty-printed JSON.
    Json,
}

/// Fully-resolved configuration after merging CLI flags, env vars, and
/// the config file.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    /// Base URL of the hort server (e.g. `https://artifacts.example.com`).
    pub server: Url,
    /// Bearer token for authentication.
    pub token: String,
    /// Default output format for commands that produce tabular data.
    pub default_format: OutputFormat,
}

/// Typed errors produced by config resolution.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required field is missing from all three sources (flag, env, file).
    #[error("required config field missing: {field} — set --{flag}, ${env_var}, or {file_key} in config file")]
    Missing {
        field: &'static str,
        flag: &'static str,
        env_var: &'static str,
        file_key: &'static str,
    },
    /// The config file exists but cannot be parsed as TOML.
    #[error("malformed config file at {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// The server URL value is not a valid URL.
    #[error("invalid server URL {value:?}: {source}")]
    InvalidUrl {
        value: String,
        #[source]
        source: url::ParseError,
    },
    /// I/O error reading the config file (not "file not found" — that is
    /// silently ignored).
    #[error("reading config file at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// -----------------------------------------------------------------
// On-disk schema
// -----------------------------------------------------------------

/// Shape of `~/.hort/config.toml`.
///
/// ```toml
/// server = "https://artifacts.example.com"
/// token  = "hort_cli_z3..."
///
/// [output]
/// default_format = "table"  # or "json"
/// ```
#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    server: Option<String>,
    token: Option<String>,
    output: Option<OutputSection>,
}

#[derive(Debug, Deserialize, Default)]
struct OutputSection {
    default_format: Option<String>,
}

// -----------------------------------------------------------------
// Resolution logic
// -----------------------------------------------------------------

/// Resolve the effective configuration from the three-layer precedence
/// chain: CLI flags → env vars → config file.
///
/// `cli_server` and `cli_token` come from clap's `--server` / `--token`
/// flags (already `Some(_)` when the user passed them). The function
/// checks `HORT_SERVER` / `HORT_TOKEN` environment variables as the second
/// layer and the config file as the third.
///
/// Returns [`ConfigError`] if a required field cannot be satisfied from
/// any layer, or if the config file exists but is malformed.
pub fn load_effective_config(
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> Result<EffectiveConfig, ConfigError> {
    // Layer 3: read (optional) config file.
    let file = read_config_file()?;

    // Resolve server URL: flag > env > file > error.
    let raw_server = cli_server
        .or_else(|| non_empty_env("HORT_SERVER"))
        .or_else(|| file.server.clone())
        .ok_or(ConfigError::Missing {
            field: "server",
            flag: "server",
            env_var: "HORT_SERVER",
            file_key: "server",
        })?;

    let server = Url::parse(&raw_server).map_err(|e| ConfigError::InvalidUrl {
        value: raw_server,
        source: e,
    })?;

    // Resolve token: flag > env > file > error.
    let token = cli_token
        .or_else(|| non_empty_env("HORT_TOKEN"))
        .or_else(|| file.token.clone())
        .ok_or(ConfigError::Missing {
            field: "token",
            flag: "token",
            env_var: "HORT_TOKEN",
            file_key: "token",
        })?;

    // Resolve output format: env > file > default (table).
    let default_format = resolve_output_format(file.output.as_ref());

    Ok(EffectiveConfig {
        server,
        token,
        default_format,
    })
}

/// Best-effort resolution of only the server URL, used by diagnostic
/// commands like `auth status` that want to surface "you're configured
/// for <server> but not authenticated" without forcing a token to be
/// present. Returns `None` on any absence, parse error, or missing
/// config file — callers are expected to render a generic message in
/// that case.
pub fn load_server_only(cli_server: Option<String>) -> Option<Url> {
    let file = read_config_file().ok()?;
    let raw = cli_server
        .or_else(|| non_empty_env("HORT_SERVER"))
        .or_else(|| file.server.clone())?;
    Url::parse(&raw).ok()
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

/// Return `$HORT_CONFIG_PATH` if set and non-empty, else
/// `$HOME/.hort/config.toml` via the `directories` crate.
pub(crate) fn config_file_path() -> Option<PathBuf> {
    // Allow override for tests and CI.
    if let Ok(p) = std::env::var("HORT_CONFIG_PATH") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    // Platform-native config dir (e.g. `~/.config` on Linux, `~/Library/...`
    // on macOS). Fall back to `$HOME/.hort/config.toml` when `BaseDirs`
    // returns `None` (unusual; only happens when $HOME is unset).
    BaseDirs::new().map(|bd| bd.home_dir().join(".hort").join("config.toml"))
}

/// Read and deserialise the config file, returning a default
/// `ConfigFile` when the file does not exist.
fn read_config_file() -> Result<ConfigFile, ConfigError> {
    let Some(path) = config_file_path() else {
        return Ok(ConfigFile::default());
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).map_err(|e| ConfigError::Toml {
            path: path.clone(),
            source: e,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(e) => Err(ConfigError::Io { path, source: e }),
    }
}

/// Return the value of `var` only when it is set and non-empty.
fn non_empty_env(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Resolve the output format from the config-file section, defaulting
/// to [`OutputFormat::Table`].
fn resolve_output_format(section: Option<&OutputSection>) -> OutputFormat {
    let raw = section
        .and_then(|s| s.default_format.as_deref())
        .unwrap_or("table");
    match raw.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Table,
    }
}

// -----------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// All env-touching tests share one mutex so they don't race on
    /// process env. On `PoisonError` (a panicking sibling held the
    /// lock) we recover the inner guard rather than cascading failures.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    const ENV_SLOTS: &[&str] = &["HORT_SERVER", "HORT_TOKEN", "HORT_CONFIG_PATH"];

    fn clear_env() {
        for s in ENV_SLOTS {
            std::env::remove_var(s);
        }
    }

    // ------------------------------------------------------------------
    // Precedence tests (Items 4–5 in the integration test plan)
    // ------------------------------------------------------------------

    #[test]
    fn cli_flag_takes_precedence_over_env() {
        let _g = lock_env();
        clear_env();
        std::env::set_var("HORT_SERVER", "https://env.example.com");
        std::env::set_var("HORT_TOKEN", "env-token");

        let cfg = load_effective_config(
            Some("https://cli.example.com".to_string()),
            Some("cli-token".to_string()),
        )
        .expect("cli flag takes precedence");

        assert_eq!(cfg.server.as_str(), "https://cli.example.com/");
        assert_eq!(cfg.token, "cli-token");
    }

    #[test]
    fn env_var_takes_precedence_over_config_file() {
        let _g = lock_env();
        clear_env();

        // Write a temporary config file.
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("config.toml");
        std::fs::write(
            &file_path,
            "server = \"https://file.example.com\"\ntoken = \"file-token\"\n",
        )
        .expect("write config");
        std::env::set_var("HORT_CONFIG_PATH", file_path.to_str().unwrap());

        // Env overrides file.
        std::env::set_var("HORT_SERVER", "https://env.example.com");
        std::env::set_var("HORT_TOKEN", "env-token");

        let cfg = load_effective_config(None, None).expect("env takes precedence over file");

        assert_eq!(cfg.server.as_str(), "https://env.example.com/");
        assert_eq!(cfg.token, "env-token");
    }

    #[test]
    fn config_file_is_used_when_flag_and_env_absent() {
        let _g = lock_env();
        clear_env();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("config.toml");
        std::fs::write(
            &file_path,
            "server = \"https://file.example.com\"\ntoken = \"file-token\"\n",
        )
        .expect("write config");
        std::env::set_var("HORT_CONFIG_PATH", file_path.to_str().unwrap());

        let cfg = load_effective_config(None, None).expect("config file is used");
        assert_eq!(cfg.server.as_str(), "https://file.example.com/");
        assert_eq!(cfg.token, "file-token");
    }

    // ------------------------------------------------------------------
    // Error cases
    // ------------------------------------------------------------------

    #[test]
    fn missing_token_from_all_sources_returns_config_error() {
        let _g = lock_env();
        clear_env();

        // Only set server — token is absent from all three sources.
        std::env::set_var("HORT_SERVER", "https://example.com");
        // Point to a non-existent config file so no file-layer token.
        std::env::set_var("HORT_CONFIG_PATH", "/tmp/no-such-file-hort-cli-test.toml");

        let err = load_effective_config(None, None).expect_err("missing token must error");
        match err {
            ConfigError::Missing { field, .. } => assert_eq!(field, "token"),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn missing_server_from_all_sources_returns_config_error() {
        let _g = lock_env();
        clear_env();

        // Only set token; point to a non-existent file so no file-layer server.
        std::env::set_var("HORT_TOKEN", "my-token");
        std::env::set_var("HORT_CONFIG_PATH", "/tmp/no-such-file-hort-cli-test.toml");

        let err = load_effective_config(None, None).expect_err("missing server must error");
        match err {
            ConfigError::Missing { field, .. } => assert_eq!(field, "server"),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn malformed_config_file_returns_toml_error() {
        let _g = lock_env();
        clear_env();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("config.toml");
        // Invalid TOML.
        std::fs::write(&file_path, "server = [not valid\n").expect("write bad config");
        std::env::set_var("HORT_CONFIG_PATH", file_path.to_str().unwrap());

        let err = load_effective_config(None, None).expect_err("malformed toml must error");
        match err {
            ConfigError::Toml { .. } => { /* expected */ }
            other => panic!("expected ConfigError::Toml, got {other:?}"),
        }
    }

    #[test]
    fn output_format_json_parsed_from_config_file() {
        let _g = lock_env();
        clear_env();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("config.toml");
        std::fs::write(
            &file_path,
            "server = \"https://a.example.com\"\ntoken = \"tok\"\n[output]\ndefault_format = \"json\"\n",
        )
        .expect("write config");
        std::env::set_var("HORT_CONFIG_PATH", file_path.to_str().unwrap());

        let cfg = load_effective_config(None, None).expect("parses");
        assert_eq!(cfg.default_format, OutputFormat::Json);
    }

    #[test]
    fn output_format_defaults_to_table_when_absent() {
        let _g = lock_env();
        clear_env();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("config.toml");
        std::fs::write(
            &file_path,
            "server = \"https://a.example.com\"\ntoken = \"tok\"\n",
        )
        .expect("write config");
        std::env::set_var("HORT_CONFIG_PATH", file_path.to_str().unwrap());

        let cfg = load_effective_config(None, None).expect("parses");
        assert_eq!(cfg.default_format, OutputFormat::Table);
    }

    #[test]
    fn invalid_server_url_returns_invalid_url_error() {
        let _g = lock_env();
        clear_env();
        std::env::set_var("HORT_TOKEN", "tok");

        let err = load_effective_config(Some("not a url !!".to_string()), None)
            .expect_err("invalid url must error");
        match err {
            ConfigError::InvalidUrl { value, .. } => assert_eq!(value, "not a url !!"),
            other => panic!("expected ConfigError::InvalidUrl, got {other:?}"),
        }
    }
}
