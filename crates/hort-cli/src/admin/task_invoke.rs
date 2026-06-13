//! `hort-cli admin task invoke` — POST to `/api/v1/admin/tasks/<kind>`.
//!
//! # Behaviour
//!
//! 1. Read `--params-file` if supplied; parse as JSON. Default: `{}`.
//! 2. Percent-encode the `kind` path segment (defensive; valid kinds are
//!    lowercase-hyphenated and need no escaping, but encoding prevents
//!    `..` traversal or injection).
//! 3. POST the body to `/api/v1/admin/tasks/<kind>`.
//! 4. Print the `task_job_id` in table mode or the full JSON in JSON mode.
//!
//! `--params-file <path>` is the only body-input mechanism in v1.
//! `--param k=v` style is deferred post-v1.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::admin::InvokeResponse;
use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Schedule-window granularities for `--idempotency-key-window`.
///
/// The CLI rounds the current UTC clock down to the granularity boundary
/// and formats it as an RFC3339-style prefix, yielding an idempotency key
/// shaped like `<formatted_time>:<kind>`. This mirrors what the chart's
/// CronJob templates used to compute with `date -u +%Y-%m-%dT%H:%M` —
/// hoisted into `hort-cli` itself so the distroless runtime image can
/// invoke the CLI directly, without a shell wrapper.
#[derive(clap::ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyKeyWindow {
    /// `YYYY-MM-DDTHH:MM` — matches the legacy `date -u +%Y-%m-%dT%H:%M`.
    Minute,
    /// `YYYY-MM-DDTHH` — for once-per-hour CronJobs.
    Hour,
    /// `YYYY-MM-DD` — for daily CronJobs.
    Day,
}

/// Arguments for `hort-cli admin task invoke`.
#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("idempotency_source")
        .multiple(false)
        .args(["idempotency_key", "idempotency_key_window"])
))]
pub struct TaskInvokeArgs {
    /// Task kind to invoke (e.g. `noop`, `staging-sweep`, `scan`).
    pub kind: String,

    /// Read JSON body from this file. Default: empty object `{}`.
    ///
    /// The file must contain valid JSON. Use this to pass task-specific
    /// parameters. v1 only supports file-based input.
    ///
    /// `--param k=v` input is deferred post-v1.
    #[arg(long, value_name = "PATH")]
    pub params_file: Option<PathBuf>,

    /// Idempotency key — server-side dedup at the framework layer.
    ///
    /// When set, the AkClient sends `Idempotency-Key: <key>` as an HTTP
    /// header. Server-side dedup short-circuits a duplicate
    /// `(kind, key)` tuple within a 5-minute window (see ADR 0028).
    ///
    /// Mutually exclusive with `--idempotency-key-window`. For operator
    /// scripts that already have a key in hand. CronJob templates use
    /// `--idempotency-key-window` instead so a controller-restart
    /// double-fire short-circuits at the framework layer.
    #[arg(long, value_name = "STRING")]
    pub idempotency_key: Option<String>,

    /// Compute the idempotency key from a UTC clock-window + the task
    /// kind, replacing the legacy shell-driven
    /// `<date -u +%Y-%m-%dT%H:%M>:<kind>` pattern. The chart's CronJob
    /// templates pass `--idempotency-key-window=minute`; the hort-server
    /// runtime image is distroless, so the previous `sh -c "KEY=..."`
    /// wrapper couldn't run.
    ///
    /// Mutually exclusive with `--idempotency-key`.
    #[arg(long, value_name = "GRANULARITY", value_enum)]
    pub idempotency_key_window: Option<IdempotencyKeyWindow>,
}

// ---------------------------------------------------------------------------
// Entry point (writes to stdout/stderr)
// ---------------------------------------------------------------------------

/// Entry point for the CLI dispatch path. Writes output to `stdout`.
pub async fn run(client: AkClient, args: TaskInvokeArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant that writes output to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: TaskInvokeArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — build the request body.
    let body: serde_json::Value = match args.params_file {
        Some(ref path) => {
            let raw = std::fs::read(path)
                .with_context(|| format!("reading --params-file {}", path.display()))?;
            serde_json::from_slice(&raw).with_context(|| {
                format!("--params-file {} must contain valid JSON", path.display())
            })?
        }
        None => serde_json::json!({}),
    };

    // Step 2 — build the URL path with a percent-encoded kind segment.
    let encoded_kind = encode_path_segment(&args.kind);
    let path = format!("/api/v1/admin/tasks/{encoded_kind}");

    // Step 3 — Resolve the idempotency key. Clap's ArgGroup guarantees
    // at most one of `--idempotency-key` / `--idempotency-key-window`
    // is set. The window form rounds the current UTC clock down and
    // appends the kind to mirror the legacy chart shell-script shape.
    let computed_key: Option<String> =
        match (args.idempotency_key.as_deref(), args.idempotency_key_window) {
            (Some(k), _) => Some(k.to_owned()),
            (None, Some(window)) => Some(format_window_key(window, Utc::now(), &args.kind)),
            (None, None) => None,
        };

    // Step 4 — POST. Attach `Idempotency-Key` only when supplied; an
    // absent flag means the request goes out without the header so the
    // server treats every invocation as distinct.
    let resp: InvokeResponse = match computed_key.as_deref() {
        Some(key) => {
            client
                .post_with_headers(&path, &body, &[("Idempotency-Key", key)])
                .await?
        }
        None => client.post(&path, &body).await?,
    };

    // Step 5 — output.
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            writeln!(out, "task_job_id: {}", resp.task_job_id)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format the clock-window-derived idempotency key.
///
/// Mirrors the legacy chart shell pattern
/// `KEY="$(date -u +%Y-%m-%dT%H:%M):<kind>"` — but performed inside
/// `hort-cli` so the chart's distroless runtime image can invoke the CLI
/// without a shell wrapper. Takes the clock as a parameter so the unit
/// tests can pin a fixed instant.
fn format_window_key(window: IdempotencyKeyWindow, now: DateTime<Utc>, kind: &str) -> String {
    let prefix = match window {
        IdempotencyKeyWindow::Minute => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute()
        ),
        IdempotencyKeyWindow::Hour => format!(
            "{:04}-{:02}-{:02}T{:02}",
            now.year(),
            now.month(),
            now.day(),
            now.hour()
        ),
        IdempotencyKeyWindow::Day => {
            format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day())
        }
    };
    format!("{prefix}:{kind}")
}

/// Percent-encode a single URL path segment using
/// `url::form_urlencoded`'s byte-level encoder.
///
/// Valid task kinds (lowercase, hyphenated) pass through unchanged.
/// The encoding is purely defensive — it prevents `..` traversal or
/// other injection if an unexpected string is passed.
fn encode_path_segment(segment: &str) -> String {
    // Use a byte-level percent encoder. We deliberately exclude `.` from the
    // pass-through set even though RFC 3986 §2.3 lists it as unreserved:
    // encoding `.` prevents `..` path-traversal sequences from reaching the
    // server router. Valid task kinds (lowercase ASCII letters and hyphens)
    // contain no dots, so this has no practical effect on real usage.
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            // Unreserved safe set: letters, digits, hyphen, underscore, tilde.
            // Note: `.` is intentionally excluded to prevent `..` traversal.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            // Everything else — percent-encode.
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
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_path_segment_passes_through_valid_kind() {
        assert_eq!(encode_path_segment("noop"), "noop");
        assert_eq!(encode_path_segment("staging-sweep"), "staging-sweep");
        assert_eq!(encode_path_segment("cron-rescan-tick"), "cron-rescan-tick");
    }

    #[test]
    fn encode_path_segment_encodes_dots_and_slashes() {
        // `..` traversal must be encoded.
        assert_eq!(encode_path_segment(".."), "%2E%2E");
        // Slash in a path segment would break routing.
        assert_eq!(encode_path_segment("foo/bar"), "foo%2Fbar");
    }

    #[test]
    fn encode_path_segment_encodes_spaces() {
        // Spaces must be %20, not `+`.
        assert_eq!(encode_path_segment("foo bar"), "foo%20bar");
    }

    // -- format_window_key --------------------------------------------------
    //
    // Pin the legacy shell shape against the new in-CLI implementation so
    // a future refactor cannot silently change the idempotency-key format.
    // Matches what `date -u +%Y-%m-%dT%H:%M` would have produced for the
    // pinned instant below.

    fn fixed_instant() -> DateTime<Utc> {
        // 2026-05-14T11:25:54.529Z — picked to exercise zero-padded month/
        // day/hour/minute fields.
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 5, 14, 11, 25, 54)
            .single()
            .expect("static date parses")
    }

    #[test]
    fn format_window_key_minute_matches_legacy_shell_shape() {
        let key = format_window_key(
            IdempotencyKeyWindow::Minute,
            fixed_instant(),
            "service-account-rotation",
        );
        assert_eq!(key, "2026-05-14T11:25:service-account-rotation");
    }

    #[test]
    fn format_window_key_hour_drops_minute() {
        let key = format_window_key(IdempotencyKeyWindow::Hour, fixed_instant(), "noop");
        assert_eq!(key, "2026-05-14T11:noop");
    }

    #[test]
    fn format_window_key_day_drops_time() {
        let key = format_window_key(IdempotencyKeyWindow::Day, fixed_instant(), "staging-sweep");
        assert_eq!(key, "2026-05-14:staging-sweep");
    }
}
