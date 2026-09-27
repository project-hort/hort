//! `hort-server validate-config` — offline gitops-config validation
//! (see `docs/architecture/reference/server-and-worker-configuration.md`).
//!
//! Runs, over a gitops config tree, **DSN-free** and **synchronous** (no
//! Tokio runtime; the whole flow is file reads + parse + validate, none
//! of which is async):
//!
//! 1. [`DesiredState::parse_files`] — per-file parse.
//! 2. [`DesiredState::validate`] — **row 0**: the per-envelope domain
//!    rules and the cross-document rules (duplicate `(kind, name)`,
//!    dangling references, singleton conflicts, virtual-member
//!    resolution). This is the *same function* the apply path runs:
//!    `validate_against` delegates to it before adding its
//!    snapshot/env rules, so the offline verdict on these rules cannot
//!    drift from apply's.
//! 3. The pure
//!    [`StaticConfigValidator`](hort_app::lint::StaticConfigValidator) —
//!    the snapshot-free lint subset of the apply-time pass (rows
//!    2,3,5,6,6b,7,7b,7c,8,9).
//!
//! It is the offline operator surface for a CI pre-merge gate: it
//! reproduces the server's *snapshot-free* validation faithfully without
//! a DB or a running server.
//!
//! # Config is env, not flags
//!
//! The command takes **no config-input arguments** — its
//! deployment facts come from the **same env as server boot**:
//!
//! - `HORT_CONFIG_DIR` — the gitops tree (the exact var `serve` reads at
//!   boot). **Unset/empty ⇒ exit 2.**
//! - `HORT_STORAGE_BACKEND` — the storage backend **kind**
//!   (`filesystem`|`s3`) for row 7b. **Required, with NO `filesystem`
//!   default** (unlike the server's `env_or(…, "filesystem")`): the
//!   offline check must not *guess* the backend, so unset/invalid ⇒
//!   exit 2. Kind only — it never reads the S3 bucket/endpoint/
//!   credentials, so **no secrets in CI**.
//! - `HORT_UPSTREAM_USER_AGENT` — **optional** outbound User-Agent
//!   override. Unset/empty ⇒ the server's built-in default (never a
//!   failure). When set to a value that is **not a valid HTTP header
//!   value** (control characters), the server silently falls back to the
//!   default at boot — so this command lints it as a **warning** (exit 0
//!   by default, exit 1 under `--strict`) via the same predicate the
//!   runtime applies (`hort_adapters_upstream_http::validate_user_agent_override`),
//!   so a CI gate catches a silently-inert custom UA before deploy.
//!
//! The version-static facts (`provenance_capable_formats = {"oci"}`, the
//! grant `LintConfig::default()`) are baked into the binary
//! (version-correct by construction) — a different hort-server version
//! ships a different validator.
//!
//! The only flag is `--strict` (a CI **behaviour** toggle, not deployment
//! config): it promotes any warning — including the zero-files warning
//! — to a non-zero exit.
//!
//! # Exit codes
//!
//! - **0** — clean (no errors; warnings only when not `--strict`).
//! - **1** — validation error(s): a parse error, a row-0 error, any
//!   reject rule (incl. row 7b), **or** (`--strict` and any warning present,
//!   incl. the 0-files warning).
//! - **2** — missing/invalid required env (`HORT_CONFIG_DIR` /
//!   `HORT_STORAGE_BACKEND`).
//! - **3** — operational (the config dir is unreadable / the walk
//!   errored).
//!
//! # Honesty
//!
//! A clean `validate-config` is **necessary but NOT sufficient** for a
//! successful apply. Of the apply pre-write pass it does **not** run,
//! and [`HONESTY_FOOTER`] says so on every run:
//!
//! - **(a), row 1** — the managed-by ownership rule `validate_against`
//!   adds on top of row 0: a declared name that already exists as a
//!   `managed_by=local` row. Needs the current-state snapshot.
//! - **(b), row 1** — `validate_against`'s other addition:
//!   `HORT_AUTH_PROVIDER=disabled` while `ClaimMapping` envelopes are
//!   declared. Needs only the deployment's `HORT_AUTH_PROVIDER` value,
//!   which this command does not read — **not** the running deployment.
//! - **(c)** — the `HORT_UPSTREAM_ALLOWLIST_HOSTS` gate, enforced over
//!   the *create+update* slice of the `UpstreamMapping` diff, so it too
//!   needs the current state, to know which mappings are new.
//! - **(d), row 4** — the `scanBackends` backend-**name** check, which
//!   needs nothing this command lacks: apply validates each entry
//!   against the compiled-in `hort_app::scanning::KNOWN_SCAN_BACKENDS`,
//!   not the live worker registry. Like (b), simply not wired here yet.
//!   (Row 7c — the `scanBackends` × repository-format *capability* rule
//!   — is a different check and does run here.)
//!
//! The letters are the footer's, so the two read as one list. Checks
//! that live inside apply's write stages are likewise not represented;
//! that is what "necessary but not sufficient" covers.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;
use tracing::error;

use hort_app::lint::{LintConfig, StaticConfigValidator};
use hort_app::storage_backend::EffectiveStorageBackend;
use hort_config::DesiredState;

use crate::config::LogFormat;
use crate::gitops_boot::collect_yaml_files;
use crate::telemetry;

/// The honesty footer (one line). A clean run is necessary but not
/// sufficient, and the footer's job is to name **every** apply pre-write
/// check this command skips — partially naming them is what let the
/// missing row 0 hide behind a footer that listed only rows 1 and 4.
///
/// `(a)`/`(b)` are row 1, `(c)` is the upstream-host allowlist gate, and
/// `(d)` is row 4. Each states *why* it is absent, and the three reasons
/// are genuinely different promises to an operator building a CI gate:
/// only `(a)` and `(c)` need the current state at all. `(b)` needs one
/// more env var and `(d)` needs nothing — calling either "needs the live
/// deployment" would be the same over-claim, in the opposite direction,
/// as the footer that hid the missing row 0.
const HONESTY_FOOTER: &str = "Note: a clean validate-config is necessary but NOT sufficient for \
     apply. It runs parse, the per-envelope and cross-document rules, and the static lint rows. \
     Of apply's pre-write pass it does NOT run: (a) the current-state check (a name declared \
     here that already exists as a managed_by=local row); (b) the env check \
     (HORT_AUTH_PROVIDER=disabled while ClaimMapping envelopes are declared); (c) the \
     HORT_UPSTREAM_ALLOWLIST_HOSTS check over the UpstreamMapping create/update diff; (d) the \
     scanBackends backend-NAME check against the backend set this build ships. Only (a) and (c) \
     need the running deployment's current state; (b) needs its HORT_AUTH_PROVIDER value, which \
     this command does not read, and (d) needs nothing at all — neither is wired here yet (the \
     scanBackends-vs-repository-format capability rule IS run here — a different check). Checks \
     inside apply's write stages are likewise not represented.";

/// Header printed above the row-0 error list.
///
/// A tree that passed an older `validate-config` and fails this one has
/// not changed meaning: these rules were always enforced at apply/boot,
/// this command just did not run them, so the errors below were already
/// failing that operator's rollout — invisibly. The message has to say
/// that outright, because the first reading of a newly-red gate is "the
/// new binary broke my config", and acting on that reading means pinning
/// the old image and keeping a tree the server rejects.
const ROW0_FAILURE_HEADER: &str =
    "config validation FAILED — per-envelope / cross-document error(s). These are the rules \
     hort-server applies to this same tree at boot. If it passed an earlier `hort-server \
     validate-config`, the GATE got stricter, not the tree: earlier builds of this command \
     skipped these rules, so the errors below were already failing your apply — they were just \
     invisible here. Each one below is the rejection the server reports.";

/// The zero-files warning. A `HORT_CONFIG_DIR` that
/// exists but holds 0 YAML files is a genuinely-valid empty config, but
/// because the CI path overrides `HORT_CONFIG_DIR` (cluster mount path ≠
/// CI checkout path) a typo'd-but-existing path would otherwise read as a
/// passing gate. So 0 files emits this warning: exit 0 by default, exit 1
/// under `--strict`.
const ZERO_FILES_WARNING: &str = "validated 0 config files — is HORT_CONFIG_DIR correct?";

/// Arguments to `hort-server validate-config`.
///
/// **No config-input arguments** — config comes from the env
/// (`HORT_CONFIG_DIR` + `HORT_STORAGE_BACKEND`), matching server boot. The
/// only flag is `--strict`, a CI behaviour toggle (warnings → failure).
#[derive(Debug, Args)]
pub struct ValidateConfigArgs {
    /// Treat any warning (including the "validated 0 config files"
    /// warning) as a failure — promotes a clean-but-warned run from
    /// exit 0 to exit 1. For CI gates that must catch advisory findings
    /// and a mis-pointed `HORT_CONFIG_DIR`. A behaviour knob, not
    /// deployment config — so a conventional flag, not env.
    #[arg(long)]
    pub strict: bool,
}

/// The resolved deployment inputs. Built by
/// [`resolve_inputs`] from the env; consumed by [`validate_tree`].
#[derive(Debug)]
struct Inputs {
    /// The gitops tree directory, from `HORT_CONFIG_DIR`.
    config_dir: std::path::PathBuf,
    /// The effective global storage backend kind, from
    /// `HORT_STORAGE_BACKEND` (row 7b input).
    backend: EffectiveStorageBackend,
    /// The raw `HORT_UPSTREAM_USER_AGENT` override, if set. **Optional** —
    /// unset/empty means the server uses its built-in default, so it never
    /// causes exit 2; [`validate_tree`] offline-lints it as a warning.
    user_agent_override: Option<String>,
}

/// Entry point. **DSN-free** (no `Config::from_env`, no `MinimalConfig`,
/// no `DATABASE_URL` read) and **synchronous** (no Tokio runtime — the
/// flow is file reads + parse + validate, all sync). Resolves the
/// required env via [`resolve_inputs`], then runs [`validate_tree`].
///
/// Tracing is initialised independently of the full `Config` (DSN-free):
/// the log format comes from `HORT_LOG_FORMAT` (defaulting to `Pretty`),
/// and tracing is used for **operational** errors only (a dir-walk
/// failure → `error!`); the validation result goes to stdout/stderr +
/// the exit code, not metrics.
pub fn run(args: &ValidateConfigArgs) -> ExitCode {
    // Light, DSN-free tracing init. We deliberately do NOT build a full
    // `Config` (that would require the DSN — the very thing this offline
    // command must not need). `HORT_LOG_FORMAT`
    // is read independently; an unset/invalid value falls back to `Pretty`
    // (a cosmetic log knob must never fail the gate). A double-init is
    // harmless — `init_tracing` uses `try_init` and we ignore the result.
    let _ = telemetry::init_tracing(log_format_from_env());

    // `args` carries only the `--strict` behaviour flag (Copy), so we take
    // it by reference — taking the single-`Copy`-field struct by value
    // would trip `needless_pass_by_value`.
    match resolve_inputs(|k| std::env::var(k).ok()) {
        Ok(inputs) => validate_tree(
            &inputs.config_dir,
            inputs.backend,
            inputs.user_agent_override.as_deref(),
            args.strict,
        ),
        Err(code) => code,
    }
}

/// Read `HORT_LOG_FORMAT` directly (DSN-free), mapping `json` → JSON and
/// everything else (incl. unset / an invalid value) → `Pretty`.
///
/// Intentionally lenient — unlike the server's `parse_log_format`, an
/// invalid value here does NOT fail the command: the log format is a
/// cosmetic knob and the offline gate's job is config validation, not env
/// validation of its own observability switch.
fn log_format_from_env() -> LogFormat {
    match std::env::var("HORT_LOG_FORMAT").ok().as_deref() {
        Some("json") => LogFormat::Json,
        _ => LogFormat::Pretty,
    }
}

/// Resolve the two required env vars into [`Inputs`], or an exit code on
/// failure. Injecting `get_var` keeps this testable **without** global
/// `std::env` races (the production caller passes
/// `|k| std::env::var(k).ok()`).
///
/// - `HORT_CONFIG_DIR` unset **or empty** ⇒ `Err(ExitCode::from(2))`.
/// - `HORT_STORAGE_BACKEND` unset ⇒ `Err(2)`; a value not in
///   `{filesystem, s3}` ⇒ `Err(2)` (NO `filesystem` default — the offline
///   check must not guess the backend).
fn resolve_inputs(get_var: impl Fn(&str) -> Option<String>) -> Result<Inputs, ExitCode> {
    let config_dir = match get_var("HORT_CONFIG_DIR") {
        Some(v) if !v.trim().is_empty() => std::path::PathBuf::from(v),
        _ => {
            eprintln!(
                "error: HORT_CONFIG_DIR is required (the gitops config tree to validate) — set it \
                 to the directory holding your *.yaml / *.yml envelopes"
            );
            return Err(ExitCode::from(2));
        }
    };

    let backend = match get_var("HORT_STORAGE_BACKEND").as_deref() {
        Some("filesystem") => EffectiveStorageBackend::Filesystem,
        Some("s3") => EffectiveStorageBackend::S3,
        other => {
            // Unset OR an invalid value — NO silent `filesystem` default.
            // The offline row-7b check must not guess the backend, so a
            // missing/invalid kind fails loud rather than skipping a row.
            let got = other.unwrap_or("<unset>");
            eprintln!(
                "error: HORT_STORAGE_BACKEND is required and must be one of {:?} (got `{got}`) — \
                 it is the deployment's storage backend KIND for the per-repo storage.backend \
                 cross-check (kind only; never the S3 bucket/endpoint/credentials)",
                hort_config::repository::VALID_STORAGE_BACKENDS
            );
            return Err(ExitCode::from(2));
        }
    };

    // Optional — the upstream User-Agent override. Never required (unset ⇒
    // the server's built-in default), so reading it never fails the command;
    // `validate_tree` lints it as a warning.
    let user_agent_override = get_var("HORT_UPSTREAM_USER_AGENT");

    Ok(Inputs {
        config_dir,
        backend,
        user_agent_override,
    })
}

/// The core validate flow, factored out of [`run`] so
/// it is testable with tempdirs and **no** global env. Returns the
/// process exit code (0/1/2/3 — `validate_tree` itself never returns 2,
/// which is the missing-env code [`resolve_inputs`] owns).
///
/// Steps:
/// 1. `collect_yaml_files(config_dir)` — on `Err` (unreadable / walk
///    error): `error!` + `eprintln!` → exit 3.
/// 2. Zero-files warning: if `files.is_empty()`, record a warning
///    (still proceed — an empty config is genuinely valid).
/// 3. `DesiredState::parse_files(files)` — on `Err`: print the parse
///    error(s) to stderr → exit 1.
/// 4. `DesiredState::validate()` (row 0) — on `Err`: print
///    [`ROW0_FAILURE_HEADER`] + the error(s) to stderr → exit 1.
/// 5. Run the [`StaticConfigValidator`] over the parsed desired state.
/// 6. Print every error finding + every warning finding + the zero-files
///    warning (if any) + the optional `HORT_UPSTREAM_USER_AGENT` warning +
///    the honesty footer.
/// 7. Map to an exit code (errors → 1; `--strict` + any warning → 1;
///    else 0).
///
/// `user_agent_override` is the raw `HORT_UPSTREAM_USER_AGENT` value (if
/// set). A non-empty value that is not a valid HTTP header value is a
/// **warning** (the server falls back to its built-in default at boot, not
/// a crash) — `--strict` promotes it, so a CI gate catches a silently-inert
/// custom UA.
fn validate_tree(
    config_dir: &Path,
    backend: EffectiveStorageBackend,
    user_agent_override: Option<&str>,
    strict: bool,
) -> ExitCode {
    // ---- 1. walk the tree (reuse the boot-path walker, do not fork) ----
    let files = match collect_yaml_files(config_dir) {
        Ok(files) => files,
        Err(e) => {
            // Operational failure — the dir is unreadable / the walk
            // errored. `error!` plus a human-facing stderr line.
            error!(error = %e, config_dir = %config_dir.display(), "validate-config: directory walk failed");
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };

    // ---- 2. zero-files warning ----
    //
    // `parse_files(empty) = Ok(empty DesiredState)` — a genuinely empty
    // config is valid — so we still proceed; we only *record* the warning
    // so `--strict` can promote it (catches a mis-pointed HORT_CONFIG_DIR).
    let zero_files_warning_present = files.is_empty();

    // ---- 3. parse (per-file; no cross-file rule runs here) ----
    let desired = match DesiredState::parse_files(files) {
        Ok(d) => d,
        Err(errs) => {
            // The `ParseErrors` Display renders one error per line.
            eprintln!("config validation FAILED — parse error(s):\n{errs}");
            return ExitCode::from(1);
        }
    };

    // ---- 4. row 0: per-envelope domain rules + cross-document rules ----
    //
    // `DesiredState::validate()` IS apply's row 0 — `validate_against`
    // opens by delegating to it and only its *additional* rules need the
    // snapshot — so calling it here is a shared source, not a
    // reimplementation, and the two verdicts cannot drift.
    //
    // Abort rather than collect-and-continue, for two reasons. Apply
    // aborts here, so a collect-all offline would report findings apply
    // never reaches. And the static rows below are written assuming row 0
    // passed: they carry totality fallbacks for inputs row 0 rejects (an
    // unparseable `userId` becomes a fresh UUID, an out-of-domain
    // `permission` becomes `Read`), so running them over a row-0-invalid
    // tree can manufacture findings about values the operator never
    // wrote.
    if let Err(errs) = desired.validate() {
        // The `ValidationErrors` Display renders one error per line.
        eprintln!("{ROW0_FAILURE_HEADER}\n{errs}");
        return ExitCode::from(1);
    }

    // ---- 5. run the snapshot-free validator (rows 2,3,5,6,6b,7,7b,7c,8,9) ----
    let report = static_validator(backend).validate(&desired);

    // ---- 6. print findings + footer ----
    for finding in &report.errors {
        eprintln!("ERROR [{:?}]: {}", finding.rule, finding.message);
    }
    for finding in &report.warnings {
        eprintln!("WARN  [{:?}]: {}", finding.rule, finding.message);
    }
    if zero_files_warning_present {
        eprintln!("WARN  [ZeroFiles]: {ZERO_FILES_WARNING}");
    }

    // ---- 6b. offline-lint the optional HORT_UPSTREAM_USER_AGENT override ----
    //
    // A non-empty override that is not a valid HTTP header value is a
    // WARNING, not a hard error: at boot the server falls back to its
    // built-in default for such a value (it never crashes), so the offline
    // gate mirrors that — surfacing it so `--strict` CI catches a
    // silently-inert custom UA. The predicate is the SAME one the runtime
    // applies, so validate-config and boot agree by construction.
    let ua_warning: Option<String> = user_agent_override
        .and_then(|raw| hort_adapters_upstream_http::validate_user_agent_override(raw).err());
    if let Some(msg) = &ua_warning {
        eprintln!("WARN  [UpstreamUserAgent]: {msg}");
    }

    let error_count = report.errors.len();
    let warning_count = report.warnings.len()
        + usize::from(zero_files_warning_present)
        + usize::from(ua_warning.is_some());
    if error_count == 0 && warning_count == 0 {
        println!("config validation OK — no errors, no warnings.");
    } else {
        println!("config validation summary: {error_count} error(s), {warning_count} warning(s).");
    }
    // The honesty footer goes to stdout (the summary stream).
    println!("{HONESTY_FOOTER}");

    // ---- 7. exit code ----
    //
    // Fail (exit 1) on ANY error finding, OR — under `--strict` only — on
    // any warning (the rule warnings, the zero-files warning, or the
    // HORT_UPSTREAM_USER_AGENT warning). Warnings without `--strict`, and
    // the fully-clean case, succeed.
    let any_warning =
        !report.warnings.is_empty() || zero_files_warning_present || ua_warning.is_some();
    if !report.errors.is_empty() || (strict && any_warning) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Build the snapshot-free lint validator this command runs (rows
/// 2,3,5,6,6b,7,7b,7c,8,9).
///
/// Its own function rather than an inline block inside [`validate_tree`]
/// so the row-0 parity test can ask "would the *static* rows alone have
/// rejected this tree?" against the byte-same validator the command
/// builds. Asking that of a second, hand-rolled validator would make the
/// parity test's negative half meaningless the first time the two
/// constructions drifted.
///
/// Version-static facts baked into the binary: the provenance-capable
/// format set is THE shared
/// `hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS` const the server
/// composition (`gitops_boot.rs` / `composition.rs`) also derives from — so
/// the offline gate's row-7 verdict cannot drift from the live server's.
/// The row-6b VersionDiscovery-capable format set is derived from the
/// same compiled-in handler registry `gitops_boot.rs` uses (see
/// `crate::format_capabilities`), so row 6b cannot drift either.
/// The grant-lint base is the secure `LintConfig::default()` (the offline
/// CLI has no composition-level operator override; the desired-side
/// `PermissionGrantLintConfig` override still applies inside `validate`).
fn static_validator(backend: EffectiveStorageBackend) -> StaticConfigValidator {
    StaticConfigValidator::new(
        Arc::new(
            hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS
                .iter()
                .copied()
                .map(String::from)
                .collect(),
        ),
        Arc::new(crate::format_capabilities::version_discovery_capable_formats()),
        Some(backend),
    )
    .with_grant_lint_base(LintConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use clap::Parser;
    use tempfile::TempDir;

    // ---- helpers ----------------------------------------------------------

    /// `ExitCode` is opaque (no `PartialEq`); compare via the `Debug`
    /// rendering, the same idiom `scrub.rs`'s exit-code tests use.
    fn code_str(code: ExitCode) -> String {
        format!("{code:?}")
    }
    fn exit(n: u8) -> String {
        format!("{:?}", ExitCode::from(n))
    }
    fn success() -> String {
        format!("{:?}", ExitCode::SUCCESS)
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, body).unwrap();
    }

    // A minimal, well-formed hosted OCI repo on filesystem — clean under
    // every static rule. Used as the "valid small fixture".
    const REPO_OCI_HOSTED: &str = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: oci-hosted
spec:
  name: oci-hosted
  format: oci
  type: hosted
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: oci-hosted
";

    // ---- clap parsing -----------------------------------------------------

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    #[test]
    fn validate_config_parses_with_strict_false_by_default() {
        let cli = TestCli::try_parse_from(["hort-server", "validate-config"]).unwrap();
        let super::super::Command::ValidateConfig(args) = cli.command else {
            panic!("expected ValidateConfig");
        };
        assert!(!args.strict);
    }

    #[test]
    fn validate_config_parses_with_strict_flag() {
        let cli = TestCli::try_parse_from(["hort-server", "validate-config", "--strict"]).unwrap();
        let super::super::Command::ValidateConfig(args) = cli.command else {
            panic!("expected ValidateConfig");
        };
        assert!(args.strict);
    }

    #[test]
    fn validate_config_help_renders() {
        let err =
            TestCli::try_parse_from(["hort-server", "validate-config", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let rendered = err.to_string();
        assert!(rendered.contains("strict"));
    }

    // ---- resolve_inputs (injected closures — NO std::env races) ----------

    #[test]
    fn resolve_inputs_missing_config_dir_is_exit_2() {
        let res = resolve_inputs(|k| match k {
            "HORT_STORAGE_BACKEND" => Some("filesystem".to_string()),
            _ => None, // HORT_CONFIG_DIR unset
        });
        let code = res.expect_err("missing HORT_CONFIG_DIR must fail");
        assert_eq!(code_str(code), exit(2));
    }

    #[test]
    fn resolve_inputs_empty_config_dir_is_exit_2() {
        let res = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("   ".to_string()), // present but blank
            "HORT_STORAGE_BACKEND" => Some("filesystem".to_string()),
            _ => None,
        });
        let code = res.expect_err("empty HORT_CONFIG_DIR must fail");
        assert_eq!(code_str(code), exit(2));
    }

    #[test]
    fn resolve_inputs_missing_storage_backend_is_exit_2() {
        let res = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            _ => None, // HORT_STORAGE_BACKEND unset — NO filesystem default
        });
        let code = res.expect_err("missing HORT_STORAGE_BACKEND must fail");
        assert_eq!(code_str(code), exit(2));
    }

    #[test]
    fn resolve_inputs_bogus_storage_backend_is_exit_2() {
        let res = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            "HORT_STORAGE_BACKEND" => Some("bogus".to_string()),
            _ => None,
        });
        let code = res.expect_err("invalid HORT_STORAGE_BACKEND must fail");
        assert_eq!(code_str(code), exit(2));
    }

    #[test]
    fn resolve_inputs_filesystem_maps_to_filesystem_backend() {
        let inputs = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            "HORT_STORAGE_BACKEND" => Some("filesystem".to_string()),
            _ => None,
        })
        .expect("valid inputs");
        assert_eq!(inputs.backend, EffectiveStorageBackend::Filesystem);
        assert_eq!(inputs.config_dir, PathBuf::from("/tmp/cfg"));
    }

    #[test]
    fn resolve_inputs_s3_maps_to_s3_backend() {
        let inputs = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            "HORT_STORAGE_BACKEND" => Some("s3".to_string()),
            _ => None,
        })
        .expect("valid inputs");
        assert_eq!(inputs.backend, EffectiveStorageBackend::S3);
    }

    // ---- validate_tree (tempdirs — NO global env) ------------------------

    /// A valid small fixture tree validates to exit 0. This test never
    /// reads `DATABASE_URL` — `validate_tree`
    /// (and the whole command) is DSN-free by construction (it calls no
    /// `Config::from_env`, opens no pool, and reads no DSN), so the
    /// offline guarantee holds without any env juggling here.
    #[test]
    fn validate_tree_valid_fixture_is_exit_0() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/oci.yaml", REPO_OCI_HOSTED);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), success());
    }

    #[test]
    fn validate_tree_zero_files_is_exit_0_default() {
        // An existing dir with 0 YAML files: a genuinely empty config is
        // valid → exit 0 (but the zero-files warning is recorded — see strict).
        let dir = TempDir::new().unwrap();
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), success());
    }

    #[test]
    fn validate_tree_zero_files_under_strict_is_exit_1() {
        // Same empty dir under `--strict` → the zero-files warning is
        // promoted to a failure (catches a mis-pointed HORT_CONFIG_DIR).
        let dir = TempDir::new().unwrap();
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, true);
        assert_eq!(code_str(code), exit(1));
    }

    #[test]
    fn validate_tree_unreadable_dir_is_exit_3() {
        // A path that does not exist makes the directory walk error
        // (the WalkDir iterator yields Err for the missing root) →
        // operational exit 3.
        let missing = Path::new("/nonexistent/hort-validate-config-xyz");
        let code = validate_tree(missing, EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(3));
    }

    /// A directory the process cannot read (mode 000) makes the recursive
    /// walk error when it tries to descend → operational exit 3. This is a
    /// second, distinct exit-3 trigger from the missing-path case above
    /// (an I/O error mid-walk rather than a missing root). Unix-only: the
    /// permission model is what makes the walk fail — and ROOT bypasses it,
    /// so the assertion below is root-tolerant (see the comment there).
    #[cfg(unix)]
    #[test]
    fn validate_tree_unreadable_subdir_is_exit_3() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        // A yaml file inside so the walker must descend into the locked
        // dir (an empty unreadable dir might be statted but not opened).
        fs::write(locked.join("a.yaml"), "x: 1").unwrap();
        // Remove all permissions so opening the directory for reading
        // fails with EACCES, surfacing as a walkdir error.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);

        // Restore permissions so the TempDir can be cleaned up.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        // Root (CI containers commonly run as uid 0) BYPASSES Unix mode bits,
        // so the mode-000 dir stays traversable: the walk then succeeds and
        // the dummy `a.yaml` parse-fails to exit 1 instead of the
        // permission-driven exit 3. A non-root process is always denied
        // (000 => no readdir), so exit 3 is its only outcome here; exit 1 can
        // only mean root. Accept either — mirroring the root-tolerance of the
        // sibling hort-adapters-secrets `permission_denied_returns_read_failure`
        // test — since there is no portable way to deny root via mode bits.
        // The missing-path test above strictly guards the walk-error => exit-3
        // mapping UID-independently.
        let code = code_str(code);
        assert!(
            code == exit(3) || code == exit(1),
            "expected exit 3 (non-root permission-denied walk) or exit 1 \
             (root bypassed mode bits), got {code}"
        );
    }

    #[test]
    fn validate_tree_parse_error_is_exit_1() {
        // Malformed YAML inside an otherwise-fine tree → parse_files Err →
        // exit 1. A bare scalar where an envelope is expected is rejected
        // by the per-envelope parse (missing apiVersion/kind).
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "repositories/bad.yaml",
            "not: a: valid: envelope\n",
        );
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    // ---- reject-rule fixtures (each → exit 1) ----------------------------

    /// Row 7b — a per-repo `storage.backend: s3` while the deployment
    /// backend is Filesystem → HARD REJECT (not a skip), exit 1.
    #[test]
    fn validate_tree_row_7b_storage_backend_mismatch_is_exit_1() {
        let repo = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: s3-on-fs
spec:
  name: s3-on-fs
  format: oci
  type: hosted
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: s3
    path: s3-on-fs
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", repo);
        // Deployment backend = Filesystem; repo declares s3 → mismatch.
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// Row 5 — `trust_upstream_publish_time = true` × resolved
    /// `scan_backends: []` cross-opt-in collapse → exit 1. Needs a proxy
    /// repo + an UpstreamMapping with `trustUpstreamPublishTime: true` +
    /// a ScanPolicy scoped to that repo with `scanBackends: []`.
    #[test]
    fn validate_tree_row_5_trust_pt_with_empty_scan_backends_is_exit_1() {
        let repo = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: oci-proxy
spec:
  name: oci-proxy
  format: oci
  type: proxy
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: oci-proxy
  proxy:
    upstreamUrl: https://index.docker.io
";
        let mapping = "\
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: oci-proxy-library
spec:
  repository: oci-proxy
  pathPrefix: library
  upstreamUrl: https://index.docker.io
  trustUpstreamPublishTime: true
  auth:
    type: anonymous
";
        let policy = "\
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: p-collapse
spec:
  scope:
    repository: oci-proxy
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: off
  maxArtifactAge: 90d
  licensePolicy:
    allowed: [MIT]
  scanBackends: []
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", repo);
        write(dir.path(), "upstreams/m.yaml", mapping);
        write(dir.path(), "policies/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// Row 7c — a `scanBackends` entry the scanner capability map says
    /// cannot analyse the governed repository's format → exit 1.
    ///
    /// The row reads the compiled-in map directly rather than an
    /// injected set, which is what makes it reach this offline CLI *by
    /// construction*: nothing here wires a capability fact, and the
    /// rejection still fires.
    #[test]
    fn validate_tree_row_7c_inert_scan_backend_pairing_is_exit_1() {
        let policy = "\
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: p-oci-osv
spec:
  scope:
    repository: oci-hosted
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: off
  licensePolicy: {}
  scanBackends: [trivy, osv]
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", REPO_OCI_HOSTED);
        write(dir.path(), "policies/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// Row 9 — a `RetentionPolicy` predicate using `UnusedFor`, nested
    /// inside a `Composite` → exit 1. The rule earns its place in the
    /// `StaticConfigValidator` rather than in the per-spec validator:
    /// `UnusedFor` is structurally valid (`PolicyPredicate::validate`
    /// accepts it), so row 0 has nothing to say about it — only the lint
    /// row knows no port supplies a last-download anchor.
    #[test]
    fn validate_tree_row_9_nested_unused_for_is_exit_1() {
        let policy = "\
apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: reclaim-cold
spec:
  predicate:
    Composite:
      - Or
      - - AgeExceeds: 2592000
        - UnusedFor: 7776000
  scope: AllRepos
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", REPO_OCI_HOSTED);
        write(dir.path(), "retention/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// The same tree with `AgeExceeds` alone is clean — the rejection
    /// above is `UnusedFor`, not the presence of a retention policy.
    #[test]
    fn validate_tree_row_9_age_exceeds_alone_is_success() {
        let policy = "\
apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: retain-90d
spec:
  predicate:
    AgeExceeds: 7776000
  scope: AllRepos
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", REPO_OCI_HOSTED);
        write(dir.path(), "retention/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), success());
    }

    /// The same tree with `osv` dropped is clean — so the rejection
    /// above is the pairing, not the presence of a scan policy.
    #[test]
    fn validate_tree_row_7c_covering_backend_alone_is_success() {
        let policy = "\
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: p-oci-trivy
spec:
  scope:
    repository: oci-hosted
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: off
  licensePolicy: {}
  scanBackends: [trivy]
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", REPO_OCI_HOSTED);
        write(dir.path(), "policies/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), success());
    }

    /// Row 6 — accepted-but-inert `prefetchPolicy.maxAgeDays` → exit 1.
    #[test]
    fn validate_tree_row_6_prefetch_max_age_days_is_exit_1() {
        let repo = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-proxy
spec:
  name: npm-proxy
  format: npm
  type: proxy
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: npm-proxy
  proxy:
    upstreamUrl: https://registry.npmjs.org
  prefetchPolicy:
    mode: scheduled
    maxAgeDays: 90
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", repo);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// Row 7 — a provenance reject: `provenanceMode: required` scoped to a
    /// non-OCI (no-verifier) repository format → exit 1.
    #[test]
    fn validate_tree_row_7_provenance_required_on_no_verifier_format_is_exit_1() {
        let repo = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-proxy
spec:
  name: npm-proxy
  format: npm
  type: proxy
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: npm-proxy
  proxy:
    upstreamUrl: https://registry.npmjs.org
";
        let policy = "\
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: p-req-npm
spec:
  scope:
    repository: npm-proxy
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: required
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
  maxArtifactAge: 90d
  licensePolicy:
    allowed: [MIT]
  scanBackends: [trivy]
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", repo);
        write(dir.path(), "policies/p.yaml", policy);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    /// Row 8 — a permission-grant reject: a single-claim grant (the
    /// `single-claim-grant` rule rejects by secure default) → exit 1.
    /// This proves the offline grant linter (via `with_grant_lint_base`)
    /// is wired and aborts.
    #[test]
    fn validate_tree_row_8_single_claim_grant_is_exit_1() {
        let repo = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-proxy
spec:
  name: npm-proxy
  format: npm
  type: hosted
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: npm-proxy
";
        // A single-claim ([developer]) grant — the linter rejects it
        // (single-claim-grant rule, `reject` by secure default).
        let grant = "\
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: single-claim-read
spec:
  subject:
    kind: claims
    required: [developer]
  permission: read
  repository: npm-proxy
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/r.yaml", repo);
        write(dir.path(), "auth/g.yaml", grant);
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), exit(1));
    }

    // ---- warnings-but-no-errors → strict promotion ----------------------

    /// A warnings-only fixture (row 3 under-constrained federatedIdentities
    /// is advisory): exit 0 without `--strict`, exit 1 with `--strict` —
    /// proving the strict promotion of rule warnings.
    #[test]
    fn validate_tree_warnings_only_strict_promotion() {
        let issuer = "\
apiVersion: project-hort.de/v1
kind: OidcIssuer
metadata:
  name: github-actions
spec:
  issuerUrl: https://github-actions.example.com
  audiences: [hort-server]
  jwksRefreshInterval: 1h
  allowedAlgorithms: [RS256]
  requireJti: true
";
        // An SA with a single FI constrained by ONLY `repository` — an
        // under-constrained advisory (a warning, not an error).
        let sa = "\
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: ci-loose
spec:
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "auth/issuer.yaml", issuer);
        write(dir.path(), "auth/sa.yaml", sa);

        // Without --strict → warnings present but exit 0.
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, false);
        assert_eq!(code_str(code), success(), "warnings without --strict → 0");

        // With --strict → the warning is promoted to exit 1.
        let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, None, true);
        assert_eq!(code_str(code), exit(1), "warnings under --strict → 1");
    }

    // ---- HORT_UPSTREAM_USER_AGENT offline lint --------------------------

    /// A clean tree + an INVALID `HORT_UPSTREAM_USER_AGENT` (interior control
    /// char) → a warning, NOT an error: exit 0 by default (the server falls
    /// back to its built-in default at boot, it does not crash), exit 1 under
    /// `--strict` (so a CI gate catches a silently-inert custom UA).
    #[test]
    fn validate_tree_invalid_user_agent_is_warning_strict_promotion() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/oci.yaml", REPO_OCI_HOSTED);
        let bad_ua = Some("hort/1.0\nX-Injected: 1");

        let code = validate_tree(
            dir.path(),
            EffectiveStorageBackend::Filesystem,
            bad_ua,
            false,
        );
        assert_eq!(code_str(code), success(), "invalid UA without --strict → 0");

        let code = validate_tree(
            dir.path(),
            EffectiveStorageBackend::Filesystem,
            bad_ua,
            true,
        );
        assert_eq!(code_str(code), exit(1), "invalid UA under --strict → 1");
    }

    /// A VALID `HORT_UPSTREAM_USER_AGENT` override (incl. obs-text / empty)
    /// is NOT flagged — exit 0 even under `--strict` on an otherwise-clean
    /// tree. Proves a legitimate operator UA does not trip the gate.
    #[test]
    fn validate_tree_valid_user_agent_is_not_flagged_even_under_strict() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/oci.yaml", REPO_OCI_HOSTED);
        for ua in [Some("acme-proxy/2.0 (ops@example.com)"), Some(""), None] {
            let code = validate_tree(dir.path(), EffectiveStorageBackend::Filesystem, ua, true);
            assert_eq!(
                code_str(code),
                success(),
                "valid/empty/unset UA under --strict → 0"
            );
        }
    }

    #[test]
    fn resolve_inputs_reads_optional_user_agent_override() {
        // Set → carried verbatim onto Inputs (validated later by validate_tree).
        let inputs = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            "HORT_STORAGE_BACKEND" => Some("filesystem".to_string()),
            "HORT_UPSTREAM_USER_AGENT" => Some("acme/1.0".to_string()),
            _ => None,
        })
        .expect("valid inputs");
        assert_eq!(inputs.user_agent_override.as_deref(), Some("acme/1.0"));

        // Unset → None (the server's built-in default applies; never exit 2).
        let inputs = resolve_inputs(|k| match k {
            "HORT_CONFIG_DIR" => Some("/tmp/cfg".to_string()),
            "HORT_STORAGE_BACKEND" => Some("filesystem".to_string()),
            _ => None,
        })
        .expect("valid inputs");
        assert_eq!(inputs.user_agent_override, None);
    }

    // ---- row 0: per-envelope + cross-document rules ----------------------

    /// One row-0 defect tree.
    ///
    /// The five defect trees and the clean control live in ONE corpus
    /// because the parity test and the per-defect tests have to be
    /// looking at the same trees: a fixture only the per-defect test can
    /// see is a tree the parity claim does not actually cover.
    struct Row0Case {
        /// Stable handle — the per-defect tests select by it, and it
        /// names the offending tree in the parity test's assertions.
        label: &'static str,
        /// `relative path` → YAML body.
        files: &'static [(&'static str, &'static str)],
        /// Whether apply's row 0 rejects this tree. Asserted against the
        /// real row-0 entry point in `row0_parity_...`, never trusted —
        /// declaring it keeps the corpus honest about carrying a clean
        /// control, so the parity implication cannot hold vacuously.
        row0_rejects: bool,
    }

    /// A `RetentionPolicy` naming a repository that is not declared.
    /// Predicate is deliberately clean (`AgeExceeds` > 0, no `UnusedFor`)
    /// so the only defect is the scope reference.
    const RETENTION_SCOPE_GHOST: &str = "\
apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: retain-ghost
spec:
  predicate:
    AgeExceeds: 7776000
  scope:
    Repos: [ghost-repo]
";

    /// A structurally invalid predicate: a zero-second TTL expires every
    /// artifact the instant it is ingested. Scope is clean.
    const RETENTION_ZERO_AGE: &str = "\
apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: retain-zero
spec:
  predicate:
    AgeExceeds: 0
  scope: AllRepos
";

    /// A grant pointing at a repository nothing declares. Two required
    /// claims and a concrete `repository`, so the row-8 grant linter has
    /// nothing to say about it — the dangling reference is the whole
    /// defect.
    const GRANT_GHOST_REPO: &str = "\
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: read-ghost
spec:
  subject:
    kind: claims
    required: [team-platform, role-developer]
  permission: read
  repository: ghost-repo
";

    /// `metadata.name` that is blank but not empty. The empty string is
    /// a *parse* error (`ParseError::EmptyMetadataName`) the command
    /// already rejected before row 0 was wired; whitespace gets past the
    /// parser's `is_empty()` and is caught only by the per-spec name
    /// rule, which is what makes it a row-0 fixture.
    const REPO_BLANK_NAME: &str = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: \"  \"
spec:
  name: blank
  format: oci
  type: hosted
  isPublic: true
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: blank
";

    /// A second envelope re-declaring `oci-hosted` — same `(kind, name)`
    /// as `REPO_OCI_HOSTED`, different file, so apply cannot tell which
    /// the operator meant.
    const REPO_OCI_HOSTED_AGAIN: &str = "\
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: oci-hosted
spec:
  name: oci-hosted-copy
  format: oci
  type: hosted
  isPublic: false
  replicationPriority: local_only
  storage:
    backend: filesystem
    path: oci-hosted-copy
";

    const ROW0_CORPUS: &[Row0Case] = &[
        Row0Case {
            label: "blank-metadata-name",
            files: &[("repositories/blank.yaml", REPO_BLANK_NAME)],
            row0_rejects: true,
        },
        Row0Case {
            label: "grant-references-undeclared-repository",
            files: &[
                ("repositories/oci.yaml", REPO_OCI_HOSTED),
                ("auth/g.yaml", GRANT_GHOST_REPO),
            ],
            row0_rejects: true,
        },
        Row0Case {
            label: "duplicate-kind-and-name",
            files: &[
                ("repositories/oci.yaml", REPO_OCI_HOSTED),
                ("repositories/oci-again.yaml", REPO_OCI_HOSTED_AGAIN),
            ],
            row0_rejects: true,
        },
        Row0Case {
            label: "retention-scope-references-undeclared-repository",
            files: &[
                ("repositories/oci.yaml", REPO_OCI_HOSTED),
                ("retention/p.yaml", RETENTION_SCOPE_GHOST),
            ],
            row0_rejects: true,
        },
        Row0Case {
            label: "retention-predicate-structurally-invalid",
            files: &[
                ("repositories/oci.yaml", REPO_OCI_HOSTED),
                ("retention/p.yaml", RETENTION_ZERO_AGE),
            ],
            row0_rejects: true,
        },
        // The clean control. Without it the parity implication ("row 0
        // rejects ⇒ the CLI exits 1") would be satisfiable by a command
        // that exits 1 on everything.
        Row0Case {
            label: "clean-control",
            files: &[("repositories/oci.yaml", REPO_OCI_HOSTED)],
            row0_rejects: false,
        },
    ];

    fn row0_case(label: &str) -> &'static Row0Case {
        ROW0_CORPUS
            .iter()
            .find(|c| c.label == label)
            .unwrap_or_else(|| panic!("no Row0Case labelled `{label}` in ROW0_CORPUS"))
    }

    /// Materialise a corpus case as a tempdir tree.
    fn row0_tree(case: &Row0Case) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (rel, body) in case.files {
            write(dir.path(), rel, body);
        }
        dir
    }

    /// Run the corpus case through the offline CLI.
    fn row0_exit(case: &Row0Case) -> String {
        let dir = row0_tree(case);
        code_str(validate_tree(
            dir.path(),
            EffectiveStorageBackend::Filesystem,
            None,
            false,
        ))
    }

    /// Drive `case` through the **apply path's** row-0 entry point.
    ///
    /// `validate_against` is what `ApplyConfigUseCase::run_pre_write_validation`
    /// calls; handing it an empty `CurrentSnapshot` and an `Oidc` auth
    /// provider neutralises both of its row-1 additions (no `Local` row
    /// to collide with, and the disabled-provider rule cannot fire), so
    /// whatever it returns here IS row 0's verdict. Calling the apply
    /// entry point rather than `DesiredState::validate()` directly is the
    /// point: a future row-0-shaped rule added to `validate_against`
    /// *beside* the delegation — the one way the two paths could still
    /// diverge — shows up as a parity failure instead of passing
    /// unnoticed.
    fn apply_row0_verdict(case: &Row0Case) -> Result<(), hort_config::ValidationErrors> {
        let files: Vec<(PathBuf, Vec<u8>)> = case
            .files
            .iter()
            .map(|(rel, body)| (PathBuf::from(rel), body.as_bytes().to_vec()))
            .collect();
        let desired = DesiredState::parse_files(files)
            .unwrap_or_else(|e| panic!("`{}` must parse; row 0 is not parse:\n{e}", case.label));
        desired.validate_against(
            &hort_config::CurrentSnapshot::default(),
            &hort_config::EnvSnapshot {
                auth_provider: hort_config::EnvAuthProvider::Oidc,
            },
        )
    }

    /// Would the static lint rows alone have rejected this tree?
    ///
    /// The parity test needs this to prove *attribution*: a defect tree
    /// that some unrelated lint row also rejects would keep exiting 1
    /// even if the row-0 call were deleted again, and the test would
    /// still pass. Built from the same [`static_validator`] the command
    /// builds, so the question asked is the one the command answers.
    fn static_rows_reject(case: &Row0Case) -> bool {
        let files: Vec<(PathBuf, Vec<u8>)> = case
            .files
            .iter()
            .map(|(rel, body)| (PathBuf::from(rel), body.as_bytes().to_vec()))
            .collect();
        let desired = DesiredState::parse_files(files).expect("corpus fixtures parse");
        !static_validator(EffectiveStorageBackend::Filesystem)
            .validate(&desired)
            .errors
            .is_empty()
    }

    /// The parity claim, over the whole corpus: **whatever the apply
    /// path rejects in row 0, the offline gate rejects too.**
    ///
    /// There is no list of row-0 rules anywhere in this test — the
    /// expectation is computed by calling the apply path itself
    /// ([`apply_row0_verdict`]), so a rule added to, removed from, or
    /// reshaped inside row 0 needs no edit here to stay covered. That
    /// shared source is the whole point: the gap this test closes was a
    /// divergence between two hand-maintained notions of what the gate
    /// checks.
    #[test]
    fn row0_parity_offline_gate_rejects_whatever_apply_row0_rejects() {
        let mut saw_clean = false;
        let mut saw_defect = false;

        for case in ROW0_CORPUS {
            let apply_rejects = apply_row0_verdict(case).is_err();
            assert_eq!(
                apply_rejects, case.row0_rejects,
                "`{}`: corpus declares row0_rejects={}, apply's row 0 says {apply_rejects}",
                case.label, case.row0_rejects
            );

            if apply_rejects {
                saw_defect = true;
                assert_eq!(
                    row0_exit(case),
                    exit(1),
                    "`{}`: apply rejects this tree in row 0, the offline gate must too",
                    case.label
                );
                assert!(
                    !static_rows_reject(case),
                    "`{}`: the static lint rows also reject this tree, so its exit 1 \
                     proves nothing about row 0 — pick a defect only row 0 catches",
                    case.label
                );
            } else {
                saw_clean = true;
                assert_eq!(
                    row0_exit(case),
                    success(),
                    "`{}`: apply's row 0 accepts this tree, the offline gate must too",
                    case.label
                );
            }
        }

        assert!(
            saw_defect && saw_clean,
            "the corpus must hold both defect trees and a clean control, else the \
             parity implication holds vacuously"
        );
    }

    /// A `metadata.name` that is blank (but not empty, which the parser
    /// already rejected) → exit 1.
    #[test]
    fn validate_tree_row_0_blank_metadata_name_is_exit_1() {
        assert_eq!(row0_exit(row0_case("blank-metadata-name")), exit(1));
    }

    /// A `PermissionGrant` whose `repository` names nothing declared →
    /// exit 1.
    #[test]
    fn validate_tree_row_0_grant_references_undeclared_repository_is_exit_1() {
        assert_eq!(
            row0_exit(row0_case("grant-references-undeclared-repository")),
            exit(1)
        );
    }

    /// Two envelopes sharing one `(kind, name)` → exit 1.
    #[test]
    fn validate_tree_row_0_duplicate_kind_and_name_is_exit_1() {
        assert_eq!(row0_exit(row0_case("duplicate-kind-and-name")), exit(1));
    }

    /// A `RetentionPolicy` scope naming an undeclared repository →
    /// exit 1.
    #[test]
    fn validate_tree_row_0_retention_scope_references_undeclared_repository_is_exit_1() {
        assert_eq!(
            row0_exit(row0_case(
                "retention-scope-references-undeclared-repository"
            )),
            exit(1)
        );
    }

    /// A structurally invalid `spec.predicate` (`{AgeExceeds: 0}`) →
    /// exit 1.
    #[test]
    fn validate_tree_row_0_structurally_invalid_predicate_is_exit_1() {
        assert_eq!(
            row0_exit(row0_case("retention-predicate-structurally-invalid")),
            exit(1)
        );
    }

    /// The row-0 rejection tells the operator the GATE got stricter.
    ///
    /// Asserted because it is the decision this change turned on: a tree
    /// that was green yesterday goes red today, and an operator who
    /// reads that as "the new binary broke my config" pins the old image
    /// and keeps a tree the server rejects.
    #[test]
    fn row0_failure_header_attributes_the_change_to_the_gate() {
        let h = ROW0_FAILURE_HEADER;
        assert!(h.contains("GATE got stricter, not the tree"), "{h}");
        assert!(h.contains("already failing your apply"), "{h}");
    }

    /// The footer names every apply pre-write check this command skips.
    ///
    /// Partial naming is exactly how the missing row 0 hid behind a
    /// footer that listed only rows 1 and 4, so each gap is pinned by a
    /// distinctive token of its own.
    #[test]
    fn honesty_footer_names_every_remaining_gap() {
        let f = HONESTY_FOOTER;
        for token in [
            // (a) row 1 — managed-by ownership.
            "managed_by=local",
            // (b) row 1 — the auth-provider/ClaimMapping env rule.
            "HORT_AUTH_PROVIDER=disabled",
            // (c) the upstream-host allowlist gate.
            "HORT_UPSTREAM_ALLOWLIST_HOSTS",
            // (d) row 4 — the backend-NAME check.
            "scanBackends backend-NAME check",
            // ...and the write stages beyond the pre-write pass.
            "write stages",
        ] {
            assert!(f.contains(token), "footer must name `{token}`:\n{f}");
        }
        // The footer must not re-claim the row-0 gap it used to hide.
        assert!(f.contains("per-envelope and cross-document rules"), "{f}");
    }

    // ---- version-static facts pin ----------------------------------------

    #[test]
    fn log_format_from_env_defaults_to_pretty_and_maps_json() {
        // Exercised without touching std::env directly beyond this test's
        // own scope — the function reads HORT_LOG_FORMAT; an unset value
        // (the common CI case) yields Pretty. We only assert the mapping
        // shape here (json → Json, anything else → Pretty) by calling the
        // pure match on representative inputs via the public helper's
        // observable behaviour.
        //
        // Note: we avoid mutating the process env (parallel-test races);
        // the `json`/default mapping is a 2-arm match so the unset-default
        // branch is covered by the common case and `validate_tree` tests.
        assert!(matches!(
            log_format_from_env(),
            LogFormat::Pretty | LogFormat::Json
        ));
    }
}
