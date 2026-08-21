//! `hort-cli completions <shell>` — shell completion generation.
//! Static structure (subcommands/flags/enums) for all shells via
//! [`run`]; the dynamic, server-aware repo-name value provider
//! ([`repo_arg_candidates`]) is wired into the clap engine in `main`.

use clap::CommandFactory;
use clap_complete::engine::{ArgValueCandidates, CompletionCandidate};
use clap_complete::Shell;
use std::time::Duration;

use crate::Cli;

// ---------------------------------------------------------------------------
// TAB-time completion helpers — repo key fetch
// ---------------------------------------------------------------------------

/// Hard timeout for completion network calls — TAB must feel instant.
const COMPLETION_TIMEOUT: Duration = Duration::from_millis(300);

#[derive(serde::Deserialize)]
struct RepoSummary {
    key: String,
}

#[derive(serde::Deserialize)]
struct RepositoriesList {
    repositories: Vec<RepoSummary>,
}

/// Fetch visible repo keys from `base_url`. Fail-closed to empty: any error
/// (network, non-2xx, timeout, parse) returns `vec![]`. Never panics, never
/// prompts; read-only on auth state (token used as-is, no refresh).
async fn fetch_repo_keys_from(base_url: &str, token: Option<&str>) -> Vec<String> {
    let url = format!("{}/api/v1/repositories", base_url.trim_end_matches('/'));
    let Ok(builder) = crate::client::apply_extra_ca_bundle(
        reqwest::Client::builder().timeout(COMPLETION_TIMEOUT),
    ) else {
        return Vec::new();
    };
    let Ok(client) = builder.build() else {
        return Vec::new();
    };
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    match resp.json::<RepositoriesList>().await {
        Ok(body) => body.repositories.into_iter().map(|r| r.key).collect(),
        Err(_) => Vec::new(),
    }
}

/// Synchronous entry point for the clap completer: load the stored
/// session (no prompt, no refresh), run the timed fetch on a throwaway
/// runtime. Returns `vec![]` on any failure.
///
/// Consumed by [`repo_arg_candidates`], which is the value provider
/// attached to every repo-key argument.
pub(crate) fn complete_repo_keys() -> Vec<String> {
    let Ok(cfg) = crate::config::load_effective_config(None, None) else {
        return Vec::new();
    };
    // cfg.server is a `url::Url`; convert to an owned String for the fetch helper.
    let base_url = cfg.server.as_str().to_owned();
    let token = cfg.token;
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    rt.block_on(fetch_repo_keys_from(&base_url, Some(&token)))
}

// ---------------------------------------------------------------------------
// Dynamic value provider (clap_complete unstable-dynamic engine)
// ---------------------------------------------------------------------------

/// clap value-candidates provider for repository-key args. Attach with
/// `#[arg(add = crate::completions::repo_arg_candidates())]`.
///
/// At TAB-time the dynamic engine ([`clap_complete::engine`], driven by
/// [`clap_complete::env::CompleteEnv`] in `main`) invokes this closure to
/// list the caller's visible repository keys. The closure is **panic-free
/// by contract** — a panic here would abort the completion subprocess and
/// break the user's shell line. [`complete_repo_keys`] is fail-closed to an
/// empty `Vec` on every error path (no config, network failure, non-2xx,
/// timeout, parse error), so the worst case is "no dynamic suggestions",
/// never a panic.
pub fn repo_arg_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        complete_repo_keys()
            .into_iter()
            .map(CompletionCandidate::new)
            .collect::<Vec<_>>()
    })
}

/// `completions <shell>` arguments.
#[derive(clap::Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Print the **static** (AOT) completion script for `shell` to stdout.
///
/// # Two completion paths
///
/// `hort-cli` ships two complementary completion mechanisms:
///
/// 1. **Static / AOT** (this function): `hort-cli completions <shell>` emits
///    a self-contained script describing the command tree, flags, and enum
///    values. It needs no running `hort-cli` at TAB-time and works on every
///    shell `clap_complete` supports (bash/zsh/fish/powershell/elvish). This
///    is the **floor** — it always works, but it cannot offer live
///    repository-key suggestions.
///
/// 2. **Dynamic** ([`repo_arg_candidates`] + [`clap_complete::env::CompleteEnv`]
///    wired in `main`): activated by sourcing `COMPLETE=<shell> hort-cli`
///    (e.g. `source <(COMPLETE=bash hort-cli)`). At TAB-time the shell
///    re-invokes `hort-cli` with the `COMPLETE` env var set; the engine then
///    calls back into the running binary, so repo-key args are completed with
///    the caller's *live* visible repository keys. The dynamic engine is
///    wired for bash/zsh/fish; powershell/elvish get static completion only.
///
/// Operators who want live repo-key completion use path 2; path 1 remains the
/// always-available fallback (and is what older shells / locked-down
/// environments rely on).
///
/// Generates into an in-memory buffer rather than writing straight to
/// `io::stdout()`: `clap_complete::generate` takes a plain `&mut dyn
/// io::Write` with no error return, so a closed pipe (`| head`) surfacing
/// mid-generation would panic inside `clap_complete`, outside this crate's
/// control. Buffering first lets the single write to stdout go through
/// `hort_attribution::write_stdout_or_exit`, which exits cleanly instead.
pub fn run(args: &CompletionsArgs) -> std::process::ExitCode {
    run_to(&mut std::io::stdout(), args)
}

/// Generic-sink form of [`run`]: same generate-then-write behaviour against
/// any [`std::io::Write`], so tests can assert on the written script's
/// content instead of dumping the full generated completion script — which
/// grows with every subcommand added, unlike the licence texts — to the
/// real stdout on every test run.
fn run_to<W: std::io::Write>(w: &mut W, args: &CompletionsArgs) -> std::process::ExitCode {
    let mut cmd = Cli::command();
    let mut buf = Vec::new();
    clap_complete::generate(args.shell, &mut cmd, "hort-cli", &mut buf);
    let script = String::from_utf8(buf).expect("clap_complete output is valid UTF-8");
    hort_attribution::write_to_or_exit(w, &script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_complete::generate;

    fn script_for(shell: Shell) -> String {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(shell, &mut cmd, "hort-cli", &mut buf);
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn bash_script_mentions_known_subcommands() {
        let s = script_for(Shell::Bash);
        assert!(!s.is_empty(), "completion script must not be empty");
        assert!(s.contains("list-versions"), "must complete list-versions");
        assert!(s.contains("admin"), "must complete admin");
    }

    #[test]
    fn zsh_and_fish_generate_nonempty() {
        assert!(!script_for(Shell::Zsh).is_empty());
        assert!(!script_for(Shell::Fish).is_empty());
    }

    #[test]
    fn run_generates_and_writes_completion_script_successfully() {
        // Exercises the buffer-then-write path in `run` itself (the
        // `script_for` helper above duplicates the `generate` call but
        // never invokes `run`, so this is the only test that covers it).
        let mut buf: Vec<u8> = Vec::new();
        let code = run_to(&mut buf, &CompletionsArgs { shell: Shell::Bash });
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", std::process::ExitCode::SUCCESS)
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.is_empty(), "completion script must not be empty");
        assert!(out.contains("list-versions"), "must complete list-versions");
    }

    #[tokio::test]
    async fn fetch_repo_keys_returns_keys_on_200() {
        let mut srv = mockito::Server::new_async().await;
        let m = srv
            .mock("GET", "/api/v1/repositories")
            .with_status(200)
            .with_body(
                r#"{"repositories":[{"key":"npm-internal","format":"npm","kind":"hosted"},{"key":"pypi-proxy","format":"pypi","kind":"proxy"}],"total":2}"#,
            )
            .create_async()
            .await;
        let keys = fetch_repo_keys_from(&srv.url(), Some("test-token")).await;
        m.assert_async().await;
        assert_eq!(
            keys,
            vec!["npm-internal".to_string(), "pypi-proxy".to_string()]
        );
    }

    #[tokio::test]
    async fn fetch_repo_keys_empty_on_5xx() {
        let mut srv = mockito::Server::new_async().await;
        let _m = srv
            .mock("GET", "/api/v1/repositories")
            .with_status(500)
            .create_async()
            .await;
        assert!(fetch_repo_keys_from(&srv.url(), Some("test-token"))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn fetch_repo_keys_empty_on_garbage_body() {
        let mut srv = mockito::Server::new_async().await;
        let _m = srv
            .mock("GET", "/api/v1/repositories")
            .with_status(200)
            .with_body("not json")
            .create_async()
            .await;
        assert!(fetch_repo_keys_from(&srv.url(), Some("test-token"))
            .await
            .is_empty());
    }
}
