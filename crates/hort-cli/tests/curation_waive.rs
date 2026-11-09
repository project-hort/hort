//! Integration tests for `hort-cli curation waive` — all three
//! addressing modes.
//!
//! The mockito pattern this crate's `tests/` share (see
//! `tests/admin_quarantine_list.rs`) plus, for the bulk modes, the two
//! properties the wire contract turns on: the request body a digest list
//! produces, and the two answers an all-or-nothing batch can get
//! (`200` applied / `409` aborted, the latter carrying the report and
//! exiting non-zero without releasing anything).

use std::process::ExitCode;
use std::sync::Mutex;

use mockito::{Matcher, Server};

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::waive::{
    run, run_artifact_with_output, run_digests_with_output, run_versions_with_output, WaiveArgs,
    WaiveArtifactArgs, WaiveCommand, WaiveDigestsArgs, WaiveVersionsArgs, WAIVE_ABORTED_EXIT,
};

// ---------------------------------------------------------------------------
// Shared helpers (the shape every `tests/` file in this crate uses)
// ---------------------------------------------------------------------------

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

fn test_client(server_url: &str) -> AkClient {
    let cfg = EffectiveConfig {
        server: url::Url::parse(server_url).expect("valid url"),
        token: "test-token".to_string(),
        default_format: OutputFormat::Table,
    };
    AkClient::new(&cfg).expect("client builds")
}

fn code(c: &ExitCode) -> String {
    format!("{c:?}")
}

const ARTIFACT_ID: &str = "11111111-1111-1111-1111-111111111111";
const ARTIFACT_B: &str = "22222222-2222-2222-2222-222222222222";
const CORRELATION_ID: &str = "33333333-3333-3333-3333-333333333333";
const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const VERSIONS_ROUTE: &str = "/api/v1/admin/curation/waive-versions";
const DIGESTS_ROUTE: &str = "/api/v1/admin/curation/waive-digests";

/// A `200` body with one fresh release and one converged entry — the
/// pair the table has to keep distinguishable.
fn applied_envelope() -> String {
    format!(
        r#"{{
            "correlation_id": "{CORRELATION_ID}",
            "released_artifact_ids": ["{ARTIFACT_ID}"],
            "already_released_ids": ["{ARTIFACT_B}"],
            "failed": []
        }}"#
    )
}

/// A `409` body: one fine entry and one the resolver could not match.
fn abort_envelope() -> String {
    format!(
        r#"{{
            "outcome": "aborted",
            "entries": [
              {{"key": "1.0.0", "artifact_id": "{ARTIFACT_ID}", "verdict": "releasable"}},
              {{"key": "9.9.9", "verdict": "unresolvable"}}
            ]
        }}"#
    )
}

// ===========================================================================
// `waive artifact` — the four scenarios the flat form used to carry
// ===========================================================================

#[tokio::test]
async fn waive_artifact_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(200)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "CVE-2026-0001 false-positive".to_string(),
    };

    let mut buf = Vec::new();
    let exit = run_artifact_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("waive succeeds");
    m.assert_async().await;

    assert_eq!(code(&exit), code(&ExitCode::SUCCESS));
    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("waived artifact"), "table label: {out}");
    assert!(out.contains(ARTIFACT_ID), "artifact id present: {out}");
}

#[tokio::test]
async fn waive_artifact_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .with_status(200)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_artifact_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("waive succeeds in JSON mode");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    let id = parsed
        .as_object()
        .expect("top-level object")
        .get("waived_artifact_id")
        .expect("waived_artifact_id field")
        .as_str()
        .expect("string");
    assert_eq!(id, ARTIFACT_ID);
}

#[tokio::test]
async fn waive_artifact_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let result = run_artifact_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("Forbidden") || err.contains("forbidden"),
        "error references 403: {err}"
    );
}

#[tokio::test]
async fn waive_artifact_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let oversize = "a".repeat(513);
    let client = test_client(&server.url());
    let args = WaiveArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: oversize,
    };

    let mut buf = Vec::new();
    let result = run_artifact_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(
        result.is_err(),
        "> 512-byte justification must return Err BEFORE the HTTP call"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("512") || err.contains("exceeds") || err.contains("justification"),
        "error references the cap: {err}"
    );
    m.assert_async().await;
}

// ===========================================================================
// `waive versions` — the version-addressed batch
// ===========================================================================

#[tokio::test]
async fn waive_versions_applied_table_separates_fresh_from_converged() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", VERSIONS_ROUTE)
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::Json(serde_json::json!({
            "repository": "npm-proxy",
            "package": "left-pad",
            "versions": ["1.0.0", "1.0.1"],
            "justification": "reviewed, risk accepted"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(applied_envelope())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "left-pad".to_string(),
        versions: vec!["1.0.0".to_string(), "1.0.1".to_string()],
        justification: "reviewed, risk accepted".to_string(),
    };

    let mut buf = Vec::new();
    let exit = run_versions_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("an applied batch is not an error");
    m.assert_async().await;

    assert_eq!(code(&exit), code(&ExitCode::SUCCESS));
    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains(CORRELATION_ID), "{out}");
    assert!(
        out.contains("RELEASED (1) — released by this call"),
        "the fresh release says it happened now: {out}"
    );
    assert!(
        out.contains("ALREADY_RELEASED (1) — already Released before this call"),
        "the converged entry says it happened earlier: {out}"
    );
}

#[tokio::test]
async fn waive_versions_json_is_the_servers_envelope() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", VERSIONS_ROUTE)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(applied_envelope())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "left-pad".to_string(),
        versions: vec!["1.0.0".to_string()],
        justification: "reviewed".to_string(),
    };

    let mut buf = Vec::new();
    run_versions_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("succeeds");

    let out = String::from_utf8(buf).expect("utf8");
    let got: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    let sent: serde_json::Value = serde_json::from_str(&applied_envelope()).expect("fixture");
    assert_eq!(got, sent, "the envelope passes through verbatim");
}

#[tokio::test]
async fn waive_versions_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", VERSIONS_ROUTE)
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "left-pad".to_string(),
        versions: vec!["1.0.0".to_string()],
        justification: "reviewed".to_string(),
    };

    let mut buf = Vec::new();
    let result = run_versions_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(
        result.is_err(),
        "a refusal that is not the report is an Err"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("403"), "surfaces the status verbatim: {err}");
}

// ===========================================================================
// `waive digests` — the digest-addressed batch
// ===========================================================================

/// The acceptance criterion: the two spellings of one digest put the
/// same bytes on the wire. `match_body` is what proves it — the mock
/// only answers a request whose `digests` array is the bare form, so a
/// CLI that forwarded the `sha256:` prefix would get no match and the
/// `assert_async` would fail.
#[tokio::test]
async fn a_prefixed_and_a_bare_digest_list_send_the_same_body() {
    {
        let _g = lock_env();
        clear_env();
    }

    for spelling in [DIGEST.to_string(), format!("sha256:{DIGEST}")] {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", DIGESTS_ROUTE)
            .match_body(Matcher::Json(serde_json::json!({
                "repository": "oci-proxy",
                "digests": [DIGEST],
                "justification": "reviewed the bytes"
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(applied_envelope())
            .create_async()
            .await;

        let client = test_client(&server.url());
        let args = WaiveDigestsArgs {
            repository: "oci-proxy".to_string(),
            digests: vec![spelling.clone()],
            justification: "reviewed the bytes".to_string(),
        };

        let mut buf = Vec::new();
        run_digests_with_output(client, args, OutputFormat::Table, &mut buf)
            .await
            .unwrap_or_else(|e| panic!("{spelling} succeeds: {e}"));
        m.assert_async().await;
    }
}

/// An aborted batch is not an error to surface — it is a report to
/// print, and an exit code a script can branch on. Nothing was
/// released, and the table says so first.
#[tokio::test]
async fn waive_digests_abort_prints_the_report_and_exits_nonzero() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", DIGESTS_ROUTE)
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(abort_envelope())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveDigestsArgs {
        repository: "oci-proxy".to_string(),
        digests: vec![DIGEST.to_string()],
        justification: "reviewed the bytes".to_string(),
    };

    let mut buf = Vec::new();
    let exit = run_digests_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("the report is an answer, not a transport failure");
    m.assert_async().await;

    assert_eq!(
        code(&exit),
        code(&ExitCode::from(WAIVE_ABORTED_EXIT)),
        "an aborted batch has its own exit code"
    );
    let out = String::from_utf8(buf).expect("utf8");
    assert!(
        out.contains("BATCH ABORTED — nothing was released."),
        "leads with the fact no release happened: {out}"
    );
    assert!(
        out.contains("1 of 2 entries cannot be released"),
        "counts only the blocking entry: {out}"
    );
    assert!(out.contains("9.9.9"), "names the blocking entry: {out}");
    assert!(
        out.contains("1.0.0"),
        "and the fine one, so the curator need not bisect: {out}"
    );
}

#[tokio::test]
async fn waive_digests_abort_json_is_the_servers_report() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", DIGESTS_ROUTE)
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(abort_envelope())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveDigestsArgs {
        repository: "oci-proxy".to_string(),
        digests: vec![DIGEST.to_string()],
        justification: "reviewed the bytes".to_string(),
    };

    let mut buf = Vec::new();
    let exit = run_digests_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("the report is an answer");
    assert_eq!(code(&exit), code(&ExitCode::from(WAIVE_ABORTED_EXIT)));

    let out = String::from_utf8(buf).expect("utf8");
    let got: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    let sent: serde_json::Value = serde_json::from_str(&abort_envelope()).expect("fixture");
    assert_eq!(got, sent, "the report passes through verbatim");
}

/// A `sha512:` digest is a request written wrongly. The CLI refuses it
/// before the round trip — `expect(0)` is what proves the server was
/// never asked.
#[tokio::test]
async fn waive_digests_wrong_algorithm_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", DIGESTS_ROUTE)
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveDigestsArgs {
        repository: "oci-proxy".to_string(),
        digests: vec![format!("sha512:{}", "a".repeat(128))],
        justification: "reviewed the bytes".to_string(),
    };

    let mut buf = Vec::new();
    let result = run_digests_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "refused before the HTTP call");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported algorithm prefix"),
        "names the cause: {err}"
    );
    m.assert_async().await;
}

// ===========================================================================
// The removed flat form, through the real dispatcher
// ===========================================================================

/// `curation waive <artifact_id>` reaches the dispatcher as the
/// catch-all arm, and the dispatcher answers with the replacement
/// command rather than a bare clap error. Nothing is sent: `expect(0)`
/// on every route of the mock server proves the message is produced
/// before any request could be.
#[tokio::test]
async fn the_removed_flat_form_answers_with_its_replacement_and_calls_nothing() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", Matcher::Any)
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArgs {
        cmd: WaiveCommand::Removed(vec![
            ARTIFACT_ID.to_string(),
            "--justification".to_string(),
            "risk accepted".to_string(),
        ]),
    };

    let result = run(client, args, OutputFormat::Table).await;
    assert!(result.is_err(), "the removed form does not run");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("was removed"), "says it went away: {err}");
    assert!(
        err.contains(&format!("curation waive artifact {ARTIFACT_ID}")),
        "names the replacement with the operator's own id: {err}"
    );
    m.assert_async().await;
}

/// An empty list is refused client-side, before the round trip — the
/// same gate `block versions` carries. Reachable through the library
/// entry point even though clap's `required = true` keeps the CLI from
/// producing it.
#[tokio::test]
async fn waive_versions_empty_list_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", VERSIONS_ROUTE)
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "left-pad".to_string(),
        versions: vec![],
        justification: "reviewed".to_string(),
    };

    let mut buf = Vec::new();
    let result = run_versions_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "refused before the HTTP call");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("--versions"), "names the flag: {err}");
    m.assert_async().await;
}
