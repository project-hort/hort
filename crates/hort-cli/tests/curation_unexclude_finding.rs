//! Integration tests for `hort-cli curation unexclude-finding`.
//!
//! Eight scenarios mirror the mockito pattern:
//!
//! 1. `unexclude_finding_happy_path_table` — 204 No Content → table
//!    prints "removed exclusion <cve> from policy <id>", exit 0.
//! 2. `unexclude_finding_happy_path_json` — JSON synthesised envelope
//!    `{"removed_exclusion_cve":"...","policy_id":"..."}`.
//! 3. `unexclude_finding_rbac_403_returns_error` — 403 → Err.
//! 4. `unexclude_finding_oversize_justification_does_not_call_server`
//!    — 513-byte justification → CLI gate fires; ZERO HTTP calls.
//! 5. `unexclude_finding_without_exclusion_id_sends_the_pre_field_body`
//!    — the serialised body is matched byte-for-byte, so the optional
//!    field cannot reach a server that predates it, not even as `null`.
//! 6. `unexclude_finding_with_exclusion_id_sends_it_in_the_body` — the
//!    flag reaches the wire as the body's `exclusion_id`.
//! 7. `unexclude_finding_ambiguous_cve_names_the_candidates_and_the_flag`
//!    — the 409 the server renders becomes the command to run next.
//! 8. `unexclude_finding_unrecognised_409_still_surfaces` — a 409 that
//!    is not the ambiguity report reaches the operator verbatim.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::unexclude_finding::{run_with_output, UnexcludeFindingArgs};

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

const POLICY_ID: &str = "77777777-7777-7777-7777-777777777777";
const CVE: &str = "CVE-2026-9999";

// ---------------------------------------------------------------------------
// Test 1 — happy path table (204 No Content)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "false-positive reversed — re-arm CVE".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("unexclude-finding succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("removed"), "label present: {out}");
    assert!(out.contains(CVE), "cve present: {out}");
    assert!(out.contains(POLICY_ID), "policy id present: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — happy path JSON synthesised envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    let obj = parsed.as_object().expect("top-level object");
    assert_eq!(
        obj.get("removed_exclusion_cve")
            .and_then(|v| v.as_str())
            .unwrap(),
        CVE
    );
    assert_eq!(
        obj.get("policy_id").and_then(|v| v.as_str()).unwrap(),
        POLICY_ID
    );
}

// ---------------------------------------------------------------------------
// Test 3 — 403 → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("DELETE", route.as_str())
        .with_status(403)
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "403 must propagate");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("403") || err.contains("orbidden"));
}

// ---------------------------------------------------------------------------
// Test 4 — > 512-byte justification → CLI gate fires; no HTTP call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "a".repeat(513),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "CLI gate must fire before HTTP");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("512") || err.contains("exceeds"),
        "error references cap: {err}"
    );
    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Fixtures for the exclusion-id scenarios
// ---------------------------------------------------------------------------

const PATTERNED_ID: &str = "11111111-1111-1111-1111-111111111111";
const UNPATTERNED_ID: &str = "22222222-2222-2222-2222-222222222222";

/// The `409` the server renders for an ambiguous CVE, reproduced
/// member-for-member from `DomainError::AmbiguousExclusion`'s
/// structured-body early-return in `hort-http-core::error`. `hort-cli`
/// carries no dependency on that crate by design, so the shape is
/// mirrored here and the `Sync-required` marker on the command's DTO is
/// what pairs the two.
fn ambiguity_409_body() -> String {
    format!(
        r#"{{"error":"multiple exclusions match {CVE}; name one with exclusion_id","cve_id":"{CVE}","candidates":[{{"exclusion_id":"{PATTERNED_ID}","package_pattern":"pkg:npm/left-pad@*"}},{{"exclusion_id":"{UNPATTERNED_ID}","package_pattern":null}}]}}"#
    )
}

// ---------------------------------------------------------------------------
// Test 5 — no --exclusion-id → byte-identical to the pre-field body
// ---------------------------------------------------------------------------

/// `Matcher::Exact` and not `Matcher::Json`: the point is the bytes.
/// An `exclusion_id` serialised as `null` would be semantically the
/// same request and a different body, and a server that predates the
/// field is exactly the reader that cannot be asked to tolerate the
/// difference.
#[tokio::test]
async fn unexclude_finding_without_exclusion_id_sends_the_pre_field_body() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .match_body(mockito::Matcher::Exact(
            r#"{"reason":"re-arm the CVE"}"#.to_string(),
        ))
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "re-arm the CVE".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("unqualified removal still succeeds");
    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 6 — --exclusion-id reaches the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_with_exclusion_id_sends_it_in_the_body() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .match_body(mockito::Matcher::Exact(format!(
            r#"{{"reason":"re-arm the CVE","exclusion_id":"{PATTERNED_ID}"}}"#
        )))
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: Some(PATTERNED_ID.parse().expect("valid uuid")),
        justification: "re-arm the CVE".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("qualified removal succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("removed"), "success output unchanged: {out}");
}

// ---------------------------------------------------------------------------
// Test 7 — the ambiguity 409 becomes the next command, not a JSON dump
// ---------------------------------------------------------------------------

/// The gap this unit closes end to end: with two rows under one CVE the
/// server removes neither, and before this the operator was handed the
/// raw body with no flag able to use it.
#[tokio::test]
async fn unexclude_finding_ambiguous_cve_names_the_candidates_and_the_flag() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(ambiguity_409_body())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "re-arm the CVE".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    m.assert_async().await;

    let err = res
        .expect_err("an ambiguous CVE removes nothing")
        .to_string();
    assert!(
        err.contains(&format!("--exclusion-id {PATTERNED_ID}")),
        "first candidate is offered as the flag to repeat with: {err}"
    );
    assert!(
        err.contains(&format!("--exclusion-id {UNPATTERNED_ID}")),
        "second candidate is offered as the flag to repeat with: {err}"
    );
    assert!(
        err.contains("pkg:npm/left-pad@*") && err.contains("no package_pattern"),
        "each row carries what tells it from its sibling: {err}"
    );
    assert!(
        err.contains("nothing was removed"),
        "the operator is told the request had no effect: {err}"
    );
    // A raw dump of the body does not pass: the JSON punctuation the
    // server sent is gone, replaced by lines the operator can run.
    assert!(
        !err.contains(r#""candidates""#),
        "the body is rendered, not echoed: {err}"
    );
    // Nothing was printed to stdout — the ambiguity is an error path.
    assert!(buf.is_empty(), "no success output: {buf:?}");
}

// ---------------------------------------------------------------------------
// Test 8 — an unrecognised 409 is not swallowed by the renderer
// ---------------------------------------------------------------------------

/// The route's other 409 (event-store optimistic concurrency) carries
/// no candidates. A parser that did not match must leave what the
/// server said intact rather than replace it with a remedy naming
/// nothing.
#[tokio::test]
async fn unexclude_finding_unrecognised_409_still_surfaces() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("DELETE", route.as_str())
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"version conflict on stream"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        exclusion_id: None,
        justification: "re-arm the CVE".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    let err = res.expect_err("a 409 is still a refusal").to_string();
    assert!(
        err.contains("409") && err.contains("version conflict on stream"),
        "the server's own words reach the operator: {err}"
    );
    assert!(
        !err.contains("--exclusion-id"),
        "no remedy is invented for a body that named no candidates: {err}"
    );
}
