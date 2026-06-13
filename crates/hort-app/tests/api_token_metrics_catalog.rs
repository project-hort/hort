//! API-token / auth-surface metrics — catalog discipline check.
//!
//! The token-issuance, token-validation, and OCI `/v2/auth` pipelines
//! emit seven metrics:
//!
//! 1. `hort_api_token_issued_total{kind, result}`
//! 2. `hort_api_token_revoked_total{actor_kind}`
//! 3. `hort_api_token_validation_total{result, cache}`
//! 4. `hort_api_token_validation_duration_seconds{result}`
//! 5. `hort_oci_v2_auth_total{result}`
//! 6. `hort_oci_v2_auth_scope_actions_granted_total{action}`
//! 7. `hort_unsafe_config_active{kind}`
//!
//! This integration test parses `docs/metrics-catalog.md` and asserts
//! every name above is mentioned in a metric-table row. The catalog
//! is the single source of truth for the metric vocabulary (ADR 0017);
//! the discipline rule (top of the catalog: "No new metric name or
//! label value may be emitted without updating it") is enforced for
//! these metrics by this test.
//!
//! ## Why an integration test, not a unit test
//!
//! The catalog file lives at the workspace root, not under
//! `crates/hort-app`. A unit test inside `hort-app` would need a
//! workspace-relative file lookup that already lives in the
//! `tests/no_bcrypt.rs` integration suite — putting this test
//! alongside that one keeps the "find the catalog from
//! `CARGO_MANIFEST_DIR`" idiom in one place. Integration tests also
//! run later in CI, which is fine for a doc-discipline check; the
//! lib-test budget stays on use-case tests where it matters.
//!
//! ## What "mentioned" means
//!
//! The metric name must appear as a backticked literal somewhere in
//! the catalog (`` `hort_api_token_issued_total` ``). The catalog
//! conventionally puts every metric in a markdown table cell wrapped
//! in backticks, so `contains("\`<name>\`")` is sufficient. The test
//! does NOT validate label sets or `result` enums — that's the job of
//! the use-case-side DebuggingRecorder tests (the closed-taxonomy
//! `*_label` helpers in the use cases pin those, and the
//! cardinality-discipline tests assert the wire form).

use std::fs;
use std::path::PathBuf;

/// Locate the workspace root from `CARGO_MANIFEST_DIR`. The crate's
/// manifest dir is `<root>/crates/hort-app`; the root is two levels up.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .and_then(std::path::Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// Read the catalog file. Fails fast with a descriptive error so a
/// missing / renamed catalog is obvious in CI output.
fn read_catalog() -> String {
    let path = workspace_root().join("docs").join("metrics-catalog.md");
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read metrics catalog at {}: {}",
            path.display(),
            e
        )
    })
}

/// Every metric the API-token / auth-surface pipelines emit. Closed
/// list — adding a new metric to these pipelines requires editing
/// this constant in the same commit that emits it.
const API_TOKEN_METRICS: &[&str] = &[
    "hort_api_token_issued_total",
    "hort_api_token_revoked_total",
    "hort_api_token_validation_total",
    "hort_api_token_validation_duration_seconds",
    "hort_oci_v2_auth_total",
    "hort_oci_v2_auth_scope_actions_granted_total",
    "hort_unsafe_config_active",
];

/// Which subsystem-keyed catalog section each metric's row must live
/// in. The section name is the exact `### ` heading text in
/// `docs/metrics-catalog.md` — a catalog restructure that renames a
/// heading must update this table in the same commit.
const METRIC_SECTIONS: &[(&str, &[&str])] = &[
    (
        "Native API token issuance + revocation",
        &[
            "hort_api_token_issued_total",
            "hort_api_token_revoked_total",
        ],
    ),
    (
        "Native API token validation",
        &[
            "hort_api_token_validation_total",
            "hort_api_token_validation_duration_seconds",
        ],
    ),
    (
        "OCI Distribution-Spec /v2/auth token exchange",
        &[
            "hort_oci_v2_auth_total",
            "hort_oci_v2_auth_scope_actions_granted_total",
        ],
    ),
    ("Unsafe config opt-ins", &["hort_unsafe_config_active"]),
];

#[test]
fn every_api_token_metric_is_in_the_catalog() {
    let catalog = read_catalog();
    let mut missing = Vec::new();
    for name in API_TOKEN_METRICS {
        // The convention in the catalog is backticked metric names in
        // the table rows. We require the backticked literal so a stray
        // mention in a paragraph (which would not be a real catalog
        // row) does not satisfy the discipline check.
        let needle = format!("`{name}`");
        if !catalog.contains(&needle) {
            missing.push(*name);
        }
    }
    assert!(
        missing.is_empty(),
        "API-token metrics missing from docs/metrics-catalog.md: {missing:?}.\n\
         Add a row in the appropriate `### …` section before merging."
    );
}

#[test]
fn api_token_metrics_appear_inside_their_named_section() {
    // Belt-and-braces: the metric must not just exist in the catalog,
    // it must live inside the catalog section that owns it. This
    // catches accidental cross-pollination — e.g. someone renames an
    // unrelated metric to `hort_api_token_validation_total` and the
    // bare name check would be satisfied by the wrong row.
    //
    // Strategy: split the catalog by `### ` headers, find the section
    // whose heading matches the expected name, and assert that
    // section's body contains the metric. This is per-metric (each
    // metric is pinned to its own section), strictly stronger than a
    // union check over all owning sections.
    let catalog = read_catalog();
    let mut failures = Vec::new();
    for (section_name, metrics) in METRIC_SECTIONS {
        let section_body: Option<&str> = catalog
            .split("### ")
            .find(|section| section.lines().next().is_some_and(|h| h == *section_name));
        let Some(body) = section_body else {
            failures.push(format!(
                "catalog section `### {section_name}` not found — \
                 update METRIC_SECTIONS if the heading was renamed"
            ));
            continue;
        };
        for name in *metrics {
            let needle = format!("`{name}`");
            if !body.contains(&needle) {
                failures.push(format!(
                    "metric `{name}` not inside catalog section `### {section_name}`"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "API-token metrics not inside their owning catalog section:\n{}\n\
         Either move the row under the named heading, or update this test \
         if a metric is now owned by a different section.",
        failures.join("\n")
    );
}

#[test]
fn api_token_metrics_have_documentation_links_to_emitting_function() {
    // Catalog discipline — each metric in the catalog mentions the
    // operation that emits it. Loosely interpreted: the owning
    // section text must reference the use-case file or function that
    // performs the emission, so an operator reading the catalog can
    // jump straight to the source code.
    //
    // We assert one well-known anchor per metric. The anchor is the
    // *file path* where the emit lives (or the use-case method name);
    // using a file path keeps this stable across refactors that
    // rename helpers but leave the file structure intact.
    let catalog = read_catalog();
    let expectations: &[(&str, &[&str])] = &[
        // (metric, list of acceptable anchors — at least one MUST appear)
        (
            "hort_api_token_issued_total",
            &["api_token_use_case.rs", "ApiTokenUseCase"],
        ),
        (
            "hort_api_token_revoked_total",
            &["api_token_use_case.rs", "ApiTokenUseCase::revoke"],
        ),
        (
            "hort_api_token_validation_total",
            &[
                "pat_validation_use_case.rs",
                "PatValidationUseCase::validate_pat",
            ],
        ),
        (
            "hort_api_token_validation_duration_seconds",
            &[
                "pat_validation_use_case.rs",
                "PatValidationUseCase::validate_pat",
            ],
        ),
        (
            "hort_oci_v2_auth_total",
            &[
                "oci_token_exchange_use_case.rs",
                "OciTokenExchangeUseCase::exchange",
            ],
        ),
        (
            "hort_oci_v2_auth_scope_actions_granted_total",
            &[
                "oci_token_exchange_use_case.rs",
                "OciTokenExchangeUseCase::exchange",
            ],
        ),
        (
            "hort_unsafe_config_active",
            &["emit_pat_over_http_signal", "hort-server::composition"],
        ),
    ];
    let mut failures = Vec::new();
    for (metric, anchors) in expectations {
        if !anchors.iter().any(|a| catalog.contains(a)) {
            failures.push(format!(
                "metric `{metric}` — none of {anchors:?} appear in the catalog"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "API-token catalog rows must link to the emitting code:\n{}",
        failures.join("\n")
    );
}
