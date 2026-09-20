//! Every gitops tree this repository ships clears the offline
//! `validate-config` static linter.
//!
//! The trees are operator-facing: the alpha-fixture walk, the compose
//! e2e stack (and its `s3` overlay), and the Ansible-deployed dogfood
//! config. A rule that rejects one of them at apply parks a real
//! deployment not-ready at boot, so the regression has to be caught here
//! rather than in a runbook.
//!
//! Runs the **same** `StaticConfigValidator` the `hort-server
//! validate-config` CLI runs, built from the same compiled-in facts
//! (`TIER1_PROVENANCE_CAPABLE_FORMATS`, the handler registry's
//! `VersionDiscovery` declarations, the tree's own storage backend, the
//! secure-default grant `LintConfig`). Nothing is injected or stubbed,
//! so a new row reaches these trees by construction — the scanner
//! capability map's row 7c is the reason this guard exists, and a future
//! row needs no edit here to be covered.
//!
//! Lives in `hort-server` because it needs the `hort-config` loader, the
//! `hort-app` validator AND the composition root's capability sets;
//! `hort-config`'s own `alpha_fixtures` guard can reach only the first
//! (it depends on `hort-domain` alone, so the linter is out of its
//! sight).
//!
//! No DB required: the validator is pure over its inputs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hort_app::lint::{LintConfig, StaticConfigValidator};
use hort_app::storage_backend::EffectiveStorageBackend;
use hort_config::DesiredState;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for hort-server is `<root>/crates/hort-server`;
    // pop twice to reach the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root reachable from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Collect the tree the way the boot-path walker does: recursive, both
/// YAML extensions, hidden directories skipped (a Kubernetes ConfigMap
/// projection mounts its generation under `..data`).
fn collect_yaml_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("read config dir") {
        let entry = entry.expect("read config entry");
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_yaml_files(&path, out);
            continue;
        }
        let is_yaml = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"));
        if !is_yaml {
            continue;
        }
        out.push((
            path.clone(),
            std::fs::read(&path).expect("read config bytes"),
        ));
    }
}

/// The trees, with the storage backend the deployment that consumes each
/// one actually runs (row 7b compares the per-repo `storage.backend`
/// against it, so a wrong value here would be a false verdict rather
/// than a skipped check).
fn trees() -> Vec<(&'static str, EffectiveStorageBackend)> {
    vec![
        (
            "scripts/alpha-fixtures/gitops-config",
            EffectiveStorageBackend::Filesystem,
        ),
        (
            "deploy/compose/example-config",
            EffectiveStorageBackend::Filesystem,
        ),
        // The `s3` compose overlay sets `HORT_STORAGE_BACKEND=s3`; its
        // repositories deliberately omit the per-repo `storage:` block
        // and inherit it.
        ("deploy/compose/s3/config", EffectiveStorageBackend::S3),
        (
            "deploy/ansible/files/gitops",
            EffectiveStorageBackend::Filesystem,
        ),
    ]
}

/// The validator the offline CLI builds — same constructor, same
/// compiled-in facts, row 8 enabled at the secure default.
fn cli_validator(backend: EffectiveStorageBackend) -> StaticConfigValidator {
    let provenance_capable: HashSet<String> =
        hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS
            .iter()
            .copied()
            .map(String::from)
            .collect();
    StaticConfigValidator::new(
        Arc::new(provenance_capable),
        Arc::new(hort_server::format_capabilities::version_discovery_capable_formats()),
        Some(backend),
    )
    .with_grant_lint_base(LintConfig::default())
}

#[test]
fn every_shipped_gitops_tree_passes_the_static_linter() {
    for (rel, backend) in trees() {
        let root = workspace_root().join(rel);
        let mut files = Vec::new();
        collect_yaml_files(&root, &mut files);
        assert!(!files.is_empty(), "{rel}: tree should not be empty");

        let desired = DesiredState::parse_files(files)
            .unwrap_or_else(|errs| panic!("{rel}: parse / cross-validate failed:\n{errs}"));

        // Sanity: the corpus actually carries the surface the rows lint.
        // A tree that lost its repositories or policies would pass every
        // row vacuously.
        assert!(
            !desired.repositories.is_empty(),
            "{rel}: tree declares no ArtifactRepository"
        );

        let report = cli_validator(backend).validate(&desired);
        assert!(
            report.errors.is_empty(),
            "{rel}: shipped gitops tree must clear the static linter — \
             fix the tree, never the rule. Findings:\n{}",
            report
                .errors
                .iter()
                .map(|f| format!("  [{:?}] {}", f.rule, f.message))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// The host-test smokes do not ship a tree of their own: they copy
/// `deploy/compose/example-config` into a staging directory and drop one
/// extra `ScanPolicy` on top before restarting `hort-server`, so the
/// boot apply sees the union. Two of them
/// (`scripts/host-tests/test-vulnerability-scan.sh`,
/// `scripts/host-tests/test-rescanning.sh`) overlay a **global**
/// `scanBackends: [osv]`, which row 7c evaluates against every
/// repository in that tree with no policy of its own — a set that
/// happens to be all-SBOM-capable today and would park the whole smoke
/// stack at boot if a repository without a scoped policy were ever added
/// on a format `osv` cannot read.
#[test]
fn the_host_test_global_osv_overlay_still_validates_against_the_compose_tree() {
    let root = workspace_root().join("deploy/compose/example-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    // The exact envelope both scripts write into the staged `policies/`
    // directory, minus the per-script policy name.
    files.push((
        PathBuf::from("policies/host-test-overlay.yaml"),
        br#"
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: host-test-smoke-policy
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 0s
  requireApproval: false
  provenanceMode: off
  scanBackends:
    - osv
"#
        .to_vec(),
    ));
    let desired = DesiredState::parse_files(files).expect("staged overlay tree parses");
    let report = cli_validator(EffectiveStorageBackend::Filesystem).validate(&desired);
    assert!(
        report.errors.is_empty(),
        "the host-test overlay must still apply cleanly — a new example-config \
         repository on a non-SBOM format with no scoped ScanPolicy would break \
         the smokes at boot, not in this assertion's absence. Findings:\n{}",
        report
            .errors
            .iter()
            .map(|f| format!("  [{:?}] {}", f.rule, f.message))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// The guard above is only meaningful if the row it exists for can
/// actually fire on a tree of this shape. Re-run the alpha-fixture tree
/// with its global policy pushed back to the pre-split `[trivy, osv]`
/// and assert row 7c rejects it — so a future edit that neuters the row
/// cannot leave `every_shipped_gitops_tree_passes_the_static_linter`
/// passing for the wrong reason.
#[test]
fn the_alpha_tree_would_be_rejected_if_its_global_policy_named_osv_over_oci() {
    use hort_app::lint::LinterRule;

    let root = workspace_root().join("scripts/alpha-fixtures/gitops-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    let mut desired = DesiredState::parse_files(files).expect("alpha fixtures parse");

    let global = desired
        .scan_policies
        .iter_mut()
        .find(|env| matches!(env.spec.scope, hort_config::scope::ScopeSpec::Global))
        .expect("the alpha tree declares a global ScanPolicy");
    global.spec.scan_backends = vec!["trivy".to_string(), "osv".to_string()];

    // The per-repository policies still shield npm/PyPI/cargo, so the
    // only pairings left for the global policy are the OCI ones.
    let report = cli_validator(EffectiveStorageBackend::Filesystem).validate(&desired);
    let hits: Vec<&str> = report
        .errors
        .iter()
        .filter(|f| f.rule == LinterRule::ScanBackendCapability)
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "one finding per OCI repository the global policy reaches: {:?}",
        report.errors
    );
    for msg in hits {
        assert!(msg.contains("entry `osv`"), "{msg}");
        assert!(msg.contains("format `oci`"), "{msg}");
    }
}
