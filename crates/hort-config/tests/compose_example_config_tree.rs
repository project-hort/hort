//! Walk `deploy/compose/example-config/` and assert every YAML envelope
//! parses, validates (per-spec), and cross-references correctly.
//!
//! This is the tree the compose E2E stack mounts at `HORT_CONFIG_DIR` and
//! applies at boot, before the listener binds. A malformed or dangling
//! envelope there does not fail one scenario — it fails the boot, so every
//! scenario in the run reports against a stack that never came up, and the
//! diagnosis lives in a container log rather than in an assertion. The
//! sibling guard over `deploy/ansible/files/gitops/`
//! (`public_deploy_gitops_tree.rs`) does the same for the production-intended
//! tree; this one closes the same gap for the tree CI actually boots.
//!
//! Cross-kind FK checks performed here (tree-level, not apply-level) mirror
//! that sibling: upstream mappings, scoped scan policies and repository-scoped
//! permission grants must each name a repository the tree declares, and a
//! serviceAccount-subject grant must name a declared ServiceAccount. A
//! dangling reference is the failure mode a hand-edited fixture tree actually
//! produces — a repository renamed in one file and not the other.
//!
//! No database required: pure filesystem + parse.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hort_config::DesiredState;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this crate is `<root>/crates/hort-config`;
    // pop twice to reach the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root reachable from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("read example-config dir") {
        let entry = entry.expect("read example-config entry");
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, out);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read example-config bytes");
        out.push((path, bytes));
    }
}

#[test]
fn compose_example_config_tree_parses_and_cross_validates() {
    let root = workspace_root().join("deploy/compose/example-config");
    assert!(
        root.exists(),
        "compose example-config tree not found at {root:?} — is the workspace root correct?"
    );

    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "deploy/compose/example-config/ should not be empty"
    );

    let state = match DesiredState::parse_files(files) {
        Ok(state) => state,
        Err(errs) => panic!("compose example-config tree parse failed:\n{errs}"),
    };

    if let Err(errs) = state.validate() {
        panic!("compose example-config tree cross-validate failed:\n{errs}");
    }

    let declared_repos: HashSet<&str> = state
        .repositories
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for um in &state.upstream_mappings {
        assert!(
            declared_repos.contains(um.spec.repository.as_str()),
            "UpstreamMapping `{}` spec.repository `{}` does not match \
             any declared ArtifactRepository name (declared: {:?})",
            um.metadata.name,
            um.spec.repository,
            declared_repos,
        );
    }

    for sp in &state.scan_policies {
        if let Some(repo_ref) = sp.spec.scope.repository_name() {
            assert!(
                declared_repos.contains(repo_ref),
                "ScanPolicy `{}` spec.scope.repository `{}` does not match \
                 any declared ArtifactRepository name (declared: {:?})",
                sp.metadata.name,
                repo_ref,
                declared_repos,
            );
        }
    }

    for pg in &state.permission_grants {
        if let Some(repo_ref) = pg.spec.repository.as_ref() {
            assert!(
                declared_repos.contains(repo_ref.as_str()),
                "PermissionGrant `{}` spec.repository `{}` does not match \
                 any declared ArtifactRepository name (declared: {:?})",
                pg.metadata.name,
                repo_ref,
                declared_repos,
            );
        }
    }

    let declared_sas: HashSet<&str> = state
        .service_accounts
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();
    for pg in &state.permission_grants {
        if let hort_config::GrantSubjectSpec::ServiceAccount { name } = &pg.spec.subject {
            assert!(
                declared_sas.contains(name.as_str()),
                "PermissionGrant `{}` subject.name `{}` does not match \
                 any declared ServiceAccount name (declared: {:?})",
                pg.metadata.name,
                name,
                declared_sas,
            );
        }
    }
}

/// Every repository the publish-chain scenario addresses is declared, with
/// the posture that scenario's assertions depend on.
///
/// The scenario reads these from a running stack, so a drift here surfaces as
/// a confusing E2E failure ~two minutes into a compose run rather than as a
/// statement about the fixture. Both properties are load-bearing rather than
/// descriptive: a zero (permissive) window would leave nothing held for the
/// chain to race, and a public repository would have cargo resolve the index
/// anonymously — hort answers `auth-required: !isPublic`, and cargo attaches
/// its registry token only when that field says `true` — where a
/// held-visibility rule keyed on the caller's granted write authority can
/// never reach it.
#[test]
fn publish_chain_repository_keeps_a_real_window_and_stays_private() {
    let root = workspace_root().join("deploy/compose/example-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    let state = DesiredState::parse_files(files).expect("compose example-config parses");

    const CHAIN_REPO: &str = "hort-crates-chain-e2e";

    let repo = state
        .repositories
        .iter()
        .find(|r| r.metadata.name == CHAIN_REPO)
        .unwrap_or_else(|| {
            panic!("`{CHAIN_REPO}` must be declared — the publish-chain scenario publishes into it")
        });
    assert!(
        !repo.spec.is_public,
        "`{CHAIN_REPO}` must stay private: a public cargo repository advertises \
         `auth-required: false`, so cargo reads its index without credentials and the \
         write-authorized hold-read the publish chain depends on can never engage"
    );

    let policy = state
        .scan_policies
        .iter()
        .find(|p| p.spec.scope.repository_name() == Some(CHAIN_REPO))
        .unwrap_or_else(|| panic!("`{CHAIN_REPO}` must be in scope of a ScanPolicy"));
    let window = policy.spec.quarantine_duration.as_str();
    assert!(
        !window.is_empty() && window != "0s",
        "`{CHAIN_REPO}` must carry a real observation window (got {window:?}): a zero \
         duration is the permissive opt-out, which skips the quarantine step entirely — \
         the chain would then resolve siblings nothing was ever holding"
    );
}
