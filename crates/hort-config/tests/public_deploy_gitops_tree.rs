//! Walk `deploy/ansible/files/gitops/` and assert every YAML envelope
//! parses, validates (per-spec), and cross-references correctly.
//!
//! Covers the production-intended gitops tree for `registry.hort.rs`:
//! repositories, upstreams, policies, OIDC issuers, identity-only
//! ServiceAccounts, and the serviceAccount-subject PermissionGrants
//! that carry each SA's authority.
//!
//! Cross-kind FK checks performed here (tree-level, not apply-level):
//! - Every `ServiceAccount.federatedIdentities[].issuer` references a
//!   declared `OidcIssuer.metadata.name`.
//! - Every `UpstreamMapping.spec.repository` references a declared
//!   `ArtifactRepository.metadata.name`.
//! - Every `ScanPolicy` (scoped) `spec.scope.repository` references a
//!   declared `ArtifactRepository.metadata.name`.
//! - Every `PermissionGrant.spec.repository` (when set) references a
//!   declared `ArtifactRepository.metadata.name`.
//! - Every `PermissionGrant` serviceAccount subject references a
//!   declared `ServiceAccount.metadata.name`.
//!
//! Cross-kind FK checks that live in the apply use case (`hort-app`),
//! NOT duplicated here:
//! - SA issuer FK against a DB snapshot (the app layer's
//!   `validate_service_account_issuer_fk`). The tree-level check above
//!   is sufficient for the gitops fixture test — the apply-layer FK
//!   check is the runtime guarantee.
//!
//! No database required — pure filesystem + parse.

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
    for entry in std::fs::read_dir(dir).expect("read gitops dir") {
        let entry = entry.expect("read gitops entry");
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, out);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read gitops bytes");
        out.push((path, bytes));
    }
}

#[test]
fn public_deploy_gitops_tree_parses_and_cross_validates() {
    let root = workspace_root().join("deploy/ansible/files/gitops");
    assert!(
        root.exists(),
        "gitops tree not found at {root:?} — is the workspace root correct?"
    );

    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "deploy/ansible/files/gitops/ should not be empty"
    );

    // -- Parse all files -------------------------------------------------------
    let state = match DesiredState::parse_files(files) {
        Ok(state) => state,
        Err(errs) => panic!("public-deploy gitops-tree parse failed:\n{errs}"),
    };

    // -- Per-spec + duplicate-name + virtual-member validation -----------------
    if let Err(errs) = state.validate() {
        panic!("public-deploy gitops-tree cross-validate failed:\n{errs}");
    }

    // -- Tree-level FK: SA.issuer → declared OidcIssuer.name ------------------
    let declared_issuers: HashSet<&str> = state
        .oidc_issuers
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();
    for sa in &state.service_accounts {
        for (idx, fi) in sa.spec.federated_identities.iter().enumerate() {
            assert!(
                declared_issuers.contains(fi.issuer.as_str()),
                "ServiceAccount `{}` federatedIdentities[{idx}].issuer `{}` does not match \
                 any declared OidcIssuer name (declared: {:?})",
                sa.metadata.name,
                fi.issuer,
                declared_issuers,
            );
        }
    }

    // -- Tree-level FK: UpstreamMapping.repository → declared repo -------------
    let declared_repos: HashSet<&str> = state
        .repositories
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();
    // (Belt-and-suspenders for this tree; DesiredState::validate already checks
    //  this via push_upstream_mapping_reference_errors, but an explicit assert
    //  makes the intent readable.)
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

    // -- Tree-level FK: ScanPolicy (scoped) scope.repository → declared repo --
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

    // -- Tree-level FK: PermissionGrant.repository → declared repo -------------
    // (Belt-and-suspenders for this tree; DesiredState::validate already
    //  reports both grant references as DanglingReference errors, but the
    //  explicit asserts make the intent readable.)
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

    // -- Tree-level FK: PermissionGrant serviceAccount subject → declared SA --
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

    // -- Audit: no under-constrained SA identities (warn-not-error) -----------
    // Surface any under-constrained findings as test output (not a failure)
    // so an operator can see them on a test run without apply-time logs.
    use hort_config::service_account::detect_under_constrained_federated_identities;
    for sa in &state.service_accounts {
        let findings = detect_under_constrained_federated_identities(sa);
        for f in &findings {
            // Print but don't panic — operator may have accepted the risk.
            eprintln!("WARN under-constrained federated identity: {}", f.message);
        }
    }
}
