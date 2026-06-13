//! The alpha auth fixtures clear the REAL `ApplyConfigUseCase`
//! permission-grant linter (apply-time linting, ADR 0015).
//!
//! The `*_jwt_only.rs` integration tests use `build_mock_ctx` +
//! a hand-built `RbacEvaluator`, which bypasses the apply-time linter
//! entirely — that mock-vs-real gap hid BOTH the original CLI-session ×
//! claim-grant footgun (ADR 0013) AND the separate lint-axis defect
//! where the alpha fixtures were single-claim ([developer]) +
//! wildcard-repo (global) grants that the grant linter rejects TWICE
//! (`single-claim-grant` AND `wildcard-repo-non-admin`, both `reject`
//! by secure default — `LintConfig::default`).
//!
//! The fixtures were reshaped to ≥2-claim + per-repo (mirroring
//! `deploy/compose/example-config/auth/dev-*-e2e.yaml`) so they clear both
//! rules WITHOUT downgrading `LintConfig` (downgrading would weaken the
//! secure-by-default linter to accommodate a malformed fixture). This
//! test runs the actual `hort_app::lint::lint_permission_grants` over the
//! parsed fixture tree with the DEFAULT (reject-posture) `LintConfig`
//! and asserts zero rejections — the regression guard that keeps the
//! reshape honest.
//!
//! Lives in `hort-server` (not `hort-config`) because it needs BOTH the
//! `hort-config` fixture loader AND the `hort-app` linter; `hort-config`
//! depends only on `hort-domain`, so it cannot reach the linter.
//!
//! No DB required: the linter is pure over its inputs. Repository names
//! are mapped to synthetic UUIDs (the linter only distinguishes
//! `repository_id IS NULL` from `Some(_)` — it never resolves the id),
//! so no `repositories` port is needed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use hort_app::lint::{lint_permission_grants, LintConfig};
use hort_config::permission_grant::GrantSubjectSpec;
use hort_config::DesiredState;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use uuid::Uuid;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for hort-server is `<root>/crates/hort-server`;
    // pop twice to reach the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root reachable from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("read fixture dir") {
        let entry = entry.expect("read fixture entry");
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, out);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read fixture bytes");
        out.push((path, bytes));
    }
}

#[test]
fn alpha_auth_fixtures_clear_the_real_section_8_1_linter() {
    let root = workspace_root().join("scripts/alpha-fixtures/gitops-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    assert!(!files.is_empty(), "alpha-fixture tree should not be empty");

    let state = DesiredState::parse_files(files).unwrap_or_else(|errs| {
        panic!("alpha-fixture parse failed:\n{errs}");
    });

    // Map each declared `repository:` name to a stable synthetic UUID.
    // The linter only branches on `repository_id IS NULL` vs `Some(_)`;
    // it never resolves the id, so any non-nil id suffices.
    let mut repo_ids: HashMap<String, Uuid> = HashMap::new();

    // Convert every PermissionGrant envelope to the domain shape the
    // linter consumes — the SAME mapping `ApplyConfigUseCase` applies
    // (sorted `Claims`, `User(uuid)`, repo-name → id).
    let mut grants: Vec<PermissionGrant> = Vec::new();
    for env in &state.permission_grants {
        let permission = Permission::from_str(&env.spec.permission)
            .unwrap_or_else(|_| panic!("permission `{}` should parse", env.spec.permission));
        let repository_id = env.spec.repository.as_deref().map(|name| {
            *repo_ids
                .entry(name.to_string())
                .or_insert_with(Uuid::new_v4)
        });
        let subject = match &env.spec.subject {
            GrantSubjectSpec::Claims { required } => {
                let mut sorted = required.clone();
                sorted.sort();
                GrantSubject::Claims(sorted)
            }
            GrantSubjectSpec::User { user_id } => {
                GrantSubject::User(Uuid::parse_str(user_id.trim()).expect("valid uuid"))
            }
        };
        grants.push(PermissionGrant {
            id: Uuid::new_v4(),
            subject,
            repository_id,
            permission,
            created_at: chrono::Utc::now(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: None,
        });
    }

    // Claim mappings (for the `claim-name-collision` rule).
    let claim_mappings: Vec<ClaimMapping> = state
        .claim_mappings
        .iter()
        .map(|env| ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: env.spec.idp_group.clone(),
            claim: env.spec.claim.clone(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: None,
        })
        .collect();

    // The alpha fixtures declare no ServiceAccounts, so there
    // are no SA-owned (provenance-justified) direct-user grants — empty
    // exemption set.
    let sa_owned_user_ids: HashSet<Uuid> = HashSet::new();

    // The whole point: DEFAULT (secure-by-default reject posture)
    // LintConfig — NOT a downgraded one. A downgrade would mask a
    // malformed fixture; the reshape must clear the linter on its own.
    let outcome = lint_permission_grants(
        &grants,
        &claim_mappings,
        &sa_owned_user_ids,
        &LintConfig::default(),
    );

    assert!(
        !outcome.rejected(),
        "alpha auth fixtures must clear the grant linter with the DEFAULT \
         (reject-posture) LintConfig — do NOT downgrade LintConfig to \
         accommodate a malformed fixture. Violations: {:#?}",
        outcome.violations
    );

    // Sanity: we actually exercised the linter over the reshaped grants
    // (≥2-claim + per-repo). If this is zero the fixture tree lost its
    // PermissionGrants and the assertion above is vacuous.
    assert!(
        grants.len() >= 6,
        "expected the reshaped per-repo Read+Prefetch grants (≥6), got {}",
        grants.len()
    );
    // And every claim-subject grant is multi-claim + repo-scoped (the
    // two properties the reshape established).
    for g in &grants {
        if let GrantSubject::Claims(required) = &g.subject {
            assert!(
                required.len() >= 2,
                "reshaped claim grants must be ≥2-claim, got {required:?}"
            );
            assert!(
                g.repository_id.is_some(),
                "reshaped claim grants must be repo-scoped (not wildcard)"
            );
        }
    }
}
