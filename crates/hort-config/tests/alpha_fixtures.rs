//! Walk `scripts/alpha-fixtures/gitops-config/` and assert every
//! YAML parses + cross-validates against the gitops apply pipeline.
//!
//! Regression guard for the alpha-fixture tree: any future fixture
//! drift (schema rename, removed kind, dangling reference) fails this
//! test before the operator hits it at boot.
//!
//! Reaches outside the crate via `CARGO_MANIFEST_DIR` → workspace
//! root → `scripts/alpha-fixtures/gitops-config/`. No DB required.

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
fn alpha_fixtures_parse_and_cross_validate() {
    let root = workspace_root().join("scripts/alpha-fixtures/gitops-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    assert!(!files.is_empty(), "alpha-fixture tree should not be empty");

    let state = match DesiredState::parse_files(files) {
        Ok(state) => state,
        Err(errs) => panic!("alpha-fixture parse failed:\n{errs}"),
    };

    if let Err(errs) = state.validate() {
        panic!("alpha-fixture cross-validate failed:\n{errs}");
    }
}
