//! Every gitops tree this repository ships clears the offline
//! `validate-config` gate — row 0 (the per-envelope and cross-document
//! rules) and the static linter rows.
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
//! sight). `hort-config`'s per-tree guards
//! (`compose_example_config_tree`, `public_deploy_gitops_tree`) run
//! `DesiredState::validate()` — row 0 — and **cannot** reach a linter
//! row, because `hort-config` must not depend on `hort-app`. So a row
//! that rejects a shipped tree is green there and red only here; reading
//! those two as the tree's gate is how an OCI-scope row landed against
//! ten checked-in policies with the four-crate unit gate still green.
//!
//! # A rejection names the document
//!
//! A linter finding names the **envelope** that offends — a policy, a
//! repository — and an envelope name is not a path. Resolving it is the
//! search the next reader would otherwise repeat by hand, and
//! `DesiredState::source_files` already holds the `(kind, name) → path`
//! map, so [`render_findings`] does it: every finding prints with the
//! on-disk file of each envelope it names. [`declared_in`] is generic
//! over the rule set — it reads the backtick-quoted names out of the
//! rendered message — so a new row is covered with no edit here, which
//! is the same property the validator construction above has.
//!
//! # Every tree, not the first one that fails
//!
//! The walk collects per-tree failures and panics once at the end. A
//! panic inside the loop reports the first failing tree and leaves the
//! rest unexamined, which is at its worst exactly when it matters: one
//! rule typically rejects *several* trees, and a reader who fixes the
//! one named gets the next one on the following run.
//!
//! No DB required: the validator is pure over its inputs.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hort_app::lint::{LintConfig, LintFinding, StaticConfigValidator};
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

/// The on-disk files declaring the envelopes a finding's message names,
/// workspace-relative, sorted.
///
/// The message is the operator-facing string, and every row renders the
/// offending envelope's `metadata.name` inside backticks. So the names
/// are read back out of it rather than threaded through `LintFinding`:
/// that keeps this generic over all eighteen rows — a new row needs no
/// entry here — and it costs nothing a structured field would have
/// bought, because the rendered message is what a reader sees anyway.
///
/// Matched on the name across **every** kind, deliberately: a row-18
/// finding names both the policy and the repository whose `format` made
/// it OCI, and both documents are part of the operator's fix. The kind
/// is printed beside each path so a name two kinds share reads as two
/// entries rather than one ambiguous path.
///
/// A name that resolves to nothing contributes nothing — the message
/// still prints in full. That is the honest degradation: a row quoting
/// something that is not an envelope name (a field, a suggested value)
/// must not make the whole line disappear. What must not degrade
/// silently is the *useful* case, which is why
/// `the_mutated_tree_is_rejected_and_the_rejection_names_the_file`
/// asserts a real path comes back.
fn declared_in(desired: &DesiredState, finding: &LintFinding) -> Vec<String> {
    // Backtick-quoted spans are the odd indices of a split on '`'.
    let quoted: HashSet<&str> = finding.message.split('`').skip(1).step_by(2).collect();
    let root = workspace_root();
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (key, paths) in &desired.source_files {
        if !quoted.contains(key.name.as_str()) {
            continue;
        }
        for path in paths {
            let shown = path.strip_prefix(&root).unwrap_or(path);
            out.insert(format!("{} `{}` → {}", key.kind, key.name, shown.display()));
        }
    }
    out.into_iter().collect()
}

/// Render a rule's findings for a panic message: the rule, the message,
/// and the document(s) the message names.
fn render_findings(desired: &DesiredState, findings: &[LintFinding]) -> String {
    findings
        .iter()
        .map(|f| {
            let mut block = format!("  [{:?}] {}", f.rule, f.message);
            for decl in declared_in(desired, f) {
                block.push_str("\n      declared in: ");
                block.push_str(&decl);
            }
            block
        })
        .collect::<Vec<_>>()
        .join("\n")
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
    // Collected, not panicked per tree: one rule usually rejects more
    // than one of these trees, and reporting only the first makes the
    // next one a second run's surprise. See the module docs.
    let mut failures: Vec<String> = Vec::new();

    for (rel, backend) in trees() {
        let root = workspace_root().join(rel);
        let mut files = Vec::new();
        collect_yaml_files(&root, &mut files);
        assert!(!files.is_empty(), "{rel}: tree should not be empty");

        let desired = DesiredState::parse_files(files)
            .unwrap_or_else(|errs| panic!("{rel}: parse failed:\n{errs}"));

        // Row 0 — the per-envelope and cross-document rules, which the
        // offline CLI now runs before the lint rows below. Asserted here
        // and not only in `hort-config`'s per-tree guards because those
        // cover three of these four trees; `deploy/compose/s3/config` is
        // reached by nothing else, and a shipped tree that fails row 0
        // parks a real deployment not-ready at boot.
        if let Err(errs) = desired.validate() {
            failures.push(format!(
                "{rel}: shipped gitops tree must clear row 0 — fix the tree:\n{errs}"
            ));
            // Row 0 failing makes the lint rows' verdict unreliable (a
            // dangling reference changes which pairings resolve), so
            // this tree contributes one failure and stops here.
            continue;
        }

        // Sanity: the corpus actually carries the surface the rows lint.
        // A tree that lost its repositories or policies would pass every
        // row vacuously.
        assert!(
            !desired.repositories.is_empty(),
            "{rel}: tree declares no ArtifactRepository"
        );

        let report = cli_validator(backend).validate(&desired);
        if !report.errors.is_empty() {
            failures.push(format!(
                "{rel}: shipped gitops tree must clear the static linter — \
                 fix the tree, never the rule. Findings:\n{}",
                render_findings(&desired, &report.errors),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} shipped gitops trees are rejected by the static linter:\n\n{}",
        failures.len(),
        trees().len(),
        failures.join("\n\n"),
    );
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
        render_findings(&desired, &report.errors),
    );
}

/// The third host-test smoke (`scripts/host-tests/test-gitops-policies.sh`)
/// stages the same way, but from a **checked-in** overlay:
/// `scripts/native-tests/fixtures/gitops-policies` copied on top of
/// `deploy/compose/example-config`. So that overlay is a shipped gitops
/// tree in every sense that matters — a rule rejecting it parks the
/// smoke stack at boot — while being invisible to
/// `every_shipped_gitops_tree_passes_the_static_linter`, which walks
/// standalone roots and would judge this one without the repositories
/// and policies it is layered onto.
///
/// It is read from disk rather than inlined (unlike the overlay above,
/// which the two scripts generate at runtime), so an edit to the fixture
/// reaches this assertion with no edit here. The licence-policy row is
/// how the gap was found: the fixture declared `allowed`/`denied` lists
/// and nothing in the workspace would have noticed the boot refusal.
#[test]
fn the_checked_in_gitops_policies_overlay_still_validates_against_the_compose_tree() {
    let mut files = Vec::new();
    collect_yaml_files(
        &workspace_root().join("deploy/compose/example-config"),
        &mut files,
    );
    let overlay_root = workspace_root().join("scripts/native-tests/fixtures/gitops-policies");
    let mut overlay = Vec::new();
    collect_yaml_files(&overlay_root, &mut overlay);
    assert!(
        !overlay.is_empty(),
        "the gitops-policies fixture overlay should not be empty — if it moved,          follow it here rather than deleting this guard"
    );
    // `cp -R fixture/. stage/` replaces a same-named file; mirror that so
    // the corpus is the tree the smoke actually boots.
    for (path, bytes) in overlay {
        let rel = path
            .strip_prefix(&overlay_root)
            .expect("overlay path under its root")
            .to_path_buf();
        files.retain(|(p, _)| !p.ends_with(&rel));
        files.push((path, bytes));
    }

    let desired = DesiredState::parse_files(files).expect("staged overlay tree parses");
    if let Err(errs) = desired.validate() {
        panic!("the staged gitops-policies tree must clear row 0:\n{errs}");
    }
    let report = cli_validator(EffectiveStorageBackend::Filesystem).validate(&desired);
    assert!(
        report.errors.is_empty(),
        "the checked-in gitops-policies overlay must still apply cleanly — fix the \
         fixture, never the rule. Findings:\n{}",
        render_findings(&desired, &report.errors),
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

/// **Break the compose tree on purpose and watch the guard say which
/// document.** The mutation check for the OCI-scope waiver row and, in
/// the same assertion, for the file-naming above — a guard nobody has
/// seen fail is a guard whose message nobody has read.
///
/// The mutation is the exact shape the ten checked-in policies carried
/// before they were corrected: an empty `scanBackends` on a policy
/// scoped to a `format: oci` repository. It is applied to the **real**
/// on-disk tree and to a policy *found* by its resolved scope rather
/// than named by path, so renaming a file or moving the waiver to a
/// different OCI repository follows automatically.
///
/// Two things are asserted, and the second is the one that cannot be
/// got from the row's own unit tests: the finding fires, **and** the
/// rendered panic text carries the offending policy's on-disk path. A
/// `declared_in` that silently resolved nothing would leave the first
/// assertion passing and the guard back to costing the reader a search.
#[test]
fn the_mutated_tree_is_rejected_and_the_rejection_names_the_file() {
    use hort_app::lint::LinterRule;

    let root = workspace_root().join("deploy/compose/example-config");
    let mut files = Vec::new();
    collect_yaml_files(&root, &mut files);
    let mut desired = DesiredState::parse_files(files).expect("compose example-config parses");

    // Find a policy scoped to an OCI repository the same way the row
    // resolves it: the declared format lives on the repository envelope,
    // never on the policy's scope.
    let oci_repos: HashSet<&str> = desired
        .repositories
        .iter()
        .filter(|r| r.spec.format == "oci")
        .map(|r| r.metadata.name.as_str())
        .collect();
    assert!(
        !oci_repos.is_empty(),
        "the compose tree must declare at least one OCI repository for this mutation to mean \
         anything"
    );
    let target = desired
        .scan_policies
        .iter()
        .find(|env| {
            env.spec
                .scope
                .repository_name()
                .is_some_and(|r| oci_repos.contains(r))
        })
        .map(|env| env.metadata.name.clone())
        .expect("the compose tree scopes a ScanPolicy to an OCI repository");

    // Pre-condition: unmutated, the tree is clean. Without this the
    // mutation could be credited with a finding the tree already had.
    let before = cli_validator(EffectiveStorageBackend::Filesystem).validate(&desired);
    assert!(
        before.errors.is_empty(),
        "the compose tree must be clean before the mutation:\n{}",
        render_findings(&desired, &before.errors),
    );

    for env in &mut desired.scan_policies {
        if env.metadata.name == target {
            env.spec.scan_backends = Vec::new();
        }
    }

    let report = cli_validator(EffectiveStorageBackend::Filesystem).validate(&desired);
    let hits: Vec<&LintFinding> = report
        .errors
        .iter()
        .filter(|f| f.rule == LinterRule::OciRepositoryRequiresScanBackends)
        .collect();
    assert!(
        !hits.is_empty(),
        "an empty `scanBackends` on an OCI-scoped policy must be rejected — if this is green \
         the row has been neutered and `every_shipped_gitops_tree_passes_the_static_linter` \
         is passing for the wrong reason: {:?}",
        report.errors
    );

    // The guard's own output, as a reader would see it.
    let rendered = render_findings(&desired, &report.errors);
    assert!(
        rendered.contains(&format!("ScanPolicy `{target}` → ")),
        "the rejection must name the offending document, not just the envelope: {rendered}"
    );
    let declared = declared_in(&desired, hits[0]);
    assert!(
        declared.iter().any(|d| d.ends_with(".yaml")),
        "a resolved declaration must be a real on-disk YAML path: {declared:?}"
    );
}
