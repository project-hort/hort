//! Intra-workspace dependency version-requirement guard.
//!
//! DB-free, network-free source scan of the workspace's `Cargo.toml`
//! files — the committed proof (in the spirit of
//! `ephemeral_keyspace_exhaustive` / `no_sensitive_drops` /
//! `retention_registration_guard` / `streaming_metadata_port`) that every
//! crate in this workspace is *packageable*.
//!
//! ## Why a guard
//!
//! `cargo package` / `cargo publish` strip the `path` key from the
//! manifest they upload — a published crate resolves its dependencies
//! through the registry, so a dependency that carries only a `path` has
//! nothing left to resolve with. Cargo therefore refuses outright:
//!
//! ```text
//! error: failed to verify manifest at `/…/crates/hort-app/Cargo.toml`
//! Caused by:
//!   all dependencies must have a version requirement specified when
//!   packaging. dependency `hort-config` does not specify a version
//! ```
//!
//! Nothing in the ordinary build notices: `cargo build`, `cargo clippy`
//! and `cargo test` all resolve intra-workspace dependencies through
//! `path` and never look at a version requirement. The defect is
//! therefore invisible until a release actually tries to publish, which
//! is the worst possible moment to discover it — and it is reintroduced
//! by the single most natural edit in the workspace, adding
//! `hort-x = { path = "../hort-x" }` to a crate.
//!
//! ## What it asserts
//!
//! 1. Every `hort-*` entry in the root `[workspace.dependencies]` carries
//!    a `path`, a `version` and a `registry`; the `path` resolves to the
//!    identically-named member directory, the version requirement is an
//!    exact pin (`=`) equal to `[workspace.package] version`, and the
//!    registry is the one the published members allow.
//! 2. Every `hort-*` entry in a member's `[dependencies]` /
//!    `[build-dependencies]` (including target-specific tables) inherits
//!    from the workspace (`workspace = true`) and declares no `path` or
//!    `version` of its own.
//! 3. Every `hort-*` entry in a member's `[dev-dependencies]` does the
//!    *opposite*: path-only, never `workspace = true`, never a `version`.
//! 4. The declared and referenced intra-workspace sets match exactly —
//!    nothing depended on is missing from the workspace block, and no
//!    stale entry keeps a version requirement alive that nothing uses.
//! 5. No crate the release publishes depends on a member that opts out of
//!    publishing (`publish = false`).
//! 6. Every member declares `publish` explicitly — either `false`, or an
//!    allow-list naming the registry. No manifest leaves the key absent.
//!
//! ## Why the requirement is an exact pin equal to the workspace version
//!
//! Every crate here inherits `[workspace.package] version` and is
//! released in lockstep, so a caret range would advertise a cross-version
//! compatibility that is never built or tested.
//!
//! Equally, the requirement cannot be a *static* string that survives a
//! release bump. Semver orders pre-release identifiers lexically, so
//! `0.11.0-beta.4` sorts *below* `0.11.0-dev`: a `-dev` requirement left
//! in place at a beta cut would not be satisfied by the beta's own
//! crates. Pinning to whatever `[workspace.package] version` currently
//! says removes the ordering question entirely — requirement and package
//! version are the same string, so satisfaction is trivial at every point
//! in the pre-release series. The release cut rewrites both together
//! (`RELEASING.md` → *Versioned files*); this test is what fails the gate
//! if it rewrites only one.
//!
//! ## Why dev-dependencies invert the rule
//!
//! Cargo *drops* a path-only dev dependency from the published manifest
//! entirely, but *keeps* one that carries a version — and then demands it
//! resolve on the registry. Giving intra-workspace dev dependencies a
//! version (directly, or by inheriting a workspace entry that has one)
//! would therefore promote every test-only edge into a publish-time
//! dependency, including edges onto crates that are not published at all.
//! Path-only is not an oversight there; it is what keeps the test graph
//! out of the published graph.
//!
//! ## The published set has to be dependency-closed
//!
//! `[package] publish` is the only definition of the published set — a
//! member ships unless it sets `publish = false`, and
//! `scripts/ci/publishable-crates-in-order.sh` derives both the set and the
//! publish order from that key. A published crate that depends on an
//! excluded member is therefore unpublishable: the dependency survives into
//! the published manifest (optional ones included) and nothing in the
//! registry can satisfy it.
//!
//! The release script rejects that too, but only at release time — after a
//! tag, in a job where the crates ahead of the broken one have already
//! uploaded and can never be withdrawn, only yanked. Asserting it here
//! moves the failure to the commit that introduces the edge.
//!
//! ## Why the intra-workspace requirement names its registry
//!
//! Without a `registry` key an intra-workspace dependency is a
//! *crates.io* dependency, and the release job runs under
//! `[source.crates-io] replace-with = "hort"` — the read-only
//! aggregation index. Cargo then searches for the just-uploaded sibling
//! in a repository the release identity holds no write grant on, and the
//! chain fails at the second crate with the earlier ones already
//! uploaded and only yankable. `--registry` on the command line does not
//! change this: source replacement is decided per dependency, from the
//! manifest. An explicit-registry dependency is exempt from replacement,
//! so it resolves where the identity can actually publish.
//!
//! The key is load-bearing in the other direction too: cargo refuses to
//! parse a manifest naming a registry it has no index configuration for,
//! so `.cargo/config.toml` must declare it or nothing in the workspace
//! builds. Assertion 1 checks both halves together — a `registry` key
//! and the declaration it depends on.
//!
//! ## Why the published set is an allow-list, not an absent key
//!
//! An absent `publish` key means "publish anywhere" — including
//! crates.io, which nothing about this workspace's manifests otherwise
//! prevents. It is also silent: a new member added without a `publish`
//! line joins the published set by default, with no signal at the point
//! it happens. `publish = ["hort-crates"]` on the six published crates
//! makes each one's status a decision recorded in its own manifest rather
//! than an assumption about what everyone else's manifest doesn't say, and
//! it scopes what cargo will accept to the one registry this workspace
//! actually uses. Assertion 6 is the other half: a manifest that leaves
//! the key out entirely — the shape that produced 32 accidentally-
//! publishable crates before this — fails immediately, instead of quietly
//! defaulting to published.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

/// The `hort-` prefix identifies an intra-workspace crate. Every member
/// directory under `crates/` carries it, and no third-party dependency in
/// the graph does.
const INTRA_WORKSPACE_PREFIX: &str = "hort-";

/// Dependency tables whose entries end up in the published manifest with
/// their `path` stripped, and therefore require a version requirement.
const PUBLISHED_DEP_TABLES: [&str; 2] = ["dependencies", "build-dependencies"];

/// The first-party registry every intra-workspace requirement names and
/// every published member allows.
const HORT_REGISTRY: &str = "hort-crates";

/// The workspace root. `CARGO_MANIFEST_DIR` is `<root>/crates/hort-server`,
/// so two levels up is the root. Mirrors how the sibling guards resolve
/// their scan roots.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)")
        .to_path_buf()
}

fn parse_manifest(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    // `FromStr for Value` parses a bare TOML *value*, not a document; a
    // manifest has to go through the document type first.
    let document: toml::Table =
        toml::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
    Value::Table(document)
}

/// Every member manifest under `crates/`, sorted for deterministic
/// failure output.
fn member_manifests() -> Vec<PathBuf> {
    let crates_dir = workspace_root().join("crates");
    let mut manifests: Vec<PathBuf> = fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("read_dir {crates_dir:?}: {e}"))
        .flatten()
        .map(|entry| entry.path().join("Cargo.toml"))
        .filter(|p| p.is_file())
        .collect();
    manifests.sort();
    assert!(
        !manifests.is_empty(),
        "no member manifests found under {crates_dir:?} — \
         CARGO_MANIFEST_DIR is expected to be <root>/crates/hort-server"
    );
    manifests
}

/// Path relative to the workspace root, for readable failure messages.
fn relative(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Yield `(table_label, table)` for a dependency table name: the
/// top-level table plus every `[target.<cfg>.<name>]` variant. A
/// target-gated dependency lands in the published manifest exactly like
/// an unconditional one, so the rules must reach it too.
fn dependency_tables<'a>(manifest: &'a Value, table_name: &str) -> Vec<(String, &'a Value)> {
    let mut tables = Vec::new();
    if let Some(table) = manifest.get(table_name) {
        tables.push((format!("[{table_name}]"), table));
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (cfg, target) in targets {
            if let Some(table) = target.get(table_name) {
                tables.push((format!("[target.{cfg}.{table_name}]"), table));
            }
        }
    }
    tables
}

/// The `hort-*` entries of a dependency table, sorted by name.
fn intra_workspace_entries(table: &Value) -> Vec<(&str, &Value)> {
    let Some(table) = table.as_table() else {
        return Vec::new();
    };
    table
        .iter()
        .filter(|(name, _)| name.starts_with(INTRA_WORKSPACE_PREFIX))
        .map(|(name, spec)| (name.as_str(), spec))
        .collect()
}

fn workspace_version(root_manifest: &Value) -> String {
    root_manifest
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(Value::as_str)
        .expect("root Cargo.toml declares [workspace.package] version")
        .to_string()
}

// ---------------------------------------------------------------------------
// 1. The root `[workspace.dependencies]` block.
// ---------------------------------------------------------------------------

#[test]
fn workspace_dependency_block_pins_every_intra_workspace_crate_to_the_workspace_version() {
    let root = workspace_root();
    let manifest = parse_manifest(&root.join("Cargo.toml"));
    let version = workspace_version(&manifest);
    let expected_req = format!("={version}");

    let table = manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .expect("root Cargo.toml declares [workspace.dependencies]");

    let entries = intra_workspace_entries(table);
    assert!(
        !entries.is_empty(),
        "[workspace.dependencies] declares no `{INTRA_WORKSPACE_PREFIX}*` crates — \
         intra-workspace dependencies are declared there once and inherited by members"
    );

    let mut failures = Vec::new();
    for (name, spec) in entries {
        let Some(spec) = spec.as_table() else {
            failures.push(format!(
                "[workspace.dependencies] `{name}` must be a table with `path` and `version`"
            ));
            continue;
        };

        match spec.get("version").and_then(Value::as_str) {
            Some(req) if req == expected_req => {}
            Some(req) => failures.push(format!(
                "[workspace.dependencies] `{name}` requires `{req}` but \
                 [workspace.package] version is `{version}` — expected `{expected_req}`. \
                 A release cut rewrites both together (RELEASING.md → Versioned files)"
            )),
            None => failures.push(format!(
                "[workspace.dependencies] `{name}` has no `version` — `cargo package` strips \
                 `path` from the published manifest and rejects a dependency it cannot \
                 resolve through the registry. Expected `version = \"{expected_req}\"`"
            )),
        }

        match spec.get("path").and_then(Value::as_str) {
            Some(path) if path == format!("crates/{name}") => {
                assert!(
                    root.join(path).join("Cargo.toml").is_file(),
                    "[workspace.dependencies] `{name}` points at `{path}`, which is not a member"
                );
            }
            Some(path) => failures.push(format!(
                "[workspace.dependencies] `{name}` points at `{path}` — expected `crates/{name}`"
            )),
            None => failures.push(format!(
                "[workspace.dependencies] `{name}` has no `path` — without it the workspace \
                 build would resolve the crate through the registry instead of the local source"
            )),
        }

        match spec.get("registry").and_then(Value::as_str) {
            Some(registry) if registry == HORT_REGISTRY => {}
            Some(registry) => failures.push(format!(
                "[workspace.dependencies] `{name}` names registry `{registry}` — expected \
                 `{HORT_REGISTRY}`, the registry the published members allow"
            )),
            None => failures.push(format!(
                "[workspace.dependencies] `{name}` has no `registry` — without it the \
                 requirement is a crates.io one, and the release job's \
                 `[source.crates-io] replace-with` sends it to the read-only aggregation \
                 index instead of the registry it was published to. Expected \
                 `registry = \"{HORT_REGISTRY}\"`"
            )),
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// 1b. The registry those requirements name is configured.
// ---------------------------------------------------------------------------

#[test]
fn the_named_registry_is_declared_in_the_cargo_configuration() {
    let config = workspace_root().join(".cargo").join("config.toml");
    assert!(
        config.is_file(),
        "{config:?} is missing — it declares the `{HORT_REGISTRY}` index that every \
         intra-workspace requirement names"
    );

    let index = parse_manifest(&config)
        .get("registries")
        .and_then(|r| r.get(HORT_REGISTRY))
        .and_then(|r| r.get("index"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let Some(index) = index else {
        panic!(
            ".cargo/config.toml declares no `[registries.{HORT_REGISTRY}] index` — cargo \
             refuses to parse a manifest naming a registry it has no index for, so every \
             workspace command fails with `registry index was not found in any \
             configuration`"
        )
    };
    assert!(
        index.starts_with("sparse+"),
        "`[registries.{HORT_REGISTRY}] index` is `{index}` — hort serves a cargo SPARSE \
         index (RFC 2789), so the URL carries the `sparse+` scheme prefix"
    );
}

// ---------------------------------------------------------------------------
// 2. Member production dependency tables inherit from the workspace.
// ---------------------------------------------------------------------------

#[test]
fn member_production_dependencies_inherit_the_workspace_declaration() {
    let mut failures = Vec::new();

    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        let file = relative(&path);

        for table_name in PUBLISHED_DEP_TABLES {
            for (label, table) in dependency_tables(&manifest, table_name) {
                for (name, spec) in intra_workspace_entries(table) {
                    let inherits = spec
                        .get("workspace")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !inherits {
                        failures.push(format!(
                            "{file} {label} `{name}` does not inherit the workspace \
                             declaration — write `{name} = {{ workspace = true }}`. A \
                             path-only dependency has no version requirement in the \
                             published manifest and makes the crate unpublishable"
                        ));
                        continue;
                    }
                    for key in ["path", "version"] {
                        if spec.get(key).is_some() {
                            failures.push(format!(
                                "{file} {label} `{name}` overrides `{key}` — the `path` and \
                                 the version requirement are the workspace declaration's to \
                                 own, so they stay in lockstep with the release version"
                            ));
                        }
                    }
                }
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// 3. Member dev-dependency tables stay path-only.
// ---------------------------------------------------------------------------

#[test]
fn member_dev_dependencies_stay_path_only() {
    let mut failures = Vec::new();

    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        let file = relative(&path);

        for (label, table) in dependency_tables(&manifest, "dev-dependencies") {
            for (name, spec) in intra_workspace_entries(table) {
                let inherits = spec
                    .get("workspace")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if inherits || spec.get("version").is_some() {
                    failures.push(format!(
                        "{file} {label} `{name}` carries a version requirement — cargo drops \
                         a path-only dev dependency from the published manifest but keeps a \
                         versioned one and then demands it resolve on the registry. Write \
                         `{name} = {{ path = \"../{name}\" }}`"
                    ));
                    continue;
                }
                match spec.get("path").and_then(Value::as_str) {
                    Some(p) if p == format!("../{name}") => {}
                    Some(p) => failures.push(format!(
                        "{file} {label} `{name}` points at `{p}` — expected `../{name}`"
                    )),
                    None => failures.push(format!(
                        "{file} {label} `{name}` has no `path` — an intra-workspace dev \
                         dependency must resolve from the local source"
                    )),
                }
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// 4. Every intra-workspace crate a member depends on is declared once.
// ---------------------------------------------------------------------------

#[test]
fn every_referenced_intra_workspace_crate_has_a_workspace_declaration() {
    let root = workspace_root();
    let root_manifest = parse_manifest(&root.join("Cargo.toml"));
    let declared: BTreeSet<&str> = root_manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .map(intra_workspace_entries)
        .expect("root Cargo.toml declares [workspace.dependencies]")
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    let mut referenced = BTreeSet::new();
    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        for table_name in PUBLISHED_DEP_TABLES {
            for (_, table) in dependency_tables(&manifest, table_name) {
                for (name, _) in intra_workspace_entries(table) {
                    referenced.insert(name.to_string());
                }
            }
        }
    }

    let missing: Vec<&String> = referenced
        .iter()
        .filter(|name| !declared.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "depended on by a member but absent from [workspace.dependencies]: {missing:?}"
    );

    let unused: Vec<&&str> = declared
        .iter()
        .filter(|name| !referenced.contains(**name))
        .collect();
    assert!(
        unused.is_empty(),
        "declared in [workspace.dependencies] but depended on by no member: {unused:?} — \
         a stale entry keeps a version requirement alive that nothing exercises"
    );
}

// ---------------------------------------------------------------------------
// 5. The published set is dependency-closed.
// ---------------------------------------------------------------------------

/// A member is published unless its manifest opts out. Cargo accepts both
/// `publish = false` and `publish = []` as the opt-out; a non-empty array
/// restricts *which* registries accept it, which is still published.
fn is_published(manifest: &Value) -> bool {
    match manifest.get("package").and_then(|p| p.get("publish")) {
        None => true,
        Some(Value::Boolean(allowed)) => *allowed,
        Some(Value::Array(registries)) => !registries.is_empty(),
        Some(other) => panic!("[package] publish has an unexpected shape: {other:?}"),
    }
}

/// Whether `[package] publish` is present at all, regardless of what it
/// says. `is_published` treats an absent key as "published" (cargo's own
/// default); this is the separate check that the key was written down —
/// the property assertion 6 requires and `is_published` alone cannot
/// express, since it makes the same absent-key case `true` on purpose.
fn declares_publish(manifest: &Value) -> bool {
    manifest
        .get("package")
        .is_some_and(|p| p.get("publish").is_some())
}

fn package_name(manifest: &Value) -> String {
    manifest
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .expect("member manifest declares [package] name")
        .to_string()
}

#[test]
fn no_published_crate_depends_on_an_unpublished_member() {
    let mut published = BTreeSet::new();
    let mut manifests = Vec::new();

    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        let name = package_name(&manifest);
        if is_published(&manifest) {
            published.insert(name.clone());
        }
        manifests.push((relative(&path), name, manifest));
    }

    assert!(
        !published.is_empty(),
        "no member is publishable — every manifest opts out of publishing"
    );

    let mut violations = Vec::new();
    for (file, name, manifest) in &manifests {
        if !published.contains(name) {
            continue;
        }
        for table_name in PUBLISHED_DEP_TABLES {
            for (label, table) in dependency_tables(manifest, table_name) {
                for (dep, _) in intra_workspace_entries(table) {
                    if !published.contains(dep) {
                        violations.push(format!(
                            "{file} {label} `{name}` depends on `{dep}`, which sets \
                             `publish = false` — the dependency survives into the published \
                             manifest and no registry can satisfy it. Publish `{dep}` too, \
                             or remove the edge"
                        ));
                    }
                }
            }
        }
    }

    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

// ---------------------------------------------------------------------------
// 6. Every member declares `publish` explicitly.
// ---------------------------------------------------------------------------

#[test]
fn every_member_declares_publish_explicitly() {
    let mut violations = Vec::new();
    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        if !declares_publish(&manifest) {
            let name = package_name(&manifest);
            violations.push(format!(
                "{} — `{name}` has no `[package] publish` key. An absent key defaults to \
                 published (to any registry, crates.io included) and joins the release set \
                 silently. Add `publish = false`, or `publish = [\"{HORT_REGISTRY}\"]` if \
                 this crate is meant to ship",
                relative(&path)
            ));
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

// ---------------------------------------------------------------------------
// 7. A published member allows exactly the registry its requirements name.
// ---------------------------------------------------------------------------

/// The `publish` allow-list and the `registry` key on the intra-workspace
/// requirements have to agree. They fail in opposite directions if they
/// drift: cargo rejects an upload to a registry outside the allow-list,
/// and a requirement naming a registry the sibling never shipped to
/// resolves nothing.
#[test]
fn every_published_member_allows_exactly_the_registry_its_requirements_name() {
    let mut violations = Vec::new();
    for path in member_manifests() {
        let manifest = parse_manifest(&path);
        if !is_published(&manifest) {
            continue;
        }
        let name = package_name(&manifest);
        let allowed: Vec<String> = match manifest.get("package").and_then(|p| p.get("publish")) {
            Some(Value::Array(registries)) => registries
                .iter()
                .map(|r| r.as_str().unwrap_or("<not-a-string>").to_string())
                .collect(),
            // `publish = true` publishes anywhere, crates.io included.
            _ => Vec::new(),
        };
        if allowed != [HORT_REGISTRY] {
            violations.push(format!(
                "{} — `{name}` allows {allowed:?}; the intra-workspace requirements name \
                 `{HORT_REGISTRY}`, so it must be exactly `publish = [\"{HORT_REGISTRY}\"]`",
                relative(&path)
            ));
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}
