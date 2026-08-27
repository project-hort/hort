//! Published-crate dependency-graph guard.
//!
//! DB-free, network-free structural guard — a sibling to
//! `ephemeral_keyspace_exhaustive` / `no_sensitive_drops` /
//! `retention_registration_guard` / `streaming_metadata_port` — that runs
//! the two hard invariants
//! `scripts/ci/publishable-crates-in-order.sh` enforces at release time
//! against the workspace on every push, so a defect surfaces at the commit
//! that introduces it instead of at the next release.
//!
//! ## Why `cargo metadata`, not a TOML walk
//!
//! `scripts/ci/publishable-crates-in-order.sh` derives its data from
//! `cargo metadata --format-version 1 --no-deps` — a pure manifest read: no
//! dependency resolution, no registry, no network. This guard reads the
//! identical source via the `cargo_metadata` crate, so the two can never
//! disagree about what a manifest says; there is no shared parsing code
//! between them to drift. `Dependency::kind` and `Package::publish` are
//! already the typed equivalents of the script's `select(.kind != "dev")`
//! and `if .publish == [] then …` — a hand-rolled TOML walk (as
//! `publishable_manifests.rs` uses for its own, differently-scoped
//! declaration-shape checks) would have to reimplement target-specific
//! table traversal to reach the same dependency set `cargo metadata`
//! already resolves.
//!
//! ## The two invariants
//!
//! 1. **No published crate depends on a `publish = false` member.** The
//!    published manifest keeps the edge — optional and build dependencies
//!    included, dev-dependencies excluded, since cargo drops a path-only
//!    dev dependency from the published manifest entirely — and the
//!    registry cannot satisfy it: a release that fails partway with the
//!    earlier crates already uploaded and unwithdrawable.
//! 2. **A topological publish order exists among published crates.** A
//!    dependency cycle among them means no order satisfies `cargo publish`,
//!    which resolves each crate's dependencies through the registry and
//!    therefore needs every dependency indexed before its dependent
//!    uploads.
//!
//! Both invariants are factored into pure functions over an in-memory
//! graph (`unpublished_dependency_edges`, `published_topological_order`)
//! and table-tested against synthetic graphs below, so the guard
//! demonstrably catches the fault class and is not merely asserting
//! "today's graph happens to be clean". The real-workspace tests at the
//! bottom call those same functions against the graph `workspace_graph()`
//! builds from the live manifests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, MetadataCommand};

// ---------------------------------------------------------------------------
// Graph representation and pure invariant functions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Node {
    published: bool,
    /// Intra-workspace dependency names that survive into the published
    /// manifest — production + optional + build; dev-dependencies excluded.
    deps: BTreeSet<String>,
}

type Graph = BTreeMap<String, Node>;

/// Invariant 1: every `(dependent, dependency)` edge where a published
/// crate depends on a member that is not itself published. An edge to a
/// name absent from the graph is not reachable here — every dependency
/// this guard records is intra-workspace by construction (see
/// `workspace_graph`) — so a missing entry is treated as unpublished
/// rather than panicking, keeping the function total over its input type.
fn unpublished_dependency_edges(graph: &Graph) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    for (name, node) in graph {
        if !node.published {
            continue;
        }
        for dep in &node.deps {
            let dep_published = graph.get(dep).is_some_and(|d| d.published);
            if !dep_published {
                violations.push((name.clone(), dep.clone()));
            }
        }
    }
    violations
}

/// Invariant 2: a topological order over the published subgraph (Kahn's
/// algorithm, mirroring the shell script). Only edges between two
/// published crates constrain the order — an edge to an unpublished crate
/// is invariant 1's concern, not this one's, so it is ignored here rather
/// than treated as an unsatisfiable dependency.
///
/// Returns the order on success, or the still-blocked crate names (those
/// participating in a dependency cycle) on failure.
fn published_topological_order(graph: &Graph) -> Result<Vec<String>, Vec<String>> {
    let mut remaining: Vec<String> = graph
        .iter()
        .filter(|(_, node)| node.published)
        .map(|(name, _)| name.clone())
        .collect();
    remaining.sort();

    let mut emitted: BTreeSet<String> = BTreeSet::new();
    let mut order = Vec::new();

    while !remaining.is_empty() {
        let (ready, blocked): (Vec<String>, Vec<String>) =
            remaining.into_iter().partition(|name| {
                graph[name].deps.iter().all(|dep| {
                    let dep_is_published_constraint = graph.get(dep).is_some_and(|d| d.published);
                    !dep_is_published_constraint || emitted.contains(dep)
                })
            });

        if ready.is_empty() {
            return Err(blocked);
        }

        for name in &ready {
            emitted.insert(name.clone());
        }
        order.extend(ready);
        remaining = blocked;
    }

    Ok(order)
}

// ---------------------------------------------------------------------------
// Synthetic table tests — prove the two pure functions catch the fault
// class, independent of the current state of the real workspace graph.
// ---------------------------------------------------------------------------

fn node(published: bool, deps: &[&str]) -> Node {
    Node {
        published,
        deps: deps.iter().map(ToString::to_string).collect(),
    }
}

#[test]
fn unpublished_dependency_edges_flags_a_published_crate_depending_on_an_unpublished_member() {
    let mut graph = Graph::new();
    graph.insert("a".to_string(), node(true, &["b"]));
    graph.insert("b".to_string(), node(false, &[]));

    let violations = unpublished_dependency_edges(&graph);
    assert_eq!(violations, vec![("a".to_string(), "b".to_string())]);
}

#[test]
fn published_topological_order_flags_a_cycle_among_published_crates() {
    let mut graph = Graph::new();
    graph.insert("a".to_string(), node(true, &["b"]));
    graph.insert("b".to_string(), node(true, &["a"]));

    let blocked = published_topological_order(&graph)
        .expect_err("a -> b -> a is a cycle and has no publish order");
    assert_eq!(blocked, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn a_correct_graph_has_no_violations_and_a_publish_order_exists() {
    let mut graph = Graph::new();
    // Published diamond: a depends on b and c, both depend on d.
    graph.insert("a".to_string(), node(true, &["b", "c"]));
    graph.insert("b".to_string(), node(true, &["d"]));
    graph.insert("c".to_string(), node(true, &["d"]));
    graph.insert("d".to_string(), node(true, &[]));
    // An unpublished, unrelated crate — present in the graph but with no
    // edge from a published crate, so it triggers neither invariant.
    graph.insert("internal-only".to_string(), node(false, &[]));

    assert_eq!(unpublished_dependency_edges(&graph), Vec::new());

    let order = published_topological_order(&graph).expect("a clean graph has a publish order");
    assert_eq!(order.len(), 4);
    assert!(!order.contains(&"internal-only".to_string()));

    let position = |name: &str| order.iter().position(|n| n == name).unwrap();
    assert!(position("d") < position("b"));
    assert!(position("d") < position("c"));
    assert!(position("b") < position("a"));
    assert!(position("c") < position("a"));
}

// ---------------------------------------------------------------------------
// Real-workspace graph, derived from `cargo metadata --no-deps`.
// ---------------------------------------------------------------------------

/// `CARGO_MANIFEST_DIR` is `<root>/crates/hort-server`, so two levels up is
/// the workspace root. Mirrors `publishable_manifests.rs::workspace_root`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)")
        .to_path_buf()
}

/// The published-crate dependency graph, built from the same
/// `cargo metadata --no-deps` read `publishable-crates-in-order.sh` uses.
fn workspace_graph() -> Graph {
    let manifest_path = workspace_root().join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .no_deps()
        .manifest_path(&manifest_path)
        .exec()
        .unwrap_or_else(|e| {
            panic!("cargo metadata --no-deps --manifest-path {manifest_path:?}: {e}")
        });

    let members: BTreeSet<String> = metadata
        .packages
        .iter()
        .map(|p| p.name.to_string())
        .collect();
    assert!(
        !members.is_empty(),
        "cargo metadata returned no packages for {manifest_path:?}"
    );

    let mut graph = Graph::new();
    for package in &metadata.packages {
        // `publish: None` means "publish anywhere" (cargo's own default);
        // `Some(registries)` publishes only if the list is non-empty —
        // `publish = false` lowers to `Some(vec![])`. Identical to the
        // script's `if $pkg.publish == [] then "0" else "1" end`.
        let published = match &package.publish {
            None => true,
            Some(registries) => !registries.is_empty(),
        };

        let deps: BTreeSet<String> = package
            .dependencies
            .iter()
            .filter(|dep| dep.kind != DependencyKind::Development)
            .map(|dep| dep.name.clone())
            .filter(|name| members.contains(name))
            .collect();

        graph.insert(package.name.to_string(), Node { published, deps });
    }

    graph
}

#[test]
fn no_published_workspace_crate_depends_on_an_unpublished_member() {
    let graph = workspace_graph();
    let violations = unpublished_dependency_edges(&graph);
    assert!(
        violations.is_empty(),
        "published crates depend on `publish = false` members — the published manifest \
         keeps the edge and the registry cannot satisfy it. Publish the dependency too, or \
         remove the edge: {violations:?}"
    );
}

#[test]
fn a_publish_order_exists_for_every_published_workspace_crate() {
    let graph = workspace_graph();
    match published_topological_order(&graph) {
        Ok(order) => assert!(!order.is_empty(), "no crate in the workspace is published"),
        Err(cyclic) => panic!(
            "dependency cycle among published crates — no publish order exists. \
             Unresolved: {cyclic:?}"
        ),
    }
}
