//! POM `<dependencies>` extraction — the Maven arm of the transitive
//! prefetch cascade's
//! [`VersionDiscovery::extract_dependency_specs`](hort_domain::ports::format_handler::VersionDiscovery::extract_dependency_specs).
//!
//! # What this reader can see, and why that is the whole story
//!
//! `extract_dependency_specs` is a pure function over **one artifact's own
//! bytes**. It holds no port, no HTTP client and no fetcher, so a POM's
//! parent chain and its imported BOMs — which is where a Spring Boot tree
//! keeps most of its versions — are structurally unreachable from here.
//! This reader therefore resolves exactly what the POM in front of it
//! declares:
//!
//! - `<dependencies>` entries whose effective scope is `compile` or
//!   `runtime` — Maven's runtime declaration classes (ADR 0053 D5), both of
//!   which Maven propagates transitively to consumers. An absent `<scope>`
//!   is Maven's own `compile` default. See [`EMITTED_SCOPES`] for why every
//!   other scope is excluded.
//! - Versions written literally, or through a property this POM itself
//!   declares in `<properties>`, or through the model built-ins that are
//!   computable from the POM alone (`${project.version}`,
//!   `${project.groupId}` and their `pom.`-prefixed spellings).
//! - Versions supplied by this POM's **own** `<dependencyManagement>`.
//!   That block is local bytes, not a parent and not a BOM import, so a
//!   dependency it manages is genuinely resolvable here — reporting it as
//!   deferred would name a coverage gap that does not exist.
//!
//! Everything else is a **counted skip**, never an error. The distinction
//! is load-bearing: `Err` aborts the cascade for the whole artifact, so it
//! is reserved for input that is not a POM at all. A POM whose versions
//! all live in its parent is a *valid* POM and yields `Ok` with every
//! dependency skipped — a partially warmed tree, which is the outcome this
//! reader exists to produce.
//!
//! # The skip count is the contract
//!
//! An operator who enables the transitive-prefetch trigger on a Maven
//! proxy believes their tree is being warmed. Because this reader cannot
//! see parent POMs or imported BOMs, the count of what it skipped — and
//! which of the reasons applied — is the only thing that tells them how
//! much of the tree it actually reached. [`PomSkipReason`] is that signal,
//! and the reasons are kept distinguishable per cause rather than
//! collapsed into one "unresolved" bucket.
//!
//! # `<optional>` is not a filter here
//!
//! An `<optional>true</optional>` dependency in an emitted scope IS emitted.
//! Maven does not propagate it to a consumer's transitive resolve, so warming
//! it is work the closure may not need — but the class boundary ADR 0053 D5
//! draws for Maven is the scope, not optionality, and the cost is asymmetric:
//! warming an extra artifact costs storage, while failing to warm one a
//! consumer opts into costs a resolver failure against a cold proxy.
//!
//! # Profiles, plugins and the rest of the model
//!
//! Element paths are matched **from the document root**, so
//! `<profiles>/<profile>/<dependencies>` and
//! `<build>/<plugins>/<plugin>/<dependencies>` are not read. Profile
//! activation depends on the build environment (JDK, OS, properties, a
//! `-P` flag) that a registry does not have and must not guess at, and a
//! plugin's own dependencies are build-time classes the cascade excludes
//! by the same rule that excludes cargo `[build-dependencies]`.

use std::collections::HashMap;
use std::io::Read;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::DependencySpec;
use quick_xml::events::Event;
use quick_xml::Reader;

use super::xml::{decode_text, local_name_of, resolve_reference, MAX_ELEMENT_DEPTH};

/// Ceiling on the POM bytes this reader will buffer. Maven Central's
/// largest published POMs are a few hundred kilobytes; 4 MiB leaves an
/// order of magnitude of headroom while keeping a hostile artifact from
/// forcing an unbounded allocation. A body over the cap is `Validation` —
/// it is not a plausible POM.
pub const POM_MAX_BYTES: usize = 4 * 1024 * 1024;

/// How many times a property value may itself expand to another property
/// before the chain is declared unresolvable. Bounds both a genuinely deep
/// chain and a reference cycle (`a → b → a`), which has no other
/// termination condition.
const MAX_PROPERTY_EXPANSION_DEPTH: usize = 16;

/// The scope Maven applies when a `<dependency>` declares none.
const DEFAULT_SCOPE: &str = "compile";

/// The scopes the cascade warms — Maven's **runtime declaration classes**
/// (ADR 0053 D5).
///
/// `compile` is on the consumer's compile AND runtime classpath.
/// `runtime` is the JDBC-driver case: not needed to compile against, required
/// to run, and Maven propagates it transitively to consumers exactly as it
/// does `compile`. Omitting it would drop real closure members from every
/// tree the cascade warms.
///
/// Every other scope is excluded and counted as
/// [`PomSkipReason::ScopeExcluded`]:
///
/// - `provided` — the container supplies it at run time and Maven does not
///   propagate it transitively; it is build-time closure, which ADR 0053 D4
///   refuses to inflate the fan-out with.
/// - `test` — the dev/test closure D5 explicitly keeps out.
/// - `system` — names a local file path, so there is no upstream artifact to
///   warm at all.
/// - `import` — only meaningful inside `<dependencyManagement>` as a BOM
///   import, which this reader deliberately does not resolve.
const EMITTED_SCOPES: [&str; 2] = ["compile", "runtime"];

/// Cap on the coordinate recorded alongside a skip. The coordinate comes
/// from artifact bytes and reaches logs and metric labels, so it is
/// truncated and stripped of control characters before it leaves this
/// module.
const SKIP_COORDINATE_MAX_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Why a declared `<dependency>` did not become a [`DependencySpec`].
///
/// Every reason here is counted, including [`PomSkipReason::ScopeExcluded`]
/// — an operator reading the skip counts needs the full accounting of a
/// declared dependency this reader chose not to emit, whether the reason is
/// a coverage gap (this reader cannot reach the version) or a deliberate
/// class-boundary exclusion (the scope is outside ADR 0053 D5's runtime
/// declaration classes). Collapsing the boundary exclusion into silence
/// would make "how much of my tree did the cascade warm" unanswerable from
/// metrics alone for a POM that declares mostly `test`/`provided` deps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PomSkipReason {
    /// The dependency declares no `<version>` and this POM's own
    /// `<dependencyManagement>` does not supply one — the version lives in
    /// a parent POM or an imported BOM, neither of which
    /// `extract_dependency_specs` can reach. The dominant reason on a
    /// managed tree (Spring Boot, Quarkus), and the one that most
    /// understates how much of a tree the cascade warmed.
    VersionFromParentOrBom,
    /// A `${...}` placeholder in the coordinate, scope or version did not
    /// resolve from this POM's own `<properties>` or the model built-ins —
    /// typically a property a parent POM declares, or an expansion chain
    /// that exceeded [`MAX_PROPERTY_EXPANSION_DEPTH`] (a cycle).
    UnresolvedProperty,
    /// The version is a Maven version *range* (`[1.0,2.0)`, `(,1.0]`).
    /// Selecting from a range needs the upstream version set, which this
    /// pure reader does not have; per ADR 0053 D2 a range is never guessed
    /// at, so it is skipped and counted rather than pinned.
    UnsupportedRange,
    /// The `<dependency>` element declares no `<groupId>` or no
    /// `<artifactId>`. Structurally incomplete rather than deferred — the
    /// dependency has no identity to enqueue even in principle.
    IncompleteCoordinate,
    /// The effective scope is not in [`EMITTED_SCOPES`]. Not a coverage
    /// gap — the dependency is outside the cascade's declared class
    /// boundary, working as specified — but counted anyway so the boundary
    /// itself is visible to an operator reading the skip counts, not just
    /// the gaps within it.
    ScopeExcluded,
}

impl PomSkipReason {
    /// Every reason, in a stable order. Consumers that surface per-reason
    /// counts iterate this so a newly added reason cannot be silently
    /// dropped from their output.
    pub const ALL: [PomSkipReason; 5] = [
        PomSkipReason::VersionFromParentOrBom,
        PomSkipReason::UnresolvedProperty,
        PomSkipReason::UnsupportedRange,
        PomSkipReason::IncompleteCoordinate,
        PomSkipReason::ScopeExcluded,
    ];

    /// Stable snake_case label. Safe as a metric label value and as a
    /// structured-log field: it is a compile-time constant, never derived
    /// from artifact bytes.
    pub fn as_str(self) -> &'static str {
        match self {
            PomSkipReason::VersionFromParentOrBom => "version_from_parent_or_bom",
            PomSkipReason::UnresolvedProperty => "unresolved_property",
            PomSkipReason::UnsupportedRange => "unsupported_range",
            PomSkipReason::IncompleteCoordinate => "incomplete_coordinate",
            PomSkipReason::ScopeExcluded => "scope_excluded",
        }
    }
}

/// One skipped `<dependency>`: which one, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PomSkip {
    /// Best-effort `groupId:artifactId` of the skipped dependency, as far
    /// as it could be resolved. Sanitised (control characters removed,
    /// truncated to [`SKIP_COORDINATE_MAX_CHARS`]) because it originates
    /// in artifact bytes.
    pub coordinate: String,
    /// The coverage gap this skip represents.
    pub reason: PomSkipReason,
}

/// Everything a single POM yielded: the dependencies that resolved, and
/// the ones that did not with the reason for each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PomDependencies {
    /// Compile-scope dependencies resolved to a concrete version, in
    /// document order.
    pub specs: Vec<DependencySpec>,
    /// Dependencies this reader could not resolve, in document order.
    pub skipped: Vec<PomSkip>,
}

impl PomDependencies {
    /// How many dependencies were skipped for `reason`.
    pub fn skip_count(&self, reason: PomSkipReason) -> usize {
        self.skipped.iter().filter(|s| s.reason == reason).count()
    }

    /// Per-reason counts over [`PomSkipReason::ALL`], including zeroes, in
    /// that order. A consumer emitting one counter per reason gets a
    /// complete series rather than one that only appears once a reason
    /// first occurs.
    pub fn skip_counts(&self) -> Vec<(PomSkipReason, usize)> {
        PomSkipReason::ALL
            .iter()
            .map(|reason| (*reason, self.skip_count(*reason)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Parse a stored Maven POM into its resolvable compile- and runtime-scope
/// dependencies plus the counted skips.
///
/// # Errors
///
/// `Validation` only for **structurally invalid input** — bytes over
/// [`POM_MAX_BYTES`], bytes that do not parse as XML, or an XML document
/// whose root element is not `<project>`. A well-formed POM always
/// succeeds, however little of it this reader could resolve.
pub fn parse_pom_dependencies(content: &mut dyn Read) -> DomainResult<PomDependencies> {
    let body = crate::stream_helpers::read_to_capped_vec(content, POM_MAX_BYTES, |len, max| {
        format!("maven pom is {len} bytes; maven pom max is {max}")
    })?;
    let raw = read_pom_document(&body)?;
    Ok(resolve(&raw))
}

// ---------------------------------------------------------------------------
// Stage 1 — read the document into its raw (uninterpolated) model
// ---------------------------------------------------------------------------

/// A `<dependency>` element exactly as written, before any property
/// substitution or defaulting.
#[derive(Debug, Default, Clone)]
struct RawDependency {
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
    scope: Option<String>,
}

impl RawDependency {
    fn set(&mut self, field: &str, value: &str) {
        let slot = match field {
            "groupId" => &mut self.group_id,
            "artifactId" => &mut self.artifact_id,
            "version" => &mut self.version,
            "scope" => &mut self.scope,
            _ => return,
        };
        *slot = Some(value.to_string());
    }
}

/// The subset of the POM model this reader consumes.
#[derive(Debug, Default)]
struct RawPom {
    group_id: Option<String>,
    version: Option<String>,
    parent_group_id: Option<String>,
    parent_version: Option<String>,
    properties: HashMap<String, String>,
    dependencies: Vec<RawDependency>,
    managed: Vec<RawDependency>,
}

/// Which text-bearing element of interest a path points at. Computed once
/// per path so the text accumulator and the recorder agree by
/// construction — an element whose text is never accumulated can never be
/// recorded, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leaf {
    ProjectGroupId,
    ProjectVersion,
    ParentGroupId,
    ParentVersion,
    Property,
    DependencyField,
    ManagedDependencyField,
}

/// Classify an element path (local names, from the root) as a leaf of
/// interest. `None` for every other element in the model — its text is
/// never decoded, which is what keeps a POM with undecodable bytes in an
/// element this reader does not need fully parseable.
fn leaf_at(path: &[String]) -> Option<Leaf> {
    match path {
        [project, field] if project == "project" => match field.as_str() {
            "groupId" => Some(Leaf::ProjectGroupId),
            "version" => Some(Leaf::ProjectVersion),
            _ => None,
        },
        [project, parent, field] if project == "project" && parent == "parent" => {
            match field.as_str() {
                "groupId" => Some(Leaf::ParentGroupId),
                "version" => Some(Leaf::ParentVersion),
                _ => None,
            }
        }
        [project, properties, _] if project == "project" && properties == "properties" => {
            Some(Leaf::Property)
        }
        [project, deps, dep, _]
            if project == "project" && deps == "dependencies" && dep == "dependency" =>
        {
            Some(Leaf::DependencyField)
        }
        [project, management, deps, dep, _]
            if project == "project"
                && management == "dependencyManagement"
                && deps == "dependencies"
                && dep == "dependency" =>
        {
            Some(Leaf::ManagedDependencyField)
        }
        _ => None,
    }
}

/// `Some(true)` if the path is a `<dependencies>/<dependency>` element,
/// `Some(false)` if it is a `<dependencyManagement>` one, `None`
/// otherwise. The boolean says which list a completed element joins.
fn dependency_element_is_direct(path: &[String]) -> Option<bool> {
    match path {
        [project, deps, dep]
            if project == "project" && deps == "dependencies" && dep == "dependency" =>
        {
            Some(true)
        }
        [project, management, deps, dep]
            if project == "project"
                && management == "dependencyManagement"
                && deps == "dependencies"
                && dep == "dependency" =>
        {
            Some(false)
        }
        _ => None,
    }
}

/// Pull-parse the POM into [`RawPom`].
///
/// # Errors
///
/// `Validation` when the bytes do not parse as XML, when the root element
/// is not `<project>`, when there is no element at all, or when nesting
/// exceeds [`MAX_ELEMENT_DEPTH`]. These are the "not a POM" cases; nothing
/// about the *content* of a well-formed POM can produce an error here.
fn read_pom_document(bytes: &[u8]) -> DomainResult<RawPom> {
    let mut reader = Reader::from_reader(bytes);
    let mut buf: Vec<u8> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut pom = RawPom::default();
    let mut current: Option<RawDependency> = None;
    let mut saw_root = false;

    loop {
        let event = reader.read_event_into(&mut buf).map_err(|e| {
            DomainError::Validation(format!("maven.pom: input is not parseable XML: {e}"))
        })?;
        match event {
            Event::Eof => break,
            Event::Start(start) => {
                let name = local_name_of(&start);
                if path.is_empty() {
                    if name != "project" {
                        return Err(not_a_pom(&name));
                    }
                    saw_root = true;
                }
                if path.len() >= MAX_ELEMENT_DEPTH {
                    return Err(DomainError::Validation(format!(
                        "maven.pom: element nesting exceeds {MAX_ELEMENT_DEPTH} levels; \
                         not a plausible POM"
                    )));
                }
                path.push(name);
                if dependency_element_is_direct(&path).is_some() {
                    current = Some(RawDependency::default());
                }
                text.clear();
            }
            Event::Empty(start) => {
                // `<version/>` is a start immediately followed by an end,
                // carrying no text. A self-closing ROOT is a document with
                // no dependencies at all, which is valid.
                let name = local_name_of(&start);
                if path.is_empty() {
                    if name != "project" {
                        return Err(not_a_pom(&name));
                    }
                    saw_root = true;
                } else {
                    path.push(name);
                    record_leaf(&path, "", &mut pom, current.as_mut());
                    path.pop();
                }
                text.clear();
            }
            Event::End(_) => {
                record_leaf(&path, &text, &mut pom, current.as_mut());
                if let Some(is_direct) = dependency_element_is_direct(&path) {
                    if let Some(dependency) = current.take() {
                        if is_direct {
                            pom.dependencies.push(dependency);
                        } else {
                            pom.managed.push(dependency);
                        }
                    }
                }
                path.pop();
                text.clear();
            }
            // Character data is decoded ONLY inside an element this
            // reader consumes; the guard is what keeps an undecodable
            // `<description>` from failing an otherwise-valid POM.
            Event::Text(chunk) if leaf_at(&path).is_some() => {
                if let Some(decoded) = decode_text(&chunk) {
                    text.push_str(&decoded);
                }
            }
            Event::CData(chunk) if leaf_at(&path).is_some() => {
                if let Ok(decoded) = chunk.decode() {
                    text.push_str(&decoded);
                }
            }
            Event::GeneralRef(reference) if leaf_at(&path).is_some() => {
                if let Some(resolved) = resolve_reference(&reference) {
                    text.push_str(&resolved);
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(DomainError::Validation(
            "maven.pom: input contains no XML element; expected a <project> document".to_string(),
        ));
    }
    Ok(pom)
}

/// The "wrong root element" rejection. The offending name is sanitised
/// before it reaches the message — it comes from artifact bytes.
fn not_a_pom(root: &str) -> DomainError {
    DomainError::Validation(format!(
        "maven.pom: root element is <{}>, expected <project>",
        sanitize(root)
    ))
}

/// Store one leaf element's text on the model it belongs to.
fn record_leaf(path: &[String], text: &str, pom: &mut RawPom, current: Option<&mut RawDependency>) {
    let Some(leaf) = leaf_at(path) else {
        return;
    };
    let value = text.trim();
    match leaf {
        Leaf::ProjectGroupId => pom.group_id = Some(value.to_string()),
        Leaf::ProjectVersion => pom.version = Some(value.to_string()),
        Leaf::ParentGroupId => pom.parent_group_id = Some(value.to_string()),
        Leaf::ParentVersion => pom.parent_version = Some(value.to_string()),
        Leaf::Property => {
            if let Some(name) = path.last() {
                pom.properties.insert(name.clone(), value.to_string());
            }
        }
        Leaf::DependencyField | Leaf::ManagedDependencyField => {
            if let (Some(dependency), Some(field)) = (current, path.last()) {
                dependency.set(field, value);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 2 — interpolate and classify
// ---------------------------------------------------------------------------

/// Property interpolation over one POM's own model.
struct Interpolator<'a> {
    properties: &'a HashMap<String, String>,
    /// The POM's effective version — its own `<version>`, or the parent's
    /// when it inherits (Maven's own rule, and computable from these bytes
    /// because `<parent><version>` is written in this document).
    project_version: Option<&'a str>,
    /// The POM's effective groupId, same inheritance rule.
    project_group_id: Option<&'a str>,
}

impl Interpolator<'_> {
    /// Resolve one `${...}` key. Model built-ins win over `<properties>`:
    /// Maven interpolates the model first, so a user property named
    /// `project.version` cannot shadow the real one.
    fn lookup(&self, key: &str) -> Option<String> {
        match key {
            "project.version" | "pom.version" => self.project_version.map(str::to_string),
            "project.groupId" | "pom.groupId" => self.project_group_id.map(str::to_string),
            _ => self.properties.get(key).cloned(),
        }
    }

    /// Expand every `${...}` in `input`, recursively.
    ///
    /// `None` when any placeholder is unknown, unterminated, or its
    /// expansion chain is longer than `depth` allows — which is also how a
    /// reference cycle terminates. Callers map `None` onto
    /// [`PomSkipReason::UnresolvedProperty`].
    fn expand(&self, input: &str, depth: usize) -> Option<String> {
        if !input.contains("${") {
            return Some(input.to_string());
        }
        if depth == 0 {
            return None;
        }
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = after.find('}')?;
            let expanded = self.expand(&self.lookup(&after[..end])?, depth - 1)?;
            out.push_str(&expanded);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }

    /// [`Self::expand`] from the configured depth ceiling.
    fn interpolate(&self, input: &str) -> Option<String> {
        self.expand(input, MAX_PROPERTY_EXPANSION_DEPTH)
    }
}

/// A Maven version *range* rather than a concrete version or a soft
/// requirement — `[1.0,2.0)`, `(,1.0]`, `[1.5,]`. Maven's grammar puts the
/// bracket first in every range form, so the leading character is the
/// whole test.
fn is_version_range(version: &str) -> bool {
    version.starts_with('[') || version.starts_with('(')
}

/// A non-empty trimmed view of an optional element, or `None`. `<version/>`
/// and `<version>   </version>` mean the same thing as an absent element.
fn present(value: &Option<String>) -> Option<&str> {
    let trimmed = value.as_deref()?.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Strip control characters and truncate — applied to every fragment of
/// artifact-supplied text that reaches an error message or a skip record.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(SKIP_COORDINATE_MAX_CHARS)
        .collect()
}

/// Turn the raw model into resolved specs plus counted skips.
fn resolve(pom: &RawPom) -> PomDependencies {
    let project_version = present(&pom.version).or_else(|| present(&pom.parent_version));
    let project_group_id = present(&pom.group_id).or_else(|| present(&pom.parent_group_id));
    let interpolator = Interpolator {
        properties: &pom.properties,
        project_version,
        project_group_id,
    };

    // Index this POM's own `<dependencyManagement>` by resolved
    // `groupId:artifactId`. Maven also keys management on type and
    // classifier; collapsing to the GA pair can only ever widen what
    // resolves, and two managed entries for one GA that disagree on
    // version are a POM defect Maven itself warns about. First entry
    // wins, matching Maven's "nearest and first" management precedence.
    let mut managed: HashMap<String, &RawDependency> = HashMap::new();
    for entry in &pom.managed {
        let (Some(group), Some(artifact)) = (present(&entry.group_id), present(&entry.artifact_id))
        else {
            continue;
        };
        let (Some(group), Some(artifact)) = (
            interpolator.interpolate(group),
            interpolator.interpolate(artifact),
        ) else {
            continue;
        };
        managed
            .entry(format!("{group}:{artifact}"))
            .or_insert(entry);
    }

    let mut out = PomDependencies::default();
    for dependency in &pom.dependencies {
        // -- identity -----------------------------------------------------
        let (Some(group), Some(artifact)) = (
            present(&dependency.group_id),
            present(&dependency.artifact_id),
        ) else {
            out.skipped.push(PomSkip {
                coordinate: raw_label(dependency),
                reason: PomSkipReason::IncompleteCoordinate,
            });
            continue;
        };
        let (Some(group), Some(artifact)) = (
            interpolator.interpolate(group),
            interpolator.interpolate(artifact),
        ) else {
            out.skipped.push(PomSkip {
                coordinate: raw_label(dependency),
                reason: PomSkipReason::UnresolvedProperty,
            });
            continue;
        };
        let coordinate = format!("{group}:{artifact}");
        let managed_entry = managed.get(&coordinate).copied();

        // -- scope --------------------------------------------------------
        //
        // The dependency's own `<scope>` wins; otherwise a managed entry
        // may set it; otherwise Maven's `compile` default applies. A scope
        // outside `EMITTED_SCOPES` is a counted skip — the boundary itself
        // stays visible to an operator reading the counts, not just the
        // gaps within it (see `PomSkipReason::ScopeExcluded`).
        let declared_scope = present(&dependency.scope)
            .or_else(|| managed_entry.and_then(|entry| present(&entry.scope)));
        let scope = match declared_scope {
            None => DEFAULT_SCOPE.to_string(),
            Some(raw) => match interpolator.interpolate(raw) {
                Some(scope) => scope,
                None => {
                    out.skipped.push(PomSkip {
                        coordinate: sanitize(&coordinate),
                        reason: PomSkipReason::UnresolvedProperty,
                    });
                    continue;
                }
            },
        };
        if !EMITTED_SCOPES.contains(&scope.trim()) {
            out.skipped.push(PomSkip {
                coordinate: sanitize(&coordinate),
                reason: PomSkipReason::ScopeExcluded,
            });
            continue;
        }

        // -- version ------------------------------------------------------
        let declared_version = present(&dependency.version)
            .or_else(|| managed_entry.and_then(|entry| present(&entry.version)));
        let Some(declared_version) = declared_version else {
            out.skipped.push(PomSkip {
                coordinate: sanitize(&coordinate),
                reason: PomSkipReason::VersionFromParentOrBom,
            });
            continue;
        };
        let Some(version) = interpolator.interpolate(declared_version) else {
            out.skipped.push(PomSkip {
                coordinate: sanitize(&coordinate),
                reason: PomSkipReason::UnresolvedProperty,
            });
            continue;
        };
        let version = version.trim();
        if version.is_empty() {
            out.skipped.push(PomSkip {
                coordinate: sanitize(&coordinate),
                reason: PomSkipReason::VersionFromParentOrBom,
            });
            continue;
        }
        if is_version_range(version) {
            out.skipped.push(PomSkip {
                coordinate: sanitize(&coordinate),
                reason: PomSkipReason::UnsupportedRange,
            });
            continue;
        }

        out.specs.push(DependencySpec {
            name: coordinate,
            range: version.to_string(),
        });
    }
    out
}

/// Best-effort label for a dependency whose coordinate did not resolve —
/// the raw, uninterpolated text with a `?` standing in for an absent
/// half, so a skip record still says which declaration it came from.
fn raw_label(dependency: &RawDependency) -> String {
    let group = present(&dependency.group_id).unwrap_or("?");
    let artifact = present(&dependency.artifact_id).unwrap_or("?");
    sanitize(&format!("{group}:{artifact}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(xml: &str) -> PomDependencies {
        parse_pom_dependencies(&mut Cursor::new(xml.as_bytes())).expect("well-formed POM parses")
    }

    fn spec(name: &str, range: &str) -> DependencySpec {
        DependencySpec {
            name: name.to_string(),
            range: range.to_string(),
        }
    }

    fn reasons(result: &PomDependencies) -> Vec<PomSkipReason> {
        result.skipped.iter().map(|s| s.reason).collect()
    }

    /// A POM with a `<dependencies>` block wrapped in the usual preamble.
    fn pom_with(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.2.3</version>
{body}
</project>"#
        )
    }

    // -- happy paths ---------------------------------------------------------

    #[test]
    fn flat_pom_yields_every_compile_dependency() {
        let result = parse(&pom_with(
            r#"<dependencies>
                 <dependency>
                   <groupId>com.google.guava</groupId>
                   <artifactId>guava</artifactId>
                   <version>31.1-jre</version>
                 </dependency>
                 <dependency>
                   <groupId>org.slf4j</groupId>
                   <artifactId>slf4j-api</artifactId>
                   <version>2.0.9</version>
                   <scope>compile</scope>
                 </dependency>
               </dependencies>"#,
        ));
        assert_eq!(
            result.specs,
            [
                spec("com.google.guava:guava", "31.1-jre"),
                spec("org.slf4j:slf4j-api", "2.0.9"),
            ]
        );
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn own_properties_resolve() {
        let result = parse(&pom_with(
            r#"<properties>
                 <guava.version>31.1-jre</guava.version>
                 <slf4j.group>org.slf4j</slf4j.group>
               </properties>
               <dependencies>
                 <dependency>
                   <groupId>com.google.guava</groupId>
                   <artifactId>guava</artifactId>
                   <version>${guava.version}</version>
                 </dependency>
                 <dependency>
                   <groupId>${slf4j.group}</groupId>
                   <artifactId>slf4j-api</artifactId>
                   <version>2.0.9</version>
                 </dependency>
               </dependencies>"#,
        ));
        assert_eq!(
            result.specs,
            [
                spec("com.google.guava:guava", "31.1-jre"),
                spec("org.slf4j:slf4j-api", "2.0.9"),
            ]
        );
    }

    #[test]
    fn property_values_expand_transitively() {
        let result = parse(&pom_with(
            r#"<properties>
                 <base>2.0</base>
                 <slf4j.version>${base}.9</slf4j.version>
               </properties>
               <dependencies>
                 <dependency>
                   <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
                   <version>${slf4j.version}</version>
                 </dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("org.slf4j:slf4j-api", "2.0.9")]);
    }

    #[test]
    fn project_builtins_and_their_pom_spellings_resolve() {
        let result = parse(&pom_with(
            r#"<dependencies>
                 <dependency>
                   <groupId>${project.groupId}</groupId><artifactId>core</artifactId>
                   <version>${project.version}</version>
                 </dependency>
                 <dependency>
                   <groupId>${pom.groupId}</groupId><artifactId>api</artifactId>
                   <version>${pom.version}</version>
                 </dependency>
               </dependencies>"#,
        ));
        assert_eq!(
            result.specs,
            [
                spec("com.example:core", "1.2.3"),
                spec("com.example:api", "1.2.3"),
            ]
        );
    }

    #[test]
    fn builtins_fall_back_to_the_parent_coordinates_when_inherited() {
        // The POM declares neither `<groupId>` nor `<version>` of its own;
        // Maven's effective values come from `<parent>`, which is written
        // in these same bytes.
        let result = parse(
            r#"<project>
                 <parent>
                   <groupId>com.example</groupId>
                   <artifactId>parent</artifactId>
                   <version>4.5.6</version>
                 </parent>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <groupId>${project.groupId}</groupId><artifactId>sibling</artifactId>
                     <version>${project.version}</version>
                   </dependency>
                 </dependencies>
               </project>"#,
        );
        assert_eq!(result.specs, [spec("com.example:sibling", "4.5.6")]);
    }

    #[test]
    fn own_version_wins_over_the_parent_version() {
        let result = parse(
            r#"<project>
                 <parent><groupId>com.example</groupId><artifactId>p</artifactId>
                   <version>4.5.6</version></parent>
                 <artifactId>child</artifactId>
                 <version>9.9.9</version>
                 <dependencies>
                   <dependency><groupId>com.example</groupId><artifactId>sibling</artifactId>
                     <version>${project.version}</version></dependency>
                 </dependencies>
               </project>"#,
        );
        assert_eq!(result.specs, [spec("com.example:sibling", "9.9.9")]);
    }

    #[test]
    fn own_dependency_management_supplies_a_missing_version() {
        let result = parse(&pom_with(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency>
                     <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
                     <version>2.0.9</version>
                   </dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency>
                   <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
                 </dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("org.slf4j:slf4j-api", "2.0.9")]);
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn a_managed_scope_applies_when_the_dependency_declares_none() {
        let result = parse(&pom_with(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency>
                     <groupId>org.junit</groupId><artifactId>junit</artifactId>
                     <version>5.10.0</version><scope>test</scope>
                   </dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency><groupId>org.junit</groupId><artifactId>junit</artifactId></dependency>
               </dependencies>"#,
        ));
        assert!(result.specs.is_empty(), "managed test scope excludes it");
        assert_eq!(reasons(&result), [PomSkipReason::ScopeExcluded]);
    }

    #[test]
    fn a_declared_scope_wins_over_the_managed_one() {
        let result = parse(&pom_with(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency><groupId>g</groupId><artifactId>a</artifactId>
                     <version>1.0</version><scope>test</scope></dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency><groupId>g</groupId><artifactId>a</artifactId>
                   <scope>compile</scope></dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn a_managed_runtime_scope_applies_when_the_dependency_declares_none() {
        let result = parse(&pom_with(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency>
                     <groupId>org.postgresql</groupId><artifactId>postgresql</artifactId>
                     <version>42.7.3</version><scope>runtime</scope>
                   </dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("org.postgresql:postgresql", "42.7.3")]);
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn a_declared_runtime_scope_wins_over_a_managed_test_scope() {
        let result = parse(&pom_with(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency><groupId>g</groupId><artifactId>a</artifactId>
                     <version>1.0</version><scope>test</scope></dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency><groupId>g</groupId><artifactId>a</artifactId>
                   <scope>runtime</scope></dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
        assert!(result.skipped.is_empty());
    }

    // -- scope filter --------------------------------------------------------

    #[test]
    fn runtime_scope_is_emitted_like_compile() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>org.postgresql</groupId>
             <artifactId>postgresql</artifactId><version>42.7.3</version>
             <scope>runtime</scope></dependency></dependencies>",
        ));
        assert_eq!(result.specs, [spec("org.postgresql:postgresql", "42.7.3")]);
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn non_emitted_scopes_are_excluded_and_counted() {
        let mut body = String::from("<dependencies>");
        for scope in ["test", "provided", "system", "import"] {
            body.push_str(&format!(
                "<dependency><groupId>g</groupId><artifactId>{scope}</artifactId>
                 <version>1.0</version><scope>{scope}</scope></dependency>"
            ));
        }
        body.push_str(
            "<dependency><groupId>g</groupId><artifactId>kept</artifactId>
             <version>1.0</version></dependency></dependencies>",
        );
        let result = parse(&pom_with(&body));
        assert_eq!(result.specs, [spec("g:kept", "1.0")]);
        assert_eq!(result.skip_count(PomSkipReason::ScopeExcluded), 4);
        assert!(reasons(&result)
            .iter()
            .all(|r| *r == PomSkipReason::ScopeExcluded));
    }

    #[test]
    fn an_absent_scope_is_compile() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
             <version>1.0</version></dependency></dependencies>",
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn an_empty_scope_element_is_compile() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
             <version>1.0</version><scope/></dependency></dependencies>",
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn a_scope_written_as_a_property_resolves() {
        let result = parse(&pom_with(
            r#"<properties><dep.scope>compile</dep.scope></properties>
               <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>1.0</version><scope>${dep.scope}</scope></dependency></dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn an_unresolvable_scope_property_is_a_counted_skip() {
        let result = parse(&pom_with(
            r#"<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>1.0</version><scope>${from.parent}</scope></dependency></dependencies>"#,
        ));
        assert!(result.specs.is_empty());
        assert_eq!(reasons(&result), [PomSkipReason::UnresolvedProperty]);
    }

    // -- skip reasons --------------------------------------------------------

    #[test]
    fn a_version_deferred_to_a_parent_is_counted_distinguishably() {
        let result = parse(&pom_with(
            "<dependencies>
               <dependency><groupId>org.springframework.boot</groupId>
                 <artifactId>spring-boot-starter-web</artifactId></dependency>
               <dependency><groupId>g</groupId><artifactId>b</artifactId>
                 <version>${unknown.version}</version></dependency>
             </dependencies>",
        ));
        assert!(result.specs.is_empty());
        assert_eq!(
            reasons(&result),
            [
                PomSkipReason::VersionFromParentOrBom,
                PomSkipReason::UnresolvedProperty,
            ],
            "a deferred version and an unresolvable property must not collapse into one reason"
        );
        assert_eq!(
            result.skipped[0].coordinate,
            "org.springframework.boot:spring-boot-starter-web"
        );
        assert_eq!(result.skip_count(PomSkipReason::VersionFromParentOrBom), 1);
        assert_eq!(result.skip_count(PomSkipReason::UnresolvedProperty), 1);
    }

    #[test]
    fn an_empty_version_element_counts_as_deferred() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
             <version>  </version></dependency></dependencies>",
        ));
        assert_eq!(reasons(&result), [PomSkipReason::VersionFromParentOrBom]);
    }

    #[test]
    fn a_property_that_expands_to_nothing_counts_as_deferred() {
        // `<empty/>` is a declared property whose value is the empty
        // string: the placeholder RESOLVES, so this is not an unresolved
        // property — there is simply no version to enqueue.
        let result = parse(&pom_with(
            r#"<properties><empty/></properties>
               <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>${empty}</version></dependency></dependencies>"#,
        ));
        assert_eq!(reasons(&result), [PomSkipReason::VersionFromParentOrBom]);
    }

    #[test]
    fn maven_version_ranges_are_counted_skips() {
        let mut body = String::from("<dependencies>");
        for (index, range) in ["[1.0,2.0)", "(,1.0]", "[1.5,]", "[1.0]"]
            .iter()
            .enumerate()
        {
            body.push_str(&format!(
                "<dependency><groupId>g</groupId><artifactId>a{index}</artifactId>
                 <version>{range}</version></dependency>"
            ));
        }
        body.push_str("</dependencies>");
        let result = parse(&pom_with(&body));
        assert!(result.specs.is_empty());
        assert_eq!(result.skip_count(PomSkipReason::UnsupportedRange), 4);
    }

    #[test]
    fn a_range_reached_through_a_property_is_still_a_range_skip() {
        let result = parse(&pom_with(
            r#"<properties><r>[1.0,2.0)</r></properties>
               <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>${r}</version></dependency></dependencies>"#,
        ));
        assert_eq!(reasons(&result), [PomSkipReason::UnsupportedRange]);
    }

    #[test]
    fn a_missing_coordinate_half_is_counted_as_incomplete() {
        let result = parse(&pom_with(
            "<dependencies>
               <dependency><artifactId>orphan</artifactId><version>1.0</version></dependency>
               <dependency><groupId>g</groupId><version>1.0</version></dependency>
             </dependencies>",
        ));
        assert!(result.specs.is_empty());
        assert_eq!(
            reasons(&result),
            [
                PomSkipReason::IncompleteCoordinate,
                PomSkipReason::IncompleteCoordinate
            ]
        );
        assert_eq!(result.skipped[0].coordinate, "?:orphan");
        assert_eq!(result.skipped[1].coordinate, "g:?");
    }

    #[test]
    fn an_unresolvable_coordinate_property_is_not_an_incomplete_coordinate() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>${from.parent}</groupId>
             <artifactId>a</artifactId><version>1.0</version></dependency></dependencies>",
        ));
        assert_eq!(reasons(&result), [PomSkipReason::UnresolvedProperty]);
        assert_eq!(result.skipped[0].coordinate, "${from.parent}:a");
    }

    #[test]
    fn a_property_reference_cycle_terminates_as_unresolved() {
        let result = parse(&pom_with(
            r#"<properties><a>${b}</a><b>${a}</b></properties>
               <dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>
                 <version>${a}</version></dependency></dependencies>"#,
        ));
        assert_eq!(reasons(&result), [PomSkipReason::UnresolvedProperty]);
    }

    #[test]
    fn an_unterminated_placeholder_is_unresolved_not_an_error() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>
             <version>${oops</version></dependency></dependencies>",
        ));
        assert_eq!(reasons(&result), [PomSkipReason::UnresolvedProperty]);
    }

    #[test]
    fn skip_counts_report_every_reason_including_zeroes() {
        let result = parse(&pom_with(
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
             </dependency></dependencies>",
        ));
        let counts = result.skip_counts();
        assert_eq!(counts.len(), PomSkipReason::ALL.len());
        assert_eq!(counts[0], (PomSkipReason::VersionFromParentOrBom, 1));
        assert_eq!(counts[1], (PomSkipReason::UnresolvedProperty, 0));
        assert_eq!(counts[2], (PomSkipReason::UnsupportedRange, 0));
        assert_eq!(counts[3], (PomSkipReason::IncompleteCoordinate, 0));
        assert_eq!(counts[4], (PomSkipReason::ScopeExcluded, 0));
    }

    #[test]
    fn every_reason_has_a_distinct_stable_label() {
        let labels: Vec<&str> = PomSkipReason::ALL.iter().map(|r| r.as_str()).collect();
        let mut sorted = labels.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "labels must be distinguishable");
        assert!(labels
            .iter()
            .all(|l| l.chars().all(|c| c.is_ascii_lowercase() || c == '_')));
    }

    // -- Ok(vec![]) vs Err ---------------------------------------------------

    #[test]
    fn a_pom_with_no_dependencies_is_ok_and_empty() {
        let result = parse(&pom_with(""));
        assert!(result.specs.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn an_empty_dependencies_block_is_ok_and_empty() {
        assert!(parse(&pom_with("<dependencies/>")).specs.is_empty());
        assert!(parse(&pom_with("<dependencies></dependencies>"))
            .specs
            .is_empty());
    }

    #[test]
    fn a_self_closing_project_root_is_ok_and_empty() {
        assert!(parse("<project/>").specs.is_empty());
    }

    #[test]
    fn a_pom_whose_versions_all_live_in_a_parent_is_ok_not_err() {
        // The regression this reader exists to avoid: a Spring-Boot-shaped
        // POM must partially warm the tree, never abort the cascade.
        let result = parse(
            r#"<project>
                 <parent><groupId>org.springframework.boot</groupId>
                   <artifactId>spring-boot-starter-parent</artifactId>
                   <version>3.2.0</version></parent>
                 <artifactId>demo</artifactId>
                 <dependencies>
                   <dependency><groupId>org.springframework.boot</groupId>
                     <artifactId>spring-boot-starter-web</artifactId></dependency>
                   <dependency><groupId>org.springframework.boot</groupId>
                     <artifactId>spring-boot-starter-test</artifactId>
                     <scope>test</scope></dependency>
                 </dependencies>
               </project>"#,
        );
        assert!(result.specs.is_empty());
        assert_eq!(result.skip_count(PomSkipReason::VersionFromParentOrBom), 1);
        assert_eq!(result.skip_count(PomSkipReason::ScopeExcluded), 1);
    }

    #[test]
    fn non_xml_bytes_are_err() {
        for bytes in [
            &b"PK\x03\x04rest-of-a-zip"[..],
            &b"\x1f\x8bgzip"[..],
            &b"{\"name\":\"not-a-pom\"}"[..],
            &b""[..],
        ] {
            let err = parse_pom_dependencies(&mut Cursor::new(bytes))
                .expect_err("non-POM bytes must be Err");
            assert!(matches!(err, DomainError::Validation(_)), "{err:?}");
        }
    }

    #[test]
    fn a_non_project_xml_root_is_err() {
        let err = parse_pom_dependencies(&mut Cursor::new(
            b"<metadata><versioning/></metadata>".as_slice(),
        ))
        .expect_err("wrong root must be Err");
        assert!(err.to_string().contains("expected <project>"));
    }

    #[test]
    fn a_self_closing_non_project_root_is_err() {
        let err = parse_pom_dependencies(&mut Cursor::new(b"<metadata/>".as_slice()))
            .expect_err("wrong self-closing root must be Err");
        assert!(err.to_string().contains("expected <project>"));
    }

    #[test]
    fn unparseable_xml_is_err() {
        let err = parse_pom_dependencies(&mut Cursor::new(
            b"<project><dependencies></project>".as_slice(),
        ))
        .expect_err("mismatched tags must be Err");
        assert!(err.to_string().contains("maven.pom"));
    }

    #[test]
    fn a_body_over_the_cap_is_err() {
        let mut oversized = vec![b'x'; POM_MAX_BYTES + 1];
        oversized[..9].copy_from_slice(b"<project>");
        let err = parse_pom_dependencies(&mut Cursor::new(oversized.as_slice()))
            .expect_err("over-cap body must be Err");
        assert!(err.to_string().contains("maven pom max is"));
    }

    #[test]
    fn a_nesting_bomb_is_err() {
        let mut xml = String::from("<project>");
        for _ in 0..(MAX_ELEMENT_DEPTH + 5) {
            xml.push_str("<a>");
        }
        let err = parse_pom_dependencies(&mut Cursor::new(xml.as_bytes()))
            .expect_err("nesting bomb must be Err");
        assert!(err.to_string().contains("element nesting exceeds"));
    }

    // -- what must NOT be read ----------------------------------------------

    #[test]
    fn profile_and_plugin_dependencies_are_not_read() {
        let result = parse(&pom_with(
            r#"<build><plugins><plugin>
                 <groupId>org.apache.maven.plugins</groupId>
                 <artifactId>maven-surefire-plugin</artifactId>
                 <dependencies><dependency><groupId>plugin</groupId>
                   <artifactId>dep</artifactId><version>1.0</version></dependency></dependencies>
               </plugin></plugins></build>
               <profiles><profile><id>it</id>
                 <dependencies><dependency><groupId>profile</groupId>
                   <artifactId>dep</artifactId><version>1.0</version></dependency></dependencies>
               </profile></profiles>
               <dependencies><dependency><groupId>real</groupId>
                 <artifactId>dep</artifactId><version>1.0</version></dependency></dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("real:dep", "1.0")]);
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn dependency_management_alone_declares_nothing() {
        // A BOM POM: everything lives in `<dependencyManagement>` and the
        // POM declares no `<dependencies>` of its own. Nothing to warm,
        // and nothing skipped — there is no declaration to have missed.
        let result = parse(&pom_with(
            "<packaging>pom</packaging>
             <dependencyManagement><dependencies>
               <dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>1.0</version></dependency>
             </dependencies></dependencyManagement>",
        ));
        assert!(result.specs.is_empty());
        assert!(result.skipped.is_empty());
    }

    // -- robustness ----------------------------------------------------------

    #[test]
    fn comments_and_cdata_inside_values_are_handled() {
        let result = parse(&pom_with(
            r#"<dependencies><dependency>
                 <groupId><![CDATA[com.example]]></groupId>
                 <artifactId>a<!-- inline comment -->pp</artifactId>
                 <version>1.<!--x-->0</version>
               </dependency></dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("com.example:app", "1.0")]);
    }

    #[test]
    fn an_explicit_namespace_prefix_still_parses() {
        let result = parse(
            r#"<m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
                 <m:groupId>com.example</m:groupId>
                 <m:artifactId>app</m:artifactId>
                 <m:version>1.0</m:version>
                 <m:dependencies><m:dependency>
                   <m:groupId>g</m:groupId><m:artifactId>a</m:artifactId>
                   <m:version>${project.version}</m:version>
                 </m:dependency></m:dependencies>
               </m:project>"#,
        );
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn undecodable_bytes_outside_the_read_elements_do_not_fail_the_pom() {
        // A Latin-1 `<description>` is not valid UTF-8, but this reader
        // never decodes it, so the `<dependencies>` still resolve.
        let mut bytes = Vec::from(
            &b"<project><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version>
               <description>caf"[..],
        );
        bytes.push(0xE9);
        bytes.extend_from_slice(
            b"</description>
              <dependencies><dependency><groupId>g</groupId><artifactId>b</artifactId>
                <version>2.0</version></dependency></dependencies></project>",
        );
        let result =
            parse_pom_dependencies(&mut Cursor::new(bytes.as_slice())).expect("still a valid POM");
        assert_eq!(result.specs, [spec("g:b", "2.0")]);
    }

    #[test]
    fn a_skip_coordinate_is_stripped_of_control_characters_and_truncated() {
        let long = "a".repeat(SKIP_COORDINATE_MAX_CHARS + 50);
        let result = parse(&pom_with(&format!(
            "<dependencies><dependency><groupId>g</groupId>
             <artifactId>{long}</artifactId></dependency></dependencies>"
        )));
        let coordinate = &result.skipped[0].coordinate;
        assert_eq!(coordinate.chars().count(), SKIP_COORDINATE_MAX_CHARS);
        assert!(!coordinate.chars().any(char::is_control));
    }

    #[test]
    fn a_later_duplicate_managed_entry_does_not_override_the_first() {
        let result = parse(&pom_with(
            "<dependencyManagement><dependencies>
               <dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>1.0</version></dependency>
               <dependency><groupId>g</groupId><artifactId>a</artifactId>
                 <version>2.0</version></dependency>
             </dependencies></dependencyManagement>
             <dependencies>
               <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
             </dependencies>",
        ));
        assert_eq!(result.specs, [spec("g:a", "1.0")]);
    }

    #[test]
    fn a_managed_entry_reached_through_properties_still_matches() {
        let result = parse(&pom_with(
            r#"<properties><g>org.slf4j</g></properties>
               <dependencyManagement><dependencies>
                 <dependency><groupId>${g}</groupId><artifactId>slf4j-api</artifactId>
                   <version>2.0.9</version></dependency>
               </dependencies></dependencyManagement>
               <dependencies>
                 <dependency><groupId>${g}</groupId><artifactId>slf4j-api</artifactId></dependency>
               </dependencies>"#,
        ));
        assert_eq!(result.specs, [spec("org.slf4j:slf4j-api", "2.0.9")]);
    }

    #[test]
    fn an_unresolvable_managed_coordinate_is_simply_not_indexed() {
        let result = parse(&pom_with(
            "<dependencyManagement><dependencies>
               <dependency><groupId>${nope}</groupId><artifactId>a</artifactId>
                 <version>1.0</version></dependency>
             </dependencies></dependencyManagement>
             <dependencies>
               <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
             </dependencies>",
        ));
        assert_eq!(reasons(&result), [PomSkipReason::VersionFromParentOrBom]);
    }

    #[test]
    fn an_incomplete_managed_entry_is_simply_not_indexed() {
        let result = parse(&pom_with(
            "<dependencyManagement><dependencies>
               <dependency><artifactId>a</artifactId><version>1.0</version></dependency>
             </dependencies></dependencyManagement>
             <dependencies>
               <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
             </dependencies>",
        ));
        assert_eq!(reasons(&result), [PomSkipReason::VersionFromParentOrBom]);
    }
}
