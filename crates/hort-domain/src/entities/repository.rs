use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

// ---------------------------------------------------------------------------
// RepositoryFormat
// ---------------------------------------------------------------------------

/// Package format that a repository hosts.
///
/// Known formats get their own variant for exhaustive matching. WASM plugin
/// formats that are not compiled-in land in [`Other`](Self::Other).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryFormat {
    Maven,
    Gradle,
    Npm,
    Pypi,
    Nuget,
    Go,
    Rubygems,
    Docker,
    /// OCI Distribution Spec v1.1 — protocol-level format served by
    /// the `hort-http-oci` handler. Distinct from `Docker` (legacy
    /// docker-specific behaviour) and `WasmOci` / `HelmOci` (subtype
    /// aliases). Generic OCI clients (skopeo, crane, podman pulls,
    /// docker pulls, helm-OCI, buildah) all push to this format.
    Oci,
    Helm,
    Rpm,
    Debian,
    Conan,
    Cargo,
    Generic,
    // OCI-based aliases
    Podman,
    Buildx,
    Oras,
    WasmOci,
    HelmOci,
    // PyPI-based aliases
    Poetry,
    Conda,
    // npm-based aliases
    Yarn,
    Bower,
    Pnpm,
    // NuGet-based aliases
    Chocolatey,
    Powershell,
    // Native format handlers
    Terraform,
    Opentofu,
    Alpine,
    CondaNative,
    Composer,
    // Language-specific
    Hex,
    Cocoapods,
    Swift,
    Pub,
    Sbt,
    // Config management
    Chef,
    Puppet,
    Ansible,
    // Git LFS
    Gitlfs,
    // Editor extensions
    Vscode,
    Jetbrains,
    // ML/AI
    Huggingface,
    Mlmodel,
    // Miscellaneous
    Cran,
    Vagrant,
    Opkg,
    P2,
    Bazel,
    // Schema registries
    Protobuf,
    // Container images
    Incus,
    Lxc,
    // WASM-plugin-provided formats
    Other(String),
}

type FormatEntry = (&'static str, fn() -> RepositoryFormat);

/// All known format names, in the same order as the enum variants.
const KNOWN_FORMATS: &[FormatEntry] = &[
    ("maven", || RepositoryFormat::Maven),
    ("gradle", || RepositoryFormat::Gradle),
    ("npm", || RepositoryFormat::Npm),
    ("pypi", || RepositoryFormat::Pypi),
    ("nuget", || RepositoryFormat::Nuget),
    ("go", || RepositoryFormat::Go),
    ("rubygems", || RepositoryFormat::Rubygems),
    ("docker", || RepositoryFormat::Docker),
    ("oci", || RepositoryFormat::Oci),
    ("helm", || RepositoryFormat::Helm),
    ("rpm", || RepositoryFormat::Rpm),
    ("debian", || RepositoryFormat::Debian),
    ("conan", || RepositoryFormat::Conan),
    ("cargo", || RepositoryFormat::Cargo),
    ("generic", || RepositoryFormat::Generic),
    ("podman", || RepositoryFormat::Podman),
    ("buildx", || RepositoryFormat::Buildx),
    ("oras", || RepositoryFormat::Oras),
    ("wasm_oci", || RepositoryFormat::WasmOci),
    ("helm_oci", || RepositoryFormat::HelmOci),
    ("poetry", || RepositoryFormat::Poetry),
    ("conda", || RepositoryFormat::Conda),
    ("yarn", || RepositoryFormat::Yarn),
    ("bower", || RepositoryFormat::Bower),
    ("pnpm", || RepositoryFormat::Pnpm),
    ("chocolatey", || RepositoryFormat::Chocolatey),
    ("powershell", || RepositoryFormat::Powershell),
    ("terraform", || RepositoryFormat::Terraform),
    ("opentofu", || RepositoryFormat::Opentofu),
    ("alpine", || RepositoryFormat::Alpine),
    ("conda_native", || RepositoryFormat::CondaNative),
    ("composer", || RepositoryFormat::Composer),
    ("hex", || RepositoryFormat::Hex),
    ("cocoapods", || RepositoryFormat::Cocoapods),
    ("swift", || RepositoryFormat::Swift),
    ("pub", || RepositoryFormat::Pub),
    ("sbt", || RepositoryFormat::Sbt),
    ("chef", || RepositoryFormat::Chef),
    ("puppet", || RepositoryFormat::Puppet),
    ("ansible", || RepositoryFormat::Ansible),
    ("gitlfs", || RepositoryFormat::Gitlfs),
    ("vscode", || RepositoryFormat::Vscode),
    ("jetbrains", || RepositoryFormat::Jetbrains),
    ("huggingface", || RepositoryFormat::Huggingface),
    ("mlmodel", || RepositoryFormat::Mlmodel),
    ("cran", || RepositoryFormat::Cran),
    ("vagrant", || RepositoryFormat::Vagrant),
    ("opkg", || RepositoryFormat::Opkg),
    ("p2", || RepositoryFormat::P2),
    ("bazel", || RepositoryFormat::Bazel),
    ("protobuf", || RepositoryFormat::Protobuf),
    ("incus", || RepositoryFormat::Incus),
    ("lxc", || RepositoryFormat::Lxc),
];

impl fmt::Display for RepositoryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Maven => f.write_str("maven"),
            Self::Gradle => f.write_str("gradle"),
            Self::Npm => f.write_str("npm"),
            Self::Pypi => f.write_str("pypi"),
            Self::Nuget => f.write_str("nuget"),
            Self::Go => f.write_str("go"),
            Self::Rubygems => f.write_str("rubygems"),
            Self::Docker => f.write_str("docker"),
            Self::Oci => f.write_str("oci"),
            Self::Helm => f.write_str("helm"),
            Self::Rpm => f.write_str("rpm"),
            Self::Debian => f.write_str("debian"),
            Self::Conan => f.write_str("conan"),
            Self::Cargo => f.write_str("cargo"),
            Self::Generic => f.write_str("generic"),
            Self::Podman => f.write_str("podman"),
            Self::Buildx => f.write_str("buildx"),
            Self::Oras => f.write_str("oras"),
            Self::WasmOci => f.write_str("wasm_oci"),
            Self::HelmOci => f.write_str("helm_oci"),
            Self::Poetry => f.write_str("poetry"),
            Self::Conda => f.write_str("conda"),
            Self::Yarn => f.write_str("yarn"),
            Self::Bower => f.write_str("bower"),
            Self::Pnpm => f.write_str("pnpm"),
            Self::Chocolatey => f.write_str("chocolatey"),
            Self::Powershell => f.write_str("powershell"),
            Self::Terraform => f.write_str("terraform"),
            Self::Opentofu => f.write_str("opentofu"),
            Self::Alpine => f.write_str("alpine"),
            Self::CondaNative => f.write_str("conda_native"),
            Self::Composer => f.write_str("composer"),
            Self::Hex => f.write_str("hex"),
            Self::Cocoapods => f.write_str("cocoapods"),
            Self::Swift => f.write_str("swift"),
            Self::Pub => f.write_str("pub"),
            Self::Sbt => f.write_str("sbt"),
            Self::Chef => f.write_str("chef"),
            Self::Puppet => f.write_str("puppet"),
            Self::Ansible => f.write_str("ansible"),
            Self::Gitlfs => f.write_str("gitlfs"),
            Self::Vscode => f.write_str("vscode"),
            Self::Jetbrains => f.write_str("jetbrains"),
            Self::Huggingface => f.write_str("huggingface"),
            Self::Mlmodel => f.write_str("mlmodel"),
            Self::Cran => f.write_str("cran"),
            Self::Vagrant => f.write_str("vagrant"),
            Self::Opkg => f.write_str("opkg"),
            Self::P2 => f.write_str("p2"),
            Self::Bazel => f.write_str("bazel"),
            Self::Protobuf => f.write_str("protobuf"),
            Self::Incus => f.write_str("incus"),
            Self::Lxc => f.write_str("lxc"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

impl FromStr for RepositoryFormat {
    type Err = std::convert::Infallible;

    /// Parses a format name. Known formats map to their variant; anything
    /// else becomes [`Other`](Self::Other). This never fails.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        for &(name, ref ctor) in KNOWN_FORMATS {
            if lower == name {
                return Ok(ctor());
            }
        }
        Ok(Self::Other(lower))
    }
}

// ---------------------------------------------------------------------------
// RepositoryType
// ---------------------------------------------------------------------------

/// Whether a repository hosts its own content, proxies an upstream, or
/// aggregates other repositories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryType {
    /// Hosts uploaded artifacts directly.
    Hosted,
    /// Proxies and caches from an upstream registry.
    Proxy,
    /// Aggregates multiple hosted/proxy repositories.
    Virtual,
    /// Like Hosted, but artifacts require promotion before release.
    Staging,
}

impl RepositoryType {
    /// `true` for Staging repositories only.
    pub fn is_staging(&self) -> bool {
        matches!(self, Self::Staging)
    }

    /// `true` for repository types that accept uploads (Hosted and Staging).
    pub fn is_hosted(&self) -> bool {
        matches!(self, Self::Hosted | Self::Staging)
    }
}

impl fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hosted => f.write_str("hosted"),
            Self::Proxy => f.write_str("proxy"),
            Self::Virtual => f.write_str("virtual"),
            Self::Staging => f.write_str("staging"),
        }
    }
}

impl FromStr for RepositoryType {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hosted" => Ok(Self::Hosted),
            "proxy" => Ok(Self::Proxy),
            "virtual" => Ok(Self::Virtual),
            "staging" => Ok(Self::Staging),
            _ => Err(DomainError::Validation(format!(
                "unknown repository type: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// ReplicationPriority
// ---------------------------------------------------------------------------

/// When and how artifacts in a repository are replicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationPriority {
    Immediate,
    Scheduled,
    OnDemand,
    LocalOnly,
}

impl fmt::Display for ReplicationPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate => f.write_str("immediate"),
            Self::Scheduled => f.write_str("scheduled"),
            Self::OnDemand => f.write_str("on_demand"),
            Self::LocalOnly => f.write_str("local_only"),
        }
    }
}

impl FromStr for ReplicationPriority {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "immediate" => Ok(Self::Immediate),
            "scheduled" => Ok(Self::Scheduled),
            "on_demand" => Ok(Self::OnDemand),
            "local_only" => Ok(Self::LocalOnly),
            _ => Err(DomainError::Validation(format!(
                "unknown replication priority: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// IndexMode
// ---------------------------------------------------------------------------

/// Per-repository quarantine-aware index-serve mode (see
/// `docs/architecture/explanation/index-construction.md`).
///
/// Controls how the served package/index/metadata document is filtered
/// against Hort's per-`(package, version)` quarantine status before being
/// returned to a client. This type is the operator-selectable knob that
/// drives the index-serve filter.
///
/// `ReleasedOnly` (the [`Default`]) is the build-safe-by-construction
/// posture: the served index lists only versions Hort holds in a servable
/// status, so a range / bare install / `latest` resolution can never
/// resolve to a version that would `503` on download. `IncludePending`
/// retains upstream's full catalog minus versions Hort *knows* are
/// non-servable — maximally discoverable, at the cost of an intermittent
/// first-build `503` when a never-ingested upstream version is resolved
/// to. The pair reads in posture order — `ReleasedOnly` (strict) →
/// `IncludePending` (permissive). (The variant was renamed pre-v1.0
/// in-place from `FilterQuarantined`, whose name suggested the opposite
/// of its behaviour — a maximal-discoverability mode shouldn't read as
/// "more filtering"; ADR 0015 covers the naming discipline.)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexMode {
    /// Default — the served index lists only versions Hort holds in a
    /// servable status (`released`, `NULL`/permissive). A range never
    /// `503`s; new versions enter via explicit pin or prefetch.
    #[default]
    ReleasedOnly,
    /// The served index is upstream's full catalog minus versions Hort
    /// *knows* are non-servable (`quarantined` / `rejected` /
    /// `scan_indeterminate`). Versions in an indeterminate state
    /// (upstream-advertised, hort-never-ingested — "Pending") stay
    /// advertised; resolving to one triggers a pull → quarantine →
    /// `503` until prefetch / age clears it.
    IncludePending,
}

impl fmt::Display for IndexMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleasedOnly => f.write_str("released_only"),
            Self::IncludePending => f.write_str("include_pending"),
        }
    }
}

impl FromStr for IndexMode {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "released_only" => Ok(Self::ReleasedOnly),
            "include_pending" => Ok(Self::IncludePending),
            _ => Err(DomainError::Validation(format!("unknown index_mode: {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// PrefetchPolicy + PrefetchTrigger
// ---------------------------------------------------------------------------

/// Trigger that schedules a prefetch (see
/// `docs/architecture/explanation/prefetch-pipeline.md`).
///
/// Variants pair 1:1 with the migration's CHECK constraint on
/// `repositories.prefetch_triggers` (each element must be one of the
/// snake_case literals). `Scheduled` and `OnDistTagMove` are
/// non-transitive — they need only per-format version *ordering*, never
/// a range resolver. `TransitiveDeps` carries the per-format range
/// resolver and the `prefetch-dependencies` cascade. This enum is CRUD
/// config; the trigger paths and the `prefetch-tick` handler consume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchTrigger {
    /// Transitive cascade: on ingest of artifact X, read X's runtime
    /// manifest, resolve each declared dependency to a concrete version
    /// (per-format range *max*), and prefetch the unseen subtree. Only
    /// the format's primary runtime-dependency class is followed: npm
    /// reads top-level `dependencies` only (`peerDependencies` /
    /// `optionalDependencies` / `devDependencies` are excluded), cargo
    /// reads `[dependencies]` only, and pypi reads `requires-dist`
    /// entries without extras. See
    /// `docs/architecture/explanation/prefetch-pipeline.md`.
    TransitiveDeps,
    // There is deliberately NO trigger that fires on an anonymous index
    // read — an implicit trigger would let unauthenticated reads drive
    // upstream fetches; the explicit replacement is `hort-cli prefetch`.
    /// A `prefetch-tick` `TaskHandler` drives a
    /// scheduled sweep — operator chooses cadence at deployment time.
    Scheduled,
    /// Prefetch the upstream's *newest* version when Hort's held
    /// set lags it. The trigger name comes from npm's native semantics —
    /// `dist-tags.latest` is a real mutable pointer that the npm hot-path
    /// trigger reads literally. For protocols WITHOUT a native mutable-
    /// tag pointer (pypi, cargo, helm `index.yaml` analogues) the
    /// hot-path triggers synthesise "newest" by per-format ordering
    /// (`max_by(VersionOrdering)`) over the upstream version set and
    /// fire this trigger when Hort's held set doesn't already contain that
    /// pick. The synthetic-newest and real-mutable-tag cases share the
    /// trigger because both answer the same operator question — "warm
    /// the version that will be picked next" — and both feed the same
    /// planner call with `trigger = OnDistTagMove`. OCI's
    /// `fire_prefetch_trigger_oci` is the third consumer; it detects
    /// real upstream-tag-digest divergence at the manifest-fetch path.
    OnDistTagMove,
}

impl fmt::Display for PrefetchTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransitiveDeps => f.write_str("transitive_deps"),
            Self::Scheduled => f.write_str("scheduled"),
            Self::OnDistTagMove => f.write_str("on_dist_tag_move"),
        }
    }
}

impl FromStr for PrefetchTrigger {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "transitive_deps" => Ok(Self::TransitiveDeps),
            "scheduled" => Ok(Self::Scheduled),
            "on_dist_tag_move" => Ok(Self::OnDistTagMove),
            // `on_index_fetch` is a retired literal — operator hits
            // surface `DomainError::Validation` at apply (no
            // `serde(alias)` shim, no deprecation soft-land). Operators
            // get pointed at `hort-cli prefetch` as the replacement.
            _ => Err(DomainError::Validation(format!(
                "unknown prefetch_trigger: {s}"
            ))),
        }
    }
}

/// Per-repository prefetch policy (see
/// `docs/architecture/explanation/prefetch-pipeline.md`).
///
/// CRUD config — no behaviour is wired here; the consumers are the
/// `on_dist_tag_move` trigger path, the `prefetch-tick` `TaskHandler`,
/// and the transitive-deps cascade (which carries the per-format
/// range resolver). Default is *disabled* with no triggers — quarantine
/// cost is opt-in per repository so an upgrade of the v2 binary does
/// not silently start mirroring upstream traffic.
///
/// The chosen defaults for `depth` / `transitive_depth` are
/// **conservative**: cost (storage,
/// bandwidth, scan load) scales with aggressiveness — operator-tunable,
/// default conservative. They are floors, not targets: a fresh
/// `PrefetchPolicy { enabled: true, triggers: vec![…], ..Default::default() }`
/// is the minimum that still meaningfully shrinks the build-time
/// quarantine window. Cranking either knob is an explicit operator
/// decision with a visible storage/bandwidth cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefetchPolicy {
    /// Master switch. Default `false` — quarantine without prefetch is
    /// the v2 baseline; this field opts the repository into proactive
    /// warming. The triggers list still has to be non-empty for any
    /// work to happen at runtime (the trigger consumers enforce that).
    pub enabled: bool,
    /// Which trigger paths schedule prefetches for this repository.
    /// Empty default — even with `enabled = true`, no triggers means
    /// no prefetch (a degenerate but valid state the consumers must
    /// tolerate).
    pub triggers: Vec<PrefetchTrigger>,
    /// N newest non-transitive versions to warm per package (applies
    /// to `Scheduled` only). Default `3` —
    /// conservative; covers a couple of point releases without warming
    /// a package's full history. Operators raise this when they want
    /// upstream catalog discoverability further into the past.
    ///
    /// `#[serde(default =
    /// "default_prefetch_depth")]` keeps this field additive on the YAML
    /// wire: a minimal `prefetchPolicy: { enabled, triggers }` block
    /// deserialises with the 3-default applied, mirroring how the DB row
    /// mapper resolves a NULL column and the struct `Default`. `enabled`
    /// and `triggers` stay required (no struct-level
    /// `#[serde(default)]`) so `prefetchPolicy: {}` cannot silently
    /// disable prefetch.
    #[serde(default = "default_prefetch_depth")]
    pub depth: u32,
    /// Cascade depth cap — backstop for the transitive cascade
    /// (`prefetch-dependencies`). Default `5` —
    /// conservative; deep enough to cover the steady-state dependency
    /// graph of every format Hort supports (typical Node trees: 4–5
    /// levels; Maven / Cargo: similar). It is a cap, NOT a target —
    /// raising it is a deliberate "I accept a wider fan-out" decision.
    ///
    /// `#[serde(default =
    /// "default_transitive_depth")]`; same wire-additivity discipline as
    /// [`PrefetchPolicy::depth`].
    #[serde(default = "default_transitive_depth")]
    pub transitive_depth: u32,
    /// Skip versions older than this many days. `None` (the default)
    /// means "no age filter" — prefetch all versions
    /// the trigger asks about. Operators tune this to bound mirror
    /// growth for long-lived packages.
    ///
    /// `#[serde(default)]` resolves an
    /// absent key to `None` (an `Option` is *not* serde-optional by
    /// default), keeping the field additive on the YAML wire.
    #[serde(default)]
    pub max_age_days: Option<u32>,
    /// Global cumulative cap on the
    /// transitive cascade. The per-package `transitive_depth` knob
    /// bounds the *depth* of a single walk but does NOT bound the
    /// *breadth*: a manifest declaring N distinct dependencies
    /// amplifies as `N × transitive_depth × …` per parent trigger.
    /// `max_descendants` caps the cumulative descendant count carried
    /// across the cascade in the `prefetch-dependencies` task params
    /// (`current_descendants_so_far`). When a cohort would exceed the
    /// cap the walk truncates the cohort *before* enqueueing and emits
    /// a `warn!` (see `prefetch_dependencies::plan_and_enqueue`).
    ///
    /// Default `200` — a typical realistic npm transitive closure for
    /// a small package is ~100 deps; 200 leaves headroom for the
    /// legitimate case and trips on a runaway. The validator caps
    /// operator-set values at 100_000 (hort-config) so an operator-typo
    /// (e.g. `4_000_000_000`) cannot effectively disable the cap.
    /// Setting `0` disables transitive enqueueing entirely (defense-
    /// in-depth — operators can collapse the feature to leaf-prefetch
    /// only without disabling the `TransitiveDeps` trigger).
    ///
    /// `#[serde(default = "default_max_descendants")]` keeps the field
    /// **additive on the YAML wire**: an operator YAML without a
    /// `maxDescendants:` key deserialises with
    /// the 200-default applied, mirroring how the row mapper resolves
    /// `NULL` on the DB column. This is the same load-bearing
    /// additivity discipline `prefetchPolicy` itself carries at the
    /// `RepositorySpec` level.
    #[serde(default = "default_max_descendants")]
    pub max_descendants: u32,
}

/// Serde default for
/// [`PrefetchPolicy::depth`]. Distinct named function (mirroring
/// [`default_max_descendants`]) so the default is pinned to the
/// design's chosen value (3) independent of any future change to
/// `u32::default()`.
fn default_prefetch_depth() -> u32 {
    3
}

/// Serde default for
/// [`PrefetchPolicy::transitive_depth`]. Distinct named function
/// (mirroring [`default_max_descendants`]) so the default is pinned to
/// the design's chosen value (5) independent of any future change to
/// `u32::default()`.
fn default_transitive_depth() -> u32 {
    5
}

/// Serde default for
/// [`PrefetchPolicy::max_descendants`]. Distinct named function
/// rather than `Default::default()` so the default is pinned to the
/// design's chosen value (200) independent of any future change to
/// `u32::default()`.
fn default_max_descendants() -> u32 {
    200
}

impl Default for PrefetchPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            triggers: Vec::new(),
            depth: 3,
            transitive_depth: 5,
            max_age_days: None,
            // See the field doc-string for the cap rationale.
            max_descendants: 200,
        }
    }
}

// ---------------------------------------------------------------------------
// CurationAction
// ---------------------------------------------------------------------------

/// Default action for packages not matching any curation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurationAction {
    /// Allow packages through by default.
    Allow,
    /// Require manual review by default.
    Review,
}

impl fmt::Display for CurationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Review => f.write_str("review"),
        }
    }
}

impl FromStr for CurationAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "review" => Ok(Self::Review),
            _ => Err(DomainError::Validation(format!(
                "unknown curation action: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionConfig
// ---------------------------------------------------------------------------
//
// There is no embedded `CurationConfig` struct; curation lives in the
// standalone [`crate::entities::curation_rule::CurationRule`]
// kind. Repositories reference curation rules by name through the
// `curation_rule_names` field on [`Repository`]; runtime lookup goes via
// `CurationRuleRepository::list_for_repo`.

/// Promotion configuration for a staging repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionConfig {
    pub target_id: Uuid,
    pub policy_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// A package repository — the top-level container for artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Repository {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    /// Optional override for protocol-specific index/metadata host on
    /// proxy repositories whose upstream's metadata + download legs are
    /// served from different hosts (split-host registries). Today only
    /// `format = cargo` consults this field — when set, Cargo metadata
    /// fetches (config.json + per-crate NDJSON) target this URL instead
    /// of `upstream_url`. Cross-spec validation in `hort-config` rejects
    /// `Some(_)` on non-cargo formats / non-proxy repo types so that
    /// surface stays narrow. The field name stays generic on purpose:
    /// other formats may grow analogous overrides without renaming.
    /// `None` for every existing repo.
    pub index_upstream_url: Option<String>,
    pub is_public: bool,
    /// Opt-in per-repository download
    /// auditing. When `true`, every *served* download from this
    /// repository appends one `ArtifactDownloaded` event to a dedicated
    /// per-`(repository, UTC-date)` `StreamCategory::DownloadAudit`
    /// stream (NOT the artifact aggregate stream), fail-open. CRUD —
    /// not event-sourced; default `false`. The opt-in flag is the
    /// volume control (there is no throttle); the per-format download
    /// *count* stays Prometheus-only (`hort_download_total`).
    pub download_audit_enabled: bool,
    pub quota_bytes: Option<i64>,
    pub replication_priority: ReplicationPriority,
    pub promotion: Option<PromotionConfig>,
    /// Names of [`CurationRule`](crate::entities::curation_rule::CurationRule)
    /// objects attached to this repository. Gitops specs declare the
    /// reference list here, the apply pipeline resolves names → ids and
    /// writes them through `CurationRuleRepository::set_curation_rules_for_repository`,
    /// and the ingest-time curation evaluator reads the linked rules
    /// via `list_for_repo`. Empty by default.
    pub curation_rule_names: Vec<String>,
    /// Quarantine-aware index-serve mode (see
    /// `docs/architecture/explanation/index-construction.md`). Controls
    /// how the served package/index/metadata document is filtered
    /// against Hort's per-`(package, version)` quarantine status. Default
    /// `ReleasedOnly` (build-safe — a range never `503`s); operators who
    /// want maximal upstream discoverability at the cost of an
    /// intermittent first-build `503` set `IncludePending`. The
    /// The serve consumer reads this field; it is the operator-selectable
    /// knob. Threaded through gitops `RepositorySpec`
    /// (`indexMode` in YAML, absent → `ReleasedOnly`).
    pub index_mode: IndexMode,
    /// Prefetch policy — proactive background ingestion so
    /// the quarantine window elapses *off the build's critical path*
    /// (see `docs/architecture/explanation/prefetch-pipeline.md`).
    /// CRUD config; the consumers are the `on_dist_tag_move` trigger
    /// path, the `scheduled` sweep via `PrefetchTickHandler`, and the
    /// transitive
    /// cascade with the per-format range resolver. Default
    /// [`PrefetchPolicy::default`] is disabled with no triggers — an
    /// upgrade of the v2 binary cannot silently turn an operator's
    /// repository into a mirror. Threaded through gitops
    /// `RepositorySpec` (`prefetchPolicy` in YAML, absent →
    /// `PrefetchPolicy::default()`).
    pub prefetch_policy: PrefetchPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Provenance — `Local` for rows created via the public CRUD API,
    /// `GitOps` for rows declared in `$HORT_CONFIG_DIR`.
    /// Mutators on `RepositoryUseCase` reject `GitOps` rows with
    /// `DomainError::ManagedByConfiguration`.
    pub managed_by: super::managed_by::ManagedBy,
    /// SHA-256 of the canonicalised gitops `spec` JSON at apply time.
    /// The gitops diff uses this to detect "spec changed since last apply"
    /// without re-comparing every field. `None` for `Local` rows.
    pub managed_by_digest: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- RepositoryFormat ---------------------------------------------------

    #[test]
    fn format_display_known_variants() {
        let cases: &[(&str, RepositoryFormat)] = &[
            ("maven", RepositoryFormat::Maven),
            ("gradle", RepositoryFormat::Gradle),
            ("npm", RepositoryFormat::Npm),
            ("pypi", RepositoryFormat::Pypi),
            ("nuget", RepositoryFormat::Nuget),
            ("go", RepositoryFormat::Go),
            ("rubygems", RepositoryFormat::Rubygems),
            ("docker", RepositoryFormat::Docker),
            ("oci", RepositoryFormat::Oci),
            ("helm", RepositoryFormat::Helm),
            ("rpm", RepositoryFormat::Rpm),
            ("debian", RepositoryFormat::Debian),
            ("conan", RepositoryFormat::Conan),
            ("cargo", RepositoryFormat::Cargo),
            ("generic", RepositoryFormat::Generic),
            ("podman", RepositoryFormat::Podman),
            ("buildx", RepositoryFormat::Buildx),
            ("oras", RepositoryFormat::Oras),
            ("wasm_oci", RepositoryFormat::WasmOci),
            ("helm_oci", RepositoryFormat::HelmOci),
            ("poetry", RepositoryFormat::Poetry),
            ("conda", RepositoryFormat::Conda),
            ("yarn", RepositoryFormat::Yarn),
            ("bower", RepositoryFormat::Bower),
            ("pnpm", RepositoryFormat::Pnpm),
            ("chocolatey", RepositoryFormat::Chocolatey),
            ("powershell", RepositoryFormat::Powershell),
            ("terraform", RepositoryFormat::Terraform),
            ("opentofu", RepositoryFormat::Opentofu),
            ("alpine", RepositoryFormat::Alpine),
            ("conda_native", RepositoryFormat::CondaNative),
            ("composer", RepositoryFormat::Composer),
            ("hex", RepositoryFormat::Hex),
            ("cocoapods", RepositoryFormat::Cocoapods),
            ("swift", RepositoryFormat::Swift),
            ("pub", RepositoryFormat::Pub),
            ("sbt", RepositoryFormat::Sbt),
            ("chef", RepositoryFormat::Chef),
            ("puppet", RepositoryFormat::Puppet),
            ("ansible", RepositoryFormat::Ansible),
            ("gitlfs", RepositoryFormat::Gitlfs),
            ("vscode", RepositoryFormat::Vscode),
            ("jetbrains", RepositoryFormat::Jetbrains),
            ("huggingface", RepositoryFormat::Huggingface),
            ("mlmodel", RepositoryFormat::Mlmodel),
            ("cran", RepositoryFormat::Cran),
            ("vagrant", RepositoryFormat::Vagrant),
            ("opkg", RepositoryFormat::Opkg),
            ("p2", RepositoryFormat::P2),
            ("bazel", RepositoryFormat::Bazel),
            ("protobuf", RepositoryFormat::Protobuf),
            ("incus", RepositoryFormat::Incus),
            ("lxc", RepositoryFormat::Lxc),
        ];
        for (expected, variant) in cases {
            assert_eq!(variant.to_string(), *expected, "Display for {variant:?}");
        }
    }

    #[test]
    fn format_from_str_known_roundtrips() {
        for &(name, ref ctor) in KNOWN_FORMATS {
            let parsed: RepositoryFormat = name.parse().unwrap();
            assert_eq!(parsed, ctor(), "FromStr for {name}");
            assert_eq!(parsed.to_string(), name, "roundtrip for {name}");
        }
    }

    #[test]
    fn format_from_str_case_insensitive() {
        let parsed: RepositoryFormat = "MAVEN".parse().unwrap();
        assert_eq!(parsed, RepositoryFormat::Maven);

        let parsed: RepositoryFormat = "PyPi".parse().unwrap();
        assert_eq!(parsed, RepositoryFormat::Pypi);
    }

    #[test]
    fn format_from_str_unknown_becomes_other() {
        let parsed: RepositoryFormat = "flatpak".parse().unwrap();
        assert_eq!(parsed, RepositoryFormat::Other("flatpak".into()));
        assert_eq!(parsed.to_string(), "flatpak");
    }

    #[test]
    fn format_from_str_never_fails() {
        // FromStr::Err is Infallible — this always succeeds
        let _: RepositoryFormat = "anything-at-all".parse().unwrap();
    }

    #[test]
    fn format_other_display() {
        let fmt = RepositoryFormat::Other("custom-wasm-format".into());
        assert_eq!(fmt.to_string(), "custom-wasm-format");
    }

    #[test]
    fn format_clone_eq() {
        let a = RepositoryFormat::Docker;
        let b = a.clone();
        assert_eq!(a, b);

        let c = RepositoryFormat::Other("x".into());
        let d = c.clone();
        assert_eq!(c, d);
    }

    // -- RepositoryType -----------------------------------------------------

    #[test]
    fn repo_type_display() {
        assert_eq!(RepositoryType::Hosted.to_string(), "hosted");
        assert_eq!(RepositoryType::Proxy.to_string(), "proxy");
        assert_eq!(RepositoryType::Virtual.to_string(), "virtual");
        assert_eq!(RepositoryType::Staging.to_string(), "staging");
    }

    #[test]
    fn repo_type_from_str_roundtrip() {
        for name in &["hosted", "proxy", "virtual", "staging"] {
            let parsed: RepositoryType = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn repo_type_from_str_case_insensitive() {
        let parsed: RepositoryType = "HOSTED".parse().unwrap();
        assert_eq!(parsed, RepositoryType::Hosted);
    }

    #[test]
    fn repo_type_from_str_invalid() {
        let result: Result<RepositoryType, _> = "mirror".parse();
        assert!(result.is_err());
    }

    /// Regression: the legacy names `"local"` / `"remote"` are
    /// not accepted — the gitops YAML schema ships the canonical
    /// `"hosted"` / `"proxy"` names, and a `FromStr` that accepts both
    /// would let an operator silently mix the legacy and canonical
    /// labels.
    #[test]
    fn repo_type_from_str_rejects_legacy_names() {
        assert!("local".parse::<RepositoryType>().is_err());
        assert!("remote".parse::<RepositoryType>().is_err());
        assert!("LOCAL".parse::<RepositoryType>().is_err());
        assert!("Remote".parse::<RepositoryType>().is_err());
    }

    #[test]
    fn repo_type_is_staging() {
        assert!(RepositoryType::Staging.is_staging());
        assert!(!RepositoryType::Hosted.is_staging());
        assert!(!RepositoryType::Proxy.is_staging());
        assert!(!RepositoryType::Virtual.is_staging());
    }

    #[test]
    fn repo_type_is_hosted() {
        assert!(RepositoryType::Hosted.is_hosted());
        assert!(RepositoryType::Staging.is_hosted());
        assert!(!RepositoryType::Proxy.is_hosted());
        assert!(!RepositoryType::Virtual.is_hosted());
    }

    // -- ReplicationPriority ------------------------------------------------

    #[test]
    fn replication_display() {
        assert_eq!(ReplicationPriority::Immediate.to_string(), "immediate");
        assert_eq!(ReplicationPriority::Scheduled.to_string(), "scheduled");
        assert_eq!(ReplicationPriority::OnDemand.to_string(), "on_demand");
        assert_eq!(ReplicationPriority::LocalOnly.to_string(), "local_only");
    }

    #[test]
    fn replication_from_str_roundtrip() {
        for name in &["immediate", "scheduled", "on_demand", "local_only"] {
            let parsed: ReplicationPriority = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn replication_from_str_case_insensitive() {
        let parsed: ReplicationPriority = "IMMEDIATE".parse().unwrap();
        assert_eq!(parsed, ReplicationPriority::Immediate);
    }

    #[test]
    fn replication_from_str_invalid() {
        let result: Result<ReplicationPriority, _> = "weekly".parse();
        assert!(result.is_err());
    }

    // -- IndexMode ----------------------------------------------------------

    #[test]
    fn index_mode_default_is_released_only() {
        // The default mirrors the migration's column DEFAULT
        // ('released_only') so any fixture / mapper that calls
        // `IndexMode::default()` agrees with the DB row.
        assert_eq!(IndexMode::default(), IndexMode::ReleasedOnly);
    }

    #[test]
    fn index_mode_display_strings_match_migration_check() {
        // These literals are the CHECK constraint values in
        // `002_repositories.sql` and the gitops YAML enum domain.
        // Changing either breaks the cross-layer contract — pin them.
        assert_eq!(IndexMode::ReleasedOnly.to_string(), "released_only");
        assert_eq!(IndexMode::IncludePending.to_string(), "include_pending");
    }

    #[test]
    fn index_mode_from_str_round_trips_both_variants() {
        for v in [IndexMode::ReleasedOnly, IndexMode::IncludePending] {
            let parsed: IndexMode = v.to_string().parse().unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn index_mode_from_str_case_insensitive() {
        assert_eq!(
            "RELEASED_ONLY".parse::<IndexMode>().unwrap(),
            IndexMode::ReleasedOnly
        );
        assert_eq!(
            "Include_Pending".parse::<IndexMode>().unwrap(),
            IndexMode::IncludePending
        );
    }

    #[test]
    fn index_mode_from_str_unknown_is_validation_err() {
        let err = "permissive".parse::<IndexMode>().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("permissive"));
    }

    #[test]
    fn repository_index_mode_serde_round_trip_both_variants() {
        // Pin both branches through the same serde path the mapper
        // uses. Default flows through the `repository_clone_eq` fixture
        // already; this test exercises the non-default explicitly so a
        // future refactor that drops the field at serde-time gets
        // caught.
        let make = |mode: IndexMode| Repository {
            id: Uuid::nil(),
            key: "npm-public".into(),
            name: "npm Public".into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/npm-public".into(),
            upstream_url: Some("https://registry.npmjs.org".into()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: mode,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: super::super::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        };

        for mode in [IndexMode::ReleasedOnly, IndexMode::IncludePending] {
            let repo = make(mode);
            let json = serde_json::to_string(&repo).expect("serialize");
            let decoded: Repository = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded.index_mode, mode);
            assert_eq!(decoded, repo);
        }
    }

    // -- CurationAction -----------------------------------------------------

    #[test]
    fn curation_action_display() {
        assert_eq!(CurationAction::Allow.to_string(), "allow");
        assert_eq!(CurationAction::Review.to_string(), "review");
    }

    #[test]
    fn curation_action_from_str_roundtrip() {
        for name in &["allow", "review"] {
            let parsed: CurationAction = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn curation_action_from_str_case_insensitive() {
        let parsed: CurationAction = "REVIEW".parse().unwrap();
        assert_eq!(parsed, CurationAction::Review);
    }

    #[test]
    fn curation_action_from_str_invalid() {
        let result: Result<CurationAction, _> = "deny".parse();
        assert!(result.is_err());
    }

    // -- Config structs -----------------------------------------------------

    #[test]
    fn promotion_config_clone_eq() {
        let cfg = PromotionConfig {
            target_id: Uuid::nil(),
            policy_id: Some(Uuid::nil()),
        };
        assert_eq!(cfg, cfg.clone());
    }

    // -- Repository ---------------------------------------------------------

    #[test]
    fn repository_clone_eq() {
        let repo = Repository {
            id: Uuid::nil(),
            key: "test-repo".into(),
            name: "Test Repo".into(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/test".into(),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: super::super::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        };
        let cloned = repo.clone();
        assert_eq!(repo, cloned);
    }

    #[test]
    fn repository_with_configs() {
        let repo = Repository {
            id: Uuid::nil(),
            key: "staging-pypi".into(),
            name: "Staging PyPI".into(),
            description: Some("staging repo".into()),
            format: RepositoryFormat::Pypi,
            repo_type: RepositoryType::Staging,
            storage_backend: "s3".into(),
            storage_path: "bucket/staging".into(),
            upstream_url: None,
            index_upstream_url: None,
            is_public: false,
            download_audit_enabled: true,
            quota_bytes: Some(1_000_000_000),
            replication_priority: ReplicationPriority::Immediate,
            promotion: Some(PromotionConfig {
                target_id: Uuid::nil(),
                policy_id: None,
            }),
            curation_rule_names: vec!["block-cve-2024-3094".into()],
            index_mode: IndexMode::IncludePending,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: super::super::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        assert!(repo.repo_type.is_staging());
        assert!(repo.repo_type.is_hosted());
        assert!(repo.promotion.is_some());
        assert_eq!(repo.curation_rule_names, vec!["block-cve-2024-3094"]);
        // B12: the opt-in download-audit flag round-trips its non-
        // default value (the struct above sets it `true`).
        assert!(repo.download_audit_enabled);
        let cloned = repo.clone();
        assert_eq!(repo, cloned);
        let json = serde_json::to_string(&repo).unwrap();
        let decoded: Repository = serde_json::from_str(&json).unwrap();
        assert!(decoded.download_audit_enabled);
        assert_eq!(decoded, repo);
    }

    /// `index_upstream_url` round-trips both `None`
    /// and `Some(_)` through serde. Covers the pure-data plumbing for
    /// the typed field; cross-spec validation lives in `hort-config`.
    #[test]
    fn repository_index_upstream_url_serde_round_trip() {
        let make = |index: Option<String>| Repository {
            id: Uuid::nil(),
            key: "cargo-proxy".into(),
            name: "Cargo Proxy".into(),
            description: None,
            format: RepositoryFormat::Cargo,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/cargo-proxy".into(),
            upstream_url: Some("https://crates.io".into()),
            index_upstream_url: index,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: super::super::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        };

        for fixture in [None, Some("https://internal-index.example.com".to_string())] {
            let repo = make(fixture.clone());
            let json = serde_json::to_string(&repo).expect("serialize");
            let decoded: Repository = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded.index_upstream_url, fixture);
            assert_eq!(decoded, repo);
        }
    }

    // -- PrefetchPolicy / PrefetchTrigger -------------------------------------

    /// The [`PrefetchPolicy::default()`] is **disabled with no triggers**.
    /// This is load-bearing: upgrading the v2 binary cannot silently
    /// turn an operator's repository into a mirror. Pin every field of
    /// the default so a future tweak that flips `enabled` (or grows the
    /// trigger list) lights this test up.
    #[test]
    fn prefetch_policy_default_is_disabled_with_no_triggers() {
        let p = PrefetchPolicy::default();
        assert!(!p.enabled, "default must be disabled");
        assert!(p.triggers.is_empty(), "default must have no triggers");
        assert_eq!(p.depth, 3, "conservative default depth");
        assert_eq!(
            p.transitive_depth, 5,
            "conservative default transitive_depth"
        );
        assert!(
            p.max_age_days.is_none(),
            "default must have no max_age_days filter"
        );
        assert_eq!(
            p.max_descendants, 200,
            "default global cumulative cascade cap"
        );
    }

    /// A *minimal* `PrefetchPolicy` wire
    /// document (`enabled` + `triggers` only) deserialises with the
    /// documented numeric defaults applied: `depth = 3` (covers
    /// [`default_prefetch_depth`]), `transitive_depth = 5` (covers
    /// [`default_transitive_depth`]), `max_age_days = None`,
    /// `max_descendants = 200`. Pins the field-level serde defaults in
    /// the domain crate itself, independent of the `hort-config` gitops
    /// wire test. Field names are camelCase (`#[serde(rename_all =
    /// "camelCase")]`); trigger literals are snake_case.
    #[test]
    fn prefetch_policy_minimal_wire_doc_applies_documented_defaults() {
        let p: PrefetchPolicy =
            serde_json::from_str(r#"{"enabled":true,"triggers":["transitive_deps"]}"#)
                .expect("minimal prefetchPolicy wire doc must deserialize");
        assert!(p.enabled);
        assert_eq!(p.triggers, vec![PrefetchTrigger::TransitiveDeps]);
        assert_eq!(p.depth, 3, "default_prefetch_depth applied");
        assert_eq!(p.transitive_depth, 5, "default_transitive_depth applied");
        assert_eq!(p.max_age_days, None, "max_age_days defaults to None");
        assert_eq!(p.max_descendants, 200, "default_max_descendants applied");
    }

    /// `enabled` and `triggers` stay
    /// **required**: there is no struct-level `#[serde(default)]`, so an
    /// empty `{}` body cannot silently materialise a disabled policy (the
    /// footgun the spec explicitly rejects). Missing `enabled` is a
    /// deserialise error.
    #[test]
    fn prefetch_policy_wire_doc_keeps_enabled_and_triggers_required() {
        let err = serde_json::from_str::<PrefetchPolicy>("{}").unwrap_err();
        assert!(
            err.to_string().contains("enabled"),
            "empty body must fail on missing `enabled`: {err}"
        );
        let err = serde_json::from_str::<PrefetchPolicy>(r#"{"enabled":true}"#).unwrap_err();
        assert!(
            err.to_string().contains("triggers"),
            "missing `triggers` must fail: {err}"
        );
    }

    /// `PrefetchTrigger::Display` emits the snake_case literal the
    /// migration's CHECK constraint pins. Changing either side breaks
    /// the cross-layer contract — this test is the canary.
    #[test]
    fn prefetch_trigger_display_strings_match_migration_check() {
        // These literals are the CHECK constraint values in
        // `002_repositories.sql` on `prefetch_triggers` element values,
        // AND the gitops YAML enum domain. Pin all three
        // variants (there is deliberately no `OnIndexFetch`).
        assert_eq!(
            PrefetchTrigger::TransitiveDeps.to_string(),
            "transitive_deps"
        );
        assert_eq!(PrefetchTrigger::Scheduled.to_string(), "scheduled");
        assert_eq!(
            PrefetchTrigger::OnDistTagMove.to_string(),
            "on_dist_tag_move"
        );
    }

    /// `PrefetchTrigger::from_str` round-trips every variant through
    /// the same string the `Display` impl produces. Anchors the bidir
    /// invariant under refactor.
    #[test]
    fn prefetch_trigger_from_str_round_trips_all_variants() {
        for v in [
            PrefetchTrigger::TransitiveDeps,
            PrefetchTrigger::Scheduled,
            PrefetchTrigger::OnDistTagMove,
        ] {
            let parsed: PrefetchTrigger = v.to_string().parse().unwrap();
            assert_eq!(parsed, v);
        }
    }

    /// The retired `on_index_fetch` string MUST be rejected at
    /// parse time. No `serde(alias)` shim, no deprecation soft-land.
    /// Operator surface gets `DomainError::Validation` pointing at
    /// `hort-cli prefetch` as the replacement workflow.
    #[test]
    fn prefetch_trigger_from_str_rejects_removed_on_index_fetch() {
        let err = "on_index_fetch".parse::<PrefetchTrigger>().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("on_index_fetch"));
    }

    #[test]
    fn prefetch_trigger_from_str_case_insensitive() {
        assert_eq!(
            "TRANSITIVE_DEPS".parse::<PrefetchTrigger>().unwrap(),
            PrefetchTrigger::TransitiveDeps
        );
        assert_eq!(
            "On_Dist_Tag_Move".parse::<PrefetchTrigger>().unwrap(),
            PrefetchTrigger::OnDistTagMove
        );
    }

    #[test]
    fn prefetch_trigger_from_str_unknown_is_validation_err() {
        let err = "eager".parse::<PrefetchTrigger>().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("eager"));
    }

    /// `PrefetchTrigger`'s serde representation MUST be the snake_case
    /// literal — the on-wire / gitops-YAML representation is the
    /// migration CHECK domain. Pin both directions through a JSON
    /// round-trip + a string-content assertion so a stray
    /// `#[serde(rename_all = …)]` change can't silently flip it.
    #[test]
    fn prefetch_trigger_serde_uses_snake_case_literals() {
        for (variant, literal) in &[
            (PrefetchTrigger::TransitiveDeps, "\"transitive_deps\""),
            (PrefetchTrigger::Scheduled, "\"scheduled\""),
            (PrefetchTrigger::OnDistTagMove, "\"on_dist_tag_move\""),
        ] {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(json, *literal, "serde literal for {variant:?}");
            let decoded: PrefetchTrigger = serde_json::from_str(literal).unwrap();
            assert_eq!(decoded, *variant);
        }
    }

    /// `PrefetchPolicy` round-trips through serde unchanged with a
    /// non-default value mix (covers every field branch in one shot).
    #[test]
    fn prefetch_policy_serde_round_trips_non_default() {
        let p = PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::Scheduled, PrefetchTrigger::OnDistTagMove],
            depth: 10,
            transitive_depth: 8,
            max_age_days: Some(180),
            // Non-default sentinel.
            max_descendants: 500,
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: PrefetchPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, p);
        assert!(
            json.contains("\"maxDescendants\":500"),
            "expected camelCase maxDescendants in wire form: {json}"
        );
    }

    /// `Repository` round-trips a non-default `PrefetchPolicy` through
    /// serde — pins the new field's plumbing on the entity itself, the
    /// same shape as the `index_mode` round-trip lock above.
    #[test]
    fn repository_prefetch_policy_serde_round_trip() {
        let policy = PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::Scheduled],
            depth: 7,
            transitive_depth: 6,
            max_age_days: Some(90),
            // Non-default sentinel.
            max_descendants: 300,
        };
        let repo = Repository {
            id: Uuid::nil(),
            key: "npm-prefetch".into(),
            name: "npm Prefetch".into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/npm-prefetch".into(),
            upstream_url: Some("https://registry.npmjs.org".into()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: policy.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: super::super::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        };
        let json = serde_json::to_string(&repo).expect("serialize");
        let decoded: Repository = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.prefetch_policy, policy);
        assert_eq!(decoded, repo);
    }
}
