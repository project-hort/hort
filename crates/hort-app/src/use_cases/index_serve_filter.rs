//! Quarantine-aware index-serve filter.
//!
//! This module is the **format-agnostic core** of the per-format
//! index/metadata serve filter. Given:
//!
//! - the upstream version set (whatever the format's index/metadata
//!   document advertises — npm's `versions{}` keys, PyPI's PEP 503
//!   anchor list, Cargo's sparse-index NDJSON, Maven's `<versions>`),
//! - the locally-held per-`(package, version)` quarantine status
//!   ([`ArtifactRepository::package_version_status`]
//!   [`crate::use_cases::artifact_use_case::ArtifactUseCase::package_version_status`]),
//! - the operator-selected [`IndexMode`], and
//! - a per-format [`VersionOrdering`] (semver / PEP 440 / Maven
//!   comparison — *ordering only*, not range satisfaction),
//!
//! [`filter_served_versions`] returns:
//!
//! - the *served* version set — every version a client resolving against
//!   this index would be allowed to download;
//! - the *resolved latest* — the newest served version per the format's
//!   ordering, or `None` if the served set is empty.
//!
//! # Mode semantics
//!
//! `ReleasedOnly` (default — build-safe by construction): the served set
//! is the **hort-held** versions in a servable status (`released`, or
//! `none` / permissive). A never-ingested upstream version is **not**
//! advertised — so a range / bare install / `latest` resolution cannot
//! land on a version that would `503` on download.
//!
//! `IncludePending`: the served set is upstream's **full catalog**
//! minus versions Hort *knows* are non-servable (`quarantined` /
//! `rejected` / `scan_indeterminate`). A never-ingested upstream version
//! (in an indeterminate / "pending" state from Hort's perspective) **stays**
//! advertised; resolving to it triggers a pull → quarantine → `503`
//! until prefetch / age clears it. (`FilterQuarantined` was renamed to
//! `IncludePending` in place, pre-v1.0 — ADR 0015.)
//!
//! # Resolved latest
//!
//! Always the newest *served* version per the supplied
//! [`VersionOrdering`]. If the served set is empty, the latest is
//! `None` (every serve-side caller should then omit the format's
//! `latest`-style pointer entirely — never let a `dist-tags.latest` /
//! `<latest>` / etc. point at a filtered version).
//!
//! # Reference implementation
//!
//! The npm packument serve path (`hort-http-npm/src/packument.rs`) wires
//! this helper; per-format callers reuse it unchanged for PyPI / Cargo /
//! Maven by passing their respective [`VersionOrdering`] implementations.
//! Picking the newest served version needs per-format *ordering* only —
//! distinct from and **far simpler than** the per-format range *resolver*
//! (`resolve_range_max`, range satisfaction), which is future territory
//! and deliberately not a dependency of this helper.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::IndexMode;

/// Per-format version ordering primitive.
///
/// Implementations supply the comparator the format would use natively
/// to pick "the newest version": semver for npm / Cargo, PEP 440 for
/// PyPI, Maven's version-comparison algorithm for Maven.
///
/// This is **ordering only** — not range satisfaction. Callers
/// (this helper, the non-transitive prefetch) need only an ordering to
/// find the newest *served* version; the range *resolver*
/// (`resolve_range_max`) is future territory.
///
/// A pure trait so callers can build a `&dyn VersionOrdering` and the
/// helper stays free-function-shaped. Implementations live in the
/// format-domain layer they speak for; the reference impl
/// [`NpmSemverOrdering`] is here because the npm wiring is the
/// reference implementation that per-format callers template from.
pub trait VersionOrdering {
    /// Compare two version strings. Returns `Ordering::Less` if `a < b`,
    /// `Equal` if `a == b`, `Greater` if `a > b`. Inputs are unvalidated
    /// (whatever the upstream document supplied) — implementations
    /// should *never* panic on malformed input. A consistent ordering
    /// over the full string domain is the contract; semantic
    /// reasonableness for well-formed versions is the goal.
    fn compare(&self, a: &str, b: &str) -> Ordering;
}

/// Outcome of [`filter_served_versions`].
///
/// `served` is the version set the format's serve path advertises;
/// `latest` is the newest entry of `served` per the supplied
/// [`VersionOrdering`], or `None` when `served` is empty.
///
/// `served` is a [`BTreeSet`] so the order is stable across runs and
/// independent of the input iteration order — useful for deterministic
/// tests and for callers that materialise the set into a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedIndex {
    /// Versions the serve path advertises. Stable iteration order
    /// (alphabetical-by-version-string, not the format's semantic
    /// order — callers that need the semantic order sort `latest`'s
    /// peers via their own [`VersionOrdering`]).
    pub served: BTreeSet<String>,
    /// The newest *served* version per the supplied
    /// [`VersionOrdering`]. `None` when `served` is empty.
    pub latest: Option<String>,
}

/// Format-agnostic quarantine-aware index-serve filter.
///
/// See the module docs for the semantics of each [`IndexMode`].
///
/// `upstream_versions` is whatever the format's index/metadata document
/// advertises — duplicates are tolerated (a [`BTreeSet`] is materialised
/// inside). `status` is the result of
/// `ArtifactRepository::package_version_status`. The function does NOT
/// validate that `status`'s `repository_id` / `package` match
/// `upstream_versions` — that is the caller's responsibility.
pub fn filter_served_versions(
    upstream_versions: &[&str],
    status: &[(String, QuarantineStatus)],
    mode: IndexMode,
    ordering: &dyn VersionOrdering,
) -> ServedIndex {
    // Materialise the upstream set once. Using a BTreeSet over &str is
    // tempting but the returned ServedIndex carries owned Strings, so
    // owning here is the smaller allocation.
    let upstream: BTreeSet<String> = upstream_versions.iter().map(|v| (*v).to_string()).collect();

    // Build a status map for O(1) lookups. A version may appear at most
    // once in the adapter's result (the artifacts projection is
    // `(repository_id, name, version)`-unique), but the
    // helper doesn't rely on that — a duplicate in `status` is resolved
    // by last-write-wins, the same as a HashMap insert.
    let status_by_version: HashMap<&str, QuarantineStatus> =
        status.iter().map(|(v, s)| (v.as_str(), *s)).collect();

    let served: BTreeSet<String> = match mode {
        IndexMode::ReleasedOnly => {
            // Served set = hort-held versions in a servable status.
            // A never-upstream-listed hort-held version is also dropped
            // (the served document is "what upstream advertises minus
            // what we know is bad", clamped to Hort's catalog) — we
            // intersect with upstream so a stale hort-held row that
            // upstream has since unpublished does not leak.
            status
                .iter()
                .filter(|(_, s)| is_servable_status(*s))
                .filter_map(|(v, _)| {
                    if upstream.contains(v) {
                        Some(v.clone())
                    } else {
                        None
                    }
                })
                .collect()
        }
        IndexMode::IncludePending => {
            // Served set = upstream catalog minus versions Hort KNOWS are
            // non-servable. Versions Hort has never ingested (no entry in
            // `status`) stay in — that's the IncludePending trade-off
            // (maximal discoverability at the cost of a possible
            // first-build 503).
            upstream
                .iter()
                .filter(|v| {
                    !matches!(
                        status_by_version.get(v.as_str()),
                        Some(s) if !is_servable_status(*s),
                    )
                })
                .cloned()
                .collect()
        }
    };

    let latest = pick_latest(&served, ordering);

    ServedIndex { served, latest }
}

/// True iff a version with this [`QuarantineStatus`] may be served to
/// clients. Used by both [`IndexMode`] arms of
/// [`filter_served_versions`]: `ReleasedOnly` includes versions for
/// which this returns `true`, `IncludePending` excludes versions for
/// which it returns `false`. The two semantics differ on *unknown*
/// versions, not on the predicate.
///
/// Servable: `Released` (review complete) and `None` (no quarantine
/// configured for this artifact / permissive — the default
/// keeps these).
///
/// Non-servable: `Quarantined`, `Rejected`, `ScanIndeterminate`
/// (fail-closed terminal scan failure — ADR 0007).
fn is_servable_status(status: QuarantineStatus) -> bool {
    matches!(status, QuarantineStatus::Released | QuarantineStatus::None)
}

/// Pick the newest version in `served` per the supplied
/// [`VersionOrdering`]. `None` when `served` is empty.
fn pick_latest(served: &BTreeSet<String>, ordering: &dyn VersionOrdering) -> Option<String> {
    served.iter().max_by(|a, b| ordering.compare(a, b)).cloned()
}

// ---------------------------------------------------------------------------
// NpmSemverOrdering — npm reference implementation
// ---------------------------------------------------------------------------

/// Semver-ish version ordering for npm — the reference
/// [`VersionOrdering`] implementation that per-format callers template from.
///
/// Parses `MAJOR.MINOR.PATCH(-prerelease)?(+build)?` and orders per
/// [semver.org §11](https://semver.org/#spec-item-11): numeric segments
/// compared as integers; missing minor/patch treated as 0; a pre-release
/// version has *lower* precedence than the same version without one
/// (`1.0.0-alpha < 1.0.0`); build metadata (`+...`) is ignored for
/// precedence (§10).
///
/// **Robustness over strictness.** Malformed input — non-numeric where
/// numeric is required, missing segments, garbage trailing characters —
/// degrades to a lexicographic fallback rather than panicking. This is
/// the safe default for a serve-side filter: a single bad upstream
/// entry must never break the index-serve path. Well-formed entries
/// dominate the comparison; ill-formed entries land somewhere
/// predictable.
///
/// Workspace policy: no `semver` crate dependency. The npm-side need
/// here is ordering of the version *strings the packument already
/// holds* — a small, well-scoped problem the inline parser handles
/// completely. A future format that needs the full semver range
/// language brings the crate dependency with it.
#[derive(Debug, Default, Clone, Copy)]
pub struct NpmSemverOrdering;

impl VersionOrdering for NpmSemverOrdering {
    fn compare(&self, a: &str, b: &str) -> Ordering {
        let pa = ParsedNpmVersion::parse(a);
        let pb = ParsedNpmVersion::parse(b);
        match (pa, pb) {
            (Some(pa), Some(pb)) => pa.cmp(&pb),
            // One side unparseable: fall back to lexicographic compare
            // so the ordering is still total. The parseable side is
            // arbitrarily greater, mirroring the spirit of §11 (a
            // canonical-form version dominates a degraded one).
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => a.cmp(b),
        }
    }
}

/// Parsed npm/semver version. Internal — exposed through
/// [`NpmSemverOrdering`] only.
#[derive(Debug, PartialEq, Eq)]
struct ParsedNpmVersion {
    major: u64,
    minor: u64,
    patch: u64,
    /// Pre-release identifiers (`-alpha.1` → `["alpha", "1"]`). Empty
    /// for a release version. A non-empty `prerelease` sorts BEFORE an
    /// empty one at the same major.minor.patch (§11.4).
    prerelease: Vec<PrereleaseIdent>,
}

#[derive(Debug, PartialEq, Eq)]
enum PrereleaseIdent {
    Numeric(u64),
    Alphanumeric(String),
}

impl ParsedNpmVersion {
    /// Parse a version string. Returns `None` if the major segment
    /// cannot be parsed; missing minor/patch are filled with 0.
    fn parse(input: &str) -> Option<Self> {
        // Strip leading 'v' / 'V' — npm tolerates `v1.2.3` as a tag
        // ref, but the packument key is always bare.
        let input = input.strip_prefix(['v', 'V']).unwrap_or(input);

        // Drop build metadata (§10 — ignored for precedence).
        let (core_and_pre, _build) = match input.split_once('+') {
            Some((cp, b)) => (cp, Some(b)),
            None => (input, None),
        };

        // Split core from prerelease.
        let (core, prerelease_str) = match core_and_pre.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (core_and_pre, None),
        };

        // Parse the numeric core. Up to three dotted segments;
        // missing segments default to 0.
        let mut segs = core.split('.');
        let major: u64 = segs.next()?.parse().ok()?;
        let minor: u64 = match segs.next() {
            Some(s) => s.parse().ok()?,
            None => 0,
        };
        let patch: u64 = match segs.next() {
            Some(s) => s.parse().ok()?,
            None => 0,
        };
        if segs.next().is_some() {
            // More than three dotted segments — reject as malformed.
            return None;
        }

        let prerelease = match prerelease_str {
            Some(s) => s
                .split('.')
                .map(|seg| {
                    // Per §9, a numeric identifier with leading zero is
                    // invalid — but we don't reject; we treat it as
                    // alphanumeric so the parser stays robust.
                    if !seg.is_empty()
                        && seg.bytes().all(|b| b.is_ascii_digit())
                        && !(seg.len() > 1 && seg.starts_with('0'))
                    {
                        match seg.parse::<u64>() {
                            Ok(n) => PrereleaseIdent::Numeric(n),
                            Err(_) => PrereleaseIdent::Alphanumeric(seg.to_string()),
                        }
                    } else {
                        PrereleaseIdent::Alphanumeric(seg.to_string())
                    }
                })
                .collect(),
            None => Vec::new(),
        };

        Some(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }
}

impl Ord for ParsedNpmVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Core comparison.
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release vs release (§11.3): a pre-release version has
        // LOWER precedence than the corresponding release.
        match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                // §11.4 — left-to-right identifier comparison.
                for (a, b) in self.prerelease.iter().zip(other.prerelease.iter()) {
                    let ord = match (a, b) {
                        (PrereleaseIdent::Numeric(x), PrereleaseIdent::Numeric(y)) => x.cmp(y),
                        // Numeric < alphanumeric (§11.4.3).
                        (PrereleaseIdent::Numeric(_), PrereleaseIdent::Alphanumeric(_)) => {
                            Ordering::Less
                        }
                        (PrereleaseIdent::Alphanumeric(_), PrereleaseIdent::Numeric(_)) => {
                            Ordering::Greater
                        }
                        (PrereleaseIdent::Alphanumeric(x), PrereleaseIdent::Alphanumeric(y)) => {
                            x.cmp(y)
                        }
                    };
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                // §11.4.4 — the side with fewer identifiers has lower
                // precedence when the shared prefix is equal.
                self.prerelease.len().cmp(&other.prerelease.len())
            }
        }
    }
}

impl PartialOrd for ParsedNpmVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// CargoSemverOrdering — Cargo reuses the npm/semver implementation
// ---------------------------------------------------------------------------

/// Cargo sparse-index version ordering. Cargo's version grammar is
/// SemVer 2.0 ([Cargo Book §SemVer compatibility][cargo-semver]) — the
/// same `MAJOR.MINOR.PATCH(-prerelease)?(+build)?` shape and the same
/// §11 precedence rules npm follows. The [`NpmSemverOrdering`]
/// reference implementation is therefore correct for Cargo too; this
/// alias spells the format at the call site without duplicating logic.
///
/// The implementation is general (semver §11, no
/// npm-specific quirks except the tolerated `v` / `V` prefix, which
/// Cargo upstream NDJSON `vers` keys never carry — degrades to a no-op
/// when absent); the name is npm-flavoured, so the alias makes the
/// per-format intent explicit at the call site.
///
/// [cargo-semver]: https://doc.rust-lang.org/cargo/reference/semver.html
pub type CargoSemverOrdering = NpmSemverOrdering;

// ---------------------------------------------------------------------------
// Pep440Ordering — PyPI PEP 440 ordering
// ---------------------------------------------------------------------------

/// [PEP 440][pep440] version ordering for PyPI.
///
/// Supports the public-version layout
/// `[N!]N(.N)*[{a|b|c|rc|alpha|beta|pre|preview}N][.postN][.devN]`:
///
/// - **Epoch** (`N!`) — leading `N!` (default 0). Higher epoch wins
///   absolutely; a present epoch sorts above an absent (default-0) one
///   only when its numeric value exceeds 0.
/// - **Release segment** (`N(.N)*`) — arbitrary count of dotted
///   non-negative integers; trailing zeros are insignificant
///   (`1.0` == `1.0.0`); fewer segments are zero-padded for comparison
///   (PEP 440 §Final releases).
/// - **Pre-release** (`a/alpha`, `b/beta`, `c/rc/pre/preview`) — sorts
///   *below* the corresponding release (`1.0a1 < 1.0`). Order between
///   markers: `a < b < c == rc == pre == preview`. PyPI normalises
///   `alpha → a`, `beta → b`, `c/pre/preview → rc`; we apply the same
///   normalisation before comparing (PEP 440 §Pre-release spelling).
/// - **Post-release** (`.postN`) — sorts *above* the corresponding
///   release (`1.0 < 1.0.post1`).
/// - **Dev-release** (`.devN`) — sorts *below* both pre-release and
///   release at the same triplet (`1.0.dev1 < 1.0a1 < 1.0`).
///
/// Implicit pre/post/dev numbers (`1.0a`, `1.0.post`, `1.0.dev`) default
/// to `0` (PEP 440 §Implicit pre-release number).
///
/// **Local versions** (`1.0+localpart`) — PEP 440 reserves them; we
/// follow PEP 440 §Local version identifiers: the local part is
/// compared by parsing it as a sequence of dot-separated segments where
/// numeric segments outrank alphanumeric ones. A version *with* a local
/// part sorts above the same version *without*. In practice an upstream
/// PyPI simple index does not advertise local versions (they exist for
/// private builds), so this branch is mainly defensive.
///
/// **Robustness over strictness.** Malformed input degrades to a
/// lexicographic fallback, never panic — mirrors the
/// [`NpmSemverOrdering`] policy. A single weird upstream entry must
/// never break the serve-side filter.
///
/// Workspace policy: no `pep440` / `pep440_rs` crate dependency. The
/// per-format need here is *ordering only* — pick the newest served
/// version from a small set Hort already holds — not range satisfaction
/// (range satisfaction is future territory). A hand-rolled parser is
/// the right size for the job and consistent with the npm path.
///
/// [pep440]: https://peps.python.org/pep-0440/
#[derive(Debug, Default, Clone, Copy)]
pub struct Pep440Ordering;

impl VersionOrdering for Pep440Ordering {
    fn compare(&self, a: &str, b: &str) -> Ordering {
        let pa = ParsedPep440Version::parse(a);
        let pb = ParsedPep440Version::parse(b);
        match (pa, pb) {
            (Some(pa), Some(pb)) => pa.cmp(&pb),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => a.cmp(b),
        }
    }
}

/// Parsed PEP 440 version. Internal — exposed through [`Pep440Ordering`] only.
#[derive(Debug, PartialEq, Eq)]
struct ParsedPep440Version {
    epoch: u64,
    /// Release segments with trailing zeros stripped (so `1.0.0` and
    /// `1.0` normalise to `[1]`). Comparison zero-pads the shorter
    /// side at compare time.
    release: Vec<u64>,
    /// `None` for a final release; `Some` for an `a`/`b`/`rc` marker.
    /// Pre-release sorts *below* release at the same epoch+release.
    pre: Option<(Pep440PreKind, u64)>,
    /// `None` for non-post; `Some(N)` for `.postN`. Post-release sorts
    /// *above* release at the same epoch+release.
    post: Option<u64>,
    /// `None` for non-dev; `Some(N)` for `.devN`. Dev-release sorts
    /// *below* pre, release, and post at the same epoch+release.
    dev: Option<u64>,
    /// Local version part (`+local.parts`), already split on `.`.
    /// Empty when absent. A non-empty `local` sorts above an empty one
    /// at the same public version (PEP 440 §Local version semantics).
    local: Vec<Pep440LocalSegment>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Pep440PreKind {
    /// `a` / `alpha`
    Alpha,
    /// `b` / `beta`
    Beta,
    /// `c` / `rc` / `pre` / `preview`
    Rc,
}

/// PEP 440 local-version segment. Per §Local version semantics, numeric
/// segments outrank alphanumeric ones (the spec wording is "numeric
/// segments are always greater than alphanumeric segments" when ordering
/// a local part). `Ord` derive on this enum places `Alphanumeric < Numeric`
/// — the variant order is load-bearing.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pep440LocalSegment {
    Alphanumeric(String),
    Numeric(u64),
}

impl ParsedPep440Version {
    fn parse(input: &str) -> Option<Self> {
        // Strip an optional leading `v` / `V` (PEP 440 §Preceding v
        // character — explicitly tolerated).
        let input = input.strip_prefix(['v', 'V']).unwrap_or(input);

        // Split off the local part (`+...`).
        let (public, local_str) = match input.split_once('+') {
            Some((p, l)) => (p, Some(l)),
            None => (input, None),
        };

        // Parse the epoch (`N!`) if present.
        let (epoch, rest) = match public.split_once('!') {
            Some((e, r)) => (e.parse::<u64>().ok()?, r),
            None => (0, public),
        };

        // The public part is now `release[pre][post][dev]`. PEP 440
        // makes the separators flexible (`.post1`, `-post1`, `_post1`,
        // and `post1` all accepted; same for pre/dev). Normalise to
        // lowercase and substitute long spellings for short ones, then
        // split off post/dev by suffix scan.
        let normalised = pep440_normalise_public(rest);

        // Pop dev: `.devN` (after normalisation, always `.dev` then digits).
        let (without_dev, dev) = pep440_pop_suffix(&normalised, ".dev");
        // Pop post: `.postN`.
        let (without_post, post) = pep440_pop_suffix(without_dev, ".post");
        // Pop pre: `a`/`b`/`rc` followed by digits (no leading `.`).
        let (release_str, pre) = pep440_pop_pre(without_post);

        // Parse the release segments.
        let release_raw: Vec<u64> = release_str
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()
            .ok()?;
        if release_raw.is_empty() {
            return None;
        }
        // Strip trailing zeros — `1.0.0` and `1.0` compare equal at the
        // release segment (PEP 440 §Insignificant trailing zeros).
        let mut release = release_raw;
        while release.len() > 1 && *release.last().unwrap() == 0 {
            release.pop();
        }

        // Parse the local part — PEP 440 §Local version segments split
        // on `.` (and accept `-` / `_` as equivalent — normalise to `.`).
        let local: Vec<Pep440LocalSegment> = local_str
            .map(|s| {
                s.to_lowercase()
                    .replace(['-', '_'], ".")
                    .split('.')
                    .filter(|seg| !seg.is_empty())
                    .map(|seg| match seg.parse::<u64>() {
                        Ok(n) => Pep440LocalSegment::Numeric(n),
                        Err(_) => Pep440LocalSegment::Alphanumeric(seg.to_string()),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }
}

impl Ord for ParsedPep440Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Epoch dominates.
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Release segments — zero-pad the shorter side.
        let max_len = self.release.len().max(other.release.len());
        for i in 0..max_len {
            let a = self.release.get(i).copied().unwrap_or(0);
            let b = other.release.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }

        // Same epoch + release: pre / post / dev decide. The PEP 440
        // ordering at this level is:
        //
        //   .devN  <  aN[.devM]  <  bN[.devM]  <  rcN[.devM]  <
        //     (release)  <  .postN[.devM]
        //
        // (i.e. a bare `.devN` with NO pre / post sorts strictly
        // *below* every pre-release; a pre with its own `.devM` sorts
        // immediately below the same pre without the dev; same for
        // post.) Canonicalise each side to a comparable key and compare
        // lexicographically.
        let a_key = pep440_postpredev_key(self);
        let b_key = pep440_postpredev_key(other);
        match a_key.cmp(&b_key) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Local version — present-outranks-absent; otherwise per-segment.
        match (self.local.is_empty(), other.local.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.local.cmp(&other.local),
        }
    }
}

impl PartialOrd for ParsedPep440Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Lower-case and rewrite the long PEP 440 pre-release spellings to
/// their canonical short forms so the suffix-scan loop has a fixed
/// alphabet. Also normalises the separators around `post` / `dev` to
/// `.` (PEP 440 accepts `-` / `_` / nothing equivalently — §Preceding
/// and trailing separators).
fn pep440_normalise_public(s: &str) -> String {
    let lower = s.to_lowercase();
    // Substitute long pre-release spellings. Order matters: longer
    // strings first so `alpha` doesn't get half-rewritten by `a`.
    // `preview` must run before `pre`, and the deprecated bare `c`
    // marker is canonicalised separately by [`pep440_canonicalise_c`]
    // so it doesn't accidentally smash the `c` already inside `rc`
    // (a naive `.replace('c', "rc")` here would turn `rc` into `rrc`).
    let lower = lower
        .replace("alpha", "a")
        .replace("beta", "b")
        .replace("preview", "rc")
        .replace("pre", "rc");
    let lower = pep440_canonicalise_c(&lower);
    // Normalise the separators *around* `post` and `dev` (PEP 440 admits
    // `.post`, `-post`, `_post`, `post`).
    let lower = lower
        .replace("_post", ".post")
        .replace("-post", ".post")
        .replace("_dev", ".dev")
        .replace("-dev", ".dev");
    // A bare `postN` / `devN` (no separator at all) — accept by
    // injecting a `.` before the marker. The release segment never
    // contains the letters `p` or `d`, so a search for `post` / `dev`
    // not preceded by `.` is unambiguous.
    let lower = pep440_inject_dot_before(&lower, "post");
    pep440_inject_dot_before(&lower, "dev")
}

/// Rewrite the deprecated bare-`c` pre-release marker into the canonical
/// `rc` spelling **without** mangling the `c` inside an existing `rc`.
///
/// PEP 440 §Pre-release spelling treats `c`, `rc`, `pre`, `preview` as
/// equivalent. The normaliser handles `pre` and `preview` with straight
/// string substitutions; the bare `c` needs the position check below to
/// avoid the naive `.replace('c', "rc")` pitfall — that pitfall would
/// turn the already-canonical `rc` into `rrc`, which then refuses to
/// parse as a pre-release marker. A standalone `c` is one preceded by an
/// ascii digit or a separator (`.` / `-` / `_`); the `c` inside `rc` is
/// preceded by `r` (an ascii letter), so we skip it. The deprecated
/// trailing-letter case (`1.0c`) is also covered: position 3 is preceded
/// by `0`, a digit.
fn pep440_canonicalise_c(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 2);
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'c' {
            let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
            let is_standalone = match prev {
                None => true,
                Some(p) => p.is_ascii_digit() || matches!(p, b'.' | b'-' | b'_'),
            };
            if is_standalone {
                out.push_str("rc");
                continue;
            }
        }
        out.push(b as char);
    }
    out
}

/// If `marker` appears in `s` without a preceding `.`, inject one.
/// Used by [`pep440_normalise_public`] to canonicalise `1.0post1` →
/// `1.0.post1`.
fn pep440_inject_dot_before(s: &str, marker: &str) -> String {
    let Some(pos) = s.find(marker) else {
        return s.to_string();
    };
    if pos == 0 {
        return s.to_string();
    }
    let prev = s.as_bytes()[pos - 1];
    if prev == b'.' {
        return s.to_string();
    }
    // Don't inject if the previous byte is a letter — that means it's
    // part of another token (e.g. the `pre` substring inside `preview`,
    // which the normaliser already rewrote anyway). The normaliser
    // ensures only canonical short forms reach this function.
    if prev.is_ascii_alphabetic() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 1);
    out.push_str(&s[..pos]);
    out.push('.');
    out.push_str(&s[pos..]);
    out
}

/// Look for `.{marker}` followed by an optional integer. If found,
/// strip the suffix and return the parsed integer (default `0` if the
/// integer is absent — PEP 440 §Implicit pre-release number).
fn pep440_pop_suffix<'a>(s: &'a str, marker: &str) -> (&'a str, Option<u64>) {
    let Some(pos) = s.rfind(marker) else {
        return (s, None);
    };
    let rest = &s[pos + marker.len()..];
    if rest.is_empty() {
        return (&s[..pos], Some(0));
    }
    match rest.parse::<u64>() {
        Ok(n) => (&s[..pos], Some(n)),
        // Trailing junk after the marker — refuse to pop; the caller
        // sees the whole string and treats it as malformed at the
        // release-parse step (which then fails and the comparator
        // falls back to lex).
        Err(_) => (s, None),
    }
}

/// Pop a pre-release marker (`a`/`b`/`rc`) from the end of `s`. Returns
/// the residual + parsed `(kind, number)`. Implicit number defaults to
/// `0`. The normaliser already rewrote long spellings (`alpha`/`beta`/
/// `pre`/`preview`/`c`) to the short forms, so the scan only needs
/// `a` / `b` / `rc`.
fn pep440_pop_pre(s: &str) -> (&str, Option<(Pep440PreKind, u64)>) {
    for (marker, kind) in [
        ("rc", Pep440PreKind::Rc),
        ("b", Pep440PreKind::Beta),
        ("a", Pep440PreKind::Alpha),
    ] {
        if let Some(pos) = s.rfind(marker) {
            // The marker must be preceded by a digit or end-of-release
            // (never by another letter — that means it's mid-token).
            if pos > 0 {
                let prev = s.as_bytes()[pos - 1];
                if !prev.is_ascii_digit() && prev != b'.' {
                    continue;
                }
            }
            let rest = &s[pos + marker.len()..];
            if rest.is_empty() {
                return (&s[..pos], Some((kind, 0)));
            }
            if let Ok(n) = rest.parse::<u64>() {
                return (&s[..pos], Some((kind, n)));
            }
            // Trailing junk — fall through, not a pre marker.
        }
    }
    (s, None)
}

/// Compute the PEP 440 post/pre/dev ordering key for a parsed version.
///
/// At the same epoch+release the order is:
///
/// ```text
///   .devN  <  aN[.devM]  <  bN[.devM]  <  rcN[.devM]  <
///     (release)  <  .postN[.devM]
/// ```
///
/// Encoded as `(pre_tier, pre_num, post_tier, post_num, dev_tier, dev_num)`:
///
/// - **`pre_tier`** — a *three-way* tier ordered `dev_only < real_pre <
///   no_pre_no_dev`:
///     - `0` for "dev-only at release level" (no pre, no post, has dev).
///       This is what makes `1.0.dev1 < 1.0a1`: the bare `.devN` sorts
///       below ALL pres at the same release.
///     - `1` + the pre kind's discriminant for a real pre — `a` (1.0),
///       `b` (1.1), `rc` (1.2). Tuple-coded as `(1, kind_disc)` so the
///       lex compare reproduces `a < b < rc`.
///     - `2` for "no pre" — either a final release or a post-release.
///       Final/post are separated by `post_tier`, not here.
///
///   `pre_num` is the pre number for tier-1, zero otherwise.
/// - **`post_tier`** — `0` if no post, `1` if a post is present. Orders
///   post-release ABOVE the corresponding release (pre is irrelevant —
///   PEP 440 §Post-releases). `post_num` is the post number or zero.
/// - **`dev_tier`** — `0` if a dev is present, `1` otherwise. Orders a
///   dev-bearing version BELOW the non-dev version with the same
///   pre/post key (so `1.0a1.dev1 < 1.0a1` and `1.0.post1.dev1 <
///   1.0.post1`). `dev_num` is the dev number or zero.
///
/// The lexicographic compare of the four-tuples therefore reproduces
/// PEP 440's section ordering exactly. The dev-only tier (`pre_tier=0`)
/// uses `dev_num` directly through the `dev_tier`/`dev_num` slot so two
/// dev-only versions order by their dev numbers.
fn pep440_postpredev_key(v: &ParsedPep440Version) -> (u8, u8, u64, u8, u64, u8, u64) {
    // Pre tier — three-way as documented above.
    let (pre_tier, pre_kind_disc, pre_num) = match (&v.pre, &v.post, &v.dev) {
        // No pre, no post, has dev: dev-only at release level — sorts
        // BELOW every pre at the same release.
        (None, None, Some(_)) => (0u8, 0u8, 0u64),
        // Real pre (with or without dev/post).
        (Some((kind, n)), _, _) => {
            let disc: u8 = match kind {
                Pep440PreKind::Alpha => 0,
                Pep440PreKind::Beta => 1,
                Pep440PreKind::Rc => 2,
            };
            (1u8, disc, *n)
        }
        // No pre — final/release or post-release. Post-release is
        // disambiguated by `post_tier` below; this tier alone is "above
        // every pre".
        (None, _, _) => (2u8, 0u8, 0u64),
    };
    let post_tier: u8 = if v.post.is_some() { 1 } else { 0 };
    let post_num = v.post.unwrap_or(0);
    // dev_tier: 0 if dev is present (sorts BELOW non-dev), 1 otherwise.
    let dev_tier: u8 = if v.dev.is_some() { 0 } else { 1 };
    let dev_num = v.dev.unwrap_or(0);
    (
        pre_tier,
        pre_kind_disc,
        pre_num,
        post_tier,
        post_num,
        dev_tier,
        dev_num,
    )
}

// ---------------------------------------------------------------------------
// MavenVersionOrdering — Maven ComparableVersion ordering
// ---------------------------------------------------------------------------

/// Maven version ordering — a faithful port of Maven's
/// [`ComparableVersion`][cv] algorithm (the shipped `maven-artifact`
/// 3.9.x implementation; the "Version Order Specification" in Maven's
/// `pom.html`). Behaviour was cross-checked against real `maven-artifact`
/// 3.9.11 over the full official vector set.
///
/// Maven ordering is **not** semver: there is no special-casing of
/// `+build` metadata, and the qualifier vocabulary and trailing-null
/// trimming are Maven-specific. The algorithm:
///
/// 1. **Lowercase** the whole string — comparison is case-insensitive
///    (`3.2-ALPHA1` == `3.2-alpha1`).
/// 2. **Tokenise** into a tree of `Int`/`Str`/`List` items. `.` continues
///    the current list; `-` flushes the token and opens a new nested
///    sub-list. `.` and `-` are the ONLY separators — `_` is *not* a
///    separator (it is an ordinary qualifier character, so `1_0` parses to
///    `1-_`, not `1.0`; this matches the cited `ComparableVersion.java`,
///    which only branches on `.` and `-`). A digit↔letter transition with
///    no separator *also* splits — and, for the `.X`/letter→digit case,
///    opens a sub-list (Maven's "treat `.X` as `-X` for any string
///    qualifier"). Empty tokens become numeric `0`.
/// 3. **Classify** each token: all-ASCII-digits → numeric (arbitrary
///    precision); else → qualifier. Aliases are applied in the qualifier
///    constructor: `ga`/`final`/`release` → `""`; `cr` → `rc`; and a
///    single-char `a`/`b`/`m` → `alpha`/`beta`/`milestone` *when it is
///    immediately followed by a digit* (so `a1` = `alpha-1`, but a bare
///    trailing `a` stays an unknown qualifier).
/// 4. **Trim trailing nulls** at the end of every sub-list (Maven's
///    `normalize`): from the end, drop null items (numeric `0`, the empty
///    `""`-equivalent qualifier, and empty/all-null lists), stopping at
///    the first non-null *scalar* (trailing nested lists are recursed
///    into and skipped past). Hence `1.ga` == `1-0` == `1.0` == `1`.
/// 5. **Compare** token-by-token; the shorter list compares its remaining
///    items against `null` (inverted when the null is on the left).
///
/// Qualifier order (the canonical `QUALIFIERS` list):
/// `alpha < beta < milestone < rc(=cr) < snapshot < (""=ga=final=release) < sp`.
/// An unknown qualifier sorts *after* every known one, then lexically
/// (Maven encodes it as `"{len}-{qualifier}"`, which collates after every
/// single-digit known index). A qualifier sorts *before* a numeric at the
/// same position (`1.K < 1.7`).
///
/// **Robustness:** the algorithm is total over all input — it never
/// panics. Numeric tokens are compared as arbitrary-precision decimals
/// (leading zeros stripped, then length-then-lexical), which exactly
/// reproduces Maven's `IntItem`/`LongItem`/`BigIntegerItem` magnitude-tier
/// cascade without a bignum dependency (a value needing a wider tier has
/// strictly more digits, so length-compare orders the tiers; equal length
/// compares lexically == numerically).
///
/// **Wiring:** consumed by the Maven serve/builder path only (constructed
/// directly into the index builder's `ordering`). It is deliberately
/// **not** registered in either `ordering_for_format` selector — Maven
/// scheduled/self-service prefetch is deferred (design §4(d), §15).
///
/// [cv]: https://maven.apache.org/pom.html#version-order-specification
#[derive(Debug, Default, Clone, Copy)]
pub struct MavenVersionOrdering;

/// Self-bounding cap on the byte length of either input to
/// [`MavenVersionOrdering::compare`].
///
/// The `ComparableVersion` parse opens one nested `List` level per `-`
/// separator, and the downstream `normalize`/`is_null`/`compare` recurse to
/// that nesting depth. A pathological version (e.g. tens of thousands of
/// `-`) would recurse deep enough to overflow the thread stack — a SIGABRT
/// that is process-wide and uncatchable, not a recoverable panic. This guard
/// makes the ordering panic-/overflow-safe **independent of any caller**: an
/// over-cap input falls back to a non-recursive byte-lexical compare.
///
/// In practice every real request is already kept far under this cap by
/// `MAX_ROUTE_PARAM_BYTES` (512) in `hort-http-core`'s `BoundedPath`
/// extractor, and a legitimate Maven version is orders of magnitude shorter
/// still. This constant is the *local, self-contained* invariant so the
/// ordering's totality does not depend on that upstream extractor being
/// present. The value (1024) sits comfortably below the recursion-overflow
/// floor and far above any real Maven version.
///
/// Over-cap inputs are pathological and never legitimate, so the cross-cap
/// fallback's consistency with the structured order is immaterial — the
/// contract this guard upholds is "total + never panics" (the fallback is
/// itself a total order, and `x` vs `x` is `Equal`).
const MAVEN_VERSION_PARSE_MAX_BYTES: usize = 1024;

impl VersionOrdering for MavenVersionOrdering {
    fn compare(&self, a: &str, b: &str) -> Ordering {
        // Self-bounding guard (see `MAVEN_VERSION_PARSE_MAX_BYTES`): if either
        // input exceeds the cap, fall back to a deterministic, non-recursive
        // byte-lexical compare rather than the depth-recursive structured
        // parse. This keeps `compare` total and panic/overflow-safe even if a
        // caller has not bounded its input.
        if a.len() > MAVEN_VERSION_PARSE_MAX_BYTES || b.len() > MAVEN_VERSION_PARSE_MAX_BYTES {
            return a.as_bytes().cmp(b.as_bytes());
        }
        let pa = MavenItem::parse(a);
        let pb = MavenItem::parse(b);
        pa.compare(Some(&pb))
    }
}

/// A parsed Maven version item — a port of `ComparableVersion`'s `Item`
/// hierarchy (`IntItem`/`LongItem`/`BigIntegerItem` collapsed into one
/// arbitrary-precision `Int`, plus `Str` and `List`).
///
/// The three numeric Java tiers collapse to a single decimal-string `Int`
/// because the cross-tier compare rules are pure magnitude ordering and a
/// leading-zero-stripped decimal string carries that magnitude in its
/// (length, lexical) order. See the type docs above.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MavenItem {
    /// Numeric token, stored leading-zero-stripped (`"0"` is canonical
    /// zero — the numeric-null sentinel). Arbitrary precision.
    Int(String),
    /// Qualifier token (already lowercased + aliased).
    Str(String),
    /// A (possibly nested) list of items.
    List(Vec<MavenItem>),
}

/// The canonical Maven qualifier ordering table. The release-equivalent
/// position (`""` / `ga` / `final` / `release`) is [`MAVEN_RELEASE_INDEX`].
const MAVEN_QUALIFIERS: [&str; 7] = [
    "alpha",     // 0
    "beta",      // 1
    "milestone", // 2
    "rc",        // 3
    "snapshot",  // 4
    "",          // 5  (== ga == final == release)
    "sp",        // 6
];

/// Index in [`MAVEN_QUALIFIERS`] of the release-equivalent qualifier
/// (`""`). A qualifier whose key is below this sorts before "nothing"
/// (a `null` pad); equal sorts equal; above sorts after.
const MAVEN_RELEASE_INDEX: usize = 5;

/// Compare two qualifiers by their Maven `comparableQualifier` keys.
fn maven_compare_qualifiers(a: &str, b: &str) -> Ordering {
    maven_comparable_qualifier(a).cmp(&maven_comparable_qualifier(b))
}

/// Maven's `comparableQualifier`: a lexically-comparable key for a
/// qualifier. Known qualifiers map to their index (`"0".."6"`); an
/// unknown qualifier maps to `"{len}-{qualifier}"` so it sorts *after*
/// every known one (because `QUALIFIERS.len() == 7 > 6`), then lexically.
///
/// The `ga`/`final`/`release` → `""` and `cr` → `rc` aliases are applied
/// in [`maven_string_value`] (the `StringItem` constructor), so by the
/// time a qualifier reaches here it is already `""` / `rc` / etc.
fn maven_comparable_qualifier(qualifier: &str) -> String {
    match MAVEN_QUALIFIERS.iter().position(|&q| q == qualifier) {
        Some(idx) => idx.to_string(),
        None => format!("{}-{}", MAVEN_QUALIFIERS.len(), qualifier),
    }
}

/// Maven's `RELEASE_VERSION_INDEX` — the comparable key of the empty
/// qualifier, used when comparing a qualifier against `null` (nothing).
fn maven_release_version_index() -> String {
    MAVEN_RELEASE_INDEX.to_string()
}

/// Compare two leading-zero-stripped decimal digit strings as
/// arbitrary-precision non-negative integers. The canonical form has no
/// leading zeros (except the single `"0"`), so the longer string is the
/// larger number and equal-length strings compare digit-by-digit
/// lexically == numerically. This reproduces Maven's
/// `IntItem`/`LongItem`/`BigIntegerItem` magnitude-tier cascade exactly
/// (a value needing a wider tier has strictly more digits) without a
/// bignum dependency.
fn maven_int_cmp(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Strip leading zeros, returning Maven's `stripLeadingZeroes` canonical
/// form: `"0"` for an empty/all-zero string, otherwise the digits from
/// the first non-zero.
fn maven_strip_leading_zeros(buf: &str) -> String {
    if buf.is_empty() {
        return "0".to_string();
    }
    match buf.find(|c| c != '0') {
        Some(pos) => buf[pos..].to_string(),
        None => "0".to_string(), // all zeros → canonical "0"
    }
}

impl MavenItem {
    /// Parse a version string into the root `List` item (Maven's
    /// `parseVersion` + the `normalize` pass).
    fn parse(input: &str) -> MavenItem {
        let lower = input.to_lowercase();
        let mut root = maven_parse_version(&lower);
        maven_normalize(&mut root);
        MavenItem::List(root)
    }

    /// Maven `Item.isNull`. `Int` zero, the empty/release-equivalent
    /// `Str` (`""` after aliasing), and an empty/all-null `List` are null.
    fn is_null(&self) -> bool {
        match self {
            MavenItem::Int(d) => d == "0",
            // After aliasing, ga/final/release are already "" — but the
            // `isNull` predicate is "comparableQualifier == release index"
            // exactly, so a qualifier whose key equals index 5 is null.
            MavenItem::Str(s) => maven_comparable_qualifier(s) == maven_release_version_index(),
            MavenItem::List(items) => items.iter().all(MavenItem::is_null),
        }
    }

    /// Maven `Item.compareTo(Item)`. `other == None` means "compare
    /// against null" (a missing item on the other side / end of list).
    fn compare(&self, other: Option<&MavenItem>) -> Ordering {
        match self {
            MavenItem::Int(_) => self.int_compare(other),
            MavenItem::Str(_) => self.str_compare(other),
            MavenItem::List(_) => self.list_compare(other),
        }
    }

    fn int_compare(&self, other: Option<&MavenItem>) -> Ordering {
        let MavenItem::Int(value) = self else {
            unreachable!("int_compare on non-int")
        };
        let Some(item) = other else {
            // vs null: 1.0 == 1, 1.1 > 1.
            return if value == "0" {
                Ordering::Equal
            } else {
                Ordering::Greater
            };
        };
        match item {
            MavenItem::Int(other_value) => maven_int_cmp(value, other_value),
            // 1.1 > 1-sp (Str) ; 1.1 > 1-1 (List).
            MavenItem::Str(_) | MavenItem::List(_) => Ordering::Greater,
        }
    }

    fn str_compare(&self, other: Option<&MavenItem>) -> Ordering {
        let MavenItem::Str(value) = self else {
            unreachable!("str_compare on non-str")
        };
        let Some(item) = other else {
            // vs null: 1-rc < 1, 1-ga == 1.
            return maven_comparable_qualifier(value).cmp(&maven_release_version_index());
        };
        match item {
            // 1.any < 1.1.
            MavenItem::Int(_) => Ordering::Less,
            MavenItem::Str(other_value) => maven_compare_qualifiers(value, other_value),
            // 1.any < 1-1.
            MavenItem::List(_) => Ordering::Less,
        }
    }

    fn list_compare(&self, other: Option<&MavenItem>) -> Ordering {
        let MavenItem::List(items) = self else {
            unreachable!("list_compare on non-list")
        };
        let Some(item) = other else {
            // vs null: compare every element against null (MNG-6964).
            if items.is_empty() {
                return Ordering::Equal; // 1-0 = 1- (normalize) = 1
            }
            for child in items {
                let result = child.compare(None);
                if result != Ordering::Equal {
                    return result;
                }
            }
            return Ordering::Equal;
        };
        match item {
            // 1-1 < 1.0.x.
            MavenItem::Int(_) => Ordering::Less,
            // 1-1 > 1-sp.
            MavenItem::Str(_) => Ordering::Greater,
            MavenItem::List(other_items) => maven_list_vs_list(items, other_items),
        }
    }
}

/// Maven `ListItem.compareTo(ListItem)` — element-wise, the shorter side
/// comparing its tail against `null` (inverted when the null is on the
/// left).
fn maven_list_vs_list(left: &[MavenItem], right: &[MavenItem]) -> Ordering {
    let max = left.len().max(right.len());
    for i in 0..max {
        let result = match (left.get(i), right.get(i)) {
            (Some(l), r) => l.compare(r),
            // left ran out: -1 * right.compareTo(null).
            (None, Some(r)) => r.compare(None).reverse(),
            (None, None) => Ordering::Equal,
        };
        if result != Ordering::Equal {
            return result;
        }
    }
    Ordering::Equal
}

/// Build a single non-list item from a buffered token, mirroring Maven's
/// `parseItem(isDigit, buf)`.
fn maven_parse_item(is_digit: bool, buf: &str) -> MavenItem {
    if is_digit {
        MavenItem::Int(maven_strip_leading_zeros(buf))
    } else {
        maven_string_item(buf, false)
    }
}

/// Maven `StringItem` constructor: apply the `a`/`b`/`m` →
/// `alpha`/`beta`/`milestone` alias when `followed_by_digit` and the
/// value is a single char, then the `ga`/`final`/`release` → `""` and
/// `cr` → `rc` aliases.
fn maven_string_item(value: &str, followed_by_digit: bool) -> MavenItem {
    MavenItem::Str(maven_string_value(value, followed_by_digit))
}

/// The aliasing logic for a Maven `StringItem` value.
fn maven_string_value(value: &str, followed_by_digit: bool) -> String {
    let mut v = value.to_string();
    if followed_by_digit && v.chars().count() == 1 {
        v = match v.as_str() {
            "a" => "alpha".to_string(),
            "b" => "beta".to_string(),
            "m" => "milestone".to_string(),
            other => other.to_string(),
        };
    }
    // ALIASES: ga/final/release → "" ; cr → rc.
    match v.as_str() {
        "ga" | "final" | "release" => String::new(),
        "cr" => "rc".to_string(),
        _ => v,
    }
}

/// Port of `ComparableVersion.parseVersion` (maven-artifact 3.9.x) —
/// returns the root list's items (without the outer `List` wrapper; the
/// caller wraps + normalizes).
///
/// We keep an explicit stack of owned item-vectors and splice each child
/// back into its parent on pop, matching the Java `Deque<ListItem>`. The
/// "current list" is always `stack.last_mut()`.
fn maven_parse_version(version: &str) -> Vec<MavenItem> {
    let mut stack: Vec<Vec<MavenItem>> = vec![Vec::new()];
    let chars: Vec<char> = version.chars().collect();
    let mut is_digit = false;
    let mut start_index = 0usize;

    // Push a fresh nested list (becomes the new "current" list).
    fn open_sublist(stack: &mut Vec<Vec<MavenItem>>) {
        stack.push(Vec::new());
    }
    fn cur_is_empty(stack: &[Vec<MavenItem>]) -> bool {
        stack.last().expect("nonempty").is_empty()
    }
    fn push_item(stack: &mut [Vec<MavenItem>], item: MavenItem) {
        stack.last_mut().expect("nonempty").push(item);
    }

    for i in 0..chars.len() {
        let c = chars[i];
        if c == '.' {
            if i == start_index {
                push_item(&mut stack, MavenItem::Int("0".to_string()));
            } else {
                let buf: String = chars[start_index..i].iter().collect();
                push_item(&mut stack, maven_parse_item(is_digit, &buf));
            }
            start_index = i + 1;
        } else if c == '-' {
            // NOTE: `-` (and `.`) are the ONLY separators. `_` is NOT a
            // separator in Maven's `ComparableVersion` — it is an ordinary
            // qualifier character (so `1_0` parses to `1-_`, NOT `1.0`).
            // The cited spec (`ComparableVersion.java`) only branches on
            // `.` and `-`; this matches real maven-artifact 3.9.11.
            if i == start_index {
                push_item(&mut stack, MavenItem::Int("0".to_string()));
            } else {
                let buf: String = chars[start_index..i].iter().collect();
                push_item(&mut stack, maven_parse_item(is_digit, &buf));
            }
            start_index = i + 1;
            // Maven 3.9.x always opens a sub-list on '-'.
            open_sublist(&mut stack);
        } else if c.is_ascii_digit() {
            if !is_digit && i > start_index {
                // letter → digit with no separator: "treat .X as -X" —
                // open a sub-list (if the current list is non-empty),
                // flush the StringItem (followedByDigit = true), then open
                // a fresh sub-list for the digit run.
                if !cur_is_empty(&stack) {
                    open_sublist(&mut stack);
                }
                let buf: String = chars[start_index..i].iter().collect();
                push_item(&mut stack, maven_string_item(&buf, true));
                start_index = i;
                open_sublist(&mut stack);
            }
            is_digit = true;
        } else {
            if is_digit && i > start_index {
                // digit → letter: flush the numeric token, then open a
                // sub-list for the qualifier section.
                let buf: String = chars[start_index..i].iter().collect();
                push_item(&mut stack, maven_parse_item(true, &buf));
                start_index = i;
                open_sublist(&mut stack);
            }
            is_digit = false;
        }
    }

    if chars.len() > start_index {
        // Trailing token. "treat .X as -X" for a string qualifier: open a
        // sub-list before flushing (Maven: `if (!isDigit && !list.isEmpty())`).
        if !is_digit && !cur_is_empty(&stack) {
            open_sublist(&mut stack);
        }
        let buf: String = chars[start_index..].iter().collect();
        push_item(&mut stack, maven_parse_item(is_digit, &buf));
    }

    // Collapse the stack: each sub-list becomes the last child of its
    // parent (nesting order preserved by splicing on pop).
    while stack.len() > 1 {
        let child = stack.pop().expect("len > 1");
        stack
            .last_mut()
            .expect("parent")
            .push(MavenItem::List(child));
    }
    stack.pop().expect("root list always present")
}

/// Port of `ListItem.normalize` (maven-artifact 3.9.x): from the end,
/// remove null trailing items (numeric `0`, the empty `""`-equivalent
/// qualifier, empty/all-null lists); stop at the first non-null item that
/// is *not* a list (trailing nested lists are skipped past, so a null
/// scalar buried behind a list still trims). Applied recursively so
/// nested lists are normalized first.
fn maven_normalize(items: &mut Vec<MavenItem>) {
    // Recurse first so nested lists are normalized before this list's
    // null-ness checks examine them.
    for item in items.iter_mut() {
        if let MavenItem::List(inner) = item {
            maven_normalize(inner);
        }
    }
    let mut i = items.len();
    while i > 0 {
        i -= 1;
        let item_is_list = matches!(items[i], MavenItem::List(_));
        if items[i].is_null() {
            items.remove(i);
        } else if !item_is_list {
            // First non-null non-list scalar from the end: stop.
            break;
        }
        // A non-null list: keep it, but continue scanning earlier items.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- NpmSemverOrdering ----------

    fn cmp(a: &str, b: &str) -> Ordering {
        NpmSemverOrdering.compare(a, b)
    }

    #[test]
    fn npm_semver_orders_core_segments_numerically() {
        // Lexicographic would put 9 > 10; the parser must compare
        // numerically.
        assert_eq!(cmp("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(cmp("2.0.0", "10.0.0"), Ordering::Less);
        assert_eq!(cmp("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn npm_semver_missing_minor_or_patch_treated_as_zero() {
        assert_eq!(cmp("1", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(cmp("1.2", "1.2.1"), Ordering::Less);
    }

    #[test]
    fn npm_semver_prerelease_orders_below_release() {
        // §11.3: 1.0.0-alpha < 1.0.0.
        assert_eq!(cmp("1.0.0-alpha", "1.0.0"), Ordering::Less);
        assert_eq!(cmp("1.0.0", "1.0.0-alpha"), Ordering::Greater);
    }

    #[test]
    fn npm_semver_prerelease_numeric_vs_alpha() {
        // §11.4.3: numeric < alphanumeric.
        assert_eq!(cmp("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
        // §11.4.4: fewer identifiers < more identifiers.
        assert_eq!(cmp("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
        // §11.4.2: numeric identifiers compared numerically.
        assert_eq!(cmp("1.0.0-alpha.2", "1.0.0-alpha.10"), Ordering::Less);
        // §11.4.1: alphanumeric identifiers compared lexicographically.
        assert_eq!(cmp("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
    }

    #[test]
    fn npm_semver_build_metadata_ignored() {
        // §10: build metadata is ignored for precedence.
        assert_eq!(cmp("1.0.0+a", "1.0.0+b"), Ordering::Equal);
        assert_eq!(cmp("1.0.0+a", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn npm_semver_v_prefix_tolerated() {
        assert_eq!(cmp("v1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp("V2.0.0", "v1.0.0"), Ordering::Greater);
    }

    #[test]
    fn npm_semver_malformed_input_falls_back_to_lex() {
        // Both unparseable → lexicographic compare.
        assert_eq!(
            cmp("not-a-version", "also-bad"),
            "not-a-version".cmp("also-bad")
        );
        // One side parseable → it wins.
        assert_eq!(cmp("1.0.0", "not-a-version"), Ordering::Greater);
        assert_eq!(cmp("not-a-version", "1.0.0"), Ordering::Less);
        // Four-segment core is malformed; the well-formed side wins.
        assert_eq!(cmp("1.0.0", "1.0.0.0"), Ordering::Greater);
    }

    #[test]
    fn npm_semver_leading_zero_in_prerelease_treated_as_alphanumeric() {
        // §9: numeric identifier with leading zero is invalid. Our
        // robust parser routes it to the alphanumeric arm so the
        // comparator stays total. `01` (alpha) vs `1` (numeric): the
        // alpha side wins by §11.4.3.
        assert_eq!(cmp("1.0.0-01", "1.0.0-1"), Ordering::Greater);
    }

    #[test]
    fn npm_semver_partial_ord_agrees_with_ord() {
        // Defensive coverage for PartialOrd::partial_cmp.
        let a = ParsedNpmVersion::parse("1.0.0").unwrap();
        let b = ParsedNpmVersion::parse("2.0.0").unwrap();
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    }

    // ---------- filter_served_versions / ReleasedOnly ----------

    #[test]
    fn released_only_includes_released_and_none_intersected_with_upstream() {
        let upstream = ["1.0.0", "1.1.0", "1.2.0", "2.0.0"];
        let status = vec![
            ("1.0.0".to_string(), QuarantineStatus::Released),
            ("1.1.0".to_string(), QuarantineStatus::Quarantined),
            ("1.2.0".to_string(), QuarantineStatus::None),
            // 2.0.0 not in Hort's catalog at all — upstream-only.
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert_eq!(
            out.served,
            BTreeSet::from(["1.0.0".to_string(), "1.2.0".to_string()])
        );
        // Newest served version per semver ordering.
        assert_eq!(out.latest, Some("1.2.0".to_string()));
    }

    #[test]
    fn released_only_excludes_never_ingested_upstream_versions() {
        // ReleasedOnly is build-safe — a never-ingested
        // upstream version is NOT advertised.
        let upstream = ["1.0.0", "9.9.9"]; // 9.9.9 is upstream-only.
        let status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert_eq!(out.served, BTreeSet::from(["1.0.0".to_string()]));
        assert_eq!(out.latest, Some("1.0.0".to_string()));
    }

    #[test]
    fn released_only_excludes_stale_hort_rows_unpublished_upstream() {
        // Hort has a Released row for 0.9.0 but upstream has unpublished it.
        // The intersect-with-upstream guard keeps the unpublished row out.
        let upstream = ["1.0.0"];
        let status = vec![
            ("0.9.0".to_string(), QuarantineStatus::Released),
            ("1.0.0".to_string(), QuarantineStatus::Released),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert_eq!(out.served, BTreeSet::from(["1.0.0".to_string()]));
    }

    #[test]
    fn released_only_quarantined_newest_falls_back_to_prior_released() {
        // The build-safety property: a quarantined newest
        // upstream version means a range resolves to the prior
        // released. The helper output is the *served* set; the format
        // crate runs its range resolver against that set.
        let upstream = ["1.0.0", "1.1.0", "1.2.0"];
        let status = vec![
            ("1.0.0".to_string(), QuarantineStatus::Released),
            ("1.1.0".to_string(), QuarantineStatus::Released),
            // 1.2.0 is held in quarantine — must NOT be the resolved
            // latest under ReleasedOnly.
            ("1.2.0".to_string(), QuarantineStatus::Quarantined),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert_eq!(out.latest, Some("1.1.0".to_string()));
        assert!(!out.served.contains("1.2.0"));
    }

    // ---------- filter_served_versions / IncludePending ----------

    #[test]
    fn include_pending_keeps_unknown_upstream_versions() {
        // IncludePending keeps never-ingested upstream
        // versions advertised — the trade-off vs ReleasedOnly.
        let upstream = ["1.0.0", "1.1.0", "9.9.9"]; // 9.9.9 unknown to hort.
        let status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::IncludePending,
            &NpmSemverOrdering,
        );
        assert_eq!(
            out.served,
            BTreeSet::from([
                "1.0.0".to_string(),
                "1.1.0".to_string(),
                "9.9.9".to_string()
            ])
        );
        assert_eq!(out.latest, Some("9.9.9".to_string()));
    }

    #[test]
    fn include_pending_drops_quarantined_rejected_indeterminate() {
        let upstream = ["1.0.0", "1.1.0", "1.2.0", "1.3.0"];
        let status = vec![
            ("1.0.0".to_string(), QuarantineStatus::Quarantined),
            ("1.1.0".to_string(), QuarantineStatus::Rejected),
            ("1.2.0".to_string(), QuarantineStatus::ScanIndeterminate),
            ("1.3.0".to_string(), QuarantineStatus::Released),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::IncludePending,
            &NpmSemverOrdering,
        );
        assert_eq!(out.served, BTreeSet::from(["1.3.0".to_string()]));
        assert_eq!(out.latest, Some("1.3.0".to_string()));
    }

    // ---------- filter_served_versions / common ----------

    #[test]
    fn empty_served_set_yields_no_latest() {
        let upstream = ["1.0.0"];
        let status = vec![("1.0.0".to_string(), QuarantineStatus::Quarantined)];
        for mode in [IndexMode::ReleasedOnly, IndexMode::IncludePending] {
            let out = filter_served_versions(&upstream, &status, mode, &NpmSemverOrdering);
            assert!(out.served.is_empty(), "{mode:?}: served must be empty");
            assert_eq!(out.latest, None, "{mode:?}: latest must be None");
        }
    }

    #[test]
    fn empty_upstream_yields_empty_served() {
        let out = filter_served_versions(
            &[],
            &[("1.0.0".to_string(), QuarantineStatus::Released)],
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert!(out.served.is_empty());
        assert_eq!(out.latest, None);

        let out = filter_served_versions(&[], &[], IndexMode::IncludePending, &NpmSemverOrdering);
        assert!(out.served.is_empty());
        assert_eq!(out.latest, None);
    }

    #[test]
    fn duplicate_upstream_versions_collapse() {
        let upstream = ["1.0.0", "1.0.0", "1.0.0"];
        let status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        assert_eq!(out.served, BTreeSet::from(["1.0.0".to_string()]));
    }

    #[test]
    fn latest_uses_semver_not_lexicographic() {
        let upstream = ["1.9.0", "1.10.0"];
        let status = vec![
            ("1.9.0".to_string(), QuarantineStatus::Released),
            ("1.10.0".to_string(), QuarantineStatus::Released),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &NpmSemverOrdering,
        );
        // Lexicographic would pick 1.9.0; the semver ordering picks 1.10.0.
        assert_eq!(out.latest, Some("1.10.0".to_string()));
    }

    #[test]
    fn is_servable_status_matrix() {
        // Servable.
        assert!(is_servable_status(QuarantineStatus::None));
        assert!(is_servable_status(QuarantineStatus::Released));
        // Non-servable.
        assert!(!is_servable_status(QuarantineStatus::Quarantined));
        assert!(!is_servable_status(QuarantineStatus::Rejected));
        assert!(!is_servable_status(QuarantineStatus::ScanIndeterminate));
    }

    // ---------- CargoSemverOrdering — Cargo reuses npm/semver ----------

    #[test]
    fn cargo_semver_alias_resolves_to_npm_impl() {
        // The alias must compare identically — it's a `type` alias on
        // the same unit struct, so a single instance constructed via
        // `NpmSemverOrdering` is assignable through the alias and
        // produces the same ordering at the trait method.
        let inst = NpmSemverOrdering;
        let _via_alias: CargoSemverOrdering = inst;
        assert_eq!(inst.compare("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(inst.compare("1.0.0-alpha", "1.0.0"), Ordering::Less);
    }

    // ---------- Pep440Ordering ----------

    fn pep(a: &str, b: &str) -> Ordering {
        Pep440Ordering.compare(a, b)
    }

    #[test]
    fn pep440_orders_release_segments_numerically() {
        // PEP 440 §Final releases: components compared as integers.
        assert_eq!(pep("1.10", "1.9"), Ordering::Greater);
        assert_eq!(pep("2.0", "10.0"), Ordering::Less);
        assert_eq!(pep("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn pep440_trailing_zeros_insignificant() {
        // PEP 440 §Insignificant trailing zeros.
        assert_eq!(pep("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(pep("1.0.0", "1.0.0.0"), Ordering::Equal);
        assert_eq!(pep("1", "1.0.0.0"), Ordering::Equal);
        assert_eq!(pep("1.0.0", "1.0.0.1"), Ordering::Less);
    }

    #[test]
    fn pep440_arbitrary_release_segment_count() {
        // Unlike semver, PEP 440 admits 4+ release segments.
        assert_eq!(pep("1.0.0.0", "1.0.0.1"), Ordering::Less);
        assert_eq!(pep("1.0.0.5", "1.0.1"), Ordering::Less);
    }

    #[test]
    fn pep440_prerelease_below_release() {
        // PEP 440 §Pre-release: aN/bN/rcN < release.
        assert_eq!(pep("1.0a1", "1.0"), Ordering::Less);
        assert_eq!(pep("1.0b1", "1.0"), Ordering::Less);
        assert_eq!(pep("1.0rc1", "1.0"), Ordering::Less);
        assert_eq!(pep("1.0", "1.0a1"), Ordering::Greater);
    }

    #[test]
    fn pep440_prerelease_alpha_beta_rc_ordering() {
        // PEP 440 §Pre-release ordering: a < b < rc.
        assert_eq!(pep("1.0a1", "1.0b1"), Ordering::Less);
        assert_eq!(pep("1.0b1", "1.0rc1"), Ordering::Less);
        // Same kind: number compared numerically (not lex).
        assert_eq!(pep("1.0a2", "1.0a10"), Ordering::Less);
    }

    #[test]
    fn pep440_normalises_long_pre_spellings() {
        // PEP 440 §Pre-release spelling: alpha→a, beta→b, c/pre/preview→rc.
        assert_eq!(pep("1.0alpha1", "1.0a1"), Ordering::Equal);
        assert_eq!(pep("1.0beta1", "1.0b1"), Ordering::Equal);
        assert_eq!(pep("1.0rc1", "1.0c1"), Ordering::Equal);
        assert_eq!(pep("1.0rc1", "1.0pre1"), Ordering::Equal);
        assert_eq!(pep("1.0rc1", "1.0preview1"), Ordering::Equal);
    }

    #[test]
    fn pep440_postrelease_above_release() {
        // PEP 440 §Post-releases: release < release.postN.
        assert_eq!(pep("1.0", "1.0.post1"), Ordering::Less);
        assert_eq!(pep("1.0.post1", "1.0.post2"), Ordering::Less);
    }

    #[test]
    fn pep440_devrelease_below_release_and_pre() {
        // PEP 440 §Developmental releases: .devN sorts below everything
        // at the same epoch+release+pre+post.
        assert_eq!(pep("1.0.dev1", "1.0"), Ordering::Less);
        assert_eq!(pep("1.0.dev1", "1.0a1"), Ordering::Less);
        assert_eq!(pep("1.0.dev1", "1.0.dev2"), Ordering::Less);
    }

    #[test]
    fn pep440_epoch_dominates() {
        // PEP 440 §Version epochs: epoch wins absolutely.
        assert_eq!(pep("1!1.0", "2.0"), Ordering::Greater);
        assert_eq!(pep("0!2.0", "1!0.0.1"), Ordering::Less);
    }

    #[test]
    fn pep440_local_version_above_public() {
        // PEP 440 §Local version semantics: local-present > local-absent
        // at the same public version.
        assert_eq!(pep("1.0", "1.0+local"), Ordering::Less);
        // Numeric segments outrank alphanumeric within the local part.
        assert_eq!(pep("1.0+abc", "1.0+1"), Ordering::Less);
    }

    #[test]
    fn pep440_implicit_pre_post_dev_number_defaults_to_zero() {
        // PEP 440 §Implicit pre-release number.
        assert_eq!(pep("1.0a", "1.0a0"), Ordering::Equal);
        assert_eq!(pep("1.0.post", "1.0.post0"), Ordering::Equal);
        assert_eq!(pep("1.0.dev", "1.0.dev0"), Ordering::Equal);
    }

    #[test]
    fn pep440_v_prefix_tolerated() {
        // PEP 440 §Preceding v character.
        assert_eq!(pep("v1.0", "1.0"), Ordering::Equal);
        assert_eq!(pep("V2.0", "v1.0"), Ordering::Greater);
    }

    #[test]
    fn pep440_malformed_input_falls_back_to_lex() {
        assert_eq!(
            pep("not-a-version", "also-bad"),
            "not-a-version".cmp("also-bad")
        );
        assert_eq!(pep("1.0", "not-a-version"), Ordering::Greater);
        assert_eq!(pep("not-a-version", "1.0"), Ordering::Less);
    }

    #[test]
    fn pep440_partial_ord_agrees_with_ord() {
        let a = ParsedPep440Version::parse("1.0").unwrap();
        let b = ParsedPep440Version::parse("2.0").unwrap();
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    }

    #[test]
    fn pep440_used_via_filter_picks_pep440_latest_not_lex() {
        // Build-safety property at the helper layer: with both versions
        // released, the filter must pick the PEP 440 latest (1.10.0),
        // not the lexicographic latest (1.9.0).
        let upstream = ["1.9.0", "1.10.0"];
        let status = vec![
            ("1.9.0".to_string(), QuarantineStatus::Released),
            ("1.10.0".to_string(), QuarantineStatus::Released),
        ];
        let out =
            filter_served_versions(&upstream, &status, IndexMode::ReleasedOnly, &Pep440Ordering);
        assert_eq!(out.latest, Some("1.10.0".to_string()));
    }

    // ---------- MavenVersionOrdering ----------

    fn mvn(a: &str, b: &str) -> Ordering {
        MavenVersionOrdering.compare(a, b)
    }

    /// Assert `a < b` and, by antisymmetry, `b > a`.
    fn assert_mvn_lt(a: &str, b: &str) {
        assert_eq!(mvn(a, b), Ordering::Less, "expected {a} < {b}");
        assert_eq!(mvn(b, a), Ordering::Greater, "antisymmetry: {b} > {a}");
    }

    /// Assert `a == b` in both directions.
    fn assert_mvn_eq(a: &str, b: &str) {
        assert_eq!(mvn(a, b), Ordering::Equal, "expected {a} == {b}");
        assert_eq!(mvn(b, a), Ordering::Equal, "expected {b} == {a}");
    }

    #[test]
    fn maven_basic_numeric_ordering() {
        // Official: 1 < 1.1.
        assert_mvn_lt("1", "1.1");
        // Numeric tokens compare as integers, not lexically.
        assert_mvn_lt("1-foo2", "1-foo10");
    }

    #[test]
    fn maven_snapshot_and_sp_around_release() {
        // Official: 1-snapshot < 1 < 1-sp.
        assert_mvn_lt("1-snapshot", "1");
        assert_mvn_lt("1", "1-sp");
        assert_mvn_lt("1-snapshot", "1-sp");
    }

    #[test]
    fn maven_qualifier_vs_subsequent_numeric_section() {
        // Official: 1.foo = 1-foo < 1-1 < 1.1.
        assert_mvn_eq("1.foo", "1-foo");
        assert_mvn_lt("1-foo", "1-1");
        assert_mvn_lt("1-1", "1.1");
    }

    #[test]
    fn maven_trailing_null_equivalences() {
        // Official: 1.ga = 1-ga = 1-0 = 1.0 = 1.
        // (The original spec wording also chains `= 1_0`, but real
        // maven-artifact does NOT treat `_` as a separator — `1_0`
        // parses to `1-_` and is NOT equal to `1`. See
        // `maven_underscore_is_not_a_separator` below. The authoritative
        // `ComparableVersion.java` branches only on `.` and `-`, so this
        // implementation follows the spec over the example's `_` link.)
        assert_mvn_eq("1.ga", "1-ga");
        assert_mvn_eq("1-ga", "1-0");
        assert_mvn_eq("1-0", "1.0");
        assert_mvn_eq("1.0", "1");
        // Transitivity spot-check through the chain.
        assert_mvn_eq("1.ga", "1");
        // final / release are also release-equivalent nulls.
        assert_mvn_eq("1.final", "1");
        assert_mvn_eq("1.release", "1");
    }

    #[test]
    fn maven_underscore_is_not_a_separator() {
        // `_` is an ordinary qualifier character, NOT a separator —
        // verified against real maven-artifact 3.9.11
        // (`1_0` -> canonical `1-_`). So `1_0` is an *unknown* qualifier
        // section and sorts ABOVE the bare release `1` (unknown > release),
        // and is distinct from `1.0` / `1-0` (which equal `1`).
        assert_mvn_lt("1", "1_0");
        assert_ne!(mvn("1_0", "1.0"), Ordering::Equal);
        assert_ne!(mvn("1_0", "1-0"), Ordering::Equal);
        // `1_0` and `1_0` are of course equal (reflexive).
        assert_mvn_eq("1_0", "1_0");
    }

    #[test]
    fn maven_alias_before_digit() {
        // Official: 1-a1 = 1-alpha-1 (a→alpha only before a digit; the
        // digit↔letter transition then splits `1` into its own section).
        assert_mvn_eq("1-a1", "1-alpha-1");
        // b→beta, m→milestone, same rule.
        assert_mvn_eq("1-b2", "1-beta-2");
        assert_mvn_eq("1-m3", "1-milestone-3");
        // cr→rc alias.
        assert_mvn_eq("1-cr1", "1-rc1");
    }

    #[test]
    fn maven_bare_letter_is_not_aliased() {
        // A bare trailing `a` is NOT alpha — it is an unknown qualifier
        // (the alias only fires before a digit). An unknown qualifier
        // sorts AFTER all known ones and after release, so `1-a` > `1`
        // (whereas `1-alpha` < `1`).
        assert_mvn_lt("1-alpha", "1");
        assert_mvn_lt("1", "1-a");
        // Therefore alpha (known, < release) sorts below a bare `a`
        // (unknown, > release).
        assert_mvn_lt("1-alpha", "1-a");
        // Same for bare `b` / `m`.
        assert_mvn_lt("1", "1-b");
        assert_mvn_lt("1", "1-m");
    }

    #[test]
    fn maven_case_insensitive() {
        // Official: 1.0-alpha1 = 1.0-ALPHA1.
        assert_mvn_eq("1.0-alpha1", "1.0-ALPHA1");
        assert_mvn_eq("3.2-ALPHA1", "3.2-alpha1");
    }

    #[test]
    fn maven_qualifier_sorts_before_numeric() {
        // Official: 1.7 > 1.K (a qualifier sorts before a numeric at the
        // same position).
        assert_eq!(mvn("1.7", "1.K"), Ordering::Greater);
        assert_eq!(mvn("1.K", "1.7"), Ordering::Less);
    }

    #[test]
    fn maven_unknown_qualifiers_lexical() {
        // Official: 5.zebra > 5.aardvark (unknown qualifiers compare
        // lexically among themselves).
        assert_mvn_lt("5.aardvark", "5.zebra");
    }

    #[test]
    fn maven_non_ascii_letters_are_unknown_qualifiers() {
        // Official: 1.α > 1.b — a non-ASCII letter is an unknown
        // qualifier, sorting after the known `beta`.
        assert_eq!(mvn("1.\u{3b1}", "1.b"), Ordering::Greater);
    }

    #[test]
    fn maven_ga_trims_but_sp_does_not() {
        // Official: 1-sp-1 < 1-ga-1. `ga` is a release-equivalent null,
        // so `1-ga-1` trims `ga` away from the section and compares as
        // `1` then `1`; `sp` is a real qualifier above release, so
        // `1-sp-1` carries the `sp` section and sorts below.
        assert_mvn_lt("1-sp-1", "1-ga-1");
    }

    #[test]
    fn maven_canonical_worked_example_equivalences() {
        // The doc's worked tokenisation: 1-1.foo-bar1baz-.1 normalises to
        // 1-1.foo-bar-1-baz-0.1 (the digit↔letter transitions split
        // bar1baz, the empty token before `.1` becomes 0). The two
        // spellings must therefore compare equal.
        assert_mvn_eq("1-1.foo-bar1baz-.1", "1-1.foo-bar-1-baz-0.1");
    }

    #[test]
    fn maven_reflexivity() {
        for v in [
            "1.0",
            "1.0.0",
            "1-SNAPSHOT",
            "31.1-jre",
            "1-alpha-1",
            "2.0-rc2",
            "",
        ] {
            assert_eq!(mvn(v, v), Ordering::Equal, "reflexivity for {v:?}");
        }
    }

    #[test]
    fn maven_sort_stability_check() {
        // Sort a shuffled set and assert the ComparableVersion order.
        let mut versions = vec![
            "1.0",
            "1-sp",
            "2.0",
            "1-snapshot",
            "1.0-alpha1",
            "1.0-beta1",
            "1.0-rc1",
            "1.0.1",
            "1-milestone1",
        ];
        versions.sort_by(|a, b| MavenVersionOrdering.compare(a, b));
        assert_eq!(
            versions,
            vec![
                "1.0-alpha1",
                "1.0-beta1",
                "1-milestone1",
                "1.0-rc1",
                "1-snapshot",
                "1.0",
                "1-sp",
                "1.0.1",
                "2.0",
            ],
        );
    }

    #[test]
    fn maven_empty_and_zero_equivalent() {
        // Empty input and "0" are both the canonical zero/null.
        assert_mvn_eq("", "0");
        assert_mvn_eq("0", "0.0");
    }

    #[test]
    fn maven_snapshot_lowercase_equivalence() {
        // SNAPSHOT is a known qualifier; case-insensitive.
        assert_mvn_eq("1.0-SNAPSHOT", "1.0-snapshot");
        assert_mvn_lt("1.0-SNAPSHOT", "1.0");
    }

    #[test]
    fn maven_self_bounding_guard_no_overflow_on_pathological_input() {
        // A version made of ~10k '-' separators would, without the guard,
        // recurse one List level per '-' through parse/normalize/compare and
        // overflow the thread stack (an uncatchable SIGABRT). With the
        // self-bounding guard it falls back to a non-recursive byte-lexical
        // compare: the call must RETURN (not abort) and be deterministic.
        let pathological = "1-".repeat(10_000);
        assert!(pathological.len() > MAVEN_VERSION_PARSE_MAX_BYTES);

        // Reflexive: x vs x is Equal (via the byte-lexical fallback).
        assert_eq!(mvn(&pathological, &pathological), Ordering::Equal);

        // a != b gives a stable, non-panicking result (over-cap on both legs).
        let other = "2-".repeat(10_000);
        let ab = mvn(&pathological, &other);
        let ba = mvn(&other, &pathological);
        assert_ne!(ab, Ordering::Equal);
        assert_eq!(ab, ab.reverse().reverse(), "result is a concrete ordering");
        assert_eq!(ba, ab.reverse(), "antisymmetric byte-lexical fallback");

        // Mixed: one leg over-cap, the other a normal version — still returns.
        let normal = "1.2.3";
        let _ = mvn(&pathological, normal);
        let _ = mvn(normal, &pathological);

        // A version exactly at the cap still uses the structured parse and is
        // reflexively Equal (boundary: `<=` cap → structured, `>` cap →
        // fallback).
        let at_cap = "a".repeat(MAVEN_VERSION_PARSE_MAX_BYTES);
        assert_eq!(at_cap.len(), MAVEN_VERSION_PARSE_MAX_BYTES);
        assert_eq!(mvn(&at_cap, &at_cap), Ordering::Equal);
    }

    #[test]
    fn maven_used_via_filter_picks_maven_latest_not_lex() {
        // Exercises MavenVersionOrdering through the shared
        // filter_served_versions helper (its real consumer shape). With
        // all versions released, the resolved latest is the Maven max
        // (1.10) — not the lexicographic max (1.9) — and a -SNAPSHOT sorts
        // below the corresponding release.
        let upstream = ["1.9", "1.10", "2.0-SNAPSHOT"];
        let status = vec![
            ("1.9".to_string(), QuarantineStatus::Released),
            ("1.10".to_string(), QuarantineStatus::Released),
            ("2.0-SNAPSHOT".to_string(), QuarantineStatus::Released),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::ReleasedOnly,
            &MavenVersionOrdering,
        );
        // 2.0-SNAPSHOT < 2.0 but here there is no 2.0 release; the served
        // set's Maven max is 2.0-SNAPSHOT (> 1.10).
        assert_eq!(out.latest, Some("2.0-SNAPSHOT".to_string()));
    }

    #[test]
    fn pep440_include_pending_drops_dev_and_keeps_release() {
        // IncludePending: never-ingested versions stay; hort-known
        // non-servable versions get dropped. The `latest` is the
        // PEP 440 max over the *served* set.
        let upstream = ["1.0", "1.0.dev1", "2.0a1", "2.0"];
        let status = vec![
            // 2.0 quarantined: drop it.
            ("2.0".to_string(), QuarantineStatus::Quarantined),
        ];
        let out = filter_served_versions(
            &upstream,
            &status,
            IndexMode::IncludePending,
            &Pep440Ordering,
        );
        assert!(
            !out.served.contains("2.0"),
            "2.0 quarantined must be dropped"
        );
        // 2.0a1 stays (never ingested → not known non-servable). PEP 440
        // max over {1.0, 1.0.dev1, 2.0a1} is 2.0a1.
        assert_eq!(out.latest, Some("2.0a1".to_string()));
    }
}
