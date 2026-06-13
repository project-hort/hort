use chrono::{DateTime, Utc};

use crate::error::DomainResult;
use crate::types::{Ecosystem, Finding, SbomComponent};

use super::BoxFuture;

/// One vulnerability entry from a bulk-diff pull.
///
/// Built by the adapter from the per-ecosystem `osv-vulnerabilities` zip
/// archives and consumed by `AdvisoryWatchTickHandler` to drive
/// targeted re-scans against the local SBOM index.
///
/// The shape stays minimal — `id`, `modified` timestamp for the
/// `> last_sync_at` filter, plus the affected-package list the handler
/// joins against `sbom_components`. Severity / CVSS / references are NOT
/// required for the watch path because the resulting per-artifact
/// `kind='scan'` job re-runs the scanning producer pipeline, which
/// re-derives those fields from a fresh per-component `AdvisoryPort::query`.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryEntry {
    /// Canonical advisory id — `"GHSA-…"`, `"CVE-…"`, `"OSV-…"`, etc.
    pub id: String,
    /// Last-modified timestamp from the OSV record's `modified` field.
    /// Used by the handler's `> last_sync_at` belt-and-braces filter.
    pub modified: DateTime<Utc>,
    /// Affected packages flattened across the OSV `affected[]` array.
    /// One [`AdvisoryAffectedPackage`] per `(ecosystem, name)` pair the
    /// advisory targets — version ranges resolved into a discrete list.
    pub affected: Vec<AdvisoryAffectedPackage>,
}

/// One `(ecosystem, name, affected_versions)` triple inside an
/// [`AdvisoryEntry`].
///
/// The adapter resolves OSV ecosystem strings (`"npm"`, `"PyPI"`,
/// `"crates.io"`, …) into the typed [`Ecosystem`] enum so the domain
/// stays decoupled from OSV's specific spelling. Entries whose
/// ecosystem cannot be mapped are dropped at the adapter boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryAffectedPackage {
    /// The package's typed ecosystem.
    pub ecosystem: Ecosystem,
    /// The package name as the ecosystem itself spells it (the same
    /// string that `sbom_components.name` carries).
    pub name: String,
    /// Concrete affected versions — the OSV record's `versions` array,
    /// flattened from any range expressions the adapter resolved. May
    /// be empty (no concrete version reported); empty lists short-
    /// circuit `SbomComponentRepository::list_artifacts_by_match` to
    /// `Ok(vec![])` per its contract.
    pub affected_versions: Vec<String>,
}

/// Result of a bulk-diff pull across all configured ecosystems.
///
/// `entries` is the flat list of advisory entries the adapter parsed
/// from the per-ecosystem zip archives whose `modified` field is
/// strictly after the `since` timestamp the caller supplied.
///
/// `all_ecosystems_ok` is `true` only when every configured ecosystem's
/// fetch + parse succeeded. The handler advances the
/// `advisory_sync_state.last_sync_at` checkpoint **only** when this
/// flag is `true`; partial-ecosystem failure preserves the prior
/// timestamp so the next tick re-attempts the missed window.
#[derive(Debug, Clone)]
pub struct AdvisoryDiffResult {
    /// Advisory entries with `modified > since`, flattened across all
    /// configured ecosystems in adapter-defined order.
    pub entries: Vec<AdvisoryEntry>,
    /// `true` iff every configured ecosystem's bulk pull + parse step
    /// completed without error. The handler reads this flag to decide
    /// whether to advance the per-feed checkpoint.
    pub all_ecosystems_ok: bool,
}

/// Outbound port for vulnerability advisory feeds (OSV batch, GitHub
/// Advisory).
///
/// Used in three places:
/// 1. **Pre-scan enrichment** — `ScanOrchestrationUseCase` queries
///    advisories for the SBOM via [`query`](Self::query) before
///    invoking scanners; merges results.
/// 2. **Stand-alone "advisory mode"** — when a `ScanPolicy` lists only
///    `"osv"` as a backend, the orchestrator skips Trivy entirely and
///    uses just `query`. Cheaper than Trivy for pure dependency-list
///    checks.
/// 3. **Bulk-diff polling** — `AdvisoryWatchTickHandler`
///    calls [`pull_diff_since`](Self::pull_diff_since) once per
///    cron tick to pull the per-ecosystem `osv-vulnerabilities` archives
///    and feed targeted re-scans into the `jobs` queue.
pub trait AdvisoryPort: Send + Sync {
    /// Resolve a list of SBOM components against the configured
    /// vulnerability feeds. Caller batches; the adapter is free to
    /// further chunk and cache.
    fn query<'a>(
        &'a self,
        components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>>;

    /// Pull the bulk OSV diff for entries modified after `since`.
    ///
    /// Returns an [`AdvisoryDiffResult`] aggregating entries across
    /// every configured ecosystem plus a boolean flag indicating
    /// whether every ecosystem's pull succeeded. The handler advances
    /// the `advisory_sync_state.last_sync_at` checkpoint only when
    /// `all_ecosystems_ok` is `true` — partial failure preserves the
    /// prior timestamp so the next tick retries the missed window.
    ///
    /// Default impl returns `DomainError::Invariant("not implemented")`
    /// so existing test fixtures that pre-date the bulk-diff path
    /// (`query`-only mocks) continue to compile without
    /// modification. Adapters with no bulk-pull capability also
    /// continue to operate via the default impl when callers only
    /// exercise `query`.
    fn pull_diff_since<'a>(
        &'a self,
        since: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<AdvisoryDiffResult>> {
        let _ = since;
        Box::pin(async {
            Err(crate::error::DomainError::Invariant(
                "pull_diff_since not implemented".into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    /// Compile-time assertion that `AdvisoryPort` is dyn-compatible.
    /// Runtime: `size_of` executes in the test body for coverage.
    #[test]
    fn advisory_port_is_dyn_compatible() {
        let _ = size_of::<&dyn AdvisoryPort>();
    }

    /// `Box<dyn AdvisoryPort>` resolves — proves the trait can be
    /// type-erased into an owned trait object the way adapter
    /// composition roots will store it.
    #[test]
    fn advisory_port_can_be_boxed() {
        let _: Option<Box<dyn AdvisoryPort>> = None;
    }

    /// `AdvisoryEntry` and `AdvisoryAffectedPackage` are `Clone +
    /// PartialEq` so handler tests can compare expected vs. observed
    /// entry lists without bespoke per-field assertions.
    #[test]
    fn advisory_entry_is_clone_and_partial_eq() {
        let entry = AdvisoryEntry {
            id: "GHSA-x".into(),
            modified: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            affected: vec![AdvisoryAffectedPackage {
                ecosystem: Ecosystem::Npm,
                name: "lodash".into(),
                affected_versions: vec!["4.17.20".into()],
            }],
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    /// The default `pull_diff_since` impl returns `DomainError::Invariant`
    /// with the documented message. Pins the contract for legacy fixtures.
    #[tokio::test]
    async fn pull_diff_since_default_impl_returns_invariant_error() {
        struct Bare;
        impl AdvisoryPort for Bare {
            fn query<'a>(
                &'a self,
                _components: &'a [SbomComponent],
            ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let port: Box<dyn AdvisoryPort> = Box::new(Bare);
        let err = port
            .pull_diff_since(Utc::now())
            .await
            .expect_err("default impl returns Invariant");
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    /// Custom `pull_diff_since` overrides dispatch through the trait
    /// object — pins the dispatch shape adapters rely on.
    #[tokio::test]
    async fn pull_diff_since_override_dispatches_through_trait_object() {
        struct WithOverride;
        impl AdvisoryPort for WithOverride {
            fn query<'a>(
                &'a self,
                _components: &'a [SbomComponent],
            ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn pull_diff_since<'a>(
                &'a self,
                _since: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<AdvisoryDiffResult>> {
                Box::pin(async {
                    Ok(AdvisoryDiffResult {
                        entries: Vec::new(),
                        all_ecosystems_ok: true,
                    })
                })
            }
        }
        let port: Box<dyn AdvisoryPort> = Box::new(WithOverride);
        let result = port
            .pull_diff_since(Utc::now())
            .await
            .expect("override returns Ok");
        assert!(result.entries.is_empty());
        assert!(result.all_ecosystems_ok);
    }
}
