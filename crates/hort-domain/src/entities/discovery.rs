//! Discovery + self-service prefetch value types (see
//! `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! These are the internal command + response shapes the
//! `DiscoveryUseCase` and `SelfServicePrefetchUseCase` consume / produce.
//! The HTTP envelope DTOs live in the inbound handler crate
//! (`hort-http-discovery`) and are converted into these types at the
//! boundary.
//!
//! # Layering rule
//!
//! Nothing in this module implements `Deserialize`. The architect-doc
//! anti-pattern *"Domain type deserialization in API layer"* is
//! unconditional: domain types do not decode from external input. The
//! inbound handler crate owns the request DTOs and converts them to
//! these types before invoking the use case.
//!
//! `Serialize` IS implemented on the read-shape response types
//! (`DiscoveryListing`, `DiscoveryVersionEntry`, `DiscoveryVersionStatus`,
//! `PrefetchOutcome`, `RejectedItem`, `FailedItem`, `PackageCoords`,
//! `RejectionReason`, `PrefetchItemError`) — the `hort-http-discovery`
//! handler renders them as the JSON response body. This mirrors the
//! `CurationUseCase::BlockOutcome` envelope discipline
//! (`crates/hort-app/src/use_cases/curation_use_case.rs:118`):
//! Serialize-only domain types used as a response envelope, never as a
//! request body. The `PrefetchRequestItem` command type is internal-only
//! (no Serialize / no Deserialize) and is constructed by the handler at
//! the inbound boundary from the DTO that DOES decode external input.
//!
//! # `SelfServicePrefetchRequest` is intentionally NOT a domain type
//!
//! The HTTP envelope wrapper is a handler-specific DTO that lives in
//! `hort-http-discovery`. Mirroring it inside the domain would
//! either force `Deserialize` (anti-pattern) or be redundant ceremony —
//! the use case takes `Vec<PrefetchRequestItem>` directly.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// DiscoveryListing — response envelope for `GET .../discovery/versions/{pkg}`
// ---------------------------------------------------------------------------

/// Discovery response for a single package in a single repository.
///
/// Carries the union of AK-held versions and upstream-advertised
/// versions, each tagged with its current [`DiscoveryVersionStatus`].
/// Returned by `DiscoveryUseCase::list_versions`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryListing {
    /// Package name, in the format-native spelling (case-preserving;
    /// the use case echoes the caller-supplied spelling and does not
    /// canonicalise here).
    pub package: String,
    /// Format identifier (`"npm"`, `"pypi"`, `"cargo"`, ...). Mirrors
    /// the `format` column on `repositories`.
    pub format: String,
    /// One entry per known version (AK-held ∪ upstream-advertised).
    pub versions: Vec<DiscoveryVersionEntry>,
}

/// One version row in a [`DiscoveryListing`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryVersionEntry {
    /// Version string in the format-native spelling.
    pub version: String,
    /// Current status of this version in this repository, including
    /// the distinction between active-quarantine and
    /// awaiting-release-authority sub-states.
    pub status: DiscoveryVersionStatus,
}

/// Per-version status, as surfaced by discovery.
///
/// `Quarantined` and `QuarantinedAwaitingRelease` are distinct
/// sub-states. The first carries a future-dated `quarantine_until`
/// (the deadline has not elapsed). The second has no `quarantine_until`
/// payload — the deadline has elapsed but no release authority
/// (`ScanSucceeded` ∨ `ScanWaived` ∨ admin override ∨ curator-waiver)
/// has fired yet; release is fail-closed on an affirmative authority,
/// never on deadline expiry alone (ADR 0007). The use case computes the
/// sub-state by comparing `artifact.quarantine_until` to `Utc::now()` at
/// read time.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiscoveryVersionStatus {
    /// Released — installable.
    Released,
    /// Quarantined with an active future-dated deadline.
    Quarantined {
        /// Future-dated UTC instant at which the quarantine window
        /// ends. Once `Utc::now() >= quarantine_until`, the use case
        /// surfaces [`Self::QuarantinedAwaitingRelease`] instead.
        quarantine_until: DateTime<Utc>,
    },
    /// Quarantine deadline elapsed; no release authority has fired
    /// (ADR 0007). Operator UX hint: *"why is this stuck?"*.
    QuarantinedAwaitingRelease,
    /// Terminally rejected by scan or curator-block.
    Rejected,
    /// Scan result was indeterminate; treated as terminal for the
    /// auto-release path. Operator must waive or admin-override.
    ScanIndeterminate,
    /// Upstream-advertised but HORT has never ingested. Prefetching
    /// transitions to `Quarantined` via the pull-through path.
    Unknown,
}

// ---------------------------------------------------------------------------
// Prefetch command types
// ---------------------------------------------------------------------------

/// One item in a self-service prefetch batch.
///
/// Internal command type — no `Serialize`, no `Deserialize`. The HTTP
/// handler in `hort-http-discovery` decodes the request DTO and
/// constructs a `Vec<PrefetchRequestItem>` at the inbound boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefetchRequestItem {
    /// Package name (format-native spelling).
    pub package: String,
    /// Optional pinned version. `None` means *latest
    /// upstream-advertised* — the use case resolves the latest
    /// upstream version at enqueue time.
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// PrefetchOutcome — response envelope for `POST .../prefetch`
// ---------------------------------------------------------------------------

/// Result envelope for a self-service prefetch batch.
///
/// Continue-on-error shape (mirrors `CurationUseCase::BlockOutcome` at
/// `crates/hort-app/src/use_cases/curation_use_case.rs:118`): one input
/// item maps to exactly one of the four output buckets.
///
/// - `enqueued_job_ids` — successful enqueues; each ID is the primary
///   key of a fresh `jobs` row.
/// - `skipped_already_held` — the registry already holds this version
///   (status `Released` ∨ `Quarantined` ∨ `QuarantinedAwaitingRelease`);
///   the ingest is a no-op. All three "in-progress or terminal-held"
///   sub-states fold here — NOT in `failed`.
/// - `rejected_packages` — terminal registry status (`Rejected` ∨
///   `ScanIndeterminate`) for the requested version. Re-prefetch is the
///   auto-release-bypass anti-pattern; the operator must use
///   curator-waive (`docs/architecture/how-to/curator-workflow.md`) or
///   admin override.
/// - `failed` — per-item upstream-fetch / parse / network failure
///   ([`PrefetchItemError`]). The other items in the batch are NOT
///   rolled back.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrefetchOutcome {
    /// Successfully enqueued `jobs` row IDs. Empty when every item
    /// short-circuited (already-held / rejected / failed).
    pub enqueued_job_ids: Vec<Uuid>,
    /// Items HORT already holds at a status that absorbs the prefetch
    /// (see struct doc).
    pub skipped_already_held: Vec<PackageCoords>,
    /// Items whose currently-known HORT status is terminal-non-installable
    /// (`ScanRejected` or `ScanIndeterminate`) — re-prefetch refused.
    pub rejected_packages: Vec<RejectedItem>,
    /// Items that hit an upstream-side failure (per-item, sanitised).
    pub failed: Vec<FailedItem>,
}

/// A package coordinate (name + optional version) — appears in every
/// outcome bucket so the operator can correlate inputs to outputs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PackageCoords {
    /// Package name (format-native spelling).
    pub package: String,
    /// Version pin, if the request supplied one. `None` mirrors a
    /// `PrefetchRequestItem.version = None` input (= "latest").
    pub version: Option<String>,
}

/// One entry in [`PrefetchOutcome::rejected_packages`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RejectedItem {
    /// The coordinate the operator submitted.
    pub coords: PackageCoords,
    /// Why this version cannot be re-prefetched.
    pub reason: RejectionReason,
}

/// Terminal HORT statuses that refuse a fresh prefetch.
///
/// **Arm set is pinned at two** — `ScanRejected` and `ScanIndeterminate`.
/// Both share the same operator-actionable handling ("curator
/// waive OR admin override"); the discriminator is preserved here so
/// dashboards / future audit consumers can distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Terminal `Rejected` status — explicit reject (scan or curator).
    ScanRejected,
    /// Terminal `ScanIndeterminate` status — scanner could not produce
    /// a verdict; treated as terminal for the auto-release path.
    ScanIndeterminate,
}

/// One entry in [`PrefetchOutcome::failed`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FailedItem {
    /// The coordinate the operator submitted.
    pub coords: PackageCoords,
    /// Per-item failure classification.
    pub error: PrefetchItemError,
}

/// Per-item upstream-fetch failure classification.
///
/// **Arm set is pinned at eight** — `UpstreamNotFound`, `Unauthorized`,
/// `RateLimited`, `Upstream4xx`, `Upstream5xx`, `NetworkError`,
/// `Timeout`, `ParseError`.
///
/// **Alignment with `UpstreamFetchError`.** These eight variants
/// map 1:1 to the upstream-fetch subset of `UpstreamErrorKind` (the
/// metric `result` taxonomy). The prefetch use case translates the
/// per-item `UpstreamFetchError` returned by the port to the matching
/// `PrefetchItemError` for the response envelope AND to the matching
/// metric `result` label — one classification at the port boundary,
/// two consumers downstream.
///
/// `UpstreamFetchError::UnsupportedFormat` is NOT mirrored here — OCI
/// rejection is a call-level short-circuit (gate order), not a
/// per-item failure.
///
/// **Sanitisation invariant.** `NetworkError` and `ParseError` carry no
/// payload precisely because their natural inner content (TLS error
/// detail, upstream-supplied bytes) is operator-untrusted. The
/// inbound-handler maps each variant to a fixed sanitised string at the
/// response boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchItemError {
    /// Upstream returned 404 — the requested package does not exist
    /// upstream.
    UpstreamNotFound,
    /// Upstream returned 401 — credentials configured on the upstream
    /// mapping are bad. Operator-side fix.
    Unauthorized,
    /// Upstream returned 429 — operator should back off / retry later.
    RateLimited,
    /// Upstream returned some other 4xx; the specific status is NOT
    /// surfaced at this layer (operator sees the bucket).
    ///
    /// The explicit `serde(rename)` matches the `upstream_4xx` label in
    /// the `UpstreamErrorKind` metrics taxonomy; the default
    /// `snake_case` rule does not insert an underscore between letters
    /// and digits, which would otherwise drift the label.
    #[serde(rename = "upstream_4xx")]
    Upstream4xx,
    /// Upstream returned 5xx — upstream is broken. See [`Self::Upstream4xx`]
    /// for the matching rename rationale.
    #[serde(rename = "upstream_5xx")]
    Upstream5xx,
    /// Connection / TLS / DNS failure (sanitised — no host detail).
    NetworkError,
    /// Upstream fetch exceeded the configured timeout.
    Timeout,
    /// Upstream returned a body that did not parse as the expected
    /// per-format metadata shape (sanitised — payload not surfaced).
    ParseError,
    /// AK-side infrastructure failure (H7) — a DB / jobs-port / status-
    /// query error, NOT an upstream-network fault. Surfaced as its own
    /// bucket so operators don't chase egress / DNS for a server-side
    /// problem (the pre-H7 code folded these into [`Self::NetworkError`],
    /// which mislabelled a `jobs_trigger_source_check` constraint
    /// violation as a network error). Sanitised — no internal detail
    /// (table names, SQL) reaches the wire.
    Internal,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Compile-time anti-pattern guards ----------------------------------
    //
    // The architect-doc anti-pattern "Domain type deserialization in API
    // layer" forbids `Deserialize` on these types. `static_assertions`
    // turns the rule into a compile error so a future stray `derive` is
    // caught at build time, not at review time.
    static_assertions::assert_not_impl_any!(DiscoveryListing: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(DiscoveryVersionEntry: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(DiscoveryVersionStatus: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(PrefetchRequestItem: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(PrefetchOutcome: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(RejectedItem: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(FailedItem: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(PackageCoords: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(RejectionReason: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(PrefetchItemError: serde::de::DeserializeOwned);

    // `PrefetchRequestItem` is the internal command type — also no
    // `Serialize` (it never appears in a response body). The other types
    // legitimately implement `Serialize` for the response envelope.
    static_assertions::assert_not_impl_any!(PrefetchRequestItem: Serialize);

    // -- DiscoveryListing --------------------------------------------------

    #[test]
    fn discovery_listing_construction_and_eq() {
        let a = DiscoveryListing {
            package: "left-pad".into(),
            format: "npm".into(),
            versions: vec![DiscoveryVersionEntry {
                version: "1.3.0".into(),
                status: DiscoveryVersionStatus::Released,
            }],
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.package, "left-pad");
        assert_eq!(a.format, "npm");
        assert_eq!(a.versions.len(), 1);
    }

    #[test]
    fn discovery_listing_serializes_to_json() {
        let listing = DiscoveryListing {
            package: "p".into(),
            format: "npm".into(),
            versions: vec![],
        };
        let json = serde_json::to_value(&listing).unwrap();
        assert_eq!(json["package"], "p");
        assert_eq!(json["format"], "npm");
        assert_eq!(json["versions"], serde_json::json!([]));
    }

    // -- DiscoveryVersionEntry ---------------------------------------------

    #[test]
    fn discovery_version_entry_construction_and_eq() {
        let a = DiscoveryVersionEntry {
            version: "1.0.0".into(),
            status: DiscoveryVersionStatus::Unknown,
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.version, "1.0.0");
    }

    // -- DiscoveryVersionStatus — every arm --------------------------------

    #[test]
    fn discovery_version_status_released_arm() {
        let s = DiscoveryVersionStatus::Released;
        assert_eq!(s.clone(), s);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "released");
    }

    #[test]
    fn discovery_version_status_quarantined_arm_carries_deadline() {
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let s = DiscoveryVersionStatus::Quarantined {
            quarantine_until: when,
        };
        // Clone + Eq.
        assert_eq!(s.clone(), s);
        // Destructure to confirm the payload survives.
        match s {
            DiscoveryVersionStatus::Quarantined { quarantine_until } => {
                assert_eq!(quarantine_until, when);
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn discovery_version_status_quarantined_serializes_deadline() {
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let s = DiscoveryVersionStatus::Quarantined {
            quarantine_until: when,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "quarantined");
        assert!(json["quarantine_until"].is_string());
    }

    #[test]
    fn discovery_version_status_awaiting_release_is_distinct_from_quarantined() {
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let active = DiscoveryVersionStatus::Quarantined {
            quarantine_until: when,
        };
        let awaiting = DiscoveryVersionStatus::QuarantinedAwaitingRelease;
        assert_ne!(active, awaiting);
    }

    #[test]
    fn discovery_version_status_awaiting_release_serializes_without_payload() {
        let s = DiscoveryVersionStatus::QuarantinedAwaitingRelease;
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "quarantined_awaiting_release");
        assert!(json.get("quarantine_until").is_none());
    }

    #[test]
    fn discovery_version_status_rejected_arm() {
        let s = DiscoveryVersionStatus::Rejected;
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "rejected");
    }

    #[test]
    fn discovery_version_status_scan_indeterminate_arm() {
        let s = DiscoveryVersionStatus::ScanIndeterminate;
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "scan_indeterminate");
    }

    #[test]
    fn discovery_version_status_unknown_arm() {
        let s = DiscoveryVersionStatus::Unknown;
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "unknown");
    }

    #[test]
    fn discovery_version_status_six_arms_are_pairwise_distinct() {
        // Sanity-check: every match-able pair is non-equal. Catches a
        // future variant-rename that accidentally collapses two arms.
        let when = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let all = [
            DiscoveryVersionStatus::Released,
            DiscoveryVersionStatus::Quarantined {
                quarantine_until: when,
            },
            DiscoveryVersionStatus::QuarantinedAwaitingRelease,
            DiscoveryVersionStatus::Rejected,
            DiscoveryVersionStatus::ScanIndeterminate,
            DiscoveryVersionStatus::Unknown,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "arm pair ({i}, {j}) collapsed");
                }
            }
        }
    }

    // -- PrefetchRequestItem -----------------------------------------------

    #[test]
    fn prefetch_request_item_with_version() {
        let a = PrefetchRequestItem {
            package: "serde".into(),
            version: Some("1.0.0".into()),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.package, "serde");
        assert_eq!(a.version, Some("1.0.0".into()));
    }

    #[test]
    fn prefetch_request_item_without_version_means_latest() {
        let a = PrefetchRequestItem {
            package: "serde".into(),
            version: None,
        };
        assert!(a.version.is_none());
    }

    // -- PrefetchOutcome ---------------------------------------------------

    #[test]
    fn prefetch_outcome_empty_is_valid() {
        let outcome = PrefetchOutcome {
            enqueued_job_ids: vec![],
            skipped_already_held: vec![],
            rejected_packages: vec![],
            failed: vec![],
        };
        let clone = outcome.clone();
        assert_eq!(outcome, clone);
    }

    #[test]
    fn prefetch_outcome_partitions_into_four_buckets() {
        let coords = PackageCoords {
            package: "p".into(),
            version: Some("1.0".into()),
        };
        let outcome = PrefetchOutcome {
            enqueued_job_ids: vec![Uuid::from_u128(0x1)],
            skipped_already_held: vec![coords.clone()],
            rejected_packages: vec![RejectedItem {
                coords: coords.clone(),
                reason: RejectionReason::ScanRejected,
            }],
            failed: vec![FailedItem {
                coords,
                error: PrefetchItemError::Timeout,
            }],
        };
        assert_eq!(outcome.enqueued_job_ids.len(), 1);
        assert_eq!(outcome.skipped_already_held.len(), 1);
        assert_eq!(outcome.rejected_packages.len(), 1);
        assert_eq!(outcome.failed.len(), 1);
    }

    #[test]
    fn prefetch_outcome_serializes_to_json() {
        let outcome = PrefetchOutcome {
            enqueued_job_ids: vec![Uuid::from_u128(0x42)],
            skipped_already_held: vec![],
            rejected_packages: vec![],
            failed: vec![],
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert!(json["enqueued_job_ids"].is_array());
        assert_eq!(json["enqueued_job_ids"].as_array().unwrap().len(), 1);
        assert_eq!(json["skipped_already_held"], serde_json::json!([]));
        assert_eq!(json["rejected_packages"], serde_json::json!([]));
        assert_eq!(json["failed"], serde_json::json!([]));
    }

    // -- PackageCoords -----------------------------------------------------

    #[test]
    fn package_coords_with_version() {
        let c = PackageCoords {
            package: "p".into(),
            version: Some("1.0".into()),
        };
        let d = c.clone();
        assert_eq!(c, d);
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["package"], "p");
        assert_eq!(json["version"], "1.0");
    }

    #[test]
    fn package_coords_without_version() {
        let c = PackageCoords {
            package: "p".into(),
            version: None,
        };
        assert!(c.version.is_none());
        let json = serde_json::to_value(&c).unwrap();
        assert!(json["version"].is_null());
    }

    // -- RejectedItem ------------------------------------------------------

    #[test]
    fn rejected_item_construction_and_eq() {
        let item = RejectedItem {
            coords: PackageCoords {
                package: "p".into(),
                version: None,
            },
            reason: RejectionReason::ScanIndeterminate,
        };
        let clone = item.clone();
        assert_eq!(item, clone);
    }

    #[test]
    fn rejected_item_serializes() {
        let item = RejectedItem {
            coords: PackageCoords {
                package: "p".into(),
                version: Some("1".into()),
            },
            reason: RejectionReason::ScanRejected,
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["coords"]["package"], "p");
        assert_eq!(json["reason"], "scan_rejected");
    }

    // -- RejectionReason — both arms ---------------------------------------

    #[test]
    fn rejection_reason_scan_rejected_arm() {
        let r = RejectionReason::ScanRejected;
        let copy = r;
        assert_eq!(r, copy);
        let json = serde_json::to_value(r).unwrap();
        assert_eq!(json, serde_json::json!("scan_rejected"));
    }

    #[test]
    fn rejection_reason_scan_indeterminate_arm() {
        let r = RejectionReason::ScanIndeterminate;
        let copy = r;
        assert_eq!(r, copy);
        let json = serde_json::to_value(r).unwrap();
        assert_eq!(json, serde_json::json!("scan_indeterminate"));
    }

    #[test]
    fn rejection_reason_arms_are_distinct() {
        assert_ne!(
            RejectionReason::ScanRejected,
            RejectionReason::ScanIndeterminate
        );
    }

    // -- FailedItem --------------------------------------------------------

    #[test]
    fn failed_item_construction_and_eq() {
        let item = FailedItem {
            coords: PackageCoords {
                package: "p".into(),
                version: None,
            },
            error: PrefetchItemError::ParseError,
        };
        let clone = item.clone();
        assert_eq!(item, clone);
    }

    #[test]
    fn failed_item_serializes() {
        let item = FailedItem {
            coords: PackageCoords {
                package: "p".into(),
                version: Some("1".into()),
            },
            error: PrefetchItemError::Timeout,
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["coords"]["package"], "p");
        assert_eq!(json["error"], "timeout");
    }

    // -- PrefetchItemError — every arm -------------------------------------

    #[test]
    fn prefetch_item_error_upstream_not_found_arm() {
        let e = PrefetchItemError::UpstreamNotFound;
        assert_eq!(e, e);
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("upstream_not_found")
        );
    }

    #[test]
    fn prefetch_item_error_unauthorized_arm() {
        let e = PrefetchItemError::Unauthorized;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("unauthorized")
        );
    }

    #[test]
    fn prefetch_item_error_rate_limited_arm() {
        let e = PrefetchItemError::RateLimited;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("rate_limited")
        );
    }

    #[test]
    fn prefetch_item_error_upstream_4xx_arm() {
        let e = PrefetchItemError::Upstream4xx;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("upstream_4xx")
        );
    }

    #[test]
    fn prefetch_item_error_upstream_5xx_arm() {
        let e = PrefetchItemError::Upstream5xx;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("upstream_5xx")
        );
    }

    #[test]
    fn prefetch_item_error_network_error_arm() {
        let e = PrefetchItemError::NetworkError;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("network_error")
        );
    }

    #[test]
    fn prefetch_item_error_timeout_arm() {
        let e = PrefetchItemError::Timeout;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("timeout")
        );
    }

    #[test]
    fn prefetch_item_error_parse_error_arm() {
        let e = PrefetchItemError::ParseError;
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!("parse_error")
        );
    }

    #[test]
    fn prefetch_item_error_eight_arms_are_pairwise_distinct() {
        // Closed enum guard — flips a future variant-rename collapse
        // into a loud test failure.
        let all = [
            PrefetchItemError::UpstreamNotFound,
            PrefetchItemError::Unauthorized,
            PrefetchItemError::RateLimited,
            PrefetchItemError::Upstream4xx,
            PrefetchItemError::Upstream5xx,
            PrefetchItemError::NetworkError,
            PrefetchItemError::Timeout,
            PrefetchItemError::ParseError,
        ];
        assert_eq!(all.len(), 8);
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "arm pair ({i}, {j}) collapsed");
                }
            }
        }
    }
}
