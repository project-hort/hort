//! Handler-specific request DTOs for the discovery + self-service prefetch
//! endpoints.
//!
//! These DTOs decode HTTP request bodies into a deserialise-only shape and
//! convert at the inbound boundary into the Deserialize-free domain
//! command types in [`hort_domain::entities::discovery`]. The architect-doc
//! anti-pattern *"Domain type deserialization in API layer"* is
//! unconditional: domain types do not decode from external input.
//!
//! Response shapes (`DiscoveryListing`, `PrefetchOutcome`) are domain
//! types with `Serialize` only; no DTO wrapper is needed for the response
//! side.

use serde::Deserialize;

use hort_domain::entities::discovery::PrefetchRequestItem;

/// JSON envelope for `POST /api/v1/repositories/{repo_key}/prefetch`.
///
/// Continue-on-error semantics: the use case partitions every input into
/// one of four buckets on [`hort_domain::entities::discovery::PrefetchOutcome`].
/// A malformed body (missing `items`, wrong types) is rejected with 400 by
/// axum's `Json` extractor before the handler runs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SelfServicePrefetchRequestDto {
    /// One entry per package the operator wants HORT to warm. An empty
    /// `items` array is valid — the handler returns a 200 with the empty
    /// envelope (no per-item ticks, no enqueue calls).
    pub items: Vec<PrefetchRequestItemDto>,
}

/// One entry in [`SelfServicePrefetchRequestDto::items`].
///
/// `version` is optional: `None` means *latest upstream-advertised*; the
/// use case resolves the latest version at enqueue time via
/// [`hort_app::ports::upstream_metadata::UpstreamMetadataPort::list_versions`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PrefetchRequestItemDto {
    /// Package name (format-native spelling).
    pub package: String,
    /// Optional pinned version. Mirrors
    /// [`hort_domain::entities::discovery::PrefetchRequestItem::version`].
    pub version: Option<String>,
}

impl From<PrefetchRequestItemDto> for PrefetchRequestItem {
    fn from(value: PrefetchRequestItemDto) -> Self {
        Self {
            package: value.package,
            version: value.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserialize-only — the architect-doc anti-pattern "Domain type
    /// deserialization in API layer" is verified at compile time on the
    /// domain side (`assert_not_impl_any!(PrefetchRequestItem:
    /// DeserializeOwned)`); these guards pin the inverse on the DTO side.
    #[test]
    fn dto_decodes_json_with_pinned_version() {
        let body = r#"{"package":"left-pad","version":"1.0.0"}"#;
        let dto: PrefetchRequestItemDto = serde_json::from_str(body).expect("decode");
        assert_eq!(dto.package, "left-pad");
        assert_eq!(dto.version, Some("1.0.0".into()));
    }

    #[test]
    fn dto_decodes_json_without_version_field() {
        // Missing `version` is `None` (= "latest upstream").
        let body = r#"{"package":"left-pad"}"#;
        let dto: PrefetchRequestItemDto = serde_json::from_str(body).expect("decode");
        assert_eq!(dto.package, "left-pad");
        assert!(dto.version.is_none());
    }

    #[test]
    fn dto_decodes_explicit_null_version() {
        let body = r#"{"package":"left-pad","version":null}"#;
        let dto: PrefetchRequestItemDto = serde_json::from_str(body).expect("decode");
        assert!(dto.version.is_none());
    }

    #[test]
    fn envelope_decodes_empty_items_array() {
        let body = r#"{"items":[]}"#;
        let dto: SelfServicePrefetchRequestDto = serde_json::from_str(body).expect("decode");
        assert!(dto.items.is_empty());
    }

    #[test]
    fn envelope_decodes_multi_item_batch() {
        let body = r#"{"items":[{"package":"a","version":"1"},{"package":"b"}]}"#;
        let dto: SelfServicePrefetchRequestDto = serde_json::from_str(body).expect("decode");
        assert_eq!(dto.items.len(), 2);
        assert_eq!(dto.items[0].package, "a");
        assert_eq!(dto.items[0].version, Some("1".into()));
        assert_eq!(dto.items[1].package, "b");
        assert!(dto.items[1].version.is_none());
    }

    #[test]
    fn envelope_rejects_missing_items_field() {
        // Malformed body — axum's Json extractor maps this to a 400 in
        // the handler test (see handlers::prefetch tests).
        let body = r#"{}"#;
        assert!(serde_json::from_str::<SelfServicePrefetchRequestDto>(body).is_err());
    }

    #[test]
    fn envelope_rejects_wrong_item_shape() {
        let body = r#"{"items":[{"name":"oops"}]}"#;
        assert!(serde_json::from_str::<SelfServicePrefetchRequestDto>(body).is_err());
    }

    #[test]
    fn from_dto_maps_package_and_version_one_to_one() {
        let dto = PrefetchRequestItemDto {
            package: "serde".into(),
            version: Some("1.0.0".into()),
        };
        let domain: PrefetchRequestItem = dto.into();
        assert_eq!(domain.package, "serde");
        assert_eq!(domain.version, Some("1.0.0".into()));
    }

    #[test]
    fn from_dto_maps_none_version() {
        let dto = PrefetchRequestItemDto {
            package: "serde".into(),
            version: None,
        };
        let domain: PrefetchRequestItem = dto.into();
        assert!(domain.version.is_none());
    }

    #[test]
    fn batch_into_domain_vec_via_iter_map_collect() {
        // The shape the prefetch handler invokes at the inbound boundary.
        let dto = SelfServicePrefetchRequestDto {
            items: vec![
                PrefetchRequestItemDto {
                    package: "a".into(),
                    version: Some("1".into()),
                },
                PrefetchRequestItemDto {
                    package: "b".into(),
                    version: None,
                },
            ],
        };
        let domain: Vec<PrefetchRequestItem> = dto.items.into_iter().map(Into::into).collect();
        assert_eq!(domain.len(), 2);
        assert_eq!(domain[0].package, "a");
        assert_eq!(domain[0].version, Some("1".into()));
        assert_eq!(domain[1].package, "b");
        assert!(domain[1].version.is_none());
    }
}
