use std::fmt;
use std::str::FromStr;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::entities::repository::RepositoryFormat;
use crate::error::DomainError;

pub mod checksum;
pub mod finding;
pub mod idempotency_key;
pub mod sbom;

pub use checksum::{HashAlgorithm, UpstreamPublishedChecksum};
pub use finding::{
    highest_severity, is_informational_class, severity_label, severity_summary_from_findings,
    Finding,
};
pub use idempotency_key::IdempotencyKey;
pub use sbom::{Ecosystem, PayloadAccess, Sbom, SbomComponent};

// ---------------------------------------------------------------------------
// PageRequest
// ---------------------------------------------------------------------------

const DEFAULT_LIMIT: u64 = 20;
const MAX_LIMIT: u64 = 1000;

/// A request for a page of results.
///
/// `limit` is silently capped to [`MAX_LIMIT`] (1 000) to prevent unbounded
/// queries. Use [`Default`] for sensible defaults (offset 0, limit 20).
#[derive(Debug, Clone, PartialEq)]
pub struct PageRequest {
    pub offset: u64,
    pub limit: u64,
}

impl PageRequest {
    /// Create a new page request, capping `limit` to [`MAX_LIMIT`].
    pub fn new(offset: u64, limit: u64) -> Self {
        Self {
            offset,
            limit: limit.min(MAX_LIMIT),
        }
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Page<T>
// ---------------------------------------------------------------------------

/// A page of results with the total count across all pages.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
}

impl<T> Page<T> {
    /// An empty page with zero total.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
        }
    }

    /// Returns `true` when the page contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ---------------------------------------------------------------------------
// LimitedList<T>
// ---------------------------------------------------------------------------

/// Maximum number of items returned from a hard-capped repository query —
/// the absolute upper bound applied by the application / adapter layer
/// when iterating a paginated read or executing a `LIMIT`-bound query.
///
/// Defence-in-depth ceiling
/// to keep `fetch_all` queries from materialising arbitrary numbers of
/// rows when an attacker can grow the underlying table via repeated
/// pull-through ingest. Set to 10 000: large enough to cover legitimate
/// per-package version sprawl on real-world public registries (the
/// largest cargo crates and PyPI packages publish a few thousand versions
/// in their lifetime; 10× headroom), small enough that loading the row
/// set into memory is bounded by a few MiB.
pub const LIMIT_LIST_MAX_ITEMS: u64 = 10_000;

/// A list of results carrying a hard upper bound and a truncation flag.
///
/// Used by repository queries that have no client-driven pagination —
/// operator-triggered sweeps and read-path queries whose protocol-level
/// response shape is a single document (PyPI simple-index, npm
/// packument). The truncation flag lets the caller surface a clear
/// "results truncated" signal:
///
/// - HTTP handlers emit a `Warning: 299 - "results truncated at N items"`
///   header (RFC 9111 §5.5) so SIEM / observability tooling can tell.
/// - Background sweeps log a `tracing::warn!` so operators see the
///   defence-in-depth bound firing — it's the rare-but-actionable kind.
///
/// **Invariant.** When `truncated == true`, `items.len() == cap` where
/// `cap` is the producer's truncation cap (typically
/// [`LIMIT_LIST_MAX_ITEMS`]). When `truncated == false`, `items.len()`
/// can be anything ≤ cap; the producer fetched everything available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitedList<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

impl<T> LimitedList<T> {
    /// An empty, non-truncated list — the natural zero value.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            truncated: false,
        }
    }

    /// Construct from an over-fetched result set. `items` is expected to
    /// be up to `cap + 1` long; if it exceeds `cap`, truncates to `cap`
    /// items and flips `truncated = true`. This is the single source of
    /// truth for the saturation-from-over-fetch rule used by the
    /// Postgres adapter (`LIMIT cap + 1`, then funnel through here).
    pub fn from_overfetch(mut items: Vec<T>, cap: usize) -> Self {
        if items.len() > cap {
            items.truncate(cap);
            Self {
                items,
                truncated: true,
            }
        } else {
            Self {
                items,
                truncated: false,
            }
        }
    }

    /// Returns `true` when the list contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of items in the list.
    pub fn len(&self) -> usize {
        self.items.len()
    }
}

// ---------------------------------------------------------------------------
// StringPage<T>
// ---------------------------------------------------------------------------

/// A cursor-paginated page of results — no total count.
///
/// Use case layer wrapper around byte-stable paginated enumerations:
/// OCI tags list, OCI `_catalog`, future cursor APIs. Callers cannot
/// compute total-count cheaply for these queries (a DISTINCT scan or
/// a cross-repo COUNT), so the envelope omits `total` and instead
/// exposes a `saturated` flag derived by over-fetching one extra row
/// under the hood.
///
/// **Saturation contract.** The use case requests `limit + 1` rows
/// from the underlying port. If the port returns more than `limit`,
/// the use case truncates to `limit` items and sets `saturated =
/// true`, signalling the caller that a next page exists. This avoids
/// a separate COUNT query and keeps the cursor walk O(limit) per page.
///
/// **Cursor semantics.** The caller supplies a string `after` cursor
/// (typically the last item's stable key — tag name, manifest name).
/// The port filters to keys strictly greater than `after` under byte
/// ordering (Postgres `COLLATE "C"`); `None` means "from the start".
/// Paginated enumerations MUST use byte ordering, not locale-aware
/// collation — the cursor walk's correctness depends on `COLLATE "C"`
/// matching the client-side sort.
///
/// Does not derive `Serialize` because `T` may be a domain entity
/// whose wire shape is handler-specific (OCI tags emit
/// `{"name":..., "tags":[...]}`, not a generic `StringPage`).
/// Handlers project into their format's response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPage<T> {
    pub items: Vec<T>,
    pub saturated: bool,
}

impl<T> StringPage<T> {
    /// An empty, non-saturated page — the terminal state of a cursor
    /// walk.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            saturated: false,
        }
    }

    /// Derive a `StringPage` from an over-fetched result set. `items`
    /// is expected to be up to `limit + 1` long; if it exceeds
    /// `limit`, truncates to `limit` and flips `saturated = true`.
    /// This is the single source of truth for the
    /// saturation-from-over-fetch rule; use-case layer callers should
    /// always funnel through it.
    pub fn from_overfetch(mut items: Vec<T>, limit: usize) -> Self {
        if items.len() > limit {
            items.truncate(limit);
            Self {
                items,
                saturated: true,
            }
        } else {
            Self {
                items,
                saturated: false,
            }
        }
    }

    /// Returns `true` when the page contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ArtifactCoords
// ---------------------------------------------------------------------------

/// Parsed artifact coordinates — format-agnostic identity.
///
/// `path` is the logical path within the repository (e.g.,
/// `requests/2.31.0/requests-2.31.0.tar.gz` for PyPI). Used for duplicate
/// detection and index generation — NOT as a storage key.
///
/// `name` should be the **normalized** form (e.g., `my-package` not
/// `My_Package`). Normalization happens at ingest time via
/// `FormatHandler::normalize_name()`.
///
/// `name_as_published` is the **exact** name the client supplied, before
/// any normalisation. It is the drift-resilience safety net: if a
/// `FormatHandler::normalize_name` implementation ever changes output for
/// the same input — deliberately, by "bug fix", or via a plugin hot-swap —
/// artifacts ingested under the old algorithm remain reachable via
/// `ArtifactRepository::find_by_name_as_published`.
///
/// `metadata` is the **opaque output of
/// [`FormatHandler::parse_download_path`](crate::ports::format_handler::FormatHandler::parse_download_path)**
/// — per-request coordinate-derived attributes only. It is *not* the
/// upload-payload metadata captured at ingest; that flows through
/// `IngestRequest.payload_metadata` and lands in
/// [`ArtifactMetadata`](crate::entities::artifact::ArtifactMetadata) via
/// the lifecycle port. The two concepts collide by name only; they have
/// different lifetimes and different persistence paths. See
/// `docs/architecture/explanation/domain-model.md` §Value types.
///
/// Does not derive `Eq` because `serde_json::Value` only implements `PartialEq`.
///
/// Derives `Serialize` + `Deserialize` because domain events carry `coords`
/// in their payloads — in particular `ArtifactGroupInitiated`.
/// The serde shape is the plain struct — each field serialises by its
/// own impl (`RepositoryFormat` gets its own serde derives; `serde_json::Value`
/// is self-describing). The canonicalisation rule used at the group-keyspace
/// adapter boundary (`coords_to_canonical_json` in the Postgres adapter) is
/// orthogonal — it zeroes per-file fields for identity purposes and is not
/// what goes on the wire inside events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactCoords {
    pub name: String,
    pub name_as_published: String,
    pub version: Option<String>,
    pub path: String,
    pub format: RepositoryFormat,
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// ByteRange
// ---------------------------------------------------------------------------

/// A client-requested byte range against a single CAS object, in its
/// declarative form per RFC 7233 §2. Resolution to absolute byte
/// offsets — including suffix clamping when the requested suffix
/// exceeds the object's size — is the storage adapter's
/// responsibility; the domain models the request shape only.
///
/// **Pre-conditions enforced by the HTTP layer.** The trait
/// [`StoragePort::get_range`](crate::ports::storage::StoragePort::get_range)
/// trusts that the caller has already validated bounds against the
/// object's size and rejected unsatisfiable variants with `416 Range
/// Not Satisfiable` per RFC 7233 §4.4. Specifically:
///
/// - `Inclusive { start, end }` — caller has verified `start <= end`
///   and `end < size`. (An `end >= size` request is RFC-clamped at the
///   HTTP layer before constructing the variant.)
/// - `From { start }` — caller has verified `start < size`. A request
///   with `start >= size` is RFC-unsatisfiable and never reaches the
///   adapter.
/// - `Suffix { last }` — `last == 0` is RFC-unsatisfiable and never
///   reaches the adapter. `last > size` is RFC-clamped at the
///   adapter ("If the selected representation is shorter than the
///   specified suffix-length, the entire representation is used"
///   — RFC 7233 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteRange {
    /// `Range: bytes=N-M` — both bounds inclusive.
    Inclusive { start: u64, end: u64 },
    /// `Range: bytes=N-` — from `N` to the end of the representation.
    From { start: u64 },
    /// `Range: bytes=-N` — last `N` bytes (suffix).
    Suffix { last: u64 },
}

// ---------------------------------------------------------------------------
// ContentHash
// ---------------------------------------------------------------------------

/// A validated SHA-256 content hash (exactly 64 lowercase hex characters).
///
/// The only way to construct a `ContentHash` is through [`FromStr`], which
/// rejects any input that is not a valid lowercase hex-encoded SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    /// Returns `true` if `s` is exactly 64 lowercase hex characters.
    fn is_valid_sha256_hex(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }
}

impl FromStr for ContentHash {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Self::is_valid_sha256_hex(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(DomainError::Validation(format!(
                "invalid SHA-256 hash: expected 64 lowercase hex characters, got {len} characters",
                len = s.len()
            )))
        }
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ContentHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- StringPage ---------------------------------------------------------

    #[test]
    fn string_page_empty_has_no_items_and_not_saturated() {
        let p: StringPage<String> = StringPage::empty();
        assert!(p.items.is_empty());
        assert!(!p.saturated);
        assert!(p.is_empty());
    }

    #[test]
    fn string_page_from_overfetch_non_saturated_when_under_limit() {
        let p: StringPage<&str> = StringPage::from_overfetch(vec!["a", "b"], 5);
        assert_eq!(p.items, vec!["a", "b"]);
        assert!(!p.saturated);
    }

    #[test]
    fn string_page_from_overfetch_non_saturated_when_exact_limit() {
        // Exactly `limit` items means the caller fetched fewer than
        // `limit + 1` — no extra row, so not saturated. This is the
        // load-bearing boundary: if the truncate-and-flip logic fires
        // when count == limit, the cursor walk emits a phantom final
        // page every time.
        let p: StringPage<&str> = StringPage::from_overfetch(vec!["a", "b", "c"], 3);
        assert_eq!(p.items.len(), 3);
        assert!(!p.saturated);
    }

    #[test]
    fn string_page_from_overfetch_saturated_when_over_limit() {
        // `limit + 1` items → truncate to `limit` and flip saturated.
        let p: StringPage<&str> = StringPage::from_overfetch(vec!["a", "b", "c", "d"], 3);
        assert_eq!(p.items, vec!["a", "b", "c"]);
        assert!(p.saturated);
    }

    #[test]
    fn string_page_from_overfetch_saturated_when_way_over_limit() {
        // Defence in depth: if an adapter overshoots `limit + 1`
        // (returning all rows, say), we still truncate to exactly
        // `limit`. Never surface more than the caller asked for.
        let p: StringPage<&str> = StringPage::from_overfetch(vec!["a", "b", "c", "d", "e"], 2);
        assert_eq!(p.items, vec!["a", "b"]);
        assert!(p.saturated);
    }

    #[test]
    fn string_page_from_overfetch_zero_limit_is_empty_and_saturated_iff_input_nonempty() {
        // Edge: `limit = 0`. Items with any content must truncate to
        // empty AND flip saturated (a non-empty source with zero
        // admitted is still "there's more"). Empty source stays empty
        // and non-saturated — terminal state of a cursor walk.
        let p: StringPage<&str> = StringPage::from_overfetch(vec!["a"], 0);
        assert!(p.items.is_empty());
        assert!(p.saturated);

        let empty: StringPage<&str> = StringPage::from_overfetch(vec![], 0);
        assert!(empty.items.is_empty());
        assert!(!empty.saturated);
    }

    // -- LimitedList<T> ------------------------------------------------------

    #[test]
    fn limited_list_empty_has_no_items_and_not_truncated() {
        let l: LimitedList<String> = LimitedList::empty();
        assert!(l.items.is_empty());
        assert!(!l.truncated);
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn limited_list_from_overfetch_under_cap_is_not_truncated() {
        let l: LimitedList<&str> = LimitedList::from_overfetch(vec!["a", "b"], 5);
        assert_eq!(l.items, vec!["a", "b"]);
        assert!(!l.truncated);
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn limited_list_from_overfetch_exact_cap_is_not_truncated() {
        // Boundary: exactly `cap` items means no over-fetch happened.
        // Mirrors `StringPage::from_overfetch` boundary semantics.
        let l: LimitedList<&str> = LimitedList::from_overfetch(vec!["a", "b", "c"], 3);
        assert_eq!(l.items.len(), 3);
        assert!(!l.truncated);
    }

    #[test]
    fn limited_list_from_overfetch_over_cap_truncates_and_flips_flag() {
        let l: LimitedList<&str> = LimitedList::from_overfetch(vec!["a", "b", "c", "d"], 3);
        assert_eq!(l.items, vec!["a", "b", "c"]);
        assert!(l.truncated);
    }

    #[test]
    fn limited_list_from_overfetch_way_over_cap_truncates_to_cap() {
        // Defence in depth: if the producer overshoots `cap + 1`, still
        // truncate to exactly `cap`. Never surface more than the cap.
        let l: LimitedList<u32> = LimitedList::from_overfetch(vec![1, 2, 3, 4, 5], 2);
        assert_eq!(l.items, vec![1, 2]);
        assert!(l.truncated);
    }

    #[test]
    fn limit_list_max_items_constant_is_ten_thousand() {
        assert_eq!(LIMIT_LIST_MAX_ITEMS, 10_000);
    }

    // -- PageRequest --------------------------------------------------------

    #[test]
    fn page_request_default() {
        let pr = PageRequest::default();
        assert_eq!(pr.offset, 0);
        assert_eq!(pr.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn page_request_new_caps_limit() {
        let pr = PageRequest::new(10, 5000);
        assert_eq!(pr.offset, 10);
        assert_eq!(pr.limit, MAX_LIMIT);
    }

    #[test]
    fn page_request_new_preserves_limit_under_max() {
        let pr = PageRequest::new(0, 50);
        assert_eq!(pr.limit, 50);
    }

    #[test]
    fn page_request_new_limit_at_max() {
        let pr = PageRequest::new(0, MAX_LIMIT);
        assert_eq!(pr.limit, MAX_LIMIT);
    }

    // -- Page<T> ------------------------------------------------------------

    #[test]
    fn page_empty() {
        let page: Page<String> = Page::empty();
        assert!(page.items.is_empty());
        assert_eq!(page.total, 0);
    }

    #[test]
    fn page_is_empty_true() {
        let page: Page<u32> = Page {
            items: vec![],
            total: 0,
        };
        assert!(page.is_empty());
    }

    #[test]
    fn page_is_empty_false() {
        let page = Page {
            items: vec![1, 2, 3],
            total: 3,
        };
        assert!(!page.is_empty());
    }

    #[test]
    fn page_clone() {
        let page = Page {
            items: vec!["a".to_string()],
            total: 1,
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // -- ContentHash --------------------------------------------------------

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn content_hash_valid() {
        let hash: ContentHash = VALID_HASH.parse().unwrap();
        assert_eq!(hash.to_string(), VALID_HASH);
    }

    #[test]
    fn content_hash_as_ref() {
        let hash: ContentHash = VALID_HASH.parse().unwrap();
        assert_eq!(hash.as_ref(), VALID_HASH);
    }

    #[test]
    fn content_hash_display_roundtrips() {
        let hash: ContentHash = VALID_HASH.parse().unwrap();
        let reparsed: ContentHash = hash.to_string().parse().unwrap();
        assert_eq!(hash, reparsed);
    }

    #[test]
    fn content_hash_rejects_uppercase() {
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let result: Result<ContentHash, _> = upper.parse();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_rejects_too_short() {
        let short = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
        assert_eq!(short.len(), 63);
        let result: Result<ContentHash, _> = short.parse();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_rejects_too_long() {
        let long = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550";
        assert_eq!(long.len(), 65);
        let result: Result<ContentHash, _> = long.parse();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_rejects_non_hex() {
        let bad = "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result: Result<ContentHash, _> = bad.parse();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_rejects_empty() {
        let result: Result<ContentHash, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_eq_and_hash() {
        use std::collections::HashSet;
        let h1: ContentHash = VALID_HASH.parse().unwrap();
        let h2: ContentHash = VALID_HASH.parse().unwrap();
        assert_eq!(h1, h2);

        let mut set = HashSet::new();
        set.insert(h1);
        assert!(set.contains(&h2));
    }

    #[test]
    fn content_hash_error_message_includes_length() {
        let result: Result<ContentHash, _> = "abc".parse();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("3 characters"));
    }

    #[test]
    fn content_hash_serialize_json() {
        let hash: ContentHash = VALID_HASH.parse().unwrap();
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{VALID_HASH}\""));
    }

    #[test]
    fn content_hash_deserialize_json() {
        let json = format!("\"{VALID_HASH}\"");
        let hash: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash.as_ref(), VALID_HASH);
    }

    #[test]
    fn content_hash_deserialize_invalid_json() {
        let json = "\"not-a-hash\"";
        let result: Result<ContentHash, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -- ByteRange (Range request shape) ------------------------------------

    #[test]
    fn byte_range_inclusive_constructor_round_trips() {
        let r = ByteRange::Inclusive { start: 0, end: 99 };
        match r {
            ByteRange::Inclusive { start, end } => {
                assert_eq!(start, 0);
                assert_eq!(end, 99);
            }
            _ => panic!("expected Inclusive variant"),
        }
    }

    #[test]
    fn byte_range_from_constructor_round_trips() {
        let r = ByteRange::From { start: 1024 };
        match r {
            ByteRange::From { start } => assert_eq!(start, 1024),
            _ => panic!("expected From variant"),
        }
    }

    #[test]
    fn byte_range_suffix_constructor_round_trips() {
        let r = ByteRange::Suffix { last: 500 };
        match r {
            ByteRange::Suffix { last } => assert_eq!(last, 500),
            _ => panic!("expected Suffix variant"),
        }
    }

    #[test]
    fn byte_range_clone_eq_debug_derive_cleanly() {
        let r = ByteRange::Inclusive { start: 10, end: 20 };
        let cloned = r.clone();
        assert_eq!(r, cloned);
        // Debug must format without panicking.
        let _ = format!("{r:?}");
    }

    #[test]
    fn byte_range_distinct_variants_are_not_equal() {
        // Distinct variants compare unequal even when carrying the
        // same numeric value — guards against accidental discriminant
        // collapse if the enum is ever flattened.
        assert_ne!(
            ByteRange::From { start: 100 },
            ByteRange::Suffix { last: 100 }
        );
        assert_ne!(
            ByteRange::Inclusive { start: 0, end: 99 },
            ByteRange::From { start: 0 },
        );
    }

    // -- ArtifactCoords (event payload serde) --------------------------------

    /// `ArtifactCoords` must round-trip through serde_json so that the
    /// `ArtifactGroupInitiated` event payload (which embeds the full
    /// coords struct) serialises and deserialises
    /// losslessly. All six fields are exercised with realistic values —
    /// the `name` / `name_as_published` split, a populated `Some(version)`,
    /// a path, a concrete `RepositoryFormat::Other` variant (which has
    /// its own serde derives — round-tripping the whole `ArtifactCoords`
    /// also proves that), and a non-trivial `metadata` object.
    #[test]
    fn artifact_coords_serde_round_trip_fully_populated() {
        let coords = ArtifactCoords {
            name: "my-pkg".into(),
            name_as_published: "My_Pkg".into(),
            version: Some("1.2.3".into()),
            path: "my-pkg/1.2.3/My_Pkg-1.2.3.tar.gz".into(),
            format: RepositoryFormat::Other("flatpak".into()),
            metadata: serde_json::json!({
                "requires_python": ">=3.8",
                "nested": {"k": ["v1", "v2"]},
            }),
        };
        let value = serde_json::to_value(&coords).unwrap();
        let back: ArtifactCoords = serde_json::from_value(value).unwrap();
        assert_eq!(back, coords);
    }
}
