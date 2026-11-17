//! `RepositoryInventoryReader` port — what each repository's **live
//! catalog** holds: rows, distinct contents, and the weight of those
//! contents.
//!
//! A retention concept without a before/after measurement is not
//! verifiable, and nothing in the product answered "how many artifacts
//! and how many bytes does this repository hold?" — the first real
//! inventory had to be taken by hand with read-only SQL against a
//! production database. This port is the read behind the answer.
//!
//! # Three numbers, and the third one is the one that can be misread
//!
//! [`RepositoryInventory`] carries
//! [`artifact_count`](RepositoryInventory::artifact_count),
//! [`distinct_content_count`](RepositoryInventory::distinct_content_count)
//! and
//! [`live_primary_content_bytes`](RepositoryInventory::live_primary_content_bytes).
//! The first two names are the ones the held-set overview already put on
//! the wire for the same two quantities
//! ([`HeldCandidateBucket`](super::held_set_reader::HeldCandidateBucket));
//! a second vocabulary for one pair of numbers is a defect in its own
//! right, so they are reused verbatim.
//!
//! The third is **not** a repository's storage share, and its name is
//! the first line of defence against being read as one:
//!
//! - **Non-additive across repositories.** One CAS entry can carry
//!   artifact rows in several repositories (ADR 0054), so each
//!   repository's distinct-content sum counts that same physical blob.
//!   Adding the figures up double-counts it, and there is no unique
//!   per-repository physical ownership to report instead.
//! - **Not disk usage.** It omits CAS-resident metadata and every other
//!   content-reference target kind — it sums only the primary content of
//!   the artifact rows themselves, which is what *primary* says.
//! - **Not reclaimable space.** A soft-deleted row is excluded from
//!   these counts while its bytes stay resident until refcount-gated GC,
//!   and what a disposal would actually free depends on every surviving
//!   claim — the question the retention preview and purge GC model.
//!
//! So the honest reading of the third number is a **catalog weight**:
//! how much the served catalog of this repository weighs, counting each
//! distinct content once. Someone wrote that distinction down before
//! this port existed —
//! [`RepositoryRepository::get_storage_usage`](super::repository_repository::RepositoryRepository::get_storage_usage)
//! sums `size_bytes` over live **rows** and says in its own comment that
//! the result "was never the figure that answers 'how much disk does the
//! repository hold'". That warning is settled truth and is taken here;
//! its value and its name are not, because summing over rows
//! double-counts a blob two artifacts in one repository share.
//!
//! # Distinctness is on the hash, never on the size
//!
//! The byte figure is the sum over **distinct contents**, which means
//! grouping by `checksum_sha256` and taking one `size_bytes` per group.
//! A `SUM(DISTINCT size_bytes)` would be a different and wrong
//! computation: two different contents can have exactly equal sizes, and
//! deduplicating the *number* would drop one of them. An implementation
//! must make the distinctness a property of the hash.
//!
//! # This is a catalog readout, not the held slice
//!
//! Deliberately **not** a widening of
//! [`HeldSetReader`](super::held_set_reader::HeldSetReader): that port's
//! name, query and `HeldCandidateBucket` are about the
//! held-pending-signature population, and this is a different question
//! over a different population — every live row, no policy resolution,
//! no quarantine predicate. One port answering both would mean the first
//! change that wanted one silently got the other. The two field names
//! and the "rows are not bytes" reasoning are shared; the port is not.
//!
//! # Domain DTO discipline
//!
//! [`RepositoryInventory`] derives no `Serialize` / `Deserialize`. The
//! HTTP DTO lives in the inbound-HTTP crate; mirrors
//! [`HeldCandidateBucket`](super::held_set_reader::HeldCandidateBucket).

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// What one repository's live catalog holds.
///
/// Every field is scoped to **live** rows — `deleted_at IS NULL`
/// (ADR 0030). A repository that holds nothing is reported with zeros
/// rather than omitted, because a readout whose purpose is a
/// before/after comparison has to be able to say "this repository is now
/// empty"; an absent row cannot be told apart from a repository the
/// readout did not know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryInventory {
    pub repository_id: Uuid,
    /// Resolved by the adapter's join — a pass-through string the HTTP
    /// DTO renders for the operator.
    pub repository_key: String,
    /// Live `artifacts` rows in this repository.
    pub artifact_count: u64,
    /// Distinct `checksum_sha256` values across those rows. Never
    /// greater than [`RepositoryInventory::artifact_count`]: CAS shares
    /// content across artifacts, so two rows can name one content.
    pub distinct_content_count: u64,
    /// `size_bytes` summed over **distinct contents** — each content
    /// counted once however many rows name it.
    ///
    /// **Non-additive across repositories, not disk usage, and not
    /// reclaimable space.** See this module's docs for all three; the
    /// name carries the first part on its own, and every surface that
    /// renders this number repeats the rest.
    pub live_primary_content_bytes: u64,
}

/// Outbound port: the per-repository live-catalog readout.
pub trait RepositoryInventoryReader: Send + Sync {
    /// Every repository's three numbers, in **one** set-based aggregate.
    ///
    /// One query rather than a per-repository loop: the question is
    /// global, and N round-trips would answer it N instants apart. If a
    /// bound ever turns out to be needed, the thing to page is the
    /// **repository keys** before their artifacts are aggregated —
    /// paginating an already-global aggregate does not bound the work it
    /// did.
    fn inventory(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryInventory>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion — the port is held as
    /// `Arc<dyn RepositoryInventoryReader>` by the use case.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RepositoryInventoryReader>();
    }

    /// The row is a plain value: comparable, clonable, and carrying no
    /// serialization of its own (ADR 0008 — the wire shape lives in the
    /// inbound-HTTP crate).
    #[test]
    fn inventory_row_is_a_comparable_value() {
        let row = RepositoryInventory {
            repository_id: Uuid::nil(),
            repository_key: "oci-main".into(),
            artifact_count: 3_647,
            distinct_content_count: 3_608,
            live_primary_content_bytes: 142_000,
        };
        assert_eq!(row.clone(), row);
        assert!(
            row.distinct_content_count <= row.artifact_count,
            "distinct contents can never exceed the rows that name them"
        );
    }
}
