//! The census behind "which of these entries would this registry refuse?"
//! — one question, one round trip, for the documents hort **builds**.
//!
//! ADR 0062 says hort advertises nothing it will not serve, and that
//! where hort constructs the document the non-servable entry is
//! **omitted**. Two hort-built OCI documents — the referrers index and
//! `tags/list` — name a manifest by digest, so each of them needs the
//! same verdict about a *set* of manifests before it builds its body.
//! This port is that verdict.
//!
//! # Non-deliverable, exactly
//!
//! A candidate hash is non-deliverable when its **own** catalog row
//! carries a terminal status, or when any member of its closure does.
//! `QuarantineStatus::is_terminal` is the one definition of terminal; an
//! implementation derives the set it matches against from
//! [`terminal_statuses_by_refusal_precedence`] and never spells the
//! statuses out.
//!
//! [`terminal_statuses_by_refusal_precedence`]:
//!     crate::ports::constituent_status::terminal_statuses_by_refusal_precedence
//!
//! # The closure comes from the membership projection here
//!
//! This is the deliberate counterpart to
//! [`ConstituentStatusReader`](crate::ports::constituent_status::ConstituentStatusReader),
//! which answers the same question about **one** document and resolves
//! its closure from that document's own bytes. The two differ because
//! the documents differ in what their reader already holds:
//!
//! - a manifest `GET` holds the bytes it is about to serve, so reading
//!   the closure out of them costs nothing and a projection read there
//!   would be a second source of truth bought for free;
//! - a **list** surface holds no bytes at all. The same closure would be
//!   one CAS-read tree per entry — N round trips on a document that
//!   names N manifests — and a list has no acceptable fail-closed answer
//!   when a per-entry budget blows: refusing one manifest is
//!   proportionate, refusing a whole `tags/list` is not.
//!
//! So the authority follows the document's input cost, and this port is
//! defined over hashes with the closure resolved **by the
//! implementation** rather than supplied by the caller. A caller that
//! already holds the bytes wants the other port.
//!
//! # Absence is not a verdict
//!
//! A candidate with no catalog row in `repository_id` is **not local
//! yet**, which is the ordinary state of a cold pull-through: an OCI tag
//! or a referrer descriptor can name a digest this registry has never
//! ingested, and the client's own `GET` is what pulls it through.
//! Treating absence as terminal would delete every pull-through entry
//! from both lists. A row the live read paths cannot see — soft-deleted
//! — is absent for this purpose too, the same choice
//! `ConstituentStatusReader` makes for the same reason: every live
//! `ArtifactRepository` read filters `deleted_at`, and deliverability is
//! their question.
//!
//! A **hold** is not a verdict either. `QuarantineStatus::Quarantined`
//! means "not yet", the client's own fetch answers it with the deadline,
//! and ADR 0062 decision 3 leaves the per-child model standing for
//! holds. Only a terminal status removes an entry from a list.
//!
//! # Why one call and not one per entry
//!
//! A per-entry resolution puts one round trip on every name in every
//! list a client resolves against. An implementation answers the whole
//! candidate set at once, and a SQL-speaking one must not express the
//! membership test as `= ANY($n)` over the hash array: Postgres folds a
//! bound array into constants only while it builds **custom** plans, so
//! the filter degrades to a linear scan of the array per candidate row
//! once the pooled prepared statement flips to a generic plan (measured
//! on this project's corpus at 1.7 s against 64.2 s). Unnest the array
//! and join it.

use std::collections::HashSet;

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// The `content_references.kind` values that make a target a **member of
/// the referring document's closure** — the projection's spelling of the
/// constituent set `ConstituentStatusReader`'s caller derives from bytes.
///
/// `oci_config` and `oci_layer` are a single-image manifest's config and
/// layer blobs; `oci_index_member` is an image index's child manifests.
/// Together they are what an OCI document binds, which is why the census
/// descends exactly these.
///
/// Three kinds are deliberately **not** here:
///
/// - `primary_content` — an artifact's own refcount row, targeting its
///   own hash. Descending it would make every artifact its own
///   constituent, which is not wrong so much as redundant (a candidate's
///   own status is already asked directly) and would hide a real
///   self-reference bug behind a universal one.
/// - `oci_subject` — the Referrers relation, which points from a
///   referrer manifest at the subject it describes. A referrer does not
///   *bind* its subject: an attestation over an image is a document in
///   its own right and stays deliverable when the image it talks about
///   is withdrawn. Descending it would also run the relation backwards
///   against the one surface that exists to report it.
/// - `metadata_blob` / `wheel_metadata` — not OCI tree edges at all.
pub const CLOSURE_EDGE_KINDS: [&str; 3] = ["oci_config", "oci_layer", "oci_index_member"];

/// Answers, for a repository and a set of candidate content hashes,
/// which of them a list surface must omit.
pub trait ListDeliverabilityCensus: Send + Sync {
    /// The subset of `candidates` that is **non-deliverable** inside
    /// `repository_id` — own status terminal, or a terminal status
    /// anywhere in the closure reached through
    /// [`CLOSURE_EDGE_KINDS`].
    ///
    /// Every returned hash MUST be one the caller supplied: the answer
    /// is a filter over the caller's own list, not a set the caller has
    /// to interpret. A candidate that is absent, held, released or
    /// clean is simply not in the result.
    ///
    /// An empty `candidates` slice MUST NOT reach the database.
    fn non_deliverable_in<'a>(
        &'a self,
        repository_id: Uuid,
        candidates: &'a [ContentHash],
    ) -> BoxFuture<'a, DomainResult<HashSet<ContentHash>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::entities::artifact::QuarantineStatus;
    use crate::ports::constituent_status::terminal_statuses_by_refusal_precedence;

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::constituent_status`]).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ListDeliverabilityCensus>();
    }

    /// The closure kinds are the OCI membership edges and nothing else.
    /// Pinned because adding `oci_subject` here would make an
    /// attestation disappear from the referrers index whenever the image
    /// it describes is withdrawn — the relation run backwards — and
    /// adding `primary_content` would make every artifact its own
    /// constituent.
    #[test]
    fn the_closure_kinds_are_the_membership_edges_only() {
        assert_eq!(
            CLOSURE_EDGE_KINDS,
            ["oci_config", "oci_layer", "oci_index_member"]
        );
        for excluded in [
            "primary_content",
            "oci_subject",
            "metadata_blob",
            "wheel_metadata",
        ] {
            assert!(
                !CLOSURE_EDGE_KINDS.contains(&excluded),
                "{excluded} is not a closure edge: see the constant's doc for which \
                 relation each of these is"
            );
        }
    }

    /// The census shares the terminal vocabulary with the by-the-bytes
    /// sibling rather than carrying its own. Asserted here so a future
    /// edit that gives this port its own status list fails at the one
    /// place that says the two must agree.
    #[test]
    fn the_terminal_vocabulary_is_the_shared_one() {
        let shared = terminal_statuses_by_refusal_precedence();
        for status in QuarantineStatus::ALL {
            assert_eq!(
                shared.contains(&status),
                status.is_terminal(),
                "{status} is terminal for this census iff is_terminal() holds for it"
            );
        }
    }

    /// A census that knows nothing omits nothing: the contract's
    /// degenerate answer is the empty set, never "everything".
    struct NothingWithheld;
    impl ListDeliverabilityCensus for NothingWithheld {
        fn non_deliverable_in<'a>(
            &'a self,
            _repository_id: Uuid,
            _candidates: &'a [ContentHash],
        ) -> BoxFuture<'a, DomainResult<HashSet<ContentHash>>> {
            Box::pin(async { Ok(HashSet::new()) })
        }
    }

    #[tokio::test]
    async fn an_implementation_that_knows_nothing_withholds_nothing() {
        let port: &dyn ListDeliverabilityCensus = &NothingWithheld;
        let hash: ContentHash = "a".repeat(64).parse().expect("valid sha256");
        assert!(port
            .non_deliverable_in(Uuid::new_v4(), &[hash])
            .await
            .expect("the no-op census cannot fail")
            .is_empty());
    }
}
