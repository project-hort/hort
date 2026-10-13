//! The catalog read behind "is every artifact in this document's closure
//! still deliverable?" — one call, one answer, and the terminal-status
//! vocabulary it asks about derived rather than re-typed.
//!
//! An OCI manifest names other content (a config blob, layer blobs,
//! child manifests). ADR 0062 makes the manifest undeliverable while any
//! of that content carries a **terminal** status, so the read path has to
//! turn a set of content hashes into "the strongest terminal verdict
//! among them, if any". This port is that turn.
//!
//! # What the caller supplies, and what it must not
//!
//! The caller supplies the **closure**: every content hash the document
//! binds, derived from the document's own bytes. It does not supply
//! artifact ids, and this port does not resolve the closure for it.
//! ADR 0039 settles why — `content_references` edges *nominate*, the
//! bytes decide, and the edge projection is repairable rather than
//! guaranteed — so an implementation that answered from the edge table
//! instead of from the hashes it was handed would be answering a
//! different question.
//!
//! # Why one call and not one per constituent
//!
//! This runs on the registry's hottest read. A per-constituent lookup
//! puts one round trip on every layer of every manifest pull; an
//! implementation therefore answers the whole set at once. A
//! SQL-speaking implementation additionally must not express the
//! membership test as `= ANY($n)` over the hash array: Postgres folds a
//! bound array into constants only while it builds **custom** plans, so
//! the filter degrades to a linear scan of the array per candidate row
//! once the pooled prepared statement flips to a generic plan (measured
//! on this project's corpus at 1.7 s against 64.2 s). Unnest the array
//! and join it.
//!
//! # Absence is not a hold
//!
//! A hash with no catalog row in `repository_id` is **not** a terminal
//! constituent and must not be reported as one. That is the ordinary
//! state of a cold pull-through manifest — the references are registered
//! by digest with no existence check, and the client's own blob GET is
//! what pulls them through — so folding absence into the terminal arm
//! would refuse every pull-through manifest whose blobs have not arrived
//! yet. Only a **present** row in a terminal state changes the answer.
//!
//! A row the live read paths cannot see is absent for this purpose too:
//! `ArtifactRepository`'s lookups filter `deleted_at IS NULL`, and
//! deliverability is precisely the question those lookups answer, so a
//! soft-deleted row must not hold a manifest back. (This is the opposite
//! choice from [`crate::ports::event_repository_resolver`], for the
//! opposite reason: that port resolves *identity*, where a retired row
//! still has to answer.)

use uuid::Uuid;

use crate::entities::artifact::QuarantineStatus;
use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// The constituent a refusal names: which content, and the terminal
/// state it carries.
///
/// Deliberately not an [`crate::entities::artifact::Artifact`]. The
/// question is a class, the answer is a class, and handing back a row
/// would invite a caller to make a second decision out of fields this
/// read never promised to populate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalConstituent {
    /// The constituent's own CAS hash — the digest the refusal reports
    /// and the server-side log line names.
    pub content_hash: ContentHash,
    /// Its status. [`QuarantineStatus::is_terminal`] holds for it, which
    /// an implementation guarantees by construction: the set it matches
    /// against comes from [`terminal_statuses_by_refusal_precedence`].
    pub status: QuarantineStatus,
}

/// Reads the terminal state of a document's constituents from the
/// artifact catalog.
pub trait ConstituentStatusReader: Send + Sync {
    /// The strongest terminal constituent among `constituents` inside
    /// `repository_id`, or [`None`] when every one of them is either
    /// absent or non-terminal.
    ///
    /// "Strongest" is [`terminal_statuses_by_refusal_precedence`]'s
    /// order. The answer MUST be deterministic for a given input:
    /// `HEAD` and `GET` resolve the same closure and must name the same
    /// constituent, so ties inside one status class are broken by the
    /// caller's own ordering of `constituents` (closure order — config
    /// before layers, a parent before its children).
    ///
    /// An empty `constituents` slice MUST NOT reach the database.
    fn strongest_terminal_constituent<'a>(
        &'a self,
        repository_id: Uuid,
        constituents: &'a [ContentHash],
    ) -> BoxFuture<'a, DomainResult<Option<TerminalConstituent>>>;
}

/// The terminal statuses, strongest first — the set an implementation
/// matches rows against, and the order it ranks them in.
///
/// Derived from [`QuarantineStatus::ALL`] through
/// [`QuarantineStatus::is_terminal`], so it cannot name a status the
/// predicate does not call terminal and cannot miss one it does. A
/// persisted query binds this; it must never spell the statuses out,
/// because a spelled-out list is a second definition of the predicate
/// that a sixth variant leaves narrower with nothing failing.
#[must_use]
pub fn terminal_statuses_by_refusal_precedence() -> Vec<QuarantineStatus> {
    let mut statuses: Vec<QuarantineStatus> = QuarantineStatus::ALL
        .into_iter()
        .filter(|status| status.is_terminal())
        .collect();
    statuses.sort_by_key(|status| refusal_precedence(*status));
    statuses
}

/// Which terminal verdict a refusal reports when a closure carries more
/// than one.
///
/// [`QuarantineStatus::Rejected`] outranks
/// [`QuarantineStatus::ScanIndeterminate`] because it is the stronger
/// statement about the content — a verdict was rendered against these
/// bytes, rather than no verdict being reachable — and because it is the
/// one that carries a diagnosis: a rejection has an axis to report,
/// while an indeterminate scan has nothing to say beyond "fail-closed".
/// Reporting the richer answer when both are present costs the client
/// nothing; both are "never".
///
/// Exhaustive with no wildcard arm, so a sixth variant is a compile
/// error here rather than a silent rank it shares with a non-terminal
/// state.
fn refusal_precedence(status: QuarantineStatus) -> u8 {
    match status {
        QuarantineStatus::Rejected => 0,
        QuarantineStatus::ScanIndeterminate => 1,
        // Not terminal, so never in the derived set. Ranked last rather
        // than `unreachable!`: this is a sort key, and a panic in one
        // would be a worse answer than an order nobody reads.
        QuarantineStatus::None | QuarantineStatus::Quarantined | QuarantineStatus::Released => {
            u8::MAX
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::event_repository_resolver`]).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ConstituentStatusReader>();
    }

    /// The derived set is exactly what the predicate calls terminal —
    /// asserted against the predicate over the **whole** vocabulary, not
    /// against a hand-written expectation, so the test cannot drift the
    /// same way a spelled-out SQL list would.
    #[test]
    fn the_terminal_set_is_exactly_what_the_predicate_calls_terminal() {
        let derived = terminal_statuses_by_refusal_precedence();
        for status in QuarantineStatus::ALL {
            assert_eq!(
                derived.contains(&status),
                status.is_terminal(),
                "{status} is in the derived set iff is_terminal() holds for it"
            );
        }
        assert_eq!(
            derived.len(),
            QuarantineStatus::ALL
                .into_iter()
                .filter(|s| s.is_terminal())
                .count(),
            "the derived set carries no duplicates"
        );
    }

    /// The order is the refusal precedence, and it is pinned because the
    /// answer a client gets when a closure carries both depends on it.
    #[test]
    fn rejected_outranks_scan_indeterminate() {
        assert_eq!(
            terminal_statuses_by_refusal_precedence(),
            vec![
                QuarantineStatus::Rejected,
                QuarantineStatus::ScanIndeterminate
            ],
        );
    }

    /// A no-op implementation proves the trait can be `dyn`-cast and
    /// documents the contract: an implementation that knows nothing
    /// answers [`None`] — "nothing terminal here" — rather than
    /// inventing a hold.
    struct NothingTerminal;
    impl ConstituentStatusReader for NothingTerminal {
        fn strongest_terminal_constituent<'a>(
            &'a self,
            _repository_id: Uuid,
            _constituents: &'a [ContentHash],
        ) -> BoxFuture<'a, DomainResult<Option<TerminalConstituent>>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[tokio::test]
    async fn an_implementation_that_knows_nothing_reports_no_terminal_constituent() {
        let port: &dyn ConstituentStatusReader = &NothingTerminal;
        let hash: ContentHash = "a".repeat(64).parse().expect("valid sha256");
        assert_eq!(
            port.strongest_terminal_constituent(Uuid::new_v4(), &[hash])
                .await
                .expect("the no-op reader cannot fail"),
            None
        );
    }
}
