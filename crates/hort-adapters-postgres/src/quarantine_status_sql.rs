//! The stored vocabulary of `artifacts.quarantine_status` — its encoder
//! and its decoder, as one inverse pair, in one file.
//!
//! ## Why the pair lives together
//!
//! `quarantine_status` is the security-load-bearing column: every
//! serving decision in the system is a function of what a read of it
//! decides. The column's **stored** vocabulary and
//! [`QuarantineStatus`]'s **display** vocabulary are not the same set,
//! and that divergence is the whole reason this module exists:
//!
//! | domain variant | stored |
//! |---|---|
//! | [`QuarantineStatus::None`] | SQL `NULL` |
//! | [`QuarantineStatus::Quarantined`] | `'quarantined'` |
//! | [`QuarantineStatus::Released`] | `'released'` |
//! | [`QuarantineStatus::Rejected`] | `'rejected'` |
//! | [`QuarantineStatus::ScanIndeterminate`] | `'scan_indeterminate'` |
//!
//! `QuarantineStatus::None` renders as `"none"` through [`Display`] and
//! parses back from `"none"` through [`FromStr`] — but `'none'` is not,
//! and never was, a value the column's CHECK constraint accepts. The
//! stored spelling of "not quarantined" is `NULL`. Writing the two
//! halves of that mapping in two places is how a column can end up with
//! a value no reader can classify, so they are written here, next to
//! each other, and nowhere else.
//!
//! ## Fail-closed decoding
//!
//! A stored value this module cannot classify is a
//! [`DomainError::Invariant`], never a fallback status. The fallback it
//! replaced was `QuarantineStatus::None` — simultaneously the most
//! permissive state ([`Artifact::is_downloadable`] admits it, and the
//! default `ReleasedOnly` index mode serves it) and a state the column
//! cannot even hold. So every value the column accepted but the domain
//! could not parse was served to clients with no release authority
//! behind it and no `ArtifactReleased` in its stream.
//!
//! The posture mirrors `hort_adapters_postgres::test_support`: a
//! configured thing that does not work is not the same as an absent
//! thing. `NULL` is the absent thing and decodes to
//! [`QuarantineStatus::None`]. Anything else that fails to decode is a
//! classification failure, and a read that cannot classify an artifact
//! must not yield a servable one — the request fails instead.
//!
//! Enforced by the structural guard
//! `crates/hort-app/tests/status_decode_fails_closed.rs`, which rejects
//! a discarded parse error or a substituted default on any
//! quarantine-status decode in `crates/*/src`.
//!
//! [`Display`]: std::fmt::Display
//! [`FromStr`]: std::str::FromStr
//! [`Artifact::is_downloadable`]: hort_domain::entities::artifact::Artifact::is_downloadable

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::constituent_status::terminal_statuses_by_refusal_precedence;

/// The [`Display`](std::fmt::Display) spelling of
/// [`QuarantineStatus::None`]. Named so the decoder can refuse it
/// explicitly rather than let [`str::parse`] quietly accept it: the
/// stored spelling of "not quarantined" is SQL `NULL`, so a literal
/// `'none'` in the column is a value no writer in this crate can
/// produce and the column's CHECK does not admit.
const DISPLAY_ONLY_NONE: &str = "none";

/// Encode `status` for the `artifacts.quarantine_status` column.
///
/// `None` is returned for [`QuarantineStatus::None`] — the column
/// stores that state as SQL `NULL`, not as the variant's `Display`
/// spelling. Every writer binds through here so the stored vocabulary
/// has exactly one author.
///
/// Callers comparing a *prior* status in a conditional UPDATE must use
/// `IS NOT DISTINCT FROM` rather than `=`, because the `None` encoding
/// is `NULL` and `NULL = NULL` is never true.
pub(crate) fn quarantine_status_to_sql(status: QuarantineStatus) -> Option<String> {
    match status {
        QuarantineStatus::None => None,
        other => Some(other.to_string()),
    }
}

/// The terminal statuses in their **stored** spelling, strongest first —
/// the array a query binds when it has to ask "is this row's lifecycle
/// concluded against delivery?".
///
/// This is the one derivation of that array in the crate, and every
/// query that needs it binds this rather than deriving it again. Two
/// derivations would not be two definitions of `is_terminal` — both
/// filter through the predicate — but they would be two places to get
/// the *encoding* wrong, and this module is where the column's stored
/// vocabulary has its single author. A spelled-out
/// `IN ('rejected','scan_indeterminate')` in SQL is the thing neither
/// may become: that is a second definition of the predicate, and a sixth
/// `QuarantineStatus` variant leaves it narrower with nothing failing.
///
/// The **order** is load-bearing for a caller that ranks verdicts: it is
/// [`terminal_statuses_by_refusal_precedence`]'s, so a query can turn the
/// array's ordinality into an `ORDER BY` key without SQL knowing which
/// verdict is stronger. A caller that only tests membership may ignore
/// it.
pub(crate) fn terminal_status_binding() -> Vec<String> {
    terminal_statuses_by_refusal_precedence()
        .into_iter()
        // `None` is the one status the column stores as SQL NULL, and it
        // is not terminal, so `filter_map` drops nothing a terminal set
        // contains. Expressed as a flatten rather than an `expect`
        // because an encoder that returned `None` for a terminal status
        // would be a mapping bug, not a reason to panic a read path.
        .filter_map(quarantine_status_to_sql)
        .collect()
}

/// Decode a stored `artifacts.quarantine_status` into the domain state,
/// failing closed on anything the domain cannot classify.
///
/// `None` (SQL `NULL`) is the stored spelling of
/// [`QuarantineStatus::None`] and is the only input that decodes to it.
/// Every other input must round-trip
/// [`quarantine_status_to_sql`]; one that does not is a
/// [`DomainError::Invariant`] naming the offending value, because the
/// alternative — substituting a status — decides a serving question the
/// data did not answer.
///
/// `context` is evaluated only on the error path (the read paths that
/// call this are the highest-QPS reads in the system, and the happy
/// path must not allocate a message nobody reads). It should name the
/// row or the query, e.g. `"artifact <uuid>"`.
pub(crate) fn quarantine_status_from_sql(
    raw: Option<&str>,
    context: impl FnOnce() -> String,
) -> DomainResult<QuarantineStatus> {
    let Some(raw) = raw else {
        return Ok(QuarantineStatus::None);
    };
    if raw.eq_ignore_ascii_case(DISPLAY_ONLY_NONE) {
        return Err(DomainError::Invariant(format!(
            "{}: quarantine_status {raw:?} is the display spelling of a state the column \
             stores as NULL — a literal 'none' is not a value this adapter writes or the \
             schema admits",
            context()
        )));
    }
    raw.parse().map_err(|_| {
        DomainError::Invariant(format!(
            "{}: unclassifiable quarantine_status {raw:?} — the artifact cannot be judged \
             downloadable or servable from it",
            context()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant survives encode → decode unchanged. This is the
    /// property the two functions exist to hold; a divergence here is
    /// the defect class the module header describes.
    #[test]
    fn every_variant_round_trips_through_the_column() {
        for status in [
            QuarantineStatus::None,
            QuarantineStatus::Quarantined,
            QuarantineStatus::Released,
            QuarantineStatus::Rejected,
            QuarantineStatus::ScanIndeterminate,
        ] {
            let stored = quarantine_status_to_sql(status);
            let decoded = quarantine_status_from_sql(stored.as_deref(), || "round-trip".into())
                .expect("an encoded status decodes");
            assert_eq!(decoded, status, "round-trip failed for {status}");
        }
    }

    /// `None` is `NULL`, not `'none'` — pinned on the encoder so a
    /// future `to_string()`-everything simplification trips here rather
    /// than against the column's CHECK constraint at runtime.
    #[test]
    fn none_encodes_to_sql_null() {
        assert_eq!(quarantine_status_to_sql(QuarantineStatus::None), None);
        assert_eq!(
            quarantine_status_to_sql(QuarantineStatus::Released).as_deref(),
            Some("released")
        );
    }

    /// SQL `NULL` is the absent thing, and the only input that may
    /// decode to the most permissive state.
    #[test]
    fn null_decodes_to_none() {
        assert_eq!(
            quarantine_status_from_sql(None, || "null".into()).expect("NULL decodes"),
            QuarantineStatus::None
        );
    }

    /// The three legacy scan-state spellings the column's CHECK still
    /// accepts are not classifiable states. They must not decode to
    /// `None`: that is the most permissive state in the system, and
    /// reaching it would advertise and serve an artifact that never
    /// acquired a release authority.
    #[test]
    fn legacy_scan_state_spellings_fail_closed() {
        for raw in ["unscanned", "clean", "flagged"] {
            let err = quarantine_status_from_sql(Some(raw), || format!("artifact for {raw}"))
                .expect_err("a legacy scan-state spelling is not a quarantine state");
            match err {
                DomainError::Invariant(msg) => {
                    assert!(
                        msg.contains(raw),
                        "the error must name the offending value; got {msg}"
                    );
                }
                other => panic!("expected Invariant, got {other:?}"),
            }
        }
    }

    /// A literal `'none'` is refused rather than quietly accepted by
    /// `FromStr`: the column's "not quarantined" spelling is `NULL`, and
    /// two spellings for one state is the ambiguity this module removes.
    #[test]
    fn the_display_spelling_of_none_is_not_a_stored_value() {
        for raw in ["none", "None", "NONE"] {
            let err = quarantine_status_from_sql(Some(raw), || "artifact".into())
                .expect_err("'none' is a display spelling, not a stored one");
            assert!(
                matches!(err, DomainError::Invariant(_)),
                "expected Invariant for {raw}, got {err:?}"
            );
        }
    }

    /// An entirely unknown value is the same failure as a legacy one —
    /// the decoder classifies by round-trip, not by an allow-list of
    /// known-bad spellings.
    #[test]
    fn an_unknown_value_fails_closed() {
        let err = quarantine_status_from_sql(Some("probably_fine"), || "artifact 7".into())
            .expect_err("an unknown status is unclassifiable");
        match err {
            DomainError::Invariant(msg) => assert!(
                msg.contains("artifact 7") && msg.contains("probably_fine"),
                "the error must carry both the context and the value; got {msg}"
            ),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    /// The context closure is for the error path only. A decode that
    /// succeeds must not pay for a message nobody reads — the hot
    /// index-serve read calls this once per row.
    #[test]
    fn the_context_closure_is_not_called_on_success() {
        let mut called = false;
        let decoded = quarantine_status_from_sql(Some("released"), || {
            called = true;
            "unused".into()
        })
        .expect("released decodes");
        assert_eq!(decoded, QuarantineStatus::Released);
        assert!(!called, "the context must be lazy");
    }

    /// Case-insensitivity comes from `QuarantineStatus::from_str` and is
    /// pinned here so a decoder rewrite that hard-codes lowercase
    /// literals does not silently narrow what a migrated database can
    /// still be read with.
    #[test]
    fn decoding_is_case_insensitive_for_real_states() {
        assert_eq!(
            quarantine_status_from_sql(Some("RELEASED"), || "artifact".into())
                .expect("case-insensitive"),
            QuarantineStatus::Released
        );
    }
}
