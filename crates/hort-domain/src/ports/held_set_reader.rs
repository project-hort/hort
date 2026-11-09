//! `HeldSetReader` port — the operator-facing view of the set the
//! release gate holds pending a signature.
//!
//! ADR 0039 D4 declines to put a deadline on an unsigned hold, and it
//! argues that on the ground that an operator can see the held set *and
//! its age*. This port is the read behind that surface. The hold is
//! indefinite, so the only thing that makes it defensible is that it is
//! visible.
//!
//! # Two precisions, each named for what it measures
//!
//! The provenance leg of the release gate is computed in exactly one
//! place (`hort_app::use_cases::release_clearance`), because two
//! independent computations of it drifted once. So this port offers two
//! different kinds of answer and never pretends they are the same kind:
//!
//! - [`HeldSetReader::aggregate_candidates`] is a **declared superset**.
//!   It resolves the policy — the quarantine duration and the
//!   provenance mode, from one resolved policy row — and the window
//!   expiry, in SQL. It does **not** evaluate the clearance verdict:
//!   that would be a second computation of the release conjunct. An
//!   artifact that carries a `ProvenanceVerified` and has simply not
//!   been swept yet is therefore counted. Hence
//!   *`held_pending_signature_candidates`*, in the method name, the
//!   response field and the docs — never "artifacts the gate is
//!   holding".
//! - [`HeldSetReader::list_candidates`] is the same superset, paged. The
//!   caller resolves each row through the one authority before showing
//!   it, so the list an operator acts on is exact per row.
//!
//! # The bucket rule is the caller's, not this port's
//!
//! Whether a held artifact is a parent-gated blob constituent (held
//! because its parent manifest is unsigned — a blob cannot carry its own
//! attestation, ADR 0039) or an artifact in its own right decides what
//! the operator does about it, so the view distinguishes. The rule
//! itself lives in exactly one place in Rust
//! (`hort_app::use_cases::referenced_descendant`) and reaches this port
//! as [`ConstituentKindSets`] — two lists of `content_references.kind`
//! values. An implementation forms only the boolean from them; it must
//! not carry a kind list of its own, because a second list is a second
//! rule.
//!
//! # Domain DTO discipline
//!
//! None of the types here derive `Serialize` / `Deserialize`. The HTTP
//! DTOs live in the inbound-HTTP crate; mirrors
//! [`CurationQueueEntry`](super::curation_queue_repository::CurationQueueEntry).

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};

use super::BoxFuture;

/// The two `content_references.kind` lists that decide the
/// constituent / in-own-right split, supplied by the caller that owns
/// the rule.
///
/// `blob_kinds` are the tree-edge kinds whose target is an OCI **blob**
/// — a target that can never be the subject of an attestation.
/// `self_referential_kinds` are an artifact's own bookkeeping edges,
/// which say nothing about who references it.
///
/// An artifact is a constituent iff it carries at least one
/// `blob_kinds` edge and **every** edge it carries is in
/// `blob_kinds ∪ self_referential_kinds`. A reference-less artifact is
/// not a constituent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstituentKindSets<'a> {
    pub blob_kinds: &'a [&'a str],
    pub self_referential_kinds: &'a [&'a str],
}

/// Which half of a repository's held set a row belongs to.
///
/// The split is not cosmetic: the two halves call for different operator
/// action. A constituent is waiting on *its parent manifest's*
/// signature and can never acquire one of its own; an artifact in its
/// own right is waiting on a signature someone could still publish for
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeldBucket {
    /// A config/layer blob whose only inbound edges are its parent
    /// manifest's.
    Constituent,
    /// An artifact that is held on its own account.
    InOwnRight,
}

impl HeldBucket {
    /// The wire token, and the value the adapter's boolean maps to.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constituent => "constituent",
            Self::InOwnRight => "in_own_right",
        }
    }

    /// Every bucket, for a caller that renders or iterates all of them.
    /// Exhaustive by construction — a new variant that is not added here
    /// leaves [`HeldBucket::as_str`]'s match arm unfilled, which is a
    /// compile error.
    pub fn all() -> [Self; 2] {
        [Self::Constituent, Self::InOwnRight]
    }

    /// `true` for [`HeldBucket::Constituent`] — the boolean the SQL
    /// forms from [`ConstituentKindSets`], named rather than spelled at
    /// each call site.
    pub fn is_constituent(self) -> bool {
        matches!(self, Self::Constituent)
    }

    /// The bucket a `is_constituent` boolean stands for.
    pub fn from_is_constituent(is_constituent: bool) -> Self {
        if is_constituent {
            Self::Constituent
        } else {
            Self::InOwnRight
        }
    }
}

impl fmt::Display for HeldBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HeldBucket {
    type Err = DomainError;

    /// Parses the wire token. Deliberately a `FromStr` rather than a
    /// `Deserialize`: a domain type is never deserialized from request
    /// input (ADR 0008), so the handler parses the query parameter and
    /// maps the `Validation` error to `400`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "constituent" => Ok(Self::Constituent),
            "in_own_right" => Ok(Self::InOwnRight),
            other => Err(DomainError::Validation(format!(
                "invalid bucket {other:?} (expected one of {} | {})",
                Self::Constituent.as_str(),
                Self::InOwnRight.as_str(),
            ))),
        }
    }
}

/// Age of a held row at `now`, in whole seconds.
///
/// Floored at zero rather than signed: `held_since` is a stored
/// timestamp and `now` a caller-pinned instant, so a clock that has gone
/// backwards (or a window anchored to an upstream-asserted publish time
/// in the future) can order them the wrong way round. An operator
/// reading "held for -4 seconds" learns nothing; zero says "no
/// measurable age", which is the truth available.
fn age_secs_at(held_since: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    let secs = (now - held_since).num_seconds();
    u64::try_from(secs).unwrap_or(0)
}

/// One `(repository, bucket)` cell of the aggregate.
///
/// Carries **both** counts, and that is the whole point of the pair: CAS
/// shares content across artifacts (ADR 0054), so an artifact count is
/// not a byte count and must not be read as reclaimable storage. The
/// first real retention dry run reported 3 647 rows against 3 608
/// distinct contents, so the two differ in practice and not only in
/// principle. What a disposal would actually free is a different
/// question again, decided by the CAS refcount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCandidateBucket {
    pub repository_id: Uuid,
    /// Resolved by the adapter's join — a pass-through string the HTTP
    /// DTO renders for the operator.
    pub repository_key: String,
    pub bucket: HeldBucket,
    /// Number of `artifacts` rows in this cell.
    pub artifact_count: u64,
    /// Number of distinct `checksum_sha256` values across those rows.
    /// Never greater than [`HeldCandidateBucket::artifact_count`].
    pub distinct_content_count: u64,
    /// The oldest hold anchor in this cell — `min(quarantine_window_start)`.
    pub oldest_held_since: DateTime<Utc>,
}

impl HeldCandidateBucket {
    /// How long the oldest row in this cell has been held, at `now`.
    ///
    /// This is the number ADR 0039 D4's "no deadline" rests on: a status
    /// transition would collapse "held for 20 seconds" and "held for 20
    /// days" into one value, and the age is what an operator actually
    /// needs. It appears in every response.
    pub fn oldest_age_secs(&self, now: DateTime<Utc>) -> u64 {
        age_secs_at(self.oldest_held_since, now)
    }
}

/// One row of the drill-down — a single held candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCandidateRow {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: Option<String>,
    /// Stored artifact path; identifies OCI blobs and manifests whose
    /// `version` is absent.
    pub path: String,
    /// The artifact's content hash. Two rows sharing one value share
    /// their bytes — see [`HeldCandidateBucket`].
    pub content_hash: String,
    pub bucket: HeldBucket,
    pub held_since: DateTime<Utc>,
}

impl HeldCandidateRow {
    /// How long this artifact has been held, at `now`.
    pub fn age_secs(&self, now: DateTime<Utc>) -> u64 {
        age_secs_at(self.held_since, now)
    }
}

/// One page request against [`HeldSetReader::list_candidates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldCandidateQuery<'a> {
    /// The instant the window-expiry comparison is taken at. Pinned by
    /// the caller so the aggregate and the drill-down can be read
    /// against one `now`.
    pub now: DateTime<Utc>,
    /// The bucket rule's input — see [`ConstituentKindSets`].
    pub kinds: ConstituentKindSets<'a>,
    /// Which half of the held set to page through. Required: the two
    /// halves are different operator tasks, so there is no "both"
    /// shape that would need an ordering between them.
    pub bucket: HeldBucket,
    pub repository_id: Option<Uuid>,
    /// Keyset cursor — the last `artifact_id` of the previous page.
    pub after: Option<Uuid>,
    /// Page size. The caller **refuses** an oversize value rather than
    /// clamping it (a clamp returns fewer rows than asked for and says
    /// nothing); an implementation still clamps defensively so a
    /// use-case bypass cannot drag the database through a 10k-row scan.
    pub limit: u32,
}

/// Outbound port: the held-set overview and its drill-down.
pub trait HeldSetReader: Send + Sync {
    /// One cell per `(repository, bucket)`, in **one** query and with no
    /// per-row event read.
    ///
    /// A **declared superset** of the held set: it resolves the policy
    /// and the window expiry, and deliberately not the provenance
    /// clearance verdict. See this module's docs.
    fn aggregate_candidates<'a>(
        &'a self,
        now: DateTime<Utc>,
        kinds: ConstituentKindSets<'a>,
    ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateBucket>>>;

    /// One page of the same superset, keyset-ordered by `artifact_id`.
    ///
    /// Rows come back in `artifact_id` order so the caller can resume
    /// from the last row it *scanned* — which is not necessarily the
    /// last row it *kept*, because the caller drops rows the authority
    /// clears.
    fn list_candidates<'a>(
        &'a self,
        query: HeldCandidateQuery<'a>,
    ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateRow>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    /// Compile-time dyn-compatibility assertion.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn HeldSetReader>();
    }

    #[test]
    fn bucket_tokens_round_trip() {
        for bucket in HeldBucket::all() {
            assert_eq!(
                bucket.as_str().parse::<HeldBucket>().expect("round trips"),
                bucket
            );
            assert_eq!(bucket.to_string(), bucket.as_str());
        }
    }

    #[test]
    fn bucket_parse_is_case_insensitive() {
        assert_eq!(
            "IN_OWN_RIGHT".parse::<HeldBucket>().expect("parses"),
            HeldBucket::InOwnRight
        );
        assert_eq!(
            "Constituent".parse::<HeldBucket>().expect("parses"),
            HeldBucket::Constituent
        );
    }

    /// An unknown token is a caller-input problem, and the message names
    /// both accepted values so the operator does not have to guess.
    #[test]
    fn bucket_parse_rejects_unknown_token() {
        let err = "both".parse::<HeldBucket>().expect_err("rejected");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("both"), "{msg}");
                assert!(msg.contains("constituent"), "{msg}");
                assert!(msg.contains("in_own_right"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn bucket_parse_rejects_empty_token() {
        assert!("".parse::<HeldBucket>().is_err());
    }

    #[test]
    fn is_constituent_maps_both_ways() {
        assert!(HeldBucket::Constituent.is_constituent());
        assert!(!HeldBucket::InOwnRight.is_constituent());
        assert_eq!(
            HeldBucket::from_is_constituent(true),
            HeldBucket::Constituent
        );
        assert_eq!(
            HeldBucket::from_is_constituent(false),
            HeldBucket::InOwnRight
        );
    }

    fn bucket_at(held_since: DateTime<Utc>) -> HeldCandidateBucket {
        HeldCandidateBucket {
            repository_id: Uuid::new_v4(),
            repository_key: "npm-main".into(),
            bucket: HeldBucket::InOwnRight,
            artifact_count: 3,
            distinct_content_count: 2,
            oldest_held_since: held_since,
        }
    }

    fn row_at(held_since: DateTime<Utc>) -> HeldCandidateRow {
        HeldCandidateRow {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            repository_key: "npm-main".into(),
            name: "left-pad".into(),
            version: Some("1.0.0".into()),
            path: "left-pad/-/left-pad-1.0.0.tgz".into(),
            content_hash: "a".repeat(64),
            bucket: HeldBucket::InOwnRight,
            held_since,
        }
    }

    #[test]
    fn age_is_the_elapsed_whole_seconds() {
        assert_eq!(bucket_at(at(0)).oldest_age_secs(at(90)), 90);
        assert_eq!(row_at(at(0)).age_secs(at(90)), 90);
    }

    /// A sub-second age truncates to zero rather than rounding up — the
    /// age is reported in whole seconds and nothing downstream treats
    /// zero as "unknown".
    #[test]
    fn age_truncates_towards_zero() {
        let held = at(0);
        let now = held + chrono::Duration::milliseconds(900);
        assert_eq!(bucket_at(held).oldest_age_secs(now), 0);
    }

    /// The boundary that matters: an anchor in the *future* (clock skew,
    /// or a window anchored to an upstream-asserted publish time) must
    /// not underflow into a huge age. Floored at zero.
    #[test]
    fn age_floors_at_zero_for_a_future_anchor() {
        assert_eq!(bucket_at(at(600)).oldest_age_secs(at(0)), 0);
        assert_eq!(row_at(at(600)).age_secs(at(0)), 0);
    }

    #[test]
    fn age_is_zero_at_the_anchor_itself() {
        assert_eq!(bucket_at(at(42)).oldest_age_secs(at(42)), 0);
        assert_eq!(row_at(at(42)).age_secs(at(42)), 0);
    }
}
