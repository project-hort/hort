//! Eventstore-retention registration-site guard (ADR 0030,
//! `docs/adr/0030-sensitive-surface-structural-guards.md`).
//!
//! This is a DB-free, network-free, sub-second guard `#[test]` (in the
//! spirit of `ephemeral_keyspace_exhaustive` / `no_bcrypt` /
//! `alpha_fixtures` / `streaming_metadata_port` / `no_sensitive_drops`)
//! over the **code-held** eventstore-retention rule set
//! ([`canonical_retention_rules`]).
//!
//! ## Why a guard and not a candidacy predicate
//!
//! The hazard ("a misconfigured retention policy could target privileged
//! streams") is **already structurally closed**. Eventstore retention
//! is fail-closed by **category registration**: the audit-retention
//! sweep (`EventStoreRetentionUseCase::process_one`, step 2) looks up the
//! candidate stream's `StreamCategory` in the registered rule set and
//! **skips** (`skipped_unregistered_category`) any candidate whose category
//! has no `CategoryRetentionRule`. That rule set is built by
//! [`canonical_retention_rules`] — a pure, code-held function, **not** a
//! DB/policy value an operator can misconfigure. So the misconfiguration
//! premise has no as-built path; the unregistered privileged categories
//! (`Authorization`, `User`, `Admin`, `Policy`, `RetentionPolicy`,
//! `Repository`, `Curation`, `Ref`, `ArtifactGroup`) are never sealed or
//! deleted.
//!
//! There is therefore deliberately **no** `is_retention_eligible()`
//! candidacy predicate and **no** `RetentionPolicy::candidate_streams()` —
//! neither exists, and `RetentionPolicy` is the *artifact*-retention entity
//! (drives `ArtifactPurged`), a different surface from
//! `EventStore::delete_stream`. A predicate that *exempted* the rotated
//! audit categories would re-open the unbounded audit-stream growth those
//! rules exist to bound (see below).
//!
//! ## What it asserts
//!
//! The residual is a **registration-site guard** that structurally prevents
//! a future dev from seeding a never-rotation *privileged* category into the
//! rule set:
//!
//!   1. **Allowlist conformance.** Every rule [`canonical_retention_rules`]
//!      emits (for representative positive floors) has a `category` in the
//!      maintained [`RETENTION_PERMITTED`] allowlist. A future dev who
//!      seeds, e.g., `StreamCategory::Authorization` into the rule set trips
//!      this assertion.
//!   2. **Exhaustiveness.** A `match` over **every** `StreamCategory`
//!      variant — **no `_` wildcard arm** — classifies each variant as
//!      `retention_permitted` or `retention_forbidden`. Because
//!      `StreamCategory` is not `#[non_exhaustive]`, a future variant added
//!      in `hort-domain` fails to COMPILE this match until consciously
//!      classified (the same compile-forcing exhaustiveness pattern as the
//!      sibling structural guards). The
//!      classification is cross-checked against [`RETENTION_PERMITTED`] so
//!      the allowlist and the match cannot drift.
//!   3. **Count.** Exactly 4 permitted / 9 forbidden, so a silent
//!      reclassification is caught.
//!
//! ## Why the four permitted categories are PRESERVED, not exempted
//!
//! [`RETENTION_PERMITTED`] = `{Artifact, AuthAttempts, DownloadAudit,
//! TokenUse}` — the `ArtifactPurged` terminal-gated lifecycle category plus
//! the three deliberately-rotated audit streams. `canonical_retention_rules`
//! seeds `AuthAttempts` (≥6mo floor), `DownloadAudit` (≥90d floor), and
//! `TokenUse` (≥36mo floor) **on purpose**: these are the high-volume
//! rotated audit streams their retention rules exist to BOUND.
//! Their retention is **preserved** here — exempting them from retention
//! would re-open the exact unbounded audit-stream growth those rules were
//! built to solve.
//!
//! This guard never reaches the seal-pool single-flight (ADR 0020); it is
//! a registration-site source-of-truth check. Concerns about *relaxing*
//! that layer do not apply to a registration-site guard test.

#![allow(clippy::expect_used)]

use hort_app::use_cases::eventstore_retention_use_case::canonical_retention_rules;
use hort_domain::events::StreamCategory;

/// **Permanent, audited security boundary.** The categories whose
/// eventstore streams [`canonical_retention_rules`] is permitted to register
/// for retention (seal + delete/archive once their floor elapses):
///
/// - [`StreamCategory::Artifact`] — the `ArtifactPurged` terminal-gated
///   artifact-lifecycle category.
/// - [`StreamCategory::AuthAttempts`] — rotated `auth-{date}` audit streams
///   (≥6mo authentication floor).
/// - [`StreamCategory::DownloadAudit`] — rotated per-`(repo, UTC-date)`
///   download-audit streams (≥90d floor).
/// - [`StreamCategory::TokenUse`] — rotated per-`(token, UTC-date)`
///   token-use audit streams (≥36mo floor).
///
/// Adding a fifth category to [`canonical_retention_rules`] requires a
/// deliberate, reviewed edit to this list. An accidental addition of a
/// privileged category (`Authorization` / `User` / `Admin` / `Policy` /
/// `RetentionPolicy` / `Repository` / `Curation` / `Ref` / `ArtifactGroup`)
/// trips the guard below — that category's privileged streams must never
/// become eligible for never-reviewed automated deletion. See module
/// docstring and ADR 0030.
const RETENTION_PERMITTED: &[StreamCategory] = &[
    StreamCategory::Artifact,
    StreamCategory::AuthAttempts,
    StreamCategory::DownloadAudit,
    StreamCategory::TokenUse,
];

/// Classify a [`StreamCategory`] for retention eligibility.
///
/// Exhaustive on purpose — **no `_` wildcard arm**. Because
/// `StreamCategory` is not `#[non_exhaustive]`, adding a new variant in
/// `hort-domain` fails to COMPILE this function until the new variant is
/// consciously classified `permitted` (and added to [`RETENTION_PERMITTED`])
/// or `forbidden`. This is the structural close: a privileged category
/// cannot silently default into retention eligibility.
fn retention_permitted(category: StreamCategory) -> bool {
    match category {
        // ── permitted: the ArtifactPurged terminal + the three
        //    deliberately-rotated audit streams ───────────────────────
        StreamCategory::Artifact
        | StreamCategory::AuthAttempts
        | StreamCategory::DownloadAudit
        | StreamCategory::TokenUse => true,
        // ── forbidden: privileged / non-rotated categories that must
        //    never become eligible for automated stream deletion ───────
        StreamCategory::Policy
        | StreamCategory::Admin
        | StreamCategory::Ref
        | StreamCategory::ArtifactGroup
        | StreamCategory::Curation
        | StreamCategory::Repository
        | StreamCategory::Authorization
        | StreamCategory::User
        | StreamCategory::RetentionPolicy => false,
    }
}

/// Every `StreamCategory` variant, listed once. The exhaustive `match` in
/// [`retention_permitted`] is the compile-time guarantee that this list is
/// complete; this array lets the count + cross-check tests iterate it.
const ALL_CATEGORIES: &[StreamCategory] = &[
    StreamCategory::Artifact,
    StreamCategory::Policy,
    StreamCategory::Admin,
    StreamCategory::Ref,
    StreamCategory::ArtifactGroup,
    StreamCategory::Curation,
    StreamCategory::Repository,
    StreamCategory::AuthAttempts,
    StreamCategory::Authorization,
    StreamCategory::User,
    StreamCategory::DownloadAudit,
    StreamCategory::TokenUse,
    StreamCategory::RetentionPolicy,
];

/// Representative positive (non-zero) floors for the four
/// `canonical_retention_rules` parameters. The exact values are irrelevant
/// to this guard — it asserts over the emitted *categories*, not the floors
/// — but using realistic production floor values documents intent.
fn representative_rules(
) -> Vec<hort_app::use_cases::eventstore_retention_use_case::CategoryRetentionRule> {
    canonical_retention_rules(
        chrono::Duration::days(183),  // ≥6mo authentication
        chrono::Duration::days(30),   // artifact-lifecycle
        chrono::Duration::days(90),   // ≥90d download-audit
        chrono::Duration::days(1096), // ≥36mo token-use
    )
}

#[test]
fn every_registered_rule_category_is_in_the_permitted_allowlist() {
    let rules = representative_rules();
    assert!(
        !rules.is_empty(),
        "canonical_retention_rules() emitted no rules — the rule set should \
         seed at least the artifact + audit-stream categories"
    );
    for rule in &rules {
        assert!(
            RETENTION_PERMITTED.contains(&rule.category),
            "canonical_retention_rules() registered a retention rule for \
             {:?}, which is NOT in the RETENTION_PERMITTED allowlist. \
             Registering a privileged / never-rotation category for \
             automated stream deletion re-opens the hazard ADR 0030 closes. \
             If this addition is deliberate, add the category to \
             RETENTION_PERMITTED *and* classify it `permitted` in \
             retention_permitted() — both are an audited security-boundary \
             edit (ADR 0030).",
            rule.category
        );
    }
}

#[test]
fn permitted_categories_match_the_canonical_rule_set_exactly() {
    // The four categories the as-built rule set actually emits
    // (AuthAttempts, Artifact, DownloadAudit, TokenUse). This pins the
    // clean rule set: dropping a deliberately-rotated audit category
    // (which would re-open the unbounded-growth class its rule bounds) is
    // as much a regression as adding a privileged one.
    let emitted: std::collections::HashSet<StreamCategory> = representative_rules()
        .into_iter()
        .map(|r| r.category)
        .collect();
    let permitted: std::collections::HashSet<StreamCategory> =
        RETENTION_PERMITTED.iter().copied().collect();
    assert_eq!(
        emitted, permitted,
        "the categories canonical_retention_rules() emits ({emitted:?}) must \
         exactly equal RETENTION_PERMITTED ({permitted:?}). A mismatch means \
         either a privileged category was seeded (security regression) or a \
         deliberately-rotated audit category was dropped (re-opens unbounded \
         audit-stream growth). See ADR 0030."
    );
}

#[test]
fn allowlist_and_exhaustive_classification_cannot_drift() {
    // Cross-check: the RETENTION_PERMITTED allowlist and the no-wildcard
    // retention_permitted() match must agree on every variant. If a future
    // edit changes one without the other, this trips.
    for &category in ALL_CATEGORIES {
        let in_allowlist = RETENTION_PERMITTED.contains(&category);
        let classified_permitted = retention_permitted(category);
        assert_eq!(
            in_allowlist, classified_permitted,
            "RETENTION_PERMITTED membership ({in_allowlist}) and \
             retention_permitted() classification ({classified_permitted}) \
             disagree for {category:?} — the allowlist and the exhaustive \
             match have drifted. Update both together (audited boundary edit)."
        );
    }
}

#[test]
fn exactly_four_permitted_and_nine_forbidden() {
    let permitted = ALL_CATEGORIES
        .iter()
        .filter(|&&c| retention_permitted(c))
        .count();
    let forbidden = ALL_CATEGORIES.len() - permitted;
    assert_eq!(
        permitted, 4,
        "expected exactly 4 retention-permitted categories (Artifact, \
         AuthAttempts, DownloadAudit, TokenUse); a silent reclassification \
         changed the count"
    );
    assert_eq!(
        forbidden, 9,
        "expected exactly 9 retention-forbidden categories (Policy, Admin, \
         Ref, ArtifactGroup, Curation, Repository, Authorization, User, \
         RetentionPolicy); a silent reclassification changed the count"
    );
    assert_eq!(
        RETENTION_PERMITTED.len(),
        4,
        "RETENTION_PERMITTED must list exactly the 4 permitted categories"
    );
}
