use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;
use crate::events::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hash() -> crate::types::ContentHash {
    VALID_HASH.parse().unwrap()
}

fn id() -> Uuid {
    Uuid::new_v4()
}

fn token() -> InternalActorToken {
    InternalActorToken(())
}

// ---------------------------------------------------------------------------
// StreamCategory
// ---------------------------------------------------------------------------

#[test]
fn stream_category_clone_copy_eq() {
    let a = StreamCategory::Artifact;
    let b = a; // Copy
    #[allow(clippy::clone_on_copy)]
    let c = a.clone(); // Intentionally test Clone impl
    assert_eq!(a, b);
    assert_eq!(a, c);

    let p = StreamCategory::Policy;
    assert_ne!(a, p);

    let admin = StreamCategory::Admin;
    assert_ne!(a, admin);
    assert_ne!(p, admin);
}

/// `StreamCategory::requires_admin` is the single source of truth for the
/// privileged-category table (hoisted here from what was
/// previously a private fn in `hort-http-events`). Every variant is pinned
/// so a new `StreamCategory` fails to compile here on purpose (the match
/// is exhaustive in the impl), and the per-repo vs admin-only split is
/// byte-identical to the pre-hoist `hort-http-events` table.
#[test]
fn stream_category_requires_admin_table() {
    // Per-repo categories — non-admin allowed, per-event filtered.
    for cat in [
        StreamCategory::Artifact,
        StreamCategory::ArtifactGroup,
        StreamCategory::Ref,
        StreamCategory::Curation,
        StreamCategory::Repository,
    ] {
        assert!(
            !cat.requires_admin(),
            "{cat:?} must be per-repo (non-admin allowed)"
        );
    }
    // Admin-only categories — Permission::Admin required (ADMIN_CATEGORIES).
    for cat in [
        StreamCategory::Policy,
        StreamCategory::Admin,
        StreamCategory::Authorization,
        StreamCategory::User,
        StreamCategory::AuthAttempts,
        StreamCategory::DownloadAudit,
        StreamCategory::TokenUse,
        StreamCategory::RetentionPolicy,
    ] {
        assert!(
            cat.requires_admin(),
            "{cat:?} must require Permission::Admin (ADMIN_CATEGORIES)"
        );
    }
}

// ---------------------------------------------------------------------------
// StreamId
// ---------------------------------------------------------------------------

#[test]
fn stream_id_artifact_constructor() {
    let uid = id();
    let sid = StreamId::artifact(uid);
    assert_eq!(sid.category, StreamCategory::Artifact);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_policy_constructor() {
    let uid = id();
    let sid = StreamId::policy(uid);
    assert_eq!(sid.category, StreamCategory::Policy);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_display_artifact() {
    let uid = Uuid::nil();
    let sid = StreamId::artifact(uid);
    assert_eq!(sid.to_string(), format!("artifact-{uid}"));
}

#[test]
fn stream_id_display_policy() {
    let uid = Uuid::nil();
    let sid = StreamId::policy(uid);
    assert_eq!(sid.to_string(), format!("policy-{uid}"));
}

#[test]
fn stream_id_admin_constructor() {
    let uid = id();
    let sid = StreamId::admin(uid);
    assert_eq!(sid.category, StreamCategory::Admin);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_display_admin() {
    let uid = Uuid::nil();
    let sid = StreamId::admin(uid);
    assert_eq!(sid.to_string(), format!("admin-{uid}"));
}

#[test]
fn stream_id_clone_eq_hash() {
    use std::collections::HashSet;
    let sid = StreamId::artifact(Uuid::nil());
    let cloned = sid.clone();
    assert_eq!(sid, cloned);

    let mut set = HashSet::new();
    set.insert(sid.clone());
    assert!(set.contains(&cloned));
}

// ---------------------------------------------------------------------------
// StreamId::FromStr
// ---------------------------------------------------------------------------

#[test]
fn stream_id_from_str_artifact_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("artifact-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::artifact(id));
    assert_eq!(parsed.to_string(), display);
}

#[test]
fn stream_id_from_str_policy_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("policy-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::policy(id));
    assert_eq!(parsed.to_string(), display);
}

#[test]
fn stream_id_from_str_admin_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("admin-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::admin(id));
    assert_eq!(parsed.to_string(), display);
}

// ---------------------------------------------------------------------------
// User stream category (native API tokens)
// ---------------------------------------------------------------------------

#[test]
fn stream_id_user_constructor() {
    let uid = id();
    let sid = StreamId::user(uid);
    assert_eq!(sid.category, StreamCategory::User);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_display_user() {
    let uid = Uuid::nil();
    let sid = StreamId::user(uid);
    assert_eq!(sid.to_string(), format!("user-{uid}"));
}

#[test]
fn stream_id_from_str_user_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("user-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::user(id));
    assert_eq!(parsed.to_string(), display);
}

#[test]
fn stream_category_user_distinct_from_admin() {
    // The B7 deviation note: `User` is structurally distinct from
    // `Admin`. Keep these on separate streams so an audit consumer
    // reading "all admin events" never collides with the per-user
    // PAT lifecycle.
    assert_ne!(StreamCategory::User, StreamCategory::Admin);
}

// ---------------------------------------------------------------------------
// Ref stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_ref_constructor() {
    let uid = id();
    let sid = StreamId::ref_(uid);
    assert_eq!(sid.category, StreamCategory::Ref);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_display_ref() {
    let uid = Uuid::nil();
    let sid = StreamId::ref_(uid);
    assert_eq!(sid.to_string(), format!("ref-{uid}"));
}

#[test]
fn stream_id_from_str_ref_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("ref-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::ref_(id));
    assert_eq!(parsed.to_string(), display);
}

// ---------------------------------------------------------------------------
// ArtifactGroup stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_artifact_group_constructor() {
    let uid = id();
    let sid = StreamId::artifact_group(uid);
    assert_eq!(sid.category, StreamCategory::ArtifactGroup);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_id_display_artifact_group() {
    let uid = Uuid::nil();
    let sid = StreamId::artifact_group(uid);
    assert_eq!(sid.to_string(), format!("artifact_group-{uid}"));
}

#[test]
fn stream_id_from_str_artifact_group_round_trip() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let display = format!("artifact_group-{id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::artifact_group(id));
    assert_eq!(parsed.to_string(), display);
}

/// **B1 regression guard** — `artifact-<uuid>` and `artifact_group-<uuid>`
/// MUST resolve to different categories. The parser splits on the first
/// `'-'`; the category prefix for groups is `"artifact_group"` (underscore,
/// then hyphen before the UUID), so the two stream forms cannot collide.
#[test]
fn stream_id_from_str_artifact_and_artifact_group_do_not_collide() {
    use std::str::FromStr;
    let artifact_uid = Uuid::new_v4();
    let group_uid = Uuid::new_v4();
    let artifact_sid = StreamId::from_str(&format!("artifact-{artifact_uid}")).unwrap();
    let group_sid = StreamId::from_str(&format!("artifact_group-{group_uid}")).unwrap();
    assert_eq!(artifact_sid.category, StreamCategory::Artifact);
    assert_eq!(artifact_sid.entity_id, artifact_uid);
    assert_eq!(group_sid.category, StreamCategory::ArtifactGroup);
    assert_eq!(group_sid.entity_id, group_uid);
    assert_ne!(artifact_sid.category, group_sid.category);
}

// ---------------------------------------------------------------------------
// Curation stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_curation_per_repo_constructor() {
    let repo_id = id();
    let sid = StreamId::curation_per_repo(repo_id);
    assert_eq!(sid.category, StreamCategory::Curation);
    assert_eq!(sid.entity_id, repo_id);
}

#[test]
fn stream_id_display_curation() {
    let repo_id = Uuid::nil();
    let sid = StreamId::curation_per_repo(repo_id);
    assert_eq!(sid.to_string(), format!("curation-{repo_id}"));
}

#[test]
fn stream_id_from_str_curation_round_trip() {
    use std::str::FromStr;
    let repo_id = Uuid::new_v4();
    let display = format!("curation-{repo_id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::curation_per_repo(repo_id));
    assert_eq!(parsed.to_string(), display);
}

#[test]
fn stream_id_from_str_unknown_category_rejected() {
    use std::str::FromStr;
    let err = StreamId::from_str(&format!("nonsense-{}", Uuid::new_v4()));
    assert!(matches!(err, Err(DomainError::Validation(_))));
}

// ---------------------------------------------------------------------------
// Repository stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_repository_constructor() {
    let repo_id = id();
    let sid = StreamId::repository(repo_id);
    assert_eq!(sid.category, StreamCategory::Repository);
    assert_eq!(sid.entity_id, repo_id);
}

#[test]
fn stream_id_display_repository() {
    let repo_id = Uuid::nil();
    let sid = StreamId::repository(repo_id);
    assert_eq!(sid.to_string(), format!("repository-{repo_id}"));
}

#[test]
fn stream_id_from_str_repository_round_trip() {
    use std::str::FromStr;
    let repo_id = Uuid::new_v4();
    let display = format!("repository-{repo_id}");
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, StreamId::repository(repo_id));
    assert_eq!(parsed.to_string(), display);
}

// ---------------------------------------------------------------------------
// AuthAttempts stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_auth_attempts_constructor() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
    let sid = StreamId::auth_attempts(date);
    assert_eq!(sid.category, StreamCategory::AuthAttempts);
    // entity_id is a deterministic UUIDv5 from the date string. We
    // don't pin a specific UUID literal here — that would make the
    // test brittle against the namespace constant — but we do assert
    // determinism + the category bit.
    let again = StreamId::auth_attempts(date);
    assert_eq!(sid.entity_id, again.entity_id);
}

#[test]
fn stream_id_auth_attempts_distinct_per_date() {
    let day1 = chrono::NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
    let day2 = chrono::NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
    assert_ne!(
        StreamId::auth_attempts(day1).entity_id,
        StreamId::auth_attempts(day2).entity_id,
    );
}

#[test]
fn stream_id_display_auth_attempts() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
    let sid = StreamId::auth_attempts(date);
    let s = sid.to_string();
    assert!(s.starts_with("auth-"), "got: {s}");
    // The entity_id is a UUID; the wire form is `auth-<uuid>` so the
    // generic FromStr parser handles it like every other category.
    let suffix = s.strip_prefix("auth-").unwrap();
    let _: Uuid = suffix.parse().unwrap();
}

#[test]
fn stream_id_from_str_auth_attempts_round_trip() {
    use std::str::FromStr;
    let date = chrono::NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
    let sid = StreamId::auth_attempts(date);
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
}

// ---------------------------------------------------------------------------
// DownloadAudit stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_download_audit_constructor() {
    let repo = Uuid::new_v4();
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let sid = StreamId::download_audit(repo, date);
    assert_eq!(sid.category, StreamCategory::DownloadAudit);
    // Deterministic: same repo+date → same entity_id.
    let again = StreamId::download_audit(repo, date);
    assert_eq!(sid.entity_id, again.entity_id);
}

#[test]
fn stream_id_download_audit_distinct_per_date() {
    let repo = Uuid::new_v4();
    let day1 = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let day2 = chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap();
    assert_ne!(
        StreamId::download_audit(repo, day1).entity_id,
        StreamId::download_audit(repo, day2).entity_id,
    );
}

#[test]
fn stream_id_download_audit_distinct_per_repo() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    assert_ne!(
        StreamId::download_audit(Uuid::new_v4(), date).entity_id,
        StreamId::download_audit(Uuid::new_v4(), date).entity_id,
    );
}

#[test]
fn stream_id_display_download_audit_uses_underscore_prefix() {
    let sid = StreamId::download_audit(Uuid::nil(), chrono::NaiveDate::MIN);
    let s = sid.to_string();
    // MUST be `download_audit-<uuid>` (underscore), NOT `download-...`.
    assert!(s.starts_with("download_audit-"), "got: {s}");
    let suffix = s.strip_prefix("download_audit-").unwrap();
    let _: Uuid = suffix.parse().unwrap();
}

#[test]
fn stream_id_from_str_download_audit_round_trip() {
    use std::str::FromStr;
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let sid = StreamId::download_audit(Uuid::new_v4(), date);
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
}

/// The `split_once('-')` parser must NOT confuse `download_audit-<uuid>`
/// with a (non-existent) `download` category — the underscore in the
/// category prefix is load-bearing, same discipline as `artifact_group`.
#[test]
fn stream_id_from_str_download_audit_no_hyphen_collision() {
    use std::str::FromStr;
    let uid = Uuid::new_v4();
    let sid = StreamId::from_str(&format!("download_audit-{uid}")).unwrap();
    assert_eq!(sid.category, StreamCategory::DownloadAudit);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_category_download_audit_requires_admin() {
    // Privileged cross-repo audit read — grouped with the
    // ADMIN_CATEGORIES set, NOT the per-repo categories.
    assert!(StreamCategory::DownloadAudit.requires_admin());
}

/// Canonical-bytes distinctness: a download-audit stream id is never
/// equal to the artifact aggregate/lifecycle stream id for the same
/// repo/artifact uuid (the symmetric stream-identity property at the
/// StreamId level — the use case asserts it on the batch too).
#[test]
fn stream_id_download_audit_never_collides_with_artifact_stream() {
    let id = Uuid::new_v4();
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let dl = StreamId::download_audit(id, date);
    let art = StreamId::artifact(id);
    assert_ne!(dl, art);
    assert_ne!(dl.category, art.category);
    assert_ne!(dl.to_string(), art.to_string());
}

// ---------------------------------------------------------------------------
// TokenUse stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_token_use_constructor() {
    let token = Uuid::new_v4();
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let sid = StreamId::token_use(token, date);
    assert_eq!(sid.category, StreamCategory::TokenUse);
    // Deterministic: same token+date → same entity_id.
    let again = StreamId::token_use(token, date);
    assert_eq!(sid.entity_id, again.entity_id);
}

#[test]
fn stream_id_token_use_distinct_per_date() {
    let token = Uuid::new_v4();
    let day1 = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let day2 = chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap();
    assert_ne!(
        StreamId::token_use(token, day1).entity_id,
        StreamId::token_use(token, day2).entity_id,
    );
}

#[test]
fn stream_id_token_use_distinct_per_token() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    assert_ne!(
        StreamId::token_use(Uuid::new_v4(), date).entity_id,
        StreamId::token_use(Uuid::new_v4(), date).entity_id,
    );
}

#[test]
fn stream_id_display_token_use_uses_underscore_prefix() {
    let sid = StreamId::token_use(Uuid::nil(), chrono::NaiveDate::MIN);
    let s = sid.to_string();
    // MUST be `token_use-<uuid>` (underscore), NOT `token-...`.
    assert!(s.starts_with("token_use-"), "got: {s}");
    let suffix = s.strip_prefix("token_use-").unwrap();
    let _: Uuid = suffix.parse().unwrap();
}

#[test]
fn stream_id_from_str_token_use_round_trip() {
    use std::str::FromStr;
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let sid = StreamId::token_use(Uuid::new_v4(), date);
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
}

/// The `split_once('-')` parser must NOT confuse `token_use-<uuid>`
/// with a (non-existent) `token` category — the underscore in the
/// category prefix is load-bearing, same discipline as
/// `artifact_group` / `download_audit`.
#[test]
fn stream_id_from_str_token_use_no_hyphen_collision() {
    use std::str::FromStr;
    let uid = Uuid::new_v4();
    let sid = StreamId::from_str(&format!("token_use-{uid}")).unwrap();
    assert_eq!(sid.category, StreamCategory::TokenUse);
    assert_eq!(sid.entity_id, uid);
}

#[test]
fn stream_category_token_use_requires_admin() {
    // Privileged per-token credential-exercise audit read — grouped
    // with the ADMIN_CATEGORIES set, NOT the per-repo categories.
    assert!(StreamCategory::TokenUse.requires_admin());
}

/// F-2 canonical-bytes distinctness: a token-use stream id is never
/// equal to the token-owner's `User` lifecycle stream id, the
/// artifact aggregate stream, or a download-audit stream for the same
/// uuid (the symmetric stream-identity property at the StreamId level —
/// the use case asserts it on the batch too).
#[test]
fn stream_id_token_use_never_collides_with_user_or_artifact_or_download() {
    let id = Uuid::new_v4();
    let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
    let tu = StreamId::token_use(id, date);
    let user = StreamId::user(id);
    let art = StreamId::artifact(id);
    let dl = StreamId::download_audit(id, date);
    for other in [&user, &art, &dl] {
        assert_ne!(&tu, other);
        assert_ne!(tu.category, other.category);
        assert_ne!(tu.to_string(), other.to_string());
    }
}

// ---------------------------------------------------------------------------
// RetentionPolicy stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_retention_policy_constructor() {
    let pid = id();
    let sid = StreamId::retention_policy(pid);
    assert_eq!(sid.category, StreamCategory::RetentionPolicy);
    assert_eq!(sid.entity_id, pid);
}

#[test]
fn stream_id_display_retention_policy_uses_underscore_prefix() {
    let pid = Uuid::nil();
    let sid = StreamId::retention_policy(pid);
    let s = sid.to_string();
    // MUST be `retention_policy-<uuid>` (underscore), NOT
    // `retention-...` (the underscore keeps the FromStr split_once
    // from confusing it with a hypothetical `retention` category).
    assert_eq!(s, format!("retention_policy-{pid}"));
    assert!(s.starts_with("retention_policy-"), "got: {s}");
}

#[test]
fn stream_id_from_str_retention_policy_round_trip() {
    use std::str::FromStr;
    let sid = StreamId::retention_policy(Uuid::new_v4());
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
}

/// Regression: the `split_once('-')` parser must NOT confuse
/// `retention_policy-<uuid>` with a non-existent `retention` category
/// — the underscore in the category prefix is load-bearing, same
/// discipline as `artifact_group` / `download_audit` / `token_use`.
#[test]
fn stream_id_from_str_retention_policy_no_hyphen_collision() {
    use std::str::FromStr;
    let uid = Uuid::new_v4();
    let sid = StreamId::from_str(&format!("retention_policy-{uid}")).unwrap();
    assert_eq!(sid.category, StreamCategory::RetentionPolicy);
    assert_eq!(sid.entity_id, uid);
}

/// A retention-policy stream id is never equal to the
/// scan-policy (`Policy`) stream id for the same uuid — the dedicated
/// category is the whole point of the retention/scan
/// divergence (a scan-policy projection and a retention-policy
/// predicate-tree projection must not share a stream category).
#[test]
fn stream_id_retention_policy_never_collides_with_scan_policy() {
    let pid = Uuid::new_v4();
    let retention = StreamId::retention_policy(pid);
    let scan = StreamId::policy(pid);
    assert_ne!(retention, scan);
    assert_ne!(retention.category, scan.category);
    assert_ne!(retention.to_string(), scan.to_string());
}

#[test]
fn stream_category_retention_policy_requires_admin() {
    // Privileged policy-mutation history read — grouped with the
    // ADMIN_CATEGORIES set (Policy / Authorization / Admin), NOT the
    // per-repo categories.
    assert!(StreamCategory::RetentionPolicy.requires_admin());
}

// ---------------------------------------------------------------------------
// Authorization stream category
// ---------------------------------------------------------------------------

#[test]
fn stream_id_authorization_constructor() {
    let sid = StreamId::authorization();
    assert_eq!(sid.category, StreamCategory::Authorization);
}

#[test]
fn stream_id_authorization_is_globally_unique_singleton() {
    // Two calls must yield the same `entity_id` — there is exactly
    // one global authorization stream per the design (audit consumer
    // reads the whole stream).
    let a = StreamId::authorization();
    let b = StreamId::authorization();
    assert_eq!(a, b);
    assert_eq!(a.entity_id, b.entity_id);
}

#[test]
fn stream_id_display_authorization() {
    let sid = StreamId::authorization();
    let s = sid.to_string();
    assert!(s.starts_with("authorization-"), "got: {s}");
    let suffix = s.strip_prefix("authorization-").unwrap();
    let _: Uuid = suffix.parse().unwrap();
}

#[test]
fn stream_id_from_str_authorization_round_trip() {
    use std::str::FromStr;
    let sid = StreamId::authorization();
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
    assert_eq!(parsed.category, StreamCategory::Authorization);
}

// ---------------------------------------------------------------------------
// eventstore-retention audit-meta stream (`StreamSealed` audit-meta)
// ---------------------------------------------------------------------------

#[test]
fn stream_id_eventstore_retention_constructor() {
    let sid = StreamId::eventstore_retention();
    assert_eq!(sid.category, StreamCategory::Admin);
    // entity_id is the deterministic UUIDv5 over the fixed
    // "eventstore-retention" label under the OID namespace — same
    // derivation shape as `StreamId::authorization()` /
    // `StreamId::auth_attempts`. Pin the exact derivation (not a UUID
    // literal) so a namespace/label change is caught.
    assert_eq!(
        sid.entity_id,
        Uuid::new_v5(&Uuid::NAMESPACE_OID, b"eventstore-retention"),
    );
}

#[test]
fn stream_id_eventstore_retention_is_a_stable_singleton() {
    // Two calls must yield the same `entity_id` — there is exactly
    // one global never-deleted audit-meta stream (the F-2
    // `StreamSealed` tombstones + F-9 Part-3 destructive-task audit
    // both land here).
    let a = StreamId::eventstore_retention();
    let b = StreamId::eventstore_retention();
    assert_eq!(a, b);
    assert_eq!(a.entity_id, b.entity_id);
}

#[test]
fn stream_id_display_eventstore_retention() {
    let sid = StreamId::eventstore_retention();
    let s = sid.to_string();
    // Wire form is `admin-<stable-uuid>` (Admin category) — the
    // generic FromStr parser handles it like every other category.
    assert!(s.starts_with("admin-"), "got: {s}");
    let suffix = s.strip_prefix("admin-").unwrap();
    let _: Uuid = suffix.parse().unwrap();
}

#[test]
fn stream_id_from_str_eventstore_retention_round_trip() {
    use std::str::FromStr;
    let sid = StreamId::eventstore_retention();
    let display = sid.to_string();
    let parsed = StreamId::from_str(&display).unwrap();
    assert_eq!(parsed, sid);
    assert_eq!(parsed.to_string(), display);
    assert_eq!(parsed.category, StreamCategory::Admin);
}

// ---------------------------------------------------------------------------
// RefMoved / RefRetired events
// ---------------------------------------------------------------------------

use crate::entities::mutable_ref::RefTarget;

fn sample_ref_moved() -> RefMoved {
    RefMoved {
        ref_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        namespace: "library/nginx".into(),
        ref_name: "latest".into(),
        from: None,
        to: RefTarget::ContentHash(hash()),
    }
}

fn sample_ref_retired() -> RefRetired {
    RefRetired {
        ref_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        namespace: "library/nginx".into(),
        ref_name: "latest".into(),
        last_target: RefTarget::ContentHash(hash()),
    }
}

#[test]
fn event_type_ref_moved() {
    let e = DomainEvent::RefMoved(sample_ref_moved());
    assert_eq!(e.event_type(), "RefMoved");
}

#[test]
fn event_type_ref_retired() {
    let e = DomainEvent::RefRetired(sample_ref_retired());
    assert_eq!(e.event_type(), "RefRetired");
}

#[test]
fn ref_moved_validate_ok_first_placement() {
    // from: None models the initial creation of a ref.
    let e = sample_ref_moved();
    assert!(e.validate().is_ok());
}

#[test]
fn ref_moved_validate_ok_content_hash_move() {
    let e = RefMoved {
        from: Some(RefTarget::ContentHash(hash())),
        to: RefTarget::Version("1.2.3".into()),
        ..sample_ref_moved()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn ref_moved_validate_rejects_same_target() {
    // §2.4 — "Idempotent re-pointing is NOT an event." Emitting `RefMoved`
    // with `from == Some(to)` is a caller mistake; the domain rejects it
    // as an Invariant violation.
    let target = RefTarget::Version("1.2.3".into());
    let e = RefMoved {
        from: Some(target.clone()),
        to: target,
        ..sample_ref_moved()
    };
    let err = e.validate().unwrap_err();
    assert!(matches!(err, DomainError::Invariant(_)));
    assert!(err.to_string().to_lowercase().contains("same"));
}

#[test]
fn ref_moved_validate_rejects_empty_namespace() {
    let e = RefMoved {
        namespace: String::new(),
        ..sample_ref_moved()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_moved_validate_rejects_over_long_namespace() {
    let e = RefMoved {
        namespace: "n".repeat(513),
        ..sample_ref_moved()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_moved_validate_namespace_at_limit_ok() {
    let e = RefMoved {
        namespace: "n".repeat(512),
        ..sample_ref_moved()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn ref_moved_validate_rejects_empty_ref_name() {
    let e = RefMoved {
        ref_name: String::new(),
        ..sample_ref_moved()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_moved_validate_rejects_over_long_ref_name() {
    let e = RefMoved {
        ref_name: "r".repeat(513),
        ..sample_ref_moved()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_moved_validate_ref_name_at_limit_ok() {
    let e = RefMoved {
        ref_name: "r".repeat(512),
        ..sample_ref_moved()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn ref_retired_validate_ok() {
    assert!(sample_ref_retired().validate().is_ok());
}

#[test]
fn ref_retired_validate_rejects_empty_namespace() {
    let e = RefRetired {
        namespace: String::new(),
        ..sample_ref_retired()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_retired_validate_rejects_over_long_namespace() {
    let e = RefRetired {
        namespace: "n".repeat(513),
        ..sample_ref_retired()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_retired_validate_namespace_at_limit_ok() {
    let e = RefRetired {
        namespace: "n".repeat(512),
        ..sample_ref_retired()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn ref_retired_validate_rejects_empty_ref_name() {
    let e = RefRetired {
        ref_name: String::new(),
        ..sample_ref_retired()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_retired_validate_rejects_over_long_ref_name() {
    let e = RefRetired {
        ref_name: "r".repeat(513),
        ..sample_ref_retired()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn ref_retired_validate_ref_name_at_limit_ok() {
    let e = RefRetired {
        ref_name: "r".repeat(512),
        ..sample_ref_retired()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn serde_roundtrip_ref_moved_first_placement() {
    let event = DomainEvent::RefMoved(RefMoved {
        from: None,
        ..sample_ref_moved()
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_ref_moved_with_prior_target() {
    let event = DomainEvent::RefMoved(RefMoved {
        from: Some(RefTarget::ContentHash(hash())),
        to: RefTarget::Version("2.0.0".into()),
        ..sample_ref_moved()
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_ref_retired() {
    let event = DomainEvent::RefRetired(sample_ref_retired());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn domain_event_validate_delegates_to_ref_moved() {
    // Drive the DomainEvent::RefMoved => e.validate() dispatcher arm —
    // bad payload must surface as an Err through the enum's validate().
    let bad = RefMoved {
        namespace: String::new(),
        ..sample_ref_moved()
    };
    let invalid = DomainEvent::RefMoved(bad);
    assert!(invalid.validate().is_err());
}

#[test]
fn domain_event_validate_delegates_to_ref_retired() {
    let bad = RefRetired {
        ref_name: String::new(),
        ..sample_ref_retired()
    };
    let invalid = DomainEvent::RefRetired(bad);
    assert!(invalid.validate().is_err());
}

// ---------------------------------------------------------------------------
// ArtifactGroup events
// ---------------------------------------------------------------------------

use crate::entities::repository::RepositoryFormat;
use crate::types::ArtifactCoords;

fn sample_coords() -> ArtifactCoords {
    ArtifactCoords {
        name: "my-pkg".into(),
        name_as_published: "My_Pkg".into(),
        version: Some("1.2.3".into()),
        path: String::new(),
        format: RepositoryFormat::Maven,
        metadata: serde_json::Value::Null,
    }
}

fn sample_group_initiated() -> ArtifactGroupInitiated {
    ArtifactGroupInitiated {
        group_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        coords: sample_coords(),
        primary_role: "pom".into(),
    }
}

fn sample_group_member_added() -> ArtifactGroupMemberAdded {
    ArtifactGroupMemberAdded {
        group_id: Uuid::new_v4(),
        role: "jar".into(),
        artifact_id: Uuid::new_v4(),
    }
}

fn sample_group_member_removed() -> ArtifactGroupMemberRemoved {
    ArtifactGroupMemberRemoved {
        group_id: Uuid::new_v4(),
        artifact_id: Uuid::new_v4(),
        reason: Some("admin removed stale sidecar".into()),
    }
}

fn sample_group_primary_role_assigned() -> ArtifactGroupPrimaryRoleAssigned {
    ArtifactGroupPrimaryRoleAssigned {
        group_id: Uuid::new_v4(),
        primary_role: "pom".into(),
    }
}

// -- event_type() ------------------------------------------------------------

#[test]
fn event_type_artifact_group_initiated() {
    let e = DomainEvent::ArtifactGroupInitiated(sample_group_initiated());
    assert_eq!(e.event_type(), "ArtifactGroupInitiated");
}

#[test]
fn event_type_artifact_group_member_added() {
    let e = DomainEvent::ArtifactGroupMemberAdded(sample_group_member_added());
    assert_eq!(e.event_type(), "ArtifactGroupMemberAdded");
}

#[test]
fn event_type_artifact_group_member_removed() {
    let e = DomainEvent::ArtifactGroupMemberRemoved(sample_group_member_removed());
    assert_eq!(e.event_type(), "ArtifactGroupMemberRemoved");
}

#[test]
fn event_type_artifact_group_primary_role_assigned() {
    let e = DomainEvent::ArtifactGroupPrimaryRoleAssigned(sample_group_primary_role_assigned());
    assert_eq!(e.event_type(), "ArtifactGroupPrimaryRoleAssigned");
}

// -- validate() happy paths -------------------------------------------------

#[test]
fn artifact_group_initiated_validate_ok_with_primary() {
    assert!(sample_group_initiated().validate().is_ok());
}

#[test]
fn artifact_group_initiated_validate_ok_empty_primary_role_sentinel() {
    // §2.10 case 2: first member is not primary → group created with
    // `primary_role = ""` sentinel. The empty string is explicitly valid
    // here — it is the signal that no primary has been assigned yet.
    let e = ArtifactGroupInitiated {
        primary_role: String::new(),
        ..sample_group_initiated()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_initiated_validate_primary_role_at_limit() {
    let e = ArtifactGroupInitiated {
        primary_role: "p".repeat(128),
        ..sample_group_initiated()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_initiated_validate_rejects_over_long_primary_role() {
    let e = ArtifactGroupInitiated {
        primary_role: "p".repeat(129),
        ..sample_group_initiated()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_member_added_validate_ok() {
    assert!(sample_group_member_added().validate().is_ok());
}

#[test]
fn artifact_group_member_added_validate_rejects_empty_role() {
    let e = ArtifactGroupMemberAdded {
        role: String::new(),
        ..sample_group_member_added()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_member_added_validate_role_at_limit() {
    let e = ArtifactGroupMemberAdded {
        role: "r".repeat(128),
        ..sample_group_member_added()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_member_added_validate_rejects_over_long_role() {
    let e = ArtifactGroupMemberAdded {
        role: "r".repeat(129),
        ..sample_group_member_added()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_member_removed_validate_ok_with_reason() {
    assert!(sample_group_member_removed().validate().is_ok());
}

#[test]
fn artifact_group_member_removed_validate_ok_without_reason() {
    let e = ArtifactGroupMemberRemoved {
        reason: None,
        ..sample_group_member_removed()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_member_removed_validate_reason_at_limit() {
    let e = ArtifactGroupMemberRemoved {
        reason: Some("r".repeat(512)),
        ..sample_group_member_removed()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_member_removed_validate_rejects_over_long_reason() {
    let e = ArtifactGroupMemberRemoved {
        reason: Some("r".repeat(513)),
        ..sample_group_member_removed()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_member_removed_validate_rejects_empty_reason() {
    // `Option<String>` semantics: `None` means "no reason"; `Some("")` is
    // a caller bug — use `None`. Mirrors `validate_optional_string`.
    let e = ArtifactGroupMemberRemoved {
        reason: Some(String::new()),
        ..sample_group_member_removed()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_primary_role_assigned_validate_ok() {
    assert!(sample_group_primary_role_assigned().validate().is_ok());
}

#[test]
fn artifact_group_primary_role_assigned_validate_rejects_empty_primary_role() {
    // The whole point of this event is to ASSIGN a role — emitting it with
    // an empty string would be a meaningless no-op. Reject at the boundary.
    let e = ArtifactGroupPrimaryRoleAssigned {
        primary_role: String::new(),
        ..sample_group_primary_role_assigned()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn artifact_group_primary_role_assigned_validate_primary_role_at_limit() {
    let e = ArtifactGroupPrimaryRoleAssigned {
        primary_role: "p".repeat(128),
        ..sample_group_primary_role_assigned()
    };
    assert!(e.validate().is_ok());
}

#[test]
fn artifact_group_primary_role_assigned_validate_rejects_over_long_primary_role() {
    let e = ArtifactGroupPrimaryRoleAssigned {
        primary_role: "p".repeat(129),
        ..sample_group_primary_role_assigned()
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

// -- DomainEvent::validate() dispatcher coverage -----------------------------

#[test]
fn domain_event_validate_delegates_to_artifact_group_initiated() {
    let bad = ArtifactGroupInitiated {
        primary_role: "p".repeat(129),
        ..sample_group_initiated()
    };
    let invalid = DomainEvent::ArtifactGroupInitiated(bad);
    assert!(invalid.validate().is_err());
}

#[test]
fn domain_event_validate_delegates_to_artifact_group_member_added() {
    let bad = ArtifactGroupMemberAdded {
        role: String::new(),
        ..sample_group_member_added()
    };
    let invalid = DomainEvent::ArtifactGroupMemberAdded(bad);
    assert!(invalid.validate().is_err());
}

#[test]
fn domain_event_validate_delegates_to_artifact_group_member_removed() {
    let bad = ArtifactGroupMemberRemoved {
        reason: Some("r".repeat(513)),
        ..sample_group_member_removed()
    };
    let invalid = DomainEvent::ArtifactGroupMemberRemoved(bad);
    assert!(invalid.validate().is_err());
}

#[test]
fn domain_event_validate_delegates_to_artifact_group_primary_role_assigned() {
    let bad = ArtifactGroupPrimaryRoleAssigned {
        primary_role: String::new(),
        ..sample_group_primary_role_assigned()
    };
    let invalid = DomainEvent::ArtifactGroupPrimaryRoleAssigned(bad);
    assert!(invalid.validate().is_err());
}

// -- Serde round-trips through the tagged-enum wire format -------------------

#[test]
fn serde_roundtrip_artifact_group_initiated() {
    let event = DomainEvent::ArtifactGroupInitiated(sample_group_initiated());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_artifact_group_member_added() {
    let event = DomainEvent::ArtifactGroupMemberAdded(sample_group_member_added());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_artifact_group_member_removed_with_reason() {
    let event = DomainEvent::ArtifactGroupMemberRemoved(sample_group_member_removed());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_artifact_group_member_removed_without_reason() {
    let event = DomainEvent::ArtifactGroupMemberRemoved(ArtifactGroupMemberRemoved {
        reason: None,
        ..sample_group_member_removed()
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_artifact_group_primary_role_assigned() {
    let event = DomainEvent::ArtifactGroupPrimaryRoleAssigned(sample_group_primary_role_assigned());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn stream_id_from_str_invalid_category() {
    use std::str::FromStr;
    let id = Uuid::new_v4();
    let err = StreamId::from_str(&format!("unknown-{id}")).unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
    assert!(err.to_string().contains("unknown stream category"));
}

#[test]
fn stream_id_from_str_invalid_uuid() {
    use std::str::FromStr;
    let err = StreamId::from_str("artifact-not-a-uuid").unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
    assert!(err.to_string().contains("invalid UUID"));
}

#[test]
fn stream_id_from_str_no_separator() {
    use std::str::FromStr;
    let err = StreamId::from_str("noseparator").unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
}

#[test]
fn stream_id_from_str_empty() {
    use std::str::FromStr;
    let err = StreamId::from_str("").unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
}

// ---------------------------------------------------------------------------
// ApiActor
// ---------------------------------------------------------------------------

#[test]
fn api_actor_construction_and_display() {
    let uid = id();
    let actor = ApiActor { user_id: uid };
    assert_eq!(actor.user_id, uid);
    assert_eq!(actor.to_string(), format!("user:{uid}"));
}

#[test]
fn api_actor_clone_eq() {
    let actor = ApiActor { user_id: id() };
    let cloned = actor.clone();
    assert_eq!(actor, cloned);
}

// ---------------------------------------------------------------------------
// InternalActor
// ---------------------------------------------------------------------------

#[test]
fn internal_actor_system_display() {
    let actor = InternalActor::system(token());
    assert_eq!(actor.to_string(), "system");
}

#[test]
fn internal_actor_timer_display() {
    let actor = InternalActor::timer(token());
    assert_eq!(actor.to_string(), "timer");
}

#[test]
fn internal_actor_retention_scheduler_display() {
    // Wire form is `retention_scheduler` (matches the
    // `004_events.sql` actor-CHECK literal + the adapter mapper).
    let actor = InternalActor::retention_scheduler(token());
    assert_eq!(actor.to_string(), "retention_scheduler");
}

#[test]
fn internal_actor_clone_eq() {
    let a = InternalActor::System;
    let b = a.clone();
    assert_eq!(a, b);

    let c = InternalActor::Timer;
    assert_ne!(a, c);

    // RetentionScheduler is distinct from System/Timer.
    let d = InternalActor::RetentionScheduler;
    let e = d.clone();
    assert_eq!(d, e);
    assert_ne!(a, d);
    assert_ne!(c, d);
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

#[test]
fn actor_api_display() {
    let uid = Uuid::nil();
    let actor = Actor::Api(ApiActor { user_id: uid });
    assert_eq!(actor.to_string(), format!("user:{uid}"));
}

#[test]
fn actor_internal_system_display() {
    let actor = Actor::Internal(InternalActor::System);
    assert_eq!(actor.to_string(), "system");
}

#[test]
fn actor_internal_timer_display() {
    let actor = Actor::Internal(InternalActor::Timer);
    assert_eq!(actor.to_string(), "timer");
}

#[test]
fn actor_internal_retention_scheduler_display() {
    let actor = Actor::Internal(InternalActor::RetentionScheduler);
    assert_eq!(actor.to_string(), "retention_scheduler");
}

#[test]
fn actor_clone_eq() {
    let a = Actor::Api(ApiActor { user_id: id() });
    let b = a.clone();
    assert_eq!(a, b);

    let c = Actor::Internal(InternalActor::System);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// DomainEvent::event_type() — one per variant
// ---------------------------------------------------------------------------

fn sample_artifact_ingested() -> ArtifactIngested {
    ArtifactIngested {
        artifact_id: id(),
        repository_id: id(),
        name: "my-pkg".into(),
        version: Some("1.0.0".into()),
        sha256: hash(),
        size_bytes: 1024,
        source: IngestSource::Direct,
        metadata: serde_json::Value::Null,
        metadata_blob: None,
        upstream_published_at: None,
    }
}

fn sample_severity_summary() -> SeveritySummary {
    SeveritySummary {
        critical: 0,
        high: 0,
        medium: 1,
        low: 2,
        negligible: 0,
    }
}

#[test]
fn event_type_artifact_ingested() {
    let e = DomainEvent::ArtifactIngested(sample_artifact_ingested());
    assert_eq!(e.event_type(), "ArtifactIngested");
}

#[test]
fn event_type_checksum_verified() {
    let e = DomainEvent::ChecksumVerified(ChecksumVerified {
        artifact_id: id(),
        algorithm: crate::types::HashAlgorithm::Sha256,
        upstream_value: VALID_HASH.into(),
        computed_value: VALID_HASH.into(),
    });
    assert_eq!(e.event_type(), "ChecksumVerified");
}

#[test]
fn event_type_checksum_mismatch() {
    let e = DomainEvent::ChecksumMismatch(ChecksumMismatch {
        repository_id: id(),
        coords: sample_coords(),
        format: "pypi".into(),
        algorithm: crate::types::HashAlgorithm::Sha256,
        upstream_value: VALID_HASH.into(),
        computed_value: VALID_HASH.into(),
    });
    assert_eq!(e.event_type(), "ChecksumMismatch");
}

#[test]
fn event_type_artifact_quarantined() {
    let e = DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
        artifact_id: id(),
        quarantine_window_start: Utc::now(),
    });
    assert_eq!(e.event_type(), "ArtifactQuarantined");
}

#[test]
fn event_type_scan_requested() {
    let e = DomainEvent::ScanRequested(ScanRequested {
        artifact_id: id(),
        scanner: "trivy".into(),
    });
    assert_eq!(e.event_type(), "ScanRequested");
}

#[test]
fn event_type_scan_completed() {
    let e = DomainEvent::ScanCompleted(ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    });
    assert_eq!(e.event_type(), "ScanCompleted");
}

#[test]
fn event_type_artifact_released() {
    let e = DomainEvent::ArtifactReleased(ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Timer,
        released_by_user_id: None,
        justification: None,
    });
    assert_eq!(e.event_type(), "ArtifactReleased");
}

#[test]
fn event_type_artifact_rejected() {
    let e = DomainEvent::ArtifactRejected(ArtifactRejected {
        artifact_id: id(),
        rejected_by: RejectionReason::Scanner,
        reason: "CVE found".into(),
    });
    assert_eq!(e.event_type(), "ArtifactRejected");
}

#[test]
fn event_type_artifact_re_evaluated() {
    use crate::entities::artifact::QuarantineStatus;
    let e = DomainEvent::ArtifactReEvaluated(ArtifactReEvaluated {
        artifact_id: id(),
        policy_id: id(),
        trigger_exclusion_id: id(),
        previous_status: QuarantineStatus::Rejected,
        new_status: QuarantineStatus::Released,
    });
    assert_eq!(e.event_type(), "ArtifactReEvaluated");
    // validate() is pure metadata — must succeed.
    assert!(e.validate().is_ok());
}

#[test]
fn serde_roundtrip_artifact_re_evaluated() {
    use crate::entities::artifact::QuarantineStatus;
    let event = DomainEvent::ArtifactReEvaluated(ArtifactReEvaluated {
        artifact_id: id(),
        policy_id: id(),
        trigger_exclusion_id: id(),
        previous_status: QuarantineStatus::Rejected,
        new_status: QuarantineStatus::Quarantined,
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn event_type_promotion_requested() {
    let e = DomainEvent::PromotionRequested(PromotionRequested {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    });
    assert_eq!(e.event_type(), "PromotionRequested");
}

#[test]
fn event_type_policy_evaluated() {
    let e = DomainEvent::PolicyEvaluated(PolicyEvaluated {
        artifact_id: id(),
        policy_id: id(),
        result: PolicyResult::Pass,
        violations: vec![],
    });
    assert_eq!(e.event_type(), "PolicyEvaluated");
}

#[test]
fn event_type_approval_requested() {
    let e = DomainEvent::ApprovalRequested(ApprovalRequested {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    });
    assert_eq!(e.event_type(), "ApprovalRequested");
}

#[test]
fn event_type_approval_decided() {
    let e = DomainEvent::ApprovalDecided(ApprovalDecided {
        artifact_id: id(),
        decision: ApprovalDecision::Approved,
        notes: None,
    });
    assert_eq!(e.event_type(), "ApprovalDecided");
}

#[test]
fn event_type_artifact_promoted() {
    let e = DomainEvent::ArtifactPromoted(ArtifactPromoted {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    });
    assert_eq!(e.event_type(), "ArtifactPromoted");
}

#[test]
fn event_type_promotion_rejected() {
    let e = DomainEvent::PromotionRejected(PromotionRejected {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
        reason: "policy fail".into(),
    });
    assert_eq!(e.event_type(), "PromotionRejected");
}

#[test]
fn event_type_policy_created() {
    let e = DomainEvent::PolicyCreated(PolicyCreated {
        policy_id: id(),
        name: "default".into(),
        scope: PolicyScope::Global,
        config_snapshot: serde_json::json!({}),
    });
    assert_eq!(e.event_type(), "PolicyCreated");
}

#[test]
fn event_type_policy_updated() {
    let e = DomainEvent::PolicyUpdated(PolicyUpdated {
        policy_id: id(),
        field: PolicyField::Name,
        previous_value: serde_json::json!("old"),
        new_value: serde_json::json!("new"),
    });
    assert_eq!(e.event_type(), "PolicyUpdated");
}

#[test]
fn event_type_exclusion_added() {
    let e = DomainEvent::ExclusionAdded(ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: "CVE-2024-0001".into(),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "accepted risk".into(),
        expires_at: None,
    });
    assert_eq!(e.event_type(), "ExclusionAdded");
}

#[test]
fn event_type_exclusion_removed() {
    let e = DomainEvent::ExclusionRemoved(ExclusionRemoved {
        policy_id: id(),
        exclusion_id: id(),
        reason: "no longer needed".into(),
    });
    assert_eq!(e.event_type(), "ExclusionRemoved");
}

#[test]
fn event_type_policy_archived() {
    let e = DomainEvent::PolicyArchived(PolicyArchived { policy_id: id() });
    assert_eq!(e.event_type(), "PolicyArchived");
}

#[test]
fn event_type_policy_reactivated() {
    let e = DomainEvent::PolicyReactivated(PolicyReactivated { policy_id: id() });
    assert_eq!(e.event_type(), "PolicyReactivated");
}

// ---------------------------------------------------------------------------
// Serialisation round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_artifact_event() {
    let event = DomainEvent::ArtifactIngested(sample_artifact_ingested());
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// ArtifactIngested.metadata — round-trip coverage
// ---------------------------------------------------------------------------

#[test]
fn artifact_ingested_metadata_defaults_when_absent() {
    // Pre-field persisted events must deserialise cleanly via #[serde(default)].
    // A minimal payload without the `metadata` key must deserialise without
    // error; the default value matches `serde_json::Value::default()` (i.e.
    // `Null`). That's the important invariant — stable, backward-compatible
    // behaviour for v0 events that predate the field.
    let payload = serde_json::json!({
        "artifact_id": Uuid::nil().to_string(),
        "repository_id": Uuid::nil().to_string(),
        "name": "pkg",
        "version": "1.0.0",
        "sha256": VALID_HASH,
        "size_bytes": 42,
        "source": "Direct",
    });
    let json = payload.to_string();
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(back.metadata, serde_json::Value::default());
    assert_eq!(back.name, "pkg");
}

#[test]
fn artifact_ingested_roundtrip_trivial_metadata() {
    let mut event = sample_artifact_ingested();
    event.metadata = serde_json::json!({"requires_python": ">=3.8"});
    let json = serde_json::to_string(&event).unwrap();
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.metadata["requires_python"], ">=3.8");
}

#[test]
fn artifact_ingested_roundtrip_large_metadata() {
    // ~100 KB payload — well under the 1 MB event-payload ceiling but big
    // enough to catch any naive per-field size assumption in serde.
    let big_description = "x".repeat(100 * 1024);
    let mut event = sample_artifact_ingested();
    event.metadata = serde_json::json!({
        "pkg_info": {
            "name": "huge-pkg",
            "description": big_description,
        }
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(
        back.metadata["pkg_info"]["description"]
            .as_str()
            .unwrap()
            .len(),
        100 * 1024
    );
}

// ---------------------------------------------------------------------------
// ArtifactIngested.metadata_blob — round-trip coverage
// ---------------------------------------------------------------------------

/// Today's shape: `metadata=Null`, `metadata_blob=None`. The field must
/// serialize to `null` and round-trip cleanly — the same shape the
/// inline-`metadata` form
/// left us with, re-verified now that a second optional field rides
/// alongside `metadata` in the event payload.
#[test]
fn artifact_ingested_roundtrip_null_metadata_no_blob() {
    let event = sample_artifact_ingested();
    assert_eq!(event.metadata, serde_json::Value::Null);
    assert_eq!(event.metadata_blob, None);
    let json = serde_json::to_string(&event).unwrap();
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.metadata_blob, None);
}

/// Inline strategy shape: full payload lives in `metadata`, blob stays
/// `None`. The blob field must not appear on the wire as anything other
/// than a bare `null` — JSON consumers outside the crate rely on that.
#[test]
fn artifact_ingested_roundtrip_inline_metadata_no_blob() {
    let mut event = sample_artifact_ingested();
    event.metadata = serde_json::json!({"requires_python": ">=3.8"});
    event.metadata_blob = None;
    let json = serde_json::to_string(&event).unwrap();
    // On-wire: metadata_blob must serialise as JSON `null`.
    let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(raw["metadata_blob"], serde_json::Value::Null);
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.metadata_blob, None);
}

/// HashReference strategy shape: `metadata` carries the summary, `metadata_blob`
/// carries a `ContentHash` pointing at the full payload in CAS. The hash
/// must serialise as the 64-char hex string (same wire shape as `sha256`)
/// and deserialise back into a `ContentHash` with validation applied.
#[test]
fn artifact_ingested_roundtrip_summary_metadata_with_blob() {
    let mut event = sample_artifact_ingested();
    event.metadata = serde_json::json!({"dist-tags": {"latest": "1.0.0"}});
    event.metadata_blob = Some(hash());
    let json = serde_json::to_string(&event).unwrap();
    // On-wire: metadata_blob must serialise as the 64-char hex string.
    let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        raw["metadata_blob"],
        serde_json::Value::String(VALID_HASH.into())
    );
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.metadata_blob, Some(hash()));
}

/// Pre-field persisted JSON (`metadata` present but
/// no `metadata_blob` key) must deserialise cleanly via `#[serde(default)]`.
/// This is the forward-compat contract that lets events written before
/// the field existed replay under current code without rewriting the
/// immutable event log.
#[test]
fn artifact_ingested_metadata_blob_defaults_when_absent() {
    let payload = serde_json::json!({
        "artifact_id": Uuid::nil().to_string(),
        "repository_id": Uuid::nil().to_string(),
        "name": "pkg",
        "version": "1.0.0",
        "sha256": VALID_HASH,
        "size_bytes": 42,
        "source": "Direct",
        "metadata": {"requires_python": ">=3.8"},
        // no "metadata_blob" key — the older persisted shape
    });
    let json = payload.to_string();
    let back: ArtifactIngested = serde_json::from_str(&json).unwrap();
    assert_eq!(back.metadata_blob, None);
    assert_eq!(back.metadata["requires_python"], ">=3.8");
}

#[test]
fn serde_roundtrip_policy_event() {
    let event = DomainEvent::PolicyCreated(PolicyCreated {
        policy_id: Uuid::nil(),
        name: "test-policy".into(),
        scope: PolicyScope::Repository(Uuid::nil()),
        config_snapshot: serde_json::json!({"threshold": "high"}),
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_scan_completed() {
    let event = DomainEvent::ScanCompleted(ScanCompleted {
        artifact_id: Uuid::nil(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// PersistedEvent
// ---------------------------------------------------------------------------

#[test]
fn persisted_event_clone_eq() {
    let pe = PersistedEvent {
        event_id: Uuid::nil(),
        stream_id: StreamId::artifact(Uuid::nil()),
        stream_position: 0,
        global_position: 42,
        event: DomainEvent::ArtifactIngested(sample_artifact_ingested()),
        correlation_id: Uuid::nil(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::nil(),
        }),
        event_version: 1,
        stored_at: Utc::now(),
    };
    let cloned = pe.clone();
    assert_eq!(pe, cloned);
}

#[test]
fn persisted_event_with_causation_id() {
    let causation = Uuid::new_v4();
    let pe = PersistedEvent {
        event_id: Uuid::nil(),
        stream_id: StreamId::policy(Uuid::nil()),
        stream_position: 5,
        global_position: 100,
        event: DomainEvent::PolicyArchived(PolicyArchived {
            policy_id: Uuid::nil(),
        }),
        correlation_id: Uuid::nil(),
        causation_id: Some(causation),
        actor: Actor::Internal(InternalActor::System),
        event_version: 2,
        stored_at: Utc::now(),
    };
    assert_eq!(pe.causation_id, Some(causation));
    assert_eq!(pe.event_version, 2);
}

// ---------------------------------------------------------------------------
// SeveritySummary
// ---------------------------------------------------------------------------

#[test]
fn severity_summary_zero() {
    let ss = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    assert!(ss.validate().is_ok());
}

#[test]
fn severity_summary_at_max() {
    let ss = SeveritySummary {
        critical: 100_000,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    assert!(ss.validate().is_ok());
}

#[test]
fn severity_summary_over_max() {
    let ss = SeveritySummary {
        critical: 100_001,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    assert!(ss.validate().is_err());
}

#[test]
fn severity_summary_each_field_over_max() {
    for field in ["high", "medium", "low", "negligible"] {
        let mut ss = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        match field {
            "high" => ss.high = 100_001,
            "medium" => ss.medium = 100_001,
            "low" => ss.low = 100_001,
            "negligible" => ss.negligible = 100_001,
            _ => unreachable!(),
        }
        let err = ss.validate().unwrap_err();
        assert!(
            err.to_string().contains(field),
            "expected error to mention {field}, got: {err}"
        );
    }
}

#[test]
fn severity_summary_clone_eq() {
    let ss = sample_severity_summary();
    let cloned = ss.clone();
    assert_eq!(ss, cloned);
}

// ---------------------------------------------------------------------------
// Helper enums — clone, eq, serialise
// ---------------------------------------------------------------------------

#[test]
fn ingest_source_clone_eq_serde() {
    let a = IngestSource::Direct;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(a, IngestSource::Proxied);

    let json = serde_json::to_string(&a).unwrap();
    let back: IngestSource = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn release_reason_clone_eq_serde() {
    // Note: this is a fixed-array literal — adding a new `ReleaseReason`
    // variant does NOT compile-force inclusion here. `Curator` was the
    // most recent addition; if a future variant is added, append it below
    // so the Clone/Eq/Serde round-trip is exercised for every reason.
    for reason in [
        ReleaseReason::Timer,
        ReleaseReason::Admin,
        ReleaseReason::PolicyReEvaluation,
        ReleaseReason::Curator,
    ] {
        let cloned = reason.clone();
        assert_eq!(reason, cloned);
        let json = serde_json::to_string(&reason).unwrap();
        let back: ReleaseReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }
}

#[test]
fn rejection_reason_clone_eq_serde() {
    let rule_id = Uuid::new_v4();
    let curator_id = Uuid::new_v4();
    for src in [
        RejectionReason::Scanner,
        RejectionReason::Admin,
        RejectionReason::CurationRetroactive { rule_id },
        // Manual-curator variant.
        RejectionReason::Curator { curator_id },
    ] {
        let cloned = src.clone();
        assert_eq!(src, cloned);
        let json = serde_json::to_string(&src).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }
}

/// Verify the JSONB roundtrip on the manual-curator tuple variant
/// (event store persists `rejected_by` as JSONB). Mirrors the
/// `CurationRetroactive` payload-pin pattern.
#[test]
fn rejection_reason_curator_serde_carries_curator_id() {
    let curator_id = Uuid::new_v4();
    let original = RejectionReason::Curator { curator_id };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Curator"));
    assert!(json.contains(&curator_id.to_string()));
    let back: RejectionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(original, back);
}

#[test]
fn rejection_reason_curation_retroactive_serde_carries_rule_id() {
    // Verify the JSONB roundtrip on the retroactive-curation
    // tuple variant. The event store persists `rejected_by` as a
    // JSONB column; a missing or mistyped Deserialize derive on a
    // future variant is what this test catches.
    let rule_id = Uuid::new_v4();
    let original = RejectionReason::CurationRetroactive { rule_id };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("CurationRetroactive"));
    assert!(json.contains(&rule_id.to_string()));
    let back: RejectionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(original, back);
}

#[test]
fn policy_result_clone_eq_serde() {
    for r in [PolicyResult::Pass, PolicyResult::Fail] {
        let c = r; // Copy
        assert_eq!(r, c);
        let json = serde_json::to_string(&r).unwrap();
        let back: PolicyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn policy_scope_clone_eq_serde() {
    let global = PolicyScope::Global;
    let repo = PolicyScope::Repository(Uuid::nil());
    assert_ne!(global, repo);
    for scope in [global, repo] {
        let cloned = scope.clone();
        assert_eq!(scope, cloned);
        let json = serde_json::to_string(&scope).unwrap();
        let back: PolicyScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }
}

#[test]
fn approval_decision_clone_eq_serde() {
    for d in [ApprovalDecision::Approved, ApprovalDecision::Rejected] {
        let c = d; // Copy
        assert_eq!(d, c);
        let json = serde_json::to_string(&d).unwrap();
        let back: ApprovalDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn policy_field_clone_eq_serde() {
    let fields = [
        PolicyField::Name,
        PolicyField::Scope,
        PolicyField::SeverityThreshold,
        PolicyField::QuarantineDuration,
        PolicyField::RequireApproval,
        PolicyField::ProvenanceMode,
        PolicyField::ProvenanceBackends,
        PolicyField::ProvenanceIdentities,
        PolicyField::MaxArtifactAge,
        PolicyField::LicensePolicy,
        PolicyField::ScanBackends,
        PolicyField::RescanIntervalHours,
    ];
    for field in fields {
        let cloned = field.clone();
        assert_eq!(field, cloned);
        let json = serde_json::to_string(&field).unwrap();
        let back: PolicyField = serde_json::from_str(&json).unwrap();
        assert_eq!(field, back);
    }
}

// ---------------------------------------------------------------------------
// Validation tests — artifact events
// ---------------------------------------------------------------------------

#[test]
fn validate_artifact_ingested_name_at_limit() {
    let mut e = sample_artifact_ingested();
    e.name = "x".repeat(1024);
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_ingested_name_over_limit() {
    let mut e = sample_artifact_ingested();
    e.name = "x".repeat(1025);
    assert!(e.validate().is_err());
}

#[test]
fn validate_artifact_ingested_version_over_limit() {
    let mut e = sample_artifact_ingested();
    e.version = Some("v".repeat(1025));
    assert!(e.validate().is_err());
}

#[test]
fn validate_artifact_rejected_reason_at_limit() {
    let e = ArtifactRejected {
        artifact_id: id(),
        rejected_by: RejectionReason::Scanner,
        reason: "r".repeat(4096),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_rejected_reason_over_limit() {
    let e = ArtifactRejected {
        artifact_id: id(),
        rejected_by: RejectionReason::Scanner,
        reason: "r".repeat(4097),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_scan_requested_scanner_over_limit() {
    let e = ScanRequested {
        artifact_id: id(),
        scanner: "s".repeat(257),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_scan_completed_finding_count_mismatch() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 999,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    };
    let err = e.validate().unwrap_err();
    assert!(err.to_string().contains("finding_count"));
}

#[test]
fn validate_scan_completed_valid() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    };
    assert!(e.validate().is_ok());
}

// ---------------------------------------------------------------------------
// ScanCompleted.findings_blob invariant
//
// `findings_blob.is_some() == (finding_count > 0)` — clean scans never
// reference a blob; non-clean scans always do. Both directions of the
// invariant must error.
// ---------------------------------------------------------------------------

#[test]
fn scan_completed_validate_rejects_findings_blob_set_with_zero_findings() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 0,
        severity_summary: SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        },
        findings_blob: Some(hash()),
    };
    let err = e.validate().unwrap_err();
    assert!(
        err.to_string().contains("findings_blob"),
        "error should mention findings_blob, got: {err}"
    );
}

#[test]
fn scan_completed_validate_rejects_finding_count_positive_with_no_findings_blob() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: None,
    };
    let err = e.validate().unwrap_err();
    assert!(
        err.to_string().contains("findings_blob"),
        "error should mention findings_blob, got: {err}"
    );
}

#[test]
fn scan_completed_validate_accepts_zero_findings_with_no_blob() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 0,
        severity_summary: SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        },
        findings_blob: None,
    };
    assert!(e.validate().is_ok());
}

#[test]
fn scan_completed_validate_accepts_positive_findings_with_blob() {
    let e = ScanCompleted {
        artifact_id: id(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    };
    assert!(e.validate().is_ok());
}

/// Forward-compat: pre-Item-2 persisted `ScanCompleted` JSON (no
/// `findings_blob` key) must deserialise cleanly via `#[serde(default)]`.
/// Mirrors `artifact_ingested_metadata_blob_defaults_when_absent` — the
/// `UpstreamPublishedChecksum::deserialize_without_re_validating`
/// precedent — so events written before the field existed replay under
/// current code without rewriting the immutable event log.
#[test]
fn scan_completed_deserialises_old_shape_without_findings_blob() {
    let raw = serde_json::json!({
        "artifact_id": "00000000-0000-0000-0000-000000000000",
        "scanner": "trivy",
        "finding_count": 0,
        "severity_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0
        }
    })
    .to_string();
    let parsed: ScanCompleted = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed.findings_blob, None);
    assert_eq!(parsed.finding_count, 0);
}

#[test]
fn scan_completed_round_trips_with_findings_blob_some() {
    let event = ScanCompleted {
        artifact_id: Uuid::nil(),
        scanner: "trivy".into(),
        finding_count: 3,
        severity_summary: sample_severity_summary(),
        findings_blob: Some(hash()),
    };
    let json = serde_json::to_string(&event).unwrap();
    // On-wire: findings_blob must serialise as the 64-char hex string.
    let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        raw["findings_blob"],
        serde_json::Value::String(VALID_HASH.into())
    );
    let back: ScanCompleted = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.findings_blob, Some(hash()));
}

#[test]
fn scan_completed_round_trips_with_findings_blob_none() {
    let event = ScanCompleted {
        artifact_id: Uuid::nil(),
        scanner: "trivy".into(),
        finding_count: 0,
        severity_summary: SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        },
        findings_blob: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ScanCompleted = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.findings_blob, None);
}

// ---------------------------------------------------------------------------
// ArtifactBecameVulnerable
// ---------------------------------------------------------------------------

fn sample_finding() -> crate::types::Finding {
    crate::types::Finding {
        purl: "pkg:npm/lodash@4.17.20".into(),
        vulnerability_id: "CVE-2021-23337".into(),
        severity: crate::entities::scan_policy::SeverityThreshold::High,
        cvss_score: Some(7.2),
        title: "Command Injection in lodash".into(),
        fixed_versions: vec!["4.17.21".into()],
        source_scanner: "trivy".into(),
        references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".into()],
        aliases: vec!["GHSA-35jh-r3h4-6jhm".into()],
    }
}

#[test]
fn artifact_became_vulnerable_round_trips_through_serde() {
    let event = ArtifactBecameVulnerable {
        artifact_id: Uuid::new_v4(),
        new_findings: vec![sample_finding()],
        previously_clean_at: Utc::now(),
    };
    let wrapped = DomainEvent::ArtifactBecameVulnerable(event.clone());
    let json = serde_json::to_string(&wrapped).unwrap();
    let back: DomainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, wrapped);
    assert_eq!(back.event_type(), "ArtifactBecameVulnerable");
    if let DomainEvent::ArtifactBecameVulnerable(inner) = back {
        assert_eq!(inner, event);
    } else {
        panic!("variant mismatch after round-trip");
    }
}

#[test]
fn artifact_became_vulnerable_validate_rejects_empty_new_findings() {
    let e = ArtifactBecameVulnerable {
        artifact_id: id(),
        new_findings: vec![],
        previously_clean_at: Utc::now(),
    };
    let err = e.validate().unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
    assert!(
        err.to_string().contains("at least one new finding"),
        "error must name the invariant; got: {err}"
    );
}

#[test]
fn artifact_became_vulnerable_validate_propagates_finding_validation_failure() {
    let mut bad = sample_finding();
    bad.purl = "x".repeat(600); // exceeds Finding's MAX_PURL_LEN of 512
    let e = ArtifactBecameVulnerable {
        artifact_id: id(),
        new_findings: vec![bad],
        previously_clean_at: Utc::now(),
    };
    let err = e.validate().unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("purl"),
        "error propagates finding error: {msg}"
    );
}

#[test]
fn artifact_became_vulnerable_validate_accepts_single_valid_finding() {
    let e = ArtifactBecameVulnerable {
        artifact_id: id(),
        new_findings: vec![sample_finding()],
        previously_clean_at: Utc::now(),
    };
    e.validate().unwrap();
}

#[test]
fn event_type_for_artifact_became_vulnerable_returns_canonical_name() {
    let e = DomainEvent::ArtifactBecameVulnerable(ArtifactBecameVulnerable {
        artifact_id: Uuid::nil(),
        new_findings: vec![sample_finding()],
        previously_clean_at: Utc::now(),
    });
    assert_eq!(e.event_type(), "ArtifactBecameVulnerable");
}

#[test]
fn validate_promotion_rejected_reason_over_limit() {
    let e = PromotionRejected {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
        reason: "r".repeat(4097),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_approval_decided_notes_over_limit() {
    let e = ApprovalDecided {
        artifact_id: id(),
        decision: ApprovalDecision::Approved,
        notes: Some("n".repeat(4097)),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_approval_decided_notes_none() {
    let e = ApprovalDecided {
        artifact_id: id(),
        decision: ApprovalDecision::Rejected,
        notes: None,
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_policy_evaluated_violation_rule_over_limit() {
    let e = PolicyEvaluated {
        artifact_id: id(),
        policy_id: id(),
        result: PolicyResult::Fail,
        violations: vec![PolicyViolation {
            rule: "r".repeat(257),
            severity: crate::entities::scan_policy::SeverityThreshold::Critical,
            message: "ok".into(),
            details: serde_json::Value::Null,
        }],
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_evaluated_violation_message_over_limit() {
    let e = PolicyEvaluated {
        artifact_id: id(),
        policy_id: id(),
        result: PolicyResult::Fail,
        violations: vec![PolicyViolation {
            rule: "ok".into(),
            severity: crate::entities::scan_policy::SeverityThreshold::Critical,
            message: "d".repeat(4097),
            details: serde_json::Value::Null,
        }],
    };
    assert!(e.validate().is_err());
}

/// The serialised `details` JSON blob is capped at 4 KiB. Per-field
/// `rule` + `message` pass; the JSON blob itself is over-cap.
#[test]
fn validate_policy_evaluated_violation_details_over_size_cap() {
    let big = serde_json::Value::String("x".repeat(5000));
    let e = PolicyEvaluated {
        artifact_id: id(),
        policy_id: id(),
        result: PolicyResult::Fail,
        violations: vec![PolicyViolation {
            rule: "ok".into(),
            severity: crate::entities::scan_policy::SeverityThreshold::Critical,
            message: "ok".into(),
            details: big,
        }],
    };
    let err = e.validate().unwrap_err();
    assert!(
        err.to_string().contains("details"),
        "expected details cap error, got: {err}"
    );
}

// -- Trivial validate() calls for full coverage --

#[test]
fn validate_checksum_verified() {
    let e = ChecksumVerified {
        artifact_id: id(),
        algorithm: crate::types::HashAlgorithm::Sha256,
        upstream_value: VALID_HASH.into(),
        computed_value: VALID_HASH.into(),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn checksum_verified_round_trips_through_serde() {
    let e = ChecksumVerified {
        artifact_id: Uuid::new_v4(),
        algorithm: crate::types::HashAlgorithm::Sha512,
        upstream_value: "a".repeat(128),
        computed_value: "a".repeat(128),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChecksumVerified = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn checksum_mismatch_round_trips_through_serde() {
    let e = ChecksumMismatch {
        repository_id: Uuid::new_v4(),
        coords: sample_coords(),
        format: "npm".into(),
        algorithm: crate::types::HashAlgorithm::Sha512,
        upstream_value: "a".repeat(128),
        computed_value: "b".repeat(128),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChecksumMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn validate_checksum_mismatch() {
    let e = ChecksumMismatch {
        repository_id: id(),
        coords: sample_coords(),
        format: "pypi".into(),
        algorithm: crate::types::HashAlgorithm::Sha256,
        upstream_value: VALID_HASH.into(),
        computed_value: "0".repeat(64),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_quarantined() {
    let e = ArtifactQuarantined {
        artifact_id: id(),
        quarantine_window_start: Utc::now(),
    };
    assert!(e.validate().is_ok());
}

// `ArtifactReleased`
// carries `released_by_user_id` + `justification` for the `Admin` reason;
// the timer / re-evaluation reasons MUST omit them. `validate()` enforces
// the variant invariant.

#[test]
fn validate_artifact_released_admin_with_attribution_ok() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Admin,
        released_by_user_id: Some(id()),
        justification: Some("CVE accepted: false-positive after manual review".into()),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_released_admin_missing_released_by_user_id_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Admin,
        released_by_user_id: None,
        justification: Some("anything".into()),
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_admin_missing_justification_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Admin,
        released_by_user_id: Some(id()),
        justification: None,
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_timer_no_attribution_ok() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Timer,
        released_by_user_id: None,
        justification: None,
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_released_timer_with_released_by_user_id_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Timer,
        released_by_user_id: Some(id()),
        justification: None,
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_timer_with_justification_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Timer,
        released_by_user_id: None,
        justification: Some("should not be set".into()),
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_policy_re_evaluation_no_attribution_ok() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::PolicyReEvaluation,
        released_by_user_id: None,
        justification: None,
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_released_policy_re_evaluation_with_released_by_user_id_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::PolicyReEvaluation,
        released_by_user_id: Some(id()),
        justification: None,
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_admin_oversize_justification_rejected() {
    // 513-byte justification — one over the 512-byte cap from §2.3.
    let oversized = "x".repeat(513);
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Admin,
        released_by_user_id: Some(id()),
        justification: Some(oversized),
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_admin_at_cap_justification_ok() {
    // 512-byte justification — at the cap, must be accepted.
    let at_cap = "x".repeat(512);
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Admin,
        released_by_user_id: Some(id()),
        justification: Some(at_cap),
    };
    assert!(e.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Curator branch of `ArtifactReleased::validate`.
//
// `ReleaseReason::Curator` shares the attribution requirement with
// `ReleaseReason::Admin` (both `released_by_user_id` and `justification`
// must be `Some`, justification ≤ 512 bytes). The variant invariant is
// asserted on the same `Admin | Curator` arm of `validate()`. These
// tests mirror the Admin suite above so the Curator branch carries the
// same coverage — including that the error messages render the
// *variant name* via `{:?}` (Debug), which is what auditors search for.
//
// The field was renamed `admin_id` → `released_by_user_id`
// to make it authority-neutral; the Curator suite asserts on the
// current field name accordingly.
// ---------------------------------------------------------------------------

#[test]
fn validate_artifact_released_curator_with_attribution_ok() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Curator,
        released_by_user_id: Some(id()),
        justification: Some("Curator waived: dev-only dependency, not shipped".into()),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_released_curator_missing_released_by_user_id_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Curator,
        released_by_user_id: None,
        justification: Some("anything".into()),
    };
    match e.validate() {
        Err(DomainError::Validation(msg)) => {
            // Error message renders the variant name via `{:?}` so
            // auditors can grep by reason.
            assert!(
                msg.contains("Curator"),
                "expected error message to mention `Curator` variant, got: {msg}"
            );
            assert!(
                msg.contains("released_by_user_id"),
                "expected error message to mention `released_by_user_id`, got: {msg}"
            );
        }
        other => panic!("expected Validation error, got {other:?}"),
    }
}

#[test]
fn validate_artifact_released_curator_missing_justification_rejected() {
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Curator,
        released_by_user_id: Some(id()),
        justification: None,
    };
    match e.validate() {
        Err(DomainError::Validation(msg)) => {
            assert!(
                msg.contains("Curator"),
                "expected error message to mention `Curator` variant, got: {msg}"
            );
            assert!(
                msg.contains("justification"),
                "expected error message to mention `justification`, got: {msg}"
            );
        }
        other => panic!("expected Validation error, got {other:?}"),
    }
}

#[test]
fn validate_artifact_released_curator_oversize_justification_rejected() {
    // 513-byte justification — one over the 512-byte cap from §2.3.
    let oversized = "x".repeat(513);
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Curator,
        released_by_user_id: Some(id()),
        justification: Some(oversized),
    };
    assert!(matches!(e.validate(), Err(DomainError::Validation(_))));
}

#[test]
fn validate_artifact_released_curator_at_cap_justification_ok() {
    // 512-byte justification — at the cap, must be accepted.
    let at_cap = "x".repeat(512);
    let e = ArtifactReleased {
        artifact_id: id(),
        released_by: ReleaseReason::Curator,
        released_by_user_id: Some(id()),
        justification: Some(at_cap),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_promotion_requested() {
    let e = PromotionRequested {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_approval_requested() {
    let e = ApprovalRequested {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_artifact_promoted() {
    let e = ArtifactPromoted {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
    };
    assert!(e.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Validation tests — policy events
// ---------------------------------------------------------------------------

#[test]
fn validate_policy_created_name_over_limit() {
    let e = PolicyCreated {
        policy_id: id(),
        name: "n".repeat(257),
        scope: PolicyScope::Global,
        config_snapshot: serde_json::json!({}),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_created_config_oversized() {
    // Build a JSON object bigger than 32 KB
    let big_string = "x".repeat(33_000);
    let e = PolicyCreated {
        policy_id: id(),
        name: "ok".into(),
        scope: PolicyScope::Global,
        config_snapshot: serde_json::json!({ "data": big_string }),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_created_config_too_deep() {
    // Build nested JSON deeper than 10 levels
    let mut val = serde_json::json!("leaf");
    for _ in 0..11 {
        val = serde_json::json!({ "nested": val });
    }
    let e = PolicyCreated {
        policy_id: id(),
        name: "ok".into(),
        scope: PolicyScope::Global,
        config_snapshot: val,
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_created_valid() {
    let e = PolicyCreated {
        policy_id: id(),
        name: "default".into(),
        scope: PolicyScope::Global,
        config_snapshot: serde_json::json!({"threshold": "high"}),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_policy_updated_value_oversized() {
    let big_string = "x".repeat(33_000);
    let e = PolicyUpdated {
        policy_id: id(),
        field: PolicyField::Name,
        previous_value: serde_json::json!("old"),
        new_value: serde_json::json!({ "data": big_string }),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_updated_valid() {
    let e = PolicyUpdated {
        policy_id: id(),
        field: PolicyField::SeverityThreshold,
        previous_value: serde_json::json!("medium"),
        new_value: serde_json::json!("high"),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_exclusion_added_cve_id_over_limit() {
    let e = ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: "C".repeat(65),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "ok".into(),
        expires_at: None,
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_added_package_pattern_over_limit() {
    let e = ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: "CVE-2024-0001".into(),
        package_pattern: Some("p".repeat(513)),
        scope: PolicyScope::Global,
        reason: "ok".into(),
        expires_at: None,
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_added_reason_over_limit() {
    let e = ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: "CVE-2024-0001".into(),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "r".repeat(4097),
        expires_at: None,
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_added_valid() {
    let e = ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: "CVE-2024-0001".into(),
        package_pattern: Some("my-pkg*".into()),
        scope: PolicyScope::Repository(id()),
        reason: "accepted".into(),
        expires_at: Some(Utc::now()),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_exclusion_removed_reason_over_limit() {
    let e = ExclusionRemoved {
        policy_id: id(),
        exclusion_id: id(),
        reason: "r".repeat(4097),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_removed_valid() {
    let e = ExclusionRemoved {
        policy_id: id(),
        exclusion_id: id(),
        reason: "no longer needed".into(),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_policy_archived() {
    let e = PolicyArchived { policy_id: id() };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_policy_reactivated() {
    let e = PolicyReactivated { policy_id: id() };
    assert!(e.validate().is_ok());
}

// ---------------------------------------------------------------------------
// DomainEvent::validate() delegation
// ---------------------------------------------------------------------------

#[test]
fn domain_event_validate_delegates_to_inner() {
    let valid = DomainEvent::ArtifactIngested(sample_artifact_ingested());
    assert!(valid.validate().is_ok());

    let mut bad = sample_artifact_ingested();
    bad.name = "x".repeat(1025);
    let invalid = DomainEvent::ArtifactIngested(bad);
    assert!(invalid.validate().is_err());
}

// ---------------------------------------------------------------------------
// Actor serialisation (serialize-only — no Deserialize by design)
// ---------------------------------------------------------------------------

#[test]
fn actor_serialize_api() {
    let actor = Actor::Api(ApiActor {
        user_id: Uuid::nil(),
    });
    let json = serde_json::to_string(&actor).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("Api").is_some());
    assert_eq!(val["Api"]["user_id"], Uuid::nil().to_string());
}

#[test]
fn actor_serialize_internal_system() {
    let actor = Actor::Internal(InternalActor::System);
    let json = serde_json::to_string(&actor).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("Internal").is_some());
    assert_eq!(val["Internal"], "System");
}

#[test]
fn actor_serialize_internal_timer() {
    let actor = Actor::Internal(InternalActor::Timer);
    let json = serde_json::to_string(&actor).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["Internal"], "Timer");
}

#[test]
fn actor_serialize_internal_retention_scheduler() {
    let actor = Actor::Internal(InternalActor::RetentionScheduler);
    let json = serde_json::to_string(&actor).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["Internal"], "RetentionScheduler");
}

// ---------------------------------------------------------------------------
// StreamId / StreamCategory serialisation (serialize-only)
// ---------------------------------------------------------------------------

#[test]
fn stream_id_serialize() {
    let sid = StreamId::artifact(Uuid::nil());
    let json = serde_json::to_string(&sid).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["category"], "Artifact");
    assert_eq!(val["entity_id"], Uuid::nil().to_string());
}

#[test]
fn stream_category_serialize() {
    let json_a = serde_json::to_string(&StreamCategory::Artifact).unwrap();
    let json_p = serde_json::to_string(&StreamCategory::Policy).unwrap();
    let json_admin = serde_json::to_string(&StreamCategory::Admin).unwrap();
    let json_curation = serde_json::to_string(&StreamCategory::Curation).unwrap();
    let json_repo = serde_json::to_string(&StreamCategory::Repository).unwrap();
    assert_eq!(json_a, "\"Artifact\"");
    assert_eq!(json_p, "\"Policy\"");
    assert_eq!(json_admin, "\"Admin\"");
    assert_eq!(json_curation, "\"Curation\"");
    assert_eq!(json_repo, "\"Repository\"");
}

// ---------------------------------------------------------------------------
// PersistedEvent serialisation (serialize-only — no Deserialize by design)
// ---------------------------------------------------------------------------

#[test]
fn persisted_event_serialize() {
    let pe = PersistedEvent {
        event_id: Uuid::nil(),
        stream_id: StreamId::artifact(Uuid::nil()),
        stream_position: 0,
        global_position: 1,
        event: DomainEvent::PolicyArchived(PolicyArchived {
            policy_id: Uuid::nil(),
        }),
        correlation_id: Uuid::nil(),
        causation_id: Some(Uuid::nil()),
        actor: Actor::Internal(InternalActor::Timer),
        event_version: 1,
        stored_at: Utc::now(),
    };
    let json = serde_json::to_string(&pe).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("event_id").is_some());
    assert!(val.get("stream_id").is_some());
    assert!(val.get("actor").is_some());
    assert_eq!(val["event_version"], 1);
    assert_eq!(val["causation_id"], Uuid::nil().to_string());
}

// ---------------------------------------------------------------------------
// PolicyViolation
// ---------------------------------------------------------------------------

#[test]
fn policy_violation_clone_eq() {
    let v = PolicyViolation {
        rule: "max-severity".into(),
        severity: crate::entities::scan_policy::SeverityThreshold::Critical,
        message: "critical > 0".into(),
        details: serde_json::json!({"count": 1}),
    };
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

// ---------------------------------------------------------------------------
// Validation: empty string rejection
// ---------------------------------------------------------------------------

#[test]
fn validate_artifact_ingested_empty_name() {
    let mut e = sample_artifact_ingested();
    e.name = String::new();
    let err = e.validate().unwrap_err();
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn validate_scan_requested_empty_scanner() {
    let e = ScanRequested {
        artifact_id: id(),
        scanner: String::new(),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_artifact_rejected_empty_reason() {
    let e = ArtifactRejected {
        artifact_id: id(),
        rejected_by: RejectionReason::Scanner,
        reason: String::new(),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_added_empty_cve_id() {
    let e = ExclusionAdded {
        policy_id: id(),
        exclusion_id: id(),
        cve_id: String::new(),
        package_pattern: None,
        scope: PolicyScope::Global,
        reason: "ok".into(),
        expires_at: None,
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_exclusion_removed_empty_reason() {
    let e = ExclusionRemoved {
        policy_id: id(),
        exclusion_id: id(),
        reason: String::new(),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_violation_empty_rule() {
    let v = PolicyViolation {
        rule: String::new(),
        severity: crate::entities::scan_policy::SeverityThreshold::Critical,
        message: "some message".into(),
        details: serde_json::Value::Null,
    };
    assert!(v.validate().is_err());
}

#[test]
fn validate_policy_violation_empty_message() {
    let v = PolicyViolation {
        rule: "some-rule".into(),
        severity: crate::entities::scan_policy::SeverityThreshold::Critical,
        message: String::new(),
        details: serde_json::Value::Null,
    };
    assert!(v.validate().is_err());
}

/// Happy-path cover: `PolicyViolation::validate` returning `Ok(())` —
/// otherwise uncovered because all other `validate_policy_violation_*`
/// tests exercise error paths via the `?` short-circuit.
#[test]
fn validate_policy_violation_ok() {
    let v = PolicyViolation {
        rule: "max-severity".into(),
        severity: crate::entities::scan_policy::SeverityThreshold::Critical,
        message: "critical > 0".into(),
        details: serde_json::json!({"count": 1, "max_allowed": 0}),
    };
    assert!(v.validate().is_ok());
}

/// Exercise `json_depth`'s `Array` arm via `validate_json` — covered
/// nowhere else because existing PolicyUpdated tests use scalar JSON
/// values (strings) which take the `_ => 0` branch.
#[test]
fn validate_policy_updated_accepts_nested_array_json() {
    let e = PolicyUpdated {
        policy_id: id(),
        field: PolicyField::SeverityThreshold,
        previous_value: serde_json::json!(["low", "medium"]),
        new_value: serde_json::json!(["medium", "high", "critical"]),
    };
    assert!(e.validate().is_ok());
}

#[test]
fn validate_promotion_rejected_empty_reason() {
    let e = PromotionRejected {
        artifact_id: id(),
        source_repository_id: id(),
        target_repository_id: id(),
        reason: String::new(),
    };
    assert!(e.validate().is_err());
}

#[test]
fn validate_policy_created_empty_name() {
    let e = PolicyCreated {
        policy_id: id(),
        name: String::new(),
        scope: PolicyScope::Global,
        config_snapshot: serde_json::json!({}),
    };
    assert!(e.validate().is_err());
}

// ---------------------------------------------------------------------------
// Validation error is DomainError::Validation
// ---------------------------------------------------------------------------

#[test]
fn validation_error_is_domain_validation() {
    let mut e = sample_artifact_ingested();
    e.name = "x".repeat(1025);
    let err = e.validate().unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
}

#[test]
fn validation_error_empty_string_is_domain_validation() {
    let mut e = sample_artifact_ingested();
    e.name = String::new();
    let err = e.validate().unwrap_err();
    assert!(matches!(err, DomainError::Validation(_)));
}

// -- Actor::from_persisted ---------------------------------------------------

#[test]
fn actor_from_persisted_api_with_id() {
    let uid = Uuid::new_v4();
    let actor = Actor::from_persisted("api", Some(uid)).unwrap();
    assert_eq!(actor, Actor::Api(ApiActor { user_id: uid }));
}

#[test]
fn actor_from_persisted_api_without_id_is_invariant() {
    let err = Actor::from_persisted("api", None).unwrap_err();
    assert!(matches!(err, DomainError::Invariant(_)));
    assert!(err.to_string().contains("api actor missing user_id"));
}

#[test]
fn actor_from_persisted_system() {
    let actor = Actor::from_persisted("system", None).unwrap();
    assert_eq!(actor, Actor::Internal(InternalActor::System));
}

#[test]
fn actor_from_persisted_timer() {
    let actor = Actor::from_persisted("timer", None).unwrap();
    assert_eq!(actor, Actor::Internal(InternalActor::Timer));
}

#[test]
fn actor_from_persisted_retention_scheduler() {
    // The no-actor-id internal-actor reconstruction.
    let actor = Actor::from_persisted("retention_scheduler", None).unwrap();
    assert_eq!(actor, Actor::Internal(InternalActor::RetentionScheduler));
}

#[test]
fn actor_from_persisted_internal_with_id_is_invariant() {
    let uid = Uuid::new_v4();
    // `retention_scheduler` joins the no-actor-id reject
    // group alongside `system` / `timer`.
    for variant in ["system", "timer", "retention_scheduler"] {
        let err = Actor::from_persisted(variant, Some(uid)).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("must not have actor_id"));
    }
}

#[test]
fn actor_from_persisted_unknown_type_is_invariant() {
    let err = Actor::from_persisted("admin", None).unwrap_err();
    assert!(matches!(err, DomainError::Invariant(_)));
    assert!(err.to_string().contains("unknown actor_type"));
}

// -- Actor factory functions -------------------------------------------------

#[test]
fn system_actor_returns_internal_system() {
    let actor = system_actor();
    assert_eq!(actor, Actor::Internal(InternalActor::System));
}

#[test]
fn timer_actor_returns_internal_timer() {
    let actor = timer_actor();
    assert_eq!(actor, Actor::Internal(InternalActor::Timer));
}

#[test]
fn retention_scheduler_actor_returns_internal_retention_scheduler() {
    // The sealed-token factory the task handlers use.
    let actor = retention_scheduler_actor();
    assert_eq!(actor, Actor::Internal(InternalActor::RetentionScheduler));
}

// -- GitOpsActor --------------------------------------------------------------

fn sample_gitops_actor() -> GitOpsActor {
    GitOpsActor {
        source_file: "repositories/npm-public.yaml".into(),
        spec_digest: [0xab; 32],
        applied_at: DateTime::<Utc>::UNIX_EPOCH,
    }
}

#[test]
fn gitops_actor_display_includes_source_file() {
    let actor = sample_gitops_actor();
    assert_eq!(actor.to_string(), "gitops:repositories/npm-public.yaml");
}

#[test]
fn actor_gitops_variant_displays_through_inner() {
    let actor = Actor::GitOps(sample_gitops_actor());
    assert_eq!(actor.to_string(), "gitops:repositories/npm-public.yaml");
}

#[test]
fn actor_from_persisted_gitops_constructs_variant() {
    let actor = Actor::from_persisted_gitops(
        "auth/admins.yaml".into(),
        [0xcd; 32],
        DateTime::<Utc>::UNIX_EPOCH,
    );
    match actor {
        Actor::GitOps(g) => {
            assert_eq!(g.source_file, "auth/admins.yaml");
            assert_eq!(g.spec_digest, [0xcd; 32]);
        }
        other => panic!("expected GitOps variant, got {other:?}"),
    }
}

#[test]
fn actor_from_persisted_rejects_gitops_kind_directing_to_helper() {
    // The two-argument signature can't see source_file/spec_digest, so
    // dispatching here would silently lose that data. Mapper must call
    // `Actor::from_persisted_gitops` instead — this test pins that
    // contract.
    let err = Actor::from_persisted("gitops", None).unwrap_err();
    assert!(matches!(err, DomainError::Invariant(_)));
    let msg = err.to_string();
    assert!(msg.contains("gitops"), "error mentions actor kind");
    assert!(
        msg.contains("from_persisted_gitops"),
        "error names the correct constructor: {msg}"
    );
}

#[test]
fn actor_from_persisted_rejects_gitops_with_actor_id() {
    // Same as above — `Some(_)` doesn't change the answer; the column
    // shape demands the helper.
    let err = Actor::from_persisted("gitops", Some(uuid::Uuid::nil())).unwrap_err();
    assert!(matches!(err, DomainError::Invariant(_)));
}

#[test]
fn gitops_actor_clone_eq() {
    let a = sample_gitops_actor();
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// OidcIssuer + ServiceAccount lifecycle
// ---------------------------------------------------------------------------
//
// Each new DomainEvent variant needs its `event_type()` arm exercised
// here. Round-trip and validation coverage live in the per-payload
// test modules (`oidc_issuer_events.rs`, `service_account_events.rs`).

#[test]
fn event_type_oidc_issuer_created() {
    let e = DomainEvent::OidcIssuerCreated(OidcIssuerCreated {
        issuer_id: id(),
        name: "github-actions".into(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "OidcIssuerCreated");
}

#[test]
fn event_type_oidc_issuer_updated() {
    let e = DomainEvent::OidcIssuerUpdated(OidcIssuerUpdated {
        issuer_id: id(),
        name: "github-actions".into(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "OidcIssuerUpdated");
}

#[test]
fn event_type_oidc_issuer_deleted() {
    let e = DomainEvent::OidcIssuerDeleted(OidcIssuerDeleted {
        issuer_id: id(),
        name: "github-actions".into(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "OidcIssuerDeleted");
}

#[test]
fn event_type_service_account_created() {
    let e = DomainEvent::ServiceAccountCreated(ServiceAccountCreated {
        service_account_id: id(),
        service_account_name: "ci-pypi-pusher".into(),
        backing_user_id: id(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "ServiceAccountCreated");
}

#[test]
fn event_type_service_account_updated() {
    let e = DomainEvent::ServiceAccountUpdated(ServiceAccountUpdated {
        service_account_id: id(),
        service_account_name: "ci-pypi-pusher".into(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "ServiceAccountUpdated");
}

#[test]
fn event_type_service_account_deleted() {
    let e = DomainEvent::ServiceAccountDeleted(ServiceAccountDeleted {
        service_account_id: id(),
        service_account_name: "ci-pypi-pusher".into(),
        backing_user_id: id(),
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "ServiceAccountDeleted");
}

#[test]
fn event_type_service_account_token_rotated() {
    let e = DomainEvent::ServiceAccountTokenRotated(ServiceAccountTokenRotated {
        service_account_id: id(),
        service_account_name: "ci-pypi-pusher".into(),
        token_id: id(),
        target_secret_namespace: "ci-system".into(),
        target_secret_name: "ci-hort-token".into(),
        format: SerdeSecretFormat::Dockerconfigjson,
        at: Utc::now(),
    });
    assert_eq!(e.event_type(), "ServiceAccountTokenRotated");
}
