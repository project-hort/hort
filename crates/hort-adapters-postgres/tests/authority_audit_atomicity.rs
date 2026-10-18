//! Authority-audit atomicity integration tests (ADR 0012 / ADR 0018).
//!
//! `PgAuthorityLifecycle` must commit the authority rows — the
//! gitops-managed `permission_grants` / `claim_mappings` partition, the
//! `oidc_issuers` upsert/delete set, the gitops-managed
//! `repository_upstream_mappings` set, the `service_accounts` aggregate
//! set — together with the audit events that attest them, in ONE
//! transaction. A failed append must leave the rows exactly as they
//! were: the five apply branches previously committed the row and
//! appended the event in a separate call, so an append failure left the
//! grant, mapping, issuer, upstream mapping or service account
//! **active with nothing in the authorization stream attesting it** —
//! and the retry could not repair it, because the next apply derives
//! its events from the prior rows, which already hold the change.
//!
//! The grant and claim-mapping **reconcile-semantics** tests live here
//! too (`*_commit_full_reconcile_*`, `*_commit_empty_set_*`,
//! `*_commit_does_not_touch_local_rows`, the round-trips). They were
//! inline `#[cfg(test)]` tests on `PgPermissionGrantRepository::save_managed`
//! / `PgClaimMappingRepository::save_managed`; those trait methods no
//! longer exist, so the tests moved onto the commit path — which is
//! strictly better coverage, because each now exercises the audit
//! append in the same transaction as the reconcile it asserts.
//!
//! Force-failure vector: `ExpectedVersion::Exact(n)` against a stream
//! whose real tail position is not `n`. `append_with_conn` reads the
//! tail and returns `DomainError::Conflict` *after* the row statements
//! have run on the same transaction — so the rollback this asserts is a
//! real rollback of executed DML, not an ordering artifact.
//!
//! `DATABASE_URL`-gated; self-skips on hosts without a database (suite
//! convention). Uses `isolated_db_from` (a per-test throwaway
//! database), which isolates the rows but not the server: creating and
//! migrating that database is cluster-global work (`CREATE DATABASE`,
//! the migration set's `CREATE ROLE`, the shared catalogs the
//! stale-database sweeper walks), so each test also carries the
//! workspace-wide `#[serial(hort_pg_db)]` key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test authority_audit_atomicity
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::authority_lifecycle::PgAuthorityLifecycle;
use hort_adapters_postgres::claim_mapping_repo::PgClaimMappingRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::permission_grant_repo::PgPermissionGrantRepository;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::service_account::{
    FallbackRotation, FederatedIdentity, SecretFormat, ServiceAccount,
};
use hort_domain::events::{
    system_actor, ClaimMappingApplied, DomainEvent, GrantSubjectRecord, OidcIssuerCreated,
    OidcIssuerDeleted, PermissionGrantApplied, PermissionGrantRevoked,
    RepositoryUpstreamMappingChanged, ServiceAccountCreated, ServiceAccountDeleted, StreamId,
    UpstreamMappingChange,
};
use hort_domain::ports::authority_lifecycle::{
    AuthorityLifecyclePort, OidcIssuerChange, ServiceAccountCommit, UpstreamMappingCommit,
};
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, UpstreamAuth,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn maybe_setup() -> Option<(PgPool, PgAuthorityLifecycle, Uuid)> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("event store init"),
    );
    let repo_id = seed_repo(&pool).await;
    Some((pool, PgAuthorityLifecycle::new(event_store), repo_id))
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-authority-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3, 'npm'::repository_format, 'hosted'::repository_type,
               'filesystem', $4, 'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repo");
    id
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn grant(claim: &str, repository_id: Option<Uuid>) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.to_string()]),
        repository_id,
        permission: Permission::Read,
        created_at: Utc::now(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some([0x11; 32]),
    }
}

fn grant_applied(g: &PermissionGrant) -> EventToAppend {
    EventToAppend::new(DomainEvent::PermissionGrantApplied(
        PermissionGrantApplied {
            grant_id: g.id,
            subject: GrantSubjectRecord::from_subject(&g.subject),
            permission: g.permission,
            repository_id: g.repository_id,
        },
    ))
}

fn grant_revoked(g: &PermissionGrant) -> EventToAppend {
    EventToAppend::new(DomainEvent::PermissionGrantRevoked(
        PermissionGrantRevoked {
            grant_id: g.id,
            subject: GrantSubjectRecord::from_subject(&g.subject),
            permission: g.permission,
            repository_id: g.repository_id,
        },
    ))
}

fn mapping(idp_group: &str) -> ClaimMapping {
    ClaimMapping {
        id: Uuid::new_v4(),
        idp_group: idp_group.to_string(),
        claim: "developer".to_string(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some([0x22; 32]),
    }
}

fn mapping_applied(m: &ClaimMapping) -> EventToAppend {
    EventToAppend::new(DomainEvent::ClaimMappingApplied(ClaimMappingApplied {
        mapping_id: m.id,
        idp_group: m.idp_group.clone(),
        claim: m.claim.clone(),
    }))
}

fn upstream_mapping(
    repository_id: Uuid,
    path_prefix: &str,
    url: &str,
) -> RepositoryUpstreamMapping {
    RepositoryUpstreamMapping {
        id: Uuid::new_v4(),
        repository_id,
        path_prefix: path_prefix.to_string(),
        upstream_url: url.to_string(),
        upstream_name_prefix: None,
        upstream_auth: UpstreamAuth::Anonymous,
        secret_ref: None,
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some([0x44; 32]),
        insecure_upstream_url: false,
        trust_upstream_publish_time: false,
        mtls_cert_ref: None,
        mtls_key_ref: None,
        ca_bundle_ref: None,
        pinned_cert_sha256: None,
        allowed_realm_hosts: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn upstream_mapping_changed(m: &RepositoryUpstreamMapping) -> EventToAppend {
    EventToAppend::new(DomainEvent::RepositoryUpstreamMappingChanged(
        RepositoryUpstreamMappingChanged {
            mapping_id: m.id,
            repository_id: m.repository_id,
            change: UpstreamMappingChange::Created,
            previous_secret_ref: None,
            new_secret_ref: None,
            previous_url: None,
            new_url: Some(m.upstream_url.clone()),
        },
    ))
}

fn service_account(name: &str, backing_user_id: Uuid) -> ServiceAccount {
    ServiceAccount {
        id: Uuid::new_v4(),
        name: name.to_string(),
        backing_user_id,
        // Non-empty claims: `chk_federated_claims_non_empty_object`
        // rejects `{}` at the schema layer (ADR 0018).
        federated_identities: vec![FederatedIdentity {
            issuer_name: "github-actions".to_string(),
            claims: [("sub".to_string(), format!("repo:acme/{name}"))]
                .into_iter()
                .collect(),
        }],
        fallback_rotation: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn service_account_created(sa: &ServiceAccount) -> EventToAppend {
    EventToAppend::new(DomainEvent::ServiceAccountCreated(ServiceAccountCreated {
        service_account_id: sa.id,
        service_account_name: sa.name.clone(),
        backing_user_id: sa.backing_user_id,
        at: Utc::now(),
    }))
}

fn issuer(name: &str) -> OidcIssuer {
    OidcIssuer {
        id: Uuid::new_v4(),
        name: name.to_string(),
        issuer_url: format!("https://{name}.example.com"),
        audiences: vec!["hort".to_string()],
        jwks_refresh_interval: Duration::from_secs(3600),
        allowed_algorithms: vec![JwtAlg::Rs256],
        require_jti: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// A batch the event store will accept: `ExpectedVersion::Any`.
fn ok_batch(stream_id: StreamId, events: Vec<EventToAppend>) -> AppendEvents {
    AppendEvents {
        stream_id,
        expected_version: ExpectedVersion::Any,
        events,
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    }
}

/// A batch the event store will REJECT: `Exact(9_999)` cannot match any
/// stream's real tail, so `append_with_conn` returns `Conflict` after
/// the row statements have already run inside the same transaction.
fn failing_batch(stream_id: StreamId, events: Vec<EventToAppend>) -> AppendEvents {
    AppendEvents {
        expected_version: ExpectedVersion::Exact(9_999),
        ..ok_batch(stream_id, events)
    }
}

// ---------------------------------------------------------------------------
// Observation helpers
// ---------------------------------------------------------------------------

async fn managed_grant_claims(pool: &PgPool) -> Vec<Vec<String>> {
    sqlx::query_scalar::<_, Vec<String>>(
        "SELECT required_claims FROM permission_grants \
         WHERE managed_by = 'gitops' ORDER BY required_claims",
    )
    .fetch_all(pool)
    .await
    .expect("read managed grants")
}

async fn managed_mapping_groups(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT idp_group FROM claim_mappings WHERE managed_by = 'gitops' ORDER BY idp_group",
    )
    .fetch_all(pool)
    .await
    .expect("read managed mappings")
}

async fn issuer_names(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>("SELECT name FROM oidc_issuers ORDER BY name")
        .fetch_all(pool)
        .await
        .expect("read issuers")
}

async fn managed_mapping_prefixes(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT path_prefix FROM repository_upstream_mappings \
         WHERE managed_by = 'gitops' ORDER BY path_prefix",
    )
    .fetch_all(pool)
    .await
    .expect("read managed upstream mappings")
}

async fn all_mapping_prefixes(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT path_prefix FROM repository_upstream_mappings ORDER BY path_prefix",
    )
    .fetch_all(pool)
    .await
    .expect("read every upstream mapping")
}

async fn service_account_names(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>("SELECT name FROM service_accounts ORDER BY name")
        .fetch_all(pool)
        .await
        .expect("read service accounts")
}

async fn rotation_formats(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT format FROM service_account_fallback_rotations ORDER BY format",
    )
    .fetch_all(pool)
    .await
    .expect("read fallback rotations")
}

async fn federated_identity_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM service_account_federated_identities")
        .fetch_one(pool)
        .await
        .expect("count federated identities")
}

/// Seed a backing `users` row with `is_service_account = true` — the FK
/// target `service_accounts.backing_user_id` requires.
async fn seed_backing_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("sa:it-authority-{}", id.simple());
    sqlx::query(
        "INSERT INTO users (id, username, email, auth_provider, is_service_account) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{username}@service-accounts.local"))
    .execute(pool)
    .await
    .expect("seed backing user");
    id
}

async fn stream_event_count(pool: &PgPool, stream_id: &StreamId) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE stream_id = $1")
        .bind(stream_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count stream events")
}

// ---------------------------------------------------------------------------
// Permission grants
// ---------------------------------------------------------------------------

/// Happy path, and the multi-stream shape: one commit call carrying a
/// repo-scoped batch and a global batch lands both streams' events plus
/// both rows.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_lands_every_stream_and_both_rows() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let scoped = grant("scoped", Some(repo_id));
    let global = grant("global", None);
    let repo_stream = StreamId::repository(repo_id);
    let authz_stream = StreamId::authorization();

    lc.commit_permission_grants(
        &[scoped.clone(), global.clone()],
        vec![
            ok_batch(authz_stream.clone(), vec![grant_applied(&global)]),
            ok_batch(repo_stream.clone(), vec![grant_applied(&scoped)]),
        ],
    )
    .await
    .expect("commit must succeed");

    assert_eq!(
        managed_grant_claims(&pool).await,
        vec![vec!["global".to_string()], vec!["scoped".to_string()]],
        "both grants are in the gitops partition"
    );
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 1);
    assert_eq!(stream_event_count(&pool, &repo_stream).await, 1);
}

/// The audit append fails and the grant partition is afterwards
/// **unchanged** — the prior row survives and the new one never lands.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_append_failure_rolls_back_the_partition() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let prior = grant("prior", None);
    lc.commit_permission_grants(
        std::slice::from_ref(&prior),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&prior)])],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    // Reconcile to a different set, with an append the store refuses.
    let replacement = grant("replacement", None);
    let err = lc
        .commit_permission_grants(
            std::slice::from_ref(&replacement),
            vec![failing_batch(
                authz_stream.clone(),
                vec![grant_applied(&replacement)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(
        err.to_string().contains("expected 9999"),
        "the expected-version conflict must surface, got: {err}"
    );

    assert_eq!(
        managed_grant_claims(&pool).await,
        vec![vec!["prior".to_string()]],
        "the partition must be exactly its pre-commit state — the DELETE of \
         'prior' and the INSERT of 'replacement' both rolled back"
    );
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before,
        "no audit event may have landed"
    );
}

/// The grouped multi-stream append commits as ONE unit: a batch list
/// whose SECOND element is rejected leaves the FIRST stream unaudited
/// too, and the rows unwritten. Pre-port this was one
/// `EventStore::append` transaction per stream, so the first stream's
/// events were already durable when the second failed.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grouped_multi_stream_append_commits_as_one_unit() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let scoped = grant("scoped", Some(repo_id));
    let global = grant("global", None);
    let repo_stream = StreamId::repository(repo_id);
    let authz_stream = StreamId::authorization();

    let err = lc
        .commit_permission_grants(
            &[scoped.clone(), global.clone()],
            vec![
                // Accepted on its own …
                ok_batch(authz_stream.clone(), vec![grant_applied(&global)]),
                // … but this one is refused, after the first was written.
                failing_batch(repo_stream.clone(), vec![grant_applied(&scoped)]),
            ],
        )
        .await
        .expect_err("a rejected batch must fail the whole commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        0,
        "the ACCEPTED batch must have rolled back with the rejected one — \
         no stream half-audited"
    );
    assert_eq!(stream_event_count(&pool, &repo_stream).await, 0);
    assert!(
        managed_grant_claims(&pool).await.is_empty(),
        "and no grant row may be in effect"
    );
}

/// A managed grant without a digest is rejected before a transaction is
/// opened — the precondition the reconcile relies on, enforced at the
/// port boundary rather than as a partially-applied partition.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_rejects_a_digestless_grant_before_writing() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let mut bad = grant("no-digest", None);
    bad.managed_by_digest = None;

    let err = lc
        .commit_permission_grants(
            std::slice::from_ref(&bad),
            vec![ok_batch(authz_stream.clone(), vec![grant_applied(&bad)])],
        )
        .await
        .expect_err("a digest-less managed grant must be refused");
    assert!(
        err.to_string().contains("managed_by_digest"),
        "the error must name the missing column, got: {err}"
    );
    assert!(managed_grant_claims(&pool).await.is_empty());
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 0);
}

/// The mirror direction: the **row** write fails and the audit append
/// rolls back with it, so no event attests a grant that is not in
/// effect. Force vector: `GrantSubject::Claims(vec![])`, which the
/// `claims_nonempty` CHECK (`001_users_roles_rbac.sql`) rejects on the
/// reconcile INSERT — after the partition DELETE has already run.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_row_failure_rolls_back_the_audit_append() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let prior = grant("prior", None);
    lc.commit_permission_grants(
        std::slice::from_ref(&prior),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&prior)])],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    let mut bad = grant("ignored", None);
    bad.subject = GrantSubject::Claims(Vec::new());
    let err = lc
        .commit_permission_grants(
            std::slice::from_ref(&bad),
            vec![ok_batch(authz_stream.clone(), vec![grant_applied(&bad)])],
        )
        .await
        .expect_err("an empty required_claims array must fail the INSERT");
    assert!(
        err.to_string().contains("claims_nonempty"),
        "the CHECK violation must surface, got: {err}"
    );

    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before,
        "the audit append must roll back with the refused row write"
    );
    assert_eq!(
        managed_grant_claims(&pool).await,
        vec![vec!["prior".to_string()]],
        "and the partition DELETE must roll back too"
    );
}

// ---------------------------------------------------------------------------
// Claim mappings
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_lands_rows_and_events() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let m = mapping("g-dev");
    lc.commit_claim_mappings(
        std::slice::from_ref(&m),
        vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&m)])],
    )
    .await
    .expect("commit must succeed");

    assert_eq!(managed_mapping_groups(&pool).await, vec!["g-dev"]);
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 1);
}

/// The audit append fails and the claim-mapping partition is afterwards
/// **unchanged**.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_append_failure_rolls_back_the_partition() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let prior = mapping("g-prior");
    lc.commit_claim_mappings(
        std::slice::from_ref(&prior),
        vec![ok_batch(
            authz_stream.clone(),
            vec![mapping_applied(&prior)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    let replacement = mapping("g-replacement");
    let err = lc
        .commit_claim_mappings(
            std::slice::from_ref(&replacement),
            vec![failing_batch(
                authz_stream.clone(),
                vec![mapping_applied(&replacement)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        managed_mapping_groups(&pool).await,
        vec!["g-prior"],
        "the partition must be exactly its pre-commit state"
    );
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before
    );
}

/// A managed mapping without a digest is refused before any statement
/// runs — the claim-mapping half of the same precondition.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_rejects_a_digestless_mapping_before_writing() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let mut bad = mapping("g-no-digest");
    bad.managed_by_digest = None;

    let err = lc
        .commit_claim_mappings(
            std::slice::from_ref(&bad),
            vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&bad)])],
        )
        .await
        .expect_err("a digest-less managed mapping must be refused");
    assert!(
        err.to_string().contains("managed_by_digest"),
        "the error must name the missing column, got: {err}"
    );
    assert!(managed_mapping_groups(&pool).await.is_empty());
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 0);
}

/// The mirror direction for claim mappings. Force vector: an
/// `idp_group` longer than the column's `character varying(255)`, which
/// the reconcile INSERT rejects after the partition DELETE has run.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_row_failure_rolls_back_the_audit_append() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let prior = mapping("g-prior");
    lc.commit_claim_mappings(
        std::slice::from_ref(&prior),
        vec![ok_batch(
            authz_stream.clone(),
            vec![mapping_applied(&prior)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    let bad = mapping(&"g".repeat(300));
    let err = lc
        .commit_claim_mappings(
            std::slice::from_ref(&bad),
            vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&bad)])],
        )
        .await
        .expect_err("an over-long idp_group must fail the INSERT");
    assert!(
        err.to_string().contains("too long") || err.to_string().contains("255"),
        "the column-width violation must surface, got: {err}"
    );

    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before,
        "the audit append must roll back with the refused row write"
    );
    assert_eq!(
        managed_mapping_groups(&pool).await,
        vec!["g-prior"],
        "and the partition DELETE must roll back too"
    );
}

// ---------------------------------------------------------------------------
// OIDC issuers
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn oidc_issuer_commit_lands_row_and_event() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let i = issuer("github-actions");
    let change = OidcIssuerChange {
        upserts: vec![i.clone()],
        deletes: Vec::new(),
    };
    lc.commit_oidc_issuers(
        &change,
        vec![ok_batch(
            authz_stream.clone(),
            vec![EventToAppend::new(DomainEvent::OidcIssuerCreated(
                OidcIssuerCreated {
                    issuer_id: i.id,
                    name: i.name.clone(),
                    at: Utc::now(),
                },
            ))],
        )],
    )
    .await
    .expect("commit must succeed");

    assert_eq!(issuer_names(&pool).await, vec!["github-actions"]);
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 1);
}

/// The audit append fails and the issuer row is afterwards **not in
/// effect**. This is the trust-anchor case (ADR 0018): a serving
/// validator reads `oidc_issuers` at validation time, so a row that
/// commits without its event is a live trust change the authorization
/// stream is silent about.
#[tokio::test]
#[serial(hort_pg_db)]
async fn oidc_issuer_commit_append_failure_leaves_the_row_absent() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let i = issuer("rogue-idp");
    let change = OidcIssuerChange {
        upserts: vec![i.clone()],
        deletes: Vec::new(),
    };

    let err = lc
        .commit_oidc_issuers(
            &change,
            vec![failing_batch(
                authz_stream.clone(),
                vec![EventToAppend::new(DomainEvent::OidcIssuerCreated(
                    OidcIssuerCreated {
                        issuer_id: i.id,
                        name: i.name.clone(),
                        at: Utc::now(),
                    },
                ))],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert!(
        issuer_names(&pool).await.is_empty(),
        "no issuer row may be trusted without an attesting event"
    );
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 0);
}

/// The delete half: a rejected append rolls the DELETE back, so the
/// issuer the operator removed is still trusted — and still has its
/// original `Created` event, with no spurious `Deleted` beside it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn oidc_issuer_delete_rolls_back_when_the_append_fails() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let i = issuer("keycloak");
    lc.commit_oidc_issuers(
        &OidcIssuerChange {
            upserts: vec![i.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![EventToAppend::new(DomainEvent::OidcIssuerCreated(
                OidcIssuerCreated {
                    issuer_id: i.id,
                    name: i.name.clone(),
                    at: Utc::now(),
                },
            ))],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    let err = lc
        .commit_oidc_issuers(
            &OidcIssuerChange {
                upserts: Vec::new(),
                deletes: vec![i.name.clone()],
            },
            vec![failing_batch(
                authz_stream.clone(),
                vec![EventToAppend::new(DomainEvent::OidcIssuerDeleted(
                    OidcIssuerDeleted {
                        issuer_id: i.id,
                        name: i.name.clone(),
                        at: Utc::now(),
                    },
                ))],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        issuer_names(&pool).await,
        vec!["keycloak"],
        "the DELETE must have rolled back with the refused append"
    );
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before,
        "and no OidcIssuerDeleted may have landed"
    );
}

/// An empty change with an empty batch list commits an empty
/// transaction — the shape an apply with nothing to do would produce if
/// it reached the port, and a no-op rather than an error.
#[tokio::test]
#[serial(hort_pg_db)]
async fn oidc_issuer_empty_change_is_a_no_op() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    lc.commit_oidc_issuers(&OidcIssuerChange::default(), Vec::new())
        .await
        .expect("an empty change must not error");
    assert!(issuer_names(&pool).await.is_empty());
    assert_eq!(
        stream_event_count(&pool, &StreamId::authorization()).await,
        0
    );
}

// ---------------------------------------------------------------------------
// Upstream mappings
// ---------------------------------------------------------------------------

/// Happy path: one commit call lands the rows and the audit events.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_commit_lands_rows_and_events() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let m = upstream_mapping(repo_id, "dockerhub/", "https://registry-1.docker.io");
    let change = UpstreamMappingCommit {
        upserts: vec![m.clone()],
        deletes: Vec::new(),
    };

    lc.commit_upstream_mappings(
        &change,
        vec![ok_batch(
            repo_stream.clone(),
            vec![upstream_mapping_changed(&m)],
        )],
    )
    .await
    .expect("commit must succeed");

    assert_eq!(
        managed_mapping_prefixes(&pool).await,
        vec!["dockerhub/".to_string()]
    );
    assert_eq!(stream_event_count(&pool, &repo_stream).await, 1);
}

/// The audit append fails and the mapping row is afterwards **not in
/// effect**. A mapping names the upstream a proxy repository trusts and
/// fetches from, with its credential reference and TLS material, so a
/// row that commits without its event is a live trust change the
/// authorization stream is silent about.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_commit_append_failure_leaves_the_row_absent() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let m = upstream_mapping(repo_id, "rogue/", "https://rogue.example.com");

    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: vec![m.clone()],
                deletes: Vec::new(),
            },
            vec![failing_batch(
                repo_stream.clone(),
                vec![upstream_mapping_changed(&m)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert!(
        managed_mapping_prefixes(&pool).await.is_empty(),
        "no upstream may be trusted without an attesting event"
    );
    assert_eq!(stream_event_count(&pool, &repo_stream).await, 0);
}

/// The update half, which is the one that matters most: a rejected
/// append rolls back the **re-point**, so the repository keeps fetching
/// from the upstream the authorization stream last attested. Without
/// the transaction the row would carry the new URL with nothing in the
/// stream naming it, and the next apply's digest comparison would see
/// the change already present and emit nothing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_repoint_rolls_back_when_the_append_fails() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let original = upstream_mapping(repo_id, "dockerhub/", "https://registry-1.docker.io");
    lc.commit_upstream_mappings(
        &UpstreamMappingCommit {
            upserts: vec![original.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            repo_stream.clone(),
            vec![upstream_mapping_changed(&original)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &repo_stream).await;

    // Same `(repository_id, path_prefix)` identity, different upstream.
    let mut repointed = original.clone();
    repointed.upstream_url = "https://attacker.example.com".into();
    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: vec![repointed.clone()],
                deletes: Vec::new(),
            },
            vec![failing_batch(
                repo_stream.clone(),
                vec![upstream_mapping_changed(&repointed)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    let url: String = sqlx::query_scalar(
        "SELECT upstream_url FROM repository_upstream_mappings \
         WHERE repository_id = $1 AND path_prefix = 'dockerhub/'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("read the mapping back");
    assert_eq!(
        url, "https://registry-1.docker.io",
        "the re-point must have rolled back — the repository still fetches \
         from the upstream the stream attested"
    );
    assert_eq!(
        stream_event_count(&pool, &repo_stream).await,
        events_before,
        "and no audit event may have landed"
    );
}

/// The delete half: a rejected append rolls the DELETE back, so the
/// mapping the operator removed is still in effect — and still has its
/// original `Created` event, with no spurious `Removed` beside it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_delete_rolls_back_when_the_append_fails() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let m = upstream_mapping(repo_id, "ghcr/", "https://ghcr.io");
    lc.commit_upstream_mappings(
        &UpstreamMappingCommit {
            upserts: vec![m.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            repo_stream.clone(),
            vec![upstream_mapping_changed(&m)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &repo_stream).await;

    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: Vec::new(),
                deletes: vec![m.id],
            },
            vec![failing_batch(
                repo_stream.clone(),
                vec![upstream_mapping_changed(&m)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        managed_mapping_prefixes(&pool).await,
        vec!["ghcr/".to_string()],
        "the DELETE must have rolled back with the refused append"
    );
    assert_eq!(stream_event_count(&pool, &repo_stream).await, events_before);
}

/// **The multi-stream property.** An upstream-mapping apply is
/// repo-scoped on every row, so one apply that touches two repositories
/// produces two batches. They commit as ONE unit: a list whose SECOND
/// element is rejected leaves the FIRST repository's stream unaudited
/// too, and neither row written. Pre-port this branch appended one
/// `EventStore::append` per stream after each row had already committed
/// on its own, so the first repository's events were already durable
/// when the second failed — some repositories audited, others not.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_multi_stream_append_commits_as_one_unit() {
    let Some((pool, lc, repo_a)) = maybe_setup().await else {
        return;
    };
    let repo_b = seed_repo(&pool).await;
    let stream_a = StreamId::repository(repo_a);
    let stream_b = StreamId::repository(repo_b);
    let m_a = upstream_mapping(repo_a, "a/", "https://a.example.com");
    let m_b = upstream_mapping(repo_b, "b/", "https://b.example.com");

    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: vec![m_a.clone(), m_b.clone()],
                deletes: Vec::new(),
            },
            vec![
                // Accepted on its own …
                ok_batch(stream_a.clone(), vec![upstream_mapping_changed(&m_a)]),
                // … but this one is refused, after the first was written.
                failing_batch(stream_b.clone(), vec![upstream_mapping_changed(&m_b)]),
            ],
        )
        .await
        .expect_err("a rejected batch must fail the whole commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        stream_event_count(&pool, &stream_a).await,
        0,
        "the ACCEPTED batch must have rolled back with the rejected one — \
         no repository half-audited"
    );
    assert_eq!(stream_event_count(&pool, &stream_b).await, 0);
    assert!(
        managed_mapping_prefixes(&pool).await.is_empty(),
        "and no mapping row may be in effect"
    );
}

/// A managed mapping without a digest is refused, and nothing is
/// written: the `(managed_by = GitOps ↔ digest = Some(_))` pairing the
/// schema CHECK mirrors, enforced in the statement helper. The refusal
/// lands inside the transaction (there is no prepared form to validate
/// up front, unlike the grant reconcile), so what the caller observes
/// is the rollback.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_commit_rejects_a_digestless_mapping() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let mut bad = upstream_mapping(repo_id, "no-digest/", "https://nd.example.com");
    bad.managed_by_digest = None;

    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: vec![bad.clone()],
                deletes: Vec::new(),
            },
            vec![ok_batch(
                repo_stream.clone(),
                vec![upstream_mapping_changed(&bad)],
            )],
        )
        .await
        .expect_err("a digest-less managed mapping must be refused");
    assert!(
        err.to_string().contains("managed_by_digest"),
        "the error must name the missing column, got: {err}"
    );
    assert!(managed_mapping_prefixes(&pool).await.is_empty());
    assert_eq!(stream_event_count(&pool, &repo_stream).await, 0);
}

/// The commit's delete leaves a `managed_by = 'local'` row alone — the
/// `managed_by = 'gitops'` predicate on the DELETE is the partition
/// boundary, and the gitops apply is not allowed to GC an
/// operator-managed mapping it never wrote.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_commit_delete_does_not_touch_local_rows() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let local_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO repository_upstream_mappings \
           (id, repository_id, path_prefix, upstream_url, upstream_auth_type, managed_by) \
         VALUES ($1, $2, 'local-only/', 'https://local.example.com', 'anonymous', 'local')",
    )
    .bind(local_id)
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("insert local mapping");

    lc.commit_upstream_mappings(
        &UpstreamMappingCommit {
            upserts: Vec::new(),
            deletes: vec![local_id],
        },
        Vec::new(),
    )
    .await
    .expect("the delete of a local row is a no-op, not an error");

    assert_eq!(
        all_mapping_prefixes(&pool).await,
        vec!["local-only/".to_string()],
        "the local row must survive a gitops-partition delete"
    );
}

/// The mirror direction: the **row** write fails and the audit append
/// rolls back with it, so no event attests a mapping that is not in
/// effect. Force vector: an `upstream_name_prefix` with a leading
/// slash, which `chk_repository_upstream_mappings_name_prefix`
/// (`007_upstream_mappings.sql`) rejects on the upsert — after the
/// accepted first mapping's INSERT has already run on the same
/// transaction.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_row_failure_rolls_back_the_audit_append() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    let repo_stream = StreamId::repository(repo_id);
    let good = upstream_mapping(repo_id, "good/", "https://good.example.com");
    let mut bad = upstream_mapping(repo_id, "bad/", "https://bad.example.com");
    bad.upstream_name_prefix = Some("/leading-slash".to_string());

    let err = lc
        .commit_upstream_mappings(
            &UpstreamMappingCommit {
                upserts: vec![good.clone(), bad.clone()],
                deletes: Vec::new(),
            },
            vec![ok_batch(
                repo_stream.clone(),
                vec![
                    upstream_mapping_changed(&good),
                    upstream_mapping_changed(&bad),
                ],
            )],
        )
        .await
        .expect_err("a CHECK-violating upstream_name_prefix must fail the upsert");
    assert!(
        err.to_string().contains("name_prefix"),
        "the CHECK violation must surface, got: {err}"
    );

    assert!(
        managed_mapping_prefixes(&pool).await.is_empty(),
        "the accepted mapping's INSERT must roll back with the refused one"
    );
    assert_eq!(
        stream_event_count(&pool, &repo_stream).await,
        0,
        "and the audit append must roll back with the refused row write"
    );
}

/// An empty commit with an empty batch list is a no-op rather than an
/// error — the shape an apply with nothing to do would produce if it
/// reached the port.
#[tokio::test]
#[serial(hort_pg_db)]
async fn upstream_mapping_empty_commit_is_a_no_op() {
    let Some((pool, lc, repo_id)) = maybe_setup().await else {
        return;
    };
    lc.commit_upstream_mappings(&UpstreamMappingCommit::default(), Vec::new())
        .await
        .expect("an empty commit must not error");
    assert!(managed_mapping_prefixes(&pool).await.is_empty());
    assert_eq!(
        stream_event_count(&pool, &StreamId::repository(repo_id)).await,
        0
    );
}

// ---------------------------------------------------------------------------
// Service accounts
// ---------------------------------------------------------------------------

/// Happy path: one commit call lands the whole aggregate — the SA row
/// AND its federated-identity sub-rows — plus the audit event.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_commit_lands_aggregate_and_event() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let backing = seed_backing_user(&pool).await;
    let sa = service_account("ci-publisher", backing);

    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![sa.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&sa)],
        )],
    )
    .await
    .expect("commit must succeed");

    assert_eq!(
        service_account_names(&pool).await,
        vec!["ci-publisher".to_string()]
    );
    assert_eq!(
        federated_identity_count(&pool).await,
        1,
        "the sub-aggregate rows land in the same transaction"
    );
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 1);
}

/// The audit append fails and the service account is afterwards **not
/// in effect** — neither the SA row nor its federated-identity rows.
/// This is the federated-identity trust-anchor case (ADR 0018): the
/// `federated_identities[].claims` decide which JWTs may assume the SA,
/// and the federation handler reads the aggregate at assume time, so a
/// row that commits without its event is a live trust grant the
/// authorization stream is silent about.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_commit_append_failure_leaves_the_aggregate_absent() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let backing = seed_backing_user(&pool).await;
    let sa = service_account("rogue-ci", backing);

    let err = lc
        .commit_service_accounts(
            &ServiceAccountCommit {
                upserts: vec![sa.clone()],
                deletes: Vec::new(),
            },
            vec![failing_batch(
                authz_stream.clone(),
                vec![service_account_created(&sa)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert!(
        service_account_names(&pool).await.is_empty(),
        "no service account may be assumable without an attesting event"
    );
    assert_eq!(
        federated_identity_count(&pool).await,
        0,
        "and no federated-identity row may be left behind"
    );
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 0);
}

/// The federated-identity **replace** is part of the same unit. The
/// adapter DELETEs the SA's existing claim bindings before INSERTing
/// the new set; a refused append has to roll that DELETE back, or the
/// SA is left assumable by nobody (or, with a partial re-INSERT, by the
/// wrong claims) with nothing attesting the change.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_identity_replace_rolls_back_when_the_append_fails() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let backing = seed_backing_user(&pool).await;
    let sa = service_account("ci-publisher", backing);
    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![sa.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&sa)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    // Same name, a widened claim set the operator must not get without
    // an audit record.
    let mut widened = sa.clone();
    widened.federated_identities = vec![FederatedIdentity {
        issuer_name: "github-actions".to_string(),
        claims: [("sub".to_string(), "repo:attacker/*".to_string())]
            .into_iter()
            .collect(),
    }];
    let err = lc
        .commit_service_accounts(
            &ServiceAccountCommit {
                upserts: vec![widened.clone()],
                deletes: Vec::new(),
            },
            vec![failing_batch(
                authz_stream.clone(),
                vec![service_account_created(&widened)],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    let claim: String = sqlx::query_scalar(
        "SELECT claims->>'sub' FROM service_account_federated_identities \
           JOIN service_accounts ON service_accounts.id = service_account_id \
         WHERE service_accounts.name = 'ci-publisher'",
    )
    .fetch_one(&pool)
    .await
    .expect("read the claim binding back");
    assert_eq!(
        claim, "repo:acme/ci-publisher",
        "the claim-binding replace must have rolled back"
    );
    assert_eq!(
        federated_identity_count(&pool).await,
        1,
        "exactly the pre-commit binding, not zero and not two"
    );
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before
    );
}

/// The delete half: a rejected append rolls the DELETE back, so the
/// service account the operator removed is still assumable — and still
/// has its original `Created` event, with no spurious `Deleted` beside
/// it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_delete_rolls_back_when_the_append_fails() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let backing = seed_backing_user(&pool).await;
    let sa = service_account("retired-ci", backing);
    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![sa.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&sa)],
        )],
    )
    .await
    .expect("seed commit");
    let events_before = stream_event_count(&pool, &authz_stream).await;

    let err = lc
        .commit_service_accounts(
            &ServiceAccountCommit {
                upserts: Vec::new(),
                deletes: vec![sa.name.clone()],
            },
            vec![failing_batch(
                authz_stream.clone(),
                vec![EventToAppend::new(DomainEvent::ServiceAccountDeleted(
                    ServiceAccountDeleted {
                        service_account_id: sa.id,
                        service_account_name: sa.name.clone(),
                        backing_user_id: sa.backing_user_id,
                        at: Utc::now(),
                    },
                ))],
            )],
        )
        .await
        .expect_err("a rejected append must fail the commit");
    assert!(err.to_string().contains("expected 9999"), "got: {err}");

    assert_eq!(
        service_account_names(&pool).await,
        vec!["retired-ci".to_string()],
        "the DELETE must have rolled back with the refused append"
    );
    assert_eq!(
        federated_identity_count(&pool).await,
        1,
        "and the CASCADE drop of the sub-rows with it"
    );
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        events_before
    );
}

/// The mirror direction: the **row** write fails and the audit append
/// rolls back with it, so no event attests a service account that is
/// not in effect. Force vector: a `backing_user_id` with no `users`
/// row, which the `service_accounts.backing_user_id` FK rejects on the
/// SA-row INSERT.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_row_failure_rolls_back_the_audit_append() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let sa = service_account("orphan-ci", Uuid::new_v4());

    let err = lc
        .commit_service_accounts(
            &ServiceAccountCommit {
                upserts: vec![sa.clone()],
                deletes: Vec::new(),
            },
            vec![ok_batch(
                authz_stream.clone(),
                vec![service_account_created(&sa)],
            )],
        )
        .await
        .expect_err("a dangling backing_user_id must fail the INSERT");

    assert!(service_account_names(&pool).await.is_empty(), "got: {err}");
    assert_eq!(
        stream_event_count(&pool, &authz_stream).await,
        0,
        "the audit append must roll back with the refused row write"
    );
}

/// The `fallback_rotation` sub-row is part of the same unit, in both
/// directions of its reconcile: the first commit INSERTs it, the second
/// takes the `ON CONFLICT (service_account_id) DO UPDATE` arm with a
/// different `format`, and a third with `fallback_rotation: None`
/// DELETEs it. The rotation target is where a minted PAT is written
/// (`ServiceAccountRotationHandler`), so it is as much part of the
/// attested aggregate as the claim bindings.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_commit_reconciles_the_fallback_rotation_row() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let backing = seed_backing_user(&pool).await;
    let mut sa = service_account("ci-rotating", backing);
    // `validity >= 2 * rotation_interval` — an apply-time invariant the
    // schema mirrors as `chk_validity_at_least_two_rotations`.
    sa.fallback_rotation = Some(FallbackRotation {
        target_secret_name: "hort-ci-pull".to_string(),
        target_secret_namespace: "ci".to_string(),
        format: SecretFormat::Dockerconfigjson,
        rotation_interval: Duration::from_secs(3600),
        validity: Duration::from_secs(4 * 3600),
    });

    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![sa.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&sa)],
        )],
    )
    .await
    .expect("commit with a rotation target");
    assert_eq!(
        rotation_formats(&pool).await,
        vec!["dockerconfigjson".to_string()],
        "the rotation row lands in the same transaction as the SA row"
    );

    // Re-commit with the other format: the ON CONFLICT update arm.
    let mut reformatted = sa.clone();
    reformatted.fallback_rotation = Some(FallbackRotation {
        format: SecretFormat::Opaque,
        ..sa.fallback_rotation.clone().expect("set above")
    });
    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![reformatted.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&reformatted)],
        )],
    )
    .await
    .expect("commit the reformatted rotation target");
    assert_eq!(
        rotation_formats(&pool).await,
        vec!["opaque".to_string()],
        "the rotation row is updated in place, not duplicated"
    );

    // And dropping the target removes the row.
    let mut without = sa.clone();
    without.fallback_rotation = None;
    lc.commit_service_accounts(
        &ServiceAccountCommit {
            upserts: vec![without.clone()],
            deletes: Vec::new(),
        },
        vec![ok_batch(
            authz_stream.clone(),
            vec![service_account_created(&without)],
        )],
    )
    .await
    .expect("commit without a rotation target");
    assert!(
        rotation_formats(&pool).await.is_empty(),
        "an absent rotation target deletes the prior row"
    );
    assert_eq!(
        service_account_names(&pool).await,
        vec!["ci-rotating".to_string()],
        "and the SA itself survives all three"
    );
}

/// An empty commit with an empty batch list is a no-op rather than an
/// error.
#[tokio::test]
#[serial(hort_pg_db)]
async fn service_account_empty_commit_is_a_no_op() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    lc.commit_service_accounts(&ServiceAccountCommit::default(), Vec::new())
        .await
        .expect("an empty commit must not error");
    assert!(service_account_names(&pool).await.is_empty());
    assert_eq!(
        stream_event_count(&pool, &StreamId::authorization()).await,
        0
    );
}

// ---------------------------------------------------------------------------
// Reconcile semantics, through the commit path
// ---------------------------------------------------------------------------
//
// These were inline `#[cfg(test)]` tests on
// `PgPermissionGrantRepository::save_managed` /
// `PgClaimMappingRepository::save_managed`. Those trait methods no
// longer exist — the whole-partition reconcile is reachable only
// through `AuthorityLifecyclePort::commit_{permission_grants,
// claim_mappings}`, which commits it with its audit batch. So each one
// now asserts the same reconcile semantics *and* exercises the append
// in the same transaction, which is strictly more than it did before.
//
// The read side is still the repository port, which is where the reads
// legitimately live.

/// A managed grant round-trips, and re-applying the same complete set
/// is a no-op: the reconcile upserts on the subject-dependent identity,
/// not the surrogate key, so an unchanged replay does not duplicate the
/// row.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_round_trips_claims_and_is_idempotent() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let repo = PgPermissionGrantRepository::new(pool.clone());
    let authz_stream = StreamId::authorization();
    let g = grant("developer", None);

    lc.commit_permission_grants(
        std::slice::from_ref(&g),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&g)])],
    )
    .await
    .expect("commit");
    lc.commit_permission_grants(
        std::slice::from_ref(&g),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&g)])],
    )
    .await
    .expect("commit again (idempotent)");

    let listed = repo.list_all().await.expect("list_all");
    let found = listed
        .iter()
        .find(|row| row.subject == g.subject && row.permission == Permission::Read)
        .expect("claims grant present");
    assert_eq!(
        found.subject,
        GrantSubject::Claims(vec!["developer".to_string()])
    );

    let managed = repo
        .list_managed_by_gitops()
        .await
        .expect("list_managed_by_gitops");
    assert_eq!(
        managed
            .iter()
            .filter(|row| row.subject == g.subject)
            .count(),
        1,
        "idempotent re-apply must not duplicate the managed row"
    );
}

/// Delete-absent: a prior managed row missing from the new
/// authoritative set is revoked. The commit IS the revoke primitive —
/// there is no separate delete method.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_full_reconcile_deletes_absent_managed_rows() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let g_a = grant("alpha", None);
    let g_b = grant("beta", None);

    lc.commit_permission_grants(
        &[g_a.clone(), g_b.clone()],
        vec![ok_batch(
            authz_stream.clone(),
            vec![grant_applied(&g_a), grant_applied(&g_b)],
        )],
    )
    .await
    .expect("first apply");

    // Second apply: only g_a — g_b must be revoked.
    lc.commit_permission_grants(
        std::slice::from_ref(&g_a),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&g_a)])],
    )
    .await
    .expect("reconcile to {g_a}");

    assert_eq!(
        managed_grant_claims(&pool).await,
        vec![vec!["alpha".to_string()]],
        "g_b absent from the new set must be deleted"
    );
}

/// An explicitly-emptied gitops config revokes the whole partition.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_empty_set_revokes_all_gitops_grants() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let g = grant("developer", None);
    lc.commit_permission_grants(
        std::slice::from_ref(&g),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&g)])],
    )
    .await
    .expect("seed one grant");

    lc.commit_permission_grants(
        &[],
        vec![ok_batch(authz_stream.clone(), vec![grant_revoked(&g)])],
    )
    .await
    .expect("reconcile to empty");

    assert!(
        managed_grant_claims(&pool).await.is_empty(),
        "empty authoritative set revokes all gitops-managed grants"
    );
}

/// A non-gitops (admin-created) row survives a gitops reconcile — the
/// partition boundary is `managed_by = 'gitops'`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_does_not_touch_local_rows() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    sqlx::query(
        "INSERT INTO permission_grants \
           (id, required_claims, permission, managed_by) \
         VALUES ($1, ARRAY['local-only'], 'read'::permission_type, 'local')",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("insert local grant");

    lc.commit_permission_grants(&[], Vec::new())
        .await
        .expect("reconcile gitops empty");

    let repo = PgPermissionGrantRepository::new(pool.clone());
    let all = repo.list_all().await.expect("list_all");
    assert!(
        all.iter().any(|row| matches!(
            &row.subject,
            GrantSubject::Claims(c) if c == &vec!["local-only".to_string()]
        )),
        "a Local row must survive a gitops-partition reconcile"
    );
    assert!(managed_grant_claims(&pool).await.is_empty());
}

/// A `User`-subject grant round-trips through the reconcile. Needs a
/// real `users` row — `permission_grants.user_id` FKs into it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn grant_commit_round_trips_user_subject() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let uid = seed_backing_user(&pool).await;
    let authz_stream = StreamId::authorization();
    let g = PermissionGrant {
        subject: GrantSubject::User(uid),
        ..grant("ignored", None)
    };

    lc.commit_permission_grants(
        std::slice::from_ref(&g),
        vec![ok_batch(authz_stream.clone(), vec![grant_applied(&g)])],
    )
    .await
    .expect("commit");

    let repo = PgPermissionGrantRepository::new(pool.clone());
    let listed = repo.list_all().await.expect("list_all");
    let found = listed
        .iter()
        .find(|row| row.subject == GrantSubject::User(uid))
        .expect("user grant present");
    assert_eq!(found.permission, Permission::Read);
    assert!(found.repository_id.is_none());
    assert_eq!(stream_event_count(&pool, &authz_stream).await, 1);
}

/// The claim-mapping half of the round-trip + idempotence pair, keyed
/// on the `(idp_group, claim)` UNIQUE identity.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_round_trips_and_is_idempotent() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let m = mapping("grp-devs");

    lc.commit_claim_mappings(
        std::slice::from_ref(&m),
        vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&m)])],
    )
    .await
    .expect("commit");
    lc.commit_claim_mappings(
        std::slice::from_ref(&m),
        vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&m)])],
    )
    .await
    .expect("commit again (idempotent)");

    let repo = PgClaimMappingRepository::new(pool.clone());
    let all = repo.list_all().await.expect("list_all");
    let found = all
        .iter()
        .find(|row| row.idp_group == "grp-devs" && row.claim == "developer")
        .expect("mapping present");
    assert_eq!(found.managed_by, ManagedBy::GitOps);
    assert_eq!(found.managed_by_digest, Some([0x22; 32]));
    assert_eq!(
        managed_mapping_groups(&pool).await,
        vec!["grp-devs".to_string()],
        "idempotent re-apply must not duplicate the managed row"
    );
}

/// Delete-absent for claim mappings.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_full_reconcile_deletes_absent_managed_rows() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let m_a = mapping("grp-a");
    let m_b = mapping("grp-b");

    lc.commit_claim_mappings(
        &[m_a.clone(), m_b.clone()],
        vec![ok_batch(
            authz_stream.clone(),
            vec![mapping_applied(&m_a), mapping_applied(&m_b)],
        )],
    )
    .await
    .expect("first apply");
    lc.commit_claim_mappings(
        std::slice::from_ref(&m_a),
        vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&m_a)])],
    )
    .await
    .expect("reconcile to {m_a}");

    assert_eq!(
        managed_mapping_groups(&pool).await,
        vec!["grp-a".to_string()],
        "a mapping absent from the new authoritative set must be deleted"
    );
}

/// An empty authoritative set revokes every gitops-managed mapping.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_empty_set_revokes_all_gitops_mappings() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    let authz_stream = StreamId::authorization();
    let m = mapping("grp-devs");
    lc.commit_claim_mappings(
        std::slice::from_ref(&m),
        vec![ok_batch(authz_stream.clone(), vec![mapping_applied(&m)])],
    )
    .await
    .expect("seed one mapping");

    lc.commit_claim_mappings(&[], Vec::new())
        .await
        .expect("reconcile to empty");

    assert!(
        managed_mapping_groups(&pool).await.is_empty(),
        "empty authoritative set revokes all gitops-managed mappings"
    );
}

/// A `managed_by = 'local'` claim mapping survives a gitops reconcile.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claim_mapping_commit_does_not_touch_local_rows() {
    let Some((pool, lc, _repo_id)) = maybe_setup().await else {
        return;
    };
    sqlx::query(
        "INSERT INTO claim_mappings (id, idp_group, claim, managed_by) \
         VALUES ($1, 'local-grp', 'local-claim', 'local')",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("insert local mapping");

    lc.commit_claim_mappings(&[], Vec::new())
        .await
        .expect("reconcile gitops empty");

    let repo = PgClaimMappingRepository::new(pool.clone());
    let all = repo.list_all().await.expect("list_all");
    assert!(
        all.iter().any(|row| row.idp_group == "local-grp"),
        "a Local row must survive a gitops-partition reconcile"
    );
    assert!(managed_mapping_groups(&pool).await.is_empty());
}
