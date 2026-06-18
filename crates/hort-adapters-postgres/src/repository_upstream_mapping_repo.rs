//! PostgreSQL adapter for [`RepositoryUpstreamMappingRepository`].
//!
//! Backed by `repository_upstream_mappings` (`007_upstream_mappings.sql`). The
//! adapter is a thin CRUD wrapper — the longest-prefix-match
//! resolution lives in [`hort_domain::ports::upstream_resolver`], not
//! here. This adapter's job is to keep the on-disk shape of the table
//! in sync with the domain port's contract.
//!
//! # Auth-variant encoding
//!
//! `upstream_auth_type` is a free-form `TEXT` column on the SQL side
//! (closed enum on the Rust side). The mapping is:
//!
//! | [`UpstreamAuth`] variant | DB string |
//! |---|---|
//! | `Anonymous` | `"anonymous"` |
//! | `BearerChallenge` | `"bearer_challenge"` |
//! | `Basic { username }` | `"basic"` (plus `secret_ref`) |
//!
//! `Basic.username` lives in a JSONB-shaped sidecar on the row?
//! Currently NO — the schema does not carry a username column.
//! For now we read/write `username = ""` for `Basic` variants; a
//! follow-up change adds the column when actual username-bearing
//! mappings are wired. That keeps the surface correct without forcing
//! schema churn before that design lands.
//!
//! Carried-forward — `UpstreamAuth::Basic` username schema gap: schema
//! extension owed to a future change; the empty-string fallback is
//! intentional until then.
//!
//! Unknown DB strings surface as [`DomainError::Invariant`] — the
//! table is operator-managed; corrupt values are bugs, not request
//! errors.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::str::FromStr;
use uuid::Uuid;

use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, RepositoryUpstreamMappingRepository,
    UpstreamAuth,
};

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of
/// [`RepositoryUpstreamMappingRepository`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the
/// pool. Construction is cheap (no I/O) — the pool itself governs
/// connection lifecycle.
pub struct PgRepositoryUpstreamMappingRepo {
    pool: PgPool,
}

impl PgRepositoryUpstreamMappingRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_COLS: &str = r#"
    id, repository_id, path_prefix, upstream_url, upstream_name_prefix,
    upstream_auth_type, secret_ref, managed_by, managed_by_digest,
    insecure_upstream_url, trust_upstream_publish_time,
    mtls_cert_ref, mtls_key_ref, ca_bundle_ref, pinned_cert_sha256,
    created_at, updated_at
"#;

// ---------------------------------------------------------------------------
// Auth-variant <-> DB string codec
// ---------------------------------------------------------------------------

const AUTH_ANONYMOUS: &str = "anonymous";
const AUTH_BEARER_CHALLENGE: &str = "bearer_challenge";
const AUTH_BASIC: &str = "basic";

fn auth_to_db(auth: &UpstreamAuth) -> &'static str {
    match auth {
        UpstreamAuth::Anonymous => AUTH_ANONYMOUS,
        UpstreamAuth::BearerChallenge => AUTH_BEARER_CHALLENGE,
        UpstreamAuth::Basic { .. } => AUTH_BASIC,
    }
}

fn auth_from_db(db: &str) -> DomainResult<UpstreamAuth> {
    match db {
        AUTH_ANONYMOUS => Ok(UpstreamAuth::Anonymous),
        AUTH_BEARER_CHALLENGE => Ok(UpstreamAuth::BearerChallenge),
        // The username column is not yet on the schema — see module
        // docs. Decode `Basic` with an empty username; a future change
        // adds the column.
        //
        // Carried-forward — `UpstreamAuth::Basic` username schema gap:
        // schema extension owed to a future change; the empty-string
        // fallback is intentional until then.
        AUTH_BASIC => Ok(UpstreamAuth::Basic {
            username: String::new(),
        }),
        other => Err(DomainError::Invariant(format!(
            "unknown upstream_auth_type `{other}` in repository_upstream_mappings"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct UpstreamMappingRow {
    id: Uuid,
    repository_id: Uuid,
    path_prefix: String,
    upstream_url: String,
    /// Optional outbound OCI path-prefix. Schema CHECK constraint
    /// `chk_repository_upstream_mappings_name_prefix` mirrors the
    /// domain constructor's `validate_upstream_name_prefix`.
    upstream_name_prefix: Option<String>,
    upstream_auth_type: String,
    /// Read raw `serde_json::Value` so the `serde_json::from_value`
    /// step in `row_to_mapping` can materialise the typed `SecretRef`
    /// or surface a clear `DomainError::Invariant` on malformed JSONB.
    secret_ref: Option<serde_json::Value>,
    managed_by: String,
    managed_by_digest: Option<Vec<u8>>,
    /// Operator-explicit opt-in to a plaintext (`http://`) upstream URL.
    /// Schema default is `false`.
    insecure_upstream_url: bool,
    /// Per-upstream opt-in to publish-time anchoring of the quarantine
    /// window. Schema default is `false`.
    trust_upstream_publish_time: bool,
    /// mTLS / cert-pinning material. Decoded the same way as `secret_ref`.
    mtls_cert_ref: Option<serde_json::Value>,
    mtls_key_ref: Option<serde_json::Value>,
    ca_bundle_ref: Option<serde_json::Value>,
    pinned_cert_sha256: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Decode an optional `SecretRef`-shaped JSONB column into the typed
/// value object. The schema CHECK constraint already validates the
/// `{source, location}` shape on insert; this is the typed-error
/// boundary for any out-of-band SQL that bypassed the constraint.
fn decode_secret_ref_jsonb(
    value: Option<serde_json::Value>,
    field: &'static str,
    id: Uuid,
) -> DomainResult<Option<hort_domain::ports::secret_port::SecretRef>> {
    match value {
        None => Ok(None),
        Some(v) => Some(serde_json::from_value(v).map_err(|e| {
            DomainError::Invariant(format!("{field} jsonb decode failed for mapping {id}: {e}"))
        }))
        .transpose(),
    }
}

fn row_to_mapping(row: UpstreamMappingRow) -> DomainResult<RepositoryUpstreamMapping> {
    let upstream_auth = auth_from_db(&row.upstream_auth_type)?;
    let secret_ref = decode_secret_ref_jsonb(row.secret_ref, "secret_ref", row.id)?;
    let mtls_cert_ref = decode_secret_ref_jsonb(row.mtls_cert_ref, "mtls_cert_ref", row.id)?;
    let mtls_key_ref = decode_secret_ref_jsonb(row.mtls_key_ref, "mtls_key_ref", row.id)?;
    let ca_bundle_ref = decode_secret_ref_jsonb(row.ca_bundle_ref, "ca_bundle_ref", row.id)?;
    let managed_by = ManagedBy::from_str(&row.managed_by).map_err(|_| {
        DomainError::Invariant(format!(
            "unknown managed_by `{}` in repository_upstream_mappings (id={})",
            row.managed_by, row.id
        ))
    })?;
    let managed_by_digest = match row.managed_by_digest {
        None => None,
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err(DomainError::Invariant(format!(
                    "managed_by_digest is {} bytes, expected 32 (id={})",
                    bytes.len(),
                    row.id
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
    };
    // The schema CHECK enforces the (managed_by=GitOps ↔ digest IS NOT NULL)
    // invariant; defence-in-depth here so a partial migration or
    // out-of-band SQL surfaces as a typed adapter error rather than
    // silently propagating.
    match (managed_by, &managed_by_digest) {
        (ManagedBy::GitOps, None) => {
            return Err(DomainError::Invariant(format!(
                "managed_by=gitops row missing managed_by_digest (id={})",
                row.id
            )));
        }
        (ManagedBy::Local, Some(_)) => {
            return Err(DomainError::Invariant(format!(
                "managed_by=local row carries managed_by_digest (id={})",
                row.id
            )));
        }
        _ => {}
    }
    // Row decoder funnels through `RepositoryUpstreamMapping::new` so
    // the value-object invariant gets re-checked against on-disk state.
    // A row that somehow ended up with a plaintext upstream and `false`
    // for `insecure_upstream_url` (out-of-band SQL, partial migration)
    // surfaces as a typed `DomainError::Validation` here rather than
    // silently propagating to the proxy adapter.
    RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
        id: row.id,
        repository_id: row.repository_id,
        path_prefix: row.path_prefix,
        upstream_url: row.upstream_url,
        upstream_name_prefix: row.upstream_name_prefix,
        upstream_auth,
        secret_ref,
        managed_by,
        managed_by_digest,
        insecure_upstream_url: row.insecure_upstream_url,
        trust_upstream_publish_time: row.trust_upstream_publish_time,
        mtls_cert_ref,
        mtls_key_ref,
        ca_bundle_ref,
        pinned_cert_sha256: row.pinned_cert_sha256,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Port impl
// ---------------------------------------------------------------------------

impl RepositoryUpstreamMappingRepository for PgRepositoryUpstreamMappingRepo {
    fn list_for_repository(
        &self,
        repository_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                %repository_id,
                "list_for_repository"
            );
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM repository_upstream_mappings
                    WHERE repository_id = $1
                    ORDER BY created_at ASC, id ASC"#
            );
            let rows: Vec<UpstreamMappingRow> = sqlx::query_as(&sql)
                .bind(repository_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "RepositoryUpstreamMapping", &repository_id.to_string())
                })?;
            rows.into_iter().map(row_to_mapping).collect()
        })
    }

    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        Box::pin(async move {
            tracing::debug!(entity = "RepositoryUpstreamMapping", "list_all");
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM repository_upstream_mappings
                    ORDER BY repository_id ASC, created_at ASC, id ASC"#
            );
            let rows: Vec<UpstreamMappingRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RepositoryUpstreamMapping", "*"))?;
            rows.into_iter().map(row_to_mapping).collect()
        })
    }

    fn upsert(&self, mapping: RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                repository_id = %mapping.repository_id,
                path_prefix = %mapping.path_prefix,
                "upsert"
            );
            let auth_db = auth_to_db(&mapping.upstream_auth);
            // `SecretRef` Serialize is total — the codec just records
            // {source, location}, both of which are infallibly
            // serialisable. Materialise to NULL for `Anonymous`.
            let secret_ref_json = mapping
                .secret_ref
                .as_ref()
                .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
            let mtls_cert_ref_json = mapping
                .mtls_cert_ref
                .as_ref()
                .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
            let mtls_key_ref_json = mapping
                .mtls_key_ref
                .as_ref()
                .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
            let ca_bundle_ref_json = mapping
                .ca_bundle_ref
                .as_ref()
                .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
            sqlx::query(
                r#"INSERT INTO repository_upstream_mappings (
                       id, repository_id, path_prefix, upstream_url,
                       upstream_name_prefix,
                       upstream_auth_type, secret_ref,
                       managed_by, managed_by_digest,
                       insecure_upstream_url, trust_upstream_publish_time,
                       mtls_cert_ref, mtls_key_ref, ca_bundle_ref, pinned_cert_sha256,
                       created_at, updated_at
                   ) VALUES (
                       $1, $2, $3, $4, $5, $6, $7, 'local', NULL, $8, $9,
                       $10, $11, $12, $13, $14, $15
                   )
                   ON CONFLICT (repository_id, path_prefix) DO UPDATE SET
                       upstream_url                = EXCLUDED.upstream_url,
                       upstream_name_prefix        = EXCLUDED.upstream_name_prefix,
                       upstream_auth_type          = EXCLUDED.upstream_auth_type,
                       secret_ref                  = EXCLUDED.secret_ref,
                       managed_by                  = 'local',
                       managed_by_digest           = NULL,
                       insecure_upstream_url       = EXCLUDED.insecure_upstream_url,
                       trust_upstream_publish_time = EXCLUDED.trust_upstream_publish_time,
                       mtls_cert_ref               = EXCLUDED.mtls_cert_ref,
                       mtls_key_ref                = EXCLUDED.mtls_key_ref,
                       ca_bundle_ref               = EXCLUDED.ca_bundle_ref,
                       pinned_cert_sha256          = EXCLUDED.pinned_cert_sha256,
                       updated_at                  = NOW()"#,
            )
            .bind(mapping.id)
            .bind(mapping.repository_id)
            .bind(&mapping.path_prefix)
            .bind(&mapping.upstream_url)
            .bind(mapping.upstream_name_prefix.as_deref())
            .bind(auth_db)
            .bind(secret_ref_json)
            .bind(mapping.insecure_upstream_url)
            .bind(mapping.trust_upstream_publish_time)
            .bind(mtls_cert_ref_json)
            .bind(mtls_key_ref_json)
            .bind(ca_bundle_ref_json)
            .bind(mapping.pinned_cert_sha256.as_deref())
            .bind(mapping.created_at)
            .bind(mapping.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                map_sqlx_error(
                    &e,
                    "RepositoryUpstreamMapping",
                    &format!("{}/{}", mapping.repository_id, mapping.path_prefix),
                )
            })?;
            Ok(())
        })
    }

    fn delete(&self, repository_id: Uuid, path_prefix: &str) -> BoxFuture<'_, DomainResult<()>> {
        let path_prefix = path_prefix.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                %repository_id,
                %path_prefix,
                "delete"
            );
            sqlx::query(
                r#"DELETE FROM repository_upstream_mappings
                    WHERE repository_id = $1 AND path_prefix = $2"#,
            )
            .bind(repository_id)
            .bind(&path_prefix)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                map_sqlx_error(
                    &e,
                    "RepositoryUpstreamMapping",
                    &format!("{repository_id}/{path_prefix}"),
                )
            })?;
            Ok(())
        })
    }

    // ---- managed-write surface ----

    fn list_managed_by_gitops(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                "list_managed_by_gitops"
            );
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM repository_upstream_mappings
                    WHERE managed_by = 'gitops'
                    ORDER BY repository_id ASC, path_prefix ASC, id ASC"#
            );
            let rows: Vec<UpstreamMappingRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RepositoryUpstreamMapping", "managed"))?;
            rows.into_iter().map(row_to_mapping).collect()
        })
    }

    fn save_managed(&self, mapping: &RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>> {
        // Validate the in-memory invariant before issuing SQL — adapters
        // are the last line of defence against a caller widening the
        // (managed_by=GitOps ↔ digest=Some(_)) pairing.
        let bad_managed_by = mapping.managed_by;
        if bad_managed_by != ManagedBy::GitOps {
            return Box::pin(async move {
                Err(DomainError::Invariant(format!(
                    "save_managed called with managed_by={bad_managed_by} (expected GitOps)"
                )))
            });
        }
        let Some(digest) = mapping.managed_by_digest else {
            return Box::pin(async move {
                Err(DomainError::Invariant(
                    "save_managed called without managed_by_digest".into(),
                ))
            });
        };

        let id = mapping.id;
        let repository_id = mapping.repository_id;
        let path_prefix = mapping.path_prefix.clone();
        let upstream_url = mapping.upstream_url.clone();
        let upstream_name_prefix = mapping.upstream_name_prefix.clone();
        let auth_db = auth_to_db(&mapping.upstream_auth);
        let secret_ref_json = mapping
            .secret_ref
            .as_ref()
            .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
        let mtls_cert_ref_json = mapping
            .mtls_cert_ref
            .as_ref()
            .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
        let mtls_key_ref_json = mapping
            .mtls_key_ref
            .as_ref()
            .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
        let ca_bundle_ref_json = mapping
            .ca_bundle_ref
            .as_ref()
            .map(|s| serde_json::to_value(s).expect("SecretRef Serialize is total"));
        let pinned_cert_sha256 = mapping.pinned_cert_sha256.clone();
        let digest_vec = digest.to_vec();
        let insecure = mapping.insecure_upstream_url;
        let trust_publish_time = mapping.trust_upstream_publish_time;

        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                %repository_id,
                %path_prefix,
                "save_managed"
            );
            sqlx::query(
                r#"INSERT INTO repository_upstream_mappings (
                       id, repository_id, path_prefix, upstream_url,
                       upstream_name_prefix,
                       upstream_auth_type, secret_ref,
                       managed_by, managed_by_digest,
                       insecure_upstream_url, trust_upstream_publish_time,
                       mtls_cert_ref, mtls_key_ref, ca_bundle_ref, pinned_cert_sha256
                   ) VALUES (
                       $1, $2, $3, $4, $5, $6, $7, 'gitops', $8, $9, $10,
                       $11, $12, $13, $14
                   )
                   ON CONFLICT (repository_id, path_prefix) DO UPDATE SET
                       upstream_url                = EXCLUDED.upstream_url,
                       upstream_name_prefix        = EXCLUDED.upstream_name_prefix,
                       upstream_auth_type          = EXCLUDED.upstream_auth_type,
                       secret_ref                  = EXCLUDED.secret_ref,
                       managed_by                  = 'gitops',
                       managed_by_digest           = EXCLUDED.managed_by_digest,
                       insecure_upstream_url       = EXCLUDED.insecure_upstream_url,
                       trust_upstream_publish_time = EXCLUDED.trust_upstream_publish_time,
                       mtls_cert_ref               = EXCLUDED.mtls_cert_ref,
                       mtls_key_ref                = EXCLUDED.mtls_key_ref,
                       ca_bundle_ref               = EXCLUDED.ca_bundle_ref,
                       pinned_cert_sha256          = EXCLUDED.pinned_cert_sha256,
                       updated_at                  = NOW()"#,
            )
            .bind(id)
            .bind(repository_id)
            .bind(&path_prefix)
            .bind(&upstream_url)
            .bind(upstream_name_prefix.as_deref())
            .bind(auth_db)
            .bind(secret_ref_json)
            .bind(&digest_vec)
            .bind(insecure)
            .bind(trust_publish_time)
            .bind(mtls_cert_ref_json)
            .bind(mtls_key_ref_json)
            .bind(ca_bundle_ref_json)
            .bind(pinned_cert_sha256.as_deref())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                map_sqlx_error(
                    &e,
                    "RepositoryUpstreamMapping",
                    &format!("{repository_id}/{path_prefix}"),
                )
            })?;
            Ok(())
        })
    }

    fn delete_managed_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "RepositoryUpstreamMapping",
                %id,
                "delete_managed_by_id"
            );
            // The `WHERE managed_by = 'gitops'` clause is the
            // defence-in-depth: the diff layer never schedules a delete
            // on a `local` row, but the port enforces the invariant if
            // out-of-band SQL leaves a row in unexpected state.
            sqlx::query(
                r#"DELETE FROM repository_upstream_mappings
                    WHERE id = $1 AND managed_by = 'gitops'"#,
            )
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "RepositoryUpstreamMapping", &id.to_string()))?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    use std::env;

    // -- Compile-time port-impl assertions ------------------------------

    #[tokio::test]
    async fn pg_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgRepositoryUpstreamMappingRepo::new(pool);
    }

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: RepositoryUpstreamMappingRepository>() {}
        _assert_port::<PgRepositoryUpstreamMappingRepo>();
    }

    // -- auth codec round-trip ------------------------------------------

    #[test]
    fn auth_codec_round_trips_anonymous() {
        let s = auth_to_db(&UpstreamAuth::Anonymous);
        assert_eq!(s, "anonymous");
        let back = auth_from_db(s).unwrap();
        assert_eq!(back, UpstreamAuth::Anonymous);
    }

    #[test]
    fn auth_codec_round_trips_bearer_challenge() {
        let s = auth_to_db(&UpstreamAuth::BearerChallenge);
        assert_eq!(s, "bearer_challenge");
        let back = auth_from_db(s).unwrap();
        assert_eq!(back, UpstreamAuth::BearerChallenge);
    }

    #[test]
    fn auth_codec_round_trips_basic_with_empty_username() {
        // Schema doesn't yet carry a username column — see module
        // docs. The decoded variant has an empty username; callers
        // that rely on the username must wait for a future schema change.
        let s = auth_to_db(&UpstreamAuth::Basic {
            username: "alice".into(),
        });
        assert_eq!(s, "basic");
        let back = auth_from_db(s).unwrap();
        assert_eq!(
            back,
            UpstreamAuth::Basic {
                username: String::new()
            }
        );
    }

    #[test]
    fn auth_codec_rejects_unknown_db_string() {
        let err = auth_from_db("hmac_signed").unwrap_err();
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("hmac_signed")),
            other => panic!("expected Invariant for unknown auth type, got {other:?}"),
        }
    }

    // -- row_to_mapping decode path ---------------------------------------
    //
    // No DB required — exercises the in-memory decoder with a
    // synthetic `UpstreamMappingRow` so the `upstream_name_prefix`
    // column-to-field threading is unit-testable without a Postgres
    // round trip. The DB-backed round-trip tests below cover the
    // encode + persist + read-back path against a live schema.

    fn synthetic_row(upstream_name_prefix: Option<String>) -> UpstreamMappingRow {
        let now = Utc::now();
        UpstreamMappingRow {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: "https://registry.example.com".into(),
            upstream_name_prefix,
            upstream_auth_type: AUTH_ANONYMOUS.into(),
            secret_ref: None,
            managed_by: "local".into(),
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn row_to_mapping_preserves_upstream_name_prefix_some() {
        let row = synthetic_row(Some("docker.io".into()));
        let m = row_to_mapping(row).expect("decode must succeed");
        assert_eq!(m.upstream_name_prefix.as_deref(), Some("docker.io"));
    }

    #[test]
    fn row_to_mapping_preserves_upstream_name_prefix_none() {
        let row = synthetic_row(None);
        let m = row_to_mapping(row).expect("decode must succeed");
        assert!(m.upstream_name_prefix.is_none());
    }

    #[test]
    fn row_to_mapping_rejects_invalid_upstream_name_prefix() {
        // The domain constructor is the last line of defence — a row
        // that somehow ended up with an invalid prefix (out-of-band SQL
        // bypassing the schema CHECK) surfaces as a typed
        // `DomainError::Validation` rather than silently propagating.
        let row = synthetic_row(Some("foo/../bar".into()));
        let err = row_to_mapping(row).expect_err("invalid prefix must be rejected");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    // -------------------------------------------------------------------
    // DB-backed integration tests. Mirrors `pg_content_reference_repo`'s
    // skip-when-DATABASE_URL-unset pattern.
    // -------------------------------------------------------------------

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-upstream-mapping-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'generic'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed repo insert");
        id
    }

    async fn cleanup_repo(pool: &PgPool, repo: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    fn make_mapping(
        repo: Uuid,
        path_prefix: &str,
        upstream_url: &str,
        auth: UpstreamAuth,
    ) -> RepositoryUpstreamMapping {
        make_mapping_with_secret(repo, path_prefix, upstream_url, auth, None)
    }

    fn make_mapping_with_secret(
        repo: Uuid,
        path_prefix: &str,
        upstream_url: &str,
        auth: UpstreamAuth,
        secret_ref: Option<hort_domain::ports::secret_port::SecretRef>,
    ) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo,
            path_prefix: path_prefix.into(),
            upstream_url: upstream_url.into(),
            upstream_name_prefix: None,
            upstream_auth: auth,
            secret_ref,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Test fixture for the gitops-write path. Mirrors `make_mapping` but
    /// sets `managed_by = GitOps` + a deterministic 32-byte digest so
    /// `save_managed`'s preconditions are satisfied.
    fn make_managed_mapping(
        repo: Uuid,
        path_prefix: &str,
        upstream_url: &str,
        auth: UpstreamAuth,
        digest: [u8; 32],
    ) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo,
            path_prefix: path_prefix.into(),
            upstream_url: upstream_url.into(),
            upstream_name_prefix: None,
            upstream_auth: auth,
            secret_ref: None,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some(digest),
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Insert + list round-trip. The empty-prefix row coexists with
    /// non-empty prefix rows under the same repository — uniqueness is
    /// per (repo, prefix), not per repo.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_and_list_round_trip_multi_prefix() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        adapter
            .upsert(make_mapping(
                repo,
                "",
                "https://default.example.com",
                UpstreamAuth::Anonymous,
            ))
            .await
            .expect("empty prefix insert");
        adapter
            .upsert(make_mapping(
                repo,
                "dockerhub/",
                "https://registry-1.docker.io",
                UpstreamAuth::BearerChallenge,
            ))
            .await
            .expect("dockerhub prefix insert");
        adapter
            .upsert(make_mapping(
                repo,
                "ghcr/",
                "https://ghcr.io",
                UpstreamAuth::Anonymous,
            ))
            .await
            .expect("ghcr prefix insert");

        let listed = adapter
            .list_for_repository(repo)
            .await
            .expect("list_for_repository");
        assert_eq!(listed.len(), 3);
        let prefixes: Vec<&str> = listed.iter().map(|m| m.path_prefix.as_str()).collect();
        assert!(prefixes.contains(&""));
        assert!(prefixes.contains(&"dockerhub/"));
        assert!(prefixes.contains(&"ghcr/"));

        cleanup_repo(&pool, repo).await;
    }

    /// Re-upsert under the same `(repository_id, path_prefix)` updates
    /// the existing row in place; `id` stays stable. This is the
    /// contract the resolver's cache invalidates against.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_replaces_existing_row_in_place() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let first = make_mapping(
            repo,
            "dockerhub/",
            "https://registry-1.docker.io",
            UpstreamAuth::BearerChallenge,
        );
        let first_id = first.id;
        adapter.upsert(first).await.expect("first upsert");

        // Same (repo, prefix); different URL + auth.
        let second = make_mapping(
            repo,
            "dockerhub/",
            "https://mirror.example.com",
            UpstreamAuth::Anonymous,
        );
        let second_id = second.id;
        assert_ne!(first_id, second_id, "test fixture pre-condition");
        adapter.upsert(second).await.expect("second upsert");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].upstream_url, "https://mirror.example.com");
        assert_eq!(listed[0].upstream_auth, UpstreamAuth::Anonymous);
        assert_eq!(
            listed[0].id, first_id,
            "row id must stay stable across upsert (cache invalidation contract)"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Delete is idempotent; a second delete (or a delete of a never-
    /// recorded row) is a no-op rather than an error.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_is_idempotent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());
        adapter
            .upsert(make_mapping(
                repo,
                "ghcr/",
                "https://ghcr.io",
                UpstreamAuth::Anonymous,
            ))
            .await
            .unwrap();
        adapter.delete(repo, "ghcr/").await.expect("first delete");
        adapter
            .delete(repo, "ghcr/")
            .await
            .expect("second delete must be a no-op");
        adapter
            .delete(repo, "no-such-prefix/")
            .await
            .expect("delete of a missing row must be a no-op");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert!(listed.is_empty());

        cleanup_repo(&pool, repo).await;
    }

    /// `list_all` returns mappings across multiple repositories. Used
    /// by the resolver's cache-refresh task.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_all_spans_repositories() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        adapter
            .upsert(make_mapping(
                repo_a,
                "",
                "https://a.example.com",
                UpstreamAuth::Anonymous,
            ))
            .await
            .unwrap();
        adapter
            .upsert(make_mapping(
                repo_b,
                "",
                "https://b.example.com",
                UpstreamAuth::Anonymous,
            ))
            .await
            .unwrap();

        let all = adapter.list_all().await.unwrap();
        // Filter to just our seeded repos (other tests may have left
        // rows behind under different repo ids).
        let filtered: Vec<_> = all
            .into_iter()
            .filter(|m| m.repository_id == repo_a || m.repository_id == repo_b)
            .collect();
        assert_eq!(filtered.len(), 2);

        cleanup_repo(&pool, repo_a).await;
        cleanup_repo(&pool, repo_b).await;
    }

    /// `SecretRef::EnvVar` round-trips through the JSONB column without
    /// lossy transformations. The decoded mapping carries an identical
    /// `secret_ref` value back.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn secret_ref_env_var_round_trips_through_jsonb() {
        use hort_domain::ports::secret_port::{SecretRef, SecretSource};
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let secret = SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_UPSTREAM_TOKEN".into(),
        };
        adapter
            .upsert(make_mapping_with_secret(
                repo,
                "ghcr/",
                "https://ghcr.io",
                UpstreamAuth::BearerChallenge,
                Some(secret.clone()),
            ))
            .await
            .expect("upsert env_var secret_ref");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].secret_ref.as_ref(), Some(&secret));

        cleanup_repo(&pool, repo).await;
    }

    /// `SecretRef::File` round-trips through the JSONB column. Mirrors
    /// the env-var case for the second source kind.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn secret_ref_file_round_trips_through_jsonb() {
        use hort_domain::ports::secret_port::{SecretRef, SecretSource};
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let secret = SecretRef {
            source: SecretSource::File,
            location: "/run/secrets/ghcr_pat".into(),
        };
        adapter
            .upsert(make_mapping_with_secret(
                repo,
                "ghcr/",
                "https://ghcr.io",
                UpstreamAuth::BearerChallenge,
                Some(secret.clone()),
            ))
            .await
            .expect("upsert file secret_ref");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].secret_ref.as_ref(), Some(&secret));

        cleanup_repo(&pool, repo).await;
    }

    /// The migration's CHECK constraint rejects malformed JSONB (missing
    /// keys or unknown source). Inserts a raw row that bypasses the
    /// typed adapter and asserts the DB surfaces the constraint
    /// violation.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn check_constraint_rejects_malformed_secret_ref_jsonb() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        // Missing `location` key — must violate the CHECK.
        let bad_jsonb = serde_json::json!({"source": "env_var"});
        let res = sqlx::query(
            r#"INSERT INTO repository_upstream_mappings (
                   id, repository_id, path_prefix, upstream_url,
                   upstream_auth_type, secret_ref
               ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind("ghcr/")
        .bind("https://ghcr.io")
        .bind("bearer_challenge")
        .bind(bad_jsonb)
        .execute(&pool)
        .await;
        assert!(
            res.is_err(),
            "DB CHECK must reject secret_ref jsonb missing `location`"
        );

        // Unknown `source` value — must violate the CHECK.
        let bad_source = serde_json::json!({"source": "vault", "location": "x"});
        let res2 = sqlx::query(
            r#"INSERT INTO repository_upstream_mappings (
                   id, repository_id, path_prefix, upstream_url,
                   upstream_auth_type, secret_ref
               ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind("ghcr2/")
        .bind("https://ghcr.io")
        .bind("bearer_challenge")
        .bind(bad_source)
        .execute(&pool)
        .await;
        assert!(
            res2.is_err(),
            "DB CHECK must reject secret_ref jsonb with unknown `source`"
        );

        // JSONB null `source` — the key is present but its value is
        // `null`. The original `secret_ref ? 'source'` check passed
        // here because the key existed; the tighter
        // `jsonb_typeof(...) = 'string'` form catches it.
        let null_source = serde_json::json!({"source": null, "location": "/x"});
        let res3 = sqlx::query(
            r#"INSERT INTO repository_upstream_mappings (
                   id, repository_id, path_prefix, upstream_url,
                   upstream_auth_type, secret_ref
               ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind("ghcr3/")
        .bind("https://ghcr.io")
        .bind("bearer_challenge")
        .bind(null_source)
        .execute(&pool)
        .await;
        assert!(
            res3.is_err(),
            "DB CHECK must reject secret_ref jsonb with null `source`"
        );

        cleanup_repo(&pool, repo).await;
    }

    // -------------------------------------------------------------------
    // managed-write surface
    // -------------------------------------------------------------------

    /// `save_managed` writes a row with managed_by=gitops + digest set;
    /// `list_managed_by_gitops` returns it. Re-issuing `save_managed`
    /// with the same `(repository_id, path_prefix)` updates in place
    /// without churning the row id.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trip_then_list_filters_to_gitops() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let mapping = make_managed_mapping(
            repo,
            "dockerhub/",
            "https://registry-1.docker.io",
            UpstreamAuth::BearerChallenge,
            [0xAB; 32],
        );
        let mapping_id = mapping.id;
        adapter.save_managed(&mapping).await.expect("save_managed");

        let listed = adapter
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        let m = listed
            .into_iter()
            .find(|m| m.repository_id == repo && m.path_prefix == "dockerhub/")
            .expect("our managed row is in the listing");
        assert_eq!(m.id, mapping_id);
        assert_eq!(m.managed_by, ManagedBy::GitOps);
        assert_eq!(m.managed_by_digest, Some([0xAB; 32]));
        assert_eq!(m.upstream_url, "https://registry-1.docker.io");

        // Idempotent re-save: same key, different URL → updates in
        // place; row id stays stable; digest reflects the latest spec.
        let mut updated = mapping.clone();
        updated.id = Uuid::new_v4(); // adapter must ignore the supplied id on update
        updated.upstream_url = "https://mirror.example.com".into();
        updated.managed_by_digest = Some([0xCD; 32]);
        adapter
            .save_managed(&updated)
            .await
            .expect("re-save_managed");

        let listed = adapter.list_managed_by_gitops().await.unwrap();
        let m = listed
            .into_iter()
            .find(|m| m.repository_id == repo && m.path_prefix == "dockerhub/")
            .unwrap();
        assert_eq!(m.id, mapping_id, "row id stays stable across re-save");
        assert_eq!(m.upstream_url, "https://mirror.example.com");
        assert_eq!(m.managed_by_digest, Some([0xCD; 32]));

        cleanup_repo(&pool, repo).await;
    }

    /// `delete_managed_by_id` removes a gitops row; calling it on an
    /// id that doesn't exist or that is `local` is a no-op (defensive).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_managed_by_id_only_removes_gitops_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        // Seed a managed row via save_managed and a local row via upsert.
        let managed = make_managed_mapping(
            repo,
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::BearerChallenge,
            [0x42; 32],
        );
        let managed_id = managed.id;
        adapter.save_managed(&managed).await.unwrap();

        let local = make_mapping(
            repo,
            "",
            "https://default.example.com",
            UpstreamAuth::Anonymous,
        );
        let local_id = local.id;
        adapter.upsert(local).await.unwrap();

        // Deleting the managed row removes it.
        adapter.delete_managed_by_id(managed_id).await.unwrap();
        let listed = adapter.list_managed_by_gitops().await.unwrap();
        assert!(listed.iter().all(|m| m.id != managed_id));

        // Deleting by the local row's id is a no-op (the WHERE clause
        // filters on managed_by='gitops'). The local row still listed
        // via list_for_repository.
        adapter.delete_managed_by_id(local_id).await.unwrap();
        let listed_local = adapter.list_for_repository(repo).await.unwrap();
        assert!(listed_local.iter().any(|m| m.id == local_id));

        // Deleting an unknown id is a no-op too.
        adapter.delete_managed_by_id(Uuid::new_v4()).await.unwrap();

        cleanup_repo(&pool, repo).await;
    }

    /// `save_managed` rejects a mapping carrying `ManagedBy::Local` —
    /// adapters do not silently widen the invariant.
    #[tokio::test]
    async fn save_managed_rejects_local_mapping() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL");
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool);

        let mut mapping = make_mapping(
            Uuid::new_v4(),
            "ghcr/",
            "https://ghcr.io",
            UpstreamAuth::Anonymous,
        );
        // managed_by defaults to Local from make_mapping; assert the
        // adapter refuses it before any SQL is issued.
        assert_eq!(mapping.managed_by, ManagedBy::Local);

        let err = adapter.save_managed(&mapping).await.unwrap_err();
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("managed_by"), "msg={msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }

        // Same rejection if managed_by is GitOps but digest is None.
        mapping.managed_by = ManagedBy::GitOps;
        mapping.managed_by_digest = None;
        let err = adapter.save_managed(&mapping).await.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    /// The schema CHECK constraint enforces "managed → digest set,
    /// local → digest NULL". A row with `managed_by='gitops'` but
    /// `managed_by_digest=NULL` must be rejected at INSERT.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn check_constraint_rejects_managed_gitops_without_digest() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let res = sqlx::query(
            r#"INSERT INTO repository_upstream_mappings (
                   id, repository_id, path_prefix, upstream_url,
                   upstream_auth_type, secret_ref,
                   managed_by, managed_by_digest
               ) VALUES ($1, $2, $3, $4, $5, NULL, 'gitops', NULL)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind("ghcr/")
        .bind("https://ghcr.io")
        .bind("bearer_challenge")
        .execute(&pool)
        .await;
        assert!(
            res.is_err(),
            "DB CHECK must reject managed_by='gitops' with NULL digest"
        );

        // Symmetric case: local + non-NULL digest must also be rejected.
        let res2 = sqlx::query(
            r#"INSERT INTO repository_upstream_mappings (
                   id, repository_id, path_prefix, upstream_url,
                   upstream_auth_type, secret_ref,
                   managed_by, managed_by_digest
               ) VALUES ($1, $2, $3, $4, $5, NULL, 'local', $6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind("ghcr2/")
        .bind("https://ghcr.io")
        .bind("bearer_challenge")
        .bind(vec![0u8; 32])
        .execute(&pool)
        .await;
        assert!(
            res2.is_err(),
            "DB CHECK must reject managed_by='local' with non-NULL digest"
        );

        cleanup_repo(&pool, repo).await;
    }

    // -------------------------------------------------------------------
    // `upstream_name_prefix` column round-trip + CHECK
    // -------------------------------------------------------------------

    /// Build a `RepositoryUpstreamMapping` with the `upstream_name_prefix`
    /// field set — used by the DB tests below.
    fn make_mapping_with_name_prefix(
        repo: Uuid,
        path_prefix: &str,
        upstream_url: &str,
        upstream_name_prefix: Option<&str>,
    ) -> RepositoryUpstreamMapping {
        let mut m = make_mapping(repo, path_prefix, upstream_url, UpstreamAuth::Anonymous);
        m.upstream_name_prefix = upstream_name_prefix.map(str::to_owned);
        m
    }

    /// `Some(prefix)` survives upsert + read-back.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upstream_name_prefix_some_round_trips() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        adapter
            .upsert(make_mapping_with_name_prefix(
                repo,
                "",
                "https://zot.example.com",
                Some("docker.io"),
            ))
            .await
            .expect("upsert with Some prefix");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].upstream_name_prefix.as_deref(), Some("docker.io"));

        cleanup_repo(&pool, repo).await;
    }

    /// `None` (default) survives upsert + read-back.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upstream_name_prefix_none_round_trips() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        adapter
            .upsert(make_mapping_with_name_prefix(
                repo,
                "",
                "https://registry.example.com",
                None,
            ))
            .await
            .expect("upsert with None prefix");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].upstream_name_prefix.is_none());

        cleanup_repo(&pool, repo).await;
    }

    /// Update from `Some` to `None` and back — `upsert` overwrites the
    /// column either direction.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upstream_name_prefix_updates_between_some_and_none() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        // Some → None.
        adapter
            .upsert(make_mapping_with_name_prefix(
                repo,
                "",
                "https://zot.example.com",
                Some("docker.io"),
            ))
            .await
            .unwrap();
        adapter
            .upsert(make_mapping_with_name_prefix(
                repo,
                "",
                "https://zot.example.com",
                None,
            ))
            .await
            .unwrap();
        let after_clear = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(after_clear.len(), 1);
        assert!(
            after_clear[0].upstream_name_prefix.is_none(),
            "upsert must clear the column when called with None"
        );

        // None → Some.
        adapter
            .upsert(make_mapping_with_name_prefix(
                repo,
                "",
                "https://zot.example.com",
                Some("acme/internal"),
            ))
            .await
            .unwrap();
        let after_set = adapter.list_for_repository(repo).await.unwrap();
        assert_eq!(after_set.len(), 1);
        assert_eq!(
            after_set[0].upstream_name_prefix.as_deref(),
            Some("acme/internal")
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `save_managed` (the gitops write path) also threads the column.
    /// Adds a digest-bearing row with the prefix set, reads back, and
    /// asserts the value survives.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_upstream_name_prefix() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let mut m = make_managed_mapping(
            repo,
            "",
            "https://zot.example.com",
            UpstreamAuth::Anonymous,
            [9u8; 32],
        );
        m.upstream_name_prefix = Some("docker.io".into());
        adapter.save_managed(&m).await.expect("save_managed");

        let listed = adapter.list_managed_by_gitops().await.unwrap();
        let row = listed
            .into_iter()
            .find(|r| r.repository_id == repo)
            .expect("seeded gitops row must be listed");
        assert_eq!(row.upstream_name_prefix.as_deref(), Some("docker.io"));

        cleanup_repo(&pool, repo).await;
    }

    /// The migration's CHECK constraint mirrors the domain regex. Raw
    /// SQL bypassing the typed adapter (e.g. an out-of-band insert)
    /// hits the DB-side guard. One shape per independent guard so the
    /// CHECK's three sub-clauses each have explicit coverage.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn check_constraint_rejects_invalid_upstream_name_prefix() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        for (bad, reason) in [
            ("../etc", "segment-of-dots + `..`-substring"),
            ("foo/", "anchored regex"),
            ("foo//bar", "anchored regex (empty segment)"),
            ("foo/./bar", "segment-of-dots"),
            ("foo..bar", "`..`-substring"),
            ("foo bar", "character-class"),
        ] {
            let res = sqlx::query(
                r#"INSERT INTO repository_upstream_mappings (
                       id, repository_id, path_prefix, upstream_url,
                       upstream_name_prefix, upstream_auth_type
                   ) VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(Uuid::new_v4())
            .bind(repo)
            .bind(format!("ck-{}", Uuid::new_v4().simple()))
            .bind("https://registry.example.com")
            .bind(bad)
            .bind("anonymous")
            .execute(&pool)
            .await;
            assert!(
                res.is_err(),
                "DB CHECK must reject upstream_name_prefix=`{bad}` ({reason})"
            );
        }

        // Accept-path sanity: `docker.io` (dots inside segment) and a
        // multi-segment path both insert cleanly so the CHECK is not
        // over-eager.
        for good in ["docker.io", "acme/internal/proxy", "v1.2_release-3"] {
            let res = sqlx::query(
                r#"INSERT INTO repository_upstream_mappings (
                       id, repository_id, path_prefix, upstream_url,
                       upstream_name_prefix, upstream_auth_type
                   ) VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(Uuid::new_v4())
            .bind(repo)
            .bind(format!("ok-{}", Uuid::new_v4().simple()))
            .bind("https://registry.example.com")
            .bind(good)
            .bind("anonymous")
            .execute(&pool)
            .await;
            assert!(
                res.is_ok(),
                "DB CHECK must accept upstream_name_prefix=`{good}` ({:?})",
                res.err()
            );
        }

        cleanup_repo(&pool, repo).await;
    }

    // -------------------------------------------------------------------
    // `trust_upstream_publish_time` round-trip
    // -------------------------------------------------------------------
    //
    // These tests pin the bind + read-back path so a regression anywhere
    // in the column-list / VALUES / EXCLUDED chain surfaces here.

    /// Both `true` and `false` round-trip through the `upsert` path —
    /// one serial test covers both so the `#[serial(hort_pg_db)]` lock
    /// is held once. Mirrors the `insecure_upstream_url` placement
    /// the adapter writes adjacent.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn trust_upstream_publish_time_round_trips_through_upsert() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        // Insert opted-in.
        let mut opted_in = make_mapping(
            repo,
            "trust-publish/",
            "https://upstream.example.com",
            UpstreamAuth::Anonymous,
        );
        opted_in.trust_upstream_publish_time = true;
        adapter.upsert(opted_in).await.expect("upsert opted-in");

        // Insert opted-out (the default).
        let opted_out = make_mapping(
            repo,
            "trust-default/",
            "https://upstream.example.com",
            UpstreamAuth::Anonymous,
        );
        // Assert the test fixture pre-condition — the default is false.
        assert!(!opted_out.trust_upstream_publish_time);
        adapter.upsert(opted_out).await.expect("upsert opted-out");

        let listed = adapter.list_for_repository(repo).await.unwrap();
        let opted_in_row = listed
            .iter()
            .find(|m| m.path_prefix == "trust-publish/")
            .expect("opted-in row in listing");
        let opted_out_row = listed
            .iter()
            .find(|m| m.path_prefix == "trust-default/")
            .expect("opted-out row in listing");
        assert!(
            opted_in_row.trust_upstream_publish_time,
            "true must survive upsert + read-back"
        );
        assert!(
            !opted_out_row.trust_upstream_publish_time,
            "false (default) must survive upsert + read-back"
        );

        // Idempotent update path: toggle the opted-out row to true and
        // confirm the EXCLUDED clause threads the new value.
        let mut flipped = make_mapping(
            repo,
            "trust-default/",
            "https://upstream.example.com",
            UpstreamAuth::Anonymous,
        );
        flipped.trust_upstream_publish_time = true;
        adapter.upsert(flipped).await.expect("re-upsert flipped");

        let after = adapter.list_for_repository(repo).await.unwrap();
        let after_row = after
            .iter()
            .find(|m| m.path_prefix == "trust-default/")
            .expect("flipped row in listing");
        assert!(
            after_row.trust_upstream_publish_time,
            "EXCLUDED.trust_upstream_publish_time must propagate on conflict-update"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `save_managed` (the gitops write path) also threads the column.
    /// Mirrors `save_managed_round_trips_upstream_name_prefix`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_trust_upstream_publish_time() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRepositoryUpstreamMappingRepo::new(pool.clone());

        let mut m = make_managed_mapping(
            repo,
            "",
            "https://upstream.example.com",
            UpstreamAuth::Anonymous,
            [0x46; 32],
        );
        m.trust_upstream_publish_time = true;
        adapter.save_managed(&m).await.expect("save_managed");

        let listed = adapter.list_managed_by_gitops().await.unwrap();
        let row = listed
            .into_iter()
            .find(|r| r.repository_id == repo)
            .expect("seeded gitops row must be listed");
        assert!(
            row.trust_upstream_publish_time,
            "save_managed must persist trust_upstream_publish_time"
        );

        cleanup_repo(&pool, repo).await;
    }
}
