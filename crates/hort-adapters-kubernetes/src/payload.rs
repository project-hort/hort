//! Pure helpers for building the Kubernetes `Secret` payload and
//! parsing the four reconciler-managed labels.
//!
//! Split out from [`secret_writer`](crate::secret_writer) so the
//! manifest-shape and label-parse logic — the parts where the bugs
//! actually live — are unit-testable without standing up a `kube::Client`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use serde_json::json;
use uuid::Uuid;

use hort_domain::entities::service_account::SecretFormat;
use hort_domain::ports::kubernetes_secret_writer::{ManagedSecret, ManagedSecretSpec};

use crate::metrics::{
    ANNOTATION_LAST_ROTATED, FIELD_MANAGER, LABEL_MANAGED_BY, LABEL_SERVICE_ACCOUNT,
    LABEL_TOKEN_ID, MANAGED_BY_VALUE,
};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Kubernetes Secret `type` for the dockerconfigjson format. Pinned as
/// a constant because k8s-openapi gives us the type as a free-form
/// string field; the apiserver enforces the literal.
const SECRET_TYPE_DOCKERCONFIGJSON: &str = "kubernetes.io/dockerconfigjson";

/// Kubernetes Secret `type` for the generic opaque format.
const SECRET_TYPE_OPAQUE: &str = "Opaque";

/// Data key used in `kubernetes.io/dockerconfigjson` Secrets. Pinned by
/// the apiserver — it refuses to store a dockerconfigjson Secret with
/// any other key.
const DATA_KEY_DOCKERCONFIGJSON: &str = ".dockerconfigjson";

/// Data key used in our Opaque Secrets. Operator-facing convention;
/// consumers reference `secretKeyRef.key: token`. Documented in
/// `docs/how-to/rotating-service-account-tokens.md`.
const DATA_KEY_OPAQUE_TOKEN: &str = "token";

// ---------------------------------------------------------------------------
// Public re-export for the field manager — secret_writer uses it.
// ---------------------------------------------------------------------------

pub(crate) const FIELD_MANAGER_RE_EXPORT: &str = FIELD_MANAGER;

// ---------------------------------------------------------------------------
// Build path — spec → Secret
// ---------------------------------------------------------------------------

/// Build a fully-populated [`Secret`] manifest from a
/// [`ManagedSecretSpec`].
///
/// The returned object is ready for either
/// `Api::<Secret>::create(&PostParams::default(), &secret)` or
/// `Api::<Secret>::patch(name, &PatchParams::apply(FIELD_MANAGER),
/// &Patch::Apply(&secret))`. The adapter uses the SSA path.
///
/// The `name` is set on `metadata.name`. The `namespace` is **not**
/// set because the namespaced `Api` handle already pins the namespace
/// and Kubernetes rejects mismatched namespace fields on apply.
pub(crate) fn build_secret(name: &str, spec: &ManagedSecretSpec) -> Secret {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_MANAGED_BY.into(), MANAGED_BY_VALUE.into());
    labels.insert(
        LABEL_SERVICE_ACCOUNT.into(),
        spec.service_account_name.clone(),
    );
    labels.insert(LABEL_TOKEN_ID.into(), spec.token_id.to_string());

    // `project-hort.de/last-rotated` lives on annotations, not labels: an RFC
    // 3339 timestamp contains `:`, which k8s rejects in label values
    // ("regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?
    // [A-Za-z0-9])?'"). Use SecondsFormat::Secs so the value
    // round-trips byte-stable across adjacent ticks.
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_LAST_ROTATED.into(),
        spec.last_rotated.to_rfc3339_opts(SecondsFormat::Secs, true),
    );

    let (type_, data) = build_payload(spec);

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        type_: Some(type_.to_string()),
        data: Some(data),
        ..Default::default()
    }
}

/// Build the `(type, data)` pair for a Secret given the
/// rotation-format choice on the spec.
///
/// - `Dockerconfigjson` → `kubernetes.io/dockerconfigjson` with one
///   `.dockerconfigjson` key whose value is the base64-encoded
///   docker-auth JSON (k8s-openapi's `ByteString` does the second
///   base64 when serialised to YAML, so we hand it the raw JSON
///   bytes).
/// - `Opaque` → `Opaque` with one `token` key whose value is the raw
///   PAT bytes.
///
/// Returned as `(type_str, BTreeMap)` because the caller assembles
/// the `Secret` struct with these inserted into the right slots.
fn build_payload(spec: &ManagedSecretSpec) -> (&'static str, BTreeMap<String, ByteString>) {
    match spec.format {
        SecretFormat::Dockerconfigjson => {
            let username = format!("sa:{}", spec.service_account_name);
            // `auth` is the base64 of `username:password` per the
            // dockerconfigjson convention. Some clients ignore it
            // (they re-compute from username/password) but operators
            // expect to see it on `kubectl describe`, and some older
            // pull-secret implementations depend on it.
            let auth_value = BASE64.encode(format!("{}:{}", username, spec.token_value.as_str()));
            let docker_json = json!({
                "auths": {
                    &spec.registry_host: {
                        "username": username,
                        // The plaintext PAT appears in this JSON
                        // exactly once. Once `serde_json::to_vec`
                        // returns it lives in a heap `Vec<u8>` we
                        // hand to `ByteString` — the original
                        // `Zeroizing<String>` on the spec is the only
                        // long-lived plaintext-bearing buffer.
                        "password": spec.token_value.as_str(),
                        "email": "service-account@hort.local",
                        "auth": auth_value,
                    }
                }
            });
            // Should not fail — `json!` always produces serialisable input.
            let bytes = serde_json::to_vec(&docker_json).expect("dockerconfigjson serialises");
            let mut data = BTreeMap::new();
            data.insert(DATA_KEY_DOCKERCONFIGJSON.into(), ByteString(bytes));
            (SECRET_TYPE_DOCKERCONFIGJSON, data)
        }
        SecretFormat::Opaque => {
            let mut data = BTreeMap::new();
            data.insert(
                DATA_KEY_OPAQUE_TOKEN.into(),
                ByteString(spec.token_value.as_bytes().to_vec()),
            );
            (SECRET_TYPE_OPAQUE, data)
        }
    }
}

// ---------------------------------------------------------------------------
// Read path — Secret → ManagedSecret
// ---------------------------------------------------------------------------

/// Project the reconciler-managed metadata off an existing
/// [`Secret`] into the domain [`ManagedSecret`] DTO.
///
/// `managed-by`, `service-account`, and `token-id` are labels;
/// `last-rotated` is an annotation (its RFC 3339 value contains `:`,
/// which k8s forbids in label values).
///
/// Parse failures on `project-hort.de/last-rotated` (not RFC 3339) or
/// `project-hort.de/token-id` (not a UUID) surface as `None` for that field
/// (the caller emits a `warn!`). The reconciler treats `None` for
/// `last_rotated` as stale-by-default; for `token_id` it is purely
/// informational, so a missing value is harmless.
///
/// `(name, namespace)` are accepted only for the warn-log scope —
/// they have no influence on the parse result.
pub(crate) fn project_managed(secret: &Secret, namespace: &str, name: &str) -> ManagedSecret {
    let labels = secret.metadata.labels.as_ref();
    let annotations = secret.metadata.annotations.as_ref();

    let managed_by = labels.and_then(|m| m.get(LABEL_MANAGED_BY).cloned());
    let service_account = labels.and_then(|m| m.get(LABEL_SERVICE_ACCOUNT).cloned());

    let last_rotated = annotations
        .and_then(|m| m.get(ANNOTATION_LAST_ROTATED))
        .and_then(|raw| match DateTime::parse_from_rfc3339(raw) {
            Ok(dt) => Some(dt.with_timezone(&Utc)),
            Err(err) => {
                tracing::warn!(
                    namespace,
                    name,
                    annotation = ANNOTATION_LAST_ROTATED,
                    raw = %raw,
                    error = %err,
                    "managed Secret carries malformed `project-hort.de/last-rotated` annotation — \
                     treating as stale (will be overwritten on next tick)",
                );
                None
            }
        });

    let token_id =
        labels
            .and_then(|m| m.get(LABEL_TOKEN_ID))
            .and_then(|raw| match Uuid::parse_str(raw) {
                Ok(id) => Some(id),
                Err(err) => {
                    tracing::warn!(
                        namespace,
                        name,
                        label = LABEL_TOKEN_ID,
                        raw = %raw,
                        error = %err,
                        "managed Secret carries malformed `project-hort.de/token-id` label — \
                         dropping for the projection (informational only)",
                    );
                    None
                }
            });

    ManagedSecret {
        managed_by,
        service_account,
        last_rotated,
        token_id,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use zeroize::Zeroizing;

    fn fixed_now() -> DateTime<Utc> {
        // Deterministic so the RFC 3339 label round-trips byte-identical.
        Utc.with_ymd_and_hms(2026, 5, 13, 12, 34, 56).unwrap()
    }

    fn sample_spec_docker() -> ManagedSecretSpec {
        ManagedSecretSpec {
            format: SecretFormat::Dockerconfigjson,
            token_value: Zeroizing::new("hort_svc_xyz".into()),
            token_id: Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
            service_account_name: "ci-pypi-pusher".into(),
            last_rotated: fixed_now(),
            registry_host: "registry.example.test".into(),
        }
    }

    fn sample_spec_opaque() -> ManagedSecretSpec {
        ManagedSecretSpec {
            format: SecretFormat::Opaque,
            token_value: Zeroizing::new("hort_svc_opaque".into()),
            token_id: Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            service_account_name: "ci-build".into(),
            last_rotated: fixed_now(),
            registry_host: "ignored.example".into(),
        }
    }

    // ----- build_secret: labels, name, type --------------------------------

    #[test]
    fn build_secret_sets_name_and_labels() {
        let spec = sample_spec_docker();
        let secret = build_secret("ci-hort-token", &spec);

        assert_eq!(secret.metadata.name.as_deref(), Some("ci-hort-token"));
        // namespace is intentionally absent — the Api handle pins it.
        assert!(secret.metadata.namespace.is_none());

        let labels = secret.metadata.labels.expect("labels present");
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("hort-worker")
        );
        assert_eq!(
            labels.get(LABEL_SERVICE_ACCOUNT).map(String::as_str),
            Some("ci-pypi-pusher")
        );
        assert_eq!(
            labels.get(LABEL_TOKEN_ID).map(String::as_str),
            Some("11111111-2222-3333-4444-555555555555")
        );
        // `project-hort.de/last-rotated` is an annotation (RFC 3339 + seconds
        // precision + Z suffix) — it cannot be a label because k8s
        // forbids `:` in label values.
        let annotations = secret.metadata.annotations.expect("annotations present");
        assert_eq!(
            annotations.get(ANNOTATION_LAST_ROTATED).map(String::as_str),
            Some("2026-05-13T12:34:56Z")
        );
    }

    #[test]
    fn build_secret_last_rotated_is_label_safe_when_re_encoded() {
        // Regression guard for the bug where `last-rotated` was a
        // label: the apiserver rejected the upsert with 422 because
        // `2026-05-14T14:14:01Z` contains `:`, which violates
        // `(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?`. Every label
        // value must satisfy that regex; verify here so future
        // refactors that move `last-rotated` back to a label fail at
        // unit-test time, not in a kind-cluster smoke run.
        let spec = sample_spec_docker();
        let secret = build_secret("ci-hort-token", &spec);
        let labels = secret.metadata.labels.expect("labels present");
        for (k, v) in labels {
            assert!(
                is_valid_k8s_label_value(&v),
                "label {k}={v:?} is not a valid k8s label value",
            );
        }
    }

    /// Mirrors the apiserver's label-value regex from `validation.go`:
    /// `(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?`. Empty string is
    /// allowed; any other value must start and end with alphanumeric
    /// and may contain only `-`, `_`, `.` in between.
    fn is_valid_k8s_label_value(v: &str) -> bool {
        if v.is_empty() {
            return true;
        }
        let bytes = v.as_bytes();
        let alphanumeric = |b: u8| b.is_ascii_alphanumeric();
        let inner = |b: u8| alphanumeric(b) || b == b'-' || b == b'_' || b == b'.';
        if !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) {
            return false;
        }
        bytes.iter().all(|&b| inner(b))
    }

    // ----- build_secret: dockerconfigjson payload --------------------------

    #[test]
    fn build_secret_dockerconfigjson_type_and_data_key() {
        let spec = sample_spec_docker();
        let secret = build_secret("ci-hort-token", &spec);
        assert_eq!(
            secret.type_.as_deref(),
            Some("kubernetes.io/dockerconfigjson")
        );

        let data = secret.data.expect("data present");
        assert_eq!(data.len(), 1);
        let payload = data
            .get(".dockerconfigjson")
            .expect(".dockerconfigjson key present");

        // The ByteString carries the raw JSON bytes (not base64; k8s-openapi
        // base64s on the wire). Decode and assert the shape.
        let json: serde_json::Value = serde_json::from_slice(&payload.0).unwrap();
        let entry = &json["auths"]["registry.example.test"];
        assert_eq!(entry["username"], "sa:ci-pypi-pusher");
        assert_eq!(entry["password"], "hort_svc_xyz");
        assert_eq!(entry["email"], "service-account@hort.local");
        // `auth` = base64("sa:ci-pypi-pusher:hort_svc_xyz")
        let expected_auth = BASE64.encode("sa:ci-pypi-pusher:hort_svc_xyz");
        assert_eq!(entry["auth"], expected_auth);
    }

    #[test]
    fn build_secret_dockerconfigjson_uses_registry_host_as_auths_key() {
        let mut spec = sample_spec_docker();
        spec.registry_host = "alt-registry.internal:8443".into();
        let secret = build_secret("x", &spec);
        let payload = &secret.data.unwrap()[".dockerconfigjson"].0;
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(json["auths"]["alt-registry.internal:8443"].is_object());
        // The default registry host from sample_spec_docker is NOT present.
        assert!(json["auths"]["registry.example.test"].is_null());
    }

    // ----- build_secret: opaque payload ------------------------------------

    #[test]
    fn build_secret_opaque_type_and_data_key() {
        let spec = sample_spec_opaque();
        let secret = build_secret("ci-token", &spec);
        assert_eq!(secret.type_.as_deref(), Some("Opaque"));

        let data = secret.data.expect("data present");
        assert_eq!(data.len(), 1);
        let payload = data.get("token").expect("token key present");
        assert_eq!(payload.0, b"hort_svc_opaque");
    }

    #[test]
    fn build_secret_opaque_ignores_registry_host() {
        // For Opaque, registry_host has no influence on the wire shape.
        let mut spec = sample_spec_opaque();
        spec.registry_host = "anything-here".into();
        let secret = build_secret("x", &spec);
        let data = secret.data.unwrap();
        assert!(data.contains_key("token"));
        // No dockerconfigjson key at all.
        assert!(!data.contains_key(".dockerconfigjson"));
    }

    // ----- project_managed: happy path -------------------------------------

    fn build_existing(labels: BTreeMap<String, String>) -> Secret {
        build_existing_with_annotations(labels, BTreeMap::new())
    }

    fn build_existing_with_annotations(
        labels: BTreeMap<String, String>,
        annotations: BTreeMap<String, String>,
    ) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some("ci-hort-token".into()),
                namespace: Some("ci-system".into()),
                labels: if labels.is_empty() {
                    None
                } else {
                    Some(labels)
                },
                annotations: if annotations.is_empty() {
                    None
                } else {
                    Some(annotations)
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn project_managed_round_trips_a_fresh_upsert() {
        // The output of `build_secret` is the input to a later
        // `project_managed`; the round-trip must preserve every field.
        let spec = sample_spec_docker();
        let built = build_secret("ci-hort-token", &spec);
        let parsed = project_managed(&built, "ci-system", "ci-hort-token");
        assert_eq!(parsed.managed_by.as_deref(), Some("hort-worker"));
        assert_eq!(parsed.service_account.as_deref(), Some("ci-pypi-pusher"));
        assert_eq!(parsed.last_rotated, Some(fixed_now()));
        assert_eq!(
            parsed.token_id.map(|id| id.to_string()),
            Some("11111111-2222-3333-4444-555555555555".into())
        );
    }

    #[test]
    fn project_managed_returns_all_none_for_unlabelled_secret() {
        // A Secret with no labels at all surfaces as a fully-None
        // projection. The reconciler treats this as a collision.
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("foreign".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let parsed = project_managed(&secret, "ci-system", "foreign");
        assert_eq!(parsed.managed_by, None);
        assert_eq!(parsed.service_account, None);
        assert_eq!(parsed.last_rotated, None);
        assert_eq!(parsed.token_id, None);
    }

    #[test]
    fn project_managed_handles_partial_labels() {
        // Only `managed-by` set; the other three labels missing.
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED_BY.into(), "hort-worker".into());
        let parsed = project_managed(&build_existing(labels), "ci-system", "ci-hort-token");
        assert_eq!(parsed.managed_by.as_deref(), Some("hort-worker"));
        assert_eq!(parsed.service_account, None);
        assert_eq!(parsed.last_rotated, None);
        assert_eq!(parsed.token_id, None);
    }

    // ----- project_managed: label parse failures ---------------------------

    #[test]
    fn project_managed_malformed_last_rotated_drops_to_none() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED_BY.into(), "hort-worker".into());
        // Wrong shape — not RFC 3339.
        let mut annotations = BTreeMap::new();
        annotations.insert(ANNOTATION_LAST_ROTATED.into(), "not-an-rfc3339-date".into());
        let parsed = project_managed(
            &build_existing_with_annotations(labels, annotations),
            "ci-system",
            "ci-hort-token",
        );
        assert_eq!(parsed.last_rotated, None);
        // managed_by must still be parsed — the failure is local to the
        // bad annotation.
        assert_eq!(parsed.managed_by.as_deref(), Some("hort-worker"));
    }

    #[test]
    fn project_managed_malformed_token_id_drops_to_none() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_TOKEN_ID.into(), "not-a-uuid".into());
        let parsed = project_managed(&build_existing(labels), "ci-system", "ci-hort-token");
        assert_eq!(parsed.token_id, None);
    }

    #[test]
    fn project_managed_empty_last_rotated_string_is_treated_as_malformed() {
        let mut annotations = BTreeMap::new();
        annotations.insert(ANNOTATION_LAST_ROTATED.into(), "".into());
        let parsed = project_managed(
            &build_existing_with_annotations(BTreeMap::new(), annotations),
            "ci-system",
            "ci-hort-token",
        );
        assert_eq!(parsed.last_rotated, None);
    }

    #[test]
    fn project_managed_preserves_unknown_managed_by_value() {
        // The collision-check is the caller's job; the projection
        // surfaces the raw value as-is.
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED_BY.into(), "some-other-controller".into());
        let parsed = project_managed(&build_existing(labels), "ci-system", "ci-hort-token");
        assert_eq!(parsed.managed_by.as_deref(), Some("some-other-controller"));
    }

    #[test]
    fn project_managed_rfc3339_with_offset_normalises_to_utc() {
        // Operators editing annotations by hand may write `+00:00`
        // instead of `Z` — both parse, and both normalise to UTC.
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_LAST_ROTATED.into(),
            "2026-05-13T12:34:56+00:00".into(),
        );
        let parsed = project_managed(
            &build_existing_with_annotations(BTreeMap::new(), annotations),
            "ci-system",
            "ci-hort-token",
        );
        assert_eq!(parsed.last_rotated, Some(fixed_now()));
    }

    // ----- field manager re-export -----------------------------------------

    #[test]
    fn field_manager_constant_pinned() {
        // Pinned by the design doc — the SSA field-manager identifies
        // this adapter. Changing it would silently re-take ownership
        // of every existing Secret on the next tick, surfacing as a
        // mass-conflict event the operator did not expect.
        assert_eq!(FIELD_MANAGER_RE_EXPORT, "hort-worker");
    }
}
