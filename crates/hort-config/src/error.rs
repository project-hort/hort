//! Error containers for parse and validate phases.
//!
//! Both phases collect every error before returning. A single malformed
//! YAML file shouldn't hide five others — operators want to fix
//! everything they can see in one boot pass.

use std::fmt;
use std::path::PathBuf;

use crate::envelope::Kind;

/// Per-file parse error.
///
/// Any condition that can be detected from a single YAML file's bytes
/// without consulting other files. Cross-file checks (duplicate names,
/// dangling references) are `ValidationError`s.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error(
        "unsupported apiVersion `{got}` — only `project-hort.de/v1beta1` is accepted in v1; \
         operators must re-emit older shapes"
    )]
    UnsupportedApiVersion { got: String },

    #[error("unknown kind `{got}` — known kinds: {}", valid.join(", "))]
    UnknownKind {
        got: String,
        valid: &'static [&'static str],
    },

    #[error("metadata.name is required")]
    MissingMetadataName,

    #[error("metadata.name must not be empty")]
    EmptyMetadataName,

    #[error("environment variable `{var}` referenced via ${{{var}}} is not set")]
    InterpolationVarNotFound { var: String },

    #[error(
        "malformed interpolation `{fragment}` — `${{VAR}}` is the only \
         supported syntax; use `$$` to emit a literal `$`"
    )]
    InterpolationMalformed { fragment: String },

    /// `proxy.credentials` is rejected as a plaintext anti-pattern.
    /// Operators use `proxy.secretRef:` even for raw env-var dev —
    /// uniform schema, no plaintext exception.
    #[error(
        "proxy.{field} is forbidden in repository config — it would store \
         credentials in plaintext. Use `proxy.secretRef:` \
         to reference a secret resolved from an env var or file at runtime; \
         see docs/architecture/how-to/wire-secrets.md for examples."
    )]
    CredentialsFieldForbidden { field: &'static str },

    /// `proxy.secretRef.location` failed format validation:
    /// `source: file` requires an absolute path; `source: env_var` requires a
    /// POSIX-portable identifier matching `^[A-Z_][A-Z0-9_]*$`. Reference
    /// existence is not checked at parse time.
    #[error("proxy.secretRef.location {detail}")]
    SecretRefLocationInvalid { detail: String },

    /// `storage.backend` is a closed enum, not a free string. It is
    /// enum-validated at parse against exactly `{filesystem, s3}`
    /// (case-sensitive, matching the global `HORT_STORAGE_BACKEND`
    /// value-domain). A distinct named variant — not the generic
    /// `deny_unknown_fields` Yaml error — because the *key* `backend`
    /// is known; only its *value* is out of domain, and the operator
    /// must learn that per-repo storage routing is unsupported in v2
    /// (the field is parsed + persisted but placement is the single
    /// global adapter), not that they typo'd a key.
    #[error(
        "storage.backend `{got}` is not a recognized storage backend — \
         only `filesystem` or `s3` are accepted (case-sensitive, matching \
         the deployment-level HORT_STORAGE_BACKEND value-domain). Note: the \
         per-repository storage backend is parsed and persisted but does \
         NOT route blob placement in v2 (placement is the single global \
         storage adapter); per-repository storage routing is not yet \
         implemented."
    )]
    InvalidStorageBackend { got: String },

    /// A YAML file under `$HORT_CONFIG_DIR` uses a legacy root shape that
    /// has been removed. The only such shape today is the
    /// `mappings: [{group, role}, ...]` alias (`detected = "mappings"`),
    /// which has been replaced by one canonical-envelope file per
    /// `GroupMapping`. The error names the detected shape and points
    /// operators at the how-to that documents the canonical layout.
    #[error(
        "unsupported root shape `{detected}` — {expected}. \
         See docs/architecture/how-to/declare-gitops-config.md for the \
         canonical envelope layout."
    )]
    UnsupportedShape {
        detected: &'static str,
        expected: &'static str,
    },
}

/// Bag of per-file parse errors, returned from `DesiredState::parse_files`.
///
/// `Display` renders one error per line — the boot caller logs the
/// rendered string at `tracing::error!` and exits non-zero.
#[derive(Debug, thiserror::Error)]
pub struct ParseErrors(pub Vec<(PathBuf, ParseError)>);

impl fmt::Display for ParseErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (path, err) in &self.0 {
            writeln!(f, "{}: {err}", path.display())?;
        }
        Ok(())
    }
}

/// Cross-object validation error.
///
/// Anything that requires looking at more than one parsed object, or
/// at an external snapshot (current DB state, env vars). The per-spec
/// per-kind validators (in `crate::repository`, `crate::group_mapping`)
/// also produce variants of this type so the error stream is uniform.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "duplicate {kind} `{name}` declared in multiple files: {}",
        files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    DuplicateName {
        kind: Kind,
        name: String,
        files: Vec<PathBuf>,
    },

    /// A `virtualMembers: [...]` entry references a key that is not
    /// declared in the desired state.
    ///
    /// Only desired-state-internal references are accepted. Mixing a managed virtual repo with a `Local` row
    /// from the current snapshot is rejected — the virtual repo itself
    /// must stay `Local` if the operator wants mixed membership. This
    /// keeps the gitops surface self-contained and avoids the `Local`
    /// row being silently load-bearing for a managed declaration.
    #[error(
        "virtual repository `{virtual_repo}` references unknown member `{missing_member}` \
         (member must also be declared in $HORT_CONFIG_DIR)"
    )]
    DanglingVirtualMember {
        virtual_repo: String,
        missing_member: String,
    },

    /// A `(kind, name)` is declared in the desired state but already
    /// exists in the current snapshot with `managed_by = Local`.
    ///
    /// Surfaced from `validate_against`, never from the no-arg
    /// `validate()` (which is environment-agnostic).
    #[error(
        "{kind} `{name}` is declared in $HORT_CONFIG_DIR but already exists with \
         managed_by=local — promote it via the operator workflow or rename one"
    )]
    ManagedConflict { kind: Kind, name: String },

    #[error(
        "HORT_AUTH_PROVIDER=disabled but {count} GroupMapping object(s) are declared \
         in $HORT_CONFIG_DIR ({}) — either set HORT_AUTH_PROVIDER=oidc or remove the \
         declarations; silent dormant state is not supported",
        names.join(", ")
    )]
    AuthProviderDisabledWithGroupMappings { count: usize, names: Vec<String> },

    #[error(
        "{field} value `{got}` is not in the allowed set: {}",
        expected.join(", ")
    )]
    UnknownEnumValue {
        field: &'static str,
        got: String,
        expected: Vec<&'static str>,
    },

    /// Per-kind regex / shape violations surface as this variant. The
    /// detailed message is composed at the call site to keep this enum
    /// small.
    #[error("{kind} `{name}` is invalid: {detail}")]
    Invalid {
        kind: Kind,
        name: String,
        detail: String,
    },

    /// An envelope references a declared object that does not exist in
    /// the desired state. Examples:
    /// - `PermissionGrant.repository` → no `ArtifactRepository` declared
    /// - `Repository.curationRules` entry → no `CurationRule` declared
    /// - `Exclusion.policy` → no `ScanPolicy` declared
    ///
    /// `referrer_kind` and `referrer_name` identify the envelope that
    /// holds the bad reference; `field`, `target_kind`, and
    /// `missing_name` describe what it pointed at and what kind of
    /// thing should have been there.
    #[error(
        "{referrer_kind} `{referrer_name}` references unknown {target_kind} `{missing_name}` \
         via {field} (no matching object declared in $HORT_CONFIG_DIR)"
    )]
    DanglingReference {
        referrer_kind: Kind,
        referrer_name: String,
        field: &'static str,
        target_kind: Kind,
        missing_name: String,
    },

    /// More than one envelope of a **singleton** kind was declared in
    /// `$HORT_CONFIG_DIR`.
    ///
    /// `PermissionGrantLintConfig` is the first (and currently only)
    /// singleton kind — at most one envelope cluster-wide. A second
    /// declaration is a *named* validation error rather than a silent
    /// last-wins, because the linter config is the load-bearing security
    /// opt-out for the permission-grant linter: a silent last-wins could
    /// non-deterministically pick a more-permissive config depending on
    /// directory-walk order. The error lists every contributing file so
    /// the operator can delete the duplicate.
    #[error(
        "{kind} is a singleton kind but {count} envelopes are declared in \
         $HORT_CONFIG_DIR ({}) — exactly one is allowed; delete all but one",
        files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    SingletonConflict {
        kind: Kind,
        count: usize,
        files: Vec<PathBuf>,
    },

    /// A `Role` envelope's `isSystem` flag disagrees with the seed
    /// table. The seeded system roles are `admin`, `developer`, and
    /// `reader` — declaring any of those names without `isSystem: true`
    /// (or any other name with `isSystem: true`) is rejected.
    #[error(
        "Role `{name}` declares `isSystem: {declared}` but the seeded value is \
         `isSystem: {expected}` — operators must mirror the seed for protected roles"
    )]
    SystemRoleMismatch {
        name: String,
        declared: bool,
        expected: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for err in &self.0 {
            writeln!(f, "{err}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_errors_display_lists_each_file() {
        let errs = ParseErrors(vec![
            (PathBuf::from("a.yaml"), ParseError::MissingMetadataName),
            (PathBuf::from("b.yaml"), ParseError::EmptyMetadataName),
        ]);
        let rendered = errs.to_string();
        assert!(rendered.contains("a.yaml"));
        assert!(rendered.contains("b.yaml"));
        assert!(rendered.contains("metadata.name is required"));
        assert!(rendered.contains("metadata.name must not be empty"));
    }

    #[test]
    fn validation_errors_display_lists_each_error() {
        let errs = ValidationErrors(vec![
            ValidationError::DanglingVirtualMember {
                virtual_repo: "all-npm".into(),
                missing_member: "ghost".into(),
            },
            ValidationError::AuthProviderDisabledWithGroupMappings {
                count: 2,
                names: vec!["admins".into(), "readers".into()],
            },
        ]);
        let rendered = errs.to_string();
        assert!(rendered.contains("all-npm"));
        assert!(rendered.contains("ghost"));
        assert!(rendered.contains("admins"));
        assert!(rendered.contains("readers"));
    }

    #[test]
    fn duplicate_name_renders_all_files() {
        let err = ValidationError::DuplicateName {
            kind: Kind::ArtifactRepository,
            name: "npm-public".into(),
            files: vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")],
        };
        let rendered = err.to_string();
        assert!(rendered.contains("npm-public"));
        assert!(rendered.contains("a.yaml"));
        assert!(rendered.contains("b.yaml"));
    }

    #[test]
    fn singleton_conflict_renders_kind_count_and_every_file() {
        let err = ValidationError::SingletonConflict {
            kind: Kind::PermissionGrantLintConfig,
            count: 2,
            files: vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")],
        };
        let rendered = err.to_string();
        assert!(rendered.contains("PermissionGrantLintConfig"));
        assert!(rendered.contains('2'));
        assert!(rendered.contains("a.yaml"));
        assert!(rendered.contains("b.yaml"));
        assert!(rendered.contains("singleton"));
    }

    #[test]
    fn credentials_field_forbidden_message_names_field_and_redirects_to_secret_ref() {
        let err = ParseError::CredentialsFieldForbidden {
            field: "credentials",
        };
        let rendered = err.to_string();
        assert!(rendered.contains("credentials"));
        assert!(rendered.contains("secretRef"));
        assert!(rendered.contains("forbidden"));
    }

    #[test]
    fn invalid_storage_backend_message_names_value_set_and_placement_note() {
        // The message must name the bad value, enumerate the allowed set,
        // AND inform the operator that per-repo storage routing is not
        // yet implemented — not that they typo'd a key (the whole point
        // of a distinct named variant over the generic
        // `deny_unknown_fields` Yaml error).
        let err = ParseError::InvalidStorageBackend {
            got: "glacier".into(),
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("glacier"),
            "must name the bad value: {rendered}"
        );
        assert!(
            rendered.contains("filesystem") && rendered.contains("s3"),
            "must enumerate the allowed set: {rendered}"
        );
        assert!(
            rendered.contains("does NOT route"),
            "must state the placement-inert honesty contract: {rendered}"
        );
    }

    #[test]
    fn unsupported_shape_renders_detected_expected_and_pointer_to_howto() {
        let err = ParseError::UnsupportedShape {
            detected: "mappings",
            expected: "one envelope per file",
        };
        let rendered = err.to_string();
        // Both the detected shape name and the canonical-form reminder
        // must surface so an operator can correct the file without
        // grepping source.
        assert!(
            rendered.contains("mappings"),
            "expected 'mappings' in message, got: {rendered}"
        );
        assert!(
            rendered.contains("one envelope per file"),
            "expected canonical-form text in message, got: {rendered}"
        );
        // Pointer to the how-to document operators read for the layout.
        assert!(
            rendered.contains("declare-gitops-config.md"),
            "expected how-to pointer in message, got: {rendered}"
        );
    }
}
