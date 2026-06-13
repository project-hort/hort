use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

// ---------------------------------------------------------------------------
// AuthProvider
// ---------------------------------------------------------------------------

/// How a user authenticates.
///
/// The domain entity carries this as identity metadata — it describes *which*
/// auth system owns the user, not *how* authentication works. Credential
/// storage, TOTP state, and lockout policy live in the auth adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthProvider {
    Local,
    Ldap,
    Saml,
    Oidc,
}

impl fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::Ldap => f.write_str("ldap"),
            Self::Saml => f.write_str("saml"),
            Self::Oidc => f.write_str("oidc"),
        }
    }
}

impl FromStr for AuthProvider {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "ldap" => Ok(Self::Ldap),
            "saml" => Ok(Self::Saml),
            "oidc" => Ok(Self::Oidc),
            _ => Err(DomainError::Validation(format!(
                "unknown auth provider: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

/// A user identity.
///
/// This is a lean entity carrying only identity state. The schema carries
/// no password / TOTP / lockout columns at all — there is no
/// HTTP-Basic-against-local-admin-row identity path, and PAT brute-force
/// protection lives in the ephemeral keyspace, not in the relational store
/// (see `docs/auth-catalog.md`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub auth_provider: AuthProvider,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- AuthProvider --------------------------------------------------------

    #[test]
    fn auth_provider_display() {
        assert_eq!(AuthProvider::Local.to_string(), "local");
        assert_eq!(AuthProvider::Ldap.to_string(), "ldap");
        assert_eq!(AuthProvider::Saml.to_string(), "saml");
        assert_eq!(AuthProvider::Oidc.to_string(), "oidc");
    }

    #[test]
    fn auth_provider_from_str_roundtrip() {
        for name in &["local", "ldap", "saml", "oidc"] {
            let parsed: AuthProvider = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn auth_provider_from_str_case_insensitive() {
        let parsed: AuthProvider = "OIDC".parse().unwrap();
        assert_eq!(parsed, AuthProvider::Oidc);

        let parsed: AuthProvider = "Ldap".parse().unwrap();
        assert_eq!(parsed, AuthProvider::Ldap);
    }

    #[test]
    fn auth_provider_from_str_invalid() {
        let result: Result<AuthProvider, _> = "kerberos".parse();
        assert!(result.is_err());
    }

    #[test]
    fn auth_provider_copy() {
        let a = AuthProvider::Saml;
        let b = a;
        assert_eq!(a, b);
    }

    // -- User ---------------------------------------------------------------

    fn sample_user() -> User {
        User {
            id: Uuid::nil(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some("Alice Smith".into()),
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn user_clone_eq() {
        let a = sample_user();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn user_external_auth() {
        let user = User {
            auth_provider: AuthProvider::Oidc,
            external_id: Some("okta|abc123".into()),
            ..sample_user()
        };
        assert_eq!(user.auth_provider, AuthProvider::Oidc);
        assert_eq!(user.external_id.as_deref(), Some("okta|abc123"));
    }

    #[test]
    fn user_service_account() {
        let user = User {
            username: "ci-bot".into(),
            is_service_account: true,
            last_login_at: None,
            ..sample_user()
        };
        assert!(user.is_service_account);
        assert!(user.last_login_at.is_none());
    }
}
