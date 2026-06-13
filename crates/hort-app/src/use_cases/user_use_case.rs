use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::{Page, PageRequest};

use crate::error::AppResult;

// ---------------------------------------------------------------------------
// Command structs
// ---------------------------------------------------------------------------

/// Command to create a new user identity.
///
/// Credentials (password, TOTP) are managed by the auth adapter — this only
/// sets identity fields. Privilege fields (`is_admin`, `is_active`,
/// `is_service_account`) are in [`UserPrivileges`], not here — the handler
/// constructs privileges from a verified caller identity, not from request
/// body input.
#[derive(Debug)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub auth_provider: AuthProvider,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
}

/// Privilege fields for user creation.
///
/// Separated from [`CreateUser`] so that handlers construct this from a
/// verified caller identity. This makes privilege escalation a compile-time
/// error when handlers are wired, not a review-time catch.
#[derive(Debug)]
pub struct UserPrivileges {
    pub is_active: bool,
    pub is_admin: bool,
    pub is_service_account: bool,
}

/// Command to partially update a user identity.
///
/// `None` = don't change, `Some(None)` = clear, `Some(Some(v))` = set.
#[derive(Debug)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
}

/// Privilege fields for user update.
///
/// Separated from [`UpdateUser`] for the same reason as [`UserPrivileges`].
#[derive(Debug)]
pub struct UpdateUserPrivileges {
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
}

// ---------------------------------------------------------------------------
// UserUseCase
// ---------------------------------------------------------------------------

/// Application use case for user identity CRUD.
///
/// Auth operations (password reset, TOTP enrollment, lockout) require the
/// auth credential port and are out of scope here.
///
/// There is deliberately no local-admin password surface here
/// (`create_or_rotate_admin` and friends): the
/// HTTP-Basic-against-local-admin-row identity path no longer exists
/// (commit b7fd6d65).
pub struct UserUseCase {
    users: Arc<dyn UserRepository>,
}

impl UserUseCase {
    pub fn new(users: Arc<dyn UserRepository>) -> Self {
        Self { users }
    }

    /// Create a new user identity.
    #[tracing::instrument(skip(self))]
    pub async fn create(&self, cmd: CreateUser, privileges: UserPrivileges) -> AppResult<User> {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            username: cmd.username,
            email: cmd.email,
            auth_provider: cmd.auth_provider,
            external_id: cmd.external_id,
            display_name: cmd.display_name,
            is_active: privileges.is_active,
            is_admin: privileges.is_admin,
            is_service_account: privileges.is_service_account,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        };

        self.users.save(&user).await?;
        Ok(user)
    }

    /// Get a user by ID.
    #[tracing::instrument(skip(self))]
    pub async fn get_by_id(&self, id: Uuid) -> AppResult<User> {
        Ok(self.users.find_by_id(id).await?)
    }

    /// Find a user by username.
    #[tracing::instrument(skip(self))]
    pub async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
        Ok(self.users.find_by_username(username).await?)
    }

    /// List users with pagination.
    #[tracing::instrument(skip(self))]
    pub async fn list(&self, page: PageRequest) -> AppResult<Page<User>> {
        Ok(self.users.list(page).await?)
    }

    /// Partially update a user identity.
    #[tracing::instrument(skip(self))]
    pub async fn update(
        &self,
        id: Uuid,
        cmd: UpdateUser,
        privileges: UpdateUserPrivileges,
    ) -> AppResult<User> {
        let mut user = self.users.find_by_id(id).await?;

        if let Some(email) = cmd.email {
            user.email = email;
        }
        if let Some(display_name) = cmd.display_name {
            user.display_name = display_name;
        }
        if let Some(is_active) = privileges.is_active {
            user.is_active = is_active;
        }
        if let Some(is_admin) = privileges.is_admin {
            user.is_admin = is_admin;
        }

        user.updated_at = Utc::now();
        self.users.save(&user).await?;
        Ok(user)
    }

    /// Delete a user by ID.
    #[tracing::instrument(skip(self))]
    pub async fn delete(&self, id: Uuid) -> AppResult<()> {
        Ok(self.users.delete(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::test_support::MockUserRepository;

    // -- Helpers ------------------------------------------------------------

    fn make_use_case() -> UserUseCase {
        UserUseCase::new(Arc::new(MockUserRepository::new()))
    }

    fn local_user_cmd() -> CreateUser {
        CreateUser {
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some("Alice Smith".into()),
        }
    }

    fn default_privileges() -> UserPrivileges {
        UserPrivileges {
            is_active: true,
            is_admin: false,
            is_service_account: false,
        }
    }

    // -- Create tests -------------------------------------------------------

    #[tokio::test]
    async fn create_local_user() {
        let uc = make_use_case();
        let user = uc
            .create(local_user_cmd(), default_privileges())
            .await
            .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.auth_provider, AuthProvider::Local);
        assert!(!user.id.is_nil());
    }

    #[tokio::test]
    async fn create_oidc_user() {
        let uc = make_use_case();
        let cmd = CreateUser {
            username: "bob".into(),
            email: "bob@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("okta|abc123".into()),
            display_name: None,
        };
        let user = uc.create(cmd, default_privileges()).await.unwrap();
        assert_eq!(user.auth_provider, AuthProvider::Oidc);
        assert_eq!(user.external_id.as_deref(), Some("okta|abc123"));
    }

    #[tokio::test]
    async fn create_service_account() {
        let uc = make_use_case();
        let cmd = CreateUser {
            username: "ci-bot".into(),
            email: "ci-bot@system.local".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
        };
        let privileges = UserPrivileges {
            is_active: true,
            is_admin: false,
            is_service_account: true,
        };
        let user = uc.create(cmd, privileges).await.unwrap();
        assert!(user.is_service_account);
    }

    // -- Get tests ----------------------------------------------------------

    #[tokio::test]
    async fn get_by_id_found() {
        let uc = make_use_case();
        let user = uc
            .create(local_user_cmd(), default_privileges())
            .await
            .unwrap();
        let found = uc.get_by_id(user.id).await.unwrap();
        assert_eq!(found.id, user.id);
    }

    #[tokio::test]
    async fn get_by_id_not_found() {
        let uc = make_use_case();
        let err = uc.get_by_id(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn find_by_username_found() {
        let uc = make_use_case();
        uc.create(local_user_cmd(), default_privileges())
            .await
            .unwrap();
        let found = uc.find_by_username("alice").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn find_by_username_not_found() {
        let uc = make_use_case();
        let found = uc.find_by_username("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    // -- List tests ---------------------------------------------------------

    #[tokio::test]
    async fn list_empty() {
        let uc = make_use_case();
        let page = uc.list(PageRequest::default()).await.unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_with_results() {
        let uc = make_use_case();
        uc.create(local_user_cmd(), default_privileges())
            .await
            .unwrap();
        let page = uc.list(PageRequest::default()).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total, 1);
    }

    // -- Update tests -------------------------------------------------------

    #[tokio::test]
    async fn update_partial_fields() {
        let uc = make_use_case();
        let user = uc
            .create(local_user_cmd(), default_privileges())
            .await
            .unwrap();

        let updated = uc
            .update(
                user.id,
                UpdateUser {
                    email: Some("alice.new@example.com".into()),
                    display_name: Some(None), // clear display name
                },
                UpdateUserPrivileges {
                    is_active: Some(false),
                    is_admin: None, // don't change
                },
            )
            .await
            .unwrap();

        assert_eq!(updated.email, "alice.new@example.com");
        assert!(updated.display_name.is_none());
        assert!(!updated.is_active);
        assert!(!updated.is_admin); // unchanged
        assert!(updated.updated_at > user.updated_at);
    }

    #[tokio::test]
    async fn update_not_found() {
        let uc = make_use_case();
        let err = uc
            .update(
                Uuid::new_v4(),
                UpdateUser {
                    email: Some("x@x.com".into()),
                    display_name: None,
                },
                UpdateUserPrivileges {
                    is_active: None,
                    is_admin: None,
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- Delete tests -------------------------------------------------------

    #[tokio::test]
    async fn delete_existing() {
        let uc = make_use_case();
        let user = uc
            .create(local_user_cmd(), default_privileges())
            .await
            .unwrap();
        uc.delete(user.id).await.unwrap();
        let err = uc.get_by_id(user.id).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_not_found() {
        let uc = make_use_case();
        let err = uc.delete(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
