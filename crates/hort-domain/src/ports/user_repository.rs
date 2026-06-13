use uuid::Uuid;

use crate::entities::user::{AuthProvider, User};
use crate::error::DomainResult;
use crate::types::{Page, PageRequest};

use super::BoxFuture;

/// Outbound port for user persistence.
///
/// The four password-cluster methods — `find_by_username_with_password`,
/// `count_local_users`, `has_local_admin`, `upsert_admin` — and their
/// `auth_provider = 'local'`-pinned variants were removed together with
/// the HTTP-Basic-against-local-admin-row identity path they fed
/// (`admin bootstrap` CLI + boot-gate, `authenticate_local` + lockout).
/// The surviving surface is OIDC JIT provisioning + CRUD.
pub trait UserRepository: Send + Sync {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<User>>;
    fn find_by_username(&self, username: &str) -> BoxFuture<'_, DomainResult<Option<User>>>;
    fn find_by_email(&self, email: &str) -> BoxFuture<'_, DomainResult<Option<User>>>;
    fn list(&self, page: PageRequest) -> BoxFuture<'_, DomainResult<Page<User>>>;
    fn save(&self, user: &User) -> BoxFuture<'_, DomainResult<()>>;
    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>>;

    /// Lookup used during OIDC JIT provisioning. Returns `None` when the
    /// `(auth_provider, external_id)` pair is unknown — callers treat `None`
    /// as "first login, create the user".
    fn find_by_external_id(
        &self,
        auth_provider: AuthProvider,
        external_id: &str,
    ) -> BoxFuture<'_, DomainResult<Option<User>>>;

    /// Idempotent create-or-refresh used by JIT provisioning.
    ///
    /// Matches existing rows on `(auth_provider, external_id)` via the
    /// adapter's unique index; concurrent first-logins for the same subject
    /// race on that constraint, and losing racers observe the committed row
    /// (both calls return the same authoritative `id`). The input `User.id`
    /// MAY be ignored by implementations — the DB authoritative id wins, and
    /// an existing row's id is preserved across the upsert.
    fn upsert_on_login(&self, user: &User) -> BoxFuture<'_, DomainResult<User>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `UserRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn UserRepository>();
    }
}
