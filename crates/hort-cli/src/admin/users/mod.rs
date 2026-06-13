//! `hort-cli admin users` subcommand group.
//!
//! One subcommand in v1:
//!
//! - `effective-permissions <user_id>` — GET
//!   `/api/v1/admin/users/<user_id>/effective-permissions` surfaces what
//!   HORT knows about a user *without their token*: the `is_admin` bit and
//!   every currently-matching grant (`User`-subject + synthetic-`admin`).
//!   The claim-based half is resolved separately via `admin rbac resolve`
//!   (see `docs/architecture/how-to/operate/claim-based-rbac.md`).
//!
//! # Why a new top-level `admin users` group?
//!
//! Mirrors the HTTP surface (`/admin/users/...`) and the existing
//! `admin quarantine` grouping convention. Future per-user admin reads
//! (token listing, etc.) nest here.
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The wire DTOs are mirrored
//! verbatim in `effective_permissions.rs`; the "sync-required" comment
//! on each DTO flags the cross-crate contract for future maintainers.

pub mod effective_permissions;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin users` arguments.
#[derive(clap::Args, Debug)]
pub struct UsersArgs {
    #[command(subcommand)]
    pub cmd: UsersCommand,
}

/// `admin users` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum UsersCommand {
    /// Show what HORT knows about a user *without their token*: the
    /// `is_admin` bit and every currently-matching grant.
    ///
    /// The user's claim-based authority is **not** resolvable here (no
    /// per-user claim cache — OIDC resolves claims live at login). The
    /// output carries a `claim_based_authority` marker and a hint
    /// pointing at `admin rbac resolve` for the claim-based half.
    EffectivePermissions(effective_permissions::EffectivePermissionsArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `admin users` subcommand tree.
pub async fn run(client: AkClient, args: UsersArgs, output: OutputFormat) -> anyhow::Result<()> {
    match args.cmd {
        UsersCommand::EffectivePermissions(ep_args) => {
            effective_permissions::run(client, ep_args, output).await
        }
    }
}
