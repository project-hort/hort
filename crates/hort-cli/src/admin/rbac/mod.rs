//! `hort-cli admin rbac` subcommand group.
//!
//! One subcommand in v1:
//!
//! - `resolve --group <g> [--group <g>...]` — POST
//!   `/api/v1/admin/rbac/resolve`. The admin what-if resolver: supply the
//!   user's IdP groups (from your own IdP / user-management) and HORT
//!   resolves the `groups → claims → effective (repo, permission) grants`
//!   half it owns (no IdP query, no cache). The claim-based-authority
//!   companion to `admin users effective-permissions`.
//!
//! # Why a new top-level `admin rbac` group?
//!
//! Mirrors the HTTP surface (`/admin/rbac/...`) and the existing
//! `admin users` / `admin quarantine` grouping convention. Future
//! RBAC-introspection reads nest here.
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The wire DTOs are mirrored
//! verbatim in `resolve.rs`; the "sync-required" comment on each DTO flags
//! the cross-crate contract for future maintainers.

pub mod resolve;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin rbac` arguments.
#[derive(clap::Args, Debug)]
pub struct RbacArgs {
    #[command(subcommand)]
    pub cmd: RbacCommand,
}

/// `admin rbac` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum RbacCommand {
    /// Resolve a set of IdP groups to the claims + effective
    /// `(repo, permission)` grants HORT would grant them (what-if resolver).
    ///
    /// The admin brings the identity→groups half (from their IdP); HORT
    /// resolves the groups→claims→permissions half it owns. No IdP query,
    /// no cache. Use this for the claim-based authority that
    /// `admin users effective-permissions` cannot resolve without the
    /// user's session.
    Resolve(resolve::ResolveArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `admin rbac` subcommand tree.
pub async fn run(client: AkClient, args: RbacArgs, output: OutputFormat) -> anyhow::Result<()> {
    match args.cmd {
        RbacCommand::Resolve(resolve_args) => resolve::run(client, resolve_args, output).await,
    }
}
