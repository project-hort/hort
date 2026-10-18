//! `hort-cli admin quarantine` subcommand group.
//!
//! One subcommand:
//!
//! - `list-patch-candidates` — GET `/api/v1/admin/quarantine/patch-candidates`
//!   surfaces the patch-candidate view.
//!
//! # Why a top-level `admin quarantine` group for one read?
//!
//! The group mirrors the HTTP surface: the listing's route nests under
//! `/admin/quarantine/...` behind `Permission::Admin`. The release an
//! operator reaches from this queue is **not** here — it is
//! `hort-cli curation waive`, the one manual release (ADR 0007, "One
//! authority owns the manual release"), so the group keeps a single
//! member rather than re-growing a second release surface beside it.
//! See `docs/architecture/how-to/quarantine-patch-release.md`.
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The wire DTOs are mirrored
//! verbatim in `list_patch_candidates.rs`. The "sync-required" comment
//! on each DTO flags the cross-crate contract for future maintainers.

pub mod list_patch_candidates;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin quarantine` arguments.
#[derive(clap::Args, Debug)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    pub cmd: QuarantineCommand,
}

/// `admin quarantine` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum QuarantineCommand {
    /// List patch-candidate rows.
    ///
    /// A patch-candidate is a quarantined artifact whose package has at
    /// least one older sibling with one or more vulnerability findings.
    /// The listing is the operator's queue of "fixed versions waiting
    /// for review" — the operator decides whether to release the newer
    /// version (`hort-cli curation waive`) after weighing residual risk.
    ListPatchCandidates(list_patch_candidates::ListPatchCandidatesArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `admin quarantine` subcommand tree.
///
/// Borrows the `AkClient` from the caller (so future routing under
/// `admin/mod.rs` can share one client across sibling dispatchers).
pub async fn run(
    client: AkClient,
    args: QuarantineArgs,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match args.cmd {
        QuarantineCommand::ListPatchCandidates(list_args) => {
            list_patch_candidates::run(client, list_args, output).await
        }
    }
}
