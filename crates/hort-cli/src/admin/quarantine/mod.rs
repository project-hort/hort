//! `hort-cli admin quarantine` subcommand group.
//!
//! Two subcommands:
//!
//! - `list-patch-candidates` — GET `/api/v1/admin/quarantine/patch-candidates`
//!   surfaces the patch-candidate view.
//! - `release` — POST `/api/v1/admin/quarantine/<artifact_id>/release` is the
//!   admin override path. The endpoint returns 204 No Content; the CLI
//!   synthesises a minimal JSON envelope under `--output json` so scripted
//!   callers still get a parseable result.
//!
//! # Why a new top-level `admin quarantine` group?
//!
//! The patch-candidate listing and the admin-release action are
//! operator-facing primitives that share a noun (`quarantine`) and a
//! permission (`Permission::Admin`). Grouping them mirrors the HTTP
//! surface (both routes nest under `/admin/quarantine/...`) and keeps
//! the CLI surface aligned with the wire surface. See
//! `docs/architecture/how-to/quarantine-patch-release.md`.
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The wire DTOs are mirrored
//! verbatim in `list_patch_candidates.rs`; the release subcommand owns
//! its own request body type. The "sync-required" comment on each DTO
//! flags the cross-crate contract for future maintainers.

pub mod list_patch_candidates;
pub mod release;

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
    /// for review" — the operator decides whether to admin-release the
    /// newer version after weighing residual risk.
    ListPatchCandidates(list_patch_candidates::ListPatchCandidatesArgs),

    /// Admin override release of a quarantined artifact.
    ///
    /// Records `released_by_user_id` + `justification` on the emitted
    /// `ArtifactReleased` event. `--justification` is required and is
    /// validated client-side (non-empty, ≤ 512 bytes) before any HTTP
    /// round-trip.
    Release(release::ReleaseArgs),
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
        QuarantineCommand::Release(release_args) => {
            release::run(client, release_args, output).await
        }
    }
}
