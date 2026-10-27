//! `hort-cli admin cli-session` subcommand group — the operator side of
//! CliSession emergency revocation.
//!
//! Two subcommands, mirroring the two HTTP surfaces:
//!
//! - `revoke --token <JWT>` / `revoke --jti <UUID> --expires-at <TS>` —
//!   POST `/api/v1/admin/cli-sessions/revoke`. Cuts exactly one
//!   session.
//! - `revoke-user <USER_ID>` — POST
//!   `/api/v1/admin/users/<USER_ID>/cli-sessions/revoke`. Cuts every
//!   session of one human issued before now.
//!
//! # Why `--token` exists
//!
//! The server takes `jti` + `expires_at`, never the token, because the
//! token is a live credential and a request body carrying one invites
//! copying it into request logs and shell history on the way to
//! revoking it. But an operator holding a token pasted into a ticket
//! has `jti` and `exp` only in base64url, so `--token` reads them out
//! **locally** and sends the two claims alone. The decode checks no
//! signature — it does not need to: a forged token names a `jti`
//! nothing will ever present, and the denylist entry self-expires.
//!
//! `--token -` reads the token from stdin, which is how to avoid
//! putting a live credential in shell history.
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The wire DTOs are
//! mirrored verbatim in `revoke.rs`.

pub mod revoke;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin cli-session` arguments.
#[derive(clap::Args, Debug)]
pub struct CliSessionArgs {
    #[command(subcommand)]
    pub cmd: CliSessionCommand,
}

/// `admin cli-session` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum CliSessionCommand {
    /// Revoke ONE CliSession, named by the token in hand.
    ///
    /// Use this when the token itself leaked — pasted into a ticket,
    /// found in a log — and the human's device is fine. The session
    /// stops working before its `exp`; every other session that human
    /// holds keeps working.
    Revoke(revoke::RevokeArgs),

    /// Revoke EVERY CliSession of one human issued before now.
    ///
    /// The "the device is gone, cut this person off" case. Nothing
    /// persists a live CliSession, so there is no listing and no `jti`
    /// to name — the cutoff is keyed on the user.
    ///
    /// This is NOT an account lockout: the human can re-run
    /// `hort-cli auth login` immediately and the new session works.
    /// Deactivating the user is a separate, deliberate action.
    RevokeUser(revoke::RevokeUserArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `admin cli-session` subcommand tree.
pub async fn run(
    client: AkClient,
    args: CliSessionArgs,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match args.cmd {
        CliSessionCommand::Revoke(a) => revoke::run(client, a, output).await,
        CliSessionCommand::RevokeUser(a) => revoke::run_user(client, a, output).await,
    }
}
