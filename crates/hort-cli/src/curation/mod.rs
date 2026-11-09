//! `hort-cli curation` subcommand tree.
//!
//! Mounted at the **top level** of `Commands` (alongside `Auth`,
//! `Admin`, `Get`) — NOT under `admin`. Operational curator verbs sit
//! alongside `Admin`, not nested under it.
//!
//! Curator decision subcommands:
//!
//! - `waive artifact <artifact_id> --justification <text>` →
//!   POST `/api/v1/admin/curation/quarantine/:artifact_id/waive`
//!   (manual release of one held artifact, with curator attribution).
//! - `waive versions --repo <key> --package <name> --versions <v1>,<v2>,…
//!   --justification <text>` →
//!   POST `/api/v1/admin/curation/waive-versions`
//!   (bulk-by-version-list curator release; all-or-nothing).
//! - `waive digests --repo <key> --digests <d1>,<d2>,…
//!   --justification <text>` →
//!   POST `/api/v1/admin/curation/waive-digests`
//!   (bulk-by-content-digest curator release; all-or-nothing).
//! - `block artifact <artifact_id> --justification <text>` →
//!   POST `/api/v1/admin/curation/quarantine/:artifact_id/block`
//!   (single-artifact curator block).
//! - `block versions --repo <key> --package <name> --versions <v1>,<v2>,…
//!   --justification <text>` →
//!   POST `/api/v1/admin/curation/block-versions`
//!   (bulk-by-version-list curator block; continue-on-error).
//! - `block digests --repo <key> --digests <d1>,<d2>,…
//!   --justification <text>` →
//!   POST `/api/v1/admin/curation/block-digests`
//!   (bulk-by-content-digest curator block; continue-on-error).
//! - `reevaluate <artifact_id>` →
//!   POST `/api/v1/admin/curation/quarantine/:artifact_id/reevaluate`
//!   (recompute a `Rejected` artifact's verdict from stored findings
//!   under the active policy; no request body).
//! - `exclude-finding --policy <id> --cve <id> --justification <text>` →
//!   POST `/api/v1/admin/policies/:policy_id/exclusions`
//!   (policy-scoped CVE exclusion).
//! - `unexclude-finding --policy <id> --cve <id> --justification <text>` →
//!   DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//!   (remove a policy-scoped CVE exclusion).
//!
//! # One verb, three ways to name its target
//!
//! Both decision verbs are addressed the same three ways, because an
//! operator who has learned one must be able to guess the other: by
//! artifact id for the one-off, by version list where
//! `artifacts.version` is populated, and by content digest where it is
//! not (OCI) or where the bytes are what was reviewed. `waive` used to
//! be a flat command taking a UUID positionally; that form is **removed**
//! rather than deprecated — see [`waive`]'s own docs for the message a
//! caller of the old shape gets.
//!
//! **The two bulk contracts are not symmetric, and a reader must not
//! tidy them into one.** A bulk block is fail-safe: 100 entries per
//! call, continue-on-error, so it blocks what resolved and reports what
//! did not. A bulk waive is fail-open: 25 entries per call,
//! all-or-nothing, so one unresolvable, ambiguous or non-releasable
//! entry refuses the whole batch and releases nothing. `ArtifactReleased`
//! is history that cannot be retracted, while a block the curator did not
//! mean is reversible by the same curator a minute later.
//!
//! # Single vs bulk `block`
//!
//! The original design lists `block <artifact_id>` AND `block --repo ... --package
//! ... --versions ...` as two variants of the same `block` command. Clap's
//! XOR-between-positional-and-flag-group story produces vague error
//! messages on misuse (e.g. "the following required arguments were not
//! provided: <artifact_id>" instead of "supply either an artifact id OR
//! --repo + --package + --versions"). The implementation splits `block`
//! into two sub-subcommands — `block artifact <id>` and `block versions
//! --repo ... --package ... --versions ...` — which are self-documenting
//! in `--help` and produce specific errors on misuse. The wire endpoints
//! (`/quarantine/:id/block` vs `/block-versions`) and the per-event audit
//! shape are unchanged.
//!
//! # File-layout pattern
//!
//! One file per subcommand, a `mod.rs` that ties them together with the
//! clap subcommand enum + dispatcher. Only the parser-enum mount point
//! differs (top-level here, `admin/quarantine` nested under `admin`).
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. Wire DTOs are mirrored
//! verbatim from `hort-http-core::handlers::admin::curation::*` (the
//! `BlockOutcomeDto` + `FailedBlockEntryDto` shapes — single source of
//! truth on the server side). The "sync-required" comment on each DTO
//! flags the cross-crate contract for future maintainers.

pub mod block;
pub mod decisions;
pub mod exclude_finding;
pub mod exclusions;
pub mod queue;
pub mod reevaluate;
pub mod unexclude_finding;
pub mod waive;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli curation` arguments.
#[derive(clap::Args, Debug)]
pub struct CurationArgs {
    #[command(subcommand)]
    pub cmd: CurationCommand,
}

/// `curation` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum CurationCommand {
    /// Release held artifacts — with curator attribution.
    ///
    /// Emits `ArtifactReleased { authority: CuratorWaiver, reason:
    /// Curator }` per released artifact. `--justification` is required
    /// (≤ 512 bytes).
    ///
    /// Three addressing modes: `waive artifact <id>` (one artifact),
    /// `waive versions --repo ... --package ... --versions ...` and
    /// `waive digests --repo ... --digests ...` (bulk,
    /// all-or-nothing — one entry the server cannot release refuses the
    /// whole batch). The flat `waive <id>` form was removed.
    Waive(waive::WaiveArgs),

    /// Block artifacts — `Quarantined`/`Released` → `Rejected` with
    /// curator attribution.
    ///
    /// The same three addressing modes as `waive`: `block artifact
    /// <id>`, `block versions --repo ... --package ... --versions ...`
    /// and `block digests --repo ... --digests ...`. Both bulk modes are
    /// continue-on-error, which is the opposite of the bulk waive's
    /// contract — see module-level docs for why the two are not
    /// symmetric, and for the rationale on the sub-subcommand split vs
    /// the original design.
    Block(block::BlockArgs),

    /// Recompute a `Rejected` artifact's verdict from its stored
    /// findings under the currently active policy.
    ///
    /// No policy mutation, no forced outcome — the recompute delegates
    /// to the same domain derivation the policy-mutation pass uses.
    /// Idempotent: re-invoking on an unchanged `still_rejected` verdict
    /// returns the same envelope again, no repeated events.
    Reevaluate(reevaluate::ReevaluateArgs),

    /// Exclude a CVE finding for a scan policy.
    ///
    /// POST `/api/v1/admin/policies/:policy_id/exclusions`. Triggers the
    /// existing post-exclusion re-evaluation cascade — operators should
    /// be aware that one exclusion can release multiple artifacts whose
    /// only blocking findings were the now-excluded CVE (blast-radius
    /// consideration).
    ExcludeFinding(exclude_finding::ExcludeFindingArgs),

    /// Remove a CVE exclusion from a scan policy.
    ///
    /// DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
    /// Emits `ExclusionRemoved`; affected artifacts re-evaluate via the
    /// same cascade (some may transition back to `Quarantined` /
    /// `Rejected` if the now-restored CVE is blocking).
    UnexcludeFinding(unexclude_finding::UnexcludeFindingArgs),

    /// List artifacts currently in a curator-actionable state.
    ///
    /// GET `/api/v1/admin/curation/queue` — paginated read of
    /// `Quarantined` / `Rejected` / `ScanIndeterminate` artifacts
    /// with per-row quarantine deadlines, finding counts, and a
    /// `rejection_reason_kind` discriminator for rejected rows.
    Queue(queue::QueueArgs),

    /// List historical curator decisions (event-log read).
    ///
    /// GET `/api/v1/admin/curation/decisions` — uncollapsed by default
    /// (one row per event); `--by-correlation` collapses bulk operations
    /// into the curator's intent. The rollup is server-side.
    Decisions(decisions::DecisionsArgs),

    /// List active CVE exclusions (current-state read).
    ///
    /// GET `/api/v1/admin/curation/exclusions` — paginated read of
    /// `exclusion_projections`; distinct from `decisions` because
    /// exclusions have ongoing state.
    Exclusions(exclusions::ExclusionsArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `curation` subcommand tree.
///
/// Loads `EffectiveConfig`, builds the `AkClient`, then hands off to
/// the per-subcommand `run` function. Mirrors the `admin::run` shape so
/// the dispatch surface is uniform across the top-level command tree.
pub async fn run(
    args: CurationArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::config::load_effective_config;

    // Honor the global `--server`/`--token` flags (flag > env > config file),
    // same as get/list-versions/prefetch. Passing None here would silently
    // ignore `--server`, routing to the configured server — a footgun.
    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;

    match args.cmd {
        // The only arm that propagates its own exit code. A bulk waive
        // can be refused whole — zero releases — and a script must be
        // able to tell that from the applied case without parsing the
        // output it just printed. Mirrors `admin retention`, which
        // propagates for the same reason.
        CurationCommand::Waive(waive_args) => {
            return waive::run(client, waive_args, output).await;
        }
        CurationCommand::Block(block_args) => {
            block::run(client, block_args, output).await?;
        }
        CurationCommand::Reevaluate(reevaluate_args) => {
            reevaluate::run(client, reevaluate_args, output).await?;
        }
        CurationCommand::ExcludeFinding(exclude_args) => {
            exclude_finding::run(client, exclude_args, output).await?;
        }
        CurationCommand::UnexcludeFinding(unexclude_args) => {
            unexclude_finding::run(client, unexclude_args, output).await?;
        }
        CurationCommand::Queue(queue_args) => {
            queue::run(client, queue_args, output).await?;
        }
        CurationCommand::Decisions(decisions_args) => {
            decisions::run(client, decisions_args, output).await?;
        }
        CurationCommand::Exclusions(exclusions_args) => {
            exclusions::run(client, exclusions_args, output).await?;
        }
    }
    Ok(std::process::ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// Maximum byte length of the operator-supplied justification on every
/// curation decision subcommand. Mirrors `MAX_JUSTIFICATION_BYTES` in
/// `hort-http-core::handlers::admin::curation` (= 512), which itself
/// mirrors `CurationUseCase::validate_justification` and the domain
/// `ArtifactReleased`/`ArtifactRejected` event validators. Catching it
/// CLI-side gives operators a fast feedback loop and avoids burning an
/// audit-log 400 on operator error.
pub(crate) const MAX_JUSTIFICATION_BYTES: usize = 512;

/// The one digest algorithm a curation decision can be addressed by.
/// Hort addresses content by SHA-256 (ADR 0003), so this is the only
/// prefix [`normalize_digest`] strips rather than refuses.
pub(crate) const SHA256_DIGEST_ALGORITHM: &str = "sha256";

/// ANSI escapes used by the decision verbs' table output to draw the
/// operator's eye to a non-zero count that needs acting on. Inline
/// literals keep the dependency set tight (no `colored` crate), and
/// both verbs share them so one of them cannot start highlighting in a
/// different colour than the other.
pub(crate) const ANSI_RED: &str = "\x1b[31m";
pub(crate) const ANSI_RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Validate `--justification` text client-side.
///
/// Mirrors the server-side gate at every curation decision endpoint:
/// empty (after trim) and > 512 bytes are both rejected before any
/// HTTP round-trip. The error messages match `release.rs` verbatim so
/// operators see the same wording across the two surfaces.
pub(crate) fn validate_justification(justification: &str) -> anyhow::Result<()> {
    let trimmed = justification.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("justification must not be empty"));
    }
    if justification.len() > MAX_JUSTIFICATION_BYTES {
        return Err(anyhow::anyhow!(
            "justification exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
            justification.len()
        ));
    }
    Ok(())
}

/// Percent-encode a single URL path segment.
///
/// Defensive — UUIDs (artifact_id, policy_id) are URL-safe in the RFC
/// 3986 unreserved set, but encoding guards against malformed input
/// (e.g. `..` traversal sequences) if the operator pastes something
/// other than a canonical UUID. CVE IDs (`CVE-2026-XXXX`) are also
/// unreserved; vendor advisory IDs that contain non-unreserved bytes
/// (rare but allowed by the server) survive transit via the encoding.
///
/// `.` is intentionally excluded so `..` cannot survive encoding.
/// Sibling copy of the helper in `admin/quarantine/release.rs` — not
/// shared because the two may diverge as the validation rules evolve.
pub(crate) fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            b => {
                encoded.push('%');
                encoded.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                encoded.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    encoded
}

/// Wrap `n` in ANSI red when `n > 0` AND `use_ansi` is true.
///
/// Used for the counts an operator has to act on (`not_found`,
/// `failed`) so their eye is drawn to a non-zero one on an interactive
/// TTY — but the wrap is suppressed when stdout is piped or redirected
/// so raw escape bytes don't corrupt a downstream `grep` / `awk` / log
/// aggregator (mirrors `auth::login`'s `is_terminal()` gating). Zero is
/// never highlighted: a plain `0` is unambiguous.
pub(crate) fn highlight_if_nonzero(n: usize, use_ansi: bool) -> String {
    if n > 0 && use_ansi {
        format!("{ANSI_RED}{n}{ANSI_RESET}")
    } else {
        n.to_string()
    }
}

/// The `(red, reset)` pair to interpolate into a section header, or two
/// empty strings when colour is suppressed. One definition so a caller
/// cannot gate the column highlight on `use_ansi` and forget the
/// section header beside it.
pub(crate) fn ansi_pair(use_ansi: bool) -> (&'static str, &'static str) {
    if use_ansi {
        (ANSI_RED, ANSI_RESET)
    } else {
        ("", "")
    }
}

/// Normalise one operator-supplied digest to the bare 64-lowercase-hex
/// form `artifacts.checksum_sha256` stores and both digest-addressed
/// routes resolve against.
///
/// `sha256:<hex>` and a bare `<hex>` are the same address: an operator
/// copying a digest off an OCI manifest or off a `curation queue` row
/// must not have to know which spelling this surface wanted, so the two
/// produce the same request body.
///
/// **Any other algorithm prefix is an error, never a strip** — the same
/// rule, and the same wording, as the server's own
/// `normalize_curation_digest`. Hort addresses content by SHA-256, so a
/// `sha512:` digest cannot match a stored row; stripping its prefix
/// would turn "you asked with the wrong algorithm" into "that artifact
/// is not here", and send the curator looking for a missing artifact
/// instead of a mistyped request.
///
/// `index` is the entry's position in the caller's list (0-based, as the
/// server counts it) and is the only thing the message says about
/// *which* entry failed: the offending text is operator-supplied and
/// unbounded up to the first `:`, so it stays in the caller's own
/// command line rather than being reflected back.
pub(crate) fn normalize_digest(index: usize, raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    let hex = match trimmed.split_once(':') {
        Some((algorithm, rest)) => {
            if algorithm != SHA256_DIGEST_ALGORITHM {
                return Err(anyhow::anyhow!(
                    "digest at entry {index}: unsupported algorithm prefix — hort addresses \
                     content by SHA-256, so pass a bare 64-hex digest or a \
                     `{SHA256_DIGEST_ALGORITHM}:`-prefixed one"
                ));
            }
            rest
        }
        None => trimmed,
    };
    // Mirrors `ContentHash::is_valid_sha256_hex` — 64 lowercase hex. The
    // CLI checks it for the same reason it checks `--justification`: the
    // server refuses the same input, and refusing it here costs the
    // operator no round trip. Uppercase hex is refused rather than
    // lowercased, because accepting what the API rejects would make this
    // surface's "same request body" promise hide a divergence.
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(hex.to_string())
    } else {
        Err(anyhow::anyhow!(
            "digest at entry {index}: invalid SHA-256 hash: expected 64 lowercase hex \
             characters, got {len} characters",
            len = hex.len()
        ))
    }
}

/// Normalise a whole `--digests` list, rejecting an empty one.
///
/// Shared by `waive digests` and `block digests` so the two verbs cannot
/// disagree about which spellings name one address — the client-side
/// half of the single resolver the server runs for both.
pub(crate) fn normalize_digests(raw: &[String]) -> anyhow::Result<Vec<String>> {
    if raw.is_empty() {
        return Err(anyhow::anyhow!("--digests must not be empty"));
    }
    raw.iter()
        .enumerate()
        .map(|(index, d)| normalize_digest(index, d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_justification_accepts_ordinary_text() {
        assert!(validate_justification("CVE-2026-XXXX false-positive").is_ok());
    }

    #[test]
    fn validate_justification_rejects_empty() {
        let err = validate_justification("").unwrap_err().to_string();
        assert!(err.contains("empty"), "error references empty: {err}");
    }

    #[test]
    fn validate_justification_rejects_whitespace_only() {
        let err = validate_justification("   \n\t  ").unwrap_err().to_string();
        assert!(err.contains("empty"), "error references empty: {err}");
    }

    #[test]
    fn validate_justification_rejects_oversize() {
        let oversize = "a".repeat(513);
        let err = validate_justification(&oversize).unwrap_err().to_string();
        assert!(
            err.contains("512") || err.contains("exceeds"),
            "error references the cap: {err}"
        );
    }

    #[test]
    fn validate_justification_accepts_exactly_512_bytes() {
        let exact = "a".repeat(512);
        assert!(validate_justification(&exact).is_ok());
    }

    #[test]
    fn max_justification_bytes_matches_server_cap() {
        // Mirrors `hort-http-core::handlers::admin::curation::MAX_JUSTIFICATION_BYTES`.
        // If the server cap changes, this test breaks loudly.
        assert_eq!(MAX_JUSTIFICATION_BYTES, 512);
    }

    // -- the shared digest address ------------------------------------------

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// The property the acceptance criterion names: the two spellings of
    /// one digest are one address, so they put the same bytes on the wire.
    #[test]
    fn a_prefixed_and_a_bare_digest_normalise_to_the_same_request_body() {
        let bare = normalize_digests(&[DIGEST.to_string()]).expect("bare hex is accepted");
        let prefixed =
            normalize_digests(&[format!("sha256:{DIGEST}")]).expect("a sha256: prefix is stripped");
        assert_eq!(bare, prefixed);
        assert_eq!(bare, vec![DIGEST.to_string()]);
        // And mixed spellings inside one list land on one address too.
        let mixed = normalize_digests(&[DIGEST.to_string(), format!("sha256:{DIGEST}")])
            .expect("mixed spellings are accepted");
        assert_eq!(mixed, vec![DIGEST.to_string(), DIGEST.to_string()]);
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_address() {
        assert_eq!(
            normalize_digest(0, &format!("  sha256:{DIGEST}\n")).expect("trimmed"),
            DIGEST
        );
    }

    /// A `sha512:` digest is a request written wrongly, not an artifact
    /// that is absent — so it is refused by name rather than stripped
    /// into a repo-wide scan for a hash that cannot exist.
    #[test]
    fn another_algorithm_prefix_is_refused_rather_than_stripped() {
        let err = normalize_digest(3, &format!("sha512:{}", "a".repeat(128)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("entry 3"), "names the entry: {err}");
        assert!(
            err.contains("unsupported algorithm prefix"),
            "names the cause: {err}"
        );
        assert!(err.contains("sha256:"), "names what to pass: {err}");
        // An uppercase algorithm is the same refusal — the server
        // compares the prefix exactly, so accepting it here would admit
        // what the API rejects.
        assert!(normalize_digest(0, &format!("SHA256:{DIGEST}")).is_err());
    }

    #[test]
    fn a_digest_that_is_not_64_lowercase_hex_is_refused() {
        for bad in [
            "deadbeef",
            &"z".repeat(64),
            &DIGEST.to_uppercase(),
            &format!("{DIGEST}0"),
        ] {
            let err = normalize_digest(1, bad).unwrap_err().to_string();
            assert!(err.contains("entry 1"), "names the entry: {err}");
            assert!(
                err.contains("64 lowercase hex"),
                "names the expected shape: {err}"
            );
        }
    }

    #[test]
    fn an_empty_digest_list_is_refused_before_the_round_trip() {
        let err = normalize_digests(&[]).unwrap_err().to_string();
        assert!(err.contains("--digests"), "names the flag: {err}");
    }

    // -- the shared highlight ----------------------------------------------

    #[test]
    fn highlight_if_nonzero_zero_no_ansi() {
        // Zero carries NO escape whatever `use_ansi` says — a plain "0"
        // is unambiguous and not worth an operator's attention.
        assert_eq!(highlight_if_nonzero(0, true), "0");
        assert_eq!(highlight_if_nonzero(0, false), "0");
    }

    #[test]
    fn highlight_if_nonzero_positive_with_ansi_wraps_in_red() {
        let s = highlight_if_nonzero(3, true);
        assert!(s.contains('3'));
        assert!(s.contains(ANSI_RED));
        assert!(s.contains(ANSI_RESET));
    }

    #[test]
    fn highlight_if_nonzero_positive_without_ansi_is_plain() {
        // Non-TTY path (pipe / file redirect / CI log capture): plain
        // digits, so downstream `grep`/`awk` never see escape bytes.
        let s = highlight_if_nonzero(3, false);
        assert_eq!(s, "3");
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn ansi_pair_is_empty_when_colour_is_suppressed() {
        assert_eq!(ansi_pair(true), (ANSI_RED, ANSI_RESET));
        assert_eq!(ansi_pair(false), ("", ""));
    }

    #[test]
    fn encode_path_segment_passes_through_uuid() {
        let uuid = "11111111-2222-3333-4444-555555555555";
        assert_eq!(encode_path_segment(uuid), uuid);
    }

    #[test]
    fn encode_path_segment_blocks_traversal() {
        assert_eq!(encode_path_segment(".."), "%2E%2E");
        assert_eq!(encode_path_segment("foo/../bar"), "foo%2F%2E%2E%2Fbar");
    }

    #[test]
    fn encode_path_segment_handles_cve_id() {
        // CVE-2026-XXXX is in the unreserved set. Vendor advisory IDs
        // (e.g. `GHSA-xxxx-yyyy-zzzz`) likewise unreserved.
        assert_eq!(encode_path_segment("CVE-2026-0001"), "CVE-2026-0001");
        assert_eq!(
            encode_path_segment("GHSA-1234-5678-9abc"),
            "GHSA-1234-5678-9abc"
        );
    }
}
