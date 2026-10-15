//! `hort-cli curation unexclude-finding` — DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
//!
//! Wire contract: `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//! (`hort-http-core::handlers::admin::policies::exclusions`).
//! Removes a CVE-scoped exclusion from a scan policy and emits
//! `ExclusionRemoved` with curator attribution.
//!
//! # Which row the CVE names
//!
//! The URL carries the CVE, but an exclusion's identity is its
//! `exclusion_id`: one policy can hold several exclusions for one CVE,
//! differing only in `package_pattern`. The server-side handler
//! resolves CVE → exclusion_id via the projection **only when that
//! resolution is unambiguous**; when the CVE names several rows it
//! answers `409` listing the candidates rather than letting the
//! projection's ordering decide which suppression ends.
//!
//! `--exclusion-id` is how the caller answers that `409`. It selects
//! *within* the path's CVE and never replaces it, so an id belonging to
//! another of the policy's CVEs is refused with `400` rather than
//! obeyed. Every `409` from this route is therefore resolvable by
//! repeating the same command with one of the ids the server just
//! listed — which is what this command prints instead of the raw body.
//!
//! # Cascade behaviour
//!
//! Removing an exclusion re-arms the now-restored CVE for the policy's
//! scope. The post-exclusion re-evaluation cascade may transition
//! artifacts that were previously released-by-exclusion back to
//! `Quarantined`/`Rejected` if the now-restored CVE is blocking.
//! Mirrors the `exclude-finding` blast-radius warning — the
//! audit-event chain (one `ExclusionRemoved` + N follow-up
//! state-change events) makes the cascade reconstructable.
//!
//! # Wire shape
//!
//! Per the server-side DELETE handler, the body is **optional** at the
//! HTTP layer (the handler accepts `Option<Json<RemoveExclusionRequestDto>>`)
//! but `reason` is REQUIRED — an empty `reason` is rejected with 400.
//! The CLI always sends the body so the curator-supplied justification
//! is recorded. The optional `exclusion_id` carries `--exclusion-id`
//! and is **omitted from the serialised body** when the flag is absent
//! — not sent as `null` — so a server that predates the field sees
//! byte-for-byte the body it has always seen.

use std::io::Write;

use anyhow::Result;
use uuid::Uuid;

use crate::client::{AkClient, HttpFailure};
use crate::config::OutputFormat;
use crate::output::format_json;

use super::{encode_path_segment, validate_justification};

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// Request body for `DELETE /admin/policies/:policy_id/exclusions/:cve_id`.
///
/// **Sync-required**: mirrors `RemoveExclusionRequestDto` in
/// `hort-http-core::handlers::admin::policies::exclusions`. The `reason`
/// field maps onto the operator-supplied `--justification`, and
/// `exclusion_id` onto `--exclusion-id`.
///
/// `exclusion_id` is skipped when absent rather than serialised as
/// `null`: an unqualified removal is the request this command has
/// always sent, and it must stay byte-identical on the wire so a server
/// that has never heard of the field keeps accepting it.
#[derive(Debug, serde::Serialize)]
struct RemoveExclusionRequestBody<'a> {
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exclusion_id: Option<Uuid>,
}

/// The `409` body the server answers with when the path's CVE names
/// several exclusions on the policy.
///
/// **Sync-required**: mirrors the `DomainError::AmbiguousExclusion`
/// structured-body early-return in `hort-http-core::error`
/// (`ApiError::into_response`). Only the members the operator's next
/// invocation needs are modelled; the body's `error` sentence is not one
/// of them, because this command states the remedy in its own words.
#[derive(Debug, serde::Deserialize)]
struct AmbiguousExclusionBody {
    cve_id: String,
    candidates: Vec<ExclusionCandidateDto>,
}

/// One row of [`AmbiguousExclusionBody::candidates`]: the identity to
/// name on the retry, plus the only field that tells two exclusions for
/// one CVE apart.
#[derive(Debug, serde::Deserialize)]
struct ExclusionCandidateDto {
    exclusion_id: Uuid,
    #[serde(default)]
    package_pattern: Option<String>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation unexclude-finding`.
#[derive(clap::Args, Debug)]
pub struct UnexcludeFindingArgs {
    /// Scan policy UUID carrying the exclusion to remove.
    #[arg(long, required = true)]
    pub policy: String,

    /// CVE identifier of the exclusion to remove (e.g. `CVE-2026-0001`).
    /// A miss surfaces as 404 (no exclusion with that CVE on this
    /// policy); a CVE naming several exclusions on the policy surfaces
    /// as 409 listing them, which `--exclusion-id` answers.
    #[arg(long, required = true)]
    pub cve: String,

    /// Which exclusion to remove, when `--cve` names more than one of
    /// them on this policy. Optional — a CVE naming exactly one
    /// exclusion needs no disambiguator. Take the value from the
    /// candidates the 409 lists, or from what `curation exclude-finding`
    /// printed. It selects within `--cve`: an id belonging to another
    /// CVE is refused, not obeyed.
    #[arg(long)]
    pub exclusion_id: Option<Uuid>,

    /// Operator justification recorded on the emitted
    /// `ExclusionRemoved` event. Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: UnexcludeFindingArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: UnexcludeFindingArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    validate_justification(&args.justification)?;
    if args.cve.trim().is_empty() {
        return Err(anyhow::anyhow!("--cve must not be empty"));
    }

    let encoded_policy = encode_path_segment(&args.policy);
    let encoded_cve = encode_path_segment(&args.cve);
    let path = format!("/api/v1/admin/policies/{encoded_policy}/exclusions/{encoded_cve}");

    let body = RemoveExclusionRequestBody {
        reason: &args.justification,
        exclusion_id: args.exclusion_id,
    };
    // The server returns 204 No Content on success. A refusal is taken
    // as a response rather than a flattened error because the ambiguity
    // 409 carries the ids the operator's next invocation has to name,
    // and an identifier recovered by parsing an error sentence is
    // exactly what that body exists to avoid.
    if let Some(failure) = client.delete_capturing_failure(&path, &body).await? {
        return Err(match render_ambiguity(&args.policy, &failure) {
            Some(rendered) => anyhow::anyhow!("{rendered}"),
            // Anything else — including a 409 whose body is not the
            // ambiguity report — surfaces verbatim, as every other call
            // in the CLI does. A parser that did not match must not
            // swallow what the server said.
            None => failure.into_error(),
        });
    }

    match output {
        OutputFormat::Json => {
            let body = serde_json::json!({
                "removed_exclusion_cve": &args.cve,
                "policy_id": &args.policy,
            });
            writeln!(out, "{}", format_json(&body))?;
        }
        OutputFormat::Table => {
            writeln!(
                out,
                "removed exclusion {cve} from policy {policy}",
                cve = args.cve,
                policy = args.policy,
            )?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ambiguity rendering
// ---------------------------------------------------------------------------

/// Render the ambiguity `409` as the command the operator should run
/// next, or `None` when this refusal is not that response.
///
/// `None` is the instruction to surface the body verbatim. Rendering a
/// 409 that carries no candidates would replace what the server said
/// with a remedy naming nothing — strictly less than the raw body, for
/// an operator who then has neither the ids nor the server's own words.
fn render_ambiguity(policy: &str, failure: &HttpFailure) -> Option<String> {
    if failure.status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let parsed: AmbiguousExclusionBody = serde_json::from_str(&failure.body).ok()?;
    if parsed.candidates.is_empty() {
        return None;
    }

    let mut lines = vec![format!(
        "{count} exclusions on policy {policy} match {cve}; nothing was removed. \
         Repeat the command with --exclusion-id naming the one to remove:",
        count = parsed.candidates.len(),
        cve = parsed.cve_id,
    )];
    lines.extend(parsed.candidates.iter().map(|candidate| {
        let pattern = match &candidate.package_pattern {
            Some(pattern) => format!("package_pattern {pattern}"),
            None => "no package_pattern".to_string(),
        };
        format!(
            "  --exclusion-id {id}  ({pattern})",
            id = candidate.exclusion_id,
        )
    }));
    Some(lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PATTERNED: &str = "11111111-1111-1111-1111-111111111111";
    const UNPATTERNED: &str = "22222222-2222-2222-2222-222222222222";

    fn conflict(body: &str) -> HttpFailure {
        HttpFailure {
            status: reqwest::StatusCode::CONFLICT,
            body: body.to_string(),
        }
    }

    /// The body an unqualified removal puts on the wire is the body it
    /// put there before `exclusion_id` existed — the field is absent,
    /// not `null`, so a server that has never heard of it still parses
    /// what it always parsed.
    #[test]
    fn an_unqualified_removal_serialises_to_the_body_it_always_did() {
        let body = RemoveExclusionRequestBody {
            reason: "re-arm the CVE",
            exclusion_id: None,
        };
        assert_eq!(
            serde_json::to_string(&body).expect("serialises"),
            r#"{"reason":"re-arm the CVE"}"#
        );
    }

    #[test]
    fn a_named_exclusion_rides_the_body_as_exclusion_id() {
        let body = RemoveExclusionRequestBody {
            reason: "re-arm the CVE",
            exclusion_id: Some(PATTERNED.parse().expect("valid uuid")),
        };
        assert_eq!(
            serde_json::to_string(&body).expect("serialises"),
            format!(r#"{{"reason":"re-arm the CVE","exclusion_id":"{PATTERNED}"}}"#)
        );
    }

    /// The gap this unit closes: on an ambiguous CVE the operator must
    /// leave with the ids AND the flag that uses them. A raw JSON dump
    /// carries the first and not the second.
    #[test]
    fn the_ambiguity_report_names_every_candidate_and_the_flag_to_repeat_with() {
        let rendered = render_ambiguity(
            "77777777-7777-7777-7777-777777777777",
            &conflict(&format!(
                r#"{{"error":"multiple exclusions match CVE-2026-9999; name one with exclusion_id",
                    "cve_id":"CVE-2026-9999",
                    "candidates":[
                      {{"exclusion_id":"{PATTERNED}","package_pattern":"pkg:npm/left-pad@*"}},
                      {{"exclusion_id":"{UNPATTERNED}","package_pattern":null}}
                    ]}}"#
            )),
        )
        .expect("the ambiguity body is recognised");

        assert!(
            rendered.contains("CVE-2026-9999"),
            "names the CVE: {rendered}"
        );
        assert!(
            rendered.contains("77777777-7777-7777-7777-777777777777"),
            "names the policy: {rendered}"
        );
        assert!(
            rendered.contains("nothing was removed"),
            "says the request had no effect: {rendered}"
        );
        // Both rows reachable — the promise this restores.
        assert!(
            rendered.contains(&format!("--exclusion-id {PATTERNED}")),
            "first candidate carries the flag: {rendered}"
        );
        assert!(
            rendered.contains(&format!("--exclusion-id {UNPATTERNED}")),
            "second candidate carries the flag: {rendered}"
        );
        // The discriminator is what lets the operator choose.
        assert!(
            rendered.contains("pkg:npm/left-pad@*"),
            "patterned row shows its pattern: {rendered}"
        );
        assert!(
            rendered.contains("no package_pattern"),
            "unpatterned row says so rather than printing null: {rendered}"
        );
        // One line per candidate, under one header.
        assert_eq!(rendered.lines().count(), 3, "header + 2 rows: {rendered}");
    }

    /// A 409 the parser does not recognise must reach the operator as
    /// the server wrote it, not be swallowed by the renderer.
    #[test]
    fn an_unrecognised_409_body_is_not_rendered() {
        assert!(render_ambiguity("p", &conflict(r#"{"error":"version conflict"}"#)).is_none());
        assert!(render_ambiguity("p", &conflict("not json at all")).is_none());
    }

    /// A 409 shaped like the report but listing nobody names no remedy;
    /// the server's own words are worth more than an empty one.
    #[test]
    fn a_409_with_no_candidates_is_not_rendered() {
        assert!(render_ambiguity(
            "p",
            &conflict(r#"{"cve_id":"CVE-2026-9999","candidates":[]}"#)
        )
        .is_none());
    }

    /// The status is half the predicate: the same members under a
    /// different status are a different answer, and guessing otherwise
    /// would rewrite an unrelated refusal into a remedy.
    #[test]
    fn an_ambiguity_shaped_body_under_another_status_is_not_rendered() {
        let failure = HttpFailure {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: format!(
                r#"{{"cve_id":"CVE-2026-9999","candidates":[{{"exclusion_id":"{PATTERNED}","package_pattern":null}}]}}"#
            ),
        };
        assert!(render_ambiguity("p", &failure).is_none());
    }
}
