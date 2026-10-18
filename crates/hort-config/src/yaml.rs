//! The one YAML parse the gitops control path performs.
//!
//! Every operator-authored envelope reaches the registry through
//! [`from_slice`], and [`from_slice`] is the only place in the workspace
//! that builds a [`serde_saphyr::Options`] value. That is deliberate: each
//! per-kind entry point in this crate parses the *same* language — a
//! single-document, strict-schema gitops envelope — so "what an operator's
//! file means" has exactly one definition. A second `Options` literal
//! beside another parse call would be a second definition of that meaning,
//! and the two could drift without any test noticing, because each site
//! would still be self-consistent.
//!
//! # Why these settings
//!
//! The replacement deserialiser's defaults are *not* the semantics this
//! tree has always had. Four of them had to be pinned back, and each is
//! load-bearing for a different reason. Every one is measured from a
//! production entry point under `tests/` — the first three in
//! `tests/gitops_parser_semantics.rs`, the comment one in
//! `tests/comment_runs_do_not_fail_the_parse.rs` — so a silent revert
//! here fails one of those targets rather than changing what a deployed
//! tree means.
//!
//! - **`duplicate_keys: Error`** — a repeated mapping key is refused
//!   outright. This reaches *inside* a map-typed spec field, where serde's
//!   derived duplicate-field rejection cannot: `FederatedIdentitySpec`'s
//!   `claims` is the exact-match condition under which a JWT may assume a
//!   service account (ADR 0018), and a last-wins there applies a trust
//!   policy the file does not read as, with the discarded entry visible
//!   nowhere in parse, validate or the apply diff. It is the parser
//!   default; it is named here because it is the one guarantee this crate
//!   must never lose, not because it needs changing.
//! - **`merge_keys: AsOrdinary`** — `<<` stays an ordinary mapping key
//!   rather than being expanded. A strict spec then rejects it by name, and
//!   a spec struct without `deny_unknown_fields` ignores it. Expansion
//!   would give `<<` a meaning it has never had on this tree: a reused
//!   domain entity with per-field defaults (`PrefetchPolicy`) would start
//!   taking merged values with no diagnostic on either side of the change
//!   — same bytes, different policy, nothing downstream able to tell which
//!   it got.
//! - **`strict_booleans: true`** — only the literals `true` and `false`
//!   resolve to a boolean. The YAML 1.1 words (`yes`/`no`/`on`/`off`/`y`/
//!   `n`) are refused in a boolean position, as they always have been here.
//!   `ScanPolicySpec::require_approval` decides whether a release needs a
//!   human: resolving `requireApproval: no` to `false` would silently
//!   answer that question for the operator, and the same resolution turns a
//!   bare `NO` into `false` in any untyped position.
//! - **`with_snippet: false` + `crop_radius: 0`** — security, not taste.
//!   With snippets on, a rendered parse error carries a rustc-style echo of
//!   the offending source line plus its neighbours. `ParseError::Yaml`
//!   renders into the boot log and the apply-time linter output, and a
//!   syntax error two lines below a plaintext `proxy.credentials` value
//!   reproduces that value verbatim. The repository entry point's
//!   forbidden-field pre-scan cannot help: the pre-scan is itself a parse,
//!   so a syntax error defeats it and the parse error is what surfaces.
//!   Rich diagnostics belong on a CLI, not in a service log. Both knobs are
//!   set because the crate's four snippet guards each test
//!   `with_snippet && crop_radius > 0` — either value alone disables the
//!   echo, so setting both means neither field's default or meaning
//!   changing upstream can re-enable it.
//! - **`emit_comments: false`** — comment *text* is not collected. This is
//!   not a diagnostics preference: it is what removes a limit on how long
//!   an operator's comment block is allowed to be. With emission on, the
//!   parser buffers the comment events it meets while resolving an
//!   ambiguous collection entry, and `Budget::max_buffered_comment_events`
//!   (default 32) refuses the 33rd — so a run of 33 or more comment lines
//!   *immediately before a collection's first entry* fails the parse with
//!   `too many consecutive comments before resolving collection entry`,
//!   while the same run **between** two entries is unbounded (200 lines
//!   parse). The retired parser had no such budget in any position, so a
//!   heavily-commented envelope that booted before the swap would stop
//!   booting, in one syntactic position only, with a message that suggests
//!   no remedy. Nothing here reads a comment: every parse deserialises
//!   into a typed envelope and no type in this workspace is a
//!   `serde_saphyr::Commented`, so collecting comment text buys nothing
//!   and the budget it brings costs an operator their file. Comments are
//!   still recognised and validated as YAML syntax — a malformed one is
//!   still a parse error. What emission-off also gives up: the parser
//!   stops counting comment bytes against `Budget::max_total_comment_bytes`
//!   (64 MiB) and excludes comment events from `max_events`. Both are
//!   weak bounds on this path, because `from_slice` is handed a document
//!   the caller has already read into memory in full
//!   (`DesiredState::parse_files` takes `Vec<u8>`) — the input's own
//!   length is the real bound, and it binds whether or not the parser
//!   counts the same bytes a second time.
//!
//! Everything else stays at the parser's defaults, including the node and
//! alias budgets (which bound an alias bomb) and the alias-to-anchor ratio.
//! The ratio is the one construct where the replacement is *stricter* than
//! what shipped before it — one anchor backing 100 or more aliases is
//! refused — and no gitops envelope in this repository uses an anchor at
//! all, so loosening a bound to accommodate a document nobody has written
//! would be the wrong direction.

use serde::de::DeserializeOwned;

/// Build the gitops parse's options.
///
/// Rebuilt per call rather than shared: `Options` carries `Rc` fields (for
/// the include-resolver and property-map hooks this crate does not use), so
/// it is neither `Copy` nor `Sync` and cannot be a constant. The value is a
/// handful of scalars and one `Budget`, which is noise beside parsing a
/// file.
fn gitops_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        strict_booleans: true,
        with_snippet: false,
        crop_radius: 0,
        emit_comments: false,
    }
}

/// Deserialise one gitops envelope from a single YAML document.
///
/// The single parse call path for this crate. Rejects a multi-document
/// stream — an envelope file declares exactly one object, and silently
/// taking the first document of several would apply a tree the operator
/// cannot see in their own file.
pub(crate) fn from_slice<T>(bytes: &[u8]) -> Result<T, serde_saphyr::Error>
where
    T: DeserializeOwned,
{
    serde_saphyr::from_slice_with_options(bytes, gitops_options())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the five settings that differ from the parser's defaults, plus
    /// the duplicate-key policy the migration exists to gain, at the
    /// definition itself. The behavioural proofs are under `tests/`,
    /// measured through the production entry points; this is the cheap
    /// tripwire beside the decision.
    #[test]
    fn the_gitops_options_pin_the_decided_flags() {
        let options = gitops_options();

        assert!(
            matches!(
                options.duplicate_keys,
                serde_saphyr::DuplicateKeyPolicy::Error
            ),
            "a repeated mapping key must be refused, including inside a map-typed spec field"
        );
        assert!(
            matches!(options.merge_keys, serde_saphyr::MergeKeyPolicy::AsOrdinary),
            "`<<` must stay an ordinary key rather than becoming an expansion"
        );
        assert!(
            options.strict_booleans,
            "only `true`/`false` may resolve to a boolean"
        );
        assert!(
            !options.with_snippet && options.crop_radius == 0,
            "a rendered parse error must not echo operator source into a service log"
        );
        assert!(
            !options.emit_comments,
            "comment collection must stay off: it is what removes the buffered-comment \
             budget that otherwise refuses a long comment block before a collection's \
             first entry"
        );
    }

    /// The budgets are the parser's own, and they are what bound an alias
    /// bomb. Asserted so a future edit that reaches for `budget: None` to
    /// make some document parse has to argue with a failing test.
    #[test]
    fn the_gitops_options_keep_the_parser_budget() {
        let options = gitops_options();
        let budget = options
            .budget
            .expect("budget enforcement must stay on: it is what bounds alias expansion");
        assert!(budget.enforce_alias_anchor_ratio);
        assert!(budget.max_nodes > 0);
    }
}
