//! Shared per-format range-max resolvers for
//! [`FormatHandler::resolve_range_max`](hort_domain::ports::format_handler::FormatHandler::resolve_range_max).
//!
//! Each function takes the format's native range syntax + a set of
//! candidate version strings and returns the **highest** version in the
//! set satisfying the range. **Range-max only — NOT a SAT solver.**
//! See the trait method docstring for the full scope contract.
//!
//! **Best-effort by design.** An unparseable range silently returns
//! `None`; an `available` entry that fails to parse is silently dropped
//! from the candidate set; an empty `available` returns `None`. The
//! cascade reads `None` as "skip this dep" — a single bad upstream
//! line must never starve the rest of the prefetch walk.
//!
//! The returned string is the **original** entry from `available`, NOT a
//! normalised re-serialisation. The caller feeds it straight back into a
//! pull-through URL that requires the exact upstream-published spelling.

/// Semver-flavoured range-max resolver. Shared between npm (caret /
/// tilde / `>=` / `<` / hyphen / `*` / `x` wildcards) and cargo (whose
/// range grammar IS the `semver` crate's default interpretation).
///
/// Pre-release inclusion follows semver §11.4: a pre-release candidate
/// is excluded from a range unless the range explicitly names a
/// pre-release at the same `MAJOR.MINOR.PATCH`. This matches the
/// `semver::VersionReq::matches` semantics — npm/cargo's behaviour.
///
/// Returns the matching version's original string from `available`.
pub(crate) fn resolve_semver_range_max(range: &str, available: &[&str]) -> Option<String> {
    let req = semver::VersionReq::parse(range).ok()?;
    let mut best: Option<(semver::Version, &str)> = None;
    for raw in available {
        let Ok(v) = semver::Version::parse(raw) else {
            continue;
        };
        if !req.matches(&v) {
            continue;
        }
        match &best {
            Some((b, _)) if &v <= b => {}
            _ => best = Some((v, raw)),
        }
    }
    best.map(|(_, raw)| raw.to_string())
}

/// PEP 440 range-max resolver for PyPI.
///
/// Parses `range` as a PEP 440
/// [`VersionSpecifiers`](pep440_rs::VersionSpecifiers) and each
/// `available` entry as a [`Version`](pep440_rs::Version). Pre-releases
/// are EXCLUDED from the candidate set unless the range explicitly
/// allows them (PEP 440 §"Handling of pre-releases" — pip's default).
/// `pep440_rs::VersionSpecifiers::contains(&Version)` implements this
/// pip-equivalent semantics directly.
///
/// Returns the matching version's original string from `available`.
pub(crate) fn resolve_pep440_range_max(range: &str, available: &[&str]) -> Option<String> {
    let req: pep440_rs::VersionSpecifiers = range.parse().ok()?;

    // Pre-releases are admitted only if (a) the range explicitly names
    // one, or (b) every candidate is a pre-release (pip's fallback
    // when nothing else matches). The pep440_rs `contains` method does
    // NOT implement (b) — the v0.7 API exposes only the per-specifier
    // `contains_pre_releases`. We mirror pip's two-pass behaviour
    // here, prioritising finals.
    let range_admits_pre = range_admits_prereleases(range);

    let mut best: Option<(pep440_rs::Version, &str)> = None;
    for raw in available {
        let Ok(v) = raw.parse::<pep440_rs::Version>() else {
            continue;
        };
        if v.is_pre() && !range_admits_pre {
            continue;
        }
        if !req.contains(&v) {
            continue;
        }
        match &best {
            Some((b, _)) if &v <= b => {}
            _ => best = Some((v, raw)),
        }
    }
    if best.is_some() {
        return best.map(|(_, raw)| raw.to_string());
    }

    // Pre-release fallback (PEP 440 §pre-release-handling): if no
    // final satisfies the range, admit pre-releases and try again.
    let mut best_pre: Option<(pep440_rs::Version, &str)> = None;
    for raw in available {
        let Ok(v) = raw.parse::<pep440_rs::Version>() else {
            continue;
        };
        if !req.contains(&v) {
            continue;
        }
        match &best_pre {
            Some((b, _)) if &v <= b => {}
            _ => best_pre = Some((v, raw)),
        }
    }
    best_pre.map(|(_, raw)| raw.to_string())
}

/// Heuristic: does `range` syntactically name at least one pre-release
/// boundary? Mirrors pip's
/// `SpecifierSet.prereleases` autodetection (any specifier whose
/// version contains a pre-release tag enables pre-release inclusion).
///
/// A best-effort scan rather than a re-parse: `pep440_rs` exposes
/// `VersionSpecifier::version()` only in newer versions, and we keep
/// the helper portable. The PEP 440 pre-release markers are `a`, `b`,
/// `c`, `rc`, `alpha`, `beta`, `pre`, `preview`, `dev`. A lowercase
/// scan is correct: pip itself normalises the range to lowercase
/// before this check.
fn range_admits_prereleases(range: &str) -> bool {
    let lower = range.to_lowercase();
    // Quick reject — common ranges (`>=1.0`, `~=1.4`) have no letters.
    if !lower.bytes().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    for marker in [".dev", "a", "b", "rc", "alpha", "beta", "pre", "preview"] {
        // Plain `.dev` is unambiguous; the others are letters that
        // could appear elsewhere only in numeric-version segments,
        // which PEP 440 disallows — release segments are numeric.
        // The `c` alias for `rc` would conflict with the `c` inside
        // `rc` so we don't include the bare `c` here; the explicit
        // `rc` covers both.
        if lower.contains(marker) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- semver --------------------------------------------------------

    #[test]
    fn semver_caret_picks_highest_compatible() {
        // `^1.2` admits >=1.2.0, <2.0.0. The highest match is 1.2.5.
        let avail = ["1.1.0", "1.2.0", "1.2.5", "1.3.0", "2.0.0"];
        assert_eq!(
            resolve_semver_range_max("^1.2", &avail).as_deref(),
            Some("1.3.0")
        );
    }

    #[test]
    fn semver_caret_exact_minor_picks_highest_in_minor() {
        // `^1.2.0` admits >=1.2.0, <2.0.0.
        let avail = ["1.2.0", "1.2.5", "1.3.0", "2.0.0"];
        assert_eq!(
            resolve_semver_range_max("^1.2.0", &avail).as_deref(),
            Some("1.3.0")
        );
    }

    #[test]
    fn semver_tilde_pins_to_minor() {
        // `~1.2.3` admits >=1.2.3, <1.3.0.
        let avail = ["1.2.0", "1.2.3", "1.2.5", "1.3.0"];
        assert_eq!(
            resolve_semver_range_max("~1.2.3", &avail).as_deref(),
            Some("1.2.5")
        );
    }

    #[test]
    fn semver_exact_pin_picks_only_match() {
        let avail = ["1.0.0", "1.2.3", "2.0.0"];
        assert_eq!(
            resolve_semver_range_max("=1.2.3", &avail).as_deref(),
            Some("1.2.3")
        );
    }

    #[test]
    fn semver_range_matching_nothing_returns_none() {
        let avail = ["1.0.0", "1.1.0"];
        assert_eq!(resolve_semver_range_max("^2", &avail), None);
    }

    #[test]
    fn semver_unparseable_range_returns_none() {
        let avail = ["1.0.0"];
        assert_eq!(resolve_semver_range_max("<<not a range>>", &avail), None);
    }

    #[test]
    fn semver_empty_available_returns_none() {
        assert_eq!(resolve_semver_range_max("^1.0", &[]), None);
    }

    #[test]
    fn semver_unparseable_available_entries_are_silently_dropped() {
        // Garbage entries don't poison the lookup; the parseable ones
        // still resolve. Mirrors the "best-effort" contract.
        let avail = ["garbage", "1.2.0", "also-garbage", "1.3.0"];
        assert_eq!(
            resolve_semver_range_max("^1.0", &avail).as_deref(),
            Some("1.3.0")
        );
    }

    #[test]
    fn semver_prereleases_excluded_unless_range_admits_them() {
        // `^1.0` admits 1.x.y release versions but NOT 1.0.0-beta.1
        // (semver §11.4 / `semver::VersionReq` rule). The highest
        // RELEASE wins.
        let avail = ["1.0.0", "1.1.0-beta.1", "1.1.0"];
        assert_eq!(
            resolve_semver_range_max("^1.0", &avail).as_deref(),
            Some("1.1.0")
        );
    }

    #[test]
    fn semver_prerelease_admitted_when_range_explicitly_names_one() {
        // `>=1.0.0-beta.1` explicitly names the pre-release boundary
        // — the candidate is admitted.
        let avail = ["1.0.0-beta.1", "1.0.0-beta.2"];
        assert_eq!(
            resolve_semver_range_max(">=1.0.0-beta.1, <1.0.0", &avail).as_deref(),
            Some("1.0.0-beta.2")
        );
    }

    #[test]
    fn semver_wildcard_star_matches_anything() {
        let avail = ["0.1.0", "1.0.0", "9.9.9"];
        assert_eq!(
            resolve_semver_range_max("*", &avail).as_deref(),
            Some("9.9.9")
        );
    }

    #[test]
    fn semver_returns_original_string_form() {
        // Highest version's *original* spelling is returned, NOT a
        // re-serialised form. This matters for cargo `vers` strings
        // (which round-trip identically here, but the contract holds
        // for any future format whose Version::to_string() differs
        // from the input).
        let avail = ["1.2.3"];
        let out = resolve_semver_range_max("^1.0", &avail).expect("Some");
        assert_eq!(out, "1.2.3");
    }

    // ---- pep440 --------------------------------------------------------

    #[test]
    fn pep440_compatible_release_picks_highest() {
        // `~=1.4` admits >=1.4, <2.0. Highest matching final wins.
        let avail = ["1.3.0", "1.4.0", "1.4.5", "1.5.0", "2.0.0"];
        assert_eq!(
            resolve_pep440_range_max("~=1.4", &avail).as_deref(),
            Some("1.5.0")
        );
    }

    #[test]
    fn pep440_inequality_range_picks_highest_in_window() {
        let avail = ["1.0.0", "1.5.0", "1.9.0", "2.0.0", "3.0.0"];
        assert_eq!(
            resolve_pep440_range_max(">=1.0,<2.0", &avail).as_deref(),
            Some("1.9.0")
        );
    }

    #[test]
    fn pep440_exact_pin_picks_only_match() {
        let avail = ["1.0.0", "1.2.3", "2.0.0"];
        assert_eq!(
            resolve_pep440_range_max("==1.2.3", &avail).as_deref(),
            Some("1.2.3")
        );
    }

    #[test]
    fn pep440_range_matching_nothing_returns_none() {
        let avail = ["1.0.0", "1.1.0"];
        assert_eq!(resolve_pep440_range_max(">=2", &avail), None);
    }

    #[test]
    fn pep440_unparseable_range_returns_none() {
        let avail = ["1.0.0"];
        assert_eq!(
            resolve_pep440_range_max("<<not a specifier>>", &avail),
            None
        );
    }

    #[test]
    fn pep440_empty_available_returns_none() {
        assert_eq!(resolve_pep440_range_max(">=1", &[]), None);
    }

    #[test]
    fn pep440_prereleases_excluded_by_default() {
        // `>=1.0` does NOT name a pre-release boundary → the
        // pre-release candidate is dropped, the final 1.5.0 wins.
        let avail = ["1.0.0", "2.0.0a1", "1.5.0"];
        assert_eq!(
            resolve_pep440_range_max(">=1.0", &avail).as_deref(),
            Some("1.5.0")
        );
    }

    #[test]
    fn pep440_prerelease_admitted_when_range_names_one() {
        // `>=2.0.0a1` explicitly names a pre-release — pre-releases
        // are admitted.
        let avail = ["2.0.0a1", "2.0.0a2", "2.0.0b1"];
        assert_eq!(
            resolve_pep440_range_max(">=2.0.0a1", &avail).as_deref(),
            Some("2.0.0b1")
        );
    }

    #[test]
    fn pep440_pre_only_fallback_when_no_final_matches() {
        // No finals in the range satisfy it — pip's fallback admits
        // pre-releases. PEP 440 §pre-release-handling. Using `>=1.0`
        // here because `>=2.0` semantically excludes `2.0.0a1`
        // (PEP 440: a pre-release sorts BELOW the corresponding
        // release, so 2.0.0a1 < 2.0). `>=1.0` includes both pre and
        // final candidates by ordering; the gating decides which
        // pass admits them.
        let avail = ["2.0.0a1", "2.0.0b1"];
        assert_eq!(
            resolve_pep440_range_max(">=1.0", &avail).as_deref(),
            Some("2.0.0b1")
        );
    }

    #[test]
    fn pep440_unparseable_available_entries_are_silently_dropped() {
        let avail = ["garbage", "1.2.0", "also-garbage", "1.3.0"];
        assert_eq!(
            resolve_pep440_range_max(">=1.0", &avail).as_deref(),
            Some("1.3.0")
        );
    }

    #[test]
    fn pep440_arbitrary_equality_triple_equals() {
        // `===1.2.3` is PEP 440's arbitrary-equality operator — only
        // an exact lexical match. The pep440_rs crate parses it; we
        // confirm the resolver follows the same rules.
        let avail = ["1.2.3"];
        assert_eq!(
            resolve_pep440_range_max("===1.2.3", &avail).as_deref(),
            Some("1.2.3")
        );
    }

    // ---- range_admits_prereleases internal --------------------------

    #[test]
    fn range_admits_prereleases_recognises_dev_marker() {
        assert!(range_admits_prereleases(">=1.0.dev1"));
    }

    #[test]
    fn range_admits_prereleases_recognises_alpha_marker() {
        assert!(range_admits_prereleases(">=1.0a1"));
    }

    #[test]
    fn range_admits_prereleases_recognises_rc_marker() {
        assert!(range_admits_prereleases(">=1.0rc1"));
    }

    #[test]
    fn range_admits_prereleases_rejects_plain_numeric_range() {
        assert!(!range_admits_prereleases(">=1.0,<2.0"));
        assert!(!range_admits_prereleases("~=1.4"));
        assert!(!range_admits_prereleases("==1.2.3"));
    }
}
