//! Tests for [`super::collapse_alias_groups`].
//!
//! The three headline cases are built from the record shapes real OSV
//! responses return for these crates — a bare GHSA mirror alongside a
//! RustSec record carrying the metadata. Two of them must stop being
//! rejected; the third **must stay rejected**, and it is the load-bearing
//! one: the best-informed member wins, and when that member carries a real
//! CVSS the package stays blocked (ADR 0007).

use super::*;
use crate::entities::scan_policy::SeverityThreshold;
use crate::types::finding::severity_summary_from_findings;

const RAND_PURL: &str = "pkg:cargo/rand@0.7.3";
const TYPEMAP_PURL: &str = "pkg:cargo/typemap@0.3.3";
const TRAITOBJECT_PURL: &str = "pkg:cargo/traitobject@0.1.1";

/// A record the advisory database returned with **no severity and no
/// informational marker** — the GHSA mirror shape. Lowering fails it
/// closed to `Critical` (SUP-4) and marks the basis `Unassessed`.
fn bare_mirror(purl: &str, id: &str, aliases: &[&str]) -> Finding {
    Finding {
        purl: purl.into(),
        vulnerability_id: id.into(),
        severity: SeverityThreshold::Critical,
        cvss_score: None,
        title: id.into(),
        fixed_versions: vec![],
        source_scanner: "osv".into(),
        references: vec![],
        aliases: aliases.iter().map(|a| (*a).to_string()).collect(),
        informational_class: None,
        severity_basis: SeverityBasis::Unassessed,
    }
}

/// A RustSec informational record: no CVSS by design, a recognised
/// `database_specific.informational` class, severity lowered to the
/// cosmetic `Low` the OSV adapters map informational advisories to.
fn informational(purl: &str, id: &str, class: &str, aliases: &[&str]) -> Finding {
    Finding {
        severity: SeverityThreshold::Low,
        informational_class: Some(class.into()),
        severity_basis: SeverityBasis::Assessed,
        ..bare_mirror(purl, id, aliases)
    }
}

/// A RustSec record carrying a real CVSS vector.
fn scored(purl: &str, id: &str, score: f32, sev: SeverityThreshold, aliases: &[&str]) -> Finding {
    Finding {
        severity: sev,
        cvss_score: Some(score),
        severity_basis: SeverityBasis::Assessed,
        ..bare_mirror(purl, id, aliases)
    }
}

/// A record whose severity the backend genuinely read (a
/// `database_specific.severity` label) but which carries no numeric score
/// and no informational class.
fn label_only(purl: &str, id: &str, sev: SeverityThreshold, aliases: &[&str]) -> Finding {
    Finding {
        severity: sev,
        severity_basis: SeverityBasis::Assessed,
        ..bare_mirror(purl, id, aliases)
    }
}

/// Collapse `input` in the given order and in reverse, assert both
/// produce the same set of findings, and return the forward result.
/// Contribution order is not stable in production — advisory enrichment
/// is seeded before the scanners but the configured backend list decides
/// what appends after — so every case is checked both ways round.
fn collapse_both_orders(input: Vec<Finding>) -> Vec<Finding> {
    let forward = collapse_alias_groups(input.clone());
    let mut reversed_input = input;
    reversed_input.reverse();
    let reversed = collapse_alias_groups(reversed_input);

    let mut a: Vec<&Finding> = forward.iter().collect();
    let mut b: Vec<&Finding> = reversed.iter().collect();
    a.sort_by(|x, y| x.vulnerability_id.cmp(&y.vulnerability_id));
    b.sort_by(|x, y| x.vulnerability_id.cmp(&y.vulnerability_id));
    assert_eq!(a, b, "collapse must not depend on contribution order");
    forward
}

// ---------------------------------------------------------------------------
// The three exemplars
// ---------------------------------------------------------------------------

/// `rand 0.7.3`: OSV returns `GHSA-cq8v-f236-94qc` (bare) alongside
/// `RUSTSEC-2026-0097` (no severity, `informational: unsound`). Before the
/// collapse the bare mirror's fail-closed `Critical` shadowed the
/// classification — and the cross-backend merge could not rescue it,
/// because the two records carry different advisory ids. After the
/// collapse there is one informational finding, which rides the negligible
/// lane and does not reject the artifact.
#[test]
fn rand_ghsa_mirror_collapses_into_the_informational_rustsec_record() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "GHSA-cq8v-f236-94qc", &["RUSTSEC-2026-0097"]),
        informational(RAND_PURL, "RUSTSEC-2026-0097", "unsound", &[]),
    ]);

    assert_eq!(out.len(), 1, "the mirror pair is one advisory");
    let f = &out[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2026-0097");
    assert!(f.is_informational(), "the classification must survive");
    assert_eq!(f.severity_basis, SeverityBasis::Assessed);
    assert!(
        f.aliases.iter().any(|a| a == "GHSA-cq8v-f236-94qc"),
        "the collapsed-away id stays matchable by an operator exclusion: {:?}",
        f.aliases,
    );

    // The whole point: it lands on the non-enforcing lane, so nothing
    // trips a severity threshold.
    let summary = severity_summary_from_findings(&out);
    assert_eq!(summary.negligible, 1);
    assert_eq!(summary.critical, 0);
}

/// `typemap 0.3.3`: `GHSA-vfv3-9w6v-23jp` (bare) + `RUSTSEC-2019-0039`
/// (`informational: unmaintained`). Same shape as the `rand` case, and
/// here the alias link points the other way — the RustSec record names the
/// GHSA — which must group them just the same.
#[test]
fn typemap_pair_collapses_to_informational_with_the_alias_link_reversed() {
    let out = collapse_both_orders(vec![
        bare_mirror(TYPEMAP_PURL, "GHSA-vfv3-9w6v-23jp", &[]),
        informational(
            TYPEMAP_PURL,
            "RUSTSEC-2019-0039",
            "unmaintained",
            &["GHSA-vfv3-9w6v-23jp"],
        ),
    ]);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].vulnerability_id, "RUSTSEC-2019-0039");
    assert!(out[0].is_informational());
    assert_eq!(severity_summary_from_findings(&out).negligible, 1);
}

/// **The load-bearing negative.** `traitobject 0.1.1` returns three
/// records: `GHSA-pp8r-vv2j-9j5v` (bare), `RUSTSEC-2020-0027` (**CVSS
/// 9.8**, `unsound`) and `RUSTSEC-2021-0144` (`unmaintained`). Collapsing
/// must pick the **scored** member, not the informational one — a real
/// CVSS outranks a classification, so the package stays rejected. A
/// collapse that preferred the informational reading here would turn an
/// over-blocking fix into an under-blocking one (ADR 0007).
#[test]
fn traitobject_group_collapses_to_the_scored_member_and_stays_blocking() {
    let out = collapse_both_orders(vec![
        bare_mirror(
            TRAITOBJECT_PURL,
            "GHSA-pp8r-vv2j-9j5v",
            &["RUSTSEC-2020-0027"],
        ),
        scored(
            TRAITOBJECT_PURL,
            "RUSTSEC-2020-0027",
            9.8,
            SeverityThreshold::Critical,
            &["GHSA-pp8r-vv2j-9j5v"],
        ),
        informational(
            TRAITOBJECT_PURL,
            "RUSTSEC-2021-0144",
            "unmaintained",
            &["RUSTSEC-2020-0027"],
        ),
    ]);

    assert_eq!(out.len(), 1, "all three records are one advisory group");
    let f = &out[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2020-0027");
    assert_eq!(f.cvss_score, Some(9.8));
    assert_eq!(f.severity, SeverityThreshold::Critical);
    assert!(
        !f.is_informational(),
        "a scored advisory must never be demoted onto the negligible lane",
    );

    // It counts on the ENFORCED lane, which is what keeps the artifact
    // rejected.
    let summary = severity_summary_from_findings(&out);
    assert_eq!(summary.critical, 1);
    assert_eq!(summary.negligible, 0);
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

#[test]
fn a_single_record_group_is_returned_untouched() {
    let one = bare_mirror(RAND_PURL, "GHSA-solo", &["CVE-1", "CVE-2"]);
    let out = collapse_alias_groups(vec![one.clone()]);
    assert_eq!(out, vec![one], "no sibling means no rewrite at all");
}

#[test]
fn unrelated_findings_for_the_same_package_are_not_grouped() {
    let a = scored(
        RAND_PURL,
        "CVE-1000",
        7.5,
        SeverityThreshold::High,
        &["GHSA-a"],
    );
    let b = scored(
        RAND_PURL,
        "CVE-2000",
        5.0,
        SeverityThreshold::Medium,
        &["GHSA-b"],
    );
    let out = collapse_both_orders(vec![a, b]);
    assert_eq!(out.len(), 2, "two advisories stay two findings");
}

/// The same advisory affecting two different packages must NOT collapse —
/// the group key is `(purl, identifier)`, mirroring the cross-backend
/// merge key. Collapsing across packages would silently drop one package's
/// finding.
#[test]
fn the_same_advisory_on_two_packages_does_not_collapse_across_purls() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "GHSA-shared", &["RUSTSEC-2026-0097"]),
        informational(
            TYPEMAP_PURL,
            "RUSTSEC-2026-0097",
            "unsound",
            &["GHSA-shared"],
        ),
    ]);
    assert_eq!(out.len(), 2, "different packages are different findings");
}

/// Grouping is transitive: A aliases B, B aliases C, and A never mentions
/// C — all three are still one advisory.
#[test]
fn grouping_is_transitive_across_a_chain_of_mirrors() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "ID-A", &["ID-B"]),
        bare_mirror(RAND_PURL, "ID-B", &["ID-C"]),
        informational(RAND_PURL, "ID-C", "notice", &[]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].vulnerability_id, "ID-C");
}

/// Two records that name no common id but both list the same third-party
/// alias are the same advisory.
#[test]
fn records_sharing_only_a_common_alias_are_grouped() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "GHSA-x", &["CVE-SHARED"]),
        informational(RAND_PURL, "RUSTSEC-y", "unmaintained", &["CVE-SHARED"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].vulnerability_id, "RUSTSEC-y");
}

/// Advisory databases are inconsistent about the spelling of a mirror's
/// id; matching is case-insensitive, as it is in the cross-backend merge.
#[test]
fn identifier_matching_is_case_insensitive() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "ghsa-CaSe", &[]),
        informational(RAND_PURL, "RUSTSEC-z", "unsound", &["GHSA-case"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].vulnerability_id, "RUSTSEC-z");
}

/// An empty or whitespace-only alias is not an identifier — it must not
/// become a join key that merges two unrelated advisories.
#[test]
fn blank_identifiers_do_not_join_unrelated_findings() {
    let out = collapse_both_orders(vec![
        scored(
            RAND_PURL,
            "CVE-1000",
            7.5,
            SeverityThreshold::High,
            &["", "   "],
        ),
        scored(
            RAND_PURL,
            "CVE-2000",
            5.0,
            SeverityThreshold::Medium,
            &["", "\t"],
        ),
    ]);
    assert_eq!(out.len(), 2);
}

#[test]
fn an_empty_input_is_returned_empty() {
    assert!(collapse_alias_groups(Vec::new()).is_empty());
}

#[test]
fn output_preserves_first_seen_group_order() {
    let out = collapse_alias_groups(vec![
        bare_mirror(RAND_PURL, "ZZZ-first", &[]),
        bare_mirror(RAND_PURL, "AAA-second", &["AAA-mirror"]),
        bare_mirror(RAND_PURL, "AAA-mirror", &[]),
    ]);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].vulnerability_id, "ZZZ-first");
    assert_eq!(out[1].vulnerability_id, "AAA-mirror");
}

// ---------------------------------------------------------------------------
// Best-informed selection — every rank boundary
// ---------------------------------------------------------------------------

#[test]
fn scored_beats_informational() {
    let out = collapse_both_orders(vec![
        informational(RAND_PURL, "A-info", "unmaintained", &["B-scored"]),
        scored(
            RAND_PURL,
            "B-scored",
            4.0,
            SeverityThreshold::Medium,
            &["A-info"],
        ),
    ]);
    assert_eq!(out[0].vulnerability_id, "B-scored");
}

#[test]
fn informational_beats_a_label_only_reading() {
    let out = collapse_both_orders(vec![
        label_only(RAND_PURL, "A-label", SeverityThreshold::High, &["B-info"]),
        informational(RAND_PURL, "B-info", "notice", &["A-label"]),
    ]);
    assert_eq!(out[0].vulnerability_id, "B-info");
}

/// The rank boundary the three named spec tiers would have collapsed
/// together: a genuinely-read severity label with no score still outranks
/// the SUP-4 fail-closed floor, so the floor cannot win a group against a
/// real reading.
#[test]
fn a_label_only_reading_beats_the_unassessed_fail_closed_floor() {
    let out = collapse_both_orders(vec![
        bare_mirror(RAND_PURL, "A-bare", &["B-label"]),
        label_only(RAND_PURL, "B-label", SeverityThreshold::Low, &["A-bare"]),
    ]);
    assert_eq!(out[0].vulnerability_id, "B-label");
    assert_eq!(out[0].severity, SeverityThreshold::Low);
}

/// Two scored readings of one advisory: the higher score wins — the
/// fail-closed choice between two real readings.
#[test]
fn the_higher_cvss_score_wins_between_two_scored_members() {
    let out = collapse_both_orders(vec![
        scored(RAND_PURL, "A-low", 3.1, SeverityThreshold::Low, &["B-high"]),
        scored(
            RAND_PURL,
            "B-high",
            9.1,
            SeverityThreshold::Critical,
            &["A-low"],
        ),
    ]);
    assert_eq!(out[0].vulnerability_id, "B-high");
    assert_eq!(out[0].cvss_score, Some(9.1));
}

/// Same rank, no score to compare: the higher severity tier wins.
#[test]
fn the_higher_severity_tier_wins_when_neither_member_is_scored() {
    let out = collapse_both_orders(vec![
        label_only(
            RAND_PURL,
            "A-medium",
            SeverityThreshold::Medium,
            &["B-high"],
        ),
        label_only(RAND_PURL, "B-high", SeverityThreshold::High, &["A-medium"]),
    ]);
    assert_eq!(out[0].vulnerability_id, "B-high");
    assert_eq!(out[0].severity, SeverityThreshold::High);
}

/// Nothing left to distinguish the members: the lexicographically
/// smallest id is the deterministic winner, so the collapse still has
/// exactly one answer.
#[test]
fn identical_members_tie_break_on_vulnerability_id() {
    let out = collapse_both_orders(vec![
        label_only(RAND_PURL, "ZZZ-id", SeverityThreshold::High, &["AAA-id"]),
        label_only(RAND_PURL, "AAA-id", SeverityThreshold::High, &["ZZZ-id"]),
    ]);
    assert_eq!(out[0].vulnerability_id, "AAA-id");
}

/// A malformed upstream vector can lower to `NaN`. That is a parse
/// artefact, not a severity reading, so it must not rank as a score and
/// hijack the group away from the backend that read the advisory
/// correctly — the real 5.0 wins.
#[test]
fn a_nan_score_does_not_rank_as_a_reading() {
    let out = collapse_both_orders(vec![
        scored(
            RAND_PURL,
            "A-nan",
            f32::NAN,
            SeverityThreshold::Critical,
            &["B-real"],
        ),
        scored(
            RAND_PURL,
            "B-real",
            5.0,
            SeverityThreshold::Medium,
            &["A-nan"],
        ),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].vulnerability_id, "B-real",
        "a real score outranks a NaN",
    );
    assert_eq!(out[0].cvss_score, Some(5.0));
}

/// An infinite score is the same class of parse artefact as a `NaN` and
/// is treated identically.
#[test]
fn an_infinite_score_does_not_rank_as_a_reading() {
    let out = collapse_both_orders(vec![
        scored(
            RAND_PURL,
            "A-inf",
            f32::INFINITY,
            SeverityThreshold::Critical,
            &["B-info"],
        ),
        informational(RAND_PURL, "B-info", "unsound", &["A-inf"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].vulnerability_id, "B-info",
        "an unusable score falls below a recognised informational class",
    );
}

// ---------------------------------------------------------------------------
// Alias union + truncation
// ---------------------------------------------------------------------------

#[test]
fn the_union_lists_collapsed_ids_first_then_the_winners_own_aliases() {
    let out = collapse_alias_groups(vec![
        informational(RAND_PURL, "RUSTSEC-win", "unsound", &["OWN-1", "OWN-2"]),
        bare_mirror(RAND_PURL, "GHSA-b", &["OTHER-B", "RUSTSEC-win"]),
        bare_mirror(RAND_PURL, "GHSA-a", &["OTHER-A", "RUSTSEC-win"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].aliases,
        vec!["GHSA-a", "GHSA-b", "OWN-1", "OWN-2", "OTHER-A", "OTHER-B"],
        "collapsed-away primary ids first (sorted), then the winner's own \
         aliases, then the others' aliases",
    );
}

#[test]
fn the_union_never_lists_the_winners_own_id_as_an_alias() {
    let out = collapse_alias_groups(vec![
        informational(RAND_PURL, "RUSTSEC-win", "notice", &[]),
        bare_mirror(RAND_PURL, "GHSA-b", &["rustsec-win"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].aliases, vec!["GHSA-b"]);
}

#[test]
fn the_union_deduplicates_case_insensitively() {
    let out = collapse_alias_groups(vec![
        informational(RAND_PURL, "RUSTSEC-win", "notice", &["shared-alias"]),
        bare_mirror(RAND_PURL, "GHSA-b", &["SHARED-ALIAS", "RUSTSEC-win"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].aliases, vec!["GHSA-b", "shared-alias"]);
}

/// A group with more mirrors than the cap collapses with a shortened
/// alias list rather than failing — and the entries that survive
/// truncation are the collapsed-away **primary ids**, the identities that
/// would otherwise stop matching an operator exclusion.
#[test]
fn the_union_truncates_at_max_aliases_keeping_collapsed_ids() {
    let winner_aliases: Vec<String> = (0..MAX_ALIASES).map(|i| format!("OWN-{i}")).collect();
    let mut winner = informational(RAND_PURL, "RUSTSEC-win", "unsound", &[]);
    winner.aliases = winner_aliases;

    let mut input = vec![winner];
    for i in 0..3 {
        input.push(bare_mirror(
            RAND_PURL,
            &format!("GHSA-{i}"),
            &["RUSTSEC-win"],
        ));
    }

    let out = collapse_alias_groups(input);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].aliases.len(), MAX_ALIASES, "hard-capped, not failed");
    for i in 0..3 {
        assert!(
            out[0].aliases.contains(&format!("GHSA-{i}")),
            "collapsed-away ids must survive truncation: {:?}",
            out[0].aliases,
        );
    }
    // The collapsed finding still passes the domain validator.
    out[0].validate().expect("truncated alias list stays valid");
}

/// The alias union is the collapse's only mutation of the survivor —
/// every other field is the best-informed member's, verbatim.
#[test]
fn the_survivor_keeps_every_other_field_from_its_own_record() {
    let mut winner = scored(
        TRAITOBJECT_PURL,
        "RUSTSEC-2020-0027",
        9.8,
        SeverityThreshold::Critical,
        &[],
    );
    winner.title = "Unsound `Trait` object handling".into();
    winner.fixed_versions = vec!["0.2.0".into()];
    winner.source_scanner = "advisory".into();
    winner.references = vec!["https://rustsec.org/advisories/RUSTSEC-2020-0027".into()];
    winner.informational_class = Some("unsound".into());

    let out = collapse_alias_groups(vec![
        bare_mirror(
            TRAITOBJECT_PURL,
            "GHSA-pp8r-vv2j-9j5v",
            &["RUSTSEC-2020-0027"],
        ),
        winner.clone(),
    ]);

    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(f.title, winner.title);
    assert_eq!(f.fixed_versions, winner.fixed_versions);
    assert_eq!(f.source_scanner, winner.source_scanner);
    assert_eq!(f.references, winner.references);
    assert_eq!(f.informational_class, winner.informational_class);
    assert_eq!(f.severity_basis, SeverityBasis::Assessed);
    assert_eq!(f.aliases, vec!["GHSA-pp8r-vv2j-9j5v"]);
}

/// A blank alias on a collapsed-away member is not an identifier and must
/// not reach the survivor's alias list as an empty string.
#[test]
fn blank_aliases_are_dropped_from_the_union() {
    let out = collapse_alias_groups(vec![
        informational(RAND_PURL, "RUSTSEC-win", "notice", &["", "  "]),
        bare_mirror(RAND_PURL, "GHSA-b", &["RUSTSEC-win", "", "\t"]),
    ]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].aliases, vec!["GHSA-b"]);
}
