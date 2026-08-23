//! Alias-group collapsing — one advisory, one finding, even when the
//! advisory database returns it under several primary ids.
//!
//! OSV returns a RustSec advisory **and** its GitHub-reviewed GHSA mirror
//! as separate vulnerability records in the same response. The RustSec
//! copy carries the metadata (`database_specific.informational`, and a
//! CVSS where one exists); the GHSA mirror frequently carries neither a
//! severity nor an informational marker. Lowered one-record-per-`Finding`,
//! the bare mirror falls back to the SUP-4 fail-closed `Critical` and then
//! shadows its better-informed sibling — and the cross-backend merge
//! cannot rescue it, because that merge reconciles findings for the *same*
//! `(purl, vulnerability_id)` and these two records have **different
//! ids**. The artifact is rejected on a verdict no backend reached, and
//! `rejected` is terminal for serving.
//!
//! [`collapse_alias_groups`] closes that gap: mutually-aliased findings
//! for one package are one advisory, and only the best-informed member
//! survives. The failure direction it corrects is over-blocking; it never
//! makes the gate more permissive about a *scored* advisory, because a
//! real CVSS outranks everything else in the group (ADR 0007).
//!
//! Shared by both OSV adapters so the grouping rule exists once. See
//! ADR 0059.

use std::collections::HashMap;

use super::finding::{severity_tier, Finding, SeverityBasis, MAX_ALIASES};

/// How much a finding actually tells us about its advisory. Higher is
/// better informed; the highest-ranked member of an alias group is the
/// one whose reading survives the collapse.
///
/// The three named tiers are the advisory-database facts: a **real CVSS
/// score**, a **recognised informational classification**, and a **bare
/// record** with neither. The bare tier is split by the
/// [`SeverityBasis`] signal, because "the backend read a severity label
/// but no score" and "the backend could not read a severity at all and
/// fell back to the `Critical` floor" are not the same evidence — and
/// collapsing them would let the fail-closed floor win a group against a
/// genuine label-derived reading, which is the exact shadowing this
/// module exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InformationRank {
    /// `SeverityBasis::Unassessed`, no score, no recognised class — the
    /// SUP-4 fail-closed `Critical` floor. The bare GHSA mirror.
    Unassessed = 0,
    /// A severity the backend genuinely read (e.g. a
    /// `database_specific.severity` label) but which carries no numeric
    /// score and no informational classification.
    Assessed = 1,
    /// A recognised informational classification (`unmaintained` /
    /// `unsound` / `notice`). Carries no CVSS by design.
    Informational = 2,
    /// A real CVSS score. The most informative reading there is, and the
    /// one that keeps a genuinely-vulnerable package blocked.
    Scored = 3,
}

/// The finding's CVSS score, if it is a *usable* number.
///
/// A malformed upstream vector can lower to `NaN` or an infinity. Such a
/// value is not a severity reading — it is a parse artefact — so it is
/// treated as no score at all rather than being ranked against real ones.
/// Ranking it as a score would let a malformed vector hijack its whole
/// alias group away from a backend that read the advisory correctly, which
/// is the shadowing this module exists to prevent.
fn usable_score(f: &Finding) -> Option<f32> {
    f.cvss_score.filter(|s| s.is_finite())
}

fn information_rank(f: &Finding) -> InformationRank {
    if usable_score(f).is_some() {
        InformationRank::Scored
    } else if f.is_informational() {
        InformationRank::Informational
    } else if matches!(f.severity_basis, SeverityBasis::Assessed) {
        InformationRank::Assessed
    } else {
        InformationRank::Unassessed
    }
}

/// Total order over the members of one alias group, best first. Every
/// component is derived from the finding's own content, never from its
/// position in the input, so the winner does not depend on the order the
/// backends contributed their records in.
///
/// 1. [`InformationRank`], descending.
/// 2. `cvss_score`, descending — two scored members mean two readings of
///    one advisory, and the higher one is the fail-closed choice. Only
///    *usable* scores compare (see [`usable_score`]); compared with
///    `f32::total_cmp`, which is a total order, so the sort cannot be
///    poisoned by an unexpected value.
/// 3. Severity tier, ascending (`Critical` first) — same posture, for
///    members that have no score to compare.
/// 4. `vulnerability_id`, ascending — the final tie-break, so a group of
///    otherwise-indistinguishable members still has exactly one winner.
fn is_better_member(candidate: &Finding, incumbent: &Finding) -> bool {
    let by_rank = information_rank(candidate).cmp(&information_rank(incumbent));
    if by_rank.is_ne() {
        return by_rank.is_gt();
    }
    let by_score = usable_score(candidate)
        .unwrap_or(f32::NEG_INFINITY)
        .total_cmp(&usable_score(incumbent).unwrap_or(f32::NEG_INFINITY));
    if by_score.is_ne() {
        return by_score.is_gt();
    }
    let by_tier = severity_tier(candidate.severity).cmp(&severity_tier(incumbent.severity));
    if by_tier.is_ne() {
        return by_tier.is_lt();
    }
    candidate.vulnerability_id < incumbent.vulnerability_id
}

/// Union-find over the identifier keys seen across a finding set, with
/// one node per finding. Groups are tiny (an advisory rarely has more
/// than a handful of mirrors), so the flat `Vec` parent array with path
/// compression is all this needs.
struct DisjointSet {
    parent: Vec<usize>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            // Path compression: point every node on the walk at its
            // grandparent, halving the path as we go.
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[rb] = ra;
        }
    }
}

/// Identifier-matching key. Vulnerability ids match case-insensitively
/// (advisory databases are inconsistent about the spelling of a mirror's
/// id); PURLs match case-sensitively. Both conventions mirror the
/// cross-backend `merge_findings` key so the two steps agree on what
/// "the same advisory for the same package" means.
fn alias_key(purl: &str, id: &str) -> (String, String) {
    (purl.to_string(), id.trim().to_ascii_lowercase())
}

/// Collapse mutually-aliased findings into one finding per advisory.
///
/// Two findings belong to the same group when they share a package
/// (`purl`, case-sensitive) **and** any identifier — one's
/// `vulnerability_id` appearing in the other's `aliases`, or both listing
/// a common alias. Grouping is transitive, so a chain of mirrors collapses
/// to a single advisory.
///
/// The surviving finding is the group's **best-informed** member (see
/// [`InformationRank`]): a real CVSS beats a recognised informational
/// class, which beats a genuinely-read severity with no score, which beats
/// the SUP-4 fail-closed `Critical` floor. Its `SeverityBasis` therefore
/// rides along, so the cross-backend merge and the ADR 0040 negligible
/// lane both see the reading the advisory database actually published.
///
/// The collapsed-away members' identifiers are unioned onto the
/// survivor's `aliases` so an operator exclusion keyed by any member id
/// still clears the advisory. Union order, which is also the truncation
/// order when the union exceeds [`MAX_ALIASES`]:
///
/// 1. the other members' **primary ids** — the identities the collapse
///    would otherwise make unmatchable, so they are never the ones
///    dropped;
/// 2. the survivor's own aliases, in their original order;
/// 3. the other members' aliases, by owning member id.
///
/// Entries are deduplicated case-insensitively, the survivor's own id is
/// never listed as its own alias, and the list is hard-truncated at
/// [`MAX_ALIASES`] — a group with more mirrors than the cap collapses
/// with a shortened alias list rather than failing.
///
/// A group of one is returned **byte-identical** to its input: a finding
/// with no aliased sibling is not rewritten, reordered, or re-derived.
/// Output preserves the order of each group's first-seen member, so a
/// fixture's finding order is stable.
pub fn collapse_alias_groups(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() < 2 {
        return findings;
    }

    // Claim every identifier for the first finding that mentions it; a
    // later finding mentioning the same identifier is unioned with the
    // claimant. One pass builds the whole transitive grouping.
    let mut dsu = DisjointSet::new(findings.len());
    let mut claims: HashMap<(String, String), usize> = HashMap::new();
    for (idx, f) in findings.iter().enumerate() {
        let ids = std::iter::once(&f.vulnerability_id).chain(f.aliases.iter());
        for id in ids {
            if id.trim().is_empty() {
                continue;
            }
            match claims.entry(alias_key(&f.purl, id)) {
                std::collections::hash_map::Entry::Occupied(e) => {
                    let claimant = *e.get();
                    dsu.union(claimant, idx);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(idx);
                }
            }
        }
    }

    // Bucket the findings by group root, preserving first-seen order for
    // both the groups and the members within a group.
    let mut group_order: Vec<usize> = Vec::new();
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for idx in 0..findings.len() {
        let root = dsu.find(idx);
        groups.entry(root).or_insert_with(|| {
            group_order.push(root);
            Vec::new()
        });
        groups
            .get_mut(&root)
            .expect("group inserted immediately above")
            .push(idx);
    }

    // `findings` is consumed member-by-member: each index is taken out
    // exactly once, so the winner can be moved rather than cloned.
    let mut slots: Vec<Option<Finding>> = findings.into_iter().map(Some).collect();
    let mut out: Vec<Finding> = Vec::with_capacity(group_order.len());
    for root in group_order {
        let members = groups.remove(&root).expect("root came from the group map");
        out.push(collapse_one_group(&mut slots, &members));
    }
    out
}

/// Reduce one alias group to its surviving finding. A single-member group
/// is returned untouched.
fn collapse_one_group(slots: &mut [Option<Finding>], members: &[usize]) -> Finding {
    let take = |slots: &mut [Option<Finding>], i: usize| {
        slots[i].take().expect("each member is taken exactly once")
    };
    if members.len() == 1 {
        return take(slots, members[0]);
    }

    let mut winner_pos = 0usize;
    for (pos, &idx) in members.iter().enumerate().skip(1) {
        let incumbent = slots[members[winner_pos]]
            .as_ref()
            .expect("winner slot is still occupied");
        let candidate = slots[idx].as_ref().expect("member slot is still occupied");
        if is_better_member(candidate, incumbent) {
            winner_pos = pos;
        }
    }

    // Collapsed-away members, ordered by primary id so the alias union is
    // independent of contribution order.
    let mut others: Vec<Finding> = members
        .iter()
        .enumerate()
        .filter(|(pos, _)| *pos != winner_pos)
        .map(|(_, &idx)| take(slots, idx))
        .collect();
    others.sort_by(|a, b| a.vulnerability_id.cmp(&b.vulnerability_id));

    let mut winner = take(slots, members[winner_pos]);
    winner.aliases = union_aliases(&winner, &others);
    winner
}

/// Build the survivor's alias list from the whole group. See
/// [`collapse_alias_groups`] for the ordering and truncation contract.
fn union_aliases(winner: &Finding, others: &[Finding]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<String> = vec![winner.vulnerability_id.trim().to_ascii_lowercase()];
    let push = |candidate: &str, out: &mut Vec<String>, seen: &mut Vec<String>| {
        let trimmed = candidate.trim();
        if trimmed.is_empty() || out.len() >= MAX_ALIASES {
            return;
        }
        let normalised = trimmed.to_ascii_lowercase();
        if seen.contains(&normalised) {
            return;
        }
        seen.push(normalised);
        out.push(trimmed.to_string());
    };

    for o in others {
        push(&o.vulnerability_id, &mut out, &mut seen);
    }
    for a in &winner.aliases {
        push(a, &mut out, &mut seen);
    }
    for o in others {
        for a in &o.aliases {
            push(a, &mut out, &mut seen);
        }
    }
    out
}

#[cfg(test)]
#[path = "alias_group_tests.rs"]
mod tests;
