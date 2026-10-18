//! A comment block must not decide whether an operator's envelope parses.
//!
//! # Why this exists
//!
//! The deserialiser this crate parses with buffers comment events while it
//! resolves an ambiguous collection entry, and at its stock options a
//! budget refuses the 33rd — so a run of 33 or more comment lines
//! *immediately before a collection's first entry* failed the parse, while
//! the same run **between** two entries had no limit at all. The position
//! dependence is what makes it unreasonable to live with: the same comment
//! block is fine two lines lower, and the message
//! (`too many consecutive comments before resolving collection entry`)
//! suggests no remedy. `hort-config` closes it with `emit_comments: false`
//! in its one `Options` definition — the derivation is in `src/yaml.rs`.
//!
//! So the property pinned here is not a number: **how long an operator's
//! comment run is, and where in the document it sits, may not change
//! whether the envelope parses.** The ladder straddles the budget that
//! used to exist (31 and 32 passed, 33 did not) and goes well past it, in
//! every position where a comment can precede or separate a collection
//! entry. Drop `emit_comments: false` from `gitops_options()` and the
//! leading-position rows go red.
//!
//! Measured through `parse_repository` — the production entry point, the
//! parse an operator's boot performs — rather than a parser built here,
//! because a parser built here would carry its own options and so would
//! stop being about this crate's decision.
//!
//! No database, no network, no filesystem: in-memory parses only.

use std::path::Path;

use hort_config::parse_repository;

/// One comment line per `lines`, each distinct, so nothing downstream can
/// collapse the run into fewer events than it has lines.
fn comment_run(lines: usize, indent: &str) -> String {
    (0..lines)
        .map(|i| {
            format!("{indent}# operator note {i}: why this repository is configured this way\n")
        })
        .collect()
}

/// Where a comment run sits relative to a collection's entries: a label, the
/// indent its lines take, and a complete `ArtifactRepository` envelope with
/// `{run}` marking the position. Every field `RepositorySpec` requires is
/// present in each template, so a rejection is always about the run.
///
/// The first row is the position that used to fail and the second is the one
/// that never did — the two the measurement contrasted. The third is the
/// same leading position one level down, before a *sequence's* first entry,
/// which the same budget refused: a future `Options` change that brings a
/// budget back in any of the three goes red here.
const POSITIONS: [(&str, &str, &str); 3] = [
    (
        "before a mapping's first entry",
        "  ",
        "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pinned-repo
spec:
{run}  name: Pinned
  format: npm
  type: hosted
  isPublic: false
  replicationPriority: on_demand
",
    ),
    (
        "between two mapping entries",
        "  ",
        "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pinned-repo
spec:
  name: Pinned
{run}  format: npm
  type: hosted
  isPublic: false
  replicationPriority: on_demand
",
    ),
    (
        "before a sequence's first entry",
        "    ",
        "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pinned-repo
spec:
  name: Pinned
  format: npm
  type: hosted
  isPublic: false
  replicationPriority: on_demand
  curationRules:
{run}    - pinned-rule
",
    ),
];

/// Run lengths: the two that passed under the old budget, the one that did
/// not, and two comfortably past it.
const RUN_LENGTHS: [usize; 5] = [31, 32, 33, 64, 200];

#[test]
fn a_comment_run_never_decides_whether_an_envelope_parses() {
    for (position, indent, template) in POSITIONS {
        for lines in RUN_LENGTHS {
            let doc = template.replace("{run}", &comment_run(lines, indent));

            // Counter-assertion: a template that silently dropped the
            // placeholder would make every row below pass without a comment
            // in the document at all.
            assert_eq!(
                doc.matches("# operator note ").count(),
                lines,
                "{lines} comment lines {position}: the document under test must actually \
                 carry the run"
            );

            let parsed = parse_repository(Path::new("pinned.yaml"), doc.as_bytes());
            let envelope = parsed.unwrap_or_else(|e| {
                panic!(
                    "a run of {lines} comment lines {position} must parse, and did not: {e}\n\
                     the parse's options are `hort_config::yaml::gitops_options`"
                )
            });
            assert_eq!(
                envelope.spec.name, "Pinned",
                "{lines} comment lines {position}: the envelope must come back whole, not \
                 merely without an error"
            );
        }
    }
}
