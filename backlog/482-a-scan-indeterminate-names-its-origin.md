# 482 — a `scan_indeterminate` names which of four origins produced it

**Issue:** #461 · **Branch:** `agent/461-cause-provenance`.

Specified after a peer review that reversed the issue's first framing. Read the
issue description before this file: two claims that framing rested on are
false, and this unit must not reintroduce either.

## What is wrong

`NotAnalysable::NoAnalyzerMatched` is reached from four distinct places, and
all four collapse to the one value before anything durable is written. An
operator reading a held artifact sees `no_analyzer_matched` and cannot tell
which of four different next steps applies.

| # | origin | site |
|---|---|---|
| 1 | effective policy pairing names a backend that cannot analyse the format | `crates/hort-app/src/use_cases/scan_orchestration.rs:826-865` |
| 2 | `Rootfs` with skipped link entries — the walked tree is not the archive | `crates/hort-adapters-scanner-trivy/src/lib.rs:703-737` |
| 3 | `Fs` with an empty report, regardless of links | `crates/hort-adapters-scanner-trivy/src/lib.rs:740-756` |
| 4 | assembled composition with an empty abstention set | `crates/hort-app/src/use_cases/composite_scan.rs:557-570` |

Origin 1 is **not** the ordinary operator path: an effectively inert
backend/format pairing is already rejected at apply time
(`crates/hort-app/src/lint/static_validate.rs:1360-1470`, ADR 0015). The
runtime arm guards stale or bypassed configuration. Do not write a message that
tells an operator to fix a policy the linter would not have accepted.

## What is already right, and must stay

- **The reason is not lost outside logs.** The orchestrator builds a
  `backend=reason` string (`scan_orchestration.rs:1282-1295`), hands it to
  `record_scan_indeterminate` (`:1569-1571`), and it reaches the
  `ScanIndeterminate` event's `reason` field
  (`crates/hort-domain/src/events/artifact_events.rs:1122-1139` via
  `crates/hort-app/src/use_cases/quarantine_use_case.rs:2605-2699`) and the job
  summary (`crates/hort-app/src/task_handlers/scan.rs:246-258`,
  `crates/hort-adapters-postgres/src/jobs_repository.rs:1181-1192`). What is
  missing is the origin *within* the value, so extend this boundary rather than
  building a second one beside it.
- **The link skip.** No symlink or hardlink entry is ever materialised
  (`crates/hort-adapters-scanner-trivy/src/extract.rs:477`, rationale at
  `:55-64`). That is workspace containment and it is not this unit's to trade.
  The analyzers' path-keyed selection missing a link-only package path is the
  consequence; naming it correctly is the work.
- **The gate table.** `NotAnalysable::gates_release`
  (`crates/hort-domain/src/ports/scanner.rs:596-603`) answers
  `!kind.is_composition_constituent()` for `UnsupportedContainer` and
  `NoAnalyzerMatched`, and `OciBlob` is a constituent
  (`crates/hort-domain/src/types/artifact_kind.rs:120-130`). ADR 0064 D2 put
  the filesystem verdict on the composition, so an abstention about an OCI
  constituent must stay non-gating. **A diagnostic label must not become a
  gate.**

## What to build

A durable, stable cause that distinguishes the four origins, carried on the
boundary that already carries the reason. The form is this unit's to choose —
a typed reason, or an explicitly versioned cause field — under two
constraints:

1. If a new domain variant is introduced, it reaches **every** exhaustive fold
   and every stable identifier, not only the adapter's log line. The known
   consumers are `composite_scan.rs:557-570` and
   `crates/hort-app/src/use_cases/manifest_deliverability.rs:206-234`; census
   the rest rather than trusting this list.
2. The `ScanIndeterminate` event and the quarantine-status projection stay
   coherent with each other. An event that names an origin the projection
   cannot represent is a trail nobody can query.

## Acceptance

- Each of the four origins is distinguishable **after the worker logs are
  gone**, through a query against the event trail or the job summary. A test
  that reads the adapter's log does not satisfy this.
- A table test pins the kind-by-reason gate answers: `UnsupportedContainer` and
  `NoAnalyzerMatched` non-gating on a composition constituent and gating
  otherwise; `UnusableArchive` and `IncompleteComposition` always gating; a
  complete `Rootfs` with zero skipped links `NotApplicable` and non-gating.
- A test asserts no link or hardlink entry is materialised, so the containment
  property survives this change.
- `cargo test --workspace` green; the new cause's identifiers are stable
  strings, asserted as such, because logs and metric labels consume them.

## Not in scope

The zstd decoder (a separate capability question with its own threat model —
it does not repair a hold, because the OCI case does not gate), the PyPI
accepted-but-unscanned container question, the read-path verdict fold on
`Artifact::is_downloadable` (#459), and the shape of the OCI refusal (#459,
unit 467, resolved as no-change).

## Governing decisions

ADR 0007, ADR 0064 D2, ADR 0015, ADR 0002, ADR 0062, ADR 0065.
