# 253 — "nothing changed" compares totals, not the artifacts

**Issue:** #326 · **Branch:** `agent/326-proposal-identity`
**Governing decisions:** ADR 0028 (destructive-task idempotency) · the
dry-run/confirm posture established by the retention CLI work.

## Why

`render::diff` (`crates/hort-cli/src/admin/retention/render.rs:396`) compares
two previews by **aggregates only**: per `(policy, repository)` group it has
`rows` and `distinct_contents`, plus the run-level totals and coverage. It
prints `NOTHING CHANGED SINCE THE PREVIEW YOU NAMED` (`:465`) when those
match, and `apply.rs` uses `PreviewDelta::changed` (`:176`) to decide whether
to demand the separate "the proposal changed" confirmation (`:184`).

**The identities are not in the data.** `PreviewGroup`
(`crates/hort-cli/src/admin/retention/dto.rs:168-184`) carries
`policy_id`, `policy_name`, `repository_id`, `repository_key`, `rows`,
`distinct_contents` — and nothing that says *which* artifacts. There is a
`sample: Vec<PreviewSampleRow>` but it is capped by a server-side
`sample_limit` and may be empty.

So the CLI cannot detect an identity change even in principle. This is a
server-side gap, not a rendering bug.

**Failure scenario.** The baseline preview proposes artifact A. Before the
apply, A stops matching and an equally sized B in the same policy and
repository starts matching. Both previews show one row, one distinct content,
the same byte total. The CLI reports nothing changed and **skips the
confirmation** — while the apply now destroys B instead of A. A capped or
disabled sample need not reveal B.

The confirmation is the last place a human sees what disappears. It fails
exactly when the target changed but the totals happened to match — and among
artifacts of the same kind, matching totals is not a rare coincidence.

## What has to hold

The comparison must decide on **identity**, not on totals. The preview
therefore has to carry something that identifies the proposed *set*, bounded
in size: a digest over the canonically ordered artifact identities is the
obvious candidate — exact, cheap to compute during the walk the preview
already does, and O(1) on the wire. Whether it is also per group (so the CLI
can say *which* group moved) is a design call worth making deliberately.

Two constraints that are easy to miss:

- **Canonical order.** Two runs proposing the same set in a different order
  must produce the same digest, or the confirmation fires on noise and is
  trained away.
- **Partial coverage now means a window.** Since the evaluation sweep persists
  its keyset position, two runs can legitimately examine **different windows**
  of the candidate set. A digest comparison across two `partial` runs compares
  windows, not proposals. The comparison has to say what it is comparing
  rather than report a spurious change — this interaction is new and is not
  handled anywhere today.

## Acceptance

- The comparison detects an equal-sized substitution within one
  `(policy, repository)` group, and demands the confirmation.
- `NOTHING CHANGED` means the same artifacts, not the same totals.
- A comparison involving partial coverage states what it compared.
- A test for the substitution case specifically.
- Gate green.
