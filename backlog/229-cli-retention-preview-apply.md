# 229 — The cleanup happens at the CLI: show the proposal, take the confirmation, execute

**Issue:** #289 · **Branch:** `agent/289-cli-retention-preview-apply`
**Depends on:** #283 (merged) — it provides the dry run this renders.
**Governing decisions:** ADR 0038 §4 (zero standing destructive privilege —
untouched here) · ADR 0046 D3 · ADR 0054 (rows are not bytes) · the concept's D2
(one mechanism for preview and proposal).

## Why

`hort-cli admin task invoke` can start a task. For a cleanup over 142 GB that is
not enough: before executing, the operator needs a readable answer to "what
exactly happens if I do this now", and afterwards the certainty that what ran is
what they saw.

**This path needs no authorization change.** A fresh, IdP-backed admin
`CliSession` already carries the destructive claim — that is what it is for. No
standing destructive authority, no new token in a secret, no exception. Since
#283, the preview needs no destructive claim at all; only the execution does.

## What #283 left to build on

`retention-evaluate` takes `{"mode": "dry_run"}` and writes into its job's
`result_summary`:

```json
{
  "mode": "dry_run",
  "coverage": "complete" | "partial",
  "policies": 3,
  "evaluated": 1200, "expired": 0, "already_expired": 0,
  "skipped_protected": 0, "skipped_stale_scan": 0, "errors": 0,
  "preview": {
    "rows": 812,
    "distinct_contents": 634,
    "freed_bytes": { "status": "exact", "bytes": 12345 },
    "groups": [ { "policy_id": "…", "policy_name": "…", "repository_id": "…",
                  "rows": 300, "distinct_contents": 240 } ],
    "sample": [ { "artifact_id": "…", "policy_id": "…", "repository_id": "…",
                  "name": "…", "version": "…", "age_seconds": 98765 } ]
  }
}
```

`freed_bytes.status` is `exact` or `omitted` (with a `reason`). There is no
estimate anywhere, and this unit must not introduce one.

## The one server-side change this unit needs

**The preview identifies repositories by UUID, and an operator cannot act on a
UUID.** `groups[]` and `sample[]` carry `repository_id` only
(`crates/hort-app/src/use_cases/retention_use_case.rs:167-176`,
`EvaluationMatch`). Rendering that would reproduce at the operator surface
exactly the defect #282 removed from the config surface.

Carry the repository's **key** through instead — `repositories.key`, because
that is the identifier `metadata.name` resolves against
(`apply_config_use_case/virtual_members.rs:63-75`, `find_by_key`), so what the
preview prints is what the operator writes in a policy. The candidate query
already joins `repositories r ON r.id = a.repository_id` for `r.format::text`;
one more column on the same join, then through the candidate row,
`EvaluationMatch`, and into `groups[]`/`sample[]` beside the id. Do not resolve
it client-side with N lookups.

## Scope

A command group `hort-cli admin retention` beside the existing domain-shaped
groups (`quarantine`, `rescan`, `rbac`) — not a raw task call.

1. **`preview`** — invokes the dry run, waits for the job to reach a terminal
   state, and renders the result. Per policy and repository: rows, **distinct
   contents**, and the bytes that would actually be freed — or the explicit
   omission with its reason. Never an estimate.

2. **Rows and bytes must not be confusable.** Name both separately and say why
   they diverge (CAS-shared content, ADR 0054). "51 535 artifacts" is not a
   storage statement, and a reader skimming the output must not be able to take
   it for one.

3. **Partial coverage belongs in the header, not a footnote.** When
   `coverage` is `partial` the operator is looking at a truncated count; that has
   to be the first thing they read, not something they find.

4. **The sample**, capped, with name, version and age, so the selection can be
   sanity-checked instead of a total believed.

5. **`apply`** — executes, but not blind:
   - `--from-preview <task_job_id>` compares against that earlier preview (read
     its `result_summary` back through the same admin-tasks surface). `apply`
     runs a **fresh** preview immediately before executing and shows the
     difference to the one named. If they differ, the operator must confirm
     again — the difference is the point, not a warning.
   - Without `--from-preview`, `apply` runs its own preview and presents *that*
     as the thing being confirmed. Do not invent a delta against nothing.
   - Without `--yes` the confirmation is interactive; with `--yes` the delta is
     still rendered and logged. `--yes` skips the prompt, never the comparison.

6. **`--output json`** like the other admin commands, so the action is scriptable
   and can be kept as a record.

7. **Waiting is bounded and honest.** Poll the job the way `admin task get`
   already reads it. On timeout, print the `task_job_id` and say plainly that
   the job is still running and how to read it later — never report a result the
   CLI did not see, and never silently give up.

## Acceptance

- `preview` shows, per policy and repository, rows, distinct contents and freed
  bytes or their explicit omission; partial coverage is visible without looking
  for it.
- Repositories are identified by the key an operator writes in a policy, in both
  the grouped output and the sample. A test pins that no bare UUID stands in for
  a repository in the rendered output.
- `apply` executes only after confirmation, and shows the difference to the named
  preview first; a stale preview cannot lead to an unnoticed execution. A test
  covers the differing case and asserts that confirmation is requested again.
- `--yes` suppresses the prompt and still emits the delta.
- No estimated byte figure is ever presented as measured — including when the
  preview reports `omitted`, where the output says so rather than showing a
  blank or a zero.
- Both commands work with a fresh admin `CliSession` and require no new
  authority. `preview` works without the destructive claim; `apply` does not.
- A run whose job does not finish inside the wait window prints the job id and
  says the job is still running.
- `--output json` carries the same information machine-readably, including the
  omission status and the coverage flag.
- Gate green; no issue, MR or backlog numbers in code comments.

## Explicitly not in this item

No unattended execution, no machine identity, no change to claims or permissions
(#285 stays deferred), no durable proposal/confirmation persistence (#2). No
change to the dry run's own semantics beyond carrying the repository key.
