# 112 — Scope-aware svc-token authority: `--repository` on issue-svc-token, threaded from the chart

Issue: #156. One reviewable unit: CLI + token-cap scoping + chart threading +
values-comment correction.

## What

`issue-svc-token --require-authority` currently preflights every declared
permission against **global** grants only
(`check_require_authority` → `authorize_granted(&principal, p, None)`,
`crates/hort-server/src/cli/admin.rs`), while runtime authorization checks
the actual repository scope. A repo-scoped grant passes runtime but fails the
preflight, and the preflight's error text steers operators toward global
over-granting — the opposite of what narrow identities (uat-smoke) exist
for. The #155 bootstrap Job hardcodes the flag, making repo-scoped bootstrap
identities impossible.

## Change

1. **CLI**: `issue-svc-token` gains optional `--repository <name>`.
   - Resolves the name to a repository id at mint time; unknown name → loud
     error naming it (fail before any DB write).
   - **Preflight** (when `--require-authority`): each declared permission is
     checked at that scope — same evaluator semantics as runtime
     (`authorize_granted(…, Some(repo_id))`), so a global grant ALSO
     satisfies a repo-scoped check (global ⊇ repo, exactly as at runtime).
     Without `--repository`: today's global-only check, unchanged.
   - The failure message names the scope it checked (`permission: read
     (repository: maven-proxy)`) and shows the matching grant YAML shape for
     THAT scope — never unconditionally the global form.
2. **Token capability scoping (confirmed by the human, 2026-08-14)**: with
   `--repository`, the minted token's cap carries
   `repository_ids: [<repo_id>]` instead of `null` — the token itself is
   narrowed, both layers (cap ∩ grants) repo-scoped. Without the flag:
   `null` (today's behavior, byte-compatible).
3. **Chart threading**: optional per-entry `repository` in
   `scheduledTasks.svcTokens`, rendered as `--repository <value>` on that
   entry's mint invocation; `values.schema.json` gains the field
   (`additionalProperties: false` intact).
4. **Values-comment correction** (in the same MR): the !391 comment saying
   every listed permission needs a **global** grant is superseded — a
   repo-scoped identity declares `repository:` and needs grants at that
   scope; global identities unchanged. State that the preflight now checks
   the declared scope.

## Out of scope

- Multiple `--repository` values / multi-repo caps (single optional value
  only; a list is a future need with its own design).
- Any change to runtime authorization or grant semantics.
- The uat-smoke grants themselves (cluster-side; already repo-scoped —
  they become mintable-with-preflight once this ships).

## Tests

- CLI/preflight (in `admin.rs`'s existing test conventions): repo-scoped
  grant + matching `--repository` → passes; wrong repository → fails naming
  the checked scope; global grant + `--repository` → passes (global ⊇ repo);
  repo-scoped grant + NO `--repository` → fails exactly as today (global
  check, regression pin); unknown repository name → loud error, no token
  row created.
- Cap scoping: minted token row/cap carries `repository_ids: [id]` with the
  flag, `null` without (regression pin). Wherever cap construction lives
  (hort-app use case), its crate's 100%-tier coverage applies.
- Chart: helm-template fixtures — entry with `repository:` renders
  `--repository` on exactly that entry; entries without render none;
  schema rejects a typo'd key. Golden checks stay green (bootstrap Job IS
  golden-pinned for the default single-entry render — the default entry has
  no `repository:`, so the golden must not change; if the loop refactor
  shifts bytes anyway, stop and report per the golden discipline).

## Acceptance

- A repo-scoped identity (uat-smoke shape: read+prefetch grants on one
  repo) mints WITH `--require-authority --repository maven-proxy`, and its
  token's `whoami` shows the cap repo-scoped.
- Global identities and flagless mints byte-compatible with today.
- Default chart render unchanged (golden-pinned).
