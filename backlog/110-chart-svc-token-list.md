# 110 — Bootstrap svc-token identities as a chart values list

Issue: #155. One reviewable unit: chart templates + values + helm-template
tests. No Rust change.

## What

Replace the hardwired single-identity svc-token bootstrap with a values-driven
list, so any environment can declare additional bootstrap identities (first
consumer: the `uat-smoke` staging smoke account) and have them minted by the
in-cluster Job on the next deploy — no manual cluster access, which no
reachable actor has.

## Current shape (all in `deploy/helm/hort-server/`)

- `templates/svc-token-bootstrap-job.yaml`: post-install/post-upgrade hook
  Job, gated on `scheduledTasks.adminTasksEnabled`. Two-container design:
  init container mints via
  `hort-server admin issue-svc-token --output=file:` onto a Memory-medium
  emptyDir; main container (`scheduledTasks.svcTokenKubectlImage`) applies
  the Secret idempotently (`--dry-run=client -o yaml | kubectl apply -f -`).
  Identity (`cronjob-tasks`), permission (`admin_task_invoke`) and Secret
  name (`<fullname>-svc-token`) are hardwired.
- `templates/svc-bootstrap-rbac.yaml`: Role with `get`/`patch`/`update`
  scoped by `resourceNames` to the one Secret, plus an unscoped `create`
  rule (k8s cannot resourceName-scope `create` — keep the comment explaining
  that).

## Change

1. **Values**:

   ```yaml
   scheduledTasks:
     svcTokens:
       - name: cronjob-tasks
         permissions: [admin_task_invoke]
         secretName: ""   # empty → <fullname>-svc-token (backward-compatible default)
   ```

   Default values ship exactly this single entry — rendered output for an
   untouched install must be byte-equivalent to today's (helm-template test
   pins this). The values comment must state BOTH load-bearing facts:
   - `secretName` is an RBAC anchor — consumers' `resourceNames` rules bind
     to it; renaming silently locks them out.
   - every listed permission must be backed by a live **global**
     `PermissionGrant` (`repository:`-less) for that identity —
     `issue-svc-token`'s preflight rejects repo-scoped backing
     (`admin.rs`: global-scope check), and the Job then fails the upgrade.
2. **Job template**: iterate `scheduledTasks.svcTokens` — mint every
   identity (each with ALL its declared `--permission` flags — effective
   authority is cap ∩ grants, a partial declaration strands sibling grants)
   and create/update every Secret. One Job with a loop or one Job per
   identity is a coding judgment; keep the Memory-medium emptyDir and the
   idempotent-apply pattern either way. Per-identity idempotence keeps
   today's semantics (existing token row + Secret → no rotation).
3. **RBAC template**: the `get`/`patch`/`update` rule's `resourceNames`
   enumerates every configured secretName (resolved through the same
   default rule as the Job).
4. **Fail loud, deliberately**: an identity whose permissions lack global
   backing grants fails its mint, the hook Job exits non-zero, the upgrade
   fails visibly. This is apply-time rejection of a misconfigured values
   entry — the alternative (log-and-continue) recreates the
   accepted-but-inert anti-pattern. Flux remediation on a failed upgrade is
   the intended alarm, not a hazard to engineer around. Document this in
   the values comment.
5. **Rotation is per entry** (operator review, 2026-08-14): the global
   `rotateSvcToken` switch is unambiguous only while there is exactly one
   token; with a list it would force rotating every identity to recover
   one lost secret, breaking every consumer that cached an unaffected
   token. Each list entry gains `rotate: false` (default). The existing
   global switch stays honored for backward compatibility as "rotate every
   entry", with a values comment steering operators to the per-entry flag;
   per-entry `rotate: true` and the global switch OR together.
6. **Explicit per-identity state machine** (replaces today's two special
   cases; document it in the values comment or template header):
   - DB row ∧ Secret → skip (no rotation) — today's idempotence;
   - no row ∧ no Secret → mint + create — fresh install;
   - no row ∧ Secret exists → mint + overwrite. Expected routine on THIS
     staging (DB wipe leaves a Secret pointing at a dead identity);
     correct and documented, not accidental;
   - row ∧ no Secret → plaintext is unrecoverable: WITHOUT `rotate: true`
     on that entry the Job fails loud naming the entry and the fix
     (one-shot `rotate: true`); with it, rotate + create. Never silently
     skip this state — a consumer expecting the Secret would fail far
     from the cause.
7. **Removing a list entry is documented-inert, never silent** (operator
   review): dropping an identity from the list leaves a live token row and
   an orphaned Secret — a valid credential with no owner in configuration.
   Automatic revocation (diffing desired vs. existing identities, deleting
   foreign-named Secrets) is out of scope for this item; instead the values
   comment states plainly that removal does NOT revoke, and names the
   manual revocation path. Implementer: verify what revocation the admin
   CLI actually offers (e.g. a rotate-and-discard or a token-row deletion)
   and name that concrete path — stop and report if none exists, since
   then a follow-up issue is needed rather than a comment pointing nowhere.

## Out of scope

- Repo-scoped mint support (`issue-svc-token --repository`) — the mint
  preflight's global-only rule is a standing decision; changing it is its
  own issue if ever needed.
- The `uat-smoke` grants themselves (cluster-side, clusters/platform): they
  are currently **repo-scoped and therefore cannot back a mint** — flagged
  on #154/#155; the operator converts them to global before or with the
  first deploy that lists `uat-smoke`.
- Any change to `issue-svc-token` itself.

## Tests

- `quality:helm-template-test` additions:
  - default values → rendered Job + RBAC byte-equivalent to today (single
    identity, `<fullname>-svc-token`);
  - two-entry list → both identities minted in the rendered Job spec, RBAC
    `resourceNames` carries both Secret names, explicit `secretName`
    respected, empty `secretName` defaults correctly;
  - `adminTasksEnabled: false` → no Job, no RBAC (unchanged gate);
  - rotation rendering: per-entry `rotate: true` reaches only that entry's
    mint invocation; global `rotateSvcToken: true` reaches all entries.

## Acceptance

- A fresh install with a two-entry list produces both Secrets with
  correctly-capped tokens, no manual step.
- Upgrade on an existing single-identity install: no re-mint, no Secret
  churn, no rendered diff beyond the template refactor itself.
- A values entry with unbacked permissions fails the upgrade with the
  mint preflight's error naming the missing global grant.
