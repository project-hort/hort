# 407 — The credential store has a horizon

**Issue:** #271 · **Branch:** `agent/271-api-tokens-hygiene` · item 2 of 2.
**Depends on item 1** only for the operator query; the sweep itself is
independent of `issued_via` and deletes by state, not by provenance.

**Governing decisions:** ADR 0030 (row deletion is not DDL, so no
`CONTRACTIONS.toml` entry; the CHECK widening is additive), ADR 0022
(migrations are frozen once applied), ADR 0066 (task tiers — **new since
this issue was specified**, and the reason this item has a design decision
it did not have before), plus the three existing row-retention sweeps as
the form.

## The property

**Every table that grows on its own has exactly one horizon.** `api_tokens`
has none. Measured on the reporting instance: 9 523 rows, 9 498 of them
expired and not revoked, about 170 new rows a day, oldest from
2026-06-28. The space is irrelevant (4.6 MB); the cost is item 1's.

Verified on `develop` at `bdc502d1`: **nothing in production deletes from
`api_tokens`** — the only `DELETE FROM public.api_tokens` in the tree is in
a test (`crates/hort-adapters-postgres/tests/subscription_repo.rs:503`), no
port method exposes one, and none of the existing sweeps reaches the table.

The rows carry `last_used_at`, `last_used_ip` and `last_used_user_agent`,
which exist nowhere else — the event store keeps `ApiTokenIssued`,
`ApiTokenRevoked` and `ApiTokenUsed` but not those three fields. **That is
why this is a horizon and not an immediate delete.**

## What to build

**`api-token-retention-sweep`, in the shape of `scan-row-retention-sweep`**
(`crates/hort-app/src/task_handlers/scan_row_retention_sweep.rs`): delete
rows that have been expired or revoked for longer than the window, for every
`kind`. Default **90 days**, maximum **365 days**.

The window plumbing already exists and must be reused rather than re-made:
`resolve_sweep_horizon(kind, params, DEFAULT, MAX)`
(`crates/hort-app/src/task_handlers/sweep_horizon.rs:57`) resolves the
horizon from the row's `params` JSONB for all three existing sweeps, so the
rule lives in one place rather than in a fourth near-verbatim copy.
`scan-row-retention-sweep` declares `DEFAULT_HORIZON` at `:77` and
`MAX_HORIZON` at `:98` and calls the helper at `:126`; copy that, with 90
days as the default.

**What that helper is and is not.** It is **not** an operator-facing window.
`sweep_horizon.rs:11-25` states the measured position in its own module
docs: *"No supported path supplies `horizon_seconds`"* — the Helm CronJobs
and the systemd timers both run `hort-server enqueue-<kind>`, those
subcommands take no arguments and write `params` unconditionally empty, and
no `hort-http-admin-tasks` route exists for a retention kind. **So the
90-day default is the horizon in force on every deployment**, and the parse
plus the cap exist to make that statement safe: a hand-written `INSERT` into
`public.jobs` carrying a nonsense value fails the task instead of running a
year-wide `DELETE`. Reuse the helper for that property, not for a
configurability the siblings do not have.

**And two of its doc statements stop being true when a fourth caller
arrives, so generalise them in the same change.** `sweep_horizon.rs:1-3`
scopes the module to *"the three `jobs`-row retention sweeps"* and names all
three; an `api_tokens` sweep is a fourth caller against a **different
table**. `SweepHorizonParams::horizon_seconds`' own field doc (`:41-43`)
defines eligibility as *"rows whose `updated_at` is older than `now() -
horizon_seconds`"*, and `api_tokens` has no `updated_at` column at all — its
eligibility is `expires_at` / `revoked_at`. Reword both to say what the
helper actually does (resolve a duration from `params`, with the caller's
default and cap) and leave the per-table predicate to each caller. Do not
leave the module claiming three callers and one column name that is wrong
for the fourth.

**The registration census — derived from the newest precedent rather than
listed from memory.** Every file that names `jobs-row-retention-sweep` on
`develop` is a site this kind needs too; the load-bearing ones:

- **The migration.** A new numbered file that redefines `jobs_kind_check`:
  `ALTER TABLE public.jobs DROP CONSTRAINT jobs_kind_check` followed by
  `ADD CONSTRAINT jobs_kind_check CHECK (kind IN (…))` with the list copied
  from the **newest defining migration** — `027_jobs_kind_jobs_row_retention_sweep.sql`,
  still the newest as of `bdc502d1` — plus the new literal. The effective
  allow-list is whichever migration defined it last, so copying from an
  older one silently narrows it.
  **The paired same-name `_check` shape is not cosmetic:** `jobs` is on the
  `no_sensitive_drops` sensitive-table list (the task queue), and that
  guard's exemption is an allow-list restricted to a
  `DROP CONSTRAINT <name>_…_check` paired with an `ADD CONSTRAINT` of the
  **same** `_check` name on the **same** table. A renamed constraint or an
  unpaired drop is rejected, by design.
- **`EVENT_TASK_KINDS`** (`crates/hort-domain/src/events/authorization_events.rs`)
  in lock-step with that list — `crates/hort-adapters-postgres/tests/task_kind_check_lockstep_guard.rs`
  resolves the effective list the same way and fails on drift.
- **The task tier** (`crates/hort-domain/src/types/task_tier.rs`). This is
  the part the original specification could not have: ADR 0066's tiers
  landed after it was written. The file carries an **exhaustive** census over
  the `jobs.kind` CHECK, so a kind absent from it fails a test rather than
  defaulting. Its three siblings are all
  `("…-row-retention-sweep", "cron", 10, BULK_BAND)` (`:820-824`), and this
  kind belongs with them: it is scheduled maintenance that no client waits
  on. Follow that unless you can show it is wrong.
- **`ADMIN_INVOKABLE_TASK_KINDS`** — membership only. **No HTTP route and
  no CLI advertisement**, which is the opposite of what an earlier draft of
  this item said and is the precedent's deliberate position rather than an
  omission. All three sibling sweeps are in both `EVENT_TASK_KINDS` and
  `ADMIN_INVOKABLE_TASK_KINDS` and **none** of them is among
  `hort-http-admin-tasks`' explicitly enumerated `post(invoke::<…>)` routes,
  so `POST /api/v1/admin/tasks/<kind>` answers 404 for all three today. The
  reason is a security posture, stated at
  `crates/hort-server/src/cli/enqueue_jobs_row_retention_sweep.rs:18-26`:
  routing a default-on schedulable tick through the `hort-cli` HTTP
  admin-task path *"would drag the whole `svc-token-bootstrap` Job chain
  (and a standing `admin_task_invoke` token mount) to default-on"*, while
  the runtime DSN can only `INSERT INTO public.jobs`. Adding a route here
  would reverse that decision for the **credential store** of all tables, so
  do not add one.
  The full invocation surface is therefore the two constants plus the
  DSN-direct subcommand below, and
  `crates/hort-app/tests/cli_advertises_only_routed_task_kinds.rs` passes
  **unchanged** — nothing is advertised and nothing is routed, so neither
  half of its property is touched. If you find yourself editing that guard,
  stop and report.
- **Worker registration** (`crates/hort-worker/src/composition.rs`), the
  DSN-direct `enqueue-…` subcommand (`crates/hort-server/src/cli/`), the
  **Helm CronJob** plus `values.yaml` and `values.schema.json`, the Ansible
  timer defaults (`deploy/ansible/roles/hort_timers/defaults/main.yml`), the
  schedule-parity test (`crates/hort-config/tests/deploy_schedule_parity.rs`),
  a per-kind CHECK test beside
  `crates/hort-adapters-postgres/tests/jobs_kind_check_jobs_row_retention_sweep.rs`,
  and the two reference docs (`docs/architecture/reference/helm-chart.md`,
  `…/server-and-worker-configuration.md`) plus `crates/hort-worker/README.md`.

**One horizon per table, and it must not eat its own state.** 027's
predicate is the textual complement of its two siblings precisely so that
exactly one horizon is ever in force per kind, and it deliberately retains
the newest `completed` and newest terminal row per kind because the
boot-time liveness gauges and the prefetch rotation cursor read them.

The same question was asked here before this item was dispatched, and the
answer is **nothing does** — but the four places it could have gone wrong
are worth having, because three of them are reads a reviewer would otherwise
have to re-derive and the fourth is a **write**:

- **The validation cache cannot resurrect a deleted row.** `PatCache` is a
  per-replica in-process LRU with a 5-minute wall-clock TTL, and the cached
  entry carries `expires_at` and `revoked_at` which the cache-hit path
  **re-checks on every hit** (`crates/hort-app/src/use_cases/pat_cache.rs:82-85`,
  fields at `:107-113`). An entry whose row is expired or revoked is
  therefore refused without a database round trip, so a row ≥90 days past
  either mark cannot be live in the cache, and the sweep needs **no**
  `ApiTokenCacheInvalidator::invalidate_token` call per deleted row. Do not
  add one.
- **The prefix lookup is `LIMIT 1`**
  (`crates/hort-adapters-postgres/src/api_token_repo.rs:188`), so removing
  dead rows *reduces* the chance a live token's lookup lands on a dead row
  sharing its 8-character prefix. The sweep improves this read; it does not
  endanger it.
- **The per-user `COUNT(*)`** (`api_token_repo.rs:233`) is `list_for_user`'s
  pagination total, not a quota — no cap is enforced on it, so a shrinking
  count changes a page total and nothing else.
- **The one outbound effect: `subscriptions.created_by_token_id` references
  `api_tokens(id) ON DELETE SET NULL`** (`migrations/012_subscriptions.sql:103`).
  So this `DELETE` *writes* to another table, and 012's own comment
  (`:30-34`) blesses that for an operator deleting a token — it was not
  written with an automated sweep in mind. It is nonetheless not a problem
  **today**, for a reason that must be stated rather than assumed: the only
  production site that builds a `Subscription` writes
  `created_by_token_id: None`
  (`crates/hort-app/src/use_cases/subscription_use_case.rs:566`); the sole
  `Some(...)` in the workspace is the FK's own test
  (`crates/hort-adapters-postgres/tests/subscription_repo.rs:492`). The
  column is inert in production, so no audit attribution exists to lose.
  Say this in the report as a finding, not as a cleared checkbox — if a
  later change starts populating it, this sweep silently begins erasing
  audit attribution, and this paragraph is the only place that connection is
  written down.

**Both marks are nullable, and that is the deletion hazard.** `expires_at`
and `revoked_at` are both `timestamp with time zone` with no `NOT NULL`
(`migrations/008_api_tokens.sql:56-57`), and a row with **both** NULL is a
durable identity that never expires — exactly the ten-or-so rows the whole
of item 1 exists to make findable. The predicate must select only a row
whose own non-NULL mark is older than the horizon; a `COALESCE`-flattened or
negated form can invert that and reach a live credential. Assert the
both-NULL row survives, as its own test.

## Explicitly not in scope

The cap model (ADR 0012), lifetimes (ADR 0013), and whether exchange tokens
should be rows at all rather than JWTs like CLI sessions. That last one is a
real design question — it would have to answer revocation and usage
tracking — and it is not this item.

## Acceptance

- A row expired longer than the window is deleted; one expired inside the
  window is not; one revoked longer than the window is deleted. Asserted
  per branch, not by a single sweep over a mixed fixture.
- The window resolves from task params and falls back to 90 days, and a
  request above 365 days is refused — through `resolve_sweep_horizon`, not a
  second implementation. Both branches are unit-asserted even though no
  supported path supplies the field, for the reason the helper's own docs
  give.
- `sweep_horizon.rs`' module docs and `horizon_seconds`' field doc no longer
  claim three callers or an `updated_at` predicate.
- The migration's CHECK list is the newest defining migration's list plus
  one literal, and `task_kind_check_lockstep_guard` passes.
- The kind has a tier and a queue priority, and `task_tier.rs`'s exhaustive
  census passes.
- `cli_advertises_only_routed_task_kinds` passes **unchanged**, with the kind
  neither routed nor advertised — the sibling position.
- `deploy_schedule_parity` passes with the new CronJob **and** the new
  Ansible timer. Membership is what it compares, so one without the other
  fails it.
- Nothing reads an `api_tokens` row as state the sweep deletes — state the
  check that was made, not just the conclusion.
