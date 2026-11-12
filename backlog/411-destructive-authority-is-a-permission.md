# 411 — Destructive authority becomes a permission, split by reversibility

**Issue:** #285 · **Branch:** `agent/285-destructive-authority-is-a-permission` ·
item 1 of 2. **No amendment to ADR 0012, 0018 or 0038** — this item uses the
extension path those ADRs already provide. It does add **one new ADR** (the
capability's own standing decision) and amends `docs/auth-catalog.md`
Entry 4.

**Governing decisions:** **#281 D6** (destructive authority becomes a
`Permission` and runs over the grant path — *decided, Tom, 2026-09-24, with
the mechanism corrected the same day after a second review*), **#281 D7**
(split by reversibility — decided), ADR 0012 (`GrantSubject` closed at two
variants; a long-lived static token's authority comes from a direct
`PermissionGrant { subject: User(sa.id) }`; the cap is frozen at mint),
ADR 0037 (`serviceAccount`-subject grants), ADR 0052 (`ReadMetrics` — the
precedent in exactly this shape), ADR 0028 (durable idempotency of the same
kinds), `docs/auth-catalog.md` Entry 4 (the canonical inbound-auth spec).

## Read this first: the shape of this item changed

An earlier grooming of this issue specified a **claim** split in two and a
`claims:`-style declaration on the `ServiceAccount` envelope. **That is a
dead end, it was found to be one in September, and #281 D6 records the
correction as decided.** The issue description carried the pre-correction
framing for nine weeks, and a re-grooming in November reproduced it from the
description. Both are now corrected. The three facts that close it:

1. **A service-account token may never carry a claim.**
   `docs/auth-catalog.md` Entry 4 lists *"no `claims:[…]` ever"* under
   **Mandatory guardrails**, and its Protection line reads *"User-subject
   grants only, never claim-mapped"*. The catalog is the canonical
   inbound-authentication control spec and outranks an individual design
   doc on exactly this question. ADR 0038 §4 says the same from the other
   side: the destructive claim is *"satisfiable only by a fresh,
   claim-bearing admin session — never a static token"*.
2. **The premise that forced the claim was false.** The claim was chosen to
   avoid growing a taxonomy that was never closed. ADR 0012 closes
   **`GrantSubject`** — *"the grant subject taxonomy is structurally
   load-bearing for the evaluator's match logic; adding a third variant
   (`Group`, `ServiceAccountToken`, …) requires re-opening this decision"*
   (`docs/adr/0012-claim-based-rbac-claimless-static-tokens.md:37`). It says
   nothing about `Permission`, which has grown **four times** past its
   original four: `AdminTaskInvoke`, `Curate`, `Prefetch`, `ReadMetrics`
   (`crates/hort-domain/src/entities/rbac.rs:26-67`).
3. **ADR 0012 prescribes the mechanism for this exact case.** *"To give a
   long-lived-token actor non-admin authority, use a direct
   `PermissionGrant { subject: User(sa.id) }` — never mapped-claim
   inheritance on the token."* So the decided design is not a workaround
   around a standing decision; it is the standing decision's own answer.

**And one argument neither grooming had.** Measured 2026-11-08:
`claims_satisfy` (`crates/hort-app/src/rbac.rs:515-526`) short-circuits on
the exact lowercase `"admin"` claim and then returns `true` for **every**
claim requirement, `task:destructive` included. A claim therefore *cannot*
be made orthogonal to `Admin` — every admin satisfies every split of it, so
the narrow authority this issue exists to create is unreachable as a claim.
A `Permission` can: `rbac.rs:386` excludes `ReadMetrics` from the admin
short-circuit, which is what makes "an admin does not implicitly hold the
scraper's grant" true in code rather than in prose.

## The property

**Two authorities, cut by what is destroyed — the artifact or the record of
it — and neither of them implied by being an admin.**

`DESTRUCTIVE_TASK_KINDS`
(`crates/hort-domain/src/events/authorization_events.rs:757-761`) holds
three kinds behind one authority:

```rust
pub const DESTRUCTIVE_TASK_KINDS: &[&str] = &[
    "retention-evaluate",
    "retention-purge",
    "eventstore-archive",
];
```

The third is categorically different. Artifact content is *the thing
itself*, and the record of its removal survives by design — `ArtifactPurged`
stays on the stream. `eventstore-archive` removes the **record**:
authentication audit, download audit, token use. Nothing reconstructs that.
So an identity trusted to reclaim storage is today also trusted to cut audit
history.

**Not cut by purpose.** "Housekeeping" is not an authority boundary: it
moves, and the next destructive operation someone calls housekeeping
inherits the authority. Named by what is destroyed, "does this belong?"
answers itself from the criterion rather than the label — which is also what
supports the kind set's own warning that extending it would be a scope-creep
regression. **The kind set stays at exactly three.**

## D1 — two `Permission` variants, in the `ReadMetrics` shape

`ReadMetrics` is the precedent, point for point, and its own doc comment is
the template to write against (`rbac.rs:57-65`): *"Granted via the audited
`ApplyConfigUseCase` apply path to a dedicated scraper `ServiceAccount`
(non-admin). Orthogonal to `Admin` — an admin caller does not implicitly
hold this grant."*

- Two variants on `Permission` (`crates/hort-domain/src/entities/rbac.rs:26`),
  named for the object destroyed. The literals this item specifies are
  **`destroy_content`** and **`destroy_record`** — a pair that reads as a
  pair, states its object, and carries no purpose in its name.
- **Three hand-maintained sites per variant, and `FromStr` is the trap.**
  The enum's own comment says it: *"`FromStr` is a NON-exhaustive match (the
  compiler will NOT force a new arm when a new `Permission` variant is
  added). When adding a variant, the corresponding `"<literal>"` arm MUST be
  added here explicitly, or gitops `PermissionGrant` parsing silently
  breaks."* `Display`, `FromStr`, and the DB enum literal all follow.
- **An additive migration** adding both literals to the permission enum, in
  the shape of `migrations/016_read_metrics_permission.sql`. Additive, so
  ADR 0030's expand half applies as written and there is no
  `CONTRACTIONS.toml` entry.
- **`Delete` is not reused.** #281 D6 names this: `Delete` is the user
  path's repository-scoped delete authority, and folding a task-tier
  destructive authority into it would make every repo-delete grant a
  retention-purge grant.

## D2 — admin-orthogonality becomes a set, read by **four** sites, not two

**Corrected 2026-11-09 by an outside review of this approach. This item named
two readers; there are four**, and the two it missed are the ones that would
have produced a surface disagreement — an admin denied `destroy_record` by
the evaluator while another surface still implies they hold it:

3. **`derive_cli_session_cap`'s admin branch** (`crates/hort-app/src/rbac.rs:577-609`)
   filters `ReadMetrics` out of a derived cap unless the admin holds an
   explicit grant. A new orthogonal permission must use the same predicate
   here, or it silently rides along in every admin CLI session's cap.
4. **whoami's global-admin projection**
   (`crates/hort-http-core/src/handlers/auth.rs:122-147,283-305`): `GlobalAdmin`
   carries a dedicated `read_metrics` boolean and the renderer looks only for
   *that* permission among the marker's explicit cells. Change only the two
   RBAC readers and **the evaluator denies while whoami keeps implying** —
   the exact "one surface and not another" failure this item called worse
   than either. Keep the existing `read_metrics` field compatible and expose
   the new orthogonal cells from `EffectiveGrantSet` in that projection.

So the declared set has four consumers, and the acceptance below counts
them.

Orthogonality to `Admin` is today one comparison:

```rust
if permission != Permission::ReadMetrics && principal.claims.iter().any(|c| c == "admin") {
```

(`crates/hort-app/src/rbac.rs:386`) — plus a second place that has to agree
with it: `EffectiveGrantSet`'s `is_global_admin` marker carve-out, which
names `ReadMetrics` in its doc and in `effective_grants` (`rbac.rs:36-39`, struct at `:41`),
so the whoami self-view, the per-user endpoint, the what-if resolver and
`derive_cli_session_cap` all report the same authority the request-time gate
enforces.

Three `!=` comparisons in two places is how the fourth one gets forgotten.
**Declare the admin-orthogonal set once** — a single predicate or `const`
slice in `hort-domain` beside `Permission` — and have both the short-circuit
and the marker carve-out read it. This is the project's own pattern
(`GC_PROTECTED_QUARANTINE_STATUSES` is the nearest exemplar: one constant,
four reading sites, a guard that the readers still read it).

## D3 — the gate's factor 2 changes authority, not structure

The two-factor gate stays two-factor and stays fail-safe-by-AND. Factor 1
(`Permission::AdminTaskInvoke`) is untouched for every kind. Factor 2
becomes an `authorize` of the matching new permission instead of a
`claims_satisfy`.

Both evaluation sites change, and the second is the one easy to miss:

- **Acceptance** — `crates/hort-app/src/use_cases/task_use_case.rs:200-216`
  (`authorize_kind`), which answers a caller with a `403`.
- **Execution re-check** —
  `crates/hort-app/src/destructive_task_reauthorization.rs:266`, which
  re-checks the requester named on the queued row against live authority
  before the handler runs, and has only the row and the log. Its refusal
  message names the claim today.

`task_invocation_is_destructive`
(`crates/hort-domain/src/events/authorization_events.rs:861-872`) answers
`DomainResult<bool>` — *"will this call destroy anything?"*. It must now also
answer **which** authority, because the two halves are no longer
interchangeable. Keep it **one function**: `task_use_case.rs:150-154`
records why — the invoke handler's durable per-UTC-day idempotency key
(ADR 0028) reads the same function, *"so the authority an invocation needs
and the single-flight claim it takes cannot come apart. Re-deriving either
one locally is how they came apart before."* A second function that answers
"which permission" beside one that answers "whether" re-opens exactly that.

**The dry run stays outside both authorities, and that is already true.**
Factor 2 is resolved per *invocation*, not per kind: `task_use_case.rs:200`
calls `task_invocation_is_destructive(kind, params)`, and
`crates/hort-http-admin-tasks/src/handlers/invoke.rs:219-228` states the
intent — the per-kind question is *"deliberately NOT"* asked because *"an
observation has no such hazard and must stay repeatable"*. It is unpinned by
a test that would fail if someone replaced the invocation predicate with the
kind predicate, and that replacement is the natural-looking simplification.
Add that test.

## D4 — the claim is removed, and its footprint is the work

`DESTRUCTIVE_TASK_CLAIM` (`authorization_events.rs:779`) goes away. #281 D6:
*"Der Claim entfällt; menschliche und maschinelle Aufrufer erhalten die
Autorität dann auf demselben Weg."* It is named in **29 files** on
`develop` — census it with

```
grep -rln "task:destructive" docs deploy crates \
  --include='*.md' --include='*.yaml' --include='*.rs' --include='*.json'
```

and treat the result as the work, not as a tail. It spans the two evaluation
sites, `rbac.rs`' own tests, four `hort-cli` retention files, the admin-tasks
handler and four of its test files, two `hort-server` tests, the three chart
CronJob templates plus `values.yaml`, the Ansible gitops `cronjob-tasks` SA
and its grant, and eight docs including **ADR 0038** and **ADR 0046**. The
two ADRs are *descriptions* of the gate rather than decisions about it; read
each before editing and keep each ADR's own decision intact.

## D5 — the operational consequence, which is a tightening

After this item **an admin no longer implicitly holds destructive
authority** — that is the whole point of orthogonality, and #281 D6 calls it
*"eine bewusste Verschärfung mit Betriebsfolge, die dokumentiert gehört"*.
Concretely: an interactive admin invoking `retention-purge` gets a `403`
until a grant exists for their identity.

The blast radius is small **today and only today**: both retention CronJobs
ship `enabled: false`, service-account tokens are claimless, and no token
carries the claim — which is exactly why #281 D6 and D7 both say now is the
cheap moment. Document the grant an operator must apply, with the gitops
snippet, where an operator reaching for the task will read it.

## D5b — what the human path trades, corrected

**An outside review found this section wrong in four ways, and two of them I
had already asserted elsewhere. The corrected accounting:**

**Today's claim is *not* bound to a 900-second session.** Native PAT
authentication adds the synthetic `admin` claim when the user is admin
(`authenticate_use_case.rs:889-907,959-980`) and `claims_satisfy` treats it
as satisfying every claim requirement (`rbac.rs:515-525`). So an **admin PAT**
with an `AdminTaskInvoke` cap already passes today's destructive gate — and
an admin PAT lasts **up to 30 days** under the admin-token opt-in
(`api_token_use_case.rs:2282-2324,2337-2380`). The 900 s cap is the
CliSession's alone (`:145-173`). The earlier claim that the claim rides a
≤15-minute credential was therefore simply untrue.

**After the change the reachable lifetime is longer, not shorter.** A
*non-admin* human holding the two explicit grants can **self-mint a PAT**
carrying both: the task gate has no token-kind restriction
(`task_use_case.rs:174-226`), self-mint accepts a non-SA user, and the
issuance gates special-case `Admin` rather than destructive permissions
(`api_token_use_case.rs:839-885,2282-2324`). A non-admin PAT defaults to
**90 days** and may request **365** (`:83-97,2402-2415`). That is materially
longer than the CliSession comparison this item originally drew.

**A pre-issued CliSession gains a newly applied grant without a new login:**
its principal carries `token_cap: None`, so the live grant leg is the only
permission gate (`rbac.rs:295-319`).

**And revocation is not immediate.** Removal does stop a *queued* row at
execution, because the reauthorizer reads the grant repository directly
(`destructive_task_reauthorization.rs:242-273`). But at **request
acceptance** it reaches an already-issued token only after the evaluator's
refresh: the default poll is **30 seconds**, and a failed read **retains the
previous snapshot**, so there is no fixed bound during refresh failure
(`hort-server/src/cli/rbac_refresh.rs:239-251,274-305`;
`hort-server/src/config.rs:338-348`). **Do not call it immediate.**

**What is genuinely gained** is audited conferral — apply commits
`PermissionGrantApplied` / `PermissionGrantRevoked`
(`apply_config_use_case/permission_grants.rs:4-31`) — where the claim arrives
from `user.is_admin` with no recorded decision behind it. And the baseline to
state honestly: the CliSession **already** has `jti` and subject-cutoff
emergency revocation (`authenticate_use_case.rs:1019-1067`), so "gained
revocation" must not be claimed against a zero baseline.

**The new ADR carries this accounting, not the earlier one.**

Removing the claim changes the human path's blast radius, in both
directions, and the new ADR owes a reader both halves rather than only the
tightening in D5.

**What is lost is a time bound, not a check.** #281 D6 established that
today's gate is not a human-in-the-loop: there is no `acr`, no `amr`, no
session-freshness test anywhere in the code. ADR 0038 §4 nonetheless
describes the claim as *"satisfiable only by a fresh, claim-bearing admin
session"*, and the property that sentence actually buys is **the CliSession
lifetime cap** — 900 s, enforced for admin and non-admin alike, and since
ADR 0013's 2026-10-28 amendment the *only* bound on a leaked session,
because refresh was retired rather than built. A `PermissionGrant` has no
such bound: it is standing until someone removes it.

**What is gained is auditability and live revocation.** The claim arrives
from `user.is_admin` via `add_admin_claim_if_admin` — nothing records a
decision to confer it, because no decision was taken. A grant is written in
the gitops tree and applied through the audited path, so conferral has an
author and a diff. And it is revocable immediately: ADR 0012's
cap-intersection makes a token's **cap** frozen at issuance but has **user
grants re-resolve on every call**, so removing the grant closes the door for
already-issued tokens — which is exactly the property the frozen cap does
*not* give (see #257).

So: a short-lived authority nobody decided to confer becomes a standing
authority someone did, revocable in one apply. Name the trade in the ADR's
Consequences; do not present the change as a pure tightening, and do not
claim a freshness check is being preserved — there is none to preserve.

## D6 — one new ADR, and the catalog entry

The capability is a standing decision and gets its own ADR, in the shape of
`docs/adr/0052-scoped-metrics-read-capability.md`: what the authority is,
why it is split by reversibility and not by purpose, why it is orthogonal to
`Admin`, why it is a `Permission` and not a claim (the three facts at the
top of this item), and the operational consequence in D5. Add the index
entry in `docs/adr/0000-historical-decisions-index.md`.

**`docs/auth-catalog.md` Entry 4 is amended in this MR** — item 2 owns the
wording, because it is item 2 that makes an SA able to hold one of these.
Do not amend ADR 0012, 0018 or 0038's decisions: none of them is being
reversed, and saying so in the new ADR's Relates line is the honest record.

## Acceptance

- Two `Permission` variants, named for the object destroyed, with `Display`,
  `FromStr` and DB literal arms, and an additive migration.
- `retention-purge` and `retention-evaluate` in execute mode require the
  content permission and **not** the record permission; `eventstore-archive`
  the reverse. One test per direction **plus the confusion case**: an
  identity holding only the record permission must not authorise a purge.
- Both evaluation sites — acceptance and the execution re-check — read the
  new authority, asserted separately. A revoked grant stops a queued
  destructive row.
- **Neither permission is implied by `Admin`**, asserted directly: an admin
  principal with no such grant is refused, and the same principal with the
  grant is admitted. Admin-orthogonality is declared **once** and all
  **four** consumers read that one declaration — the request-time
  short-circuit, the `EffectiveGrantSet` marker, `derive_cli_session_cap`'s
  admin branch, and whoami's global-admin projection. The decisive test is
  cross-surface: an admin without the grant must be denied by the evaluator
  **and** must not appear to hold it on whoami.
- `task_invocation_is_destructive` remains the single answer and now names
  the authority; the ADR 0028 idempotency key still derives from it.
- The dry run is invocable with neither permission, the executing mode with
  the content permission, pinned by a test that fails if the invocation
  predicate is replaced by the kind predicate.
- `DESTRUCTIVE_TASK_CLAIM` is gone, and the 29-file footprint carries no
  stale reference — verified by the census grep returning only
  `CHANGELOG.md`.
- `Delete` is not reused; the `GrantSubject` taxonomy is untouched.
- The new ADR exists with its index entry; no ADR 0012/0018/0038 decision is
  changed. Its Consequences carry the **corrected** accounting: that today's
  claim already reaches a 30-day admin PAT rather than only a 900 s session;
  that a non-admin grant-holder can self-mint a 90-to-365-day PAT afterwards;
  that a pre-issued CliSession picks up a new grant without re-login; that
  grant revocation at request acceptance is **30-second-polled and unbounded
  during refresh failure**, immediate only for a queued row; and that the
  CliSession denylist is the pre-existing baseline rather than a gain.
- Gate green; `hort-domain`/`hort-app` add no uncovered lines; no ticket
  numbers in code comments.
