# 0065 — Irreversibility is a first-class property of an operation

- **Status:** Accepted
- **Enforced by:** per surface — there is no central guard, because "what
  counts as evidence here" is a question only the surface can answer. It is
  already structural at every irreversible path this repository has: the
  `events_immutable` trigger plus its deliberately narrow
  `current_user = 'hort_retention_role'` exemption
  (`migrations/004_events.sql`), under which a stream's rows can be removed
  only after a `StreamSealed` tombstone has appended successfully and only by
  a `DELETE` carrying its own same-snapshot `NOT EXISTS` tail check
  (`crates/hort-adapters-postgres/src/event_store.rs`); `purge_gc`'s
  requirement of an `ArtifactExpired` / `ArtifactDeleted` work item, its
  exclusion of the GC-protected statuses and its re-read of the protecting
  predicate under the artifact lock
  (`crates/hort-adapters-postgres/src/purge_gc.rs`); and
  `resolve_finding_age_anchor` returning `Option`, so a retention predicate
  with no age evidence does not match
  (`crates/hort-domain/src/retention/anchor.rs`).
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md),
  [0027](0027-artifact-provenance-verification.md),
  [0038](0038-admin-identity-model.md),
  [0039](0039-keyed-provenance-verification.md),
  [0061](0061-store-driven-notification-delivery.md),
  [0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md) — the
  five decisions that derived this rule independently;
  [0028](0028-destructive-task-idempotency.md) and
  [0030](0030-sensitive-surface-structural-guards.md) (the destructive-task
  and sensitive-schema guards that instantiate it);
  [0054](0054-content-level-age-evidence-anchors-quarantine.md) (the same
  earliest-evidence shape at the quarantine anchor, where the direction of
  conservatism is the opposite one). Source: the finding-age anchor review
  (issue #369) and the maintainer's 2026-10-28 decision.

## Context

Hort already reasons this way and has never written it down. Five accepted
ADRs argue the same point from scratch, each in its own domain:

- **0007** declines to escalate a recoverable outage to the stricter terminal
  state — the artifact stays `quarantined` and heals through the existing
  authority.
- **0027 and 0039** replace a terminal rejection with an indefinite hold
  *because* the hold is recoverable: sign the parent, the cascade clears.
- **0061** disables a subscription rather than skipping an event, in its own
  words because "a gap is recoverable by nobody, a disabled subscription is
  recoverable by an operator".
- **0064** runs a new analysis path as a shadow assessment carrying no release
  authority, because a pipeline whose first act can be irreversible is the
  thing to avoid.
- **0038** keeps destructive operations behind a fresh, claim-bearing admin
  session, so there is zero *standing* destructive privilege.

A rule re-typed once per consumer eventually fails at a consumer, which is why
this repository single-sources such rules elsewhere. It failed here. The
retention predicate `HasFindingDetectedFor` resolved its age anchor through a
three-rung ladder whose last rung was `artifact.created_at` — the largest age
the data could support, asserted from no evidence, in a predicate whose match
appends `ArtifactExpired` and leads to deletion. The governing rule was
already written one function above it: `scan_is_fresh` refuses to expire an
artifact whose scan freshness is unprovable. Nobody carried it one function
down.

"Fail-closed" did not catch it, and could not have. Fail-closed says which way
to fail when one direction is permissive. At a retention predicate both
directions look defensible — deleting enforces the operator's policy, keeping
preserves availability — and on the availability axis "do not delete" is the
*permissive* choice. Something else has to decide.

## Decision

**Irreversibility is a property an operation is classified by, and it is cut
on the recoverability of the outcome, not on the reversibility of the
operation.**

1. **An operation is irreversible when nobody — including an operator with
   full authority — can restore the state afterwards.** By this cut a token
   revocation is not irreversible (authenticate again), nor is a gitops
   reconcile delete (apply the envelope again), nor pruning terminal job rows
   (the work is done). These are not exceptions to the rule; they are outside
   it by definition.
2. **An irreversible operation acts only on positive evidence.** Absent or
   ambiguous evidence means *do not act*. A value substituted for missing
   evidence — a default, a fallback, a swallowed error — is not evidence, and
   is most dangerous when it happens to be the permissive one.
3. **An irreversible operation requires explicit, fresh authority**, never
   ambient or standing privilege.
4. **Where both directions look restrictive, recoverability decides.** Prefer
   the outcome an operator can still undo.
5. **Classify by the worse case.** Recoverability is not a fixed property of
   an operation: a purged pull-through artifact returns from upstream, a
   hosted upload does not. The operation is classified by the case where
   recovery is impossible.

## What this decision does not say

- **It is not "delete nothing without proof it is worthless."** The evidence
  required is evidence for the predicate the operator configured — a retention
  policy that matches *is* the evidence. Read the other way, retention itself
  would be the first exception, and the rule would be useless.
- **It does not define what counts as evidence.** That stays a per-surface
  decision, which is why this ADR names no central guard.
- **It does not cover additive operations.** Appending an event is
  irreversible and deliberately so; it destroys nothing and forecloses no
  decision.

## Consequences

- A new surface that destroys state or forecloses a decision states, in its
  design, two things: what evidence it requires, and whose authority it acts
  under. A surface that can name neither is not ready to be built.
- The five decisions above stop being five independent arguments and become
  five applications. A future decision in this class cites this ADR instead of
  re-deriving it.
- The rule is retrospective by construction — it was distilled from what the
  system already does — so it creates no migration and no exemption list. Its
  value is at the next destructive surface, not at the existing ones.
