# 0060 — Append-conflict reaction contract

- **Status:** Accepted
- **Enforced by:** `hort_app::append_conflict::append_with_conflict_retry` —
  the bounded read-decide-append combinator implementing steps (a)-(d)
  below, with 100%-covered unit tests pinning immediate success,
  satisfied-on-recheck, retry-then-success, exhaustion at the bound (attempt
  count asserted), non-`Conflict` passthrough, and the bound-of-one edge
  case. No call site adopts the combinator yet — that is a follow-up
  change; today the contract is a design rule this ADR states and the two
  sanctioned exceptions it names, checked at review rather than compile
  time.
- **Supersedes:** —
- **Relates:** [0004](0004-pluggable-eventstore-port.md) (the loud
  optimistic-concurrency append this ADR defines the reaction to —
  unchanged); issue #221 (this ADR + the primitive; adoption at the two
  broken call sites is a separate change against the same issue).

## Context

[0004](0004-pluggable-eventstore-port.md) makes `EventStore::append`
conflict loudly on a version mismatch: concurrent writers to one stream
never silently interleave, they get `DomainError::Conflict`. What a writer
*does* with that loud conflict was never a standing decision, so four call
sites answered it four different ways, each patched in isolation:

1. **Token-exchange bounded retry** —
   `ApiTokenUseCase`'s `ApiTokenIssued` append onto a per-user stream
   (`crates/hort-app/src/use_cases/api_token_use_case.rs`) races other
   mints for the same subject. It retries through the shared
   `append_any_with_conflict_retry` helper
   (`crates/hort-app/src/use_cases/mod.rs`). This is real prior art for
   *bounded* retry, but a narrower shape than the contract below: the
   append uses `ExpectedVersion::Any`, so there is no stream content to
   re-read and no intent to re-check against a specific version — a losing
   `Conflict` is resolved by re-issuing the byte-identical append, because
   nothing about the decision depended on the version number in the first
   place. It answers "how do I retry an unconditional append", not "how do
   I react to a conflicting *decision*".
2. **Curation classification** — `classify_append_error` in
   `crates/hort-app/src/use_cases/curation_use_case.rs` turns a `Conflict`
   (and the state-machine `Invariant`/`InvalidState` flavours) into a
   `CurationDecisionResult::Conflict` metric label and returns the error to
   the caller as a decided outcome. No retry.
3. **OCI group-attach / ref-set → 500** —
   `crates/hort-http-oci/src/manifests_write.rs`'s `stage =
   "group_attach_manifest"` / `"group_attach_config"` /
   `"group_attach_layer"` / `"ref_set"` sites map *any* error from
   `ArtifactGroupUseCase::add_member` / `RefUseCase::set`, `Conflict`
   included, straight to `OciError::Internal` (HTTP 500). A concurrent
   multi-arch manifest push that loses a real version race — not a
   duplicate, a genuine divergent write — surfaces to the client as a
   server bug.
4. **Ingest-hook swallow-to-warn** — the post-commit group-membership hook
   in `crates/hort-app/src/use_cases/ingest_use_case.rs` calls
   `add_member` after `ArtifactIngested` has already landed in a separate
   transaction. Any failure, `Conflict` included, is logged `warn!` and the
   ingest still returns `Ok`: the artifact is durably persisted but
   silently unlinked from its group until the reconcile sweep next runs.

Two more existing behaviors are deliberate, not omissions, and this ADR
names both so a reviewer does not mistake either for an instance of the
contract below:

- **`ArtifactGroupUseCase::add_member`'s `GroupAlreadyExists` single
  retry** is the closest existing example of the *shape* this ADR
  standardizes — re-read (`find_by_coords` to pick up the winner's
  `primary_role`), rebuild a fresh batch scoped to the observed
  `existing_id`, re-append once — even though its trigger is a
  discriminated adapter outcome (`GroupCommitOutcome::GroupAlreadyExists`),
  not a raised `DomainError::Conflict`. A second `GroupAlreadyExists` is
  not retried again; it is `DomainError::Invariant` (the adapter lied about
  a `Committed` result). **Prior art**, cited by the backlog item as the
  shape to standardize.
- **The group primary-role race is an unrecoverable conflict, by design.**
  The adapter's conditional `UPDATE ... WHERE primary_role = ''` lets
  exactly one racing caller win; the loser's whole transaction — member
  insert included — rolls back and surfaces `DomainError::Conflict`
  (`ArtifactGroupLifecyclePort::commit_member_added`, step 4). The use
  case does not retry with `is_primary = false`: the caller asked for a
  privileged role assignment and must learn, as a conflict, that it did
  not stick — silently downgrading it to a non-primary member would grant
  a role nobody asked for. **Sanctioned exception #1.**

## Decision

**On `DomainError::Conflict` from an expected-version append, a writer
MUST:**

**(a)** re-read the stream or aggregate the append targeted;
**(b)** re-evaluate its original intent against the refreshed state — if
the intent is already true (the member is present with the same role, the
ref is already at the target, the state machine already reached the
target), succeed **idempotently**, with no further append;
**(c)** otherwise, rebuild the event batch against the refreshed version
and re-append — bounded by a small attempt cap, never unbounded;
**(d)** at exhaustion, surface a **retryable-busy** outcome: `503` +
`Retry-After` at HTTP edges, a typed error internally.

**A `DomainError::Conflict` surfacing as HTTP `500` is a defect by
definition.** `Conflict` from an expected-version append is never evidence
of a broken server — it is evidence that (b) or (c) was skipped. Evidence
class 3 above (the OCI `group_attach_*` / `ref_set` sites) is exactly this
defect, live in production code today; closing it is the follow-up change
this ADR licenses, not part of it.

### The shared primitive

`hort_app::append_conflict::append_with_conflict_retry<T, Fut>(attempts:
u8, cycle: impl FnMut(u8) -> Fut) -> AppResult<T>` is the reusable shape
for (a)-(d). `cycle` is called once per attempt (1-based) and owns the
**entire** read + intent-recheck + rebuild + append cycle for that
attempt, returning:

- `Ok(ConflictCycleOutcome::Satisfied(T))` — intent achieved (append
  committed, or the recheck already found it true). Terminal.
- `Ok(ConflictCycleOutcome::Retry)` — this attempt's append lost to
  `Conflict`; call again.
- `Err(_)` — anything else. Propagates immediately, unretried.

The combinator itself performs **no I/O** and does not inspect or classify
any error: it only counts attempts, invokes the closure, and interprets
the three-way outcome. This is deliberate — the closure is the only code
that calls `append`, so it is the only code that can tell a `Conflict`
apart from every other error, and the primitive cannot be tempted to widen
a retry onto a decided outcome it never sees (see *Alternatives
considered*). On exhaustion — every attempt reporting `Retry` — the
combinator returns `AppError::Domain(DomainError::Contended(_))`.

`DomainError::Contended` is reused deliberately rather than inventing a new
variant: it is already the documented "system is contended right now, not
broken" signal (`crates/hort-domain/src/error.rs`), and it is already
mappable to the existing `503` + `Retry-After` contention vocabulary at the
OCI edge (`manifest_write_contention` in
`crates/hort-http-oci/src/manifests_write.rs`, which already classifies
`AppError::Domain(DomainError::Contended(_))` for the storage-contention
case) without adding new HTTP surface — an edge that already answers one
`Contended` reason with `503` + `Retry-After` answers this one identically,
for free.

### Sanctioned exceptions (deliberate non-retry)

Two behaviors deliberately do not follow (a)-(d), and are not violations
of this contract:

- **Curation's user-facing conflict results.** `classify_append_error`
  (evidence class 2) surfaces a curation decision's `Conflict` to the
  caller as a decided classification outcome, not a transient failure to
  retry past. A curation decision race is meaningful to the caller — it
  needs to know its decision collided with a concurrent one — not
  something to paper over with a silent rebuild-and-reappend.
- **The group primary-role race**, described above under *Context*: the
  loser must learn the privileged assignment did not stick, not have the
  use case quietly retry into a demoted role the caller never requested.

## Consequences

- Evidence classes 3 and 4 above are contract violations today. Fixing
  them — `add_member` and `RefUseCase::set` adopting the primitive, and
  the OCI edge's `group_attach_*` / `ref_set` mappings moving from `500` to
  the `Contended` → `503` + `Retry-After` path — is deliberately **out of
  scope for this change** (no use-case behavior changes here; `add_member`
  and `RefUseCase::set` stay untouched) and is the immediate follow-up.
- Evidence class 1 (token-exchange) is not migrated to the new primitive.
  Its `ExpectedVersion::Any` shape genuinely has no read-decide step to
  express — migrating it would force a vacuous re-read onto a call site
  that never needed one. `append_any_with_conflict_retry` stays the right
  tool for that narrower shape; the two helpers coexist by design, keyed
  on whether the append is protecting a decision made from the stream's
  content.
- A future append site with a real read-decide-rebuild need should use
  `append_with_conflict_retry` rather than hand-rolling a fifth ad-hoc
  answer. A reviewer citing this ADR against a new hand-rolled retry loop
  is enforcing it correctly; citing it against evidence class 1's shape,
  or against either sanctioned exception, is a misread — see *Context* and
  *Sanctioned exceptions* above for why those are not instances of the
  problem.
- The primitive does not sleep or back off between attempts — that stays
  the closure's business (or is simply omitted, for a fast local re-read).
  Keeping the combinator dependency-free means it introduces nothing new
  to audit; a caller that wants jittered backoff composes it in the
  closure, or reuses `event_append_backoff`
  (`crates/hort-app/src/use_cases/mod.rs`) exactly as `EVENT_APPEND_RETRY_ATTEMPTS`-bounded
  callers do today.

## Alternatives considered

- **A transparent retry layer wrapped around `EventStore::append` itself,
  retrying any `Conflict` automatically.** Rejected: `DomainError::Contended`'s
  own doc comment states the reason this would be wrong — a `Conflict` is a
  *decided* outcome against a specific expected version, and re-running the
  *identical* batch against it returns the identical `Conflict` forever. A
  transparent layer sitting below the use case cannot perform the
  re-read-and-rebuild that would actually change the outcome; it can only
  either loop forever doing nothing or bail out no better informed than a
  single attempt. The reaction has to live where the intent and the batch
  construction live — inside the use case's closure — which is exactly why
  the primitive takes a closure instead of an `EventStore` handle.
- **Baking bounded backoff (sleep + jitter) into the primitive.** Rejected
  for this item: it would add a timing dependency to a primitive whose
  value is being pure orchestration, and it would duplicate
  `event_append_backoff`'s existing jittered-exponential shape
  (`crates/hort-app/src/use_cases/mod.rs`) rather than reuse it. Left to
  the calling closure.
- **Migrating the token-exchange (`ExpectedVersion::Any`) call sites onto
  the new primitive for consistency.** Rejected: forcing a vacuous
  read-decide step onto an append that structurally has no decision to
  protect would not simplify anything — it would just be
  `append_with_conflict_retry` wrapping a closure whose "recheck" is
  always trivially "not yet satisfied", which is exactly what
  `append_any_with_conflict_retry` already expresses more directly.
- **Migrating the group primary-role race or curation's classification
  onto the primitive.** Rejected: both are deliberate non-retry semantics
  where retrying would either grant an unrequested role or hide a decision
  race the caller needs visibility into. Named as sanctioned exceptions
  instead of forced into a shape that does not fit them.

## References

- `crates/hort-app/src/append_conflict.rs` — `append_with_conflict_retry`,
  `ConflictCycleOutcome`.
- `crates/hort-domain/src/error.rs` — `DomainError::Conflict` vs.
  `DomainError::Contended` (the doc comment this ADR's "never widen a
  retry onto a decided `Conflict`" argument restates).
- `crates/hort-app/src/use_cases/artifact_group_use_case.rs` — the
  `GroupAlreadyExists` single retry (prior art) and the primary-role race
  (sanctioned exception).
- `crates/hort-app/src/use_cases/curation_use_case.rs` —
  `classify_append_error` (sanctioned exception).
- `crates/hort-app/src/use_cases/mod.rs` — `append_any_with_conflict_retry`
  and `event_append_backoff` (the `ExpectedVersion::Any` prior art this ADR
  does not fold into the new primitive).
- `crates/hort-http-oci/src/manifests_write.rs` — `manifest_write_contention`
  (the existing `Contended` → `503` + `Retry-After` vocabulary the new
  primitive's exhaustion error reuses) and the `stage = "group_attach_*"` /
  `"ref_set"` `500` sites (evidence class 3, the contract violation the
  follow-up change closes).
- `crates/hort-app/src/use_cases/ingest_use_case.rs` — the post-commit
  group-membership hook (evidence class 4).
