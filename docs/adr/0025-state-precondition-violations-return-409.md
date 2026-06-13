# 0025 — Caller-reachable state-precondition violations return 409, not 500

- **Status:** Accepted
- **Enforced by:** the `DomainError::InvalidState → 409` arm in `crates/hort-http-core/src/error.rs` (test `invalid_state_is_409`); the caller-reachable entity state guards (`Artifact::release` source-state guard, `PromotionUseCase`'s not-promotable guard) construct `InvalidState`, never `Invariant`. `Invariant → 500` and `Conflict → 409` (optimistic-concurrency) are unchanged (tests `invariant_is_500`, the OCC-409 mapping).
- **Supersedes:** —

## Context

`DomainError` mapped `Conflict → 409` (reserved for event-store optimistic-concurrency version conflicts) and `Invariant → 500` ("a domain invariant that should be impossible to violate if the application layer is correct"). But several **caller-reachable state-machine preconditions** were constructed as `Invariant`:

- `Artifact::release`'s source-state guard — releasing an artifact that is not `Quarantined`/`ScanIndeterminate` (admin release or curator waive).
- `PromotionUseCase` — promoting an artifact that is `Quarantined`/`Rejected`.

An operator reaches these directly — e.g. `POST /api/v1/admin/quarantine/:id/release` on a `rejected` artifact. The result was **HTTP 500 `{"error":"internal error"}`** for a well-formed request the server fully understood and *deliberately refused* because of the resource's state.

That is semantically wrong (5xx means *the server failed*; nothing failed) and operationally harmful: it pages on-call, burns error budgets, and invites client/proxy retries of a request that can never succeed — while telling the operator nothing actionable. The defect surfaced during the alpha-testing runbook walk (admin release of a `rejected` artifact). The `Invariant → 500` mapping itself is correct for genuine internal breaches; the bug was **overloading `Invariant`** for guards a caller can legitimately reach by choosing a target in the wrong state.

## Decision

Add `DomainError::InvalidState(String)`, mapped to **409 Conflict** at the HTTP boundary, carrying the real domain message. It denotes a caller-reachable state-machine precondition: the request is well-formed and understood, but the target resource is in a state incompatible with the requested transition.

- `Invariant` keeps `→ 500` — reserved for should-never-happen-via-a-correct-caller internal breaches (and adapter-wrapped infrastructure failures surfaced through a domain trait's return type).
- `Conflict` keeps `→ 409` — reserved for event-store optimistic-concurrency version conflicts. `Conflict` and `InvalidState` both yield 409; they are distinguished in domain code, logs, and metrics, and disambiguated **on the wire by the response body**, not the status code.

Applied to the caller-reachable entity guards: `Artifact::release` source-state guard and `PromotionUseCase`'s not-promotable guard. The curator-waive metric classifier (`classify_append_error`) maps `InvalidState` to the `conflict` label — matching its prior `Invariant → conflict` classification, so the metric is unchanged. Internal-only / infrastructure guards (`fail_scan_indeterminate`, port-default and adapter-wrapping `Invariant`s) are **unchanged** — they remain `Invariant → 500`.

## Consequences

- Releasing a `rejected` / `released` / `None` artifact, or promoting a `quarantined` / `rejected` one, now returns **409** with an actionable message (e.g. `cannot release artifact in state rejected`) instead of an opaque 500.
- `rejected` is terminal under **both** the admin and curator release surfaces — neither `admin_release` nor curator-waive exits it (both go through the same source-state guard). The supported path to clear a `rejected` artifact is finding-exclusion re-evaluation (`hort-cli curation exclude-finding` → `re_evaluate`, authority `PolicyReEvaluation`). Architect invariant 3 is reconciled to state this (its earlier wording implied `admin_release` reverses `rejected`).
- 409 now spans two domain causes (OCC version conflict; state precondition). Acceptable: 409 is the correct HTTP status for "request conflicts with the current resource state," and clients distinguish via the body.
- Monitoring: wrong-state operator mistakes no longer inflate 5xx error rates or page on-call.

## Alternatives considered

- **Map wrong-state to 422** (keep 409 strictly OCC). Rejected: 409 is the more precise HTTP semantic for resource-state conflicts; 422 is associated with request-*body* validation (the codebase already uses 400 `Validation` for that).
- **Reuse `Conflict` for wrong-state.** Rejected: a distinct `InvalidState` variant preserves the deliberate OCC-only meaning of `Conflict` in domain code and metrics while still mapping both to 409.
- **Leave 500 (the prior tested behaviour, pinned by `waive_already_released_artifact_returns_500_for_invariant`).** Rejected: a 500 for a deliberately-refused, well-formed request is an HTTP-semantics and operability defect; the test codified incidental behaviour with a post-hoc rationale and is updated here (`waive_non_quarantined_artifact_returns_409_invalid_state`).
