# 335 — An exclusion is removed by its identity, not by its CVE

**Issue:** #349 · **Branch:** `agent/349-the-predicate-of-the-purpose`
**Governing decisions:** ADR 0025 (a caller-reachable state-precondition
violation is a 409 carrying the domain message, never a 500 and never a silent
choice) · ADR 0011 (authority hierarchy and API versioning — why the route is
not removed) · ADR 0008.

**Depends on nothing.** One handler, one request DTO, their tests.

## 1. The route picks a row by a predicate that is not its identity

`crates/hort-http-core/src/handlers/admin/policies/exclusions.rs:325`, on
`DELETE /api/v1/admin/policies/{policy_id}/exclusions/{cve_id}`
(`handlers/admin/policies/mod.rs:59`):

```rust
let Some(found) = exclusions.into_iter().find(|e| e.cve_id == cve_id) else {
```

**The predicate of the purpose is the row's identity.** An exclusion is
identified by `ExclusionProjection::exclusion_id`
(`crates/hort-domain/src/entities/scan_policy.rs:642`), and a policy can hold
several exclusions for the **same CVE** that differ only in
`package_pattern` (`AddExclusionCommand.package_pattern: Option<String>`,
`crates/hort-app/src/use_cases/policy_use_case.rs:212`). The use case already
takes the right thing — `RemoveExclusionCommand.exclusion_id`
(`policy_use_case.rs:228`) — and the POST hands that id back to the caller
(`exclusions.rs:259-262`), so the caller holds it.

**What happens instead.** The route throws the identity away and searches by
CVE. With more than one match, the projection's ordering decides which row
dies and the others are **unreachable through the API**: the operator either
withdraws the wrong suppression or can never withdraw one at all. A
suppression that outlives the operator's decision to end it is the real cost —
findings stay hidden that were meant to come back.

No privilege is crossed; the only precondition is two exclusions for one CVE.

## 2. The chosen form, and the one rejected

The architecturally purest reading would move the route onto `exclusion_id` —
the predicate of the purpose directly in the path. **Rejected:** that removes
an existing admin route, and a removed route is behaviour-relevant here by
standing practice. The additive form instead:

- **Exactly one match for the CVE → unchanged behaviour**, byte for byte.
- **More than one match and no disambiguator → `409`** carrying the
  candidates (`exclusion_id` plus `package_pattern` for each) **as structured
  members of the JSON body, not as text inside the message**. ADR 0025
  governs the *status*: the resource's state is incompatible with the
  requested transition, so 409, never a 500 and never `DomainError::Conflict`
  (reserved for event-store optimistic concurrency).

  It does **not** go through `DomainError::InvalidState`'s generic
  `{"error": message}` tail, and the reason is the codebase's own, written at
  the two sites that already do this: `ManagedByConfiguration` emits an
  RFC 9457 body *"so operators (and automation) can route on the `managedBy`
  member without string-matching the error message"*
  (`crates/hort-http-core/src/error.rs:75-101`), and `UpstreamBodyTooLarge`
  emits `bytes_read` + `cap` as members so the operator gets *"the exact
  numbers they need"* (`:103-129`). The caller here needs the `exclusion_id`
  to make the request that succeeds; recovering a UUID by parsing an error
  sentence is exactly what those two arms exist to avoid.

  The shape follows them: a **typed `DomainError` variant** carrying the CVE
  and its candidates, an **early-return arm** in `ApiError::into_response`
  rendering `application/json` with the candidates as members, and an arm in
  the inner `match` kept for exhaustiveness with the `debug_assert!` that
  `ManagedByConfiguration` and `Contended` carry (`error.rs:218-232`) — so a
  future edit that drops the early return fails loudly instead of silently
  falling through to the generic tail.
- **`RemoveExclusionRequestDto` gains an optional `exclusion_id`**
  (`exclusions.rs:185-188`, today only `reason`). Set → it selects the row.
  Set but not among the policy's exclusions for the path's CVE → a validation
  error, never a silent override of the path.
- **No match for the CVE → `404`**, unchanged.

This answers the ambiguity where it can actually be answered — by the caller
who knows which row they mean — instead of hiding it behind an ordering. The
request stays backward-compatible: every body that works today keeps working,
and only the previously-undecidable case changes its answer.

## 3. What must not drift

The repository-scope `info!` at `exclusions.rs:345-357` and the
`reason`/`MAX_JUSTIFICATION_BYTES` validation at `:288-301` run before the
lookup and keep running before it. The 409 is raised **after** the reason
validation, so a malformed request is still answered as malformed.

## Acceptance

- A test that **kills the wrong predicate**: a policy with two exclusions for
  the same CVE and different `package_pattern`s — the unqualified `DELETE`
  answers `409` and lists both candidates, a `DELETE` naming the first
  `exclusion_id` removes exactly that row, and a second `DELETE` naming the
  other removes it too. **Both rows are reachable**; neither is stranded.
- A test asserting the 409 body's **members**, not its prose: each candidate's
  `exclusion_id` is readable as a field, so a caller never parses the message.
- A test pinning the single-match path unchanged: `204`, and the use case is
  called with the same `RemoveExclusionCommand` as today.
- A test for `exclusion_id` present but belonging to another CVE on the same
  policy → validation error, and the use case is **not** called.
- A test for the unchanged `404`.
- Tests use `build_mock_ctx` (no hand-rolled `AppContext`).
- No file under `migrations/` is changed.
- Full gate green (`CHECK/FMT/CLIPPY/TEST/AUDIT/DENY/ATTR`). No issue/MR
  references in code comments.

## Out of scope

- The two other findings on this issue (items 334 and 336).
- Moving or removing the route, and any change to `PolicyUseCase`.
- The repository-scope reporting decision recorded in the comment at
  `exclusions.rs:332-344` — read it, leave it.
